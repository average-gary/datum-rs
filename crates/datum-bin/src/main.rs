use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use datum_api::{ApiState, MetricsSource};
use datum_config::{Config, ConfigError};
use datum_stratum_sv1::assembler::JobMeta;
use serde_json::{json, Value};
use tokio::sync::Mutex;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG_PATH: &str = "./datum_gateway_config.json";

fn main() -> ExitCode {
    let git_sha = option_env!("DATUM_GIT_SHA").unwrap_or("dev");
    let argv: Vec<String> = std::env::args().skip(1).collect();

    match parse_args(&argv) {
        Cmd::Help => {
            print_help();
            ExitCode::SUCCESS
        }
        Cmd::Version => {
            println!("datum_gateway {PKG_VERSION} ({git_sha})");
            ExitCode::SUCCESS
        }
        Cmd::ExampleConf => {
            println!("{}", Config::example_json());
            ExitCode::SUCCESS
        }
        Cmd::ValidateConfig(path) => match validate_config(&path) {
            Ok(()) => {
                println!("OK: {} is valid", path.display());
                ExitCode::SUCCESS
            }
            Err(report) => {
                eprintln!("{report}");
                ExitCode::from(1)
            }
        },
        Cmd::Run { config } => run(&config, git_sha),
        Cmd::ParseError(msg) => {
            eprintln!("error: {msg}");
            eprintln!();
            print_help();
            ExitCode::from(1)
        }
    }
}

fn run(config_path: &PathBuf, git_sha: &str) -> ExitCode {
    eprintln!("datum_gateway {PKG_VERSION} ({git_sha})");

    let cfg = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(errs) = cfg.validate() {
        eprintln!(
            "error: {} validation issue(s) in {}:",
            errs.len(),
            config_path.display()
        );
        for e in errs {
            eprintln!("  - {e}");
        }
        return ExitCode::from(1);
    }
    eprintln!("config OK: {}", config_path.display());

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    rt.block_on(async move {
        run_async(cfg).await;
    });
    ExitCode::SUCCESS
}

async fn run_async(cfg: Config) {
    let filter = std::env::var("DATUM_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = datum_logger::install_global(&filter);
    spawn_signal_handlers();

    let runtime = Arc::new(RuntimeStats::new());

    // Job tracker — keyed by the SV1 job-id hex string emitted in
    // mining.notify. Populated by the assembler whenever it builds a notify
    // (so the assembler-side state and the share-relay-side state are
    // consistent) and read by the share-relay when a miner submits.
    //
    // The C reference also tracks per-(job, coinbase_id) `server_has_coinbase`
    // and per-job `server_has_merkle_branches` flags so the optional 0x01 /
    // 0x02 sub-blocks of the share submission are sent only on first use. We
    // track those here as `AtomicBool`s embedded in the JobEntry.
    let jobs = Arc::new(Mutex::new(JobTracker::new()));

    // SV1 stratum server. Bound on the configured port; receives notifies via
    // a watch channel that the runtime publishes to once a template + coinbaser
    // pair lands. Phase 4 wires the publisher; today the channel stays empty
    // and clients block until the gateway gets real templates.
    let (notify_tx, notify_rx) =
        tokio::sync::watch::channel::<Option<datum_stratum_sv1::server::NotifyJob>>(None);
    // Pool-supplied vardiff floor. Updated whenever ClientConfig arrives from
    // the upstream. SV1 server clamps every miner's current_diff to
    // max(local_min, pool_min) so shares never land below the pool's minimum
    // (which would all reject as DATUM_REJECT_BAD_TARGET).
    let (pool_min_diff_tx, pool_min_diff_rx) = tokio::sync::watch::channel::<u64>(0);
    // Pool-supplied coinbase tag override (primary only — C reference never
    // overrides the secondary tag). `None` = pre-handshake / no ClientConfig
    // yet, fall back to operator config. `Some(bytes)` = ClientConfig has
    // spoken; honor pool override even if empty (matches C behavior of
    // `override_mining_coinbase_tag_primary` driven by `datum_protocol_is_active`).
    let (pool_coinbase_tag_tx, pool_coinbase_tag_rx) =
        tokio::sync::watch::channel::<Option<Vec<u8>>>(None);
    let (sv1_shutdown_tx, sv1_shutdown_rx) = tokio::sync::watch::channel::<bool>(false);
    let (submit_tx, mut submit_rx) =
        tokio::sync::mpsc::channel::<datum_stratum_sv1::server::SubmittedShare>(64);
    let sv1_addr: SocketAddr = format!(
        "{}:{}",
        stratum_addr_or_default(&cfg),
        cfg.stratum.listen_port
    )
    .parse()
    .expect("stratum.listen_addr/listen_port parses");
    let vardiff_params = datum_stratum_sv1::server::VardiffParams {
        min: cfg.stratum.vardiff_min,
        target_shares_min: cfg.stratum.vardiff_target_shares_min.max(1) as u32,
        recheck_secs: 30,
        max: 1u64 << 40,
    };
    let sv1_state =
        datum_stratum_sv1::server::ServerState::new(notify_rx, pool_min_diff_rx.clone())
            .with_submit_tx(submit_tx.clone())
            .with_vardiff(vardiff_params);

    let sv1_handle = match tokio::net::TcpListener::bind(sv1_addr).await {
        Ok(listener) => {
            tracing::info!(%sv1_addr, "sv1 stratum listener bound");
            Some(tokio::spawn(datum_stratum_sv1::server::run(
                listener,
                sv1_state,
                sv1_shutdown_rx,
            )))
        }
        Err(e) => {
            tracing::error!(%sv1_addr, error = %e, "sv1 bind failed; SV1 server disabled");
            None
        }
    };

    // SV2 channel registry — exists from boot so future wiring can hand out
    // channel_ids without restart. Server task itself awaits SRI integration.
    let sv2_registry = datum_stratum_sv2::ChannelRegistry::new();
    runtime.set_sv2_registry(sv2_registry.clone());

    // RPC client + template puller. If the operator hasn't configured a
    // bitcoind endpoint yet, the gateway runs in "stratum-only / awaiting
    // bitcoind" mode — useful for operator pre-flight.
    let mut block_submitter: Option<Arc<datum_submitblock::BlockSubmitter>> = None;
    let template_channel: Option<datum_blocktemplates::TemplateChannel> =
        if !cfg.bitcoind.rpcurl.is_empty() {
            let auth = if !cfg.bitcoind.rpccookiefile.is_empty() {
                Some(datum_rpc::Auth::Cookie(
                    cfg.bitcoind.rpccookiefile.clone().into(),
                ))
            } else if !cfg.bitcoind.rpcuser.is_empty() {
                Some(datum_rpc::Auth::UserPass {
                    user: cfg.bitcoind.rpcuser.clone(),
                    pass: cfg.bitcoind.rpcpassword.clone(),
                })
            } else {
                None
            };
            match auth
                .and_then(|auth| datum_rpc::Client::new(cfg.bitcoind.rpcurl.clone(), auth).ok())
            {
                Some(client) => {
                    runtime.set_rpc_url(cfg.bitcoind.rpcurl.clone());
                    tracing::info!(rpcurl = %cfg.bitcoind.rpcurl, "datum-rpc client constructed");
                    let rpc = std::sync::Arc::new(client);
                    block_submitter = Some(Arc::new(datum_submitblock::BlockSubmitter::new(
                        rpc.clone(),
                    )));
                    let (puller, ch) =
                        datum_blocktemplates::TemplatePuller::new(rpc, ["segwit".to_string()]);
                    tokio::spawn(puller.run());
                    Some(ch)
                }
                None => {
                    tracing::warn!("bitcoind RPC auth missing; template puller not spawned");
                    None
                }
            }
        } else {
            tracing::warn!("bitcoind.rpcurl empty; template puller not spawned");
            None
        };

    // Coinbaser channel. The DATUM upstream task is responsible for fetching
    // the OCEAN coinbaser blob and publishing it. Until that lands here,
    // operators running against a real OCEAN endpoint will see notifies
    // gated on the first coinbaser response from upstream.
    let (coinbaser_pub, coinbaser_sub) = datum_coinbaser::CoinbaserPublisher::new();

    // Phase 1 of the SV2 listener plan: shared `TemplateState` watch channel.
    // Both SV1 (today) and SV2 (Phase 4) consume the same `Arc<TemplateState>`
    // so the prevhash/coinbase/merkle bytes are produced once per (template,
    // coinbaser) pair. Per the SV2 architecture playbook §6, the watch channel
    // hands both protocols the same `Arc` on every transition — they cannot
    // diverge on prevhash.
    let (template_state_pub, template_state_ch) =
        datum_blocktemplates::TemplateStatePublisher::new();
    if let Some(template_ch) = template_channel.clone() {
        let mut t_sub = template_ch.clone();
        let mut c_sub = coinbaser_sub.clone();
        let coinbase_tag_primary = cfg.mining.coinbase_tag_primary.clone();
        let coinbase_tag_secondary = cfg.mining.coinbase_tag_secondary.clone();
        let coinbase_unique_id = cfg.mining.coinbase_unique_id;
        let pool_coinbase_tag_rx_for_state = pool_coinbase_tag_rx.clone();
        let template_state_pub_for_task = template_state_pub.clone();
        tokio::spawn(async move {
            // Per-job 2-byte enprefix counter, XOR'd with 0xB10C — mirrors
            // `stratum_enprefix ^ 0xB10C` in datum_stratum.c:71, 2030-2031.
            // Lives on the TemplateState driver so the bytes baked into
            // `coinb1` are stable for both SV1 + SV2 consumers of a given
            // TemplateState `Arc`.
            let mut enprefix_counter: u16 = 0;
            // Job-id seed monotonically increases per published TemplateState.
            // SV1 derives its 18-char hex job-id from this; SV2 will derive
            // its u32 channel-scoped job-id from the same seed (Phase 4).
            let mut seed: u64 = 0;
            loop {
                tokio::select! {
                    biased;
                    t = t_sub.changed() => { if t.is_err() { return; } }
                    c = c_sub.changed() => { if c.is_err() { return; } }
                }
                let template = match template_ch.current() {
                    Some(t) => t,
                    None => continue,
                };
                let coinbaser = match coinbaser_sub.current() {
                    Some(c) => c,
                    None => continue,
                };
                let enprefix = enprefix_counter ^ 0xB10C;
                enprefix_counter = enprefix_counter.wrapping_add(1);
                // Pool override semantics match C: when ClientConfig has been
                // received, override_mining_coinbase_tag_primary unconditionally
                // wins — even if empty. Only the primary tag is overridable.
                let pool_override = pool_coinbase_tag_rx_for_state.borrow().clone();
                let primary_owned: String = match &pool_override {
                    Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                    None => coinbase_tag_primary.clone(),
                };
                let scriptsig = datum_blocktemplates::ScriptSigInputs {
                    coinbase_tag_primary: primary_owned.as_str(),
                    coinbase_tag_secondary: coinbase_tag_secondary.as_str(),
                    // Config field is u32 for forward-compat; the C reference's
                    // uid push only stores 2 bytes — truncate.
                    coinbase_unique_id: coinbase_unique_id as u16,
                    enprefix,
                    pot_placeholder: 0xFF,
                };
                let state = datum_blocktemplates::TemplateState::from_template_and_blob(
                    &template, &coinbaser, scriptsig, seed,
                );
                seed = seed.wrapping_add(1);
                if template_state_pub_for_task.publish(state).is_err() {
                    return;
                }
            }
        });
    }

    // SV1 notify assembler: subscribe to the shared TemplateState watch and
    // emit `mining.notify` jobs. Phase 4 will mirror this with a parallel SV2
    // assembler that consumes from the same channel and emits
    // `NewExtendedMiningJob` + `SetNewPrevHash` instead.
    {
        let notify_tx_for_assembler = notify_tx.clone();
        let mut state_sub = template_state_ch.clone();
        let jobs_for_assembler = jobs.clone();
        tokio::spawn(async move {
            let mut tick: u32 = 0;
            // Coinbase variant — our SV1 server doesn't multi-coinbase (yet);
            // OCEAN's pool dispatches up to 8 in the C reference. Use 0 for
            // every emitted notify so the relay/upstream side stays consistent.
            const COINBASE_ID: u8 = 0;
            loop {
                let state = match state_sub.changed().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let datum_job_idx = {
                    let mut g = jobs_for_assembler.lock().await;
                    g.next_idx()
                };
                // C job-id format: `%8.8x%2.2x%4.4x` then notify line appends
                // `%2.2x` for cbselect → 18-char hex string. Match this exactly
                // so the relay can recover `coinbase_id` from job_id[14..16]
                // (the offset OCEAN's server expects per C reference).
                let head = format!(
                    "{:08x}{:02x}{:04x}",
                    tick,
                    datum_job_idx,
                    (state.height as u16) ^ 0xC0DE
                );
                let job_id = format!("{head}{COINBASE_ID:02x}");
                let (params, meta) = datum_stratum_sv1::assembler::notify_from_template_state(
                    &job_id,
                    datum_job_idx,
                    COINBASE_ID,
                    &state,
                    true,
                );
                let target_pot_index = meta.target_pot_index;
                let coinb1_bin_for_emit = meta.coinb1_bin.clone();
                {
                    let mut g = jobs_for_assembler.lock().await;
                    g.insert(job_id.clone(), meta);
                }
                let job = datum_stratum_sv1::server::NotifyJob::with_coinb1(
                    params.to_json_array(),
                    target_pot_index,
                    coinb1_bin_for_emit,
                    job_id.clone(),
                );
                if notify_tx_for_assembler.send(Some(job)).is_err() {
                    return;
                }
                tick = tick.wrapping_add(1);
            }
        });
    }
    // Reserve the channel handle for Phase 4 (SV2 consumer). Holding a clone
    // here keeps the watch sender alive even if no consumer subscribes yet.
    let _template_state_ch_reserved_for_sv2 = template_state_ch.clone();

    // Persistent outbound-commands channel for the DATUM upstream task. Lives
    // across reconnects so other tasks (the share-relay below) can keep a stable
    // sender. `run_datum_upstream` drains from this on each successful connect.
    let (commands_tx, commands_rx) =
        tokio::sync::mpsc::channel::<datum_protocol::UpstreamCommand>(64);
    let commands_rx_shared = std::sync::Arc::new(tokio::sync::Mutex::new(commands_rx));

    // Share-relay: pop SubmittedShare from the SV1 submit channel, look up the
    // corresponding JobEntry in the JobTracker, encode the full DATUM `0x27`
    // share-submission body (prefix + username + reserved + 0x01/0x02 first-
    // share-of-job/coinbase blobs + 0xFE cap + padding), and forward.
    let user_cfg = ShareUserConfig {
        pool_address: cfg.mining.pool_address.clone(),
        pass_full_users: cfg.datum.pool_pass_full_users,
        pass_workers: cfg.datum.pool_pass_workers,
    };
    {
        let commands_tx_for_relay = commands_tx.clone();
        let jobs_for_relay = jobs.clone();
        let user_cfg_for_relay = user_cfg.clone();
        let block_submitter_for_relay = block_submitter.clone();
        let runtime_for_relay = runtime.clone();
        tokio::spawn(async move {
            while let Some(share) = submit_rx.recv().await {
                // Per-miner diff is stamped on the SubmittedShare by the SV1
                // server's vardiff loop.
                let current_diff = share.current_diff;
                let encoded = {
                    let mut g = jobs_for_relay.lock().await;
                    let Some(entry) = g.get_mut(&share.job_id) else {
                        tracing::warn!(
                            user = %share.username,
                            job = %share.job_id,
                            "share-relay: no JobEntry for job_id; dropping (likely stale or pre-notify share)"
                        );
                        continue;
                    };
                    match build_share_submission(&share, entry, &user_cfg_for_relay, current_diff) {
                        Ok(enc) => enc,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "share-relay: encode failed; dropping submit"
                            );
                            continue;
                        }
                    }
                };
                let ShareEncoded {
                    body,
                    block_submission,
                } = encoded;
                // Path-1 (bitcoind submitblock) and path-2 (DATUM 0x27 with
                // is_block bit) MUST run as independent tasks per the
                // gateway-internals architecture rule. Spawn submitblock
                // BEFORE forwarding the share so it isn't gated on commands_tx
                // backpressure.
                if let (Some(payload), Some(submitter)) =
                    (block_submission, block_submitter_for_relay.as_ref())
                {
                    runtime_for_relay.record_block_found();
                    let submitter = submitter.clone();
                    let block_hash = payload.block_hash_hex.clone();
                    tracing::warn!(%block_hash, "BLOCK FOUND — submitting to bitcoind");
                    tokio::spawn(async move {
                        match submitter
                            .submit(&payload.block_hex, &payload.block_hash_hex)
                            .await
                        {
                            Ok(()) => tracing::info!(
                                block_hash = %payload.block_hash_hex,
                                "submitblock accepted"
                            ),
                            Err(e) => tracing::error!(
                                error = %e,
                                block_hash = %payload.block_hash_hex,
                                "submitblock failed"
                            ),
                        }
                    });
                }
                if let Err(e) = commands_tx_for_relay
                    .send(datum_protocol::UpstreamCommand::SubmitShare(body))
                    .await
                {
                    tracing::warn!(error = %e, "share-relay: commands_tx send failed");
                    return;
                }
                tracing::info!(
                    user = %share.username,
                    job = %share.job_id,
                    "share forwarded to DATUM upstream"
                );
            }
        });
    }

    // DATUM upstream task. Spawn it lazily; if the connect fails we log and
    // retry on a fixed backoff. The first successful connect publishes a
    // CoinbaserResponse which unblocks the assembler.
    {
        let pool_host = cfg.datum.pool_host.clone();
        let pool_port = cfg.datum.pool_port;
        let pool_pubkey_hex = cfg.datum.pool_pubkey.clone();
        let mining_pool_address = cfg.mining.pool_address.clone();
        let coinbaser_pub = coinbaser_pub;
        let template_ch_for_upstream = template_channel.clone();
        let commands_rx_shared = commands_rx_shared.clone();
        let runtime_for_upstream = runtime.clone();
        let pool_min_diff_tx_for_upstream = pool_min_diff_tx.clone();
        let pool_coinbase_tag_tx_for_upstream = pool_coinbase_tag_tx.clone();
        let jobs_for_upstream = jobs.clone();
        if !pool_host.is_empty() && !pool_pubkey_hex.is_empty() {
            tokio::spawn(async move {
                if let Err(e) = run_datum_upstream(
                    &pool_host,
                    pool_port,
                    &pool_pubkey_hex,
                    &mining_pool_address,
                    coinbaser_pub,
                    template_ch_for_upstream,
                    commands_rx_shared,
                    runtime_for_upstream,
                    pool_min_diff_tx_for_upstream,
                    pool_coinbase_tag_tx_for_upstream,
                    jobs_for_upstream,
                )
                .await
                {
                    tracing::error!(error = %e, "datum upstream task exited with error");
                }
            });
        } else {
            tracing::warn!("datum.pool_host or pool_pubkey empty; DATUM upstream task not spawned");
        }
    }

    runtime.mark_started();
    let metrics: Arc<dyn MetricsSource> = Arc::new(RuntimeMetrics {
        runtime: runtime.clone(),
        cfg_summary: cfg_summary(&cfg),
    });
    let app = datum_api::router(ApiState { metrics });

    if cfg.api.listen_port == 0 {
        tracing::info!("API listen_port=0; HTTP API disabled");
        wait_for_shutdown().await;
        let _ = sv1_shutdown_tx.send(true);
        if let Some(h) = sv1_handle {
            let _ = h.await;
        }
        return;
    }

    let api_addr: SocketAddr = format!("{}:{}", api_addr_or_default(&cfg), cfg.api.listen_port)
        .parse()
        .expect("api listen_addr/listen_port parses");
    tracing::info!(%api_addr, "datum_gateway: HTTP API binding");
    let listener = match tokio::net::TcpListener::bind(api_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%api_addr, error = %e, "API bind failed");
            return;
        }
    };

    let api_shutdown = async {
        wait_for_shutdown().await;
    };

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(api_shutdown)
        .await
    {
        tracing::error!(error = %e, "axum server exited with error");
    }

    let _ = sv1_shutdown_tx.send(true);
    if let Some(h) = sv1_handle {
        let _ = h.await;
    }
    let _ = notify_tx;
}

/// Per-job context tracked by [`JobTracker`]. Wraps [`JobMeta`] with the
/// "send-once-per-(job, coinbase_id)" flags the C reference uses to amortise
/// the bulky 0x01 / 0x02 sub-blocks of the DATUM `0x27` share submission.
#[derive(Debug)]
struct JobEntry {
    meta: JobMeta,
    server_has_merkle_branches: bool,
    server_has_coinbase: [bool; 8],
}

#[derive(Debug, Default)]
struct JobTracker {
    /// Bounded map keyed by the SV1 wire job-id (hex string emitted in
    /// `mining.notify`). The C reference uses an 8-bit ring of 256 slots; we
    /// model the same eviction explicitly via `order` queue.
    by_job_id: HashMap<String, JobEntry>,
    /// Insertion order — oldest entries are evicted when capacity is reached.
    order: std::collections::VecDeque<String>,
    /// 8-bit ring counter for `datum_job_idx`; wraps at 255.
    next_datum_idx: u8,
}

impl JobTracker {
    const MAX: usize = 256;

    fn new() -> Self {
        Self::default()
    }

    fn next_idx(&mut self) -> u8 {
        let v = self.next_datum_idx;
        self.next_datum_idx = self.next_datum_idx.wrapping_add(1);
        v
    }

    fn insert(&mut self, job_id: String, meta: JobMeta) {
        if self.by_job_id.len() >= Self::MAX {
            if let Some(oldest) = self.order.pop_front() {
                self.by_job_id.remove(&oldest);
            }
        }
        self.order.push_back(job_id.clone());
        self.by_job_id.insert(
            job_id,
            JobEntry {
                meta,
                server_has_merkle_branches: false,
                server_has_coinbase: [false; 8],
            },
        );
    }

    fn get_mut(&mut self, job_id: &str) -> Option<&mut JobEntry> {
        self.by_job_id.get_mut(job_id)
    }

    /// Clear every per-(job, coinbase_id) `server_has_*` send-once flag.
    /// Called on DATUM upstream reconnect: the upstream's slot table is
    /// state-on-the-wire, so when we lose+reestablish a connection the pool
    /// has no record of any job we previously announced. The next share we
    /// forward must carry the 0x01 + 0x02 sub-blocks again, otherwise OCEAN
    /// rejects with BAD_JOB_ID (10).
    fn reset_send_once_flags(&mut self) {
        for entry in self.by_job_id.values_mut() {
            entry.server_has_merkle_branches = false;
            entry.server_has_coinbase = [false; 8];
        }
    }
}

async fn wait_for_shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    match ctrl_c.await {
        Ok(()) => tracing::info!("SIGINT/Ctrl-C received; shutting down"),
        Err(e) => tracing::warn!(error = %e, "ctrl_c handler failed"),
    }
}

/// Drive the DATUM upstream connection. On connect, push the OCEAN-supplied
/// coinbaser blob to `coinbaser_pub` so the assembler can build notifies.
/// Reconnects on disconnect with a fixed backoff.
#[allow(clippy::too_many_arguments)]
async fn run_datum_upstream(
    pool_host: &str,
    pool_port: u16,
    pool_pubkey_hex: &str,
    _mining_pool_address: &str,
    coinbaser_pub: datum_coinbaser::CoinbaserPublisher,
    template_channel: Option<datum_blocktemplates::TemplateChannel>,
    external_commands_rx: std::sync::Arc<
        tokio::sync::Mutex<tokio::sync::mpsc::Receiver<datum_protocol::UpstreamCommand>>,
    >,
    runtime: Arc<RuntimeStats>,
    pool_min_diff_tx: tokio::sync::watch::Sender<u64>,
    pool_coinbase_tag_tx: tokio::sync::watch::Sender<Option<Vec<u8>>>,
    jobs: Arc<Mutex<JobTracker>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pool_pubkey =
        hex::decode(pool_pubkey_hex).map_err(|e| format!("decode pool pubkey hex: {e}"))?;
    if pool_pubkey.len() != 64 {
        return Err(format!(
            "pool pubkey must be 64 bytes (128 hex chars); got {}",
            pool_pubkey.len()
        )
        .into());
    }
    let pool_x25519: [u8; 32] = pool_pubkey[32..].try_into().unwrap();

    let endpoint = format!("{pool_host}:{pool_port}");
    let backoff = std::time::Duration::from_secs(5);

    loop {
        tracing::info!(%endpoint, "DATUM upstream: connecting");
        match datum_protocol::DatumClient::connect(
            &endpoint,
            &pool_x25519,
            "v0.4.1-beta",
            "/datum-rs runtime",
            std::time::Duration::from_secs(30),
        )
        .await
        {
            Ok(connected) => {
                tracing::info!(motd = %connected.motd, "DATUM handshake complete");

                // The pool's slot table resets when the TCP connection drops.
                // Clear every per-(job, coinbase_id) send-once flag so the
                // first share on each tracked job re-includes the 0x01 + 0x02
                // sub-blocks. Without this, every post-reconnect share lands
                // as DATUM_REJECT_BAD_JOB_ID (10).
                {
                    let mut g = jobs.lock().await;
                    g.reset_send_once_flags();
                }

                let connected = std::sync::Arc::new(connected);
                let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(64);
                let (commands_tx, commands_rx) = tokio::sync::mpsc::channel(64);

                // Bridge external commands (e.g. share submissions from the
                // SV1 server's submit handler) into this per-connection
                // commands channel. The bridge ends when this connection is
                // torn down so the next reconnect starts fresh.
                let bridge_tx = commands_tx.clone();
                let bridge_rx = external_commands_rx.clone();
                let bridge = tokio::spawn(async move {
                    let mut guard = bridge_rx.lock().await;
                    while let Some(cmd) = guard.recv().await {
                        if bridge_tx.send(cmd).await.is_err() {
                            return;
                        }
                    }
                });

                let coinbaser_pub = coinbaser_pub.clone();
                let event_loop = {
                    let conn = connected.clone();
                    tokio::spawn(async move { conn.run(events_tx, commands_rx).await })
                };

                // Per datum_protocol.c, the coinbaser fetch should be issued
                // AFTER ClientConfig arrives (state 3). It also needs the
                // current template's prevhash + coinbase_value. We track
                // both and fire when both are ready.
                let mut client_config_seen = false;
                let mut coinbaser_requested = false;

                // If the template arrives before ClientConfig (or vice versa)
                // we need a way to retry on the OTHER signal arriving. Watch
                // the template channel in a side task; nudge `commands_tx`
                // with a Raw passthrough that we ignore in the main loop just
                // to wake the select. Actually simpler: poll inside the main
                // loop alongside events.
                let mut template_sub = template_channel.clone();

                loop {
                    let event = tokio::select! {
                        e = events_rx.recv() => match e {
                            Some(ev) => ev,
                            None => break,
                        },
                        changed = async {
                            if let Some(s) = &mut template_sub {
                                s.changed().await.map(|_| ())
                            } else {
                                std::future::pending::<Result<(), _>>().await
                            }
                        } => {
                            if changed.is_err() {
                                continue;
                            }
                            if client_config_seen && !coinbaser_requested {
                                maybe_request_coinbaser(&commands_tx, &template_channel, true).await;
                                coinbaser_requested = true;
                            }
                            continue;
                        }
                    };
                    match event {
                        datum_protocol::UpstreamEvent::Coinbaser(resp) => {
                            tracing::info!(
                                value = resp.coinbase_value,
                                blob_len = resp.v2_blob.len(),
                                "coinbaser response received"
                            );
                            match datum_coinbaser::parse_v2_blob(&resp.v2_blob, resp.coinbase_value)
                            {
                                Ok(blob) => {
                                    if coinbaser_pub.publish(blob).is_err() {
                                        tracing::warn!("coinbaser_pub: no subscribers");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "failed to parse v2 blob");
                                }
                            }
                        }
                        datum_protocol::UpstreamEvent::ClientConfig(cfg) => {
                            tracing::info!(
                                prime_id = cfg.prime_id,
                                vardiff_min = cfg.vardiff_min,
                                pool_coinbase_tag_len = cfg.pool_coinbase_tag.len(),
                                "client_config received from pool"
                            );
                            // Publish the pool's vardiff floor so per-miner
                            // vardiff loops never drop below it. Without this
                            // every share rejects as DATUM_REJECT_BAD_TARGET.
                            let _ = pool_min_diff_tx.send(cfg.vardiff_min);
                            // Publish the pool's primary-tag override. Cap at
                            // 86 bytes (MAX_COINBASE_TAG_SPACE in C) so a
                            // misbehaving pool can't overflow the scriptsig
                            // budget. Always Some — empty pool tag is a
                            // legitimate override (matches C semantics).
                            let mut tag_bytes = cfg.pool_coinbase_tag.clone();
                            tag_bytes.truncate(86);
                            let _ = pool_coinbase_tag_tx.send(Some(tag_bytes));
                            client_config_seen = true;
                            if !coinbaser_requested {
                                maybe_request_coinbaser(
                                    &commands_tx,
                                    &template_channel,
                                    client_config_seen,
                                )
                                .await;
                                if template_channel
                                    .as_ref()
                                    .and_then(|ch| ch.current())
                                    .is_some()
                                {
                                    coinbaser_requested = true;
                                }
                            }
                        }
                        datum_protocol::UpstreamEvent::ShareResponse(resp) => {
                            // Pool-side correlation only — the wire ShareResponse
                            // carries no username/request-id, so we cannot route
                            // back to the originating SV1 miner here. Counters
                            // are lifetime totals across reconnects.
                            match resp.status {
                                datum_protocol::ShareStatus::Accepted
                                | datum_protocol::ShareStatus::AcceptedTentatively => {
                                    runtime.record_share_accepted();
                                    tracing::info!(
                                        target: "datum_bin::shares",
                                        status = ?resp.status,
                                        nonce = format!("{:08x}", resp.nonce),
                                        target_pot = resp.target_pot,
                                        job_id = resp.job_id,
                                        "pool accepted share"
                                    );
                                }
                                datum_protocol::ShareStatus::Rejected => {
                                    runtime.record_share_rejected();
                                    tracing::info!(
                                        target: "datum_bin::shares",
                                        reject_reason = resp.reject_reason,
                                        nonce = format!("{:08x}", resp.nonce),
                                        target_pot = resp.target_pot,
                                        job_id = resp.job_id,
                                        "pool rejected share"
                                    );
                                }
                            }
                        }
                        datum_protocol::UpstreamEvent::BlockNotify(_) => {
                            tracing::info!("block_notify from pool");
                        }
                        datum_protocol::UpstreamEvent::JobValidationRequest(body) => {
                            tracing::info!(
                                body_len = body.len(),
                                first_bytes = %hex::encode(&body[..body.len().min(16)]),
                                "job validation request from pool (not yet handled)"
                            );
                        }
                        datum_protocol::UpstreamEvent::UnknownFrame { proto_cmd, body } => {
                            tracing::info!(
                                proto_cmd = format!("{proto_cmd:#04x}"),
                                body_len = body.len(),
                                first_bytes = %hex::encode(&body[..body.len().min(32)]),
                                "unknown frame from pool"
                            );
                        }
                    }
                }
                event_loop.abort();
                bridge.abort();
                // Reset pool overrides on disconnect — the C state machine
                // drops `datum_state` below 3 on any error, after which
                // override_mining_coinbase_tag_primary is no longer consulted.
                let _ = pool_coinbase_tag_tx.send(None);
                tracing::warn!("DATUM event stream closed");
            }
            Err(e) => {
                tracing::error!(error = %e, "DATUM upstream connect failed");
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

/// Configuration knobs the share-relay needs to format the username field of a
/// DATUM `0x27` share submission.
#[derive(Debug, Clone)]
struct ShareUserConfig {
    pool_address: String,
    pass_full_users: bool,
    pass_workers: bool,
}

/// Format the share's username field per `datum_protocol.c:1340-1351`. Three
/// behaviors: both flags false OR no miner username uses the configured pool
/// address; `pass_full_users` with a miner username that doesn't start with
/// `.` uses the miner username verbatim; otherwise the result is
/// `pool_address` joined with the miner username (with a `.` separator unless
/// the miner already prefixed one). Cap at 384 bytes (matches the C
/// `username[385]` buffer minus null).
fn format_share_username(miner_user: &str, cfg: &ShareUserConfig) -> Vec<u8> {
    let s = if (!cfg.pass_full_users && !cfg.pass_workers) || miner_user.is_empty() {
        cfg.pool_address.clone()
    } else if cfg.pass_full_users && !miner_user.starts_with('.') {
        miner_user.to_string()
    } else if cfg.pass_full_users || cfg.pass_workers {
        let sep = if miner_user.starts_with('.') { "" } else { "." };
        format!("{}{}{}", cfg.pool_address, sep, miner_user)
    } else {
        cfg.pool_address.clone()
    };
    let mut out = s.into_bytes();
    out.truncate(384);
    out
}

/// `floorPoT(x)`: position of the highest set bit; 0 for x=0. Mirrors
/// `datum_utils.c::floorPoT`.
fn floor_pot(x: u64) -> u8 {
    if x == 0 {
        0
    } else {
        (63 - x.leading_zeros()) as u8
    }
}

/// Bitcoin double-SHA256: `sha256(sha256(x))` — both passes return 32 bytes.
fn double_sha256(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(input);
    Sha256::digest(first).into()
}

/// Walk the merkle tree from the coinbase outward. `coinb1_patched` MUST be
/// the bytes the miner actually hashed (PoT byte already applied);
/// `extranonce` is the 12-byte xn1||xn2 the miner concatenated. Branches in
/// `branches` are stored in BIG-ENDIAN display order (matching what the SV1
/// wire frame emits — see `assembler.rs::build_merkle_branch`); we reverse
/// each one to internal byte order before concatenating, mirroring what the
/// miner does. Returns the merkle root in INTERNAL byte order, ready to drop
/// into header bytes 36..68 unchanged.
fn compute_merkle_root(
    coinb1_patched: &[u8],
    extranonce: &[u8; 12],
    coinb2: &[u8],
    branches: &[[u8; 32]],
) -> [u8; 32] {
    let mut full_cb = Vec::with_capacity(coinb1_patched.len() + 12 + coinb2.len());
    full_cb.extend_from_slice(coinb1_patched);
    full_cb.extend_from_slice(extranonce);
    full_cb.extend_from_slice(coinb2);
    let mut acc = double_sha256(&full_cb);
    let mut buf = [0u8; 64];
    for sib in branches {
        let mut sib_le = *sib;
        sib_le.reverse(); // wire BE display -> internal LE
        buf[..32].copy_from_slice(&acc);
        buf[32..].copy_from_slice(&sib_le);
        acc = double_sha256(&buf);
    }
    acc
}

/// Compare a candidate hash against a target, both in internal-LE byte order.
/// Mirrors `datum_utils.c::compare_hashes`: walk from MSB (index 31) down,
/// returning true iff `hash <= target`. A win means the hash is at-or-below
/// the network target (i.e. a valid block).
fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        match hash[i].cmp(&target[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

/// Push a Bitcoin varint as hex characters onto `out`. Mirrors
/// `assembler.rs::push_varint`'s byte form, hex-encoded inline.
fn push_varint_hex(out: &mut String, v: u64) {
    if v < 0xfd {
        out.push_str(&format!("{:02x}", v as u8));
    } else if v <= 0xffff {
        out.push_str("fd");
        out.push_str(&format!("{:02x}{:02x}", v as u8, (v >> 8) as u8));
    } else if v <= 0xffff_ffff {
        out.push_str("fe");
        out.push_str(&hex::encode((v as u32).to_le_bytes()));
    } else {
        out.push_str("ff");
        out.push_str(&hex::encode(v.to_le_bytes()));
    }
}

/// Block-found context returned alongside the encoded share body when a share
/// hash meets the network target. Caller is responsible for spawning the
/// `BlockSubmitter::submit` task — path-1 (bitcoind submitblock) MUST run
/// independently of path-2 (DATUM 0x27) per the architecture rule.
#[derive(Debug, Clone)]
struct BlockSubmissionPayload {
    /// Full block hex: 80-byte header + varint(tx_count + 1) + full coinbase
    /// + each `template.transactions[*].data` hex appended verbatim.
    block_hex: String,
    /// Block hash in big-endian display order — what bitcoind expects for
    /// `preciousblock`.
    block_hash_hex: String,
}

/// Encoded share output: the wire body for the DATUM 0x27 frame, plus an
/// optional block-submission payload when the share's header hash meets the
/// network target.
#[derive(Debug)]
struct ShareEncoded {
    body: Vec<u8>,
    block_submission: Option<BlockSubmissionPayload>,
}

/// Encode a `mining.submit` payload into a complete DATUM `0x27` share
/// submission body, matching `datum_protocol.c::datum_protocol_pow:1313-1438`.
///
/// Layout: fixed 30-byte prefix, null-terminated username, 4 reserved zero
/// bytes, optional 0x01 first-share-of-job block (prevhash, target byte index,
/// nbits, datum_coinbaser_id, height, coinbase_value, four tx counts, and the
/// merkle-branch table), optional 0x02 first-share-of-coinbase block
/// (coinb1_len, coinb2_len, coinb1_bin, coinb2_bin), 0xFE cap, random padding
/// of 1 to 80 bytes.
///
/// The 0x01 / 0x02 sub-blocks are sent ONCE per (job, coinbase_id); the
/// `entry` flags track that. The runtime is responsible for never resetting
/// these flags after a successful submit.
fn build_share_submission(
    share: &datum_stratum_sv1::server::SubmittedShare,
    entry: &mut JobEntry,
    user_cfg: &ShareUserConfig,
    current_diff: u64,
) -> Result<ShareEncoded, String> {
    let ntime = parse_u32_be_hex(&share.ntime_hex).ok_or("invalid ntime hex")?;
    let nonce = parse_u32_be_hex(&share.nonce_hex).ok_or("invalid nonce hex")?;
    // BIP-310: the miner's nversion has been masked by the SV1 server against
    // the negotiated mask before reaching us, so a plain OR is safe (mirrors
    // `bver |= vroll_uint;` at datum_stratum.c:1068).
    let mut version: u32 = entry.meta.version;
    version |= share.version_rolling;

    let extranonce2 = hex::decode(&share.extranonce2_hex).map_err(|e| e.to_string())?;
    let mut extranonce = [0u8; 12];
    extranonce[..4].copy_from_slice(&share.extranonce1);
    let take = extranonce2.len().min(8);
    extranonce[4..4 + take].copy_from_slice(&extranonce2[..take]);

    // PoT target byte tied to the diff active at the LAST notify emit for
    // this job_id (carried forward from the SV1 server's emit-time snapshot).
    let target_byte = floor_pot(current_diff);

    // Block-found check. Reconstruct the patched coinbase, double-SHA the
    // 80-byte header, compare hash against the network target. Use the SAME
    // patched coinb1 the miner hashed — sourced from the share's emit
    // snapshot (or rebuild if absent for compatibility, though the relay
    // should drop None upstream of this call).
    let coinb1_patched = match share.patched_coinb1_bin.as_deref() {
        Some(b) => b.to_vec(),
        None => {
            let mut b = entry.meta.coinb1_bin.clone();
            let pot_index = entry.meta.target_pot_index as usize;
            if pot_index < b.len() {
                b[pot_index] = target_byte;
            }
            b
        }
    };
    let merkle_root = compute_merkle_root(
        &coinb1_patched,
        &extranonce,
        &entry.meta.coinb2_bin,
        &entry.meta.merkle_branches_bin,
    );
    // Build 80-byte header in canonical Bitcoin layout (LE for version /
    // ntime / nbits / nonce; internal-order for prevhash / merkle_root).
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&version.to_le_bytes());
    header[4..36].copy_from_slice(&entry.meta.prevhash_bin);
    header[36..68].copy_from_slice(&merkle_root);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    // meta.nbits_bin is BIG-ENDIAN display bytes; header offset 72..76 wants
    // little-endian. Reverse on write.
    let mut nbits_le = entry.meta.nbits_bin;
    nbits_le.reverse();
    header[72..76].copy_from_slice(&nbits_le);
    header[76..80].copy_from_slice(&nonce.to_le_bytes());
    let share_hash = double_sha256(&header);
    let is_block = hash_meets_target(&share_hash, &entry.meta.block_target);
    // Flags: bit0=is_block, bit1=subsidy_only, bit2=quickdiff. We don't run
    // subsidy_only or quickdiff today.
    const FLAG_IS_BLOCK: u8 = 0x01;
    let flags: u8 = if is_block { FLAG_IS_BLOCK } else { 0 };

    let prefix = datum_protocol::ShareSubmissionPrefix {
        job_id: entry.meta.datum_job_idx,
        coinbase_id: entry.meta.coinbase_id,
        flags,
        target_byte,
        ntime,
        nonce,
        version,
        extranonce,
    };
    let mut body = prefix.encode();

    // Username (null-terminated). C uses snprintf which always writes a NUL.
    let user_bytes = format_share_username(&share.username, user_cfg);
    body.extend_from_slice(&user_bytes);
    body.push(0);

    // 4 reserved bytes (zero) for future use.
    body.extend_from_slice(&[0u8; 4]);

    // 0x01 sub-block: prevhash + nbits + height + coinbase_value + tx counts
    // + merkle branches. Sent once per job until server has it.
    if !entry.server_has_merkle_branches {
        body.push(0x01);
        body.extend_from_slice(&entry.meta.prevhash_bin);
        body.extend_from_slice(&entry.meta.target_pot_index.to_le_bytes());
        // C ships sjob->nbits_bin verbatim and that buffer is the RPC hex
        // reversed (datum_blocktemplates.c:252 `bits_bin[3-i] = hex2bin_uchar(...)`)
        // = internal LE. Our JobMeta stores BE display order, so reverse.
        let mut nbits_le = entry.meta.nbits_bin;
        nbits_le.reverse();
        body.extend_from_slice(&nbits_le);
        body.push(entry.meta.datum_coinbaser_id);
        body.extend_from_slice(&entry.meta.height.to_le_bytes());
        body.extend_from_slice(&entry.meta.coinbase_value.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_count.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_total_weight.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_total_size.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_total_sigops.to_le_bytes());
        body.push(entry.meta.merkle_branches_bin.len() as u8);
        // C ships merklebranches_bin in INTERNAL byte order: txid_bin is built
        // via hex_to_bin_le (RPC hex reversed) and higher levels are raw
        // double_sha256 outputs (already internal). Our JobMeta stores them in
        // BE display order to match the SV1 wire frame, so reverse here.
        for branch in &entry.meta.merkle_branches_bin {
            let mut le = *branch;
            le.reverse();
            body.extend_from_slice(&le);
        }
        entry.server_has_merkle_branches = true;
    }

    // 0x02 sub-block: full coinb1/coinb2 binaries. Sent once per (job,
    // coinbase_id) until server has it.
    //
    // C ships sjob->coinbase[id].coinb1_bin verbatim — the TEMPLATE-ORIGINAL
    // coinb1 with the 0xFF PoT placeholder still in place at target_pot_index
    // (datum_protocol.c:1417, datum_coinbaser.c:165/171). The server applies
    // floorPoT(diff) at target_pot_index itself when reconstructing the
    // miner's hash; sending a pre-patched coinb1 desyncs that.
    let cb_id = entry.meta.coinbase_id as usize;
    let already_sent_coinbase =
        cb_id < entry.server_has_coinbase.len() && entry.server_has_coinbase[cb_id];
    if !already_sent_coinbase {
        body.push(0x02);
        body.push(entry.meta.coinbase_id);
        let cb1_len = entry.meta.coinb1_bin.len() as u16;
        let cb2_len = entry.meta.coinb2_bin.len() as u16;
        body.extend_from_slice(&cb1_len.to_le_bytes());
        body.extend_from_slice(&cb2_len.to_le_bytes());
        body.extend_from_slice(&entry.meta.coinb1_bin);
        body.extend_from_slice(&entry.meta.coinb2_bin);
        if cb_id < entry.server_has_coinbase.len() {
            entry.server_has_coinbase[cb_id] = true;
        }
    }

    // Cap byte.
    body.push(0xFE);

    // Random padding 1-80 bytes (matches C's `1 + (rand() % 80)` plus repeat
    // of a single random byte). Use a counter-derived "random" since the C
    // path also doesn't seed from CSPRNG — this is purely traffic-shape
    // obfuscation and doesn't need cryptographic strength.
    let rb = padding_byte();
    let pad_len = 1 + (rb as usize % 80);
    body.extend(std::iter::repeat_n(rb, pad_len));

    let block_submission = if is_block {
        let mut hash_be = share_hash;
        hash_be.reverse();
        let block_hash_hex = hex::encode(hash_be);

        let mut full_cb =
            Vec::with_capacity(coinb1_patched.len() + 12 + entry.meta.coinb2_bin.len());
        full_cb.extend_from_slice(&coinb1_patched);
        full_cb.extend_from_slice(&extranonce);
        full_cb.extend_from_slice(&entry.meta.coinb2_bin);

        // Block hex: header + varint(tx_count + 1) + coinbase + each tx.data.
        let txn_count = entry.meta.txn_count as u64;
        let mut block_hex = String::with_capacity(160 + full_cb.len() * 2 + 200_000);
        block_hex.push_str(&hex::encode(header));
        push_varint_hex(&mut block_hex, txn_count + 1);
        block_hex.push_str(&hex::encode(&full_cb));
        for tx_hex in entry.meta.txn_data_hex.iter() {
            block_hex.push_str(tx_hex);
        }
        Some(BlockSubmissionPayload {
            block_hex,
            block_hash_hex,
        })
    } else {
        None
    };

    Ok(ShareEncoded {
        body,
        block_submission,
    })
}

fn parse_u32_be_hex(s: &str) -> Option<u32> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(trimmed, 16).ok()
}

fn padding_byte() -> u8 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let mut x = STATE.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    STATE.store(x, Ordering::Relaxed);
    (x & 0xFF) as u8
}

async fn maybe_request_coinbaser(
    commands_tx: &tokio::sync::mpsc::Sender<datum_protocol::UpstreamCommand>,
    template_channel: &Option<datum_blocktemplates::TemplateChannel>,
    client_config_seen: bool,
) {
    if !client_config_seen {
        return;
    }
    let Some(template_ch) = template_channel else {
        tracing::warn!("client_config received but no template channel; skipping coinbaser fetch");
        return;
    };
    let Some(template) = template_ch.current() else {
        tracing::info!("client_config received; awaiting first template before coinbaser fetch");
        return;
    };
    let Ok(prevhash_be) = hex::decode(&template.previous_block_hash) else {
        tracing::warn!("template previous_block_hash not valid hex");
        return;
    };
    if prevhash_be.len() != 32 {
        tracing::warn!(len = prevhash_be.len(), "template prevhash not 32 bytes");
        return;
    }
    // C source uses prevhash_bin (LE internal byte order). GBT returns the
    // big-endian display hex; reverse to get internal.
    let mut prevhash_bin = [0u8; 32];
    for (i, b) in prevhash_be.iter().rev().enumerate() {
        prevhash_bin[i] = *b;
    }
    let cmd = datum_protocol::UpstreamCommand::RequestCoinbaser {
        coinbase_value: template.coinbase_value,
        prevhash_bin,
    };
    if let Err(e) = commands_tx.send(cmd).await {
        tracing::warn!(error = %e, "failed to enqueue coinbaser request");
    } else {
        tracing::info!(
            value = template.coinbase_value,
            "coinbaser request enqueued"
        );
    }
}

fn api_addr_or_default(cfg: &Config) -> &str {
    if cfg.api.listen_addr.is_empty() {
        "0.0.0.0"
    } else {
        &cfg.api.listen_addr
    }
}

fn stratum_addr_or_default(cfg: &Config) -> &str {
    if cfg.stratum.listen_addr.is_empty() {
        "0.0.0.0"
    } else {
        &cfg.stratum.listen_addr
    }
}

fn cfg_summary(cfg: &Config) -> Value {
    json!({
        "stratum_listen_port": cfg.stratum.listen_port,
        "stratum_v2_enabled": cfg.stratum_v2.enabled,
        "stratum_v2_listen_port": cfg.stratum_v2.listen_port,
        "api_listen_port": cfg.api.listen_port,
        "datum_pool_host": cfg.datum.pool_host,
        "datum_pool_port": cfg.datum.pool_port,
    })
}

#[derive(Default)]
struct RuntimeStats {
    started: parking_lot::RwLock<bool>,
    rpc_url: parking_lot::RwLock<String>,
    sv2_registry: parking_lot::RwLock<Option<Arc<datum_stratum_sv2::ChannelRegistry>>>,
    // Lifetime totals — survive across upstream reconnects on purpose; OCEAN's
    // dashboard frames the same way. Process-restart resets are expected.
    shares_accepted: AtomicU64,
    shares_rejected: AtomicU64,
    /// Local block-found candidates (count of times the share-hash met the
    /// network target and we attempted submitblock). Independent from
    /// `shares_accepted` / `shares_rejected` which track upstream pool acks.
    blocks_found: AtomicU64,
}

impl RuntimeStats {
    fn new() -> Self {
        Self::default()
    }

    fn mark_started(&self) {
        *self.started.write() = true;
    }

    fn set_rpc_url(&self, url: String) {
        *self.rpc_url.write() = url;
    }

    fn set_sv2_registry(&self, reg: Arc<datum_stratum_sv2::ChannelRegistry>) {
        *self.sv2_registry.write() = Some(reg);
    }

    fn record_share_accepted(&self) {
        self.shares_accepted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_share_rejected(&self) {
        self.shares_rejected.fetch_add(1, Ordering::Relaxed);
    }

    fn record_block_found(&self) {
        self.blocks_found.fetch_add(1, Ordering::Relaxed);
    }

    fn shares_accepted(&self) -> u64 {
        self.shares_accepted.load(Ordering::Relaxed)
    }

    fn shares_rejected(&self) -> u64 {
        self.shares_rejected.load(Ordering::Relaxed)
    }

    fn blocks_found(&self) -> u64 {
        self.blocks_found.load(Ordering::Relaxed)
    }
}

struct RuntimeMetrics {
    runtime: Arc<RuntimeStats>,
    cfg_summary: Value,
}

impl MetricsSource for RuntimeMetrics {
    fn snapshot(&self) -> Value {
        json!({
            "version": PKG_VERSION,
            "started": *self.runtime.started.read(),
            "rpc_url": *self.runtime.rpc_url.read(),
            "shares_accepted": self.runtime.shares_accepted(),
            "shares_rejected": self.runtime.shares_rejected(),
            "blocks_found": self.runtime.blocks_found(),
            "config": &self.cfg_summary,
            "note": "alpha — sv1 listener bound, sv2 registry online, protocol/template runtimes pending wiring"
        })
    }
}

#[cfg(unix)]
fn spawn_signal_handlers() {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async {
        let mut sig = match signal(SignalKind::user_defined1()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGUSR1 handler");
                return;
            }
        };
        while sig.recv().await.is_some() {
            tracing::info!(
                "SIGUSR1 received; would force GBT refresh (template puller hookup pending)"
            );
        }
    });
    tokio::spawn(async {
        let mut sig = match signal(SignalKind::pipe()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGPIPE handler");
                return;
            }
        };
        while sig.recv().await.is_some() {
            tracing::trace!("SIGPIPE ignored");
        }
    });
}

#[cfg(not(unix))]
fn spawn_signal_handlers() {
    tracing::debug!("non-unix target; skipping SIGUSR1/SIGPIPE handlers");
}

#[derive(Debug)]
enum Cmd {
    Help,
    Version,
    ExampleConf,
    ValidateConfig(PathBuf),
    Run { config: PathBuf },
    ParseError(String),
}

fn parse_args(args: &[String]) -> Cmd {
    let mut config: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "-?" | "--help" => return Cmd::Help,
            "-V" | "--version" => return Cmd::Version,
            "--example-conf" => return Cmd::ExampleConf,
            "--validate-config" => match iter.next() {
                Some(p) => return Cmd::ValidateConfig(PathBuf::from(p)),
                None => return Cmd::ParseError("--validate-config requires a path".into()),
            },
            "-c" | "--config" => match iter.next() {
                Some(p) => config = Some(PathBuf::from(p)),
                None => return Cmd::ParseError(format!("{arg} requires a path")),
            },
            arg if arg.starts_with("--config=") => {
                config = Some(PathBuf::from(&arg["--config=".len()..]));
            }
            other => return Cmd::ParseError(format!("unknown argument: {other}")),
        }
    }
    Cmd::Run {
        config: config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
    }
}

fn validate_config(path: &PathBuf) -> Result<(), String> {
    let cfg = Config::from_file(path).map_err(|e| match e {
        ConfigError::Read { path, source } => {
            format!("error: cannot read {}: {source}", path.display())
        }
        ConfigError::Parse(source) => format!("error: invalid JSON: {source}"),
        ConfigError::Invalid(_) => unreachable!("from_file does not run validation"),
    })?;
    cfg.validate().map_err(|errs| {
        let mut out = format!(
            "error: {} validation issue(s) in {}:\n",
            errs.len(),
            path.display()
        );
        for e in errs {
            out.push_str("  - ");
            out.push_str(&e.to_string());
            out.push('\n');
        }
        out
    })
}

fn print_help() {
    println!(
        "datum_gateway {PKG_VERSION} — drop-in Rust port of OCEAN-xyz/datum_gateway\n\
\n\
USAGE:\n\
    datum_gateway [-c PATH | --config PATH]\n\
    datum_gateway --validate-config PATH\n\
    datum_gateway --example-conf\n\
    datum_gateway --version | -V\n\
    datum_gateway --help | -h | -?\n\
\n\
DEFAULT CONFIG PATH: {DEFAULT_CONFIG_PATH}\n\
\n\
This is alpha software. Today --version, --validate-config, --example-conf,\n\
and the HTTP API skeleton at api.listen_port work end-to-end. Stratum SV1/SV2\n\
servers and the encrypted DATUM upstream client are scaffolded but not yet\n\
wired into the run loop — block submission against live OCEAN is not\n\
operational. See the v0.1.0 release notes for the runtime checklist.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_stats_counters_start_zero_and_increment() {
        let s = RuntimeStats::new();
        assert_eq!(s.shares_accepted(), 0);
        assert_eq!(s.shares_rejected(), 0);
        s.record_share_accepted();
        s.record_share_accepted();
        s.record_share_rejected();
        assert_eq!(s.shares_accepted(), 2);
        assert_eq!(s.shares_rejected(), 1);
    }

    #[test]
    fn runtime_metrics_snapshot_exposes_share_counters() {
        let runtime = Arc::new(RuntimeStats::new());
        runtime.record_share_accepted();
        runtime.record_share_rejected();
        runtime.record_share_rejected();
        runtime.record_block_found();
        let m = RuntimeMetrics {
            runtime: runtime.clone(),
            cfg_summary: serde_json::json!({}),
        };
        let snap = m.snapshot();
        assert_eq!(snap["shares_accepted"], 1);
        assert_eq!(snap["shares_rejected"], 2);
        assert_eq!(snap["blocks_found"], 1);
    }

    #[test]
    fn double_sha256_known_vector() {
        // Bitcoin genesis block coinbase tx hash — well-known test vector.
        // Empty input double-sha256 ends in d2 1b cf bd ef cf b1 fb (known
        // first bytes of `sha256(sha256("")))`).
        let h = double_sha256(b"");
        // Hex of sha256d("") = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        assert_eq!(
            hex::encode(h),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn hash_meets_target_walks_msb_down() {
        // MSB byte controls the comparison.
        let mut hash = [0u8; 32];
        let mut target = [0u8; 32];
        // hash MSB < target MSB → meets.
        hash[31] = 0x10;
        target[31] = 0x20;
        assert!(hash_meets_target(&hash, &target));
        // hash MSB > target MSB → fails.
        hash[31] = 0x30;
        assert!(!hash_meets_target(&hash, &target));
        // Equal MSB but lower byte decides → meets.
        hash[31] = 0x20;
        hash[30] = 0x05;
        target[30] = 0x10;
        assert!(hash_meets_target(&hash, &target));
        // Equal everywhere → meets (boundary).
        let z = [0u8; 32];
        assert!(hash_meets_target(&z, &z));
    }

    #[test]
    fn compute_merkle_root_no_branches_is_double_sha_of_full_cb() {
        let coinb1 = vec![0xaa; 30];
        let xn = [0xbbu8; 12];
        let coinb2 = vec![0xccu8; 20];
        let mut full = Vec::new();
        full.extend_from_slice(&coinb1);
        full.extend_from_slice(&xn);
        full.extend_from_slice(&coinb2);
        let expected = double_sha256(&full);
        let got = compute_merkle_root(&coinb1, &xn, &coinb2, &[]);
        assert_eq!(got, expected);
    }

    #[test]
    fn push_varint_hex_thresholds() {
        let mut s = String::new();
        push_varint_hex(&mut s, 0);
        assert_eq!(s, "00");
        s.clear();
        push_varint_hex(&mut s, 0xfc);
        assert_eq!(s, "fc");
        s.clear();
        push_varint_hex(&mut s, 0xfd);
        assert_eq!(s, "fdfd00");
        s.clear();
        push_varint_hex(&mut s, 0xffff);
        assert_eq!(s, "fdffff");
        s.clear();
        push_varint_hex(&mut s, 0x10000);
        assert_eq!(s, "fe00000100");
    }

    fn synthetic_job_entry(target: [u8; 32]) -> JobEntry {
        JobEntry {
            meta: JobMeta {
                datum_job_idx: 0,
                coinbase_id: 0,
                target_pot_index: 0,
                version: 0x20000000,
                height: 1,
                coinbase_value: 5_000_000_000,
                prevhash_bin: [0u8; 32],
                nbits_bin: [0x20, 0x7f, 0xff, 0xff], // BE display "207fffff"
                merkle_branches_bin: vec![],
                coinb1_bin: vec![0u8; 50],
                coinb2_bin: vec![0u8; 10],
                datum_coinbaser_id: 0,
                txn_count: 0,
                txn_total_weight: 0,
                txn_total_size: 0,
                txn_total_sigops: 0,
                block_target: target,
                txn_data_hex: std::sync::Arc::new(vec![]),
            },
            server_has_merkle_branches: false,
            server_has_coinbase: [false; 8],
        }
    }

    fn synthetic_share() -> datum_stratum_sv1::server::SubmittedShare {
        datum_stratum_sv1::server::SubmittedShare {
            username: "bc1q".into(),
            job_id: "job-1".into(),
            extranonce2_hex: "0000000000000000".into(),
            ntime_hex: "00000000".into(),
            nonce_hex: "00000000".into(),
            extranonce1: [0u8; 4],
            version_rolling: 0,
            current_diff: 1,
            patched_coinb1_bin: Some(vec![0u8; 50]),
        }
    }

    #[test]
    fn block_found_when_target_is_max() {
        // target = all 0xFF means every share-hash <= target → is_block.
        let mut entry = synthetic_job_entry([0xFFu8; 32]);
        let share = synthetic_share();
        let user = ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let enc = build_share_submission(&share, &mut entry, &user, 1).unwrap();
        assert!(enc.block_submission.is_some(), "should detect block");
        let payload = enc.block_submission.unwrap();
        // 80-byte header = 160 hex chars at the front of block_hex.
        assert!(payload.block_hex.len() >= 160);
        // Hash hex is 64 chars (32 bytes display).
        assert_eq!(payload.block_hash_hex.len(), 64);
        // Body must encode the is_block flag bit.
        // Prefix layout: see ShareSubmissionPrefix; flags is one byte. We
        // don't reproduce the exact offset here — round-trip test covers it
        // upstream. Just assert non-empty body.
        assert!(!enc.body.is_empty());
    }

    #[test]
    fn no_block_when_target_is_zero() {
        // target = all zero means NO share-hash can meet it.
        let mut entry = synthetic_job_entry([0u8; 32]);
        let share = synthetic_share();
        let user = ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let enc = build_share_submission(&share, &mut entry, &user, 1).unwrap();
        assert!(enc.block_submission.is_none());
    }

    /// Byte-fidelity gate. Pins the EXACT 0x27 body bytes for a deterministic
    /// input vector (everything up to and including the 0xFE cap). The trailing
    /// padding is non-deterministic (xorshift static state shared across the
    /// process) so we only check pad-shape invariants.
    #[test]
    fn share_submission_body_byte_fidelity() {
        let mut entry = JobEntry {
            meta: JobMeta {
                datum_job_idx: 0x07,
                coinbase_id: 0x00,
                target_pot_index: 42,
                version: 0x2000_0000,
                height: 800_000,
                coinbase_value: 5_000_000_000,
                prevhash_bin: {
                    let mut a = [0u8; 32];
                    for (i, b) in a.iter_mut().enumerate() {
                        *b = (i + 1) as u8;
                    }
                    a
                },
                nbits_bin: [0x20, 0x7f, 0xff, 0xff], // BE display
                merkle_branches_bin: vec![{
                    let mut a = [0u8; 32];
                    for (i, b) in a.iter_mut().enumerate() {
                        *b = i as u8;
                    }
                    a
                }],
                coinb1_bin: vec![0xCB, 0x11, 0x22, 0x33, 0x44, 0x55, 0xFF, 0x66, 0x77, 0x88],
                coinb2_bin: vec![0xC2, 0x99, 0xAA],
                datum_coinbaser_id: 0x05,
                txn_count: 0,
                txn_total_weight: 0,
                txn_total_size: 0,
                txn_total_sigops: 0,
                block_target: [0u8; 32],
                txn_data_hex: std::sync::Arc::new(vec![]),
            },
            server_has_merkle_branches: false,
            server_has_coinbase: [false; 8],
        };
        let share = datum_stratum_sv1::server::SubmittedShare {
            username: String::new(),
            job_id: "deadbeef".into(),
            extranonce2_hex: "a1a2a3a4a5a6a7a8".into(),
            ntime_hex: "12345678".into(),
            nonce_hex: "9abcdef0".into(),
            extranonce1: [0xE1, 0xE2, 0xE3, 0xE4],
            version_rolling: 0,
            current_diff: 65536,
            patched_coinb1_bin: Some(vec![
                0xCB, 0x11, 0x22, 0x33, 0x44, 0x55, 0x10, 0x66, 0x77, 0x88,
            ]),
        };
        let user = ShareUserConfig {
            pool_address: "1POOLADDR".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let enc = build_share_submission(&share, &mut entry, &user, 65536).unwrap();
        assert!(enc.block_submission.is_none());

        // Build the canonical expected hex programmatically — every byte
        // sourced from the C reference (datum_protocol.c:1329-1441).
        let mut expected = String::new();
        expected.push_str("27"); // opcode
        expected.push_str("07"); // datum_job_idx
        expected.push_str("00"); // coinbase_id
        expected.push_str("00"); // flags
        expected.push_str("10"); // target_byte
        expected.push_str("78563412"); // ntime LE
        expected.push_str("f0debc9a"); // nonce LE
        expected.push_str("00000020"); // version LE
        expected.push_str("0c"); // extranonce_size
        expected.push_str("e1e2e3e4a1a2a3a4a5a6a7a8"); // extranonce
        expected.push_str(&hex::encode(b"1POOLADDR"));
        expected.push_str("00"); // username NUL
        expected.push_str("00000000"); // 4 reserved zeros
                                       // 0x01 sub-block
        expected.push_str("01");
        for i in 1u8..=32 {
            expected.push_str(&format!("{i:02x}"));
        }
        expected.push_str("2a00"); // target_pot_index u16 LE
        expected.push_str("ffff7f20"); // nbits LE (reversed from BE display)
        expected.push_str("05"); // datum_coinbaser_id
        expected.push_str("00350c00"); // height LE
        expected.push_str("00f2052a01000000"); // coinbase_value LE
        expected.push_str("00000000"); // txn_count
        expected.push_str("00000000"); // txn_total_weight
        expected.push_str("00000000"); // txn_total_size
        expected.push_str("00000000"); // txn_total_sigops
        expected.push_str("01"); // merkle_branch_count
        for i in (0u8..=31).rev() {
            expected.push_str(&format!("{i:02x}"));
        }
        // 0x02 sub-block (UNPATCHED coinb1)
        expected.push_str("02");
        expected.push_str("00"); // coinbase_id
        expected.push_str("0a00"); // cb1_len LE = 10
        expected.push_str("0300"); // cb2_len LE = 3
        expected.push_str("cb1122334455ff667788"); // unpatched coinb1
        expected.push_str("c299aa"); // coinb2
                                     // Cap
        expected.push_str("fe");

        let expected_bytes = hex::decode(&expected).unwrap();
        let cap_pos = expected_bytes.len();
        assert!(
            enc.body.len() > cap_pos && enc.body.len() <= cap_pos + 80,
            "body length {} outside expected window ({}, {}+80]",
            enc.body.len(),
            cap_pos,
            cap_pos
        );
        assert_eq!(
            hex::encode(&enc.body[..cap_pos]),
            expected,
            "structured 0x27 body bytes diverge from C reference"
        );
        // Padding shape: all bytes equal, length 1..=80.
        let pad = &enc.body[cap_pos..];
        assert!((1..=80).contains(&pad.len()));
        let p0 = pad[0];
        assert!(pad.iter().all(|b| *b == p0));
    }
}
