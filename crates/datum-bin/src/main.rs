use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use datum_api::{ApiState, MetricsSource};
use datum_config::{Config, ConfigError};
use datum_share_relay::{
    build_share_submission, JobKey, JobTracker, ShareEncoded, ShareUserConfig, SubmittedShareInputs,
};
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

    // SV2 listener (Phase 3): bind only when the operator has opted in via
    // `cfg.stratum_v2.enabled` AND set both authority key paths.
    // `ListenerConfig::from_datum_config` validates the keys exist + match,
    // so a misconfigured authority pubkey/secret pair fails loud at startup
    // rather than silently rejecting every miner cert.
    let sv2_handle = if cfg.stratum_v2.is_active() {
        match datum_stratum_sv2::ListenerConfig::from_datum_config(&cfg.stratum_v2) {
            Ok(sv2_cfg) => {
                tracing::info!(
                    sv2_authority_pubkey_b58 = %sv2_cfg.authority.pubkey_b58,
                    "sv2: authority pubkey (publish to miners for pinning)"
                );
                // Phase 6: publish the authority pubkey + bind addr to /metrics
                // BEFORE bind so the row is populated even if bind fails (which
                // surfaces the misconfig in the JSON the operator polls).
                runtime.set_sv2_authority_pubkey_b58(sv2_cfg.authority.pubkey_b58.clone());
                match datum_stratum_sv2::Listener::bind(sv2_cfg).await {
                    Ok(listener) => Some(tokio::spawn(listener.run())),
                    Err(e) => {
                        tracing::error!(error = %e, "sv2 listener bind failed; SV2 disabled");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "sv2 listener config build failed; SV2 disabled");
                None
            }
        }
    } else {
        tracing::info!("sv2 stratum_v2 listener not configured; SV2 disabled");
        None
    };

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
                let template_seed = state.job_id_seed;
                {
                    let mut g = jobs_for_assembler.lock().await;
                    g.insert(JobKey::sv1(job_id.clone()), meta, template_seed);
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
                let key = JobKey::sv1(share.job_id.clone());
                let encoded = {
                    let mut g = jobs_for_relay.lock().await;
                    if !g.contains(&key) {
                        tracing::warn!(
                            user = %share.username,
                            job = %share.job_id,
                            "share-relay: no JobEntry for job_id; dropping (likely stale or pre-notify share)"
                        );
                        continue;
                    }
                    let entry_version = g.get_mut(&key).expect("just checked").meta.version;
                    let inputs = match sv1_share_to_inputs(&share, entry_version) {
                        Ok(i) => i,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "share-relay: input conversion failed; dropping submit"
                            );
                            continue;
                        }
                    };
                    // Snapshot template_seed + cross-protocol sentinel before
                    // taking a mutable borrow on the entry.
                    let template_seed = g.get_mut(&key).unwrap().template_seed;
                    let coinbase_id = g.get_mut(&key).unwrap().meta.coinbase_id;
                    let xprot_seen =
                        g.cross_protocol_coinbase_already_seen(template_seed, coinbase_id);
                    let entry = g.get_mut(&key).expect("contains() was true");
                    let enc = match build_share_submission(
                        &inputs,
                        entry,
                        &user_cfg_for_relay,
                        xprot_seen,
                    ) {
                        Ok(enc) => enc,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "share-relay: encode failed; dropping submit"
                            );
                            continue;
                        }
                    };
                    // If we just emitted the 0x02 sub-block (entry's flag
                    // flipped to true and xprot_seen was false), mark the
                    // cross-protocol sentinel so a concurrent SV2 share for
                    // the same (template_seed, coinbase) skips 0x02.
                    if !xprot_seen
                        && entry
                            .server_has_coinbase
                            .get(coinbase_id as usize)
                            .copied()
                            .unwrap_or(false)
                    {
                        g.mark_cross_protocol_coinbase_seen(template_seed, coinbase_id);
                    }
                    enc
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
        if let Some(h) = sv2_handle {
            h.abort();
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
    if let Some(h) = sv2_handle {
        // SV2 listener has no graceful-shutdown channel today; abort the
        // accept loop. Per-connection tasks running through Noise/SetupConn
        // also get cancelled via task tree, which is fine — Phase 4 will add
        // a watch channel like SV1's.
        h.abort();
    }
    let _ = notify_tx;
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

/// Parse a big-endian u32 hex string (with or without the `0x` prefix).
fn parse_u32_be_hex(s: &str) -> Option<u32> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(trimmed, 16).ok()
}

/// Build [`SubmittedShareInputs`] from an SV1 [`SubmittedShare`]. Hoists the
/// pre-Phase-5 inline conversion that lived in the share-relay loop so the
/// shared `build_share_submission` builder gets a protocol-neutral input
/// regardless of which protocol delivered the share.
fn sv1_share_to_inputs(
    share: &datum_stratum_sv1::server::SubmittedShare,
    entry_version: u32,
) -> Result<SubmittedShareInputs, String> {
    let ntime = parse_u32_be_hex(&share.ntime_hex).ok_or("invalid ntime hex")?;
    let nonce = parse_u32_be_hex(&share.nonce_hex).ok_or("invalid nonce hex")?;
    // BIP-310: SV1 server already masked the version-rolling bits against the
    // negotiated mask. Plain OR is safe.
    let version: u32 = entry_version | share.version_rolling;
    let extranonce2 = hex::decode(&share.extranonce2_hex).map_err(|e| e.to_string())?;
    let mut extranonce = [0u8; 12];
    extranonce[..4].copy_from_slice(&share.extranonce1);
    let take = extranonce2.len().min(8);
    extranonce[4..4 + take].copy_from_slice(&extranonce2[..take]);
    Ok(SubmittedShareInputs {
        username: share.username.clone(),
        extranonce,
        ntime,
        nonce,
        version,
        current_diff: share.current_diff,
        patched_coinb1_bin: share.patched_coinb1_bin.clone(),
    })
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
    /// Phase 6: published authority pubkey (base58check) for /metrics.
    /// Empty when SV2 is disabled.
    sv2_authority_pubkey_b58: parking_lot::RwLock<String>,
    // Lifetime totals — survive across upstream reconnects on purpose; OCEAN's
    // dashboard frames the same way. Process-restart resets are expected.
    shares_accepted: AtomicU64,
    shares_rejected: AtomicU64,
    /// SV2-specific share counters (Phase 6 /metrics rows). These live
    /// alongside the cross-protocol `shares_accepted` / `shares_rejected`
    /// because operators want to see how the SV2 leg is performing
    /// independently of SV1.
    sv2_shares_accepted: AtomicU64,
    sv2_shares_rejected: AtomicU64,
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

    fn set_sv2_authority_pubkey_b58(&self, pubkey_b58: String) {
        *self.sv2_authority_pubkey_b58.write() = pubkey_b58;
    }

    fn record_share_accepted(&self) {
        self.shares_accepted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_share_rejected(&self) {
        self.shares_rejected.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn record_sv2_share_accepted(&self) {
        self.sv2_shares_accepted.fetch_add(1, Ordering::Relaxed);
        self.shares_accepted.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn record_sv2_share_rejected(&self) {
        self.sv2_shares_rejected.fetch_add(1, Ordering::Relaxed);
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

    fn sv2_shares_accepted(&self) -> u64 {
        self.sv2_shares_accepted.load(Ordering::Relaxed)
    }

    fn sv2_shares_rejected(&self) -> u64 {
        self.sv2_shares_rejected.load(Ordering::Relaxed)
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
        // Phase 6: surface SV2-specific rows so operators can verify (a) the
        // listener is bound + advertising its authority pubkey for miner-side
        // pinning, and (b) per-protocol share traffic. `sv2_active_channels`
        // reads through `ChannelRegistry::active_count()` which is a synchronous
        // atomic-load — safe inside this synchronous trait method.
        let sv2_active_channels: u64 = self
            .runtime
            .sv2_registry
            .read()
            .as_ref()
            .map(|r| r.active_count() as u64)
            .unwrap_or(0);
        let sv2_authority_pubkey_b58 = self.runtime.sv2_authority_pubkey_b58.read().clone();
        json!({
            "version": PKG_VERSION,
            "started": *self.runtime.started.read(),
            "rpc_url": *self.runtime.rpc_url.read(),
            "shares_accepted": self.runtime.shares_accepted(),
            "shares_rejected": self.runtime.shares_rejected(),
            "blocks_found": self.runtime.blocks_found(),
            "sv2_active_channels": sv2_active_channels,
            "sv2_shares_accepted": self.runtime.sv2_shares_accepted(),
            "sv2_shares_rejected": self.runtime.sv2_shares_rejected(),
            "sv2_authority_pubkey_b58": sv2_authority_pubkey_b58,
            "config": &self.cfg_summary,
            "note": "alpha — sv1 listener bound; sv2 listener bound when stratum_v2.enabled + authority paths set"
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
    fn runtime_metrics_snapshot_exposes_sv2_rows() {
        // Phase 6: /metrics MUST surface sv2_active_channels,
        // sv2_shares_accepted, sv2_shares_rejected, sv2_authority_pubkey_b58.
        let runtime = Arc::new(RuntimeStats::new());
        // Default state: SV2 disabled, all rows zero / empty.
        let m = RuntimeMetrics {
            runtime: runtime.clone(),
            cfg_summary: serde_json::json!({}),
        };
        let snap = m.snapshot();
        assert_eq!(snap["sv2_active_channels"], 0);
        assert_eq!(snap["sv2_shares_accepted"], 0);
        assert_eq!(snap["sv2_shares_rejected"], 0);
        assert_eq!(snap["sv2_authority_pubkey_b58"], "");

        // After publishing a pubkey + recording SV2 shares, rows populate.
        runtime.set_sv2_authority_pubkey_b58("sv2k-fake-pubkey-b58".into());
        runtime.record_sv2_share_accepted();
        runtime.record_sv2_share_accepted();
        runtime.record_sv2_share_rejected();
        let snap = m.snapshot();
        assert_eq!(snap["sv2_authority_pubkey_b58"], "sv2k-fake-pubkey-b58");
        assert_eq!(snap["sv2_shares_accepted"], 2);
        assert_eq!(snap["sv2_shares_rejected"], 1);
        // Cross-protocol totals also bumped.
        assert_eq!(snap["shares_accepted"], 2);
        assert_eq!(snap["shares_rejected"], 1);
    }

    // Byte-fidelity, block-found, double_sha256, hash_meets_target, and
    // compute_merkle_root tests moved with the implementation to the
    // `datum-share-relay` crate. See
    // `crates/datum-share-relay/src/share_encoder.rs` mod tests.
}
