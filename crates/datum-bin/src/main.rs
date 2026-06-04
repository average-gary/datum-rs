use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use datum_api::{ApiState, MetricsSource};
use datum_config::{Config, ConfigError};
use serde_json::{json, Value};

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

    // SV1 stratum server. Bound on the configured port; receives notifies via
    // a watch channel that the runtime publishes to once a template + coinbaser
    // pair lands. Phase 4 wires the publisher; today the channel stays empty
    // and clients block until the gateway gets real templates.
    let (notify_tx, notify_rx) =
        tokio::sync::watch::channel::<Option<datum_stratum_sv1::server::NotifyParams>>(None);
    let (sv1_shutdown_tx, sv1_shutdown_rx) = tokio::sync::watch::channel::<bool>(false);
    let sv1_addr: SocketAddr = format!(
        "{}:{}",
        stratum_addr_or_default(&cfg),
        cfg.stratum.listen_port
    )
    .parse()
    .expect("stratum.listen_addr/listen_port parses");
    let sv1_state = datum_stratum_sv1::server::ServerState::new(notify_rx);

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

    // Assembler task: when both channels have a value, build mining.notify
    // params and broadcast to all subscribed SV1 miners. Re-runs on either
    // channel changing.
    if let Some(template_ch) = template_channel.clone() {
        let notify_tx_for_assembler = notify_tx.clone();
        let mut t_sub = template_ch.clone();
        let mut c_sub = coinbaser_sub.clone();
        let coinbase_tag = cfg.mining.coinbase_tag_primary.clone();
        tokio::spawn(async move {
            let mut job_counter: u64 = 1;
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
                let job_id = format!("{job_counter:016x}");
                let params = datum_stratum_sv1::assembler::assemble_notify(
                    &job_id,
                    &template,
                    &coinbaser,
                    coinbase_tag.as_bytes(),
                    true,
                );
                if notify_tx_for_assembler
                    .send(Some(params.to_json_array()))
                    .is_err()
                {
                    return;
                }
                job_counter = job_counter.wrapping_add(1);
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
        if !pool_host.is_empty() && !pool_pubkey_hex.is_empty() {
            tokio::spawn(async move {
                if let Err(e) = run_datum_upstream(
                    &pool_host,
                    pool_port,
                    &pool_pubkey_hex,
                    &mining_pool_address,
                    coinbaser_pub,
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
async fn run_datum_upstream(
    pool_host: &str,
    pool_port: u16,
    pool_pubkey_hex: &str,
    _mining_pool_address: &str,
    coinbaser_pub: datum_coinbaser::CoinbaserPublisher,
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

                let connected = std::sync::Arc::new(connected);
                let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(64);
                let (commands_tx, commands_rx) = tokio::sync::mpsc::channel(64);

                let coinbaser_pub = coinbaser_pub.clone();
                let event_loop = {
                    let conn = connected.clone();
                    tokio::spawn(async move { conn.run(events_tx, commands_rx).await })
                };

                let _ = commands_tx
                    .send(datum_protocol::UpstreamCommand::RequestCoinbaser)
                    .await;

                while let Some(event) = events_rx.recv().await {
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
                                "client_config received from pool"
                            );
                        }
                        datum_protocol::UpstreamEvent::ShareResponse(resp) => {
                            tracing::debug!(?resp, "share response");
                        }
                        datum_protocol::UpstreamEvent::BlockNotify(_) => {
                            tracing::info!("block_notify from pool");
                        }
                        datum_protocol::UpstreamEvent::JobValidationRequest(_) => {
                            tracing::debug!("job validation request from pool (not yet handled)");
                        }
                        datum_protocol::UpstreamEvent::UnknownFrame { proto_cmd, .. } => {
                            tracing::debug!(?proto_cmd, "unknown frame from pool");
                        }
                    }
                }
                event_loop.abort();
                tracing::warn!("DATUM event stream closed");
            }
            Err(e) => {
                tracing::error!(error = %e, "DATUM upstream connect failed");
            }
        }
        tokio::time::sleep(backoff).await;
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
