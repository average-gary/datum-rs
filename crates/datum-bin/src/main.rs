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
    tracing_subscriber::fmt::init();

    let metrics: Arc<dyn MetricsSource> = Arc::new(StubMetrics);
    let app = datum_api::router(ApiState { metrics });

    let api_addr: SocketAddr = format!("{}:{}", api_addr_or_default(&cfg), cfg.api.listen_port)
        .parse()
        .expect("api listen_addr/listen_port parses");

    if cfg.api.listen_port == 0 {
        tracing::info!("API listen_port=0; HTTP API disabled");
        std::future::pending::<()>().await;
        return;
    }

    tracing::info!(%api_addr, "datum_gateway: HTTP API binding");
    let listener = match tokio::net::TcpListener::bind(api_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%api_addr, error = %e, "API bind failed");
            return;
        }
    };

    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        match ctrl_c.await {
            Ok(()) => tracing::info!("SIGINT/Ctrl-C received; shutting down"),
            Err(e) => tracing::warn!(error = %e, "ctrl_c handler failed"),
        }
    };

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!(error = %e, "axum server exited with error");
    }
}

fn api_addr_or_default(cfg: &Config) -> &str {
    if cfg.api.listen_addr.is_empty() {
        "0.0.0.0"
    } else {
        &cfg.api.listen_addr
    }
}

struct StubMetrics;
impl MetricsSource for StubMetrics {
    fn snapshot(&self) -> Value {
        json!({
            "version": PKG_VERSION,
            "miner_count": 0,
            "share_rate_5m": 0.0,
            "ocean_connected": false,
            "note": "alpha — stratum/protocol runtimes not yet wired"
        })
    }
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
