use std::path::PathBuf;
use std::process::ExitCode;

use datum_config::{Config, ConfigError};

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
        Cmd::Run { config } => {
            eprintln!("datum_gateway {PKG_VERSION} ({git_sha})");
            match validate_config(&config) {
                Ok(()) => {
                    eprintln!("config OK: {}", config.display());
                    eprintln!(
                        "not yet implemented: gateway runtime is built incrementally over Phase 1-4"
                    );
                    eprintln!("Working today: --version, --validate-config, --example-conf");
                    ExitCode::from(1)
                }
                Err(report) => {
                    eprintln!("{report}");
                    ExitCode::from(1)
                }
            }
        }
        Cmd::ParseError(msg) => {
            eprintln!("error: {msg}");
            eprintln!();
            print_help();
            ExitCode::from(1)
        }
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
This is alpha software. The gateway runtime (`-c PATH`) is not yet wired up.\n\
Today --version, --validate-config, --example-conf work end-to-end.\n"
    );
}
