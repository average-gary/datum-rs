use std::process::ExitCode;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let git_sha = option_env!("DATUM_GIT_SHA").unwrap_or("dev");

    match args.as_slice() {
        [] => {
            eprintln!("datum_gateway {PKG_VERSION} ({git_sha})");
            eprintln!("not yet implemented");
            ExitCode::from(1)
        }
        [flag] if flag == "--version" || flag == "-V" => {
            println!("datum_gateway {PKG_VERSION} ({git_sha})");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("datum_gateway {PKG_VERSION} ({git_sha})");
            eprintln!("not yet implemented");
            ExitCode::from(1)
        }
    }
}
