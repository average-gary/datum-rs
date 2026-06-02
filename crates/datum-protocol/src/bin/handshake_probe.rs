//! Live DATUM handshake probe.
//!
//! Connects to OCEAN's DATUM beta endpoint, completes the encrypted handshake
//! with version `"v0.4.1-beta"`, prints the server response (echoed pubkeys,
//! pool session keys, MOTD), and exits 0. Exits 1 with a labeled failure
//! kind on any error.
//!
//! USAGE:
//!     handshake_probe [--endpoint host:port] [--version str] [--pool-pubkey 128hex]
//!                     [--timeout-secs N] [--save-capture PATH] [-v]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use datum_protocol::{
    build_hello_payload, frame_for_hello, parse_received_header, seal_hello, ClientKeypairs,
    DatumCrypto, DryocCrypto, HeaderObfuscator, ProtoCmd, CRYPTO_BOX_SEAL_BYTES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DEFAULT_ENDPOINT: &str = "datum-beta1.mine.ocean.xyz:28915";
const DEFAULT_VERSION: &str = "v0.4.1-beta";
const DEFAULT_POOL_PUBKEY_HEX: &str =
    "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const CLIENT_ID: &str = "/datum-rs handshake_probe";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("error: {msg}");
            print_help();
            return ExitCode::from(1);
        }
    };

    if opts.help {
        print_help();
        return ExitCode::SUCCESS;
    }

    if opts.verbose {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("info,datum_protocol=debug")
            .try_init();
    }

    match probe(&opts).await {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAILED: {e}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Default)]
struct Opts {
    endpoint: Option<String>,
    version: Option<String>,
    pool_pubkey_hex: Option<String>,
    timeout_secs: Option<u64>,
    save_capture: Option<PathBuf>,
    verbose: bool,
    help: bool,
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => o.help = true,
            "-v" | "--verbose" => o.verbose = true,
            "--endpoint" => {
                i += 1;
                o.endpoint = Some(args.get(i).ok_or("--endpoint requires a value")?.clone());
            }
            "--version" => {
                i += 1;
                o.version = Some(args.get(i).ok_or("--version requires a value")?.clone());
            }
            "--pool-pubkey" => {
                i += 1;
                o.pool_pubkey_hex =
                    Some(args.get(i).ok_or("--pool-pubkey requires a value")?.clone());
            }
            "--timeout-secs" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("--timeout-secs requires a value")?
                    .parse::<u64>()
                    .map_err(|e| format!("--timeout-secs: {e}"))?;
                o.timeout_secs = Some(v);
            }
            "--save-capture" => {
                i += 1;
                o.save_capture = Some(PathBuf::from(
                    args.get(i).ok_or("--save-capture requires a path")?,
                ));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(o)
}

fn print_help() {
    println!(
        "handshake_probe — DATUM upstream handshake test client\n\
\n\
USAGE:\n\
    handshake_probe [OPTIONS]\n\
\n\
OPTIONS:\n\
    --endpoint <host:port>    DATUM pool endpoint (default: {DEFAULT_ENDPOINT})\n\
    --version <str>           Protocol version literal (default: {DEFAULT_VERSION})\n\
    --pool-pubkey <128-hex>   Pool long-term Ed25519+X25519 pubkey (default: OCEAN beta)\n\
    --timeout-secs <N>        Send/recv timeout in seconds (default: {DEFAULT_TIMEOUT_SECS})\n\
    --save-capture <path>     Write the bytes we sent + bytes we received to a fixture file\n\
    -v, --verbose             Enable tracing logs\n\
    -h, --help                Print this help\n"
    );
}

#[derive(Debug, thiserror::Error)]
enum ProbeError {
    #[error("hex decode pool pubkey: {0}")]
    BadPoolPubkey(String),
    #[error("dns / tcp connect to {endpoint}: {source}")]
    Connect {
        endpoint: String,
        source: std::io::Error,
    },
    #[error("send timeout after {0:?}")]
    SendTimeout(Duration),
    #[error("recv timeout after {0:?}")]
    RecvTimeout(Duration),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] datum_protocol::CryptoError),
    #[error("frame: {0}")]
    Frame(#[from] datum_protocol::FrameError),
    #[error("handshake build: {0}")]
    HandshakeBuild(#[from] datum_protocol::HandshakeError),
    #[error(
        "server returned unexpected proto_cmd {got:?}; the body flags suggest is_signed={signed}, is_encrypted_pubkey={enc_pub}"
    )]
    UnexpectedProtoCmd {
        got: ProtoCmd,
        signed: bool,
        enc_pub: bool,
    },
    #[error(
        "response cmd_len {got} exceeds 1MB sanity cap; not even close to a real DATUM response"
    )]
    OversizedResponse { got: u32 },
    #[error("response cmd_len {got} too short to hold any payload")]
    UndersizedResponse { got: u32 },
    #[error("echoed pubkey mismatch: {field} we sent {ours} but server echoed {theirs}")]
    EchoMismatch {
        field: &'static str,
        ours: String,
        theirs: String,
    },
}

async fn probe(opts: &Opts) -> Result<String, ProbeError> {
    let endpoint = opts
        .endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.into());
    let version = opts
        .version
        .clone()
        .unwrap_or_else(|| DEFAULT_VERSION.into());
    let pool_pubkey_hex = opts
        .pool_pubkey_hex
        .clone()
        .unwrap_or_else(|| DEFAULT_POOL_PUBKEY_HEX.into());
    let timeout_dur = Duration::from_secs(opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));

    let pool_keys = decode_pool_pubkey(&pool_pubkey_hex)?;

    let crypto = DryocCrypto;
    let keys = ClientKeypairs::generate(&crypto);

    let nk = u32::from_le_bytes(crypto.random_bytes(4).try_into().unwrap());
    let padding_len = 1 + (crypto.random_bytes(1)[0] as usize % 200);
    let padding = crypto.random_bytes(padding_len);

    let plaintext = build_hello_payload(&crypto, &keys, &version, CLIENT_ID, nk, &padding)?;
    let sealed = seal_hello(&crypto, &plaintext, &pool_keys.x25519_pub)?;
    let framed = frame_for_hello(&sealed)?;

    tracing::debug!(
        endpoint = %endpoint,
        version = %version,
        plaintext_len = plaintext.len(),
        sealed_len = sealed.len(),
        framed_len = framed.len(),
        nk = format!("{nk:#010x}"),
        "built hello frame"
    );

    let stream = timeout(timeout_dur, TcpStream::connect(&endpoint))
        .await
        .map_err(|_| ProbeError::Connect {
            endpoint: endpoint.clone(),
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp connect timed out"),
        })?
        .map_err(|source| ProbeError::Connect {
            endpoint: endpoint.clone(),
            source,
        })?;
    let (mut rd, mut wr) = stream.into_split();

    timeout(timeout_dur, wr.write_all(&framed))
        .await
        .map_err(|_| ProbeError::SendTimeout(timeout_dur))??;

    let mut whatever = Vec::new();
    let read_result = timeout(timeout_dur, rd.read_to_end(&mut whatever)).await;
    if let Some(path) = &opts.save_capture {
        let mut capture = Vec::new();
        capture.extend_from_slice(b"# datum-rs handshake_probe capture\n");
        capture.extend_from_slice(format!("# endpoint: {endpoint}\n").as_bytes());
        capture.extend_from_slice(format!("# version: {version}\n").as_bytes());
        capture.extend_from_slice(format!("# nk: {nk:#010x}\n").as_bytes());
        capture.extend_from_slice(format!("# sent_len: {}\n", framed.len()).as_bytes());
        capture.extend_from_slice(format!("# recv_len: {}\n", whatever.len()).as_bytes());
        capture.extend_from_slice(b"## sent\n");
        capture.extend_from_slice(&framed);
        capture.extend_from_slice(b"\n## recv\n");
        capture.extend_from_slice(&whatever);
        std::fs::write(path, capture)?;
    }
    tracing::info!(
        sent = framed.len(),
        recv = whatever.len(),
        "transfer complete"
    );

    if whatever.len() < 4 {
        return Err(ProbeError::OversizedResponse {
            got: whatever.len() as u32,
        });
    }

    let header_buf: [u8; 4] = whatever[0..4].try_into().unwrap();
    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(ProbeError::Io(e)),
        Err(_) => return Err(ProbeError::RecvTimeout(timeout_dur)),
    }
    let mut receiver_obf = HeaderObfuscator::for_receiver(nk);
    let resp_header = parse_received_header(&mut receiver_obf, header_buf)?;

    tracing::debug!(?resp_header, "parsed response header");

    if resp_header.cmd_len > 1_048_576 {
        return Err(ProbeError::OversizedResponse {
            got: resp_header.cmd_len,
        });
    }
    if (resp_header.cmd_len as usize) < CRYPTO_BOX_SEAL_BYTES {
        return Err(ProbeError::UndersizedResponse {
            got: resp_header.cmd_len,
        });
    }

    if whatever.len() < 4 + resp_header.cmd_len as usize {
        return Err(ProbeError::UndersizedResponse {
            got: whatever.len() as u32,
        });
    }
    let sealed_resp = &whatever[4..4 + resp_header.cmd_len as usize];

    let response_cmd = ProtoCmd::from_bits(resp_header.proto_cmd);
    if !matches!(response_cmd, ProtoCmd::Pong) {
        return Err(ProbeError::UnexpectedProtoCmd {
            got: response_cmd,
            signed: resp_header.is_signed,
            enc_pub: resp_header.is_encrypted_pubkey,
        });
    }

    let plaintext_resp = crypto.box_seal_open(
        sealed_resp,
        &keys.session_x25519_pub,
        &keys.session_x25519_sec,
    )?;

    if plaintext_resp.len() < 32 * 6 + 1 {
        return Err(ProbeError::UndersizedResponse {
            got: plaintext_resp.len() as u32,
        });
    }
    let echoed_lt_ed: &[u8; 32] = plaintext_resp[0..32].try_into().unwrap();
    let echoed_lt_x: &[u8; 32] = plaintext_resp[32..64].try_into().unwrap();
    let echoed_s_ed: &[u8; 32] = plaintext_resp[64..96].try_into().unwrap();
    let echoed_s_x: &[u8; 32] = plaintext_resp[96..128].try_into().unwrap();
    if echoed_lt_ed != &keys.long_term_ed25519_pub {
        return Err(ProbeError::EchoMismatch {
            field: "long_term_ed25519_pub",
            ours: hex::encode(keys.long_term_ed25519_pub),
            theirs: hex::encode(echoed_lt_ed),
        });
    }
    if echoed_lt_x != &keys.long_term_x25519_pub {
        return Err(ProbeError::EchoMismatch {
            field: "long_term_x25519_pub",
            ours: hex::encode(keys.long_term_x25519_pub),
            theirs: hex::encode(echoed_lt_x),
        });
    }
    if echoed_s_ed != &keys.session_ed25519_pub {
        return Err(ProbeError::EchoMismatch {
            field: "session_ed25519_pub",
            ours: hex::encode(keys.session_ed25519_pub),
            theirs: hex::encode(echoed_s_ed),
        });
    }
    if echoed_s_x != &keys.session_x25519_pub {
        return Err(ProbeError::EchoMismatch {
            field: "session_x25519_pub",
            ours: hex::encode(keys.session_x25519_pub),
            theirs: hex::encode(echoed_s_x),
        });
    }

    let pool_session_ed25519: [u8; 32] = plaintext_resp[128..160].try_into().unwrap();
    let pool_session_x25519: [u8; 32] = plaintext_resp[160..192].try_into().unwrap();
    let motd_bytes = &plaintext_resp[192..];
    let motd_end = motd_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(motd_bytes.len());
    let motd = String::from_utf8_lossy(&motd_bytes[..motd_end]);

    Ok(format!(
        "OK: handshake completed against {endpoint} with version \"{version}\"\n\
         pool MOTD: \"{motd}\"\n\
         pool session ed25519: {}\n\
         pool session x25519:  {}\n\
         response_cmd: {response_cmd:?}, response_cmd_len: {}",
        hex::encode(pool_session_ed25519),
        hex::encode(pool_session_x25519),
        resp_header.cmd_len,
    ))
}

struct PoolKeys {
    #[allow(dead_code)]
    ed25519_pub: [u8; 32],
    x25519_pub: [u8; 32],
}

fn decode_pool_pubkey(hex_str: &str) -> Result<PoolKeys, ProbeError> {
    let bytes = hex::decode(hex_str).map_err(|e| ProbeError::BadPoolPubkey(e.to_string()))?;
    if bytes.len() != 64 {
        return Err(ProbeError::BadPoolPubkey(format!(
            "expected 64 bytes (128 hex chars), got {}",
            bytes.len()
        )));
    }
    let ed25519_pub: [u8; 32] = bytes[..32].try_into().unwrap();
    let x25519_pub: [u8; 32] = bytes[32..].try_into().unwrap();
    Ok(PoolKeys {
        ed25519_pub,
        x25519_pub,
    })
}
