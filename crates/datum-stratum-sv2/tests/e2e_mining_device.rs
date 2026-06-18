//! End-to-end native-SV2 interop test.
//!
//! Drives a full SV2 share path against a real third-party CPU miner — SRI's
//! `mining_device` binary (from sv2-apps's `integration_tests_sv2` crate):
//!
//!   sv2-apps `mining_device` (real upstream binary)
//!     ─Noise NX─▶ datum-rs Listener (real production code path)
//!     ─0x27────▶ mock DATUM upstream (mpsc::Receiver in this process)
//!
//! Why this swaps in for the prior `e2e_translator.rs`:
//!   datum-rs already accepts SV1 natively on a separate listener; downstream
//!   miners that speak SV1 connect there directly. The SRI translator only
//!   matters for SV1-hardware-talking-to-SV2-only-pools, which is not us. So
//!   the translator is not a representative client for our SV2 listener — the
//!   native SV2 CPU miner is.
//!
//! Why a separate file instead of extending sv2_dispatch.rs:
//!   - This test depends on building an external Cargo workspace
//!     (`stratum-mining/sv2-apps`, ~3-10 min on first run), so it lives behind
//!     the `e2e` feature flag AND is `#[ignore]`d on top so even
//!     `--features e2e` won't run it without `-- --ignored`.
//!   - sv2_dispatch.rs is the fast, hermetic dispatch test; we mustn't
//!     regress its runtime.
//!
//! Run:
//!   cargo test -p datum-stratum-sv2 --features e2e \
//!     --test e2e_mining_device -- --ignored --nocapture
//!
//! What this proves end-to-end:
//!   1. Our authority pubkey base58 encoding is wire-compatible with SRI's
//!      `Secp256k1PublicKey::from_str` (both decode `[0x01,0x00] || x_only_pk[32]`).
//!   2. Our Noise NX responder accepts SRI's mining_device initiator's act-1,
//!      and our cert is accepted by the miner's verifier.
//!   3. Our `SetupConnectionSuccess` flags are compatible with the SV2 CPU
//!      miner's expectations.
//!   4. Our **Standard** mining channel path: `OpenStandardMiningChannel` →
//!      `OpenStandardMiningChannelSuccess` → `NewMiningJob` (with server-side
//!      precomputed merkle_root) → `SetNewPrevHash` → `SetTarget` produces a
//!      `SubmitSharesStandard` (0x1a) from a real native SV2 client.
//!   5. The submit reaches our dispatch loop and forwards to the mock DATUM
//!      upstream as a 0x27 body. (No translator, no SV1 — pure SV2 wire.)

#![cfg(feature = "e2e")]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use datum_blocktemplates::{ScriptSigInputs, Template, TemplateState, TemplateStatePublisher};
use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use datum_share_relay::{JobTracker, ShareUserConfig};
use datum_stratum_sv2::auth::AuthorityKey;
use datum_stratum_sv2::listener::{ListenerConfig, ListenerRuntime, UpstreamShareCommand};
use datum_stratum_sv2::Listener;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::{mpsc, Mutex};

// ---------------------------------------------------------------------------
// Authority fixture (mirrors sv2_dispatch.rs `make_authority_files`).
// Kept inline rather than moved to a shared module so this file is the single
// touchpoint for the e2e feature.
// ---------------------------------------------------------------------------

fn write_temp(name: &str, contents: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "datum-rs-e2e-mining-device-{}-{:?}-{}-{}",
        std::process::id(),
        std::thread::current().id(),
        n,
        name
    ));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path
}

fn make_authority_files() -> (PathBuf, PathBuf, [u8; 32], String) {
    use secp256k1::{
        rand::{rngs::StdRng, SeedableRng},
        Keypair, Secp256k1,
    };
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(0xe2e_07ea7e_u64);
    let kp = Keypair::new(&secp, &mut rng);
    let pubkey_bytes = kp.x_only_public_key().0.serialize();
    let secret_bytes = kp.secret_key().secret_bytes();

    let pub_b58 = datum_stratum_sv2::auth::encode_authority_pubkey_b58(&pubkey_bytes);
    let sec_b58 = bs58::encode(secret_bytes).with_check().into_string();

    let pub_path = write_temp("e2e-pub.txt", &pub_b58);
    let sec_path = write_temp("e2e-sec.txt", &sec_b58);
    (pub_path, sec_path, pubkey_bytes, pub_b58)
}

// ---------------------------------------------------------------------------
// Synthetic template (mirrors sv2_dispatch.rs).
//
// We pair `bits = 1d00ffff` (network difficulty 1) with the miner CLI
// `--nominal-hashrate-multiplier 0.001`. The Standard-channel target the
// listener emits (`SetTarget`) is derived from the miner's advertised
// hashrate — at 0.001× CPU capacity that's effectively trivial, and the first
// nonce the miner tries is overwhelmingly likely to satisfy it.
// ---------------------------------------------------------------------------

fn template() -> Template {
    Template {
        version: 0x2000_0000,
        previous_block_hash: "00".repeat(32),
        bits: "1d00ffff".into(),
        height: 800_000,
        coinbase_value: 312_500_000,
        curtime: 0x6712_3456,
        mintime: 0,
        sizelimit: 4_000_000,
        weightlimit: 4_000_000,
        sigop_limit: 80_000,
        default_witness_commitment: None,
        transactions: vec![],
        long_poll_id: None,
        target: None,
    }
}

fn blob() -> CoinbaserBlob {
    CoinbaserBlob {
        datum_id: 0,
        outputs: vec![CoinbaseOutput {
            value_sats: 312_500_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd],
        }],
    }
}

fn synth_state(seed: u64) -> TemplateState {
    TemplateState::from_template_and_blob(&template(), &blob(), ScriptSigInputs::default(), seed)
}

// ---------------------------------------------------------------------------
// Locate or build sv2-apps's `mining_device` binary.
//
// Strategy: clone shallow to `<workspace_root>/target/e2e/sv2-apps`, then
// `cargo build --release -p integration_tests_sv2 --bin mining_device` inside
// it. Override the cloned repo's `rust-toolchain.toml` (1.85.0) with our
// workspace's 1.89.0 via the `RUSTUP_TOOLCHAIN` env var so we don't need a
// second toolchain installed.
//
// First-time cost: 3-10 minutes. Cached afterward — subsequent runs reuse the
// binary at `target/e2e/sv2-apps/integration-tests/target/release/mining_device`.
// ---------------------------------------------------------------------------

const SV2_APPS_REPO: &str = "https://github.com/stratum-mining/sv2-apps";
const SV2_APPS_PINNED_SHA: &str = "f863be07378e525d66a653187f87eb7ac6413eb2";

fn workspace_root() -> PathBuf {
    // The test runs with CARGO_MANIFEST_DIR set to the crate's manifest dir;
    // workspace root is two levels up (`<root>/crates/datum-stratum-sv2`).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

fn miner_paths() -> (PathBuf, PathBuf, PathBuf) {
    let root = workspace_root();
    let clone_dir = root.join("target/e2e/sv2-apps");
    // sv2-apps is multi-workspace; `integration_tests_sv2` is a standalone
    // package with its own target dir under `integration-tests/`.
    let pkg_dir = clone_dir.join("integration-tests");
    let bin = pkg_dir.join("target/release/mining_device");
    (clone_dir, pkg_dir, bin)
}

/// Ensure the `mining_device` binary exists. Returns `(path, build_secs)`.
/// On any failure during clone or build, panics with the captured stderr —
/// per the prompt's "DO NOT swallow" guidance.
fn ensure_mining_device_built() -> (PathBuf, f64) {
    let (clone_dir, pkg_dir, bin) = miner_paths();

    if bin.exists() {
        eprintln!("[e2e] mining_device binary cached at {}", bin.display());
        return (bin, 0.0);
    }

    if !clone_dir.exists() {
        eprintln!("[e2e] cloning {} → {}", SV2_APPS_REPO, clone_dir.display());
        if let Some(parent) = clone_dir.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let out = std::process::Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                SV2_APPS_REPO,
                clone_dir.to_str().unwrap(),
            ])
            .output()
            .expect("spawn git clone");
        if !out.status.success() {
            panic!(
                "git clone failed (status {:?}):\nstdout: {}\nstderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // Surface the actual sha for traceability — depth-1 clones can't fetch
    // arbitrary shas reliably, so we accept whatever main is at and just log.
    let head_out = std::process::Command::new("git")
        .args(["-C", clone_dir.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .expect("spawn git rev-parse");
    let head_sha = String::from_utf8_lossy(&head_out.stdout).trim().to_string();
    eprintln!(
        "[e2e] sv2-apps HEAD = {head_sha} (expected pin: {SV2_APPS_PINNED_SHA}; if these diverge, \
         mining_device behavior may differ — check upstream main)"
    );

    // The cloned `integration-tests/Cargo.toml` is a *standalone* package
    // (not a member of any sub-workspace inside sv2-apps). Because we clone
    // it under our own workspace's `target/` dir, cargo will refuse to build
    // it with "current package believes it's in a workspace when it's not"
    // — our root `[workspace]` claims the path, but the manifest isn't a
    // member. Fix: append an empty `[workspace]` table to that manifest so
    // cargo treats it as its own workspace root. Idempotent.
    let pkg_manifest = pkg_dir.join("Cargo.toml");
    let manifest_str =
        std::fs::read_to_string(&pkg_manifest).expect("read integration-tests Cargo.toml");
    if !manifest_str.contains("\n[workspace]") && !manifest_str.starts_with("[workspace]") {
        let patched = format!("{manifest_str}\n[workspace]\n");
        std::fs::write(&pkg_manifest, patched).expect("patch integration-tests Cargo.toml");
        eprintln!(
            "[e2e] patched {} with an empty [workspace] table to escape our root workspace",
            pkg_manifest.display()
        );
    }

    eprintln!(
        "[e2e] cargo build --release -p integration_tests_sv2 --bin mining_device \
         (this is a multi-minute first run)"
    );
    let t0 = Instant::now();
    // Override the cloned repo's `rust-toolchain.toml` (channel "1.85.0") with
    // our workspace's toolchain. Prefer an active `RUSTUP_TOOLCHAIN`; otherwise
    // fall back to the workspace pin "1.89.0". SRI's MSRV is 1.85 so 1.89 is
    // forward-compatible.
    let toolchain = std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "1.89.0".to_string());
    let out = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "integration_tests_sv2",
            "--bin",
            "mining_device",
        ])
        .current_dir(&pkg_dir)
        .env("RUSTUP_TOOLCHAIN", toolchain)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn cargo build");
    let build_secs = t0.elapsed().as_secs_f64();
    if !out.status.success() {
        panic!(
            "cargo build --bin mining_device failed in {build_secs:.1}s (status {:?}):\n\
             stdout (last 2KB): {}\n\
             stderr (last 4KB): {}",
            out.status,
            tail(&out.stdout, 2048),
            tail(&out.stderr, 4096)
        );
    }
    eprintln!(
        "[e2e] mining_device built in {build_secs:.1}s → {}",
        bin.display()
    );
    assert!(
        bin.exists(),
        "mining_device binary missing after build: {}",
        bin.display()
    );
    (bin, build_secs)
}

fn tail(buf: &[u8], n: usize) -> String {
    let start = buf.len().saturating_sub(n);
    String::from_utf8_lossy(&buf[start..]).into_owned()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Reserve a free TCP port, then drop it. Standard short-window probe — same
/// pattern sv2_dispatch.rs uses.
async fn pick_free_port() -> std::net::SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "mining_device build is multi-minute; run with --ignored"]
async fn e2e_mining_device_sv2_to_datum_27() {
    let test_t0 = Instant::now();

    // 1. Build (or reuse) the mining_device binary.
    let (miner_bin, build_secs) = ensure_mining_device_built();

    // 2. Boot a real datum-rs Listener.
    let (pub_path, sec_path, _pubkey, pub_b58) = make_authority_files();

    let (upstream_tx, mut upstream_rx) = mpsc::channel::<UpstreamShareCommand>(8);

    let (publisher, sub) = TemplateStatePublisher::new();
    publisher.publish(synth_state(1)).unwrap();

    let jobs = Arc::new(Mutex::new(JobTracker::new()));

    let listener_addr = pick_free_port().await;

    let cfg = ListenerConfig {
        bind_addr: listener_addr,
        cert_validity: Duration::from_secs(60),
        authority: AuthorityKey::load(&pub_path, &sec_path).unwrap(),
        handshake_timeout: Duration::from_secs(5),
        // Test fixture overrides — production uses 1 TH/s + 6 SPM. The
        // CPU-bound `mining_device` advertises hashrate proportional to
        // its single-core CPU speed (megahash range), nowhere near 1 TH/s,
        // and it must clear the floor for the channel to open. We also
        // pick a high `expected_share_per_minute` (60) so the clamped
        // target stays trivial enough that the first nonce is overwhelmingly
        // likely to satisfy it within the 60s deadline.
        min_hashrate_threshold: 1.0e6,
        expected_share_per_minute: 60.0,
    };
    let rt = ListenerRuntime {
        cfg: Arc::new(cfg),
        template_rx: sub.into_receiver(),
        commands_tx: upstream_tx,
        jobs: jobs.clone(),
        user_cfg: ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        },
        block_found: None,
    };
    let listener = Listener::bind_with_runtime(rt).await.expect("bind");
    let server = tokio::spawn(listener.run());
    let listener_bound_at = Instant::now();
    eprintln!(
        "[e2e] datum-rs listener bound on {} (authority_pubkey_b58={})",
        listener_addr, pub_b58
    );

    // 3. Spawn `mining_device` pointed at our listener.
    //
    // CLI rationale:
    //   --address-pool             our listener's bound port
    //   --pubkey-pool              our authority pubkey (base58-check); the
    //                              miner's `Secp256k1PublicKey::from_str` is
    //                              the same parser SRI's translator uses, so
    //                              format compatibility is already proven.
    //   --id-user                  arbitrary worker id
    //   --nominal-hashrate-multiplier 0.001
    //                              advertise tiny hashrate so the listener's
    //                              `SetTarget` lands at trivial difficulty
    //                              and the first valid nonce passes.
    //   --handicap 0               no inter-hash sleep — fastest first-share.
    //   --cores 1                  single-threaded for deterministic timing.
    eprintln!(
        "[e2e] spawning mining_device: {} --address-pool 127.0.0.1:{} \
         --pubkey-pool {} --id-user e2e-test --nominal-hashrate-multiplier 1.0 \
         --handicap 0 --cores 1",
        miner_bin.display(),
        listener_addr.port(),
        pub_b58,
    );
    // Bug B (2026-06-16): downstream miners must advertise ≥
    // `min_hashrate_threshold` H/s. With the test fixture's 1 MH/s floor +
    // multiplier 1.0 the CPU miner reports its real benchmarked rate
    // (megahash range on a modern Mac) — well above 1 MH/s.
    let mut child = TokioCommand::new(&miner_bin)
        .args([
            "--address-pool",
            &format!("127.0.0.1:{}", listener_addr.port()),
            "--pubkey-pool",
            &pub_b58,
            "--id-user",
            "e2e-test",
            "--nominal-hashrate-multiplier",
            "1.0",
            "--handicap",
            "0",
            "--cores",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn mining_device at {}: {e}", miner_bin.display()));

    // Drain stdout/stderr in background so the child doesn't block on a full
    // pipe. We keep the captured logs in shared Arc<Mutex<Vec<String>>> for
    // end-of-test diagnostics.
    let stderr_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let stdout_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let stderr_pipe = child.stderr.take().expect("stderr piped");
    let stdout_pipe = child.stdout.take().expect("stdout piped");
    {
        let log = stderr_log.clone();
        tokio::spawn(async move {
            let mut r = BufReader::new(stderr_pipe);
            let mut line = String::new();
            loop {
                line.clear();
                match r.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let l = line.trim_end().to_string();
                        eprintln!("[mining_device stderr] {l}");
                        log.lock().await.push(l);
                    }
                }
            }
        });
    }
    {
        let log = stdout_log.clone();
        tokio::spawn(async move {
            let mut r = BufReader::new(stdout_pipe);
            let mut line = String::new();
            loop {
                line.clear();
                match r.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let l = line.trim_end().to_string();
                        eprintln!("[mining_device stdout] {l}");
                        log.lock().await.push(l);
                    }
                }
            }
        });
    }

    // 4. Hard assertion: a 0x27 body must land on the mock DATUM upstream
    //    within 60s. With `--nominal-hashrate-multiplier 0.001` the listener
    //    derives a trivial target and the first valid nonce passes. The
    //    timeout is generous (5-15s typical, sandbox margin to 60s).
    //
    //    No PRIMARY/SECONDARY split: if this fails, the SV2 share path is
    //    broken end-to-end.
    let assert_deadline = Duration::from_secs(60);
    let recv_result = tokio::time::timeout(assert_deadline, upstream_rx.recv()).await;
    let listener_to_27 = match recv_result {
        Ok(Some(UpstreamShareCommand::SubmitShare(body))) => {
            assert!(
                body.len() >= 32,
                "DATUM 0x27 body too short: {} bytes",
                body.len()
            );
            let elapsed = Instant::now()
                .duration_since(listener_bound_at)
                .as_secs_f64();
            eprintln!(
                "[e2e] DATUM 0x27 ({} bytes) — listener_bind→0x27 = {:.1}s",
                body.len(),
                elapsed
            );
            elapsed
        }
        Ok(None) => {
            // Capture last 30 stderr lines for diagnostics.
            let logs = stderr_log
                .lock()
                .await
                .iter()
                .rev()
                .take(30)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            // Make sure the child gets reaped before we panic.
            let _ = child.kill().await;
            panic!(
                "upstream channel closed without 0x27 — listener tore down the \
                 dispatch loop. Last 30 mining_device stderr lines:\n{logs}"
            );
        }
        Err(_) => {
            let logs = stderr_log
                .lock()
                .await
                .iter()
                .rev()
                .take(30)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            // Surface child status in case it crashed silently.
            let child_status = match child.try_wait() {
                Ok(Some(s)) => format!("exited with {s:?}"),
                Ok(None) => "still running".into(),
                Err(e) => format!("try_wait error: {e}"),
            };
            let _ = child.kill().await;
            panic!(
                "no DATUM 0x27 within {assert_deadline:?} — mining_device {child_status}.\n\
                 Last 30 mining_device stderr lines:\n{logs}"
            );
        }
    };

    // 5. mining_device must still be alive at the end.
    match child.try_wait() {
        Ok(None) => { /* still running, good */ }
        Ok(Some(status)) => panic!("mining_device exited prematurely with status {status:?}"),
        Err(e) => panic!("mining_device try_wait error: {e}"),
    }

    // 6. Tear down. Kill the miner, give it 5s to die, fail if it hangs.
    eprintln!("[e2e] killing mining_device");
    let _ = child.kill().await;
    let exit = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    if exit.is_err() {
        panic!("mining_device did not exit within 5s of SIGKILL — sloppy shutdown");
    }

    server.abort();
    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&sec_path);

    // 7. Summary diagnostics.
    let total = test_t0.elapsed().as_secs_f64();
    let last20 = stderr_log
        .lock()
        .await
        .iter()
        .rev()
        .take(20)
        .rev()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    eprintln!("[e2e] ---- summary ----");
    eprintln!("[e2e] mining_device_build_secs = {build_secs:.1}");
    eprintln!("[e2e] listener_bind→0x27       = {listener_to_27:.1}s");
    eprintln!("[e2e] total_test_runtime       = {total:.1}s");
    eprintln!("[e2e] last 20 mining_device stderr lines:\n{last20}");
}
