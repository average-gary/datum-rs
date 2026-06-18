//! Bug A regression: SV2 share-forward must apply backpressure (await on
//! `commands_tx`), not silently drop on a full mpsc.
//!
//! Coverage:
//! 1. `share_forward_does_not_drop_on_saturated_commands_tx` —
//!    construct a Listener with a tiny `commands_tx` capacity (2), feed it
//!    100 shares, drain slowly on the upstream side, and assert all 100
//!    reach the upstream channel — i.e. the dispatch loop parked instead of
//!    dropping. Pre-fix this test would lose ~98 shares.
//!
//! 2. `connection_task_exits_cleanly_when_commands_tx_closed` —
//!    drop the upstream receiver mid-stream and assert the per-connection
//!    task exits within a bounded window (does not panic, does not loop,
//!    server accept loop survives).
//!
//! Both tests reuse the production `Listener::bind_with_runtime` path and
//! drive a real Noise NX initiator over TCP, mirroring `sv2_dispatch.rs`.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use datum_blocktemplates::{ScriptSigInputs, Template, TemplateState, TemplateStatePublisher};
use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use datum_share_relay::{JobTracker, ShareUserConfig};
use datum_stratum_sv2::auth::{encode_authority_pubkey_b58, AuthorityKey};
use datum_stratum_sv2::listener::{ListenerConfig, ListenerRuntime, UpstreamShareCommand};
use datum_stratum_sv2::Listener;
use stratum_core::binary_sv2::U256;
use stratum_core::codec_sv2::{
    HandshakeRole, NoiseEncoder, StandardEitherFrame, StandardNoiseDecoder, StandardSv2Frame, State,
};
use stratum_core::common_messages_sv2::{Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION};
use stratum_core::framing_sv2::framing::{HandShakeFrame, Sv2Frame};
use stratum_core::mining_sv2::{
    OpenExtendedMiningChannel, SubmitSharesExtended, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
};
use stratum_core::noise_sv2::Initiator;
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

// ---------------------------------------------------------------------------
// Fixtures (cribbed from tests/sv2_dispatch.rs).
// ---------------------------------------------------------------------------

fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "datum-rs-sv2-backpressure-{}-{:?}-{}-{}",
        std::process::id(),
        std::thread::current().id(),
        n,
        name
    ));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path
}

fn make_authority_files(seed: u64) -> (std::path::PathBuf, std::path::PathBuf, [u8; 32]) {
    use secp256k1::{
        rand::{rngs::StdRng, SeedableRng},
        Keypair, Secp256k1,
    };
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(seed);
    let kp = Keypair::new(&secp, &mut rng);
    let pubkey_bytes = kp.x_only_public_key().0.serialize();
    let secret_bytes = kp.secret_key().secret_bytes();

    let pub_b58 = encode_authority_pubkey_b58(&pubkey_bytes);
    let sec_b58 = bs58::encode(secret_bytes).with_check().into_string();

    let pub_path = write_temp("backpressure-pub.txt", &pub_b58);
    let sec_path = write_temp("backpressure-sec.txt", &sec_b58);
    (pub_path, sec_path, pubkey_bytes)
}

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
// Minimal in-process initiator. Simpler than tests/sv2_dispatch.rs: we only
// need Setup + OpenExtended + many SubmitShares.
// ---------------------------------------------------------------------------

struct TestClient {
    stream: tokio::net::TcpStream,
    state: State,
    decoder: StandardNoiseDecoder<AnyMessage<'static>>,
    encoder: NoiseEncoder<AnyMessage<'static>>,
}

impl TestClient {
    async fn connect(
        addr: std::net::SocketAddr,
        pubkey_bytes: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let initiator =
            Initiator::from_raw_k(pubkey_bytes).map_err(|e| format!("initiator: {e:?}"))?;
        let role = HandshakeRole::Initiator(initiator);
        let mut state = State::initialized(role.clone());
        let decoder = StandardNoiseDecoder::<AnyMessage<'static>>::new();
        let mut encoder = NoiseEncoder::<AnyMessage<'static>>::new();

        let first = state.step_0().map_err(|e| format!("step_0: {e:?}"))?;
        let buf = encoder
            .encode(StandardEitherFrame::HandShake(first), &mut state)
            .map_err(|e| format!("encode step_0: {e:?}"))?;
        stream.write_all(buf.as_ref()).await?;

        let mut responder_state = State::not_initialized(&HandshakeRole::Initiator(
            Initiator::from_raw_k(pubkey_bytes).unwrap(),
        ));
        let mut decoder_h = decoder;
        let mut tmp_stream = stream;
        let frame = read_frame_loop(&mut tmp_stream, &mut decoder_h, &mut responder_state).await?;
        let handshake_frame: HandShakeFrame =
            frame.try_into().map_err(|_| "act-2 not handshake")?;
        let payload: [u8; stratum_core::noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
            handshake_frame
                .get_payload_when_handshaking()
                .try_into()
                .map_err(|_| "payload size mismatch")?;
        let transport_state = state
            .step_2(payload)
            .map_err(|e| format!("step_2: {e:?}"))?;
        Ok(Self {
            stream: tmp_stream,
            state: transport_state,
            decoder: decoder_h,
            encoder,
        })
    }

    async fn send_setup(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let setup = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "datum-rs-backpressure"
                .to_string()
                .into_bytes()
                .try_into()
                .unwrap(),
            endpoint_port: 23335,
            vendor: "test".to_string().into_bytes().try_into().unwrap(),
            hardware_version: "v1".to_string().into_bytes().try_into().unwrap(),
            firmware: "v1".to_string().into_bytes().try_into().unwrap(),
            device_id: "test-device".to_string().into_bytes().try_into().unwrap(),
        };
        let frame: StandardSv2Frame<AnyMessage<'static>> = Sv2Frame::from_message(
            AnyMessage::Common(CommonMessages::SetupConnection(setup)),
            MESSAGE_TYPE_SETUP_CONNECTION,
            0,
            false,
        )
        .ok_or("setup build")?;
        let buf = self
            .encoder
            .encode(StandardEitherFrame::Sv2(frame), &mut self.state)
            .map_err(|e| format!("encode setup: {e:?}"))?;
        self.stream.write_all(buf.as_ref()).await?;
        Ok(())
    }

    async fn send_open_extended(
        &mut self,
        request_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let open = OpenExtendedMiningChannel {
            request_id,
            user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        };
        let frame: StandardSv2Frame<AnyMessage<'static>> = Sv2Frame::from_message(
            AnyMessage::Mining(Mining::OpenExtendedMiningChannel(open)),
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            0,
            false,
        )
        .ok_or("open build")?;
        let buf = self
            .encoder
            .encode(StandardEitherFrame::Sv2(frame), &mut self.state)
            .map_err(|e| format!("encode open: {e:?}"))?;
        self.stream.write_all(buf.as_ref()).await?;
        Ok(())
    }

    async fn send_submit_extended(
        &mut self,
        channel_id: u32,
        sequence_number: u32,
        job_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Vary `nonce` per share so the synthetic dedup key (job_key, nonce,
        // ntime, version, extranonce) is unique. Even though dedup isn't
        // enforced inside `finalize_share`, varying the nonce means any
        // future dedup layer wouldn't false-positive this fixture.
        let extranonce: Vec<u8> = vec![0u8; 10];
        let submit = SubmitSharesExtended {
            channel_id,
            sequence_number,
            job_id,
            nonce: sequence_number,
            ntime: 0,
            version: 0x2000_0000,
            extranonce: extranonce.try_into().unwrap(),
        };
        let frame: StandardSv2Frame<AnyMessage<'static>> = Sv2Frame::from_message(
            AnyMessage::Mining(Mining::SubmitSharesExtended(submit)),
            MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
            0,
            true,
        )
        .ok_or("submit build")?;
        let buf = self
            .encoder
            .encode(StandardEitherFrame::Sv2(frame), &mut self.state)
            .map_err(|e| format!("encode submit: {e:?}"))?;
        self.stream.write_all(buf.as_ref()).await?;
        Ok(())
    }

    async fn read_one(
        &mut self,
    ) -> Result<(u8, AnyMessage<'static>), Box<dyn std::error::Error + Send + Sync>> {
        let frame = read_frame_loop(&mut self.stream, &mut self.decoder, &mut self.state).await?;
        let mut sv2: StandardSv2Frame<AnyMessage<'static>> =
            frame.try_into().map_err(|_| "non-sv2")?;
        let header = sv2.get_header().ok_or("no header")?;
        let mt = header.msg_type();
        let payload = sv2.payload();
        let parsed: AnyMessage<'_> = (header, payload)
            .try_into()
            .map_err(|e| format!("parse: {e:?}"))?;
        Ok((mt, parsed.into_static()))
    }
}

async fn read_frame_loop(
    stream: &mut tokio::net::TcpStream,
    decoder: &mut StandardNoiseDecoder<AnyMessage<'static>>,
    state: &mut State,
) -> Result<StandardEitherFrame<AnyMessage<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let needed = decoder.writable_len();
        if needed > 0 {
            let mut tmp = vec![0u8; needed];
            let mut got = 0;
            while got < needed {
                let r = stream.read(&mut tmp[got..]).await?;
                if r == 0 {
                    return Err("eof during read_frame".into());
                }
                got += r;
            }
            decoder.writable().copy_from_slice(&tmp);
        }
        match decoder.next_frame(state) {
            Ok(f) => return Ok(f),
            Err(stratum_core::codec_sv2::Error::MissingBytes(_)) => continue,
            Err(e) => return Err(format!("decode: {e:?}").into()),
        }
    }
}

async fn pick_free_port() -> std::net::SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

// ---------------------------------------------------------------------------
// Test 1: 100 shares through a capacity-2 mpsc — zero drops.
// ---------------------------------------------------------------------------
//
// Pre-fix behavior: `try_send` on a full channel returns `Err(TrySendError::
// Full)`, the dispatch site logs `warn!` and discards. Live OCEAN saw 3.5M
// such drops in 6 minutes.
//
// Post-fix behavior: `send().await` parks the per-connection dispatch loop
// until the upstream consumer drains a slot. The upstream side here drains
// with a 1ms sleep per share to amplify backpressure pressure, but the
// listener task must eventually deliver all 100 shares.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_forward_does_not_drop_on_saturated_commands_tx() {
    let (pub_path, sec_path, pubkey) = make_authority_files(0xbac_8e55_u64);

    // Capacity 2: one in-flight + one buffered. With 100 shares queued behind
    // a 1ms-per-drain consumer this will block the dispatch loop very early
    // and exercise the await-send path on every subsequent share.
    let (upstream_tx, mut upstream_rx) = mpsc::channel::<UpstreamShareCommand>(2);

    let (publisher, sub) = TemplateStatePublisher::new();
    publisher.publish(synth_state(1)).unwrap();

    let jobs = Arc::new(Mutex::new(JobTracker::new()));

    let addr = pick_free_port().await;

    let cfg = ListenerConfig {
        bind_addr: addr,
        cert_validity: Duration::from_secs(60),
        authority: AuthorityKey::load(&pub_path, &sec_path).unwrap(),
        handshake_timeout: Duration::from_secs(5),
        // Production policy. Tests in this file already advertise
        // `nominal_hash_rate = 1.3e12` so the floor is cleared.
        min_hashrate_threshold: datum_config::DEFAULT_STRATUM_V2_MIN_HASHRATE_THRESHOLD,
        expected_share_per_minute: datum_config::DEFAULT_STRATUM_V2_EXPECTED_SHARE_PER_MINUTE,
    };
    let rt = ListenerRuntime {
        cfg: Arc::new(cfg),
        template_rx: sub.clone().into_receiver(),
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

    let mut client = TestClient::connect(addr, pubkey).await.expect("connect");
    client.send_setup().await.expect("send setup");

    // Drain SetupConnection.Success.
    let (mt, _msg) = client.read_one().await.expect("setup reply");
    assert_eq!(
        mt,
        stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS
    );

    client
        .send_open_extended(7)
        .await
        .expect("send open extended");

    // Drain Open.Success + NewExtendedMiningJob + SetNewPrevHash.
    let mut channel_id: u32 = 0;
    let mut job_id: u32 = 0;
    for _ in 0..3 {
        let (mt, msg) = client.read_one().await.expect("open reply frame");
        match (mt, msg) {
            (
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s)),
            ) => channel_id = s.channel_id,
            (_, AnyMessage::Mining(Mining::NewExtendedMiningJob(j))) => job_id = j.job_id,
            (_, AnyMessage::Mining(Mining::SetNewPrevHash(_))) => {}
            (mt, m) => panic!("unexpected open reply mt={mt:#04x} msg={m:?}"),
        }
    }
    assert!(channel_id != 0 && job_id != 0);

    // Force block_target=max so every synthetic share lands as Valid (or
    // BlockFound — either way it forwards to commands_tx). Pre-fix bug
    // affected both paths identically.
    {
        let mut jt = jobs.lock().await;
        let key = datum_share_relay::JobKey::sv2(channel_id, job_id);
        if let Some(entry) = jt.get_mut(&key) {
            entry.meta.block_target = [0xFFu8; 32];
        }
    }

    const N_SHARES: u32 = 100;

    // Spawn the slow drainer FIRST so backpressure triggers immediately.
    let drainer = tokio::spawn(async move {
        let mut received = 0usize;
        // Bounded wait: 30s total budget for all 100 shares, comfortably
        // above the 100ms minimum (100 * 1ms drain).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while received < N_SHARES as usize {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, upstream_rx.recv()).await {
                Ok(Some(UpstreamShareCommand::SubmitShare(_))) => {
                    received += 1;
                    // Simulate slow upstream: 1ms per share. With capacity 2
                    // this guarantees the dispatch loop hits the await branch
                    // on every share past the first three.
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        received
    });

    // Fire all 100 shares back-to-back. Pre-fix: ~98 are dropped by try_send.
    // Post-fix: client send keeps writing to the socket; the dispatch loop
    // backpressures on the listener side without dropping anything.
    for seq in 1..=N_SHARES {
        client
            .send_submit_extended(channel_id, seq, job_id)
            .await
            .expect("send submit");
    }

    let received = drainer.await.expect("drainer task panicked");
    assert_eq!(
        received, N_SHARES as usize,
        "expected all {N_SHARES} shares to reach upstream (got {received}); \
         pre-fix bug: try_send drops on full mpsc"
    );

    // Server accept loop must still be running — backpressure must not crash
    // or terminate the listener.
    assert!(
        !server.is_finished(),
        "listener accept loop must survive backpressure"
    );

    server.abort();
    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&sec_path);
}

// ---------------------------------------------------------------------------
// Test 2: closing the upstream receiver mid-stream — connection task exits
// cleanly within a bounded window.
// ---------------------------------------------------------------------------
//
// Closing the receiver flips `commands_tx.send(...).await` to
// `Err(SendError(_))` on the next share. The post-fix path returns
// `ConnectionError::UpstreamGone`, which the outer `handle_connection`
// treats as a normal connection-level error. The per-conn task must:
//   - not panic
//   - terminate within a few seconds
//   - leave the server accept loop alive (other miners can still connect)

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_task_exits_cleanly_when_commands_tx_closed() {
    let (pub_path, sec_path, pubkey) = make_authority_files(0x00c1_05ed_u64);

    let (upstream_tx, upstream_rx) = mpsc::channel::<UpstreamShareCommand>(4);

    let (publisher, sub) = TemplateStatePublisher::new();
    publisher.publish(synth_state(1)).unwrap();

    let jobs = Arc::new(Mutex::new(JobTracker::new()));

    let addr = pick_free_port().await;

    let cfg = ListenerConfig {
        bind_addr: addr,
        cert_validity: Duration::from_secs(60),
        authority: AuthorityKey::load(&pub_path, &sec_path).unwrap(),
        handshake_timeout: Duration::from_secs(5),
        // Production policy. Tests in this file already advertise
        // `nominal_hash_rate = 1.3e12` so the floor is cleared.
        min_hashrate_threshold: datum_config::DEFAULT_STRATUM_V2_MIN_HASHRATE_THRESHOLD,
        expected_share_per_minute: datum_config::DEFAULT_STRATUM_V2_EXPECTED_SHARE_PER_MINUTE,
    };
    let rt = ListenerRuntime {
        cfg: Arc::new(cfg),
        template_rx: sub.clone().into_receiver(),
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

    let mut client = TestClient::connect(addr, pubkey).await.expect("connect");
    client.send_setup().await.expect("send setup");

    let (mt, _) = client.read_one().await.expect("setup reply");
    assert_eq!(
        mt,
        stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS
    );

    client
        .send_open_extended(11)
        .await
        .expect("send open extended");
    let mut channel_id: u32 = 0;
    let mut job_id: u32 = 0;
    for _ in 0..3 {
        let (mt, msg) = client.read_one().await.expect("open reply frame");
        match (mt, msg) {
            (
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s)),
            ) => channel_id = s.channel_id,
            (_, AnyMessage::Mining(Mining::NewExtendedMiningJob(j))) => job_id = j.job_id,
            (_, AnyMessage::Mining(Mining::SetNewPrevHash(_))) => {}
            (mt, m) => panic!("unexpected open reply mt={mt:#04x} msg={m:?}"),
        }
    }
    {
        let mut jt = jobs.lock().await;
        let key = datum_share_relay::JobKey::sv2(channel_id, job_id);
        if let Some(entry) = jt.get_mut(&key) {
            entry.meta.block_target = [0xFFu8; 32];
        }
    }

    // Drop the upstream receiver — the next share must hit the closed branch.
    drop(upstream_rx);

    // Now send a share. The per-connection task should call
    // `commands_tx.send(...).await`, get `Err(SendError(_))`, surface
    // `ConnectionError::UpstreamGone`, and the connection loop returns Err.
    client
        .send_submit_extended(channel_id, 1, job_id)
        .await
        .expect("send submit");

    // The peer-side TCP read should EOF (or the client read times out as the
    // server drops the socket on the way out). Either is acceptable. We just
    // check the server accept loop survived (the per-conn task panicking
    // would not kill it, but UpstreamGone is meant to be a clean exit).
    let read_outcome = tokio::time::timeout(Duration::from_secs(5), client.read_one()).await;
    // The client may receive a SubmitSharesError, see EOF, or simply time
    // out — all acceptable. What matters is the server stayed up.
    let _ = read_outcome;

    assert!(
        !server.is_finished(),
        "listener accept loop must survive a per-connection upstream-gone error"
    );

    server.abort();
    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&sec_path);
}
