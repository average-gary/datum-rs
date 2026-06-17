//! Gap 1 dispatch integration test.
//!
//! Boots a real production [`Listener`] (not the hand-rolled `serve_one` of
//! `sv2_loopback.rs`) on a random localhost port. Connects an in-process SV2
//! client through Noise NX, and walks:
//!
//!   SetupConnection
//!     -> SetupConnection.Success
//!   OpenExtendedMiningChannel
//!     -> OpenExtendedMiningChannelSuccess + NewExtendedMiningJob + SetNewPrevHash
//!   SubmitSharesExtended
//!     -> assert mock DATUM upstream sees a 0x27 frame
//!   <publisher emits a new TemplateState>
//!     -> assert client receives (NewExtendedMiningJob, SetNewPrevHash) again
//!
//! Every byte traverses the production codec path: `Listener::run` →
//! `handle_connection` → `dispatch_frame` → `ChannelManager` →
//! `validate_extended_share` → bridge into mock upstream channel.
//!
//! Per Gap 1's "Validation" deliverable: this is the automated dispatch test.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use datum_blocktemplates::{ScriptSigInputs, Template, TemplateState, TemplateStatePublisher};
use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use datum_share_relay::{JobTracker, ShareUserConfig};
use datum_stratum_sv2::auth::{encode_authority_pubkey_b58, AuthorityKey};
use datum_stratum_sv2::listener::{ListenerConfig, ListenerRuntime, UpstreamShareCommand};
use datum_stratum_sv2::Listener;
use stratum_core::binary_sv2::{Seq0255, B0255, B064K, U256};
use stratum_core::codec_sv2::{
    HandshakeRole, NoiseEncoder, StandardEitherFrame, StandardNoiseDecoder, StandardSv2Frame, State,
};
use stratum_core::common_messages_sv2::{Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION};
use stratum_core::framing_sv2::framing::{HandShakeFrame, Sv2Frame};
use stratum_core::mining_sv2::{
    OpenExtendedMiningChannel, SetCustomMiningJob, SubmitSharesExtended,
    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_SET_CUSTOM_MINING_JOB, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
};
use stratum_core::noise_sv2::Initiator;
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

// ---------------------------------------------------------------------------
// Authority fixture
// ---------------------------------------------------------------------------

fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "datum-rs-sv2-dispatch-{}-{:?}-{}-{}",
        std::process::id(),
        std::thread::current().id(),
        n,
        name
    ));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path
}

fn make_authority_files() -> (std::path::PathBuf, std::path::PathBuf, [u8; 32]) {
    use secp256k1::{
        rand::{rngs::StdRng, SeedableRng},
        Keypair, Secp256k1,
    };
    let secp = Secp256k1::new();
    // Different seed than sv2_loopback so concurrent test runs don't collide
    // on the (deterministic) keypair fingerprint when building temp paths.
    let mut rng = StdRng::seed_from_u64(0xd15_ba7c_u64);
    let kp = Keypair::new(&secp, &mut rng);
    let pubkey_bytes = kp.x_only_public_key().0.serialize();
    let secret_bytes = kp.secret_key().secret_bytes();

    let pub_b58 = encode_authority_pubkey_b58(&pubkey_bytes);
    let sec_b58 = bs58::encode(secret_bytes).with_check().into_string();

    let pub_path = write_temp("dispatch-pub.txt", &pub_b58);
    let sec_path = write_temp("dispatch-sec.txt", &sec_b58);
    (pub_path, sec_path, pubkey_bytes)
}

// ---------------------------------------------------------------------------
// Synthetic template
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
// In-process initiator (test client)
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

        // Read responder act-2 from the wire using a temporary handshake-only
        // decoder + state. After step_2, the main `state` is in transport mode.
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
            endpoint_host: "datum-rs-dispatch"
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
        let extranonce: Vec<u8> = vec![0u8; 10];
        let submit = SubmitSharesExtended {
            channel_id,
            sequence_number,
            job_id,
            nonce: 0,
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

    /// Send a `SetCustomMiningJob` (msg 0x22) post-Setup. We rejected
    /// `REQUIRES_WORK_SELECTION` at SetupConnection, so a well-behaved peer
    /// would not do this — this simulates a malformed/malicious peer.
    async fn send_set_custom_mining_job(
        &mut self,
        channel_id: u32,
        request_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let token: B0255<'static> = vec![0xAA, 0xBB, 0xCC].try_into().unwrap();
        let coinbase_prefix: B0255<'static> = vec![0x03, 0x10, 0x27, 0x00].try_into().unwrap();
        let coinbase_outputs: B064K<'static> = vec![0u8; 32].try_into().unwrap();
        let merkle_path: Seq0255<'static, U256<'static>> = Seq0255::new(Vec::new()).unwrap();
        let scmj = SetCustomMiningJob {
            channel_id,
            request_id,
            token,
            version: 0x2000_0000,
            prev_hash: U256::from([0u8; 32]),
            min_ntime: 0,
            nbits: 0x1d00_ffff,
            coinbase_tx_version: 1,
            coinbase_prefix,
            coinbase_tx_input_n_sequence: 0xffff_ffff,
            coinbase_tx_outputs: coinbase_outputs,
            coinbase_tx_locktime: 0,
            merkle_path,
        };
        let frame: StandardSv2Frame<AnyMessage<'static>> = Sv2Frame::from_message(
            AnyMessage::Mining(Mining::SetCustomMiningJob(scmj)),
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
            0,
            true,
        )
        .ok_or("scmj build")?;
        let buf = self
            .encoder
            .encode(StandardEitherFrame::Sv2(frame), &mut self.state)
            .map_err(|e| format!("encode scmj: {e:?}"))?;
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

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatch_setup_open_submit_then_template_update() {
    let (pub_path, sec_path, pubkey) = make_authority_files();

    // Mock DATUM upstream — collects every share body the dispatch loop forwards.
    let (upstream_tx, mut upstream_rx) = mpsc::channel::<UpstreamShareCommand>(8);

    // Shared template state — the runtime publishes updates here; both the
    // initial channel-open and the template-update path read from it.
    let (publisher, sub) = TemplateStatePublisher::new();
    publisher.publish(synth_state(1)).unwrap();

    // Cross-protocol JobTracker (shared with SV1 in production). Force
    // block_target = max so any synthetic share lands BlockFound, exercising
    // the flags|=1 + share-relay-forward path.
    let jobs = Arc::new(Mutex::new(JobTracker::new()));

    // Probe a free port — `Listener::bind_with_runtime` does not yet expose
    // its bound `local_addr`, so we use the standard pattern: bind a probe
    // socket to :0, capture its addr, drop it, and immediately re-bind via
    // the production path. The window between drop and re-bind is short
    // enough on 127.0.0.1 that this is reliable in CI.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let cfg = ListenerConfig {
        bind_addr: addr,
        cert_validity: Duration::from_secs(60),
        authority: AuthorityKey::load(&pub_path, &sec_path).unwrap(),
        handshake_timeout: Duration::from_secs(3),
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

    // Drive the initiator.
    let mut client = TestClient::connect(addr, pubkey).await.expect("connect");
    client.send_setup().await.expect("send setup");

    // Read SetupConnection.Success.
    let (mt, msg) = client.read_one().await.expect("setup reply");
    assert_eq!(
        mt,
        stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS
    );
    assert!(matches!(
        msg,
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(_))
    ));

    // OpenExtendedMiningChannel.
    client
        .send_open_extended(7)
        .await
        .expect("send open extended");

    // Expect 3 frames: Success + NewExtendedMiningJob + SetNewPrevHash.
    let mut channel_id: u32 = 0;
    let mut job_id: u32 = 0;
    let mut got_success = false;
    let mut got_new_job = false;
    let mut got_snph = false;
    for _ in 0..3 {
        let (mt, msg) = client.read_one().await.expect("open reply frame");
        match (mt, msg) {
            (
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s)),
            ) => {
                channel_id = s.channel_id;
                got_success = true;
            }
            (
                MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                AnyMessage::Mining(Mining::NewExtendedMiningJob(j)),
            ) => {
                job_id = j.job_id;
                got_new_job = true;
            }
            (
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
                AnyMessage::Mining(Mining::SetNewPrevHash(_)),
            ) => {
                got_snph = true;
            }
            (mt, m) => panic!("unexpected frame mt={mt:#04x} msg={m:?}"),
        }
    }
    assert!(got_success, "expected OpenExtendedMiningChannelSuccess");
    assert!(got_new_job, "expected NewExtendedMiningJob");
    assert!(got_snph, "expected SetNewPrevHash");
    assert!(channel_id != 0, "non-zero channel_id");
    assert!(job_id != 0, "non-zero job_id");

    // Force the registered job's block_target to max so the synthetic share
    // lands as BlockFound — that path exercises share-relay forwarding even
    // with all-zero nonce/ntime.
    {
        let mut jt = jobs.lock().await;
        let key = datum_share_relay::JobKey::sv2(channel_id, job_id);
        if let Some(entry) = jt.get_mut(&key) {
            entry.meta.block_target = [0xFFu8; 32];
        }
    }

    // SubmitSharesExtended.
    client
        .send_submit_extended(channel_id, 1, job_id)
        .await
        .expect("send submit");

    // Assert the mock DATUM upstream sees a 0x27 body within timeout.
    let cmd = tokio::time::timeout(Duration::from_secs(3), upstream_rx.recv())
        .await
        .expect("share never reached mock upstream")
        .expect("upstream channel closed");
    match cmd {
        UpstreamShareCommand::SubmitShare(body) => {
            assert!(
                body.len() >= 32,
                "DATUM 0x27 body too short: {}",
                body.len()
            );
            assert_eq!(body[3] & 0x01, 0x01, "flags|=1 must be set on BlockFound");
        }
    }

    // Drain the SubmitSharesSuccess (BlockFound emits an immediate ack).
    // We don't assert on it explicitly — the dispatch may emit it before or
    // after the upstream send depending on scheduling. Just consume it so
    // the connection stays clean.
    let _ = tokio::time::timeout(Duration::from_millis(500), client.read_one()).await;

    // Now mutate the TemplateState watch and assert the next
    // (NewExtendedMiningJob, SetNewPrevHash) hits the connected client.
    publisher.publish(synth_state(2)).unwrap();
    let mut got_new_job_after = false;
    let mut got_snph_after = false;
    for _ in 0..2 {
        let (mt, msg) = tokio::time::timeout(Duration::from_secs(3), client.read_one())
            .await
            .expect("template-update frame timeout")
            .expect("template-update read");
        match (mt, msg) {
            (
                MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                AnyMessage::Mining(Mining::NewExtendedMiningJob(_)),
            ) => got_new_job_after = true,
            (
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
                AnyMessage::Mining(Mining::SetNewPrevHash(_)),
            ) => got_snph_after = true,
            (mt, m) => panic!("template-update: unexpected frame mt={mt:#04x} msg={m:?}"),
        }
    }
    assert!(
        got_new_job_after,
        "template-update must re-emit NewExtendedMiningJob"
    );
    assert!(
        got_snph_after,
        "template-update must re-emit SetNewPrevHash"
    );

    // Tear down.
    server.abort();
    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&sec_path);
}

/// Gap 2 dispatch integration test: a peer that sends `SetCustomMiningJob`
/// (msg 0x22) post-Setup — even though we rejected `REQUIRES_WORK_SELECTION`
/// at SetupConnection — must NOT panic the per-connection task. Instead the
/// dispatcher replies with a `SetCustomMiningJobError` (msg 0x24,
/// `error_code = "jd-not-supported"`) and the connection stays open.
///
/// Before Gap 2 the defensive `unreachable!()` at the SetCustomMiningJob
/// branch would panic the per-conn task, drop the TCP socket, and the test
/// client below would fail to receive an Sv2 frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatch_set_custom_mining_job_replies_error_keeps_connection_alive() {
    let (pub_path, sec_path, pubkey) = make_authority_files();

    let (upstream_tx, _upstream_rx) = mpsc::channel::<UpstreamShareCommand>(8);

    let (publisher, sub) = TemplateStatePublisher::new();
    publisher.publish(synth_state(1)).unwrap();

    let jobs = Arc::new(Mutex::new(JobTracker::new()));

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let cfg = ListenerConfig {
        bind_addr: addr,
        cert_validity: Duration::from_secs(60),
        authority: AuthorityKey::load(&pub_path, &sec_path).unwrap(),
        handshake_timeout: Duration::from_secs(3),
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

    // Drive the initiator.
    let mut client = TestClient::connect(addr, pubkey).await.expect("connect");
    client.send_setup().await.expect("send setup");

    // Read SetupConnection.Success.
    let (mt, msg) = client.read_one().await.expect("setup reply");
    assert_eq!(
        mt,
        stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS
    );
    assert!(matches!(
        msg,
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(_))
    ));

    // Open an Extended channel so we have a valid `channel_id` to echo in
    // the SetCustomMiningJob.
    client
        .send_open_extended(11)
        .await
        .expect("send open extended");
    let mut channel_id: u32 = 0;
    for _ in 0..3 {
        let (mt, msg) = client.read_one().await.expect("open reply frame");
        if let (
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
            AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s)),
        ) = (mt, msg)
        {
            channel_id = s.channel_id;
        }
    }
    assert!(channel_id != 0, "channel open must succeed");

    // Now send an unsolicited SetCustomMiningJob — simulating a malicious /
    // malformed peer.
    let scmj_request_id = 0x1234_5678u32;
    client
        .send_set_custom_mining_job(channel_id, scmj_request_id)
        .await
        .expect("send SetCustomMiningJob");

    // The server must reply with SetCustomMiningJobError (msg 0x24) — NOT
    // panic, NOT close the socket, NOT silently drop.
    let (mt, msg) = tokio::time::timeout(Duration::from_secs(3), client.read_one())
        .await
        .expect("SetCustomMiningJobError frame timeout — connection task may have panicked")
        .expect("SetCustomMiningJobError read");
    assert_eq!(
        mt, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
        "expected SetCustomMiningJobError msg type 0x24, got {mt:#04x}"
    );
    match msg {
        AnyMessage::Mining(Mining::SetCustomMiningJobError(err)) => {
            assert_eq!(err.channel_id, channel_id, "channel_id must echo back");
            assert_eq!(err.request_id, scmj_request_id, "request_id must echo back");
            assert_eq!(
                err.error_code.inner_as_ref(),
                b"jd-not-supported",
                "error_code must be SRI's ERROR_CODE_SET_CUSTOM_MINING_JOB_JD_NOT_SUPPORTED"
            );
        }
        other => panic!("expected SetCustomMiningJobError, got {other:?}"),
    }

    // Connection must stay alive — drive a TemplateState transition through
    // the publisher and assert we still receive the (NewExtendedMiningJob,
    // SetNewPrevHash) re-emission. If the per-conn task had panicked, the
    // socket would be closed and read_one() would EOF instead of returning
    // a frame.
    publisher.publish(synth_state(2)).unwrap();
    let mut got_new_job_after = false;
    let mut got_snph_after = false;
    for _ in 0..2 {
        let (mt, msg) = tokio::time::timeout(Duration::from_secs(3), client.read_one())
            .await
            .expect("post-SCMJ template-update frame timeout — task panicked?")
            .expect("post-SCMJ template-update read");
        match (mt, msg) {
            (
                MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                AnyMessage::Mining(Mining::NewExtendedMiningJob(_)),
            ) => got_new_job_after = true,
            (
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
                AnyMessage::Mining(Mining::SetNewPrevHash(_)),
            ) => got_snph_after = true,
            (mt, m) => panic!("post-SCMJ unexpected frame mt={mt:#04x} msg={m:?}"),
        }
    }
    assert!(
        got_new_job_after,
        "connection must stay alive: NewExtendedMiningJob expected after SCMJ rejection"
    );
    assert!(
        got_snph_after,
        "connection must stay alive: SetNewPrevHash expected after SCMJ rejection"
    );

    // Server task must still be running (no panic).
    assert!(
        !server.is_finished(),
        "listener accept loop must not have stopped"
    );

    // Tear down.
    server.abort();
    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&sec_path);
}
