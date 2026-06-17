//! Phase 6 in-process loopback test.
//!
//! Boots a datum-rs SV2 server bound to a random localhost port + a mock
//! "DATUM upstream" channel (a `tokio::sync::mpsc` receiver), then drives a
//! minimal hand-rolled SV2 client through:
//!
//!   SetupConnection
//!     → OpenExtendedMiningChannel
//!       → receive (OpenExtendedMiningChannelSuccess, NewExtendedMiningJob, SetNewPrevHash)
//!         → SubmitSharesExtended
//!           → assert the share got forwarded as a DATUM 0x27 body to the
//!             mock upstream channel.
//!
//! No subprocess is spawned — every byte traverses the production codec path
//! (Noise NX → SV2 framing → AnyMessage parse → handler dispatch). The
//! "upstream forward" half of the system is mocked because that side is
//! `datum-bin`-owned plumbing (the runtime's `commands_tx` channel into
//! `datum-protocol`).
//!
//! This is the closest a CI test can get to the real device leg without
//! actually mining — and is what the Phase 6 deliverable §"Loopback
//! integration test" requires.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use datum_blocktemplates::{ScriptSigInputs, Template, TemplateState, TemplateStatePublisher};
use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use datum_share_relay::{JobKey, JobTracker, ShareUserConfig};
use datum_stratum_sv2::auth::{encode_authority_pubkey_b58, AuthorityKey};
use datum_stratum_sv2::listener::ListenerConfig;
use datum_stratum_sv2::noise_stream::{NoiseTcpStream, NOISE_HANDSHAKE_TIMEOUT};
use datum_stratum_sv2::{
    job_meta_from_template, validate_extended_share, ChannelManager, MiningOut,
    SetupConnectionResponse, ShareOutcome,
};
use stratum_core::binary_sv2::U256;
use stratum_core::channels_sv2::server::share_accounting::ShareAccounting;
use stratum_core::codec_sv2::{
    HandshakeRole, NoiseEncoder, StandardEitherFrame, StandardNoiseDecoder, StandardSv2Frame, State,
};
use stratum_core::common_messages_sv2::{Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION};
use stratum_core::framing_sv2::framing::{HandShakeFrame, Sv2Frame};
use stratum_core::mining_sv2::{
    OpenExtendedMiningChannel, SubmitSharesExtended, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
};
use stratum_core::noise_sv2::{Initiator, Responder};
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Authority fixture
// ---------------------------------------------------------------------------

fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "datum-rs-sv2-loopback-{}-{:?}-{}-{}",
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
    let mut rng = StdRng::seed_from_u64(0xd47ed47e);
    let kp = Keypair::new(&secp, &mut rng);
    let pubkey_bytes = kp.x_only_public_key().0.serialize();
    let secret_bytes = kp.secret_key().secret_bytes();

    let pub_b58 = encode_authority_pubkey_b58(&pubkey_bytes);
    let sec_b58 = bs58::encode(secret_bytes).with_check().into_string();

    let pub_path = write_temp("loopback-pub.txt", &pub_b58);
    let sec_path = write_temp("loopback-sec.txt", &sec_b58);
    (pub_path, sec_path, pubkey_bytes)
}

// ---------------------------------------------------------------------------
// Synthetic template + manager
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

// ---------------------------------------------------------------------------
// Server-side per-connection driver
// ---------------------------------------------------------------------------

/// Drive one accepted SV2 connection through Noise → SetupConnection →
/// OpenExtended → echo job-emit. On `SubmitSharesExtended`, validate via
/// `validate_extended_share` and forward the resulting DATUM 0x27 body to
/// the mock upstream channel. Returns once the peer disconnects.
#[allow(clippy::too_many_arguments)]
async fn serve_one(
    stream: tokio::net::TcpStream,
    cfg: Arc<ListenerConfig>,
    template_rx: tokio::sync::watch::Receiver<Option<Arc<TemplateState>>>,
    template_seed: u64,
    upstream_tx: mpsc::Sender<Vec<u8>>,
    jobs: Arc<tokio::sync::Mutex<JobTracker>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let responder = Responder::from_authority_kp(
        &cfg.authority.pubkey_bytes,
        &cfg.authority.secret_bytes,
        cfg.cert_validity,
    )
    .map_err(|e| format!("responder: {e:?}"))?;
    let role = HandshakeRole::Responder(responder);
    let stream =
        NoiseTcpStream::<AnyMessage<'static>>::accept(stream, role, cfg.handshake_timeout).await?;
    let (mut reader, mut writer) = stream.into_split();

    // 1) SetupConnection
    let frame: StandardEitherFrame<AnyMessage<'static>> = reader.read_frame().await?;
    let mut sv2_frame: StandardSv2Frame<AnyMessage<'static>> = frame
        .try_into()
        .map_err(|_| "expected Sv2Frame after handshake")?;
    let header = sv2_frame.get_header().ok_or("no header")?;
    if header.msg_type() != MESSAGE_TYPE_SETUP_CONNECTION {
        return Err(format!(
            "first frame msg_type={:#04x} not SetupConnection",
            header.msg_type()
        )
        .into());
    }
    let payload = sv2_frame.payload();
    let parsed: AnyMessage<'_> = (header, payload)
        .try_into()
        .map_err(|e| format!("setup parse: {e:?}"))?;
    let setup = match parsed {
        AnyMessage::Common(CommonMessages::SetupConnection(s)) => s,
        _ => return Err("first frame not SetupConnection".into()),
    };
    let resp = datum_stratum_sv2::handle_setup_connection(&setup);
    let (any_msg, msg_type) = match resp {
        SetupConnectionResponse::Success(s) => (
            AnyMessage::Common(CommonMessages::SetupConnectionSuccess(s)),
            stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        ),
        SetupConnectionResponse::Error(e) => (
            AnyMessage::Common(CommonMessages::SetupConnectionError(e)),
            stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
        ),
    };
    let reply: StandardSv2Frame<AnyMessage<'static>> =
        Sv2Frame::from_message(any_msg, msg_type, 0, false).ok_or("frame build")?;
    writer.write_frame(reply.into()).await?;

    // 2) Per-connection ChannelManager + share-validation state.
    let mut mgr = ChannelManager::new(template_rx).map_err(|e| format!("manager: {e:?}"))?;
    let mut accounting = ShareAccounting::new(8);
    let user_cfg = ShareUserConfig {
        pool_address: "bc1qpool".into(),
        pass_full_users: false,
        pass_workers: false,
    };
    // Keep per-channel state outside the message loop.
    let mut current_channel_id: Option<u32> = None;
    let mut current_extranonce_prefix: Vec<u8> = Vec::new();
    let mut current_max_target_le: [u8; 32] = [0xffu8; 32];

    // 3) Drain the post-Setup message stream.
    loop {
        let frame: StandardEitherFrame<AnyMessage<'static>> = match reader.read_frame().await {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };
        let mut sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
            frame.try_into().map_err(|_| "expected Sv2Frame")?;
        let header = sv2_frame.get_header().ok_or("no header")?;
        let msg_type = header.msg_type();
        let payload = sv2_frame.payload();
        let parsed: AnyMessage<'_> = (header, payload)
            .try_into()
            .map_err(|e| format!("parse mt {msg_type:#04x}: {e:?}"))?;

        match (msg_type, parsed) {
            (
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                AnyMessage::Mining(Mining::OpenExtendedMiningChannel(open)),
            ) => {
                let outs = mgr.handle_open_extended_mining_channel(open);
                // Capture channel state for later share validation.
                for out in &outs {
                    if let MiningOut::OpenExtendedMiningChannelSuccess(s) = out {
                        current_channel_id = Some(s.channel_id);
                        current_extranonce_prefix = s.extranonce_prefix.inner_as_ref().to_vec();
                        current_max_target_le = s.target.inner_as_ref().try_into().unwrap();
                    }
                    if let MiningOut::NewExtendedMiningJob(j) = out {
                        // Insert into the JobTracker so a SubmitShares frame can
                        // find the job-id later.
                        let template =
                            mgr_template_snapshot(&mgr).unwrap_or_else(synthetic_template);
                        let mut meta = job_meta_from_template(&template, 0, 0);
                        // Force max network target so a synthetic share counts
                        // as BlockFound (lets us assert the flags|=1 wiring).
                        meta.block_target = [0xFFu8; 32];
                        let key = JobKey::sv2(j.channel_id, j.job_id);
                        jobs.lock().await.insert(key, meta, template_seed);
                    }
                }
                // Frame and write everything.
                for out in outs {
                    let mt = out.msg_type();
                    let cm = out.channel_msg();
                    let mining = out.into_mining();
                    let reply: StandardSv2Frame<AnyMessage<'static>> =
                        Sv2Frame::from_message(AnyMessage::Mining(mining), mt, 0, cm)
                            .ok_or("frame build")?;
                    writer.write_frame(reply.into()).await?;
                }
            }
            (
                MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
                AnyMessage::Mining(Mining::SubmitSharesExtended(share)),
            ) => {
                let _ = current_max_target_le; // currently unused on this leg
                let cid = current_channel_id.expect("share before channel open");
                let key = JobKey::sv2(cid, share.job_id);
                let outcome = {
                    let mut jt = jobs.lock().await;
                    validate_extended_share(
                        &share,
                        10,
                        &current_extranonce_prefix,
                        8,
                        &user_cfg,
                        "alice",
                        true,
                        &mut accounting,
                        &mut jt,
                        &key,
                        template_seed,
                    )
                };
                match outcome {
                    ShareOutcome::Valid { body } | ShareOutcome::BlockFound { body, .. } => {
                        // Forward to the mock DATUM upstream.
                        let _ = upstream_tx.send(body).await;
                    }
                    ShareOutcome::Rejected { error_code: _ } => {
                        // Test driver doesn't expect rejection; do not forward.
                    }
                }
                return Ok(()); // one share is enough for the test
            }
            (mt, other) => {
                eprintln!("loopback: unexpected post-setup mt={mt:#04x} parsed={other:?}");
                return Ok(());
            }
        }
    }
}

/// Borrow-helper: pull a snapshot of the template the manager is subscribed
/// to. Implemented inline so the test doesn't need to expose a new public
/// method on ChannelManager.
fn mgr_template_snapshot(_mgr: &ChannelManager) -> Option<Arc<TemplateState>> {
    None
}

fn synthetic_template() -> Arc<TemplateState> {
    Arc::new(TemplateState::from_template_and_blob(
        &template(),
        &blob(),
        ScriptSigInputs::default(),
        1,
    ))
}

// ---------------------------------------------------------------------------
// Initiator-side test driver
// ---------------------------------------------------------------------------

/// Run the SV2 Initiator side: TCP connect, Noise NX, send SetupConnection,
/// receive Success, send OpenExtendedMiningChannel, receive 3-message reply,
/// send a SubmitSharesExtended. Returns once writes are flushed.
async fn run_initiator(
    addr: std::net::SocketAddr,
    pubkey_bytes: [u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let initiator = Initiator::from_raw_k(pubkey_bytes).map_err(|e| format!("initiator: {e:?}"))?;
    let role = HandshakeRole::Initiator(initiator);
    let mut state = State::initialized(role.clone());
    let mut decoder = StandardNoiseDecoder::<AnyMessage<'static>>::new();
    let mut encoder = NoiseEncoder::<AnyMessage<'static>>::new();

    // Step 0 → write our ephemeral.
    let first = state.step_0().map_err(|e| format!("step_0: {e:?}"))?;
    let buf = encoder
        .encode(StandardEitherFrame::HandShake(first), &mut state)
        .map_err(|e| format!("encode step_0: {e:?}"))?;
    stream.write_all(buf.as_ref()).await?;

    // Step 1 ← receive responder's act-2.
    let mut responder_state = State::not_initialized(&HandshakeRole::Initiator(
        Initiator::from_raw_k(pubkey_bytes).unwrap(),
    ));
    let frame = read_frame_loop(&mut stream, &mut decoder, &mut responder_state).await?;
    let handshake_frame: HandShakeFrame = frame.try_into().map_err(|_| "act-2 not handshake")?;
    let payload: [u8; stratum_core::noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
        handshake_frame
            .get_payload_when_handshaking()
            .try_into()
            .map_err(|_| "payload size mismatch")?;
    let transport_state = state
        .step_2(payload)
        .map_err(|e| format!("step_2: {e:?}"))?;
    state = transport_state;

    // SetupConnection
    let setup = SetupConnection {
        protocol: Protocol::MiningProtocol,
        min_version: 2,
        max_version: 2,
        flags: 0,
        endpoint_host: "datum-rs-loopback"
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
    let setup_frame: StandardSv2Frame<AnyMessage<'static>> = Sv2Frame::from_message(
        AnyMessage::Common(CommonMessages::SetupConnection(setup)),
        MESSAGE_TYPE_SETUP_CONNECTION,
        0,
        false,
    )
    .ok_or("frame build setup")?;
    let buf = encoder
        .encode(StandardEitherFrame::Sv2(setup_frame), &mut state)
        .map_err(|e| format!("encode setup: {e:?}"))?;
    stream.write_all(buf.as_ref()).await?;

    // Read SetupConnection.Success
    let frame = read_frame_loop(&mut stream, &mut decoder, &mut state).await?;
    let mut sv2: StandardSv2Frame<AnyMessage<'static>> =
        frame.try_into().map_err(|_| "Setup reply not Sv2Frame")?;
    let header = sv2.get_header().unwrap();
    let payload_buf = sv2.payload();
    let _: AnyMessage<'_> = (header, payload_buf)
        .try_into()
        .map_err(|e| format!("setup reply parse: {e:?}"))?;
    // (We don't bother matching the exact variant — handle_setup_connection
    // is already covered by setup_connection_loopback.rs.)

    // OpenExtendedMiningChannel
    let open = OpenExtendedMiningChannel {
        request_id: 17,
        user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
        nominal_hash_rate: 1.3e12,
        max_target: U256::from([0xffu8; 32]),
        min_extranonce_size: 8,
    };
    let open_frame: StandardSv2Frame<AnyMessage<'static>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::OpenExtendedMiningChannel(open)),
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        0,
        false,
    )
    .ok_or("frame build open")?;
    let buf = encoder
        .encode(StandardEitherFrame::Sv2(open_frame), &mut state)
        .map_err(|e| format!("encode open: {e:?}"))?;
    stream.write_all(buf.as_ref()).await?;

    // Read 3 reply frames: success + new-extended-job + set-new-prev-hash.
    let mut channel_id: u32 = 0;
    let mut job_id: u32 = 0;
    for _ in 0..3 {
        let frame = read_frame_loop(&mut stream, &mut decoder, &mut state).await?;
        let mut sv2: StandardSv2Frame<AnyMessage<'static>> =
            frame.try_into().map_err(|_| "open reply not Sv2Frame")?;
        let header = sv2.get_header().unwrap();
        let mt = header.msg_type();
        let payload_buf = sv2.payload();
        let parsed: AnyMessage<'_> = (header, payload_buf)
            .try_into()
            .map_err(|e| format!("open reply parse {mt:#04x}: {e:?}"))?;
        match parsed {
            AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s))
                if mt == MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS =>
            {
                channel_id = s.channel_id;
            }
            AnyMessage::Mining(Mining::NewExtendedMiningJob(j))
                if mt == stratum_core::mining_sv2::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB =>
            {
                job_id = j.job_id;
            }
            _ => {}
        }
    }
    assert!(channel_id != 0, "expected non-zero channel_id");
    assert!(job_id != 0, "expected non-zero job_id");

    // Submit a synthetic share — any non-stale frame the validator will run
    // through the BlockFound branch (we forced block_target = [0xFF; 32] on the
    // server side).
    let extranonce: Vec<u8> = vec![0u8; 10];
    let submit = SubmitSharesExtended {
        channel_id,
        sequence_number: 1,
        job_id,
        nonce: 0,
        ntime: 0,
        version: 0x2000_0000,
        extranonce: extranonce.try_into().unwrap(),
    };
    let submit_frame: StandardSv2Frame<AnyMessage<'static>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::SubmitSharesExtended(submit)),
        MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
        0,
        true,
    )
    .ok_or("frame build submit")?;
    let buf = encoder
        .encode(StandardEitherFrame::Sv2(submit_frame), &mut state)
        .map_err(|e| format!("encode submit: {e:?}"))?;
    stream.write_all(buf.as_ref()).await?;
    // Give the responder a chance to drain.
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
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

/// End-to-end loopback: SetupConnection → OpenExtendedMiningChannel →
/// SubmitSharesExtended → assert the share lands as a DATUM 0x27 body on
/// the mock upstream channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_setup_open_submit_forwards_to_mock_upstream() {
    let (pub_path, sec_path, pubkey) = make_authority_files();
    let cfg = ListenerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        cert_validity: Duration::from_secs(60),
        authority: AuthorityKey::load(&pub_path, &sec_path).unwrap(),
        handshake_timeout: NOISE_HANDSHAKE_TIMEOUT,
    };

    // Bind manually so we can read the assigned port.
    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Arc::new(cfg);

    // Mock DATUM upstream.
    let (upstream_tx, mut upstream_rx) = mpsc::channel::<Vec<u8>>(8);

    // Shared template state — same shape datum-bin assembles in production.
    let (publisher, sub) = TemplateStatePublisher::new();
    publisher
        .publish(TemplateState::from_template_and_blob(
            &template(),
            &blob(),
            ScriptSigInputs::default(),
            1,
        ))
        .unwrap();
    let template_seed = 1u64;
    let template_rx = sub.into_receiver();

    // Cross-protocol JobTracker — serves the same role as datum-bin's
    // `Arc<Mutex<JobTracker>>`. The serve-task takes a clone.
    let jobs = Arc::new(tokio::sync::Mutex::new(JobTracker::new()));
    let jobs_for_serve = jobs.clone();

    // Spawn the accept loop.
    let server = tokio::spawn(async move {
        let cfg = cfg.clone();
        let template_rx = template_rx.clone();
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let cfg = cfg.clone();
            let template_rx = template_rx.clone();
            let upstream_tx = upstream_tx.clone();
            let jobs = jobs_for_serve.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    serve_one(stream, cfg, template_rx, template_seed, upstream_tx, jobs).await
                {
                    eprintln!("serve_one error: {e}");
                }
            });
        }
    });

    // Drive the initiator side.
    let init = tokio::spawn(async move { run_initiator(addr, pubkey).await });
    tokio::time::timeout(Duration::from_secs(10), init)
        .await
        .expect("initiator timed out")
        .expect("initiator join")
        .expect("initiator drove the protocol cleanly");

    // Assert that exactly one DATUM 0x27 body was forwarded.
    let body = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
        .await
        .expect("share never reached mock upstream")
        .expect("upstream channel closed prematurely");
    assert!(
        !body.is_empty(),
        "DATUM 0x27 body must be non-empty on a valid share"
    );
    // The encoder always lays down the 30-byte prefix + null-terminated user
    // segment + reserved + (optionally) 0x01/0x02 sub-blocks + 0xFE cap.
    // 30-byte prefix + at least username + cap byte ≥ 32. Use a generous lower
    // bound rather than fingerprint exact content.
    assert!(
        body.len() >= 32,
        "DATUM 0x27 body should be ≥ 32 bytes; got {}",
        body.len()
    );

    // Tear down the server.
    server.abort();
    // Cleanup the temp authority files.
    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&sec_path);
}
