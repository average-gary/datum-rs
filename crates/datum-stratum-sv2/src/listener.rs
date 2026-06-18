//! SV2 Noise listener.
//!
//! Binds a `tokio::net::TcpListener` and runs a Noise NX handshake per
//! [SV2 Noise Handshake](https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md)
//! against each accepted connection. Once the handshake completes, the
//! listener reads the first SV2 frame, expects a `SetupConnection`, and replies
//! with `SetupConnection.Success` or `SetupConnection.Error`. After
//! `SetupConnection.Success` the per-connection task enters a `select!` loop
//! that:
//!
//! - decodes the next post-Setup SV2 frame and dispatches Mining messages to
//!   the per-connection [`ChannelManager`] (Open/Close/Update/Submit handlers);
//! - awaits [`TemplateState`] updates from the shared watch channel and
//!   re-emits `(NewMiningJob | NewExtendedMiningJob, SetNewPrevHash)` to every
//!   open channel via [`ChannelManager::on_template_update`];
//! - awaits the shutdown signal so `datum-bin` can drain in-flight Noise
//!   handshakes on Ctrl-C.
//!
//! ## Cert lifecycle
//! `noise_sv2::Responder::from_authority_kp(public, private, cert_validity)`
//! signs a fresh server static key with the authority key on construction.
//! The signed cert (`version=0 || valid_from || not_valid_after || sig`) is
//! recomputed inside `Responder::step_1` per-connection: SRI sets
//! `valid_from = now`, `not_valid_after = now + cert_validity` (saturating
//! u32 add — see SRI #2103, why we cap config input).
//!
//! ## Authority pubkey publication
//! At startup we log the base58check authority pubkey
//! (`bs58check([0x01,0x00] || pubkey[32])`) so the operator can pin it in
//! the miner config. See [`crate::auth::encode_authority_pubkey_b58`].
//!
//! ## Share-relay
//! Each connection holds a clone of the runtime's `commands_tx` (the
//! `datum_protocol::UpstreamCommand` channel that feeds the DATUM upstream
//! 0x27 share submitter). When [`crate::share_path::validate_extended_share`]
//! / [`crate::share_path::validate_standard_share`] returns
//! `ShareOutcome::Valid` or `ShareOutcome::BlockFound` the body is forwarded
//! verbatim — the SV1 share-relay shape, byte-identical.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use datum_blocktemplates::TemplateState;
use datum_share_relay::{JobKey, JobTracker, ShareUserConfig};
use stratum_core::channels_sv2::server::share_accounting::ShareAccounting;
use stratum_core::codec_sv2::{HandshakeRole, StandardEitherFrame, StandardSv2Frame};
use stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION;
use stratum_core::framing_sv2::framing::Sv2Frame;
use stratum_core::mining_sv2::{
    ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID, MESSAGE_TYPE_CLOSE_CHANNEL,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_SET_CUSTOM_MINING_JOB, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
    MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_UPDATE_CHANNEL,
};
use stratum_core::noise_sv2::Responder;
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining, ParserError};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::auth::AuthorityKey;
use crate::channel_manager::{ChannelManager, MiningOut};
use crate::noise_stream::{NoiseStreamError, NoiseTcpStream, NOISE_HANDSHAKE_TIMEOUT};
use crate::setup_connection::{handle_setup_connection, SetupConnectionResponse};
use crate::share_path::{
    build_submit_shares_error, build_submit_shares_success, handle_set_custom_mining_job,
    handle_update_channel, validate_extended_share, validate_standard_share, ShareOutcome,
};

/// Outbound DATUM `0x27` share submission. Mirrors
/// `datum_protocol::UpstreamCommand::SubmitShare(Vec<u8>)` without forcing the
/// SV2 crate to depend on `datum-protocol` — `datum-bin` adapts on its side.
#[derive(Debug, Clone)]
pub enum UpstreamShareCommand {
    SubmitShare(Vec<u8>),
}

/// Optional callback the listener invokes whenever a share's hash meets the
/// network target. `datum-bin` plumbs in a closure that spawns a
/// `datum_submitblock::BlockSubmitter::submit` call. Held as a trait object so
/// this crate stays free of the bitcoind RPC dependency.
pub type BlockFoundCallback =
    Arc<dyn Fn(datum_share_relay::BlockSubmissionPayload) + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid authority key: {0}")]
    Authority(#[from] crate::auth::AuthorityKeyError),
    /// SRI's `noise_sv2::Error` doesn't impl `Display` on this rev — surface
    /// the variant via `Debug` instead. Re-check at each SRI minor bump.
    #[error("noise responder: {0:?}")]
    Responder(stratum_core::noise_sv2::Error),
}

/// Configuration for an SV2 listener task. Built once at startup from
/// `cfg.stratum_v2`.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub bind_addr: SocketAddr,
    pub cert_validity: Duration,
    pub authority: AuthorityKey,
    pub handshake_timeout: Duration,
    /// Minimum supported downstream hashrate, in H/s. `OpenChannel` and
    /// `UpdateChannel` requests with `nominal_hash_rate < min_hashrate_threshold`
    /// are rejected. The same value drives the SetTarget clamp ceiling.
    /// See live-OCEAN bug B (2026-06-16) and
    /// [`datum_config::DEFAULT_STRATUM_V2_MIN_HASHRATE_THRESHOLD`].
    pub min_hashrate_threshold: f64,
    /// Per-channel target shares-per-minute. Drives `min_target_le` from
    /// `min_hashrate_threshold` via SRI's `hash_rate_to_target`.
    pub expected_share_per_minute: f32,
}

impl ListenerConfig {
    pub fn from_datum_config(cfg: &datum_config::StratumV2Config) -> Result<Self, ListenerError> {
        let listen_addr = if cfg.listen_addr.is_empty() {
            datum_config::DEFAULT_STRATUM_V2_LISTEN_ADDR.to_string()
        } else {
            cfg.listen_addr.clone()
        };
        let bind_addr: SocketAddr = format!("{listen_addr}:{}", cfg.listen_port)
            .parse()
            .map_err(|_| ListenerError::Bind {
                addr: ([0, 0, 0, 0], cfg.listen_port).into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stratum_v2.listen_addr/listen_port",
                ),
            })?;
        let authority = AuthorityKey::load(&cfg.authority_pubkey_path, &cfg.authority_secret_path)?;
        Ok(Self {
            bind_addr,
            cert_validity: Duration::from_secs(cfg.cert_validity_sec as u64),
            authority,
            handshake_timeout: NOISE_HANDSHAKE_TIMEOUT,
            min_hashrate_threshold: cfg.min_hashrate_threshold,
            expected_share_per_minute: cfg.expected_share_per_minute,
        })
    }
}

/// Per-connection runtime context. Cheap to clone (everything inside is
/// `Arc` / channel-handle / config-by-value) so the accept loop can hand a
/// clone to each spawned task.
#[derive(Clone)]
pub struct ListenerRuntime {
    pub cfg: Arc<ListenerConfig>,
    pub template_rx: watch::Receiver<Option<Arc<TemplateState>>>,
    pub commands_tx: mpsc::Sender<UpstreamShareCommand>,
    pub jobs: Arc<tokio::sync::Mutex<JobTracker>>,
    pub user_cfg: ShareUserConfig,
    pub block_found: Option<BlockFoundCallback>,
}

/// Bind + accept loop. Runs until the listener errors fatally; panics in a
/// per-connection task do not bring down the listener.
pub struct Listener {
    rt: ListenerRuntime,
    inner: TcpListener,
}

impl Listener {
    /// Bind without per-connection runtime — kept for callers that only want
    /// the Noise+SetupConnection path (legacy Phase 1-3 entry point). New
    /// callers should use [`Listener::bind_with_runtime`].
    pub async fn bind(cfg: ListenerConfig) -> Result<Self, ListenerError> {
        // Construct a runtime with disconnected, no-op channels. The dispatch
        // loop still works (template-update path is gated on `borrow()`),
        // shares are routed to a closed mpsc and silently dropped — matches
        // the pre-Gap-1 behavior.
        let (publisher, sub) = datum_blocktemplates::TemplateStatePublisher::new();
        // Drop the publisher so the receiver only ever sees `None`. The
        // borrow is still safe.
        drop(publisher);
        let (tx, _rx) = mpsc::channel(1);
        let rt = ListenerRuntime {
            cfg: Arc::new(cfg),
            template_rx: sub.into_receiver(),
            commands_tx: tx,
            jobs: Arc::new(tokio::sync::Mutex::new(JobTracker::new())),
            user_cfg: ShareUserConfig {
                pool_address: String::new(),
                pass_full_users: false,
                pass_workers: false,
            },
            block_found: None,
        };
        Self::bind_with_runtime(rt).await
    }

    /// Bind with a fully-wired per-connection runtime.
    pub async fn bind_with_runtime(rt: ListenerRuntime) -> Result<Self, ListenerError> {
        let inner = TcpListener::bind(rt.cfg.bind_addr)
            .await
            .map_err(|e| ListenerError::Bind {
                addr: rt.cfg.bind_addr,
                source: e,
            })?;
        info!(
            sv2_addr = %rt.cfg.bind_addr,
            cert_validity_sec = rt.cfg.cert_validity.as_secs(),
            authority_pubkey_b58 = %rt.cfg.authority.pubkey_b58,
            "sv2 stratum listener bound"
        );
        Ok(Self { rt, inner })
    }

    /// Run the accept loop. Each accepted TCP connection spawns a per-conn
    /// task that runs Noise + SetupConnection + post-Setup dispatch; the loop
    /// itself never blocks on a slow client.
    pub async fn run(self) {
        // Headless mode (no shutdown signal). Used by tests + legacy callers.
        let (_tx, rx) = tokio::sync::watch::channel(false);
        self.run_with_shutdown(rx).await;
    }

    /// Run the accept loop until `shutdown_rx` flips to `true`.
    pub async fn run_with_shutdown(self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        loop {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    let stop = changed.is_err() || *shutdown_rx.borrow();
                    if stop {
                        info!(sv2_addr = %self.rt.cfg.bind_addr, "sv2 stratum listener shutting down");
                        return;
                    }
                }
                accept = self.inner.accept() => match accept {
                    Ok((stream, peer)) => {
                        debug!(%peer, "sv2: connection accepted");
                        let rt = self.rt.clone();
                        let conn_shutdown = shutdown_rx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, rt, conn_shutdown).await {
                                warn!(%peer, error = %e, "sv2: connection ended with error");
                            } else {
                                debug!(%peer, "sv2: connection closed");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "sv2: accept failed");
                        // Brief backoff to avoid spinning on a permanently-broken
                        // listener (e.g. fd exhaustion).
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

#[derive(Debug, Error)]
enum ConnectionError {
    #[error("noise stream: {0}")]
    Noise(#[from] NoiseStreamError),
    #[error("expected SetupConnection (msg_type=0x00) as first frame; got msg_type={got:#04x}")]
    UnexpectedFirstFrame { got: u8 },
    #[error("encoded frame too large for {kind}")]
    FrameBuild { kind: &'static str },
    #[error("frame parse: {0:?}")]
    Parse(ParserError),
    /// `commands_tx` (the DATUM upstream sender) returned `SendError`,
    /// meaning the upstream task has terminated. This per-connection task
    /// cannot continue forwarding shares — drop the socket so the miner
    /// reconnects (and, if datum-bin reconnects to the upstream, lands on a
    /// healthy share-relay).
    #[error("DATUM upstream commands_tx closed")]
    UpstreamGone,
}

/// Per-connection driver. Returns `Ok(())` on a clean close (after Setup
/// reply / shutdown), or `Err(_)` on protocol/IO errors.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    rt: ListenerRuntime,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), ConnectionError> {
    // Build the responder fresh per-connection so each handshake gets a new
    // ephemeral keypair (Noise NX requirement). The authority keypair is
    // shared across connections.
    let responder = Responder::from_authority_kp(
        &rt.cfg.authority.pubkey_bytes,
        &rt.cfg.authority.secret_bytes,
        rt.cfg.cert_validity,
    )
    .map_err(|_| ConnectionError::Noise(NoiseStreamError::HandshakeRemoteInvalidMessage))?;
    let role = HandshakeRole::Responder(responder);

    let stream =
        NoiseTcpStream::<AnyMessage<'static>>::accept(stream, role, rt.cfg.handshake_timeout)
            .await?;
    let (mut reader, mut writer) = stream.into_split();

    // First post-handshake frame must be SetupConnection.
    let frame: StandardEitherFrame<AnyMessage<'static>> = reader.read_frame().await?;
    let mut sv2_frame: StandardSv2Frame<AnyMessage<'static>> = frame
        .try_into()
        .map_err(|_| ConnectionError::UnexpectedFirstFrame { got: 0xff })?;
    let header = sv2_frame
        .get_header()
        .expect("Sv2Frame always has a header");
    let msg_type = header.msg_type();
    if msg_type != MESSAGE_TYPE_SETUP_CONNECTION {
        return Err(ConnectionError::UnexpectedFirstFrame { got: msg_type });
    }
    let payload = sv2_frame.payload();
    let parsed: AnyMessage<'_> = (header, payload)
        .try_into()
        .map_err(ConnectionError::Parse)?;
    let setup_msg = match parsed {
        AnyMessage::Common(CommonMessages::SetupConnection(s)) => s,
        other => {
            warn!(
                ?other,
                "sv2: first frame parsed but was not SetupConnection"
            );
            return Err(ConnectionError::UnexpectedFirstFrame { got: msg_type });
        }
    };

    let response = handle_setup_connection(&setup_msg);
    let setup_ok = matches!(response, SetupConnectionResponse::Success(_));
    let (any_msg, response_msg_type) = match response {
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
        Sv2Frame::from_message(any_msg, response_msg_type, 0, false).ok_or(
            ConnectionError::FrameBuild {
                kind: "SetupConnection.Reply",
            },
        )?;
    writer.write_frame(reply.into()).await?;

    if !setup_ok {
        // Spec: after SetupConnection.Error the connection should be closed.
        debug!("sv2: SetupConnection rejected; closing connection");
        return Ok(());
    }

    info!("sv2: SetupConnection.Success sent; entering dispatch loop");

    // Per-connection state. The hashrate policy fields on the listener
    // config flow through to every channel: rejection at OpenChannel /
    // UpdateChannel and clamping at every SetTarget emission site.
    let mut mgr = ChannelManager::with_policy(
        rt.template_rx.clone(),
        rt.cfg.min_hashrate_threshold,
        rt.cfg.expected_share_per_minute,
    )
    .map_err(|e| {
        warn!(error = ?e, "sv2: ChannelManager init failed");
        ConnectionError::FrameBuild {
            kind: "ChannelManager",
        }
    })?;
    // ShareAccounting batch size 8 mirrors the SRI default; configurable via
    // future cfg.stratum_v2.share_batch_size.
    let mut accounting = ShareAccounting::new(8);
    let mut template_rx = rt.template_rx.clone();

    // Dispatch loop. Three select arms:
    //   1. next decoded SV2 frame
    //   2. TemplateState updates (re-emit jobs to all channels)
    //   3. shutdown signal
    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    debug!("sv2: connection shutdown signalled; closing");
                    return Ok(());
                }
            }
            tch = template_rx.changed() => {
                if tch.is_err() {
                    // Publisher dropped — nothing more to push. Keep serving
                    // existing frames so the miner closes us, not vice versa.
                    continue;
                }
                let snapshot = template_rx.borrow_and_update().clone();
                if let Some(state) = snapshot {
                    let outs = mgr.on_template_update(&state);
                    for out in outs {
                        write_mining_frame(&mut writer, out).await?;
                    }
                }
            }
            frame = reader.read_frame() => {
                let frame = match frame {
                    Ok(f) => f,
                    Err(NoiseStreamError::SocketClosed) => return Ok(()),
                    Err(e) => return Err(ConnectionError::Noise(e)),
                };
                let mut sv2_frame: StandardSv2Frame<AnyMessage<'static>> = frame
                    .try_into()
                    .map_err(|_| ConnectionError::UnexpectedFirstFrame { got: 0xff })?;
                let header = sv2_frame.get_header().expect("Sv2Frame always has a header");
                let msg_type = header.msg_type();
                let payload = sv2_frame.payload();
                let parsed: AnyMessage<'_> = match (header, payload).try_into() {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(?e, msg_type = format!("{msg_type:#04x}"), "sv2: parse failed; dropping frame");
                        continue;
                    }
                };
                dispatch_frame(
                    &rt,
                    &mut mgr,
                    &mut accounting,
                    &mut writer,
                    msg_type,
                    parsed,
                )
                .await?;
            }
        }
    }
}

/// Dispatch a single post-Setup SV2 frame. Returns `Err` only on fatal IO /
/// frame-build errors — protocol-level rejections produce
/// `SubmitSharesError` / `OpenMiningChannel.Error` / `UpdateChannelError` and
/// keep the connection alive.
async fn dispatch_frame(
    rt: &ListenerRuntime,
    mgr: &mut ChannelManager,
    accounting: &mut ShareAccounting,
    writer: &mut crate::noise_stream::NoiseTcpWriteHalf<AnyMessage<'static>>,
    msg_type: u8,
    parsed: AnyMessage<'_>,
) -> Result<(), ConnectionError> {
    match (msg_type, parsed) {
        (
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            AnyMessage::Mining(Mining::OpenStandardMiningChannel(open)),
        ) => {
            let outs = mgr.handle_open_standard_mining_channel(open);
            // For each opened channel: insert one JobMeta into the shared
            // tracker so a subsequent SubmitSharesStandard's job_id resolves.
            seed_job_tracker(rt, mgr, &outs).await;
            for out in outs {
                write_mining_frame(writer, out).await?;
            }
        }
        (
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            AnyMessage::Mining(Mining::OpenExtendedMiningChannel(open)),
        ) => {
            let outs = mgr.handle_open_extended_mining_channel(open);
            seed_job_tracker(rt, mgr, &outs).await;
            for out in outs {
                write_mining_frame(writer, out).await?;
            }
        }
        (MESSAGE_TYPE_CLOSE_CHANNEL, AnyMessage::Mining(Mining::CloseChannel(close))) => {
            mgr.handle_close_channel(close.channel_id);
        }
        (MESSAGE_TYPE_UPDATE_CHANNEL, AnyMessage::Mining(Mining::UpdateChannel(upd))) => {
            // Bug-B: enforce the listener's hashrate policy on every
            // UpdateChannel — reject < threshold, clamp emitted SetTarget.
            match handle_update_channel(&upd, rt.cfg.min_hashrate_threshold, mgr.min_target_le()) {
                Ok(set_target) => {
                    write_mining_frame(writer, MiningOut::SetTarget(set_target)).await?;
                }
                Err(err) => {
                    write_mining_frame(writer, MiningOut::UpdateChannelError(err)).await?;
                }
            }
        }
        (
            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
            AnyMessage::Mining(Mining::SubmitSharesStandard(share)),
        ) => {
            handle_submit_standard(rt, mgr, accounting, writer, share).await?;
        }
        (
            MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
            AnyMessage::Mining(Mining::SubmitSharesExtended(share)),
        ) => {
            handle_submit_extended(rt, mgr, accounting, writer, share).await?;
        }
        (
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
            AnyMessage::Mining(Mining::SetCustomMiningJob(scmj)),
        ) => {
            // We rejected REQUIRES_WORK_SELECTION at SetupConnection — a
            // well-behaved client cannot reach this. A malformed/malicious
            // peer used to trip a defensive `unreachable!()` and panic the
            // per-conn task; we now reply with a polite
            // `SetCustomMiningJobError { error_code = "jd-not-supported" }`
            // (per SRI `ERROR_CODE_SET_CUSTOM_MINING_JOB_JD_NOT_SUPPORTED`)
            // and keep the connection alive.
            warn!(
                channel_id = scmj.channel_id,
                request_id = scmj.request_id,
                "sv2: SetCustomMiningJob received but JD is not supported; replying with SetCustomMiningJobError"
            );
            let err = handle_set_custom_mining_job(&scmj);
            write_mining_frame(writer, MiningOut::SetCustomMiningJobError(err)).await?;
        }
        (mt, other) => {
            warn!(
                msg_type = format!("{mt:#04x}"),
                ?other,
                "sv2: unsupported / unexpected post-Setup mining message; dropping"
            );
        }
    }
    Ok(())
}

/// Insert a `JobMeta` into the shared `JobTracker` for every freshly-emitted
/// job in a Channel-open reply, keyed by `(channel_id, job_id)`. This keeps
/// the share-validation path's `tracker.contains(JobKey::sv2(...))` check
/// honest when a SubmitShares frame arrives later.
async fn seed_job_tracker(rt: &ListenerRuntime, mgr: &ChannelManager, outs: &[MiningOut]) {
    let template = match mgr.current_template() {
        Some(t) => t,
        None => return,
    };
    let mut to_insert: Vec<(JobKey, datum_share_relay::JobMeta, u64)> = Vec::new();
    for out in outs {
        match out {
            MiningOut::NewExtendedMiningJob(j) => {
                let meta = crate::share_path::job_meta_from_template(&template, 0, 0);
                to_insert.push((
                    JobKey::sv2(j.channel_id, j.job_id),
                    meta,
                    template.job_id_seed,
                ));
            }
            MiningOut::NewMiningJob(j) => {
                let meta = crate::share_path::job_meta_from_template(&template, 0, 0);
                to_insert.push((
                    JobKey::sv2(j.channel_id, j.job_id),
                    meta,
                    template.job_id_seed,
                ));
            }
            _ => {}
        }
    }
    if to_insert.is_empty() {
        return;
    }
    let mut g = rt.jobs.lock().await;
    for (key, meta, seed) in to_insert {
        g.insert(key, meta, seed);
    }
}

async fn handle_submit_extended(
    rt: &ListenerRuntime,
    mgr: &mut ChannelManager,
    accounting: &mut ShareAccounting,
    writer: &mut crate::noise_stream::NoiseTcpWriteHalf<AnyMessage<'static>>,
    share: stratum_core::mining_sv2::SubmitSharesExtended<'_>,
) -> Result<(), ConnectionError> {
    let cid = share.channel_id;
    let seq = share.sequence_number;
    let (extranonce_prefix, username, current_diff) = match mgr.channel(cid) {
        Some(ch) if ch.is_extended => (
            ch.extranonce_prefix.as_bytes().to_vec(),
            ch.user_identity.clone(),
            // Until we wire per-channel vardiff state into the dispatcher,
            // start at the floor. A future commit can plumb the channel's
            // VardiffState through.
            8u64,
        ),
        Some(_) => {
            // Channel exists but is Standard; SubmitSharesExtended on a
            // Standard channel is invalid — surface as bad-extranonce-size
            // (closest-fitting wire string).
            let err = build_submit_shares_error(
                cid,
                seq,
                stratum_core::mining_sv2::ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
            );
            write_mining_frame(writer, MiningOut::SubmitSharesError(err)).await?;
            return Ok(());
        }
        None => {
            let err =
                build_submit_shares_error(cid, seq, ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
            write_mining_frame(writer, MiningOut::SubmitSharesError(err)).await?;
            return Ok(());
        }
    };
    let template_seed = mgr
        .current_template()
        .as_ref()
        .map(|t| t.job_id_seed)
        .unwrap_or(0);
    let key = JobKey::sv2(cid, share.job_id);
    let outcome = {
        let mut jt = rt.jobs.lock().await;
        validate_extended_share(
            &share,
            10,
            &extranonce_prefix,
            current_diff,
            &rt.user_cfg,
            &username,
            true,
            accounting,
            &mut jt,
            &key,
            template_seed,
        )
    };
    forward_share_outcome(rt, accounting, writer, cid, seq, outcome).await
}

async fn handle_submit_standard(
    rt: &ListenerRuntime,
    mgr: &mut ChannelManager,
    accounting: &mut ShareAccounting,
    writer: &mut crate::noise_stream::NoiseTcpWriteHalf<AnyMessage<'static>>,
    share: stratum_core::mining_sv2::SubmitSharesStandard,
) -> Result<(), ConnectionError> {
    let cid = share.channel_id;
    let seq = share.sequence_number;
    let (extranonce_prefix, username, current_diff) = match mgr.channel(cid) {
        Some(ch) if !ch.is_extended => (
            ch.extranonce_prefix.as_bytes().to_vec(),
            ch.user_identity.clone(),
            8u64,
        ),
        Some(_) => {
            let err = build_submit_shares_error(
                cid,
                seq,
                stratum_core::mining_sv2::ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE,
            );
            write_mining_frame(writer, MiningOut::SubmitSharesError(err)).await?;
            return Ok(());
        }
        None => {
            let err =
                build_submit_shares_error(cid, seq, ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
            write_mining_frame(writer, MiningOut::SubmitSharesError(err)).await?;
            return Ok(());
        }
    };
    let template_seed = mgr
        .current_template()
        .as_ref()
        .map(|t| t.job_id_seed)
        .unwrap_or(0);
    let key = JobKey::sv2(cid, share.job_id);
    let outcome = {
        let mut jt = rt.jobs.lock().await;
        validate_standard_share(
            &share,
            &extranonce_prefix,
            current_diff,
            &rt.user_cfg,
            &username,
            true,
            accounting,
            &mut jt,
            &key,
            template_seed,
        )
    };
    forward_share_outcome(rt, accounting, writer, cid, seq, outcome).await
}

async fn forward_share_outcome(
    rt: &ListenerRuntime,
    accounting: &mut ShareAccounting,
    writer: &mut crate::noise_stream::NoiseTcpWriteHalf<AnyMessage<'static>>,
    channel_id: u32,
    sequence_number: u32,
    outcome: ShareOutcome,
) -> Result<(), ConnectionError> {
    match outcome {
        ShareOutcome::Valid { body } => {
            // Forward to DATUM upstream with backpressure: `send().await` parks
            // this per-connection task if the upstream is slow, instead of
            // dropping shares on a full mpsc. The dispatch loop's `select!` is
            // not deadlock-prone here — the only producer to `commands_tx` on
            // this task is *this* call, and the upstream consumer
            // (`run_datum_upstream`) drains independently. A `SendError`
            // (channel closed) means the upstream task is gone — that is
            // catastrophic, so propagate as a connection error and let the
            // outer accept loop drop this socket cleanly.
            if let Err(e) = rt
                .commands_tx
                .send(UpstreamShareCommand::SubmitShare(body))
                .await
            {
                error!(
                    error = %e,
                    "sv2: commands_tx closed — DATUM upstream task is gone; dropping connection"
                );
                return Err(ConnectionError::UpstreamGone);
            }
            // Batched ack — only emit when the accounting layer says so.
            if accounting.should_acknowledge() {
                let ack = build_submit_shares_success(channel_id, accounting);
                write_mining_frame(writer, MiningOut::SubmitSharesSuccess(ack)).await?;
            }
        }
        ShareOutcome::BlockFound {
            body,
            block_payload,
        } => {
            // BlockFound: a found-block share that we cannot forward is the
            // most catastrophic data loss possible. Same `send().await`
            // backpressure policy; on closed channel log at error! and
            // propagate so the connection drops cleanly rather than silently
            // discarding the block.
            if let Err(e) = rt
                .commands_tx
                .send(UpstreamShareCommand::SubmitShare(body))
                .await
            {
                error!(
                    error = %e,
                    block_hash = %block_payload.block_hash_hex,
                    "sv2: BlockFound share forward FAILED — commands_tx closed; \
                     DATUM upstream task is gone. This share will not reach the pool."
                );
                return Err(ConnectionError::UpstreamGone);
            }
            if let Some(cb) = &rt.block_found {
                cb(block_payload);
            } else {
                info!(
                    block_hash = %block_payload.block_hash_hex,
                    "sv2: BlockFound but no block-submitter wired (test/dev mode)"
                );
            }
            // BlockFound always emits a one-share Success ack, regardless of
            // the batching gate (per SRI behavior).
            let ack = build_submit_shares_success(channel_id, accounting);
            write_mining_frame(writer, MiningOut::SubmitSharesSuccess(ack)).await?;
        }
        ShareOutcome::Rejected { error_code } => {
            let err = build_submit_shares_error(channel_id, sequence_number, error_code);
            write_mining_frame(writer, MiningOut::SubmitSharesError(err)).await?;
        }
    }
    Ok(())
}

async fn write_mining_frame(
    writer: &mut crate::noise_stream::NoiseTcpWriteHalf<AnyMessage<'static>>,
    out: MiningOut,
) -> Result<(), ConnectionError> {
    let mt = out.msg_type();
    let cm = out.channel_msg();
    let mining = out.into_mining();
    let frame: StandardSv2Frame<AnyMessage<'static>> =
        Sv2Frame::from_message(AnyMessage::Mining(mining), mt, 0, cm)
            .ok_or(ConnectionError::FrameBuild { kind: "MiningOut" })?;
    writer.write_frame(frame.into()).await?;
    Ok(())
}
