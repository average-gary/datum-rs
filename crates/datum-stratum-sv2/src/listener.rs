//! SV2 Noise listener (Phase 3).
//!
//! Binds a `tokio::net::TcpListener` and runs a Noise NX handshake per
//! [SV2 Noise Handshake](https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md)
//! against each accepted connection. Once the handshake completes, the
//! listener reads the first SV2 frame, expects a `SetupConnection`, and replies
//! with `SetupConnection.Success` or `SetupConnection.Error`. Channel-level
//! handling is Phase 4 — for now the per-connection task closes after the
//! reply.
//!
//! ## What this is NOT
//! - **Not** a full mining server: open / submit / vardiff handlers are Phase
//!   4 / 5.
//! - **Not** a re-implementation of Noise: every cryptographic primitive
//!   comes from `noise_sv2` / `codec_sv2` via the pinned `stratum-core` git
//!   rev. Per the playbook §3 "Use SRI's `noise-sv2` crate. Do not roll our
//!   own."
//!
//! ## Cert lifecycle
//! `noise_sv2::Responder::from_authority_kp(public, private, cert_validity)`
//! signs a fresh server static key with the authority key on construction.
//! The signed cert (`version=0 || valid_from || not_valid_after || sig`) is
//! recomputed inside `Responder::step_1` per-connection: SRI sets
//! `valid_from = now`, `not_valid_after = now + cert_validity` (saturating
//! u32 add — see SRI #2103, why we cap config input). datum-rs does NOT add
//! a `now - 60s` skew today; per spec, miners with broken NTP will reject
//! and that's documented as an operator runbook prerequisite.
//!
//! ## Authority pubkey publication
//! At startup we log the base58check authority pubkey
//! (`bs58check([0x01,0x00] || pubkey[32])`) so the operator can pin it in
//! the miner config. See [`crate::auth::encode_authority_pubkey_b58`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stratum_core::codec_sv2::{HandshakeRole, StandardEitherFrame, StandardSv2Frame};
use stratum_core::common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION;
use stratum_core::framing_sv2::framing::Sv2Frame;
use stratum_core::noise_sv2::Responder;
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages};
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::auth::AuthorityKey;
use crate::noise_stream::{NoiseStreamError, NoiseTcpStream, NOISE_HANDSHAKE_TIMEOUT};
use crate::setup_connection::{handle_setup_connection, SetupConnectionResponse};

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
}

impl ListenerConfig {
    pub fn from_datum_config(
        cfg: &datum_config::StratumV2Config,
    ) -> Result<Self, ListenerError> {
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
        let authority =
            AuthorityKey::load(&cfg.authority_pubkey_path, &cfg.authority_secret_path)?;
        Ok(Self {
            bind_addr,
            cert_validity: Duration::from_secs(cfg.cert_validity_sec as u64),
            authority,
            handshake_timeout: NOISE_HANDSHAKE_TIMEOUT,
        })
    }
}

/// Bind + accept loop. Runs until the listener errors fatally; panics in a
/// per-connection task do not bring down the listener.
pub struct Listener {
    cfg: Arc<ListenerConfig>,
    inner: TcpListener,
}

impl Listener {
    pub async fn bind(cfg: ListenerConfig) -> Result<Self, ListenerError> {
        let inner = TcpListener::bind(cfg.bind_addr)
            .await
            .map_err(|e| ListenerError::Bind {
                addr: cfg.bind_addr,
                source: e,
            })?;
        info!(
            sv2_addr = %cfg.bind_addr,
            cert_validity_sec = cfg.cert_validity.as_secs(),
            authority_pubkey_b58 = %cfg.authority.pubkey_b58,
            "sv2 stratum listener bound"
        );
        Ok(Self {
            cfg: Arc::new(cfg),
            inner,
        })
    }

    /// Run the accept loop. Each accepted TCP connection spawns a per-conn
    /// task that runs Noise + SetupConnection; the loop itself never blocks
    /// on a slow client.
    pub async fn run(self) {
        // Headless mode (no shutdown signal) — used by Phase 1-3 callers that
        // run-forever. New callers should prefer [`Listener::run_with_shutdown`].
        let (_tx, rx) = tokio::sync::watch::channel(false);
        self.run_with_shutdown(rx).await;
    }

    /// Run the accept loop until `shutdown_rx` flips to `true`.
    ///
    /// Per Phase 3's gap notes ("the listener has no graceful-shutdown
    /// channel today — Phase 4 should add a `tokio::sync::watch::Sender<bool>`
    /// like SV1's `sv1_shutdown_tx`"). The shutdown signal lets `datum-bin`
    /// drain in-flight Noise handshakes on Ctrl-C; the per-connection tasks
    /// remain to wind themselves down at their own pace, but the accept
    /// loop returns immediately.
    pub async fn run_with_shutdown(self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        loop {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    // `changed()` returns Err if the sender is dropped — treat
                    // that as a shutdown too (no point staying bound).
                    let stop = changed.is_err() || *shutdown_rx.borrow();
                    if stop {
                        info!(sv2_addr = %self.cfg.bind_addr, "sv2 stratum listener shutting down");
                        return;
                    }
                }
                accept = self.inner.accept() => match accept {
                    Ok((stream, peer)) => {
                        debug!(%peer, "sv2: connection accepted");
                        let cfg = self.cfg.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, cfg).await {
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
    #[error("encoded frame too large for SetupConnection.{kind}")]
    FrameBuild { kind: &'static str },
    #[error("frame parse: {0:?}")]
    Parse(stratum_core::parsers_sv2::ParserError),
}

/// Per-connection driver. Returns `Ok(())` on a clean close (after the reply
/// is written), or `Err(_)` on protocol/IO errors.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    cfg: Arc<ListenerConfig>,
) -> Result<(), ConnectionError> {
    // Build the responder fresh per-connection so each handshake gets a new
    // ephemeral keypair (Noise NX requirement). The authority keypair is
    // shared across connections.
    let responder = Responder::from_authority_kp(
        &cfg.authority.pubkey_bytes,
        &cfg.authority.secret_bytes,
        cfg.cert_validity,
    )
    .map_err(|_| {
        ConnectionError::Noise(NoiseStreamError::HandshakeRemoteInvalidMessage)
    })?;
    let role = HandshakeRole::Responder(responder);

    let stream =
        NoiseTcpStream::<AnyMessage<'static>>::accept(stream, role, cfg.handshake_timeout)
            .await?;
    let (mut reader, mut writer) = stream.into_split();

    // First post-handshake frame must be SetupConnection (msg_type 0x00, ext
    // 0x00). We decode through `AnyMessage` and dispatch.
    let frame: StandardEitherFrame<AnyMessage<'static>> = reader.read_frame().await?;
    let mut sv2_frame: StandardSv2Frame<AnyMessage<'static>> = frame
        .try_into()
        .map_err(|_| ConnectionError::UnexpectedFirstFrame { got: 0xff })?;
    let header = sv2_frame.get_header().expect("Sv2Frame always has a header");
    let msg_type = header.msg_type();
    if msg_type != MESSAGE_TYPE_SETUP_CONNECTION {
        return Err(ConnectionError::UnexpectedFirstFrame { got: msg_type });
    }
    // Parse the SetupConnection payload via AnyMessage::TryFrom<(Header,
    // &mut [u8])>. SRI's Sv2Frame keeps the payload bytes alongside the
    // header; we extract them and feed AnyMessage's parser.
    let payload = sv2_frame.payload();
    let parsed: AnyMessage<'_> =
        (header, payload).try_into().map_err(ConnectionError::Parse)?;
    let setup_msg = match parsed {
        AnyMessage::Common(CommonMessages::SetupConnection(s)) => s,
        other => {
            warn!(?other, "sv2: first frame parsed but was not SetupConnection");
            return Err(ConnectionError::UnexpectedFirstFrame { got: msg_type });
        }
    };

    let response = handle_setup_connection(&setup_msg);
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

    info!(
        msg_type = format!("{:#04x}", response_msg_type),
        "sv2: SetupConnection reply sent; further channel handling pending Phase 4"
    );

    // Phase 4 will replace this with a real channel/session loop. For now we
    // drain frames until the peer disconnects so the connection doesn't sit
    // half-open on the responder side.
    loop {
        match reader.read_frame().await {
            Ok(_frame) => {
                debug!("sv2: post-Setup frame received but channel handling not yet wired (Phase 4)");
            }
            Err(NoiseStreamError::SocketClosed) => return Ok(()),
            Err(e) => return Err(ConnectionError::Noise(e)),
        }
    }
}
