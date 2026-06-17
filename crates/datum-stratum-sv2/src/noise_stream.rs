//! Noise-encrypted SV2 framed stream over `tokio::net::TcpStream`.
//!
//! This is a minimal mirror of SRI's `stratum-apps/src/network_helpers/noise_stream.rs`
//! (fetched at the rev pinned in the workspace `Cargo.toml`). We mirror the
//! responder path only — datum-rs is always the SV2 server. We do **not**
//! reimplement Noise; the handshake is run by `noise_sv2::Responder` via
//! `codec_sv2::State::step_1`.
//!
//! Why mirror instead of pulling `network_helpers_sv2` directly: SRI's
//! network_helpers crate ships an `async_channel`-flavored API that does
//! `tokio::signal::ctrl_c` inside reader/writer tasks. We want plain
//! `tokio::sync::mpsc` plumbing and we own SIGINT in `datum-bin`, so a slim
//! local copy is the cleaner choice. Structure verbatim from SRI to keep
//! semantics aligned.

use std::time::Duration;

use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::{HandshakeRole, NoiseEncoder, StandardEitherFrame, StandardNoiseDecoder, State},
    framing_sv2::framing::HandShakeFrame,
    noise_sv2::ELLSWIFT_ENCODING_SIZE,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tracing::debug;

/// Default timeout for a single handshake-frame read. Matches SRI's
/// `NOISE_HANDSHAKE_TIMEOUT` (3 s) so a stuck miner can't tie up a worker
/// task indefinitely.
pub const NOISE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Error)]
pub enum NoiseStreamError {
    #[error("socket closed")]
    SocketClosed,
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("handshake remote sent invalid message")]
    HandshakeRemoteInvalidMessage,
    #[error("codec error: {0:?}")]
    CodecError(stratum_core::codec_sv2::Error),
    #[error("noise error: {0:?}")]
    NoiseError(stratum_core::codec_sv2::Error),
}

impl From<stratum_core::codec_sv2::Error> for NoiseStreamError {
    fn from(e: stratum_core::codec_sv2::Error) -> Self {
        Self::CodecError(e)
    }
}

/// A Noise-encrypted, SV2-framed duplex stream over TCP. The handshake runs
/// inside [`Self::accept`]; once it returns, the stream is in transport mode
/// and read/write_frame are usable.
pub struct NoiseTcpStream<Message: Serialize + Deserialize<'static> + GetSize + Send + 'static> {
    pub reader: NoiseTcpReadHalf<Message>,
    pub writer: NoiseTcpWriteHalf<Message>,
}

pub struct NoiseTcpReadHalf<Message: Serialize + Deserialize<'static> + GetSize + Send + 'static> {
    reader: OwnedReadHalf,
    decoder: StandardNoiseDecoder<Message>,
    state: State,
    current_frame_buf: Vec<u8>,
    bytes_read: usize,
}

pub struct NoiseTcpWriteHalf<Message: Serialize + Deserialize<'static> + GetSize + Send + 'static> {
    writer: OwnedWriteHalf,
    encoder: NoiseEncoder<Message>,
    state: State,
}

impl<Message> NoiseTcpStream<Message>
where
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Run the SV2 Noise handshake as the responder, then return the
    /// transport-mode stream split into read + write halves.
    ///
    /// Cribbed from SRI `stratum-apps/src/network_helpers/noise_stream.rs`
    /// `NoiseTcpStream::new`. We only support the responder path because
    /// datum-rs is always the SV2 server.
    pub async fn accept(
        stream: TcpStream,
        role: HandshakeRole,
        timeout: Duration,
    ) -> Result<Self, NoiseStreamError> {
        let (mut reader, mut writer) = stream.into_split();
        let mut decoder = StandardNoiseDecoder::<Message>::new();
        let mut encoder = NoiseEncoder::<Message>::new();
        let mut state = State::initialized(role.clone());

        match role {
            HandshakeRole::Initiator(_) => {
                // datum-rs is always the responder. If a caller hands us an
                // initiator role, the codec will refuse the responder steps;
                // we surface that as an explicit error rather than half-doing
                // it.
                return Err(NoiseStreamError::HandshakeRemoteInvalidMessage);
            }
            HandshakeRole::Responder(_) => {
                let mut initiator_state = State::not_initialized(&role);
                loop {
                    match receive_message::<Message>(
                        &mut reader,
                        &mut initiator_state,
                        &mut decoder,
                        timeout,
                    )
                    .await
                    {
                        Ok(first_msg) => {
                            debug!("noise: first handshake message received");
                            let handshake_frame: HandShakeFrame = first_msg
                                .try_into()
                                .map_err(|_| NoiseStreamError::HandshakeRemoteInvalidMessage)?;
                            let payload: [u8; ELLSWIFT_ENCODING_SIZE] = handshake_frame
                                .get_payload_when_handshaking()
                                .try_into()
                                .map_err(|_| NoiseStreamError::HandshakeRemoteInvalidMessage)?;
                            let (second_msg, transport_state) = state
                                .step_1(payload)
                                .map_err(NoiseStreamError::NoiseError)?;
                            send_message::<Message>(
                                &mut writer,
                                second_msg.into(),
                                &mut state,
                                &mut encoder,
                            )
                            .await?;
                            debug!("noise: second handshake message sent");
                            state = transport_state;
                            break;
                        }
                        Err(NoiseStreamError::CodecError(
                            stratum_core::codec_sv2::Error::MissingBytes(_),
                        )) => {
                            debug!("noise: waiting for more bytes during handshake");
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        Ok(Self {
            reader: NoiseTcpReadHalf {
                reader,
                decoder,
                state: state.clone(),
                current_frame_buf: Vec::new(),
                bytes_read: 0,
            },
            writer: NoiseTcpWriteHalf {
                writer,
                encoder,
                state,
            },
        })
    }

    pub fn into_split(self) -> (NoiseTcpReadHalf<Message>, NoiseTcpWriteHalf<Message>) {
        (self.reader, self.writer)
    }
}

impl<Message> NoiseTcpReadHalf<Message>
where
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Read one full SV2 frame. Loops until the codec yields a frame; each
    /// iteration reads exactly `decoder.writable_len()` bytes from the
    /// underlying socket. Not cancellation-safe.
    pub async fn read_frame(&mut self) -> Result<StandardEitherFrame<Message>, NoiseStreamError> {
        loop {
            let expected = self.decoder.writable_len();
            if self.current_frame_buf.len() != expected {
                self.current_frame_buf.resize(expected, 0);
                self.bytes_read = 0;
            }
            while self.bytes_read < expected {
                let n = self
                    .reader
                    .read(&mut self.current_frame_buf[self.bytes_read..])
                    .await
                    .map_err(|_| NoiseStreamError::SocketClosed)?;
                if n == 0 {
                    return Err(NoiseStreamError::SocketClosed);
                }
                self.bytes_read += n;
            }
            self.decoder
                .writable()
                .copy_from_slice(&self.current_frame_buf[..]);
            self.bytes_read = 0;
            match self.decoder.next_frame(&mut self.state) {
                Ok(frame) => return Ok(frame),
                Err(stratum_core::codec_sv2::Error::MissingBytes(_)) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(NoiseStreamError::CodecError(e)),
            }
        }
    }
}

impl<Message> NoiseTcpWriteHalf<Message>
where
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Encode + encrypt + write one SV2 frame. Not cancellation-safe.
    pub async fn write_frame(
        &mut self,
        frame: StandardEitherFrame<Message>,
    ) -> Result<(), NoiseStreamError> {
        let buf = self.encoder.encode(frame, &mut self.state)?;
        self.writer
            .write_all(buf.as_ref())
            .await
            .map_err(|_| NoiseStreamError::SocketClosed)?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<(), NoiseStreamError> {
        self.writer
            .shutdown()
            .await
            .map_err(|_| NoiseStreamError::SocketClosed)
    }
}

async fn send_message<Message>(
    writer: &mut OwnedWriteHalf,
    msg: StandardEitherFrame<Message>,
    state: &mut State,
    encoder: &mut NoiseEncoder<Message>,
) -> Result<(), NoiseStreamError>
where
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let buffer = encoder.encode(msg, state)?;
    writer
        .write_all(buffer.as_ref())
        .await
        .map_err(|_| NoiseStreamError::SocketClosed)?;
    Ok(())
}

async fn receive_message<Message>(
    reader: &mut OwnedReadHalf,
    state: &mut State,
    decoder: &mut StandardNoiseDecoder<Message>,
    timeout: Duration,
) -> Result<StandardEitherFrame<Message>, NoiseStreamError>
where
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let mut buffer = vec![0u8; decoder.writable_len()];
    tokio::time::timeout(timeout, reader.read_exact(&mut buffer))
        .await
        .map_err(|_| NoiseStreamError::HandshakeTimeout)?
        .map_err(|_| NoiseStreamError::SocketClosed)?;
    decoder.writable().copy_from_slice(&buffer);
    decoder
        .next_frame(state)
        .map_err(NoiseStreamError::CodecError)
}
