//! Long-lived DATUM upstream client.
//!
//! The one-shot equivalent is `bin/handshake_probe.rs`; this is the version
//! the gateway runtime drives forever — completes the handshake, then loops
//! send_frame/recv_frame translating the wire bytes into typed events.
//!
//! Wire details ported from `datum_protocol.c`:
//! - Post-handshake header XOR chain advances per-frame via
//!   `HeaderObfuscator::for_sender(nk)` / `for_receiver(nk)` (sender uses
//!   `datum_header_xor_feedback(nk)`, receiver uses `~nk`).
//! - Session precomputed key = `crypto_box_beforenm(pool_session_x25519_pub,
//!   our_session_x25519_sec)` (datum_protocol.c:201, 1180).
//! - Sender / receiver session nonces are derived deterministically from `nk`
//!   per `datum_protocol.c:1060-1069`.
//! - Body cipher = XSalsa20Poly1305 (`crypto_box_easy_afternm`); MAC is
//!   prepended to ciphertext (16 bytes); nonce increments after each send.

use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::crypto::{CryptoError, DatumCrypto, DryocCrypto};
use crate::frame::FrameHeader;
use crate::handshake::{
    build_hello_payload, frame_for_hello, parse_received_header, seal_hello, ClientKeypairs,
    HandshakeError, CRYPTO_BOX_SEAL_BYTES,
};
use crate::messages::{
    BlockNotify, ClientConfig, CoinbaserResponse, MessageError, ShareResponse,
    CLIENT_CONFIG_OPCODE, COINBASER_RESPONSE_OPCODE, JOB_VALIDATION_OPCODE, SHARE_RESPONSE_OPCODE,
};
use crate::obfuscation::{datum_header_xor_feedback, HeaderObfuscator};
use crate::opcodes::ProtoCmd;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("frame: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("message: {0}")]
    Message(#[from] MessageError),
    #[error("connect timeout after {0:?}")]
    ConnectTimeout(Duration),
    #[error("send timeout after {0:?}")]
    SendTimeout(Duration),
    #[error("recv timeout after {0:?}")]
    RecvTimeout(Duration),
    #[error("hex decode pool pubkey: {0}")]
    BadPoolPubkey(String),
    #[error("response cmd_len {got} too short to hold a sealed envelope")]
    UndersizedResponse { got: u32 },
    #[error("response cmd_len {got} exceeds 4MB sanity cap")]
    OversizedResponse { got: u32 },
    #[error("server rejected handshake (response proto_cmd != Pong): got {got:?}")]
    HandshakeRejected { got: ProtoCmd },
    #[error("server echoed pubkeys did not match what we sent")]
    EchoMismatch,
    #[error("undersized response for {message}: got {got}, need {need}")]
    UndersizedDecoded {
        message: &'static str,
        got: usize,
        need: usize,
    },
}

/// Inbound events the runtime cares about. Encrypted frames are decoded into
/// these typed values before being forwarded.
#[derive(Debug)]
pub enum UpstreamEvent {
    Coinbaser(CoinbaserResponse),
    ClientConfig(ClientConfig),
    ShareResponse(ShareResponse),
    BlockNotify(BlockNotify),
    /// Job-validation request — the runtime decides what payload to send back.
    JobValidationRequest(Vec<u8>),
    /// A frame we couldn't classify — usually a benign protocol extension.
    UnknownFrame {
        proto_cmd: u8,
        body: Vec<u8>,
    },
}

/// Outbound commands the runtime can ask the upstream task to send.
#[derive(Debug, Clone)]
pub enum UpstreamCommand {
    /// Submit a share. Body is the full encoded ShareSubmissionPrefix +
    /// (optional) merkle-branch suffix the runtime computed.
    SubmitShare(Vec<u8>),
    /// Request a coinbase split for the current job. Per
    /// `datum_protocol.c::datum_protocol_coinbaser_fetch:320-354`, the body
    /// is `[0x10][coinbase_value LE u64][prevhash_bin 32B][0xFE][padding]`
    /// sent via mining cmd (proto_cmd=5, is_encrypted_channel=true).
    RequestCoinbaser {
        coinbase_value: u64,
        prevhash_bin: [u8; 32],
    },
    /// Send a verbatim frame (`proto_cmd`, body). Escape hatch for paths the
    /// runtime later realizes it needs.
    Raw { proto_cmd: u8, body: Vec<u8> },
}

pub struct DatumClient;

impl DatumClient {
    /// Establish a TCP connection, complete the handshake, return a
    /// `Connected` ready for send_frame/recv_frame.
    pub async fn connect(
        endpoint: &str,
        pool_long_term_x25519_pub: &[u8; 32],
        version: &str,
        client_id: &str,
        timeout_dur: Duration,
    ) -> Result<Connected, ClientError> {
        let crypto: Arc<dyn DatumCrypto> = Arc::new(DryocCrypto);
        let keys = ClientKeypairs::generate(crypto.as_ref());
        let nk = u32::from_le_bytes(crypto.random_bytes(4).try_into().unwrap());
        let padding_len = 1 + (crypto.random_bytes(1)[0] as usize % 200);
        let padding = crypto.random_bytes(padding_len);

        let plaintext =
            build_hello_payload(crypto.as_ref(), &keys, version, client_id, nk, &padding)?;
        let sealed = seal_hello(crypto.as_ref(), &plaintext, pool_long_term_x25519_pub)?;
        let framed = frame_for_hello(&sealed)?;

        let stream = timeout(timeout_dur, TcpStream::connect(endpoint))
            .await
            .map_err(|_| ClientError::ConnectTimeout(timeout_dur))??;
        let (mut rd, mut wr) = stream.into_split();
        timeout(timeout_dur, wr.write_all(&framed))
            .await
            .map_err(|_| ClientError::SendTimeout(timeout_dur))??;

        let mut header_buf = [0u8; 4];
        timeout(timeout_dur, rd.read_exact(&mut header_buf))
            .await
            .map_err(|_| ClientError::RecvTimeout(timeout_dur))??;
        let mut recv_obf = HeaderObfuscator::for_receiver(nk);
        let resp_header = parse_received_header(&mut recv_obf, header_buf)?;
        // recv_obf has now advanced one position; we MUST hand it to the
        // Connected struct so subsequent frames continue the chain
        // correctly. Do NOT create a fresh `for_receiver(nk)` — that would
        // reset the chain by one and desync against the pool.

        if resp_header.cmd_len > 4 * 1024 * 1024 {
            return Err(ClientError::OversizedResponse {
                got: resp_header.cmd_len,
            });
        }
        if (resp_header.cmd_len as usize) < CRYPTO_BOX_SEAL_BYTES {
            return Err(ClientError::UndersizedResponse {
                got: resp_header.cmd_len,
            });
        }
        let response_cmd = ProtoCmd::from_bits(resp_header.proto_cmd);
        if !matches!(response_cmd, ProtoCmd::Pong) {
            return Err(ClientError::HandshakeRejected { got: response_cmd });
        }

        let mut sealed_resp = vec![0u8; resp_header.cmd_len as usize];
        timeout(timeout_dur, rd.read_exact(&mut sealed_resp))
            .await
            .map_err(|_| ClientError::RecvTimeout(timeout_dur))??;
        let plaintext_resp = crypto.box_seal_open(
            &sealed_resp,
            &keys.session_x25519_pub,
            &keys.session_x25519_sec,
        )?;

        if plaintext_resp.len() < 192 {
            return Err(ClientError::UndersizedDecoded {
                message: "handshake_response",
                got: plaintext_resp.len(),
                need: 192,
            });
        }
        if plaintext_resp[0..32] != keys.long_term_ed25519_pub
            || plaintext_resp[32..64] != keys.long_term_x25519_pub
            || plaintext_resp[64..96] != keys.session_ed25519_pub
            || plaintext_resp[96..128] != keys.session_x25519_pub
        {
            return Err(ClientError::EchoMismatch);
        }
        let pool_session_ed25519: [u8; 32] = plaintext_resp[128..160].try_into().unwrap();
        let pool_session_x25519: [u8; 32] = plaintext_resp[160..192].try_into().unwrap();
        let motd_bytes = &plaintext_resp[192..];
        let motd_end = motd_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(motd_bytes.len());
        let motd = String::from_utf8_lossy(&motd_bytes[..motd_end]).into_owned();

        let precomp = crypto.box_beforenm(&pool_session_x25519, &keys.session_x25519_sec)?;
        let (sender_nonce, receiver_nonce) = derive_session_nonces(nk, &keys.session_ed25519_pub);

        Ok(Connected {
            crypto,
            rd: Arc::new(Mutex::new(rd)),
            wr: Arc::new(Mutex::new(wr)),
            sender_obf: Mutex::new(HeaderObfuscator::for_sender(nk)),
            receiver_obf: Mutex::new(recv_obf),
            precomp_key: precomp,
            sender_nonce: Mutex::new(sender_nonce),
            receiver_nonce: Mutex::new(receiver_nonce),
            timeout_dur,
            pool_session_ed25519,
            pool_session_x25519,
            motd,
        })
    }
}

/// Established post-handshake state. Send/recv operations are mutex-guarded so
/// the client task can safely fan-out frames from multiple producers.
pub struct Connected {
    crypto: Arc<dyn DatumCrypto>,
    rd: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
    wr: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    sender_obf: Mutex<HeaderObfuscator>,
    receiver_obf: Mutex<HeaderObfuscator>,
    precomp_key: [u8; 32],
    sender_nonce: Mutex<[u8; 24]>,
    receiver_nonce: Mutex<[u8; 24]>,
    timeout_dur: Duration,
    pub pool_session_ed25519: [u8; 32],
    pub pool_session_x25519: [u8; 32],
    pub motd: String,
}

impl Connected {
    /// Encrypt `plaintext` with the precomputed key + sender nonce, frame
    /// with the next sender obfuscator key, send. Increments the sender
    /// nonce on success.
    pub async fn send_frame(&self, proto_cmd: u8, plaintext: &[u8]) -> Result<(), ClientError> {
        let mut nonce = self.sender_nonce.lock().await;
        let ciphertext = self
            .crypto
            .box_easy_afternm(&self.precomp_key, &nonce, plaintext)?;

        let header = FrameHeader {
            cmd_len: ciphertext.len() as u32,
            is_signed: false,
            is_encrypted_pubkey: false,
            is_encrypted_channel: true,
            proto_cmd,
        };
        let raw = header.pack()?;
        let plain_word = u32::from_le_bytes(raw);
        let xored = {
            let mut obf = self.sender_obf.lock().await;
            obf.encrypt(plain_word)
        };

        let mut wr = self.wr.lock().await;
        timeout(self.timeout_dur, wr.write_all(&xored.to_le_bytes()))
            .await
            .map_err(|_| ClientError::SendTimeout(self.timeout_dur))??;
        timeout(self.timeout_dur, wr.write_all(&ciphertext))
            .await
            .map_err(|_| ClientError::SendTimeout(self.timeout_dur))??;

        increment_nonce(&mut nonce);
        Ok(())
    }

    /// Read 4-byte header, de-XOR with receiver chain, read body, decrypt.
    pub async fn recv_frame(&self) -> Result<(FrameHeader, Vec<u8>), ClientError> {
        let mut rd = self.rd.lock().await;
        let mut header_buf = [0u8; 4];
        rd.read_exact(&mut header_buf).await?;
        let wire_word = u32::from_le_bytes(header_buf);
        let plain_word = {
            let mut obf = self.receiver_obf.lock().await;
            obf.decrypt(wire_word)
        };
        let header = FrameHeader::unpack(plain_word.to_le_bytes());
        tracing::debug!(
            proto_cmd = format!("{:#04x}", header.proto_cmd),
            cmd_len = header.cmd_len,
            is_signed = header.is_signed,
            is_encrypted_pubkey = header.is_encrypted_pubkey,
            is_encrypted_channel = header.is_encrypted_channel,
            "recv_frame: header"
        );
        if header.cmd_len > 16 * 1024 * 1024 {
            return Err(ClientError::OversizedResponse {
                got: header.cmd_len,
            });
        }
        let mut raw = vec![0u8; header.cmd_len as usize];
        rd.read_exact(&mut raw).await?;
        drop(rd);

        // Three body modes per datum_protocol.c::datum_protocol_server_msg:
        // - encrypted_pubkey=1, encrypted_channel=0 → sealed-to-our-session-x25519
        // - encrypted_pubkey=0, encrypted_channel=1 → secretbox via precomputed key
        // - both=0 → no body encryption (signature-only or plaintext)
        let mut body = if header.is_encrypted_pubkey && !header.is_encrypted_channel {
            // sealed to our session pubkey — but we've thrown away the
            // session keypair after handshake. The only sealed-pubkey
            // frame we expect is the handshake response, which is handled
            // in DatumClient::connect, not here. Treat as plaintext for
            // now and surface the bytes.
            tracing::warn!(
                "recv_frame: encrypted_pubkey body without our session keypair; passing through"
            );
            raw
        } else if !header.is_encrypted_pubkey && header.is_encrypted_channel {
            let mut nonce = self.receiver_nonce.lock().await;
            let pt = self
                .crypto
                .box_open_easy_afternm(&self.precomp_key, &nonce, &raw)?;
            increment_nonce(&mut nonce);
            pt
        } else {
            raw
        };

        // Strip detached signature suffix if present. Per
        // datum_protocol.c:1213-1233 the signature is the LAST 64 bytes of
        // the (decrypted) body and we strip it before dispatching. We don't
        // verify it today — that's a TODO once we wire pool_session_ed25519
        // through to here.
        if header.is_signed && body.len() >= 64 {
            body.truncate(body.len() - 64);
        }

        tracing::debug!(
            proto_cmd = format!("{:#04x}", header.proto_cmd),
            body_len = body.len(),
            first_bytes = %hex::encode(&body[..body.len().min(32)]),
            "recv_frame: decoded body"
        );
        Ok((header, body))
    }

    /// Drive the loop. Decodes incoming frames into `UpstreamEvent`s,
    /// forwards on `events_tx`. Reads outbound `UpstreamCommand`s from
    /// `commands_rx`.
    pub async fn run(
        self: Arc<Self>,
        events_tx: tokio::sync::mpsc::Sender<UpstreamEvent>,
        mut commands_rx: tokio::sync::mpsc::Receiver<UpstreamCommand>,
    ) -> Result<(), ClientError> {
        let recv_self = self.clone();
        let recv_events = events_tx.clone();
        let recv_handle: tokio::task::JoinHandle<Result<(), ClientError>> =
            tokio::spawn(async move {
                loop {
                    let (header, body) = match recv_self.recv_frame().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::warn!(error = %e, "recv_frame failed; recv loop exiting");
                            return Err(e);
                        }
                    };
                    let event = match decode_event(header, body) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(error = %e, "decode_event failed; recv loop exiting");
                            return Err(e);
                        }
                    };
                    if recv_events.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            });

        // No outbound heartbeat — proto_cmd 0x01 is HELLO, and OCEAN drops
        // post-handshake 0x01 frames as a malformed re-init (live bench:
        // every connection died exactly 20s after handshake). The C reference
        // ships no keepalive either; the recv-side global timeout
        // (datum_conf.c:192, 60s default) is satisfied by ordinary share-
        // response / notify traffic.
        while let Some(cmd) = commands_rx.recv().await {
            match cmd {
                UpstreamCommand::SubmitShare(body) => {
                    // Share submissions go via mining cmd (proto_cmd=5) with
                    // is_encrypted_channel=true. The body is the encoded
                    // ShareSubmissionPrefix; the leading 0x27 sub-opcode is
                    // included in `body` per messages::SHARE_SUBMISSION_PREFIX_LEN.
                    self.send_frame(5, &body).await?;
                }
                UpstreamCommand::RequestCoinbaser {
                    coinbase_value,
                    prevhash_bin,
                } => {
                    let mut body = Vec::with_capacity(64);
                    body.push(0x10);
                    body.extend_from_slice(&coinbase_value.to_le_bytes());
                    body.extend_from_slice(&prevhash_bin);
                    body.push(0xFE);
                    // Random pad 1-80 bytes per datum_protocol.c:346.
                    let pad_len = 1 + (self.crypto.random_bytes(1)[0] as usize % 80);
                    body.extend_from_slice(&self.crypto.random_bytes(pad_len));
                    self.send_frame(5, &body).await?;
                }
                UpstreamCommand::Raw { proto_cmd, body } => {
                    self.send_frame(proto_cmd, &body).await?;
                }
            }
        }
        recv_handle.abort();
        Ok(())
    }
}

fn decode_event(header: FrameHeader, body: Vec<u8>) -> Result<UpstreamEvent, ClientError> {
    let proto_cmd = ProtoCmd::from_bits(header.proto_cmd);
    // top-level proto_cmd 0xF9 → BlockNotify (5-bit collision with ClientConfig
    // resolved by raw byte: BlockNotify is on a top-level frame, ClientConfig
    // is a sub-opcode of mining-cmd-5).
    if header.proto_cmd == 0xF9 & 0x1F && !header.is_signed && !header.is_encrypted_pubkey {
        return Ok(UpstreamEvent::BlockNotify(BlockNotify::decode(&body)));
    }
    match proto_cmd {
        ProtoCmd::Coinbaser => {
            // body[0] is the sub-opcode; rest is the structured response
            if body.is_empty() {
                return Err(ClientError::UndersizedDecoded {
                    message: "coinbaser/share-mux frame",
                    got: 0,
                    need: 1,
                });
            }
            if body[0] == COINBASER_RESPONSE_OPCODE {
                Ok(UpstreamEvent::Coinbaser(CoinbaserResponse::decode(
                    &body[1..],
                )?))
            } else if body[0] == JOB_VALIDATION_OPCODE {
                Ok(UpstreamEvent::JobValidationRequest(body[1..].to_vec()))
            } else {
                Ok(UpstreamEvent::UnknownFrame {
                    proto_cmd: header.proto_cmd,
                    body,
                })
            }
        }
        _ => {
            // proto_cmd = 5 in the C reference covers ClientConfig (0x99),
            // ShareResponse (0x8F), JobValidation (0x50), Coinbaser (0x11).
            // We dispatch on the body's first byte.
            if !body.is_empty() {
                match body[0] {
                    SHARE_RESPONSE_OPCODE => {
                        return Ok(UpstreamEvent::ShareResponse(ShareResponse::decode(
                            &body[1..],
                        )?));
                    }
                    CLIENT_CONFIG_OPCODE => {
                        return Ok(UpstreamEvent::ClientConfig(ClientConfig::decode(
                            &body[1..],
                        )?));
                    }
                    COINBASER_RESPONSE_OPCODE => {
                        return Ok(UpstreamEvent::Coinbaser(CoinbaserResponse::decode(
                            &body[1..],
                        )?));
                    }
                    JOB_VALIDATION_OPCODE => {
                        return Ok(UpstreamEvent::JobValidationRequest(body[1..].to_vec()));
                    }
                    _ => {}
                }
            }
            Ok(UpstreamEvent::UnknownFrame {
                proto_cmd: header.proto_cmd,
                body,
            })
        }
    }
}

/// Port of `datum_protocol.c:1060-1069`. Returns (sender_nonce, receiver_nonce)
/// — both 24 bytes. Receiver is computed first, sender is XOR'd from it.
pub fn derive_session_nonces(nk: u32, session_ed25519_pub: &[u8; 32]) -> ([u8; 24], [u8; 24]) {
    let mut receiver = [0u8; 24];
    let mut sender = [0u8; 24];
    // nk -= 42; nk ^= upk_u32le(session_ed25519_pub, 7) — note "7" is byte
    // offset 7, NOT u32 index 7.
    let pub_word_at_7 = u32::from_le_bytes([
        session_ed25519_pub[7],
        session_ed25519_pub[8],
        session_ed25519_pub[9],
        session_ed25519_pub[10],
    ]);
    let mut nk = nk.wrapping_sub(42) ^ pub_word_at_7;
    let mut j = 0;
    while j < 24 {
        let recv_word = datum_header_xor_feedback(nk.wrapping_sub(42));
        let send_word = recv_word ^ 0x5757_5757;
        let recv_le = recv_word.to_le_bytes();
        let send_le = send_word.to_le_bytes();
        receiver[j..j + 4].copy_from_slice(&recv_le);
        sender[j..j + 4].copy_from_slice(&send_le);
        nk = !recv_word;
        j += 4;
    }
    (sender, receiver)
}

fn increment_nonce(n: &mut [u8; 24]) {
    let mut i = 0;
    while i < 24 {
        let word = u32::from_le_bytes([n[i], n[i + 1], n[i + 2], n[i + 3]]).wrapping_add(1);
        n[i..i + 4].copy_from_slice(&word.to_le_bytes());
        if word != 0 {
            return;
        }
        i += 4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_increment_basic() {
        let mut n = [0u8; 24];
        increment_nonce(&mut n);
        assert_eq!(n[0], 1);
        increment_nonce(&mut n);
        assert_eq!(n[0], 2);
    }

    #[test]
    fn nonce_increment_carries() {
        let mut n = [0u8; 24];
        n[..4].fill(0xFF);
        increment_nonce(&mut n);
        assert_eq!(&n[0..4], &[0, 0, 0, 0]);
        assert_eq!(n[4], 1);
    }

    #[test]
    fn derive_session_nonces_deterministic() {
        let pub_key = [0x42u8; 32];
        let (s1, r1) = derive_session_nonces(0xDEAD_BEEF, &pub_key);
        let (s2, r2) = derive_session_nonces(0xDEAD_BEEF, &pub_key);
        assert_eq!(s1, s2);
        assert_eq!(r1, r2);
        assert_ne!(s1, r1, "sender and receiver nonces must differ");
    }

    #[test]
    fn derive_session_nonces_change_with_nk() {
        let pub_key = [0x42u8; 32];
        let (s_a, _) = derive_session_nonces(1, &pub_key);
        let (s_b, _) = derive_session_nonces(2, &pub_key);
        assert_ne!(s_a, s_b);
    }
}
