//! DATUM handshake hello payload assembly + sealing + framing.
//!
//! Implements the structured client-hello plaintext per
//! `datum_protocol.c:996-1043` and wraps it in a sealed-box per
//! `datum_protocol.c:1042-1051`.
//!
//! Field order in the plaintext:
//! 1. long-term Ed25519 pubkey (32B)
//! 2. long-term X25519 pubkey (32B)
//! 3. session Ed25519 pubkey (32B)
//! 4. session X25519 pubkey (32B)
//! 5. version string + NUL terminator
//! 6. client identifier (`/<git-sha>` or similar) + NUL terminator
//! 7. sentinel byte `0xFE`
//! 8. nk = 4-byte LE u32 (random; seeds the post-handshake header XOR chain)
//! 9. random padding (1-200 bytes)
//! 10. detached Ed25519 signature over fields 1-9 (64B)

use thiserror::Error;

use crate::crypto::{CryptoError, DatumCrypto};
use crate::frame::{FrameError, FrameHeader, MAX_CMD_LEN};
use crate::obfuscation::HeaderObfuscator;

/// Sentinel byte separating fields 6 and 8 in the hello payload (from
/// `datum_protocol.c:1018`).
pub const HELLO_SENTINEL: u8 = 0xFE;

/// Hello opcode in the proto_cmd field (from `datum_protocol.c:983-985`).
pub const HELLO_PROTO_CMD: u8 = 0x01;

/// Crypto-box-seal overhead (32-byte ephemeral pubkey + 16-byte MAC).
pub const CRYPTO_BOX_SEAL_BYTES: usize = 48;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("padding length {got} out of allowed range [1, 200]")]
    BadPaddingLen { got: usize },
    #[error("version string contains NUL byte")]
    VersionHasNul,
    #[error("client_id string contains NUL byte")]
    ClientIdHasNul,
    #[error("sealed payload {got} bytes exceeds 22-bit cmd_len limit ({MAX_CMD_LEN})")]
    PayloadTooLarge { got: usize },
}

/// Long-term + session Ed25519 + X25519 keypairs for one handshake.
#[derive(Debug, Clone)]
pub struct ClientKeypairs {
    pub long_term_ed25519_pub: [u8; 32],
    pub long_term_ed25519_sec: [u8; 64],
    pub long_term_x25519_pub: [u8; 32],
    pub long_term_x25519_sec: [u8; 32],
    pub session_ed25519_pub: [u8; 32],
    pub session_ed25519_sec: [u8; 64],
    pub session_x25519_pub: [u8; 32],
    pub session_x25519_sec: [u8; 32],
}

impl ClientKeypairs {
    pub fn generate(crypto: &dyn DatumCrypto) -> Self {
        let (lt_ed_pk, lt_ed_sk) = crypto.sign_keypair();
        let (s_ed_pk, s_ed_sk) = crypto.sign_keypair();
        let (lt_x_pk, lt_x_sk) = crypto.box_keypair();
        let (s_x_pk, s_x_sk) = crypto.box_keypair();
        Self {
            long_term_ed25519_pub: lt_ed_pk,
            long_term_ed25519_sec: lt_ed_sk,
            long_term_x25519_pub: lt_x_pk,
            long_term_x25519_sec: lt_x_sk,
            session_ed25519_pub: s_ed_pk,
            session_ed25519_sec: s_ed_sk,
            session_x25519_pub: s_x_pk,
            session_x25519_sec: s_x_sk,
        }
    }
}

/// Build the hello payload plaintext (fields 1-10), ready for sealing.
///
/// `nk` is a client-chosen random u32 that seeds the post-handshake header
/// XOR chain on both sides (`datum_protocol.c:1057-1058`).
///
/// `padding` must be 1-200 bytes (matches `datum_protocol.c:1032-1034`).
/// `client_id` is typically `/<git-sha>(<git-tag>)`; for the probe we pass
/// `/datum-rs handshake_probe`.
pub fn build_hello_payload(
    crypto: &dyn DatumCrypto,
    keys: &ClientKeypairs,
    version: &str,
    client_id: &str,
    nk: u32,
    padding: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    if version.as_bytes().contains(&0) {
        return Err(HandshakeError::VersionHasNul);
    }
    if client_id.as_bytes().contains(&0) {
        return Err(HandshakeError::ClientIdHasNul);
    }
    if !(1..=200).contains(&padding.len()) {
        return Err(HandshakeError::BadPaddingLen { got: padding.len() });
    }

    let mut buf =
        Vec::with_capacity(128 + version.len() + client_id.len() + 2 + 1 + 4 + padding.len() + 64);
    buf.extend_from_slice(&keys.long_term_ed25519_pub);
    buf.extend_from_slice(&keys.long_term_x25519_pub);
    buf.extend_from_slice(&keys.session_ed25519_pub);
    buf.extend_from_slice(&keys.session_x25519_pub);
    buf.extend_from_slice(version.as_bytes());
    buf.push(0);
    buf.extend_from_slice(client_id.as_bytes());
    buf.push(0);
    buf.push(HELLO_SENTINEL);
    buf.extend_from_slice(&nk.to_le_bytes());
    buf.extend_from_slice(padding);

    let signature = crypto.sign_detached(&buf, &keys.long_term_ed25519_sec)?;
    buf.extend_from_slice(&signature);

    Ok(buf)
}

/// Wrap the plaintext hello with `crypto_box_seal` to the pool's long-term
/// X25519 pubkey. Adds 48 bytes of overhead (ephemeral X25519 pubkey + MAC).
pub fn seal_hello(
    crypto: &dyn DatumCrypto,
    plaintext: &[u8],
    pool_x25519_pub: &[u8; 32],
) -> Result<Vec<u8>, HandshakeError> {
    let sealed = crypto.box_seal(pool_x25519_pub, plaintext)?;
    Ok(sealed)
}

/// Build the framed hello: `[XOR'd 4-byte header] || [sealed payload]`.
/// The first frame's header is XOR'd with [`INITIAL_SENDING_HEADER_KEY`] —
/// the sender chain reseeds via `datum_header_xor_feedback(nk)` only after
/// the handshake response arrives.
pub fn frame_for_hello(sealed: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let cmd_len: u32 = sealed
        .len()
        .try_into()
        .map_err(|_| HandshakeError::PayloadTooLarge { got: sealed.len() })?;
    let header = FrameHeader {
        cmd_len,
        is_signed: true,
        is_encrypted_pubkey: true,
        is_encrypted_channel: false,
        proto_cmd: HELLO_PROTO_CMD,
    };
    let raw_header = header.pack()?;
    let header_word = u32::from_le_bytes(raw_header);
    let mut obf = HeaderObfuscator::initial_sender();
    let xored_word = obf.encrypt(header_word);

    let mut out = Vec::with_capacity(4 + sealed.len());
    out.extend_from_slice(&xored_word.to_le_bytes());
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Parse the raw 4-byte header off the wire (after de-XOR'ing).
pub fn parse_received_header(
    obf: &mut HeaderObfuscator,
    wire: [u8; 4],
) -> Result<FrameHeader, FrameError> {
    let wire_word = u32::from_le_bytes(wire);
    let plain_word = obf.decrypt(wire_word);
    Ok(FrameHeader::unpack(plain_word.to_le_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DryocCrypto;

    fn fixed_padding() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn build_hello_payload_layout() {
        let crypto = DryocCrypto;
        let keys = ClientKeypairs::generate(&crypto);
        let payload = build_hello_payload(
            &crypto,
            &keys,
            "v0.4.1-beta",
            "/test",
            0xdead_beef,
            &fixed_padding(),
        )
        .unwrap();

        assert_eq!(&payload[0..32], &keys.long_term_ed25519_pub[..]);
        assert_eq!(&payload[32..64], &keys.long_term_x25519_pub[..]);
        assert_eq!(&payload[64..96], &keys.session_ed25519_pub[..]);
        assert_eq!(&payload[96..128], &keys.session_x25519_pub[..]);

        let version = b"v0.4.1-beta\0";
        assert_eq!(&payload[128..128 + version.len()], version);
        let after_version = 128 + version.len();
        let client_id = b"/test\0";
        assert_eq!(
            &payload[after_version..after_version + client_id.len()],
            client_id
        );
        let after_client = after_version + client_id.len();
        assert_eq!(payload[after_client], HELLO_SENTINEL);

        let nk_offset = after_client + 1;
        assert_eq!(
            u32::from_le_bytes(payload[nk_offset..nk_offset + 4].try_into().unwrap()),
            0xdead_beef
        );

        let padding_offset = nk_offset + 4;
        assert_eq!(
            &payload[padding_offset..padding_offset + 32],
            &fixed_padding()[..]
        );

        let sig_offset = padding_offset + 32;
        assert_eq!(payload.len(), sig_offset + 64);

        let signed_part = &payload[..sig_offset];
        let signature: [u8; 64] = payload[sig_offset..].try_into().unwrap();
        crypto
            .verify_detached(signed_part, &signature, &keys.long_term_ed25519_pub)
            .expect("hello signature should verify");
    }

    #[test]
    fn rejects_version_with_nul() {
        let crypto = DryocCrypto;
        let keys = ClientKeypairs::generate(&crypto);
        let err = build_hello_payload(
            &crypto,
            &keys,
            "v0.4.1-beta\0evil",
            "/test",
            0,
            &fixed_padding(),
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::VersionHasNul));
    }

    #[test]
    fn rejects_padding_out_of_range() {
        let crypto = DryocCrypto;
        let keys = ClientKeypairs::generate(&crypto);
        let err = build_hello_payload(&crypto, &keys, "v", "/", 0, &[]).unwrap_err();
        assert!(matches!(err, HandshakeError::BadPaddingLen { got: 0 }));
        let err = build_hello_payload(&crypto, &keys, "v", "/", 0, &vec![0u8; 201]).unwrap_err();
        assert!(matches!(err, HandshakeError::BadPaddingLen { got: 201 }));
    }

    #[test]
    fn seal_then_unseal_round_trip() {
        let crypto = DryocCrypto;
        let (pool_pub, pool_sec) = crypto.box_keypair();
        let plaintext = b"hello DATUM";
        let sealed = seal_hello(&crypto, plaintext, &pool_pub).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + CRYPTO_BOX_SEAL_BYTES);

        let unsealed = crypto
            .box_seal_open(&sealed, &pool_pub, &pool_sec)
            .expect("unseal");
        assert_eq!(unsealed, plaintext);
    }

    #[test]
    fn frame_for_hello_first_word_is_xored() {
        use crate::obfuscation::INITIAL_SENDING_HEADER_KEY;
        let sealed = vec![0u8; 256];
        let framed = frame_for_hello(&sealed).unwrap();
        assert_eq!(framed.len(), 4 + 256);

        let xored_word = u32::from_le_bytes(framed[..4].try_into().unwrap());
        let plain_word = xored_word ^ INITIAL_SENDING_HEADER_KEY;
        let plain_header = FrameHeader::unpack(plain_word.to_le_bytes());
        assert_eq!(plain_header.cmd_len, 256);
        assert_eq!(plain_header.proto_cmd, HELLO_PROTO_CMD);
        assert!(plain_header.is_signed);
        assert!(plain_header.is_encrypted_pubkey);
        assert!(!plain_header.is_encrypted_channel);
    }
}
