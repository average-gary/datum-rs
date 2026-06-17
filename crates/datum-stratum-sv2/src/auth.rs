//! Authority key handling for the SV2 Noise listener.
//!
//! Per [SV2 Spec ch.4](https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md):
//!
//! - The pool persists a long-lived **authority keypair** (Schnorr / x-only).
//! - The pool's **server static key** is signed by the authority; the cert
//!   format is `version=0 || valid_from || not_valid_after || signature`.
//! - The authority pubkey is published as base58check of `[0x01, 0x00] ||
//!   x_only_pubkey[32]` so miners can pin per-pool.
//!
//! This module:
//! 1. Loads the authority pubkey + secret from operator-supplied paths
//!    (matching SRI's `key_utils` base58check encoding so we share the same
//!    on-disk format as upstream tooling like `pool-config-gen`).
//! 2. Verifies the keypair is consistent (pubkey matches secret).
//! 3. Re-emits the pubkey in the canonical base58check form for log lines /
//!    `/metrics` rows (so an operator can pin it).
//!
//! We do **not** roll our own Noise: cert generation + signing happens inside
//! `noise_sv2::Responder::from_authority_kp` / `step_1` (per SRI's responder.rs
//! lines 254-390 — the responder fills `valid_from = now`, `not_valid_after =
//! now + cert_validity`, signs with the authority secret, and embeds the
//! signature noise message in the act-2 frame). Our job is only to hand it
//! the keypair + cert validity.

use std::fs;
use std::path::{Path, PathBuf};

use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use thiserror::Error;

/// Base58check version prefix used by SRI's `key_utils` for x-only pubkey
/// strings. Two LE bytes: `[0x01, 0x00]`. See SV2 Spec ch.4 §4.5.4.
pub const AUTHORITY_PUBKEY_VERSION: [u8; 2] = [0x01, 0x00];

#[derive(Debug, Error)]
pub enum AuthorityKeyError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("base58check decode {path}: {kind}")]
    Bs58 { path: PathBuf, kind: &'static str },
    #[error(
        "authority pubkey at {path} has wrong base58check version (got {got:#06x}, want 0x0001)"
    )]
    WrongVersion { path: PathBuf, got: u16 },
    #[error("authority pubkey at {path} has wrong length (got {got} bytes, want 34 = 2 version + 32 key)")]
    WrongPubkeyLen { path: PathBuf, got: usize },
    #[error("authority secret at {path} has wrong length (got {got} bytes, want 32)")]
    WrongSecretLen { path: PathBuf, got: usize },
    #[error("authority pubkey/secret mismatch (the pubkey in {pubkey_path} is not derived from the secret in {secret_path})")]
    Mismatch {
        pubkey_path: PathBuf,
        secret_path: PathBuf,
    },
    #[error("invalid secret key bytes at {path}: {source}")]
    InvalidSecret {
        path: PathBuf,
        #[source]
        source: secp256k1::Error,
    },
    #[error("invalid x-only pubkey bytes at {path}: {source}")]
    InvalidPubkey {
        path: PathBuf,
        #[source]
        source: secp256k1::Error,
    },
}

/// Loaded + verified authority keypair, ready to hand to
/// `noise_sv2::Responder::from_authority_kp`.
#[derive(Debug, Clone)]
pub struct AuthorityKey {
    /// 32-byte x-only authority public key.
    pub pubkey_bytes: [u8; 32],
    /// 32-byte authority secret.
    pub secret_bytes: [u8; 32],
    /// Cached base58check encoding (`[0x01,0x00] || pubkey[32]`) — what gets
    /// printed at startup and surfaced in `/metrics` so operators can pin it.
    pub pubkey_b58: String,
}

impl AuthorityKey {
    /// Read the operator-supplied pubkey + secret files, decode base58check,
    /// and verify they match. Both files must contain a single base58check
    /// string (whitespace trimmed). The pubkey's two-byte version prefix must
    /// be `[0x01, 0x00]` per SV2 spec; the secret has no version prefix.
    pub fn load(pubkey_path: &Path, secret_path: &Path) -> Result<Self, AuthorityKeyError> {
        let pub_text = fs::read_to_string(pubkey_path).map_err(|e| AuthorityKeyError::Read {
            path: pubkey_path.to_path_buf(),
            source: e,
        })?;
        let sec_text = fs::read_to_string(secret_path).map_err(|e| AuthorityKeyError::Read {
            path: secret_path.to_path_buf(),
            source: e,
        })?;

        let pub_decoded = bs58::decode(pub_text.trim())
            .with_check(None)
            .into_vec()
            .map_err(|_| AuthorityKeyError::Bs58 {
                path: pubkey_path.to_path_buf(),
                kind: "pubkey",
            })?;
        let sec_decoded = bs58::decode(sec_text.trim())
            .with_check(None)
            .into_vec()
            .map_err(|_| AuthorityKeyError::Bs58 {
                path: secret_path.to_path_buf(),
                kind: "secret",
            })?;

        if pub_decoded.len() != 34 {
            return Err(AuthorityKeyError::WrongPubkeyLen {
                path: pubkey_path.to_path_buf(),
                got: pub_decoded.len(),
            });
        }
        let version = u16::from_le_bytes([pub_decoded[0], pub_decoded[1]]);
        if version != 1 {
            return Err(AuthorityKeyError::WrongVersion {
                path: pubkey_path.to_path_buf(),
                got: version,
            });
        }
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&pub_decoded[2..]);

        if sec_decoded.len() != 32 {
            return Err(AuthorityKeyError::WrongSecretLen {
                path: secret_path.to_path_buf(),
                got: sec_decoded.len(),
            });
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&sec_decoded);

        // Validate the secret parses, derive the pubkey it corresponds to,
        // and compare against the operator-supplied pubkey. This catches the
        // class of misconfig where the operator copy-pasted a stale pubkey.
        let secp = Secp256k1::new();
        let secret =
            SecretKey::from_slice(&secret_bytes).map_err(|e| AuthorityKeyError::InvalidSecret {
                path: secret_path.to_path_buf(),
                source: e,
            })?;
        let derived = Keypair::from_secret_key(&secp, &secret)
            .x_only_public_key()
            .0
            .serialize();
        if derived != pubkey_bytes {
            return Err(AuthorityKeyError::Mismatch {
                pubkey_path: pubkey_path.to_path_buf(),
                secret_path: secret_path.to_path_buf(),
            });
        }
        // Also validate the pubkey bytes parse as an XOnlyPublicKey — the
        // derivation above will have caught most cases, but this gives a
        // sharp error message if someone hand-edits the file.
        let _ = XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|e| {
            AuthorityKeyError::InvalidPubkey {
                path: pubkey_path.to_path_buf(),
                source: e,
            }
        })?;

        let pubkey_b58 = encode_authority_pubkey_b58(&pubkey_bytes);
        Ok(Self {
            pubkey_bytes,
            secret_bytes,
            pubkey_b58,
        })
    }
}

/// Encode an x-only authority pubkey as the SV2-canonical base58check string:
/// `bs58check([0x01, 0x00] || pubkey[32])`. Public for use in tests + the
/// startup log line.
pub fn encode_authority_pubkey_b58(pubkey: &[u8; 32]) -> String {
    let mut buf = [0u8; 34];
    buf[..2].copy_from_slice(&AUTHORITY_PUBKEY_VERSION);
    buf[2..].copy_from_slice(pubkey);
    bs58::encode(buf).with_check().into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_keypair() -> (Keypair, [u8; 32], [u8; 32]) {
        use secp256k1::rand::{rngs::StdRng, SeedableRng};
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(0xdeadbeef);
        let kp = Keypair::new(&secp, &mut rng);
        let sec = kp.secret_key().secret_bytes();
        let pub_ = kp.x_only_public_key().0.serialize();
        (kp, pub_, sec)
    }

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "datum-rs-sv2-auth-{}-{:?}-{}-{}",
            std::process::id(),
            std::thread::current().id(),
            n,
            name
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    fn pub_b58(pubkey: &[u8; 32]) -> String {
        encode_authority_pubkey_b58(pubkey)
    }

    fn sec_b58(secret: &[u8; 32]) -> String {
        bs58::encode(secret).with_check().into_string()
    }

    #[test]
    fn loads_matched_keypair_and_emits_b58() {
        let (_kp, pub_bytes, sec_bytes) = make_keypair();
        let pub_path = write_temp("pub-ok.txt", &pub_b58(&pub_bytes));
        let sec_path = write_temp("sec-ok.txt", &sec_b58(&sec_bytes));
        let k = AuthorityKey::load(&pub_path, &sec_path).expect("matched keypair loads");
        assert_eq!(k.pubkey_bytes, pub_bytes);
        assert_eq!(k.secret_bytes, sec_bytes);
        assert!(!k.pubkey_b58.is_empty());
        // Re-encoding the b58 we got back must match what we wrote.
        assert_eq!(k.pubkey_b58, pub_b58(&pub_bytes));
    }

    #[test]
    fn rejects_mismatched_keypair() {
        let (_a, pub_a, _sec_a) = make_keypair();
        // Generate a *different* keypair via a different seed.
        use secp256k1::rand::{rngs::StdRng, SeedableRng};
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(0xdeadc0de);
        let kp_b = Keypair::new(&secp, &mut rng);
        let sec_b = kp_b.secret_key().secret_bytes();

        let pub_path = write_temp("pub-mismatch.txt", &pub_b58(&pub_a));
        let sec_path = write_temp("sec-mismatch.txt", &sec_b58(&sec_b));
        let err = AuthorityKey::load(&pub_path, &sec_path).unwrap_err();
        assert!(matches!(err, AuthorityKeyError::Mismatch { .. }));
    }

    #[test]
    fn rejects_garbage_pubkey() {
        let (_kp, _pub_bytes, sec_bytes) = make_keypair();
        let pub_path = write_temp("pub-garbage.txt", "not-base58");
        let sec_path = write_temp("sec-garbage.txt", &sec_b58(&sec_bytes));
        let err = AuthorityKey::load(&pub_path, &sec_path).unwrap_err();
        assert!(matches!(err, AuthorityKeyError::Bs58 { .. }));
    }

    #[test]
    fn b58_encoding_round_trip() {
        let raw = [0x42u8; 32];
        let s = encode_authority_pubkey_b58(&raw);
        let decoded = bs58::decode(&s).with_check(None).into_vec().unwrap();
        assert_eq!(decoded.len(), 34);
        assert_eq!(&decoded[..2], &AUTHORITY_PUBKEY_VERSION);
        assert_eq!(&decoded[2..], &raw);
    }
}
