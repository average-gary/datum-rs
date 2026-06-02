use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("dryoc: {0}")]
    Dryoc(String),
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Cipher abstraction so we can swap in `libsodium-sys-stable` for byte-exact
/// cross-validation tests against the C reference.
pub trait DatumCrypto: Send + Sync {
    fn box_seal(
        &self,
        recipient_x25519_pubkey: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Inverse of `box_seal`: given a ciphertext sealed to our X25519
    /// keypair, recover the plaintext.
    fn box_seal_open(
        &self,
        ciphertext: &[u8],
        recipient_x25519_pub: &[u8; 32],
        recipient_x25519_sec: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError>;

    /// XSalsa20Poly1305 (libsodium default — NOT ChaCha20-Poly1305). See the
    /// wiki article datum-protocol-rust-implementation § critical correction.
    /// Output layout matches libsodium's `crypto_box_easy_afternm`: `mac || ct`
    /// (16-byte MAC prepended).
    fn box_easy_afternm(
        &self,
        precomputed_key: &[u8; 32],
        nonce: &[u8; 24],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn box_open_easy_afternm(
        &self,
        precomputed_key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn box_beforenm(
        &self,
        their_x25519_pubkey: &[u8; 32],
        our_x25519_secret: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError>;

    /// Generate a fresh Ed25519 keypair `(public[32], secret[64])`. Secret is
    /// libsodium's seed||pubkey concatenation (matches `dryoc::sign`).
    fn sign_keypair(&self) -> ([u8; 32], [u8; 64]);

    /// Detached Ed25519 signature over `message` using `secret_key` (the
    /// 64-byte libsodium-format secret). Returns the 64-byte signature.
    fn sign_detached(&self, message: &[u8], secret_key: &[u8; 64])
        -> Result<[u8; 64], CryptoError>;

    /// Verify an Ed25519 detached signature. Returns Ok(()) iff valid.
    fn verify_detached(
        &self,
        message: &[u8],
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<(), CryptoError>;

    /// Generate a fresh X25519 keypair `(public[32], secret[32])`.
    fn box_keypair(&self) -> ([u8; 32], [u8; 32]);

    fn random_bytes(&self, n: usize) -> Vec<u8>;
}

pub struct DryocCrypto;

impl DryocCrypto {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DryocCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl DatumCrypto for DryocCrypto {
    fn box_seal(
        &self,
        recipient_x25519_pubkey: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use dryoc::dryocbox::{DryocBox, PublicKey};
        let pk: [u8; 32] = recipient_x25519_pubkey
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let pk: PublicKey = pk.into();
        let sealed: Vec<u8> = DryocBox::seal_to_vecbox(plaintext, &pk)
            .map_err(|e| CryptoError::Dryoc(e.to_string()))?
            .to_vec();
        Ok(sealed)
    }

    fn box_seal_open(
        &self,
        ciphertext: &[u8],
        recipient_x25519_pub: &[u8; 32],
        recipient_x25519_sec: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        use dryoc::classic::crypto_box::crypto_box_seal_open;
        const CRYPTO_BOX_SEALBYTES: usize = 48;
        if ciphertext.len() < CRYPTO_BOX_SEALBYTES {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut pt = vec![0u8; ciphertext.len() - CRYPTO_BOX_SEALBYTES];
        crypto_box_seal_open(
            &mut pt,
            ciphertext,
            recipient_x25519_pub,
            recipient_x25519_sec,
        )
        .map_err(|e| CryptoError::Dryoc(e.to_string()))?;
        Ok(pt)
    }

    fn box_easy_afternm(
        &self,
        precomputed_key: &[u8; 32],
        nonce: &[u8; 24],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use dryoc::classic::crypto_secretbox::{crypto_secretbox_easy, Key, Nonce};
        let key: Key = *precomputed_key;
        let nonce: Nonce = *nonce;
        let mut ct = vec![0u8; plaintext.len() + 16];
        crypto_secretbox_easy(&mut ct, plaintext, &nonce, &key)
            .map_err(|e| CryptoError::Dryoc(e.to_string()))?;
        Ok(ct)
    }

    fn box_open_easy_afternm(
        &self,
        precomputed_key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use dryoc::classic::crypto_secretbox::{crypto_secretbox_open_easy, Key, Nonce};
        let key: Key = *precomputed_key;
        let nonce: Nonce = *nonce;
        if ciphertext.len() < 16 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut pt = vec![0u8; ciphertext.len() - 16];
        crypto_secretbox_open_easy(&mut pt, ciphertext, &nonce, &key)
            .map_err(|e| CryptoError::Dryoc(e.to_string()))?;
        Ok(pt)
    }

    fn box_beforenm(
        &self,
        their_x25519_pubkey: &[u8; 32],
        our_x25519_secret: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        use dryoc::classic::crypto_box::crypto_box_beforenm;
        Ok(crypto_box_beforenm(their_x25519_pubkey, our_x25519_secret))
    }

    fn sign_keypair(&self) -> ([u8; 32], [u8; 64]) {
        use dryoc::classic::crypto_sign::crypto_sign_keypair;
        crypto_sign_keypair()
    }

    fn sign_detached(
        &self,
        message: &[u8],
        secret_key: &[u8; 64],
    ) -> Result<[u8; 64], CryptoError> {
        use dryoc::classic::crypto_sign::crypto_sign_detached;
        let mut sig = [0u8; 64];
        crypto_sign_detached(&mut sig, message, secret_key)
            .map_err(|e| CryptoError::Dryoc(e.to_string()))?;
        Ok(sig)
    }

    fn verify_detached(
        &self,
        message: &[u8],
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<(), CryptoError> {
        use dryoc::classic::crypto_sign::crypto_sign_verify_detached;
        crypto_sign_verify_detached(signature, message, public_key)
            .map_err(|e| CryptoError::Dryoc(e.to_string()))
    }

    fn box_keypair(&self) -> ([u8; 32], [u8; 32]) {
        use dryoc::classic::crypto_box::crypto_box_keypair;
        let (pk, sk) = crypto_box_keypair();
        (pk, sk)
    }

    fn random_bytes(&self, n: usize) -> Vec<u8> {
        use dryoc::rng::randombytes_buf;
        randombytes_buf(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xsalsa20poly1305_round_trip() {
        let crypto = DryocCrypto::new();
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 24];
        let pt = b"DATUM steady-state cipher = XSalsa20Poly1305";
        let ct = crypto.box_easy_afternm(&key, &nonce, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
        let recovered = crypto.box_open_easy_afternm(&key, &nonce, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn random_bytes_are_random_ish() {
        let crypto = DryocCrypto::new();
        let a = crypto.random_bytes(32);
        let b = crypto.random_bytes(32);
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a, b);
    }
}
