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
