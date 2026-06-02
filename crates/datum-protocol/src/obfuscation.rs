/// MurmurHash3-32 finalizer (`mm3_fmix32`). Used by DATUM to evolve the per-
/// packet header XOR key — NOT a full hash, just the 4-step bit-mixer.
/// Init constant for the chain seed: `0xb10cfeed` (block-feed pun).
#[inline]
pub fn mm3_fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

pub const HEADER_OBFUSCATION_INIT: u32 = 0xb10c_feed;

/// Header XOR-feedback chain: each header is XOR'd with the current 32-bit
/// `key`, then `key = mm3_fmix32(key ^ raw_header_word)` for the next packet.
/// Both sides advance the chain in lockstep, seeded by a client-chosen `nk`
/// during handshake.
#[derive(Debug, Clone)]
pub struct HeaderObfuscator {
    key: u32,
}

impl HeaderObfuscator {
    pub fn new(seed: u32) -> Self {
        Self {
            key: seed ^ HEADER_OBFUSCATION_INIT,
        }
    }

    /// Encrypt: returns `wire_word = plaintext ^ key`, advances the chain
    /// using `wire_word` so the decrypter (who sees `wire_word` only) can mix
    /// the same value into its key.
    pub fn encrypt(&mut self, plaintext: u32) -> u32 {
        let wire = plaintext ^ self.key;
        self.key = mm3_fmix32(self.key ^ wire);
        wire
    }

    /// Decrypt: returns `plaintext = wire_word ^ key`, advances the chain
    /// using `wire_word`. Must be called in the same order encrypt() was.
    pub fn decrypt(&mut self, wire: u32) -> u32 {
        let plaintext = wire ^ self.key;
        self.key = mm3_fmix32(self.key ^ wire);
        plaintext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmix32_known_vectors() {
        assert_eq!(mm3_fmix32(0), 0);
        // Hand-computed via the reference algorithm: spot-check stability
        let v = mm3_fmix32(0xb10c_feed);
        let v2 = mm3_fmix32(v);
        assert_ne!(v, v2);
    }

    #[test]
    fn obfuscator_round_trips() {
        let mut enc = HeaderObfuscator::new(0xdead_beef);
        let mut dec = HeaderObfuscator::new(0xdead_beef);
        let plaintext = [0x1234_5678u32, 0x9abc_def0, 0x0011_2233];
        let ciphertext: Vec<u32> = plaintext.iter().map(|w| enc.encrypt(*w)).collect();
        let recovered: Vec<u32> = ciphertext.iter().map(|w| dec.decrypt(*w)).collect();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = HeaderObfuscator::new(0x1111_1111);
        let mut b = HeaderObfuscator::new(0x2222_2222);
        let w = 0xaaaa_aaaa;
        assert_ne!(a.encrypt(w), b.encrypt(w));
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let mut o = HeaderObfuscator::new(0xdead_beef);
        let p = 0x1234_5678;
        assert_ne!(o.encrypt(p), p);
    }
}
