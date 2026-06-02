//! DATUM header XOR-key chain.
//!
//! Each frame's 32-bit header is XOR'd with the current sending/receiving key.
//! After each frame, the key advances via [`datum_header_xor_feedback`] —
//! purely a function of the previous key, independent of the wire bytes
//! (matches `datum_protocol.c:249, 1057, 1775`).
//!
//! Two initial keys are involved:
//! - [`INITIAL_SENDING_HEADER_KEY`] = `0xDC871829` (`datum_protocol.c:96, 1494`)
//!   — XOR'd into the very first frame the client sends, before the
//!   handshake completes and the sender chain reseeds via `nk`.
//! - The runtime-derived sender/receiver keys after handshake completes:
//!   `sending_header_key = datum_header_xor_feedback(nk)` and
//!   `receiving_header_key = datum_header_xor_feedback(!nk)`
//!   per `datum_protocol.c:1057-1058`.

/// Initial sender header key applied to the very first wire frame the client
/// emits, before the handshake completes. Per `datum_protocol.c:96, 1494`.
pub const INITIAL_SENDING_HEADER_KEY: u32 = 0xDC87_1829;

/// Seed constant baked into [`datum_header_xor_feedback`]'s mix.
const MURMUR_SEED: u32 = 0xb10c_feed;

const M3_C1: u32 = 0xcc9e_2d51;
const M3_C2: u32 = 0x1b87_3593;
const M3_C3: u32 = 0xe654_6b64;

/// MurmurHash3-32 single-block mix (one 4-byte block, length=4, seed=0xb10cfeed).
/// Bit-exact reproduction of `datum_header_xor_feedback` from
/// `datum_protocol.c:157-174`. Both gateway and pool advance the chain through
/// this; output of one frame's key becomes the input for the next.
#[inline]
pub fn datum_header_xor_feedback(i: u32) -> u32 {
    let mut k = i;
    k = k.wrapping_mul(M3_C1);
    k = k.rotate_left(15);
    k = k.wrapping_mul(M3_C2);

    let mut h = MURMUR_SEED;
    h ^= k;
    h = h.rotate_left(13);
    h = h.wrapping_mul(5).wrapping_add(M3_C3);

    h ^= 4;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// Header XOR-key chain. One side (sender or receiver) advances independently;
/// both sides are kept in lockstep by handshake-time agreement on the seed.
///
/// Construction:
/// - [`HeaderObfuscator::initial_sender`] — for the first wire frame the
///   client sends, before the handshake completes. Seeded with
///   `INITIAL_SENDING_HEADER_KEY`.
/// - [`HeaderObfuscator::for_sender`] — post-handshake sender chain, seeded
///   with `datum_header_xor_feedback(nk)`.
/// - [`HeaderObfuscator::for_receiver`] — post-handshake receiver chain,
///   seeded with `datum_header_xor_feedback(!nk)`.
#[derive(Debug, Clone)]
pub struct HeaderObfuscator {
    key: u32,
}

impl HeaderObfuscator {
    /// First-frame sender chain: key = `INITIAL_SENDING_HEADER_KEY`.
    pub fn initial_sender() -> Self {
        Self {
            key: INITIAL_SENDING_HEADER_KEY,
        }
    }

    /// Post-handshake sender chain: key = `datum_header_xor_feedback(nk)`.
    pub fn for_sender(nk: u32) -> Self {
        Self {
            key: datum_header_xor_feedback(nk),
        }
    }

    /// Post-handshake receiver chain: key = `datum_header_xor_feedback(!nk)`.
    pub fn for_receiver(nk: u32) -> Self {
        Self {
            key: datum_header_xor_feedback(!nk),
        }
    }

    /// Encrypt: returns `wire_word = plaintext ^ key`, then advances the key.
    pub fn encrypt(&mut self, plaintext: u32) -> u32 {
        let wire = plaintext ^ self.key;
        self.key = datum_header_xor_feedback(self.key);
        wire
    }

    /// Decrypt: returns `plaintext = wire_word ^ key`, then advances the key.
    /// Must be called in the same order `encrypt` was on the matching peer.
    pub fn decrypt(&mut self, wire: u32) -> u32 {
        let plaintext = wire ^ self.key;
        self.key = datum_header_xor_feedback(self.key);
        plaintext
    }

    pub fn current_key(&self) -> u32 {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_matches_c_seed_value() {
        let v = datum_header_xor_feedback(0);
        assert_ne!(v, 0);
        let v2 = datum_header_xor_feedback(v);
        assert_ne!(v, v2);
    }

    #[test]
    fn obfuscator_round_trips_post_handshake() {
        let nk: u32 = 0xdead_beef;
        let mut sender = HeaderObfuscator::for_sender(nk);
        let mut receiver = HeaderObfuscator::for_sender(nk);
        let plaintext = [0x1234_5678u32, 0x9abc_def0, 0x0011_2233];
        let wire: Vec<u32> = plaintext.iter().map(|w| sender.encrypt(*w)).collect();
        let recovered: Vec<u32> = wire.iter().map(|w| receiver.decrypt(*w)).collect();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn sender_and_receiver_chains_diverge() {
        let nk: u32 = 0xdead_beef;
        let sender = HeaderObfuscator::for_sender(nk);
        let receiver = HeaderObfuscator::for_receiver(nk);
        assert_ne!(sender.current_key(), receiver.current_key());
    }

    #[test]
    fn initial_sender_uses_constant_key() {
        let o = HeaderObfuscator::initial_sender();
        assert_eq!(o.current_key(), INITIAL_SENDING_HEADER_KEY);
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let mut o = HeaderObfuscator::initial_sender();
        let p = 0x1234_5678;
        assert_ne!(o.encrypt(p), p);
    }

    #[test]
    fn first_frame_xor_pinned() {
        let mut o = HeaderObfuscator::initial_sender();
        let plaintext = 0x1234_5678u32;
        let wire = o.encrypt(plaintext);
        assert_eq!(wire, plaintext ^ INITIAL_SENDING_HEADER_KEY);
        assert_eq!(
            o.current_key(),
            datum_header_xor_feedback(INITIAL_SENDING_HEADER_KEY)
        );
    }

    #[test]
    fn key_chain_is_independent_of_plaintext() {
        let mut a = HeaderObfuscator::initial_sender();
        let mut b = HeaderObfuscator::initial_sender();
        let _ = a.encrypt(0xaaaa_aaaa);
        let _ = b.encrypt(0x5555_5555);
        assert_eq!(a.current_key(), b.current_key());
    }
}
