//! Asserts our wire-format decoder agrees with bytes captured from a real
//! C `datum_gateway` build (commit a3da9e69 via Docker; see capture
//! procedure in TESTING.md).
//!
//! Captures vary in length per-run because the C reference picks a random
//! padding byte count [1, 200] and a random nk. What stays stable across
//! captures is:
//!
//! - First 4 bytes are the XOR'd frame header.
//! - De-XOR with INITIAL_SENDING_HEADER_KEY = 0xDC871829 yields a header
//!   whose flag bits are: is_signed=1, is_encrypted_pubkey=1,
//!   is_encrypted_channel=0, proto_cmd=0x01.
//! - cmd_len matches `total_bytes - 4` (i.e. captured payload size).
//!
//! These three invariants pin the C-side wire format we must produce.

use datum_protocol::{FrameHeader, HeaderObfuscator};

const CAPTURE: &[u8] = include_bytes!("fixtures/c-hello-capture.bin");

#[test]
fn c_capture_has_at_least_a_header_and_seal_overhead() {
    assert!(
        CAPTURE.len() > 4 + 48,
        "capture is too short to contain a sealed payload: {}",
        CAPTURE.len()
    );
}

#[test]
fn c_header_flags_match_our_encoding() {
    let mut obf = HeaderObfuscator::initial_sender();
    let wire_word = u32::from_le_bytes(CAPTURE[..4].try_into().unwrap());
    let plain_word = obf.decrypt(wire_word);
    let header = FrameHeader::unpack(plain_word.to_le_bytes());

    assert!(header.is_signed, "C hello should be signed");
    assert!(
        header.is_encrypted_pubkey,
        "C hello should be encrypted to pool's pubkey"
    );
    assert!(
        !header.is_encrypted_channel,
        "C hello pre-handshake should not have channel encryption set"
    );
    assert_eq!(header.proto_cmd, 0x01, "C hello opcode is 0x01");

    assert_eq!(
        header.cmd_len as usize,
        CAPTURE.len() - 4,
        "header cmd_len should equal sealed-payload byte count"
    );
}
