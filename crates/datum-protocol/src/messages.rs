//! Post-handshake DATUM message bodies.
//!
//! Once the handshake completes, every frame the gateway and pool exchange is
//! a [`FrameHeader`] (XOR'd with the sender's chain) followed by an
//! XSalsa20Poly1305-sealed body. The frame's `proto_cmd` field selects the
//! top-level message; for `proto_cmd = 5` (`Coinbaser`/mining-multiplexed)
//! the first byte of the body further selects a sub-command.
//!
//! ## Opcode map (from `datum_protocol.c:929-958`)
//!
//! | proto_cmd | sub | direction | Meaning |
//! |-----------|-----|-----------|---------|
//! | 0x10 | 0x10 | client → pool | Coinbaser fetch request |
//! | 0x10 | 0x11 | pool → client | Coinbaser fetch response (V2 blob; see `datum_coinbaser`) |
//! | 0x05 | 0x99 | pool → client | Client configuration override |
//! | 0x05 | 0x50 | pool → client | Job-validation sub-command |
//! | 0x05 | 0x8F | pool → client | Share submission ack (accepted/rejected) |
//! | 0xF9 | -    | pool → client | Block-found notification |
//! | 0x27 | -    | client → pool | Share submission |
//!
//! ## Phase 2 status
//!
//! - **Coinbaser request (0x10)**: implemented + tested below. The body is a
//!   single byte and the simplest possible codec — useful as a smoke test
//!   for the post-handshake encrypted pipeline.
//! - **All other opcodes**: documented here for grep-parity with the C
//!   reference but **not yet implemented**. Each follows the same shape:
//!   one struct per message, an `encode(&self) -> Vec<u8>` method that
//!   produces the body plaintext, a `decode(bytes: &[u8]) -> Result` that
//!   parses it back. They land in subsequent commits as the runtime needs
//!   them. Tracked in issue #2 under "DATUM messages".

use thiserror::Error;

/// Sub-opcode for client→pool coinbaser-fetch under `proto_cmd = 0x10`.
pub const COINBASER_FETCH_OPCODE: u8 = 0x10;

/// Sub-opcode for pool→client coinbaser-fetch response under `proto_cmd = 0x10`.
pub const COINBASER_RESPONSE_OPCODE: u8 = 0x11;

/// Sub-opcode for client-configuration override under `proto_cmd = 0x05`.
/// See `datum_protocol.c:932-936`.
pub const CLIENT_CONFIG_OPCODE: u8 = 0x99;

/// Sub-opcode for share submission ack under `proto_cmd = 0x05`.
/// See `datum_protocol.c:950-954`.
pub const SHARE_RESPONSE_OPCODE: u8 = 0x8F;

/// Sub-opcode for job-validation under `proto_cmd = 0x05`.
/// See `datum_protocol.c:944-948`.
pub const JOB_VALIDATION_OPCODE: u8 = 0x50;

/// Share-response status: accepted.
pub const SHARE_ACCEPTED: u8 = 0x01;
/// Share-response status: tentatively accepted (typically a low-PoW share).
pub const SHARE_ACCEPTED_TENTATIVELY: u8 = 0x02;
/// Share-response status: rejected.
pub const SHARE_REJECTED: u8 = 0x80;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageError {
    #[error("body too short: got {got}, need at least {need}")]
    TooShort { got: usize, need: usize },
    #[error("invalid sub-opcode: got {got:#04x}, expected {expected:#04x}")]
    BadSubOpcode { got: u8, expected: u8 },
    #[error("invalid share-response status byte: {0:#04x}")]
    BadShareStatus(u8),
}

/// `proto_cmd = 0x10` body for a client→pool coinbaser-fetch request.
/// Wire body is just the single-byte sub-opcode `0x10`. The C reference does
/// not pad coinbaser requests (`datum_protocol.c` does not call coinbaser
/// fetch from the gateway in master, but the inverse — pool sending the
/// blob — uses sub-opcode `0x11` with a longer body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinbaserFetchRequest;

impl CoinbaserFetchRequest {
    pub fn encode(self) -> Vec<u8> {
        vec![COINBASER_FETCH_OPCODE]
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.is_empty() {
            return Err(MessageError::TooShort { got: 0, need: 1 });
        }
        if body[0] != COINBASER_FETCH_OPCODE {
            return Err(MessageError::BadSubOpcode {
                got: body[0],
                expected: COINBASER_FETCH_OPCODE,
            });
        }
        Ok(CoinbaserFetchRequest)
    }
}

/// `proto_cmd = 0x05` `sub = 0x8F` body: pool's response to a share submission.
/// The C reference parses this at `datum_protocol.c:889-923`. The body shape
/// (after the leading sub-opcode byte stripped by the caller) is:
///
/// - byte 0: status (one of [`SHARE_ACCEPTED`], [`SHARE_ACCEPTED_TENTATIVELY`],
///   [`SHARE_REJECTED`] — actual values from the C source)
/// - bytes 1-2: rejection reason code (LE u16; only meaningful when rejected)
/// - bytes 3-6: nonce (LE u32) of the original share
/// - byte 7: target power-of-two (`TargetPOT`) field
/// - byte 8: job ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareResponse {
    pub status: ShareStatus,
    pub reject_reason: u16,
    pub nonce: u32,
    pub target_pot: u8,
    pub job_id: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareStatus {
    Accepted,
    AcceptedTentatively,
    Rejected,
}

impl ShareResponse {
    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() < 9 {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: 9,
            });
        }
        let status = match body[0] {
            SHARE_ACCEPTED => ShareStatus::Accepted,
            SHARE_ACCEPTED_TENTATIVELY => ShareStatus::AcceptedTentatively,
            SHARE_REJECTED => ShareStatus::Rejected,
            other => return Err(MessageError::BadShareStatus(other)),
        };
        let reject_reason = u16::from_le_bytes([body[1], body[2]]);
        let nonce = u32::from_le_bytes([body[3], body[4], body[5], body[6]]);
        Ok(ShareResponse {
            status,
            reject_reason,
            nonce,
            target_pot: body[7],
            job_id: body[8],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbaser_fetch_round_trip() {
        let req = CoinbaserFetchRequest;
        let bytes = req.encode();
        assert_eq!(bytes, vec![COINBASER_FETCH_OPCODE]);
        let decoded = CoinbaserFetchRequest::decode(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn coinbaser_fetch_decode_empty() {
        assert!(matches!(
            CoinbaserFetchRequest::decode(&[]),
            Err(MessageError::TooShort { got: 0, need: 1 })
        ));
    }

    #[test]
    fn coinbaser_fetch_decode_wrong_opcode() {
        assert!(matches!(
            CoinbaserFetchRequest::decode(&[0x42]),
            Err(MessageError::BadSubOpcode {
                got: 0x42,
                expected: 0x10
            })
        ));
    }

    #[test]
    fn share_response_decode_accepted() {
        let body = vec![
            SHARE_ACCEPTED,
            0x00,
            0x00,
            0x12,
            0x34,
            0x56,
            0x78,
            0x10,
            0x07,
        ];
        let r = ShareResponse::decode(&body).unwrap();
        assert!(matches!(r.status, ShareStatus::Accepted));
        assert_eq!(r.nonce, 0x7856_3412);
        assert_eq!(r.target_pot, 0x10);
        assert_eq!(r.job_id, 0x07);
    }

    #[test]
    fn share_response_decode_rejected_with_reason() {
        let body = vec![SHARE_REJECTED, 0x05, 0x00, 0, 0, 0, 0, 0xFF, 0x42];
        let r = ShareResponse::decode(&body).unwrap();
        assert!(matches!(r.status, ShareStatus::Rejected));
        assert_eq!(r.reject_reason, 5);
        assert_eq!(r.target_pot, 0xFF);
        assert_eq!(r.job_id, 0x42);
    }

    #[test]
    fn share_response_decode_too_short() {
        let body = vec![SHARE_ACCEPTED, 0, 0, 0];
        assert!(matches!(
            ShareResponse::decode(&body),
            Err(MessageError::TooShort { .. })
        ));
    }

    #[test]
    fn share_response_decode_unknown_status() {
        let body = vec![0xCC, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            ShareResponse::decode(&body),
            Err(MessageError::BadShareStatus(0xCC))
        ));
    }
}
