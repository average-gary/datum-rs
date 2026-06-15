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

/// Share-response status: accepted. C reference `datum_protocol.h:168`.
pub const SHARE_ACCEPTED: u8 = 0x50;
/// Share-response status: tentatively accepted (typically a low-PoW share).
/// C reference `datum_protocol.h:169`.
pub const SHARE_ACCEPTED_TENTATIVELY: u8 = 0x55;
/// Share-response status: rejected. C reference `datum_protocol.h:170`.
pub const SHARE_REJECTED: u8 = 0x66;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageError {
    #[error("body too short: got {got}, need at least {need}")]
    TooShort { got: usize, need: usize },
    #[error("invalid sub-opcode: got {got:#04x}, expected {expected:#04x}")]
    BadSubOpcode { got: u8, expected: u8 },
    #[error("invalid share-response status byte: {0:#04x}")]
    BadShareStatus(u8),
    #[error("invalid client-configuration version: got {got}, expected 1")]
    BadConfigVersion { got: u8 },
    #[error("missing client-configuration trailer (expected 0x00 0xFE)")]
    MissingConfigTrailer,
    #[error("invalid coinbaser-response length field: blob_len={blob_len}, body trailing bytes={trailing}")]
    BadCoinbaserLength { blob_len: u32, trailing: usize },
    #[error("share extranonce length must be 12, got {got}")]
    BadExtranonceLength { got: u8 },
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

/// `proto_cmd = 0x05` `sub = 0x11` body: pool's coinbaser response containing
/// the V2 blob (see `datum-coinbaser` for blob format). Per
/// `datum_protocol.c:275-318`:
///
/// - bytes 0-7: coinbase value (LE u64)
/// - bytes 8-11: blob length (LE u32; must be in [1, 32767] and ≤ trailing-bytes)
/// - bytes 12..12+blob_len: V2 coinbaser blob
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaserResponse {
    pub coinbase_value: u64,
    pub v2_blob: Vec<u8>,
}

impl CoinbaserResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.v2_blob.len());
        out.extend_from_slice(&self.coinbase_value.to_le_bytes());
        out.extend_from_slice(&(self.v2_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.v2_blob);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() < 12 {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: 12,
            });
        }
        let coinbase_value = u64::from_le_bytes(body[..8].try_into().unwrap());
        let blob_len = u32::from_le_bytes(body[8..12].try_into().unwrap());
        let trailing = body.len() - 12;
        if !(1..=32767).contains(&blob_len) || (blob_len as usize) > trailing {
            return Err(MessageError::BadCoinbaserLength { blob_len, trailing });
        }
        Ok(CoinbaserResponse {
            coinbase_value,
            v2_blob: body[12..12 + blob_len as usize].to_vec(),
        })
    }
}

/// `proto_cmd = 0x05` `sub = 0x99` body: pool-pushed configuration override.
/// Per `datum_protocol.c:390-435`:
///
/// - byte 0: config version (must be 1)
/// - byte 1: pool scriptsig length N
/// - bytes 2..2+N: pool scriptsig
/// - bytes 2+N..6+N: prime_id (LE u32)
/// - byte 6+N: pool coinbase tag length M
/// - bytes 7+N..7+N+M: pool coinbase tag
/// - bytes 7+N+M..15+N+M: vardiff_min (LE u64)
/// - bytes 15+N+M..17+N+M: trailer 0x00 0xFE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub pool_scriptsig: Vec<u8>,
    pub prime_id: u32,
    pub pool_coinbase_tag: Vec<u8>,
    pub vardiff_min: u64,
}

impl ClientConfig {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1);
        out.push(self.pool_scriptsig.len() as u8);
        out.extend_from_slice(&self.pool_scriptsig);
        out.extend_from_slice(&self.prime_id.to_le_bytes());
        out.push(self.pool_coinbase_tag.len() as u8);
        out.extend_from_slice(&self.pool_coinbase_tag);
        out.extend_from_slice(&self.vardiff_min.to_le_bytes());
        out.push(0);
        out.push(0xFE);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        let mut i = 0usize;
        if body.is_empty() {
            return Err(MessageError::TooShort { got: 0, need: 1 });
        }
        if body[i] != 1 {
            return Err(MessageError::BadConfigVersion { got: body[i] });
        }
        i += 1;

        if i >= body.len() {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: i + 1,
            });
        }
        let scriptsig_len = body[i] as usize;
        i += 1;
        if i + scriptsig_len > body.len() {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: i + scriptsig_len,
            });
        }
        let pool_scriptsig = body[i..i + scriptsig_len].to_vec();
        i += scriptsig_len;

        if i + 4 > body.len() {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: i + 4,
            });
        }
        let prime_id = u32::from_le_bytes(body[i..i + 4].try_into().unwrap());
        i += 4;

        if i >= body.len() {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: i + 1,
            });
        }
        let tag_len = body[i] as usize;
        i += 1;
        if i + tag_len > body.len() {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: i + tag_len,
            });
        }
        let pool_coinbase_tag = body[i..i + tag_len].to_vec();
        i += tag_len;

        if i + 8 > body.len() {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: i + 8,
            });
        }
        let vardiff_min = u64::from_le_bytes(body[i..i + 8].try_into().unwrap());
        i += 8;

        if i + 2 > body.len() {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: i + 2,
            });
        }
        if body[i] != 0 || body[i + 1] != 0xFE {
            return Err(MessageError::MissingConfigTrailer);
        }

        Ok(ClientConfig {
            pool_scriptsig,
            prime_id,
            pool_coinbase_tag,
            vardiff_min,
        })
    }
}

/// `proto_cmd = 0x27` body: client→pool share submission. Fixed-prefix portion
/// (29 bytes). The variable-length suffix (username, optional merkle-branch
/// payload) is left for the runtime to assemble; this struct covers the prefix
/// that's identical across every share submission per `datum_protocol.c:1329-
/// 1340`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareSubmissionPrefix {
    pub job_id: u8,
    pub coinbase_id: u8,
    pub flags: u8,
    pub target_byte: u8,
    pub ntime: u32,
    pub nonce: u32,
    pub version: u32,
    pub extranonce: [u8; 12],
}

/// 30 bytes: 1 opcode + 4 single-byte fields + 3 LE u32s + 1 xn_len + 12 extranonce.
pub const SHARE_SUBMISSION_PREFIX_LEN: usize = 30;

impl ShareSubmissionPrefix {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SHARE_SUBMISSION_PREFIX_LEN);
        out.push(0x27);
        out.push(self.job_id);
        out.push(self.coinbase_id);
        out.push(self.flags);
        out.push(self.target_byte);
        out.extend_from_slice(&self.ntime.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(12);
        out.extend_from_slice(&self.extranonce);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() < SHARE_SUBMISSION_PREFIX_LEN {
            return Err(MessageError::TooShort {
                got: body.len(),
                need: SHARE_SUBMISSION_PREFIX_LEN,
            });
        }
        if body[0] != 0x27 {
            return Err(MessageError::BadSubOpcode {
                got: body[0],
                expected: 0x27,
            });
        }
        let xn_len = body[17];
        if xn_len != 12 {
            return Err(MessageError::BadExtranonceLength { got: xn_len });
        }
        Ok(ShareSubmissionPrefix {
            job_id: body[1],
            coinbase_id: body[2],
            flags: body[3],
            target_byte: body[4],
            ntime: u32::from_le_bytes(body[5..9].try_into().unwrap()),
            nonce: u32::from_le_bytes(body[9..13].try_into().unwrap()),
            version: u32::from_le_bytes(body[13..17].try_into().unwrap()),
            extranonce: body[18..30].try_into().unwrap(),
        })
    }
}

/// `proto_cmd = 0xF9` body: pool-pushed block-found notification (a peer in
/// the network mined a new tip). The C reference treats the whole frame as a
/// single binary payload of variable length used to short-circuit GBT polls.
/// We surface the body bytes verbatim — the contents are best handled at the
/// runtime level (refresh template).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockNotify {
    pub payload: Vec<u8>,
}

impl BlockNotify {
    pub fn encode(&self) -> Vec<u8> {
        self.payload.clone()
    }

    pub fn decode(body: &[u8]) -> Self {
        BlockNotify {
            payload: body.to_vec(),
        }
    }
}

/// `proto_cmd = 0x05` `sub = 0x50` body: job-validation. Three sub-sub
/// commands per `datum_protocol.c:862-883`:
/// - `0x10`: pool requests stxids list for a job.
/// - `0x11`: pool requests specific transactions by id.
/// - `0x12`: pool requests the entire serialized block (minus coinbase).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobValidationCmd {
    StxidsList,
    StxidsListById,
    SerializedBlock,
}

impl JobValidationCmd {
    pub fn opcode(self) -> u8 {
        match self {
            JobValidationCmd::StxidsList => 0x10,
            JobValidationCmd::StxidsListById => 0x11,
            JobValidationCmd::SerializedBlock => 0x12,
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.is_empty() {
            return Err(MessageError::TooShort { got: 0, need: 1 });
        }
        match body[0] {
            0x10 => Ok(JobValidationCmd::StxidsList),
            0x11 => Ok(JobValidationCmd::StxidsListById),
            0x12 => Ok(JobValidationCmd::SerializedBlock),
            other => Err(MessageError::BadSubOpcode {
                got: other,
                expected: 0x10,
            }),
        }
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

    #[test]
    fn coinbaser_response_round_trip() {
        let resp = CoinbaserResponse {
            coinbase_value: 312_500_000,
            v2_blob: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let bytes = resp.encode();
        assert_eq!(bytes.len(), 12 + 4);
        let decoded = CoinbaserResponse::decode(&bytes).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn coinbaser_response_rejects_zero_blob() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            CoinbaserResponse::decode(&bytes),
            Err(MessageError::BadCoinbaserLength { blob_len: 0, .. })
        ));
    }

    #[test]
    fn coinbaser_response_rejects_overlong_blob_len() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u64.to_le_bytes());
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        assert!(matches!(
            CoinbaserResponse::decode(&bytes),
            Err(MessageError::BadCoinbaserLength {
                blob_len: 100,
                trailing: 2
            })
        ));
    }

    #[test]
    fn client_config_round_trip() {
        let cfg = ClientConfig {
            pool_scriptsig: vec![0x01, 0x02, 0x03],
            prime_id: 0xCAFE_BABE,
            pool_coinbase_tag: b"ocean-tag".to_vec(),
            vardiff_min: 16384,
        };
        let bytes = cfg.encode();
        assert_eq!(*bytes.last().unwrap(), 0xFE);
        let decoded = ClientConfig::decode(&bytes).unwrap();
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn client_config_rejects_bad_version() {
        let bytes = vec![2u8, 0, 0xFE];
        assert!(matches!(
            ClientConfig::decode(&bytes),
            Err(MessageError::BadConfigVersion { got: 2 })
        ));
    }

    #[test]
    fn client_config_rejects_missing_trailer() {
        let cfg = ClientConfig {
            pool_scriptsig: vec![],
            prime_id: 0,
            pool_coinbase_tag: vec![],
            vardiff_min: 0,
        };
        let mut bytes = cfg.encode();
        let last = bytes.len() - 1;
        bytes[last] = 0xFD;
        assert!(matches!(
            ClientConfig::decode(&bytes),
            Err(MessageError::MissingConfigTrailer)
        ));
    }

    #[test]
    fn share_submission_prefix_round_trip() {
        let p = ShareSubmissionPrefix {
            job_id: 7,
            coinbase_id: 1,
            flags: 0b0000_0011,
            target_byte: 0x10,
            ntime: 0x6712_3456,
            nonce: 0xCAFE_BABE,
            version: 0x2000_0000,
            extranonce: [0x11; 12],
        };
        let bytes = p.encode();
        assert_eq!(bytes.len(), SHARE_SUBMISSION_PREFIX_LEN);
        assert_eq!(bytes[0], 0x27);
        assert_eq!(bytes[17], 12);
        let decoded = ShareSubmissionPrefix::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn share_submission_rejects_bad_extranonce_length() {
        let mut bytes = vec![0u8; SHARE_SUBMISSION_PREFIX_LEN];
        bytes[0] = 0x27;
        bytes[17] = 8;
        assert!(matches!(
            ShareSubmissionPrefix::decode(&bytes),
            Err(MessageError::BadExtranonceLength { got: 8 })
        ));
    }

    #[test]
    fn block_notify_round_trip() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let n = BlockNotify::decode(&payload);
        assert_eq!(n.payload, payload);
        assert_eq!(n.encode(), payload);
    }

    #[test]
    fn job_validation_decode_each_sub() {
        assert_eq!(
            JobValidationCmd::decode(&[0x10]).unwrap(),
            JobValidationCmd::StxidsList
        );
        assert_eq!(
            JobValidationCmd::decode(&[0x11]).unwrap(),
            JobValidationCmd::StxidsListById
        );
        assert_eq!(
            JobValidationCmd::decode(&[0x12]).unwrap(),
            JobValidationCmd::SerializedBlock
        );
    }

    #[test]
    fn job_validation_rejects_unknown_sub() {
        assert!(matches!(
            JobValidationCmd::decode(&[0xFF]),
            Err(MessageError::BadSubOpcode {
                got: 0xFF,
                expected: 0x10
            })
        ));
    }
}
