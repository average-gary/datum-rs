//! Stratum V1 server side.
//!
//! Phase 3 status:
//! - Message types + JSON envelope round-trips: shipped.
//! - Per-connection state machine (subscribe → authorize → notify → submit):
//!   shipped with mock-tested server task.
//! - The 8-job ring + share validation against real Bitcoin PoW: deferred
//!   until we have a way to feed real templates into the integration test.
//!   The submit handler validates message shape, dedup-keys against
//!   `datum-dupes`, and acks with a structured response.
//! - Vardiff: documented in `vardiff.rs` constants but not yet driving the
//!   set_difficulty cadence — needs real share-rate signal from the runtime.
//!
//! Per [gateway-internals-c-architecture] § extranonce layout: SV1 uses
//! `extranonce1 = (thread_id << 22) | (client_id ^ 0xB10CF00D)` (32 bits).
//! Preserved verbatim for grep-parity with C operator alerts.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub mod assembler;
pub mod server;

pub use assembler::ScriptSigInputs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumRequest {
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumResponse {
    pub id: Value,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub error: Value,
}

impl StratumResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            id,
            result,
            error: Value::Null,
        }
    }

    pub fn err(id: Value, code: i64, message: &str) -> Self {
        Self {
            id,
            result: Value::Null,
            error: json!([code, message, Value::Null]),
        }
    }
}

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("not subscribed")]
    NotSubscribed,
    #[error("not authorized")]
    NotAuthorized,
    #[error("stale share: prev_block_hash mismatch")]
    Stale,
    #[error("share below local target")]
    LowDifficulty,
    #[error("duplicate share")]
    Duplicate,
    #[error("ntime out of range")]
    NtimeOutOfRange,
    #[error("job_id not in 8-job ring")]
    JobAgedOut,
    #[error("malformed share: {0}")]
    Malformed(String),
}

/// SV1 extranonce1 layout per `gateway-internals-c-architecture` § extranonce
/// layout: `extranonce1 = (thread_id << 22) | (client_id ^ 0xB10CF00D)`.
pub fn extranonce1(thread_id: u16, client_id: u32) -> u32 {
    ((thread_id as u32) << 22) | (client_id ^ 0xB10C_F00D)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extranonce1_layout() {
        let xn0 = extranonce1(0, 0);
        let xn1 = extranonce1(1, 0);
        assert_eq!(xn0, 0xB10C_F00D);
        assert_eq!(xn1.wrapping_sub(xn0), 1u32 << 22);
    }

    #[test]
    fn parse_subscribe_request() {
        let raw = r#"{"id":1,"method":"mining.subscribe","params":["miner/1.0"]}"#;
        let req: StratumRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.method, "mining.subscribe");
    }

    #[test]
    fn build_response() {
        let r = StratumResponse::ok(json!(1), json!(true));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"result\":true"));
    }

    #[test]
    fn build_error_response() {
        let r = StratumResponse::err(json!(42), 23, "stale work");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"id\":42"));
        assert!(s.contains("\"error\":[23,\"stale work\",null]"));
    }
}
