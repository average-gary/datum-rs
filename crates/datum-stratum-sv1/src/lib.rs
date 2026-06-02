//! Stratum V1 server side.
//!
//! Phase 3 status: SV1 message types + JSON envelope round-trips +
//! extranonce layout helper land here. The full direct-serve runtime
//! (`mining.subscribe`, `mining.authorize`, vardiff loop, share validation
//! against the 8-job ring) is deferred — it requires a tokio TCP listener
//! and golden-vector tests against a running C `datum_gateway` to confirm
//! byte-exact `mining.notify` parity.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

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
/// 32-bit field. The 0xB10CF00D mask keeps collision distinguishability in
/// logs — preserved verbatim for parity with the C gateway.
pub fn extranonce1(thread_id: u16, client_id: u32) -> u32 {
    ((thread_id as u32) << 22) | (client_id ^ 0xB10C_F00D)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extranonce1_layout() {
        let xn = extranonce1(0, 0);
        assert_eq!(xn, 0xB10C_F00D);
        let xn0 = extranonce1(0, 0);
        let xn1 = extranonce1(1, 0);
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
        let r = StratumResponse {
            id: json!(1),
            result: json!(true),
            error: json!(null),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"result\":true"));
    }
}
