use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::watch;

pub const MAX_OUTPUTS: usize = 512;
pub const MIN_SCRIPT_LEN: u8 = 2;
pub const MAX_SCRIPT_LEN: u8 = 64;

/// One generation output produced by OCEAN's V2 coinbaser blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseOutput {
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
}

impl CoinbaseOutput {
    /// Mirrors the C kludge: P2PKH outputs are charged 4 sigops; everything else 0.
    pub fn sigops(&self) -> u32 {
        if self.script_pubkey.first() == Some(&0x76) {
            4
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaserBlob {
    pub datum_id: u8,
    pub outputs: Vec<CoinbaseOutput>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoinbaserError {
    #[error("blob too short ({got} bytes; need >= 9 to hold a datum_id + 1 output)")]
    TooShort { got: usize },
    #[error("output {idx}: trailing bytes ({remaining}) less than required ({need})")]
    Truncated {
        idx: usize,
        remaining: usize,
        need: usize,
    },
    #[error("output {idx}: script length {slen} not in [2, 64]")]
    BadScriptLen { idx: usize, slen: u8 },
}

/// Parse a V2 coinbaser blob: `[datum_id 1B][outval LE 8B][slen 1B][script slen]…`.
///
/// `coinbase_value` caps the running total; outputs that would exceed it are
/// silently dropped, matching the C reference.
///
/// **Empty blob handling**: per the C reference (datum_coinbaser.c:776-781), a
/// blob shorter than 9 bytes is logged at WARN level and treated as zero
/// outputs. We surface it as an error so callers explicitly choose what to do.
pub fn parse_v2_blob(blob: &[u8], coinbase_value: u64) -> Result<CoinbaserBlob, CoinbaserError> {
    if blob.len() < 9 {
        return Err(CoinbaserError::TooShort { got: blob.len() });
    }

    let datum_id = blob[0];
    let mut idx = 1usize;
    let mut tally: u64 = 0;
    let mut outputs: Vec<CoinbaseOutput> = Vec::new();

    while idx < blob.len() {
        let remaining = blob.len() - idx;
        if remaining < 9 {
            return Err(CoinbaserError::Truncated {
                idx: outputs.len(),
                remaining,
                need: 9,
            });
        }
        let outval = u64::from_le_bytes(blob[idx..idx + 8].try_into().unwrap());
        idx += 8;
        let slen = blob[idx];
        idx += 1;

        if !(MIN_SCRIPT_LEN..=MAX_SCRIPT_LEN).contains(&slen) {
            return Err(CoinbaserError::BadScriptLen {
                idx: outputs.len(),
                slen,
            });
        }
        if blob.len() - idx < slen as usize {
            return Err(CoinbaserError::Truncated {
                idx: outputs.len(),
                remaining: blob.len() - idx,
                need: slen as usize,
            });
        }

        if outval.saturating_add(tally) > coinbase_value {
            tracing::debug!(
                tally,
                outval,
                coinbase_value,
                "coinbaser blob: drop output that exceeds coinbase_value"
            );
            break;
        }
        let script = blob[idx..idx + slen as usize].to_vec();
        idx += slen as usize;
        tally += outval;
        outputs.push(CoinbaseOutput {
            value_sats: outval,
            script_pubkey: script,
        });

        if outputs.len() >= MAX_OUTPUTS {
            break;
        }
    }

    Ok(CoinbaserBlob { datum_id, outputs })
}

/// Encode a CoinbaserBlob back to the wire V2 format. For test fixtures and
/// mock-pool round-trip checks. Returns BadScriptLen on individual outputs that
/// violate the [2, 64] constraint.
pub fn encode_v2_blob(blob: &CoinbaserBlob) -> Result<Vec<u8>, CoinbaserError> {
    let mut out = Vec::with_capacity(1 + blob.outputs.len() * 16);
    out.push(blob.datum_id);
    for (idx, o) in blob.outputs.iter().enumerate() {
        let slen = o.script_pubkey.len();
        let slen_u8 = u8::try_from(slen).unwrap_or(255);
        if !(MIN_SCRIPT_LEN..=MAX_SCRIPT_LEN).contains(&slen_u8) {
            return Err(CoinbaserError::BadScriptLen { idx, slen: slen_u8 });
        }
        out.extend_from_slice(&o.value_sats.to_le_bytes());
        out.push(slen_u8);
        out.extend_from_slice(&o.script_pubkey);
    }
    Ok(out)
}

/// Single source-of-truth coinbase outputs broadcast channel. Both SV1 and SV2
/// paths consume from the same `Receiver<Arc<CoinbaserBlob>>`. Per the wiki
/// plan, divergence here is a catastrophic failure mode (operator could pay
/// self instead of OCEAN).
#[derive(Clone)]
pub struct CoinbaserChannel {
    rx: watch::Receiver<Option<Arc<CoinbaserBlob>>>,
}

impl CoinbaserChannel {
    pub fn current(&self) -> Option<Arc<CoinbaserBlob>> {
        self.rx.borrow().clone()
    }

    pub async fn changed(&mut self) -> Result<Arc<CoinbaserBlob>, watch::error::RecvError> {
        loop {
            self.rx.changed().await?;
            if let Some(t) = self.rx.borrow_and_update().clone() {
                return Ok(t);
            }
        }
    }
}

pub struct CoinbaserPublisher {
    tx: watch::Sender<Option<Arc<CoinbaserBlob>>>,
}

impl CoinbaserPublisher {
    pub fn new() -> (Self, CoinbaserChannel) {
        let (tx, rx) = watch::channel(None);
        (Self { tx }, CoinbaserChannel { rx })
    }

    pub fn publish(
        &self,
        blob: CoinbaserBlob,
    ) -> Result<(), watch::error::SendError<Option<Arc<CoinbaserBlob>>>> {
        self.tx.send(Some(Arc::new(blob)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p2pkh(byte: u8) -> Vec<u8> {
        vec![0x76, 0xa9, byte, byte, byte]
    }

    #[test]
    fn parse_simple_blob() {
        let blob = CoinbaserBlob {
            datum_id: 7,
            outputs: vec![
                CoinbaseOutput {
                    value_sats: 100_000,
                    script_pubkey: p2pkh(0xaa),
                },
                CoinbaseOutput {
                    value_sats: 50_000,
                    script_pubkey: vec![0x00, 0x14, 0xbb, 0xbb, 0xbb],
                },
            ],
        };
        let bytes = encode_v2_blob(&blob).unwrap();
        let parsed = parse_v2_blob(&bytes, 1_000_000).unwrap();
        assert_eq!(parsed, blob);
    }

    #[test]
    fn parse_too_short() {
        let err = parse_v2_blob(&[1, 2, 3], 1000).unwrap_err();
        assert!(matches!(err, CoinbaserError::TooShort { got: 3 }));
    }

    #[test]
    fn parse_drops_outputs_exceeding_coinbase_value() {
        let blob = CoinbaserBlob {
            datum_id: 1,
            outputs: vec![
                CoinbaseOutput {
                    value_sats: 600,
                    script_pubkey: p2pkh(1),
                },
                CoinbaseOutput {
                    value_sats: 500,
                    script_pubkey: p2pkh(2),
                },
                CoinbaseOutput {
                    value_sats: 100,
                    script_pubkey: p2pkh(3),
                },
            ],
        };
        let bytes = encode_v2_blob(&blob).unwrap();
        let parsed = parse_v2_blob(&bytes, 1000).unwrap();
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.outputs[0].value_sats, 600);
    }

    #[test]
    fn rejects_bad_script_len_short() {
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&100u64.to_le_bytes());
        bytes.push(1);
        bytes.push(0xaa);
        let err = parse_v2_blob(&bytes, 1000).unwrap_err();
        assert!(matches!(err, CoinbaserError::BadScriptLen { slen: 1, .. }));
    }

    #[test]
    fn rejects_bad_script_len_long() {
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&100u64.to_le_bytes());
        bytes.push(65);
        bytes.extend(std::iter::repeat_n(0u8, 65));
        let err = parse_v2_blob(&bytes, 1000).unwrap_err();
        assert!(matches!(err, CoinbaserError::BadScriptLen { slen: 65, .. }));
    }

    #[test]
    fn rejects_truncated_script() {
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&100u64.to_le_bytes());
        bytes.push(20);
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let err = parse_v2_blob(&bytes, 1000).unwrap_err();
        assert!(matches!(err, CoinbaserError::Truncated { need: 20, .. }));
    }

    #[test]
    fn p2pkh_sigops_kludge() {
        let p2pkh_out = CoinbaseOutput {
            value_sats: 0,
            script_pubkey: p2pkh(1),
        };
        let p2wpkh_out = CoinbaseOutput {
            value_sats: 0,
            script_pubkey: vec![0x00, 0x14, 0x00],
        };
        assert_eq!(p2pkh_out.sigops(), 4);
        assert_eq!(p2wpkh_out.sigops(), 0);
    }

    #[tokio::test]
    async fn watch_channel_round_trips() {
        let (pub_, mut sub) = CoinbaserPublisher::new();
        let blob = CoinbaserBlob {
            datum_id: 9,
            outputs: vec![CoinbaseOutput {
                value_sats: 1234,
                script_pubkey: p2pkh(0x42),
            }],
        };
        pub_.publish(blob.clone()).unwrap();
        let received = sub.changed().await.unwrap();
        assert_eq!(*received, blob);
    }

    #[test]
    fn parse_512_output_cap() {
        let mut blob = Vec::new();
        blob.push(1u8);
        for _ in 0..600 {
            blob.extend_from_slice(&1u64.to_le_bytes());
            blob.push(2);
            blob.extend_from_slice(&[0xaa, 0xbb]);
        }
        let parsed = parse_v2_blob(&blob, u64::MAX).unwrap();
        assert_eq!(parsed.outputs.len(), MAX_OUTPUTS);
    }
}
