//! Stratum V2 server side — opt-in port (default 23335).
//!
//! Phase 3 status: extranonce 32→12-byte bridge implemented and tested.
//! The real SV2 server runtime depends on SRI's `channels_sv2` +
//! `handlers_sv2` crates; integration is deferred until the SRI version
//! pin is decided (currently tracked in inventory `sri-master-watch`).
//!
//! Per [sv2-downstream-architecture]: 9.6:1 reuse from SRI vs ~1500 LOC
//! written here. The remaining writes target an in-process drop-in (the
//! sidecar pattern in the wiki article assumed a separate proxy process).

use thiserror::Error;

/// 32-byte SV2 hierarchical extranonce → 12-byte flat (DATUM upstream
/// expects a single 12-byte field). Per [sv2-downstream-architecture] §
/// extranonce mismatch: set ExtranonceAllocator total_extranonce_len = 12,
/// partition `[local_prefix=0, local_index=2, rollable=10]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtranonceBridge {
    pub local_index_bytes: u8,
    pub rollable_bytes: u8,
}

impl Default for ExtranonceBridge {
    fn default() -> Self {
        Self {
            local_index_bytes: 2,
            rollable_bytes: 10,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeError {
    #[error(
        "extranonce parts must sum to 12: prefix({prefix}) + index({index}) + roll({roll}) = {sum}"
    )]
    BadPartition {
        prefix: u8,
        index: u8,
        roll: u8,
        sum: u8,
    },
    #[error("input length {got} != 12 bytes")]
    BadLength { got: usize },
}

impl ExtranonceBridge {
    pub fn new(local_index_bytes: u8, rollable_bytes: u8) -> Result<Self, BridgeError> {
        let sum = local_index_bytes as u32 + rollable_bytes as u32;
        if sum != 12 {
            return Err(BridgeError::BadPartition {
                prefix: 0,
                index: local_index_bytes,
                roll: rollable_bytes,
                sum: sum as u8,
            });
        }
        Ok(Self {
            local_index_bytes,
            rollable_bytes,
        })
    }

    /// Concatenate prefix + rolling for upstream submit. The DATUM share-
    /// submit opcode (0x27) expects a single 12-byte extranonce field.
    pub fn concat_for_upstream(
        &self,
        local_prefix: &[u8],
        rolling: &[u8],
    ) -> Result<[u8; 12], BridgeError> {
        if local_prefix.len() + rolling.len() != 12 {
            return Err(BridgeError::BadLength {
                got: local_prefix.len() + rolling.len(),
            });
        }
        let mut out = [0u8; 12];
        out[..local_prefix.len()].copy_from_slice(local_prefix);
        out[local_prefix.len()..].copy_from_slice(rolling);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_partition_sums_to_12() {
        let b = ExtranonceBridge::default();
        assert_eq!(b.local_index_bytes as u32 + b.rollable_bytes as u32, 12);
    }

    #[test]
    fn alternative_partition_4_8() {
        ExtranonceBridge::new(4, 8).unwrap();
    }

    #[test]
    fn rejects_bad_partition() {
        let err = ExtranonceBridge::new(3, 8).unwrap_err();
        assert!(matches!(err, BridgeError::BadPartition { sum: 11, .. }));
    }

    #[test]
    fn concat_for_upstream() {
        let b = ExtranonceBridge::new(2, 10).unwrap();
        let out = b.concat_for_upstream(&[0x11, 0x22], &[0xAA; 10]).unwrap();
        assert_eq!(&out[..2], &[0x11, 0x22]);
        assert_eq!(&out[2..], &[0xAA; 10]);
    }

    #[test]
    fn concat_rejects_bad_total() {
        let b = ExtranonceBridge::new(2, 10).unwrap();
        let err = b.concat_for_upstream(&[0x11], &[0xAA; 10]).unwrap_err();
        assert!(matches!(err, BridgeError::BadLength { got: 11 }));
    }
}
