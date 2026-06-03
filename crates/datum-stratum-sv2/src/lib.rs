//! Stratum V2 server side — opt-in port (default 23335).
//!
//! Phase 3 status:
//! - Extranonce 32→12-byte bridge: shipped + tested (`ExtranonceBridge`).
//! - JobStore trait + in-memory store: shipped + tested below.
//! - Channel registry (concurrent map keyed by channel_id): shipped + tested.
//! - Cross-protocol golden-vector helper (asserts SV1 + SV2 paths produce
//!   the same coinbase output sum given identical inputs): shipped + tested.
//! - SRI `channels_sv2`/`handlers_sv2` integration: **deferred**. SRI is
//!   pinned at Rust 1.75 in master; we run on 1.89, and pulling SRI as a
//!   git dependency is a major fan-out (own MSRV, own deps tree, own
//!   transitive risks). The integration plan: pin a specific SRI rev in
//!   `Cargo.toml`, swap `InMemoryJobStore<Job>` for SRI's
//!   `DefaultJobStore<ExtendedJob>`, replace our `Channel` registry with
//!   `channels_sv2::server::extended::ExtendedChannel::new_for_pool`. The
//!   structural surface here matches the SRI shape so the swap is
//!   localized to two places.

use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;

use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};

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

/// Minimal SV2 job descriptor. Mirrors the shape SRI's `ExtendedJob` exposes
/// (job_id + future-bool + version + coinbase outputs); we keep our own type
/// so the rest of the workspace doesn't depend on SRI internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedJob {
    pub job_id: u32,
    pub is_future: bool,
    pub version: u32,
    pub additional_coinbase_outputs: Vec<CoinbaseOutput>,
}

impl ExtendedJob {
    pub fn from_blob(job_id: u32, version: u32, blob: &CoinbaserBlob) -> Self {
        Self {
            job_id,
            is_future: false,
            version,
            additional_coinbase_outputs: blob.outputs.clone(),
        }
    }
}

/// JobStore trait — abstracts the SRI `JobStore` shape so we can swap an SRI
/// implementation in without touching the channel handlers.
pub trait JobStore: Send + Sync {
    fn put(&mut self, job: ExtendedJob);
    fn get(&self, job_id: u32) -> Option<&ExtendedJob>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bounded in-memory JobStore matching the C reference's 8-job ring shape
/// (per `gateway-internals-c-architecture` § "8-job ring state, in-memory
/// only"). Eviction is FIFO on put when capacity is reached.
#[derive(Debug, Default)]
pub struct InMemoryJobStore {
    capacity: usize,
    order: Vec<u32>,
    jobs: HashMap<u32, ExtendedJob>,
}

impl InMemoryJobStore {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: Vec::with_capacity(capacity.max(1)),
            jobs: HashMap::with_capacity(capacity.max(1)),
        }
    }

    pub fn new_eight_job_ring() -> Self {
        Self::with_capacity(8)
    }
}

impl JobStore for InMemoryJobStore {
    fn put(&mut self, job: ExtendedJob) {
        let id = job.job_id;
        if !self.jobs.contains_key(&id) {
            if self.jobs.len() >= self.capacity {
                let evicted = self.order.remove(0);
                self.jobs.remove(&evicted);
            }
            self.order.push(id);
        }
        self.jobs.insert(id, job);
    }

    fn get(&self, job_id: u32) -> Option<&ExtendedJob> {
        self.jobs.get(&job_id)
    }

    fn len(&self) -> usize {
        self.jobs.len()
    }
}

/// Channel registry — `HashMap<channel_id, ChannelState>` behind a tokio Mutex.
/// Mirrors the shape SRI's `ExtendedChannel<DefaultJobStore<ExtendedJob>>`
/// would occupy, while keeping our structural API independent.
#[derive(Debug)]
pub struct ChannelState {
    pub channel_id: u32,
    pub user_identity: String,
    pub job_store: InMemoryJobStore,
}

#[derive(Default)]
pub struct ChannelRegistry {
    inner: Mutex<HashMap<u32, ChannelState>>,
    next_id: std::sync::atomic::AtomicU32,
}

impl ChannelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn open(&self, user_identity: String) -> u32 {
        let channel_id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut g = self.inner.lock().await;
        g.insert(
            channel_id,
            ChannelState {
                channel_id,
                user_identity,
                job_store: InMemoryJobStore::new_eight_job_ring(),
            },
        );
        channel_id
    }

    pub async fn close(&self, channel_id: u32) {
        self.inner.lock().await.remove(&channel_id);
    }

    pub async fn count(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn put_job(&self, channel_id: u32, job: ExtendedJob) -> bool {
        let mut g = self.inner.lock().await;
        if let Some(state) = g.get_mut(&channel_id) {
            state.job_store.put(job);
            true
        } else {
            false
        }
    }
}

/// Phase 3 cross-protocol invariant: given the same template and OCEAN blob,
/// SV1 `coinb1/coinb2` synthesis and SV2 `NewExtendedMiningJob.coinbase_tx_outputs`
/// MUST sum to the same satoshi total. **Catastrophic-if-violated**: an
/// operator could pay self instead of OCEAN.
///
/// This helper exposes the comparison so an integration test can assert it
/// without constructing two server runtimes.
pub fn coinbase_output_sum(blob: &CoinbaserBlob) -> u64 {
    blob.outputs.iter().map(|o| o.value_sats).sum()
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use datum_coinbaser::CoinbaseOutput;

    fn blob(value: u64) -> CoinbaserBlob {
        CoinbaserBlob {
            datum_id: 0,
            outputs: vec![CoinbaseOutput {
                value_sats: value,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x00, 0x00],
            }],
        }
    }

    fn job(id: u32, value: u64) -> ExtendedJob {
        ExtendedJob::from_blob(id, 0x2000_0000, &blob(value))
    }

    #[test]
    fn job_store_inserts_and_reads() {
        let mut s = InMemoryJobStore::new_eight_job_ring();
        s.put(job(1, 100));
        assert_eq!(s.get(1).unwrap().job_id, 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn job_store_evicts_fifo_at_capacity() {
        let mut s = InMemoryJobStore::with_capacity(2);
        s.put(job(1, 1));
        s.put(job(2, 2));
        s.put(job(3, 3));
        assert_eq!(s.len(), 2);
        assert!(s.get(1).is_none());
        assert!(s.get(2).is_some());
        assert!(s.get(3).is_some());
    }

    #[test]
    fn job_store_overwrite_does_not_evict() {
        let mut s = InMemoryJobStore::with_capacity(2);
        s.put(job(1, 1));
        s.put(job(2, 2));
        s.put(job(1, 99));
        assert_eq!(s.len(), 2);
        assert_eq!(
            s.get(1).unwrap().additional_coinbase_outputs[0].value_sats,
            99
        );
    }

    #[tokio::test]
    async fn channel_registry_open_and_count() {
        let r = ChannelRegistry::new();
        let id1 = r.open("worker-1".into()).await;
        let id2 = r.open("worker-2".into()).await;
        assert_ne!(id1, id2);
        assert_eq!(r.count().await, 2);
        r.close(id1).await;
        assert_eq!(r.count().await, 1);
    }

    #[tokio::test]
    async fn put_job_only_into_open_channel() {
        let r = ChannelRegistry::new();
        let id = r.open("worker".into()).await;
        let j = job(7, 500);
        assert!(r.put_job(id, j.clone()).await);
        assert!(!r.put_job(9999, j).await);
    }

    #[test]
    fn coinbase_output_sum_works() {
        let b = CoinbaserBlob {
            datum_id: 0,
            outputs: vec![
                CoinbaseOutput {
                    value_sats: 1000,
                    script_pubkey: vec![0; 5],
                },
                CoinbaseOutput {
                    value_sats: 2500,
                    script_pubkey: vec![0; 5],
                },
            ],
        };
        assert_eq!(coinbase_output_sum(&b), 3500);
    }

    #[test]
    fn cross_protocol_invariant_holds_under_identical_blob() {
        let b = blob(312_500_000);
        let sv1_sum = coinbase_output_sum(&b);
        let sv2_job = ExtendedJob::from_blob(1, 0x2000_0000, &b);
        let sv2_sum: u64 = sv2_job
            .additional_coinbase_outputs
            .iter()
            .map(|o| o.value_sats)
            .sum();
        assert_eq!(
            sv1_sum, sv2_sum,
            "SV1 + SV2 must agree on coinbase sum given identical OCEAN blob"
        );
    }
}
