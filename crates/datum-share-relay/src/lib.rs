//! Shared share-relay primitives: cross-protocol [`JobTracker`], DATUM `0x27`
//! share-submission body builder, and the block-found ([`BlockSubmissionPayload`])
//! escape hatch.
//!
//! # Why a separate crate?
//!
//! Phase 5 of the SV2 listener plan introduces a parallel SV2 share path that
//! must produce **identical** DATUM `0x27` frames as today's SV1 path, while
//! sharing two pieces of cross-cutting state with SV1:
//!
//! 1. **`flags |= 1` block-found wiring** — closes the gap noted in the
//!    README ("Block-found escape hatch: flags |= 1 not yet wired"). Both
//!    protocols feed the SAME share-relay so a meet-network-target candidate
//!    sets `flags |= 1` AND triggers `datum-submitblock` regardless of which
//!    listener saw the share first.
//! 2. **First-share-of-(job, coinbase) sentinel (0x01 / 0x02 sub-blocks)** —
//!    these were per-(SV1 wire job-id) before. With SV2 in the mix the keying
//!    must span both protocols so a coincidental SV1+SV2 first-share race
//!    emits the bulky 0x01/0x02 blob exactly ONCE per (job, coinbase) — not
//!    twice.
//!
//! # Migration from `datum-bin/main.rs`
//!
//! Phase 4 left the share encoding in `datum-bin/src/main.rs`. Phase 5 hoists
//! it here so `datum-stratum-sv2` can call it without taking a circular dep
//! on `datum-bin`.
//!
//! The contract preserved verbatim:
//! - `build_share_submission` byte-fidelity test (`share_submission_body_byte_fidelity`)
//!   moves with the implementation.
//! - The 256-slot insertion-order JobTracker capacity is preserved.
//! - `reset_send_once_flags` semantics on DATUM upstream reconnect preserved.
//!
//! # Cross-protocol JobKey
//!
//! [`JobKey`] is the cross-protocol identifier the JobTracker keys on. SV1
//! uses the 18-char hex job-id string; SV2 uses `(channel_id, job_id)` u32
//! pair. A `JobEntry` lives at exactly one `JobKey` and is shared between
//! protocols only when their job-id binding maps to the same underlying
//! template (the runtime is the only thing that can establish that mapping —
//! today both protocols allocate disjoint job-id spaces, so cross-protocol
//! deduping for first-share-of-job is a forward-compat hook, not a current
//! requirement).
//!
//! What IS unified today: per-(template, coinbase) first-share. Two SV1 and
//! SV2 jobs derived from the SAME `TemplateState` push share the same
//! `template_seed` and `coinbase_id`, so the `(template_seed, coinbase_id)`
//! tuple acts as the cross-protocol "first-share-of-coinbase" sentinel.

use std::collections::HashMap;

pub use datum_stratum_sv1::assembler::JobMeta;

mod share_encoder;

pub use share_encoder::{
    build_share_submission, format_share_username, hash_meets_target, BlockSubmissionPayload,
    ShareEncoded, ShareUserConfig, SubmittedShareInputs,
};

/// Cross-protocol job identity. SV1 keys on the wire job-id hex string;
/// SV2 keys on `(channel_id, sv2_job_id)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JobKey {
    Sv1(String),
    Sv2 { channel_id: u32, job_id: u32 },
}

impl JobKey {
    pub fn sv1(job_id_hex: impl Into<String>) -> Self {
        Self::Sv1(job_id_hex.into())
    }

    pub fn sv2(channel_id: u32, job_id: u32) -> Self {
        Self::Sv2 { channel_id, job_id }
    }
}

/// Per-job context tracked by [`JobTracker`].
///
/// Wraps [`JobMeta`] with the per-(job, coinbase_id) "send-once" flags the
/// DATUM `0x27` body needs for the bulky 0x01 / 0x02 sub-blocks. Now also
/// carries `template_seed` so SV1 and SV2 jobs derived from the same
/// `TemplateState` share a coinbase first-use sentinel.
#[derive(Debug)]
pub struct JobEntry {
    pub meta: JobMeta,
    /// `template_seed` from `TemplateState::job_id_seed`. SV1 + SV2 jobs
    /// derived from the same `TemplateState` carry identical seeds; the
    /// JobTracker's coinbase first-use sentinel keys on `(seed, coinbase_id)`
    /// so a cross-protocol first-share race emits 0x02 exactly ONCE.
    pub template_seed: u64,
    pub server_has_merkle_branches: bool,
    pub server_has_coinbase: [bool; 8],
}

/// Cross-protocol job tracker.
///
/// Holds a bounded `HashMap<JobKey, JobEntry>` (256 slots, FIFO eviction —
/// matches the C reference's 8-bit ring x 32 ops/job amortised) plus a
/// `(template_seed, coinbase_id) → bool` "first-share-of-coinbase" sentinel
/// shared across both protocols.
///
/// Per-(job, coinbase) first-share is keyed on the SV1/SV2 job-id; that
/// sentinel lives on `JobEntry::server_has_coinbase` and is per-key. The
/// **cross-protocol** sentinel — used to dedupe coinbase first-shares across
/// protocols — lives on the tracker itself.
#[derive(Debug, Default)]
pub struct JobTracker {
    by_key: HashMap<JobKey, JobEntry>,
    order: std::collections::VecDeque<JobKey>,
    /// (template_seed, coinbase_id) → already-seen-cross-protocol.
    /// Set on the FIRST share that lands for the (template, coinbase) pair,
    /// regardless of which protocol it came in on. The downstream effect:
    /// the SECOND protocol to land a share on the same `(template_seed,
    /// coinbase_id)` skips the 0x02 sub-block emission, matching what OCEAN
    /// expects (the first share carried it; the second on a different SV1/
    /// SV2 job-id but identical template+coinbase shouldn't duplicate it).
    seen_template_coinbase: HashMap<(u64, u8), ()>,
    next_datum_idx: u8,
}

impl JobTracker {
    pub const MAX: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next 8-bit `datum_job_idx` (wraps at 255).
    pub fn next_idx(&mut self) -> u8 {
        let v = self.next_datum_idx;
        self.next_datum_idx = self.next_datum_idx.wrapping_add(1);
        v
    }

    pub fn insert(&mut self, key: JobKey, meta: JobMeta, template_seed: u64) {
        if self.by_key.len() >= Self::MAX {
            if let Some(oldest) = self.order.pop_front() {
                self.by_key.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.by_key.insert(
            key,
            JobEntry {
                meta,
                template_seed,
                server_has_merkle_branches: false,
                server_has_coinbase: [false; 8],
            },
        );
    }

    pub fn get_mut(&mut self, key: &JobKey) -> Option<&mut JobEntry> {
        self.by_key.get_mut(key)
    }

    pub fn contains(&self, key: &JobKey) -> bool {
        self.by_key.contains_key(key)
    }

    /// Returns true if the (template_seed, coinbase_id) tuple has already
    /// been seen on ANY protocol since the last `reset_send_once_flags()`.
    /// Idempotent — call before emitting 0x02 to decide whether to emit.
    pub fn cross_protocol_coinbase_already_seen(
        &self,
        template_seed: u64,
        coinbase_id: u8,
    ) -> bool {
        self.seen_template_coinbase
            .contains_key(&(template_seed, coinbase_id))
    }

    /// Mark a (template_seed, coinbase_id) tuple as seen across protocols.
    /// Called immediately after a share-relay decides to include the 0x02
    /// sub-block in a forwarded `0x27` frame.
    pub fn mark_cross_protocol_coinbase_seen(&mut self, template_seed: u64, coinbase_id: u8) {
        self.seen_template_coinbase
            .insert((template_seed, coinbase_id), ());
    }

    /// Clear every per-(job, coinbase_id) `server_has_*` send-once flag AND
    /// the cross-protocol `(template_seed, coinbase_id)` map. Called on DATUM
    /// upstream reconnect: the upstream's slot table is state-on-the-wire,
    /// so when we lose+reestablish a connection the pool has no record of
    /// any job we previously announced. The next share we forward must carry
    /// the 0x01 + 0x02 sub-blocks again.
    pub fn reset_send_once_flags(&mut self) {
        for entry in self.by_key.values_mut() {
            entry.server_has_merkle_branches = false;
            entry.server_has_coinbase = [false; 8];
        }
        self.seen_template_coinbase.clear();
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// Block-found dispatch handle. The share-relay returns the encoded block
/// payload to the caller, who is responsible for spawning the actual
/// `submitblock` against bitcoind. Per the gateway-internals architecture
/// rule, path-1 (bitcoind submitblock) and path-2 (DATUM `0x27` with
/// `flags|=1`) MUST run as independent tasks. Keeping the actual
/// [`datum_submitblock::BlockSubmitter`] dep on the call site lets us avoid
/// pulling RPC types into this crate.
///
/// [`datum_submitblock::BlockSubmitter`]: ../datum_submitblock/struct.BlockSubmitter.html
pub use share_encoder::BlockSubmissionPayload as _BlockSubmissionPayload;

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_meta(seed_byte: u8) -> JobMeta {
        JobMeta {
            datum_job_idx: seed_byte,
            coinbase_id: 0,
            target_pot_index: 0,
            version: 0x2000_0000,
            height: 1,
            coinbase_value: 5_000_000_000,
            prevhash_bin: [0u8; 32],
            nbits_bin: [0x20, 0x7f, 0xff, 0xff],
            merkle_branches_bin: vec![],
            coinb1_bin: vec![0u8; 50],
            coinb2_bin: vec![0u8; 10],
            datum_coinbaser_id: 0,
            txn_count: 0,
            txn_total_weight: 0,
            txn_total_size: 0,
            txn_total_sigops: 0,
            block_target: [0u8; 32],
            txn_data_hex: std::sync::Arc::new(vec![]),
        }
    }

    #[test]
    fn job_tracker_inserts_and_reads_sv1_key() {
        let mut t = JobTracker::new();
        let k = JobKey::sv1("abc");
        t.insert(k.clone(), synthetic_meta(1), 42);
        assert!(t.contains(&k));
        assert_eq!(t.len(), 1);
        let e = t.get_mut(&k).unwrap();
        assert_eq!(e.template_seed, 42);
    }

    #[test]
    fn job_tracker_inserts_and_reads_sv2_key() {
        let mut t = JobTracker::new();
        let k = JobKey::sv2(7, 99);
        t.insert(k.clone(), synthetic_meta(2), 100);
        assert!(t.contains(&k));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn job_tracker_evicts_at_capacity() {
        let mut t = JobTracker::new();
        for i in 0..(JobTracker::MAX as u32 + 5) {
            t.insert(JobKey::sv2(0, i), synthetic_meta(0), 0);
        }
        assert_eq!(t.len(), JobTracker::MAX);
        // Earliest 5 must be gone.
        assert!(!t.contains(&JobKey::sv2(0, 0)));
        assert!(!t.contains(&JobKey::sv2(0, 4)));
        assert!(t.contains(&JobKey::sv2(0, 5)));
    }

    #[test]
    fn cross_protocol_coinbase_sentinel() {
        let mut t = JobTracker::new();
        assert!(!t.cross_protocol_coinbase_already_seen(7, 0));
        t.mark_cross_protocol_coinbase_seen(7, 0);
        assert!(t.cross_protocol_coinbase_already_seen(7, 0));
        // Different coinbase_id is independent.
        assert!(!t.cross_protocol_coinbase_already_seen(7, 1));
        // Different seed is independent.
        assert!(!t.cross_protocol_coinbase_already_seen(8, 0));
        // Reset clears cross-protocol map.
        t.reset_send_once_flags();
        assert!(!t.cross_protocol_coinbase_already_seen(7, 0));
    }

    #[test]
    fn reset_send_once_flags_clears_per_entry_state() {
        let mut t = JobTracker::new();
        let k = JobKey::sv1("x");
        t.insert(k.clone(), synthetic_meta(0), 0);
        {
            let e = t.get_mut(&k).unwrap();
            e.server_has_merkle_branches = true;
            e.server_has_coinbase[0] = true;
        }
        t.reset_send_once_flags();
        let e = t.get_mut(&k).unwrap();
        assert!(!e.server_has_merkle_branches);
        assert!(!e.server_has_coinbase[0]);
    }

    /// Dual-protocol first-share-of-coinbase: SV1 and SV2 both land a first
    /// share for the SAME (template_seed, coinbase_id). The second one to
    /// land MUST observe the sentinel as already-seen, so the share-relay
    /// can skip the bulky 0x02 sub-block.
    #[test]
    fn dual_protocol_first_share_of_coinbase_sentinel_emits_once() {
        let mut t = JobTracker::new();
        // SV1 gets there first.
        assert!(!t.cross_protocol_coinbase_already_seen(99, 0));
        t.mark_cross_protocol_coinbase_seen(99, 0);
        // SV2 lands its first share for the same template+coinbase pair.
        // The relay must observe the sentinel as seen and skip 0x02.
        assert!(t.cross_protocol_coinbase_already_seen(99, 0));
    }
}
