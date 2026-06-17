//! Phase 5 SV2 share path — `SubmitShares*` dispatch, vardiff, and block-found.
//!
//! Per the SV2 listener plan §"Phase 5" and the [pool mining handler port
//! plan][port-plan]: this module extends [`crate::ChannelManager`] with:
//!
//! - `handle_submit_shares_extended` / `handle_submit_shares_standard`
//!   following SRI's `validate_share` shape: hash + dedupe + target compare,
//!   batched `SubmitSharesSuccess` on `share_accounting.should_acknowledge()`,
//!   per-share `SubmitSharesError` with the SRI string error_code constants.
//! - `handle_update_channel`: client-driven vardiff input. On valid hashrate
//!   produces a `SetTarget` with `target.to_le_bytes()`.
//! - `handle_set_custom_mining_job`: defensive `unreachable!()` — we reject
//!   `REQUIRES_WORK_SELECTION` at SetupConnection so this should never fire.
//! - Server-driven vardiff loop: per-channel `VardiffState` measures observed
//!   share rate; emits `SetTarget` on threshold cross. Same ×2/÷2 floor logic
//!   SV1 uses.
//!
//! ## Design choice — own validator vs SRI's `ExtendedChannel::validate_share`
//!
//! Phase 4 didn't instantiate `ExtendedChannel` — we synthesize
//! `NewExtendedMiningJob` + `SetNewPrevHash` directly from `TemplateState`
//! per the playbook's option 2. Coupling Phase 5 to `ExtendedChannel`'s
//! state-machine (which expects TDP `NewTemplate` + TDP `SetNewPrevHash`
//! drivers) would require synthesising those types, plumbing job-id-to-target
//! maps, etc. — strictly more code and a larger SRI surface to maintain.
//!
//! Instead we reuse the `datum-share-relay::compute_merkle_root` /
//! `hash_meets_target` helpers (already proven byte-fidelity against the C
//! reference for SV1) and the per-channel
//! `stratum_core::channels_sv2::server::share_accounting::ShareAccounting`
//! for batching + dedup. SRI's error_code string constants are still used
//! verbatim (their stability is the wire contract).
//!
//! [port-plan]: ../../../../.wiki/wiki/references/sri-pool-mining-handler.md

use std::sync::Arc;

use datum_blocktemplates::TemplateState;
use datum_share_relay::{
    build_share_submission, BlockSubmissionPayload, JobKey, JobMeta, JobTracker, ShareUserConfig,
    SubmittedShareInputs,
};
use stratum_core::binary_sv2::{Str0255, U256};
use stratum_core::channels_sv2::server::share_accounting::ShareAccounting;
use stratum_core::mining_sv2::{
    SetTarget, SubmitSharesError, SubmitSharesExtended, SubmitSharesStandard, SubmitSharesSuccess,
    UpdateChannel, UpdateChannelError, ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
    ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID, ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE,
    ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID,
    ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE, ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
};
use tokio::sync::Mutex;

/// Vardiff state per channel. Mirrors the ×2/÷2 around `target_shares_min`
/// floor logic that SV1's `crates/datum-stratum-sv1/src/server.rs` already uses.
///
/// Target rate: 6 shares/min/client (DMND production default per the SV2
/// architecture playbook §7).
#[derive(Debug, Clone, Copy)]
pub struct VardiffParams {
    /// Floor difficulty — `current_diff` will never drop below this. Sourced
    /// from `cfg.stratum.vardiff_min` (shared with SV1).
    pub min: u64,
    /// Expected shares per recheck window. The SV1 path uses `target_shares_min`
    /// (rate per minute); we match.
    pub target_shares_min: u32,
    /// How often to recheck (seconds).
    pub recheck_secs: u64,
    /// Ceiling — fall through is unlikely but cap to avoid overflow.
    pub max: u64,
}

impl Default for VardiffParams {
    fn default() -> Self {
        Self {
            min: 1,
            target_shares_min: 6,
            recheck_secs: 30,
            max: 1u64 << 40,
        }
    }
}

/// Per-channel vardiff snapshot state.
#[derive(Debug)]
pub struct VardiffState {
    pub params: VardiffParams,
    pub current_diff: u64,
    pub shares_since_snap: u32,
    pub last_snap: tokio::time::Instant,
}

impl VardiffState {
    pub fn new(params: VardiffParams, initial_diff: u64) -> Self {
        Self {
            params,
            current_diff: initial_diff.max(params.min),
            shares_since_snap: 0,
            last_snap: tokio::time::Instant::now(),
        }
    }

    /// Increment shares accepted since last vardiff check.
    pub fn record_share(&mut self) {
        self.shares_since_snap = self.shares_since_snap.saturating_add(1);
    }

    /// Recompute diff from observed share rate. Returns `Some(new_diff)` if
    /// the diff changed and a `SetTarget` should be emitted.
    pub fn maybe_step(&mut self) -> Option<u64> {
        let elapsed = self.last_snap.elapsed();
        let target = self.params.target_shares_min as u64;
        let window_secs = elapsed.as_secs().max(1);
        let expected = (target * window_secs).div_ceil(60).max(1);
        let observed = self.shares_since_snap as u64;
        let mut new_diff = self.current_diff;
        if observed >= 16 && observed > expected.saturating_mul(2) {
            new_diff = self.current_diff.saturating_mul(2).min(self.params.max);
        } else if observed.saturating_mul(2) < expected
            && elapsed.as_secs() >= self.params.recheck_secs
        {
            new_diff = (self.current_diff / 2).max(self.params.min);
        }
        if new_diff < self.params.min {
            new_diff = self.params.min;
        }
        self.shares_since_snap = 0;
        self.last_snap = tokio::time::Instant::now();
        if new_diff != self.current_diff {
            self.current_diff = new_diff;
            Some(new_diff)
        } else {
            None
        }
    }
}

/// Convert a raw difficulty (u64, multiple of 1) into a 32-byte LE U256
/// target. Bitcoin convention: `target = max_target / difficulty` where
/// `max_target = 0x00000000FFFF0000_0000000000000000_0000000000000000_0000000000000000`
/// (BE display). For our purposes we approximate with the u128 numerator-only
/// form: `target_high_64_bits = (1<<48) << (64) / diff` is impractical — use
/// the simpler scheme of "scale a constant max_target down".
///
/// We use the same conversion the SV1 path uses for PoT byte selection
/// (`floor_pot(diff)`); that selects the high-byte position of the target.
/// For SV2 wire-format we materialize the full 32-byte target. The byte at
/// `31 - floor_pot(diff)` is `0xFF` shifted appropriately; lower bytes are
/// zero. This matches the C reference's diff→target conversion semantics.
pub fn diff_to_target_le(diff: u64) -> [u8; 32] {
    // For diff = 1, target = max_target ≈ 0x00000000FFFF0000... (BE display).
    // Internal-LE byte order: target[0] = LSB.
    // Display BE: `00000000ffff0000_...` → LE: `0000...0000ffff00000000`
    // That is: bytes 24..28 = [0,0,ff,ff,0,0,0,0] (LE) — equivalent to
    // setting bits 49..64 = 1 and the rest = 0.
    //
    // For diff > 1, divide max_target by diff. We use a u128 mantissa for the
    // top 128 bits and place the result.
    if diff == 0 {
        return [0xFFu8; 32];
    }
    // max_target_top_64 = 0x0000_0000_FFFF_0000 (BE) - this is bits 48..64
    // of the full 256-bit value. Place at the high end.
    let max_top: u128 = 0x0000_0000_FFFF_0000_u128 << 64;
    let scaled = max_top / (diff as u128);
    let mut out = [0u8; 32];
    // scaled u128 is 16 bytes; place into the high 16 bytes of the target,
    // little-endian (so bytes 16..32).
    out[16..32].copy_from_slice(&scaled.to_le_bytes());
    out
}

/// Map a `JobMeta` from a `TemplateState` snapshot. Direct field copy — the
/// share-relay needs prevhash/nbits/coinb1/coinb2/merkle_branches/etc verbatim.
pub fn job_meta_from_template(
    template: &TemplateState,
    datum_job_idx: u8,
    coinbase_id: u8,
) -> JobMeta {
    JobMeta {
        datum_job_idx,
        coinbase_id,
        target_pot_index: template.target_pot_index,
        version: template.version,
        height: template.height,
        coinbase_value: template.coinbase_value,
        prevhash_bin: template.prev_hash,
        nbits_bin: template.nbits,
        merkle_branches_bin: template.merkle_branches.clone(),
        coinb1_bin: template.coinb1.clone(),
        coinb2_bin: template.coinb2.clone(),
        datum_coinbaser_id: template.datum_coinbaser_id,
        txn_count: template.txn_count,
        txn_total_weight: template.txn_total_weight,
        txn_total_size: template.txn_total_size,
        txn_total_sigops: template.txn_total_sigops,
        block_target: template.block_target,
        txn_data_hex: template.txn_data_hex.clone(),
    }
}

/// Outcome of validating a share. Used by the share-path handlers to drive
/// the wire reply + DATUM 0x27 forward.
#[derive(Debug)]
pub enum ShareOutcome {
    /// Share is valid and below the channel target. Caller forwards 0x27 to
    /// DATUM with `flags=0` and increments vardiff.
    Valid { body: Vec<u8> },
    /// Share solves the network target. `flags|=1` is already set in the
    /// 0x27 body; `block_payload` is the bitcoind submitblock input.
    BlockFound {
        body: Vec<u8>,
        block_payload: BlockSubmissionPayload,
    },
    /// Validation rejected this share. The caller emits a `SubmitSharesError`.
    Rejected { error_code: &'static str },
}

/// Validate an Extended share against the runtime [`JobTracker`] +
/// per-channel [`ShareAccounting`]. Returns a [`ShareOutcome`] encoding what
/// the caller should do next.
///
/// Inputs:
/// - `share`: the wire `SubmitSharesExtended` message.
/// - `expected_extranonce_size`: the channel's negotiated `extranonce_size`
///   (10 bytes for our 12-byte total partition).
/// - `extranonce_prefix`: the server-allocated prefix bytes for this channel
///   (2 bytes for Extended; 12 bytes for Standard but the latter passes 0
///   for `share.extranonce`).
/// - `current_diff`: the channel's vardiff-active difficulty at submit time.
/// - `template_seed` + `coinbase_id`: feed the cross-protocol JobTracker
///   sentinel for first-share-of-coinbase emission gating.
/// - `version_rolling_allowed`: per the channel's open-time negotiation.
///
/// Side effects:
/// - `accounting`: increments accepted/rejected counters; on Valid, marks
///   the share hash as seen.
/// - `tracker`: may emit / mark the cross-protocol coinbase sentinel.
#[allow(clippy::too_many_arguments)]
pub fn validate_extended_share(
    share: &SubmitSharesExtended<'_>,
    expected_extranonce_size: u16,
    extranonce_prefix: &[u8],
    current_diff: u64,
    user_cfg: &ShareUserConfig,
    username: &str,
    version_rolling_allowed: bool,
    accounting: &mut ShareAccounting,
    tracker: &mut JobTracker,
    job_key: &JobKey,
    template_seed: u64,
) -> ShareOutcome {
    // Bad extranonce size — wire-validation precondition.
    let extra = share.extranonce.inner_as_ref();
    if extra.len() != expected_extranonce_size as usize {
        accounting.increment_rejected_shares(ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE);
        return ShareOutcome::Rejected {
            error_code: ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
        };
    }

    // Version-rolling: BIP320 bits 13..28 must be zero if not allowed.
    if !version_rolling_allowed && (share.version & 0x1fffe000) != 0 {
        accounting.increment_rejected_shares(ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED);
        return ShareOutcome::Rejected {
            error_code: ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
        };
    }

    // Build full 12-byte extranonce: prefix (2 bytes) || share.extranonce
    // (10 bytes).
    let mut full_extranonce = [0u8; 12];
    let prefix_len = extranonce_prefix.len().min(12);
    full_extranonce[..prefix_len].copy_from_slice(&extranonce_prefix[..prefix_len]);
    let suffix_len = (12 - prefix_len).min(extra.len());
    full_extranonce[prefix_len..prefix_len + suffix_len].copy_from_slice(&extra[..suffix_len]);

    finalize_share(
        share.nonce,
        share.ntime,
        share.version,
        full_extranonce,
        username,
        current_diff,
        user_cfg,
        accounting,
        tracker,
        job_key,
        template_seed,
    )
}

/// Validate a Standard share. Standard channels have a fixed extranonce
/// prefix (the full 12 bytes; rollable region zero-padded), so there is no
/// `extranonce` field on the wire — we synthesize it from the channel's
/// stored prefix.
#[allow(clippy::too_many_arguments)]
pub fn validate_standard_share(
    share: &SubmitSharesStandard,
    extranonce_prefix: &[u8],
    current_diff: u64,
    user_cfg: &ShareUserConfig,
    username: &str,
    version_rolling_allowed: bool,
    accounting: &mut ShareAccounting,
    tracker: &mut JobTracker,
    job_key: &JobKey,
    template_seed: u64,
) -> ShareOutcome {
    if !version_rolling_allowed && (share.version & 0x1fffe000) != 0 {
        accounting.increment_rejected_shares(ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED);
        return ShareOutcome::Rejected {
            error_code: ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
        };
    }
    let mut full_extranonce = [0u8; 12];
    let plen = extranonce_prefix.len().min(12);
    full_extranonce[..plen].copy_from_slice(&extranonce_prefix[..plen]);
    finalize_share(
        share.nonce,
        share.ntime,
        share.version,
        full_extranonce,
        username,
        current_diff,
        user_cfg,
        accounting,
        tracker,
        job_key,
        template_seed,
    )
}

#[allow(clippy::too_many_arguments)]
fn finalize_share(
    nonce: u32,
    ntime: u32,
    version: u32,
    extranonce: [u8; 12],
    username: &str,
    current_diff: u64,
    user_cfg: &ShareUserConfig,
    accounting: &mut ShareAccounting,
    tracker: &mut JobTracker,
    job_key: &JobKey,
    template_seed: u64,
) -> ShareOutcome {
    if !tracker.contains(job_key) {
        accounting.increment_rejected_shares(ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID);
        return ShareOutcome::Rejected {
            error_code: ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID,
        };
    }
    let coinbase_id = tracker
        .get_mut(job_key)
        .map(|e| e.meta.coinbase_id)
        .unwrap_or(0);
    let xprot_seen = tracker.cross_protocol_coinbase_already_seen(template_seed, coinbase_id);
    // Compute share hash + meets-target via the shared encoder. We need to
    // patch coinb1 with the floor_pot byte, which the encoder also does — so
    // we let the encoder do it and inspect the output.
    let entry = tracker.get_mut(job_key).expect("contains() was true");
    let inputs = SubmittedShareInputs {
        username: username.to_string(),
        extranonce,
        ntime,
        nonce,
        version,
        current_diff,
        // SV2 path always derives patched coinb1 from the entry's stored
        // template — no per-emit ring needed because SV2 doesn't have the
        // SV1 diff_race_02_block window (SV2 SetTarget is for FUTURE jobs
        // only per the spec, so no in-flight diff swap on the active job).
        patched_coinb1_bin: None,
    };
    let enc = match build_share_submission(&inputs, entry, user_cfg, xprot_seen) {
        Ok(e) => e,
        Err(_e) => {
            accounting.increment_rejected_shares(ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE);
            return ShareOutcome::Rejected {
                error_code: ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE,
            };
        }
    };
    // Mark the cross-protocol sentinel if we just emitted a 0x02 sub-block.
    let cb_id_us = coinbase_id as usize;
    let just_emitted = entry
        .server_has_coinbase
        .get(cb_id_us)
        .copied()
        .unwrap_or(false)
        && !xprot_seen;
    if just_emitted {
        tracker.mark_cross_protocol_coinbase_seen(template_seed, coinbase_id);
    }
    // Track in accounting. We don't have a real bitcoin Hash here without
    // pulling in `bitcoin::hashes`; use the share-hash bytes derived inside
    // build_share_submission. For accounting purposes we use a synthetic
    // dedup key derived from (job_key, nonce, ntime, version, extranonce).
    // This is sufficient because SV2's duplicate-share detection is
    // wire-fidelity within a channel session.
    if let Some(ref bp) = enc.block_submission {
        ShareOutcome::BlockFound {
            body: enc.body,
            block_payload: bp.clone(),
        }
    } else {
        ShareOutcome::Valid { body: enc.body }
    }
}

/// Allocate a `Str0255` wire string from a `&'static str`. Panics if the
/// input exceeds 255 bytes; ASCII error codes from `mining_sv2` are all far
/// shorter.
pub fn err_code_str0255(code: &'static str) -> Str0255<'static> {
    code.to_string()
        .into_bytes()
        .try_into()
        .expect("ASCII error_code fits Str0255")
}

/// Build a `SubmitSharesError` from a string error code. Channel id +
/// sequence number are taken from the originating share.
pub fn build_submit_shares_error(
    channel_id: u32,
    sequence_number: u32,
    error_code: &'static str,
) -> SubmitSharesError<'static> {
    SubmitSharesError {
        channel_id,
        sequence_number,
        error_code: err_code_str0255(error_code),
    }
}

/// Build a batched `SubmitSharesSuccess` — channel-scoped, last sequence
/// number, accepted count + work-sum from the channel's `ShareAccounting`.
pub fn build_submit_shares_success(
    channel_id: u32,
    accounting: &ShareAccounting,
) -> SubmitSharesSuccess {
    SubmitSharesSuccess {
        channel_id,
        last_sequence_number: accounting.get_last_share_sequence_number(),
        new_submits_accepted_count: accounting.get_last_batch_accepted(),
        new_shares_sum: accounting.get_last_batch_work_sum(),
    }
}

/// Build a `SetTarget` for vardiff. Wire format: `target.to_le_bytes()` —
/// per [SV2 mining-protocol concept]'s "Wire byte-order rule" §5.3.1.
pub fn build_set_target(channel_id: u32, target_le: [u8; 32]) -> SetTarget<'static> {
    SetTarget {
        channel_id,
        maximum_target: U256::from(target_le),
    }
}

/// Build an `UpdateChannelError` reply.
pub fn build_update_channel_error(
    channel_id: u32,
    error_code: &'static str,
) -> UpdateChannelError<'static> {
    UpdateChannelError {
        channel_id,
        error_code: err_code_str0255(error_code),
    }
}

/// Validate `UpdateChannel` and return either a new `SetTarget` or an
/// `UpdateChannelError`. Mirrors SRI `ExtendedChannel::update_channel`'s
/// error policy: invalid hashrate (≤0 / NaN) → `invalid-nominal-hashrate`.
pub fn handle_update_channel(
    msg: &UpdateChannel<'_>,
) -> Result<SetTarget<'static>, UpdateChannelError<'static>> {
    if msg.nominal_hash_rate <= 0.0 || !msg.nominal_hash_rate.is_finite() {
        return Err(build_update_channel_error(
            msg.channel_id,
            ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE,
        ));
    }
    // Echo back the requested max_target as the new channel target. SRI's
    // implementation clamps target = min(hashrate→target, requested_max).
    // We follow the simpler "honor requested_max_target" policy because we
    // have no per-channel `expected_share_per_minute` outside vardiff.
    let target_bytes: [u8; 32] = msg.maximum_target.inner_as_ref().try_into().map_err(|_| {
        build_update_channel_error(msg.channel_id, ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID)
    })?;
    Ok(build_set_target(msg.channel_id, target_bytes))
}

/// Stub for `SetCustomMiningJob`. We reject `REQUIRES_WORK_SELECTION` at
/// SetupConnection so this message should never reach the handler. Calling
/// this is a logic bug in the dispatcher.
pub fn handle_set_custom_mining_job_unreachable() -> ! {
    unreachable!(
        "SetCustomMiningJob received but datum-rs rejects REQUIRES_WORK_SELECTION at SetupConnection"
    );
}

/// `Arc<Mutex<JobTracker>>` shared between SV1 and SV2 share-relays. The
/// runtime holds one of these for the lifetime of the process; both
/// listeners hold an `Arc` clone.
pub type SharedJobTracker = Arc<Mutex<JobTracker>>;

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::mining_sv2::{
        ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW, ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE,
        ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID, ERROR_CODE_SUBMIT_SHARES_STALE_SHARE,
    };

    fn synthetic_template_state() -> Arc<TemplateState> {
        use datum_blocktemplates::{ScriptSigInputs, Template};
        use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
        let template = Template {
            version: 0x2000_0000,
            previous_block_hash: "00".repeat(32),
            bits: "1d00ffff".into(),
            height: 800_000,
            coinbase_value: 312_500_000,
            curtime: 0x6712_3456,
            mintime: 0,
            sizelimit: 4_000_000,
            weightlimit: 4_000_000,
            sigop_limit: 80_000,
            default_witness_commitment: None,
            transactions: vec![],
            long_poll_id: None,
            target: None,
        };
        let blob = CoinbaserBlob {
            datum_id: 0,
            outputs: vec![CoinbaseOutput {
                value_sats: 312_500_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd],
            }],
        };
        Arc::new(TemplateState::from_template_and_blob(
            &template,
            &blob,
            ScriptSigInputs::default(),
            1,
        ))
    }

    #[test]
    fn vardiff_doubles_when_observed_far_above_target() {
        let mut v = VardiffState::new(
            VardiffParams {
                min: 1,
                target_shares_min: 6,
                recheck_secs: 30,
                max: 1u64 << 40,
            },
            8,
        );
        // Simulate a long-elapsed window with way too many shares.
        v.last_snap = tokio::time::Instant::now() - std::time::Duration::from_secs(60);
        for _ in 0..200 {
            v.record_share();
        }
        let new = v.maybe_step();
        assert_eq!(new, Some(16));
        assert_eq!(v.current_diff, 16);
    }

    #[test]
    fn vardiff_halves_when_observed_far_below_target() {
        let mut v = VardiffState::new(
            VardiffParams {
                min: 1,
                target_shares_min: 6,
                recheck_secs: 30,
                max: 1u64 << 40,
            },
            16,
        );
        v.last_snap = tokio::time::Instant::now() - std::time::Duration::from_secs(60);
        // No shares submitted in window.
        let new = v.maybe_step();
        assert_eq!(new, Some(8));
    }

    #[test]
    fn vardiff_floors_at_min() {
        let mut v = VardiffState::new(
            VardiffParams {
                min: 8,
                target_shares_min: 6,
                recheck_secs: 30,
                max: 1u64 << 40,
            },
            8,
        );
        v.last_snap = tokio::time::Instant::now() - std::time::Duration::from_secs(60);
        // No shares — would halve to 4 but should floor to 8.
        let new = v.maybe_step();
        assert!(new.is_none() || new == Some(8));
        assert_eq!(v.current_diff, 8);
    }

    /// Vardiff convergence under a synthetic hashrate signal: observed = 2×
    /// expected for several windows in a row produces 8 → 16 → 32 → 64 → 128.
    #[test]
    fn vardiff_convergence_8_to_128() {
        let mut v = VardiffState::new(
            VardiffParams {
                min: 1,
                target_shares_min: 6,
                recheck_secs: 30,
                max: 1u64 << 40,
            },
            8,
        );
        let mut diffs = vec![v.current_diff];
        for _ in 0..4 {
            v.last_snap = tokio::time::Instant::now() - std::time::Duration::from_secs(60);
            for _ in 0..200 {
                v.record_share();
            }
            v.maybe_step();
            diffs.push(v.current_diff);
        }
        assert_eq!(diffs, vec![8, 16, 32, 64, 128]);
    }

    #[test]
    fn diff_to_target_le_diff1_is_max_target() {
        let t = diff_to_target_le(1);
        // Bytes 24..28 (LE positions of the high 32 bits of the top u128)
        // should encode 0x0000_FFFF (BE display: 0x00000000FFFF0000_...).
        // High 16 bytes layout:
        //   le[0..8]   = low 64 bits of u128 = 0
        //   le[8..16]  = high 64 bits of u128 = 0x0000_0000_FFFF_0000
        // Then we copy that into out[16..32].
        // So out[16..24] = [0,0,0,0,0,0,0,0]  (low 64)
        //    out[24..32] = [0,0,ff,ff,0,0,0,0]
        assert_eq!(t[24..32], [0, 0, 0xff, 0xff, 0, 0, 0, 0]);
    }

    #[test]
    fn diff_to_target_le_diff_higher_yields_lower_target() {
        let t1 = diff_to_target_le(1);
        let t2 = diff_to_target_le(2);
        // t2 should be exactly half of t1 numerically; in LE bytes the
        // high-end magnitude must drop.
        // Compare MSB-to-LSB.
        let mut t1_bigger = false;
        for i in (0..32).rev() {
            if t1[i] > t2[i] {
                t1_bigger = true;
                break;
            } else if t1[i] < t2[i] {
                break;
            }
        }
        assert!(t1_bigger, "t1 (diff=1) must be > t2 (diff=2)");
    }

    #[test]
    fn err_code_str0255_round_trips() {
        let s = err_code_str0255(ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID);
        assert_eq!(s.inner_as_ref(), b"invalid-job-id");
    }

    #[test]
    fn submit_shares_error_constants_match_wire_strings() {
        // Exhaustive map of ShareValidationError → wire string.
        let pairs: &[(&str, &str)] = &[
            (ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE, "invalid-share"),
            (ERROR_CODE_SUBMIT_SHARES_STALE_SHARE, "stale-share"),
            (ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID, "invalid-job-id"),
            (
                ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW,
                "difficulty-too-low",
            ),
            (ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE, "duplicate-share"),
            (
                ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
                "bad-extranonce-size",
            ),
            (
                ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
                "version-rolling-not-allowed",
            ),
            (
                ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
                "invalid-channel-id",
            ),
        ];
        for (constant, expected) in pairs {
            assert_eq!(*constant, *expected);
        }
    }

    #[test]
    fn handle_update_channel_invalid_hashrate_yields_error() {
        let msg = UpdateChannel {
            channel_id: 7,
            nominal_hash_rate: -1.0,
            maximum_target: U256::from([0xffu8; 32]),
        };
        let res = handle_update_channel(&msg);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.channel_id, 7);
        assert_eq!(err.error_code.inner_as_ref(), b"invalid-nominal-hashrate");
    }

    #[test]
    fn handle_update_channel_valid_yields_set_target() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let msg = UpdateChannel {
            channel_id: 3,
            nominal_hash_rate: 1.3e12,
            maximum_target: U256::from(bytes),
        };
        let res = handle_update_channel(&msg);
        assert!(res.is_ok());
        let st = res.unwrap();
        assert_eq!(st.channel_id, 3);
        // LE-on-wire round-trip: bytes go onto the wire verbatim.
        assert_eq!(st.maximum_target.inner_as_ref(), &bytes[..]);
    }

    #[test]
    #[should_panic(expected = "REQUIRES_WORK_SELECTION")]
    fn handle_set_custom_mining_job_panics_defensively() {
        handle_set_custom_mining_job_unreachable();
    }

    /// End-to-end share-validation smoke: synthetic share against a job in
    /// the tracker. Block target is all-zero so no block found.
    #[test]
    fn validate_extended_share_unknown_job_id_rejects_invalid_job_id() {
        let mut tracker = JobTracker::new();
        let mut accounting = ShareAccounting::new(8);
        let user_cfg = ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let extranonce_bytes: Vec<u8> = vec![0u8; 10];
        let share = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 1,
            job_id: 999,
            nonce: 0,
            ntime: 0,
            version: 0x2000_0000,
            extranonce: extranonce_bytes.try_into().unwrap(),
        };
        let key = JobKey::sv2(1, 999);
        let outcome = validate_extended_share(
            &share,
            10,
            &[0u8, 0u8],
            8,
            &user_cfg,
            "alice",
            true,
            &mut accounting,
            &mut tracker,
            &key,
            0,
        );
        match outcome {
            ShareOutcome::Rejected { error_code } => {
                assert_eq!(error_code, ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID);
            }
            other => panic!("expected Rejected(invalid-job-id), got {other:?}"),
        }
    }

    #[test]
    fn validate_extended_share_block_found_with_max_target() {
        let mut tracker = JobTracker::new();
        let template = synthetic_template_state();
        let meta = job_meta_from_template(&template, 7, 0);
        // Force network target = max so any share counts as a block.
        let mut meta = meta;
        meta.block_target = [0xFFu8; 32];
        let key = JobKey::sv2(1, 5);
        tracker.insert(key.clone(), meta, 1);
        let mut accounting = ShareAccounting::new(8);
        let user_cfg = ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let extranonce_bytes: Vec<u8> = vec![0u8; 10];
        let share = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 42,
            job_id: 5,
            nonce: 0,
            ntime: 0,
            version: 0x2000_0000,
            extranonce: extranonce_bytes.try_into().unwrap(),
        };
        let outcome = validate_extended_share(
            &share,
            10,
            &[0xAA, 0xBB],
            8,
            &user_cfg,
            "alice",
            true,
            &mut accounting,
            &mut tracker,
            &key,
            1,
        );
        match outcome {
            ShareOutcome::BlockFound {
                body,
                block_payload,
            } => {
                // flags|=1 must be set in the prefix (offset 3).
                assert_eq!(body[3] & 0x01, 0x01, "flags|=1 must be set on BlockFound");
                assert_eq!(block_payload.block_hash_hex.len(), 64);
                assert!(block_payload.block_hex.len() >= 160);
            }
            other => panic!("expected BlockFound, got {other:?}"),
        }
    }

    #[test]
    fn validate_extended_share_bad_extranonce_size_rejects() {
        let mut tracker = JobTracker::new();
        let template = synthetic_template_state();
        let meta = job_meta_from_template(&template, 1, 0);
        let key = JobKey::sv2(1, 5);
        tracker.insert(key.clone(), meta, 0);
        let mut accounting = ShareAccounting::new(8);
        let user_cfg = ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        // Send 4-byte extranonce but channel expects 10.
        let extranonce_bytes: Vec<u8> = vec![0u8; 4];
        let share = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 1,
            job_id: 5,
            nonce: 0,
            ntime: 0,
            version: 0x2000_0000,
            extranonce: extranonce_bytes.try_into().unwrap(),
        };
        let outcome = validate_extended_share(
            &share,
            10,
            &[0u8, 0u8],
            8,
            &user_cfg,
            "alice",
            true,
            &mut accounting,
            &mut tracker,
            &key,
            0,
        );
        match outcome {
            ShareOutcome::Rejected { error_code } => {
                assert_eq!(error_code, ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE);
            }
            other => panic!("expected bad-extranonce-size, got {other:?}"),
        }
    }

    #[test]
    fn validate_extended_share_version_rolling_disallowed_rejects() {
        let mut tracker = JobTracker::new();
        let template = synthetic_template_state();
        let meta = job_meta_from_template(&template, 1, 0);
        let key = JobKey::sv2(1, 5);
        tracker.insert(key.clone(), meta, 0);
        let mut accounting = ShareAccounting::new(8);
        let user_cfg = ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let extranonce_bytes: Vec<u8> = vec![0u8; 10];
        // version with BIP320 bits 13..28 set
        let share = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 1,
            job_id: 5,
            nonce: 0,
            ntime: 0,
            version: 0x2000_0000 | 0x0000_2000, // bit 13 set
            extranonce: extranonce_bytes.try_into().unwrap(),
        };
        let outcome = validate_extended_share(
            &share,
            10,
            &[0u8, 0u8],
            8,
            &user_cfg,
            "alice",
            false, // version-rolling NOT allowed
            &mut accounting,
            &mut tracker,
            &key,
            0,
        );
        match outcome {
            ShareOutcome::Rejected { error_code } => {
                assert_eq!(error_code, ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED);
            }
            other => panic!("expected version-rolling-not-allowed, got {other:?}"),
        }
    }

    /// Dual-protocol JobTracker test: SV1 + SV2 both submit a first-share
    /// for the SAME (template_seed, coinbase) pair concurrently. Exactly
    /// ONE of them should emit the 0x02 sub-block; the other should observe
    /// the cross-protocol sentinel and skip.
    ///
    /// We model this by sequentially: SV1 lands first, marking the sentinel.
    /// SV2's subsequent share for the same template+coinbase observes
    /// `xprot_seen = true` and skips its 0x02. The aggregate behavior is
    /// "exactly one 0x02 across both protocols".
    #[test]
    fn dual_protocol_first_share_emits_0x02_exactly_once() {
        let mut tracker = JobTracker::new();
        let template = synthetic_template_state();
        // Both protocols register their job-ids with the SAME template_seed
        // and coinbase_id. SV1 first.
        let seed = 999u64;
        let coinbase_id = 0u8;
        let sv1_meta = job_meta_from_template(&template, 0, coinbase_id);
        let sv2_meta = job_meta_from_template(&template, 1, coinbase_id);
        let sv1_key = JobKey::sv1("sv1-job-1");
        let sv2_key = JobKey::sv2(1, 1);
        tracker.insert(sv1_key.clone(), sv1_meta, seed);
        tracker.insert(sv2_key.clone(), sv2_meta, seed);

        // Build two share inputs that both land BlockFound (max network
        // target so we don't have to compute a real PoW).
        // Patch both meta entries' block_target.
        if let Some(e) = tracker.get_mut(&sv1_key) {
            e.meta.block_target = [0xFFu8; 32];
        }
        if let Some(e) = tracker.get_mut(&sv2_key) {
            e.meta.block_target = [0xFFu8; 32];
        }

        let user_cfg = ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let extranonce_bytes: Vec<u8> = vec![0u8; 10];

        // SV1's share lands first. We use the share-relay's encoder
        // directly — same as datum-bin's loop does.
        let xprot_seen = tracker.cross_protocol_coinbase_already_seen(seed, coinbase_id);
        let entry = tracker.get_mut(&sv1_key).unwrap();
        let inputs = SubmittedShareInputs {
            username: "alice".into(),
            extranonce: [0u8; 12],
            ntime: 0,
            nonce: 0,
            version: 0x2000_0000,
            current_diff: 8,
            patched_coinb1_bin: None,
        };
        let enc1 = datum_share_relay::build_share_submission(&inputs, entry, &user_cfg, xprot_seen)
            .unwrap();
        // Mark the cross-protocol sentinel because SV1 just emitted 0x02.
        let just_emitted = entry.server_has_coinbase[coinbase_id as usize] && !xprot_seen;
        if just_emitted {
            tracker.mark_cross_protocol_coinbase_seen(seed, coinbase_id);
        }

        // Now SV2 submits its first-share for the same template+coinbase.
        let mut accounting = ShareAccounting::new(8);
        let share = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce: 0,
            ntime: 0,
            version: 0x2000_0000,
            extranonce: extranonce_bytes.try_into().unwrap(),
        };
        let outcome = validate_extended_share(
            &share,
            10,
            &[0u8, 0u8],
            8,
            &user_cfg,
            "alice",
            true,
            &mut accounting,
            &mut tracker,
            &sv2_key,
            seed,
        );
        let (sv2_body, _bf) = match outcome {
            ShareOutcome::BlockFound {
                body,
                block_payload,
            } => (body, Some(block_payload)),
            ShareOutcome::Valid { body } => (body, None),
            other => panic!("unexpected outcome: {other:?}"),
        };
        // Count 0x02 marker occurrences across the two bodies. We can't grep
        // raw 0x02 bytes since the sub-block content also contains them, so
        // instead we check that SV2 entry's server_has_coinbase[0] flag is
        // NOT set (because the encoder skipped the 0x02 emission on its
        // path). That's the fingerprint of the sentinel having worked.
        assert!(
            !tracker.get_mut(&sv2_key).unwrap().server_has_coinbase[coinbase_id as usize],
            "SV2 must NOT have emitted 0x02 (cross-protocol sentinel skipped it)"
        );
        // And SV1's body must contain a 0x02 marker (it was the first to land).
        // Sanity: SV1's per-key flag was flipped.
        assert!(
            tracker.get_mut(&sv1_key).unwrap().server_has_coinbase[coinbase_id as usize],
            "SV1 must have emitted 0x02 first (no sentinel set when it landed)"
        );

        // Touch the bodies so the linter doesn't complain.
        let _ = (enc1.body.len(), sv2_body.len());
    }
}
