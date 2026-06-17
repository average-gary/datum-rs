//! Template + CoinbaserBlob → SV1 `mining.notify` params assembler.
//!
//! The SV1 `mining.notify` params array per Stratum V1 spec:
//!
//! ```text
//! [job_id, prevhash, coinb1, coinb2, merkle_branch[], version, nbits, ntime, clean_jobs]
//! ```
//!
//! ## Phase 1 of the SV2 listener plan
//!
//! Byte-level work (coinbase split, merkle path, target decode) lives in
//! `datum_blocktemplates::template_state::TemplateState`. SV1's
//! `assemble_notify_meta` is a thin shim that reads from a `TemplateState`
//! and emits the SV1-specific JSON shape. SV2 will call into the same
//! `TemplateState` for `coinbase_tx_prefix` / `coinbase_tx_suffix` /
//! `merkle_path` (Phase 4).
//!
//! ## Status & honest scope
//!
//! Coinbase byte layout matches `datum_coinbaser.c::generate_coinbase_input`
//! verbatim (asserted by `tests/sv1_notify_byte_fixture.rs`).

use datum_blocktemplates::Template;
use datum_blocktemplates::TemplateState;
use datum_coinbaser::CoinbaserBlob;
use serde_json::{json, Value};

// Re-export the constants and helpers that consumers of this module already
// rely on. Their canonical home is `datum_blocktemplates::template_state`
// from Phase 1 onward; the re-exports keep callers compiling unchanged.
pub use datum_blocktemplates::template_state::{
    nbits_to_target_le, swap_prev_hash_for_stratum, ScriptSigInputs, ENPREFIX_LEN,
    EXTRANONCE_PLACEHOLDER_LEN,
};

#[derive(Debug, Clone)]
pub struct NotifyParams {
    pub job_id: String,
    pub prev_hash: String,
    pub coinb1: String,
    pub coinb2: String,
    pub merkle_branch: Vec<String>,
    pub version_hex: String,
    pub nbits_hex: String,
    pub ntime_hex: String,
    pub clean_jobs: bool,
}

/// Per-job context the runtime needs to encode a DATUM `0x27` share submission.
/// Built alongside [`NotifyParams`] by [`assemble_notify_meta`]. The runtime
/// stores one of these per emitted job-id so the share-relay can reconstruct
/// every byte the upstream pool needs.
///
/// Most fields are mirror images of the corresponding `TemplateState` fields;
/// the runtime keeps a `JobMeta` per-emitted-job-id rather than per-template
/// because the C reference's `0x27` body needs the per-job assembly pinned.
#[derive(Debug, Clone)]
pub struct JobMeta {
    /// 8-bit job index assigned by the runtime — populated into the `0x27`
    /// `datum_job_id` field. The runtime owns the allocator (8-bit ring per C).
    pub datum_job_idx: u8,
    /// 8-bit coinbase variant used for this notify (always 0 today; OCEAN's
    /// pool may select among up to 8 variants per the C reference).
    pub coinbase_id: u8,
    /// `target_pot_index`: byte offset in `coinb1` of the PoT placeholder.
    pub target_pot_index: u16,
    /// Block version baked into the notify; copied verbatim into the share's
    /// `version` field.
    pub version: u32,
    /// Block height of this template.
    pub height: u32,
    /// Coinbase value (sats) of this template.
    pub coinbase_value: u64,
    /// Internal byte-order prevhash (the same 32 bytes used in
    /// `RequestCoinbaser`).
    pub prevhash_bin: [u8; 32],
    /// `nbits` as 4 big-endian display bytes (matches what GBT returns).
    pub nbits_bin: [u8; 4],
    /// Sibling-path merkle branches (each 32 bytes, big-endian txid display
    /// order — matches what the assembler put in the SV1 wire frame).
    pub merkle_branches_bin: Vec<[u8; 32]>,
    /// Full coinb1 / coinb2 raw bytes (NOT the hex). Forwarded to the upstream
    /// pool the first time a share lands for this (job, coinbase_id).
    pub coinb1_bin: Vec<u8>,
    pub coinb2_bin: Vec<u8>,
    /// Coinbaser blob id (`datum_id`) that produced this job's outputs.
    pub datum_coinbaser_id: u8,
    /// Transaction count from the GBT template.
    pub txn_count: u32,
    /// Total weight of all transactions in the template.
    pub txn_total_weight: u32,
    /// Total size in bytes of all transactions.
    pub txn_total_size: u32,
    /// Total sigops across all transactions.
    pub txn_total_sigops: u32,
    /// Network block target in INTERNAL little-endian byte order.
    pub block_target: [u8; 32],
    /// Hex-encoded `data` field of every transaction in the template.
    pub txn_data_hex: std::sync::Arc<Vec<String>>,
}

impl NotifyParams {
    pub fn to_json_array(&self) -> Value {
        json!([
            self.job_id,
            self.prev_hash,
            self.coinb1,
            self.coinb2,
            self.merkle_branch,
            self.version_hex,
            self.nbits_hex,
            self.ntime_hex,
            self.clean_jobs,
        ])
    }
}

/// Assemble `mining.notify` params from a template + coinbaser blob, with
/// scriptsig layout matching `datum_coinbaser.c::generate_coinbase_input`
/// byte-for-byte.
///
/// Convenience wrapper around [`assemble_notify_with_scriptsig`] using the
/// default scriptsig defaults (matches C `coinbase_tag_primary`,
/// `coinbase_tag_secondary`, `coinbase_unique_id` defaults).
pub fn assemble_notify(
    job_id: &str,
    template: &Template,
    coinbaser: &CoinbaserBlob,
    coinbase_tag: &[u8],
    clean_jobs: bool,
) -> NotifyParams {
    let primary = std::str::from_utf8(coinbase_tag).unwrap_or("DATUM Gateway");
    assemble_notify_with_scriptsig(
        job_id,
        template,
        coinbaser,
        ScriptSigInputs {
            coinbase_tag_primary: primary,
            coinbase_tag_secondary: "DATUM User",
            ..ScriptSigInputs::default()
        },
        clean_jobs,
    )
}

/// Full-fidelity entry point. Produces `mining.notify` params using the exact
/// scriptsig layout the C gateway emits.
pub fn assemble_notify_with_scriptsig(
    job_id: &str,
    template: &Template,
    coinbaser: &CoinbaserBlob,
    scriptsig: ScriptSigInputs<'_>,
    clean_jobs: bool,
) -> NotifyParams {
    assemble_notify_meta(job_id, 0, 0, template, coinbaser, scriptsig, clean_jobs).0
}

/// Like [`assemble_notify_with_scriptsig`] but also returns a [`JobMeta`] that
/// captures every per-job field the share-relay later needs to encode the
/// DATUM `0x27` share-submission body.
pub fn assemble_notify_meta(
    job_id: &str,
    datum_job_idx: u8,
    coinbase_id: u8,
    template: &Template,
    coinbaser: &CoinbaserBlob,
    scriptsig: ScriptSigInputs<'_>,
    clean_jobs: bool,
) -> (NotifyParams, JobMeta) {
    let state = TemplateState::from_template_and_blob(template, coinbaser, scriptsig, 0);
    notify_from_template_state(job_id, datum_job_idx, coinbase_id, &state, clean_jobs)
}

/// Build `(NotifyParams, JobMeta)` from an existing `TemplateState`. This is
/// the load-bearing path — Phase 1 of the SV2 listener plan: SV1 reads its
/// notify bytes from the same `TemplateState` SV2 will consume in Phase 4
/// for `coinbase_tx_prefix` / `coinbase_tx_suffix` / `merkle_path`. The byte
/// equivalence between SV1 and SV2 is the catastrophic-if-violated invariant
/// from the SV2 architecture playbook (cross-protocol coinbase-sum).
pub fn notify_from_template_state(
    job_id: &str,
    datum_job_idx: u8,
    coinbase_id: u8,
    state: &TemplateState,
    clean_jobs: bool,
) -> (NotifyParams, JobMeta) {
    let prev_hash_be_hex = {
        // TemplateState carries internal-LE; SV1 wants GBT's BE display hex
        // word-swapped. Reverse to BE display first, then word-swap.
        let mut be = state.prev_hash;
        be.reverse();
        swap_prev_hash_for_stratum(&hex::encode(be))
    };
    let version_hex = format!("{:08x}", state.version);
    let ntime_hex = format!("{:08x}", state.min_ntime);
    let nbits_hex = hex::encode(state.nbits);

    let merkle_branch: Vec<String> = state.merkle_branches.iter().map(hex::encode).collect();

    let notify = NotifyParams {
        job_id: job_id.to_string(),
        prev_hash: prev_hash_be_hex,
        coinb1: hex::encode(&state.coinb1),
        coinb2: hex::encode(&state.coinb2),
        merkle_branch,
        version_hex,
        nbits_hex,
        ntime_hex,
        clean_jobs,
    };

    let meta = JobMeta {
        datum_job_idx,
        coinbase_id,
        target_pot_index: state.target_pot_index,
        version: state.version,
        height: state.height,
        coinbase_value: state.coinbase_value,
        prevhash_bin: state.prev_hash,
        nbits_bin: state.nbits,
        merkle_branches_bin: state.merkle_branches.clone(),
        coinb1_bin: state.coinb1.clone(),
        coinb2_bin: state.coinb2.clone(),
        datum_coinbaser_id: state.datum_coinbaser_id,
        txn_count: state.txn_count,
        txn_total_weight: state.txn_total_weight,
        txn_total_size: state.txn_total_size,
        txn_total_sigops: state.txn_total_sigops,
        block_target: state.block_target,
        txn_data_hex: state.txn_data_hex.clone(),
    };

    (notify, meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use datum_coinbaser::CoinbaseOutput;

    fn template() -> Template {
        Template {
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
        }
    }

    fn p2pkh_blob() -> CoinbaserBlob {
        CoinbaserBlob {
            datum_id: 1,
            outputs: vec![CoinbaseOutput {
                value_sats: 312_500_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            }],
        }
    }

    #[test]
    fn assemble_notify_round_trip_to_json() {
        let n = assemble_notify("job-1", &template(), &p2pkh_blob(), b"datum-rs", true);
        let json = n.to_json_array();
        assert_eq!(json[0], "job-1");
        assert_eq!(json[8], true);
        let coinb1 = json[2].as_str().unwrap();
        let coinb2 = json[3].as_str().unwrap();
        assert!(coinb1.starts_with("01000000"));
        assert!(!coinb1.is_empty() && !coinb2.is_empty());
        assert_eq!(json[5].as_str().unwrap().len(), 8);
        assert_eq!(json[6].as_str().unwrap(), "1d00ffff");
        assert_eq!(json[7].as_str().unwrap().len(), 8);
    }

    #[test]
    fn coinb1_then_coinb2_decodes_as_legacy_coinbase() {
        let n = assemble_notify("j", &template(), &p2pkh_blob(), b"", false);
        let mut full = hex::decode(&n.coinb1).unwrap();
        full.extend(vec![0u8; EXTRANONCE_PLACEHOLDER_LEN]);
        full.extend(hex::decode(&n.coinb2).unwrap());
        assert!(full.len() > 60);
        assert_eq!(&full[0..4], &[0x01, 0x00, 0x00, 0x00], "version");
        assert_eq!(full[4], 0x01, "tx_in_count");
        assert_eq!(&full[5..37], &[0u8; 32], "prev_hash zeroed");
    }

    #[test]
    fn scriptsig_matches_c_layout_for_known_inputs() {
        let n = assemble_notify_with_scriptsig(
            "j",
            &Template {
                version: 0x2000_0000,
                previous_block_hash: "00".repeat(32),
                bits: "207fffff".into(),
                height: 102,
                coinbase_value: 5_000_000_000,
                curtime: 0,
                mintime: 0,
                sizelimit: 4_000_000,
                weightlimit: 4_000_000,
                sigop_limit: 80_000,
                default_witness_commitment: None,
                transactions: vec![],
                long_poll_id: None,
                target: None,
            },
            &CoinbaserBlob {
                datum_id: 0,
                outputs: vec![],
            },
            ScriptSigInputs {
                coinbase_tag_primary: "datum-rs cap",
                coinbase_tag_secondary: "T",
                coinbase_unique_id: 4242,
                enprefix: 0x0db1,
                pot_placeholder: 0x03,
            },
            true,
        );
        let coinb1 = hex::decode(&n.coinb1).unwrap();
        let scriptsig_len = coinb1[41] as usize;
        assert_eq!(scriptsig_len, 37, "C-equivalent scriptsig is 37 bytes");
        let ss = &coinb1[42..];
        assert_eq!(&ss[0..2], &[0x01, 0x66]);
        let expected_tag = b"\x0fdatum-rs cap\x0fT\x00";
        assert_eq!(&ss[2..2 + expected_tag.len()], expected_tag);
        let after_tag = 2 + expected_tag.len();
        assert_eq!(&ss[after_tag..after_tag + 4], &[0x03, 0x03, 0x92, 0x10]);
        let after_uid = after_tag + 4;
        assert_eq!(&ss[after_uid..after_uid + 3], &[0x0e, 0xb1, 0x0d]);
    }

    #[test]
    fn outputs_with_witness_commitment_extra_output() {
        let mut t = template();
        t.default_witness_commitment = Some(hex::encode(vec![0xaa; 38]));
        let n = assemble_notify("j", &t, &p2pkh_blob(), b"", false);
        let coinb2_bytes = hex::decode(&n.coinb2).unwrap();
        assert!(coinb2_bytes.len() > p2pkh_blob().outputs[0].script_pubkey.len() + 38);
    }

    #[test]
    fn merkle_branch_empty_for_no_transactions() {
        let n = assemble_notify("j", &template(), &p2pkh_blob(), b"", false);
        assert_eq!(n.merkle_branch.len(), 0);
    }

    #[test]
    fn merkle_branch_single_tx_returns_just_that_tx() {
        use datum_blocktemplates::TemplateTransaction;
        let mut t = template();
        t.transactions = vec![TemplateTransaction {
            data: "00".into(),
            txid: "11".repeat(32),
            hash: "11".repeat(32),
            fee: 0,
            sigops: 0,
            weight: 0,
            depends: vec![],
        }];
        let n = assemble_notify("j", &t, &p2pkh_blob(), b"", false);
        assert_eq!(n.merkle_branch.len(), 1);
        assert_eq!(n.merkle_branch[0], "11".repeat(32));
    }

    #[test]
    fn merkle_branch_grows_logarithmically() {
        use datum_blocktemplates::TemplateTransaction;
        let mut t = template();
        t.transactions = (0..4u8)
            .map(|i| TemplateTransaction {
                data: "00".into(),
                txid: format!("{i:02x}").repeat(32),
                hash: format!("{i:02x}").repeat(32),
                fee: 0,
                sigops: 0,
                weight: 0,
                depends: vec![],
            })
            .collect();
        let n = assemble_notify("j", &t, &p2pkh_blob(), b"", false);
        assert_eq!(
            n.merkle_branch.len(),
            3,
            "ceil(log2(N+1)) = 3 for N=4 transactions"
        );
        assert_eq!(n.merkle_branch[0], "00".repeat(32));
    }

    #[test]
    fn merkle_branch_three_txs_branch_len_2() {
        use datum_blocktemplates::TemplateTransaction;
        let mut t = template();
        t.transactions = (0..3u8)
            .map(|i| TemplateTransaction {
                data: "00".into(),
                txid: format!("{i:02x}").repeat(32),
                hash: format!("{i:02x}").repeat(32),
                fee: 0,
                sigops: 0,
                weight: 0,
                depends: vec![],
            })
            .collect();
        let n = assemble_notify("j", &t, &p2pkh_blob(), b"", false);
        assert_eq!(n.merkle_branch.len(), 2);
    }

    #[test]
    fn nbits_to_target_le_difficulty_one() {
        let t = nbits_to_target_le("1d00ffff");
        assert_eq!(t[26], 0xff);
        assert_eq!(t[27], 0xff);
        assert_eq!(t[28], 0x00);
        assert_eq!(t[31], 0x00);
    }

    #[test]
    fn nbits_to_target_le_regtest() {
        let t = nbits_to_target_le("207fffff");
        assert_eq!(t[29], 0xff);
        assert_eq!(t[30], 0xff);
        assert_eq!(t[31], 0x7f);
    }

    #[test]
    fn nbits_to_target_le_malformed_returns_zero() {
        let t = nbits_to_target_le("zz");
        assert_eq!(t, [0u8; 32]);
    }

    #[test]
    fn block_target_decoded_from_template_target_field() {
        let mut t = template();
        t.target = Some("00000000000000000000000000000000000000000000000000000000000000ff".into());
        let (_n, meta) = assemble_notify_meta(
            "j",
            0,
            0,
            &t,
            &p2pkh_blob(),
            ScriptSigInputs::default(),
            true,
        );
        assert_eq!(meta.block_target[0], 0xff);
        for &b in &meta.block_target[1..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn block_target_falls_back_to_nbits_when_target_absent() {
        let t = template();
        assert!(t.target.is_none());
        let (_n, meta) = assemble_notify_meta(
            "j",
            0,
            0,
            &t,
            &p2pkh_blob(),
            ScriptSigInputs::default(),
            true,
        );
        assert_eq!(meta.block_target, nbits_to_target_le(&t.bits));
    }

    #[test]
    fn prev_hash_is_word_swapped() {
        let original = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let swapped = swap_prev_hash_for_stratum(original);
        assert_eq!(
            swapped,
            "0403020108070605".to_string()
                + "0c0b0a09100f0e0d"
                + "1413121118171615"
                + "1c1b1a19201f1e1d"
        );
    }

    #[test]
    fn notify_from_template_state_matches_assemble_notify_meta() {
        // The new code path (Phase 1) must produce identical output to the
        // legacy path. Build via both and assert byte equality on every
        // field the share-relay depends on.
        let template_in = template();
        let blob = p2pkh_blob();
        let scriptsig = ScriptSigInputs {
            coinbase_tag_primary: "datum-rs cap",
            coinbase_tag_secondary: "T",
            coinbase_unique_id: 4242,
            enprefix: 0x0db1,
            pot_placeholder: 0x03,
        };
        let (legacy_notify, legacy_meta) = assemble_notify_meta(
            "abcdef0123456789",
            7,
            3,
            &template_in,
            &blob,
            scriptsig.clone(),
            true,
        );
        let state =
            TemplateState::from_template_and_blob(&template_in, &blob, scriptsig.clone(), 99);
        let (state_notify, state_meta) =
            notify_from_template_state("abcdef0123456789", 7, 3, &state, true);
        assert_eq!(state_notify.coinb1, legacy_notify.coinb1);
        assert_eq!(state_notify.coinb2, legacy_notify.coinb2);
        assert_eq!(state_notify.merkle_branch, legacy_notify.merkle_branch);
        assert_eq!(state_notify.prev_hash, legacy_notify.prev_hash);
        assert_eq!(state_notify.version_hex, legacy_notify.version_hex);
        assert_eq!(state_notify.nbits_hex, legacy_notify.nbits_hex);
        assert_eq!(state_notify.ntime_hex, legacy_notify.ntime_hex);
        assert_eq!(state_meta.coinb1_bin, legacy_meta.coinb1_bin);
        assert_eq!(state_meta.coinb2_bin, legacy_meta.coinb2_bin);
        assert_eq!(
            state_meta.merkle_branches_bin,
            legacy_meta.merkle_branches_bin
        );
        assert_eq!(state_meta.target_pot_index, legacy_meta.target_pot_index);
        assert_eq!(state_meta.block_target, legacy_meta.block_target);
        assert_eq!(state_meta.prevhash_bin, legacy_meta.prevhash_bin);
        assert_eq!(state_meta.nbits_bin, legacy_meta.nbits_bin);
    }
}
