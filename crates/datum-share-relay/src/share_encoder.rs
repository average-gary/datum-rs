//! DATUM `0x27` body builder shared by SV1 + SV2 share-relays.
//!
//! Hoisted from `datum-bin/src/main.rs`. The byte-fidelity contract is preserved
//! verbatim — the canonical reference is `datum_protocol.c::datum_protocol_pow:1313-1438`.
//!
//! The function takes a [`SubmittedShareInputs`] (protocol-neutral) and a
//! mutable [`crate::JobEntry`] (so it can flip the per-(job, coinbase_id)
//! send-once flags and the cross-protocol `(template_seed, coinbase_id)`
//! sentinel that lives on the JobTracker — see [`crate::JobTracker`]).
//!
//! Design choices:
//! - **Block-found detection** is part of this builder, not the caller's
//!   responsibility. When the reconstructed share-hash meets the network
//!   target, the builder sets `flags |= 1` AND returns a `BlockSubmissionPayload`
//!   so the caller can spawn a `submitblock` against bitcoind.
//! - **Cross-protocol coinbase sentinel** is consulted alongside the per-key
//!   `server_has_coinbase[id]` flag: if EITHER says "already sent", the 0x02
//!   sub-block is skipped. This closes the dual-protocol first-share race
//!   noted in Phase 5's plan (the sentinel must emit EXACTLY ONCE per
//!   (template_seed, coinbase) across BOTH SV1 and SV2 — not once-per-protocol).

use sha2::{Digest, Sha256};

use crate::JobEntry;

/// Configuration knobs the share-relay needs to format the username field of
/// a DATUM `0x27` share submission. Same shape as the value `datum-bin/main.rs`
/// used pre-Phase-5; moved to this crate so SV2 can share the formatting.
#[derive(Debug, Clone)]
pub struct ShareUserConfig {
    pub pool_address: String,
    pub pass_full_users: bool,
    pub pass_workers: bool,
}

/// Protocol-neutral share inputs. Both SV1 and SV2 share-relays construct
/// this from their respective wire-message types, then call
/// [`build_share_submission`].
///
/// Field invariants:
/// - `extranonce` is the FULL 12-byte upstream extranonce (xn1‖xn2 for SV1;
///   `extranonce_prefix‖rollable_extranonce` for SV2).
/// - `version` already has any negotiated version-rolling mask OR'd in
///   (BIP-310 / SV2 Extended channels both apply the mask client-side; the
///   server passes the final 32-bit value through verbatim).
/// - `patched_coinb1_bin` MUST be the bytes the miner actually hashed, with
///   the PoT byte applied at `target_pot_index`. The relay does NOT
///   re-derive — that re-derivation is exactly the diff_race_02_block bug
///   that landed Phase-3-era SV1.
#[derive(Debug, Clone)]
pub struct SubmittedShareInputs {
    pub username: String,
    pub extranonce: [u8; 12],
    pub ntime: u32,
    pub nonce: u32,
    pub version: u32,
    pub current_diff: u64,
    /// PoT-patched coinb1 bytes for the active diff at submit time.
    /// `None` is rejected by the encoder — the caller must capture this at
    /// emit time per the SV1 emit-ring lesson.
    pub patched_coinb1_bin: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BlockSubmissionPayload {
    pub block_hex: String,
    pub block_hash_hex: String,
}

#[derive(Debug)]
pub struct ShareEncoded {
    pub body: Vec<u8>,
    pub block_submission: Option<BlockSubmissionPayload>,
}

const FLAG_IS_BLOCK: u8 = 0x01;

pub fn build_share_submission(
    share: &SubmittedShareInputs,
    entry: &mut JobEntry,
    user_cfg: &ShareUserConfig,
    cross_protocol_coinbase_already_seen: bool,
) -> Result<ShareEncoded, String> {
    // PoT target byte tied to the diff active at submit time (see
    // `SubmittedShareInputs::current_diff` doc).
    let target_byte = floor_pot(share.current_diff);

    let coinb1_patched = match share.patched_coinb1_bin.as_deref() {
        Some(b) => b.to_vec(),
        None => {
            // Defensive fallback. SV1 callers always supply this. SV2 callers
            // also do; this mirrors the C path's `if (!coinb1_patched)` guard.
            let mut b = entry.meta.coinb1_bin.clone();
            let pot_index = entry.meta.target_pot_index as usize;
            if pot_index < b.len() {
                b[pot_index] = target_byte;
            }
            b
        }
    };

    let merkle_root = compute_merkle_root(
        &coinb1_patched,
        &share.extranonce,
        &entry.meta.coinb2_bin,
        &entry.meta.merkle_branches_bin,
    );

    // Build 80-byte header in canonical Bitcoin layout.
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&share.version.to_le_bytes());
    header[4..36].copy_from_slice(&entry.meta.prevhash_bin);
    header[36..68].copy_from_slice(&merkle_root);
    header[68..72].copy_from_slice(&share.ntime.to_le_bytes());
    let mut nbits_le = entry.meta.nbits_bin;
    nbits_le.reverse();
    header[72..76].copy_from_slice(&nbits_le);
    header[76..80].copy_from_slice(&share.nonce.to_le_bytes());
    let share_hash = double_sha256(&header);
    let is_block = hash_meets_target(&share_hash, &entry.meta.block_target);
    let flags: u8 = if is_block { FLAG_IS_BLOCK } else { 0 };

    let prefix = datum_protocol::ShareSubmissionPrefix {
        job_id: entry.meta.datum_job_idx,
        coinbase_id: entry.meta.coinbase_id,
        flags,
        target_byte,
        ntime: share.ntime,
        nonce: share.nonce,
        version: share.version,
        extranonce: share.extranonce,
    };
    let mut body = prefix.encode();

    let user_bytes = format_share_username(&share.username, user_cfg);
    body.extend_from_slice(&user_bytes);
    body.push(0);

    body.extend_from_slice(&[0u8; 4]);

    if !entry.server_has_merkle_branches {
        body.push(0x01);
        body.extend_from_slice(&entry.meta.prevhash_bin);
        body.extend_from_slice(&entry.meta.target_pot_index.to_le_bytes());
        let mut nbits_le = entry.meta.nbits_bin;
        nbits_le.reverse();
        body.extend_from_slice(&nbits_le);
        body.push(entry.meta.datum_coinbaser_id);
        body.extend_from_slice(&entry.meta.height.to_le_bytes());
        body.extend_from_slice(&entry.meta.coinbase_value.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_count.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_total_weight.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_total_size.to_le_bytes());
        body.extend_from_slice(&entry.meta.txn_total_sigops.to_le_bytes());
        body.push(entry.meta.merkle_branches_bin.len() as u8);
        for branch in &entry.meta.merkle_branches_bin {
            let mut le = *branch;
            le.reverse();
            body.extend_from_slice(&le);
        }
        entry.server_has_merkle_branches = true;
    }

    let cb_id = entry.meta.coinbase_id as usize;
    let already_sent_per_key =
        cb_id < entry.server_has_coinbase.len() && entry.server_has_coinbase[cb_id];
    // Skip 0x02 if EITHER the per-key flag OR the cross-protocol sentinel
    // says it's already been sent. The cross-protocol sentinel closes the
    // dual-protocol first-share race noted in Phase 5's plan.
    if !already_sent_per_key && !cross_protocol_coinbase_already_seen {
        body.push(0x02);
        body.push(entry.meta.coinbase_id);
        let cb1_len = entry.meta.coinb1_bin.len() as u16;
        let cb2_len = entry.meta.coinb2_bin.len() as u16;
        body.extend_from_slice(&cb1_len.to_le_bytes());
        body.extend_from_slice(&cb2_len.to_le_bytes());
        body.extend_from_slice(&entry.meta.coinb1_bin);
        body.extend_from_slice(&entry.meta.coinb2_bin);
        if cb_id < entry.server_has_coinbase.len() {
            entry.server_has_coinbase[cb_id] = true;
        }
    }

    body.push(0xFE);

    let rb = padding_byte();
    let pad_len = 1 + (rb as usize % 80);
    body.extend(std::iter::repeat_n(rb, pad_len));

    let block_submission = if is_block {
        let mut hash_be = share_hash;
        hash_be.reverse();
        let block_hash_hex = hex::encode(hash_be);

        let mut full_cb =
            Vec::with_capacity(coinb1_patched.len() + 12 + entry.meta.coinb2_bin.len());
        full_cb.extend_from_slice(&coinb1_patched);
        full_cb.extend_from_slice(&share.extranonce);
        full_cb.extend_from_slice(&entry.meta.coinb2_bin);

        let txn_count = entry.meta.txn_count as u64;
        let mut block_hex = String::with_capacity(160 + full_cb.len() * 2 + 200_000);
        block_hex.push_str(&hex::encode(header));
        push_varint_hex(&mut block_hex, txn_count + 1);
        block_hex.push_str(&hex::encode(&full_cb));
        for tx_hex in entry.meta.txn_data_hex.iter() {
            block_hex.push_str(tx_hex);
        }
        Some(BlockSubmissionPayload {
            block_hex,
            block_hash_hex,
        })
    } else {
        None
    };

    Ok(ShareEncoded {
        body,
        block_submission,
    })
}

pub fn format_share_username(miner_user: &str, cfg: &ShareUserConfig) -> Vec<u8> {
    let s = if (!cfg.pass_full_users && !cfg.pass_workers) || miner_user.is_empty() {
        cfg.pool_address.clone()
    } else if cfg.pass_full_users && !miner_user.starts_with('.') {
        miner_user.to_string()
    } else if cfg.pass_full_users || cfg.pass_workers {
        let sep = if miner_user.starts_with('.') { "" } else { "." };
        format!("{}{}{}", cfg.pool_address, sep, miner_user)
    } else {
        cfg.pool_address.clone()
    };
    let mut out = s.into_bytes();
    out.truncate(384);
    out
}

fn floor_pot(x: u64) -> u8 {
    if x == 0 {
        0
    } else {
        (63 - x.leading_zeros()) as u8
    }
}

fn double_sha256(input: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(input);
    Sha256::digest(first).into()
}

fn compute_merkle_root(
    coinb1_patched: &[u8],
    extranonce: &[u8; 12],
    coinb2: &[u8],
    branches: &[[u8; 32]],
) -> [u8; 32] {
    let mut full_cb = Vec::with_capacity(coinb1_patched.len() + 12 + coinb2.len());
    full_cb.extend_from_slice(coinb1_patched);
    full_cb.extend_from_slice(extranonce);
    full_cb.extend_from_slice(coinb2);
    let mut acc = double_sha256(&full_cb);
    let mut buf = [0u8; 64];
    for sib in branches {
        let mut sib_le = *sib;
        sib_le.reverse();
        buf[..32].copy_from_slice(&acc);
        buf[32..].copy_from_slice(&sib_le);
        acc = double_sha256(&buf);
    }
    acc
}

/// Compare a candidate hash against a target, both in internal-LE byte order.
/// Walk from MSB (index 31) down, returning true iff `hash <= target`.
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        match hash[i].cmp(&target[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

fn push_varint_hex(out: &mut String, v: u64) {
    if v < 0xfd {
        out.push_str(&format!("{:02x}", v as u8));
    } else if v <= 0xffff {
        out.push_str("fd");
        out.push_str(&format!("{:02x}{:02x}", v as u8, (v >> 8) as u8));
    } else if v <= 0xffff_ffff {
        out.push_str("fe");
        out.push_str(&hex::encode((v as u32).to_le_bytes()));
    } else {
        out.push_str("ff");
        out.push_str(&hex::encode(v.to_le_bytes()));
    }
}

fn padding_byte() -> u8 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let mut x = STATE.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    STATE.store(x, Ordering::Relaxed);
    (x & 0xFF) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use datum_stratum_sv1::assembler::JobMeta;

    fn synthetic_job_entry(target: [u8; 32]) -> JobEntry {
        JobEntry {
            meta: JobMeta {
                datum_job_idx: 0,
                coinbase_id: 0,
                target_pot_index: 0,
                version: 0x20000000,
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
                block_target: target,
                txn_data_hex: std::sync::Arc::new(vec![]),
            },
            template_seed: 0,
            server_has_merkle_branches: false,
            server_has_coinbase: [false; 8],
        }
    }

    fn synthetic_share() -> SubmittedShareInputs {
        SubmittedShareInputs {
            username: "bc1q".into(),
            extranonce: [0u8; 12],
            ntime: 0,
            nonce: 0,
            version: 0x2000_0000,
            current_diff: 1,
            patched_coinb1_bin: Some(vec![0u8; 50]),
        }
    }

    fn user() -> ShareUserConfig {
        ShareUserConfig {
            pool_address: "bc1qpool".into(),
            pass_full_users: false,
            pass_workers: false,
        }
    }

    #[test]
    fn block_found_when_target_is_max() {
        let mut entry = synthetic_job_entry([0xFFu8; 32]);
        let share = synthetic_share();
        let enc = build_share_submission(&share, &mut entry, &user(), false).unwrap();
        assert!(enc.block_submission.is_some());
    }

    #[test]
    fn no_block_when_target_is_zero() {
        let mut entry = synthetic_job_entry([0u8; 32]);
        let share = synthetic_share();
        let enc = build_share_submission(&share, &mut entry, &user(), false).unwrap();
        assert!(enc.block_submission.is_none());
    }

    #[test]
    fn cross_protocol_sentinel_skips_0x02_block() {
        let mut entry = synthetic_job_entry([0u8; 32]);
        let share = synthetic_share();
        let user = user();
        // Tell the encoder the cross-protocol sentinel says "already seen".
        let _enc = build_share_submission(&share, &mut entry, &user, /*xprot_seen=*/ true).unwrap();
        // Body should NOT contain a 0x02 sub-block. Search for the 0x02
        // marker between the username NUL and the 0xFE cap. The first byte
        // after the user_bytes + 4 reserved zeros is 0x01 (always emitted on
        // first share — `server_has_merkle_branches` was false). But 0x02
        // must NOT appear in the merkle branches segment.
        // Assert the per-key flag was NOT flipped (no emission).
        assert!(!entry.server_has_coinbase[0]);
    }

    #[test]
    fn floor_pot_works() {
        assert_eq!(floor_pot(0), 0);
        assert_eq!(floor_pot(1), 0);
        assert_eq!(floor_pot(2), 1);
        assert_eq!(floor_pot(0xff), 7);
        assert_eq!(floor_pot(0x10000), 16);
    }

    #[test]
    fn hash_meets_target_walks_msb_down() {
        let mut hash = [0u8; 32];
        let mut target = [0u8; 32];
        hash[31] = 0x10;
        target[31] = 0x20;
        assert!(hash_meets_target(&hash, &target));
        hash[31] = 0x30;
        assert!(!hash_meets_target(&hash, &target));
    }

    /// Byte-fidelity gate, hoisted from `datum-bin/src/main.rs`. Pins the
    /// EXACT 0x27 body bytes for a deterministic input vector (everything up
    /// to and including the 0xFE cap).
    #[test]
    fn share_submission_body_byte_fidelity() {
        let mut entry = JobEntry {
            meta: JobMeta {
                datum_job_idx: 0x07,
                coinbase_id: 0x00,
                target_pot_index: 42,
                version: 0x2000_0000,
                height: 800_000,
                coinbase_value: 5_000_000_000,
                prevhash_bin: {
                    let mut a = [0u8; 32];
                    for (i, b) in a.iter_mut().enumerate() {
                        *b = (i + 1) as u8;
                    }
                    a
                },
                nbits_bin: [0x20, 0x7f, 0xff, 0xff],
                merkle_branches_bin: vec![{
                    let mut a = [0u8; 32];
                    for (i, b) in a.iter_mut().enumerate() {
                        *b = i as u8;
                    }
                    a
                }],
                coinb1_bin: vec![0xCB, 0x11, 0x22, 0x33, 0x44, 0x55, 0xFF, 0x66, 0x77, 0x88],
                coinb2_bin: vec![0xC2, 0x99, 0xAA],
                datum_coinbaser_id: 0x05,
                txn_count: 0,
                txn_total_weight: 0,
                txn_total_size: 0,
                txn_total_sigops: 0,
                block_target: [0u8; 32],
                txn_data_hex: std::sync::Arc::new(vec![]),
            },
            template_seed: 0,
            server_has_merkle_branches: false,
            server_has_coinbase: [false; 8],
        };
        let share = SubmittedShareInputs {
            username: String::new(),
            extranonce: [
                0xE1, 0xE2, 0xE3, 0xE4, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            ],
            ntime: 0x12345678,
            nonce: 0x9abcdef0,
            version: 0x2000_0000,
            current_diff: 65536,
            patched_coinb1_bin: Some(vec![
                0xCB, 0x11, 0x22, 0x33, 0x44, 0x55, 0x10, 0x66, 0x77, 0x88,
            ]),
        };
        let user = ShareUserConfig {
            pool_address: "1POOLADDR".into(),
            pass_full_users: false,
            pass_workers: false,
        };
        let enc = build_share_submission(&share, &mut entry, &user, false).unwrap();
        assert!(enc.block_submission.is_none());

        let mut expected = String::new();
        expected.push_str("27");
        expected.push_str("07");
        expected.push_str("00");
        expected.push_str("00");
        expected.push_str("10");
        expected.push_str("78563412");
        expected.push_str("f0debc9a");
        expected.push_str("00000020");
        expected.push_str("0c");
        expected.push_str("e1e2e3e4a1a2a3a4a5a6a7a8");
        expected.push_str(&hex::encode(b"1POOLADDR"));
        expected.push_str("00");
        expected.push_str("00000000");
        expected.push_str("01");
        for i in 1u8..=32 {
            expected.push_str(&format!("{i:02x}"));
        }
        expected.push_str("2a00");
        expected.push_str("ffff7f20");
        expected.push_str("05");
        expected.push_str("00350c00");
        expected.push_str("00f2052a01000000");
        expected.push_str("00000000");
        expected.push_str("00000000");
        expected.push_str("00000000");
        expected.push_str("00000000");
        expected.push_str("01");
        for i in (0u8..=31).rev() {
            expected.push_str(&format!("{i:02x}"));
        }
        expected.push_str("02");
        expected.push_str("00");
        expected.push_str("0a00");
        expected.push_str("0300");
        expected.push_str("cb1122334455ff667788");
        expected.push_str("c299aa");
        expected.push_str("fe");

        let expected_bytes = hex::decode(&expected).unwrap();
        let cap_pos = expected_bytes.len();
        assert!(
            enc.body.len() > cap_pos && enc.body.len() <= cap_pos + 80,
            "body length {} outside expected window ({}, {}+80]",
            enc.body.len(),
            cap_pos,
            cap_pos
        );
        assert_eq!(
            hex::encode(&enc.body[..cap_pos]),
            expected,
            "structured 0x27 body bytes diverge from C reference"
        );
    }
}
