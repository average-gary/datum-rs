//! Shared template/job state, watched by both SV1 and SV2 protocols.
//!
//! Per the SV2 listener plan ([phase 1](../../../.wiki/output/plan-stratum-v2-listener-2026-06-16.md))
//! and [SV2 downstream architecture playbook §6][playbook]: a single source of
//! truth for the template-derived bytes both protocols need.
//!
//! - SV1 reads `coinb1` / `coinb2` / `merkle_branches` from here for its
//!   `mining.notify` params.
//! - SV2 will reuse the same `coinb1` as `coinbase_tx_prefix`, `coinb2` as
//!   `coinbase_tx_suffix`, and `merkle_branches` as the `merkle_path` for its
//!   `NewExtendedMiningJob` (Phase 4).
//!
//! The split has to be byte-identical across protocols: both miners hash the
//! same coinbase bytes, and a divergence here means an operator pays
//! themselves on one path and OCEAN on the other.
//!
//! [playbook]: ../../../.wiki/wiki/topics/sv2-downstream-architecture.md

use std::sync::Arc;

use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use tokio::sync::watch;

use crate::Template;

/// Total extranonce bytes the miner fills in: extranonce1 (4) + extranonce2 (4)
/// matches `extranonce1` returned in `mining.subscribe` (8 hex chars). Plus the
/// 2-byte `enprefix` written by the gateway right before the placeholder makes
/// the total `OP_PUSHBYTES 14`-payload region 14 bytes wide on the wire — but
/// only 12 of those bytes are "the placeholder" the miner fills.
pub const EXTRANONCE_PLACEHOLDER_LEN: usize = 12;

/// Bytes the gateway writes before the extranonce placeholder (the 2-byte
/// `enprefix` from `datum_coinbaser.c:392-395`). They go inside the same
/// `OP_PUSHBYTES 14` block in scriptsig, BEFORE the 12-byte placeholder.
pub const ENPREFIX_LEN: usize = 2;

/// Inputs for the scriptsig portion of the coinbase tx — directly maps to the
/// configurable fields in `datum_conf.c`. Lives here (not in SV1) so SV2 can
/// build a `TemplateState` without depending on SV1.
#[derive(Debug, Clone)]
pub struct ScriptSigInputs<'a> {
    pub coinbase_tag_primary: &'a str,
    pub coinbase_tag_secondary: &'a str,
    /// Per-instance unique identifier (`coinbase_unique_id` in
    /// `datum_conf.c`). Encoded as 2 LE bytes inside the uid push.
    pub coinbase_unique_id: u16,
    /// Per-job 2-byte extranonce prefix (`enprefix` in `datum_coinbaser.c`).
    /// The gateway picks this; we accept it from the runtime.
    pub enprefix: u16,
    /// PoT placeholder byte. C writes 0xFF and overwrites later when the
    /// vardiff target is known. We mirror that — runtime patches the byte.
    pub pot_placeholder: u8,
}

impl Default for ScriptSigInputs<'_> {
    fn default() -> Self {
        Self {
            coinbase_tag_primary: "DATUM Gateway",
            coinbase_tag_secondary: "DATUM User",
            coinbase_unique_id: 4242,
            enprefix: 0,
            pot_placeholder: 0xFF,
        }
    }
}

/// Single source of truth for template/job state shared by SV1 and SV2.
///
/// Per [SV2 downstream architecture §6][playbook]: SV2's `NewExtendedMiningJob`
/// reuses `coinb1` as `coinbase_tx_prefix`, `coinb2` as `coinbase_tx_suffix`,
/// and `merkle_branches` as `merkle_path`. SV1's `mining.notify` consumes the
/// same fields. Both protocols transition prevhash atomically because the
/// runtime's `tokio::sync::watch::Sender<Arc<TemplateState>>` hands them the
/// same `Arc`.
///
/// [playbook]: ../../../.wiki/wiki/topics/sv2-downstream-architecture.md
#[derive(Debug, Clone)]
pub struct TemplateState {
    /// Internal-LE byte order (`prev_hash[0]` is the LSB). Same convention as
    /// the C reference's `prevhash_bin`. SV2's `SetNewPrevHash.prev_hash` is
    /// emitted as `to_le_bytes()` — i.e. these bytes go on the wire verbatim
    /// (per [SV2 mining protocol §"Wire byte-order rule"][mining]).
    ///
    /// [mining]: ../../../.wiki/wiki/concepts/sv2-mining-protocol.md
    pub prev_hash: [u8; 32],
    /// Block height of the template (BIP34 height push uses this).
    pub height: u32,
    /// `nbits` as 4 big-endian display bytes (matches what GBT returns
    /// verbatim). The SV1 path emits these in the `mining.notify` `nbits`
    /// field unchanged. The SV2 path / DATUM `0x27` path want LE on wire
    /// and reverse on emit.
    pub nbits: [u8; 4],
    /// Earliest valid `ntime` per the GBT template. SV2's `NewExtendedMiningJob`
    /// uses this for `min_ntime` on the *current* (non-future) job.
    pub min_ntime: u32,
    /// `coinbasevalue` from GBT (subsidy + fees the coinbase claims).
    pub coinbase_value: u64,
    /// OCEAN-supplied (or local) coinbase outputs. Reuses
    /// `datum_coinbaser::CoinbaseOutput` directly — single source of truth
    /// across both protocols (catastrophic-if-divergent invariant from
    /// [SV2 downstream architecture §"cross-protocol coinbase-sum"][playbook]).
    ///
    /// [playbook]: ../../../.wiki/wiki/topics/sv2-downstream-architecture.md
    pub coinbase_outputs: Vec<CoinbaseOutput>,
    /// Coinbase bytes BEFORE the 12-byte extranonce placeholder. SV1 ships
    /// this hex-encoded as `mining.notify` field [2]; SV2 ships it raw as
    /// `NewExtendedMiningJob.coinbase_tx_prefix`. Identical bytes both ways.
    pub coinb1: Vec<u8>,
    /// Coinbase bytes AFTER the placeholder. Same dual role as `coinb1`.
    pub coinb2: Vec<u8>,
    /// Sibling-path of the (yet-unknown) coinbase position in the merkle
    /// tree, in BIG-ENDIAN display order (txid display order — the same
    /// convention SV1's `mining.notify` `merkle_branch` field uses). Each
    /// entry is 32 bytes. SV2's `merkle_path` wants internal-LE on wire, so
    /// the SV2 emitter reverses each entry on encode.
    pub merkle_branches: Vec<[u8; 32]>,
    /// Block version from GBT. Used as the SV1 `version` notify field and as
    /// `NewExtendedMiningJob.version` on the SV2 side.
    pub version: u32,
    /// Per-job seed the runtime can derive a u32/u64 job_id from. Today this
    /// is a tick-derived counter; both protocols hash/derive their own job-id
    /// representations from it but share the same numbering.
    pub job_id_seed: u64,
    /// `target_pot_index`: byte offset in `coinb1` of the PoT placeholder. The
    /// runtime overwrites this byte with `floor_pot(diff)` immediately before
    /// hashing the candidate header. Both protocols need this offset to patch
    /// the per-miner-diff byte.
    pub target_pot_index: u16,
    /// `datum_id` from the OCEAN-supplied coinbaser blob. Forwarded as
    /// `datum_coinbaser_id` in the DATUM `0x27` first-share-of-job sub-block.
    pub datum_coinbaser_id: u8,
    /// Network block target in INTERNAL little-endian byte order
    /// (`target[0]` is the LSB). Decoded from GBT's `target` field
    /// (big-endian display hex, reversed) or derived from `nbits` if absent.
    pub block_target: [u8; 32],
    /// Transaction count of the GBT template (for the DATUM `0x27` 0x01
    /// sub-block).
    pub txn_count: u32,
    /// Total weight of all transactions in the template.
    pub txn_total_weight: u32,
    /// Total size in bytes of all transactions.
    pub txn_total_size: u32,
    /// Total sigops across all transactions.
    pub txn_total_sigops: u32,
    /// Hex-encoded `data` field of every transaction in the template. Shared
    /// via `Arc` so all consumers (SV1 / SV2 share-relay; block submitter)
    /// share one allocation.
    pub txn_data_hex: Arc<Vec<String>>,
}

impl TemplateState {
    /// Construct a `TemplateState` from a GBT template, the OCEAN coinbaser
    /// blob, and the per-job scriptsig inputs.
    ///
    /// All byte-level work happens here so SV1 + SV2 produce **identical**
    /// `coinb1` / `coinb2` / `merkle_branches`. SV1's existing
    /// `assemble_notify_meta` is a thin shim around this.
    pub fn from_template_and_blob(
        template: &Template,
        coinbaser: &CoinbaserBlob,
        scriptsig: ScriptSigInputs<'_>,
        job_id_seed: u64,
    ) -> Self {
        let outputs_blob = build_outputs(template, coinbaser);
        let (coinb1, coinb2, target_pot_index) =
            build_split_coinbase_bin(template, &scriptsig, &outputs_blob);
        let merkle_branches = build_merkle_branches(template);

        let nbits: [u8; 4] = hex::decode(&template.bits)
            .ok()
            .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok())
            .unwrap_or([0u8; 4]);

        let prev_hash: [u8; 32] = hex::decode(&template.previous_block_hash)
            .ok()
            .and_then(|v| {
                let mut a = <[u8; 32]>::try_from(v.as_slice()).ok()?;
                // GBT returns big-endian display hex; internal-order is reversed.
                a.reverse();
                Some(a)
            })
            .unwrap_or([0u8; 32]);

        let block_target: [u8; 32] = template
            .target
            .as_deref()
            .and_then(|hex_be| hex::decode(hex_be).ok())
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .map(|mut a| {
                a.reverse();
                a
            })
            .unwrap_or_else(|| nbits_to_target_le(&template.bits));

        let txn_count = template.transactions.len() as u32;
        let txn_total_weight: u32 = template.transactions.iter().map(|t| t.weight).sum();
        let txn_total_size: u32 = template
            .transactions
            .iter()
            .map(|t| t.data.len() as u32 / 2)
            .sum();
        let txn_total_sigops: u32 = template.transactions.iter().map(|t| t.sigops).sum();
        let txn_data_hex = Arc::new(
            template
                .transactions
                .iter()
                .map(|t| t.data.clone())
                .collect::<Vec<_>>(),
        );

        Self {
            prev_hash,
            height: template.height,
            nbits,
            min_ntime: template.curtime as u32,
            coinbase_value: template.coinbase_value,
            coinbase_outputs: coinbaser.outputs.clone(),
            coinb1,
            coinb2,
            merkle_branches,
            version: template.version,
            job_id_seed,
            target_pot_index,
            datum_coinbaser_id: coinbaser.datum_id,
            block_target,
            txn_count,
            txn_total_weight,
            txn_total_size,
            txn_total_sigops,
            txn_data_hex,
        }
    }
}

/// Watch-channel handle for `TemplateState`. Cloneable; consumers
/// `.subscribe()` for `Receiver<Arc<TemplateState>>`. Both SV1 and SV2 use
/// this — the same `Arc` reaches both protocols on every transition.
#[derive(Clone)]
pub struct TemplateStateChannel {
    rx: watch::Receiver<Option<Arc<TemplateState>>>,
}

impl TemplateStateChannel {
    pub fn current(&self) -> Option<Arc<TemplateState>> {
        self.rx.borrow().clone()
    }

    pub async fn changed(&mut self) -> Result<Arc<TemplateState>, watch::error::RecvError> {
        loop {
            self.rx.changed().await?;
            if let Some(t) = self.rx.borrow_and_update().clone() {
                return Ok(t);
            }
        }
    }

    /// Consume the channel and yield the inner `watch::Receiver`. SV2's
    /// `ChannelManager` needs an owned receiver because it calls `.borrow()`
    /// directly (no async wrap on the immediate channel-open path).
    pub fn into_receiver(self) -> watch::Receiver<Option<Arc<TemplateState>>> {
        self.rx
    }
}

/// Publisher half of the template-state watch channel. The runtime holds one
/// of these and `publish`es a fresh `TemplateState` whenever GBT or DATUM
/// `client_config` produces a new prevhash / new template.
#[derive(Clone)]
pub struct TemplateStatePublisher {
    tx: watch::Sender<Option<Arc<TemplateState>>>,
}

impl TemplateStatePublisher {
    pub fn new() -> (Self, TemplateStateChannel) {
        let (tx, rx) = watch::channel(None);
        (Self { tx }, TemplateStateChannel { rx })
    }

    /// Publish a new `TemplateState`. Returns the `Arc` so the caller can
    /// also keep its own reference (e.g. for inserting into the runtime's
    /// JobTracker without re-cloning the inner state).
    pub fn publish(
        &self,
        state: TemplateState,
    ) -> Result<Arc<TemplateState>, watch::error::SendError<Option<Arc<TemplateState>>>> {
        let arc = Arc::new(state);
        self.tx.send(Some(arc.clone()))?;
        Ok(arc)
    }
}

// ---------------------------------------------------------------------------
// Coinbase build helpers
//
// Moved from `datum-stratum-sv1::assembler` so SV2 can reuse the same code
// path for `coinbase_tx_prefix` / `coinbase_tx_suffix` / `merkle_path` (Phase
// 4). The byte layout here is the C-reference legacy-serialization layout
// asserted by the existing `coinb1_byte_exact_against_c_capture` test.

/// Decode `nbits` (big-endian display hex from GBT) into a 32-byte target in
/// internal little-endian byte order. Mirrors `datum_utils.c::nbits_to_target`.
pub fn nbits_to_target_le(nbits_hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = match hex::decode(nbits_hex) {
        Ok(b) if b.len() == 4 => b,
        _ => return out,
    };
    let nbits = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let exp = (nbits >> 24) as usize;
    let mantissa = nbits & 0x00FF_FFFF;
    if !(3..=32).contains(&exp) {
        return out;
    }
    let base = exp - 3;
    if base + 3 > 32 {
        return out;
    }
    out[base] = (mantissa & 0xFF) as u8;
    out[base + 1] = ((mantissa >> 8) & 0xFF) as u8;
    out[base + 2] = ((mantissa >> 16) & 0xFF) as u8;
    out
}

/// SV1 `prev_hash` field is the GBT `previousblockhash` with **internal-byte
/// order swap** at the 4-byte word level (per Stratum V1 spec): each 4-byte
/// chunk reversed independently.
pub fn swap_prev_hash_for_stratum(hash_hex: &str) -> String {
    let bytes = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return hash_hex.to_string(),
    };
    let mut out = Vec::with_capacity(32);
    for chunk in bytes.chunks_exact(4) {
        let mut rev: Vec<u8> = chunk.iter().rev().copied().collect();
        out.append(&mut rev);
    }
    hex::encode(out)
}

fn build_outputs(template: &Template, coinbaser: &CoinbaserBlob) -> Vec<u8> {
    let mut buf = Vec::new();

    let total_outputs = coinbaser.outputs.len()
        + if template.default_witness_commitment.is_some() {
            1
        } else {
            0
        };
    push_varint(&mut buf, total_outputs as u64);

    for o in &coinbaser.outputs {
        buf.extend_from_slice(&o.value_sats.to_le_bytes());
        push_varint(&mut buf, o.script_pubkey.len() as u64);
        buf.extend_from_slice(&o.script_pubkey);
    }

    if let Some(commitment_hex) = &template.default_witness_commitment {
        if let Ok(commitment) = hex::decode(commitment_hex) {
            buf.extend_from_slice(&0u64.to_le_bytes());
            push_varint(&mut buf, commitment.len() as u64);
            buf.extend_from_slice(&commitment);
        }
    }

    buf
}

/// Returns `(coinb1, coinb2, target_pot_index)`. `target_pot_index` is the
/// byte offset in `coinb1` where the PoT placeholder lives — per
/// `datum_coinbaser.c:62-167`, the PoT byte is the FIRST byte of the uid push
/// block (`[0x03][PoT][uid_lo][uid_hi]`), placed immediately after the tag
/// block.
fn build_split_coinbase_bin(
    template: &Template,
    scriptsig: &ScriptSigInputs<'_>,
    outputs_blob: &[u8],
) -> (Vec<u8>, Vec<u8>, u16) {
    // CRITICAL: Stratum V1 mining.notify uses LEGACY (non-segwit) coinbase
    // serialization. The witness commitment lives as a normal output in the
    // outputs blob (handled by build_outputs); no marker/flag in the tx
    // itself, no witness reserved value. Matched against C-emitted fixture
    // in crates/datum-stratum-sv1/tests/fixtures/c-mining-notify.txt.
    //
    // ScriptSig layout per `datum_coinbaser.c::generate_coinbase_input`:
    //   [BIP34 height push] [tag block push] [uid push (PoT + uid LE)]
    //   [enprefix push: 0x0E + 2-byte enprefix + 12-byte placeholder]
    let mut coinb1 = Vec::new();
    let mut coinb2 = Vec::new();

    // version (4)
    coinb1.extend_from_slice(&1u32.to_le_bytes());
    // tx_in_count (1)
    coinb1.push(0x01);
    // prev_hash (32) — zero
    coinb1.extend_from_slice(&[0u8; 32]);
    // prev_idx (4) — 0xFFFFFFFF
    coinb1.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let height_script = bip34_height_script(template.height);
    let tag_block = build_tag_push_block(
        scriptsig.coinbase_tag_primary,
        scriptsig.coinbase_tag_secondary,
    );
    let uid_block = build_uid_push_block(scriptsig.pot_placeholder, scriptsig.coinbase_unique_id);

    // 0x0E push prefix + 2-byte enprefix + 12-byte placeholder = 15 bytes
    let scriptsig_len = height_script.len()
        + tag_block.len()
        + uid_block.len()
        + 1
        + ENPREFIX_LEN
        + EXTRANONCE_PLACEHOLDER_LEN;
    push_varint(&mut coinb1, scriptsig_len as u64);
    coinb1.extend_from_slice(&height_script);
    coinb1.extend_from_slice(&tag_block);
    // The PoT placeholder byte lives at offset 1 of `uid_block` (right after
    // the 0x03 push-3 opcode). Capture the absolute coinb1 offset BEFORE we
    // append uid_block.
    let target_pot_index = (coinb1.len() + 1) as u16;
    coinb1.extend_from_slice(&uid_block);
    coinb1.push(0x0E);
    coinb1.extend_from_slice(&scriptsig.enprefix.to_le_bytes());

    // PLACEHOLDER (12 bytes): split point. coinb1 ends here; coinb2 begins.

    // sequence (4)
    coinb2.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // outputs
    coinb2.extend_from_slice(outputs_blob);
    // locktime (4)
    coinb2.extend_from_slice(&0u32.to_le_bytes());

    (coinb1, coinb2, target_pot_index)
}

/// BIP34 coinbase scriptSig height encoding via the C reference's
/// `append_UNum_hex` algorithm: count significant bytes; if MSB is set, append
/// a zero byte to keep the value unsigned (BIP34 minimal CScriptNum-ish).
fn bip34_height_script(height: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut n = height;
    if n == 0 {
        bytes.push(0);
    } else {
        while n != 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
    }
    if let Some(&last) = bytes.last() {
        if last & 0x80 != 0 {
            bytes.push(0);
        }
    }
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(bytes.len() as u8);
    out.extend_from_slice(&bytes);
    out
}

/// Build the tag-push block. Per `datum_coinbaser.c:75-159`: combined size
/// `k = primary.len() + secondary.len() + 2` (two separator bytes); push
/// prefix is single-byte if k ≤ 75 else `0x4C` + length byte. Body is
/// `primary + 0x0F + secondary + 0x00` if both non-empty; just `primary +
/// 0x00` if no secondary; etc.
fn build_tag_push_block(primary: &str, secondary: &str) -> Vec<u8> {
    let p = primary.as_bytes();
    let s = secondary.as_bytes();
    let mut body = Vec::new();
    if !p.is_empty() {
        body.extend_from_slice(p);
        if s.is_empty() {
            body.push(0x00);
        } else {
            body.push(0x0F);
        }
    } else if !s.is_empty() {
        body.push(0x0F);
    }
    if !s.is_empty() {
        body.extend_from_slice(s);
        body.push(0x00);
    }

    let mut out = Vec::new();
    if body.is_empty() {
        // C reference fallback: push a NUL byte to avoid parsing the UID
        // as a pool name.
        out.push(0x01);
        out.push(0x00);
        return out;
    }
    let k = body.len();
    if k <= 75 {
        out.push(k as u8);
    } else {
        out.push(0x4C);
        out.push(k as u8);
    }
    out.extend_from_slice(&body);
    out
}

/// Build the unique-id push block. Per `datum_coinbaser.c:162-167` (no
/// DATUM-active path): push 3 bytes = `[pot_placeholder][unique_id_lo][unique_id_hi]`.
fn build_uid_push_block(pot_placeholder: u8, unique_id: u16) -> Vec<u8> {
    vec![
        0x03,
        pot_placeholder,
        (unique_id & 0xFF) as u8,
        ((unique_id >> 8) & 0xFF) as u8,
    ]
}

fn push_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Merkle branch computation per Stratum V1 spec, ported from
/// `datum_stratum.c::stratum_calculate_merkle_branches`.
///
/// Returns the sibling-path of the (yet-unknown) coinbase tx (always
/// position 0) as 32-byte arrays in BIG-ENDIAN display order — the same byte
/// order SV1's `mining.notify.merkle_branch` field uses. SV2's `merkle_path`
/// wants internal-LE; the SV2 emitter reverses each entry on encode.
fn build_merkle_branches(template: &Template) -> Vec<[u8; 32]> {
    if template.transactions.is_empty() {
        return Vec::new();
    }

    // Each transaction's `txid` is in big-endian display hex; flip to little-
    // endian internal byte order for tree computation.
    let mut current_level: Vec<[u8; 32]> = template
        .transactions
        .iter()
        .map(|t| {
            let mut b = hex::decode(&t.txid).unwrap_or_else(|_| vec![0u8; 32]);
            b.reverse();
            let mut a = [0u8; 32];
            if b.len() == 32 {
                a.copy_from_slice(&b);
            }
            a
        })
        .collect();

    let mut branch: Vec<[u8; 32]> = Vec::new();
    branch.push(current_level[0]);

    let mut effective_size = current_level.len() + 1;
    while effective_size > 1 {
        let dup_last = effective_size % 2 != 0;
        let padded_size = if dup_last {
            effective_size + 1
        } else {
            effective_size
        };
        let next_size = padded_size / 2;

        let mut next_level: Vec<[u8; 32]> = Vec::with_capacity(next_size);
        for i in 0..next_size {
            if i == 0 {
                next_level.push([0u8; 32]);
            } else {
                let left = current_level[(i * 2) - 1];
                let right_idx = i * 2;
                let right = if right_idx < current_level.len() {
                    current_level[right_idx]
                } else {
                    debug_assert!(dup_last, "out-of-range right but no dup_last");
                    current_level[(i * 2) - 1]
                };
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&left);
                combined[32..].copy_from_slice(&right);
                next_level.push(double_sha256(&combined));
            }
        }

        if next_size > 1 {
            branch.push(next_level[1]);
        }
        current_level = next_level;
        effective_size = next_size;
    }

    branch
        .into_iter()
        .map(|h| {
            let mut be = h;
            be.reverse();
            be
        })
        .collect()
}

fn double_sha256(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(input);
    let first: [u8; 32] = h.finalize().into();
    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TemplateTransaction;
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
    fn template_state_roundtrip_basic_fields() {
        let s = TemplateState::from_template_and_blob(
            &template(),
            &p2pkh_blob(),
            ScriptSigInputs::default(),
            42,
        );
        assert_eq!(s.height, 800_000);
        assert_eq!(s.version, 0x2000_0000);
        assert_eq!(s.coinbase_value, 312_500_000);
        assert_eq!(s.coinbase_outputs.len(), 1);
        assert_eq!(s.coinbase_outputs[0].value_sats, 312_500_000);
        assert_eq!(s.datum_coinbaser_id, 1);
        assert_eq!(s.job_id_seed, 42);
        // prev_hash decoded + reversed (internal-LE).
        assert_eq!(s.prev_hash, [0u8; 32]);
        // nbits = BE display bytes verbatim.
        assert_eq!(s.nbits, [0x1d, 0x00, 0xff, 0xff]);
    }

    #[test]
    fn template_state_coinb_split_starts_with_version_and_in_count() {
        let s = TemplateState::from_template_and_blob(
            &template(),
            &p2pkh_blob(),
            ScriptSigInputs::default(),
            0,
        );
        let mut full = s.coinb1.clone();
        full.extend(vec![0u8; EXTRANONCE_PLACEHOLDER_LEN]);
        full.extend(s.coinb2.clone());
        assert_eq!(&full[0..4], &[0x01, 0x00, 0x00, 0x00], "version LE");
        assert_eq!(full[4], 0x01, "tx_in_count (LEGACY)");
        assert_eq!(&full[5..37], &[0u8; 32], "prev_hash zeroed");
        // PoT byte sits at offset 1 of the uid push, which lands right after
        // the BIP34 height push + tag block. The exact value depends on the
        // default tag lengths so we just assert it points inside the
        // scriptsig (after version+in_count+prevhash+previdx+varint = 42).
        assert!(s.target_pot_index >= 42);
        assert!((s.target_pot_index as usize) < s.coinb1.len());
        // The byte at target_pot_index in coinb1 is the PoT placeholder
        // (default 0xFF); the runtime overwrites it per-miner-diff before
        // sending notify.
        assert_eq!(s.coinb1[s.target_pot_index as usize], 0xFF);
        assert!(s.merkle_branches.is_empty());
    }

    #[test]
    fn template_state_merkle_branches_match_count() {
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
        let s =
            TemplateState::from_template_and_blob(&t, &p2pkh_blob(), ScriptSigInputs::default(), 0);
        assert_eq!(s.merkle_branches.len(), 3, "ceil(log2(4+1)) = 3");
        // First branch is tx[0], in big-endian display order.
        let mut first = [0u8; 32];
        first.copy_from_slice(&hex::decode("00".repeat(32)).unwrap());
        assert_eq!(s.merkle_branches[0], first);
    }

    #[test]
    fn template_state_block_target_from_target_field() {
        let mut t = template();
        t.target = Some("00000000000000000000000000000000000000000000000000000000000000ff".into());
        let s =
            TemplateState::from_template_and_blob(&t, &p2pkh_blob(), ScriptSigInputs::default(), 0);
        assert_eq!(s.block_target[0], 0xff);
        for &b in &s.block_target[1..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn template_state_block_target_falls_back_to_nbits() {
        let s = TemplateState::from_template_and_blob(
            &template(),
            &p2pkh_blob(),
            ScriptSigInputs::default(),
            0,
        );
        assert_eq!(s.block_target, nbits_to_target_le("1d00ffff"));
    }

    #[tokio::test]
    async fn watch_channel_round_trips() {
        let (publisher, mut sub) = TemplateStatePublisher::new();
        let s = TemplateState::from_template_and_blob(
            &template(),
            &p2pkh_blob(),
            ScriptSigInputs::default(),
            7,
        );
        publisher.publish(s).unwrap();
        let received = sub.changed().await.unwrap();
        assert_eq!(received.job_id_seed, 7);
        assert_eq!(received.height, 800_000);
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
    fn swap_prev_hash_word_swap() {
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
}
