//! Template + CoinbaserBlob → SV1 `mining.notify` params assembler.
//!
//! The SV1 `mining.notify` params array per Stratum V1 spec:
//!
//! ```text
//! [job_id, prevhash, coinb1, coinb2, merkle_branch[], version, nbits, ntime, clean_jobs]
//! ```
//!
//! ## Status & honest scope
//!
//! Phase B target: produce structurally valid params that drive a real miner
//! through subscribe → notify → submit. The miner concatenates
//! `coinb1 || extranonce1 || extranonce2 || coinb2` and double-SHA256s it
//! along with the merkle branch + header.
//!
//! Phase C target (separate task): byte-exact equality with what the C
//! gateway emits for matched (template, coinbaser) inputs. Until that
//! fixture is captured + asserted, this assembler should be treated as
//! "structurally valid, not yet bit-equivalent." Real-money mainnet use is
//! hard-gated on Phase C closing.
//!
//! ## Coinbase tx layout
//!
//! Standard Bitcoin coinbase tx (segwit-aware):
//!
//! ```text
//! version(4) | marker(1)?=00 | flag(1)?=01 | tx_in_count(1)=01
//!   | prev_hash(32)=0...0 | prev_idx(4)=0xFFFFFFFF
//!   | scriptSig_len(varint) | scriptSig=[height_BIP34][extranonce_placeholder][optional tag]
//!   | sequence(4)=0xFFFFFFFF
//! tx_out_count(varint)
//!   | [for each output: value(8) | scriptPubKey_len(varint) | scriptPubKey]
//! [witness if segwit: count_per_in(1)=01 | witness_stack_item_len(1)=20 | 32-byte witness reserved]
//! locktime(4)=0
//! ```
//!
//! The extranonce placeholder splits coinb1 and coinb2: bytes BEFORE the
//! placeholder go in coinb1, bytes AFTER go in coinb2. The miner fills the
//! placeholder with `extranonce1 || extranonce2`.

use datum_blocktemplates::Template;
use datum_coinbaser::CoinbaserBlob;
use serde_json::{json, Value};

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
/// configurable fields in `datum_conf.c`.
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
#[derive(Debug, Clone)]
pub struct JobMeta {
    /// 8-bit job index assigned by the runtime — populated into the `0x27`
    /// `datum_job_id` field. The runtime owns the allocator (8-bit ring per C).
    pub datum_job_idx: u8,
    /// 8-bit coinbase variant used for this notify (always 0 today; OCEAN's
    /// pool may select among up to 8 variants per the C reference).
    pub coinbase_id: u8,
    /// `target_pot_index`: byte offset in `coinb1` of the PoT placeholder. The
    /// runtime overwrites this byte with `floorPoT(diff)` immediately before
    /// hashing the candidate header, and the same byte is sent in the share
    /// submission so the server can verify the work-against-PoT-target.
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
    /// `nbits` as 4 little-endian bytes.
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
    /// Network block target in INTERNAL little-endian byte order
    /// (`target[0]` is the LSB). Decoded from GBT's `target` field
    /// (big-endian display hex, reversed) or derived from `nbits` if
    /// absent. Used by the share-relay's block-found check to compare
    /// the candidate header hash against the network target with the
    /// same byte-walk semantics as `datum_utils.c::compare_hashes`.
    pub block_target: [u8; 32],
    /// Hex-encoded `data` field of every transaction in the template,
    /// shared via Arc so all 256 JobEntries pointing at the same template
    /// share one allocation. Snapshotted at notify-build time so block_hex
    /// assembly doesn't need the original Template Arc at submit time.
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
    let coinbase_tx_outputs = build_outputs(template, coinbaser);
    let (coinb1_bin, coinb2_bin, target_pot_index) =
        build_split_coinbase_bin(template, &scriptsig, &coinbase_tx_outputs);
    let merkle_branch = build_merkle_branch(template);

    let prev_hash = swap_prev_hash_for_stratum(&template.previous_block_hash);
    let version_hex = format!("{:08x}", template.version);
    let ntime_hex = format!("{:08x}", template.curtime as u32);

    let merkle_branches_bin: Vec<[u8; 32]> = merkle_branch
        .iter()
        .filter_map(|hex_be| {
            let v = hex::decode(hex_be).ok()?;
            (v.len() == 32).then(|| <[u8; 32]>::try_from(v.as_slice()).ok())?
        })
        .collect();

    let nbits_bin: [u8; 4] = hex::decode(&template.bits)
        .ok()
        .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok())
        .unwrap_or([0u8; 4]);

    let prevhash_bin: [u8; 32] = hex::decode(&template.previous_block_hash)
        .ok()
        .and_then(|v| {
            // GBT returns big-endian display hex; internal-order is reversed.
            let mut a = <[u8; 32]>::try_from(v.as_slice()).ok()?;
            a.reverse();
            Some(a)
        })
        .unwrap_or([0u8; 32]);

    let txn_count = template.transactions.len() as u32;
    let txn_total_weight: u32 = template.transactions.iter().map(|t| t.weight).sum();
    let txn_total_size: u32 = template
        .transactions
        .iter()
        .map(|t| t.data.len() as u32 / 2)
        .sum();
    let txn_total_sigops: u32 = template.transactions.iter().map(|t| t.sigops).sum();

    // Block target: prefer GBT-supplied target (big-endian display hex);
    // reverse to internal-LE for byte-wise compare. Fall back to deriving
    // from `nbits` when absent — matches C reference which always recomputes
    // via nbits_to_target.
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

    let txn_data_hex = std::sync::Arc::new(
        template
            .transactions
            .iter()
            .map(|t| t.data.clone())
            .collect::<Vec<_>>(),
    );

    let notify = NotifyParams {
        job_id: job_id.to_string(),
        prev_hash,
        coinb1: hex::encode(&coinb1_bin),
        coinb2: hex::encode(&coinb2_bin),
        merkle_branch,
        version_hex,
        nbits_hex: template.bits.clone(),
        ntime_hex,
        clean_jobs,
    };
    let meta = JobMeta {
        datum_job_idx,
        coinbase_id,
        target_pot_index,
        version: template.version,
        height: template.height,
        coinbase_value: template.coinbase_value,
        prevhash_bin,
        nbits_bin,
        merkle_branches_bin,
        coinb1_bin,
        coinb2_bin,
        datum_coinbaser_id: coinbaser.datum_id,
        txn_count,
        txn_total_weight,
        txn_total_size,
        txn_total_sigops,
        block_target,
        txn_data_hex,
    };
    (notify, meta)
}

/// Decode `nbits` (big-endian display hex from GBT) into a 32-byte target in
/// internal little-endian byte order. Mirrors `datum_utils.c::nbits_to_target`:
/// the high byte is the exponent; the low three bytes are the 24-bit
/// mantissa. The mantissa is written into bytes `target[exp-3 .. exp]`
/// little-endian; the rest of the array stays zero. Returns all-zero on a
/// malformed `nbits_hex` (which means "no share can satisfy" — safe default).
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
fn swap_prev_hash_for_stratum(hash_hex: &str) -> String {
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
    //
    // Total scriptsig bytes (the varint length-prefix counts ALL of these):
    //   height_script.len() + tag_block_with_push.len() + uid_block.len()
    //   + 1 + 2 + 12.
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
/// The miner computes the merkle root by:
///   `root = combine(combine(combine(coinbase_hash, branch[0]), branch[1]), …)`
/// where `combine(a, b) = double_sha256(a || b)`. So `branch` is the
/// sibling-path of the coinbase position (always position 0).
///
/// Returns hex strings in BIG-ENDIAN byte order (txid display order, NOT
/// internal-byte order — matches what the C gateway emits in `mining.notify`).
fn build_merkle_branch(template: &Template) -> Vec<String> {
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
    // First branch element: txn[0] is the sibling of the (yet-unknown)
    // coinbase tx at the leaf level.
    branch.push(current_level[0]);

    // Mirror the C loop exactly. effective size = current_level.len() + 1
    // (phantom coinbase). When effective size > 1, halve (with odd-dup)
    // until size 1.
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
                // Pair (phantom_coinbase, current_level[0]).
                // Output unknown until miner provides coinbase.
                next_level.push([0u8; 32]);
            } else {
                // Pair (current_level[2i-1], current_level[2i]). Index
                // arithmetic shifted by 1 because phantom occupies index 0.
                let left = current_level[(i * 2) - 1];
                let right_idx = i * 2;
                // If right is in-range use it; otherwise duplicate left (the
                // C reference does this when level_size is odd and we're at
                // the last pair).
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
            hex::encode(be)
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
        // Per Stratum V1 spec, mining.notify coinbase is LEGACY-serialized,
        // so byte 4 is tx_in_count (0x01), NOT segwit marker (0x00).
        assert_eq!(full[4], 0x01, "tx_in_count");
        assert_eq!(&full[5..37], &[0u8; 32], "prev_hash zeroed");
    }

    #[test]
    fn scriptsig_matches_c_layout_for_known_inputs() {
        // From the captured C fixture (regtest height 102, primary="datum-rs cap",
        // secondary="T", coinbase_unique_id=4242, enprefix=0x0db1, pot_placeholder
        // overwritten to 0x03 by C runtime): scriptsig (37 bytes) =
        //   01 66                                      height push
        //   0f 64 61 74 75 6d 2d 72 73 20 63 61 70 0f 54 00   tag block (15 + 1)
        //   03 03 92 10                                uid push (PoT=0x03, uid=4242 LE)
        //   0e b1 0d                                   enprefix push prefix + 2-byte enprefix
        //   <12-byte placeholder>
        //
        // We assemble with pot_placeholder=0x03 to match the *post-PoT-overwrite*
        // bytes in the fixture (the C source writes 0xFF and patches it later).
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
        // After version(4) + tx_in_count(1) + prev_hash(32) + prev_idx(4) = 41
        // bytes, the scriptsig length varint and bytes follow.
        let scriptsig_len = coinb1[41] as usize;
        assert_eq!(scriptsig_len, 37, "C-equivalent scriptsig is 37 bytes");
        let ss = &coinb1[42..];
        // height push
        assert_eq!(&ss[0..2], &[0x01, 0x66]);
        // tag push: 0x0f + "datum-rs cap" + 0x0f + "T" + 0x00
        let expected_tag = b"\x0fdatum-rs cap\x0fT\x00";
        assert_eq!(&ss[2..2 + expected_tag.len()], expected_tag);
        // uid push: 03 03 92 10
        let after_tag = 2 + expected_tag.len();
        assert_eq!(&ss[after_tag..after_tag + 4], &[0x03, 0x03, 0x92, 0x10]);
        // enprefix push prefix + 2-byte enprefix: 0e b1 0d
        let after_uid = after_tag + 4;
        assert_eq!(&ss[after_uid..after_uid + 3], &[0x0e, 0xb1, 0x0d]);
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
    fn varint_thresholds() {
        let mut b = Vec::new();
        push_varint(&mut b, 0xFC);
        assert_eq!(b, vec![0xFC]);
        b.clear();
        push_varint(&mut b, 0xFD);
        assert_eq!(b, vec![0xFD, 0xFD, 0x00]);
        b.clear();
        push_varint(&mut b, 0x1_0000);
        assert_eq!(b, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
        b.clear();
        push_varint(&mut b, 0x1_0000_0000);
        assert_eq!(b[0], 0xFF);
    }

    #[test]
    fn bip34_height_minimal_encoding() {
        let h1 = bip34_height_script(0x00);
        assert_eq!(h1, vec![0x01, 0x00]);
        let h_low = bip34_height_script(0x7F);
        assert_eq!(h_low, vec![0x01, 0x7F]);
        let h_pad = bip34_height_script(0x80);
        assert_eq!(h_pad, vec![0x02, 0x80, 0x00]);
        let h_3byte = bip34_height_script(800_000);
        assert_eq!(h_3byte[0], 0x03);
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
        // Single tx: the only pair is (coinbase, tx[0]); branch = [tx[0]].
        assert_eq!(n.merkle_branch.len(), 1);
        assert_eq!(n.merkle_branch[0], "11".repeat(32));
    }

    #[test]
    fn merkle_branch_grows_logarithmically() {
        use datum_blocktemplates::TemplateTransaction;
        let mut t = template();
        // 4 transactions + 1 phantom coinbase = 5 leaves; branch length =
        // ceil(log2(5)) = 3 levels.
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
        // First branch element is always tx[0] in display order:
        assert_eq!(n.merkle_branch[0], "00".repeat(32));
    }

    #[test]
    fn merkle_branch_three_txs_branch_len_2() {
        use datum_blocktemplates::TemplateTransaction;
        let mut t = template();
        // 3 transactions + 1 phantom = 4 leaves; branch length = 2.
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
    fn double_sha256_known_vector() {
        // Bitcoin block 0 merkle root double-SHA256 well-known input.
        // Empty input double-SHA256 = sha256("") double-hashed.
        let h = double_sha256(b"");
        assert_eq!(
            hex::encode(h),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn nbits_to_target_le_difficulty_one() {
        // nbits "1d00ffff" — the canonical difficulty-1 target.
        // Internal-LE result: 0xffff at exp-3..exp = 26..29; rest zero.
        let t = nbits_to_target_le("1d00ffff");
        // Bytes 26 = 0xff, 27 = 0xff, 28 = 0x00. (mantissa 0x00ffff little-endian.)
        assert_eq!(t[26], 0xff);
        assert_eq!(t[27], 0xff);
        assert_eq!(t[28], 0x00);
        // Top byte (MSB) is zero — difficulty-1 doesn't reach.
        assert_eq!(t[31], 0x00);
    }

    #[test]
    fn nbits_to_target_le_regtest() {
        // nbits "207fffff" — regtest max target. exp = 0x20 = 32, mantissa
        // 0x7fffff. Bytes 29,30,31 = 0xff,0xff,0x7f.
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
        // Set a specific BE-display target hex; expect LE-internal in JobMeta.
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
        // BE display puts 0xff at the END; LE internal puts it at index 0.
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
}
