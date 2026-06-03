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

pub const EXTRANONCE_PLACEHOLDER_LEN: usize = 8;

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

/// Assemble `mining.notify` params from a template + coinbaser blob.
///
/// `job_id` is whatever the runtime wants to use for tracking (typically a
/// monotonic counter, hex-encoded). `coinbase_tag` is appended to scriptSig
/// after the BIP34 height + extranonce placeholder; pass empty for none.
pub fn assemble_notify(
    job_id: &str,
    template: &Template,
    coinbaser: &CoinbaserBlob,
    coinbase_tag: &[u8],
    clean_jobs: bool,
) -> NotifyParams {
    let coinbase_tx_outputs = build_outputs(template, coinbaser);
    let (coinb1, coinb2) = build_split_coinbase(template, coinbase_tag, &coinbase_tx_outputs);
    let merkle_branch = build_merkle_branch(template);

    let prev_hash = swap_prev_hash_for_stratum(&template.previous_block_hash);
    let version_hex = format!("{:08x}", template.version);
    let ntime_hex = format!("{:08x}", template.curtime as u32);

    NotifyParams {
        job_id: job_id.to_string(),
        prev_hash,
        coinb1,
        coinb2,
        merkle_branch,
        version_hex,
        nbits_hex: template.bits.clone(),
        ntime_hex,
        clean_jobs,
    }
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

fn build_split_coinbase(
    template: &Template,
    coinbase_tag: &[u8],
    outputs_blob: &[u8],
) -> (String, String) {
    let mut coinb1 = Vec::new();
    let mut coinb2 = Vec::new();

    coinb1.extend_from_slice(&1u32.to_le_bytes());

    coinb1.push(0x00);
    coinb1.push(0x01);

    coinb1.push(0x01);
    coinb1.extend_from_slice(&[0u8; 32]);
    coinb1.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let height_script = bip34_height_script(template.height);
    let scriptsig_len = height_script.len() + EXTRANONCE_PLACEHOLDER_LEN + coinbase_tag.len();
    push_varint(&mut coinb1, scriptsig_len as u64);
    coinb1.extend_from_slice(&height_script);

    coinb2.extend_from_slice(coinbase_tag);
    coinb2.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    coinb2.extend_from_slice(outputs_blob);

    coinb2.push(0x01);
    coinb2.push(0x20);
    coinb2.extend_from_slice(&[0u8; 32]);

    coinb2.extend_from_slice(&0u32.to_le_bytes());

    (hex::encode(coinb1), hex::encode(coinb2))
}

/// BIP34 coinbase scriptSig height encoding: a minimal-length CScriptNum push.
fn bip34_height_script(height: u32) -> Vec<u8> {
    let mut bytes = height.to_le_bytes().to_vec();
    while bytes.len() > 1 && *bytes.last().unwrap() == 0 {
        bytes.pop();
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

/// Merkle branch from the template's transactions list. SV1 expects each
/// branch element as 64-hex (little-endian double-SHA256 hashes).
///
/// **Phase B status**: returns the txid list verbatim (one branch per tx).
/// This is structurally valid for a coinbase-at-position-0 merkle proof in
/// an absolute sense but **NOT correct for shares**: the proper SV1 merkle
/// branch is a logarithmic-depth path of sibling hashes, not the full list.
/// Phase C closes this with byte-fixture validation.
fn build_merkle_branch(template: &Template) -> Vec<String> {
    template
        .transactions
        .iter()
        .map(|t| t.txid.clone())
        .collect()
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
    fn coinb1_then_coinb2_decodes_as_full_coinbase() {
        let n = assemble_notify("j", &template(), &p2pkh_blob(), b"", false);
        let mut full = hex::decode(&n.coinb1).unwrap();
        full.extend(vec![0u8; EXTRANONCE_PLACEHOLDER_LEN]);
        full.extend(hex::decode(&n.coinb2).unwrap());
        assert!(full.len() > 60);
        assert_eq!(&full[0..4], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(full[4..6], [0x00, 0x01]);
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
}
