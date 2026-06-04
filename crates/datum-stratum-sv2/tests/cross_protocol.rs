//! End-to-end cross-protocol golden-vector test.
//!
//! Given the same `Template` + `CoinbaserBlob`:
//! - The SV1 path (datum-stratum-sv1::assembler::assemble_notify) builds
//!   `mining.notify` params; the coinbase tx outputs are encoded inside
//!   coinb2.
//! - The SV2 path (datum-stratum-sv2::ExtendedJob::from_blob) materializes
//!   the OCEAN-supplied coinbase outputs into `additional_coinbase_outputs`.
//!
//! The catastrophic-if-violated invariant: **both must reach the exact same
//! sum of satoshis paid to the same script_pubkeys**. Otherwise the operator
//! is paying themselves on one protocol path and OCEAN on the other.

use datum_blocktemplates::Template;
use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use datum_stratum_sv1::assembler::assemble_notify;
use datum_stratum_sv2::{coinbase_output_sum, ExtendedJob};

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

fn ocean_blob() -> CoinbaserBlob {
    // Realistic-ish OCEAN-style split: 99% to a P2PKH, 1% to a P2WPKH dev fee.
    CoinbaserBlob {
        datum_id: 7,
        outputs: vec![
            CoinbaseOutput {
                value_sats: 309_375_000,
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44,
                    0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x88, 0xac,
                ],
            },
            CoinbaseOutput {
                value_sats: 3_125_000,
                script_pubkey: vec![
                    0x00, 0x14, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22,
                    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                ],
            },
        ],
    }
}

#[test]
fn sv1_and_sv2_pay_identical_satoshis_to_identical_scripts() {
    let blob = ocean_blob();

    // SV2 path: outputs from the blob.
    let sv2_job = ExtendedJob::from_blob(1, 0x2000_0000, &blob);
    let sv2_sum: u64 = sv2_job
        .additional_coinbase_outputs
        .iter()
        .map(|o| o.value_sats)
        .sum();

    // SV1 path: assemble_notify embeds the same outputs into coinb2. We
    // re-decode them to validate equality.
    let notify = assemble_notify("job-1", &template(), &blob, b"datum-rs", true);
    let coinb2_bytes = hex::decode(&notify.coinb2).unwrap();

    // Parse the outputs blob from coinb2. Layout (after coinbase_tag bytes
    // consumed before extranonce + sequence):
    //   sequence(4) | output_count(varint) | [value(8) + scriptlen(varint) + script]…
    //   | locktime(4)
    //
    // For this fixture coinbase_tag is "datum-rs" (8 bytes); extranonce
    // placeholder is in coinb1. coinb2 begins with the rest of the
    // coinbase_tag bytes (in our assembler this is *all* the tag bytes
    // since we put the placeholder before the tag in coinb1) + sequence.
    // Easier: skip the coinbase_tag prefix + 4-byte sequence (always
    // 0xFFFFFFFF) and walk the outputs.
    let tag_len = b"datum-rs".len();
    let mut idx = tag_len + 4;
    assert_eq!(
        u32::from_le_bytes(coinb2_bytes[tag_len..idx].try_into().unwrap()),
        0xFFFFFFFF,
        "sequence is 0xFFFFFFFF"
    );
    let output_count = coinb2_bytes[idx];
    idx += 1;
    assert_eq!(output_count as usize, blob.outputs.len());

    let mut sv1_sum: u64 = 0;
    let mut decoded_outputs: Vec<(u64, Vec<u8>)> = Vec::new();
    for _ in 0..output_count {
        let value = u64::from_le_bytes(coinb2_bytes[idx..idx + 8].try_into().unwrap());
        idx += 8;
        let scriptlen = coinb2_bytes[idx] as usize;
        idx += 1;
        let script = coinb2_bytes[idx..idx + scriptlen].to_vec();
        idx += scriptlen;
        sv1_sum += value;
        decoded_outputs.push((value, script));
    }

    // Trailing bytes should be locktime(4) = 0
    assert_eq!(
        coinb2_bytes.len() - idx,
        4,
        "trailing bytes are just locktime"
    );
    assert_eq!(
        u32::from_le_bytes(coinb2_bytes[idx..idx + 4].try_into().unwrap()),
        0,
        "locktime is 0"
    );

    // The catastrophic invariant:
    assert_eq!(
        sv1_sum, sv2_sum,
        "SV1 (decoded from coinb2) and SV2 (additional_coinbase_outputs) must sum identically"
    );
    assert_eq!(coinbase_output_sum(&blob), sv1_sum);

    // And per-output equality:
    for ((sv1_val, sv1_script), sv2_out) in decoded_outputs
        .iter()
        .zip(sv2_job.additional_coinbase_outputs.iter())
    {
        assert_eq!(*sv1_val, sv2_out.value_sats, "per-output value equality");
        assert_eq!(
            sv1_script, &sv2_out.script_pubkey,
            "per-output script equality"
        );
    }
}
