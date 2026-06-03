//! Phase C: byte-fidelity test for `mining.notify` params vs the C reference.
//!
//! ## Status
//!
//! This test is **scaffolding-only** today. The assembler produces structurally
//! valid notify params (subscribe → notify → submit completes against a real
//! miner), but several pieces have **known structural differences** from
//! `OCEAN-xyz/datum_gateway`'s C output:
//!
//! - `merkle_branch` returns the txid list verbatim instead of computing the
//!   logarithmic-depth path of sibling hashes (assembler.rs::build_merkle_branch
//!   acknowledges this with a TODO).
//! - `coinbase_tag` placement and length-prefixing is approximated; the C
//!   gateway has additional bookkeeping for `coinbase_unique_id` injection.
//! - The witness commitment output assembly assumes `default_witness_commitment`
//!   is the OP_RETURN form; segwit-active templates may produce a different
//!   shape that we haven't pinned.
//!
//! ## How to capture the C reference fixture
//!
//! Future contributor: build the C `OCEAN-xyz/datum_gateway` in Docker
//! (`epoll-shim` + `debian:bookworm-slim` per the existing
//! `Dockerfile`), point it at a regtest bitcoind + the in-tree
//! `MockPool`, and capture one `mining.notify` line off the SV1 socket
//! with `nc -l`. Save the captured line as
//! `tests/fixtures/c-mining-notify.txt`. Then enable the byte-equality
//! assertion below by removing the `#[ignore]` attribute.
//!
//! Until that fixture exists, this test runs `assemble_notify` against the
//! template/coinbaser pair the fixture would have used, and prints a
//! human-readable diff helper. **Real-money mainnet operation is hard-gated
//! on this test passing without `#[ignore]`.**

use datum_blocktemplates::Template;
use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use datum_stratum_sv1::assembler::assemble_notify;
use serde_json::Value;

fn fixture_template() -> Template {
    Template {
        version: 0x2000_0000,
        previous_block_hash: "0000000000000000000a85b9b3eb04ed5e3c95a3a82bbe44839dd3b0f8d4f5c1"
            .into(),
        bits: "1d00ffff".into(),
        height: 800_000,
        coinbase_value: 312_500_000,
        curtime: 0x6712_3456,
        mintime: 0,
        sizelimit: 4_000_000,
        weightlimit: 4_000_000,
        sigop_limit: 80_000,
        default_witness_commitment: Some("6a24aa21a9ed".to_string() + &"00".repeat(32)),
        transactions: vec![],
        long_poll_id: None,
        target: None,
    }
}

fn fixture_coinbaser() -> CoinbaserBlob {
    CoinbaserBlob {
        datum_id: 1,
        outputs: vec![CoinbaseOutput {
            value_sats: 312_500_000,
            script_pubkey: vec![
                0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44,
            ],
        }],
    }
}

#[test]
fn assemble_notify_produces_well_formed_json_array() {
    let n = assemble_notify(
        "0000000000000001",
        &fixture_template(),
        &fixture_coinbaser(),
        b"datum-rs bench",
        true,
    );
    let json = n.to_json_array();
    let arr = json.as_array().expect("notify params is an array");
    assert_eq!(arr.len(), 9, "SV1 mining.notify has 9 fields");

    assert!(matches!(arr[0], Value::String(_)), "job_id");
    assert_eq!(arr[0].as_str().unwrap(), "0000000000000001");
    assert!(matches!(arr[1], Value::String(_)), "prev_hash");
    assert_eq!(arr[1].as_str().unwrap().len(), 64);
    assert!(matches!(arr[2], Value::String(_)), "coinb1");
    assert!(matches!(arr[3], Value::String(_)), "coinb2");
    assert!(matches!(arr[4], Value::Array(_)), "merkle_branch");
    assert!(matches!(arr[5], Value::String(_)), "version");
    assert_eq!(arr[5].as_str().unwrap().len(), 8);
    assert!(matches!(arr[6], Value::String(_)), "nbits");
    assert_eq!(arr[6].as_str().unwrap().len(), 8);
    assert!(matches!(arr[7], Value::String(_)), "ntime");
    assert_eq!(arr[7].as_str().unwrap().len(), 8);
    assert!(matches!(arr[8], Value::Bool(true)), "clean_jobs");
}

#[test]
fn coinbase_reconstruction_is_valid_bitcoin_tx() {
    let n = assemble_notify("j", &fixture_template(), &fixture_coinbaser(), b"", true);
    let mut full = hex::decode(&n.coinb1).unwrap();
    full.extend(vec![
        0u8;
        datum_stratum_sv1::assembler::EXTRANONCE_PLACEHOLDER_LEN
    ]);
    full.extend(hex::decode(&n.coinb2).unwrap());

    assert_eq!(&full[0..4], &[0x01, 0x00, 0x00, 0x00], "version");
    assert_eq!(full[4..6], [0x00, 0x01], "segwit marker+flag");
    assert_eq!(full[6], 0x01, "tx_in_count = 1");
    assert_eq!(&full[7..39], &[0u8; 32], "prev_hash zeroed for coinbase");
    assert_eq!(
        u32::from_le_bytes(full[39..43].try_into().unwrap()),
        0xFFFFFFFF,
        "prev_idx 0xFFFFFFFF"
    );
    assert_eq!(&full[full.len() - 4..], &[0u8; 4], "locktime is 0");
}

#[test]
#[ignore = "needs c-mining-notify.txt fixture; see file-level docs"]
fn mining_notify_matches_c_byte_for_byte() {
    let fixture = include_str!("fixtures/c-mining-notify.txt");
    let c_value: Value = serde_json::from_str(fixture).expect("fixture is valid JSON");
    let c_params = c_value
        .get("params")
        .expect("c fixture has params field")
        .clone();
    let n = assemble_notify(
        "0000000000000001",
        &fixture_template(),
        &fixture_coinbaser(),
        b"datum-rs bench",
        true,
    );
    let our_params = n.to_json_array();
    assert_eq!(
        our_params, c_params,
        "assembler output must match C output byte-for-byte"
    );
}
