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
fn coinbase_reconstruction_is_valid_legacy_bitcoin_tx() {
    let n = assemble_notify("j", &fixture_template(), &fixture_coinbaser(), b"", true);
    let mut full = hex::decode(&n.coinb1).unwrap();
    full.extend(vec![
        0u8;
        datum_stratum_sv1::assembler::EXTRANONCE_PLACEHOLDER_LEN
    ]);
    full.extend(hex::decode(&n.coinb2).unwrap());

    assert_eq!(&full[0..4], &[0x01, 0x00, 0x00, 0x00], "version");
    // SV1 mining.notify uses legacy serialization: tx_in_count immediately
    // follows version, no segwit marker/flag.
    assert_eq!(full[4], 0x01, "tx_in_count");
    assert_eq!(&full[5..37], &[0u8; 32], "prev_hash zeroed for coinbase");
    assert_eq!(
        u32::from_le_bytes(full[37..41].try_into().unwrap()),
        0xFFFFFFFF,
        "prev_idx 0xFFFFFFFF"
    );
    assert_eq!(&full[full.len() - 4..], &[0u8; 4], "locktime is 0");
}

/// Captured from a real `OCEAN-xyz/datum_gateway` (Docker C build) running
/// against a regtest bitcoind on 2026-06-03. The C gateway was configured
/// with:
///   - `mining.pool_address` = `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` (P2PKH)
///   - `coinbase_tag_primary` = `"datum-rs cap"`
///   - `coinbase_tag_secondary` = `"T"`
///   - `datum.pool_host` = `""`  (NON-POOLED MINING mode — uses
///     mining.pool_address verbatim as the only output)
///   - regtest height 102
///
/// Use this test to assert the **field shapes** our assembler matches today.
/// Full byte-for-byte parity over coinb1/coinb2/merkle_branch is not yet
/// achieved; the deltas are documented inline as TODOs and tracked in
/// issue #2 under "datum-stratum-sv1 golden vectors".
#[test]
fn mining_notify_field_shapes_match_c_capture() {
    let fixture = include_str!("fixtures/c-mining-notify.txt").trim();
    let c_value: Value = serde_json::from_str(fixture).expect("fixture is valid JSON");
    let c_params = c_value
        .get("params")
        .expect("c fixture has params field")
        .as_array()
        .expect("params is an array")
        .clone();
    assert_eq!(c_params.len(), 9, "C mining.notify params has 9 fields");

    // Field shapes we should always match:
    let c_job_id = c_params[0].as_str().unwrap();
    assert_eq!(c_job_id.len(), 16, "C job_id is 16 hex chars (8 bytes)");
    let c_prev_hash = c_params[1].as_str().unwrap();
    assert_eq!(
        c_prev_hash.len(),
        64,
        "C prev_hash is 64 hex chars (32 bytes)"
    );
    let c_coinb1 = c_params[2].as_str().unwrap();
    let c_coinb2 = c_params[3].as_str().unwrap();
    let c_merkle = c_params[4].as_array().unwrap();
    let c_version = c_params[5].as_str().unwrap();
    let c_nbits = c_params[6].as_str().unwrap();
    let c_ntime = c_params[7].as_str().unwrap();
    let c_clean = c_params[8].as_bool().unwrap();
    assert_eq!(c_version.len(), 8);
    assert_eq!(c_nbits.len(), 8);
    assert_eq!(c_ntime.len(), 8);
    assert!(c_clean, "C emits clean_jobs=true on the first notify");

    // Coinbase legacy-serialization invariants we assert hold for the C
    // fixture — and that our assembler also produces the same shape.
    let c_coinb1_bytes = hex::decode(c_coinb1).unwrap();
    assert_eq!(
        &c_coinb1_bytes[0..4],
        &[0x01, 0x00, 0x00, 0x00],
        "C coinb1 starts with version=1 (LE)"
    );
    assert_eq!(
        c_coinb1_bytes[4], 0x01,
        "C coinb1: tx_in_count immediately after version (LEGACY serialization)"
    );
    assert_eq!(
        &c_coinb1_bytes[5..37],
        &[0u8; 32],
        "C coinb1: prev_hash zeroed"
    );
    assert_eq!(
        u32::from_le_bytes(c_coinb1_bytes[37..41].try_into().unwrap()),
        0xFFFFFFFF,
        "C coinb1: prev_idx 0xFFFFFFFF"
    );

    let c_coinb2_bytes = hex::decode(c_coinb2).unwrap();
    assert_eq!(
        &c_coinb2_bytes[c_coinb2_bytes.len() - 4..],
        &[0u8; 4],
        "C coinb2: locktime 0"
    );

    // merkle_branch is empty when the template has no transactions:
    assert_eq!(
        c_merkle.len(),
        0,
        "C captured fixture has empty merkle_branch (regtest tip with no txs)"
    );

    // Now run our assembler against a template with the SAME number of
    // transactions and assert *our* output produces the same field shapes.
    let our = assemble_notify(
        "0000000000000001",
        &fixture_template(),
        &fixture_coinbaser(),
        b"datum-rs bench",
        true,
    );
    let our_params = our.to_json_array();
    let our_arr = our_params.as_array().unwrap();
    assert_eq!(our_arr.len(), 9);
    let our_coinb1_bytes = hex::decode(our_arr[2].as_str().unwrap()).unwrap();
    assert_eq!(&our_coinb1_bytes[0..4], &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(
        our_coinb1_bytes[4], 0x01,
        "OUR coinb1 also legacy-serialized"
    );
    let our_coinb2_bytes = hex::decode(our_arr[3].as_str().unwrap()).unwrap();
    assert_eq!(&our_coinb2_bytes[our_coinb2_bytes.len() - 4..], &[0u8; 4]);
}

/// Pin the precise scriptsig structure the C reference emits at this height +
/// tag combo. **Does not run today** — depends on assembler producing
/// identical scriptsig bytes, which requires porting the C
/// coinbase_unique_id injection + tag-len-prefixing logic. Tracking the
/// remaining deltas:
///
/// 1. **Composite tag with secondary length-prefix**: C scriptsig embeds the
///    primary tag, then a 1-byte length, then the secondary tag (e.g.
///    `0f 646174756d2d7273206361700f54` decodes to length-15 push of
///    `"datum-rs cap" + 0x0f + "T"`). Our assembler treats coinbase_tag as
///    a single opaque byte slice — wrong shape.
/// 2. **coinbase_unique_id injection**: a 3-byte LE-encoded ID derived from
///    `coinbase_unique_id` config field gets injected after the extranonce
///    placeholder. Not modeled in our assembler at all today.
/// 3. **Trailing scriptsig bytes**: C captures show `b10d` as the very last
///    bytes of scriptsig — origin not yet identified.
///
/// Removing the `#[ignore]` on this test is the **v0.1.0 mainnet-readiness
/// gate**: until our scriptsig matches C byte-for-byte, mining shares
/// against mainnet OCEAN risks coinbase-output divergence (operator pays
/// self instead of OCEAN). Signet bench operation per BENCH_VALIDATION.md
/// is safe today; mainnet is not.
#[test]
#[ignore = "scriptsig structure deltas (composite tag, unique_id injection); see file-level docs"]
fn coinb1_byte_exact_against_c_capture() {
    let fixture = include_str!("fixtures/c-mining-notify.txt").trim();
    let c_value: Value = serde_json::from_str(fixture).unwrap();
    let c_coinb1 = c_value["params"][2].as_str().unwrap();

    let our = assemble_notify(
        "0000000000000001",
        &fixture_template(),
        &fixture_coinbaser(),
        b"datum-rs cap",
        true,
    );
    assert_eq!(our.coinb1, c_coinb1);
}
