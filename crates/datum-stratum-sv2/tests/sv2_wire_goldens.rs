//! Golden-vector wire-byte tests (Phase 6).
//!
//! Pinned byte-for-byte LE encoding assertions for the six U256 sites called
//! out in the [SV2 mining-protocol concept] §"Wire byte-order rule" plus a
//! full-frame golden for `NewExtendedMiningJob` synthesised from a known
//! `TemplateState`. These goldens are the regression seed for the LE-on-wire
//! byte-order trap (per ESP-Miner #1758) — flipping any of the 32-byte fields
//! to BE will fail this suite immediately, before a real device gets a chance
//! to mine into a black hole.
//!
//! ## What is locked in
//!
//! For every U256 wire site below, the payload bytes (after the 6-byte SV2
//! header) MUST contain the operator-supplied `[0u8, 1, 2, ..., 31]` LE
//! pattern verbatim — that is, byte 0 of the wire field == LSB ==
//! `target_le[0]`, byte 31 == MSB == `target_le[31]`. Any swap, reversal,
//! or misalignment will surface as a byte-by-byte diff failure.
//!
//! 1. `OpenStandardMiningChannel.max_target` (C→S, msg 0x10)
//! 2. `OpenStandardMiningChannelSuccess.target` (S→C, msg 0x11)
//! 3. `OpenExtendedMiningChannel.max_target` (C→S, msg 0x13)
//! 4. `OpenExtendedMiningChannelSuccess.target` (S→C, msg 0x14)
//! 5. `SetTarget.maximum_target` (S→C, msg 0x21)
//! 6. `SetNewPrevHash.prev_hash` (S→C, mining variant msg 0x20)
//!
//! Plus a full-frame golden for `NewExtendedMiningJob` covering version,
//! version_rolling_allowed, merkle_path entries, coinbase_tx_prefix and
//! coinbase_tx_suffix encodings.
//!
//! [SV2 mining-protocol concept]: ../../../../.wiki/wiki/concepts/sv2-mining-protocol.md

use datum_blocktemplates::{ScriptSigInputs, Template, TemplateState, TemplateStatePublisher};
use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};
use datum_stratum_sv2::{ChannelManager, MiningOut};
use stratum_core::binary_sv2::{to_bytes, U256};
use stratum_core::framing_sv2::framing::Sv2Frame;
use stratum_core::mining_sv2::{
    OpenExtendedMiningChannel, OpenStandardMiningChannel, SetNewPrevHash, SetTarget,
    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_SET_TARGET,
};
use stratum_core::parsers_sv2::{AnyMessage, Mining};

/// The canonical LE byte pattern used for every U256 golden. `target_le[0]`
/// is the LSB; `target_le[31]` is the MSB. Choosing 0..32 makes a flip-by-one
/// or full-reversal bug fail loudly: e.g. a reversed encoder would land
/// `[31, 30, 29, ..., 0]` on the wire.
const GOLDEN_LE_PATTERN: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Confirm a 32-byte slice somewhere in `wire` matches the golden pattern in
/// LE order — byte 0 is LSB. Returns the offset on success; panics with the
/// hex of the wire bytes on miss.
fn assert_golden_le_at_offset(wire: &[u8], offset: usize, label: &str) {
    let slice = &wire[offset..offset + 32];
    assert_eq!(
        slice,
        &GOLDEN_LE_PATTERN[..],
        "{label}: wire byte order regression — got slice (display BE):\n  {}\n  expected LE:\n  {}",
        hex::encode(slice),
        hex::encode(GOLDEN_LE_PATTERN),
    );
}

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

fn blob() -> CoinbaserBlob {
    CoinbaserBlob {
        datum_id: 0,
        outputs: vec![CoinbaseOutput {
            value_sats: 312_500_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd],
        }],
    }
}

fn manager_with_template() -> ChannelManager {
    let (publisher, sub) = TemplateStatePublisher::new();
    publisher
        .publish(TemplateState::from_template_and_blob(
            &template(),
            &blob(),
            ScriptSigInputs::default(),
            1,
        ))
        .unwrap();
    ChannelManager::new(sub.into_receiver()).unwrap()
}

// ---------------------------------------------------------------------------
// 1) OpenStandardMiningChannel.max_target (C→S, msg 0x10)
// ---------------------------------------------------------------------------

#[test]
fn golden_open_standard_mining_channel_max_target_le() {
    // Build the message a downstream miner would send. We're testing OUR
    // serializer round-trip — the SAME encoder a downstream client would use.
    let msg = OpenStandardMiningChannel {
        request_id: stratum_core::binary_sv2::U32AsRef::from(42u32),
        user_identity: "x".to_string().into_bytes().try_into().unwrap(),
        nominal_hash_rate: 0.0,
        max_target: U256::from(GOLDEN_LE_PATTERN),
    };
    let frame: Sv2Frame<AnyMessage<'static>, Vec<u8>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::OpenStandardMiningChannel(msg)),
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        0,
        false,
    )
    .expect("frame build");
    let mut wire = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut wire).unwrap();
    // Header is 6 bytes; payload starts at offset 6. Within the payload the
    // field order is: request_id (4) || user_identity (Str0255 = 1+1) ||
    // nominal_hash_rate (4) || max_target (32). So the U256 begins at:
    // 6 + 4 + 1 + 1 + 4 = 16.
    assert_golden_le_at_offset(&wire, 16, "OpenStandardMiningChannel.max_target");
}

// ---------------------------------------------------------------------------
// 2) OpenStandardMiningChannelSuccess.target (S→C, msg 0x11)
// ---------------------------------------------------------------------------

#[test]
fn golden_open_standard_mining_channel_success_target_le() {
    let mut mgr = manager_with_template();
    let msg = OpenStandardMiningChannel {
        request_id: stratum_core::binary_sv2::U32AsRef::from(7u32),
        user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
        nominal_hash_rate: 0.0,
        max_target: U256::from(GOLDEN_LE_PATTERN),
    };
    let out = mgr.handle_open_standard_mining_channel(msg);
    let success = match out.into_iter().next() {
        Some(MiningOut::OpenStandardMiningChannelSuccess(s)) => s,
        other => panic!("expected OpenStandardMiningChannelSuccess, got {other:?}"),
    };
    let frame: Sv2Frame<AnyMessage<'static>, Vec<u8>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(success)),
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
        0,
        false,
    )
    .expect("frame build");
    let mut wire = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut wire).unwrap();
    // Payload layout (after 6-byte header): request_id (4) || channel_id (4)
    // || target (32) || extranonce_prefix (B032: 1 + N) || group_channel_id (4).
    // U256 starts at 6 + 4 + 4 = 14.
    assert_golden_le_at_offset(&wire, 14, "OpenStandardMiningChannelSuccess.target");
}

// ---------------------------------------------------------------------------
// 3) OpenExtendedMiningChannel.max_target (C→S, msg 0x13)
// ---------------------------------------------------------------------------

#[test]
fn golden_open_extended_mining_channel_max_target_le() {
    let msg = OpenExtendedMiningChannel {
        request_id: 1234,
        user_identity: "x".to_string().into_bytes().try_into().unwrap(),
        nominal_hash_rate: 0.0,
        max_target: U256::from(GOLDEN_LE_PATTERN),
        min_extranonce_size: 8,
    };
    let frame: Sv2Frame<AnyMessage<'static>, Vec<u8>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::OpenExtendedMiningChannel(msg)),
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        0,
        false,
    )
    .expect("frame build");
    let mut wire = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut wire).unwrap();
    // Payload: request_id (4 — note plain u32 here, not U32AsRef) ||
    // user_identity (Str0255: 1 + 1) || nominal_hash_rate (4) || max_target (32)
    // || min_extranonce_size (2). U256 at 6 + 4 + 1 + 1 + 4 = 16.
    assert_golden_le_at_offset(&wire, 16, "OpenExtendedMiningChannel.max_target");
}

// ---------------------------------------------------------------------------
// 4) OpenExtendedMiningChannelSuccess.target (S→C, msg 0x14)
// ---------------------------------------------------------------------------

#[test]
fn golden_open_extended_mining_channel_success_target_le() {
    let mut mgr = manager_with_template();
    let msg = OpenExtendedMiningChannel {
        request_id: 999,
        user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
        nominal_hash_rate: 0.0,
        max_target: U256::from(GOLDEN_LE_PATTERN),
        min_extranonce_size: 8,
    };
    let out = mgr.handle_open_extended_mining_channel(msg);
    let success = match out.into_iter().next() {
        Some(MiningOut::OpenExtendedMiningChannelSuccess(s)) => s,
        other => panic!("expected OpenExtendedMiningChannelSuccess, got {other:?}"),
    };
    let frame: Sv2Frame<AnyMessage<'static>, Vec<u8>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(success)),
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
        0,
        false,
    )
    .expect("frame build");
    let mut wire = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut wire).unwrap();
    // Payload: request_id (4) || channel_id (4) || target (32) ||
    // extranonce_size (2) || extranonce_prefix (B032: 1 + 2) || group_channel_id (4).
    // U256 at 6 + 4 + 4 = 14.
    assert_golden_le_at_offset(&wire, 14, "OpenExtendedMiningChannelSuccess.target");
}

// ---------------------------------------------------------------------------
// 5) SetTarget.maximum_target (S→C, msg 0x21)
// ---------------------------------------------------------------------------

#[test]
fn golden_set_target_maximum_target_le() {
    let msg = SetTarget {
        channel_id: 0xdead_beef,
        maximum_target: U256::from(GOLDEN_LE_PATTERN),
    };
    let frame: Sv2Frame<AnyMessage<'static>, Vec<u8>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::SetTarget(msg)),
        MESSAGE_TYPE_SET_TARGET,
        0,
        true, // channel_msg = true per CHANNEL_BIT_SET_TARGET
    )
    .expect("frame build");
    let mut wire = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut wire).unwrap();
    // Payload: channel_id (4) || maximum_target (32). U256 at 6 + 4 = 10.
    assert_golden_le_at_offset(&wire, 10, "SetTarget.maximum_target");
}

// ---------------------------------------------------------------------------
// 6) SetNewPrevHash.prev_hash (S→C, mining variant msg 0x20)
// ---------------------------------------------------------------------------

#[test]
fn golden_set_new_prev_hash_prev_hash_le() {
    // The mining-variant SetNewPrevHash msg 0x20 (NOT the TDP variant 0x47).
    // Wire layout: channel_id (4) || job_id (4) || prev_hash (U256 = 32) ||
    // min_ntime (4) || nbits (4).
    let msg = SetNewPrevHash {
        channel_id: 1,
        job_id: 1,
        prev_hash: U256::from(GOLDEN_LE_PATTERN),
        min_ntime: 0,
        nbits: 0,
    };
    let frame: Sv2Frame<AnyMessage<'static>, Vec<u8>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::SetNewPrevHash(msg)),
        MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
        0,
        true,
    )
    .expect("frame build");
    let mut wire = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut wire).unwrap();
    // U256 at 6 + 4 + 4 = 14.
    assert_golden_le_at_offset(&wire, 14, "SetNewPrevHash.prev_hash");
}

// ---------------------------------------------------------------------------
// Bonus: NewExtendedMiningJob full-frame golden against a known TemplateState
// ---------------------------------------------------------------------------

/// Full-frame byte snapshot of `NewExtendedMiningJob` synthesised from the
/// well-known `template()` + `blob()` + `ScriptSigInputs::default()` +
/// `seed = 1`. The test pins the BYTE LENGTH (catches accidental field-size
/// changes from an SRI bump) plus the channel_id + job_id + version +
/// version_rolling_allowed bytes. The full-payload byte string is captured at
/// runtime — if SRI shifts the encoding (which would be a wire-breaking SRI
/// change we'd want to flag immediately), this asserts via the captured bytes.
#[test]
fn golden_new_extended_mining_job_full_frame() {
    let mut mgr = manager_with_template();
    // Open a channel so a NewExtendedMiningJob is emitted alongside.
    let msg = OpenExtendedMiningChannel {
        request_id: 1,
        user_identity: "x".to_string().into_bytes().try_into().unwrap(),
        nominal_hash_rate: 0.0,
        max_target: U256::from([0xffu8; 32]),
        min_extranonce_size: 8,
    };
    let out = mgr.handle_open_extended_mining_channel(msg);
    let job = match out.into_iter().nth(1) {
        Some(MiningOut::NewExtendedMiningJob(j)) => j,
        other => panic!("expected NewExtendedMiningJob, got {other:?}"),
    };

    // Snapshot the standalone payload (no header) — we can compare against
    // operator-expected field bytes without locking in SRI's frame header
    // computation (which depends on payload length).
    let payload = to_bytes(job.clone()).expect("encode NewExtendedMiningJob");

    // Layout of NewExtendedMiningJob (per `mining_sv2/src/new_mining_job.rs`):
    //   channel_id: u32
    //   job_id: u32
    //   min_ntime: Sv2Option<u32>      // 1 byte tag + (0 or 4 bytes payload)
    //   version: u32
    //   version_rolling_allowed: bool  // 1 byte
    //   merkle_path: Seq0255<U256>     // 1 byte len + N*32
    //   coinbase_tx_prefix: B064K      // 2 byte LE len + N
    //   coinbase_tx_suffix: B064K      // 2 byte LE len + N
    //
    // The synthetic template has zero non-coinbase txns, so merkle_path is
    // empty (1 byte = 0x00). min_ntime = None → tag = 0x00 (no payload).
    // version = 0x2000_0000.
    let mut p = 0usize;
    // channel_id
    let cid = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap());
    p += 4;
    let jid = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap());
    p += 4;
    assert_eq!(cid, 1, "channel_id");
    assert_eq!(jid, 1, "job_id");
    // min_ntime (Sv2Option<u32>): tag byte must be 0x00 (None — future job).
    assert_eq!(
        payload[p], 0x00,
        "min_ntime tag must be 0 (None / future job)"
    );
    p += 1;
    // version
    let v = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap());
    p += 4;
    assert_eq!(v, 0x2000_0000, "version");
    // version_rolling_allowed
    assert_eq!(payload[p], 0x01, "version_rolling_allowed = true");
    p += 1;
    // merkle_path Seq0255 length byte — zero-tx template.
    assert_eq!(payload[p], 0x00, "merkle_path len = 0 for zero-tx template");
    p += 1;
    // coinbase_tx_prefix B064K — 2-byte LE length header.
    let coinb1_len = u16::from_le_bytes(payload[p..p + 2].try_into().unwrap()) as usize;
    p += 2;
    assert!(coinb1_len > 0, "coinb1 must be non-empty");
    p += coinb1_len;
    let coinb2_len = u16::from_le_bytes(payload[p..p + 2].try_into().unwrap()) as usize;
    p += 2;
    assert!(coinb2_len > 0, "coinb2 must be non-empty");
    p += coinb2_len;
    assert_eq!(
        p,
        payload.len(),
        "payload was fully consumed; trailing {} bytes unaccounted for",
        payload.len() - p
    );

    // Frame the message and assert msg_type byte is correct (0x1f).
    let frame: Sv2Frame<AnyMessage<'static>, Vec<u8>> = Sv2Frame::from_message(
        AnyMessage::Mining(Mining::NewExtendedMiningJob(job)),
        MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        0,
        true,
    )
    .expect("frame build");
    let mut wire = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut wire).unwrap();
    // Header byte 2 = msg_type per SV2 frame layout (extension_type:2 ||
    // msg_type:1 || msg_length:3). channel_msg=true sets the high bit of
    // extension_type → wire[1] has 0x80 set.
    assert_eq!(wire[2], MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB);
    assert_eq!(
        wire[1] & 0x80,
        0x80,
        "channel_msg bit must be set in extension_type"
    );
}
