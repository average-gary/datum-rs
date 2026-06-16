---
title: "ESP-Miner #1758: SV2 No SubmitSharesExtended frames sent — byte-order trap"
source: "https://github.com/bitaxeorg/ESP-Miner/issues/1758"
type: notes
ingested: 2026-06-16
tags: [sv2, byte-order, interop, integration-test, bitaxe, downstream-client]
summary: "Real frame trace from Bitaxe v2.14.0 against a third-party SV2 pool. Documents the dominant interop bug — U256 fields must be little-endian on the wire — plus the full handshake/job message sequence."
---

# ESP-Miner #1758 — SV2 byte-order debugging

This single thread is effectively a **free integration-test plan** for datum-rs SV2.

## Extended channel sequence (observed wire)

```
C → S  SetupConnection (0x00)
S → C  SetupConnectionSuccess (0x01)
C → S  OpenExtendedMiningChannel (0x13)
S → C  OpenExtendedMiningChannelSuccess (0x14)
S → C  NewExtendedMiningJob (0x1f)
S → C  SetNewPrevHash (0x20)
                          ← server expects SubmitSharesExtended (0x1b) from miner
```

## Standard channel sequence (observed wire)

```
C → S  OpenStandardMiningChannel (0x10)
S → C  OpenStandardMiningChannelSuccess (0x11)
S → C  NewMiningJob (0x15)
S → C  SetNewPrevHash (0x20)
```

## The byte-order trap (warioishere identifies; pool maintainer confirms)

Per spec §5.3.1 all `U256` fields **on the wire are little-endian**. The bug class: implementations send big-endian targets / max_targets / prev hashes. Result: channel opens, miner mines silently, **zero submits**.

Sites that must be LE on wire:

- `OpenStandardMiningChannel.max_target` (C→S)
- `OpenStandardMiningChannelSuccess.target` (S→C)
- `OpenExtendedMiningChannel.max_target` (C→S)
- `OpenExtendedMiningChannelSuccess.target` (S→C)
- `SetTarget.maximum_target` (S→C)
- `SetNewPrevHashTdp.target` (TDP)

## VarDiff observation

Bitaxe SV2 client only submits when `nonce_diff >= pool_diff` derived from the (LE) target. **If the pool never sends `SetTarget`**, the initial target persists for the channel's whole lifetime — same dvb-WarpPool maintainer notes adaptive vardiff via SetTarget is needed for small devices.

## Post-fix accept rates (after byte-order corrected)

- NerdOctaxe ~88%
- Bitaxe-602-Gamma ~35%
- NerdAxeGamma ~16%

(Variance is initial-target / vardiff related, not protocol.)

## datum-rs regression tests to derive from this

1. **Wire snapshot**: byte-for-byte capture of `OpenExtendedMiningChannelSuccess.target` and `SetTarget.maximum_target` against a known target value. Decoding-encoding round-trip must produce the same little-endian bytes.
2. **Endianness asymmetry test**: verify `target` deserializes from LE on input and serializes to LE on output. SRI's `binary_sv2` already does this — but if datum-rs writes any custom encoder for fast-path messages, it must be guarded.
3. **Vardiff floor test**: connect a simulated 1 TH/s downstream miner; verify `SetTarget` is emitted within N seconds of channel open.
4. **Three live miner fingerprints**: NerdOctaxe, Bitaxe-Gamma, NerdAxeGamma — each model self-reports a different `firmware` string in `SetupConnection`.

## datum-rs implication

The byte-order bug is the **#1 interop failure mode in the wild**. A test suite that asserts LE on the six U256 sites listed above is non-negotiable.
