---
title: "Bitaxe ESP-Miner PR #1553 — Add Stratum V2 (SV2) protocol support"
source: "https://github.com/bitaxeorg/ESP-Miner/pull/1553"
type: repos
ingested: 2026-06-16
tags: [bitaxe, esp-miner, sv2, firmware, downstream-client, native-sv2]
summary: "Merged 2026-05-16 into ESP-Miner mainline. First (and effectively only) widely-shipped native SV2 firmware. Validates exactly what messages a downstream miner client speaks on the wire."
---

# Bitaxe ESP-Miner PR #1553 — SV2 merge

- Merged 2026-05-16 into ESP-Miner mainline by `warioishere`.
- Opened 2026-02-14, sat ~3 months. Closes the long-running #168 "Adding Support for StratumV2 Protocol".
- Diff: **+3,838 / -288** across 40 files.
- Ships in ESP-Miner **v2.14.0**.

## What was added

- SV2 binary protocol implementation.
- **Noise_NX handshake** with ChaCha20-Poly1305 via `libsecp256k1` (git submodule v0.6.0).
- Protocol coordinator with separate V1/V2 task files and fallback/recovery logic.
- AxeOS Pool Settings UI: per-pool selectable V1/V2 (primary + fallback). NVS persistence.

## Messages implemented (downstream client side)

- `SetupConnection`
- `OpenStandardMiningChannel`
- `NewMiningJob`
- `SetNewPrevHash`
- `SetTarget`
- `SubmitSharesStandard`

(NerdQAxe+ companion PR #544 adds Extended channel — `OpenExtendedMiningChannel`, `NewExtendedMiningJob`, `SubmitSharesExtended`. See related ingest.)

## Validated hardware

- BM1370 (Bitaxe Gamma) at full 1.3 TH/s
- Also tested on BM1366, BM1368, BM1397

Tested against:

- SRI reference pool at `75.119.150.111:3333` with authority pubkey `9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72`
- Author's own `blitzpool.yourdevice.ch:3333`

## Author note

Author candidly states "most of this implementation was done with the help of Claude (Opus 4.6)." This is a real merged firmware with real test traces, not a vibe-coded PR — it works against the SRI reference pool.

## Implications for datum-rs

- **Bitaxe v2.14.0+ devices will connect to a datum-rs SV2 listener** if they exist on the same LAN. They constitute a real-world integration test target.
- Bitaxe ships **Standard channel**; NerdQAxe+ ships **Extended**. datum-rs must support both — but Standard is simpler (no merkle path, server pre-computes merkle_root). Standard suits Bitaxe-class devices; Extended suits everything else.
- Authority pubkey must be exposed as a base58 config knob; miners pin it per-pool. The base58 format is `[0x01, 0x00] || x_only_pubkey[32]` per spec Ch.4.
- A `SetTarget` (0x21) implementation is **required** — Bitaxe's small hashrate (1.3 TH/s) means it would otherwise lock to the initial target and never submit a non-stale share.

## Related

- Issue #168 — 25-month thread that culminated in this PR. Maintainers initially preferred a proxy approach; native won.
- PR #544 (NerdQAxe+) — sibling Extended-channel impl by same author.
- Issue #1758 — first public byte-order interop bug (LE/BE U256 confusion). Required reading.
