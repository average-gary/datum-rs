---
title: "SV2 Channel Types"
category: concept
sources:
  - raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md
  - raw/repos/2026-06-16-bitaxe-esp-miner-pr-1553-sv2-merge.md
created: 2026-06-16
updated: 2026-06-16
tags: [sv2, channels, standard, extended, group]
aliases: ["Standard channel", "Extended channel", "Group channel"]
confidence: high
volatility: cold
verified: 2026-06-16
summary: "SV2 has three channel types — Standard, Extended, Group — distinguished by where coinbase reconstruction happens and how the extranonce is allocated."
---

# SV2 Channel Types

> A *channel* in SV2 is a per-(connection, miner) stream of jobs and shares. The choice of channel type determines whether the miner reconstructs its own coinbase or receives a pre-computed merkle root.

## Standard channel

- Fixed `extranonce_prefix` (no rollable region — the miner cannot vary the coinbase).
- Server pre-computes `merkle_root` and ships it in `NewMiningJob` (msg 0x15).
- Coinbase reconstruction lives entirely on the pool side.
- `SubmitSharesStandard` (0x1a) carries `(nonce, ntime, version)` only — no extranonce.

Suits: dumb ASICs that can't roll the coinbase. Bitaxe ships Standard in [[bitaxe-esp-miner-pr-1553-sv2-merge|ESP-Miner v2.14.0]] ([details](../../raw/repos/2026-06-16-bitaxe-esp-miner-pr-1553-sv2-merge.md)) — though NerdQAxe+ adds Extended in the sibling PR.

## Extended channel

- `extranonce_prefix` (fixed by server) + miner-rollable `extranonce` (size negotiated via `OpenExtendedMiningChannel`).
- Server ships `coinbase_tx_prefix`, `coinbase_tx_suffix`, and `merkle_path` in `NewExtendedMiningJob` (msg 0x1f).
- Miner reconstructs:
  ```
  coinbase = coinbase_tx_prefix || extranonce_prefix || extranonce || coinbase_tx_suffix
  ```
  then computes `merkle_root` from `coinbase` + `merkle_path`.
- `SubmitSharesExtended` (0x1b) carries the rollable `extranonce` along with `(nonce, ntime, version)`.

Suits: anything bigger than a Bitaxe; **default in SRI's `translator_sv2` and NerdQAxe+ native firmware**. The **dominant production form**.

## Group channel

- Aggregates multiple Standard channels under one parent for shared lifecycle messages.
- All members must have **identical total extranonce length**.
- Server addresses the group via `SetGroupChannel` (msg 0x25).

datum-rs skips Group channels — there's no win when DATUM upstream collapses to a single stream regardless.

## Channel-id namespace

A single TCP connection can host many channels. The `channel_id` is unique within the connection and is the routing key for channel-scoped messages (frame `extension_type` bit 15 set; first 4 payload bytes = `channel_id`).

## Picking a type

| Constraint | Pick |
|------------|------|
| Miner self-reports it can roll coinbase | Extended |
| Miner sets `REQUIRES_STANDARD_JOBS` flag | Standard |
| Miner is Bitaxe v2.14.0+ | Standard (matches firmware) |
| Miner is NerdQAxe+ or a translator | Extended |

For datum-rs: support both Standard and Extended; reject Group.

## See Also

- [[sv2-mining-protocol|SV2 Mining Protocol]] ([SV2 Mining Protocol](sv2-mining-protocol.md)) — message-by-message.
- [[sv2-extranonce-hierarchy|SV2 Extranonce Hierarchy]] ([SV2 Extranonce Hierarchy](sv2-extranonce-hierarchy.md)) — how extranonce ranges are allocated.
- [[sv2-downstream-architecture|SV2 Downstream Architecture]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) — datum-rs choices.

## Sources

- [SV2 Spec Ch.5: Mining Protocol](../../raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md) — primary.
- [Bitaxe ESP-Miner PR #1553](../../raw/repos/2026-06-16-bitaxe-esp-miner-pr-1553-sv2-merge.md) — Standard channel in production firmware.
