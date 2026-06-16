---
title: "SV2 Mining Protocol"
category: concept
sources:
  - raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md
  - raw/papers/2026-06-16-sv2-spec-08-message-types.md
  - raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md
created: 2026-06-16
updated: 2026-06-16
tags: [sv2, mining-protocol, channels, jobs, shares]
aliases: ["Stratum V2 Mining sub-protocol"]
confidence: high
volatility: cold
verified: 2026-06-16
summary: "Stratum V2's Mining sub-protocol (extension 0x01): how a Pool and a downstream Mining Device exchange channel setup, jobs, share submissions, and difficulty updates."
---

# SV2 Mining Protocol

> The SV2 sub-protocol that any downstream miner speaks. It carries channel lifecycle, job updates, share submissions, and target updates. Extension byte = `0x01`.

## Channel lifecycle

A connection (post-Noise + post-`SetupConnection`) opens **channels**. Each channel is a separate stream of jobs and shares with its own extranonce, target, and version-rolling rules. There are three [[sv2-channel-types|channel types]] ([SV2 Channel Types](sv2-channel-types.md)).

```
C → S  OpenStandardMiningChannel | OpenExtendedMiningChannel
S → C  OpenStandardMiningChannel.Success | OpenExtendedMiningChannel.Success | OpenMiningChannel.Error
```

Subsequent server messages (job, prev hash, target) are **channel-scoped** — bit 15 of the frame `extension_type` is set, and the first 4 payload bytes carry `channel_id`.

## Job lifecycle

Jobs are issued by the server, identified by `(channel_id, job_id)`. A new job can be:

- **Active** — `min_ntime` carries a `Some(...)` value; valid immediately for the current chain tip.
- **Future** — `min_ntime` is `None`; the job is queued, awaiting `SetNewPrevHash` to activate it.

Standard variant (`NewMiningJob`, msg 0x15) ships a precomputed `merkle_root U256`.

Extended variant (`NewExtendedMiningJob`, msg 0x1f) ships:

```
merkle_path        SEQ0_255[U256]
coinbase_tx_prefix B0_64K
coinbase_tx_suffix B0_64K
```

The miner reconstructs the coinbase as:

```
coinbase = coinbase_tx_prefix || extranonce_prefix || extranonce || coinbase_tx_suffix
```

then computes `merkle_root` from `coinbase` and `merkle_path`.

## SetNewPrevHash (mining variant, msg 0x20)

```
channel_id  U32
job_id      U32       # which queued future job becomes active
prev_hash   U256      # LE on wire
min_ntime   U32
nbits       U32
```

Atomically activates one future job and **invalidates all other queued futures**. There is also a TDP variant at msg type `0x72` — same name, different extension.

## SetTarget (msg 0x21)

```
channel_id     U32
maximum_target U256   # LE on wire — absolute hash threshold
```

Replaces SV1's `mining.set_difficulty`. Two key differences:

1. **Absolute U256 hash threshold**, not a difficulty multiplier. Conversion: `target = max_target / difficulty`.
2. **Applies to future jobs only**, not retroactively to already-issued jobs.

`SetTarget` is the **only** vardiff knob on SV2. Bitaxe-class devices (1.3 TH/s) lock against the initial target if `SetTarget` never fires (per [[esp-miner-issue-1758-sv2-byte-order-debugging|ESP-Miner #1758]] ([details](../../raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md))).

## SubmitSharesExtended (msg 0x1b)

```
channel_id      U32
sequence_number U32
job_id          U32
nonce           U32
ntime           U32
version         U32
extranonce      B0_32   # size MUST equal negotiated extranonce_size
```

`SubmitSharesStandard` (0x1a) is identical minus the `extranonce` field (Standard channels have a fixed `extranonce_prefix` and no rollable region).

## Server share replies

`SubmitShares.Success` (0x1c) is **batched**:

```
channel_id                 U32
last_sequence_number       U32
new_submits_accepted_count U32
new_shares_sum             U64
```

`SubmitShares.Error` (0x1d) is per-share. Standard error codes are listed in the [[sv2-downstream-architecture|architecture playbook]] ([architecture playbook](../topics/sv2-downstream-architecture.md)) §9.

## Server-originated messages summary

For a Pool role:

| Code | Message |
|------|---------|
| 0x11 / 0x14 | Open*MiningChannel.Success |
| 0x12 | OpenMiningChannel.Error |
| 0x15 | NewMiningJob |
| 0x17 | UpdateChannel.Error |
| 0x18 | CloseChannel |
| 0x19 | SetExtranoncePrefix |
| 0x1c / 0x1d | SubmitShares.Success / .Error |
| 0x1f | NewExtendedMiningJob |
| 0x20 | SetNewPrevHash |
| 0x21 | SetTarget |
| 0x25 | SetGroupChannel |
| 0x03 (Common) | ChannelEndpointChanged |
| 0x04 (Common) | Reconnect |

## SetupConnection flags

Mining sub-protocol flags:

- `REQUIRES_STANDARD_JOBS` (bit 0) — client wants Standard channels only.
- `REQUIRES_WORK_SELECTION` (bit 1) — client wants `SetCustomMiningJob` (JD); **datum-rs rejects this**.
- `REQUIRES_VERSION_ROLLING` (bit 2) — BIP320 16-bit version rolling.

`.Success` flags:

- `REQUIRES_FIXED_VERSION` (bit 0) — server forbids version rolling.
- `REQUIRES_EXTENDED_CHANNELS` (bit 1) — server only offers Extended channels.

## Wire byte-order rule

All multi-byte integers are little-endian. **U256 fields on the wire are LE** (spec §5.3.1). The byte-order trap is the dominant interop bug observed in the wild — see [[esp-miner-issue-1758-sv2-byte-order-debugging|ESP-Miner #1758]] ([trace](../../raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md)) for the failure mode (channel opens, miner mines silently, zero submits).

## See Also

- [[sv2-channel-types|SV2 Channel Types]] ([SV2 Channel Types](sv2-channel-types.md)) — Standard / Extended / Group.
- [[sv2-extranonce-hierarchy|SV2 Extranonce Hierarchy]] ([SV2 Extranonce Hierarchy](sv2-extranonce-hierarchy.md)) — extranonce partitioning.
- [[sv2-noise-handshake|SV2 Noise Handshake]] ([SV2 Noise Handshake](sv2-noise-handshake.md)) — what comes before any Mining message.
- [[sv2-message-types|SV2 Message Types]] ([SV2 Message Types](../references/sv2-message-types.md)) — full numeric table.
- [[sv2-downstream-architecture|SV2 Downstream Architecture]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) — datum-rs implementation playbook.

## Sources

- [SV2 Spec Ch.5: Mining Protocol](../../raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md) — primary.
- [SV2 Spec Ch.8: Message Types](../../raw/papers/2026-06-16-sv2-spec-08-message-types.md) — dispatch table.
- [ESP-Miner #1758](../../raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md) — observed wire trace.
