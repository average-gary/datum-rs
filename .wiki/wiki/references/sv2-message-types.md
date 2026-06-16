---
title: "SV2 Message Types (numeric reference)"
category: reference
sources:
  - raw/papers/2026-06-16-sv2-spec-08-message-types.md
created: 2026-06-16
updated: 2026-06-16
tags: [sv2, message-types, dispatch, framing]
aliases: ["SV2 message ids", "SV2 numeric reference"]
confidence: high
volatility: cold
verified: 2026-06-16
summary: "One-page reference for SV2's `(extension_type, msg_type)` dispatch byte. Common 0x00, Mining 0x01, Job Declaration 0x02, Template Distribution 0x03."
---

# SV2 Message Types

> Frame header is `extension_type U16 || msg_type U8 || msg_length U24 (LE) || payload`. Bit 15 of `extension_type` is `channel_msg`. When set, the first 4 payload bytes are `channel_id U32`.

## Common (extension 0x00)

| msg_type | Name | channel_msg |
|----------|------|-------------|
| 0x00 | SetupConnection | 0 |
| 0x01 | SetupConnection.Success | 0 |
| 0x02 | SetupConnection.Error | 0 |
| 0x03 | ChannelEndpointChanged | 1 |
| 0x04 | Reconnect | 0 |

## Mining (extension 0x01)

| msg_type | Name | channel_msg |
|----------|------|-------------|
| 0x10 | OpenStandardMiningChannel | 0 |
| 0x11 | OpenStandardMiningChannel.Success | 0 |
| 0x12 | OpenMiningChannel.Error | 0 |
| 0x13 | OpenExtendedMiningChannel | 0 |
| 0x14 | OpenExtendedMiningChannel.Success | 0 |
| 0x15 | NewMiningJob | 1 |
| 0x16 | UpdateChannel | 1 |
| 0x17 | UpdateChannel.Error | 1 |
| 0x18 | CloseChannel | 1 |
| 0x19 | SetExtranoncePrefix | 1 |
| 0x1a | SubmitSharesStandard | 1 |
| 0x1b | SubmitSharesExtended | 1 |
| 0x1c | SubmitShares.Success | 1 |
| 0x1d | SubmitShares.Error | 1 |
| 0x1f | NewExtendedMiningJob | 1 |
| 0x20 | SetNewPrevHash (mining variant) | 1 |
| 0x21 | SetTarget | 1 |
| 0x22 | SetCustomMiningJob | 0 |
| 0x23 | SetCustomMiningJob.Success | 0 |
| 0x24 | SetCustomMiningJob.Error | 0 |
| 0x25 | SetGroupChannel | 0 |

## Job Declaration (extension 0x02) — datum-rs unused

| msg_type | Name |
|----------|------|
| 0x50 | AllocateMiningJobToken |
| 0x51 | AllocateMiningJobToken.Success |
| 0x55 | ProvideMissingTransactions |
| 0x56 | ProvideMissingTransactions.Success |
| 0x57 | DeclareMiningJob |
| 0x58 | DeclareMiningJob.Success |
| 0x59 | DeclareMiningJob.Error |
| 0x60 | PushSolution |

## Template Distribution (extension 0x03) — datum-rs unused

| msg_type | Name |
|----------|------|
| 0x70 | CoinbaseOutputConstraints |
| 0x71 | NewTemplate |
| 0x72 | SetNewPrevHash (TDP variant — different ext from mining 0x20) |
| 0x73 | RequestTransactionData |
| 0x74 | RequestTransactionData.Success |
| 0x75 | RequestTransactionData.Error |
| 0x76 | SubmitSolution |

## datum-rs server demultiplex set

Total dispatch surface for a non-JD, non-TDP gateway is ~17 message types:

- ext 0x00 — `SetupConnection` (0x00) → emit `.Success` (0x01) / `.Error` (0x02). Originate `Reconnect` (0x04) on graceful shutdown; `ChannelEndpointChanged` (0x03) on prefix shifts.
- ext 0x01 channel_msg=0:
  - C→S: `OpenStandardMiningChannel` (0x10), `OpenExtendedMiningChannel` (0x13).
  - S→C: matching Successes, plus `OpenMiningChannel.Error` (0x12).
- ext 0x01 channel_msg=1:
  - C→S: `UpdateChannel` (0x16), `CloseChannel` (0x18), `SubmitSharesStandard` (0x1a), `SubmitSharesExtended` (0x1b).
  - S→C: `NewMiningJob` (0x15), `NewExtendedMiningJob` (0x1f), `SetNewPrevHash` (0x20), `SetTarget` (0x21), `SetExtranoncePrefix` (0x19), `SubmitShares.Success/.Error` (0x1c/0x1d), `UpdateChannel.Error` (0x17).

Everything else returns `SetupConnection.Error` with `unsupported-feature`.

## See Also

- [[sv2-mining-protocol|SV2 Mining Protocol]] ([SV2 Mining Protocol](../concepts/sv2-mining-protocol.md)) — semantic detail on the mining set.
- [[sv2-downstream-architecture|SV2 Downstream Architecture]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) — datum-rs scope decision.

## Sources

- [SV2 Spec Ch.8](../../raw/papers/2026-06-16-sv2-spec-08-message-types.md) — primary.
