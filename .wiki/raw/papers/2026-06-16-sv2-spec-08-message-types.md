---
title: "Stratum V2 Specification — Chapter 8: Message Types (numeric IDs)"
source: "https://github.com/stratum-mining/sv2-spec/blob/main/08-Message-Types.md"
type: papers
ingested: 2026-06-16
tags: [sv2, spec, message-types, framing, dispatch]
summary: "Canonical message-type byte table. extension_type 0x00 = Common; 0x01 = Mining; 0x02 = JD; 0x03 = TDP. Bit 15 of extension_type = channel_msg flag."
---

# SV2 Spec Ch.8 — Message Types

## Frame header (recap from Ch.3)

```
extension_type U16
msg_type       U8
msg_length     U24 (LE)
payload        ...
```

Bit 15 of `extension_type` = `channel_msg` flag. When set, first 4 payload bytes are `channel_id U32`.

## Common (extension 0x00)

| Code | Message | channel_msg |
|------|---------|-------------|
| 0x00 | SetupConnection | 0 |
| 0x01 | SetupConnection.Success | 0 |
| 0x02 | SetupConnection.Error | 0 |
| 0x03 | ChannelEndpointChanged | 1 |
| 0x04 | Reconnect | 0 |

## Mining (extension 0x01)

| Code | Message | channel_msg |
|------|---------|-------------|
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
| 0x20 | SetNewPrevHash | 1 |
| 0x21 | SetTarget | 1 |
| 0x22 | SetCustomMiningJob | 0 |
| 0x23 | SetCustomMiningJob.Success | 0 |
| 0x24 | SetCustomMiningJob.Error | 0 |
| 0x25 | SetGroupChannel | 0 |

## Job Declaration (extension 0x02) — out of scope for datum-rs

| Code | Message |
|------|---------|
| 0x50 | AllocateMiningJobToken |
| 0x51 | AllocateMiningJobToken.Success |
| 0x55 | ProvideMissingTransactions |
| 0x56 | ProvideMissingTransactions.Success |
| 0x57 | DeclareMiningJob |
| 0x58 | DeclareMiningJob.Success |
| 0x59 | DeclareMiningJob.Error |
| 0x60 | PushSolution |

## Template Distribution (extension 0x03) — out of scope for datum-rs upstream

| Code | Message |
|------|---------|
| 0x70 | CoinbaseOutputConstraints |
| 0x71 | NewTemplate |
| 0x72 | SetNewPrevHash (TDP — same name, different ext) |
| 0x73 | RequestTransactionData |
| 0x74 | RequestTransactionData.Success |
| 0x75 | RequestTransactionData.Error |
| 0x76 | SubmitSolution |

Note: `SetNewPrevHash` exists in **both** Mining (0x20) and TDP (0x72). Same semantic intent, different extension namespace.

## datum-rs server demultiplex set

For the role datum-rs plays (Mining sub-protocol, no JD/TDP), the dispatch table is:

- ext 0x00 → SetupConnection (0x00) only handled C→S; emit `.Success` (0x01) or `.Error` (0x02). Emit `Reconnect` (0x04) on graceful upstream loss; broadcast `ChannelEndpointChanged` (0x03) on prefix shifts.
- ext 0x01 channel_msg=0:
  - C→S: `OpenStandardMiningChannel` (0x10), `OpenExtendedMiningChannel` (0x13).
  - S→C: matching Successes, plus `OpenMiningChannel.Error` (0x12).
- ext 0x01 channel_msg=1:
  - C→S: `UpdateChannel` (0x16), `CloseChannel` (0x18), `SubmitSharesStandard` (0x1a), `SubmitSharesExtended` (0x1b).
  - S→C: `NewMiningJob` (0x15), `NewExtendedMiningJob` (0x1f), `SetNewPrevHash` (0x20), `SetTarget` (0x21), `SetExtranoncePrefix` (0x19), `SubmitShares.Success/.Error` (0x1c/0x1d), `UpdateChannel.Error` (0x17).

## datum-rs implication

The total dispatch surface for a non-JD, non-TDP gateway is ~17 message types. That is the entire scope; everything else can return `SetupConnection.Error` with `unsupported-feature`.
