---
title: "Stratum V2 Specification — Chapter 5: Mining Protocol"
source: "https://github.com/stratum-mining/sv2-spec/blob/main/05-Mining-Protocol.md"
type: papers
ingested: 2026-06-16
tags: [sv2, spec, mining-protocol, channels, jobs, shares]
summary: "Canonical Mining sub-protocol. Channel types (Standard, Extended, Group); job lifecycle; share submission. Server→client messages include OpenChannel.Success, NewMiningJob/NewExtendedMiningJob, SetNewPrevHash, SetTarget."
---

# SV2 Spec Ch.5 — Mining Protocol

## Channel types

### Standard channel

- Fixed `extranonce_prefix`. Pool pre-computes `merkle_root` and ships it in `NewMiningJob`.
- Suited to dumb ASICs that never roll the coinbase.
- Coinbase reconstruction lives entirely on the pool side.

### Extended channel

- `extranonce_prefix` + miner-rollable `extranonce` (size negotiated).
- Miner reconstructs coinbase from `coinbase_tx_prefix || extranonce_prefix || extranonce || coinbase_tx_suffix`.
- Server ships `merkle_path` so the miner can compute `merkle_root` per share.
- **This is the dominant channel type for real downstream clients** (NerdQAxe+ default; SRI translator default).

### Group channel

- Aggregates multiple Standard channels for shared lifecycle messages.
- All members must have identical total extranonce length.

## OpenStandardMiningChannel

Request:

```
req_id            U32
user_identity     STR0_255
nominal_hash_rate F32
max_target        U256
```

`.Success`:

```
req_id            U32
channel_id        U32
target            U256
extranonce_prefix B0_32
group_channel_id  U32
```

## OpenExtendedMiningChannel

Adds:

```
min_extranonce_size U16
```

`.Success` adds:

```
extranonce_size U16   # rollable bytes the device controls
```

## NewExtendedMiningJob

```
channel_id              U32
job_id                  U32
min_ntime               OPTION[U32]   # empty = future job awaiting SetNewPrevHash
version                 U32
version_rolling_allowed BOOL
merkle_path             SEQ0_255[U256]
coinbase_tx_prefix      B0_64K
coinbase_tx_suffix      B0_64K
```

`NewMiningJob` (Standard variant) replaces `merkle_path`/`coinbase_*` with a precomputed `merkle_root U256`.

## SetNewPrevHash

```
channel_id  U32
job_id      U32
prev_hash   U256
min_ntime   U32
nbits       U32
```

Atomically activates one queued **future** job and invalidates all others.

## SetTarget

```
channel_id     U32
maximum_target U256   # absolute hash threshold, NOT a difficulty multiplier
```

- Applies to all future jobs.
- **Never retroactively** changes the target of already-active jobs.
- This is the SV2 vardiff primitive. Replaces SV1's `mining.set_difficulty`. **Critical for small devices** (Bitaxe class) that pin against the initial target if `SetTarget` never fires.

## SubmitSharesExtended

```
channel_id      U32
sequence_number U32
job_id          U32
nonce           U32
ntime           U32
version         U32
extranonce      B0_32   # size MUST equal negotiated extranonce_size
```

Standard variant omits `extranonce`.

## Server reply: SubmitShares.Success / .Error

`.Success` is **batched**:

```
channel_id                  U32
last_sequence_number        U32
new_submits_accepted_count  U32
new_shares_sum              U64
```

`.Error` is per-share. Standard error codes include `invalid-job-id`, `bad-extranonce-size`, `difficulty-too-low`, `duplicate-share`, `stale-share`, `invalid-share`, `version-rolling-not-allowed`.

## Server-originated messages (all relevant for a Pool role)

- `OpenStandardMiningChannel.Success` / `OpenExtendedMiningChannel.Success`
- `OpenMiningChannel.Error`
- `NewMiningJob` / `NewExtendedMiningJob`
- `SetNewPrevHash`
- `SetTarget`
- `SetExtranoncePrefix`
- `SubmitShares.Success` / `.Error`
- `SetGroupChannel`
- `CloseChannel`
- `Reconnect`
- `ChannelEndpointChanged`

## SetupConnection flags (mining sub-protocol)

- `REQUIRES_STANDARD_JOBS` (bit 0)
- `REQUIRES_WORK_SELECTION` (bit 1) — i.e. the miner wants `SetCustomMiningJob`; for a non-JD pool, **reject** this flag with an Error.
- `REQUIRES_VERSION_ROLLING` (bit 2)

`.Success` flags:

- `REQUIRES_FIXED_VERSION` (bit 0)
- `REQUIRES_EXTENDED_CHANNELS` (bit 1)

## Wire byte order trap

Per spec §5.3.1 all `U256` fields **on the wire are little-endian**. The byte-order trap is the dominant interop bug observed in the wild (see `esp-miner-issue-1758-sv2-byte-order-debugging`). Sites that must be LE on wire:

- `OpenStandardMiningChannel.max_target`
- `OpenStandardMiningChannelSuccess.target`
- `OpenExtendedMiningChannel.max_target`
- `OpenExtendedMiningChannelSuccess.target`
- `SetTarget.maximum_target`
- `SetNewPrevHashTdp.target` (TDP)

## datum-rs implications

- **Extended channel is the must-have**; standard is optional.
- The DATUM upstream expects a flat 12-byte extranonce. SRI partitions are larger (see `sri-pool-channel-manager-impl`: `FULL_EXTRANONCE_SIZE = 20`). datum-rs's `ExtranonceBridge` collapses to 12 by setting `local_prefix=0`, `local_index=2`, `rollable=10`.
- `SetTarget` cannot be omitted (vardiff for small devices).
- Reject `REQUIRES_WORK_SELECTION` — datum-rs is not a JD pool.
