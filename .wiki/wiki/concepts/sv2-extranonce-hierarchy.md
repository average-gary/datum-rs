---
title: "SV2 Extranonce Hierarchy"
category: concept
sources:
  - raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md
  - raw/repos/2026-06-16-sri-pool-channel-manager-impl.md
created: 2026-06-16
updated: 2026-06-16
tags: [sv2, extranonce, channel-allocation, coinbase]
aliases: ["extranonce_prefix", "extranonce partition"]
confidence: high
volatility: warm
verified: 2026-06-16
summary: "How SV2 partitions the extranonce: a per-channel `extranonce_prefix` (server-allocated) plus a miner-rollable `extranonce` (Extended channels only). The total bytes must fit a single integer field."
---

# SV2 Extranonce Hierarchy

> SV2's extranonce splits into two non-overlapping byte ranges: a `extranonce_prefix` allocated by the pool (per-channel, fixed for the channel's lifetime) and a `extranonce` rollable region the miner controls. Standard channels have no rollable region.

## The two regions

```
extended-channel:
  extranonce_prefix [P bytes] | extranonce (rollable) [R bytes]

standard-channel:
  extranonce_prefix [P bytes]
```

`P + R` is the **total extranonce length**, which must fit the single integer field the upstream consumes when reconstructing the coinbase.

## Server-side allocation (SRI reference)

Per [[sri-pool-channel-manager-impl|SRI sv2-apps Pool ChannelManager]] ([reference impl](../../raw/repos/2026-06-16-sri-pool-channel-manager-impl.md)):

```
POOL_SERVER_BYTES         = 1     # up to 256 distinct pool servers
POOL_LOCAL_PREFIX_BYTES   = 3     # 24-bit channel space (16,777,216 channels)
POOL_ALLOCATION_BYTES     = 4
CLIENT_SEARCH_SPACE_BYTES = 16
FULL_EXTRANONCE_SIZE      = 20
```

So SRI's reference Pool gives each Extended channel a 4-byte server-side prefix and 16 bytes of rollable space; total 20 bytes.

A `ExtranonceAllocator` is shared across both Standard and Extended downstreams. Allocations are RAII — when the channel state drops, the prefix slot is freed via `AllocatedExtranoncePrefix`.

## datum-rs constraint: 12-byte upstream

DATUM upstream's `0x27` share-submission frame expects a **single 12-byte extranonce field**. datum-rs cannot use SRI's 20-byte default. Per `crates/datum-stratum-sv2/src/lib.rs:31`:

```rust
ExtranonceBridge {
    local_prefix:    0,    // bytes
    local_index:     2,    // bytes  -> up to 65,536 channels per server
    rollable_bytes:  10,   // bytes
}
// total = 12
```

This is a deliberate **collapse** of SRI's 3-tier (server / channel / rollable) to a 2-tier (channel-index / rollable) split, because the gateway runs as a single process and doesn't need a `POOL_SERVER_BYTES` discriminator.

`concat_for_upstream(local_prefix, rolling) -> [u8; 12]` does the wire concatenation for the DATUM frame.

## Implications

- `OpenExtendedMiningChannel.Success.extranonce_prefix` is the 2-byte channel-index portion.
- `OpenExtendedMiningChannel.Success.extranonce_size` advertised to the miner is **10 bytes**.
- Coinbase reconstruction: `coinbase_tx_prefix || extranonce_prefix(2 B) || extranonce(10 B) || coinbase_tx_suffix`.
- Channel limit per gateway: 65,536. Beyond that, `OpenMiningChannel.Error` with `unsupported-feature` or a custom code.

## Allocation policy

- Allocate prefixes monotonically (`AtomicU16::fetch_add`); on channel close, return slot to a freelist.
- For long-running gateways, prefer slot-reuse over monotonic increment to avoid eventual exhaustion (65,536 churn is small but real).
- A bounded freelist matches the SRI RAII model; both work.

## See Also

- [[sv2-channel-types|SV2 Channel Types]] ([SV2 Channel Types](sv2-channel-types.md)) — Standard has no rollable region.
- [[sv2-mining-protocol|SV2 Mining Protocol]] ([SV2 Mining Protocol](sv2-mining-protocol.md)) — `OpenExtendedMiningChannel.Success` shape.
- [[sv2-downstream-architecture|SV2 Downstream Architecture]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) — full integration.

## Sources

- [SV2 Spec Ch.5: Mining Protocol](../../raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md) — extranonce field semantics.
- [SRI sv2-apps Pool ChannelManager](../../raw/repos/2026-06-16-sri-pool-channel-manager-impl.md) — reference 20-byte partition.
