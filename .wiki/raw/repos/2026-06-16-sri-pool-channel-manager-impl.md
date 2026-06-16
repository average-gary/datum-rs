---
title: "SRI sv2-apps Pool ChannelManager — reference Pool-toward-miner impl"
source: "https://github.com/stratum-mining/sv2-apps/blob/main/pool-apps/pool/src/lib/channel_manager/mod.rs"
type: repos
ingested: 2026-06-16
tags: [sri, sv2, pool, channel-manager, extranonce, vardiff, reference-impl]
summary: "The only working production-grade Pool that uses the new channels_sv2/handlers_sv2 API. Mirror this for datum-rs's SV2 server toward downstream miners."
---

# sv2-apps Pool ChannelManager

## Repo split

The SRI `roles/` directory **moved** out of `stratum-mining/stratum` into `stratum-mining/sv2-apps`. That repo now holds:

- `pool-apps/pool` — Pool binary (crate `pool_sv2 0.4.0`)
- `pool-apps/jd-server`
- `miner-apps/jd-client`
- `miner-apps/translator` (SV1↔SV2 proxy)
- `stratum-apps/` — shared LAN/network/payout helpers
- `bitcoin-core-sv2/`
- `integration-tests/`

MSRV here is **1.85.0** (`rust-toolchain.toml`), one major notch above the protocol library's 1.75 — apps may use a newer toolchain than libs.

## Cargo dependency pattern (cribbed for datum-rs)

`stratum-apps` pulls SRI as a **git dep, not crates.io**:

```toml
stratum-core = { git = "https://github.com/stratum-mining/stratum", branch = "main", optional = true }
```

Cargo.toml comment: "fetching from github enables synchronizing development workflows across sv2-apps and stratum repos. it MUST be changed before stratum-apps is published to crates.io." This is **the** pattern datum-rs should mirror until SRI publishes to crates.io.

`stratum-apps` feature flags:

- `pool`
- `jd_client`
- `jd_server`
- `translator`
- `mining_device`
- `sv1`
- `monitoring`
- `with_buffer_pool`

`pool` feature bundles `network + config + with_buffer_pool + core + payout`.

## ChannelManagerData state

```rust
struct ChannelManagerData {
    downstream:           HashMap<DownstreamId, Downstream>,
    extranonce_allocator: ExtranonceAllocator,            // shared across standard + extended
    downstream_id_factory: AtomicUsize,
    vardiff:              HashMap<VardiffKey, VardiffState>,
    coinbase_outputs:     Vec<u8>,
    last_new_prev_hash:   Option<SetNewPrevHash<'static>>,
    last_future_template: Option<NewTemplate<'static>>,
}
```

Comment: "Unified extranonce prefix allocator, shared by standard and extended downstream channels. The allocated `ExtranoncePrefix` is stored on the channel itself, so dropping the channel automatically releases the slot." → confirms RAII allocation.

## Production extranonce constants

```
POOL_SERVER_BYTES        = 1                     // up to 256 distinct pool servers
POOL_MAX_CHANNELS        = 16_777_216            // 24-bit channel space
POOL_LOCAL_PREFIX_BYTES  = bytes_needed(POOL_MAX_CHANNELS)  // = 3
POOL_ALLOCATION_BYTES    = 4
CLIENT_SEARCH_SPACE_BYTES = 16
FULL_EXTRANONCE_SIZE     = 20                    // total bytes
```

For datum-rs the constraint is **DATUM upstream expects a flat 12-byte extranonce**. The `ExtranonceBridge` already partitions `[local_prefix=0, local_index=2, rollable=10]` to fit. SRI's 20-byte total layout is wider — when porting, do NOT copy SRI's constants verbatim.

## Noise wiring

```rust
start_downstream_server(authority_public_key, authority_secret_key, cert_validity_sec, listen_address, ...)
    -> stratum_apps::network_helpers::accept_noise_connection(...)
```

Authentication via `Secp256k1PublicKey` / `Secp256k1SecretKey` from `key_utils 1.2.0` (in workspace deps).

## Message dispatch

Channel manager has separate sub-handlers:

- `mining_message_handler.rs` — `impl HandleMiningMessagesFromClientAsync`
- `template_distribution_message_handler.rs` — `impl HandleTemplateDistributionMessagesFromServerAsync`

Tuple type passed through `async_channel`: `(usize, Mining<'static>, Option<Vec<Tlv>>)` where `usize` is downstream id and `Tlv` is parsed extension data.

## JobDeclarator embedding

`JobDeclarator` is **embedded** into the pool when `[jds]` config block exists (and requires `BitcoinCoreIpc` template provider, not Sv2 TP). JDS used to be a separate binary; it is now in-process.

For datum-rs: skip JD entirely, leave the config block unset, leave the JD pathway compiled out.

## datum-rs implication

This file is the **reference architecture**. The minimal port:

1. Replace `Sv2Tp` / `BitcoinCoreIPCEngine` upstream with `datum-protocol::DatumClient`.
2. Replace `template_distribution_message_handler` with a DATUM→ExtendedChannel adapter that synthesizes `(NewTemplate, SetNewPrevHash)` from DATUM messages — **OR** call `ExtendedChannel`'s lower-level setters directly.
3. Keep `mining_message_handler.rs` intact.
4. Replace SRI's payout module — datum-rs already has its own coinbaser logic.
5. Set `extranonce_allocator` total to **12 bytes**, not 20.
