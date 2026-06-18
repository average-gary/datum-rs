---
title: "SRI Crate Map (current `main`)"
category: reference
sources:
  - raw/repos/2026-06-16-sri-stratum-mining-stratum.md
  - raw/repos/2026-06-16-sri-pool-channel-manager-impl.md
created: 2026-06-16
updated: 2026-06-16
tags: [sri, sv2, crates, msrv, dependencies]
aliases: ["SRI crates", "stratum-mining/stratum crate map"]
confidence: high
volatility: hot
verified: 2026-06-16
summary: "Current crate layout of `stratum-mining/stratum` (libraries) and `stratum-mining/sv2-apps` (binaries). Includes versions on main as of 2026-06-16, MSRV pins, and which crates datum-rs needs."
---

# SRI Crate Map (current `main`)

> SRI was restructured in 2026: `roles_logic_sv2`, `roles/`, `protocols/`, `examples/`, `utils/` are gone. Documentation that references those names is stale.

## Two repos, two MSRVs

| Repo | Role | MSRV | Branch policy |
|------|------|------|---------------|
| `stratum-mining/stratum` | Protocol libraries | **1.75.0** | hard-pinned in `rust-toolchain.toml`, CI-enforced |
| `stratum-mining/sv2-apps` | Binaries (pool, jds, jdc, translator) | **1.85.0** | apps may use a newer toolchain than libs |

datum-rs (MSRV 1.89) consumes only the **library** crates from `stratum`. Rust is forward-compatible — library code that compiles on 1.75 also compiles on 1.89.

> **Lesson learned (2026-06-18)**: SRI's MSRV pin is a *contributor* constraint, NOT a consumer one. We initially scoped Phase 3 as "blocked on SRI MSRV bump" — that was wrong. See [lessons-learned 2026-06-18 §7](../../raw/notes/2026-06-18-ll-sv2-listener-live-validation.md).

## Library crates (in `stratum-mining/stratum/sv2/`)

| Path | Crate | Version on main (2026-06-16) | Purpose |
|------|-------|------------------------------|---------|
| `binary-sv2/` | `binary_sv2` | 6.0.0 | Encoder / decoder for primitive SV2 types |
| `buffer-sv2/` | `buffer_sv2` | — | Buffer pool |
| `channels-sv2/` | `channels_sv2` | 7.0.0 | **Server- and client-side channel state machines** |
| `codec-sv2/` | `codec_sv2` | 6.0.0 | Noise + framing wrapper |
| `extensions-sv2/` | `extensions_sv2` | — | TLV extensions |
| `framing-sv2/` | `framing_sv2` | 7.0.0 | 6-byte header framing |
| `handlers-sv2/` | `handlers_sv2` | 0.5.0 | Async message handler traits |
| `noise-sv2/` | `noise_sv2` | 1.0.0 | Noise_NX handshake |
| `parsers-sv2/` | `parsers_sv2` | 0.5.0 | Top-level Mining/JD/TDP enums |
| `subprotocols/common-messages/` | `common_messages_sv2` | — | Common-messages types |
| `subprotocols/job-declaration/` | `job_declaration_sv2` | — | JD types (datum-rs unused) |
| `subprotocols/mining/` | `mining_sv2` | 11.0.0 | Mining-specific message types |
| `subprotocols/template-distribution/` | `template_distribution_sv2` | — | TDP types (datum-rs unused) |
| `stratum-core` | `stratum-core` | 0.5.0 | **Umbrella crate that re-exports all of the above** |

`stratum-core` is the thing to depend on; it re-exports the rest.

## App crates (in `stratum-mining/sv2-apps/`)

| Path | Crate | Purpose |
|------|-------|---------|
| `pool-apps/pool` | `pool_sv2` | The reference Pool binary — what [[sv2-downstream-architecture|datum-rs's SV2 server]] mirrors. |
| `pool-apps/jd-server` | `jd_server_sv2` | Job Declaration Server. datum-rs unused. |
| `miner-apps/jd-client` | `jd_client_sv2` | Job Declaration Client (LAN-side). datum-rs unused. |
| `miner-apps/translator` | `translator_sv2` | SV1↔SV2 proxy. The dominant downstream-client form datum-rs will see. |
| `stratum-apps/` | — | Shared LAN/network/payout helpers. Feature-gated. |

## Stale names → current names

| Stale | Current |
|-------|---------|
| `roles_logic_sv2` | split into `parsers_sv2`, `handlers_sv2`, `channels_sv2` |
| `ChannelFactory` | per-channel `JobFactory` in `channels_sv2::server::jobs::factory` |
| `DefaultJobStore<ExtendedJob>` | `JobStore` trait + default impl in `channels_sv2::server::jobs::job_store` |
| `ParseDownstreamMiningMessages` | `HandleMiningMessagesFromClientAsync` / `…Sync` in `handlers_sv2::mining` |

## datum-rs Cargo dependency pattern

Mirror `stratum-mining/sv2-apps/stratum-apps/Cargo.toml`:

```toml
[dependencies]
stratum-core = { git = "https://github.com/stratum-mining/stratum", rev = "<pin>" }
```

Pin a specific rev. Re-review at each SRI minor release (cadence: monthly — v1.6 Nov 2025, v1.7 Jan 2026, v1.8 Mar 2026, v1.9 May 2026, v1.10 Jun 2026).

## What to import for the SV2 Pool role

```rust
use stratum_core::channels_sv2::{
    extranonce_manager::{bytes_needed, AllocatedExtranoncePrefix, ExtranonceAllocator},
    server::{
        extended::ExtendedChannel,
        standard::StandardChannel,
        share_accounting::{ShareAccounting, ShareValidationError, ShareValidationResult},
        jobs::{extended::ExtendedJob, factory::JobFactory, job_store::JobStore, JobOrigin},
    },
    Vardiff, VardiffState,
};
use stratum_core::handlers_sv2::HandleMiningMessagesFromClientAsync;
use stratum_core::parsers_sv2::{Mining, Tlv};
use stratum_core::mining_sv2::{
    SetCustomMiningJob, SubmitSharesExtended,
    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE,
    ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
    ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW,
    ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE,
    ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID,
    ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE,
    ERROR_CODE_SUBMIT_SHARES_STALE_SHARE,
    ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE,
    ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
};
```

## See Also

- [[sv2-downstream-architecture|SV2 Downstream Architecture]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) — how datum-rs uses these.
- [[sv2-noise-handshake|SV2 Noise Handshake]] ([SV2 Noise Handshake](../concepts/sv2-noise-handshake.md)) — `noise_sv2` consumer.
- [[sv2-message-types|SV2 Message Types]] ([SV2 Message Types](sv2-message-types.md)) — `mining_sv2` constants.

## Sources

- [SRI stratum repo](../../raw/repos/2026-06-16-sri-stratum-mining-stratum.md) — restructure, MSRV, version table.
- [SRI sv2-apps Pool ChannelManager](../../raw/repos/2026-06-16-sri-pool-channel-manager-impl.md) — import patterns.
