---
title: "SRI: stratum-mining/stratum (canonical SV2 protocol libraries)"
source: "https://github.com/stratum-mining/stratum"
type: repos
ingested: 2026-06-16
tags: [sri, sv2, rust, msrv, channels-sv2, repo-restructure]
summary: "SRI's protocol library repo — the canonical Rust impl of SV2 message types, channel state machines, Noise handshake. Hard-pinned at MSRV 1.75.0 on `main`. Restructured: roles_logic_sv2 is gone."
---

# stratum-mining/stratum

## Repo state (as of 2026-06-16)

- 346 stars, last push 2026-06-16. Default branch `main`.
- Latest release: **v1.10.0** (2026-06-03).
- Maintainers: `@plebhash` (lead), `@GitGab19`.

## MSRV

- **Hard-pinned at 1.75.0** on `main` via `rust-toolchain.toml` (`channel = "1.75.0"`).
- Enforced by CI `.github/workflows/rust-msrv.yaml` ("MSRV 1.75 Check") on every PR.
- README badges of every sub-crate (e.g. `channels_sv2`) state `rustc-1.75.0+`.
- Workspace `Cargo.toml` pins `quickcheck >= 1.0.3, < 1.1` and `quickcheck_macros` similarly because newer versions require Rust 2024 edition not supported on 1.75.

## Restructure (important — invalidates older docs)

`roles_logic_sv2`, `roles/`, `protocols/`, `examples/`, `utils/` are **GONE** on `main`. Old layout still exists on `release/v1.0.0` … `release/v1.5.0`.

Current top-level dirs: `stratum-core/`, `sv1/`, `sv2/`, `fuzz/`, `scripts/`.

## Crate map (current `sv2/`)

```
sv2/binary-sv2          # Encoder/decoder for primitive types
sv2/buffer-sv2          # Buffer pool
sv2/channels-sv2        # Server- and client-side channel state machines
sv2/codec-sv2           # Noise + framing wrapper
sv2/extensions-sv2      # TLV extensions
sv2/framing-sv2         # 6-byte header framing
sv2/handlers-sv2        # Async message handler traits
sv2/noise-sv2           # Noise_NX handshake
sv2/parsers-sv2         # Top-level Mining/JD/TDP enums
sv2/subprotocols/
    common-messages
    job-declaration
    mining
    template-distribution
```

`stratum-core` is the **umbrella crate** that re-exports all sub-crates.

## Crate versions on main

- `stratum-core 0.5.0`
- `channels_sv2 7.0.0`
- `mining_sv2 11.0.0`
- `parsers_sv2 0.5.0`
- `handlers_sv2 0.5.0`
- `framing_sv2 7.0.0`
- `binary_sv2 6.0.0`
- `codec_sv2 6.0.0`
- `noise_sv2 1.0.0`

Release cadence is monthly (v1.6 Nov 2025, v1.7 Jan 2026, v1.8 Mar 2026, v1.9 May 2026, v1.10 Jun 2026).

## Key types for a Pool role (`channels_sv2/src/server/`)

```
extended.rs         # ExtendedChannel  ← THE primary type for datum-rs
standard.rs         # StandardChannel
group.rs            # GroupChannel
share_accounting.rs # ShareAccounting, ShareValidationError, ShareValidationResult
jobs/factory.rs     # JobFactory (per-channel)
jobs/job_store.rs   # JobStore trait + default impl
jobs/extended.rs    # ExtendedJob type
error.rs
```

`ExtendedChannel::new_for_pool(...)` is the canonical Pool-side constructor:

```rust
ExtendedChannel::new_for_pool(
    channel_id,
    user_identity,
    extranonce_prefix,
    max_target,
    nominal_hashrate,
    version_rolling_allowed,
    rollable_extranonce_size,
    share_batch_size,
    expected_share_per_minute,
    pool_tag_string,
)
```

Methods mapped 1:1 to spec messages:

- `update_channel(...)` ← UpdateChannel
- `on_new_template(...)` / `on_set_new_prev_hash(...)` → drives NewExtendedMiningJob + SetNewPrevHash emission
- `on_set_custom_mining_job(...)` → SetCustomMiningJob (work selection)
- `set_target(...)` → SetTarget
- `set_extranonce_prefix(...)` → SetExtranoncePrefix
- `validate_share(SubmitSharesExtended) -> ShareValidationResult`
- Job lookup: `get_active_job() / get_future_job(job_id) / get_past_job(job_id)`

`extranonce_manager` exposes `MAX_EXTRANONCE_LEN` and `AllocatedExtranoncePrefix` (RAII slot allocation).

## Stale names from older project notes

The following names are **stale** (likely from `roles_logic_sv2` v0.x docs, pre-restructure) — do not use them in new code:

- `roles_logic_sv2` → split into `parsers_sv2`, `handlers_sv2`, `channels_sv2`.
- `ChannelFactory` → per-channel `JobFactory` in `server::jobs::factory`.
- `DefaultJobStore<ExtendedJob>` → actual name is `JobStore` trait; default impl in `server::jobs::job_store`.
- `ParseDownstreamMiningMessages` → `HandleMiningMessagesFromClientAsync` / `…Sync` in `handlers_sv2::mining`.

## SRI assumes a TDP upstream

The Pool-side `ExtendedChannel` drives `NewExtendedMiningJob` from a `NewTemplateTdp` (Template Distribution input). For datum-rs's DATUM-upstream gateway you must either:

1. Synthesize equivalent template state from DATUM and call `on_new_template` / `on_set_new_prev_hash`, **or**
2. Bypass and emit `NewExtendedMiningJob` + `SetNewPrevHash` directly using your own job factory.

Option 2 keeps the dependency on `mining_sv2` types only and avoids dragging in TDP state machines.

## datum-rs MSRV consumption pattern

Rust is forward-compatible: depending on `stratum-core` (1.75) from a 1.89 project compiles on 1.89. The constraint is that **SRI commits not to introducing features past 1.75** in their library code. There is no SRI fork on a newer MSRV because none is needed.

The recommended Cargo pattern (cribbed from `sv2-apps`):

```toml
[dependencies]
stratum-core = { git = "https://github.com/stratum-mining/stratum", branch = "main" }
```

Pin a specific rev for reproducibility once integration begins.
