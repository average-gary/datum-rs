---
title: "SV2 Downstream Architecture for datum-rs"
category: topic
sources:
  - raw/papers/2026-06-16-sv2-spec-04-noise-handshake.md
  - raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md
  - raw/papers/2026-06-16-sv2-spec-08-message-types.md
  - raw/repos/2026-06-16-sri-stratum-mining-stratum.md
  - raw/repos/2026-06-16-sri-pool-channel-manager-impl.md
  - raw/repos/2026-06-16-bitaxe-esp-miner-pr-1553-sv2-merge.md
  - raw/notes/2026-06-16-ocean-datum-gateway-sv2-issue-146.md
  - raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md
  - raw/notes/2026-06-16-delvingbitcoin-sjors-sv2-noise-bip324-413.md
  - raw/notes/2026-06-16-sri-issue-2103-noise-responder-overflow.md
created: 2026-06-16
updated: 2026-06-16
tags: [sv2, datum-rs, architecture, downstream-miners, playbook]
aliases: ["SV2 server architecture", "datum-rs SV2 plan"]
confidence: high
volatility: warm
verified: 2026-06-16
summary: "How datum-rs should implement an SV2 server toward downstream miners while bridging to OCEAN's DATUM upstream. Synthesized from spec, SRI reference impl, and observed downstream-client behavior."
---

# SV2 Downstream Architecture for datum-rs

> The role: datum-rs is a Pool-side SV2 server. It accepts Stratum v2 connections from downstream miners (Bitaxe, NerdQAxe+, SRI translator-fronted ASICs) and forwards shares to OCEAN over the encrypted DATUM upstream. The SV1 server already ships on port 23334; SV2 will sit on **port 23335**.

This article is the playbook. It synthesizes the SV2 spec, the SRI reference implementation, the observed wire behavior of real downstream clients, and the prior-art proposal in OCEAN [`datum_gateway#146`](../../raw/notes/2026-06-16-ocean-datum-gateway-sv2-issue-146.md).

## 1. Scope decision

**In scope** (Mining sub-protocol only):

- `SetupConnection` / `.Success` / `.Error` / `Reconnect` / `ChannelEndpointChanged` (Common, ext 0x00)
- `OpenStandardMiningChannel` / `.Success` (0x10 / 0x11)
- `OpenExtendedMiningChannel` / `.Success` (0x13 / 0x14) — **dominant in production**
- `OpenMiningChannel.Error` (0x12)
- `UpdateChannel` / `.Error` (0x16 / 0x17)
- `CloseChannel` (0x18)
- `SetExtranoncePrefix` (0x19)
- `SubmitSharesStandard` / `Extended` / `.Success` / `.Error` (0x1a / 0x1b / 0x1c / 0x1d)
- `NewMiningJob` / `NewExtendedMiningJob` (0x15 / 0x1f)
- `SetNewPrevHash` (0x20) — **mining variant only; not the TDP one**
- `SetTarget` (0x21) — **non-negotiable** for Bitaxe-class devices

**Out of scope**:

- Job Declaration sub-protocol (ext 0x02). datum-rs is not a JD pool; OCEAN's DATUM protocol owns template construction. Reject any client setting `REQUIRES_WORK_SELECTION`.
- Template Distribution sub-protocol (ext 0x03). datum-rs's upstream is DATUM, not bitcoind-via-TDP; no TDP listener.
- `SetCustomMiningJob` (0x22 / 0x23 / 0x24). Tied to JD; reject the `REQUIRES_WORK_SELECTION` flag at SetupConnection.
- `SetGroupChannel` (0x25). Group channels offer no win when the upstream collapses to one DATUM stream anyway.

Total dispatch surface: **~17 message types**. Everything else returns `SetupConnection.Error` with `unsupported-feature`.

The same scope choices appear independently in OCEAN [`datum_gateway#146`](../../raw/notes/2026-06-16-ocean-datum-gateway-sv2-issue-146.md) — convergent evidence the surface is right.

## 2. Wire layer

### Framing

6-byte header per [[sv2-message-types|Message Types]] ([Message Types](../references/sv2-message-types.md)):

```
extension_type U16 || msg_type U8 || msg_length U24 (LE) || payload
```

Bit 15 of `extension_type` is `channel_msg`; when set, first 4 payload bytes are `channel_id U32`.

### Encoding

All multi-byte integers little-endian. Use `binary_sv2` from SRI rather than rolling our own — the spec is too ambiguous in spots (per [[sjors-sv2-noise-critique|Sjors' Delving Bitcoin post]] ([Sjors' critique](../concepts/sv2-noise-handshake.md))) to reimplement safely.

### Byte-order trap (the dominant interop bug)

Per spec §5.3.1 all `U256` fields **on the wire are little-endian**. The bug class: implementations send big-endian targets / max_targets / prev hashes, channel opens, miner mines silently, **zero submits**.

Sites that must be LE on wire:

| Site | Direction |
|------|-----------|
| `OpenStandardMiningChannel.max_target` | C→S |
| `OpenStandardMiningChannelSuccess.target` | S→C |
| `OpenExtendedMiningChannel.max_target` | C→S |
| `OpenExtendedMiningChannelSuccess.target` | S→C |
| `SetTarget.maximum_target` | S→C |
| `SetNewPrevHash.prev_hash` (mining variant) | S→C |

Regression-test these six sites. See [[esp-miner-issue-1758-sv2-byte-order-debugging|ESP-Miner #1758]] ([details](../../raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md)).

## 3. Noise handshake

Pattern: `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`. See [[sv2-noise-handshake|SV2 Noise Handshake]] ([details](../concepts/sv2-noise-handshake.md)).

Three acts:

```
-> e
<- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
```

Operationally:

- Persist a long-lived **authority keypair** in datum-rs config (Schnorr / x-only).
- The pool's **server static key** is signed by the authority; the signed cert (`version, valid_from, not_valid_after, sig`) is generated at startup and rotated periodically.
- Publish the authority pubkey base58 as `[0x01,0x00] || x_only_pubkey[32]` so miners can pin it per-pool.
- Use SRI's `noise-sv2` crate. **Do not roll our own.** Pin a known-good rev (current crate version `noise_sv2 1.0.0`, on SRI `main`).
- Validate `cert_validity_sec` config input: cap at 1 year (31_536_000) to dodge the [[sri-issue-2103-noise-responder-overflow|`u32` overflow class]] ([details](../../raw/notes/2026-06-16-sri-issue-2103-noise-responder-overflow.md)).

NTP-synced clock is a **hard prerequisite** (cert validity is absolute Unix timestamps). Document this in the operator runbook.

## 4. Channel model

datum-rs supports both [[sv2-channel-types|channel types]] ([details](../concepts/sv2-channel-types.md)):

- **Standard** — fixed `extranonce_prefix`, server pre-computes `merkle_root`, server emits `NewMiningJob`. Suits Bitaxe (per [[bitaxe-esp-miner-pr-1553-sv2-merge|ESP-Miner v2.14.0]] ([details](../../raw/repos/2026-06-16-bitaxe-esp-miner-pr-1553-sv2-merge.md))).
- **Extended** — miner-rollable extranonce, server emits `merkle_path` + `coinbase_tx_prefix/suffix`, server emits `NewExtendedMiningJob`. **Default in NerdQAxe+ and SRI translator** — i.e. the dominant downstream-client form.

`channel_id` namespace is per-connection (a single TCP socket can open many channels).

A channel registry behind a `Mutex<HashMap<u32, ChannelState>>` (already scaffolded in `crates/datum-stratum-sv2/src/lib.rs`) is the right shape — it mirrors SRI's `ExtendedChannel<DefaultJobStore<…>>` shape closely enough to swap in the SRI types later.

## 5. Extranonce bridge

DATUM upstream expects a flat 12-byte extranonce. SRI's reference Pool partitions a 20-byte total. See [[sv2-extranonce-hierarchy|SV2 Extranonce Hierarchy]] ([details](../concepts/sv2-extranonce-hierarchy.md)).

datum-rs partitions:

```
local_prefix     = 0 bytes
local_index      = 2 bytes  // up to 65,536 channels per server
rollable_extranonce = 10 bytes
total            = 12 bytes
```

Already implemented as `ExtranonceBridge` (`crates/datum-stratum-sv2/src/lib.rs:31`).

Allocation is RAII: the prefix slot is freed when the channel state drops. Match SRI's `AllocatedExtranoncePrefix` shape.

## 6. Job factory and lifecycle

The SRI Pool drives `NewExtendedMiningJob` from `NewTemplateTdp`. datum-rs's upstream is DATUM, which already supplies:

- `prev_hash`, `nbits`, `min_ntime`, `height`
- The full coinbase blob from coinbaser
- The merkle branch list

We can either:

1. **Synthesize TDP equivalents** and call SRI's `ExtendedChannel::on_new_template` / `on_set_new_prev_hash`. Pro: aligns with SRI's state machine. Con: extra translation layer.
2. **Bypass** and emit `NewExtendedMiningJob` + `SetNewPrevHash` directly using a thin job factory. Pro: smaller dependency surface, no TDP types pulled in. Con: must mirror SRI's job-id allocation and stale-job invalidation logic by hand.

Recommend option 2. The DATUM bridge already builds `coinb1`/`coinb2` for SV1; reuse that to fill `coinbase_tx_prefix` / `coinbase_tx_suffix` for SV2 — they are the same conceptual split with different framing.

Job ring: `InMemoryJobStore::new_eight_job_ring()` already in `crates/datum-stratum-sv2/src/lib.rs:186` matches the C reference's 8-slot capacity.

## 7. SetTarget / vardiff

- `SetTarget` is the **only** vardiff knob in SV2. There is no `mining.set_difficulty` analog.
- Target is an **absolute U256 hash threshold** (LE on wire), not a multiplier.
- Bitaxe-class devices (1.3 TH/s) lock against initial target if `SetTarget` never fires; matches the OCEAN `datum_gateway#146` author's deferral, but that author's only test client was `cpuminer` which doesn't care.
- datum-rs already implements per-miner SV1 vardiff. Port the same logic — same `target_shares_min` and ×2/÷2 floor — into a SetTarget emitter on the SV2 side. The conversion is `target = max_target / difficulty`.
- Vardiff target: 6 shares/min/client (matches DMND production). Configurable.

## 8. Share validation

Reuse the existing share validator. The SV1 path already:

1. Reconstructs the header from `(version, prev_hash, merkle_root, ntime, nbits, nonce)`.
2. Hashes once with `dhash256` and compares against the per-share target.
3. Dedupes via `datum-dupes`.
4. Forwards to DATUM upstream as a `0x27` frame, populating the first-share-of-job 0x01 block on first share for a given job and the first-share-of-coinbase 0x02 block on first share for a given coinbase.

For SV2 `SubmitSharesExtended`:

- The miner provides `(channel_id, sequence_number, job_id, nonce, ntime, version, extranonce)`.
- Look up `(channel_id, job_id)` in the channel registry.
- Reconstruct coinbase from `coinbase_tx_prefix || extranonce_prefix || extranonce || coinbase_tx_suffix`. The `extranonce` size MUST equal the negotiated `extranonce_size`.
- Compute `merkle_root` from `coinbase` + `merkle_path`.
- Run the same hash + dedupe + DATUM 0x27 relay as SV1.

Reply must be **batched** Successes (per `(channel_id, last_sequence_number, new_submits_accepted_count, new_shares_sum)`). Errors are per-share.

## 9. Per-channel error catalogue (what `SubmitShares.Error` codes to send)

The reference list (from `mining_sv2`):

```
ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE
ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE
ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW
ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE
ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID
ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE
ERROR_CODE_SUBMIT_SHARES_STALE_SHARE
ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE
ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED
```

Map our existing internal share-result enum onto these.

## 10. SRI integration: pin via git, not crates.io

SRI's protocol library MSRV is 1.75. datum-rs is on 1.89. **This is not a blocker** — Rust is forward-compatible; consumers on a higher MSRV build SRI just fine. The MSRV pin only constrains *SRI's own contributors* not to introduce features past 1.75.

Cribbed pattern from `stratum-mining/sv2-apps/stratum-apps/Cargo.toml`:

```toml
[dependencies]
stratum-core = { git = "https://github.com/stratum-mining/stratum", rev = "<pin>" }
```

Pin a known-good rev. Re-review at each SRI minor release (current cadence: monthly).

We use only the **library** crates from `stratum`, not the apps from `sv2-apps`. We don't need their pool binary; we have our own. We also don't need `stratum-apps`'s payout module; we have our own coinbaser.

## 11. Stale type names to avoid

The following names appear in older SRI docs / project comments and are **stale** (post-restructure):

| Stale | Current |
|-------|---------|
| `roles_logic_sv2` | split into `parsers_sv2`, `handlers_sv2`, `channels_sv2` |
| `ChannelFactory` | per-channel `JobFactory` in `server::jobs::factory` |
| `DefaultJobStore<ExtendedJob>` | `JobStore` trait + default impl in `server::jobs::job_store` |
| `ParseDownstreamMiningMessages` | `HandleMiningMessagesFromClientAsync` in `handlers_sv2::mining` |

The comment in `crates/datum-stratum-sv2/src/lib.rs` referring to `DefaultJobStore<ExtendedJob>` should be updated.

## 12. Real downstream clients to test against

- **Bitaxe v2.14.0+** — Standard channel, Noise NX. Validated on BM1370/1368/1366/1397.
- **NerdQAxe+** — Extended channel, Noise NX with libsecp256k1.
- **SRI translator (`translator_sv2`)** — Extended channel, the dominant production form. Will be the bulk of real connections.
- **DMND pool's reference miner** — none ships standalone; DMND expects miners to use SRI translator.
- **SRI `mining_device`** (sv2-apps `integration_tests_sv2` crate, `mining_device` binary) — native CPU-side SV2 client, opens Standard channel by default. **This is what `tests/e2e_mining_device.rs` exercises today** (feature-gated `e2e`). Useful for CI; not a real miner.
- **mujina** (`256foundation/mujina`, [PR #65](https://github.com/256foundation/mujina/pull/65), branch `feature/sv2-support`) — open-source mining firmware adding native SV2 via SRI's `stratum-apps`. Extended channel only. Has a first-class CPU backend (`MUJINA_CPUMINER_THREADS=1` + `MUJINA_POOL_FORCED_RATE`) plus real-ASIC support on Bitaxe Gamma. **Wait for #65 to merge to `main` before adding a second e2e test against it** — the PR is currently a draft, gets force-pushed during rebases, and a duplicate-share fix may rewrite share-handling in a follow-up. Once merged, mujina is a strict superset of `mining_device` for our purposes: same `stratum-apps` lineage but a different consumer pattern (custom dispatcher, real-deployed-miner reconnect logic, RFC-1982 sequence-number handling), and the same binary that runs against datum-rs in CI also runs on a Bitaxe attached over USB. Estimated integration effort post-merge: 3-5 dev-days. See `.wiki/raw/notes/2026-06-18-mujina-sv2-pr-65-research.md` (to be ingested when revisited) for the full architectural breakdown.

Author tested against the SRI reference pool at `75.119.150.111:3333` (authority pubkey `9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72`). datum-rs SV2 listener should publish a similar bench-test pubkey for community testing.

## 13. Risks and known footguns

| Risk | Mitigation |
|------|-----------|
| Spec ambiguity in Noise framing (Sjors) | Use SRI `noise-sv2` verbatim; pin rev. |
| `cert_validity_sec` overflow DoS | Cap at 1 year in config validation. |
| Byte-order bug at the six U256 sites | Add a wire-snapshot regression test per site. |
| Bitaxe-class devices locked at initial target | `SetTarget` is non-negotiable on day one. |
| SRI breaking-change cadence (channels_sv2 7.0.0 dropped reference getters) | Re-review at each SRI minor release; keep our wrapper layer thin. |
| Channels_sv2 share-validation panic after `on_set_new_prev_hash` in custom-work mode (PR #2156) | We don't use custom-work mode (no JD); not exposed. |
| Two protocols sharing one outbound `commands_tx` need matching send semantics — `try_send` on one side silently drops while the other backpressures. | Both SV1 and SV2 must use `send().await`. See lessons-learned 2026-06-18 §1. |
| Echoing client-supplied `max_target` without an upper-bound clamp lets a malicious client peg the target to 2^256-1. | Two-layer defense: gate at OpenChannel (reject low `nominal_hash_rate`) + clamp at every `SetTarget` emission. See lessons-learned 2026-06-18 §2. |
| `on_template_update` rotating job_id on every TemplateState change (including coinbase-only changes) breaks active in-flight shares with `invalid-job-id`. | Only emit `SetNewPrevHash` when `prev_hash` bytes actually change. See lessons-learned 2026-06-18 §3. |
| `validate_*_share` returning `invalid-job-id` for past-job submissions (instead of `stale-share`) misleads accounting. | Consult `get_past_job` after active-job miss; classify as `Stale`. See lessons-learned 2026-06-18 §4. |

## See Also

- [[sv2-mining-protocol|SV2 Mining Protocol]] ([SV2 Mining Protocol](../concepts/sv2-mining-protocol.md)) — message-by-message reference.
- [[sv2-noise-handshake|SV2 Noise Handshake]] ([SV2 Noise Handshake](../concepts/sv2-noise-handshake.md)) — handshake details and cert format.
- [[sv2-channel-types|SV2 Channel Types]] ([SV2 Channel Types](../concepts/sv2-channel-types.md)) — Standard / Extended / Group.
- [[sv2-extranonce-hierarchy|SV2 Extranonce Hierarchy]] ([SV2 Extranonce Hierarchy](../concepts/sv2-extranonce-hierarchy.md)) — partitioning across pool / channel / miner.
- [[sri-crate-map|SRI Crate Map]] ([SRI Crate Map](../references/sri-crate-map.md)) — what each `*_sv2` crate provides.
- [[sv2-message-types|SV2 Message Types]] ([SV2 Message Types](../references/sv2-message-types.md)) — numeric IDs.

## Sources

- [SV2 Spec Ch.4: Noise](../../raw/papers/2026-06-16-sv2-spec-04-noise-handshake.md) — handshake & cert format.
- [SV2 Spec Ch.5: Mining Protocol](../../raw/papers/2026-06-16-sv2-spec-05-mining-protocol.md) — channel types, jobs, shares.
- [SV2 Spec Ch.8: Message Types](../../raw/papers/2026-06-16-sv2-spec-08-message-types.md) — dispatch table.
- [SRI stratum repo](../../raw/repos/2026-06-16-sri-stratum-mining-stratum.md) — MSRV, restructure, current crate map.
- [SRI sv2-apps Pool ChannelManager](../../raw/repos/2026-06-16-sri-pool-channel-manager-impl.md) — reference Pool-toward-miner impl.
- [Bitaxe ESP-Miner PR #1553](../../raw/repos/2026-06-16-bitaxe-esp-miner-pr-1553-sv2-merge.md) — first widely-shipped native SV2 miner client.
- [OCEAN datum_gateway #146](../../raw/notes/2026-06-16-ocean-datum-gateway-sv2-issue-146.md) — parallel C-side SV2 proposal.
- [ESP-Miner #1758](../../raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md) — byte-order interop trap.
- [Sjors / Delving Bitcoin Noise critique](../../raw/notes/2026-06-16-delvingbitcoin-sjors-sv2-noise-bip324-413.md) — spec ambiguity.
- [SRI #2103 Noise responder overflow](../../raw/notes/2026-06-16-sri-issue-2103-noise-responder-overflow.md) — cert_validity_sec footgun.
