---
title: "Plan: Stratum v2 listener for datum-rs"
type: plan
format: roadmap
sources:
  - wiki/topics/sv2-downstream-architecture.md
  - wiki/references/sri-pool-mining-handler.md
  - wiki/references/sri-crate-map.md
  - wiki/references/sv2-message-types.md
  - wiki/concepts/sv2-mining-protocol.md
  - wiki/concepts/sv2-noise-handshake.md
  - wiki/concepts/sv2-channel-types.md
  - wiki/concepts/sv2-extranonce-hierarchy.md
  - raw/repos/2026-06-16-sri-pool-mining-message-handler.md
  - raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md
generated: 2026-06-16
---

# Plan: Stratum v2 listener for datum-rs

> Generated from the local datum-rs research wiki (8 articles, 11 sources consulted). Roadmap format.

## Executive summary

Stand up an SV2 server on `cfg.stratum_v2.listen_port` (default `23335`) that accepts both Standard and Extended channels from downstream miners and bridges shares to OCEAN over the existing DATUM upstream. The listener consumes a shared `TemplateState` (refactored out of the SV1 path) so a single prevhash/job pipeline drives both protocols. Implementation depends on SRI's `stratum-core` via a pinned git rev — mirroring `sv2-apps` — and reuses `ExtendedChannel::validate_share` and `noise_sv2` rather than reimplementing them. Block-found wires `flags|=1` + `datum-submitblock` from day one (closing the README-flagged gap for SV1 too). Ship-bar: golden vectors on the six LE U256 sites, in-process loopback against `translator_sv2`, and one real-device run against an ESP-Miner v2.14.0 or SRI translator on a real LAN.

## Architecture decisions

### Decision 1: Channel scope = Standard + Extended

**Context**: Per [[sv2-channel-types|Channel Types]] ([Channel Types](../wiki/concepts/sv2-channel-types.md)), Bitaxe v2.14.0+ ships Standard while NerdQAxe+ and the SRI translator default to Extended. Per [[sv2-mining-protocol|Mining Protocol]] ([Mining Protocol](../wiki/concepts/sv2-mining-protocol.md)) §SetupConnection flags, a downstream can set `REQUIRES_STANDARD_JOBS`.

**Options considered**:
- Extended only — covers SRI translator + NerdQAxe+; defers Bitaxe.
- Both Standard and Extended — full coverage; ~25% more code.
- Standard only — small surface but skips the dominant production form.

**Decision**: Both. Standard adds one extra handler (`handle_open_standard_mining_channel`, `handle_submit_shares_standard`) plus a server-side `merkle_root` precompute step; the rest of the pipeline (Noise, framing, dispatch, vardiff, share-relay) is shared.

**Consequences**: Bitaxe v2.14.0+ works against datum-rs without a translator. The server must precompute `merkle_root` for Standard channels per-job-per-channel (cheap; the merkle path is short).

### Decision 2: SRI dependency = git rev pin of `stratum-core`

**Context**: Per [[sri-crate-map|SRI Crate Map]] ([SRI Crate Map](../wiki/references/sri-crate-map.md)), SRI lib MSRV is 1.75 and apps MSRV is 1.85, both compatible with datum-rs's 1.89 (Rust is forward-compatible). `sv2-apps` ships the canonical pattern: `stratum-core = { git = "https://github.com/stratum-mining/stratum", branch = "main" }`.

**Options considered**:
- Git rev pin of `stratum-core` (umbrella crate that re-exports `channels_sv2`, `handlers_sv2`, `mining_sv2`, `noise_sv2`, `parsers_sv2`, `framing_sv2`, `binary_sv2`, `codec_sv2`, `extensions_sv2`).
- Slim hand-rolled: `mining_sv2` types only via crates.io, reimplement the rest (~3× effort, owns Noise reimplementation — explicitly discouraged by [[sv2-noise-handshake|Noise Handshake]] given spec ambiguity).
- Vendor a forked SRI subset (creates a maintenance burden).

**Decision**: Git rev pin. Use a specific commit, not `branch = "main"`, for reproducibility. Re-review at each SRI minor release (cadence: monthly).

**Consequences**: One workspace-level Cargo dep replaces today's empty `crates/datum-stratum-sv2` dependency tree. Stale type names in `crates/datum-stratum-sv2/src/lib.rs` (`DefaultJobStore<ExtendedJob>`, `ChannelFactory`, `ParseDownstreamMiningMessages`) get replaced with their current equivalents (`JobStore`, `JobFactory`, `HandleMiningMessagesFromClientAsync`). The MSRV-blocker comment in that file is wrong and gets updated (Rust is forward-compatible).

### Decision 3: Topology = Shared `TemplateState` behind a `watch`/`broadcast`

**Context**: Today SV1 owns the GBT→template→`mining.notify` pipeline. SV2 needs the same prevhash, job state, coinbase split, and merkle path. Per [[sv2-downstream-architecture|the playbook]] ([the playbook](../wiki/topics/sv2-downstream-architecture.md)) §6, datum-rs synthesizes `NewExtendedMiningJob` + `SetNewPrevHash` directly (option 2 in the playbook) rather than going through SRI's TDP types.

**Options considered**:
- Shared `TemplateState` watched by both listeners.
- SV2 polls SV1's `mining.notify` cache (racier on prevhash transitions).
- Independent SV2 path consuming GBT/DATUM in parallel (doubles upstream-watch cost).

**Decision**: Shared. Introduce `datum-template-state` (or extend `datum-blocktemplates`) to expose:

```rust
pub struct TemplateState {
    pub prev_hash: [u8; 32],
    pub height: u32,
    pub nbits: u32,
    pub min_ntime: u32,
    pub coinbase_outputs: Vec<TxOut>,    // single source of truth, already in datum-coinbaser
    pub coinb1: Vec<u8>,                  // SV1 split  → reused by SV2 as coinbase_tx_prefix
    pub coinb2: Vec<u8>,                  // SV1 split  → reused by SV2 as coinbase_tx_suffix
    pub merkle_branches: Vec<[u8; 32]>,   // sibling-path → SV2 merkle_path
    pub version: u32,
    pub job_id_seed: u64,
}
```

Distributed via `tokio::sync::watch::Sender<Arc<TemplateState>>` from the GBT/DATUM-driver task. Both SV1 and SV2 subscribe.

**Consequences**: One refactor of SV1's existing assembler to read from `TemplateState` instead of building inline. Negligible CPU cost; the data is already computed per-template. Both protocols transition prevhash atomically because the watch channel hands them the same `Arc`.

### Decision 4: Block-found = wire `flags|=1` + `datum-submitblock` on day one

**Context**: `crates/datum-protocol`'s `0x27` codec already reserves the `flags` byte but `flags |= 1` is not yet wired (per `README.md` "What does not work yet"). SRI's [[sri-pool-mining-handler|mining handler]] ([port plan](../wiki/references/sri-pool-mining-handler.md)) returns full coinbase from `validate_share` on `BlockFound`, ready to route.

**Options considered**:
- Wire it now from the SV2 share path; SV1 inherits the plumbing.
- Defer.

**Decision**: Wire it now. This closes a long-standing gap and has a single owner (the share-relay).

**Consequences**: First SV2 share that meets network target sets `flags |= 1` on the DATUM `0x27` frame and triggers `datum-submitblock` against bitcoind. Same plumbing reused by SV1.

### Decision 5: Test bar = golden vectors + loopback + 1 real device

**Context**: Per [[esp-miner-issue-1758-sv2-byte-order-debugging|ESP-Miner #1758]] ([details](../raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md)) the LE-U256 byte-order trap is the dominant in-the-wild interop bug. Per [[sri-issue-2103-noise-responder-overflow|SRI #2103]] the Noise responder shipped with a trivial DoS the first time it was fuzzed.

**Decision**: Three layers:
1. **Golden vectors**: byte-for-byte snapshot tests for the six LE U256 sites (`OpenStandardMiningChannel.max_target` C→S, `OpenStandardMiningChannelSuccess.target` S→C, `OpenExtendedMiningChannel.max_target` C→S, `OpenExtendedMiningChannelSuccess.target` S→C, `SetTarget.maximum_target` S→C, mining `SetNewPrevHash.prev_hash` S→C) plus the cross-protocol coinbase-sum invariant (already scaffolded as `coinbase_output_sum` in `crates/datum-stratum-sv2/src/lib.rs:276`).
2. **Loopback**: in-process integration test running `translator_sv2` (or a minimal SRI mining-device skeleton) against datum-rs's listener on a tokio runtime; CI-runnable.
3. **One real device**: ESP-Miner v2.14.0+ or an SRI translator on a real LAN, run by the operator pre-tag.

### Decision 6: Out of scope for first ship

- **Job Declaration** (ext 0x02). datum-rs is a custodial-template gateway; reject `REQUIRES_WORK_SELECTION` at SetupConnection. Stub `handle_set_custom_mining_job` with `unreachable!()`.
- **Template Distribution** (ext 0x03). DATUM is the upstream, not bitcoind-via-TDP.
- **Group channels** (msg 0x25). No win when DATUM upstream is one stream.
- **Worker hashrate tracking TLV extension** (`EXTENSION_TYPE_WORKER_HASHRATE_TRACKING`). Negotiated as `vec![]`.
- **Subscribe-extranonce push for SV2** — `SetExtranoncePrefix` (0x19) emission is implemented but only triggered manually; automatic mid-channel re-allocation is deferred.

## Implementation phases

### Phase 1: Refactor — extract shared `TemplateState` (effort: M, ~2-3 days)

**Goal**: Single source of truth for template/job state, watched by both protocols.

**Tasks**:
- [ ] Define `TemplateState` (and `TemplateUpdate` enum: `NewPrevHash`, `NewTemplate`) in `datum-blocktemplates` (or a new `datum-template-state` crate).
- [ ] In `datum-bin`, replace SV1's inline assembly with a `tokio::sync::watch::Sender<Arc<TemplateState>>`. The GBT-driver task (and DATUM `client_config`) writes; SV1's listener subscribes.
- [ ] Move SV1's `coinb1`/`coinb2` split + merkle-branch computation into a function on `TemplateState` so SV2 can call the same.
- [ ] Verify the existing 176+ tests still green.

**Dependencies**: None.

**Validation**: Existing SV1 tests pass unchanged; existing bench against OCEAN beta produces byte-identical `mining.notify` output.

**Wiki grounding**: [[sv2-downstream-architecture|playbook §6 "Job factory and lifecycle"]] ([playbook](../wiki/topics/sv2-downstream-architecture.md)) — the recommendation to bypass SRI's TDP types and emit `NewExtendedMiningJob` directly relies on having job state already in our hands. Coinbase-blob source-of-truth pattern matches `datum-coinbaser`'s existing `Vec<TxOut>` discipline (see top-level `Cargo.toml` workspace comment).

---

### Phase 2: SRI integration scaffolding (effort: S, ~1 day)

**Goal**: Pull SRI types into datum-rs; align names; remove the stale MSRV-blocker comment.

**Tasks**:
- [ ] Add to root `Cargo.toml` workspace deps:
  ```toml
  stratum-core = { git = "https://github.com/stratum-mining/stratum", rev = "<HEAD as of pin>" }
  ```
- [ ] In `crates/datum-stratum-sv2/Cargo.toml`, add `stratum-core = { workspace = true }`.
- [ ] Replace stale references in `crates/datum-stratum-sv2/src/lib.rs`:
  - `DefaultJobStore<ExtendedJob>` → drop our `InMemoryJobStore` if SRI's `JobStore` covers our 8-job ring. Keep ours if its ergonomics differ.
  - Update the doc-comment that says SRI is "gated on an MSRV bump upstream" — Rust is forward-compatible; the real prerequisites are pin + naming alignment.
- [ ] Add a `compile_test` that imports `stratum_core::channels_sv2::server::extended::ExtendedChannel` to confirm the dep resolves.

**Dependencies**: None (parallel with Phase 1).

**Validation**: `cargo check -p datum-stratum-sv2` succeeds; the import compile-test passes.

**Wiki grounding**: [[sri-crate-map|SRI Crate Map]] ([SRI Crate Map](../wiki/references/sri-crate-map.md)) — current versions, MSRV reality, the canonical import block.

---

### Phase 3: Noise listener + `SetupConnection` (effort: M, ~2 days)

**Goal**: A datum-rs SV2 socket that completes Noise NX and `SetupConnection`/`.Success` against `translator_sv2`.

**Tasks**:
- [ ] Add `cfg.stratum_v2`:
  ```json
  {
    "listen_addr": "0.0.0.0",
    "listen_port": 23335,
    "authority_pubkey_path": "...",
    "authority_secret_path": "...",
    "cert_validity_sec": 3600
  }
  ```
  Validate `cert_validity_sec ≤ 31_536_000` (1 year cap to dodge SRI #2103).
- [ ] Bind a tokio listener; per-connection task accepts via `noise_sv2`'s responder (mirror `accept_noise_connection` from `stratum_apps::network_helpers`). Pin `noise_sv2 1.0.0` via the `stratum-core` rev.
- [ ] Generate the authority cert at startup, sign with the authority key (see [[sv2-noise-handshake|Noise Handshake]] ([Noise Handshake](../wiki/concepts/sv2-noise-handshake.md))).
- [ ] Add a `/metrics`-style API row exposing the authority pubkey base58 (`[0x01,0x00] || x_only_pubkey[32]`) so operators can pin it.
- [ ] Implement `SetupConnection` handler:
  - Reject `flags & REQUIRES_WORK_SELECTION` with `SetupConnection.Error("unsupported-feature")`.
  - Accept `REQUIRES_VERSION_ROLLING` (we always allow BIP320 16-bit).
  - Accept `REQUIRES_STANDARD_JOBS` (we'll honor it in Phase 4).
  - Reply `SetupConnection.Success { used_version: 2, flags: 0 }`.

**Dependencies**: Phase 2.

**Validation**:
- Unit: golden frame snapshot of `SetupConnection.Success` bytes.
- Integration: `translator_sv2` pointed at `127.0.0.1:23335` completes Noise + SetupConnection without error.

**Wiki grounding**: [[sv2-noise-handshake|Noise Handshake]] ([Noise Handshake](../wiki/concepts/sv2-noise-handshake.md)) for the cert/handshake details; [[sv2-mining-protocol|Mining Protocol]] §SetupConnection flags for the flag matrix; [[sri-pool-mining-handler|Mining Handler port plan]] ([port plan](../wiki/references/sri-pool-mining-handler.md)) §"datum-rs config of the four selector methods" for the four overrides.

---

### Phase 4: Channel open + first job (effort: L, ~3-5 days)

**Goal**: Both `OpenStandardMiningChannel` and `OpenExtendedMiningChannel` open successfully and the miner receives a `NewMiningJob`/`NewExtendedMiningJob` + `SetNewPrevHash` immediately.

**Tasks**:
- [ ] Implement `ChannelManager` with `Arc<Mutex<HashMap<u32, ChannelState>>>` (already scaffolded in `lib.rs:223`).
- [ ] Implement `HandleMiningMessagesFromClientAsync::{is_client_authorized, get_channel_type_for_client, is_work_selection_enabled_for_client, get_negotiated_extensions_with_client}` per [[sri-pool-mining-handler|port plan]] §"datum-rs config of the four selector methods":
  - `SupportedChannelTypes::StandardAndExtended`
  - `is_work_selection_enabled_for_client = false`
  - `is_client_authorized` reuses SV1's username-parser → BIP-style address.
  - `get_negotiated_extensions_with_client = Ok(vec![])`.
- [ ] Implement `handle_open_extended_mining_channel`:
  - Use the existing `ExtranonceBridge` (12-byte total: 0+2+10) but allocate prefix via `ExtranonceAllocator` from `channels_sv2::extranonce_manager`. Configure: `total_extranonce_len = 12`, `local_prefix=0`, `local_index=2`, `rollable=10`.
  - Build `ExtendedChannel::new_for_pool(channel_id, user_identity, extranonce_prefix, max_target, nominal_hashrate, /*version_rolling=*/true, /*rollable=*/10, share_batch_size, expected_share_per_minute=6.0, pool_tag_string)`.
  - Reply `OpenExtendedMiningChannelSuccess { ..., target: target.to_le_bytes(), ... }`.
  - Synthesize `NewExtendedMiningJob` from current `TemplateState`: set `coinbase_tx_prefix = coinb1`, `coinbase_tx_suffix = coinb2`, `merkle_path = merkle_branches`, `version_rolling_allowed = true`, `min_ntime = None` (future job).
  - Push `SetNewPrevHash` immediately (mining variant 0x20, `prev_hash.to_le_bytes()`).
  - Subscribe the channel to the `TemplateState` watch; send `(NewExtendedMiningJob, SetNewPrevHash)` on every prevhash transition.
- [ ] Implement `handle_open_standard_mining_channel`:
  - Same flow but with a server-side `merkle_root` precompute (`coinbase = coinb1 || extranonce_prefix || coinb2`, then `merkle_root_from_path(coinbase, merkle_branches)`).
  - Reply `OpenStandardMiningChannelSuccess`. Push `NewMiningJob { merkle_root.to_le_bytes() }`.
- [ ] Implement `handle_close_channel` (drop channel, drop vardiff state, free extranonce slot via RAII drop).

**Dependencies**: Phase 1, Phase 3.

**Validation**:
- Unit: golden vectors for `OpenExtendedMiningChannelSuccess` and `OpenStandardMiningChannelSuccess` byte-for-byte. Six U256 LE-on-wire sites snapshot-tested.
- Cross-protocol invariant: SV1 `coinb1/coinb2` + SV2 `coinbase_tx_prefix/coinbase_tx_suffix` produce identical satoshi sums (extend the existing `coinbase_output_sum` test in `crates/datum-stratum-sv2/src/lib.rs:276`).
- Integration: `translator_sv2` opens an Extended channel and receives a job within 5s of connect.

**Wiki grounding**: [[sri-pool-mining-handler|Mining Handler port plan]] §"handle_open_extended_mining_channel" + §"handle_open_standard_mining_channel"; [[sv2-extranonce-hierarchy|Extranonce Hierarchy]] ([Extranonce Hierarchy](../wiki/concepts/sv2-extranonce-hierarchy.md)) for the 12-byte partition; [[esp-miner-issue-1758-sv2-byte-order-debugging|ESP-Miner #1758]] for the LE wire trace.

---

### Phase 5: Share path + vardiff + block-found (effort: L, ~3-4 days)

**Goal**: Shares from a real downstream miner forward to OCEAN over DATUM `0x27`; vardiff converges; first block-meeting-network-target triggers `flags|=1` + `datum-submitblock`.

**Tasks**:
- [ ] Implement `handle_submit_shares_extended`:
  - Look up channel by `msg.channel_id`; fall through to `SubmitSharesError { error_code: "submit-shares-invalid-channel-id" }` if missing.
  - Call `extended_channel.validate_share(msg.clone())`.
  - On `Ok(ShareValidationResult::Valid)`: increment vardiff share count; if `share_accounting.should_acknowledge()`, push batched `SubmitSharesSuccess`. Forward to DATUM as `0x27` reusing the existing relay (the SV1 path's `0x01/0x02` block plumbing applies — first share of job sets 0x01, first share of coinbase sets 0x02).
  - On `Ok(ShareValidationResult::BlockFound { coinbase, .. })`: route the full coinbase to `datum-submitblock` (best-effort `submitblock` against bitcoind) and emit a DATUM `0x27` with `flags |= 1`. Always push a one-share `SubmitSharesSuccess`.
  - On `Err(...)`: map every variant (`Invalid`, `Stale`, `InvalidJobId`, `DoesNotMeetTarget`, `DuplicateShare`, `BadExtranonceSize`, `VersionRollingNotAllowed`) to `SubmitSharesError { channel_id, sequence_number, error_code: <stringified> }` reusing SRI's wire strings.
- [ ] Implement `handle_submit_shares_standard` — same structure, no `extranonce` field.
- [ ] Implement `handle_update_channel`: `channel.update_channel(new_nominal_hashrate, Some(target))` → push `SetTarget { channel_id, maximum_target: target.to_le_bytes() }`.
- [ ] Implement server-driven vardiff: per-channel `VardiffState` updates on observed share rate; emit `SetTarget` with the same ×2/÷2 floor logic the SV1 path already uses (`vardiff_target_shares_min`). Target: 6 shares/min/client.
- [ ] Stub `handle_set_custom_mining_job` with `unreachable!()` (we rejected `REQUIRES_WORK_SELECTION` at SetupConnection).

**Dependencies**: Phase 4.

**Validation**:
- Unit: each `ShareValidationError` arm produces the correct `error_code` string.
- Unit: vardiff loop converges from 8 → 16 → 32 → 64 → 128 against a synthetic hashrate signal.
- Integration: `translator_sv2` mining at a synthetic difficulty submits ≥10 valid shares, all forwarded to a mock DATUM endpoint as `0x27` frames.
- Regtest: a forced solve on regtest exercises the `BlockFound` branch end-to-end (DATUM `flags|=1` + bitcoind `submitblock`).

**Wiki grounding**: [[sri-pool-mining-handler|Mining Handler port plan]] §"handle_submit_shares_extended" + §"handle_update_channel"; [[sv2-mining-protocol|Mining Protocol]] §SetTarget and §"Server share replies"; [[sv2-downstream-architecture|playbook]] §7 (SetTarget/vardiff) + §8 (share validation).

---

### Phase 6: Wire `cfg.stratum_v2` end-to-end + integration test bar (effort: M, ~2-3 days)

**Goal**: `datum-bin` boots both listeners (SV1 on 23334, SV2 on 23335) from one config; the test bar is met.

**Tasks**:
- [ ] In `datum-bin`, accept `cfg.stratum_v2` (gated on a top-level enable flag); spawn the SV2 listener task alongside SV1.
- [ ] Hook the new `TemplateState` watch into both listeners.
- [ ] Hook the SV2 share-relay into the existing DATUM `0x27` codec / `JobTracker` so per-job 0x01 / per-coinbase 0x02 first-share blocks are emitted exactly once across both protocols (do NOT double-emit if both SV1 and SV2 hit the same job/coinbase first-share boundary).
- [ ] Add `/metrics` rows: `sv2_active_channels`, `sv2_shares_accepted`, `sv2_shares_rejected`, `sv2_authority_pubkey_b58`.
- [ ] Update `BENCH_VALIDATION.md` with an SV2 runbook (point a `translator_sv2` at port 23335; expected log lines).
- [ ] **Golden vectors**: byte-for-byte snapshot tests for the six LE U256 sites listed in [[sv2-mining-protocol|Mining Protocol]] §"Wire byte-order rule" plus `OpenExtendedMiningChannelSuccess` and `NewExtendedMiningJob`.
- [ ] **Loopback**: a `tests/sv2_loopback.rs` integration test that boots datum-rs with a mock DATUM upstream, runs `translator_sv2` (or a minimal hand-rolled SRI mining-device skeleton) against it, and asserts a share is accepted.
- [ ] **Real device**: the operator runs ESP-Miner v2.14.0+ or `translator_sv2` against the binary on a real LAN before tagging.
- [ ] Update `crates/datum-stratum-sv2/src/lib.rs` doc-comment to remove the stale MSRV-blocker narrative.

**Dependencies**: Phase 5.

**Validation**:
- Whole-system: a full `cargo run --release -p datum-bin` against OCEAN beta with both ports listening; SV1 miner on 23334 and SV2 translator on 23335 both submit shares forwarded to OCEAN.
- All goldens green; loopback green in CI; one real-device run logged.

**Wiki grounding**: [[esp-miner-issue-1758-sv2-byte-order-debugging|ESP-Miner #1758]] for the byte-order regression seeds; [[sv2-downstream-architecture|playbook]] §12 "Real downstream clients to test against".

## Effort summary

| Phase | Effort | Cumulative |
|-------|--------|-----------|
| 1. Shared `TemplateState` refactor | M (2-3 d) | 3 d |
| 2. SRI integration scaffolding | S (1 d) | 4 d |
| 3. Noise listener + SetupConnection | M (2 d) | 6 d |
| 4. Channel open + first job | L (3-5 d) | 11 d |
| 5. Share path + vardiff + block-found | L (3-4 d) | 15 d |
| 6. Wire `cfg.stratum_v2` + test bar | M (2-3 d) | 18 d |

**Total**: ~13-18 working days for one engineer. Phases 1 and 2 are independent and can run in parallel.

## Risks & mitigations

| # | Risk | Source | Mitigation |
|---|------|--------|-----------|
| 1 | LE-on-wire byte-order bug at one of the six U256 sites — channel opens, miner mines silently, zero submits. | [[esp-miner-issue-1758-sv2-byte-order-debugging\|ESP-Miner #1758]] | Phase 6's golden-vector snapshot tests. Use SRI's `target.to_le_bytes()` / `Target::from_le_bytes(...)` patterns verbatim per [[sri-pool-mining-handler\|port plan]] §"LE-on-wire as a code pattern". |
| 2 | `cert_validity_sec` overflow DoS in Noise responder. | [[sri-issue-2103-noise-responder-overflow\|SRI #2103]] | Cap config input at 31_536_000 (1 year) in Phase 3. Pin a known-good `noise_sv2` rev. |
| 3 | NTP-skewed miners reject the cert. | [[sv2-noise-handshake\|Noise Handshake]] | Document NTP as a hard prerequisite in `BENCH_VALIDATION.md`. Use generous `valid_from = now − 60s`. |
| 4 | SRI breaking-change cadence (channels_sv2 7.0.0 dropped reference getters). | [[sri-crate-map\|SRI Crate Map]] | Pin a specific git rev, not `branch = "main"`. Re-review at each SRI minor release. Keep our wrapper layer thin. |
| 5 | SV1 ↔ SV2 share-relay double-emission of per-job 0x01 / per-coinbase 0x02 first-share blocks. | [[sv2-downstream-architecture\|playbook]] §8 | The shared `JobTracker` (`crates/datum-bin`) already serializes job-id → metadata; extend its sentinel state to span both protocols, not per-protocol. Test with a forced concurrent first-share. |
| 6 | Bitaxe-class miners lock at initial target if `SetTarget` never fires. | [[esp-miner-issue-1758-sv2-byte-order-debugging\|ESP-Miner #1758]] | Phase 5 ships SetTarget on day one; vardiff floor of 8 keeps even slow devices submitting. |
| 7 | Spec ambiguity in Noise framing → custom encoder drift. | [[sv2-noise-handshake\|Noise Handshake]] (Sjors) | Use SRI's `noise-sv2` and `framing-sv2` directly. Do not reimplement. |
| 8 | Stale type names in `crates/datum-stratum-sv2/src/lib.rs` (`DefaultJobStore`, `ChannelFactory`, `ParseDownstreamMiningMessages`) cause confusion when reading SRI source. | This wiki | Phase 2 corrects names + the MSRV-blocker comment. |
| 9 | DATUM upstream protocol changes invalidate the shared `TemplateState` shape. | (DATUM is a closed protocol) | Keep `TemplateState` typed in our own crate; map DATUM messages → `TemplateState` in `datum-protocol`'s consumer task. |

## Open questions

These are the surviving items from the research session's gap list that the plan does not resolve:

1. **OCEAN's stance on `datum_gateway#146`** — the issue is open with one Concept-ACK request and one comment. If OCEAN ships an SV2 endpoint upstream-side first, our work composes; if they invalidate the issue, we ship anyway (datum-rs is a third-party gateway).
2. **Braiins-OS-Plus SV2 client status on Antminer S19/S17** — would expand the validated downstream-client list. Today's plan validates against ESP-Miner v2.14.0 + SRI translator only.
3. **`SetExtranoncePrefix` (0x19) automatic-trigger conditions** — we ship the message but not an automatic re-allocation policy. The followup is a research+phase pair if ever needed.
4. **Hashrate-tracking TLV extension** (`EXTENSION_TYPE_WORKER_HASHRATE_TRACKING`) — explicitly out of scope but worth a follow-up if multi-worker analytics matter.

Run `/wiki:research --local "OCEAN datum_gateway#146 implementation"` if/when OCEAN's branch lands; rerun `/wiki:research --local "Braiins-OS-Plus SV2 client"` if Antminer support becomes a customer ask.

## Sources consulted

- [SV2 Downstream Architecture](../wiki/topics/sv2-downstream-architecture.md) — the spine of every phase.
- [SRI Pool Mining Handler (port plan)](../wiki/references/sri-pool-mining-handler.md) — Phase 4 + Phase 5 dispatch logic, error-code catalogue, the four selector-method overrides.
- [SRI Crate Map](../wiki/references/sri-crate-map.md) — Phase 2 dep pattern, current versions, MSRV reality.
- [SV2 Message Types](../wiki/references/sv2-message-types.md) — the ~17-message dispatch surface scope.
- [SV2 Mining Protocol](../wiki/concepts/sv2-mining-protocol.md) — message semantics, six LE-U256 sites, SetupConnection flag matrix.
- [SV2 Noise Handshake](../wiki/concepts/sv2-noise-handshake.md) — Phase 3 cert format, NTP requirement, overflow trap.
- [SV2 Channel Types](../wiki/concepts/sv2-channel-types.md) — Decision 1 (Standard + Extended both shipped).
- [SV2 Extranonce Hierarchy](../wiki/concepts/sv2-extranonce-hierarchy.md) — Phase 4 partition (`0+2+10`).
- [Raw: SRI pool mining_message_handler.rs](../raw/repos/2026-06-16-sri-pool-mining-message-handler.md) — the file Phase 4 + 5 mirrors.
- [Raw: ESP-Miner #1758](../raw/notes/2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md) — Phase 6 golden-vector seeds.
- [Raw: SRI #2103 Noise responder overflow](../raw/notes/2026-06-16-sri-issue-2103-noise-responder-overflow.md) — Phase 3 cert_validity_sec cap.
- [Raw: Sjors / Delving Bitcoin](../raw/notes/2026-06-16-delvingbitcoin-sjors-sv2-noise-bip324-413.md) — "use SRI noise-sv2 directly" rationale.
