---
title: "SRI pool_sv2 mining_message_handler — port reference for datum-rs"
category: reference
sources:
  - raw/repos/2026-06-16-sri-pool-mining-message-handler.md
  - raw/repos/2026-06-16-sri-pool-channel-manager-impl.md
created: 2026-06-16
updated: 2026-06-16
tags: [sri, sv2, pool, mining-message-handler, port-plan, dispatch]
aliases: ["pool mining handler", "HandleMiningMessagesFromClientAsync"]
confidence: high
volatility: hot
verified: 2026-06-16
summary: "Concrete handler-by-handler porting plan for the SV2 client-message surface. Every method datum-rs's `ChannelManager` needs to implement on `HandleMiningMessagesFromClientAsync`, with SRI's reference behavior and where datum-rs diverges."
---

# SRI pool_sv2 mining_message_handler — port reference

> The exact dispatch logic the [[sv2-downstream-architecture|datum-rs SV2 server]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) must mirror toward downstream miners. SRI's reference impl is `pool-apps/pool/src/lib/channel_manager/mining_message_handler.rs` (1199 lines). This page distills the trait surface, the success/error paths per handler, and the points where datum-rs diverges.

## The trait

```rust
impl HandleMiningMessagesFromClientAsync for ChannelManager {
    type Error = PoolError<…>;

    fn get_channel_type_for_client(&self, _) -> SupportedChannelTypes;
    fn is_work_selection_enabled_for_client(&self, _) -> bool;
    fn is_client_authorized(&self, _, _user_identity: &Str0255) -> Result<bool, _>;
    fn get_negotiated_extensions_with_client(&self, client_id) -> Result<Vec<u16>, _>;

    async fn handle_close_channel(...);
    async fn handle_open_standard_mining_channel(...);
    async fn handle_open_extended_mining_channel(...);
    async fn handle_submit_shares_standard(...);
    async fn handle_submit_shares_extended(...);
    async fn handle_update_channel(...);
    async fn handle_set_custom_mining_job(...);
}
```

That is the **entire client-side surface**. Server→client messages (`NewMiningJob`, `SetTarget`, `Reconnect`, etc.) are **emitted** from these handlers and from independent timer / template-update tasks; they are not in this trait.

## datum-rs config of the four "selector" methods

| Method | SRI returns | datum-rs returns | Why |
|--------|-------------|------------------|-----|
| `get_channel_type_for_client` | `SupportedChannelTypes::GroupAndExtended` | `SupportedChannelTypes::StandardAndExtended` | No groups — DATUM upstream is one stream. |
| `is_work_selection_enabled_for_client` | `true` | **`false`** | datum-rs is not a JD pool. |
| `is_client_authorized` | `Ok(true)` | Reuse SV1 `username` → BIP-style address parser; reject malformed. | We can require a payout address. |
| `get_negotiated_extensions_with_client` | TLV-aware | `Ok(vec![])` | We don't ship any SV2 extension on day one. |

## Handler-by-handler porting plan

### `handle_close_channel`

Input: `CloseChannel { channel_id, reason_code }`.

Action: remove `channel_id` from the standard/extended channel maps; drop `VardiffState` keyed by `(downstream_id, channel_id)`. **No reply** is required.

datum-rs: direct port. Free the extranonce-prefix slot via the RAII `AllocatedExtranoncePrefix` drop.

### `handle_open_standard_mining_channel`

SRI flow:

1. Authorize.
2. Allocate prefix via `extranonce_allocator.allocate_standard()`.
3. `StandardChannel::new_for_pool(...)`.
4. Push `Mining::OpenStandardMiningChannelSuccess { request_id, channel_id, target.to_le_bytes(), extranonce_prefix, group_channel_id }`.
5. Immediately push `Mining::NewMiningJob` (server pre-computes `merkle_root`) and `Mining::SetNewPrevHash`.

datum-rs: direct port. Bitaxe v2.14.0+ uses Standard, so this path matters. Server pre-computes `merkle_root` from the cached DATUM template + the channel's fixed prefix.

### `handle_open_extended_mining_channel` (the centerpiece)

SRI's success path (lines 264-552 of [the source](../../raw/repos/2026-06-16-sri-pool-mining-message-handler.md)):

1. **Allocate extranonce_prefix**: `extranonce_allocator.allocate_extended(requested_min_rollable_extranonce_size)`.
2. Resolve user identity (SRI parses solo/donate strings; datum-rs reuses existing username logic).
3. **Mint a `channel_id`** atomically.
4. `ExtendedChannel::new_for_pool(channel_id, user_identity, extranonce_prefix, requested_max_target, nominal_hash_rate, /*version_rolling=*/true, CLIENT_SEARCH_SPACE_BYTES, share_batch_size, shares_per_minute, pool_tag_string)`.
5. Push `Mining::OpenExtendedMiningChannelSuccess { request_id, channel_id, target: target.to_le_bytes().into(), extranonce_prefix, extranonce_size, group_channel_id }`.
6. **If client doesn't require custom work**, immediately push:
   - `Mining::NewExtendedMiningJob(future_extended_job_message)` — derived from `last_future_template`.
   - `Mining::SetNewPrevHash { channel_id, job_id, prev_hash, min_ntime, nbits }` — activates the future job.
7. Insert into `extended_channels`; create a `VardiffState::new()` keyed by `(downstream_id, channel_id)`.

Error codes (string constants from `mining_sv2`):

- `ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE`
- `ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE`
- `ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY`
- `ERROR_CODE_OPEN_MINING_CHANNEL_EXTENDED_CHANNELS_NOT_SUPPORTED_FOR_STANDARD_JOBS`

datum-rs: port verbatim, but with our 12-byte extranonce ([[sv2-extranonce-hierarchy|partition](../concepts/sv2-extranonce-hierarchy.md)) and our DATUM-derived `last_future_template` substitute. Skip the SRI `PayoutMode` parsing.

### `handle_submit_shares_extended`

The dispatch loop (lines 732-939 of [the source](../../raw/repos/2026-06-16-sri-pool-mining-message-handler.md)):

```rust
let res = extended_channel.validate_share(msg.clone());
vardiff.increment_shares_since_last_update();

match res {
    Ok(ShareValidationResult::Valid(share_hash)) => {
        if share_accounting.should_acknowledge() {
            // emit batched SubmitSharesSuccess { last_sequence_number, accepted_count, shares_sum }
        }
    }
    Ok(ShareValidationResult::BlockFound(share_hash, template_id, coinbase)) => {
        // 💰 Block found
        if let Some(template_id) = template_id {
            // Route to upstream: TemplateDistribution::SubmitSolution { template_id, version, ntime, nonce, coinbase_tx }
        }
        // Always send a success per-share at this moment too
    }
    Err(ShareValidationError::Invalid(code))
    | Err(...Stale)
    | Err(...InvalidJobId)
    | Err(...DoesNotMeetTarget)
    | Err(...DuplicateShare)
    | Err(...BadExtranonceSize)
    | Err(...VersionRollingNotAllowed) => {
        // emit SubmitSharesError { channel_id, sequence_number, error_code: code.to_string() }
    }
}
```

Three points worth pinning:

1. **`extended_channel.validate_share(msg)` does the full validation** — header reconstruction, hash, dupe, target, stale. datum-rs can either call `ExtendedChannel::validate_share` directly (if we own one) or replicate.
2. **Successes are batched**, gated by `share_accounting.should_acknowledge()`. We do **not** send a Success per share — only at batch boundaries.
3. **`BlockFound` returns the full coinbase**. SRI routes it to a TDP `SubmitSolution`. **datum-rs routes it to (a) DATUM `0x27` with `flags |= 1` and (b) `datum-submitblock`** — the existing block-found pathway. This closes the `flags |= 1` gap noted in the README.

`SubmitSharesStandard` is identical except the share carries no `extranonce`.

### `handle_update_channel`

Input: `UpdateChannel { channel_id, nominal_hash_rate, maximum_target }`.

SRI flow:

1. Lookup channel (Standard or Extended map).
2. `channel.update_channel(new_nominal_hash_rate, Some(requested_maximum_target))`.
3. On error: `Mining::UpdateChannelError { channel_id, error_code: "update-channel-invalid-nominal-hashrate" }` or `…-invalid-channel-id`.
4. On success: `channel.get_target() → SetTarget { channel_id, maximum_target: target.to_le_bytes() }`.

This is the **client-driven** vardiff path. The server's own vardiff loop separately pushes `SetTarget` based on observed share rate; both paths must coexist.

datum-rs: direct port.

### `handle_set_custom_mining_job` — stub

Tied to JD. datum-rs **disables work selection** in `is_work_selection_enabled_for_client`, so the `REQUIRES_WORK_SELECTION` flag is rejected at `SetupConnection`. This handler is unreachable; stub `unreachable!()` or return an `unsupported-feature` error defensively.

## LE-on-wire as a code pattern

Every U256 going onto the wire is `target.to_le_bytes()`. Every U256 coming off the wire is `Target::from_le_bytes(msg.max_target.inner_as_ref().try_into().unwrap())`. The SRI source is the **canonical example** for the byte-order rule from [[sv2-mining-protocol|the Mining Protocol concept]] ([Mining Protocol](../concepts/sv2-mining-protocol.md)). Copy the pattern verbatim.

## Where datum-rs diverges from SRI structurally

1. **No upstream Template Provider**. SRI synthesizes `NewExtendedMiningJob` from a `NewTemplateTdp` cached in `last_future_template`. datum-rs caches a DATUM-derived job state and synthesizes the equivalent.
2. **No JD path**. Drop `jd_server_sv2::SetCustomMiningJobResponse` entirely.
3. **No SRI `PayoutMode`**. Reuse our existing username/address logic.
4. **Smaller extranonce**: 12 bytes total vs SRI's 20 ([[sv2-extranonce-hierarchy|details](../concepts/sv2-extranonce-hierarchy.md)).
5. **`SupportedChannelTypes::StandardAndExtended`** instead of `GroupAndExtended`.
6. **Block-found path** routes to `datum-submitblock` + DATUM `0x27` `flags|=1`, not to TDP `SubmitSolution`.

## See Also

- [[sv2-downstream-architecture|SV2 Downstream Architecture]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) — the playbook this handler implements.
- [[sv2-mining-protocol|SV2 Mining Protocol]] ([SV2 Mining Protocol](../concepts/sv2-mining-protocol.md)) — message semantics.
- [[sri-crate-map|SRI Crate Map]] ([SRI Crate Map](sri-crate-map.md)) — the imports above.
- [[sv2-extranonce-hierarchy|SV2 Extranonce Hierarchy]] ([SV2 Extranonce Hierarchy](../concepts/sv2-extranonce-hierarchy.md)) — how prefixes get allocated.

## Sources

- [SRI sv2-apps mining_message_handler.rs](../../raw/repos/2026-06-16-sri-pool-mining-message-handler.md) — the file itself, ingested.
- [SRI sv2-apps Pool ChannelManager](../../raw/repos/2026-06-16-sri-pool-channel-manager-impl.md) — surrounding state and config.
