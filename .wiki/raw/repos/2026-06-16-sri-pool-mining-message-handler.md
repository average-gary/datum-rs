---
title: "SRI sv2-apps pool mining_message_handler.rs (1199 lines)"
source: "https://github.com/stratum-mining/sv2-apps/blob/main/pool-apps/pool/src/lib/channel_manager/mining_message_handler.rs"
type: repos
ingested: 2026-06-16
tags: [sri, sv2, pool, mining-message-handler, reference-impl, dispatch]
summary: "The exact dispatch logic the datum-rs SV2 server must mirror. Implements `HandleMiningMessagesFromClientAsync` for `ChannelManager`. 7 handlers: close, open standard/extended, submit standard/extended, update_channel, set_custom_mining_job."
---

# pool_sv2 mining_message_handler.rs

## Top-of-file imports (the canonical SRI imports for a Pool toward miners)

```rust
use stratum_apps::stratum_core::{
    binary_sv2::Str0255,
    bitcoin::Target,
    channels_sv2::{
        server::{
            error::{ExtendedChannelError, StandardChannelError},
            extended::ExtendedChannel,
            share_accounting::{ShareValidationError, ShareValidationResult},
            standard::StandardChannel,
        },
        Vardiff, VardiffState,
    },
    extensions_sv2::{
        UserIdentity, EXTENSION_TYPE_WORKER_HASHRATE_TRACKING, TLV_FIELD_TYPE_USER_IDENTITY,
    },
    handlers_sv2::{HandleMiningMessagesFromClientAsync, SupportedChannelTypes},
    mining_sv2::*,
    parsers_sv2::{Mining, TemplateDistribution, Tlv, TlvField},
    template_distribution_sv2::SubmitSolution,
};
```

## Trait surface

```rust
impl HandleMiningMessagesFromClientAsync for ChannelManager {
    type Error = PoolError<error::ChannelManager>;

    fn get_channel_type_for_client(&self, _client_id: Option<usize>) -> SupportedChannelTypes;
    fn is_work_selection_enabled_for_client(&self, _client_id: Option<usize>) -> bool;
    fn is_client_authorized(&self, _client_id, _user_identity: &Str0255) -> Result<bool, _>;
    fn get_negotiated_extensions_with_client(&self, client_id) -> Result<Vec<u16>, _>;

    async fn handle_close_channel(&mut self, client_id, msg: CloseChannel<'_>, _tlv) -> _;
    async fn handle_open_standard_mining_channel(&mut self, …, msg: OpenStandardMiningChannel<'_>, _tlv) -> _;
    async fn handle_open_extended_mining_channel(&mut self, …, msg: OpenExtendedMiningChannel<'_>, _tlv) -> _;
    async fn handle_submit_shares_standard(&mut self, …, msg: SubmitSharesStandard<'_>, tlv) -> _;
    async fn handle_submit_shares_extended(&mut self, …, msg: SubmitSharesExtended<'_>, tlv) -> _;
    async fn handle_update_channel(&mut self, …, msg: UpdateChannel<'_>, _tlv) -> _;
    async fn handle_set_custom_mining_job(&mut self, …, msg: SetCustomMiningJob<'_>, _tlv) -> _;
}
```

That is the **entire client-side message surface for a Pool**. Note the absence of any inbound `SetTarget`, `Reconnect`, `NewMiningJob` etc. — those are server→client only, and the trait does not invert.

## SRI's `SupportedChannelTypes`

SRI's pool advertises:

```rust
fn get_channel_type_for_client(&self, _) -> SupportedChannelTypes {
    SupportedChannelTypes::GroupAndExtended
}
fn is_work_selection_enabled_for_client(&self, _) -> bool { true }
```

i.e. it serves Group + Extended and accepts custom-work clients. **datum-rs differs** — we want `SupportedChannelTypes::StandardAndExtended` (or just `Extended`) and `is_work_selection_enabled_for_client = false` (datum-rs is not a JD pool).

## handle_open_extended_mining_channel — the centerpiece (lines 264-552)

The full success path is:

1. **Allocate extranonce_prefix** via `channel_manager_data.extranonce_allocator.allocate_extended(requested_min_rollable_extranonce_size)`.
2. Resolve `PayoutMode::try_from(user_identity)` (SRI-specific solo/donate parsing — datum-rs reuses its existing pool-address logic instead).
3. **Mint a channel_id** via `downstream_data.channel_id_factory.fetch_add(1, SeqCst)`.
4. Construct `ExtendedChannel::new_for_pool(channel_id, user_identity, extranonce_prefix, requested_max_target, nominal_hash_rate, /*version_rolling=*/true, CLIENT_SEARCH_SPACE_BYTES, share_batch_size, shares_per_minute, pool_tag_string)`.
5. Push `Mining::OpenExtendedMiningChannelSuccess { request_id, channel_id, target: target.to_le_bytes().into(), extranonce_prefix, extranonce_size, group_channel_id }`.
6. **If client doesn't require custom work**, immediately push:
   - `Mining::NewExtendedMiningJob(future_extended_job_message)` — the queued future job derived from `last_future_template`.
   - `Mining::SetNewPrevHash { channel_id, job_id, prev_hash, min_ntime, nbits }` — activates that future job.
7. Insert the channel into `extended_channels` and create a `VardiffState::new()` keyed by `(downstream_id, channel_id)`.

Error paths emit `Mining::OpenMiningChannelError` with one of:
- `ERROR_CODE_OPEN_MINING_CHANNEL_EXTENDED_CHANNELS_NOT_SUPPORTED_FOR_STANDARD_JOBS`
- `ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE`
- `ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY`
- `ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE`

## handle_submit_shares_extended (lines 732-939)

```rust
let res = extended_channel.validate_share(msg.clone());
vardiff.increment_shares_since_last_update();

match res {
    Ok(ShareValidationResult::Valid(share_hash)) => {
        if share_accounting.should_acknowledge() { /* push SubmitSharesSuccess (batched) */ }
    }
    Ok(ShareValidationResult::BlockFound(share_hash, template_id, coinbase)) => {
        // 💰 Block Found
        if let Some(template_id) = template_id {
            messages.push(TemplateDistribution::SubmitSolution(SubmitSolution {
                template_id, version, header_timestamp: ntime, header_nonce: nonce, coinbase_tx,
            }).into());
        }
        // also push a one-share SubmitSharesSuccess
    }
    Err(ShareValidationError::Invalid(code))
    | Err(ShareValidationError::Stale(code))
    | Err(ShareValidationError::InvalidJobId(code))
    | Err(ShareValidationError::DoesNotMeetTarget(code))
    | Err(ShareValidationError::DuplicateShare(code))
    | Err(ShareValidationError::BadExtranonceSize(code))
    | Err(ShareValidationError::VersionRollingNotAllowed(code)) => {
        // emit SubmitSharesError { channel_id, sequence_number, error_code: code.to_string() }
    }
    Err(e) => return Err(PoolError::disconnect(e, downstream_id)),
}
```

Notably:

- **`extended_channel.validate_share(msg)`** does the entire validation (header reconstruction, hash, dupe check, target check, stale check). datum-rs can call into this directly if it owns an `ExtendedChannel`; otherwise replicate the algorithm.
- **Batched `SubmitSharesSuccess`** is gated by `share_accounting.should_acknowledge()`. It does NOT Ack every share — only at batch boundaries.
- **`BlockFound` returns the full coinbase**, which then becomes a `SubmitSolution` to the upstream Template Provider. **For datum-rs, this is the moment to send a DATUM `0x27` with `flags |= 1` and submitblock to bitcoind** — the existing `datum-submitblock` crate.
- TLV negotiation: if `EXTENSION_TYPE_WORKER_HASHRATE_TRACKING` is in the negotiated extensions, the per-share TLVs may carry a `UserIdentity` to enhance per-worker monitoring. datum-rs does not need to support this extension on day one.

## handle_update_channel (lines 941-1095)

Client sends `UpdateChannel { channel_id, nominal_hash_rate, maximum_target }`. Server response sequence:

1. Find the channel (Standard or Extended hash map).
2. Call `channel.update_channel(new_nominal_hash_rate, Some(requested_maximum_target))`.
3. On error: emit `Mining::UpdateChannelError { channel_id, error_code: "update-channel-invalid-nominal-hashrate" }`.
4. On success: read `channel.get_target()`, push `Mining::SetTarget { channel_id, maximum_target: target.to_le_bytes() }`.

`UpdateChannel` is the miner's voluntary signal that its hashrate has shifted — it is the SV2 vardiff *initiator from the client*. The server's vardiff loop separately pushes `SetTarget` based on observed share rate, but a polite miner volunteers updates. datum-rs needs both paths.

## Note on `to_le_bytes()` everywhere

Every U256 going onto the wire (`target`, `maximum_target`) is serialized via `.to_le_bytes()` and every U256 coming off the wire is parsed via `Target::from_le_bytes(msg.max_target.inner_as_ref().try_into().unwrap())`. This is the **canonical example** of the LE-on-wire convention discussed in [byte-order debugging](2026-06-16-esp-miner-issue-1758-sv2-byte-order-debugging.md) — copy the SRI pattern verbatim and you are safe.

## handle_set_custom_mining_job (lines 1097-1199)

Tied to JD. **datum-rs disables this path** by setting `is_work_selection_enabled_for_client = false`; the `REQUIRES_WORK_SELECTION` flag in `SetupConnection` should be rejected at the connection level. We never reach this handler.

## datum-rs porting plan (handler-by-handler)

| SRI handler | datum-rs action |
|-------------|-----------------|
| `handle_close_channel` | Direct port. Remove channel from registry, drop vardiff state. |
| `handle_open_standard_mining_channel` | Direct port. Use `StandardChannel::new_for_pool`. |
| `handle_open_extended_mining_channel` | Direct port. Skip `PayoutMode` parsing — reuse datum-rs's existing username→address logic. Use `ExtendedChannel::new_for_pool`. |
| `handle_submit_shares_standard` | Port. Call `standard_channel.validate_share`. On `BlockFound`, route to `datum-submitblock` and DATUM `0x27` with `flags|=1`. On `Valid`, route to DATUM `0x27` with the existing 0x01/0x02 frame logic. |
| `handle_submit_shares_extended` | Same as standard but the share carries the rollable `extranonce`. |
| `handle_update_channel` | Direct port — recompute target, push `SetTarget`. |
| `handle_set_custom_mining_job` | **Stub: `unreachable!()`** (rejected at SetupConnection). |

## Where datum-rs diverges from SRI structurally

1. **No upstream Template Provider**. SRI synthesizes `NewExtendedMiningJob` from a `NewTemplateTdp` cached in `last_future_template`. datum-rs caches a `DatumWork` (or analogous DATUM-derived job state) and synthesizes the equivalent.
2. **No JD path**. Drop `jd_server_sv2::job_declarator::SetCustomMiningJobResponse` entirely.
3. **No SRI `PayoutMode`**. datum-rs already has its own.
4. **Smaller extranonce**: 12 bytes total vs SRI's 20.
5. **`SupportedChannelTypes::StandardAndExtended`** instead of `GroupAndExtended` (no group).

## Catalogue of error codes used by SRI (string constants in `mining_sv2::*`)

Open-channel:
- `ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE`
- `ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE`
- `ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY`
- `ERROR_CODE_OPEN_MINING_CHANNEL_EXTENDED_CHANNELS_NOT_SUPPORTED_FOR_STANDARD_JOBS`

Submit:
- `ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID`
- `ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID`
- `ERROR_CODE_SUBMIT_SHARES_DOES_NOT_MEET_TARGET` (mapped from `ShareValidationError::DoesNotMeetTarget`)
- `ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE`
- `ERROR_CODE_SUBMIT_SHARES_STALE_SHARE`
- `ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE`
- `ERROR_CODE_SUBMIT_SHARES_VERSION_ROLLING_NOT_ALLOWED`
- `ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE`

Update:
- `ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE`
- `ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID`

These are wire-level error_code strings the spec doesn't fix; SRI defines them. **datum-rs should reuse the same strings** so off-the-shelf miners interpret errors identically.
