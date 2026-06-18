//! Phase 4 ChannelManager — `OpenStandardMiningChannel` /
//! `OpenExtendedMiningChannel` open + immediate first job emission.
//!
//! Per the SV2 listener plan §"Phase 4" and the [pool mining handler port
//! plan][port-plan]: this module implements the four selector methods
//! (`get_channel_type_for_client` etc.) and the two `handle_open_*` paths
//! that translate a downstream channel-open request into:
//!
//! 1. `OpenStandardMiningChannelSuccess` / `OpenExtendedMiningChannelSuccess`
//!    with the (server-allocated) `extranonce_prefix` and `target.to_le_bytes()`.
//! 2. An immediate `NewMiningJob` (Standard) or `NewExtendedMiningJob`
//!    (Extended) carrying the current `TemplateState` as a future job.
//! 3. An immediate `SetNewPrevHash` (mining variant, msg type 0x20) with
//!    `prev_hash.to_le_bytes()` to activate the future job.
//!
//! The handler trait surface follows SRI's
//! `HandleMiningMessagesFromClientAsync` (see [the spec][sri-handler]) but we
//! keep it pre-trait — emitting a `Vec<MiningOut>` directly — because the
//! SRI trait returns `Result<(), Error>` and queues outgoing messages via
//! handler-internal state. We collapse that into one `Vec` so the
//! per-connection task can drain it after each call.
//!
//! ## Why not `HandleMiningMessagesFromClientAsync` directly
//!
//! SRI's trait is `#[trait_variant::make(Send)]` and stores per-client
//! outgoing-message queues internally. For the datum-rs structure (one
//! `ChannelManager` per connection, no global session map) the simpler
//! `Vec<MiningOut>`-return shape composes more naturally with the
//! per-connection driver. We keep the **same selector-method names and
//! semantics** so a future swap to the SRI trait is a refactor, not a
//! rewrite.
//!
//! ## Extranonce partition (Phase 4)
//!
//! Per the [extranonce hierarchy concept][extranonce-hierarchy]: total = 12
//! bytes, `local_prefix = 0`, `local_index = 2`, `rollable = 10`. We delegate
//! allocation to SRI's `ExtranonceAllocator::new(vec![], 12, 65_536)` which
//! produces a 2-byte server prefix (the local-index region) and reserves the
//! 10-byte rollable region for the miner. `AllocatedExtranoncePrefix`'s `Drop`
//! frees the slot RAII-style — exactly the SRI pattern.
//!
//! ## TemplateState integration
//!
//! On channel open the manager `borrow()`s the current `TemplateState` from
//! a `tokio::sync::watch::Receiver<Option<Arc<TemplateState>>>` and synthesizes
//! `(NewExtendedMiningJob, SetNewPrevHash)` (or the Standard pair). On every
//! template transition the connection driver calls
//! [`ChannelManager::on_template_update`] to re-emit the pair to **all** open
//! channels.
//!
//! [port-plan]: ../../../../.wiki/wiki/references/sri-pool-mining-handler.md
//! [sri-handler]: ../../../../.wiki/wiki/references/sri-pool-mining-handler.md
//! [extranonce-hierarchy]: ../../../../.wiki/wiki/concepts/sv2-extranonce-hierarchy.md

use std::collections::HashMap;
use std::sync::Arc;

use datum_blocktemplates::TemplateState;
use stratum_core::binary_sv2::{Seq0255, Str0255, Sv2Option, U256};
use stratum_core::channels_sv2::extranonce_manager::{
    AllocatedExtranoncePrefix, ExtranonceAllocator, ExtranonceAllocatorError,
};
use stratum_core::mining_sv2::{
    NewExtendedMiningJob, NewMiningJob, OpenExtendedMiningChannel,
    OpenExtendedMiningChannelSuccess, OpenMiningChannelError, OpenStandardMiningChannel,
    OpenStandardMiningChannelSuccess, SetCustomMiningJobError, SetNewPrevHash, SetTarget,
    SubmitSharesError, SubmitSharesSuccess, UpdateChannelError,
    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE,
    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
};
use stratum_core::parsers_sv2::Mining;
use thiserror::Error;
use tokio::sync::watch;

use crate::SupportedChannelTypes;

/// Total extranonce length advertised to the DATUM upstream (`0x27` frames
/// expect a single 12-byte field).
pub const TOTAL_EXTRANONCE_LEN: u8 = 12;

/// Maximum concurrent channels per gateway. With `total=12` and
/// `local_prefix=0`, a `local_index_len = ceil(log_256(65536)) = 2` byte
/// channel-index region matches the [extranonce hierarchy concept][hier]
/// `[local_prefix=0, local_index=2, rollable=10]` partition.
///
/// [hier]: ../../../../.wiki/wiki/concepts/sv2-extranonce-hierarchy.md
pub const MAX_CHANNELS: u32 = 65_536;

/// Default minimum supported downstream hashrate, in H/s. Mirrors
/// [`datum_config::DEFAULT_STRATUM_V2_MIN_HASHRATE_THRESHOLD`]. We duplicate
/// the constant here rather than depending on `datum-config` so this crate
/// stays config-agnostic at the type level (the listener reads the value
/// out of `StratumV2Config` and forwards it via [`ChannelManager::with_policy`]).
pub const DEFAULT_MIN_HASHRATE_THRESHOLD: f64 = 1.0e12;
/// Default per-channel target shares-per-minute. Mirrors
/// [`datum_config::DEFAULT_STRATUM_V2_EXPECTED_SHARE_PER_MINUTE`].
pub const DEFAULT_EXPECTED_SHARE_PER_MINUTE: f32 = 6.0;

/// Outgoing message produced by a `handle_open_*` call. The connection driver
/// frames each variant with `Sv2Frame::from_message(msg, msg_type, ext=0,
/// channel_msg=<per spec>)` — `channel_msg=true` for everything except
/// `OpenMiningChannel.Error` and the `OpenMiningChannel*Success` pair (those
/// reply to a non-channel-bound `OpenMiningChannel*`).
#[derive(Debug)]
pub enum MiningOut {
    OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess<'static>),
    OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess<'static>),
    OpenMiningChannelError(OpenMiningChannelError<'static>),
    NewExtendedMiningJob(NewExtendedMiningJob<'static>),
    NewMiningJob(NewMiningJob<'static>),
    SetNewPrevHash(SetNewPrevHash<'static>),
    /// Phase 5 share-path output (batched ack). `channel_msg=true`.
    SubmitSharesSuccess(SubmitSharesSuccess),
    /// Phase 5 share-path output (per-share rejection). `channel_msg=true`.
    SubmitSharesError(SubmitSharesError<'static>),
    /// Phase 5 vardiff output. `channel_msg=true`.
    SetTarget(SetTarget<'static>),
    /// Phase 5 reply to `UpdateChannel` when nominal hashrate is invalid.
    /// `channel_msg=true`.
    UpdateChannelError(UpdateChannelError<'static>),
    /// Phase 5 reply to an unsolicited `SetCustomMiningJob` (msg 0x22).
    /// datum-rs rejects `REQUIRES_WORK_SELECTION` at SetupConnection so a
    /// well-behaved client never reaches this; a malformed/malicious peer
    /// previously tripped `unreachable!()` and used to panic the per-conn
    /// task. We reply with `error_code = "jd-not-supported"` and keep the
    /// connection alive instead. `channel_msg=true`.
    SetCustomMiningJobError(SetCustomMiningJobError<'static>),
}

impl MiningOut {
    /// Convert into the SRI `Mining` enum for routing through `parsers_sv2`'s
    /// generic encoder. Loses the type discrimination; the caller has already
    /// looked up the message type via [`MiningOut::msg_type`].
    pub fn into_mining(self) -> Mining<'static> {
        match self {
            Self::OpenExtendedMiningChannelSuccess(m) => {
                Mining::OpenExtendedMiningChannelSuccess(m)
            }
            Self::OpenStandardMiningChannelSuccess(m) => {
                Mining::OpenStandardMiningChannelSuccess(m)
            }
            Self::OpenMiningChannelError(m) => Mining::OpenMiningChannelError(m),
            Self::NewExtendedMiningJob(m) => Mining::NewExtendedMiningJob(m),
            Self::NewMiningJob(m) => Mining::NewMiningJob(m),
            Self::SetNewPrevHash(m) => Mining::SetNewPrevHash(m),
            Self::SubmitSharesSuccess(m) => Mining::SubmitSharesSuccess(m),
            Self::SubmitSharesError(m) => Mining::SubmitSharesError(m),
            Self::SetTarget(m) => Mining::SetTarget(m),
            Self::UpdateChannelError(m) => Mining::UpdateChannelError(m),
            Self::SetCustomMiningJobError(m) => Mining::SetCustomMiningJobError(m),
        }
    }

    /// SV2 message type byte for this message. Mirrors the `MESSAGE_TYPE_*`
    /// constants in `mining_sv2`.
    pub fn msg_type(&self) -> u8 {
        use stratum_core::mining_sv2::{
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
            MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
            MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR, MESSAGE_TYPE_SET_TARGET,
            MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
            MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
        };
        match self {
            Self::OpenExtendedMiningChannelSuccess(_) => {
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS
            }
            Self::OpenStandardMiningChannelSuccess(_) => {
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS
            }
            Self::OpenMiningChannelError(_) => MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
            Self::NewExtendedMiningJob(_) => MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
            Self::NewMiningJob(_) => MESSAGE_TYPE_NEW_MINING_JOB,
            Self::SetNewPrevHash(_) => MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
            Self::SubmitSharesSuccess(_) => MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
            Self::SubmitSharesError(_) => MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
            Self::SetTarget(_) => MESSAGE_TYPE_SET_TARGET,
            Self::UpdateChannelError(_) => MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
            Self::SetCustomMiningJobError(_) => MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
        }
    }

    /// Whether the SV2 frame should set the `channel_msg` bit (bit 15 of
    /// `extension_type`). Mirrors `mining_sv2::CHANNEL_BIT_*`.
    pub fn channel_msg(&self) -> bool {
        match self {
            Self::OpenExtendedMiningChannelSuccess(_)
            | Self::OpenStandardMiningChannelSuccess(_)
            | Self::OpenMiningChannelError(_) => false,
            Self::NewExtendedMiningJob(_)
            | Self::NewMiningJob(_)
            | Self::SetNewPrevHash(_)
            | Self::SubmitSharesSuccess(_)
            | Self::SubmitSharesError(_)
            | Self::SetTarget(_)
            | Self::UpdateChannelError(_)
            | Self::SetCustomMiningJobError(_) => true,
        }
    }
}

/// Per-channel state. Kept lean — Phase 5 will add `ExtendedChannel` /
/// `StandardChannel` from `channels_sv2::server` once the share-validation
/// path needs them.
#[derive(Debug)]
pub struct OpenedChannel {
    pub channel_id: u32,
    pub user_identity: String,
    /// `true` for Extended, `false` for Standard. Used by `on_template_update`
    /// to decide which job-message variant to emit.
    pub is_extended: bool,
    /// Allocated extranonce prefix bytes (2 bytes for our 12-byte partition).
    /// Held to keep the slot reserved — `Drop` frees the bitmap slot.
    pub extranonce_prefix: AllocatedExtranoncePrefix,
    /// Last `job_id` we issued to this channel — used as the `job_id` in
    /// `SetNewPrevHash` (which activates that future job).
    pub last_job_id: u32,
    /// `nominal_hash_rate` from the `OpenChannel` message. Phase 5 will use
    /// this to seed vardiff.
    pub nominal_hash_rate: f32,
    /// Negotiated `max_target` (LE-internal byte order). For Standard
    /// channels this is the device's `max_target`; for Extended channels
    /// likewise. The server-side initial `target` we issue is bounded by
    /// this — Phase 6's vardiff loop calls [`clamp_target_to_channel_max`]
    /// to ensure a `SetTarget` we emit never lowers difficulty below what
    /// the device is willing to accept.
    pub max_target_le: [u8; 32],
}

#[derive(Debug, Error)]
pub enum ChannelOpenError {
    /// SRI's `ExtranonceAllocatorError` does **not** impl `std::error::Error`
    /// on this rev (`c7113e7`), so we can't use `#[from]` — wrap by hand.
    #[error("extranonce allocator: {0}")]
    Allocator(ExtranonceAllocatorError),
    #[error("template state not yet available")]
    NoTemplateYet,
    #[error("invalid user identity (empty or non-UTF8)")]
    InvalidUserIdentity,
    /// Should be unreachable — we control the server-side construction of
    /// every Sv2 datatype. Surfaces upstream as a 500-class error.
    #[error("encode: {0:?}")]
    Encode(stratum_core::binary_sv2::Error),
}

impl From<ExtranonceAllocatorError> for ChannelOpenError {
    fn from(e: ExtranonceAllocatorError) -> Self {
        Self::Allocator(e)
    }
}

impl From<stratum_core::binary_sv2::Error> for ChannelOpenError {
    fn from(e: stratum_core::binary_sv2::Error) -> Self {
        Self::Encode(e)
    }
}

/// Phase 4 channel manager — one per SV2 connection.
///
/// Owns:
/// - An `ExtranonceAllocator` (its 2-byte channel-index slot per channel).
/// - A `HashMap<channel_id, OpenedChannel>`.
/// - A `tokio::sync::watch::Receiver<Option<Arc<TemplateState>>>` for the
///   shared template state (Phase 1 publisher in `datum-blocktemplates`).
///
/// Selector-method overrides match the [SRI port plan][port-plan]:
/// - `get_channel_type_for_client = StandardAndExtended`
/// - `is_work_selection_enabled_for_client = false`
/// - `is_client_authorized = !user_identity.is_empty()` (SV1 parity — we
///   accept any non-empty username; payout-address parsing is Phase 5+)
/// - `get_negotiated_extensions_with_client = Ok(vec![])`
///
/// [port-plan]: ../../../../.wiki/wiki/references/sri-pool-mining-handler.md
pub struct ChannelManager {
    allocator: ExtranonceAllocator,
    channels: HashMap<u32, OpenedChannel>,
    template_rx: watch::Receiver<Option<Arc<TemplateState>>>,
    next_channel_id: u32,
    next_job_id: u32,
    /// Minimum supported downstream hashrate, in H/s. `OpenChannel` requests
    /// with `nominal_hash_rate < min_hashrate_threshold` are rejected with
    /// `invalid-nominal-hashrate`. See live-OCEAN bug B (2026-06-16).
    min_hashrate_threshold: f64,
    /// Precomputed `hash_rate_to_target(min_hashrate_threshold,
    /// expected_share_per_minute).to_le_bytes()`. ANY emitted SetTarget /
    /// `Open*MiningChannelSuccess.target` is clamped from above by this
    /// value — a malicious / misconfigured client cannot widen the target.
    min_target_le: [u8; 32],
}

impl std::fmt::Debug for ChannelManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelManager")
            .field("channels", &self.channels.len())
            .field("next_channel_id", &self.next_channel_id)
            .field("next_job_id", &self.next_job_id)
            .field("allocator", &self.allocator)
            .finish()
    }
}

impl ChannelManager {
    /// Build a fresh manager with the production hashrate policy
    /// (1 TH/s floor + 6 shares/min, per
    /// [`datum_config::DEFAULT_STRATUM_V2_MIN_HASHRATE_THRESHOLD`] +
    /// [`datum_config::DEFAULT_STRATUM_V2_EXPECTED_SHARE_PER_MINUTE`]).
    /// Allocator is configured for our 12-byte partition: total=12,
    /// local_prefix=0, local_index=2 (auto-derived from
    /// max_channels=65_536), rollable=10.
    ///
    /// Tests / fixtures with non-default policy needs should call
    /// [`Self::with_policy`] explicitly.
    pub fn new(
        template_rx: watch::Receiver<Option<Arc<TemplateState>>>,
    ) -> Result<Self, ExtranonceAllocatorError> {
        Self::with_policy(
            template_rx,
            DEFAULT_MIN_HASHRATE_THRESHOLD,
            DEFAULT_EXPECTED_SHARE_PER_MINUTE,
        )
    }

    /// Build a fresh manager with an explicit hashrate policy. Used by the
    /// listener at boot (forwarding `cfg.stratum_v2.min_hashrate_threshold` +
    /// `cfg.stratum_v2.expected_share_per_minute`) and by tests that need to
    /// override the production 1 TH/s floor.
    pub fn with_policy(
        template_rx: watch::Receiver<Option<Arc<TemplateState>>>,
        min_hashrate_threshold: f64,
        expected_share_per_minute: f32,
    ) -> Result<Self, ExtranonceAllocatorError> {
        let allocator = ExtranonceAllocator::new(Vec::new(), TOTAL_EXTRANONCE_LEN, MAX_CHANNELS)?;
        // Sanity assert the partition matches what the wiki claims. If SRI's
        // `bytes_needed(MAX_CHANNELS)` ever drifts to 3 bytes, our wire shape
        // would silently break; fail loudly here instead.
        debug_assert_eq!(allocator.upstream_prefix_len(), 0);
        debug_assert_eq!(allocator.local_prefix_len(), 0);
        debug_assert_eq!(allocator.local_index_len(), 2);
        debug_assert_eq!(allocator.rollable_extranonce_size(), 10);
        let min_target_le = crate::share_path::compute_min_target_le(
            min_hashrate_threshold,
            expected_share_per_minute,
        );
        Ok(Self {
            allocator,
            channels: HashMap::new(),
            template_rx,
            next_channel_id: 1,
            next_job_id: 1,
            min_hashrate_threshold,
            min_target_le,
        })
    }

    /// `min_hashrate_threshold` (H/s) configured at boot.
    pub fn min_hashrate_threshold(&self) -> f64 {
        self.min_hashrate_threshold
    }

    /// Precomputed clamp ceiling — every emitted SetTarget / channel-open
    /// `target` is `min(client_request, min_target_le)`. LE byte order.
    pub fn min_target_le(&self) -> [u8; 32] {
        self.min_target_le
    }

    // ------------------------------------------------------------------
    // Selector methods (mirror SRI's HandleMiningMessagesFromClientAsync).
    // ------------------------------------------------------------------

    pub fn get_channel_type_for_client(&self) -> SupportedChannelTypes {
        SupportedChannelTypes::StandardAndExtended
    }

    pub fn is_work_selection_enabled_for_client(&self) -> bool {
        false
    }

    /// SV1 parity: accept any non-empty username. A future phase will parse
    /// the leading segment as a Bitcoin payout address and reject malformed
    /// inputs.
    pub fn is_client_authorized(&self, user_identity: &Str0255<'_>) -> bool {
        let bytes = user_identity.inner_as_ref();
        !bytes.is_empty()
    }

    pub fn get_negotiated_extensions_with_client(&self) -> Vec<u16> {
        Vec::new()
    }

    // ------------------------------------------------------------------
    // Open handlers.
    // ------------------------------------------------------------------

    /// Handle `OpenExtendedMiningChannel` (msg 0x13).
    ///
    /// On success: emits 3 messages — `OpenExtendedMiningChannelSuccess`,
    /// `NewExtendedMiningJob` (future), `SetNewPrevHash`.
    /// On failure (no template yet / bad user identity / allocator
    /// exhausted): emits 1 message — `OpenMiningChannelError`.
    pub fn handle_open_extended_mining_channel(
        &mut self,
        msg: OpenExtendedMiningChannel<'_>,
    ) -> Vec<MiningOut> {
        let request_id = msg.request_id;
        if !self.is_client_authorized(&msg.user_identity) {
            return vec![MiningOut::OpenMiningChannelError(open_error(
                request_id,
                ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
            ))];
        }

        let user_identity = match str_from_str0255(&msg.user_identity) {
            Some(s) => s,
            None => {
                return vec![MiningOut::OpenMiningChannelError(open_error(
                    request_id,
                    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
                ))];
            }
        };
        let nominal_hash_rate = msg.nominal_hash_rate;
        // Bug-B layer 1: reject clients that advertise less than our
        // hashrate floor. SRI's `ExtendedChannel::new` runs an equivalent
        // check via `hash_rate_to_target` — we explicitly enforce the
        // datum-rs policy threshold so a misconfigured downstream gets a
        // clear, actionable error before any SetTarget is computed.
        if !nominal_hash_rate.is_finite()
            || nominal_hash_rate <= 0.0
            || (nominal_hash_rate as f64) < self.min_hashrate_threshold
        {
            return vec![MiningOut::OpenMiningChannelError(open_error(
                request_id,
                ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE,
            ))];
        }
        // We accept the device's `max_target` as the initial channel target.
        // Phase 5 will narrow this via vardiff; here we just round-trip the
        // bytes so the LE-on-wire round-trip is byte-for-byte verifiable.
        let max_target_le: [u8; 32] = match msg.max_target.inner_as_ref().try_into() {
            Ok(t) => t,
            Err(_) => {
                return vec![MiningOut::OpenMiningChannelError(open_error(
                    request_id,
                    "max-target-out-of-range",
                ))];
            }
        };

        match self.open_extended_inner(request_id, user_identity, nominal_hash_rate, max_target_le)
        {
            Ok(out) => out,
            Err(ChannelOpenError::Allocator(_)) => vec![MiningOut::OpenMiningChannelError(
                open_error(request_id, "min-extranonce-size-too-large"),
            )],
            Err(ChannelOpenError::NoTemplateYet) => vec![MiningOut::OpenMiningChannelError(
                open_error(request_id, "unknown-user"),
            )],
            Err(ChannelOpenError::InvalidUserIdentity) => {
                vec![MiningOut::OpenMiningChannelError(open_error(
                    request_id,
                    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
                ))]
            }
            Err(ChannelOpenError::Encode(_)) => vec![MiningOut::OpenMiningChannelError(
                open_error(request_id, "internal-encode-error"),
            )],
        }
    }

    fn open_extended_inner(
        &mut self,
        request_id: u32,
        user_identity: String,
        nominal_hash_rate: f32,
        max_target_le: [u8; 32],
    ) -> Result<Vec<MiningOut>, ChannelOpenError> {
        let template = self
            .template_rx
            .borrow()
            .clone()
            .ok_or(ChannelOpenError::NoTemplateYet)?;

        let allocated = self.allocator.allocate_extended(10)?;
        let extranonce_prefix_bytes = allocated.as_bytes().to_vec();

        let channel_id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        let job_id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);

        // Bug-B layer 2: clamp the success-target to `min_target_le` so a
        // client cannot widen the target by passing a `max_target` above
        // our hashrate-floor-derived ceiling.
        let initial_target_le =
            crate::share_path::clamp_target_to_min_hashrate_le(max_target_le, self.min_target_le);
        let success = OpenExtendedMiningChannelSuccess {
            request_id,
            channel_id,
            target: U256::from(initial_target_le),
            extranonce_size: 10,
            extranonce_prefix: extranonce_prefix_bytes.clone().try_into()?,
            group_channel_id: 0,
        };

        let new_job = build_new_extended_job(channel_id, job_id, &template)?;
        let snph = build_set_new_prev_hash(channel_id, job_id, &template);

        self.channels.insert(
            channel_id,
            OpenedChannel {
                channel_id,
                user_identity,
                is_extended: true,
                extranonce_prefix: allocated,
                last_job_id: job_id,
                nominal_hash_rate,
                max_target_le,
            },
        );

        Ok(vec![
            MiningOut::OpenExtendedMiningChannelSuccess(success),
            MiningOut::NewExtendedMiningJob(new_job),
            MiningOut::SetNewPrevHash(snph),
        ])
    }

    /// Handle `OpenStandardMiningChannel` (msg 0x10).
    ///
    /// Same flow as Extended, but with a server-side `merkle_root`
    /// precompute (Standard channels carry no rollable extranonce, so the
    /// server fixes the entire coinbase up front).
    pub fn handle_open_standard_mining_channel(
        &mut self,
        msg: OpenStandardMiningChannel<'_>,
    ) -> Vec<MiningOut> {
        let request_id = msg.get_request_id_as_u32();
        if !self.is_client_authorized(&msg.user_identity) {
            return vec![MiningOut::OpenMiningChannelError(open_error(
                request_id,
                ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
            ))];
        }

        let user_identity = match str_from_str0255(&msg.user_identity) {
            Some(s) => s,
            None => {
                return vec![MiningOut::OpenMiningChannelError(open_error(
                    request_id,
                    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
                ))];
            }
        };
        let nominal_hash_rate = msg.nominal_hash_rate;
        // Bug-B layer 1: reject clients that advertise less than our
        // hashrate floor. See [`Self::handle_open_extended_mining_channel`]
        // for the rationale.
        if !nominal_hash_rate.is_finite()
            || nominal_hash_rate <= 0.0
            || (nominal_hash_rate as f64) < self.min_hashrate_threshold
        {
            return vec![MiningOut::OpenMiningChannelError(open_error(
                request_id,
                ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE,
            ))];
        }
        let max_target_le: [u8; 32] = match msg.max_target.inner_as_ref().try_into() {
            Ok(t) => t,
            Err(_) => {
                return vec![MiningOut::OpenMiningChannelError(open_error(
                    request_id,
                    "max-target-out-of-range",
                ))];
            }
        };

        match self.open_standard_inner(request_id, user_identity, nominal_hash_rate, max_target_le)
        {
            Ok(out) => out,
            Err(ChannelOpenError::Allocator(_)) => vec![MiningOut::OpenMiningChannelError(
                open_error(request_id, "min-extranonce-size-too-large"),
            )],
            Err(ChannelOpenError::NoTemplateYet) => vec![MiningOut::OpenMiningChannelError(
                open_error(request_id, "unknown-user"),
            )],
            Err(ChannelOpenError::InvalidUserIdentity) => {
                vec![MiningOut::OpenMiningChannelError(open_error(
                    request_id,
                    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
                ))]
            }
            Err(ChannelOpenError::Encode(_)) => vec![MiningOut::OpenMiningChannelError(
                open_error(request_id, "internal-encode-error"),
            )],
        }
    }

    fn open_standard_inner(
        &mut self,
        request_id: u32,
        user_identity: String,
        nominal_hash_rate: f32,
        max_target_le: [u8; 32],
    ) -> Result<Vec<MiningOut>, ChannelOpenError> {
        let template = self
            .template_rx
            .borrow()
            .clone()
            .ok_or(ChannelOpenError::NoTemplateYet)?;

        // Standard allocate returns the full 12-byte prefix (rollable
        // zero-padded). The wire field is `B032` so this fits comfortably.
        let allocated = self.allocator.allocate_standard()?;
        let extranonce_prefix_bytes = allocated.as_bytes().to_vec();

        let channel_id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        let job_id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);

        // Standard channels: server fixes the entire coinbase, so we precompute
        // `merkle_root` from `coinb1 || full_extranonce_prefix || coinb2`.
        let merkle_root_le = compute_merkle_root_for_standard(
            &template.coinb1,
            &extranonce_prefix_bytes,
            &template.coinb2,
            &template.merkle_branches,
        );

        // SRI's `OpenStandardMiningChannelSuccess.extranonce_prefix` is `B032`
        // (≤ 32 bytes). For our 12-byte upstream we pass the full 12 bytes so
        // a downstream reconstructing the coinbase locally still gets the
        // identical prefix the server used in `merkle_root`.
        //
        // Bug-B layer 2: clamp the success-target to `min_target_le`. See
        // [`Self::open_extended_inner`] for the rationale.
        let initial_target_le =
            crate::share_path::clamp_target_to_min_hashrate_le(max_target_le, self.min_target_le);
        let success = OpenStandardMiningChannelSuccess {
            request_id: stratum_core::binary_sv2::U32AsRef::from(request_id),
            channel_id,
            target: U256::from(initial_target_le),
            extranonce_prefix: extranonce_prefix_bytes.clone().try_into()?,
            group_channel_id: 0,
        };

        let new_job = NewMiningJob {
            channel_id,
            job_id,
            min_ntime: Sv2Option::new(None),
            version: template.version,
            merkle_root: U256::from(merkle_root_le),
        };
        let snph = build_set_new_prev_hash(channel_id, job_id, &template);

        self.channels.insert(
            channel_id,
            OpenedChannel {
                channel_id,
                user_identity,
                is_extended: false,
                extranonce_prefix: allocated,
                last_job_id: job_id,
                nominal_hash_rate,
                max_target_le,
            },
        );

        Ok(vec![
            MiningOut::OpenStandardMiningChannelSuccess(success),
            MiningOut::NewMiningJob(new_job),
            MiningOut::SetNewPrevHash(snph),
        ])
    }

    /// Handle `CloseChannel` (msg 0x18). No reply per spec. The
    /// `AllocatedExtranoncePrefix`'s `Drop` frees the slot.
    pub fn handle_close_channel(&mut self, channel_id: u32) {
        self.channels.remove(&channel_id);
    }

    /// Re-emit `(NewMiningJob | NewExtendedMiningJob, SetNewPrevHash)` to
    /// every open channel after a `TemplateState` transition. The connection
    /// driver calls this whenever the watch channel signals.
    pub fn on_template_update(&mut self, template: &TemplateState) -> Vec<MiningOut> {
        let mut out = Vec::with_capacity(self.channels.len() * 2);
        // Snapshot the channel ids first so we can mut-borrow `next_job_id`
        // freely. Iteration order is HashMap-undefined which is fine — the
        // miner only cares per-channel.
        let ids: Vec<u32> = self.channels.keys().copied().collect();
        for cid in ids {
            let job_id = self.next_job_id;
            self.next_job_id = self.next_job_id.wrapping_add(1);

            let is_extended = self
                .channels
                .get(&cid)
                .map(|c| c.is_extended)
                .unwrap_or(false);
            if is_extended {
                if let Ok(new_job) = build_new_extended_job(cid, job_id, template) {
                    out.push(MiningOut::NewExtendedMiningJob(new_job));
                }
            } else {
                let extranonce_prefix_bytes = self
                    .channels
                    .get(&cid)
                    .map(|c| c.extranonce_prefix.as_bytes().to_vec())
                    .unwrap_or_default();
                let merkle_root_le = compute_merkle_root_for_standard(
                    &template.coinb1,
                    &extranonce_prefix_bytes,
                    &template.coinb2,
                    &template.merkle_branches,
                );
                out.push(MiningOut::NewMiningJob(NewMiningJob {
                    channel_id: cid,
                    job_id,
                    min_ntime: Sv2Option::new(None),
                    version: template.version,
                    merkle_root: U256::from(merkle_root_le),
                }));
            }
            out.push(MiningOut::SetNewPrevHash(build_set_new_prev_hash(
                cid, job_id, template,
            )));
            if let Some(c) = self.channels.get_mut(&cid) {
                c.last_job_id = job_id;
            }
        }
        out
    }

    /// Channel count (test/diagnostic).
    pub fn open_channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Active channel ids (test/diagnostic).
    pub fn channel_ids(&self) -> Vec<u32> {
        self.channels.keys().copied().collect()
    }

    /// Read-only accessor for an open channel. Used by the per-connection
    /// dispatcher to recover the channel's `extranonce_prefix` /
    /// `max_target_le` / `is_extended` flag at share-validation time.
    pub fn channel(&self, channel_id: u32) -> Option<&OpenedChannel> {
        self.channels.get(&channel_id)
    }

    /// Snapshot the current `TemplateState` from the watch channel.
    /// Returns `None` until the publisher has emitted at least one state.
    pub fn current_template(&self) -> Option<Arc<TemplateState>> {
        self.template_rx.borrow().clone()
    }
}

// ----------------------------------------------------------------------
// Pure helpers (no `&mut self` — exported for unit testing).
// ----------------------------------------------------------------------

/// Build `NewExtendedMiningJob` from a `TemplateState` snapshot.
///
/// Per the SV2 mining-protocol concept §"Job lifecycle": `min_ntime = None`
/// means **future job** — the matching `SetNewPrevHash.job_id` activates it.
/// We always emit a future job because the caller pairs it with an
/// immediate `SetNewPrevHash`.
fn build_new_extended_job(
    channel_id: u32,
    job_id: u32,
    template: &TemplateState,
) -> Result<NewExtendedMiningJob<'static>, stratum_core::binary_sv2::Error> {
    // SV1's `merkle_branches` are stored in big-endian display order (txid
    // display). SV2 wants internal-LE on wire — reverse each entry.
    let merkle_path: Vec<U256<'static>> = template
        .merkle_branches
        .iter()
        .map(|be| {
            let mut le = *be;
            le.reverse();
            U256::from(le)
        })
        .collect();
    let merkle_path = Seq0255::new(merkle_path)?;

    let coinbase_tx_prefix = template.coinb1.clone().try_into()?;
    let coinbase_tx_suffix = template.coinb2.clone().try_into()?;

    Ok(NewExtendedMiningJob {
        channel_id,
        job_id,
        min_ntime: Sv2Option::new(None),
        version: template.version,
        version_rolling_allowed: true,
        merkle_path,
        coinbase_tx_prefix,
        coinbase_tx_suffix,
    })
}

/// Build a `SetNewPrevHash` (mining variant, msg 0x20) from `TemplateState`.
///
/// `prev_hash` is internal-LE bytes (per `TemplateState::prev_hash` doc). SV2
/// wants LE on the wire; passing those bytes through `U256::from` writes them
/// verbatim — no reversal — matching the [SV2 mining-protocol concept][mining]
/// "Wire byte-order rule" (§5.3.1, all U256 fields LE).
///
/// `nbits` in `TemplateState` is stored in BE display order (matches GBT).
/// SRI's `SetNewPrevHash.nbits` field is a `U32` — encoded LE on wire — so
/// we reverse to internal-LE here, store as `u32`, and the encoder writes it
/// back out LE.
///
/// [mining]: ../../../../.wiki/wiki/concepts/sv2-mining-protocol.md
fn build_set_new_prev_hash(
    channel_id: u32,
    job_id: u32,
    template: &TemplateState,
) -> SetNewPrevHash<'static> {
    // BE display bytes -> u32 (BE-interpreted) -> emit LE on wire automatically.
    let nbits = u32::from_be_bytes(template.nbits);
    SetNewPrevHash {
        channel_id,
        job_id,
        prev_hash: U256::from(template.prev_hash),
        min_ntime: template.min_ntime,
        nbits,
    }
}

/// Server-side `merkle_root` precompute for Standard channels.
///
/// `coinbase = coinb1 || extranonce_prefix || coinb2`. For Standard the prefix
/// is the full 12 bytes (rollable region zero-padded). Then we walk the
/// `merkle_branches` (sibling-path stored in BE display order) — re-using the
/// SV1 sha256d-based merkle algorithm.
///
/// Returns the merkle root in **internal-LE byte order** — identical to the
/// bytes that go on the SV2 wire (per the byte-order rule). The SV1 path's
/// merkle root display is the same bytes reversed.
fn compute_merkle_root_for_standard(
    coinb1: &[u8],
    extranonce_prefix: &[u8],
    coinb2: &[u8],
    merkle_branches_be: &[[u8; 32]],
) -> [u8; 32] {
    let mut coinbase = Vec::with_capacity(coinb1.len() + extranonce_prefix.len() + coinb2.len());
    coinbase.extend_from_slice(coinb1);
    coinbase.extend_from_slice(extranonce_prefix);
    coinbase.extend_from_slice(coinb2);

    // Coinbase txid in internal-LE order (sha256d of serialized tx).
    let mut hash_le = sha256d(&coinbase);

    for branch_be in merkle_branches_be {
        // Branches are stored in BE display order; flip to internal-LE.
        let mut branch_le = *branch_be;
        branch_le.reverse();

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&hash_le);
        combined[32..].copy_from_slice(&branch_le);
        hash_le = sha256d(&combined);
    }
    hash_le
}

/// Double-SHA256 of `input`, returning internal byte order.
fn sha256d(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first: [u8; 32] = Sha256::new().chain_update(input).finalize().into();
    Sha256::new().chain_update(first).finalize().into()
}

fn open_error(request_id: u32, code: &'static str) -> OpenMiningChannelError<'static> {
    let error_code: Str0255<'static> = code
        .to_string()
        .into_bytes()
        .try_into()
        .expect("ASCII error_code fits Str0255");
    OpenMiningChannelError {
        request_id,
        error_code,
    }
}

fn str_from_str0255(s: &Str0255<'_>) -> Option<String> {
    let bytes = s.inner_as_ref();
    if bytes.is_empty() {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

/// Clamp a vardiff-derived target (LE-internal bytes) to the channel's
/// max_target. The wire-spec invariant is `current_target ≤ max_target`,
/// where smaller-as-256bit-integer == easier-as-difficulty. If the proposed
/// vardiff target is HIGHER than the channel's max (i.e. easier), it gets
/// clamped down to `max_target` — the device explicitly refused to mine at
/// anything easier. Per the [SV2 mining-protocol concept] §SetTarget §"server
/// MUST NOT set a target above max_target".
///
/// Both inputs are 32-byte little-endian. Comparison is done by reading them
/// as 256-bit big-endian integers (i.e. compare bytes from index 31 down to
/// 0). Returns `proposed` clamped to `[0, max_target_le]`.
pub fn clamp_target_to_channel_max(proposed_le: [u8; 32], max_target_le: [u8; 32]) -> [u8; 32] {
    // Compare as big-endian: walk from MSB (byte index 31 in LE) down to LSB.
    for i in (0..32).rev() {
        if proposed_le[i] > max_target_le[i] {
            return max_target_le;
        }
        if proposed_le[i] < max_target_le[i] {
            return proposed_le;
        }
    }
    // Equal — either is fine; return proposed.
    proposed_le
}

#[cfg(test)]
mod clamp_tests {
    use super::*;

    #[test]
    fn clamp_returns_max_when_proposed_higher() {
        // proposed > max → clamp.
        let mut proposed = [0u8; 32];
        proposed[31] = 0xff;
        let max = [0xaau8; 32];
        let out = clamp_target_to_channel_max(proposed, max);
        assert_eq!(out, max);
    }

    #[test]
    fn clamp_returns_proposed_when_below_max() {
        let proposed = [0x55u8; 32];
        let max = [0xffu8; 32];
        let out = clamp_target_to_channel_max(proposed, max);
        assert_eq!(out, proposed);
    }

    #[test]
    fn clamp_returns_proposed_when_equal() {
        let v = [0x42u8; 32];
        let out = clamp_target_to_channel_max(v, v);
        assert_eq!(out, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datum_blocktemplates::{ScriptSigInputs, Template, TemplateStatePublisher};
    use datum_coinbaser::{CoinbaseOutput, CoinbaserBlob};

    fn template() -> Template {
        Template {
            version: 0x2000_0000,
            previous_block_hash: "00".repeat(32),
            bits: "1d00ffff".into(),
            height: 800_000,
            coinbase_value: 312_500_000,
            curtime: 0x6712_3456,
            mintime: 0,
            sizelimit: 4_000_000,
            weightlimit: 4_000_000,
            sigop_limit: 80_000,
            default_witness_commitment: None,
            transactions: vec![],
            long_poll_id: None,
            target: None,
        }
    }

    fn blob() -> CoinbaserBlob {
        CoinbaserBlob {
            datum_id: 0,
            outputs: vec![CoinbaseOutput {
                value_sats: 312_500_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd],
            }],
        }
    }

    fn synthetic_template() -> Arc<TemplateState> {
        let s = TemplateState::from_template_and_blob(
            &template(),
            &blob(),
            ScriptSigInputs::default(),
            1,
        );
        Arc::new(s)
    }

    fn manager_with_template() -> ChannelManager {
        let (publisher, sub) = TemplateStatePublisher::new();
        // Publisher publishes immediately so `borrow()` returns Some(_).
        publisher
            .publish(TemplateState::from_template_and_blob(
                &template(),
                &blob(),
                ScriptSigInputs::default(),
                1,
            ))
            .unwrap();
        // Wire-shape unit tests use the production manager (1 TH/s floor +
        // 6 SPM clamp). New variants below exercise the bug-B floor / clamp
        // explicitly; a couple of legacy tests need to override to a very
        // low floor to keep their `nominal_hash_rate = 0.0` payloads valid.
        ChannelManager::new(sub.into_receiver()).unwrap()
    }

    /// Test fixture: same as [`manager_with_template`] but with a 1 H/s
    /// floor + 60 SPM ceiling so tests can use synthetic `nominal_hash_rate
    /// = 0.0`-or-higher payloads without tripping the production bug-B
    /// rejection. The clamp is still active but loose.
    fn manager_with_template_low_floor() -> ChannelManager {
        let (publisher, sub) = TemplateStatePublisher::new();
        publisher
            .publish(TemplateState::from_template_and_blob(
                &template(),
                &blob(),
                ScriptSigInputs::default(),
                1,
            ))
            .unwrap();
        // 1 H/s floor → any positive nominal_hash_rate clears the gate.
        // 60 SPM target → min_target_le ≈ 2^256/60 — extremely loose, lets
        // the legacy `target = [0xff; 32]` round-trip mostly intact in the
        // tests that pin LE byte order.
        ChannelManager::with_policy(sub.into_receiver(), 1.0, 60.0).unwrap()
    }

    #[test]
    fn allocator_partition_matches_wiki() {
        let (_p, sub) = TemplateStatePublisher::new();
        let mgr = ChannelManager::new(sub.into_receiver()).unwrap();
        assert_eq!(mgr.allocator.total_extranonce_len(), 12);
        assert_eq!(mgr.allocator.upstream_prefix_len(), 0);
        assert_eq!(mgr.allocator.local_prefix_len(), 0);
        assert_eq!(mgr.allocator.local_index_len(), 2);
        assert_eq!(mgr.allocator.rollable_extranonce_size(), 10);
    }

    #[test]
    fn open_extended_emits_success_job_snph() {
        let mut mgr = manager_with_template();
        let msg = OpenExtendedMiningChannel {
            request_id: 42,
            user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        };
        let out = mgr.handle_open_extended_mining_channel(msg);
        assert_eq!(
            out.len(),
            3,
            "expected Success + NewExtJob + SetNewPrevHash"
        );
        match (&out[0], &out[1], &out[2]) {
            (
                MiningOut::OpenExtendedMiningChannelSuccess(s),
                MiningOut::NewExtendedMiningJob(j),
                MiningOut::SetNewPrevHash(p),
            ) => {
                assert_eq!(s.request_id, 42);
                assert_eq!(s.channel_id, j.channel_id);
                assert_eq!(s.channel_id, p.channel_id);
                assert_eq!(j.job_id, p.job_id);
                assert!(j.is_future(), "first job must be future (min_ntime=None)");
                assert_eq!(s.extranonce_size, 10);
                // 2-byte prefix per partition.
                assert_eq!(s.extranonce_prefix.inner_as_ref().len(), 2);
                // Bug-B clamp: requested `[0xff; 32]` is wider than our
                // `min_target_le` (1 TH/s + 6 SPM); the success-target must
                // be the clamped value, NOT an echo of the attacker bytes.
                let on_wire: [u8; 32] = s.target.inner_as_ref().try_into().unwrap();
                assert_eq!(on_wire, mgr.min_target_le());
                assert_ne!(on_wire, [0xffu8; 32]);
                assert!(j.version_rolling_allowed);
            }
            other => panic!("unexpected outputs: {other:?}"),
        }
        assert_eq!(mgr.open_channel_count(), 1);
    }

    #[test]
    fn open_extended_below_min_hashrate_yields_invalid_nominal_hashrate() {
        // Live-OCEAN bug B: a client advertising < 1 TH/s must be rejected.
        let mut mgr = manager_with_template();
        let msg = OpenExtendedMiningChannel {
            request_id: 100,
            user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 5.0e9, // 5 GH/s — well below 1 TH/s
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        };
        let out = mgr.handle_open_extended_mining_channel(msg);
        assert_eq!(out.len(), 1);
        match &out[0] {
            MiningOut::OpenMiningChannelError(e) => {
                assert_eq!(e.request_id, 100);
                assert_eq!(e.error_code.inner_as_ref(), b"invalid-nominal-hashrate");
            }
            other => panic!("expected OpenMiningChannelError, got {other:?}"),
        }
        // No channel slot consumed.
        assert_eq!(mgr.open_channel_count(), 0);
    }

    #[test]
    fn open_extended_above_min_hashrate_clamps_target() {
        // 1.3 TH/s clears the floor; the emitted Success.target must be
        // ≤ min_target_le.
        let mut mgr = manager_with_template();
        let min_target = mgr.min_target_le();
        let msg = OpenExtendedMiningChannel {
            request_id: 101,
            user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        };
        let out = mgr.handle_open_extended_mining_channel(msg);
        let on_wire: [u8; 32] = match &out[0] {
            MiningOut::OpenExtendedMiningChannelSuccess(s) => {
                s.target.inner_as_ref().try_into().unwrap()
            }
            other => panic!("expected Success, got {other:?}"),
        };
        // Compare as 256-bit BE: on_wire must be ≤ min_target.
        let mut on_le = on_wire;
        let mut min_le = min_target;
        on_le.reverse();
        min_le.reverse();
        assert!(on_le <= min_le, "Success.target must be ≤ min_target_le");
    }

    #[test]
    fn open_standard_emits_success_job_snph_with_merkle_root() {
        let mut mgr = manager_with_template();
        let msg = OpenStandardMiningChannel {
            request_id: stratum_core::binary_sv2::U32AsRef::from(7u32),
            user_identity: "bitaxe.worker1"
                .to_string()
                .into_bytes()
                .try_into()
                .unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
        };
        let out = mgr.handle_open_standard_mining_channel(msg);
        assert_eq!(out.len(), 3);
        match (&out[0], &out[1], &out[2]) {
            (
                MiningOut::OpenStandardMiningChannelSuccess(s),
                MiningOut::NewMiningJob(j),
                MiningOut::SetNewPrevHash(p),
            ) => {
                assert_eq!(s.get_request_id_as_u32(), 7);
                assert_eq!(s.channel_id, j.channel_id);
                assert_eq!(s.channel_id, p.channel_id);
                assert_eq!(j.job_id, p.job_id);
                assert!(j.is_future());
                // Standard prefix is the full 12 bytes (rollable padded zero).
                assert_eq!(s.extranonce_prefix.inner_as_ref().len(), 12);
                // merkle_root is 32 bytes regardless of branch count.
                assert_eq!(j.merkle_root.inner_as_ref().len(), 32);
                // Bug-B clamp: target on the wire is min_target_le, not
                // the echo of attacker `[0xff; 32]`.
                let on_wire: [u8; 32] = s.target.inner_as_ref().try_into().unwrap();
                assert_eq!(on_wire, mgr.min_target_le());
                assert_ne!(on_wire, [0xffu8; 32]);
            }
            other => panic!("unexpected outputs: {other:?}"),
        }
    }

    #[test]
    fn close_channel_frees_slot() {
        let mut mgr = manager_with_template();
        let msg = OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: "alice".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        };
        let out = mgr.handle_open_extended_mining_channel(msg);
        let cid = match &out[0] {
            MiningOut::OpenExtendedMiningChannelSuccess(s) => s.channel_id,
            _ => panic!(),
        };
        assert_eq!(mgr.allocator.allocated_count(), 1);
        mgr.handle_close_channel(cid);
        assert_eq!(mgr.allocator.allocated_count(), 0);
        assert_eq!(mgr.open_channel_count(), 0);
    }

    #[test]
    fn empty_user_identity_yields_open_error() {
        let mut mgr = manager_with_template();
        let msg = OpenExtendedMiningChannel {
            request_id: 9,
            user_identity: Vec::<u8>::new().try_into().unwrap(),
            nominal_hash_rate: 0.0,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        };
        let out = mgr.handle_open_extended_mining_channel(msg);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], MiningOut::OpenMiningChannelError(_)));
    }

    #[test]
    fn template_update_re_emits_to_all_channels() {
        let mut mgr = manager_with_template();
        // Open an extended + a standard. Both at ≥ 1 TH/s to clear the
        // bug-B floor — the template-update path is independent of
        // hashrate policy, so any value above the floor works.
        let _ = mgr.handle_open_extended_mining_channel(OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: "a".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        });
        let _ = mgr.handle_open_standard_mining_channel(OpenStandardMiningChannel {
            request_id: stratum_core::binary_sv2::U32AsRef::from(2u32),
            user_identity: "b".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
        });
        assert_eq!(mgr.open_channel_count(), 2);

        let template = synthetic_template();
        let out = mgr.on_template_update(&template);
        // Two channels × (job + snph) = 4 messages.
        assert_eq!(out.len(), 4);
        let mut nemj = 0;
        let mut nmj = 0;
        let mut snph = 0;
        for m in &out {
            match m {
                MiningOut::NewExtendedMiningJob(_) => nemj += 1,
                MiningOut::NewMiningJob(_) => nmj += 1,
                MiningOut::SetNewPrevHash(_) => snph += 1,
                _ => panic!("unexpected variant in template-update emission"),
            }
        }
        assert_eq!(nemj, 1);
        assert_eq!(nmj, 1);
        assert_eq!(snph, 2);
    }

    #[test]
    fn open_extended_succ_target_serializes_le() {
        // GOLDEN: a known target round-trips through OpenExtendedMiningChannelSuccess
        // byte-for-byte. The wire field is U256 LE — i.e. the bytes we pass to
        // U256::from go onto the wire verbatim.
        //
        // Uses [`manager_with_template_low_floor`] so the bug-B clamp is
        // effectively unreachable (min_target_le ≈ 2^256/60 — anything less
        // than the high 1/60th of the 256-bit space round-trips unchanged).
        // The chosen pattern `target_le[i] = i` (high byte 0x1f) is well below.
        let mut mgr = manager_with_template_low_floor();
        // target = 0x00000000_ffff_0000... in display BE => internal-LE bytes
        // are  [..., 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00] little end then high.
        // We'll use a distinctive, palindrome-rejecting pattern so a flipped
        // byte order would fail loudly.
        let mut target_le = [0u8; 32];
        for (i, b) in target_le.iter_mut().enumerate() {
            *b = i as u8;
        }
        let msg = OpenExtendedMiningChannel {
            request_id: 999,
            user_identity: "x".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.0,
            max_target: U256::from(target_le),
            min_extranonce_size: 8,
        };
        let out = mgr.handle_open_extended_mining_channel(msg);
        match &out[0] {
            MiningOut::OpenExtendedMiningChannelSuccess(s) => {
                let on_wire = s.target.inner_as_ref();
                assert_eq!(on_wire, &target_le[..]);
                // First byte is the LSB (LE).
                assert_eq!(on_wire[0], 0x00);
                assert_eq!(on_wire[31], 0x1f);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn open_standard_succ_target_serializes_le() {
        let mut mgr = manager_with_template_low_floor();
        let mut target_le = [0u8; 32];
        for (i, b) in target_le.iter_mut().enumerate() {
            *b = i as u8;
        }
        let msg = OpenStandardMiningChannel {
            request_id: stratum_core::binary_sv2::U32AsRef::from(1u32),
            user_identity: "x".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.0,
            max_target: U256::from(target_le),
        };
        let out = mgr.handle_open_standard_mining_channel(msg);
        match &out[0] {
            MiningOut::OpenStandardMiningChannelSuccess(s) => {
                assert_eq!(s.target.inner_as_ref(), &target_le[..]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn snph_prev_hash_serializes_le() {
        // GOLDEN: SetNewPrevHash.prev_hash on the wire is the bytes from
        // TemplateState::prev_hash (internal-LE) verbatim.
        let mut mgr = manager_with_template();
        let _ = mgr.handle_open_extended_mining_channel(OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: "x".to_string().into_bytes().try_into().unwrap(),
            nominal_hash_rate: 1.3e12,
            max_target: U256::from([0xffu8; 32]),
            min_extranonce_size: 8,
        });
        // template_state's prev_hash is all-zero (template().previous_block_hash is "00".repeat(32)).
        // Use the on_template_update path with a non-zero prev_hash to assert byte order.
        let mut new_state = TemplateState::from_template_and_blob(
            &template(),
            &blob(),
            ScriptSigInputs::default(),
            2,
        );
        // Override prev_hash with a distinctive LE pattern.
        for (i, b) in new_state.prev_hash.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(0x0a);
        }
        let out = mgr.on_template_update(&new_state);
        let snph = out.iter().find_map(|m| match m {
            MiningOut::SetNewPrevHash(p) => Some(p),
            _ => None,
        });
        let snph = snph.expect("SetNewPrevHash present in template-update emission");
        assert_eq!(snph.prev_hash.inner_as_ref(), &new_state.prev_hash[..]);
        // First byte is the LSB; sanity-check it's NOT byte-flipped.
        assert_eq!(snph.prev_hash.inner_as_ref()[0], 0x0a);
        assert_eq!(snph.prev_hash.inner_as_ref()[1], 0x0d);
    }
}
