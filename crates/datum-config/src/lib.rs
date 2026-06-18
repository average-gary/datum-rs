use std::path::Path;

use serde::{Deserialize, Serialize};

pub mod sections;
mod validate;

pub use sections::{
    ApiConfig, BitcoindConfig, DatumConfig, ExtraBlockSubmissionsConfig, LoggerConfig,
    MiningConfig, StratumConfig, StratumV2Config, UsernameModifier,
};
pub use validate::{ConfigError, ValidationError};

pub const DEFAULT_OCEAN_POOL_HOST: &str = "datum-beta1.mine.ocean.xyz";
pub const DEFAULT_OCEAN_POOL_PORT: u16 = 28915;
pub const DEFAULT_OCEAN_POOL_PUBKEY: &str = "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003";

pub const DEFAULT_STRATUM_LISTEN_PORT: u16 = 23334;
pub const DEFAULT_STRATUM_V2_LISTEN_ADDR: &str = "0.0.0.0";
pub const DEFAULT_STRATUM_V2_LISTEN_PORT: u16 = 23335;
pub const DEFAULT_STRATUM_V2_CERT_VALIDITY_SEC: u32 = 3600;
/// Hard cap on `cert_validity_sec` per [SRI #2103](https://github.com/stratum-mining/stratum/issues/2103).
/// `now + cert_validity_sec` is computed as `u32` saturating-add inside SRI's
/// `noise_sv2` responder; allowing the operator to configure the full year is
/// fine, but anything above wraps or trips the absolute bound check on
/// post-2106 deployments. 31_536_000 = 365 * 86_400 = one calendar year.
pub const STRATUM_V2_CERT_VALIDITY_SEC_HARD_CAP: u32 = 31_536_000;
/// Minimum supported downstream hashrate, in H/s. Defaults to 1 TH/s — any
/// `OpenChannel` / `UpdateChannel` advertising less is rejected with
/// `invalid-nominal-hashrate`. The same value drives the SetTarget clamp:
/// no emitted target may exceed `hash_rate_to_target(min_hashrate_threshold,
/// expected_share_per_minute)` regardless of vardiff state or client request.
/// See live-OCEAN bug B (2026-06-16): a misconfigured mining_device with
/// `--nominal-hashrate-multiplier 0.001` advertised ~5 KH/s, the listener
/// echoed back `target = 0xff..ff = 2^256-1` and produced a share storm.
pub const DEFAULT_STRATUM_V2_MIN_HASHRATE_THRESHOLD: f64 = 1.0e12;
/// Per-channel target shares-per-minute, used to compute `target_at_min_hashrate`
/// for the SetTarget clamp. 6.0 mirrors DMND production (per the SV2
/// architecture playbook §7).
pub const DEFAULT_STRATUM_V2_EXPECTED_SHARE_PER_MINUTE: f32 = 6.0;
/// Upper bound on `expected_share_per_minute`. Anything above is almost
/// certainly a typo (1000+ shares/min/channel is not a real workload) and
/// would produce an unreasonably high target.
pub const STRATUM_V2_EXPECTED_SHARE_PER_MINUTE_MAX: f32 = 10_000.0;
pub const DEFAULT_API_LISTEN_PORT: u16 = 0;

pub const COINBASE_TAGS_COMBINED_MAX: usize = 88;
pub const COINBASE_TAG_INDIVIDUAL_MAX: usize = 60;
pub const MAX_EXTRA_BLOCK_SUBMIT_URLS: usize = 32;
pub const MAX_EXTRA_BLOCK_SUBMIT_URL_LEN: usize = 512;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub bitcoind: BitcoindConfig,
    #[serde(default)]
    pub stratum: StratumConfig,
    #[serde(default)]
    pub stratum_v2: StratumV2Config,
    #[serde(default)]
    pub mining: MiningConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub extra_block_submissions: ExtraBlockSubmissionsConfig,
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub datum: DatumConfig,
}

impl Config {
    pub fn from_json_str(s: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(s).map_err(ConfigError::Parse)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json_str(&text)
    }

    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        validate::validate(self)
    }

    pub fn example() -> Self {
        Self::default()
    }

    pub fn example_json() -> String {
        serde_json::to_string_pretty(&Self::example()).expect("Default config is JSON-safe")
    }
}
