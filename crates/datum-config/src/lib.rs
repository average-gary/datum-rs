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
pub const DEFAULT_STRATUM_V2_LISTEN_PORT: u16 = 23335;
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
