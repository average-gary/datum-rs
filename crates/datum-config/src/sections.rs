use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    DEFAULT_API_LISTEN_PORT, DEFAULT_OCEAN_POOL_HOST, DEFAULT_OCEAN_POOL_PORT,
    DEFAULT_OCEAN_POOL_PUBKEY, DEFAULT_STRATUM_LISTEN_PORT, DEFAULT_STRATUM_V2_LISTEN_PORT,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoindConfig {
    #[serde(default)]
    pub rpccookiefile: String,
    #[serde(default)]
    pub rpcuser: String,
    #[serde(default)]
    pub rpcpassword: String,
    #[serde(default)]
    pub rpcurl: String,
    #[serde(default = "default_work_update_seconds")]
    pub work_update_seconds: i32,
    #[serde(default = "default_true")]
    pub notify_fallback: bool,
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        Self {
            rpccookiefile: String::new(),
            rpcuser: String::new(),
            rpcpassword: String::new(),
            rpcurl: String::new(),
            work_update_seconds: 40,
            notify_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumConfig {
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default = "default_stratum_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_max_clients")]
    pub max_clients: i32,
    #[serde(default = "default_max_threads")]
    pub max_threads: i32,
    #[serde(default = "default_max_clients_per_thread")]
    pub max_clients_per_thread: i32,
    #[serde(default = "default_trust_proxy")]
    pub trust_proxy: i32,
    #[serde(default = "default_vardiff_min")]
    pub vardiff_min: u64,
    #[serde(default = "default_vardiff_target_shares_min")]
    pub vardiff_target_shares_min: i32,
    #[serde(default = "default_vardiff_quickdiff_count")]
    pub vardiff_quickdiff_count: i32,
    #[serde(default = "default_vardiff_quickdiff_delta")]
    pub vardiff_quickdiff_delta: i32,
    #[serde(default = "default_share_stale_seconds")]
    pub share_stale_seconds: i32,
    #[serde(default = "default_true")]
    pub fingerprint_miners: bool,
    #[serde(default = "default_idle_timeout_no_subscribe")]
    pub idle_timeout_no_subscribe: i32,
    #[serde(default = "default_idle_timeout_no_shares")]
    pub idle_timeout_no_shares: i32,
    #[serde(default)]
    pub idle_timeout_max_last_work: i32,
    #[serde(default)]
    pub username_modifiers: BTreeMap<String, UsernameModifier>,
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::new(),
            listen_port: DEFAULT_STRATUM_LISTEN_PORT,
            max_clients: 1024,
            max_threads: 8,
            max_clients_per_thread: 128,
            trust_proxy: -1,
            vardiff_min: 16384,
            vardiff_target_shares_min: 8,
            vardiff_quickdiff_count: 8,
            vardiff_quickdiff_delta: 8,
            share_stale_seconds: 120,
            fingerprint_miners: true,
            idle_timeout_no_subscribe: 15,
            idle_timeout_no_shares: 7200,
            idle_timeout_max_last_work: 0,
            username_modifiers: BTreeMap::new(),
        }
    }
}

/// Username modifier: maps Bitcoin payout addresses to a proportion of shares
/// (proportions across one modifier sum to 1.0).
pub type UsernameModifier = BTreeMap<String, f64>;

/// Stratum V2 listener — additive vs the C gateway. Disabled by default to
/// preserve drop-in parity with C; operators opt in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumV2Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default = "default_stratum_v2_listen_port")]
    pub listen_port: u16,
}

impl Default for StratumV2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: String::new(),
            listen_port: DEFAULT_STRATUM_V2_LISTEN_PORT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    #[serde(default)]
    pub pool_address: String,
    #[serde(default = "default_coinbase_tag_primary")]
    pub coinbase_tag_primary: String,
    #[serde(default = "default_coinbase_tag_secondary")]
    pub coinbase_tag_secondary: String,
    #[serde(default = "default_coinbase_unique_id")]
    pub coinbase_unique_id: u32,
    #[serde(default)]
    pub save_submitblocks_dir: String,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            pool_address: String::new(),
            coinbase_tag_primary: "DATUM Gateway".to_string(),
            coinbase_tag_secondary: "DATUM User".to_string(),
            coinbase_unique_id: 4242,
            save_submitblocks_dir: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub admin_password: String,
    #[serde(default)]
    pub allow_insecure_auth: bool,
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default = "default_api_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub modify_conf: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtraBlockSubmissionsConfig {
    #[serde(default)]
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    #[serde(default = "default_true")]
    pub log_to_console: bool,
    #[serde(default)]
    pub log_to_stderr: bool,
    #[serde(default)]
    pub log_to_file: bool,
    #[serde(default)]
    pub log_file: String,
    #[serde(default = "default_true")]
    pub log_rotate_daily: bool,
    #[serde(default = "default_true")]
    pub log_calling_function: bool,
    #[serde(default = "default_log_level_console")]
    pub log_level_console: i32,
    #[serde(default = "default_log_level_file")]
    pub log_level_file: i32,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            log_to_console: true,
            log_to_stderr: false,
            log_to_file: false,
            log_file: String::new(),
            log_rotate_daily: true,
            log_calling_function: true,
            log_level_console: 2,
            log_level_file: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatumConfig {
    #[serde(default = "default_pool_host")]
    pub pool_host: String,
    #[serde(default = "default_pool_port")]
    pub pool_port: u16,
    #[serde(default = "default_pool_pubkey")]
    pub pool_pubkey: String,
    #[serde(default = "default_true")]
    pub pool_pass_workers: bool,
    #[serde(default = "default_true")]
    pub pool_pass_full_users: bool,
    #[serde(default = "default_true")]
    pub always_pay_self: bool,
    #[serde(default = "default_true")]
    pub pooled_mining_only: bool,
    #[serde(default = "default_protocol_global_timeout")]
    pub protocol_global_timeout: i32,
}

impl Default for DatumConfig {
    fn default() -> Self {
        Self {
            pool_host: DEFAULT_OCEAN_POOL_HOST.to_string(),
            pool_port: DEFAULT_OCEAN_POOL_PORT,
            pool_pubkey: DEFAULT_OCEAN_POOL_PUBKEY.to_string(),
            pool_pass_workers: true,
            pool_pass_full_users: true,
            always_pay_self: true,
            pooled_mining_only: true,
            protocol_global_timeout: 60,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_work_update_seconds() -> i32 {
    40
}
fn default_stratum_listen_port() -> u16 {
    DEFAULT_STRATUM_LISTEN_PORT
}
fn default_stratum_v2_listen_port() -> u16 {
    DEFAULT_STRATUM_V2_LISTEN_PORT
}
fn default_api_listen_port() -> u16 {
    DEFAULT_API_LISTEN_PORT
}
fn default_max_clients() -> i32 {
    1024
}
fn default_max_threads() -> i32 {
    8
}
fn default_max_clients_per_thread() -> i32 {
    128
}
fn default_trust_proxy() -> i32 {
    -1
}
fn default_vardiff_min() -> u64 {
    16384
}
fn default_vardiff_target_shares_min() -> i32 {
    8
}
fn default_vardiff_quickdiff_count() -> i32 {
    8
}
fn default_vardiff_quickdiff_delta() -> i32 {
    8
}
fn default_share_stale_seconds() -> i32 {
    120
}
fn default_idle_timeout_no_subscribe() -> i32 {
    15
}
fn default_idle_timeout_no_shares() -> i32 {
    7200
}
fn default_coinbase_tag_primary() -> String {
    "DATUM Gateway".to_string()
}
fn default_coinbase_tag_secondary() -> String {
    "DATUM User".to_string()
}
fn default_coinbase_unique_id() -> u32 {
    4242
}
fn default_log_level_console() -> i32 {
    2
}
fn default_log_level_file() -> i32 {
    1
}
fn default_pool_host() -> String {
    DEFAULT_OCEAN_POOL_HOST.to_string()
}
fn default_pool_port() -> u16 {
    DEFAULT_OCEAN_POOL_PORT
}
fn default_pool_pubkey() -> String {
    DEFAULT_OCEAN_POOL_PUBKEY.to_string()
}
fn default_protocol_global_timeout() -> i32 {
    60
}
