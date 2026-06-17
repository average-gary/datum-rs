use std::path::PathBuf;

use thiserror::Error;

use crate::{
    Config, COINBASE_TAGS_COMBINED_MAX, COINBASE_TAG_INDIVIDUAL_MAX, MAX_EXTRA_BLOCK_SUBMIT_URLS,
    MAX_EXTRA_BLOCK_SUBMIT_URL_LEN, STRATUM_V2_CERT_VALIDITY_SEC_HARD_CAP,
};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse: {0}")]
    Parse(#[source] serde_json::Error),
    #[error("invalid config: {} validation error(s)", .0.len())]
    Invalid(Vec<ValidationError>),
}

#[derive(Debug, Clone, Error, PartialEq)]
pub enum ValidationError {
    #[error(
        "bitcoind: missing RPC credentials — set bitcoind.rpccookiefile OR (bitcoind.rpcuser AND bitcoind.rpcpassword)"
    )]
    BitcoindMissingCredentials,
    #[error("bitcoind.rpcuser set but bitcoind.rpcpassword empty")]
    BitcoindRpcUserMissingPassword,
    #[error("bitcoind.rpcurl is required and must not be empty")]
    BitcoindRpcUrlEmpty,
    #[error("bitcoind.work_update_seconds={got} out of range [5, 120]")]
    BitcoindWorkUpdateSecondsOutOfRange { got: i32 },

    #[error("stratum.max_threads={got} exceeds hard cap 256")]
    StratumMaxThreadsTooHigh { got: i32 },
    #[error("stratum.max_clients_per_thread={got} exceeds hard cap 1024")]
    StratumMaxClientsPerThreadTooHigh { got: i32 },
    #[error(
        "stratum.max_clients={max_clients} exceeds max_threads*max_clients_per_thread={threads}*{per_thread}={cap}"
    )]
    StratumMaxClientsExceedsCap {
        max_clients: i32,
        threads: i32,
        per_thread: i32,
        cap: i64,
    },
    #[error("stratum.vardiff_min={got} must be >= 1")]
    StratumVardiffMinTooLow { got: u64 },
    #[error("stratum.vardiff_min={got} is not a power of 2 (auto-rounded down to {rounded})")]
    StratumVardiffMinNotPowerOfTwo { got: u64, rounded: u64 },
    #[error("stratum.vardiff_target_shares_min={got} must be >= 1")]
    StratumVardiffTargetSharesMinTooLow { got: i32 },
    #[error("stratum.vardiff_quickdiff_count={got} must be >= 4")]
    StratumVardiffQuickdiffCountTooLow { got: i32 },
    #[error("stratum.vardiff_quickdiff_delta={got} must be >= 3")]
    StratumVardiffQuickdiffDeltaTooLow { got: i32 },
    #[error("stratum.share_stale_seconds={got} out of range [60, 150]")]
    StratumShareStaleSecondsOutOfRange { got: i32 },
    #[error(
        "stratum.username_modifiers[{modifier}]: address proportions sum to {sum:.6}, expected 1.0"
    )]
    StratumUsernameModifierProportions { modifier: String, sum: f64 },

    #[error(
        "mining.coinbase_tag_primary length {got} exceeds individual limit {COINBASE_TAG_INDIVIDUAL_MAX}"
    )]
    MiningCoinbaseTagPrimaryTooLong { got: usize },
    #[error(
        "mining.coinbase_tag_secondary length {got} exceeds individual limit {COINBASE_TAG_INDIVIDUAL_MAX}"
    )]
    MiningCoinbaseTagSecondaryTooLong { got: usize },
    #[error(
        "mining.coinbase_tag_primary + coinbase_tag_secondary combined length {got} exceeds {COINBASE_TAGS_COMBINED_MAX}"
    )]
    MiningCoinbaseTagsCombinedTooLong { got: usize },
    #[error("mining.pool_address is required and must not be empty")]
    MiningPoolAddressEmpty,

    #[error(
        "extra_block_submissions.urls has {got} entries, exceeds limit {MAX_EXTRA_BLOCK_SUBMIT_URLS}"
    )]
    ExtraBlockSubmitTooManyUrls { got: usize },
    #[error(
        "extra_block_submissions.urls[{idx}] length {got} exceeds {MAX_EXTRA_BLOCK_SUBMIT_URL_LEN}"
    )]
    ExtraBlockSubmitUrlTooLong { idx: usize, got: usize },

    #[error(
        "datum.protocol_global_timeout={got} must be >= bitcoind.work_update_seconds+5 ({floor})"
    )]
    DatumProtocolTimeoutTooLow { got: i32, floor: i32 },
    #[error("datum.pooled_mining_only=true but datum.pool_host is empty")]
    DatumPooledMiningWithoutHost,
    #[error("datum.pool_pubkey must be empty or 128 hex chars (got length {got})")]
    DatumPoolPubkeyBadLength { got: usize },
    #[error("datum.pool_pubkey contains non-hex characters")]
    DatumPoolPubkeyNotHex,

    #[error("logger.log_to_file=true but logger.log_file is empty")]
    LoggerFileWithoutPath,
    #[error("logger.log_level_console={got} out of range [0, 5]")]
    LoggerLevelConsoleOutOfRange { got: i32 },
    #[error("logger.log_level_file={got} out of range [0, 5]")]
    LoggerLevelFileOutOfRange { got: i32 },

    #[error(
        "stratum_v2.cert_validity_sec={got} exceeds hard cap {STRATUM_V2_CERT_VALIDITY_SEC_HARD_CAP} \
         (1 year) — see SRI #2103 for the overflow rationale"
    )]
    StratumV2CertValiditySecTooLarge { got: u32 },
    #[error("stratum_v2.enabled=true but stratum_v2.authority_pubkey_path is empty")]
    StratumV2EnabledWithoutAuthorityPubkey,
    #[error("stratum_v2.enabled=true but stratum_v2.authority_secret_path is empty")]
    StratumV2EnabledWithoutAuthoritySecret,
}

pub fn validate(c: &Config) -> Result<(), Vec<ValidationError>> {
    let mut errs = Vec::new();
    validate_bitcoind(c, &mut errs);
    validate_stratum(c, &mut errs);
    validate_stratum_v2(c, &mut errs);
    validate_mining(c, &mut errs);
    validate_extra_block_submissions(c, &mut errs);
    validate_datum(c, &mut errs);
    validate_logger(c, &mut errs);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn validate_bitcoind(c: &Config, errs: &mut Vec<ValidationError>) {
    let b = &c.bitcoind;

    let has_cookie = !b.rpccookiefile.is_empty();
    let has_user = !b.rpcuser.is_empty();
    let has_pass = !b.rpcpassword.is_empty();
    if !has_cookie && !has_user && !has_pass {
        errs.push(ValidationError::BitcoindMissingCredentials);
    } else if has_user && !has_pass {
        errs.push(ValidationError::BitcoindRpcUserMissingPassword);
    }

    if b.rpcurl.is_empty() {
        errs.push(ValidationError::BitcoindRpcUrlEmpty);
    }

    if !(5..=120).contains(&b.work_update_seconds) {
        errs.push(ValidationError::BitcoindWorkUpdateSecondsOutOfRange {
            got: b.work_update_seconds,
        });
    }
}

fn validate_stratum(c: &Config, errs: &mut Vec<ValidationError>) {
    let s = &c.stratum;

    if s.max_threads > 256 {
        errs.push(ValidationError::StratumMaxThreadsTooHigh { got: s.max_threads });
    }
    if s.max_clients_per_thread > 1024 {
        errs.push(ValidationError::StratumMaxClientsPerThreadTooHigh {
            got: s.max_clients_per_thread,
        });
    }
    let cap = (s.max_threads as i64) * (s.max_clients_per_thread as i64);
    if (s.max_clients as i64) > cap {
        errs.push(ValidationError::StratumMaxClientsExceedsCap {
            max_clients: s.max_clients,
            threads: s.max_threads,
            per_thread: s.max_clients_per_thread,
            cap,
        });
    }

    if s.vardiff_min < 1 {
        errs.push(ValidationError::StratumVardiffMinTooLow { got: s.vardiff_min });
    } else if !s.vardiff_min.is_power_of_two() {
        let rounded = prev_power_of_two(s.vardiff_min);
        errs.push(ValidationError::StratumVardiffMinNotPowerOfTwo {
            got: s.vardiff_min,
            rounded,
        });
    }

    if s.vardiff_target_shares_min < 1 {
        errs.push(ValidationError::StratumVardiffTargetSharesMinTooLow {
            got: s.vardiff_target_shares_min,
        });
    }
    if s.vardiff_quickdiff_count < 4 {
        errs.push(ValidationError::StratumVardiffQuickdiffCountTooLow {
            got: s.vardiff_quickdiff_count,
        });
    }
    if s.vardiff_quickdiff_delta < 3 {
        errs.push(ValidationError::StratumVardiffQuickdiffDeltaTooLow {
            got: s.vardiff_quickdiff_delta,
        });
    }
    if !(60..=150).contains(&s.share_stale_seconds) {
        errs.push(ValidationError::StratumShareStaleSecondsOutOfRange {
            got: s.share_stale_seconds,
        });
    }

    for (name, modifier) in &s.username_modifiers {
        let sum: f64 = modifier.values().sum();
        if (sum - 1.0).abs() > 1e-6 {
            errs.push(ValidationError::StratumUsernameModifierProportions {
                modifier: name.clone(),
                sum,
            });
        }
    }
}

fn validate_stratum_v2(c: &Config, errs: &mut Vec<ValidationError>) {
    let s = &c.stratum_v2;
    // The cap applies whether or not the listener is enabled — a config that
    // sets a too-large value is invalid even if the operator hasn't flipped
    // `enabled` yet (catches the misconfig early).
    if s.cert_validity_sec > STRATUM_V2_CERT_VALIDITY_SEC_HARD_CAP {
        errs.push(ValidationError::StratumV2CertValiditySecTooLarge {
            got: s.cert_validity_sec,
        });
    }
    if s.enabled {
        if s.authority_pubkey_path.as_os_str().is_empty() {
            errs.push(ValidationError::StratumV2EnabledWithoutAuthorityPubkey);
        }
        if s.authority_secret_path.as_os_str().is_empty() {
            errs.push(ValidationError::StratumV2EnabledWithoutAuthoritySecret);
        }
    }
}

fn validate_mining(c: &Config, errs: &mut Vec<ValidationError>) {
    let m = &c.mining;
    if m.pool_address.is_empty() {
        errs.push(ValidationError::MiningPoolAddressEmpty);
    }
    if m.coinbase_tag_primary.len() > COINBASE_TAG_INDIVIDUAL_MAX {
        errs.push(ValidationError::MiningCoinbaseTagPrimaryTooLong {
            got: m.coinbase_tag_primary.len(),
        });
    }
    if m.coinbase_tag_secondary.len() > COINBASE_TAG_INDIVIDUAL_MAX {
        errs.push(ValidationError::MiningCoinbaseTagSecondaryTooLong {
            got: m.coinbase_tag_secondary.len(),
        });
    }
    let combined = m.coinbase_tag_primary.len() + m.coinbase_tag_secondary.len();
    if combined > COINBASE_TAGS_COMBINED_MAX {
        errs.push(ValidationError::MiningCoinbaseTagsCombinedTooLong { got: combined });
    }
}

fn validate_extra_block_submissions(c: &Config, errs: &mut Vec<ValidationError>) {
    let urls = &c.extra_block_submissions.urls;
    if urls.len() > MAX_EXTRA_BLOCK_SUBMIT_URLS {
        errs.push(ValidationError::ExtraBlockSubmitTooManyUrls { got: urls.len() });
    }
    for (idx, url) in urls.iter().enumerate() {
        if url.len() > MAX_EXTRA_BLOCK_SUBMIT_URL_LEN {
            errs.push(ValidationError::ExtraBlockSubmitUrlTooLong {
                idx,
                got: url.len(),
            });
        }
    }
}

fn validate_datum(c: &Config, errs: &mut Vec<ValidationError>) {
    let d = &c.datum;

    let floor = c.bitcoind.work_update_seconds.saturating_add(5);
    if d.protocol_global_timeout < floor {
        errs.push(ValidationError::DatumProtocolTimeoutTooLow {
            got: d.protocol_global_timeout,
            floor,
        });
    }
    if d.pooled_mining_only && d.pool_host.is_empty() {
        errs.push(ValidationError::DatumPooledMiningWithoutHost);
    }
    if !d.pool_pubkey.is_empty() {
        if d.pool_pubkey.len() != 128 {
            errs.push(ValidationError::DatumPoolPubkeyBadLength {
                got: d.pool_pubkey.len(),
            });
        } else if !d.pool_pubkey.chars().all(|ch| ch.is_ascii_hexdigit()) {
            errs.push(ValidationError::DatumPoolPubkeyNotHex);
        }
    }
}

fn validate_logger(c: &Config, errs: &mut Vec<ValidationError>) {
    let l = &c.logger;
    if l.log_to_file && l.log_file.is_empty() {
        errs.push(ValidationError::LoggerFileWithoutPath);
    }
    if !(0..=5).contains(&l.log_level_console) {
        errs.push(ValidationError::LoggerLevelConsoleOutOfRange {
            got: l.log_level_console,
        });
    }
    if !(0..=5).contains(&l.log_level_file) {
        errs.push(ValidationError::LoggerLevelFileOutOfRange {
            got: l.log_level_file,
        });
    }
}

fn prev_power_of_two(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        1u64 << (63 - n.leading_zeros())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn min_valid_config() -> Config {
        let mut c = Config::default();
        c.bitcoind.rpccookiefile = "/var/run/bitcoin/cookie".into();
        c.bitcoind.rpcurl = "http://127.0.0.1:8332".into();
        c.mining.pool_address = "bc1qexample".into();
        c
    }

    #[test]
    fn defaults_alone_fail_validation() {
        let c = Config::default();
        let errs = c.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::BitcoindMissingCredentials)));
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::BitcoindRpcUrlEmpty)));
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::MiningPoolAddressEmpty)));
    }

    #[test]
    fn min_valid_passes() {
        min_valid_config().validate().expect("should pass");
    }

    #[test]
    fn vardiff_min_must_be_power_of_two() {
        let mut c = min_valid_config();
        c.stratum.vardiff_min = 16385;
        let errs = c.validate().unwrap_err();
        assert!(matches!(
            errs[0],
            ValidationError::StratumVardiffMinNotPowerOfTwo {
                got: 16385,
                rounded: 16384
            }
        ));
    }

    #[test]
    fn coinbase_tag_combined_limit() {
        let mut c = min_valid_config();
        c.mining.coinbase_tag_primary = "a".repeat(50);
        c.mining.coinbase_tag_secondary = "b".repeat(50);
        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::MiningCoinbaseTagsCombinedTooLong { got: 100 }
        )));
    }

    #[test]
    fn coinbase_tag_individual_limit() {
        let mut c = min_valid_config();
        c.mining.coinbase_tag_primary = "a".repeat(61);
        c.mining.coinbase_tag_secondary = "b".repeat(20);
        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::MiningCoinbaseTagPrimaryTooLong { got: 61 }
        )));
    }

    #[test]
    fn share_stale_seconds_range() {
        let mut c = min_valid_config();
        c.stratum.share_stale_seconds = 30;
        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::StratumShareStaleSecondsOutOfRange { got: 30 }
        )));
        c.stratum.share_stale_seconds = 200;
        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::StratumShareStaleSecondsOutOfRange { got: 200 }
        )));
    }

    #[test]
    fn protocol_timeout_floor_tracks_work_update() {
        let mut c = min_valid_config();
        c.bitcoind.work_update_seconds = 90;
        c.datum.protocol_global_timeout = 60;
        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::DatumProtocolTimeoutTooLow { got: 60, floor: 95 }
        )));
    }

    #[test]
    fn pool_pubkey_length_and_hex() {
        let mut c = min_valid_config();
        c.datum.pool_pubkey = "abcd".into();
        let errs = c.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::DatumPoolPubkeyBadLength { got: 4 })));

        c.datum.pool_pubkey = "z".repeat(128);
        let errs = c.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::DatumPoolPubkeyNotHex)));
    }

    #[test]
    fn empty_pool_pubkey_allowed() {
        let mut c = min_valid_config();
        c.datum.pool_pubkey = String::new();
        c.validate().expect("empty pubkey should pass");
    }

    #[test]
    fn pooled_mining_without_host_fails() {
        let mut c = min_valid_config();
        c.datum.pool_host = String::new();
        c.datum.pooled_mining_only = true;
        let errs = c.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::DatumPooledMiningWithoutHost)));
    }

    #[test]
    fn rpc_user_without_password_fails() {
        let mut c = min_valid_config();
        c.bitcoind.rpccookiefile = String::new();
        c.bitcoind.rpcuser = "rpc".into();
        c.bitcoind.rpcpassword = String::new();
        let errs = c.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::BitcoindRpcUserMissingPassword)));
    }

    #[test]
    fn max_clients_exceeds_cap() {
        let mut c = min_valid_config();
        c.stratum.max_threads = 4;
        c.stratum.max_clients_per_thread = 100;
        c.stratum.max_clients = 1000;
        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::StratumMaxClientsExceedsCap {
                max_clients: 1000,
                ..
            }
        )));
    }

    #[test]
    fn parses_minimal_json() {
        let json = r#"{
            "bitcoind": {"rpccookiefile": "/c", "rpcurl": "http://127.0.0.1:8332"},
            "mining": {"pool_address": "bc1qexample"}
        }"#;
        let c = Config::from_json_str(json).unwrap();
        c.validate().expect("should pass");
        assert_eq!(c.stratum.listen_port, 23334);
        assert_eq!(c.datum.pool_port, 28915);
        assert_eq!(c.datum.pool_host, "datum-beta1.mine.ocean.xyz");
    }

    #[test]
    fn unknown_keys_silently_ignored() {
        let json = r#"{
            "bitcoind": {"rpccookiefile": "/c", "rpcurl": "http://127.0.0.1:8332", "future_key": 42},
            "mining": {"pool_address": "bc1q"},
            "completely_made_up_section": {"x": 1}
        }"#;
        Config::from_json_str(json).unwrap().validate().unwrap();
    }

    #[test]
    fn prev_power_of_two_works() {
        assert_eq!(prev_power_of_two(16384), 16384);
        assert_eq!(prev_power_of_two(16385), 16384);
        assert_eq!(prev_power_of_two(1), 1);
        assert_eq!(prev_power_of_two(2), 2);
        assert_eq!(prev_power_of_two(3), 2);
    }

    #[test]
    fn example_json_round_trips() {
        let json = Config::example_json();
        let c: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(c.stratum.listen_port, 23334);
        assert_eq!(c.datum.pool_host, "datum-beta1.mine.ocean.xyz");
    }

    #[test]
    fn stratum_v2_cert_validity_hard_cap_rejects_above_one_year() {
        let mut c = min_valid_config();
        c.stratum_v2.cert_validity_sec = STRATUM_V2_CERT_VALIDITY_SEC_HARD_CAP + 1;
        let errs = c.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::StratumV2CertValiditySecTooLarge { .. })));
    }

    #[test]
    fn stratum_v2_cert_validity_hard_cap_accepts_one_year_exactly() {
        let mut c = min_valid_config();
        c.stratum_v2.cert_validity_sec = STRATUM_V2_CERT_VALIDITY_SEC_HARD_CAP;
        c.validate().expect("1-year cert_validity_sec is allowed");
    }

    #[test]
    fn stratum_v2_default_disabled_passes() {
        let c = min_valid_config();
        assert!(!c.stratum_v2.enabled);
        c.validate().expect("disabled SV2 listener should not fail");
    }

    #[test]
    fn stratum_v2_enabled_without_keys_fails() {
        let mut c = min_valid_config();
        c.stratum_v2.enabled = true;
        // both paths default to empty PathBuf
        let errs = c.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::StratumV2EnabledWithoutAuthorityPubkey)));
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::StratumV2EnabledWithoutAuthoritySecret)));
    }

    #[test]
    fn stratum_v2_enabled_with_keys_passes() {
        let mut c = min_valid_config();
        c.stratum_v2.enabled = true;
        c.stratum_v2.authority_pubkey_path = "/etc/datum/sv2_pub.txt".into();
        c.stratum_v2.authority_secret_path = "/etc/datum/sv2_sec.txt".into();
        c.validate().expect("enabled with paths should pass");
        assert!(c.stratum_v2.is_active());
    }
}
