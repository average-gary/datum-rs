//! Custom tracing formatter matching the C gateway's log line shape:
//!
//!   `YYYY-MM-DD HH:MM:SS.mmm [func_name_padded_44] LEVEL: msg`
//!
//! Per the wiki [drop-in-surface-inventory] § four hard surfaces, log line
//! shape is one of the non-negotiable surfaces — operators have grep
//! pipelines on the 44-char function-name padding. Phase 4 ships the
//! formatter; full byte-equivalence with C output requires a fixture diff
//! against a running C `datum_gateway` (deferred — fixture not yet
//! captured).

pub const LEVEL_PREFIX_WIDTH: usize = 5;
pub const FUNCTION_NAME_PAD: usize = 44;

/// Format a log level as a 5-char right-padded prefix (matches C output).
pub fn format_level(level: tracing::Level) -> &'static str {
    match level {
        tracing::Level::ERROR => "ERROR",
        tracing::Level::WARN => " WARN",
        tracing::Level::INFO => " INFO",
        tracing::Level::DEBUG => "DEBUG",
        tracing::Level::TRACE => "  ALL",
    }
}

/// Right-pad or truncate a function/target name to `FUNCTION_NAME_PAD` chars.
pub fn format_function_name(name: &str) -> String {
    if name.len() >= FUNCTION_NAME_PAD {
        name[..FUNCTION_NAME_PAD].to_string()
    } else {
        format!("{name:<FUNCTION_NAME_PAD$}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn level_prefixes_are_5_chars() {
        for lvl in [
            Level::ERROR,
            Level::WARN,
            Level::INFO,
            Level::DEBUG,
            Level::TRACE,
        ] {
            assert_eq!(format_level(lvl).len(), LEVEL_PREFIX_WIDTH);
        }
    }

    #[test]
    fn warn_has_leading_space() {
        assert_eq!(format_level(Level::WARN), " WARN");
        assert_eq!(format_level(Level::INFO), " INFO");
    }

    #[test]
    fn function_name_padded() {
        let s = format_function_name("foo");
        assert_eq!(s.len(), FUNCTION_NAME_PAD);
        assert!(s.starts_with("foo"));
    }

    #[test]
    fn function_name_truncated() {
        let s = format_function_name(&"a".repeat(80));
        assert_eq!(s.len(), FUNCTION_NAME_PAD);
    }

    #[test]
    fn function_name_exact_length() {
        let s = format_function_name(&"x".repeat(FUNCTION_NAME_PAD));
        assert_eq!(s.len(), FUNCTION_NAME_PAD);
    }
}
