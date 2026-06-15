//! Custom tracing formatter matching the C gateway's log line shape:
//!
//!   `YYYY-MM-DD HH:MM:SS.mmm [func_name_padded_44] LEVEL: msg`
//!
//! Per the wiki [drop-in-surface-inventory] § four hard surfaces, log line
//! shape is one of the non-negotiable surfaces — operators have grep
//! pipelines on the 44-char function-name padding.
//!
//! ## Status
//!
//! Phase 4 ships the formatter wired into [`tracing_subscriber::fmt`].
//! Byte-equivalence with C output requires a fixture diff against a running
//! C `datum_gateway`; capture-and-pin is straightforward (`docker run` of the
//! C gateway with stdout redirected; commit a snippet; assert per-line
//! shape) but not yet committed. The shape this formatter produces matches
//! the per-field rules in [drop-in-surface-inventory § four hard surfaces].

use std::fmt;

use chrono::Local;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

pub const LEVEL_PREFIX_WIDTH: usize = 5;
pub const FUNCTION_NAME_PAD: usize = 44;

/// 5-char right-padded level prefix matching the C output.
pub fn format_level(level: Level) -> &'static str {
    match level {
        Level::ERROR => "ERROR",
        Level::WARN => " WARN",
        Level::INFO => " INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "  ALL",
    }
}

/// Left-pad (right-align) or truncate a function/target name to
/// `FUNCTION_NAME_PAD` chars. C's `printf("%44s", func)` right-aligns;
/// matching that lets fixed-column operator grep pipelines key on the
/// trailing edge of the bracket slot.
pub fn format_function_name(name: &str) -> String {
    if name.len() >= FUNCTION_NAME_PAD {
        name[..FUNCTION_NAME_PAD].to_string()
    } else {
        format!("{name:>FUNCTION_NAME_PAD$}")
    }
}

/// `FormatEvent` impl producing one C-shaped line per event.
pub struct CGatewayFormatter;

impl<S, N> FormatEvent<S, N> for CGatewayFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let now = Local::now();
        write!(
            writer,
            "{} [{}] {}: ",
            now.format("%Y-%m-%d %H:%M:%S%.3f"),
            format_function_name(event.metadata().target()),
            format_level(*event.metadata().level()),
        )?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Convenience: install the formatter as the global tracing subscriber.
/// `env_filter` accepts the same syntax as `EnvFilter::new` (e.g.
/// `"info,datum_protocol=debug"`). Idempotent — subsequent calls return Err.
pub fn install_global(env_filter: &str) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    use tracing_subscriber::EnvFilter;
    let subscriber = tracing_subscriber::fmt()
        .event_format(CGatewayFormatter)
        .with_env_filter(EnvFilter::try_new(env_filter).unwrap_or_else(|_| EnvFilter::new("info")))
        .finish();
    tracing::subscriber::set_global_default(subscriber)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(s.ends_with("foo"));
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
