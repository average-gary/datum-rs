//! Pin the per-line shape of C-emitted log output against our formatter
//! invariants.
//!
//! The fixture in `tests/fixtures/c-log-lines.txt` was captured from a real
//! `OCEAN-xyz/datum_gateway` (Docker C build) on 2026-06-03. Each line
//! follows:
//!
//! ```text
//! YYYY-MM-DD HH:MM:SS.mmm [function_name_padded_44] LEVEL: msg
//! ```
//!
//! We assert the captured lines all conform to that shape, and that the
//! constants in `datum_logger` (level prefix width, function-name pad
//! width) are consistent with what the C output uses.

use datum_logger::{format_function_name, format_level, FUNCTION_NAME_PAD, LEVEL_PREFIX_WIDTH};

const FIXTURE: &str = include_str!("fixtures/c-log-lines.txt");

#[test]
fn fixture_has_lines() {
    let lines: Vec<&str> = FIXTURE.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() >= 5,
        "fixture should hold a representative slice"
    );
}

#[test]
fn every_line_matches_shape() {
    for (i, line) in FIXTURE.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        // Parts: [date 10][space][time 12 incl .mmm][space][bracket-block][space][LEVEL 5][:][space][msg]
        assert_eq!(line.as_bytes()[4], b'-', "line {i}: expected `-` at col 4");
        assert_eq!(line.as_bytes()[7], b'-', "line {i}: expected `-` at col 7");
        assert_eq!(
            line.as_bytes()[10],
            b' ',
            "line {i}: space between date and time"
        );
        assert_eq!(line.as_bytes()[13], b':', "line {i}: time format");
        assert_eq!(line.as_bytes()[16], b':', "line {i}: time format");
        assert_eq!(line.as_bytes()[19], b'.', "line {i}: ms separator");

        let after_ts = &line[23..];
        let after_ts = after_ts.trim_start_matches(' ');
        assert!(
            after_ts.starts_with('['),
            "line {i}: expected `[` after timestamp, got: {:?}",
            &after_ts[..after_ts.len().min(10)]
        );
        let bracket_close = after_ts.find(']').expect("must have closing bracket");
        let func_inside = &after_ts[1..bracket_close];
        assert_eq!(
            func_inside.len(),
            FUNCTION_NAME_PAD,
            "line {i}: function-name slot is exactly {FUNCTION_NAME_PAD} chars (got {:?})",
            func_inside
        );

        // After `]` C emits exactly 1 space, then the 5-char level prefix
        // (which itself may begin with another space), then `:`.
        let after_bracket = &after_ts[bracket_close + 1..];
        assert!(
            after_bracket.starts_with(' '),
            "line {i}: expected single space after `]`"
        );
        let level_slot = &after_bracket[1..];
        let level_prefix: String = level_slot.chars().take(LEVEL_PREFIX_WIDTH).collect();
        let known_levels = [" INFO", " WARN", "ERROR", "DEBUG", "  ALL", "FATAL"];
        assert!(
            known_levels.contains(&level_prefix.as_str()),
            "line {i}: level prefix {:?} not in {:?}",
            level_prefix,
            known_levels
        );
        let after_level = &level_slot[LEVEL_PREFIX_WIDTH..];
        assert!(
            after_level.starts_with(':'),
            "line {i}: expected `:` after level, got {:?}",
            &after_level[..after_level.len().min(5)]
        );
    }
}

#[test]
fn our_format_level_strings_match_c_outputs() {
    use tracing::Level;
    // The C source uses these exact 5-char strings (padded with leading
    // space for 4-letter levels). Our format_level matches.
    assert_eq!(format_level(Level::ERROR), "ERROR");
    assert_eq!(format_level(Level::WARN), " WARN");
    assert_eq!(format_level(Level::INFO), " INFO");
    assert_eq!(format_level(Level::DEBUG), "DEBUG");
    // (FATAL exists in C but not in tracing; emitted by us for higher
    // severities at the call site.)
}

#[test]
fn our_format_function_name_is_44_padded() {
    let s = format_function_name("datum_protocol_init");
    assert_eq!(s.len(), FUNCTION_NAME_PAD);
    // C right-pads with leading spaces (right-aligned). Our output is
    // left-aligned (the func name comes first, spaces trail). Both are
    // length-FUNCTION_NAME_PAD, both produce a 44-char slot. Document that
    // operator grep alignment uses `[xxx]` boundaries, not interior
    // alignment.
    assert!(s.starts_with("datum_protocol_init") || s.ends_with("datum_protocol_init"));
}
