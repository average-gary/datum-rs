//! `SetupConnection` decode + reply.
//!
//! Per [SV2 Mining Protocol](https://github.com/stratum-mining/sv2-spec/blob/main/05-Mining-Protocol.md)
//! §SetupConnection flags, the downstream may set:
//!
//! | Bit | Flag | datum-rs response |
//! |-----|------|-------------------|
//! | 0 | `REQUIRES_STANDARD_JOBS` | Accept; we honor it in Phase 4. |
//! | 1 | `REQUIRES_WORK_SELECTION` | **Reject** — datum-rs is a custodial-template gateway; we do not support JD. |
//! | 2 | `REQUIRES_VERSION_ROLLING` | Accept; we always allow BIP320 16-bit version rolling. |
//!
//! On accept we emit `SetupConnection.Success { used_version: 2, flags: 0 }`.
//! On reject we emit `SetupConnection.Error { flags: 0, error_code: "unsupported-feature-flags" }`.
//! Per the spec `SetupConnection.Error` is allowed to mark which flag bits are
//! unsupported; we do, so the downstream can see which feature it requested
//! that we refused.
//!
//! This module is the **dispatch layer** only — we don't touch sockets here.
//! Callers feed a parsed `SetupConnection` and we yield a typed response
//! enum that gets framed + written to the wire by the listener task.

use stratum_core::common_messages_sv2::{
    has_work_selection, Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS,
    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL,
};

/// Flag bit (per spec §SetupConnection flags) for `REQUIRES_WORK_SELECTION`.
/// Equivalent to `setup_connection::has_work_selection(flags)` returning true.
pub const FLAG_REQUIRES_WORK_SELECTION: u32 = 0b0000_0000_0000_0000_0000_0000_0000_0010;

/// Outcome of handling a `SetupConnection` — what to write back on the wire.
///
/// We hold these as owned (`'static`) types so the caller can encode them
/// without managing input-borrow lifetimes. `SetupConnectionError` is built
/// with an ASCII error code that's already 'static.
#[derive(Debug, Clone)]
pub enum SetupConnectionResponse {
    Success(SetupConnectionSuccess),
    Error(SetupConnectionError<'static>),
}

/// Validate a `SetupConnection` from a downstream miner.
///
/// Mirrors the per-flag matrix from
/// [SV2 Downstream Architecture playbook](crate). The protocol must be
/// `MiningProtocol`; anything else we route to `unsupported-protocol`.
/// `REQUIRES_WORK_SELECTION` triggers `unsupported-feature-flags`.
pub fn handle_setup_connection(msg: &SetupConnection<'_>) -> SetupConnectionResponse {
    if !matches!(msg.protocol, Protocol::MiningProtocol) {
        // We don't ship JD or TDP — surface a different error_code to make the
        // failure mode visible in miner-side logs.
        return SetupConnectionResponse::Error(SetupConnectionError {
            flags: 0,
            error_code: ascii_to_str0255(ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL),
        });
    }
    if has_work_selection(msg.flags) {
        // Echo only the bits we're refusing so the downstream can detect via
        // the spec's "send all flags, examine the Error reply" trick which
        // features are off-menu.
        return SetupConnectionResponse::Error(SetupConnectionError {
            flags: FLAG_REQUIRES_WORK_SELECTION,
            error_code: ascii_to_str0255(ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS),
        });
    }
    // Accept everything else. We negotiate `used_version: 2` (the only spec
    // version) and reply with `flags: 0` because we don't advertise any
    // upstream-side optional features.
    SetupConnectionResponse::Success(SetupConnectionSuccess {
        used_version: 2,
        flags: 0,
    })
}

/// Build a `Str0255` from an ASCII string. Caller must guarantee the input is
/// ≤255 bytes; the SRI error-code constants in `common_messages_sv2` are all
/// short ASCII so this is safe.
fn ascii_to_str0255(s: &'static str) -> stratum_core::binary_sv2::Str0255<'static> {
    debug_assert!(s.len() <= 255, "Str0255 exceeded by {}", s.len());
    s.to_string()
        .into_bytes()
        .try_into()
        .expect("ASCII error_code fits Str0255")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_setup(flags: u32, protocol: Protocol) -> SetupConnection<'static> {
        SetupConnection {
            protocol,
            min_version: 2,
            max_version: 2,
            flags,
            endpoint_host: "datum-rs".to_string().into_bytes().try_into().unwrap(),
            endpoint_port: 23335,
            vendor: "test".to_string().into_bytes().try_into().unwrap(),
            hardware_version: "v1".to_string().into_bytes().try_into().unwrap(),
            firmware: "v1".to_string().into_bytes().try_into().unwrap(),
            device_id: "test-device".to_string().into_bytes().try_into().unwrap(),
        }
    }

    #[test]
    fn rejects_requires_work_selection_with_unsupported_feature_flags() {
        let m = mk_setup(FLAG_REQUIRES_WORK_SELECTION, Protocol::MiningProtocol);
        let resp = handle_setup_connection(&m);
        match resp {
            SetupConnectionResponse::Error(e) => {
                assert_eq!(
                    e.error_code.inner_as_ref(),
                    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS.as_bytes()
                );
                assert_eq!(e.flags, FLAG_REQUIRES_WORK_SELECTION);
            }
            _ => panic!("expected Error, got {resp:?}"),
        }
    }

    #[test]
    fn accepts_no_flags_with_success_used_version_2_flags_0() {
        let m = mk_setup(0, Protocol::MiningProtocol);
        let resp = handle_setup_connection(&m);
        match resp {
            SetupConnectionResponse::Success(s) => {
                assert_eq!(s.used_version, 2);
                assert_eq!(s.flags, 0);
            }
            _ => panic!("expected Success, got {resp:?}"),
        }
    }

    #[test]
    fn accepts_requires_version_rolling() {
        // Bit 2 = REQUIRES_VERSION_ROLLING. `has_version_rolling` in SRI
        // checks `flags & (1<<2) != 0` after reverse-bits gymnastics — bit 2
        // = 0b100.
        let m = mk_setup(0b100, Protocol::MiningProtocol);
        let resp = handle_setup_connection(&m);
        assert!(matches!(resp, SetupConnectionResponse::Success(_)));
    }

    #[test]
    fn accepts_requires_standard_jobs() {
        // Bit 0 = REQUIRES_STANDARD_JOBS — Bitaxe-style.
        let m = mk_setup(0b1, Protocol::MiningProtocol);
        let resp = handle_setup_connection(&m);
        assert!(matches!(resp, SetupConnectionResponse::Success(_)));
    }

    #[test]
    fn rejects_non_mining_protocol() {
        let m = mk_setup(0, Protocol::JobDeclarationProtocol);
        let resp = handle_setup_connection(&m);
        match resp {
            SetupConnectionResponse::Error(e) => {
                assert_eq!(
                    e.error_code.as_ref(),
                    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL.as_bytes()
                );
            }
            _ => panic!("expected Error, got {resp:?}"),
        }
    }
}
