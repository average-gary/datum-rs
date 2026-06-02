//! DATUM upstream protocol — encrypted gateway-to-OCEAN wire format.
//!
//! See the wiki article `datum-protocol-rust-implementation` for the full
//! design rationale. Cipher is **XSalsa20Poly1305** (libsodium default), NOT
//! ChaCha20-Poly1305. `dryoc 0.8` is the pure-Rust libsodium-compatible crate.
//!
//! Phase 2 status: wire-format primitives implemented and tested in-tree;
//! live-OCEAN handshake against `datum-beta1.mine.ocean.xyz:28915` is the
//! release gate (tracked in inventory: `ocean-production-protocol-version`).

pub mod crypto;
pub mod frame;
pub mod obfuscation;
pub mod opcodes;

pub use crypto::{CryptoError, DatumCrypto, DryocCrypto};
pub use frame::{FrameError, FrameHeader, HEADER_LEN, MAX_CMD_LEN};
pub use obfuscation::{mm3_fmix32, HeaderObfuscator, HEADER_OBFUSCATION_INIT};
pub use opcodes::ProtoCmd;
