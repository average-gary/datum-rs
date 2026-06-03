//! DATUM upstream protocol — encrypted gateway-to-OCEAN wire format.
//!
//! See the wiki article `datum-protocol-rust-implementation` for the full
//! design rationale. Cipher is **XSalsa20Poly1305** (libsodium default), NOT
//! ChaCha20-Poly1305. `dryoc 0.8` is the pure-Rust libsodium-compatible crate.
//!
//! Phase 2 status: wire-format primitives implemented and tested in-tree;
//! live-OCEAN handshake against `datum-beta1.mine.ocean.xyz:28915` is the
//! release gate (tracked in inventory: `ocean-production-protocol-version`).

pub mod client;
pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod messages;
pub mod mock_pool;
pub mod obfuscation;
pub mod opcodes;

pub use client::{ClientError, Connected, DatumClient, UpstreamCommand, UpstreamEvent};

pub use crypto::{CryptoError, DatumCrypto, DryocCrypto};
pub use frame::{FrameError, FrameHeader, HEADER_LEN, MAX_CMD_LEN};
pub use handshake::{
    build_hello_payload, frame_for_hello, parse_received_header, seal_hello, ClientKeypairs,
    HandshakeError, CRYPTO_BOX_SEAL_BYTES, HELLO_PROTO_CMD, HELLO_SENTINEL,
};
pub use messages::{
    BlockNotify, ClientConfig, CoinbaserFetchRequest, CoinbaserResponse, JobValidationCmd,
    MessageError, ShareResponse, ShareStatus, ShareSubmissionPrefix, CLIENT_CONFIG_OPCODE,
    COINBASER_FETCH_OPCODE, COINBASER_RESPONSE_OPCODE, JOB_VALIDATION_OPCODE, SHARE_ACCEPTED,
    SHARE_ACCEPTED_TENTATIVELY, SHARE_REJECTED, SHARE_RESPONSE_OPCODE, SHARE_SUBMISSION_PREFIX_LEN,
};
pub use obfuscation::{datum_header_xor_feedback, HeaderObfuscator, INITIAL_SENDING_HEADER_KEY};
pub use opcodes::ProtoCmd;
