use thiserror::Error;

/// 32-bit packed DATUM frame header. Bit layout (LSB → MSB on the wire):
///
/// | bits 0..21 | 22..23 | 24      | 25                  | 26                   | 27..31    |
/// |-----------|--------|---------|---------------------|----------------------|-----------|
/// | cmd_len   | rsvd   | is_signed | is_encrypted_pubkey | is_encrypted_channel | proto_cmd |
///
/// **Byte ordering on the wire is unverified from spec alone — must capture-and-pin
/// against a real C-emitted frame** (see inventory candidate
/// `datum-header-bitfield-byte-ordering`). This implementation treats the
/// header as a little-endian u32. If the capture-and-pin shows otherwise, swap
/// `to_le_bytes`/`from_le_bytes` for `to_be_bytes`/`from_be_bytes` and re-pin
/// the test vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub cmd_len: u32,
    pub is_signed: bool,
    pub is_encrypted_pubkey: bool,
    pub is_encrypted_channel: bool,
    pub proto_cmd: u8,
}

pub const MAX_CMD_LEN: u32 = 4 * 1024 * 1024;
pub const HEADER_LEN: usize = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("cmd_len {got} exceeds 22-bit field max ({MAX_CMD_LEN})")]
    CmdLenTooLarge { got: u32 },
    #[error("proto_cmd {got} exceeds 5-bit field max (31)")]
    ProtoCmdTooLarge { got: u8 },
}

impl FrameHeader {
    pub fn pack(self) -> Result<[u8; HEADER_LEN], FrameError> {
        if self.cmd_len >= (1 << 22) || self.cmd_len > MAX_CMD_LEN {
            return Err(FrameError::CmdLenTooLarge { got: self.cmd_len });
        }
        if self.proto_cmd >= 32 {
            return Err(FrameError::ProtoCmdTooLarge {
                got: self.proto_cmd,
            });
        }
        let mut word: u32 = self.cmd_len & 0x3F_FFFF;
        if self.is_signed {
            word |= 1 << 24;
        }
        if self.is_encrypted_pubkey {
            word |= 1 << 25;
        }
        if self.is_encrypted_channel {
            word |= 1 << 26;
        }
        word |= (self.proto_cmd as u32 & 0x1F) << 27;
        Ok(word.to_le_bytes())
    }

    pub fn unpack(bytes: [u8; HEADER_LEN]) -> Self {
        let word = u32::from_le_bytes(bytes);
        FrameHeader {
            cmd_len: word & 0x3F_FFFF,
            is_signed: word & (1 << 24) != 0,
            is_encrypted_pubkey: word & (1 << 25) != 0,
            is_encrypted_channel: word & (1 << 26) != 0,
            proto_cmd: ((word >> 27) & 0x1F) as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basic() {
        let h = FrameHeader {
            cmd_len: 100,
            is_signed: true,
            is_encrypted_pubkey: false,
            is_encrypted_channel: true,
            proto_cmd: 0x10,
        };
        assert_eq!(FrameHeader::unpack(h.pack().unwrap()), h);
    }

    #[test]
    fn round_trip_zero() {
        let h = FrameHeader {
            cmd_len: 0,
            is_signed: false,
            is_encrypted_pubkey: false,
            is_encrypted_channel: false,
            proto_cmd: 0,
        };
        assert_eq!(FrameHeader::unpack(h.pack().unwrap()), h);
    }

    #[test]
    fn round_trip_all_set() {
        let h = FrameHeader {
            cmd_len: (1 << 22) - 1,
            is_signed: true,
            is_encrypted_pubkey: true,
            is_encrypted_channel: true,
            proto_cmd: 31,
        };
        assert_eq!(FrameHeader::unpack(h.pack().unwrap()), h);
    }

    #[test]
    fn cmd_len_overflow() {
        let h = FrameHeader {
            cmd_len: 1 << 22,
            is_signed: false,
            is_encrypted_pubkey: false,
            is_encrypted_channel: false,
            proto_cmd: 0,
        };
        assert!(matches!(h.pack(), Err(FrameError::CmdLenTooLarge { .. })));
    }

    #[test]
    fn proto_cmd_overflow() {
        let h = FrameHeader {
            cmd_len: 0,
            is_signed: false,
            is_encrypted_pubkey: false,
            is_encrypted_channel: false,
            proto_cmd: 32,
        };
        assert!(matches!(h.pack(), Err(FrameError::ProtoCmdTooLarge { .. })));
    }
}
