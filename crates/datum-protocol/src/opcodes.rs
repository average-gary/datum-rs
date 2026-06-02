/// DATUM `proto_cmd` field. Stored as a 5-bit value on the wire, so opcodes
/// from the C reference (which span the full byte range like 0x8F, 0xF9) get
/// truncated to their low 5 bits during framing.
///
/// We retain the *byte* opcode names from the C reference for grep parity,
/// even though `Share` (0x27) and `JobValidation` (0x50) are distinguishable
/// only by combining the proto_cmd field with the `is_signed` /
/// `is_encrypted_*` flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoCmd {
    Ping,
    Pong,
    Hello,
    Coinbaser,
    CoinbaserAck,
    Share,
    ShareAck,
    JobValidation,
    ClientConfig,
    BlockNotify,
    Unknown(u8),
}

impl ProtoCmd {
    /// Byte opcode from the C reference. The on-wire field stores `byte_value() & 0x1F`.
    pub fn byte_value(self) -> u8 {
        match self {
            ProtoCmd::Ping => 0x01,
            ProtoCmd::Pong => 0x02,
            ProtoCmd::Hello => 0x03,
            ProtoCmd::Coinbaser => 0x10,
            ProtoCmd::CoinbaserAck => 0x11,
            ProtoCmd::Share => 0x27,
            ProtoCmd::ShareAck => 0x8F,
            ProtoCmd::JobValidation => 0x50,
            ProtoCmd::ClientConfig => 0x99,
            ProtoCmd::BlockNotify => 0xF9,
            ProtoCmd::Unknown(b) => b,
        }
    }

    /// Recover the variant from the 5-bit on-wire value alone. **Known
    /// collisions** (require frame-flag disambiguation by the caller):
    /// - 0x10: Coinbaser (0x10) and JobValidation (0x50); returns Coinbaser
    /// - 0x19: ClientConfig (0x99) and BlockNotify (0xF9); returns ClientConfig
    pub fn from_bits(b: u8) -> Self {
        match b & 0x1F {
            0x01 => ProtoCmd::Ping,
            0x02 => ProtoCmd::Pong,
            0x03 => ProtoCmd::Hello,
            0x10 => ProtoCmd::Coinbaser,
            0x11 => ProtoCmd::CoinbaserAck,
            0x07 => ProtoCmd::Share,
            0x0F => ProtoCmd::ShareAck,
            0x19 => ProtoCmd::ClientConfig,
            x => ProtoCmd::Unknown(x),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_round_trip_via_bits() {
        let bits = ProtoCmd::Ping.byte_value() & 0x1F;
        assert_eq!(ProtoCmd::from_bits(bits), ProtoCmd::Ping);
    }

    #[test]
    fn share_5bit_recovery() {
        let bits = ProtoCmd::Share.byte_value() & 0x1F;
        assert_eq!(ProtoCmd::from_bits(bits), ProtoCmd::Share);
    }

    #[test]
    fn coinbaser_round_trip() {
        let bits = ProtoCmd::Coinbaser.byte_value() & 0x1F;
        assert_eq!(ProtoCmd::from_bits(bits), ProtoCmd::Coinbaser);
    }

    #[test]
    fn share_ack_recovery() {
        let bits = ProtoCmd::ShareAck.byte_value() & 0x1F;
        assert_eq!(ProtoCmd::from_bits(bits), ProtoCmd::ShareAck);
    }

    #[test]
    fn known_collision_block_notify_vs_client_config() {
        let block_notify_bits = ProtoCmd::BlockNotify.byte_value() & 0x1F;
        let client_config_bits = ProtoCmd::ClientConfig.byte_value() & 0x1F;
        assert_eq!(block_notify_bits, client_config_bits);
        assert_eq!(
            ProtoCmd::from_bits(block_notify_bits),
            ProtoCmd::ClientConfig
        );
    }

    #[test]
    fn known_collision_coinbaser_vs_job_validation() {
        let coinbaser_bits = ProtoCmd::Coinbaser.byte_value() & 0x1F;
        let job_validation_bits = ProtoCmd::JobValidation.byte_value() & 0x1F;
        assert_eq!(coinbaser_bits, job_validation_bits);
    }
}
