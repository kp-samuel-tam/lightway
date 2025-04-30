use std::sync::Arc;

use bytes::BytesMut;

/// PacketEncoder and PacketDecoder's trait function's return type
pub type PacketCodecResult<T> = std::result::Result<T, Box<dyn std::error::Error + Sync + Send>>;

/// PacketEncode trait. Accumulates inside packets and turn them to encoded packets
pub trait PacketEncoder {
    /// Store one inside packet into the PacketEncoder
    ///
    /// Returns a [`CodecStatus`].
    /// If the status is [`CodecStatus::PacketAccepted`], the packet is accepted by the encoder.
    /// If the status is [`CodecStatus::SkipPacket`], the packet is skipped by the encoder and lightway
    /// may send it as a normal wire::Data packet.
    fn store(&self, data: &mut BytesMut) -> PacketCodecResult<CodecStatus>;

    /// Get the encoding state
    ///
    /// The returned bool indicates whether encoding is enabled.
    fn get_encoding_state(&self) -> bool;

    /// Set the encoding status
    ///
    /// The param indicates whether encoding is enabled or disabled.
    fn set_encoding_state(&self, enabled: bool);
}

/// PacketDecoder trait to accumulate encoded packets and turn them to inside packets.
pub trait PacketDecoder {
    /// Store one encoded packet into the PacketDecoder
    ///
    /// Returns a [`CodecStatus`].
    /// If the status is [`CodecStatus::PacketAccepted`], the packet is accepted by the encoder.
    /// If the status is [`CodecStatus::SkipPacket`], the packet should not be added to the decoder.
    /// and should be sent directly.
    fn store(&self, data: &mut BytesMut) -> PacketCodecResult<CodecStatus>;
}

/// Indicates the status of [`PacketEncoder`] or [`PacketDecoder`] after storing the current packet
pub enum CodecStatus {
    /// The codec accepted this packet.
    PacketAccepted,

    /// The codec does not accept this particular packet.
    /// The packet should be sent directly.
    #[allow(dead_code)]
    SkipPacket,
}

/// Type for [`PacketEncoder`]
pub type PacketEncoderType = Arc<dyn PacketEncoder + Send + Sync>;

/// Type for [`PacketDecoder`]
pub type PacketDecoderType = Arc<dyn PacketDecoder + Send + Sync>;
