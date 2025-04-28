use lightway_core::{PacketDecoderType, PacketEncoderType};

/// Factory to build [`PacketEncoderType`] and [`PacketDecoderType`]
/// This will be used to build a new instance of [`PacketEncoderType`] and [`PacketDecoderType`] for every connection.
pub trait PacketCodecFactory {
    /// Build a new instance of [`PacketEncoderType`]
    fn build_encoder(&self) -> PacketEncoderType;

    /// Build a new instance of [`PacketDecoderType`]
    fn build_decoder(&self) -> PacketDecoderType;

    /// Returns the codec name for debugging purpose
    fn get_codec_name(&self) -> String;
}

/// Type for [`PacketCodecFactory`]
pub type PacketCodecFactoryType = Box<dyn PacketCodecFactory + Send + Sync>;
