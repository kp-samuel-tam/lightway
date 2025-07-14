/// Optional lightway features, which can be negotiated during the auth.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum LightwayFeature {
    /// Whether the server will accept EncodingRequests.
    InsidePktCodec,
}
