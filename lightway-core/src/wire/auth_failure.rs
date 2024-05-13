use bytes::{Buf, BufMut, BytesMut};

use crate::borrowed_bytesmut::BorrowedBytesMut;

use super::{FromWireError, FromWireResult};

/// Authentication Failure Response (only sent from server to client)
///
/// See [`super::Frame::AuthRequest`] for the corresponding request.
///
/// Wire Format:
///
/// This frame consists of 52 bytes of padding (zeroes).
///
/// NOTE: In the lightway-core C implementation this is
/// `HE_MSGID_AUTH_RESPONSE` with `he_msg_auth_response_t` as the
/// payload. However this frame is only ever generated on auth failure
/// with the status field set to 0 (incorrectly since this is
/// `HE_AUTH_STATUS_SUCCESS` and no `status_msg` (length and data both
/// all zeroes).
#[derive(PartialEq, Debug)]
pub(crate) struct AuthFailure;

impl AuthFailure {
    /// Wire Size in bytes
    const WIRE_SIZE: usize = 52;

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(FromWireError::InsufficientData);
        };

        buf.advance(Self::WIRE_SIZE); // Skip padding

        Ok(Self)
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(Self::WIRE_SIZE);
        buf.put_bytes(0, Self::WIRE_SIZE); // Pad msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;

    #[test]
    fn try_from_wire_too_short() {
        let mut buf = ImmutableBytesMut::from(&[0u8; AuthFailure::WIRE_SIZE - 1][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            AuthFailure::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }
}
