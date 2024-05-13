use crate::borrowed_bytesmut::BorrowedBytesMut;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use more_asserts::*;

use super::{FromWireError, FromWireResult};

/// Server configuration data pushed to the client by the server
///
/// This is a variable length frame
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        buffer_length          | ... buffer_length bytes
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub(crate) struct ServerConfig {
    pub(crate) data: Bytes,
}

impl ServerConfig {
    /// The maximum number of bytes in the buffer.
    const MAX_SERVER_CONFIG_BYTES: usize = 1350 - std::mem::size_of::<u16>();

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < 2 {
            return Err(FromWireError::InsufficientData);
        };

        let data_len = buf.get_u16() as usize;

        if data_len > Self::MAX_SERVER_CONFIG_BYTES {
            return Err(FromWireError::FieldTooLarge);
        }

        if buf.len() < data_len {
            return Err(FromWireError::InsufficientData);
        }

        let data = buf.commit_and_split_to(data_len);

        Ok(Self {
            data: data.freeze(),
        })
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        debug_assert_le!(self.data.len(), Self::MAX_SERVER_CONFIG_BYTES);

        buf.reserve(2 + buf.len());

        buf.put_u16(self.data.len() as u16);
        buf.put(&self.data[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;
    use test_case::test_case;

    #[test_case(&[0_u8; 0]; "no data")]
    #[test_case(&[0_u8; 1]; "only one length byte")]
    #[test_case(&[0x00, 0x02, 0x00]; "fewer bytes than length says")]
    fn try_from_wire_too_short(buf: &'static [u8]) {
        let mut buf = ImmutableBytesMut::from(buf);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            ServerConfig::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_too_long() {
        let mut buf = BytesMut::with_capacity(2 + 1350 + 1);
        buf.extend_from_slice(b"\x05\x45");
        buf.extend_from_slice(&[0; ServerConfig::MAX_SERVER_CONFIG_BYTES + 1]);
        let mut buf = ImmutableBytesMut::from(buf.freeze());
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            ServerConfig::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::FieldTooLarge
        ));
    }
}
