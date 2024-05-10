use bytes::{Buf, BufMut, BytesMut};

use super::{FromWireError, FromWireResult};
use crate::borrowed_bytesmut::BorrowedBytesMut;

/// A pong request in response to a ping
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         id                    |           reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub(crate) struct Pong {
    pub(crate) id: u16,
}

impl Pong {
    /// Wire Size in bytes
    const WIRE_SIZE: usize = 4;

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(FromWireError::InsufficientData);
        };

        let id = buf.get_u16();
        let _ = buf.get_u16();

        Ok(Self { id })
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(Self::WIRE_SIZE);

        buf.put_u16(self.id);
        buf.put_u16(0); // padding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;

    #[test]
    fn try_from_wire_too_short() {
        let mut buf = ImmutableBytesMut::from(&[0u8; Pong::WIRE_SIZE - 1][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            Pong::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_header_reserved_ignored() {
        let mut buf = ImmutableBytesMut::from(&b"\x12\x34\x01\x02"[..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert_eq!(Pong::try_from_wire(&mut buf).unwrap(), Pong { id: 0x1234 });
        assert!(buf.is_empty(), "buf should be consumed");
    }

    #[test]
    fn append_to_wire() {
        let pong = Pong { id: 0xdee4 };
        let mut buf = BytesMut::new();
        pong.append_to_wire(&mut buf);
        assert_eq!(&buf[..], b"\xde\xe4\x00\x00");
    }
}
