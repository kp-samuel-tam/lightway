use crate::borrowed_bytesmut::BorrowedBytesMut;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use more_asserts::*;

use super::{FromWireError, FromWireResult};

/// A fragmented data frame
///
/// This is a variable sized request.
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        data length            |       fragment id             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  fragment offset[3:15]  |M|0|0| ... length bytes of data
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Where `M` is 1 if there are more fragments in this package and 0
/// if not (i.e. if this is the final fragment).
///
/// Note that unlike the `wire::Data` type the length field is always
/// network/big endian.

#[derive(PartialEq, Debug)]
pub(crate) struct DataFrag {
    pub(crate) id: u16,
    pub(crate) offset: usize,
    pub(crate) more_fragments: bool,
    pub(crate) data: Bytes,
}

/// Helper struct for encoding offset and more fragments word
struct OffsetAndMoreFragments(u16);

impl OffsetAndMoreFragments {
    const MORE_FRAGMENTS_MASK: u16 = 0x2000;
    const OFFSET_MASK: u16 = 0x1fff;
    const OFFSET_SHIFT: usize = 3;

    fn from_parts(offset: usize, more_fragments: bool) -> Self {
        debug_assert_le!(offset, u16::MAX as usize, "offset must fit in 16 bits");
        debug_assert_eq!(
            0,
            offset & ((1 << Self::OFFSET_SHIFT) - 1),
            "fragment offset must be 8 byte aligned"
        );

        let mf_bit = if more_fragments {
            Self::MORE_FRAGMENTS_MASK
        } else {
            0
        };
        Self(mf_bit | (offset as u16 >> Self::OFFSET_SHIFT))
    }

    fn into_parts(self) -> (usize, bool) {
        let more_fragments = (self.0 & Self::MORE_FRAGMENTS_MASK) != 0;
        let offset = (self.0 & Self::OFFSET_MASK) << Self::OFFSET_SHIFT;
        (offset as usize, more_fragments)
    }

    fn into_inner(self) -> u16 {
        self.0
    }
}

impl From<u16> for OffsetAndMoreFragments {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl DataFrag {
    /// Wire overhead in bytes
    pub(crate) const WIRE_OVERHEAD: usize = 6;

    /// The maximum payload size for a given Packetization Layer PMTU
    /// (correctly aligned).
    pub(crate) fn maximum_packet_size_for_plpmtu(plpmtu: usize) -> usize {
        debug_assert_gt!(
            plpmtu,
            std::mem::size_of::<crate::wire::FrameKind>() + Self::WIRE_OVERHEAD,
            "plpmtu too small"
        );
        let mut size = plpmtu - Self::WIRE_OVERHEAD - std::mem::size_of::<crate::wire::FrameKind>();
        size &= !((1 << OffsetAndMoreFragments::OFFSET_SHIFT) - 1);
        debug_assert_gt!(size, 0, "chunk size too small");
        size
    }

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < Self::WIRE_OVERHEAD {
            return Err(FromWireError::InsufficientData);
        };

        let data_len = buf.get_u16() as usize;
        let fragment_id = buf.get_u16();
        let offset_and_mf: OffsetAndMoreFragments = buf.get_u16().into();

        if buf.len() < data_len {
            return Err(FromWireError::InsufficientData);
        }

        let (offset, more_fragments) = offset_and_mf.into_parts();

        let data = buf.commit_and_split_to(data_len);

        Ok(Self {
            id: fragment_id,
            data: data.into(),
            offset,
            more_fragments,
        })
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        debug_assert_le!(self.data.len(), u16::MAX as usize);

        buf.reserve(Self::WIRE_OVERHEAD + self.data.len());

        let offset_and_mf = OffsetAndMoreFragments::from_parts(self.offset, self.more_fragments);

        buf.put_u16(self.data.len() as u16);
        buf.put_u16(self.id);
        buf.put_u16(offset_and_mf.into_inner());
        buf.put(&self.data[..])
    }

    /// The offset of this fragment
    pub(crate) fn start_offset(&self) -> usize {
        self.offset
    }

    /// The offset of end of this fragment, i.e. one past the final byte.
    pub(crate) fn end_offset(&self) -> usize {
        self.offset + self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;
    use test_case::test_case;

    #[cfg(debug_assertions)]
    #[test_case(0 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(1 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(2 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(3 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(4 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(5 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(6 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(7 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(8 => panics "chunk size too small")]
    #[cfg(debug_assertions)]
    #[test_case(9 => panics "chunk size too small")]
    #[cfg(debug_assertions)]
    #[test_case(10 => panics "chunk size too small")]
    #[cfg(debug_assertions)]
    #[test_case(11 => panics "chunk size too small")]
    #[cfg(debug_assertions)]
    #[test_case(12 => panics "chunk size too small")]
    #[cfg(debug_assertions)]
    #[test_case(13 => panics "chunk size too small")]
    #[cfg(debug_assertions)]
    #[test_case(14 => panics "chunk size too small")]
    #[test_case(15 => 8)]
    #[test_case(16 => 8)]
    #[test_case(17 => 8)]
    #[test_case(18 => 8)]
    #[test_case(19 => 8)]
    #[test_case(20 => 8)]
    #[test_case(21 => 8)]
    #[test_case(22 => 8)]
    #[test_case(23 => 16)]
    #[test_case(24 => 16)]
    #[test_case(1200 => 1192)]
    #[test_case(1300 => 1288)]
    #[test_case(1500 => 1488)]
    fn maximum_packet_size_for_plpmtu(size: usize) -> usize {
        DataFrag::maximum_packet_size_for_plpmtu(size)
    }

    #[test_case(DataFrag{ id: 0, offset: 0, more_fragments: true, data: std::iter::repeat_n(b'.', 3).collect::<Vec<_>>().into() } => (0,3))]
    #[test_case(DataFrag{ id: 0, offset: 0xfff1, more_fragments: true, data: std::iter::repeat_n(b'.', 32).collect::<Vec<_>>().into() } => (65521, 65553))]
    #[test_case(DataFrag{ id: 0, offset: 0xfff1, more_fragments: true, data: std::iter::repeat_n(b'.', 0xffff).collect::<Vec<_>>().into() } => (65521,131056))]
    fn start_end_offset(frag: DataFrag) -> (usize, usize) {
        (frag.start_offset(), frag.end_offset())
    }

    #[test_case(&[0_u8; 0]; "no data")]
    #[test_case(&[0_u8; 1]; "only one length byte")]
    #[test_case(&[0_u8; 5]; "not full header")]
    #[test_case(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]; "fewer bytes than length says")]
    fn try_from_wire_too_short(buf: &'static [u8]) {
        let mut buf = ImmutableBytesMut::from(buf);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            DataFrag::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test_case(0x00000, false => 0x0000)]
    #[test_case(0x00000, true  => 0x2000)]
    #[cfg(debug_assertions)]
    #[test_case(0x00001, false => panics "fragment offset must be 8 byte aligned")]
    #[cfg(debug_assertions)]
    #[test_case(0x00002, false => panics "fragment offset must be 8 byte aligned")]
    #[cfg(debug_assertions)]
    #[test_case(0x00003, false => panics "fragment offset must be 8 byte aligned")]
    #[cfg(debug_assertions)]
    #[test_case(0x00004, false => panics "fragment offset must be 8 byte aligned")]
    #[cfg(debug_assertions)]
    #[test_case(0x00005, false => panics "fragment offset must be 8 byte aligned")]
    #[cfg(debug_assertions)]
    #[test_case(0x00006, false => panics "fragment offset must be 8 byte aligned")]
    #[cfg(debug_assertions)]
    #[test_case(0x00007, false => panics "fragment offset must be 8 byte aligned")]
    #[test_case(0x00008, false => 0x0001)]
    #[test_case(0x00008, true  => 0x2001)]
    #[test_case(0x01000, false => 0x0200)]
    #[test_case(0x01000, true  => 0x2200)]
    #[test_case(0x0fff8, false => 0x1fff)]
    #[test_case(0x0fff8, true  => 0x3fff)]
    #[cfg(debug_assertions)]
    #[test_case(0x0ffff, false => panics "fragment offset must be 8 byte aligned")]
    #[cfg(debug_assertions)]
    #[test_case(0x10000, false => panics "offset must fit in 16 bits")]
    #[cfg(debug_assertions)]
    #[test_case(0x1000f, false => panics "offset must fit in 16 bits")]
    fn encode_offset_and_mf(offset: usize, mf: bool) -> u16 {
        OffsetAndMoreFragments::from_parts(offset, mf).into_inner()
    }

    #[test_case(0x0000 => (0x0000, false))]
    #[test_case(0x2000 => (0x0000, true ))]
    #[test_case(0x0001 => (0x0008, false))]
    #[test_case(0x2001 => (0x0008, true ))]
    #[test_case(0x0200 => (0x1000, false))]
    #[test_case(0x2200 => (0x1000, true ))]
    #[test_case(0x1fff => (0xfff8, false))]
    #[test_case(0x3fff => (0xfff8, true ))]
    fn decode_offset_and_mf(val: u16) -> (usize, bool) {
        OffsetAndMoreFragments::from(val).into_parts()
    }
}
