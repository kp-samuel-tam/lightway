use bytes::{Buf, BytesMut};
use std::ops::Deref;

/// `BorrowedBytesMut`
///
/// New type to wrap `BytesMut` and provide `bytes::Buf` trait.
/// This is useful when we don't want to advance the `BytesMut` cursor, but
/// still like to use the `Buf::get_*` helper methods.
///
/// A separate cursor is maintained inside `BorrowedBytesMut` instead of
/// the cursor inside `BytesMut`.
/// After completing the get/advance operations, `BorrowedBytesMut::commit()` can be
/// invoked to update the `BytesMut` cursor. If commit() is not called, the underlying
/// `BytesMut` will not be touched.
///
/// Note: `bytes::BytesMut::clone()` is not cheap
pub(crate) struct BorrowedBytesMut<'a> {
    cursor: usize,
    bytes: &'a mut BytesMut,
    committed: bool,
}

/// Create `BorrowedBytesMut` from `&mut BytesMut`
impl<'a> From<&'a mut BytesMut> for BorrowedBytesMut<'a> {
    fn from(src: &'a mut BytesMut) -> BorrowedBytesMut<'a> {
        Self {
            cursor: 0,
            bytes: src,
            committed: false,
        }
    }
}

impl<'a> BorrowedBytesMut<'a> {
    /// Get the length of the remaining buffer
    pub(crate) fn len(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    /// Advance the underlying `BytesMut` with the current cursor.
    pub(crate) fn commit(self) -> &'a mut BytesMut {
        // Either:
        // This is the first time this buffer has been committed.
        // -or-
        // Nothing extra has been consumed since the first commit.
        assert!(
            !self.committed || self.cursor == 0,
            "recommitting a BorrowedBytesBuf"
        );
        self.bytes.advance(self.cursor);
        self.bytes
    }

    /// Advance the underlying `BytesMut` with the current cursor and
    /// then split to `cnt`.
    ///
    /// The returned new/owned `BytesMut` will contain `[cursor,
    /// cursor+cnt)` and the returned reference to the original
    /// `BytesMut` will contain `[cursor+cnt, len)`. The bytes in `[0,
    /// cursor)` are discarded.
    ///
    /// The creation of the split `BytesMut` is an O(1) operation
    /// that just increases the reference count and sets a few
    /// indices.
    ///
    /// Nothing further may be consumed from this `BorrowedBytesMut`
    /// after this point, including via a second call to
    /// `commit_and_split`. Any attempt to do so will panic. Note that
    /// additional `commit`s are ok.
    pub(crate) fn commit_and_split_to(&mut self, cnt: usize) -> BytesMut {
        assert!(!self.committed, "recommitting a BorrowedBytesBuf");

        self.committed = true;
        self.bytes.advance(self.cursor);
        self.cursor = 0;
        self.bytes.split_to(cnt)
    }
}

/// `bytes::Buf` trait for `BorrowedBytesMut`
/// These are the only required methods. All get_* helpers are provided
/// from the trait
impl<'a> Buf for BorrowedBytesMut<'a> {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn chunk(&self) -> &[u8] {
        &self.bytes[self.cursor..]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(
            !self.committed,
            "consuming from already committed BorrowedBytesMut"
        );
        assert!(
            cnt <= self.remaining(),
            "{cnt} greater than remaining size {}",
            self.remaining()
        );
        self.cursor += cnt;
    }
}

impl<'a> Deref for BorrowedBytesMut<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes[self.cursor..]
    }
}

/// Helper for test cases where the underlying buffer must not be advanced
/// (e.g. on failure).
#[cfg(test)]
mod immutable_bytesmut {
    use bytes::Bytes;

    use super::*;

    pub(crate) struct ImmutableBytesMut {
        orig: Bytes,
        mutable: BytesMut,
    }

    impl ImmutableBytesMut {
        pub fn from<T: Into<Bytes>>(from: T) -> Self {
            let orig: Bytes = from.into();
            let mutable: BytesMut = (&orig[..]).into(); // copies
            Self { orig, mutable }
        }

        pub fn as_borrowed_bytesmut(&mut self) -> BorrowedBytesMut {
            BorrowedBytesMut::from(&mut self.mutable)
        }
    }

    impl Drop for ImmutableBytesMut {
        fn drop(&mut self) {
            assert_eq!(
                dbg!(&self.orig[..]),
                dbg!(&self.mutable[..]),
                "ImmutableBytesMut has changed"
            );
        }
    }

    #[test]
    #[should_panic(expected = "ImmutableBytesMut has changed")]
    fn panic_on_drop_if_modified() {
        let mut buf = ImmutableBytesMut::from(&[1, 2, 3][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert_eq!(buf.get_u8(), 1);
        buf.commit(); // provoke panic
    }
}

#[cfg(test)]
pub(crate) use immutable_bytesmut::ImmutableBytesMut;

#[cfg(test)]
mod tests {
    use super::*;

    use test_case::test_case;

    #[test]
    fn test_borrowed_bytes_create() {
        let mut buf = BytesMut::from(&[127u8; 1][..]);
        let borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.cursor, 0);
        assert_eq!(borrowed_buf.len(), 1);
    }

    #[test]
    fn test_borrowed_bytes_buf_len() {
        let mut buf = BytesMut::from(&[127u8; 10][..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.len(), 10);

        borrowed_buf.get_u32();
        assert_eq!(borrowed_buf.len(), 6);
        assert_eq!(borrowed_buf.cursor, 4);

        borrowed_buf.get_u16();
        assert_eq!(borrowed_buf.len(), 4);
        assert_eq!(borrowed_buf.cursor, 6);

        borrowed_buf.get_u8();
        assert_eq!(borrowed_buf.len(), 3);
        assert_eq!(borrowed_buf.cursor, 7);

        borrowed_buf.get_u8();
        assert_eq!(borrowed_buf.len(), 2);
        assert_eq!(borrowed_buf.cursor, 8);
    }

    #[test]
    fn test_borrowed_bytes_buf_chunk() {
        let buf_value = [127u8; 10];
        let mut buf = BytesMut::from(&buf_value[..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.chunk(), &buf_value[..]);

        borrowed_buf.get_u32();
        assert_eq!(borrowed_buf.chunk(), &buf_value[4..]);

        borrowed_buf.get_u16();
        assert_eq!(borrowed_buf.chunk(), &buf_value[6..]);

        borrowed_buf.get_u32();
        assert_eq!(borrowed_buf.chunk(), &buf_value[10..]);
    }

    #[test]
    fn test_borrowed_bytes_buf_advance() {
        let buf_value = [127u8; 10];
        let mut buf = BytesMut::from(&buf_value[..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.chunk(), &buf_value[..]);

        borrowed_buf.advance(4);
        assert_eq!(borrowed_buf.len(), 10 - 4);

        borrowed_buf.advance(2);
        assert_eq!(borrowed_buf.len(), 10 - 4 - 2);

        borrowed_buf.advance(4);
        assert_eq!(borrowed_buf.len(), 10 - 4 - 2 - 4);
    }

    #[test_case(9 => vec![127u8]; "Remaining buffer")]
    #[test_case(10 => Vec::<u8>::new(); "Full buffer")]
    #[test_case(11 => panics "11 greater than remaining size 10"; "Overflow")]
    fn test_borrowed_bytes_advance(cnt: usize) -> Vec<u8> {
        let buf_value = [127u8; 10];
        let mut buf = BytesMut::from(&buf_value[..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);

        borrowed_buf.advance(cnt);
        borrowed_buf.chunk().to_vec()
    }

    #[test]
    fn test_borrowed_bytes_commit() {
        let raw_buf = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut buf = BytesMut::from(&raw_buf[..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.len(), 10);

        borrowed_buf.get_u32();
        borrowed_buf.get_u16();

        let buf = borrowed_buf.commit();
        assert_eq!(buf.len(), 4);
        assert_eq!(buf[..], raw_buf[6..]);
    }

    #[test]
    fn test_borrowed_bytes_commit_and_split() {
        let mut buf = BytesMut::from(&[0, 0, 0, 3, 4, 5, 6, 7, 8, 9][..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.len(), 10);

        let val = borrowed_buf.get_u32();
        assert_eq!(borrowed_buf.len(), 6);
        assert_eq!(val, 3);

        let split_buf = borrowed_buf.commit_and_split_to(4);
        assert_eq!(borrowed_buf.cursor, 0);
        assert_eq!(&borrowed_buf[..], &[8, 9][..]);
        assert_eq!(split_buf, &[4, 5, 6, 7][..]);

        assert_eq!(&buf[..], &[8, 9][..]);
    }

    #[test]
    fn test_borrowed_bytes_commit_and_split_then_commit() {
        let mut buf = BytesMut::from(&[0, 0, 0, 3, 4, 5, 6, 7, 8, 9][..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.len(), 10);

        let val = borrowed_buf.get_u32();
        assert_eq!(borrowed_buf.len(), 6);
        assert_eq!(val, 3);

        let split_buf = borrowed_buf.commit_and_split_to(4);
        assert_eq!(borrowed_buf.cursor, 0);
        assert_eq!(&borrowed_buf[..], &[8, 9][..]);
        assert_eq!(split_buf, &[4, 5, 6, 7][..]);

        let split_buf = borrowed_buf.commit();
        assert_eq!(&split_buf[..], &[8, 9][..]);
        assert_eq!(&buf[..], &[8, 9][..]);
    }

    #[test]
    #[should_panic(expected = "recommitting a BorrowedBytesBuf")]
    fn test_borrowed_bytes_commit_and_split_twice() {
        let mut buf = BytesMut::from(&[0, 0, 0, 3, 4, 5, 6, 7, 8, 9][..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.len(), 10);

        let val = borrowed_buf.get_u32();
        assert_eq!(borrowed_buf.len(), 6);
        assert_eq!(val, 3);

        let split_buf = borrowed_buf.commit_and_split_to(3);
        assert_eq!(borrowed_buf.cursor, 0);
        assert_eq!(&borrowed_buf[..], &[7, 8, 9][..]);
        assert_eq!(split_buf, &[4, 5, 6][..]);

        borrowed_buf.commit_and_split_to(2); // panic
    }

    #[test]
    #[should_panic(expected = "consuming from already committed BorrowedBytesMut")]
    fn test_borrowed_bytes_commit_and_split_then_get() {
        let mut buf = BytesMut::from(&[0, 0, 0, 3, 4, 5, 6, 7, 8, 9][..]);
        let mut borrowed_buf = BorrowedBytesMut::from(&mut buf);
        assert_eq!(borrowed_buf.len(), 10);

        let val = borrowed_buf.get_u32();
        assert_eq!(borrowed_buf.len(), 6);
        assert_eq!(val, 3);

        let split_buf = borrowed_buf.commit_and_split_to(3);
        assert_eq!(borrowed_buf.cursor, 0);
        assert_eq!(&borrowed_buf[..], &[7, 8, 9][..]);
        assert_eq!(split_buf, &[4, 5, 6][..]);

        borrowed_buf.get_u8(); // panic
    }

    #[test]
    fn test_borrowed_bytes_deref() {
        let buf_value = [127u8; 10];
        let mut buf = BytesMut::from(&buf_value[..]);
        let borrowed_buf = BorrowedBytesMut::from(&mut buf);

        assert_eq!(&borrowed_buf[..], &buf_value[..]);
    }
}
