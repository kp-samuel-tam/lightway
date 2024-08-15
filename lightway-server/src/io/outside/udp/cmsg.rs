//! Encapsulates the control message apis used with `recvmsg(2)`.
#![allow(unsafe_code)]

pub(crate) struct Buffer<const N: usize>([std::mem::MaybeUninit<u8>; N]);

impl<const N: usize> Buffer<N> {
    pub(crate) fn new() -> Self {
        Self([std::mem::MaybeUninit::<u8>::uninit(); N])
    }

    pub(crate) fn as_mut(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        &mut self.0
    }

    /// # Safety
    ///
    /// `control_len` must have been set to the number of bytes of the
    /// buffer which have been initialized.
    pub(crate) unsafe fn iter(&self, control_len: usize) -> Iter<N> {
        // Build a `msghdr` so we can use the `CMSG_*` functionality in
        // libc. We will only use the `CMSG_*` macros which only use
        // the `msg_control*` fields.
        let msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: self.0.as_ptr() as *mut _,
            msg_controllen: control_len,
            msg_flags: 0,
        };
        // SAFETY: We constructed a sufficiently valid `msghdr` above.
        // `msg_control[..msg_controllen]` are valid initialized bytes
        // per the safety requirements for calling this method.
        let cursor = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
        Iter {
            msghdr,
            cursor,
            _phantom: std::marker::PhantomData,
        }
    }
}

pub enum Message<'a> {
    IpPktinfo(&'a libc::in_pktinfo),
    Unknown(#[allow(dead_code)] &'a libc::cmsghdr),
}

impl<'a> Message<'a> {
    pub(crate) const fn space<T>() -> usize {
        // SAFETY: CMSG_SPACE is always safe
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<T>() as libc::c_uint) as usize }
    }
}

pub(crate) struct Iter<'a, const N: usize> {
    msghdr: libc::msghdr,
    cursor: *const libc::cmsghdr,
    // `msghdr` contains a raw pointer into the owning `Buffer` and
    // `cursor` is within that buffer. Ensure it remains live longer
    // than this iterator.
    _phantom: std::marker::PhantomData<&'a Buffer<N>>,
}

impl<'a, const N: usize> Iterator for Iter<'a, N> {
    type Item = Message<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.is_null() {
            None
        } else {
            // SAFETY: `cursor` is set by either `CMSG_FIRSTHDR` or
            // `CMSGNXTHDR`, we dealt with the null case above.
            let item = unsafe { &*self.cursor };

            // SAFETY: `msghdr` was constructed as a sufficiently
            // valid `msghdr` by `Buffer::iter()`. `cursor` is valid
            // since it came from a prior `CMSG_FIRSTHDR` or
            // `CMSG_NXTHDR`.
            self.cursor = unsafe { libc::CMSG_NXTHDR(&self.msghdr, self.cursor) };

            Some(match (item.cmsg_level, item.cmsg_type) {
                (libc::SOL_IP, libc::IP_PKTINFO) => {
                    // SAFETY: `item` is a valid `cmsghdr` from a
                    // prior call to `CMSG_FIRSTHDR` or `CMSG_NXTHDR`.
                    let data = unsafe { libc::CMSG_DATA(item) as *const libc::in_pktinfo };
                    // SAFETY: we constructed `data` above
                    let pi = unsafe { &*data };
                    Message::IpPktinfo(pi)
                }
                (_, _) => Message::Unknown(item),
            })
        }
    }
}
