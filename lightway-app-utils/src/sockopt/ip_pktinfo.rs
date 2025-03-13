#![allow(unsafe_code)]

#[cfg(not(target_vendor = "apple"))]
use std::os::fd::AsRawFd;

#[cfg(not(target_vendor = "apple"))]
/// Enable IP_PKTINFO sockopt.
pub fn socket_enable_pktinfo(sock: &impl AsRawFd) -> std::io::Result<()> {
    // SAFETY: `setsockopt` requires a valid fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_PKTINFO,
            &1 as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
