#![allow(unsafe_code)]
//! Support some socket options we need.
//!
//! In the absence of something like
//! <https://github.com/rust-lang/socket2/issues/487> we have to reach
//! for libc and unsafety.

use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

/// From `include/uapi/linux/in.h`:
///
/// ```ignore
/// #define IP_PMTUDISC_DONT                0       /* Never send DF frames */
/// #define IP_PMTUDISC_WANT                1       /* Use per route hints  */
/// #define IP_PMTUDISC_DO                  2       /* Always DF            */
/// #define IP_PMTUDISC_PROBE               3       /* Ignore dst pmtu      */
/// ```
#[derive(Copy, Clone)]
pub(super) enum IpPmtudisc {
    Dont,
    Want,
    Do,
    Probe,
}

impl From<IpPmtudisc> for libc::c_int {
    fn from(value: IpPmtudisc) -> Self {
        match value {
            IpPmtudisc::Dont => 0,
            IpPmtudisc::Want => 1,
            IpPmtudisc::Do => 2,
            IpPmtudisc::Probe => 3,
        }
    }
}

impl TryFrom<libc::c_int> for IpPmtudisc {
    type Error = std::io::Error;

    fn try_from(value: libc::c_int) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IpPmtudisc::Dont),
            1 => Ok(IpPmtudisc::Want),
            2 => Ok(IpPmtudisc::Do),
            3 => Ok(IpPmtudisc::Probe),
            _ => Err(std::io::Error::other("unexpected value for IP_PMTUDISC")),
        }
    }
}

pub(super) fn get_ip_mtu_discover(sock: &tokio::net::UdpSocket) -> std::io::Result<IpPmtudisc> {
    let mut value: MaybeUninit<libc::c_int> = MaybeUninit::uninit();
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let level: i32;
    let optname: i32;

    #[cfg(target_os = "macos")]
    {
        level = libc::IPPROTO_IP;
        optname = libc::IP_DONTFRAG;
    }

    #[cfg(not(target_os = "macos"))]
    {
        level = libc::SOL_IP;
        optname = libc::IP_MTU_DISCOVER;
    }

    // SAFETY: `getsockopt` requires an fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            level,
            optname,
            value.as_mut_ptr().cast(),
            &mut len,
        )
    };

    if res == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::c_int>() {
        return Err(std::io::Error::other(
            "unexpect len for IP_MTU_DISCOVER result",
        ));
    }

    // SAFETY: `getsockopt` initialised `value` for us.
    let value = unsafe { value.assume_init() };

    value.try_into()
}

pub(super) fn set_ip_mtu_discover(
    sock: &tokio::net::UdpSocket,
    pmtudisc: IpPmtudisc,
) -> std::io::Result<()> {
    let pmtudisc: libc::c_int = pmtudisc.into();
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let level: i32;
    let optname: i32;

    #[cfg(target_os = "macos")]
    {
        level = libc::IPPROTO_IP;
        optname = libc::IP_DONTFRAG;
    }

    #[cfg(not(target_os = "macos"))]
    {
        level = libc::SOL_IP;
        optname = libc::IP_MTU_DISCOVER;
    }

    // SAFETY: `setsockopt` requires an fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            optname,
            &pmtudisc as *const libc::c_int as *const libc::c_void,
            len,
        )
    };

    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
