use crate::{io::inside::InsideIO, metrics};

use crate::connection::ConnectionState;
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use lightway_app_utils::{Tun as AppUtilsTun, TunConfig};
use lightway_core::{
    ipv4_update_source, IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg,
};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

pub(crate) struct Tun(AppUtilsTun);

impl Tun {
    pub async fn new(tun: TunConfig, iouring: Option<usize>) -> Result<Self> {
        let tun = match iouring {
            Some(ring_size) => AppUtilsTun::iouring(tun, None, ring_size).await?,
            None => AppUtilsTun::direct(tun, None).await?,
        };
        Ok(Tun(tun))
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[async_trait]
impl InsideIO for Tun {
    async fn recv_buf(&self) -> IOCallbackResult<bytes::BytesMut> {
        match self.0.recv_buf().await {
            IOCallbackResult::Ok(buf) => {
                metrics::tun_to_client(buf.len());
                IOCallbackResult::Ok(buf)
            }
            e => e,
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState> {
        self
    }
}

impl InsideIOSendCallback<ConnectionState> for Tun {
    fn send(&self, mut buf: BytesMut, state: &mut ConnectionState) -> IOCallbackResult<usize> {
        let Some(client_ip) = state.ip else {
            metrics::tun_rejected_packet_no_client_ip();
            // Ip address not found, dropping the packet
            return IOCallbackResult::Ok(buf.len());
        };

        ipv4_update_source(buf.as_mut(), client_ip);
        metrics::tun_from_client(buf.len());
        self.0.try_send(buf)
    }

    fn mtu(&self) -> usize {
        self.0.mtu()
    }
}
