use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use pnet::packet::ipv4::Ipv4Packet;

use lightway_app_utils::{Tun as AppUtilsTun, TunConfig};
use lightway_core::{
    ipv4_update_destination, ipv4_update_source, IOCallbackResult, InsideIOSendCallback,
    InsideIOSendCallbackArg, InsideIpConfig,
};

use crate::{io::inside::InsideIO, ConnectionState};

pub struct Tun {
    tun: AppUtilsTun,
    ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
}

impl Tun {
    pub async fn new(
        tun: TunConfig,
        ip: Ipv4Addr,
        dns_ip: Ipv4Addr,
        mtu: Option<u16>,
        #[cfg(feature = "io-uring")] iouring: Option<usize>,
    ) -> Result<Self> {
        #[cfg(feature = "io-uring")]
        let tun = match iouring {
            Some(ring_size) => AppUtilsTun::iouring(tun, mtu, ring_size).await?,
            None => AppUtilsTun::direct(tun, mtu).await?,
        };
        #[cfg(not(feature = "io-uring"))]
        let tun = AppUtilsTun::direct(tun, mtu).await?;
        Ok(Tun { tun, ip, dns_ip })
    }

    /// Api to send packet in the tunnel
    pub fn try_send(&self, mut pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize> {
        let pkt_len = pkt.len();
        // Update destination IP from server provided inside ip to TUN device ip
        ipv4_update_destination(pkt.as_mut(), self.ip);

        // Update source IP from server DNS ip to TUN DNS ip
        if let Some(ip_config) = ip_config {
            let packet = Ipv4Packet::new(pkt.as_ref());
            if let Some(packet) = packet {
                if packet.get_source() == ip_config.dns_ip {
                    ipv4_update_source(pkt.as_mut(), self.dns_ip);
                }
            };
        }

        self.tun.try_send(pkt);
        Ok(pkt_len)
    }
}

#[async_trait]
impl InsideIO for Tun {
    async fn recv_buf(&self) -> IOCallbackResult<BytesMut> {
        self.tun.recv_buf().await
    }

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState> {
        self
    }
}

impl InsideIOSendCallback<ConnectionState> for Tun {
    fn send(&self, mut buf: BytesMut, state: &mut ConnectionState) -> IOCallbackResult<usize> {
        // Update destination IP from server provided inside ip to TUN device ip
        ipv4_update_destination(buf.as_mut(), self.ip);

        // Update source IP from server DNS ip to TUN DNS ip
        if let Some(ip_config) = state.ip_config {
            let packet = Ipv4Packet::new(buf.as_ref());
            if let Some(packet) = packet {
                if packet.get_source() == ip_config.dns_ip {
                    ipv4_update_source(buf.as_mut(), self.dns_ip);
                }
            };
        }

        self.tun.try_send(buf)
    }

    fn mtu(&self) -> usize {
        self.tun.mtu()
    }
}
