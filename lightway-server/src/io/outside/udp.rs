mod cmsg;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use lightway_app_utils::sockopt::socket_enable_pktinfo;
use lightway_core::{
    ConnectionType, Header, IOCallbackResult, OutsideIOSendCallback, OutsidePacket, SessionId,
    Version, MAX_OUTSIDE_MTU,
};
use socket2::{MaybeUninitSlice, MsgHdrMut, SockAddr, SockRef};
use tokio::io::Interest;
use tracing::{info, instrument, warn};

use crate::{connection_manager::ConnectionManager, metrics};

use super::Server;

const SOCKET_BUFFER_SIZE: usize = 15 * 1024 * 1024;

struct UdpSocket {
    sock: Arc<tokio::net::UdpSocket>,
    peer_addr: RwLock<SocketAddr>,
}

impl OutsideIOSendCallback for UdpSocket {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.sock.try_send_to(buf, *self.peer_addr.read().unwrap()) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        *self.peer_addr.read().unwrap()
    }

    fn set_peer_addr(&self, addr: SocketAddr) -> SocketAddr {
        let mut peer_addr = self.peer_addr.write().unwrap();
        let old_addr = *peer_addr;
        *peer_addr = addr;
        old_addr
    }
}

pub(crate) struct UdpServer {
    conn_manager: Arc<ConnectionManager>,
    sock: Arc<tokio::net::UdpSocket>,
    local_addr: SocketAddr,
}

impl UdpServer {
    pub(crate) async fn new(
        conn_manager: Arc<ConnectionManager>,
        bind_address: SocketAddr,
    ) -> Result<UdpServer> {
        let sock = Arc::new(tokio::net::UdpSocket::bind(bind_address).await?);

        let local_addr = sock.local_addr()?;

        let socket = socket2::SockRef::from(&sock);
        socket.set_send_buffer_size(SOCKET_BUFFER_SIZE)?;
        socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE)?;

        socket_enable_pktinfo(&sock)?;

        Ok(Self {
            conn_manager,
            sock,
            local_addr,
        })
    }

    #[instrument(level = "trace", skip_all)]
    async fn data_received(&mut self, addr: SocketAddr, buf: BytesMut) {
        let pkt = OutsidePacket::Wire(buf, ConnectionType::Datagram);
        let pkt = match self.conn_manager.parse_raw_outside_packet(pkt) {
            Ok(hdr) => hdr,
            Err(e) => {
                metrics::udp_parse_wire_failed();
                warn!("Extracting header from packet failed: {e}");
                return;
            }
        };

        let Some(hdr) = pkt.header() else {
            metrics::udp_no_header();
            warn!("Packet parsing error: Not a UDP frame");
            return;
        };
        if !self.conn_manager.is_supported_version(hdr.version) {
            // If the protocol version is not supported then drop
            // the packet.
            metrics::udp_bad_packet_version(hdr.version);
            return;
        }

        let may_be_conn = self.conn_manager.find_datagram_connection_with(addr);
        let (conn, update_peer_address) = match may_be_conn {
            Some(conn) => (conn, false),
            None => {
                let conn_result = self.conn_manager.find_or_create_datagram_connection_with(
                    addr,
                    hdr.version,
                    hdr.session,
                    || {
                        Arc::new(UdpSocket {
                            sock: self.sock.clone(),
                            peer_addr: RwLock::new(addr),
                        })
                    },
                );

                match conn_result {
                    Ok(conn) => conn,
                    Err(_e) => {
                        self.send_reject(addr).await;
                        return;
                    }
                }
            }
        };

        let session = hdr.session;

        match conn.outside_data_received(pkt) {
            Ok(0) => {
                // We will hit this case when there is UDP packet duplication.
                // Wolfssl skip duplicate packets and thus no frames read.
                // It is also possible that adversary can capture the packet
                // and replay it. In any case, skip processing further
                if update_peer_address {
                    metrics::udp_session_rotation_attempted_via_replay();
                }
            }
            Ok(_) => {
                // NOTE: We wait until the first successful WolfSSL
                // decrypt to protect against the case where a crafted
                // packet with a session ID causes us to change the
                // connection IP without verifying the SSL connection
                // first
                if update_peer_address {
                    metrics::udp_conn_recovered_via_session(session);
                    conn.begin_session_id_rotation();
                    self.conn_manager.set_peer_addr(&conn, addr);
                }
            }
            Err(err) => {
                warn!("Failed to process outside data: {err}");
                let _ = conn.handle_outside_data_error(&err);
                // Fatal or not, we are done with this packet.
                return;
            }
        }
    }

    async fn send_reject(&self, addr: SocketAddr) {
        metrics::udp_rejected_session();
        let msg = Header {
            version: Version::MINIMUM,
            aggressive_mode: false,
            session: SessionId::REJECTED,
        };

        let mut buf = BytesMut::with_capacity(Header::WIRE_SIZE);
        msg.append_to_wire(&mut buf);

        // Ignore failure to send.
        let _ = self.sock.send_to(&buf, addr).await;
    }
}

#[async_trait]
impl Server for UdpServer {
    async fn run(&mut self) -> Result<()> {
        info!("Accepting traffic on {}", self.local_addr);
        loop {
            let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);

            let addr = self
                .sock
                .async_io(Interest::READABLE, || {
                    let sock = SockRef::from(self.sock.as_ref());
                    let mut raw_buf = [MaybeUninitSlice::new(buf.spare_capacity_mut())];

                    #[allow(unsafe_code)]
                    let mut sock_addr = {
                        // SAFETY: sockaddr_storage is defined
                        // (<https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_socket.h.html>)
                        // as being a suitable size and alignment for
                        // "all supported protocol-specific address
                        // structures" in the underlying OS APIs.
                        //
                        // All zeros is a valid representation,
                        // corresponding to the `ss_family` having a
                        // value of `AF_UNSPEC`.
                        let addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                        let len = std::mem::size_of_val(&addr_storage) as libc::socklen_t;
                        // SAFETY: We initialized above as `AF_UNSPEC`
                        // so the storage is correct from that
                        // angle. The `recvmsg` call will change this
                        // which should be ok since `sockaddr_storage`
                        // is big enough.
                        unsafe { SockAddr::new(addr_storage, len) }
                    };

                    const SIZE: usize = cmsg::Message::space::<libc::in_pktinfo>();
                    let mut control = cmsg::Buffer::<SIZE>::new();

                    let mut msg = MsgHdrMut::new()
                        .with_addr(&mut sock_addr)
                        .with_buffers(&mut raw_buf)
                        .with_control(control.as_mut());

                    let len = sock.recvmsg(&mut msg, 0)?;

                    let control_len = msg.control_len();

                    // SAFETY: We rely on recv_from giving us the correct size
                    #[allow(unsafe_code)]
                    unsafe {
                        buf.set_len(len)
                    };

                    let Some(addr) = sock_addr.as_socket() else {
                        // Since we only bind to IP sockets this shouldn't happen.
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "failed to convert local addr to socketaddr",
                        ));
                    };

                    #[allow(unsafe_code)]
                    let Some(local_addr) =
                        // SAFETY: The call to `recvmsg` above updated
                        // the control buffer length field.
                        unsafe { control.iter(control_len) }.find_map(|cmsg| {
                            match cmsg {
                                cmsg::Message::IpPktinfo(pi) => {
                                    // From https://pubs.opengroup.org/onlinepubs/009695399/basedefs/netinet/in.h.html
                                    // the `s_addr` is an `in_addr`
                                    // which is in network byte order
                                    // (big endian).
                                    let ipv4 = u32::from_be(pi.ipi_spec_dst.s_addr);
                                    let ipv4 = Ipv4Addr::from_bits(ipv4);
                                    let ip = IpAddr::V4(ipv4);
                                    Some(SocketAddr::new(ip, self.local_addr.port()))
                                },
                                _ => None,
                            }
                        }) else {
                            // Since we have a bound socket this shouldn't happen.
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "recvmsg did not return IP_PKTINFO",
                            ));
                        };
                    tracing::debug!(?local_addr, "Received data");

                    Ok(addr)
                })
                .await?;

            self.data_received(addr, buf).await;
        }
    }
}
