use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use lightway_core::{
    ConnectionType, IOCallbackResult, OutsideIOSendCallback, OutsidePacket, Version,
    MAX_OUTSIDE_MTU,
};
use socket2::SockRef;
use tracing::{info, instrument, warn};

use crate::connection::Connection;
use crate::connection_manager::ConnectionManager;

use super::Server;

struct TcpStream {
    sock: Arc<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
}

impl OutsideIOSendCallback for TcpStream {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.sock.try_write(buf) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

#[instrument(level = "trace", skip_all, fields(session = ?conn.session_id()))]
async fn handle_connection(sock: Arc<tokio::net::TcpStream>, conn: Arc<Connection>) {
    let err: anyhow::Error = loop {
        if let Err(e) = sock.readable().await {
            break anyhow!(e).context("Sock readable error");
        }

        let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);

        match sock.try_read_buf(&mut buf) {
            Ok(0) => {
                // EOF
                conn.handle_end_of_stream();
                break anyhow!("End of stream");
            }
            Ok(_nr) => {}
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                // Spuriously failed to read, keep waiting
                continue;
            }
            Err(err) => break anyhow!(err).context("TCP read error"),
        };

        let pkt = OutsidePacket::Wire(buf, ConnectionType::Stream);
        if let Err(err) = conn.outside_data_received(pkt) {
            warn!("Failed to process outside data: {err}");
            if conn.handle_outside_data_error(&err).is_break() {
                break anyhow!(err).context("Outside data fatal error");
            }
        }
    };

    info!("Connection closed: {:?}", err);
}

pub(crate) struct TcpServer {
    conn_manager: Arc<ConnectionManager>,
    sock: Arc<tokio::net::TcpListener>,
}

impl TcpServer {
    pub(crate) async fn new(
        conn_manager: Arc<ConnectionManager>,
        bind_address: SocketAddr,
    ) -> Result<TcpServer> {
        let sock = Arc::new(tokio::net::TcpListener::bind(bind_address).await?);

        Ok(Self { conn_manager, sock })
    }
}

#[async_trait]
impl Server for TcpServer {
    async fn run(&mut self) -> Result<()> {
        info!("Accepting traffic on {}", self.sock.local_addr()?);

        loop {
            let (sock, addr) = self.sock.accept().await?;

            let local_addr = match SockRef::from(&sock).local_addr() {
                Ok(local_addr) => local_addr,
                Err(err) => {
                    // Since we have a bound socket this shouldn't happen.
                    tracing::debug!(?err, "Failed to get local addr");
                    return Err(err.into());
                }
            };
            let Some(local_addr) = local_addr.as_socket() else {
                // Since we only bind to IP sockets this shouldn't happen.
                tracing::debug!("Failed to convert local addr to socketaddr");
                return Err(anyhow!("Failed to convert local addr to socketaddr"));
            };

            let sock = Arc::new(sock);

            let outside_io = Arc::new(TcpStream {
                sock: sock.clone(),
                peer_addr: addr,
            });
            // TCP has no version indication, default to the minimum
            // supported version.
            let conn = self.conn_manager.create_streaming_connection(
                Version::MINIMUM,
                local_addr,
                outside_io,
            )?;

            tokio::spawn(handle_connection(sock, conn));
        }
    }
}
