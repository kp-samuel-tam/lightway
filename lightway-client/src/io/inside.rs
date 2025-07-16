pub mod tun;

use anyhow::Result;
use bytes::BytesMut;
pub use tun::Tun;

use async_trait::async_trait;
use lightway_core::{IOCallbackResult, InsideIpConfig};

#[async_trait]
pub trait InsideIORecv: Sync + Send {
    async fn recv_buf(&self) -> IOCallbackResult<BytesMut>;

    fn try_send(&self, pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize>;
}
