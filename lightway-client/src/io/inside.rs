pub mod tun;

use anyhow::Result;
use bytes::BytesMut;
pub use tun::Tun;

use async_trait::async_trait;
use lightway_core::{IOCallbackResult, InsideIOSendCallbackArg, InsideIpConfig};
use std::sync::Arc;

use crate::ConnectionState;

#[async_trait]
pub trait InsideIO: Sync + Send {
    async fn recv_buf(&self) -> IOCallbackResult<BytesMut>;

    fn try_send(&self, pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize>;

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState>;
}
