pub(crate) mod tun;

use bytes::BytesMut;
pub(crate) use tun::Tun;

use async_trait::async_trait;
use lightway_core::{IOCallbackResult, InsideIOSendCallbackArg};
use std::sync::Arc;

use crate::ConnectionState;

#[async_trait]
pub(crate) trait InsideIO: Sync + Send {
    async fn recv_buf(&self) -> IOCallbackResult<BytesMut>;

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState>;
}
