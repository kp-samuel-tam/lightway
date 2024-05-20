use bytes::BytesMut;
use thiserror::Error;

use crate::{plugin::PluginList, ConnectionType, Header, PluginResult};

#[derive(Debug)]
/// Packet structure used by application to inject outside packets into lightway-core
pub enum OutsidePacket {
    /// Opaque wire packet, before running plugin chain
    Wire(BytesMut, ConnectionType),
    /// Raw TCP frame, after running plugin chain
    TcpFrame(BytesMut),
    /// Raw UDP frame, after running plugin chain
    UdpFrame(BytesMut, Header),
}

impl OutsidePacket {
    pub(crate) fn into_payload(self) -> Option<BytesMut> {
        match self {
            Self::Wire(_, _) => None,
            Self::TcpFrame(buf) => Some(buf),
            Self::UdpFrame(buf, _hdr) => Some(buf),
        }
    }

    /// Returns the `Header` from the UDP OutsidePacket
    pub fn header(&self) -> Option<&Header> {
        match self {
            Self::UdpFrame(_buf, hdr) => Some(hdr),
            _ => None,
        }
    }

    pub(crate) fn apply_ingress_chain(
        self,
        plugins: &PluginList,
    ) -> Result<Self, OutsidePacketError> {
        match self {
            Self::Wire(mut buf, conn_type) => {
                let mut buf = match plugins.do_ingress(&mut buf) {
                    PluginResult::Accept => buf,
                    PluginResult::Drop => return Err(OutsidePacketError::PluginDrop),
                    PluginResult::DropWithReply(_) => return Err(OutsidePacketError::PluginDrop),
                    PluginResult::Error(e) => return Err(OutsidePacketError::PluginError(e)),
                };

                match conn_type {
                    ConnectionType::Stream => Ok(Self::TcpFrame(buf)),
                    ConnectionType::Datagram => {
                        let hdr = Header::try_from_wire(&mut buf)
                            .map_err(|e| OutsidePacketError::PluginError(e.into()))?;
                        Ok(Self::UdpFrame(buf, hdr))
                    }
                }
            }

            // Plugin chain already ran
            _ => Ok(self),
        }
    }
}

/// An error with [`OutsidePacket`]
#[derive(Debug, Error)]
pub enum OutsidePacketError {
    /// Plugin dropped the packet
    #[error("Plugin dropped outside packet")]
    PluginDrop,

    /// Plugin returned error
    #[error("Plugin Error: {0}")]
    PluginError(Box<dyn std::error::Error + Sync + Send>),
}
