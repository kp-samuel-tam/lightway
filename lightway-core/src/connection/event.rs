use crate::{SessionId, State};

/// A lightway event
#[derive(Debug)]
pub enum Event {
    /// The connection state has changed
    StateChanged(State),
    /// A reply was received after a [`crate::Connection::keepalive()`]
    KeepaliveReply,
    /// A pending session id change (following a call to
    /// [`crate::Connection::rotate_session_id`]) has been
    /// acknowledged and applied to the connection.
    ///
    /// Server connections only
    SessionIdRotationAcknowledged {
        /// The original [`SessionId`]
        old: SessionId,
        /// The new [`SessionId`]
        new: SessionId,
    },
    /// A key rollover as triggered for a TLS or DTLS 1.3 connection.
    ///
    /// Server connections only
    TlsKeysUpdate,
}
