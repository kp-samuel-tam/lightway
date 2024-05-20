use lightway_core::{SessionId, Version};
use metrics::{counter, gauge, histogram};
use tracing::trace;

use crate::connection::Connection;

// Connection lifecycle
const METRIC_CONNECTION_CREATED: &str = "conn_created";
const METRIC_CONNECTION_LINK_UP: &str = "conn_link_up";
const METRIC_CONNECTION_REJECTED_NO_FREE_IP: &str = "conn_rejected_no_free_ip";
const METRIC_CONNECTION_REJECTED_ACCESS_DENIED: &str = "conn_rejected_access_denied";
const METRIC_CONNECTION_TLS_ERROR: &str = "conn_tls_error";
const METRIC_CONNECTION_UNKNOWN_ERROR: &str = "conn_unknown_error";
const METRIC_CONNECTION_AGED_OUT: &str = "conn_aged_out";
const METRIC_CONNECTION_EVICTED: &str = "user_auth_eviction";
const METRIC_CONNECTION_CLOSED: &str = "conn_closed";

// UDP specific session and version handling
const METRIC_UDP_CONNECTION_RECOVERED_VIA_SESSION: &str = "udp_conn_recovered_via_session";
const METRIC_UDP_BAD_PACKET_VERSION: &str = "udp_bad_packet_version";
const METRIC_UDP_REJECTED_SESSION: &str = "udp_rejected_session";
const METRIC_UDP_PARSE_WIRE_FAILED: &str = "udp_parse_wire_failed";
const METRIC_UDP_NO_HEADER: &str = "udp_no_header";
const METRIC_UDP_SESSION_ROTATION_BEGIN: &str = "udp_session_rotation_begin";
const METRIC_UDP_SESSION_ROTATION_FINALIZED: &str = "udp_session_rotation_finalized";
const METRIC_UDP_SESSION_ROTATION_ATTEMPTED_VIA_REPLAY: &str =
    "udp_session_rotation_attempted_via_replay";

// Connection performance
const METRIC_TO_LINK_UP_TIME: &str = "to_link_up_time";
const METRIC_TO_ONLINE_TIME: &str = "to_online_time";

// TUN
const METRIC_TUN_REJECTED_INVALID_STATE: &str = "tun_rejected_packet_invalid_state";
const METRIC_TUN_REJECTED_INVALID_INSIDE_PACKET: &str = "tun_rejected_packet_invalid_inside_packet";
const METRIC_TUN_REJECTED_OTHER: &str = "tun_rejected_packet_invalid_other";
const METRIC_TUN_REJECTED_NO_CONNECTION: &str = "tun_rejected_packet_no_connection";
const METRIC_TUN_REJECTED_NO_CLIENT_IP: &str = "tun_rejected_packet_no_client_ip";

// Traffic volume
const METRIC_TUN_FROM_CLIENT: &str = "tun_from_client";
const METRIC_TUN_TO_CLIENT: &str = "tun_to_client";

const METRIC_SESSIONS_CURRENT_ONLINE: &str = "sessions_current_online";
const METRIC_SESSIONS_LIFETIME_TOTAL: &str = "sessions_lifetime_total";
const METRIC_SESSIONS_PENDING_ID_ROTATIONS: &str = "sessions_pending_id_rotations";
const METRIC_SESSIONS_ACTIVE_5M: &str = "sessions_active_5m";
const METRIC_SESSIONS_ACTIVE_15M: &str = "sessions_active_15m";
const METRIC_SESSIONS_ACTIVE_60M: &str = "sessions_active_60m";
const METRIC_SESSIONS_STANDBY_5M: &str = "sessions_standby_5m";
const METRIC_SESSIONS_STANDBY_15M: &str = "sessions_standby_15m";
const METRIC_SESSIONS_STANDBY_60M: &str = "sessions_standby_60m";

const METRIC_ASSIGNED_INTERNAL_IPS: &str = "assigned_internal_ips";

// Labels for use with the above
const CIPHER_LABEL: &str = "cipher";
const CURVE_LABEL: &str = "curve";
const TLS_PROTOCOL_VERSION_LABEL: &str = "tls_protocol_version";
const LIGHTWAY_PROTOCOL_VERSION_LABEL: &str = "lightway_protocol_version";
const FATAL_LABEL: &str = "fatal";

#[derive(Default, Debug)]
pub(crate) struct ConnectionIntervalStats {
    pub five_minutes: usize,
    pub fifteen_minutes: usize,
    pub sixty_minutes: usize,
}

/// Connection lifecycle: New [`lightway_core::Connection`] created
pub(crate) fn connection_created(lw_protocol_version: &Version) {
    counter!(
        METRIC_CONNECTION_CREATED,
        LIGHTWAY_PROTOCOL_VERSION_LABEL => lw_protocol_version.to_string()
    )
    .increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] transitioned
/// to [`lightway_core::State::LinkUp`] state
pub(crate) fn connection_link_up(conn: &Connection) {
    let to_link_up = conn.connection_started.elapsed();
    let cipher = conn
        .current_cipher()
        .unwrap_or_else(|| "unknown".to_string());
    let curve = conn
        .current_curve()
        .unwrap_or_else(|| "unknown".to_string());

    let tls_protocol_version = conn.tls_protocol_version();

    trace!(cipher, curve, to_link_up = ?to_link_up);
    histogram!(METRIC_TO_LINK_UP_TIME).record(to_link_up);
    counter!(METRIC_CONNECTION_LINK_UP,
                       CIPHER_LABEL => cipher,
                       CURVE_LABEL => curve,
                       TLS_PROTOCOL_VERSION_LABEL => tls_protocol_version.as_str(),
    )
    .increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] transitioned
/// to [`lightway_core::State::Online`] state
pub(crate) fn connection_online(conn: &Connection) {
    let to_online = conn.connection_started.elapsed();
    histogram!(METRIC_TO_ONLINE_TIME).record(to_online);
}

/// Connection lifecycle: [`lightway_core::Connection`] rejected, no
/// available IPs.
pub(crate) fn connection_rejected_no_free_ip() {
    counter!(METRIC_CONNECTION_REJECTED_NO_FREE_IP).increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] rejected,
/// authentication failed.
pub(crate) fn connection_rejected_access_denied() {
    counter!(METRIC_CONNECTION_REJECTED_ACCESS_DENIED).increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] aged out due
/// to exceeding idle threshold.
pub(crate) fn connection_aged_out() {
    counter!(METRIC_CONNECTION_AGED_OUT).increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] authentication
/// expired.
pub(crate) fn connection_expired() {
    counter!(METRIC_CONNECTION_EVICTED).increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] closed.
pub(crate) fn connection_closed() {
    counter!(METRIC_CONNECTION_CLOSED).increment(1);
}

/// UDP: Session recovered
pub(crate) fn udp_conn_recovered_via_session(session: SessionId) {
    trace!(?session, "Recovered UDP session");
    counter!(METRIC_UDP_CONNECTION_RECOVERED_VIA_SESSION).increment(1);
}

/// UDP: session id rotation using replay packets
pub(crate) fn udp_session_rotation_attempted_via_replay() {
    counter!(METRIC_UDP_SESSION_ROTATION_ATTEMPTED_VIA_REPLAY).increment(1);
}

/// UDP: Session ID rotation started
pub(crate) fn udp_session_rotation_begin() {
    trace!("Begin session rotation");
    counter!(METRIC_UDP_SESSION_ROTATION_BEGIN).increment(1);
}

/// UDP: Session ID rotation complete
pub(crate) fn udp_session_rotation_finalized() {
    trace!("Finalize session rotation");
    counter!(METRIC_UDP_SESSION_ROTATION_FINALIZED).increment(1);
}

/// UDP: Bad lightway protocol version
pub(crate) fn udp_bad_packet_version(version: Version) {
    counter!(
        METRIC_UDP_BAD_PACKET_VERSION,
        LIGHTWAY_PROTOCOL_VERSION_LABEL => version.to_string(),
    )
    .increment(1);
}

/// UDP: Session rejected
pub(crate) fn udp_rejected_session() {
    counter!(METRIC_UDP_REJECTED_SESSION).increment(1);
}

pub(crate) fn udp_parse_wire_failed() {
    counter!(METRIC_UDP_PARSE_WIRE_FAILED).increment(1);
}

pub(crate) fn udp_no_header() {
    counter!(METRIC_UDP_NO_HEADER).increment(1);
}

/// Fatal TLS error for [`lightway_core::Connection`].
pub(crate) fn connection_tls_error(fatal: bool) {
    counter!(METRIC_CONNECTION_TLS_ERROR, FATAL_LABEL => fatal.to_string()).increment(1);
}

/// Unknown error for [`lightway_core::Connection`].
pub(crate) fn connection_unknown_error(fatal: bool) {
    counter!(METRIC_CONNECTION_UNKNOWN_ERROR, FATAL_LABEL => fatal.to_string()).increment(1);
}

/// Tunnel rejected packet, [`lightway_core::Connection`] not in
/// [`lightway_core::State::Online`] state
pub(crate) fn tun_rejected_packet_invalid_state() {
    counter!(METRIC_TUN_REJECTED_INVALID_STATE).increment(1);
}

/// Tunnel rejected packet, inside packet invalid
pub(crate) fn tun_rejected_packet_invalid_inside_packet() {
    counter!(METRIC_TUN_REJECTED_INVALID_INSIDE_PACKET).increment(1);
}

/// Tunnel rejected packet, other reasons
pub(crate) fn tun_rejected_packet_invalid_other() {
    counter!(METRIC_TUN_REJECTED_OTHER).increment(1);
}

/// Tunnel rejected packet, no corresponding
/// [`lightway_core::Connection`] found.
pub(crate) fn tun_rejected_packet_no_connection() {
    counter!(METRIC_TUN_REJECTED_NO_CONNECTION).increment(1);
}

/// Tunnel rejected packet, since there was no clientip in app state
pub(crate) fn tun_rejected_packet_no_client_ip() {
    counter!(METRIC_TUN_REJECTED_NO_CLIENT_IP).increment(1);
}

/// Bytes sent from client to the TUN device.
pub(crate) fn tun_from_client(sz: usize) {
    counter!(METRIC_TUN_FROM_CLIENT).increment(sz as u64);
}

/// Bytes received from TUN device (destined for client).
pub(crate) fn tun_to_client(sz: usize) {
    counter!(METRIC_TUN_TO_CLIENT).increment(sz as u64);
}

/// Current session statistics
pub(crate) fn sessions_statistics(
    current_sessions: usize,
    total_sessions: usize,
    pending_session_id_rotations: usize,
    active: ConnectionIntervalStats,
    standby: ConnectionIntervalStats,
) {
    gauge!(METRIC_SESSIONS_CURRENT_ONLINE).set(current_sessions as f64);
    gauge!(METRIC_SESSIONS_LIFETIME_TOTAL).set(total_sessions as f64);
    gauge!(METRIC_SESSIONS_PENDING_ID_ROTATIONS).set(pending_session_id_rotations as f64);

    gauge!(METRIC_SESSIONS_ACTIVE_5M).set(active.five_minutes as f64);
    gauge!(METRIC_SESSIONS_ACTIVE_15M).set(active.fifteen_minutes as f64);
    gauge!(METRIC_SESSIONS_ACTIVE_60M).set(active.sixty_minutes as f64);
    gauge!(METRIC_SESSIONS_STANDBY_5M).set(standby.five_minutes as f64);
    gauge!(METRIC_SESSIONS_STANDBY_15M).set(standby.fifteen_minutes as f64);
    gauge!(METRIC_SESSIONS_STANDBY_60M).set(standby.sixty_minutes as f64);
}

/// Number of IP addresses in use
pub(crate) fn assigned_internal_ips(nr: usize) {
    gauge!(METRIC_ASSIGNED_INTERNAL_IPS).set(nr as f64);
}
