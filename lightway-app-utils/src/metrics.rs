use metrics::counter;

const METRIC_TUN_IOURING_PACKET_DROPPED: &str = "tun_iouring_packet_dropped";

/// Counter for "sending into a full channel" type of error ([`async_channel::TrySendError::Full`])
pub(crate) fn tun_iouring_packet_dropped() {
    counter!(METRIC_TUN_IOURING_PACKET_DROPPED).increment(1);
}
