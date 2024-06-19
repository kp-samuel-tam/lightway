use metrics::counter;

const METRIC_TUN_IOURING_DATA_DROPPED: &str = "tun_iouring_data_dropped";

/// Counter for "sending into a full channel" type of error ([`async_channel::TrySendError::Full`])
pub(crate) fn tun_iouring_data_dropped() {
    counter!(METRIC_TUN_IOURING_DATA_DROPPED).increment(1);
}
