use metrics::{counter, histogram};

const METRIC_TUN_IOURING_PACKET_DROPPED: &str = "tun_iouring_packet_dropped";
const METRIC_TUN_IOURING_COMPLETION_BATCH_SIZE: &str = "tun_iouring_completion_batch_size";

/// Counter for "sending into a full channel" type of error ([`async_channel::TrySendError::Full`])
pub(crate) fn tun_iouring_packet_dropped() {
    counter!(METRIC_TUN_IOURING_PACKET_DROPPED).increment(1);
}

pub(crate) fn tun_iouring_completion_batch_size(sz: usize) {
    histogram!(METRIC_TUN_IOURING_COMPLETION_BATCH_SIZE).record(sz as f64);
}
