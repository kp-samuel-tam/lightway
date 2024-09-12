use metrics::{counter, histogram, Counter, Histogram};
use std::sync::LazyLock;

static METRIC_TUN_IOURING_PACKET_DROPPED: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_packet_dropped"));
static METRIC_TUN_IOURING_COMPLETION_BATCH_SIZE: LazyLock<Histogram> =
    LazyLock::new(|| histogram!("tun_iouring_completion_batch_size"));

/// Counter for "sending into a full channel" type of error ([`async_channel::TrySendError::Full`])
pub(crate) fn tun_iouring_packet_dropped() {
    METRIC_TUN_IOURING_PACKET_DROPPED.increment(1);
}

pub(crate) fn tun_iouring_completion_batch_size(sz: usize) {
    METRIC_TUN_IOURING_COMPLETION_BATCH_SIZE.record(sz as f64);
}
