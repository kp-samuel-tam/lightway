use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram};
use std::{sync::LazyLock, time::Duration};

static METRIC_TUN_IOURING_COMPLETION_BATCH_SIZE: LazyLock<Histogram> =
    LazyLock::new(|| histogram!("tun_iouring_completion_batch_size"));
static METRIC_TUN_IOURING_COMPLETIONS_BEFORE_BLOCKING: LazyLock<Histogram> =
    LazyLock::new(|| histogram!("tun_iouring_completions_before_blocking"));

static METRIC_TUN_IOURING_RX_EAGAIN: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_rx_eagain"));
static METRIC_TUN_IOURING_RX_ERR: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_rx_err"));

static METRIC_TUN_IOURING_BLOCKED: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_blocked"));
static METRIC_TUN_IOURING_WAKE_EVENTFD: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_wake_eventfd"));
static METRIC_TUN_IOURING_WAKE_TX: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_wake_tx"));

static METRIC_TUN_IOURING_TOTAL_THREAD_TIME: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("tun_iouring_total_thread_time"));
static METRIC_TUN_IOURING_IDLE_THREAD_TIME: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("tun_iouring_idle_thread_time"));

/// Monitors size of uring completion queue on each iteration
pub(crate) fn tun_iouring_completion_batch_size(sz: usize) {
    METRIC_TUN_IOURING_COMPLETION_BATCH_SIZE.record(sz as f64);
}

pub(crate) fn tun_iouring_completions_before_blocking(sz: usize) {
    METRIC_TUN_IOURING_COMPLETIONS_BEFORE_BLOCKING.record(sz as f64)
}

/// Count iouring RX entries which complete with EAGAIN
pub(crate) fn tun_iouring_rx_eagain() {
    METRIC_TUN_IOURING_RX_EAGAIN.increment(1)
}

/// Count iouring RX entries which complete with an error
pub(crate) fn tun_iouring_rx_err() {
    METRIC_TUN_IOURING_RX_ERR.increment(1)
}

pub(crate) fn tun_iouring_blocked() {
    METRIC_TUN_IOURING_BLOCKED.increment(1)
}

pub(crate) fn tun_iouring_wake_eventfd() {
    METRIC_TUN_IOURING_WAKE_EVENTFD.increment(1)
}

pub(crate) fn tun_iouring_wake_tx() {
    METRIC_TUN_IOURING_WAKE_TX.increment(1)
}

pub(crate) fn tun_iouring_total_thread_time(t: Duration) {
    METRIC_TUN_IOURING_TOTAL_THREAD_TIME.set(t.as_millis() as f64);
}

pub(crate) fn tun_iouring_idle_thread_time(t: Duration) {
    METRIC_TUN_IOURING_IDLE_THREAD_TIME.increment(t.as_millis() as f64);
}
