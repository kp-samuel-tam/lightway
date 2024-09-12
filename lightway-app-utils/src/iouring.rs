use anyhow::Result;
use async_channel::{bounded, Receiver, Sender};
use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use thiserror::Error;

use crate::metrics;
use io_uring::{
    cqueue::Entry as CEntry, opcode, squeue::Entry as SEntry, types::Fixed, CompletionQueue,
    IoUring,
};
use std::{
    os::fd::{AsRawFd, RawFd},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};
use tokio::{io::AsyncReadExt, sync::Semaphore};
use tokio_eventfd::EventFd;

const REGISTERED_FD_INDEX: u32 = 0;
const IOURING_SQPOLL_IDLE_TIME: u32 = 100;

#[allow(dead_code)]
/// IO-uring Struct
pub struct IOUring<T: AsRawFd> {
    /// Any struct corresponds to a file descriptor
    owned_fd: Arc<T>,
    /// Handle to thread created for io-uring
    io_uring_thread_handle: JoinHandle<Result<()>>,
    inner: IOUringInner,
}

enum Operation {
    TX,
    RX,
}

/// An error from read/write operation
#[derive(Debug, Error)]
pub enum IOUringError {
    /// A recv error occurred
    #[error("Recv Error: {0}")]
    RecvError(#[from] async_channel::RecvError),

    /// A send error occurred
    #[error("Send Error: {0}")]
    SendError(#[from] async_channel::TrySendError<BytesMut>),
}

pub type IOUringResult<T> = std::result::Result<T, IOUringError>;

#[derive(Clone)]
struct Queue<T: Clone> {
    tx: Sender<T>,
    rx: Receiver<T>,
}

impl<T: Clone> From<(Sender<T>, Receiver<T>)> for Queue<T> {
    fn from(d: (Sender<T>, Receiver<T>)) -> Self {
        Self { tx: d.0, rx: d.1 }
    }
}

#[derive(Clone)]
struct IOUringInner {
    id: Arc<AtomicU64>,
    submit_map: Arc<DashMap<u64, (Operation, BytesMut)>>,
    sqe_channel_rx: Receiver<SubmitEntry>,
    sqe_channel_tx: Sender<SubmitEntry>,
    send_q: Queue<BytesMut>,
    recv_q: Queue<BytesMut>,
    sq_avail_size: Arc<Semaphore>,
    mtu: usize,
}

pub struct SubmitEntry {
    sqe: SEntry,
    operation: Operation,
    buf: BytesMut,
}

impl IOUringInner {
    async fn send_task(&self) -> Result<()> {
        while let Ok(mut buf) = self.send_q.rx.recv().await {
            let sqe =
                opcode::Write::new(Fixed(REGISTERED_FD_INDEX), buf.as_mut_ptr(), buf.len() as _)
                    .build();

            let submit_entry = SubmitEntry {
                sqe,
                operation: Operation::TX,
                buf,
            };
            self.sqe_channel_tx.send(submit_entry).await?;
        }
        Ok(())
    }

    async fn recv_task(&self) -> Result<()> {
        while let Ok(guard) = self.sq_avail_size.acquire().await {
            guard.forget();
            let mut buf = BytesMut::with_capacity(self.mtu);
            let sqe = opcode::Read::new(
                Fixed(REGISTERED_FD_INDEX),
                buf.as_mut_ptr(),
                buf.capacity() as _,
            )
            .build();

            let submit_entry = SubmitEntry {
                sqe,
                operation: Operation::RX,
                buf,
            };
            self.sqe_channel_tx.send(submit_entry).await?;
        }
        Ok(())
    }
}

impl<T: AsRawFd> IOUring<T> {
    /// Create `IOUring` struct
    pub async fn new(
        owned_fd: Arc<T>,
        ring_size: usize,
        channel_size: usize,
        mtu: usize,
    ) -> Result<Self> {
        let fd = owned_fd.as_raw_fd();

        let send_q: Queue<BytesMut> = bounded(channel_size).into();
        let recv_q: Queue<BytesMut> = bounded(channel_size).into();

        // Using half of total io-uring size
        let sq_avail_size = Arc::new(Semaphore::const_new(ring_size / 2));
        let submit_map: Arc<DashMap<u64, (Operation, BytesMut)>> = Arc::new(DashMap::new());
        let id = Arc::new(AtomicU64::new(0));
        let (sqe_channel_tx, sqe_channel_rx): (Sender<SubmitEntry>, Receiver<SubmitEntry>) =
            async_channel::bounded(ring_size);

        let inner: IOUringInner = IOUringInner {
            id,
            submit_map: submit_map.clone(),
            sqe_channel_rx: sqe_channel_rx.clone(),
            sqe_channel_tx,
            send_q,
            recv_q,
            sq_avail_size: sq_avail_size.clone(),
            mtu,
        };

        let sent_inner = inner.clone();
        tokio::spawn(async move { sent_inner.send_task().await });

        let recv_inner = inner.clone();
        tokio::spawn(async move { recv_inner.recv_task().await });

        let inner_clone = inner.clone();
        let io_uring_thread_handle = thread::Builder::new()
            .name("io_uring-main".to_string())
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed building Tokio Runtime")
                    .block_on(main_task(fd, ring_size, inner_clone))
            })?;

        Ok(Self {
            owned_fd,
            io_uring_thread_handle,
            inner,
        })
    }

    /// Retrieve a reference to the underlying device
    pub fn owned_fd(&self) -> &T {
        &self.owned_fd
    }

    /// Receive packet from Tun device
    pub async fn recv(&self) -> IOUringResult<BytesMut> {
        self.inner
            .recv_q
            .rx
            .recv()
            .await
            .map_err(IOUringError::RecvError)
    }

    /// Try Send packet to Tun device
    pub fn try_send(&self, buf: BytesMut) -> IOUringResult<()> {
        let try_send_res = self.inner.send_q.tx.try_send(buf);
        match try_send_res {
            Ok(()) => Ok(()),
            Err(e) if e.is_full() => {
                // it is effectively the same scenario as a buffer in a network
                // switch/router filling up so dropping the traffic is appropriate
                metrics::tun_iouring_packet_dropped();
                Ok(())
            }
            Err(e) => Err(IOUringError::SendError(e)),
        }
    }
}

async fn process_cqe_task(
    mut cq: CompletionQueue<'_>,
    mut evt_fd: EventFd,
    inner: IOUringInner,
) -> Result<()> {
    let mut completed_number: [u8; 8] = [0; 8];

    loop {
        cq.sync();
        // This avoids reading eventfd frequently and wait only if the CQ is empty
        // and thus saving number of syscalls
        if cq.is_empty() {
            let a = evt_fd.read(&mut completed_number).await?;
            assert_eq!(a, 8);
            cq.sync();
        }
        metrics::tun_iouring_completion_batch_size(cq.len());
        for cqe in cq.by_ref() {
            let key = cqe.user_data();
            let res: i32 = cqe.result();

            // Find udata from Hashmap
            // 1. If it is TX, free the buf
            // 2. If it is RX, move the buf to `recv_q_tx`
            if let Some((_, (op, mut buf))) = inner.submit_map.remove(&key) {
                match op {
                    Operation::RX => {
                        if res > 0 {
                            // SAFETY: upon completion `Operation::RX`
                            // has initialized `res` bytes of the
                            // buffer. We know that
                            // `IOUringInner::recv_task` injects
                            // matched pairs of `Operation:RX` and a
                            // buffer into the queue so they must
                            // correspond.
                            #[allow(unsafe_code)]
                            unsafe {
                                buf.advance_mut(res as _);
                            }
                            inner
                                .recv_q
                                .tx
                                .send(buf)
                                .await
                                .expect("Buffer Rx channel send failed");
                        } else {
                            // TODO Add metrics
                        }
                        inner.sq_avail_size.add_permits(1);
                    }
                    Operation::TX => {
                        if res < 0 {
                            // TODO Add metrics
                            println!("Error receiving CQE : {} for key: {} Op: TX", res, key);
                        }
                    }
                }
            }
        }
    }
}

async fn main_task(fd: RawFd, ring_size: usize, inner: IOUringInner) -> Result<()> {
    let event_fd: EventFd = EventFd::new(0, false)?;
    let mut ring: IoUring<SEntry, CEntry> = IoUring::builder()
        // This setting makes CPU go 100% when there is continuous traffic
        .setup_sqpoll(IOURING_SQPOLL_IDLE_TIME) // Needs 5.13
        .build(ring_size as u32)?;

    let (sbmt, mut sq, cq) = ring.split();

    // Register event-fd to cqe entries
    sbmt.register_eventfd(event_fd.as_raw_fd())?;
    sbmt.register_files(&[fd])?;

    let inner_clone = inner.clone();
    tokio::select!(
        _ = async move {
            while let Ok(entry) = inner_clone.sqe_channel_rx.recv().await {
                let SubmitEntry{mut sqe, operation, buf} = entry;

                let id = inner_clone.id.fetch_add(1, Ordering::Relaxed);
                sqe = sqe.user_data(id);

                #[allow(unsafe_code)]
                // SAFETY: We only construct valid `sqe`s in
                // `IOUringInner::{send_task,recv_task}` which feed
                // `sqe_channel_rx` above.
                let push_result = unsafe { sq.push(&sqe) };

                match push_result {
                    Ok(_) => {
                        inner_clone.submit_map.insert(id, (operation, buf));
                    },
                    Err(_) => {
                        if matches!(operation, Operation::RX) {
                            inner_clone.sq_avail_size.add_permits(1);
                        }
                    },
                }
                sq.sync();
                sbmt.submit().expect("failed submitting to uring");
            }
        } => {},
        _ = process_cqe_task(cq, event_fd, inner) => {},
    );

    Ok(())
}
