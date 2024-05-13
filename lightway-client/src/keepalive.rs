//! Keepalive processing
use futures::future::OptionFuture;
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::ConnectionState;

pub(crate) trait Connection: Send {
    fn keepalive(&self) -> lightway_core::ConnectionResult<()>;
}

impl Connection for Weak<Mutex<lightway_core::Connection<ConnectionState>>> {
    fn keepalive(&self) -> lightway_core::ConnectionResult<()> {
        let Some(conn) = self.upgrade() else {
            return Ok(());
        };
        let mut conn = conn.lock().unwrap();
        conn.keepalive()
    }
}

pub(crate) trait SleepManager: Send {
    fn interval_is_zero(&self) -> bool;
    fn timeout_is_zero(&self) -> bool;
    fn sleep_for_interval(&self) -> impl std::future::Future<Output = ()> + std::marker::Send;
    fn sleep_for_timeout(&self) -> impl std::future::Future<Output = ()> + std::marker::Send;
}

pub(crate) struct Config {
    pub(crate) interval: Duration,
    pub(crate) timeout: Duration,
}

impl SleepManager for Config {
    fn interval_is_zero(&self) -> bool {
        self.interval.is_zero()
    }

    fn timeout_is_zero(&self) -> bool {
        self.timeout.is_zero()
    }

    async fn sleep_for_interval(&self) {
        tokio::time::sleep(self.interval).await
    }

    async fn sleep_for_timeout(&self) {
        tokio::time::sleep(self.timeout).await
    }
}

pub(crate) enum Message {
    Online,
    OutsideActivity,
    ReplyReceived,
}

pub(crate) enum KeepaliveResult {
    Cancelled,
    Timedout,
}

#[derive(Clone)]
pub(crate) struct Keepalive {
    tx: Option<mpsc::Sender<Message>>,
    _cancellation: Arc<DropGuard>,
}

impl Keepalive {
    /// Create a new keepalive manager for the given connection
    pub(crate) fn new<CONFIG: SleepManager + 'static, CONNECTION: Connection + 'static>(
        config: CONFIG,
        conn: CONNECTION,
    ) -> (Self, OptionFuture<JoinHandle<KeepaliveResult>>) {
        let cancel = CancellationToken::new();

        if config.interval_is_zero() {
            return (
                Self {
                    tx: None,
                    _cancellation: Arc::new(cancel.drop_guard()),
                },
                None.into(),
            );
        }

        let (tx, rx) = mpsc::channel(3);
        let task = tokio::spawn(keepalive(config, conn, rx, cancel.clone()));
        let cancel = Arc::new(cancel.drop_guard());
        (
            Self {
                tx: Some(tx),
                _cancellation: cancel,
            },
            Some(task).into(),
        )
    }

    /// Signal that the connection is now online
    pub async fn online(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Message::Online).await;
        }
    }

    /// Signal that outside activity was observed
    pub async fn outside_activity(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Message::OutsideActivity).await;
        }
    }

    /// Signal that a pong was received
    pub async fn reply_received(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Message::ReplyReceived).await;
        }
    }
}

async fn keepalive<CONFIG: SleepManager, CONNECTION: Connection>(
    config: CONFIG,
    conn: CONNECTION,
    mut rx: mpsc::Receiver<Message>,
    token: CancellationToken,
) -> KeepaliveResult {
    enum State {
        // Not yet online
        Offline,
        // We are waiting between keepalive intervals
        Waiting,
        // A keepalive has been sent, reply is pending
        Pending,
    }

    let mut state = State::Offline;

    // Unlike the interval timeout this should not be reset if the
    // select picks a different case.
    let timeout: OptionFuture<_> = None.into();
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                println!("Keepalive cancelled");
                return KeepaliveResult::Cancelled;
            }
            Some(msg) = rx.recv() => {
                match msg {
                    Message::Online  => {
                        if matches!(state, State::Offline) {
                            println!("Starting keepalives");
                            state = State::Waiting;
                        }
                    },
                    Message::OutsideActivity => {
                        // The interval timer is restarted on the next
                        // iteration of the loop. IOW just by taking
                        // this branch of the select we have achieved
                        // the aim of not sending keepalives if there
                        // is active traffic.
                        //
                        // On the other hand the timeout timer is not
                        // restarted, if a ping has been sent then a
                        // pong is required even in the presence of
                        // other outside traffic. This helps to catch
                        // connectivity issues even if traffic is
                        // flowing only in one direction.
                        continue
                    }
                    Message::ReplyReceived => {
                        state = State::Waiting;
                        timeout.as_mut().set(None.into())
                    }
                }
            }

            _ = config.sleep_for_interval(), if matches!(state, State::Waiting | State::Pending) => {
                if let Err(e) = conn.keepalive() {
                    eprintln!("Send Keepalive failed: {e:?}");
                }
                if matches!(state, State::Waiting) && !config.timeout_is_zero() {
                    state = State::Pending;
                    let fut = config.sleep_for_timeout();
                    timeout.as_mut().set(Some(fut).into());
                }
            }

            // Note that `timeout` is `Some` only when state ==
            // `State::Pending` and `config.timeout` is non-zero and
            // evaluates to `None` otherwise.
            Some(_) = timeout.as_mut() => {
                // Return will exit the client
                return KeepaliveResult::Timedout;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use more_asserts::*;
    use std::collections::VecDeque;
    use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex};

    #[derive(Copy, Clone, Debug)]
    enum FixtureEvent {
        Wait,
        Online,
        IntervalExpired,
        ReplyReceived,
        OutsideActivity,
        TimeoutExpired,
    }

    struct FixtureState {
        events: VecDeque<FixtureEvent>,
        sleep_requests: usize,
        keepalive_count: usize,
        done: mpsc::UnboundedSender<()>,
        pending_interval: Option<oneshot::Sender<()>>,
        pending_timeout: Option<oneshot::Sender<()>>,
    }

    impl FixtureState {
        fn sleep_event(&mut self) {
            let Some(ev) = self.events.front() else {
                return;
            };

            // In order to operate in lockstep with the keepalive task
            // we model which timers the keepalive main loop is
            // expected to become armed on each iteration.
            //
            // Most events just expect the interval timer to be
            // created (since it is recreated on every loop).
            //
            // `TimeoutExpired` must follow `IntervalExpired` and in
            // this case both timers are primed, the timeout while
            // handling interval expiration and then interval again on
            // the next iteration of the loop.
            //
            // Note that `tokio::select` always executes the
            // expression of each branch, even if the guard condition
            // is false (it just never polls the resulting future in
            // that case). This is why one timer is expected even for
            // `Online`.
            let required_sleeps = if matches!(ev, FixtureEvent::TimeoutExpired) {
                2
            } else {
                1
            };

            assert_lt!(self.sleep_requests, required_sleeps);

            self.sleep_requests += 1;

            if self.sleep_requests == required_sleeps {
                println!("ev {ev:?} is complete");
                self.sleep_requests = 0;
                self.events.pop_front();
                self.done.send(()).unwrap();
            } else {
                println!("ev {ev:?} still waiting");
            }
        }
    }

    #[derive(Clone)]
    struct Fixture(
        Arc<Mutex<FixtureState>>,
        Arc<TokioMutex<mpsc::UnboundedReceiver<()>>>,
    );

    impl Fixture {
        fn new(value: Vec<FixtureEvent>) -> Self {
            let (tx, rx) = mpsc::unbounded_channel();

            Self(
                Arc::new(Mutex::new(FixtureState {
                    events: value.into(),
                    sleep_requests: 0,
                    keepalive_count: 0,
                    done: tx,
                    pending_interval: None,
                    pending_timeout: None,
                })),
                Arc::new(TokioMutex::new(rx)),
            )
        }

        fn event(&self) -> Option<FixtureEvent> {
            let inner = self.0.lock().unwrap();
            inner.events.front().copied()
        }

        fn keepalive_count(&self) -> usize {
            self.0.lock().unwrap().keepalive_count
        }

        fn interval_expired(&self) {
            println!("Interval expired");
            let mut inner = self.0.lock().unwrap();
            let tx = inner.pending_interval.take().unwrap();
            tx.send(()).unwrap();
        }

        fn timeout_expired(&self) {
            println!("Timeout expired");
            let mut inner = self.0.lock().unwrap();
            let tx = inner.pending_timeout.take().unwrap();
            tx.send(()).unwrap();
        }

        async fn run(&self) -> (Keepalive, OptionFuture<JoinHandle<KeepaliveResult>>) {
            let (keepalive, task) = Keepalive::new(self.clone(), self.clone());

            loop {
                let Some(ev) = self.event() else { break };
                println!("run: wait for tick: {ev:?}");
                self.1.lock().await.recv().await.unwrap();
                println!("run: handle {ev:?}");
                match ev {
                    FixtureEvent::Online => keepalive.online().await,
                    FixtureEvent::IntervalExpired => self.interval_expired(),
                    FixtureEvent::ReplyReceived => keepalive.reply_received().await,
                    FixtureEvent::OutsideActivity => keepalive.outside_activity().await,
                    FixtureEvent::TimeoutExpired => self.timeout_expired(),
                    FixtureEvent::Wait => {}
                }
            }

            (keepalive, task)
        }
    }

    impl SleepManager for Fixture {
        fn interval_is_zero(&self) -> bool {
            println!("interval_is_zero");
            self.0.lock().unwrap().events.is_empty()
        }

        fn timeout_is_zero(&self) -> bool {
            println!("timeout_is_zero");
            !self
                .0
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|ev| matches!(ev, FixtureEvent::TimeoutExpired))
        }

        fn sleep_for_interval(&self) -> futures::future::BoxFuture<()> {
            println!("sleep_for_interval");
            let mut inner = self.0.lock().unwrap();

            inner.sleep_event();

            let (tx, rx) = oneshot::channel();
            inner.pending_interval = Some(tx);
            Box::pin(async move { rx.await.unwrap() })
        }

        fn sleep_for_timeout(&self) -> futures::future::BoxFuture<()> {
            println!("sleep_for_timeout");
            let mut inner = self.0.lock().unwrap();

            inner.sleep_event();

            let (tx, rx) = oneshot::channel();
            inner.pending_timeout = Some(tx);
            Box::pin(async move { rx.await.unwrap() })
        }
    }

    impl Connection for Fixture {
        fn keepalive(&self) -> lightway_core::ConnectionResult<()> {
            println!("Ping!");
            self.0.lock().unwrap().keepalive_count += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn keepalives_can_be_disabled() {
        let fixture = Fixture::new(vec![]);

        let (keepalive, task) = fixture.run().await;

        keepalive.online().await;
        keepalive.outside_activity().await;
        keepalive.reply_received().await;

        assert!(task.await.is_none());

        assert_eq!(0, fixture.keepalive_count());
    }

    #[tokio::test]
    async fn keepalives_are_sent() {
        use FixtureEvent::*;
        let fixture = Fixture::new(vec![Online, IntervalExpired, Wait]);

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(1, fixture.keepalive_count());
    }

    #[tokio::test]
    async fn multiple_keepalives_are_sent_without_reply() {
        use FixtureEvent::*;
        let fixture = Fixture::new(vec![
            Online,
            IntervalExpired,
            IntervalExpired,
            IntervalExpired,
            Wait,
        ]);

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(3, fixture.keepalive_count());
    }

    #[tokio::test]
    async fn multiple_keepalives_are_sent_with_reply() {
        use FixtureEvent::*;
        let fixture = Fixture::new(vec![
            Online,
            IntervalExpired,
            ReplyReceived,
            IntervalExpired,
            ReplyReceived,
            IntervalExpired,
            ReplyReceived,
            Wait,
        ]);

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(3, fixture.keepalive_count());
    }

    #[tokio::test]
    async fn multiple_keepalives_are_sent_before_reply() {
        use FixtureEvent::*;
        let fixture = Fixture::new(vec![
            Online,
            IntervalExpired,
            IntervalExpired,
            IntervalExpired,
            ReplyReceived,
            Wait,
        ]);

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(3, fixture.keepalive_count());
    }

    #[tokio::test]
    async fn timeout_if_no_reply() {
        use FixtureEvent::*;
        let fixture = Fixture::new(vec![Online, IntervalExpired, TimeoutExpired]);

        let (_keepalive, task) = fixture.run().await;

        assert!(matches!(task.await.unwrap(), Ok(KeepaliveResult::Timedout)));

        assert_eq!(1, fixture.keepalive_count());
    }

    #[tokio::test]
    async fn timeout_if_no_reply_even_if_outside_data() {
        use FixtureEvent::*;
        let fixture = Fixture::new(vec![
            Online,
            IntervalExpired,
            OutsideActivity,
            TimeoutExpired,
        ]);

        let (_keepalive, task) = fixture.run().await;

        assert!(matches!(task.await.unwrap(), Ok(KeepaliveResult::Timedout)));

        assert_eq!(1, fixture.keepalive_count());
    }
}
