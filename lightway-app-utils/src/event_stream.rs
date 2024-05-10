//! Forward event notifications to a channel

use lightway_core::{Event, EventCallback};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Helper to propagate events into an async stream. Pass this type to
/// `with_event_cb`.
pub struct EventStreamCallback(mpsc::Sender<Event>);

/// A stream of [`Event`].
pub type EventStream = ReceiverStream<Event>;

impl EventStreamCallback {
    /// Construct a new `EventStreamChannel` and the correspondining
    /// `EventStreamCallback`.
    pub fn new() -> (Self, EventStream) {
        let (send, recv) = mpsc::channel(1);

        (Self(send), EventStream::new(recv))
    }
}

impl EventCallback for EventStreamCallback {
    fn event(&self, event: Event) {
        let sender = self.0.clone();
        tokio::spawn(async move {
            sender.send(event).await.unwrap();
        });
    }
}
