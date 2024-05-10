//! Forward state change notifications to a stream

use lightway_core::{State, StateChangeCallback};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Helper to propagate state change events into an async
/// stream. Pass this type to `with_state_change_cb`.
pub struct StateStreamCallback(mpsc::Sender<State>);

/// A stream of [`State`].
pub type StateStream = ReceiverStream<State>;

impl StateStreamCallback {
    /// Construct a new `StateStreamCallback` and the correspondining
    /// `StateStream`.
    pub fn new() -> (Self, StateStream) {
        let (send, recv) = mpsc::channel(1);

        (Self(send), StateStream::new(recv))
    }
}

impl StateChangeCallback for StateStreamCallback {
    fn state_change(&self, state: State) {
        let sender = self.0.clone();
        tokio::spawn(async move {
            sender.send(state).await.unwrap();
        });
    }
}
