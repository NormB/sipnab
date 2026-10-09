// SPDX-License-Identifier: MIT OR Apache-2.0

//! A stop that `shutdown_server` agreed to, carried out once its reply is
//! written.
//!
//! # Why the stop waits for the reply
//!
//! `shutdown_server` stops the process through the same flag SIGTERM sets, and
//! the batch keep-alive loop polls that flag every 100 ms and then exits. The
//! handler used to set it before returning, which is before rmcp had written
//! the reply. Two threads then raced: the transport writing
//! `would_stop: true`, and the main thread leaving the process. On an idle
//! host the write nearly always won. On a loaded one the client read EOF in
//! place of the answer to the call it had just made, which is a client that
//! cannot tell a stop it asked for from a crash.
//!
//! Over stdio the transport is the one place that knows when a reply has been
//! written, so the handler records WHICH request's reply ends the run
//! ([`StopAfterReply::after_reply_to`]), and [`StopAfterReplyTransport`] sets
//! the flag once the send of that reply has completed. Completed means the
//! codec has flushed the bytes into stdout, so a client reading its end of the
//! pipe receives the reply before it reads EOF.
//!
//! # What does not stop
//!
//! A reply rmcp never sends stops nothing. rmcp 3.5's service loop drops the
//! reply to a call the client has canceled (the `Event::ToSink` arm of its
//! `service.rs`), so a cancellation that lands after the handler decided
//! stops nothing. The client withdrew the request, so the
//! process keeps running, and no client was ever told `would_stop: true` by a
//! process that then kept running. A client that stops reading stdout holds
//! the reply, and so the stop, until it reads or closes stdin; closing stdin
//! ends the process through `mcp_stdio_done` either way.
//!
//! The HTTP transport does not use this. A server built without a
//! [`StopAfterReply`] stops at once, as it always did.

use std::future::Future;
use std::sync::Arc;

use rmcp::RoleServer;
use rmcp::model::{RequestId, ServerJsonRpcMessage};
use rmcp::service::RxJsonRpcMessage;
use rmcp::transport::Transport;

/// The action that stops the process, shared by the handle and the transport.
type StopFn = Arc<dyn Fn() + Send + Sync>;

/// The request whose reply ends the run, and what ending it does.
///
/// Cloned into the server (which records the request) and into the transport
/// (which acts on it). Both clones share one slot.
#[derive(Clone)]
pub struct StopAfterReply {
    /// The id of the call whose reply is the last thing this process must
    /// write, once a stop has been agreed to.
    pending: Arc<parking_lot::Mutex<Option<RequestId>>>,
    /// Sets the shutdown flag. `crate::signals::request_shutdown` in the
    /// binary; a counter in the tests below, so they do not stop the test
    /// process's own loops.
    stop: StopFn,
}

impl std::fmt::Debug for StopAfterReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StopAfterReply")
            .field("pending", &*self.pending.lock())
            .finish_non_exhaustive()
    }
}

impl StopAfterReply {
    /// A handle that runs `stop` once the recorded reply has been written.
    pub fn new(stop: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            pending: Arc::new(parking_lot::Mutex::new(None)),
            stop: Arc::new(stop),
        }
    }

    /// Stop the process once the reply to request `id` has been written.
    pub fn after_reply_to(&self, id: RequestId) {
        *self.pending.lock() = Some(id);
    }

    /// Whether `msg` is the reply the pending stop waits for. Takes the
    /// pending id when it is, so the stop runs once.
    ///
    /// An error reply counts: it is still the last answer the client gets to
    /// that call.
    fn take_if_reply_to(&self, msg: &ServerJsonRpcMessage) -> bool {
        let id = match msg {
            rmcp::model::JsonRpcMessage::Response(r) => Some(&r.id),
            rmcp::model::JsonRpcMessage::Error(e) => e.id.as_ref(),
            _ => None,
        };
        let mut pending = self.pending.lock();
        if id.is_some() && pending.as_ref() == id {
            *pending = None;
            true
        } else {
            false
        }
    }
}

/// A server transport that carries out a [`StopAfterReply`] once the reply it
/// waits for has been sent.
pub struct StopAfterReplyTransport<T> {
    /// The transport that does the reading and writing.
    inner: T,
    /// Shared with the server, which records the request.
    stop: StopAfterReply,
}

impl<T> StopAfterReplyTransport<T> {
    /// Wrap `inner`, acting on the request `stop` records.
    pub fn new(inner: T, stop: StopAfterReply) -> Self {
        Self { inner, stop }
    }
}

impl<T> Transport<RoleServer> for StopAfterReplyTransport<T>
where
    T: Transport<RoleServer>,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        // Decided now, while the message is in hand; acted on only after the
        // send completes. A send that FAILED still stops: the stop was agreed
        // to, and a reply that cannot be written means the client is gone.
        let stop_after = self
            .stop
            .take_if_reply_to(&item)
            .then(|| Arc::clone(&self.stop.stop));
        let send = self.inner.send(item);
        async move {
            let result = send.await;
            if let Some(stop) = stop_after {
                stop();
            }
            result
        }
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleServer>>> + Send {
        self.inner.receive()
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{ErrorData, JsonRpcMessage, ServerResult};
    use std::sync::atomic::{AtomicUsize, Ordering};

    type TestError = Box<dyn std::error::Error>;

    /// A transport whose sends finish only when the test says so, and which
    /// fails them on request.
    struct HeldTransport {
        /// Each send waits for one permit.
        release: Arc<tokio::sync::Semaphore>,
        /// Whether sends report failure once released.
        fail: bool,
    }

    impl Transport<RoleServer> for HeldTransport {
        type Error = std::io::Error;

        fn send(
            &mut self,
            _item: ServerJsonRpcMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            let release = Arc::clone(&self.release);
            let fail = self.fail;
            async move {
                release
                    .acquire()
                    .await
                    .map_err(std::io::Error::other)?
                    .forget();
                if fail {
                    Err(std::io::Error::other("the client is gone"))
                } else {
                    Ok(())
                }
            }
        }

        async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
            None
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// A handle whose stop counts instead of stopping, and the count.
    fn counting() -> (StopAfterReply, Arc<AtomicUsize>) {
        let stops = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&stops);
        let handle = StopAfterReply::new(move || {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        (handle, stops)
    }

    fn wrapped(
        stop: &StopAfterReply,
        fail: bool,
    ) -> (
        StopAfterReplyTransport<HeldTransport>,
        Arc<tokio::sync::Semaphore>,
    ) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let inner = HeldTransport {
            release: Arc::clone(&release),
            fail,
        };
        (StopAfterReplyTransport::new(inner, stop.clone()), release)
    }

    fn reply(id: i64) -> ServerJsonRpcMessage {
        JsonRpcMessage::response(ServerResult::empty(()), RequestId::Number(id))
    }

    fn error_reply(id: i64) -> ServerJsonRpcMessage {
        JsonRpcMessage::error(
            ErrorData::internal_error("refused", None),
            Some(RequestId::Number(id)),
        )
    }

    /// Recording the stop stops nothing; the reply's send completing does.
    ///
    /// The defect this module exists for: the flag was set while the reply
    /// was still unwritten.
    #[tokio::test]
    async fn the_stop_waits_for_its_reply_to_be_written() -> Result<(), TestError> {
        let (stop, stops) = counting();
        let (mut transport, release) = wrapped(&stop, false);

        stop.after_reply_to(RequestId::Number(7));
        assert_eq!(stops.load(Ordering::SeqCst), 0, "stopped before any reply");

        let send = tokio::spawn(transport.send(reply(7)));
        tokio::task::yield_now().await;
        assert_eq!(
            stops.load(Ordering::SeqCst),
            0,
            "stopped while the reply was still being written"
        );

        release.add_permits(1);
        send.await??;
        assert_eq!(
            stops.load(Ordering::SeqCst),
            1,
            "the written reply did not stop"
        );
        Ok(())
    }

    /// Another call's reply is not the one the stop waits for.
    ///
    /// Calls run concurrently, so the reply written next is not necessarily
    /// the shutdown's.
    #[tokio::test]
    async fn only_the_named_reply_stops() -> Result<(), TestError> {
        let (stop, stops) = counting();
        let (mut transport, release) = wrapped(&stop, false);
        stop.after_reply_to(RequestId::Number(7));

        release.add_permits(2);
        transport.send(reply(6)).await?;
        assert_eq!(stops.load(Ordering::SeqCst), 0, "a different reply stopped");
        transport.send(reply(7)).await?;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    /// The stop runs once, however many times that id is answered.
    #[tokio::test]
    async fn the_stop_runs_once() -> Result<(), TestError> {
        let (stop, stops) = counting();
        let (mut transport, release) = wrapped(&stop, false);
        stop.after_reply_to(RequestId::Number(7));

        release.add_permits(2);
        transport.send(reply(7)).await?;
        transport.send(reply(7)).await?;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    /// An error reply to the named call still ends the run.
    #[tokio::test]
    async fn an_error_reply_to_the_named_call_stops() -> Result<(), TestError> {
        let (stop, stops) = counting();
        let (mut transport, release) = wrapped(&stop, false);
        stop.after_reply_to(RequestId::Number(7));

        release.add_permits(1);
        transport.send(error_reply(7)).await?;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    /// A reply that cannot be written still stops: the stop was agreed to,
    /// and the client that would have read the reply is gone.
    #[tokio::test]
    async fn a_failed_write_still_stops() -> Result<(), TestError> {
        let (stop, stops) = counting();
        let (mut transport, release) = wrapped(&stop, true);
        stop.after_reply_to(RequestId::Number(7));

        release.add_permits(1);
        assert!(
            transport.send(reply(7)).await.is_err(),
            "the fake must fail"
        );
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    /// Nothing stops when no stop was recorded.
    #[tokio::test]
    async fn no_recorded_stop_stops_nothing() -> Result<(), TestError> {
        let (stop, stops) = counting();
        let (mut transport, release) = wrapped(&stop, false);

        release.add_permits(1);
        transport.send(reply(7)).await?;
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
