// SPDX-License-Identifier: MIT OR Apache-2.0

//! The thread that asks a relay about a stream nothing explains (RE4).
//!
//! # Why this is a thread and not a call
//!
//! Asking is a UDP round trip with a ceiling measured in seconds. Making it
//! from the packet path would stall capture for as long as the relay stays
//! quiet -- dropped packets traded for an attribution, which is the wrong way
//! round for a tool whose job is to see the traffic. So the capture path only
//! OFFERS a socket, without waiting, and this thread does the asking.
//!
//! # Why it is still not a poller
//!
//! There is no timer here. The loop blocks on the hand-off queue and wakes
//! only when the capture path found a stream nothing explained. When every
//! sink is dropped the queue closes, the loop ends, and the thread reports
//! what it did. A run whose relay holds every stream it sees asks nothing
//! after startup, and a run with no unexplained streams never wakes at all.
//!
//! # What bounds it
//!
//! Three things, none of which depend on how much traffic the capture
//! carries: the reconciler asks about each socket at most once for the run,
//! its transaction ceiling caps the total, and the hand-off queue is bounded
//! so a slow relay cannot grow it. Each of those, when it bites, is COUNTED
//! and reported -- a stream that was never asked about is not a stream the
//! relay disowned.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use parking_lot::RwLock;

use crate::relay::reconcile::{ReadOnlyRelay, Reconciler, Unattributed};
use crate::rtp::stream_store::StreamStore;
use crate::security::transmit_guard::TransmitPermit;

/// Run the reconciler until the hand-off queue closes.
///
/// Applies what each answer teaches to `store` as it is learned, stamped with
/// the moment the relay answered.
///
/// # Arguments
///
/// * `reconciler` — already past its startup snapshot.
/// * `permit` — the run's permission to transmit, which is what makes the
///   two read-only questions reachable at all.
/// * `rx` — the hand-off queue; the loop ends when every sink is dropped.
/// * `store` — the stream store to apply attributions to.
fn run<R: ReadOnlyRelay>(
    mut reconciler: Reconciler<R>,
    permit: &TransmitPermit,
    rx: &Receiver<(IpAddr, u16)>,
    store: &Arc<RwLock<StreamStore>>,
) {
    let relay = reconciler.describe_relay();
    let mut asked = 0_u64;
    let mut attributed = 0_u64;
    // Said ONCE. A relay that is down answers the same way for every socket,
    // and a line per orphan stream would bury the capture's own output.
    let mut reported: Option<String> = None;

    for (address, port) in rx {
        match reconciler.on_unexplained_stream(permit, address, port) {
            Ok(_) => attributed += 1,
            Err(why) => {
                let line = why.describe();
                if reported.as_deref() != Some(line.as_str()) {
                    match why {
                        // A relay saying "not mine" about traffic that is not
                        // its own is the expected answer, not news.
                        Unattributed::RelayDoesNotHoldIt => {}
                        _ => tracing::info!("rtpengine at {relay}: {line}"),
                    }
                    reported = Some(line);
                }
            }
        }
        asked += 1;

        // Only what THIS answer taught, stamped with now: re-applying the
        // whole index would re-date every endpoint the startup snapshot
        // registered and disable the store's staleness bound on all of them.
        let learned = reconciler.take_new_links(chrono::Utc::now());
        if learned.taken_at.is_some() {
            crate::pipeline::apply_relay_snapshot(&mut store.write(), &learned);
        }
    }

    tracing::info!(
        "rtpengine at {relay}: {asked} unexplained stream(s) offered, \
         {attributed} attributed, {} control transaction(s) spent of a \
         ceiling of {}",
        reconciler.transactions(),
        reconciler.budget(),
    );
}

/// Spawn the reconciler thread.
///
/// # Errors
///
/// When the thread cannot be spawned. A run whose reconciler will not start
/// is still worth capturing, so the caller reports and continues rather than
/// exiting.
pub fn spawn<R: ReadOnlyRelay + Send + 'static>(
    reconciler: Reconciler<R>,
    permit: TransmitPermit,
    rx: Receiver<(IpAddr, u16)>,
    store: Arc<RwLock<StreamStore>>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("rtpengine-reconcile".to_owned())
        .spawn(move || run(reconciler, &permit, &rx, &store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureSource;
    use crate::relay::reconcile::orphan_channel;
    use crate::relay::types::{CallView, ControlReply, Enumeration, RelayStream, RelayTag};

    /// A relay holding one call on one socket.
    struct OneCallRelay;

    impl ReadOnlyRelay for OneCallRelay {
        fn list(&self, _permit: &TransmitPermit, _limit: u32) -> anyhow::Result<ControlReply> {
            Ok(ControlReply::Calls(Enumeration {
                call_ids: vec!["mid-call".to_owned()],
                truncated: false,
            }))
        }

        fn query(&self, _permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            Ok(ControlReply::Call(CallView {
                call_id: call_id.to_owned(),
                tags: vec![RelayTag {
                    tag: "from-tag".to_owned(),
                    in_dialogue_with: vec!["to-tag".to_owned()],
                    media_subscriptions: Vec::new(),
                    codec: Some("PCMU".to_owned()),
                    streams: vec![RelayStream {
                        local_address: "10.0.0.2".to_owned(),
                        local_port: 30000,
                        endpoint: None,
                        advertised_endpoint: None,
                        is_rtcp: false,
                        ssrcs: Vec::new(),
                    }],
                }],
            }))
        }

        fn describe(&self) -> String {
            "10.0.0.2:22222".to_owned()
        }
        fn statistics(
            &self,
            _permit: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            // A double, and no test asks it for counters. Refusing is what a
            // relay without statistics support would do, so this is the honest
            // stand-in rather than a fabricated answer.
            anyhow::bail!("this double answers no statistics")
        }
    }

    fn permit() -> TransmitPermit {
        TransmitPermit::for_source(&CaptureSource::Live {
            device: "eth0".to_owned(),
        })
        .expect("a live source grants a permit")
    }

    /// The loop drains the hand-off, asks about the socket, and applies what
    /// it learns to the store the capture path is writing to.
    #[test]
    fn an_offered_socket_becomes_an_attribution_in_the_store() {
        let relay: IpAddr = "10.0.0.2".parse().expect("a literal v4 address parses");
        let store = Arc::new(RwLock::new(StreamStore::new(100)));
        let (sink, rx) = orphan_channel();

        sink.offer(relay, 30000);
        // Dropping every sink is what ends the loop -- no flag, no timeout.
        drop(sink);

        run(Reconciler::new(OneCallRelay), &permit(), &rx, &store);

        let provenance = store
            .read()
            .sdp_endpoint_provenance(relay, 30000)
            .expect("the relay's answer must reach the store");
        assert_eq!(
            provenance.asserted_by,
            crate::rtp::stream_store::EndpointAssertion::media_relay(
                crate::relay::RelayImplementation::Rtpengine,
                crate::relay::ControlDelivery::Encapsulated
            )
        );
        assert_eq!(
            provenance.origin, None,
            "asked for, not captured -- so no capture source to record"
        );
    }

    /// Closing the hand-off is what stops the thread. Nothing polls a flag and
    /// nothing waits out a timeout.
    #[test]
    fn dropping_every_sink_ends_the_loop() {
        let store = Arc::new(RwLock::new(StreamStore::new(100)));
        let (sink, rx) = orphan_channel();
        drop(sink);

        let joined = spawn(Reconciler::new(OneCallRelay), permit(), rx, store)
            .expect("the thread spawns")
            .join();

        assert!(joined.is_ok(), "the loop must end when the queue closes");
    }

    /// A socket offered after the reconciler has stopped is COUNTED. It was
    /// never asked about, which is not the same as the relay disowning it.
    #[test]
    fn a_socket_offered_after_the_queue_closes_is_counted() {
        let (sink, rx) = orphan_channel();
        drop(rx);

        sink.offer("10.0.0.2".parse().expect("valid"), 30000);

        assert_eq!(
            sink.dropped(),
            1,
            "an unofferable socket must be counted, not silently discarded"
        );
    }

    /// A `tracing` writer that keeps every line, so a test can read what the
    /// loop told the operator.
    #[derive(Clone, Default)]
    struct CaptureBuf(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureBuf {
        type Writer = CaptureBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run the loop on this thread over `sockets` and return what it logged.
    ///
    /// The log IS the loop's output: it returns nothing, and the only other
    /// thing it touches is the store, which an unanswered socket leaves alone.
    fn run_logged<R: ReadOnlyRelay>(reconciler: Reconciler<R>, sockets: &[u16]) -> String {
        let store = Arc::new(RwLock::new(StreamStore::new(100)));
        let (sink, rx) = orphan_channel();
        let relay: IpAddr = "10.0.0.2".parse().expect("a literal v4 address parses");
        for port in sockets {
            sink.offer(relay, *port);
        }
        drop(sink);

        let buf = CaptureBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            run(reconciler, &permit(), &rx, &store);
        });
        let bytes = buf.0.lock().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// A relay that attributes nothing: it cannot be reached, or it names
    /// calls it then cannot describe, or it holds no call at all.
    struct UnhelpfulRelay {
        /// Fail every `list` rather than answering it.
        down: bool,
        /// Calls `list` names; every `query` about them fails.
        unreadable: Vec<&'static str>,
    }

    impl ReadOnlyRelay for UnhelpfulRelay {
        fn list(&self, _permit: &TransmitPermit, _limit: u32) -> anyhow::Result<ControlReply> {
            if self.down {
                anyhow::bail!("connection refused");
            }
            Ok(ControlReply::Calls(Enumeration {
                call_ids: self.unreadable.iter().map(|c| (*c).to_owned()).collect(),
                truncated: false,
            }))
        }

        fn query(&self, _permit: &TransmitPermit, _call_id: &str) -> anyhow::Result<ControlReply> {
            anyhow::bail!("relay busy")
        }

        fn describe(&self) -> String {
            "10.0.0.2:22222".to_owned()
        }

        fn statistics(&self, _permit: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("this double answers no statistics")
        }
    }

    /// A relay that is down answers the same way for every socket, so the
    /// loop says so ONCE. A line per orphan stream would bury the capture's
    /// own output under one fact repeated.
    #[test]
    fn a_relay_that_is_down_is_reported_once_not_once_per_stream() {
        let logs = run_logged(
            Reconciler::new(UnhelpfulRelay {
                down: true,
                unreadable: Vec::new(),
            }),
            &[30000, 30002, 30004],
        );
        assert_eq!(
            logs.matches("could not be asked (connection refused)")
                .count(),
            1,
            "one failure, said once: {logs}"
        );
        assert!(
            logs.contains(
                "rtpengine at 10.0.0.2:22222: 3 unexplained stream(s) offered, 0 attributed, \
                 3 control transaction(s) spent of a ceiling of 66"
            ),
            "the closing line reports what the run did: {logs}"
        );
    }

    /// "Not mine" about traffic that is not the relay's is the expected
    /// answer, not news -- but a DIFFERENT reason arriving after it is.
    #[test]
    fn not_mine_is_not_news_but_a_new_reason_after_it_is() {
        let logs = run_logged(
            Reconciler::new(UnhelpfulRelay {
                down: false,
                unreadable: Vec::new(),
            })
            .with_budget(2),
            &[30000, 30002, 30004],
        );
        assert!(
            !logs.contains("does not hold this port"),
            "a relay disowning traffic it does not carry is not reported: {logs}"
        );
        assert_eq!(
            logs.matches("was never asked about").count(),
            1,
            "the ceiling running out on the third socket is new, so it is said: {logs}"
        );
        assert!(
            logs.contains(
                "3 unexplained stream(s) offered, 0 attributed, 2 control transaction(s)"
            ),
            "{logs}"
        );
    }

    /// An answered socket is counted as attributed in the closing line, and
    /// raises no per-socket line at all.
    #[test]
    fn an_attributed_socket_is_counted_in_the_closing_line() {
        let logs = run_logged(Reconciler::new(OneCallRelay), &[30000]);
        assert!(
            logs.contains(
                "rtpengine at 10.0.0.2:22222: 1 unexplained stream(s) offered, 1 attributed, \
                 2 control transaction(s) spent of a ceiling of 66"
            ),
            "{logs}"
        );
        assert_eq!(logs.lines().count(), 1, "nothing else is news: {logs}");
    }

    /// A relay that named a call it then could not describe left a GAP, and
    /// a gap is news -- unlike "not mine" -- so it is said, once.
    #[test]
    fn a_snapshot_with_an_unreadable_call_is_said_once_as_a_gap() {
        let logs = run_logged(
            Reconciler::new(UnhelpfulRelay {
                down: false,
                unreadable: vec!["mid-call"],
            }),
            &[30000, 30002],
        );
        assert_eq!(
            logs.matches("named 1 call(s) that could not be read")
                .count(),
            1,
            "{logs}"
        );
        assert!(
            logs.contains(
                "2 unexplained stream(s) offered, 0 attributed, 4 control transaction(s)"
            ),
            "each refresh retries the unread call rather than writing it off: {logs}"
        );
    }
}
