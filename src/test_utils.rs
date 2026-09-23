// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared helpers for the test suite: fixtures and builders.
//!
//! Shared across modules, and only compiled in test builds.

/// Build raw SIP bytes from a request/status line, header lines, and an optional body.
///
/// Each header line gets `\r\n` appended; the blank line separator between
/// headers and body is added automatically.
pub fn build_sip_message(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(first_line.as_bytes());
    msg.extend_from_slice(b"\r\n");
    for h in headers {
        msg.extend_from_slice(h.as_bytes());
        msg.extend_from_slice(b"\r\n");
    }
    msg.extend_from_slice(b"\r\n");
    msg.extend_from_slice(body);
    msg
}

/// A classic little-endian Ethernet pcap holding one record that captured
/// `caplen` of the `origlen` bytes that crossed the wire -- a snapped frame
/// when `caplen` is the smaller -- filled with `0xAB`.
///
/// Built by hand so the record's two lengths are whatever the caller says:
/// every writer in the tree stamps both from the bytes it is handed, so none of
/// them can produce the frame a snaplen does.
pub fn one_record_pcap(caplen: u32, origlen: u32) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // microsecond magic
    f.extend_from_slice(&2u16.to_le_bytes()); // version major
    f.extend_from_slice(&4u16.to_le_bytes()); // version minor
    f.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    f.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    f.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
    f.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    f.extend_from_slice(&1_700_000_000u32.to_le_bytes()); // ts_sec
    f.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    f.extend_from_slice(&caplen.to_le_bytes());
    f.extend_from_slice(&origlen.to_le_bytes());
    f.extend(std::iter::repeat_n(0xabu8, caplen as usize));
    f
}

/// Run `f` under a subscriber that records every event at `level` or above,
/// and return what it wrote, without ANSI colors.
///
/// The one place a unit test installs a subscriber
/// (`tests/log_capture_hygiene_test.rs` holds that). `with_default` covers
/// this thread only, while `tracing` caches per call site, for the whole
/// process, whether anyone wants its events. A test thread running with no
/// subscriber can reach a call site first and leave "nobody" cached, and
/// then this capture misses the event. So the cache is rebuilt once this
/// subscriber is in place.
#[cfg(feature = "native")]
pub fn capture_logs(level: tracing::Level, f: impl FnOnce()) -> String {
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        f();
    });
    let bytes = buf.0.lock().clone();
    String::from_utf8_lossy(&bytes).into_owned()
}
