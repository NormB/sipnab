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

/// The HEP copy of one INVITE, as a proxy sends it, in a classic pcap.
///
/// The OUTER frame is one Ethernet/IPv4/UDP datagram on loopback,
/// 127.0.0.1:40000 -> 127.0.0.1:9063, stamped `1_700_000_000` seconds. The
/// INNER message, encoded by the production HEP encoder, is the INVITE
/// `call_id` from 10.1.0.1:5060 to 10.2.0.1:5060, stamped `hep_time`. Read
/// without `--hep-parse` the frame holds no SIP at all (its payload starts
/// `HEP3`); unwrapped, it is one dialog with the inner addresses and the HEP
/// time, so a test can tell which of the two a reader used.
#[cfg(feature = "hep")]
pub fn hep_invite_pcap(call_id: &str, hep_time: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    use crate::capture::hep::{HepEndpoint, HepProtocol, build_hep_v3};
    let invite = build_sip_message(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bKhepcopy",
            "Max-Forwards: 70",
            "From: Alice <sip:alice@example.com>;tag=hepcopy",
            "To: <sip:bob@example.com>",
            &format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let inner = HepEndpoint {
        src_addr: [10, 1, 0, 1].into(),
        dst_addr: [10, 2, 0, 1].into(),
        src_port: 5060,
        dst_port: 5060,
        transport: crate::net::TransportProto::Udp,
    };
    let hep = build_hep_v3(&inner, hep_time, HepProtocol::Sip, 1, None, &invite);

    // IPv4 header with its checksum, then UDP (checksum 0 = not computed).
    let udp_len = 8 + hep.len();
    let total_len = 20 + udp_len;
    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00]);
    ip.extend_from_slice(&[127, 0, 0, 1]);
    ip.extend_from_slice(&[127, 0, 0, 1]);
    let mut sum: u32 = ip
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    let mut frame = Vec::with_capacity(14 + total_len);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&40_000u16.to_be_bytes());
    frame.extend_from_slice(&9_063u16.to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&hep);

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
    f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    f.extend_from_slice(&frame);
    f
}

/// Keep one more dispatcher registered for the rest of the process.
///
/// tracing-core registers a call site the first time any thread reaches it,
/// and caches the combined interest of every registered dispatcher. While only
/// one dispatcher is registered it takes a shortcut and asks only the
/// registering thread's own default instead. A test thread with no subscriber
/// answers "never", and the call site then stays silent for every thread
/// until the cache is rebuilt. A capture running at that moment, whose
/// dispatcher was the only one, loses the event: that is how
/// `a_relay_that_is_down_is_reported_once_not_once_per_stream` lost its
/// closing line in CI. Rebuilding once at the start of a capture does not
/// cover a call site first reached after it.
///
/// The shortcut is decided when a dispatcher registers, from how many are
/// registered then. With this one alive, every capture registers as the
/// second or later, so the shortcut is off for as long as any capture runs,
/// and a call site's interest always includes the capture's own answer. A
/// `NoSubscriber` wants nothing, so it records nothing and changes no
/// answer. `capture_logs_sees_a_call_site_another_thread_registered_first`
/// below fails without it.
#[cfg(feature = "native")]
fn keep_the_single_dispatcher_shortcut_off() {
    static KEEP: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    KEEP.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
}

/// Run `f` under a subscriber that records every event at `level` or above,
/// and return what it wrote, without ANSI colors.
///
/// The one place a unit test installs a subscriber
/// (`tests/log_capture_hygiene_test.rs` holds that). `with_default` covers
/// this thread only, while `tracing` caches per call site, for the whole
/// process, whether anyone wants its events. See
/// `keep_the_single_dispatcher_shortcut_off` for how another test thread
/// could leave "nobody" cached and hide an event from this capture. The cache
/// is also rebuilt once this subscriber is in place, which clears a "never"
/// cached before the capture began.
#[cfg(feature = "native")]
pub fn capture_logs(level: tracing::Level, f: impl FnOnce()) -> String {
    keep_the_single_dispatcher_shortcut_off();
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

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::capture_logs;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// The one call site of the event below. Nothing else in the suite
    /// reaches it, so the thread that reaches it first decides its cached
    /// interest.
    fn announce(n: u32) {
        tracing::info!("capture_logs interest probe {n}");
    }

    /// An event is captured even when another thread, with no subscriber of
    /// its own, reached its call site first while the capture was running.
    ///
    /// `tracing` registers a call site the first time any thread reaches it
    /// and caches the combined interest of every live dispatcher. With exactly
    /// one dispatcher alive (this capture's), tracing-core takes a shortcut:
    /// it asks only the REGISTERING thread's default subscriber. A thread with
    /// none answers "never", and the call site then stays silent for every
    /// thread, the capturing one included, until something rebuilds the cache.
    /// Rebuilding once at the start of the capture does not cover a call site
    /// first reached after that. That is how
    /// `a_relay_that_is_down_is_reported_once_not_once_per_stream` lost its
    /// closing line in CI.
    ///
    /// Deterministic when this test runs alone (`cargo test --lib
    /// capture_logs_sees_a_call_site`), where no other dispatcher exists.
    /// Inside the full suite another test's capture may happen to be alive,
    /// which hides the defect, so run it alone to see it fail.
    #[test]
    fn capture_logs_sees_a_call_site_another_thread_registered_first() -> Result<(), TestError> {
        let mut joined = None;
        let logs = capture_logs(tracing::Level::INFO, || {
            joined = Some(std::thread::spawn(|| announce(1)).join());
            announce(2);
        });
        joined
            .ok_or("capture_logs ran the closure")?
            .map_err(|e| format!("the probe thread does not panic: {e:?}"))?;
        assert!(
            logs.contains("capture_logs interest probe 2"),
            "the capturing thread's event was dropped because a thread with \
             no subscriber registered its call site first: {logs:?}"
        );
        Ok(())
    }
}
