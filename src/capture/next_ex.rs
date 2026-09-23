// SPDX-License-Identifier: MIT OR Apache-2.0

//! One `pcap_next_ex` read that does not take a success code as proof that a
//! packet arrived.
//!
//! The `pcap` crate's `Capture::next_packet` builds a slice from whatever data
//! pointer `pcap_next_ex` left behind whenever the return code is 1 or more.
//! libpcap's netmap module breaks that contract. `pcap_netmap_dispatch` returns
//! the count `nm_dispatch` reports, and that count includes packets the BPF
//! filter rejected (`pcap_netmap_filter` counts every packet but calls the
//! callback only for the ones that pass). So a rejected packet makes
//! `pcap_next_ex` return 1 with the data pointer still NULL and the header
//! pointer aimed at the PREVIOUS packet's header, caplen included. Copying that
//! "packet" is a `memcpy` of the previous packet's length from address 0.
//!
//! That is NM1: sipnab captured SIP through `netmap:nmv0`, then the first
//! non-SIP frame on the link (an IPv6 router solicitation, a neighbor
//! discovery probe) killed the capture thread with a NULL read in `memcpy`.
//! An idle capture survived only because no packet had ever set a header, so
//! the stale caplen was 0 and the copy moved nothing.
//!
//! [`classify`] is the rule, as a pure function of the return code and the two
//! pointers. [`next_packet`] applies it BEFORE any slice exists and reports an
//! undelivered read as `Ok(None)`.

use std::ffi::c_int;

use pcap::{Packet, PacketHeader};

/// What one `pcap_next_ex` call produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextEx {
    /// A packet was delivered: the header and the data both point at it.
    Packet,
    /// libpcap reported a read but delivered no packet. The netmap module does
    /// this for every packet its BPF filter rejects. The frame is gone, and the
    /// header pointer, if set, describes an older packet.
    Undelivered,
    /// Return code 0: the live read timeout expired with nothing to read.
    Timeout,
    /// Return code -1: libpcap reports an error through `pcap_geterr`.
    Error,
    /// Return code -2: end of a savefile, or `pcap_breakloop` on a live handle.
    End,
}

/// Decide what a `pcap_next_ex` call produced, from its return code and the
/// header and data pointers it left behind.
///
/// Pure, so the rule is testable without a netmap host. The pointers are only
/// compared with null, never read.
///
/// # Arguments
///
/// * `retcode` - what `pcap_next_ex` returned.
/// * `header` - the header pointer after the call.
/// * `data` - the data pointer after the call. The caller must set it to null
///   before the call, or a stale pointer from an earlier read looks delivered.
///
/// # Returns
///
/// The [`NextEx`] outcome. Any return code below -2, which libpcap does not
/// define for `pcap_next_ex`, reads as [`NextEx::Error`].
pub(crate) fn classify(retcode: c_int, header: *const PacketHeader, data: *const u8) -> NextEx {
    match retcode {
        r if r >= 1 && (header.is_null() || data.is_null()) => NextEx::Undelivered,
        r if r >= 1 => NextEx::Packet,
        0 => NextEx::Timeout,
        -2 => NextEx::End,
        _ => NextEx::Error,
    }
}

/// Run one read through `read` and turn it into the `pcap` crate's types,
/// applying [`classify`] before any slice is built.
///
/// # Safety
///
/// Whatever `read` stores in the two out-pointers when it returns 1 or more
/// with both non-null must describe `caplen` readable bytes of packet data and
/// one valid header, and both must stay valid and unmodified for `'a`.
/// `pcap_next_ex` guarantees this until the next call on the same handle,
/// which [`next_packet`] enforces by borrowing the capture for `'a`.
///
/// # Arguments
///
/// * `read` - performs the `pcap_next_ex` call, given the out-pointers.
/// * `error_text` - reads the error message when `read` returns -1.
///
/// # Errors
///
/// `TimeoutExpired` on return code 0, `NoMorePackets` on -2, and `PcapError`
/// with libpcap's message on -1 or any other negative code.
unsafe fn read_with<'a>(
    read: impl FnOnce(&mut *mut PacketHeader, &mut *const u8) -> c_int,
    error_text: impl FnOnce() -> String,
) -> Result<Option<Packet<'a>>, pcap::Error> {
    let mut header: *mut PacketHeader = std::ptr::null_mut();
    let mut data: *const u8 = std::ptr::null();
    let retcode = read(&mut header, &mut data);
    match classify(retcode, header, data) {
        NextEx::Packet => {
            // SAFETY: `classify` returned `Packet`, so both pointers are
            // non-null, and the caller's contract makes them a valid header
            // and `caplen` bytes of data that stay put for `'a`.
            let (header, data) = unsafe {
                let header: &'a PacketHeader = &*header;
                (
                    header,
                    std::slice::from_raw_parts(data, header.caplen as usize),
                )
            };
            Ok(Some(Packet::new(header, data)))
        }
        NextEx::Undelivered => Ok(None),
        NextEx::Timeout => Err(pcap::Error::TimeoutExpired),
        NextEx::End => Err(pcap::Error::NoMorePackets),
        NextEx::Error => Err(pcap::Error::PcapError(error_text())),
    }
}

/// Read the next packet from `cap`, or report that libpcap delivered none.
///
/// A drop-in for `Capture::next_packet` that cannot turn an undelivered read
/// into a copy from address 0. See the module documentation for the netmap
/// behavior this exists for.
///
/// # Arguments
///
/// * `cap` - an activated capture, borrowed for as long as the returned packet
///   lives, because libpcap reuses the buffer on the next read.
///
/// # Returns
///
/// `Ok(Some(packet))` for a delivered packet and `Ok(None)` when libpcap
/// reported a read but delivered nothing (the caller reads again).
///
/// # Errors
///
/// As `Capture::next_packet`: `TimeoutExpired`, `NoMorePackets`, or
/// `PcapError` with libpcap's message.
pub(crate) fn next_packet<T: pcap::Activated + ?Sized>(
    cap: &mut pcap::Capture<T>,
) -> Result<Option<Packet<'_>>, pcap::Error> {
    // The `pcap` crate keeps its bindings private, so these two are declared
    // here against the same library, with no `#[link]` of their own, exactly as
    // `capture::libpcap::running` declares `pcap_lib_version`. The handle is
    // opaque, so it crosses as a void pointer.
    unsafe extern "C" {
        fn pcap_next_ex(
            p: *mut std::ffi::c_void,
            pkt_header: *mut *mut PacketHeader,
            pkt_data: *mut *const u8,
        ) -> c_int;
        fn pcap_geterr(p: *mut std::ffi::c_void) -> *const std::ffi::c_char;
    }
    let handle = cap.as_ptr().cast::<std::ffi::c_void>();
    // SAFETY: `handle` is the live `pcap_t` that `cap` owns, and `cap` stays
    // mutably borrowed for the lifetime of the returned packet, so no other
    // read on this handle can reuse libpcap's buffer while the packet is alive.
    // `pcap::PacketHeader` is `#[repr(C)]` with the same fields as
    // `struct pcap_pkthdr` (the crate casts between the two itself), and
    // `pcap_next_ex` leaves pointers that stay valid until the next call on the
    // handle, which is the contract `read_with` asks for.
    unsafe {
        read_with(
            |header, data| pcap_next_ex(handle, header, data),
            || {
                let msg = pcap_geterr(handle);
                if msg.is_null() {
                    String::from("libpcap reported an error without a message")
                } else {
                    std::ffi::CStr::from_ptr(msg).to_string_lossy().into_owned()
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    //! The netmap wire cannot be driven here. Reproducing NM1 needs the netmap
    //! kernel module loaded, a netmap-capable libpcap (the musl artifacts
    //! embed one, Debian's and the CI runners' do not), and root to put an
    //! interface into netmap mode. So these tests drive the CONVERSION the live
    //! loop performs on each read: the exact pointer and return-code state
    //! libpcap 1.10.6's `pcap_netmap_dispatch` leaves behind for a
    //! filter-rejected packet, measured on the x86_64 OpenSIPS lab VM on
    //! 2026-09-23. The live proof is the lab reproduction recorded in the
    //! CHANGELOG entry.

    use super::*;

    /// A header as `pcap_next_ex` leaves it after a delivered 512-byte frame.
    /// libpcap keeps this in the `pcap_t` and hands back a pointer to it on the
    /// next read whether or not that read delivers anything.
    fn stale_header() -> PacketHeader {
        PacketHeader {
            ts: libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            },
            caplen: 512,
            len: 512,
        }
    }

    /// The NM1 state: return code 1, header pointing at the previous packet's
    /// header, data pointer never written. It must not read as a packet.
    #[test]
    fn a_read_that_delivered_no_data_is_not_a_packet() {
        let header = stale_header();
        assert_eq!(
            classify(1, &header, std::ptr::null()),
            NextEx::Undelivered,
            "pcap_next_ex returned 1 but left the data pointer null: libpcap's \
             netmap module does this for every packet its filter rejects, and \
             copying it reads caplen bytes from address 0"
        );
    }

    /// A null header with a success code is the same defect from the other
    /// side and gets the same answer.
    #[test]
    fn a_read_without_a_header_is_not_a_packet() {
        let byte = 0u8;
        assert_eq!(classify(1, std::ptr::null(), &byte), NextEx::Undelivered);
    }

    #[test]
    fn a_delivered_read_is_a_packet_and_the_other_codes_keep_their_meaning() {
        let header = stale_header();
        let byte = 0u8;
        assert_eq!(classify(1, &header, &byte), NextEx::Packet);
        assert_eq!(
            classify(0, std::ptr::null(), std::ptr::null()),
            NextEx::Timeout
        );
        assert_eq!(
            classify(-1, std::ptr::null(), std::ptr::null()),
            NextEx::Error
        );
        assert_eq!(
            classify(-2, std::ptr::null(), std::ptr::null()),
            NextEx::End
        );
        assert_eq!(
            classify(-3, std::ptr::null(), std::ptr::null()),
            NextEx::Error
        );
    }

    /// The effect, through the reader the live loop calls: a filter-rejected
    /// netmap read comes back as `Ok(None)`, so no slice is ever built over
    /// address 0.
    #[test]
    fn the_reader_reports_an_undelivered_read_instead_of_a_packet() {
        let header = stale_header();
        let header_ptr = &header as *const PacketHeader as *mut PacketHeader;
        // SAFETY: the closure stores only a pointer to `header`, which outlives
        // the call, and leaves the data pointer null. That is the state under
        // test, and `read_with` must not build a slice from it.
        let got = unsafe {
            read_with(
                |h, _data| {
                    *h = header_ptr;
                    1
                },
                || unreachable!("no error was reported"),
            )
        };
        // Deliberately not formatting `got`: were it `Some`, printing it would
        // read the bogus slice and crash the test instead of failing it.
        assert!(
            matches!(got, Ok(None)),
            "a read with no data must be reported as undelivered, not as a \
             {}-byte packet at address 0",
            header.caplen
        );
    }

    /// The reader against a real libpcap handle agrees with the crate's own
    /// `next_packet` on a capture file, byte for byte, then reports the end.
    #[test]
    fn the_reader_matches_the_crates_reads_on_a_real_capture() {
        let path = "tests/pcap-samples/invite-opus-bye.pcap";
        let mut expected = Vec::new();
        let mut cap = pcap::Capture::from_file(path).expect("fixture opens");
        while let Ok(pkt) = cap.next_packet() {
            expected.push((pkt.header.caplen, pkt.data.to_vec()));
        }
        assert!(!expected.is_empty(), "the fixture must hold packets");

        let mut got = Vec::new();
        let mut cap = pcap::Capture::from_file(path).expect("fixture opens");
        let end = loop {
            match next_packet(&mut cap) {
                Ok(Some(pkt)) => got.push((pkt.header.caplen, pkt.data.to_vec())),
                Ok(None) => panic!("a savefile read never comes back undelivered"),
                Err(e) => break e,
            }
        };
        assert_eq!(got, expected);
        assert!(
            matches!(end, pcap::Error::NoMorePackets),
            "a savefile ends with NoMorePackets, got {end:?}"
        );
    }
}
