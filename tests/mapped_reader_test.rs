//! The mapped reader must be indistinguishable from libpcap.
//!
//! `MappedPcap` exists only to remove a copy, so the single thing that must
//! stay true is that removing it changes nothing a user can observe. These
//! tests compare it against libpcap frame for frame rather than against
//! hand-written expectations: a fixture and an assertion built from the same
//! misreading would agree with each other and with nothing else.

#![cfg(feature = "native")]

use sipnab::capture::mapped::MappedPcap;

/// Every frame libpcap reads, the mapping reads identically.
#[test]
fn a_mapped_read_yields_the_same_frames_as_libpcap() {
    for fixture in [
        "tests/fixtures/sip_call.pcap",
        "tests/fixtures/udp_5060.pcap",
    ] {
        let mut cap = pcap::Capture::from_file(fixture).expect("fixture opens");
        let reference_link = cap.get_datalink().0;
        let mut reference = Vec::new();
        while let Ok(pkt) = cap.next_packet() {
            // The casts are redundant on Linux, where both `timeval` fields are
            // already `i64`, and REQUIRED on macOS, where `suseconds_t` is
            // `i32`. clippy only ever sees one target, so it calls them
            // unnecessary; CI builds the other one.
            #[allow(clippy::unnecessary_cast)]
            reference.push((
                pkt.header.ts.tv_sec as i64,
                pkt.header.ts.tv_usec as i64,
                pkt.header.caplen as usize,
                pkt.header.len as usize,
                pkt.data.to_vec(),
            ));
        }
        assert!(!reference.is_empty(), "{fixture} has frames to compare");

        let mut mapped = MappedPcap::open(std::path::Path::new(fixture))
            .expect("fixture opens")
            .unwrap_or_else(|| panic!("{fixture} is a classic pcap and must map"));
        assert_eq!(mapped.link_type(), reference_link, "{fixture} datalink");

        let mut n = 0usize;
        while let Some(frame) = mapped.next_frame() {
            let (sec, usec, caplen, origlen, data) = &reference[n];
            assert_eq!(&frame.data[..], &data[..], "{fixture} frame {n} bytes");
            assert_eq!(frame.caplen, *caplen, "{fixture} frame {n} caplen");
            assert_eq!(frame.origlen, *origlen, "{fixture} frame {n} origlen");
            assert_eq!(
                frame.timestamp.timestamp(),
                *sec,
                "{fixture} frame {n} seconds"
            );
            assert_eq!(
                i64::from(frame.timestamp.timestamp_subsec_micros()),
                *usec,
                "{fixture} frame {n} microseconds"
            );
            n += 1;
        }
        assert_eq!(n, reference.len(), "{fixture} frame count");
    }
}

/// Build a one-record classic pcap by hand, so the record's declared lengths
/// are whatever the caller says rather than whatever a writer would allow.
fn one_record_pcap(snaplen: u32, incl_len: u32, orig_len: u32) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // little-endian, µs
    f.extend_from_slice(&2u16.to_le_bytes()); // version major
    f.extend_from_slice(&4u16.to_le_bytes()); // version minor
    f.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    f.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    f.extend_from_slice(&snaplen.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    f.extend_from_slice(&1_700_000_000u32.to_le_bytes()); // ts_sec
    f.extend_from_slice(&123_456u32.to_le_bytes()); // ts_usec
    f.extend_from_slice(&incl_len.to_le_bytes());
    f.extend_from_slice(&orig_len.to_le_bytes());
    f.extend(std::iter::repeat_n(0xabu8, incl_len as usize));
    f
}

/// A SNAPPED capture must read to the end.
///
/// This is the case the two committed fixtures could not discriminate, because
/// neither is snapped. `orig_len > snaplen` is not corruption — it is the
/// definition of snapping: capture 96 bytes of a 1500-byte frame and the record
/// says `incl_len 96, orig_len 1500`. libpcap reads it; a stricter reader
/// rejects the record and stops, which would silently truncate a user's capture
/// at its first snapped packet while reporting success.
#[test]
fn a_snapped_capture_reads_every_frame_just_as_libpcap_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("snapped.pcap");
    std::fs::write(&path, one_record_pcap(96, 96, 1500)).expect("write");

    // libpcap is the reference: whatever it reads, the mapping must read.
    let mut cap = pcap::Capture::from_file(&path).expect("libpcap opens");
    let mut expected = Vec::new();
    while let Ok(pkt) = cap.next_packet() {
        expected.push((pkt.header.caplen as usize, pkt.header.len as usize));
    }
    assert_eq!(
        expected,
        vec![(96, 1500)],
        "libpcap reads the snapped record"
    );

    let mut mapped = MappedPcap::open(&path)
        .expect("opens")
        .expect("a classic pcap maps");
    let mut got = Vec::new();
    while let Some(f) = mapped.next_frame() {
        got.push((f.caplen, f.origlen));
    }
    assert_eq!(
        got, expected,
        "the mapping dropped a snapped record libpcap read"
    );
}

/// A format the mapping cannot read declines, so the caller falls back to
/// libpcap rather than reading nothing. `None` is the contract, not an error.
#[test]
fn a_format_the_mapping_cannot_read_declines_rather_than_failing() {
    let dir = tempfile::tempdir().expect("tempdir");

    let pcapng = dir.path().join("capture.pcapng");
    // A pcapng Section Header Block: valid capture, wrong container for us.
    std::fs::write(
        &pcapng,
        [
            0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0,
        ],
    )
    .expect("write");
    assert!(
        MappedPcap::open(&pcapng).expect("open succeeds").is_none(),
        "pcapng declines"
    );

    let garbage = dir.path().join("garbage.pcap");
    std::fs::write(&garbage, b"not a capture file at all").expect("write");
    assert!(
        MappedPcap::open(&garbage).expect("open succeeds").is_none(),
        "garbage declines"
    );

    let empty = dir.path().join("empty.pcap");
    std::fs::write(&empty, b"").expect("write");
    assert!(
        MappedPcap::open(&empty).expect("open succeeds").is_none(),
        "an empty file declines"
    );
}

/// A truncated file stops at the last whole frame instead of panicking or
/// inventing one. Capture files are routinely cut off mid-write.
#[test]
fn a_truncated_file_stops_at_the_last_whole_frame() {
    let whole = std::fs::read("tests/fixtures/sip_call.pcap").expect("fixture reads");
    let dir = tempfile::tempdir().expect("tempdir");

    let mut full = MappedPcap::open(std::path::Path::new("tests/fixtures/sip_call.pcap"))
        .expect("opens")
        .expect("maps");
    let mut count = 0usize;
    while full.next_frame().is_some() {
        count += 1;
    }
    assert_eq!(
        full.truncation(),
        None,
        "an intact file must not be reported as truncated"
    );

    // Cut one byte at a time off the tail. Every prefix must terminate, and
    // none may yield more frames than the intact file.
    for cut in 1..=std::cmp::min(64, whole.len() - 24) {
        let path = dir.path().join(format!("cut{cut}.pcap"));
        std::fs::write(&path, &whole[..whole.len() - cut]).expect("write");
        let Some(mut trunc) = MappedPcap::open(&path).expect("open succeeds") else {
            continue;
        };
        let mut got = 0usize;
        while trunc.next_frame().is_some() {
            got += 1;
            assert!(got <= count, "truncated file invented frames at cut {cut}");
        }
        // Losing frames SILENTLY is the failure that matters. libpcap reports a
        // truncated dump, and a capture cut off mid-write is missing the end of
        // whatever it recorded, so a reader that returns fewer frames while
        // reporting a clean read tells the operator their incomplete capture is
        // complete.
        if got < count {
            assert!(
                trunc.truncation().is_some(),
                "cut {cut} dropped {} frame(s) without reporting truncation",
                count - got
            );
        }
    }
}
