// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire rules weighed against real traffic rather than argued: what RFC 3550
//! Appendix A.2's remaining condition would cost the RTCP decoder, and what
//! the two DTLS length rules cost the DTLS detector.
//!
//! # The condition that is deliberately not implemented
//!
//! RFC 3550 Appendix A.2's validity routine has one condition
//! [`looks_like_rtcp`] does not apply: *"The length fields of the individual
//! RTCP packets must total to the overall length of the compound packet as
//! received."* sipnab frames only the FIRST sub-packet. Walking the chain and
//! requiring it to land on the datagram length would be a far stronger
//! discriminator — every sub-packet's word count would have to line up, not
//! just the first — and the backlog carried it as an open question for exactly
//! that reason.
//!
//! # What the corpus says
//!
//! It is not a trade-off. It is a false-negative generator, and the traffic it
//! loses is encrypted call control.
//!
//! RFC 3711 leaves an SRTCP packet's first sub-packet header in the clear,
//! encrypts everything after it, and appends a four-byte E-flag/index plus an
//! authentication tag. What lands on the wire is a valid RTCP header over
//! bytes that cannot chain — the exact shape the rule refuses.
//!
//! Measured, on 2026-09-10, across 126 captures holding 4,904,975 UDP
//! datagrams: 11,696 are accepted as RTCP, and requiring the chain to total
//! the datagram loses 67 of them. Sixty-one stop dead after the cleartext
//! first sub-packet, on a port pair whose DTLS-SRTP handshake sits in the same
//! capture. The other six read every sub-packet and leave one to three bytes
//! over, which is a sender's ragged tail rather than a lie about a length.
//! Nothing else in the corpus is refused — the rule's entire effect is to
//! discard encrypted call control.
//!
//! A refused datagram does not vanish. It goes down the RTP path, where a
//! version-2 header and a payload-type byte are enough to register a media
//! stream nobody sent — which is the misclassification the RTCP length check
//! exists to prevent, arrived at from the other side.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips and says so. The corpus is not committed and is assumed to contain
//! PII, so nothing derived from a packet's contents is printed — assertions
//! and diagnostics carry counts and file names only.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};

use sipnab::capture::dtls::is_dtls;
use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::rtp::rtcp::looks_like_rtcp;

/// Files larger than this are skipped: the corpus root can hold archives that
/// are not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[path = "support/corpus.rs"]
mod corpus_support;

/// The corpus root, or `None` when `SIPNAB_CORPUS` is unset.
fn corpus_root() -> Option<PathBuf> {
    corpus_support::root()
}

/// Every regular file at or below `root`, in sorted order.
fn captures(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file()
                && path.metadata().map(|m| m.len()).unwrap_or(0) <= MAX_FILE_BYTES
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Whether every sub-packet length in `data` totals the datagram exactly.
///
/// RFC 3550 Appendix A.2's remaining condition, written out so the corpus can
/// be asked what applying it would cost. Nothing in `src/` calls this — it is
/// the rule under measurement, not a rule in force.
fn lengths_chain_to_the_end(data: &[u8]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        if data.len() - off < 4 {
            return false;
        }
        let words = (usize::from(data[off + 2]) << 8) | usize::from(data[off + 3]);
        let sub = (words + 1) * 4;
        if off + sub > data.len() {
            return false;
        }
        off += sub;
    }
    off == data.len()
}

/// What one capture holds, counted without retaining anything from the wire.
#[derive(Default, Debug)]
struct Counts {
    /// UDP payloads examined.
    datagrams: u64,
    /// Payloads `looks_like_rtcp` accepts.
    rtcp: u64,
    /// Accepted payloads whose sub-packet lengths do NOT total the datagram.
    unchained: u64,
    /// Unchained payloads whose remainder is one unreadable block: the walk
    /// consumes the cleartext first sub-packet and can go no further.
    encrypted_remainder: u64,
    /// Unchained payloads whose sub-packets all read, leaving 1-3 bytes.
    ragged_tail: u64,
    /// Anything that is neither, described by shape and never by content.
    unexplained: Vec<String>,
    /// Payloads `is_dtls` accepts.
    dtls: u64,
    /// Accepted DTLS whose first record does NOT frame inside the datagram.
    dtls_overruns: u64,
    /// Accepted DTLS whose length exceeds what any TLS record may declare.
    dtls_over_ceiling: u64,
}

/// The widest a TLS or DTLS record's length field may legally be.
///
/// RFC 5246 section 6.2.3, which RFC 6347 section 4.1's length field defers to:
/// TLSCiphertext's *"length MUST NOT exceed 2^14 + 2048"*. Written out here
/// rather than imported because this file measures what a rule COSTS, and a
/// measurement that shares the rule's constant cannot notice the constant
/// moving.
const TLS_RECORD_CEILING: usize = (1 << 14) + 2048;

/// Advance `off` by one sub-packet, or report that it cannot.
fn data_step(data: &[u8], off: &mut usize) -> bool {
    if data.len() - *off < 4 {
        return false;
    }
    let words = (usize::from(data[*off + 2]) << 8) | usize::from(data[*off + 3]);
    let sub = (words + 1) * 4;
    if *off + sub > data.len() {
        return false;
    }
    *off += sub;
    true
}

/// Read one capture, classifying every UDP payload it holds.
fn read(path: &Path) -> Option<Counts> {
    let data = std::fs::read(path).ok()?;
    let inflated = decompress_capture(&data).ok()?;
    let reader = PcapReader::new(&inflated).ok()?;

    let mut counts = Counts::default();
    for pkt in reader {
        let ts = chrono::DateTime::from_timestamp(
            pkt.timestamp_secs as i64,
            (u64::from(pkt.timestamp_usecs) * 1000).min(999_999_999) as u32,
        )
        .unwrap_or_default();
        let caplen = pkt.data.len();
        let orig_len = pkt.orig_len as usize;
        let link_type = pkt.link_type as i32;
        let packet = Packet::new(ts, pkt.data, caplen, orig_len, pkt.interface, link_type);
        let Ok(parsed) = parse_packet(&packet) else {
            continue;
        };
        if parsed.transport != sipnab::net::TransportProto::Udp || parsed.payload.is_empty() {
            continue;
        }
        counts.datagrams += 1;
        if is_dtls(&parsed.payload) {
            counts.dtls += 1;
            let declared =
                usize::from(u16::from_be_bytes([parsed.payload[11], parsed.payload[12]]));
            if 13 + declared > parsed.payload.len() {
                counts.dtls_overruns += 1;
            }
            if declared > TLS_RECORD_CEILING {
                counts.dtls_over_ceiling += 1;
            }
        }
        if !looks_like_rtcp(&parsed.payload) {
            continue;
        }
        counts.rtcp += 1;
        if lengths_chain_to_the_end(&parsed.payload) {
            continue;
        }
        counts.unchained += 1;
        let mut off = 0usize;
        let mut steps = 0usize;
        while data_step(&parsed.payload, &mut off) {
            steps += 1;
        }
        let tail = parsed.payload.len() - off;
        if steps == 1 && tail >= 4 {
            // The cleartext header, then a block nothing can walk: SRTCP.
            counts.encrypted_remainder += 1;
        } else if (1..4).contains(&tail) {
            // Whole sub-packets, then bytes too few to be another header.
            counts.ragged_tail += 1;
        } else {
            counts.unexplained.push(format!(
                "{} bytes, {steps} sub-packet(s) read, {tail} left",
                parsed.payload.len()
            ));
        }
    }
    Some(counts)
}

/// The corpus holds RTCP whose lengths cannot chain, and sipnab reads it.
///
/// The finding restated as a test. Two things have to hold together for the
/// decision to stand: the corpus must actually contain the shape, or the test
/// proves nothing, and every instance of it must be the SRTCP trailer rather
/// than arbitrary junk, or the rule would be refusing something worth
/// refusing.
#[test]
fn the_corpus_holds_rtcp_whose_lengths_cannot_chain() {
    let Some(root) = corpus_root() else { return };

    let mut files = 0usize;
    let mut totals = Counts::default();
    let mut files_with_unchained = 0usize;
    for path in captures(&root) {
        let Some(counts) = read(&path) else { continue };
        files += 1;
        totals.datagrams += counts.datagrams;
        totals.rtcp += counts.rtcp;
        totals.unchained += counts.unchained;
        totals.encrypted_remainder += counts.encrypted_remainder;
        totals.ragged_tail += counts.ragged_tail;
        totals.unexplained.extend(counts.unexplained);
        totals.dtls += counts.dtls;
        totals.dtls_overruns += counts.dtls_overruns;
        totals.dtls_over_ceiling += counts.dtls_over_ceiling;
        if counts.unchained > 0 {
            files_with_unchained += 1;
        }
    }

    eprintln!(
        "corpus: {files} captures, {} UDP datagrams, {} accepted as RTCP, \
         {} of those cannot chain -- {} an unreadable remainder after the \
         first sub-packet, {} a ragged tail -- across {files_with_unchained} \
         file(s)",
        totals.datagrams,
        totals.rtcp,
        totals.unchained,
        totals.encrypted_remainder,
        totals.ragged_tail
    );

    assert!(
        files > 0,
        "no capture under SIPNAB_CORPUS could be read, so this test proves nothing"
    );
    assert!(
        totals.rtcp > 0,
        "the corpus at SIPNAB_CORPUS holds no RTCP at all, so this test proves \
         nothing — point it at a corpus that does"
    );
    assert!(
        totals.unchained > 0,
        "the corpus at SIPNAB_CORPUS holds no RTCP whose sub-packet lengths \
         fail to total the datagram, so it cannot say what RFC 3550 A.2's \
         remaining condition would cost. That condition stays unimplemented on \
         the strength of this measurement; a corpus that cannot make it needs \
         SRTCP in it"
    );
    assert!(
        totals.encrypted_remainder > 0,
        "no unchained datagram in the corpus stops after its first sub-packet, \
         which is the SRTCP shape this decision rests on. The corpus cannot \
         support the reasoning any more and it needs re-measuring"
    );
    assert!(
        totals.unexplained.is_empty(),
        "these datagrams cannot chain and are neither an unreadable remainder \
         after the cleartext header nor a ragged tail: {:?}. A.2's rule would \
         refuse them for some third reason, and that reason has to be \
         understood before it can be called a false negative",
        totals.unexplained
    );
    assert_eq!(
        totals.encrypted_remainder + totals.ragged_tail,
        totals.unchained,
        "the two shapes do not account for every unchained datagram"
    );
}

/// The DTLS length rules refuse nothing the corpus holds.
///
/// `is_dtls` applies both since 2026-09-10, and the argument for applying them
/// rests on this: they are free. A `true` from that detector makes the pipeline
/// consume the datagram, so a rule that refused real DTLS would delete packets
/// rather than misfile them. This asserts the corpus can speak to the question
/// at all, and then that neither rule has anything to say about it.
///
/// It reads the rules as the RFCs state them rather than importing the
/// module's constant, so a change to that constant shows up here as a
/// disagreement instead of moving both sides at once.
#[test]
fn the_dtls_length_rules_refuse_nothing_the_corpus_holds() {
    let Some(root) = corpus_root() else { return };

    let mut files = 0usize;
    let mut totals = Counts::default();
    for path in captures(&root) {
        let Some(counts) = read(&path) else { continue };
        files += 1;
        totals.dtls += counts.dtls;
        totals.dtls_overruns += counts.dtls_overruns;
        totals.dtls_over_ceiling += counts.dtls_over_ceiling;
    }

    eprintln!(
        "corpus: {files} captures, {} datagrams accepted as DTLS, {} whose first \
         record overruns the datagram, {} past the TLS record ceiling",
        totals.dtls, totals.dtls_overruns, totals.dtls_over_ceiling
    );

    assert!(
        files > 0,
        "no capture under SIPNAB_CORPUS could be read, so this test proves nothing"
    );
    assert!(
        totals.dtls > 0,
        "the corpus at SIPNAB_CORPUS holds no DTLS at all, so it cannot say what \
         these rules cost — point it at a corpus that does"
    );
    assert_eq!(
        totals.dtls_overruns, 0,
        "{} real DTLS datagram(s) declare a record that does not fit inside \
         them. RFC 6347 4.1.1 forbids that, so either the capture is truncated \
         or the rule is wrong — and `is_dtls` deletes what it refuses, so the \
         answer has to be known rather than assumed",
        totals.dtls_overruns
    );
    assert_eq!(
        totals.dtls_over_ceiling, 0,
        "{} real DTLS datagram(s) declare more than 2^14 + 2048, which no TLS \
         record may. The ceiling was landed on the strength of this being zero",
        totals.dtls_over_ceiling
    );
}

/// The measurement's own rule is the one it claims to be.
///
/// [`lengths_chain_to_the_end`] is written here rather than imported, because
/// it is a rule sipnab does not implement — and a private copy of a rule is
/// how one goes wrong unnoticed. These cases pin it to A.2's wording so the
/// corpus counts above are counting what they say they count.
#[test]
fn the_rule_under_measurement_is_the_one_rfc_3550_states() {
    // One packet filling the datagram: chains.
    assert!(lengths_chain_to_the_end(&[0x80, 201, 0, 1, 0, 0, 0, 1]));
    // Two packets totalling the datagram: chains.
    let mut compound = vec![0x80u8, 201, 0, 1, 0, 0, 0, 1];
    compound.extend_from_slice(&[0x80, 203, 0, 1, 0, 0, 0, 2]);
    assert!(lengths_chain_to_the_end(&compound));
    // The SRTCP shape: a valid first header, then a trailer that cannot chain.
    let mut srtcp = vec![0x80u8, 201, 0, 1, 0, 0, 0, 1];
    srtcp.extend_from_slice(&[0xA5; 20]);
    assert!(
        !lengths_chain_to_the_end(&srtcp),
        "the rule under measurement must refuse the SRTCP shape, or the corpus \
         counts are measuring nothing"
    );
    // A first packet claiming more than the datagram holds: does not chain.
    assert!(!lengths_chain_to_the_end(&[0x80, 200, 0, 6, 0, 0, 0, 1]));
    // A tail too short to hold another header: does not chain.
    let mut ragged = vec![0x80u8, 201, 0, 1, 0, 0, 0, 1];
    ragged.extend_from_slice(&[0, 0]);
    assert!(!lengths_chain_to_the_end(&ragged));
}
