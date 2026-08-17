// SPDX-License-Identifier: MIT OR Apache-2.0

//! How many real messages carry `P-Charging-Vector` — the population behind
//! the two RFC 7315 correlation strategies.
//!
//! # Why this file is a population count and not a correlation test
//!
//! `docs/design/icid-correlation.md` §7 names the failure mode this file
//! exists to make impossible. A corpus test phrased as *"run over the captures
//! and check that icid correlation works"* passes trivially on a corpus in
//! which no capture carries the header at all: nothing correlates, nothing is
//! asserted to correlate, green. It looks like validation and is not, and it
//! is the shape that survives review because the word "corpus" is in the name.
//!
//! So this file asserts the **population**, not the behavior. It answers one
//! question — how many parsed SIP messages carry the header, and how many
//! dialogs — and pins the answer. Two properties follow:
//!
//! * **A zero cannot be mistaken for validation.** When the count is zero the
//!   suite writes a line to the real stderr saying, in those words, that the
//!   charging-vector strategies are exercised by SYNTHETIC unit fixtures only.
//!   `eprintln!` is not used: libtest captures it per test and discards the
//!   buffer when the test passes, which is exactly how this project's previous
//!   corpus notice managed to be emitted and reach nobody
//!   (`tests/support/corpus.rs`).
//! * **A non-zero fails.** The moment a real capture carries the header, this
//!   test goes red and says what to do: promote it from a population probe to
//!   the correlation validation the strategies have never had. A ratchet is
//!   the only way a "we will revisit it when we have data" note survives
//!   contact with a year of commits.
//!
//! # Why the sweep itself cannot go vacuous
//!
//! A count of zero over zero captures is not a measurement. So the sweep also
//! asserts that it read at least one capture and parsed at least one SIP
//! message; without that, deleting the corpus would turn this into a green
//! test that proves nothing, which is the same defect one level down.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips and says so. Nothing derived from a packet is ever printed — the
//! output is counts and file counts, never an address, a Call-ID or an
//! `icid-value`. RFC 7315 §4.6's suggested construction embeds the generating
//! proxy's hostname in the icid, so it is operator-internal by design and this
//! file treats it that way.
#![cfg(feature = "native")]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::pipeline::{MediaDecrypt, PacketAction, PipelineOptions, classify_packet};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::sip::charging_vector::P_CHARGING_VECTOR;

#[path = "support/corpus.rs"]
mod corpus_support;

/// Files larger than this are skipped: the corpus root holds archives that are
/// not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Messages carrying `P-Charging-Vector` across the whole corpus, as measured
/// when the two RFC 7315 strategies were written.
///
/// **Zero, and the zero is the point.** Nothing in any capture available to
/// this project exercises `charging_vector_related_icid` or
/// `charging_vector_icid`; both are proved by synthetic fixtures in
/// `src/sip/charging_vector.rs` and `src/sip/dialog_store.rs` and by nothing
/// else. Raising this number is not a maintenance chore — it means real
/// traffic finally carries the header, and the correct response is to write
/// the correlation validation this pin stands in for.
const EXPECTED_MESSAGES_WITH_HEADER: usize = 0;

/// The corpus root, or `None` when `SIPNAB_CORPUS` is unset.
fn corpus_root() -> Option<PathBuf> {
    corpus_support::root()
}

/// Every regular file under `root`, recursively, in sorted order.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                Ok(t) if t.is_file() => out.push(path),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// What one pass over the corpus measured. Counts only — no packet-derived
/// value is retained, so nothing here can reach a report.
#[derive(Default)]
struct Population {
    /// Captures that yielded at least one SIP message.
    captures_with_sip: usize,
    /// SIP messages parsed, across every capture.
    sip_messages: usize,
    /// SIP messages carrying at least one `P-Charging-Vector` header.
    messages_with_header: usize,
    /// Distinct Call-IDs among those messages. A count, never the values.
    dialogs_with_header: usize,
}

/// Read one capture through the pipeline's own classifier and fold it into
/// `pop`.
///
/// Deliberately `classify_packet` rather than a private reader: a population
/// measured through a different ingestion path than the product uses measures
/// the harness.
fn ingest(path: &Path, pop: &mut Population) {
    let Ok(data) = std::fs::read(path) else {
        return;
    };
    let Ok(inflated) = decompress_capture(&data) else {
        return;
    };
    let Ok(reader) = PcapReader::new(&inflated) else {
        return;
    };

    let mut heuristic = RtpHeuristic::default();
    let opts = PipelineOptions::default();
    let mut call_ids = std::collections::BTreeSet::new();
    let mut sip_here = 0usize;

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
        let mut decrypt = MediaDecrypt::default();
        if let PacketAction::Sip { msg, .. } =
            classify_packet(&parsed, &mut heuristic, &opts, &mut decrypt)
        {
            sip_here += 1;
            if !msg.headers_by_name(P_CHARGING_VECTOR).is_empty() {
                pop.messages_with_header += 1;
                call_ids.insert(msg.call_id().map(str::to_string));
            }
        }
    }

    pop.sip_messages += sip_here;
    pop.dialogs_with_header += call_ids.len();
    if sip_here > 0 {
        pop.captures_with_sip += 1;
    }
}

/// Sweep the corpus once.
fn measure(root: &Path) -> Population {
    let mut pop = Population::default();
    for path in walk(root) {
        let too_big = std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_FILE_BYTES);
        if too_big {
            continue;
        }
        ingest(&path, &mut pop);
    }
    pop
}

/// Say out loud that nothing real exercises the charging-vector strategies.
///
/// Written to the process's real stderr rather than through `eprintln!`,
/// because libtest replaces the print machinery's sink per test and discards
/// the buffer for a test that passes — which is how a notice gets emitted and
/// reaches nobody.
fn announce_synthetic_only(pop: &Population) {
    let _ = writeln!(
        std::io::stderr(),
        "NOTICE: no message in the corpus carries {P_CHARGING_VECTOR} \
         ({} SIP messages across {} captures). The correlation strategies \
         `charging_vector_related_icid` and `charging_vector_icid` are exercised by \
         SYNTHETIC fixtures ONLY; this suite being green is not evidence that they \
         work on real traffic.",
        pop.sip_messages,
        pop.captures_with_sip
    );
}

/// The population, pinned.
///
/// Read the two failure messages: they are the whole design. Zero is expected
/// and is announced rather than passed over; anything else is a demand to
/// write real validation, not a number to bump.
#[test]
fn the_charging_vector_population_is_pinned_and_zero_is_announced() {
    let Some(root) = corpus_root() else {
        return;
    };
    let pop = measure(&root);

    // A count of zero over zero captures is not a measurement. Without this the
    // whole file goes green against an empty directory.
    assert!(
        pop.captures_with_sip > 0 && pop.sip_messages > 0,
        "the sweep read {} SIP messages from {} captures under {}: there was \
         nothing to measure, so the header count below means nothing",
        pop.sip_messages,
        pop.captures_with_sip,
        root.display()
    );

    if pop.messages_with_header == 0 {
        announce_synthetic_only(&pop);
    }

    assert_eq!(
        pop.messages_with_header, EXPECTED_MESSAGES_WITH_HEADER,
        "the corpus now carries {P_CHARGING_VECTOR} on {} message(s) across {} \
         dialog(s), where it carried none when the RFC 7315 strategies were \
         written. This is not a number to bump: it means real traffic can now \
         answer the questions docs/design/icid-correlation.md §8 left open — \
         which legs carry the header, and whether the intermediary forwards the \
         icid, mints a new one, or emits related-icid. Replace this pin with \
         correlation assertions over those captures.",
        pop.messages_with_header, pop.dialogs_with_header
    );
}
