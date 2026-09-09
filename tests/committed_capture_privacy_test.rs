// SPDX-License-Identifier: MIT OR Apache-2.0

//! No committed capture may carry a real subscriber's identity.
//!
//! Five LTE captures entered the private corpus on 2026-09-06 and are the
//! reason a GTPv2-C control message reported as an RTP stream with a confident
//! `mos: 1.0` was ever found. They stay private for two independent reasons,
//! either sufficient on its own: the source page states no license at all, and
//! absence of terms is "all rights reserved" rather than permission; and they
//! carry a real IMEI in a `+sip.instance` URN together with an IMSI-derived
//! subscriber identity.
//!
//! That decision was written in the backlog and enforced by nothing. A backlog
//! entry does not survive a `git add`, and the whole risk is a capture landing
//! in `tests/pcap-samples/` because somebody was moving fast — at which point
//! it is in the history of a public repository permanently.
//!
//! So the rule is a gate, and it is keyed on what a capture CONTAINS rather
//! than on the five filenames. A denylist of names is exactly the wrong shape:
//! it passes the sixth capture, and the sixth capture is the one nobody
//! thought about.
//!
//! **What this does not check.** Two of those five hold roughly 19 MB of one
//! person's DNS queries and TLS SNI, which is as disqualifying as the IMEI and
//! has no crisp byte pattern — a fixture may legitimately carry DNS. That half
//! stays a human decision, recorded in the backlog under LIVE4, and this file
//! deliberately does not pretend to cover it.

use std::path::{Path, PathBuf};

#[path = "support/corpus.rs"]
mod corpus_support;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Byte patterns that mean a real subscriber, and why each one does.
///
/// Both are ASCII and appear in SIP headers inside the capture, so the scan
/// needs no pcap parser and has no file it cannot read. That matters more than
/// it sounds: a scan built on a parser reports the same clean answer for a file
/// it found nothing in and a file it could not open.
const SUBSCRIBER_IDENTIFIERS: &[(&str, &str)] = &[
    (
        "urn:gsma:imei",
        "an IMEI in a +sip.instance URN (GSMA PRD TS.06 / RFC 5626 instance-id) \
         is the permanent serial number of one physical handset",
    ),
    (
        "3gppnetwork.org",
        "the IMS home-network domain is derived from a subscriber's IMSI \
         (3GPP TS 23.003 s13.2), so the identity in front of it is a person's \
         SIM and not a lab account",
    ),
];

/// Committed capture files, wherever they live.
///
/// The whole repository, not `tests/`. Four captures ship from outside it —
/// one fuzz seed, two SIPp media files and the sample the browser analyzer
/// loads — and the sample on the website is the one that reaches the most
/// people. A walk scoped to `tests/` would have passed every one of them.
///
/// `target/` and `.git/` are skipped: the first is build output that mirrors
/// what is already checked, and walking a packed object store byte by byte
/// would cost minutes and find the same files a second time.
fn committed_captures() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                if !matches!(
                    p.file_name().and_then(|n| n.to_str()),
                    Some("target" | ".git" | "node_modules")
                ) {
                    stack.push(p);
                }
            } else if p.extension().is_some_and(|x| {
                let x = x.to_string_lossy().to_ascii_lowercase();
                x == "pcap" || x == "pcapng" || x == "cap" || x == "gz"
            }) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Every pattern this file finds in `bytes`, case-insensitively.
///
/// Case-insensitive because a SIP header value is not required to preserve the
/// case a specification wrote it in, and `URN:GSMA:IMEI` is the same
/// disclosure as the lowercase form.
fn identifiers_in(bytes: &[u8]) -> Vec<&'static str> {
    SUBSCRIBER_IDENTIFIERS
        .iter()
        .filter(|(needle, _)| contains(bytes, needle.as_bytes()))
        .map(|(needle, _)| *needle)
        .collect()
}

/// Naive case-insensitive substring search over bytes.
///
/// No regex, no parser, and deliberately no lowercased COPY of the haystack:
/// the first draft allocated one, and over 8.8 GB of corpus that turned a scan
/// grep does in a second into six minutes on a gate people run before every
/// push. `eq_ignore_ascii_case` compares in place.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// The patterns a file carries, read in bounded chunks.
///
/// Streamed rather than slurped so one large capture cannot decide how much
/// memory the gate needs. Chunks overlap by `needle - 1` bytes, or a match
/// lying across a boundary would be invisible — which is the classic way a
/// chunked scanner reports a clean file.
fn identifiers_in_file(path: &Path) -> std::io::Result<Vec<&'static str>> {
    use std::io::Read as _;

    let longest = SUBSCRIBER_IDENTIFIERS
        .iter()
        .map(|(n, _)| n.len())
        .max()
        .unwrap_or(1);
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut carry: Vec<u8> = Vec::with_capacity(longest);
    let mut found: Vec<&'static str> = Vec::new();
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut window = carry.clone();
        window.extend_from_slice(&buf[..n]);
        for id in identifiers_in(&window) {
            if !found.contains(&id) {
                found.push(id);
            }
        }
        if found.len() == SUBSCRIBER_IDENTIFIERS.len() {
            break;
        }
        let keep = window.len().saturating_sub(longest.saturating_sub(1));
        carry = window[keep..].to_vec();
    }
    Ok(found)
}

/// A path as the repository writes it, for a message somebody has to act on.
fn rel(p: &Path) -> String {
    p.strip_prefix(repo())
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

/// No file this repository ships carries either identifier.
#[test]
fn no_committed_capture_carries_a_subscriber_identifier() {
    let captures = committed_captures();
    let mut offenders: Vec<String> = Vec::new();
    for p in &captures {
        let Ok(found_ids) = identifiers_in_file(p) else {
            continue;
        };
        for found in found_ids {
            let why = SUBSCRIBER_IDENTIFIERS
                .iter()
                .find(|(n, _)| *n == found)
                .map(|(_, w)| *w)
                .unwrap_or("");
            offenders.push(format!("  {}: {found} — {why}", rel(p)));
        }
    }
    assert!(
        offenders.is_empty(),
        "a committed capture carries a real subscriber's identity. Once this \\
         is in the history of a public repository it stays there.\\n{}\\n\\nPut \\
         the capture under SIPNAB_CORPUS, where the corpus gates read it and \\
         nothing publishes it, or redact it before committing.",
        offenders.join("\n")
    );
}

/// The scan examined the captures it claims to.
///
/// A scan that matched nothing is indistinguishable from one whose walk
/// stopped finding files, and this file already asserts an absence — the one
/// shape where a broken instrument and a clean result look identical.
#[test]
fn the_scan_examined_the_captures_it_claims_to() {
    let captures = committed_captures();
    assert!(
        captures.len() >= 45,
        "found only {} committed capture(s); the walk has stopped matching and \\
         the absence above would be an absence of looking",
        captures.len()
    );
    // And it can actually read them, which is a separate claim from finding them.
    let readable = captures
        .iter()
        .filter(|p| identifiers_in_file(p).is_ok())
        .count();
    assert_eq!(
        readable,
        captures.len(),
        "{} capture(s) were found and could not be read; a file the scan never \\
         opened reports the same clean answer as one it read",
        captures.len() - readable
    );
}

/// Every pattern fires on material that carries it.
///
/// The mandatory positive control. A needle with a typo in it finds nothing and
/// passes forever, which is the failure mode of every absence-asserting gate
/// this repository has had to fix.
#[test]
fn each_pattern_fires_on_material_that_carries_it() {
    for (needle, why) in SUBSCRIBER_IDENTIFIERS {
        assert!(
            !why.trim().is_empty(),
            "{needle} is refused with no reason; a reader meeting this gate \\
             has to be told what the pattern means, not only that it matched"
        );
        // Built rather than written out, so the fixture cannot drift from the
        // constant it is supposed to exercise.
        let synthetic = format!("Contact: <sip:a@b>;+sip.instance=\"<{needle}:x>\"");
        let found = identifiers_in(synthetic.as_bytes());
        assert!(
            found.contains(needle),
            "the scan did not find {needle} in material built from it"
        );
        // And the same material in the case a header might actually carry.
        let upper = synthetic.to_ascii_uppercase();
        assert!(
            identifiers_in(upper.as_bytes()).contains(needle),
            "{needle} escaped detection in upper case; a SIP header value is \\
             not required to preserve the case a specification wrote"
        );
    }
}

/// One header line per pattern, written out by hand from the specification.
///
/// Owed, for a mutation that survived: mistyping `urn:gsma:imei` as
/// `urn:gsma:imie` changed no assertion, because the positive control below it
/// BUILT its fixture by interpolating the constant. A test that constructs its
/// input from the thing under test agrees with any typo, and the other pattern
/// still matched in the corpus, so one of the two needles could have been dead
/// with everything green.
///
/// Every value here is from a reserved test range. MCC 001 is the test mobile
/// country code (ITU-T E.212), and the IMEI is the all-zero body no allocated
/// Type Allocation Code uses — so this file carries the SHAPE of a subscriber
/// identifier and nobody's actual one, which is the whole point of the gate it
/// exercises.
const WIRE_EXAMPLES: &[(&str, &str)] = &[
    (
        "urn:gsma:imei",
        "Contact: <sip:u@10.0.0.1>;+sip.instance=\"<urn:gsma:imei:00000000-000000-0>\"",
    ),
    (
        "3gppnetwork.org",
        // No local part before the host, deliberately. `g1_no_address_reaches_a_real_mailbox`
        // refuses any `user@domain` at a domain somebody owns, and 3GPP owns
        // this one — so a realistic-looking IMSI in front of it would be an
        // address in this tree that could reach a real operator's network.
        // The pattern is about the HOST, and the host is what this exercises.
        "From: <sip:ims.mnc001.mcc001.3gppnetwork.org>;tag=a1b2",
    ),
];

/// Every pattern fires on a header line nobody derived from it.
#[test]
fn each_pattern_matches_a_literal_example_written_out_by_hand() {
    for (needle, line) in WIRE_EXAMPLES {
        assert!(
            identifiers_in(line.as_bytes()).contains(needle),
            "{needle} did not match the header line it was written for, so the \
             pattern and the wire have parted company:\n  {line}"
        );
    }
}

/// Every pattern HAS a hand-written example.
///
/// Owed alongside the test above, and the half that keeps it honest. Without
/// this, a third pattern could be added with no independent example and the
/// self-referential control would be back for that one alone.
#[test]
fn every_pattern_has_a_literal_example() {
    for (needle, _) in SUBSCRIBER_IDENTIFIERS {
        assert!(
            WIRE_EXAMPLES.iter().any(|(n, _)| n == needle),
            "{needle} is refused with no hand-written example of what it \
             refuses. Add one to WIRE_EXAMPLES, taken from the specification \
             rather than from the constant."
        );
    }
    // And no example describes a pattern nothing enforces.
    for (needle, _) in WIRE_EXAMPLES {
        assert!(
            SUBSCRIBER_IDENTIFIERS.iter().any(|(n, _)| n == needle),
            "{needle} has an example and is not in SUBSCRIBER_IDENTIFIERS, so \
             the example exercises nothing"
        );
    }
}

/// A match lying across a chunk boundary is still found.
///
/// The classic way a chunked scanner reports a clean file. The reader works in
/// 1 MiB blocks and carries `needle - 1` bytes forward; without that carry a
/// pattern straddling the boundary is invisible, and the file it is in passes.
/// Driven against a real file rather than the in-memory helper, because the
/// carry lives in the reader and the helper never sees a boundary.
#[test]
fn a_match_across_a_chunk_boundary_is_still_found() {
    let (needle, _) = SUBSCRIBER_IDENTIFIERS[0];
    let dir = std::env::temp_dir().join(format!(
        "sipnab-boundary-{}-{}",
        std::process::id(),
        needle.len()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("straddle.pcap");

    // Place the needle so it starts one byte before the 1 MiB block ends and
    // finishes after it. Computed from the constant rather than written down,
    // so changing the block size or the pattern cannot leave the fixture
    // sitting comfortably inside one chunk.
    const BLOCK: usize = 1 << 20;
    let mut bytes = vec![b'.'; BLOCK + needle.len()];
    let at = BLOCK - 1;
    bytes[at..at + needle.len()].copy_from_slice(needle.as_bytes());
    assert!(
        at < BLOCK && at + needle.len() > BLOCK,
        "the fixture must straddle the boundary or it proves nothing"
    );
    std::fs::write(&path, &bytes).expect("write fixture");

    let found = identifiers_in_file(&path).expect("read fixture");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        found.contains(&needle),
        "{needle} straddling a chunk boundary escaped the scan, which is how a \
         chunked reader reports a clean file it never really read"
    );
}

/// Ordinary fixture material does not trip the gate.
///
/// The paired half. A pattern broad enough to catch everything catches every
/// fixture, and a gate that fires on its own repository gets disabled.
#[test]
fn ordinary_sip_material_does_not_trip_the_gate() {
    for benign in [
        // RFC 5626 instance-id as a UUID, which is the common form and is not
        // a device serial number.
        "Contact: <sip:a@b>;+sip.instance=\"<urn:uuid:0c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f>\"",
        "From: <sip:alice@example.com>;tag=1928301774",
        "P-Asserted-Identity: <sip:+15551234567@carrier.example>",
    ] {
        assert!(
            identifiers_in(benign.as_bytes()).is_empty(),
            "the gate fires on ordinary material: {benign}"
        );
    }
}

/// The private corpus is why this gate exists, and it proves the patterns
/// describe real traffic rather than a hypothetical.
///
/// Skipped, loudly, when `SIPNAB_CORPUS` is unset — the corpus is not
/// committed and cannot be. When it is set, at least one file must trip the
/// scan: if none does, either the corpus no longer holds the captures this
/// gate was written for, or the patterns have stopped describing them.
#[test]
fn the_corpus_holds_what_this_gate_refuses() {
    // Through the shared helper, never `std::env::var` here: the skip has to
    // be ANNOUNCED, and a binary that reads the variable itself skips silently
    // — which is how nine corpus binaries once reported `ok` while proving
    // nothing. `corpus_skip_notice_test` fails on a direct read.
    let Some(dir) = corpus_support::root() else {
        return;
    };
    // Collect first, then read SMALLEST FIRST. One hit is the whole claim, so
    // the cheapest evidence should be reached first: `read_dir` order put a
    // multi-gigabyte capture ahead of the 19 MB one that actually carries the
    // identifiers, and the control cost a minute on a gate people run before
    // every push.
    let mut files: Vec<(u64, PathBuf)> = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let size = e.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
                files.push((size, p));
            }
        }
    }
    files.sort();
    for (_, p) in &files {
        if identifiers_in_file(p).is_ok_and(|f| !f.is_empty()) {
            // One is the whole claim: the patterns describe real traffic.
            // Reading the rest of an 8.8 GB corpus to count more would make
            // this the most expensive test in the suite and prove nothing
            // further.
            return;
        }
    }
    panic!(
        "no capture under SIPNAB_CORPUS carries either identifier. The five \
         LTE captures added on 2026-09-06 do, and they are what this gate was \
         written against — so either they are gone or the patterns no longer \
         match them, and in both cases the gate above is now guarding against \
         a shape nobody has seen."
    );
}
