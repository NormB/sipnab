// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every committed capture is public or synthetic, and says which.
//!
//! The rule is Norm's, from 2026-09-22: the local corpus of real captures is
//! never pushed, and a capture that is pushed is either public, with a source
//! anyone can check, or synthetic, with the generator that makes it. Until
//! then two committed fixtures were live captures from a lab network and a fuzz
//! seed was a copy of a third-party capture, and nothing noticed, because
//! nothing asked where a capture came from unless it sat in
//! `tests/pcap-samples/`.
//!
//! So this gate asks it of every file in the INDEX, wherever it lives:
//!
//! * A capture is recognized by its first bytes, never by its name. Two fuzz
//!   seeds have no extension at all, and a renamed or gzip-wrapped capture is
//!   exactly the one a name-based walk would miss.
//! * Each one outside `tests/pcap-samples/` needs an entry in
//!   `tests/PROVENANCE.md`: `public` with its source URL and license, or
//!   `synthetic` with the tracked generator that writes it, plus the SHA-256
//!   of the bytes the entry vouches for. Replacing a fixture's bytes without
//!   restating where they came from fails here.
//! * Direct children of `tests/pcap-samples/` keep their own manifest and
//!   their own gate, `every_committed_capture_fixture_says_where_it_came_from`
//!   in `tests/repo_hygiene_test.rs`, with its shrink-only pre-manifest list.
//!   This file defers to it rather than keeping a second record of the same
//!   fixtures.
//! * An entry whose file is gone from the index is refused: a manifest that
//!   vouches for nothing is how the next reader stops trusting it.
//!
//! The detection and the matching are pure functions over a path and a
//! file's first bytes, tested against built inputs below, so the gate's own
//! logic is exercised before it is trusted with the repository.
//!
//! Reading `git ls-files` rather than walking the disk is deliberate: a
//! capture that has just been `git add`ed is in the index before it is in any
//! commit, which is the last moment it is cheap to take back.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The manifest, relative to the repository root.
const MANIFEST: &str = "tests/PROVENANCE.md";

/// The directory whose direct children answer to their own manifest.
const SAMPLES_DIR: &str = "tests/pcap-samples";

/// How many leading bytes of each tracked file the gate reads.
///
/// Enough to see through a gzip header carrying a long file name or comment
/// and still inflate the few bytes that name the format inside.
const HEAD: usize = 64 * 1024;

/// Committed captures that are neither provably public nor synthetic yet.
///
/// **Shrink-only**, like the pre-manifest list in `repo_hygiene_test.rs`. An
/// entry leaves by gaining a real manifest entry (a public source with a
/// license, or a generator) or by the file being deleted, never by being
/// described from memory. [`UNRESOLVED_CEILING`] is the ratchet: a gate that
/// has to be edited to grow is a gate that cannot grow by accident.
const UNRESOLVED: &[(&str, &str)] = &[
    (
        "harness/sipp/scenarios/g711a.pcap",
        "not the g711a.pcap SIPp publishes (that one is 73,184 bytes; this is \
         1,273,074). Byte-identical to g711a.pcap in \
         https://github.com/vnyb/sipp-scenarios, which states no license, and \
         its media flows from a public address",
    ),
    (
        "harness/sipp/scenarios/g722.pcap",
        "SIPp publishes no g722.pcap. Byte-identical to g722.pcap in \
         https://github.com/vnyb/sipp-scenarios, which states no license, and \
         its media flows from a public address",
    ),
    (
        "tests/fixtures/rtpengine-opensips-ng.pcap",
        "a harness capture, but its G.722 RTP payloads are the first 21 frames \
         of harness/sipp/scenarios/g722.pcap, which is unresolved above",
    ),
    (
        "tests/fixtures/rtpengine-opensips-media-only.pcap",
        "the media-only twin of rtpengine-opensips-ng.pcap, carrying the same \
         g722.pcap-derived payloads",
    ),
    (
        "tests/fixtures/ice_checks.pcap",
        "constructed by hand (RFC 5737 addresses, RFC 7042 MACs), and no \
         generator for it was ever committed",
    ),
    (
        "tests/fixtures/stun_nat_probe.pcap",
        "constructed by hand with no generator committed, and both its MAC \
         addresses are outside the RFC 7042 documentation block",
    ),
    (
        "tests/fixtures/stun_sdp_mismatch.pcap",
        "constructed by hand with no generator committed, carrying the same \
         two non-documentation MAC addresses",
    ),
    (
        "tests/fixtures/turn_relay.pcap",
        "constructed by hand (RFC 5737 addresses, RFC 7042 MACs), and no \
         generator for it was ever committed",
    ),
];

/// The most entries [`UNRESOLVED`] may hold. Lower it when one leaves; never
/// raise it.
const UNRESOLVED_CEILING: usize = 8;

// ── what a capture looks like ───────────────────────────────────────

/// A capture container, as its leading bytes declare it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    /// Classic libpcap, in either byte order and either timestamp precision.
    Pcap { big_endian: bool, nanosecond: bool },
    /// pcapng, starting with its Section Header Block.
    Pcapng,
    /// Microsoft Network Monitor 2.x, which sipnab recognizes and refuses.
    NetMon,
}

/// A detected capture: its container, and whether gzip wrapped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Format {
    container: Container,
    gzip: bool,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.gzip {
            f.write_str("gzip-compressed ")?;
        }
        match self.container {
            Container::Pcap {
                big_endian,
                nanosecond,
            } => write!(
                f,
                "classic pcap ({}-endian, {} timestamps)",
                if big_endian { "big" } else { "little" },
                if nanosecond {
                    "nanosecond"
                } else {
                    "microsecond"
                }
            ),
            Container::Pcapng => f.write_str("pcapng"),
            Container::NetMon => f.write_str("NetMon 2.x capture"),
        }
    }
}

/// The container `head` starts with, without looking inside compression.
fn container_of(head: &[u8]) -> Option<Container> {
    let pcap = |big_endian, nanosecond| {
        Some(Container::Pcap {
            big_endian,
            nanosecond,
        })
    };
    match head.get(..4)? {
        [0xd4, 0xc3, 0xb2, 0xa1] => pcap(false, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => pcap(true, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => pcap(false, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => pcap(true, true),
        // A Section Header Block: its type, its length, then the byte-order
        // magic in whichever order the writer used. The type alone is CR LF
        // CR LF, which prose can start with.
        [0x0a, 0x0d, 0x0d, 0x0a] => match head.get(8..12)? {
            [0x4d, 0x3c, 0x2b, 0x1a] | [0x1a, 0x2b, 0x3c, 0x4d] => Some(Container::Pcapng),
            _ => None,
        },
        b"GMBU" => Some(Container::NetMon),
        _ => None,
    }
}

/// Enough inflated bytes to name any container above: pcapng needs twelve.
const MAGIC_WINDOW: usize = 12;

/// The capture format `head` starts with, looking inside gzip, or `None`.
fn capture_format(head: &[u8]) -> Option<Format> {
    if let Some(container) = container_of(head) {
        return Some(Format {
            container,
            gzip: false,
        });
    }
    if !head.starts_with(&[0x1f, 0x8b]) {
        return None;
    }
    // Inflate just far enough to read the inner magic. `head` may end
    // mid-member, so a read that fails after some bytes came out still leaves
    // those bytes to judge.
    let mut decoder = flate2::read::GzDecoder::new(head);
    let mut inner = Vec::with_capacity(MAGIC_WINDOW);
    let mut buf = [0u8; MAGIC_WINDOW];
    while inner.len() < MAGIC_WINDOW {
        match decoder.read(&mut buf[..MAGIC_WINDOW - inner.len()]) {
            Ok(0) | Err(_) => break,
            Ok(n) => inner.extend_from_slice(&buf[..n]),
        }
    }
    container_of(&inner).map(|container| Format {
        container,
        gzip: true,
    })
}

// ── the manifest ────────────────────────────────────────────────────

/// Where a manifest entry says a capture came from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    /// Published by someone else: where, and under what terms.
    Public { source: String, license: String },
    /// Built by this repository: the tracked file that writes it.
    Synthetic { generator: String },
}

/// One `### <path>` section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    path: String,
    origin: Origin,
    sha256: String,
}

/// The labels an entry is made of.
const CATEGORY: &str = "**Category:**";
const GENERATOR: &str = "**Generator:**";
const SOURCE: &str = "**Source:**";
const LICENSE: &str = "**License:**";
const SHA256: &str = "**SHA-256:**";

/// The first backquoted span in `value`, if it is not empty.
fn backquoted(value: &str) -> Option<&str> {
    let start = value.find('`')? + 1;
    let len = value[start..].find('`')?;
    Some(&value[start..start + len]).filter(|s| !s.is_empty())
}

/// The first `https://` URL in `value`, without angle brackets around it.
fn https_url(value: &str) -> Option<String> {
    let start = value.find("https://")?;
    let rest = &value[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '>' || c == ')')
        .unwrap_or(rest.len());
    Some(rest[..end].to_string()).filter(|u| u.len() > "https://".len())
}

/// Parse the manifest into entries, and every problem found doing so.
///
/// An entry is a `### <path>` heading followed by `- **Label:** value`
/// lines. Fenced code blocks are skipped, so a manifest can show an example
/// entry without it counting as one.
fn parse_manifest(text: &str) -> (Vec<Entry>, Vec<String>) {
    let mut sections: Vec<(String, Vec<&str>)> = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        if let Some(path) = line.strip_prefix("### ") {
            sections.push((path.trim().to_string(), Vec::new()));
        } else if let Some((_, body)) = sections.last_mut() {
            body.push(line);
        }
    }

    let mut entries = Vec::new();
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for (path, body) in sections {
        if !seen.insert(path.clone()) {
            problems.push(format!(
                "{MANIFEST} describes {path} twice. One capture, one entry: two \
                 records of the same file are how they come apart."
            ));
            continue;
        }
        let label = |name: &str| {
            body.iter().find_map(|line| {
                line.trim_start()
                    .strip_prefix("- ")
                    .and_then(|l| l.strip_prefix(name))
                    .map(str::trim)
            })
        };
        let refuse = |what: String| format!("{MANIFEST}: the entry for {path} {what}");

        let sha = label(SHA256).and_then(backquoted).filter(|h| {
            h.len() == 64
                && h.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        });
        let Some(sha) = sha else {
            problems.push(refuse(format!(
                "has no {SHA256} line holding a 64-digit lowercase hex hash in \
                 backquotes. The hash is what ties the entry to the bytes it \
                 vouches for."
            )));
            continue;
        };
        let origin = match label(CATEGORY) {
            Some("synthetic") => match label(GENERATOR).and_then(backquoted) {
                Some(generator) => Origin::Synthetic {
                    generator: generator.to_string(),
                },
                None => {
                    problems.push(refuse(format!(
                        "is synthetic and has no {GENERATOR} line naming, in \
                         backquotes, the tracked file that writes it."
                    )));
                    continue;
                }
            },
            Some("public") => {
                let Some(source) = label(SOURCE).and_then(https_url) else {
                    problems.push(refuse(format!(
                        "is public and has no {SOURCE} line carrying the https:// \
                         URL it was published at."
                    )));
                    continue;
                };
                let Some(license) = label(LICENSE).filter(|l| !l.is_empty()) else {
                    problems.push(refuse(format!(
                        "is public and has no {LICENSE} line. Published is not \
                         the same as redistributable: say under what terms."
                    )));
                    continue;
                };
                Origin::Public {
                    source,
                    license: license.to_string(),
                }
            }
            Some(other) => {
                problems.push(refuse(format!(
                    "has category `{other}`. There are two: `public` and \
                     `synthetic`."
                )));
                continue;
            }
            None => {
                problems.push(refuse(format!("has no {CATEGORY} line.")));
                continue;
            }
        };
        entries.push(Entry {
            path,
            origin,
            sha256: sha.to_string(),
        });
    }
    (entries, problems)
}

// ── the verdict on one tracked file ─────────────────────────────────

/// What the gate concludes about one tracked file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Not a capture at all.
    NotACapture,
    /// A direct child of `tests/pcap-samples/`, which its own gate covers.
    Deferred,
    /// Listed in the manifest.
    Listed,
    /// On the shrink-only unresolved list.
    Unresolved,
    /// A capture nobody has accounted for. The message says what to do.
    Unlisted(String),
}

/// Whether `path` is a direct child of `tests/pcap-samples/`.
///
/// Direct children only, because that is what its gate reads: a capture in a
/// subdirectory there would be seen by neither gate.
fn deferred_to_samples_gate(path: &str) -> bool {
    Path::new(path).parent() == Some(Path::new(SAMPLES_DIR))
}

/// The verdict on the tracked file at `path` whose leading bytes are `head`.
fn verdict(
    path: &str,
    head: &[u8],
    listed: &BTreeSet<&str>,
    unresolved: &[(&str, &str)],
) -> Verdict {
    let Some(format) = capture_format(head) else {
        return Verdict::NotACapture;
    };
    if deferred_to_samples_gate(path) {
        return Verdict::Deferred;
    }
    if listed.contains(path) {
        return Verdict::Listed;
    }
    if unresolved.iter().any(|(p, _)| *p == path) {
        return Verdict::Unresolved;
    }
    Verdict::Unlisted(format!(
        "{path} is a {format} that nothing accounts for. Add an entry for it \
         to {MANIFEST}: `synthetic` with the tracked generator that writes it \
         (a builder in tests/support/synthetic_captures.rs, listed in OWNED, is \
         rebuilt and compared byte for byte by the suite), or `public` with the \
         URL it was published at and its license. A capture from a live network \
         is neither: it belongs in the private corpus under SIPNAB_CORPUS, and \
         never in this repository."
    ))
}

/// Problems with the manifest and the unresolved list, given what the index
/// holds: `tracked` maps every tracked path to its detected format.
fn manifest_problems(
    entries: &[Entry],
    tracked: &BTreeMap<String, Option<Format>>,
    unresolved: &[(&str, &str)],
) -> Vec<String> {
    let mut problems = Vec::new();
    for e in entries {
        match tracked.get(&e.path) {
            None => problems.push(format!(
                "{MANIFEST} vouches for {}, which is not in the index. Delete \
                 the entry with the file: an entry for a capture nobody can \
                 open is worse than no entry.",
                e.path
            )),
            Some(None) => problems.push(format!(
                "{MANIFEST} vouches for {}, which is not a capture by its \
                 leading bytes. The manifest is for captures only.",
                e.path
            )),
            Some(Some(_)) => {}
        }
        if deferred_to_samples_gate(&e.path) {
            problems.push(format!(
                "{} is in {SAMPLES_DIR}/, whose captures are recorded in \
                 tests/pcap-samples/PROVENANCE.md and checked by that \
                 directory's own gate. Take it out of {MANIFEST}.",
                e.path
            ));
        }
        if let Origin::Synthetic { generator } = &e.origin
            && !tracked.contains_key(generator)
        {
            problems.push(format!(
                "{MANIFEST} says {generator} writes {}, and {generator} is \
                 not in the index, so nobody else can run it.",
                e.path
            ));
        }
    }
    let listed: BTreeSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    for (path, why) in unresolved {
        if listed.contains(path) {
            problems.push(format!(
                "{path} is on UNRESOLVED and has a {MANIFEST} entry: both. The \
                 entry is the better answer; take it off the list and lower \
                 UNRESOLVED_CEILING."
            ));
        }
        if !tracked.get(*path).is_some_and(Option::is_some) {
            problems.push(format!(
                "UNRESOLVED names {path}, which is not a capture in the index. \
                 Remove it and lower UNRESOLVED_CEILING."
            ));
        }
        if why.trim().is_empty() {
            problems.push(format!(
                "UNRESOLVED lists {path} with no reason. The reason is what the \
                 next person needs to resolve it."
            ));
        }
    }
    problems
}

/// The problem, if any, with an entry whose file hashes to `actual`.
fn hash_problem(entry: &Entry, actual: &str) -> Option<String> {
    (entry.sha256 != actual).then(|| {
        format!(
            "{} hashes to {actual}, and {MANIFEST} vouches for {}. The bytes \
             changed after the entry was written. If its generator rewrote \
             them, update the hash; if not, find out where the new bytes came \
             from before committing them.",
            entry.path, entry.sha256
        )
    })
}

/// The hash problems of every entry whose file is a capture in the index,
/// hashing each with `hash_of`.
///
/// `hash_of` is a parameter so the loop can be driven without a repository:
/// the gate passes a reader of the file on disk, the tests a table.
fn hash_problems(
    entries: &[Entry],
    tracked: &BTreeMap<String, Option<Format>>,
    hash_of: impl Fn(&str) -> String,
) -> Vec<String> {
    entries
        .iter()
        .filter(|e| tracked.get(&e.path).is_some_and(Option::is_some))
        .filter_map(|e| hash_problem(e, &hash_of(&e.path)))
        .collect()
}

// ── reading the repository ──────────────────────────────────────────

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every path in the index, as git writes it.
///
/// The hook's `GIT_INDEX_FILE` is inherited on purpose: under `git commit` it
/// names the index being committed, which is the set this gate is about.
fn tracked_paths() -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo())
        .args(["ls-files", "-z"])
        .output()
        .expect("run git ls-files");
    assert!(
        out.status.success(),
        "git ls-files failed, so the gate cannot see the index: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect()
}

/// Up to [`HEAD`] leading bytes of a tracked file, or `None` if it is not on
/// disk (a symlink to nowhere, or a path staged and then deleted).
fn head_of(rel: &str) -> Option<Vec<u8>> {
    let file = std::fs::File::open(repo().join(rel)).ok()?;
    let mut head = Vec::with_capacity(HEAD);
    file.take(HEAD as u64).read_to_end(&mut head).ok()?;
    Some(head)
}

/// The lowercase hex SHA-256 of a tracked file.
fn sha256_of(rel: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ── the gate ────────────────────────────────────────────────────────

/// Every capture in the index is accounted for, and the manifest vouches only
/// for files that are there, with the bytes it names.
#[test]
fn every_committed_capture_is_public_or_synthetic() {
    let text = std::fs::read_to_string(repo().join(MANIFEST))
        .unwrap_or_else(|e| panic!("read {MANIFEST}: {e}"));
    let (entries, mut problems) = parse_manifest(&text);
    let listed: BTreeSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();

    let mut tracked: BTreeMap<String, Option<Format>> = BTreeMap::new();
    let mut captures = 0usize;
    let mut deferred = 0usize;
    for path in tracked_paths() {
        let Some(head) = head_of(&path) else {
            tracked.insert(path, None);
            continue;
        };
        let format = capture_format(&head);
        if format.is_some() {
            captures += 1;
        }
        match verdict(&path, &head, &listed, UNRESOLVED) {
            Verdict::Unlisted(why) => problems.push(why),
            Verdict::Deferred => deferred += 1,
            Verdict::NotACapture | Verdict::Listed | Verdict::Unresolved => {}
        }
        tracked.insert(path, format);
    }

    problems.extend(manifest_problems(&entries, &tracked, UNRESOLVED));
    problems.extend(hash_problems(&entries, &tracked, sha256_of));

    assert!(
        problems.is_empty(),
        "{} problem(s) with committed captures:\n\n{}",
        problems.len(),
        problems.join("\n\n")
    );

    // Floors, not facts: they exist so that a detector or an index read that
    // stopped matching reports as a failure instead of as an empty, passing
    // sweep. 53 captures were in the index when this was written: 37 direct
    // children of tests/pcap-samples/, 8 listed in the manifest and 8
    // unresolved.
    assert!(
        captures >= 45,
        "found only {captures} captures in the index; detection has stopped \
         matching and every absence above would be an absence of looking"
    );
    assert!(
        deferred >= 30,
        "only {deferred} captures deferred to the tests/pcap-samples gate; \
         the path rule has stopped matching"
    );
    assert!(
        UNRESOLVED.len() <= UNRESOLVED_CEILING,
        "UNRESOLVED holds {} entries against a ceiling of {UNRESOLVED_CEILING}. \
         The list only shrinks: account for a new capture in {MANIFEST} instead.",
        UNRESOLVED.len()
    );
}

// ── the logic, driven with built inputs ─────────────────────────────

/// A 24-byte classic pcap header with the given magic, written in the byte
/// order the magic itself declares.
fn pcap_header(magic: u32, big_endian: bool) -> Vec<u8> {
    let (m, v2, v4, snap, link) = if big_endian {
        (
            magic.to_be_bytes(),
            2u16.to_be_bytes(),
            4u16.to_be_bytes(),
            65535u32.to_be_bytes(),
            1u32.to_be_bytes(),
        )
    } else {
        (
            magic.to_le_bytes(),
            2u16.to_le_bytes(),
            4u16.to_le_bytes(),
            65535u32.to_le_bytes(),
            1u32.to_le_bytes(),
        )
    };
    let mut h = Vec::new();
    h.extend_from_slice(&m);
    h.extend_from_slice(&v2);
    h.extend_from_slice(&v4);
    h.extend_from_slice(&[0; 8]);
    h.extend_from_slice(&snap);
    h.extend_from_slice(&link);
    h
}

/// The leading bytes of a pcapng Section Header Block, little-endian.
fn pcapng_head() -> Vec<u8> {
    let mut h = vec![0x0a, 0x0d, 0x0d, 0x0a];
    h.extend_from_slice(&28u32.to_le_bytes());
    h.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes());
    h.extend_from_slice(&(-1i64).to_le_bytes());
    h.extend_from_slice(&28u32.to_le_bytes());
    h
}

/// `data` gzip-compressed with real deflate, as `gzip` on a shell would.
fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("compress");
    enc.finish().expect("finish")
}

/// A manifest entry in the shape `tests/PROVENANCE.md` uses.
fn synthetic_entry(path: &str, generator: &str, sha: &str) -> String {
    format!(
        "### {path}\n\n- {CATEGORY} synthetic\n- {GENERATOR} `{generator}`\n- {SHA256} `{sha}`\n\n"
    )
}

/// A SHA-256 shaped string for manifest fixtures.
const SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn classic_pcap_is_recognized_in_both_byte_orders_and_both_precisions() {
    for (magic, big_endian, nanosecond) in [
        (0xA1B2_C3D4u32, false, false),
        (0xA1B2_C3D4, true, false),
        (0xA1B2_3C4D, false, true),
        (0xA1B2_3C4D, true, true),
    ] {
        let head = pcap_header(magic, big_endian);
        assert_eq!(
            capture_format(&head),
            Some(Format {
                container: Container::Pcap {
                    big_endian,
                    nanosecond
                },
                gzip: false
            }),
            "magic {magic:#010x} written {}-endian",
            if big_endian { "big" } else { "little" }
        );
    }
}

#[test]
fn pcapng_and_netmon_are_recognized() {
    assert_eq!(
        capture_format(&pcapng_head()).map(|f| f.container),
        Some(Container::Pcapng)
    );
    let mut netmon = b"GMBU".to_vec();
    netmon.extend_from_slice(&[0x00, 0x02, 0x01, 0x00]);
    assert_eq!(
        capture_format(&netmon).map(|f| f.container),
        Some(Container::NetMon)
    );
}

/// A pcapng magic alone is not enough: the byte-order magic must follow.
///
/// `0A 0D 0D 0A` is CR/LF bytes, which a text file can start with; the
/// byte-order magic eight bytes in is what makes it a Section Header Block.
#[test]
fn text_that_starts_like_pcapng_is_not_a_capture() {
    assert_eq!(capture_format(b"\n\r\r\nhello, this is prose\n"), None);
}

#[test]
fn a_gzip_wrapped_capture_is_recognized_by_looking_inside() {
    let pcap = pcap_header(0xA1B2_C3D4, false);
    assert_eq!(
        capture_format(&gzip(&pcap)),
        Some(Format {
            container: Container::Pcap {
                big_endian: false,
                nanosecond: false
            },
            gzip: true
        })
    );
    assert_eq!(
        capture_format(&gzip(&pcapng_head())).map(|f| (f.container, f.gzip)),
        Some((Container::Pcapng, true))
    );
}

/// gzip around something that is not a capture is not a capture.
#[test]
fn gzip_around_text_is_not_a_capture() {
    assert_eq!(capture_format(&gzip(b"just a compressed README\n")), None);
}

#[test]
fn a_renamed_pcap_is_caught_and_the_message_says_what_to_do() {
    let head = pcap_header(0xA1B2_C3D4, false);
    let Verdict::Unlisted(why) = verdict("docs/diagram.png", &head, &BTreeSet::new(), &[]) else {
        panic!("a pcap renamed to .png must still be caught");
    };
    assert!(why.contains("docs/diagram.png"), "names the file: {why}");
    assert!(why.contains("classic pcap"), "names the format: {why}");
    assert!(why.contains(MANIFEST), "names the manifest: {why}");
    assert!(
        why.contains("generator") && why.contains("public"),
        "says how to account for it, either way: {why}"
    );
}

#[test]
fn an_extensionless_pcapng_is_caught() {
    let Verdict::Unlisted(why) = verdict(
        "fuzz/corpus/pcap_reader/seed-7",
        &pcapng_head(),
        &BTreeSet::new(),
        &[],
    ) else {
        panic!("an extensionless pcapng must be caught");
    };
    assert!(why.contains("pcapng"), "{why}");
}

#[test]
fn a_gzip_wrapped_pcap_is_caught() {
    let head = gzip(&pcap_header(0xA1B2_3C4D, true));
    let Verdict::Unlisted(why) = verdict("tests/fixtures/call.bin", &head, &BTreeSet::new(), &[])
    else {
        panic!("a gzip-wrapped pcap must be caught");
    };
    assert!(why.contains("gzip-compressed classic pcap"), "{why}");
}

#[test]
fn a_text_file_is_not_flagged() {
    assert_eq!(
        verdict(
            "tests/fixtures/notes.pcap",
            b"# a text file with a capture's name\n",
            &BTreeSet::new(),
            &[]
        ),
        Verdict::NotACapture,
        "a name is not a format"
    );
}

#[test]
fn a_listed_capture_passes() {
    let head = pcap_header(0xA1B2_C3D4, false);
    let listed: BTreeSet<&str> = ["tests/fixtures/call.pcap"].into_iter().collect();
    assert_eq!(
        verdict("tests/fixtures/call.pcap", &head, &listed, &[]),
        Verdict::Listed
    );
}

#[test]
fn an_unresolved_capture_passes_and_nothing_else_does() {
    let head = pcap_header(0xA1B2_C3D4, false);
    let unresolved = [("tests/fixtures/old.pcap", "why")];
    assert_eq!(
        verdict(
            "tests/fixtures/old.pcap",
            &head,
            &BTreeSet::new(),
            &unresolved
        ),
        Verdict::Unresolved
    );
    assert!(matches!(
        verdict(
            "tests/fixtures/new.pcap",
            &head,
            &BTreeSet::new(),
            &unresolved
        ),
        Verdict::Unlisted(_)
    ));
}

/// Direct children of tests/pcap-samples/ answer to that directory's gate;
/// anything deeper answers to this one, because that gate reads one level.
#[test]
fn only_direct_children_of_the_samples_directory_are_deferred() {
    let head = pcap_header(0xA1B2_C3D4, false);
    assert_eq!(
        verdict("tests/pcap-samples/x.pcap", &head, &BTreeSet::new(), &[]),
        Verdict::Deferred
    );
    assert!(matches!(
        verdict(
            "tests/pcap-samples/sub/x.pcap",
            &head,
            &BTreeSet::new(),
            &[]
        ),
        Verdict::Unlisted(_)
    ));
}

#[test]
fn a_synthetic_entry_parses() {
    let text = format!(
        "# heading\n\nprose\n\n{}",
        synthetic_entry("tests/fixtures/a.pcap", "tests/support/gen.rs", SHA)
    );
    let (entries, problems) = parse_manifest(&text);
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(
        entries,
        vec![Entry {
            path: "tests/fixtures/a.pcap".into(),
            origin: Origin::Synthetic {
                generator: "tests/support/gen.rs".into()
            },
            sha256: SHA.into(),
        }]
    );
}

#[test]
fn a_public_entry_parses_and_needs_a_url_and_a_license() {
    let good = format!(
        "### a.pcap\n\n- {CATEGORY} public\n- {SOURCE} <https://example.org/a.pcap>\n\
         - {LICENSE} CC0-1.0\n- {SHA256} `{SHA}`\n"
    );
    let (entries, problems) = parse_manifest(&good);
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(
        entries[0].origin,
        Origin::Public {
            source: "https://example.org/a.pcap".into(),
            license: "CC0-1.0".into()
        }
    );

    let no_url = good.replace("<https://example.org/a.pcap>", "somewhere online");
    assert!(
        parse_manifest(&no_url).1.iter().any(|p| p.contains("URL")),
        "a public entry with no URL is refused"
    );
    let no_license = good.replace(&format!("- {LICENSE} CC0-1.0\n"), "");
    assert!(
        parse_manifest(&no_license)
            .1
            .iter()
            .any(|p| p.contains("License")),
        "a public entry with no license is refused"
    );
}

/// A fenced block can show an entry without the manifest counting it.
///
/// Otherwise an example in the prose would vouch for a file, or fail as an
/// entry for one that is not in the index.
#[test]
fn an_entry_inside_a_fenced_block_is_only_an_example() {
    let text = format!(
        "# heading\n\n```markdown\n{}```\n",
        synthetic_entry("tests/fixtures/example.pcap", "tests/support/gen.rs", SHA)
    );
    let (entries, problems) = parse_manifest(&text);
    assert!(problems.is_empty(), "{problems:?}");
    assert!(
        entries.is_empty(),
        "an example in a fence is not an entry: {entries:?}"
    );
}

/// The hash is 64 lowercase hex digits or the entry is refused: a hash the
/// gate cannot compare vouches for nothing.
#[test]
fn a_hash_that_is_not_sixty_four_lowercase_hex_digits_is_refused() {
    for bad in [
        SHA.to_uppercase().replace('0', "A"),
        SHA[..63].to_string(),
        format!("{}g", &SHA[..63]),
    ] {
        let text = synthetic_entry("a.pcap", "g.rs", &bad);
        let (entries, problems) = parse_manifest(&text);
        assert!(entries.is_empty(), "{bad} was accepted: {entries:?}");
        assert!(
            problems.iter().any(|p| p.contains("SHA-256")),
            "{bad}: {problems:?}"
        );
    }
}

/// An unresolved capture carries its reason, because the reason is the
/// whole of what the next person has to go on.
#[test]
fn an_unresolved_capture_needs_a_reason() {
    let problems = manifest_problems(&[], &index(), &[("tests/fixtures/a.pcap", "  ")]);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("tests/fixtures/a.pcap") && p.contains("no reason")),
        "{problems:?}"
    );
}

#[test]
fn a_malformed_entry_is_refused() {
    let unknown = format!("### a.pcap\n\n- {CATEGORY} found-it-somewhere\n- {SHA256} `{SHA}`\n");
    assert!(
        parse_manifest(&unknown)
            .1
            .iter()
            .any(|p| p.contains("found-it-somewhere")),
        "an unknown category is refused by name"
    );
    let no_generator = format!("### a.pcap\n\n- {CATEGORY} synthetic\n- {SHA256} `{SHA}`\n");
    assert!(
        parse_manifest(&no_generator)
            .1
            .iter()
            .any(|p| p.contains("Generator")),
        "a synthetic entry with no generator is refused"
    );
    let no_hash = format!("### a.pcap\n\n- {CATEGORY} synthetic\n- {GENERATOR} `g.rs`\n");
    assert!(
        parse_manifest(&no_hash)
            .1
            .iter()
            .any(|p| p.contains("SHA-256")),
        "an entry with no hash is refused"
    );
    let twice = format!(
        "{}{}",
        synthetic_entry("a.pcap", "g.rs", SHA),
        synthetic_entry("a.pcap", "g.rs", SHA)
    );
    assert!(
        parse_manifest(&twice).1.iter().any(|p| p.contains("twice")),
        "a path described twice is refused"
    );
}

/// Tracked paths for the manifest checks: one capture, one generator.
fn index() -> BTreeMap<String, Option<Format>> {
    let pcap = capture_format(&pcap_header(0xA1B2_C3D4, false));
    BTreeMap::from([
        ("tests/fixtures/a.pcap".to_string(), pcap),
        ("tests/fixtures/b.pcap".to_string(), pcap),
        ("tests/support/gen.rs".to_string(), None),
    ])
}

fn entry(path: &str, generator: &str) -> Entry {
    Entry {
        path: path.into(),
        origin: Origin::Synthetic {
            generator: generator.into(),
        },
        sha256: SHA.into(),
    }
}

#[test]
fn an_entry_whose_file_is_gone_is_refused() {
    let problems = manifest_problems(
        &[entry("tests/fixtures/deleted.pcap", "tests/support/gen.rs")],
        &index(),
        &[],
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("tests/fixtures/deleted.pcap") && p.contains("not in the index")),
        "{problems:?}"
    );
}

#[test]
fn a_sound_manifest_has_no_problems() {
    let problems = manifest_problems(
        &[
            entry("tests/fixtures/a.pcap", "tests/support/gen.rs"),
            entry("tests/fixtures/b.pcap", "tests/support/gen.rs"),
        ],
        &index(),
        &[],
    );
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn an_entry_for_a_file_that_is_not_a_capture_is_refused() {
    let problems = manifest_problems(
        &[entry("tests/support/gen.rs", "tests/support/gen.rs")],
        &index(),
        &[],
    );
    assert!(
        problems.iter().any(|p| p.contains("not a capture")),
        "{problems:?}"
    );
}

#[test]
fn a_generator_that_is_not_tracked_is_refused() {
    let problems = manifest_problems(
        &[entry(
            "tests/fixtures/a.pcap",
            "tools/generate-lost-capture.py",
        )],
        &index(),
        &[],
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("tools/generate-lost-capture.py")),
        "{problems:?}"
    );
}

#[test]
fn a_samples_fixture_belongs_to_its_own_manifest() {
    let mut idx = index();
    let pcap = capture_format(&pcap_header(0xA1B2_C3D4, false));
    idx.insert("tests/pcap-samples/s.pcap".into(), pcap);
    let problems = manifest_problems(
        &[entry("tests/pcap-samples/s.pcap", "tests/support/gen.rs")],
        &idx,
        &[],
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("tests/pcap-samples/PROVENANCE.md")),
        "{problems:?}"
    );
}

#[test]
fn the_unresolved_list_must_name_live_captures_and_stay_disjoint() {
    let listed_and_unresolved = manifest_problems(
        &[entry("tests/fixtures/a.pcap", "tests/support/gen.rs")],
        &index(),
        &[("tests/fixtures/a.pcap", "why")],
    );
    assert!(
        listed_and_unresolved.iter().any(|p| p.contains("both")),
        "{listed_and_unresolved:?}"
    );
    let stale = manifest_problems(&[], &index(), &[("tests/fixtures/gone.pcap", "why")]);
    assert!(
        stale.iter().any(|p| p.contains("tests/fixtures/gone.pcap")),
        "an unresolved entry for a file that is gone is refused: {stale:?}"
    );
}

#[test]
fn a_hash_that_does_not_match_is_refused() {
    let e = entry("tests/fixtures/a.pcap", "tests/support/gen.rs");
    assert_eq!(hash_problem(&e, SHA), None);
    let other = "1".repeat(64);
    let why = hash_problem(&e, &other).expect("a changed file is refused");
    assert!(
        why.contains("tests/fixtures/a.pcap") && why.contains(&other),
        "{why}"
    );
}

/// Every entry whose file is a capture is hashed and compared; an entry
/// whose file is not one is left to the problems above rather than hashed.
#[test]
fn every_listed_capture_is_hashed_and_compared() {
    let entries = [
        entry("tests/fixtures/a.pcap", "tests/support/gen.rs"),
        entry("tests/fixtures/b.pcap", "tests/support/gen.rs"),
        entry("tests/support/gen.rs", "tests/support/gen.rs"),
    ];
    let changed = "2".repeat(64);
    let hashed = std::cell::RefCell::new(Vec::new());
    let problems = hash_problems(&entries, &index(), |path| {
        hashed.borrow_mut().push(path.to_string());
        if path == "tests/fixtures/b.pcap" {
            changed.clone()
        } else {
            SHA.to_string()
        }
    });
    assert_eq!(
        hashed.into_inner(),
        ["tests/fixtures/a.pcap", "tests/fixtures/b.pcap"],
        "both captures are hashed, and the generator, which is not one, is not"
    );
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("tests/fixtures/b.pcap") && problems[0].contains(&changed),
        "{problems:?}"
    );
}
