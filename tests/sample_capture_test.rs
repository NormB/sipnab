// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one-click sample capture shows a phone's whole life, under DEFAULTS.
//!
//! # The defect this file exists for
//!
//! `website/static/demos/sample-call.pcap` is the first capture most visitors
//! ever open in sipnab: the browser analyzer's "Load a sample call" button and
//! the homepage's "Try a sample capture" link both load it. It shipped holding
//! a single INVITE dialog -- no registration, no keep-alive, nothing before or
//! after one call -- and its SIP sat on port 5080, outside the default
//! `--portrange 5060-5061`.
//!
//! So `sipnab -I sample-call.pcap`, with no flags, reported **zero SIP
//! messages** and two orphan RTP streams. The sample that exists to show a
//! first-time reader what the tool does showed them nothing.
//!
//! # Why nothing caught it
//!
//! Something did check this file. `site_journey_test` asserts it EXISTS,
//! because `analyze.js` fetches it by URL and a 404 there is a dead button.
//! Existence is not the property that matters, and a gate on the wrong
//! property is quieter than no gate at all: the file was present, the check
//! was green, and the capture was empty under the settings a reader uses.
//!
//! What is pinned here is the content, and specifically the content **as
//! parsed with default arguments**. A sample that needs a flag to show
//! anything is a sample that fails for the person it was written for.

#![cfg(feature = "full")]

use std::path::PathBuf;
use std::process::Command;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The shipped sample capture.
fn sample() -> PathBuf {
    repo().join("website/static/demos/sample-call.pcap")
}

/// Run the built binary against the sample with NO arguments beyond the file.
///
/// Deliberately no `--portrange`, no `--report`, no feature flags. The whole
/// point is what a reader sees when they type the obvious thing.
fn analyze_with_defaults() -> String {
    let bin = env!("CARGO_BIN_EXE_sipnab");
    let out = Command::new(bin)
        .arg("-N")
        .arg("-I")
        .arg(sample())
        .output()
        .expect("the sipnab binary must run");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

/// The sample is present and non-trivial.
///
/// The old gate's property, kept, because a missing file really is a dead
/// button on the site. It is the floor here rather than the ceiling.
#[test]
fn the_sample_capture_exists_and_is_not_empty() {
    let p = sample();
    let meta = std::fs::metadata(&p).unwrap_or_else(|e| panic!("{} is missing: {e}", p.display()));
    assert!(
        meta.len() > 10_000,
        "{} is {} bytes; a capture that small cannot hold a registration, a \
         probe, a call and its media",
        p.display(),
        meta.len()
    );
}

/// Parsing it with default arguments finds SIP.
///
/// The exact failure that shipped. The file had SIP in it the whole time; the
/// default port range did not cover the port it was on, so the tool correctly
/// reported nothing and the sample was silently useless.
#[test]
fn the_sample_parses_under_default_arguments() {
    let out = analyze_with_defaults();
    assert!(
        !out.contains("No SIP signaling found"),
        "the sample capture yields no SIP under default arguments. This is \
         what shipped: SIP on port 5080, outside the default portrange, so a \
         reader typing `sipnab -I sample-call.pcap` saw nothing.\n\n{out}"
    );
    assert!(
        !out.contains("outside --portrange"),
        "the sample capture puts SIP outside the DEFAULT port range, so the \
         tool has to tell a first-time reader to re-run with a flag:\n\n{out}"
    );
}

/// It shows a phone's whole life, not one call.
///
/// The property the sample is for. A single INVITE demonstrates that sipnab
/// parses an INVITE; a registration, a probe, a call and a hangup demonstrate
/// what the tool is for.
#[test]
fn the_sample_shows_a_registration_a_probe_a_call_and_a_hangup() {
    let out = analyze_with_defaults();
    for method in ["REGISTER", "OPTIONS", "INVITE", "BYE"] {
        assert!(
            out.contains(method),
            "the sample capture contains no {method}. It is the first capture \
             most visitors open, and it shipped once as a lone INVITE:\n\n{out}"
        );
    }
}

/// The call carries real media, not just an SDP offer describing some.
///
/// An `m=audio` line costs nothing to write and proves nothing. RTP packets on
/// the wire are what make the ladder show media beside signaling, which is the
/// thing the homepage claims sipnab does.
#[test]
fn the_sample_carries_real_rtp_in_both_directions() {
    let out = analyze_with_defaults();
    assert!(
        out.contains("RTP packets across"),
        "the analyzer reported no RTP summary for the sample:\n\n{out}"
    );
    let streams = out
        .split("RTP packets across ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
    assert!(
        streams >= 2,
        "the sample carries {streams} RTP stream(s); a two-way call has two, \
         and one-way media is a defect to demonstrate deliberately rather than \
         the default first impression:\n\n{out}"
    );
}

/// The generator that produced it is committed beside it.
///
/// A binary fixture with no generator can only be edited by whoever still has
/// the shell history that made it. Every other pcap under `demos/` is
/// generated by a script in the same directory; this one was not, which is
/// part of why it sat wrong.
#[test]
fn the_sample_has_a_committed_generator() {
    let generator = repo().join("demos/gen-sample-call.py");
    assert!(
        generator.is_file(),
        "demos/gen-sample-call.py is missing. The sample capture is then a \
         binary nobody can regenerate, which is how it drifted to a lone \
         INVITE on a non-default port."
    );
    let src = std::fs::read_to_string(&generator).expect("the generator is readable");
    for expected in ["REGISTER", "OPTIONS", "INVITE", "BYE", "def rtp("] {
        assert!(
            src.contains(expected),
            "the generator no longer emits {expected}, so regenerating the \
             sample would not reproduce what this file pins"
        );
    }
}

/// It uses documentation addresses only.
///
/// The captures in this repository are proven against real traffic but never
/// ship it. This one is synthetic and must stay that way: it is downloaded by
/// anyone who clicks the button.
#[test]
fn the_sample_uses_documentation_addresses_only() {
    let out = analyze_with_defaults();
    let bytes = std::fs::read(sample()).expect("readable");
    let text = String::from_utf8_lossy(&bytes);
    // RFC 5737 documentation ranges, plus loopback which the old file used.
    for line in text.lines() {
        if let Some(host) = line.strip_prefix("c=IN IP4 ") {
            let host = host.trim();
            assert!(
                host.starts_with("192.0.2.")
                    || host.starts_with("198.51.100.")
                    || host.starts_with("203.0.113."),
                "the sample advertises media at {host}, which is not an RFC \
                 5737 documentation address"
            );
        }
    }
    assert!(
        out.contains("192.0.2."),
        "the sample no longer uses documentation addresses at all:\n\n{out}"
    );
}
