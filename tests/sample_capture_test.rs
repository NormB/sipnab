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
/// parses an INVITE; a registration, a probe, a call, a hangup and the binding
/// coming back off demonstrate what the tool is for.
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

/// Two registrations, and only one of them comes off.
///
/// RFC 3261 §10.2.2: a binding is removed by re-registering it with a zero
/// expiry, not by any method called UNREGISTER — there is no such method.
///
/// The sample carries two registrations on purpose. Alice registers and is
/// still bound when the capture ends; bob registers, takes the call, and
/// removes his binding. Side by side they are the only way to see that sipnab
/// reports BOTH as `Registered` — there is no `Unregistered` state, which is
/// backlog REG1. One registration alone hides that; two make it a question a
/// reader can ask.
///
/// Both spellings of the zero interval are asserted because registrars read
/// them in that order: the `expires=0` Contact parameter first, the
/// `Expires: 0` header as the fallback. Real phones send both, and sipnab
/// reads both — a Contact parameter with no value used to hide the header from
/// the parser entirely.
#[test]
fn the_sample_has_one_registration_that_stays_and_one_that_comes_off() {
    let bytes = std::fs::read(sample()).expect("readable");
    let text = String::from_utf8_lossy(&bytes);

    assert!(
        text.contains("Expires: 0\r\n"),
        "no `Expires: 0` header in the sample; nothing gives up a binding"
    );
    assert!(
        text.contains(";expires=0"),
        "no `expires=0` Contact parameter. A registrar reads that before the \
         header, so a sample carrying only the header shows a shape real \
         phones do not send."
    );

    // Alice stays. If she ever unregisters, the capture no longer shows the
    // contrast it exists for.
    let alice_unregisters = text.match_indices("sip:alice@").any(|(i, _)| {
        text[i..]
            .split("\r\n")
            .next()
            .is_some_and(|l| l.contains("expires=0"))
    });
    assert!(
        !alice_unregisters,
        "alice unregisters. She is the control: the sample needs one binding \
         still up at the end, or both rows read the same and there is nothing \
         to notice."
    );

    // Bob does. Both his REGISTERs share a Call-ID, which is what RFC 3261
    // §10.2.4 tells a UA to reuse for the same binding.
    assert!(
        text.contains("sip:bob@") && text.contains(";expires=0"),
        "bob never removes his binding"
    );

    // And the removal is the LAST thing in the capture, not an aside.
    let last_register = text.rfind("REGISTER sip:").expect("a REGISTER exists");
    let last_invite = text.rfind("INVITE sip:").expect("an INVITE exists");
    assert!(
        last_register > last_invite,
        "the final REGISTER comes before the call rather than after it, so the \
         capture does not end on a phone going away"
    );
}

/// The sample reaches every state the RFCs define for its dialogs.
///
/// Five dialogs, five states, chosen so each of 0.5.135's four restored
/// transitions has a worked example rather than only a unit test:
///
/// | dialog | state | why it is here |
/// |---|---|---|
/// | REGISTER alice | `Registered` | the control for `Expired` |
/// | REGISTER bob | `Expired` | RFC 3261 §10.2.2, zero interval |
/// | SUBSCRIBE alice (message-summary) | `Active` | the control for the other two |
/// | SUBSCRIBE bob (dialog-info) | `Pending` | RFC 6665 §4.1.3, awaiting authorization |
/// | SUBSCRIBE alice (presence) | `Terminated` | RFC 6665 §4.2.1, un-SUBSCRIBE |
///
/// `Pending` and `Expired` were both DECLARED AND UNREACHABLE before 0.5.135,
/// and the test named for reachability was green the whole time because it
/// asserted a hardcoded list. A state with unit tests and no worked example is
/// exactly the state those two were in when they were silently wrong, so the
/// sample carries one of each and this gate keeps them there.
#[test]
fn the_sample_reaches_every_state_its_dialogs_can_have() {
    let bytes = std::fs::read(sample()).expect("readable");
    let text = String::from_utf8_lossy(&bytes);

    // The wire evidence for each. The states themselves are asserted by
    // `dialog_state_machine`'s own tests; what this pins is that the SAMPLE
    // still contains the traffic that produces them.
    for (needle, why) in [
        (
            "Subscription-State: active",
            "the healthy subscription, the control",
        ),
        (
            "Subscription-State: pending",
            "RFC 6665 §4.1.3 pending -- a subscription taken but not authorized.              This state was unreachable before 0.5.135 and reported as active.",
        ),
        (
            "Subscription-State: terminated",
            "RFC 6665 §4.1.3 terminated -- reported as active before 0.5.135",
        ),
        ("Event: message-summary", "alice's MWI subscription"),
        ("Event: dialog-info", "bob's busy-lamp subscription"),
        ("Event: presence", "the subscription that gets removed"),
    ] {
        assert!(
            text.contains(needle),
            "the sample no longer carries {needle:?}: {why}"
        );
    }

    // A 202 as well as a 200: RFC 6665 §4.1.2 lets a notifier accept a
    // subscription it has not authorized, and that is what leaves one pending.
    assert!(
        text.contains("SIP/2.0 202 Accepted"),
        "no 202 in the sample, so nothing shows a subscription accepted but          not yet authorized"
    );
}
