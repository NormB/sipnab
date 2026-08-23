// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which sources in a capture are probing rather than calling (BA1).
//!
//! An operator whose SIP port is reachable receives scans continuously, and
//! the evidence is already in every capture they take. Until now sipnab said
//! nothing about it: the traffic parsed, the dialogs appeared in the report,
//! and nothing distinguished a customer's failed call from a sweep.
//!
//! This was raised by traffic rather than by speculation. While proving the
//! rtpengine work, a public address placed calls into a lab proxy that
//! answered them and anchored media for them, and it was noticed only because
//! twelve of its exchanges had to be filtered out of a test fixture by hand.
//!
//! # Signals, not verdicts
//!
//! Every signal here is individually weak, and several are outright normal in
//! isolation. A monitoring system sends `OPTIONS` all day. A click-to-dial
//! gateway places calls without registering. A load generator dials fast. Any
//! one of them is a bad reason to name somebody's address as hostile.
//!
//! So [`assess`] reports WHICH signals fired and how many, and refuses to
//! report a source at all on fewer than [`MIN_SIGNALS`]. The output is
//! evidence an operator reads, not a verdict sipnab reached — the failure mode
//! being guarded against is a confident accusation about a real address, which
//! is worse than saying nothing.
//!
//! Nothing here blocks, sends, or reaches a firewall. BA2 turns this into a
//! rule an operator can apply, and stops at printing it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::dialog::SipDialog;
use super::method::SipMethod;

/// How many independent signals a source must trip before it is reported.
///
/// Two, and the number is the whole safety property. Each signal below has a
/// legitimate explanation on its own; what does not have one is a source that
/// never registered AND swept forty extensions, or one running a scanner's
/// user-agent AND dialing at machine cadence. Raising this misses real
/// attackers; lowering it to one starts naming monitoring systems and
/// click-to-dial gateways.
pub const MIN_SIGNALS: usize = 2;

/// Distinct callees before a source is sweeping rather than calling.
///
/// Eight. A human or a normal client calls a handful of destinations in a
/// capture window; a scanner walks an extension range. Chosen as a threshold
/// low enough to catch a short sweep and high enough that a busy click-to-dial
/// user does not trip it alone — and it cannot convict alone in any case.
const SWEEP_DISTINCT_TARGETS: usize = 8;

/// Attempts per minute above which the cadence is not a person dialing.
///
/// Twenty. A person redialing hard manages a few per minute; a scanner is
/// bounded by the network. Rate is measured over the source's own first-to-last
/// span, so a capture that happens to be short does not manufacture a rate.
const MACHINE_ATTEMPTS_PER_MIN: u64 = 20;

/// Below this many attempts, no rate is computed at all.
///
/// Three attempts two seconds apart is 30/min by arithmetic and means nothing.
/// A rate needs enough samples to be a rate.
const MIN_ATTEMPTS_FOR_RATE: u64 = 6;

/// User-agent substrings belonging to known SIP scanning and fraud tools.
///
/// Matched case-insensitively on a substring, because these tools are
/// routinely rebuilt with a version suffix. `sipsak` and `sipp` are absent on
/// purpose despite being usable for scanning: both are ordinary diagnostic
/// tools that an operator runs against their own gear, and flagging them would
/// make this report noisy in exactly the environments most likely to read it.
const SCANNER_AGENTS: &[&str] = &[
    "friendly-scanner",
    "sipvicious",
    "sipcli",
    "vaxsipuseragent",
    "sundayddr",
    "iwar",
    "smap",
    "sipscan",
    "pplsip",
    "sip-scan",
];

/// One reason to think a source is probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostileSignal {
    /// Placed call attempts and never registered from this address.
    ///
    /// Normal for a trunk or a click-to-dial gateway, which is why it cannot
    /// convict alone.
    NeverRegistered {
        /// Call attempts seen from the source.
        attempts: u64,
    },
    /// A `User-Agent` naming a known scanning tool.
    ScannerUserAgent {
        /// The matched tool name, as written on the wire.
        agent: String,
    },
    /// Many distinct callees from one source: an extension or number sweep.
    TargetSweep {
        /// How many distinct callees.
        distinct: usize,
    },
    /// Attempts arriving faster than a person dials.
    MachineCadence {
        /// Attempts per minute over the source's own active span.
        per_minute: u64,
    },
}

impl HostileSignal {
    /// A short, stable name for output surfaces.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::NeverRegistered { .. } => "never-registered",
            Self::ScannerUserAgent { .. } => "scanner-user-agent",
            Self::TargetSweep { .. } => "target-sweep",
            Self::MachineCadence { .. } => "machine-cadence",
        }
    }

    /// One line an operator can read without consulting the code.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::NeverRegistered { attempts } => {
                format!("{attempts} call attempt(s), never registered")
            }
            Self::ScannerUserAgent { agent } => format!("scanner user-agent {agent:?}"),
            Self::TargetSweep { distinct } => format!("{distinct} distinct callees"),
            Self::MachineCadence { per_minute } => format!("{per_minute} attempts/min"),
        }
    }
}

/// One source, and what it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostileSource {
    /// Where it came from.
    pub addr: IpAddr,
    /// The signals it tripped, in a stable order.
    pub signals: Vec<HostileSignal>,
    /// Call attempts from this source.
    pub attempts: u64,
    /// `REGISTER` requests from this source.
    pub registrations: u64,
    /// Distinct callees it tried.
    pub distinct_targets: usize,
    /// First and last time it was seen.
    pub first_seen: DateTime<Utc>,
    /// Last time it was seen.
    pub last_seen: DateTime<Utc>,
    /// Whether ANY dialog from this source completed normally.
    ///
    /// Counter-evidence, carried deliberately. A source that also placed a
    /// normal answered call is one a block would disconnect, and an operator
    /// deciding whether to act needs that in the same place as the accusation.
    pub had_successful_call: bool,
}

/// Per-source accumulator.
#[derive(Default)]
struct Tally {
    /// `INVITE` dialogs seen from this source.
    attempts: u64,
    /// `REGISTER` dialogs seen from this source.
    registrations: u64,
    /// Distinct callees, deduplicated -- a scanner retrying one extension is
    /// not sweeping, and a set rather than a count is what tells them apart.
    targets: BTreeSet<String>,
    /// Scanner user-agents this source sent, deduplicated.
    agents: BTreeSet<String>,
    /// Earliest activity, for the cadence span.
    first: Option<DateTime<Utc>>,
    /// Latest activity, for the cadence span.
    last: Option<DateTime<Utc>>,
    /// Whether any call from here was answered. Counter-evidence.
    answered: bool,
}

/// Assess every source in the capture.
///
/// Returns only sources tripping at least [`MIN_SIGNALS`], ordered by signal
/// count and then by address so the output is stable.
#[must_use]
pub fn assess(dialogs: &[&SipDialog]) -> Vec<HostileSource> {
    let mut by_src: BTreeMap<IpAddr, Tally> = BTreeMap::new();

    for d in dialogs {
        let t = by_src.entry(d.src_addr).or_default();
        match d.method {
            SipMethod::Register => t.registrations += 1,
            SipMethod::Invite => {
                t.attempts += 1;
                if let Some(to) = d.to_user.as_deref()
                    && !to.is_empty()
                {
                    t.targets.insert(to.to_string());
                }
            }
            _ => {}
        }

        // A 2xx on an INVITE is the counter-evidence: this source placed a
        // call that actually connected.
        if d.method == SipMethod::Invite
            && d.messages
                .iter()
                .any(|m| matches!(m.status_code, Some(c) if (200..300).contains(&c)))
        {
            t.answered = true;
        }

        for m in &d.messages {
            // Only the source's OWN messages carry its user-agent; a response
            // traveling back names the far end.
            if m.src_addr == d.src_addr
                && let Some(ua) = m.user_agent()
            {
                let lower = ua.to_ascii_lowercase();
                if SCANNER_AGENTS.iter().any(|s| lower.contains(s)) {
                    t.agents.insert(ua.to_string());
                }
            }
        }

        t.first = Some(t.first.map_or(d.created_at, |f| f.min(d.created_at)));
        t.last = Some(t.last.map_or(d.updated_at, |l| l.max(d.updated_at)));
    }

    let mut out: Vec<HostileSource> = by_src
        .into_iter()
        .filter_map(|(addr, t)| {
            let mut signals = Vec::new();

            if t.attempts > 0 && t.registrations == 0 {
                signals.push(HostileSignal::NeverRegistered {
                    attempts: t.attempts,
                });
            }
            if let Some(agent) = t.agents.iter().next() {
                signals.push(HostileSignal::ScannerUserAgent {
                    agent: agent.clone(),
                });
            }
            if t.targets.len() >= SWEEP_DISTINCT_TARGETS {
                signals.push(HostileSignal::TargetSweep {
                    distinct: t.targets.len(),
                });
            }
            let (first, last) = (t.first?, t.last?);
            if t.attempts >= MIN_ATTEMPTS_FOR_RATE {
                let secs = (last - first).num_seconds().max(1);
                let per_minute = t.attempts.saturating_mul(60) / secs.unsigned_abs().max(1);
                if per_minute >= MACHINE_ATTEMPTS_PER_MIN {
                    signals.push(HostileSignal::MachineCadence { per_minute });
                }
            }

            if signals.len() < MIN_SIGNALS {
                return None;
            }
            Some(HostileSource {
                addr,
                signals,
                attempts: t.attempts,
                registrations: t.registrations,
                distinct_targets: t.targets.len(),
                first_seen: first,
                last_seen: last,
                had_successful_call: t.answered,
            })
        })
        .collect();

    // Most signals first; address as the tie-break so the order is stable
    // across runs over the same capture.
    out.sort_by(|a, b| {
        b.signals
            .len()
            .cmp(&a.signals.len())
            .then_with(|| a.addr.cmp(&b.addr))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::dialog::SipDialog;
    use crate::sip::parser::parse_sip;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("timestamp")
    }

    /// A real request from `src`, parsed the way the capture path parses it.
    ///
    /// Built from bytes rather than by filling in a struct: a test that
    /// constructs `SipDialog` by hand agrees with the test author, not with
    /// the parser every real input goes through.
    fn dialog(
        method: &str,
        src: &str,
        to_user: &str,
        ua: Option<&str>,
        secs: i64,
        answered: bool,
    ) -> SipDialog {
        let mut lines = vec![
            format!("{method} sip:{to_user}@example.com SIP/2.0"),
            "Via: SIP/2.0/UDP host:5060;branch=z9hG4bK1".to_string(),
            format!("From: <sip:caller@{src}>;tag=t1"),
            format!("To: <sip:{to_user}@example.com>"),
            format!("Call-ID: {method}-{to_user}-{secs}@{src}"),
            format!("CSeq: 1 {method}"),
            "Content-Length: 0".to_string(),
        ];
        if let Some(ua) = ua {
            lines.push(format!("User-Agent: {ua}"));
        }
        let raw = format!("{}\r\n\r\n", lines.join("\r\n"));
        let addr: IpAddr = src.parse().expect("src addr");
        let msg = parse_sip(
            raw.as_bytes(),
            at(secs),
            addr,
            "192.0.2.1".parse().expect("dst"),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("request parses");
        let mut d = SipDialog::new(&msg).expect("dialog");
        // The store records the seeding request too; a dialog whose messages
        // start at the first RESPONSE would hide the caller's own user-agent.
        d.messages.push(msg);
        if answered {
            let resp = format!(
                "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP host:5060;branch=z9hG4bK1\r\n\
                 From: <sip:caller@{src}>;tag=t1\r\nTo: <sip:{to_user}@example.com>;tag=t2\r\n\
                 Call-ID: {method}-{to_user}-{secs}@{src}\r\nCSeq: 1 {method}\r\n\
                 Content-Length: 0\r\n\r\n"
            );
            let rmsg = parse_sip(
                resp.as_bytes(),
                at(secs + 1),
                "192.0.2.1".parse().expect("dst"),
                addr,
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("response parses");
            d.messages.push(rmsg);
        }
        d
    }

    fn assess_owned(ds: &[SipDialog]) -> Vec<HostileSource> {
        let refs: Vec<&SipDialog> = ds.iter().collect();
        assess(&refs)
    }

    /// THE safety property. One signal must never name an address.
    ///
    /// A click-to-dial gateway places calls and never registers, which is the
    /// `NeverRegistered` signal on its own. Reporting it would put a customer's
    /// integration in a list headed "hostile".
    #[test]
    fn one_signal_alone_never_names_a_source() {
        let ds: Vec<SipDialog> = (0..3)
            .map(|i| dialog("INVITE", "198.51.100.7", "1000", None, i, true))
            .collect();
        let found = assess_owned(&ds);
        assert!(
            found.is_empty(),
            "a source with only NeverRegistered must not be reported: {found:?}"
        );
    }

    /// Two independent signals is the threshold, and here it is met by a
    /// scanner user-agent on top of never registering.
    #[test]
    fn two_signals_report_the_source_with_both() {
        let ds: Vec<SipDialog> = (0..3)
            .map(|i| {
                dialog(
                    "INVITE",
                    "198.51.100.8",
                    "1000",
                    Some("friendly-scanner 3.0"),
                    i * 30,
                    false,
                )
            })
            .collect();
        let found = assess_owned(&ds);
        assert_eq!(found.len(), 1, "expected one source, got {found:?}");
        let ids: Vec<&str> = found[0].signals.iter().map(HostileSignal::id).collect();
        assert!(ids.contains(&"never-registered"), "got {ids:?}");
        assert!(ids.contains(&"scanner-user-agent"), "got {ids:?}");
    }

    /// A sweep across many callees, plus never registering.
    #[test]
    fn sweeping_many_extensions_is_a_signal() {
        let ds: Vec<SipDialog> = (0..12)
            .map(|i| {
                dialog(
                    "INVITE",
                    "198.51.100.9",
                    &format!("10{i:02}"),
                    None,
                    i * 30,
                    false,
                )
            })
            .collect();
        let found = assess_owned(&ds);
        assert_eq!(found.len(), 1, "expected one source, got {found:?}");
        assert_eq!(found[0].distinct_targets, 12);
        assert!(
            found[0].signals.iter().any(|s| s.id() == "target-sweep"),
            "sweep must fire: {:?}",
            found[0].signals
        );
    }

    /// A registered caller doing ordinary things is never reported, however
    /// many calls it places.
    #[test]
    fn a_registered_caller_is_left_alone() {
        let mut ds = vec![dialog("REGISTER", "198.51.100.10", "user", None, 0, true)];
        for i in 0..20 {
            ds.push(dialog(
                "INVITE",
                "198.51.100.10",
                &format!("20{i:02}"),
                None,
                i * 5,
                true,
            ));
        }
        let found = assess_owned(&ds);
        assert!(
            found.iter().all(|h| h.addr.to_string() != "198.51.100.10"),
            "a registered caller must not be reported: {found:?}"
        );
    }

    /// A burst too small to be a rate must not become one by arithmetic.
    #[test]
    fn a_short_burst_does_not_manufacture_a_rate() {
        let ds: Vec<SipDialog> = (0..3)
            .map(|i| dialog("INVITE", "198.51.100.11", &format!("30{i}"), None, i, false))
            .collect();
        let found = assess_owned(&ds);
        assert!(
            found
                .iter()
                .flat_map(|h| h.signals.iter())
                .all(|s| s.id() != "machine-cadence"),
            "three attempts is not a cadence: {found:?}"
        );
    }

    /// Counter-evidence travels with the accusation.
    #[test]
    fn a_source_that_also_completed_a_call_says_so() {
        let mut ds: Vec<SipDialog> = (0..12)
            .map(|i| {
                dialog(
                    "INVITE",
                    "198.51.100.12",
                    &format!("40{i:02}"),
                    None,
                    i * 30,
                    false,
                )
            })
            .collect();
        ds.push(dialog(
            "INVITE",
            "198.51.100.12",
            "realcustomer",
            None,
            400,
            true,
        ));
        let found = assess_owned(&ds);
        assert_eq!(found.len(), 1, "expected one source, got {found:?}");
        assert!(
            found[0].had_successful_call,
            "a block here would disconnect a working call, and the report must say so"
        );
    }

    /// The far end's user-agent is not the source's.
    ///
    /// Responses travel back from the callee. Reading a user-agent off one
    /// would attribute the answering server's software to the caller — and if
    /// the answering side were a scanner-shaped UA, it would accuse the wrong
    /// address entirely.
    #[test]
    fn a_user_agent_on_a_response_is_not_the_sources() {
        let mut d = dialog("INVITE", "198.51.100.13", "1000", None, 0, false);
        let resp = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP host:5060;branch=z9hG4bK1\r\n\
             From: <sip:caller@198.51.100.13>;tag=t1\r\nTo: <sip:1000@example.com>;tag=t2\r\n\
             Call-ID: INVITE-1000-0@198.51.100.13\r\nCSeq: 1 INVITE\r\n\
             User-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n";
        let rmsg = parse_sip(
            resp.as_bytes(),
            at(1),
            "192.0.2.1".parse().expect("dst"),
            "198.51.100.13".parse().expect("src"),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("response parses");
        d.messages.push(rmsg);

        let found = assess_owned(&[d]);
        assert!(
            found
                .iter()
                .flat_map(|h| h.signals.iter())
                .all(|s| s.id() != "scanner-user-agent"),
            "a UA on a response must not be read as the source's: {found:?}"
        );
    }

    #[test]
    fn output_order_is_stable_and_worst_first() {
        let mut ds: Vec<SipDialog> = (0..12)
            .map(|i| {
                dialog(
                    "INVITE",
                    "198.51.100.20",
                    &format!("50{i:02}"),
                    Some("sipvicious"),
                    i * 30,
                    false,
                )
            })
            .collect();
        ds.extend((0..3).map(|i| {
            dialog(
                "INVITE",
                "198.51.100.21",
                "1000",
                Some("sipcli"),
                i * 30,
                false,
            )
        }));
        let found = assess_owned(&ds);
        assert_eq!(found.len(), 2, "expected two sources, got {found:?}");
        assert!(
            found[0].signals.len() >= found[1].signals.len(),
            "worst first: {found:?}"
        );
        assert_eq!(found[0].addr.to_string(), "198.51.100.20");
    }
}
