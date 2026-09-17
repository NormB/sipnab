// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-group carrier metrics: ASR, NER, ACD, PDD percentiles, MOS p10 and a
//! retransmit rate, computed in one pass over the dialog store and grouped by
//! one dimension.
//!
//! This is the rule behind the MCP `group_dialogs` tool and the REST
//! `/v1/dialogs/rates` route. It lives outside the `mcp` feature so both
//! surfaces compute the same figures the same way — a carrier reading an ASR
//! from one door and an ASR from the other must not get two answers. Every
//! figure carries the population it was computed over, and a metric whose
//! population is empty is refused with the reason rather than reported as a
//! zero: an ASR of zero over a group of registrations is not a failing trunk.

use crate::rtp::quality::MosDelay;
use crate::rtp::stream::RtpStream;
use crate::sip::dialog::SipDialog;

/// Dimensions per-group metrics accept beyond the shared
/// [`GROUPABLE`](crate::sip::dialog::GROUPABLE) list.
///
/// A strict SUPERSET of the count dimensions: everything a bare count groups
/// by, a rate groups by too, plus these three. They earn their place from the
/// metrics — "which trunk", "which customer domain" and "which hour" are the
/// questions a per-group ASR exists to answer.
pub const EXTRA_DIMENSIONS: &[&str] = &["to_domain", "hour", "next_hop"];

/// Seconds in the calendar hour the `hour` dimension buckets on.
const HOUR_SECONDS: i64 = 3600;

/// Every metric computed, with the unit it is expressed in.
///
/// One table rather than a list and a lookup beside it, so a metric cannot be
/// offered without a unit, accepted without being computed, or computed in a
/// unit the answer does not name.
pub const METRICS: &[(&str, &str)] = &[
    ("count", "dialogs"),
    ("asr", "percent"),
    ("ner", "percent"),
    ("acd", "seconds"),
    ("pdd_p50", "milliseconds"),
    ("pdd_p95", "milliseconds"),
    ("mos_p10", "mos"),
    ("retransmit_rate", "retransmissions per dialog"),
];

/// Final INVITE responses that mean the network DELIVERED the call and the far
/// end decided its fate. The numerator of NER, per ITU-T E.411.
///
/// NER separates "the network could not carry this call" from "the network
/// carried it and the callee said no". 480 and 486 are the callee unavailable
/// or busy, 600 is busy everywhere, 603 is an explicit decline, and 487 is the
/// CALLER hanging up on a call that had already reached the far end. 408 Request
/// Timeout is deliberately absent: a proxy emits it for a silent phone and an
/// unreachable next hop alike, and crediting it to the network is the exact
/// misattribution NER was defined to prevent.
const DESTINATION_DECIDED: &[u16] = &[480, 486, 487, 600, 603];

/// Decimal places every metric is rounded to. A ratio over three dialogs is not
/// accurate to fourteen places, and the population is published beside each
/// figure so a reader who wants the exact ratio divides the two integers.
const METRIC_DECIMALS: f64 = 100.0;

/// The host portion of a `host:port`, leaving a bracketed IPv6 literal intact
/// and not mistaking a bare IPv6 address's colons for a port separator.
fn host_only(host_port: &str) -> &str {
    if host_port.starts_with('[') {
        return match host_port.find(']') {
            Some(close) => &host_port[..=close],
            None => host_port,
        };
    }
    match host_port.rsplit_once(':') {
        Some((host, _)) if !host.contains(':') => host,
        _ => host_port,
    }
}

/// The group `dialog` falls into for `key`, as written on the wire (unfenced).
///
/// The three [`EXTRA_DIMENSIONS`] are handled here; every shared key defers to
/// [`dialog_group_value_raw`](crate::sip::dialog::dialog_group_value_raw), so
/// the count and rate tools cannot disagree about what `ua` or `rtp.codec`
/// means for one dialog. `None` for a key outside the offered set.
///
/// RAW, like its sibling: the sender-controlled dimensions (`to_domain` joins
/// `from.user`/`to.user`/`ua`/`rtp.codec`) come back verbatim, and the MCP
/// surface fences them before a value reaches a model. `hour` and `next_hop`
/// are sipnab's own computation and are never fenced.
pub fn group_value_raw(key: &str, dialog: &SipDialog, streams: &[&RtpStream]) -> Option<String> {
    match key {
        // The To URI's host, written by whoever sent the request.
        "to_domain" => Some(
            dialog
                .to_host
                .as_deref()
                .map_or("(none)", host_only)
                .to_string(),
        ),
        // The calendar hour the dialog opened in, aligned to the epoch (the
        // reason `timeline_buckets` aligns there): two captures of one window
        // then land on the same boundaries and lay side by side.
        "hour" => Some(
            chrono::DateTime::from_timestamp(
                dialog
                    .created_at
                    .timestamp()
                    .div_euclid(HOUR_SECONDS)
                    .saturating_mul(HOUR_SECONDS),
                0,
            )
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        // Where the dialog's opening message was addressed on the wire — read
        // off the IP and transport headers, so it is sipnab's observation
        // rather than anything a peer claimed.
        "next_hop" => Some(format!("{}:{}", dialog.dst_addr, dialog.dst_port)),
        _ => crate::sip::dialog::dialog_group_value_raw(key, dialog, streams),
    }
}

/// The populations a group's metrics were computed over, published beside the
/// figures so a reader can check every ratio against its denominator (and
/// recompute the exact one the two-decimal rounding dropped). Each surface
/// renders these into its own response shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Population {
    /// Every dialog that fell in the group.
    pub dialogs: usize,
    /// INVITE dialogs that reached a final response.
    pub seizures: usize,
    /// Seizures answered with a 2xx.
    pub answered: usize,
    /// Seizures the far end decided (answered or an E.411 destination code).
    pub delivered: usize,
    /// Calls both answered and torn down inside the capture (the ACD base).
    pub completed_calls: usize,
    /// Dialogs a post-dial delay was measured for.
    pub pdd_measured: usize,
    /// Dialogs a grounded MOS was scored for.
    pub mos_grounded_dialogs: usize,
    /// Retransmitted messages summed across the group.
    pub retransmits: u64,
}

/// Everything one group needs, accumulated in one pass over the store.
///
/// Populations are counted rather than derived afterwards because most cannot
/// be recovered from the others: "answered" and "seizures" are not "count"
/// minus anything, since a group of REGISTER dialogs has a count and no
/// seizures at all.
#[derive(Debug, Clone, Default)]
pub struct GroupAccumulator {
    /// Every dialog that fell in this group.
    dialogs: usize,
    /// INVITE dialogs that reached a final response.
    seizures: usize,
    /// Seizures answered with a 2xx.
    answered: usize,
    /// Seizures whose final response says the far end decided.
    delivered: usize,
    /// Conversation milliseconds summed over answered-and-ended calls.
    conversation_ms_total: i64,
    /// How many calls contributed to `conversation_ms_total`.
    completed_calls: usize,
    /// Every measured post-dial delay, in milliseconds.
    pdd_ms: Vec<f64>,
    /// One grounded MOS per dialog: the worst across its scorable streams.
    mos: Vec<f64>,
    /// Retransmitted messages summed across the group.
    retransmits: u64,
}

impl GroupAccumulator {
    /// How many dialogs have folded into this group.
    #[must_use]
    pub fn dialogs(&self) -> usize {
        self.dialogs
    }

    /// The populations behind this group's metrics, for a surface to publish
    /// beside the figures.
    #[must_use]
    pub fn population(&self) -> Population {
        Population {
            dialogs: self.dialogs,
            seizures: self.seizures,
            answered: self.answered,
            delivered: self.delivered,
            completed_calls: self.completed_calls,
            pdd_measured: self.pdd_ms.len(),
            mos_grounded_dialogs: self.mos.len(),
            retransmits: self.retransmits,
        }
    }

    /// Fold one dialog and its streams into this group.
    pub fn add(&mut self, dialog: &SipDialog, streams: &[&RtpStream], delay: MosDelay<'_>) {
        self.dialogs += 1;
        self.retransmits += u64::from(dialog.timing.total_retransmits());

        // A seizure is an INVITE that got an answer of some kind. Both halves
        // matter: a REGISTER is not a call attempt, and an INVITE still ringing
        // when the capture ended has not failed.
        if dialog.method == crate::sip::method::SipMethod::Invite
            && let Some(code) = dialog.final_status_code()
        {
            self.seizures += 1;
            if (200..300).contains(&code) {
                self.answered += 1;
                self.delivered += 1;
            } else if DESTINATION_DECIDED.contains(&code) {
                self.delivered += 1;
            }
        }

        if let Some(ms) = dialog.timing.conversation_ms() {
            self.conversation_ms_total = self.conversation_ms_total.saturating_add(ms);
            self.completed_calls += 1;
        }
        if let Some(ms) = dialog.timing.pdd_ms() {
            self.pdd_ms.push(ms as f64);
        }

        // Only streams whose codec has a real impairment factor, and the WORST
        // of them, matching what `rtp.mos` means in the filter DSL. Scoring an
        // unpublished codec would put a placeholder into a percentile.
        if let Some(worst) = streams
            .iter()
            .filter(|s| crate::rtp::quality::mos_is_grounded(s.codec.as_deref()))
            .map(|s| delay.score(s))
            .reduce(f64::min)
        {
            self.mos.push(worst);
        }
    }

    /// This group's value for `metric`.
    ///
    /// `None` for a metric with no extractor — the caller raises that as an
    /// internal error rather than reporting a silent zero. `Some(Err(why))` is
    /// the grounding refusal: the metric exists and this group's population
    /// cannot support it, and `why` names the population that was missing.
    #[must_use]
    pub fn value_of(&self, metric: &str) -> Option<Result<f64, String>> {
        /// The refusal an empty population produces, phrased as "what was
        /// missing" rather than "no data".
        fn empty(reason: &str) -> Option<Result<f64, String>> {
            Some(Err(reason.to_string()))
        }

        let ratio =
            |numerator: usize, denominator: usize| numerator as f64 * 100.0 / denominator as f64;
        let seizure_refusal = "no INVITE in this group reached a final response, so nothing in \
                               it was a decided call attempt";

        Some(Ok(match metric {
            "count" => self.dialogs as f64,
            "asr" => {
                if self.seizures == 0 {
                    return empty(seizure_refusal);
                }
                ratio(self.answered, self.seizures)
            }
            "ner" => {
                if self.seizures == 0 {
                    return empty(seizure_refusal);
                }
                ratio(self.delivered, self.seizures)
            }
            "acd" => {
                if self.completed_calls == 0 {
                    return empty(
                        "no call in this group was both answered and torn down inside the \
                         capture, so no conversation was timed",
                    );
                }
                self.conversation_ms_total as f64 / self.completed_calls as f64 / 1000.0
            }
            "pdd_p50" | "pdd_p95" => {
                let p = if metric == "pdd_p50" { 50.0 } else { 95.0 };
                let mut sorted = self.pdd_ms.clone();
                crate::sort::sort_by_dyn(&mut sorted, &mut f64::total_cmp);
                match percentile_nearest_rank(&sorted, p) {
                    Some(v) => v,
                    None => {
                        return empty(
                            "no INVITE in this group was followed by a 180 or 183, so post-dial \
                             delay was never measured",
                        );
                    }
                }
            }
            "mos_p10" => {
                let mut sorted = self.mos.clone();
                crate::sort::sort_by_dyn(&mut sorted, &mut f64::total_cmp);
                match percentile_nearest_rank(&sorted, 10.0) {
                    Some(v) => v,
                    None => {
                        return empty(
                            "no stream in this group uses a codec with a published or \
                             operator-declared impairment factor, so every MOS here would be a \
                             placeholder rather than an estimate",
                        );
                    }
                }
            }
            // Never refused: a group exists because a dialog fell into it, so
            // the denominator is at least one. It is a FLOOR — a dialog past
            // `MAX_SEEN_CSEQ_PER_DIALOG` stops recognizing new retransmissions —
            // and it counts retransmitted messages per dialog.
            "retransmit_rate" => self.retransmits as f64 / self.dialogs.max(1) as f64,
            _ => return None,
        }))
    }
}

/// The value at percentile `p` (0-100) of `sorted`, by nearest rank.
///
/// No interpolation, deliberately. An interpolated p95 returns a number no call
/// experienced, and these percentiles are quoted back to a carrier as evidence
/// about real calls; nearest rank always names an observed sample. `None` for
/// an empty slice — a percentile of nothing is not zero.
pub(crate) fn percentile_nearest_rank<T: Copy>(sorted: &[T], p: f64) -> Option<T> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (p / 100.0 * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted.get(rank.min(sorted.len()) - 1).copied()
}

/// `value` rounded to two decimal places, with a non-finite result reported as
/// absent.
///
/// A NaN or an infinity is not a measurement, and `serde_json` cannot carry one
/// anyway — it would serialize as `null` with nothing saying why. Rounding is
/// where both are caught.
#[must_use]
pub fn rounded(value: f64) -> Option<f64> {
    value
        .is_finite()
        .then(|| (value * METRIC_DECIMALS).round() / METRIC_DECIMALS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use chrono::{TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn parse(
        start: &str,
        call_id: &str,
        cseq: &str,
        to_tag: bool,
    ) -> crate::sip::message::SipMessage {
        let to = if to_tag {
            "To: <sip:bob@example.com>;tag=t2"
        } else {
            "To: <sip:bob@example.com>"
        };
        let raw = build_sip(
            start,
            &[
                "From: <sip:alice@example.com>;tag=t1",
                to,
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse")
    }

    /// Build an answered or failed INVITE dialog under one Call-ID.
    fn call(call_id: &str, final_code: u16) -> SipDialog {
        let invite = parse(
            "INVITE sip:bob@example.com SIP/2.0",
            call_id,
            "1 INVITE",
            false,
        );
        let mut d = SipDialog::new(&invite).expect("dialog");
        let resp = parse(
            &format!("SIP/2.0 {final_code} X"),
            call_id,
            "1 INVITE",
            true,
        );
        crate::sip::dialog::update_state(&mut d, &resp);
        d.messages.push(resp);
        d
    }

    /// ASR is answered seizures over all seizures, as a percent, and NER credits
    /// a far-end decline (486) that ASR does not. Two answered and one busy
    /// gives ASR 66.67 and NER 100 over three seizures.
    #[test]
    fn asr_counts_answers_and_ner_credits_the_far_end_decline() {
        let ss = crate::rtp::stream_store::StreamStore::new(100);
        let delay = MosDelay::from_capture(&ss);
        let mut acc = GroupAccumulator::default();
        for id in ["a@h", "b@h"] {
            acc.add(&call(id, 200), &[], delay);
        }
        acc.add(&call("c@h", 486), &[], delay);

        assert_eq!(acc.dialogs(), 3);
        assert_eq!(acc.value_of("asr"), Some(Ok(200.0 / 3.0)));
        // NER credits the busy: the network delivered all three, the callee
        // declined one, so every seizure was network-effective.
        assert_eq!(acc.value_of("ner"), Some(Ok(100.0)));
    }

    /// A group with no seizures refuses ASR with the reason rather than
    /// reporting a zero that reads as a failing trunk.
    #[test]
    fn asr_over_no_seizures_is_refused_not_zero() {
        let ss = crate::rtp::stream_store::StreamStore::new(100);
        let mut acc = GroupAccumulator::default();
        // A REGISTER-style dialog: no INVITE, so no seizure.
        acc.add(
            &{
                let reg = parse(
                    "REGISTER sip:example.com SIP/2.0",
                    "r@h",
                    "1 REGISTER",
                    false,
                );
                SipDialog::new(&reg).expect("dialog")
            },
            &[],
            MosDelay::from_capture(&ss),
        );
        match acc.value_of("asr") {
            Some(Err(why)) => assert!(why.contains("final response"), "got {why}"),
            other => panic!("expected a grounding refusal, got {other:?}"),
        }
    }

    /// An unknown metric name has no extractor, which the caller surfaces as an
    /// internal error rather than a silent zero.
    #[test]
    fn an_unknown_metric_has_no_extractor() {
        let acc = GroupAccumulator::default();
        assert_eq!(acc.value_of("throughput"), None);
    }

    /// Nearest rank names a sample that was actually observed, at both ends.
    ///
    /// An interpolating percentile would answer 25 for the median of
    /// `[10, 20, 30, 40]`, a post-dial delay no call in the set ever had — and
    /// these figures are quoted back to a carrier as evidence about real calls.
    #[test]
    fn percentile_nearest_rank_names_an_observed_sample() {
        let samples = [10.0, 20.0, 30.0, 40.0];
        assert_eq!(percentile_nearest_rank(&samples, 50.0), Some(20.0));
        assert_eq!(percentile_nearest_rank(&samples, 95.0), Some(40.0));
        // p10 of four samples rounds up to rank 1: the worst one, not a
        // fraction of it, and not an index before the slice.
        assert_eq!(percentile_nearest_rank(&samples, 10.0), Some(10.0));
        assert_eq!(percentile_nearest_rank(&samples, 0.0), Some(10.0));
        assert_eq!(
            percentile_nearest_rank::<f64>(&[], 50.0),
            None,
            "a percentile of nothing is not zero"
        );
    }

    /// A port is stripped and an address is not. The IPv6 arm is the one that
    /// matters: `[2001:db8::1]` split at its last colon yields `[2001:db8:`,
    /// which is neither a host nor a group anybody could act on.
    #[test]
    fn host_only_strips_a_port_and_keeps_an_address() {
        assert_eq!(host_only("example.com:5060"), "example.com");
        assert_eq!(host_only("example.com"), "example.com");
        assert_eq!(host_only("[2001:db8::1]:5060"), "[2001:db8::1]");
        assert_eq!(host_only("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(host_only("2001:db8::1"), "2001:db8::1");
    }

    /// A value that is not a finite number never reaches the answer as one.
    #[test]
    fn rounded_refuses_a_value_that_is_not_a_number() {
        assert_eq!(rounded(66.66666), Some(66.67));
        assert_eq!(rounded(f64::NAN), None);
        assert_eq!(rounded(f64::INFINITY), None);
    }
}
