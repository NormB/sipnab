// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The call records a fleet member pushes to its center.
//!
//! A member ([`super::fleet_member`]) looks at the dialogs it holds, and for
//! each ended one that `[fleet] call_push` selects it sends one record. The
//! record's `call` is the member's own REST answer for that dialog
//! ([`crate::output::api::dialog_answer`]), so the center and the member
//! cannot disagree about a call.
//!
//! # What is here
//!
//! The rules, each a function of its arguments: which calls the push rule
//! selects ([`selected_by`]), when a call is due ([`call_due`]), how many
//! exceptions a second leave the member ([`RateCap`]), the line the center
//! reads ([`call_line`]), how lines are grouped into deliveries
//! ([`batches`]), and the sealed file a delivery waits in ([`seal_batch`],
//! [`open_batch`]). A record waits on the member's disk only inside a sealed
//! file, under the key in `[fleet] spool_key_file`.

use chrono::{DateTime, Utc};

use super::fleet_seal::{Draw, Keys, MasterKey, SealError};

/// The value of `kind` in a call record.
pub const KIND_CALL: &str = "call";

/// The default most exception records a member pushes a second.
pub const DEFAULT_EXCEPTION_MAX_PER_SEC: u32 = 10;

/// The largest `[fleet] exception_max_per_sec`.
pub const MAX_EXCEPTION_MAX_PER_SEC: u32 = 10_000;

/// How many seconds of unused allowance the cap keeps.
///
/// Not a setting: the member looks at its dialogs every few seconds, so the
/// calls of that many seconds arrive at the cap together.
pub const CAP_BURST_SECS: u32 = 10;

/// The most records in one delivery.
pub const MAX_DELIVERY_RECORDS: usize = 500;

/// The most bytes of records in one delivery: half the center's body limit.
pub const MAX_DELIVERY_BYTES: usize = 2 * 1024 * 1024;

/// What the name of a sealed delivery in a spool ends in.
const BATCH_SUFFIX: &str = ".sealed";

/// Which ended calls a member pushes: `[fleet] call_push`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPush {
    /// Calls that failed, were degraded or raised a finding.
    Exceptions,
    /// Every call.
    All,
    /// No call.
    None,
}

impl CallPush {
    /// The rule `text` names.
    ///
    /// # Errors
    ///
    /// `text` is not `exceptions`, `all` or `none`. The message names the
    /// key and the three values.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "exceptions" => Ok(Self::Exceptions),
            "all" => Ok(Self::All),
            "none" => Ok(Self::None),
            other => Err(format!(
                "[fleet] call_push {:?} is not one of \"exceptions\", \"all\", \"none\"",
                other.chars().take(32).collect::<String>()
            )),
        }
    }

    /// The value that names this rule.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exceptions => "exceptions",
            Self::All => "all",
            Self::None => "none",
        }
    }
}

/// What the push rule reads of one ended call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CallFacts {
    /// The call ended on a final error response.
    pub failed: bool,
    /// Audio flowed one way only.
    pub one_way_audio: bool,
    /// Media was negotiated and none was seen.
    pub no_media: bool,
    /// The media came from another address than the SDP named.
    pub nat_mismatch: bool,
    /// The two directions differ in codec, packet time, payload type or
    /// duration.
    pub asymmetry: bool,
    /// The media started late.
    pub late_media: bool,
    /// The diagnosis wrote this many findings.
    pub findings: usize,
}

impl CallFacts {
    /// The facts of a call that `failed` or did not, under `diagnosis`.
    #[must_use]
    pub fn of(failed: bool, diagnosis: &crate::rtp::diagnosis::MediaDiagnosis) -> Self {
        Self {
            failed,
            one_way_audio: diagnosis.one_way_audio,
            no_media: diagnosis.no_media,
            nat_mismatch: diagnosis.nat_mismatch,
            asymmetry: diagnosis.codec_asymmetry.is_some()
                || diagnosis.ptime_asymmetry.is_some()
                || diagnosis.payload_type_asymmetry.is_some()
                || diagnosis.duration_asymmetry.is_some(),
            late_media: diagnosis.late_media.is_some(),
            findings: diagnosis.hints.len(),
        }
    }

    /// Why this call is an exception, by the first fact that makes it one,
    /// or `None` for a call with nothing to report.
    #[must_use]
    pub fn exception(&self) -> Option<&'static str> {
        [
            (self.failed, "failed"),
            (self.one_way_audio, "one_way_audio"),
            (self.no_media, "no_media"),
            (self.nat_mismatch, "nat_mismatch"),
            (self.asymmetry, "asymmetry"),
            (self.late_media, "late_media"),
            (self.findings > 0, "finding"),
        ]
        .into_iter()
        .find_map(|(holds, name)| holds.then_some(name))
    }
}

/// What selected a call for the push under `rule`: `"all"`, the exception's
/// reason, or `None` when the call is not pushed.
#[must_use]
pub fn selected_by(rule: CallPush, facts: &CallFacts) -> Option<&'static str> {
    match rule {
        CallPush::None => None,
        CallPush::All => Some("all"),
        CallPush::Exceptions => facts.exception(),
    }
}

/// Whether a call is pushed now.
///
/// A call is due once it has ended and been quiet for `settle`, and it is
/// not pushed again at the `updated_at` it was pushed at. A call that
/// changes after its push (a late `BYE`, a `2xx` that crossed a `CANCEL`) is
/// due again with what it became.
#[must_use]
pub fn call_due(
    ended: bool,
    updated_at: DateTime<Utc>,
    now: DateTime<Utc>,
    settle: chrono::TimeDelta,
    pushed_at: Option<DateTime<Utc>>,
) -> bool {
    ended && now - updated_at >= settle && pushed_at != Some(updated_at)
}

/// [`call_due`] for a member that has seen the call as it stands since
/// `seen_since`: the call is due only when it has also stood unchanged in
/// this member's sight for `settle`. A capture read from a file carries
/// times long past, and a call in it may still change as the file is read.
#[must_use]
pub fn call_due_seen(
    ended: bool,
    updated_at: DateTime<Utc>,
    seen_since: DateTime<Utc>,
    now: DateTime<Utc>,
    settle: chrono::TimeDelta,
    pushed_at: Option<DateTime<Utc>>,
) -> bool {
    now - seen_since >= settle && call_due(ended, updated_at, now, settle, pushed_at)
}

/// The calls a member has pushed, by Call-ID, with the `updated_at` each was
/// pushed at.
#[derive(Debug, Default)]
pub struct Pushed {
    /// Call-ID to the `updated_at` its record was built at.
    at: std::collections::HashMap<String, DateTime<Utc>>,
    /// Call-ID of an ended call to the `updated_at` it was last seen at, and
    /// since when the member has seen it stand so.
    seen: std::collections::HashMap<String, (DateTime<Utc>, DateTime<Utc>)>,
}

impl Pushed {
    /// The `updated_at` the call was pushed at, if it was.
    #[must_use]
    pub fn at(&self, call_id: &str) -> Option<DateTime<Utc>> {
        self.at.get(call_id).copied()
    }

    /// Note at `now` that the call stands at `updated_at`, and return since
    /// when this member has seen it stand so.
    pub fn see(
        &mut self,
        call_id: &str,
        updated_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> DateTime<Utc> {
        let since = self.seen_since_at(call_id, updated_at, now);
        if since == now {
            self.seen.insert(call_id.to_string(), (updated_at, now));
        }
        since
    }

    /// [`Self::see`] without noting anything.
    #[must_use]
    pub fn seen_since_at(
        &self,
        call_id: &str,
        updated_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> DateTime<Utc> {
        match self.seen.get(call_id) {
            Some((at, since)) if *at == updated_at => *since,
            _ => now,
        }
    }

    /// Record that the call was pushed as it stood at `updated_at`.
    pub fn mark(&mut self, call_id: &str, updated_at: DateTime<Utc>) {
        self.at.insert(call_id.to_string(), updated_at);
    }

    /// Forget every call `held` no longer answers for, so the record is
    /// bounded by the dialogs the member holds.
    pub fn prune(&mut self, held: impl Fn(&str) -> bool) {
        self.at.retain(|call_id, _| held(call_id));
        self.seen.retain(|call_id, _| held(call_id));
    }

    /// How many calls are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.at.len()
    }

    /// Whether no call is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.at.is_empty()
    }
}

/// The exception cap: `[fleet] exception_max_per_sec`, with the allowance of
/// at most [`CAP_BURST_SECS`] seconds kept.
#[derive(Debug, Clone, PartialEq)]
pub struct RateCap {
    /// Records a second.
    per_sec: u32,
    /// Records the cap admits now.
    allowance: f64,
    /// When the allowance was last counted, since the member started.
    counted_at: std::time::Duration,
    /// Records the cap refused.
    dropped: u64,
}

impl RateCap {
    /// A cap of `per_sec` records a second, holding one second's allowance.
    #[must_use]
    pub fn new(per_sec: u32) -> Self {
        Self {
            per_sec,
            allowance: f64::from(per_sec),
            counted_at: std::time::Duration::ZERO,
            dropped: 0,
        }
    }

    /// Whether one more record passes at `at`, a time since the member
    /// started. A refused record is counted.
    pub fn admit(&mut self, at: std::time::Duration) -> bool {
        if at > self.counted_at {
            let earned = f64::from(self.per_sec) * (at - self.counted_at).as_secs_f64();
            let most = f64::from(self.per_sec) * f64::from(CAP_BURST_SECS);
            self.allowance = (self.allowance + earned).min(most);
            self.counted_at = at;
        }
        if self.allowance >= 1.0 {
            self.allowance -= 1.0;
            true
        } else {
            self.dropped = self.dropped.saturating_add(1);
            false
        }
    }

    /// Records the cap refused since the member started.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// One call a look selected: what selected it, and the call as the member's
/// REST API answers for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Selected {
    /// `"all"`, or the exception's reason.
    pub selected_by: &'static str,
    /// The dialog in full ([`crate::output::api::dialog_answer`]).
    pub call: serde_json::Value,
}

/// What a member has done with its ended calls since it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct CallCounts {
    /// Calls the push rule selected and the cap let through.
    pub selected: u64,
    /// Exceptions the cap refused.
    pub dropped_by_cap: u64,
    /// Calls left out because one record is over a delivery's size, or
    /// would not serialize.
    pub left_out: u64,
    /// Calls written to the spool.
    pub spooled: u64,
}

/// A member's push of its ended calls: the rule, the cap, and which calls
/// it has pushed.
#[derive(Debug)]
pub struct CallPusher {
    /// `[fleet] call_push`.
    rule: CallPush,
    /// The exception cap.
    cap: RateCap,
    /// The calls pushed, so each is pushed once per state it ended in.
    pushed: Pushed,
    /// What happened to the calls so far.
    counts: CallCounts,
}

impl CallPusher {
    /// A push under `rule`, with exceptions capped at `per_sec` a second.
    #[must_use]
    pub fn new(rule: CallPush, per_sec: u32) -> Self {
        Self {
            rule,
            cap: RateCap::new(per_sec),
            pushed: Pushed::default(),
            counts: CallCounts::default(),
        }
    }

    /// The counts so far.
    #[must_use]
    pub fn counts(&self) -> CallCounts {
        CallCounts {
            dropped_by_cap: self.cap.dropped(),
            ..self.counts
        }
    }

    /// How many calls the push remembers: those it pushed, passed over or
    /// refused, while the store holds them.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.pushed.len()
    }

    /// Count `n` calls written to the spool, and `left_out` that were not.
    pub fn spooled(&mut self, n: u64, left_out: u64) {
        self.counts.spooled = self.counts.spooled.saturating_add(n);
        self.counts.left_out = self.counts.left_out.saturating_add(left_out);
    }

    /// Look at the dialogs once: every call that is due at `now`
    /// ([`call_due`], with `settle`) and that the rule selects, in the
    /// store's order. `elapsed` is the time since the member started, which
    /// the cap counts in. A call the rule passes over or the cap refuses is
    /// not looked at again until it changes.
    pub fn look(
        &mut self,
        dialogs: &crate::sip::dialog_store::DialogStore,
        streams: &crate::rtp::stream_store::StreamStore,
        now: DateTime<Utc>,
        elapsed: std::time::Duration,
        settle: chrono::TimeDelta,
    ) -> Vec<Selected> {
        use crate::sip::dialog::DialogState;
        self.pushed.prune(|call_id| dialogs.get(call_id).is_some());
        let mut out = Vec::new();
        for dialog in dialogs.iter() {
            let call_id = dialog.call_id.as_str();
            let ended = dialog.state().is_final();
            if !ended {
                continue;
            }
            let seen = self.pushed.see(call_id, dialog.updated_at, now);
            let pushed_at = self.pushed.at(call_id);
            if !call_due_seen(ended, dialog.updated_at, seen, now, settle, pushed_at) {
                continue;
            }
            // Decided now, whatever the decision: a call is looked at once
            // per state it ended in.
            self.pushed.mark(call_id, dialog.updated_at);
            let (claimed, diagnosis) =
                crate::output::api::diagnose_dialog(dialog, call_id, streams);
            let failed = *dialog.state() == DialogState::Failed;
            let Some(selected_by) = selected_by(self.rule, &CallFacts::of(failed, &diagnosis))
            else {
                continue;
            };
            if self.rule == CallPush::Exceptions && !self.cap.admit(elapsed) {
                continue;
            }
            let answer =
                crate::output::api::dialog_answer_of(dialog, &claimed, &diagnosis, streams);
            match serde_json::from_str(&answer) {
                Ok(call) => {
                    self.counts.selected = self.counts.selected.saturating_add(1);
                    out.push(Selected { selected_by, call });
                }
                Err(_) => self.counts.left_out = self.counts.left_out.saturating_add(1),
            }
        }
        out
    }
}

/// One call record as the line the center reads, newline included.
#[must_use]
pub fn call_line(
    stream: &str,
    seq: u64,
    sent_at: DateTime<Utc>,
    selected_by: &str,
    call: &serde_json::Value,
) -> String {
    let mut line = serde_json::json!({
        "schema_version": super::fleet_center::RECORD_SCHEMA_VERSION,
        "kind": KIND_CALL,
        "stream": stream,
        "seq": seq,
        "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        "selected_by": selected_by,
        "call": call,
    })
    .to_string();
    line.push('\n');
    line
}

/// `lines` grouped into deliveries of at most `max_records` lines and
/// `max_bytes` bytes each, in order, and how many lines were left out
/// because one alone is over `max_bytes`.
#[must_use]
pub fn batches(
    lines: Vec<String>,
    max_records: usize,
    max_bytes: usize,
) -> (Vec<Vec<String>>, usize) {
    let mut out: Vec<Vec<String>> = Vec::new();
    let (mut bytes, mut left_out) = (0usize, 0usize);
    for line in lines {
        if line.len() > max_bytes {
            left_out += 1;
            continue;
        }
        let fits = out
            .last()
            .is_some_and(|batch| batch.len() < max_records && bytes + line.len() <= max_bytes);
        if !fits {
            out.push(Vec::new());
            bytes = 0;
        }
        bytes += line.len();
        if let Some(batch) = out.last_mut() {
            batch.push(line);
        }
    }
    (out, left_out)
}

/// The spool file of the delivery whose first record is at `seq`:
/// zero-padded like a heartbeat's, so name order is position order.
#[must_use]
pub fn batch_file_name(seq: u64) -> String {
    format!("{seq:020}{BATCH_SUFFIX}")
}

/// Whether `name` is a sealed delivery in a spool.
#[must_use]
pub fn is_batch_file(name: &str) -> bool {
    !name.starts_with('.') && name.len() > BATCH_SUFFIX.len() && name.ends_with(BATCH_SUFFIX)
}

/// The sealed file that holds `lines`, one record each, under `key`.
///
/// # Errors
///
/// `source` failed, a line is over the sealed layer's record bound, or the
/// cipher failed.
pub fn seal_batch(key: &MasterKey, lines: &[String], source: Draw<'_>) -> Result<Vec<u8>, String> {
    use super::fleet_seal::{Kind, LogSealer};
    let (mut sealer, header) = LogSealer::new(key, Kind::Spool, source)?;
    let mut out = header.to_vec();
    for line in lines {
        out.extend(sealer.record(line.as_bytes())?);
    }
    out.extend(sealer.base_end()?);
    Ok(out)
}

/// The lines a sealed delivery holds, joined as the body the center reads.
///
/// # Errors
///
/// A [`SealError`]: the bytes are not a sealed delivery, the key is not in
/// `keys`, or the file was modified or cut short. A delivery is written
/// whole before it is renamed into the spool, so one that ends in a partly
/// written record is refused as truncated.
pub fn open_batch(bytes: &[u8], keys: &Keys) -> Result<Vec<u8>, SealError> {
    let log = super::fleet_seal::open_log(bytes, keys, super::fleet_seal::Kind::Spool)?;
    if log.torn_tail {
        return Err(SealError::Truncated);
    }
    Ok(log.records.concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn success_each_push_rule_parses_from_its_name() -> TestResult {
        for rule in [CallPush::Exceptions, CallPush::All, CallPush::None] {
            assert_eq!(CallPush::parse(rule.name())?, rule, "{}", rule.name());
        }
        Ok(())
    }

    #[test]
    fn failure_an_unknown_push_rule_names_the_key_and_the_three_values() {
        let shown: String = "x".repeat(80);
        for text in ["", "ALL", "exception", " all", shown.as_str()] {
            let e = CallPush::parse(text).err().unwrap_or_default();
            assert!(
                e.starts_with("[fleet] call_push ")
                    && e.ends_with("is not one of \"exceptions\", \"all\", \"none\""),
                "{text:?}: '{e}'"
            );
            assert!(e.len() < 150, "a long value is cut: '{e}'");
        }
    }

    /// Facts with only `set` applied to a clean call.
    fn facts(set: impl Fn(&mut CallFacts)) -> CallFacts {
        let mut facts = CallFacts::default();
        set(&mut facts);
        facts
    }

    #[test]
    fn success_a_failed_call_is_an_exception_named_failed() {
        assert_eq!(
            facts(|f| f.failed = true).exception(),
            Some("failed"),
            "success a failed call is an exception named failed"
        );
    }

    #[test]
    fn edge_a_call_with_nothing_to_report_is_no_exception() {
        assert_eq!(
            CallFacts::default().exception(),
            None,
            "edge a call with nothing to report is no exception"
        );
    }

    #[test]
    fn success_each_media_fact_alone_is_an_exception_named_for_it() {
        /// A fact's name and how to set it.
        type Case = (&'static str, fn(&mut CallFacts));
        let cases: [Case; 6] = [
            ("one_way_audio", |f| f.one_way_audio = true),
            ("no_media", |f| f.no_media = true),
            ("nat_mismatch", |f| f.nat_mismatch = true),
            ("asymmetry", |f| f.asymmetry = true),
            ("late_media", |f| f.late_media = true),
            ("finding", |f| f.findings = 1),
        ];
        for (name, set) in cases {
            assert_eq!(
                facts(set).exception(),
                Some(name),
                "success each media fact alone is an exception named for it"
            );
        }
    }

    #[test]
    fn edge_a_call_with_several_facts_is_named_by_the_first_in_order() {
        let all = CallFacts {
            failed: true,
            one_way_audio: true,
            no_media: true,
            nat_mismatch: true,
            asymmetry: true,
            late_media: true,
            findings: 3,
        };
        assert_eq!(
            all.exception(),
            Some("failed"),
            "edge a call with several facts is named by the first in order"
        );
        let media = CallFacts {
            failed: false,
            ..all
        };
        assert_eq!(
            media.exception(),
            Some("one_way_audio"),
            "edge a call with several facts is named by the first in order"
        );
        let late = CallFacts {
            late_media: true,
            findings: 3,
            ..CallFacts::default()
        };
        assert_eq!(
            late.exception(),
            Some("late_media"),
            "edge a call with several facts is named by the first in order"
        );
    }

    #[test]
    fn success_the_rule_all_selects_a_call_with_nothing_to_report() {
        assert_eq!(
            selected_by(CallPush::All, &CallFacts::default()),
            Some("all"),
            "success the rule all selects a call with nothing to report"
        );
    }

    #[test]
    fn failure_the_rule_none_selects_no_call_not_even_a_failed_one() {
        let failed = facts(|f| f.failed = true);
        assert_eq!(
            selected_by(CallPush::None, &failed),
            None,
            "failure the rule none selects no call not even a failed one"
        );
        assert_eq!(
            selected_by(CallPush::None, &CallFacts::default()),
            None,
            "failure the rule none selects no call not even a failed one"
        );
    }

    #[test]
    fn success_the_rule_exceptions_selects_an_exception_by_its_reason() {
        let one_way = facts(|f| f.one_way_audio = true);
        assert_eq!(
            selected_by(CallPush::Exceptions, &one_way),
            Some("one_way_audio"),
            "success the rule exceptions selects an exception by its reason"
        );
    }

    #[test]
    fn failure_the_rule_exceptions_leaves_a_call_with_nothing_to_report() {
        assert_eq!(
            selected_by(CallPush::Exceptions, &CallFacts::default()),
            None,
            "failure the rule exceptions leaves a call with nothing to report"
        );
    }

    /// A time `secs` seconds after a fixed start.
    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::seconds(1_800_000_000 + secs)
    }

    /// Five seconds, the settle time the tests use.
    const SETTLE: chrono::TimeDelta = chrono::TimeDelta::seconds(5);

    #[test]
    fn success_an_ended_call_quiet_for_the_settle_time_is_due() {
        assert!(
            call_due(true, at(0), at(60), SETTLE, None),
            "success an ended call quiet for the settle time is due"
        );
    }

    #[test]
    fn failure_a_call_that_has_not_ended_is_not_due_however_quiet() {
        assert!(
            !call_due(false, at(0), at(86_400), SETTLE, None),
            "failure a call that has not ended is not due however quiet"
        );
    }

    #[test]
    fn failure_an_ended_call_inside_the_settle_time_is_not_due() {
        assert!(
            !call_due(true, at(0), at(4), SETTLE, None),
            "failure an ended call inside the settle time is not due"
        );
    }

    #[test]
    fn failure_a_call_pushed_at_this_updated_at_is_not_due_again() {
        assert!(
            !call_due(true, at(0), at(60), SETTLE, Some(at(0))),
            "failure a call pushed at this updated at is not due again"
        );
    }

    #[test]
    fn edge_a_call_quiet_for_exactly_the_settle_time_is_due() {
        assert!(
            call_due(true, at(0), at(5), SETTLE, None),
            "edge a call quiet for exactly the settle time is due"
        );
    }

    #[test]
    fn edge_a_call_that_changed_after_its_push_is_due_again() {
        assert!(
            call_due(true, at(30), at(60), SETTLE, Some(at(0))),
            "edge a call that changed after its push is due again"
        );
    }

    #[test]
    fn success_a_marked_call_is_recorded_at_its_updated_at() {
        let mut pushed = Pushed::default();
        assert_eq!(
            pushed.at("a@example.com"),
            None,
            "success a marked call is recorded at its updated at"
        );
        pushed.mark("a@example.com", at(0));
        pushed.mark("a@example.com", at(9));
        assert_eq!(pushed.at("a@example.com"), Some(at(9)), "the later mark");
        assert_eq!(
            pushed.len(),
            1,
            "success a marked call is recorded at its updated at"
        );
    }

    #[test]
    fn success_pruning_forgets_only_the_calls_no_longer_held() {
        let mut pushed = Pushed::default();
        pushed.mark("kept@example.com", at(0));
        pushed.mark("gone@example.com", at(0));
        pushed.prune(|call_id| call_id == "kept@example.com");
        assert_eq!(
            pushed.at("kept@example.com"),
            Some(at(0)),
            "success pruning forgets only the calls no longer held"
        );
        assert_eq!(
            pushed.at("gone@example.com"),
            None,
            "success pruning forgets only the calls no longer held"
        );
        assert!(
            !pushed.is_empty(),
            "success pruning forgets only the calls no longer held"
        );
    }

    /// A time `millis` after the member started.
    fn ms(millis: u64) -> std::time::Duration {
        std::time::Duration::from_millis(millis)
    }

    /// How many of `tries` records `cap` admits at `at`.
    fn admitted(cap: &mut RateCap, at: std::time::Duration, tries: usize) -> usize {
        (0..tries).filter(|_| cap.admit(at)).count()
    }

    #[test]
    fn success_a_new_cap_admits_one_second_of_records_and_counts_the_rest() {
        let mut cap = RateCap::new(3);
        assert_eq!(
            admitted(&mut cap, ms(0), 5),
            3,
            "success a new cap admits one second of records and counts the rest"
        );
        assert_eq!(
            cap.dropped(),
            2,
            "success a new cap admits one second of records and counts the rest"
        );
    }

    #[test]
    fn success_the_allowance_returns_with_time() {
        let mut cap = RateCap::new(3);
        assert_eq!(
            admitted(&mut cap, ms(0), 3),
            3,
            "success the allowance returns with time"
        );
        assert_eq!(admitted(&mut cap, ms(2000), 9), 6, "two seconds later");
        assert_eq!(cap.dropped(), 3, "success the allowance returns with time");
    }

    #[test]
    fn edge_a_long_quiet_time_keeps_at_most_the_burst_allowance() {
        let mut cap = RateCap::new(2);
        let kept = usize::try_from(2 * CAP_BURST_SECS).unwrap_or(usize::MAX);
        assert_eq!(
            admitted(&mut cap, ms(3_600_000), 1000),
            kept,
            "edge a long quiet time keeps at most the burst allowance"
        );
    }

    #[test]
    fn edge_a_cap_of_zero_admits_nothing_and_counts_every_record() {
        let mut cap = RateCap::new(0);
        assert_eq!(
            admitted(&mut cap, ms(60_000), 4),
            0,
            "edge a cap of zero admits nothing and counts every record"
        );
        assert_eq!(
            cap.dropped(),
            4,
            "edge a cap of zero admits nothing and counts every record"
        );
    }

    #[test]
    fn edge_a_part_of_a_second_gives_a_part_of_the_allowance() {
        let mut cap = RateCap::new(1);
        assert!(
            cap.admit(ms(0)),
            "edge a part of a second gives a part of the allowance"
        );
        assert!(!cap.admit(ms(500)), "half a record is not a record");
        assert!(cap.admit(ms(1000)), "and the half is kept");
    }

    #[test]
    fn edge_a_time_before_the_last_count_adds_no_allowance() {
        let mut cap = RateCap::new(1);
        assert_eq!(
            admitted(&mut cap, ms(5000), 100),
            6,
            "what five seconds earned"
        );
        assert!(!cap.admit(ms(1000)), "an earlier time");
        assert!(
            !cap.admit(ms(5999)),
            "the time before it did not move the count"
        );
        assert!(
            cap.admit(ms(6000)),
            "edge a time before the last count adds no allowance"
        );
    }

    #[test]
    fn success_a_call_line_is_one_json_line_with_the_envelope_and_the_call() -> TestResult {
        let call = serde_json::json!({"call_id": "a@example.com", "state": "Failed"});
        let line = call_line("s-1", 7, at(0), "failed", &call);
        assert!(
            line.ends_with('\n') && line.matches('\n').count() == 1,
            "{line:?}"
        );
        let got: serde_json::Value = serde_json::from_str(&line)?;
        let want = serde_json::json!({
            "schema_version": 1, "kind": "call", "stream": "s-1", "seq": 7,
            "sent_at": "2027-01-15T08:00:00.000000000Z", "selected_by": "failed", "call": call,
        });
        assert_eq!(
            got, want,
            "success a call line is one json line with the envelope and the call"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_whose_text_holds_a_line_break_is_still_one_line() {
        let call = serde_json::json!({"reason": "first\nsecond\r\nthird"});
        let line = call_line("s-1", 1, at(0), "all", &call);
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        assert!(line.len() > 60 && line.ends_with("}\n"), "{line:?}");
    }

    /// `n` lines of `len` bytes each, numbered so their order shows.
    fn lines(n: usize, len: usize) -> Vec<String> {
        (0..n).map(|i| format!("{i:0len$}")).collect()
    }

    #[test]
    fn success_more_lines_than_a_delivery_holds_are_split_in_order() {
        let (got, left_out) = batches(lines(5, 4), 2, 1000);
        assert_eq!(
            left_out, 0,
            "success more lines than a delivery holds are split in order"
        );
        let sizes: Vec<usize> = got.iter().map(Vec::len).collect();
        assert_eq!(
            sizes,
            vec![2, 2, 1],
            "success more lines than a delivery holds are split in order"
        );
        assert_eq!(got.concat(), lines(5, 4), "nothing lost, nothing reordered");
    }

    #[test]
    fn edge_lines_are_split_where_the_bytes_of_a_delivery_run_out() {
        let (got, left_out) = batches(lines(5, 4), 100, 10);
        assert_eq!(
            left_out, 0,
            "edge lines are split where the bytes of a delivery run out"
        );
        let sizes: Vec<usize> = got.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![2, 2, 1], "two lines of 4 bytes fit in 10");
    }

    #[test]
    fn failure_a_line_too_large_for_any_delivery_is_left_out_and_counted() {
        let mut all = lines(3, 4);
        all.insert(1, "x".repeat(11));
        let (got, left_out) = batches(all, 100, 10);
        assert_eq!(
            left_out, 1,
            "failure a line too large for any delivery is left out and counted"
        );
        assert_eq!(got.concat(), lines(3, 4), "the others are delivered");
    }

    #[test]
    fn edge_no_lines_make_no_delivery() {
        assert_eq!(
            batches(Vec::new(), 10, 10),
            (Vec::new(), 0),
            "edge no lines make no delivery"
        );
    }

    #[test]
    fn edge_a_line_of_exactly_the_byte_bound_is_a_delivery_of_its_own() {
        let (got, left_out) = batches(vec!["a".repeat(10), "b".repeat(10)], 100, 10);
        assert_eq!(
            (got.len(), left_out),
            (2, 0),
            "edge a line of exactly the byte bound is a delivery of its own"
        );
    }

    #[test]
    fn success_delivery_files_sort_with_heartbeats_in_position_order() {
        assert_eq!(
            batch_file_name(7),
            "00000000000000000007.sealed",
            "success delivery files sort with heartbeats in position order"
        );
        let mut names = [
            batch_file_name(10),
            crate::app::fleet_member::file_name(9),
            batch_file_name(8),
            crate::app::fleet_member::file_name(100),
        ];
        names.sort();
        let order: Vec<&str> = names.iter().map(|n| n.trim_start_matches('0')).collect();
        assert_eq!(
            order,
            vec!["8.sealed", "9.json", "10.sealed", "100.json"],
            "success delivery files sort with heartbeats in position order"
        );
    }

    #[test]
    fn failure_only_a_sealed_delivery_name_is_a_delivery() {
        assert!(
            is_batch_file(&batch_file_name(1)),
            "failure only a sealed delivery name is a delivery"
        );
        for name in [
            "00000000000000000001.json",
            ".00000000000000000001.sealed.partial",
            ".00000000000000000001.sealed",
            ".sealed",
            "sealed",
            "00000000000000000001.sealed.partial",
        ] {
            assert!(!is_batch_file(name), "{name}");
        }
    }

    /// A key whose every byte is `b`, alone.
    fn keys(b: u8) -> Keys {
        Keys::new(MasterKey::from_bytes([b; 32]), Vec::new())
    }

    /// Two call lines that name a number and a host.
    fn two_lines() -> Vec<String> {
        [
            "sip:+12025550101@example.com",
            "sip:+12025550102@example.com",
        ]
        .iter()
        .enumerate()
        .map(|(i, from)| {
            call_line(
                "s-1",
                1 + i as u64,
                at(0),
                "all",
                &serde_json::json!({"from": from}),
            )
        })
        .collect()
    }

    /// `two_lines` sealed under key 1 from the system source.
    fn sealed_two() -> Result<Vec<u8>, String> {
        seal_batch(
            keys(1).current(),
            &two_lines(),
            &super::super::fleet_seal::system_draw,
        )
    }

    #[test]
    fn success_a_sealed_delivery_opens_to_its_lines_as_one_body() -> TestResult {
        let body = open_batch(&sealed_two()?, &keys(1)).map_err(|e| e.to_string())?;
        assert_eq!(
            String::from_utf8(body)?,
            two_lines().concat(),
            "success a sealed delivery opens to its lines as one body"
        );
        Ok(())
    }

    #[test]
    fn success_a_sealed_delivery_holds_no_number_or_host_in_clear() -> TestResult {
        let bytes = sealed_two()?;
        assert!(
            bytes.len() > two_lines().concat().len(),
            "it holds the records"
        );
        for clear in ["2025550101", "example.com", "call"] {
            assert!(
                !bytes.windows(clear.len()).any(|w| w == clear.as_bytes()),
                "{clear} is in the sealed file"
            );
        }
        Ok(())
    }

    #[test]
    fn failure_a_delivery_under_a_key_that_is_not_loaded_is_refused() -> TestResult {
        let e = open_batch(&sealed_two()?, &keys(2)).err();
        assert_eq!(
            e,
            Some(SealError::KeyNotLoaded(keys(1).current().id())),
            "failure a delivery under a key that is not loaded is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_delivery_with_a_changed_byte_is_refused() -> TestResult {
        let mut bytes = sealed_two()?;
        let last = bytes.len() - 40;
        bytes[last] ^= 1;
        assert!(
            open_batch(&bytes, &keys(1)).is_err(),
            "failure a delivery with a changed byte is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_delivery_cut_short_is_refused() -> TestResult {
        let bytes = sealed_two()?;
        for cut in [1, 10, 60, bytes.len() - 20] {
            assert!(
                open_batch(&bytes[..bytes.len() - cut], &keys(1)).is_err(),
                "cut {cut}"
            );
        }
        Ok(())
    }

    #[test]
    fn failure_a_sealed_file_of_another_kind_is_not_a_delivery() -> TestResult {
        use super::super::fleet_seal::{Kind, LogSealer, system_draw};
        let (mut sealer, header) = LogSealer::new(keys(1).current(), Kind::Registry, &system_draw)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.record(two_lines()[0].as_bytes())?);
        bytes.extend(sealer.base_end()?);
        assert!(
            open_batch(&bytes, &keys(1)).is_err(),
            "failure a sealed file of another kind is not a delivery"
        );
        Ok(())
    }

    #[test]
    fn failure_records_in_clear_are_not_a_delivery() {
        let clear = two_lines().concat();
        assert_eq!(
            open_batch(clear.as_bytes(), &keys(1)).err(),
            Some(SealError::NotSealed),
            "failure records in clear are not a delivery"
        );
    }

    #[test]
    fn edge_two_seals_of_the_same_lines_share_no_record_bytes() -> TestResult {
        let (a, b) = (sealed_two()?, sealed_two()?);
        assert_eq!(
            a.len(),
            b.len(),
            "edge two seals of the same lines share no record bytes"
        );
        let tail = a.len() - 64;
        assert_ne!(a[tail..], b[tail..], "each file has its own data key");
        Ok(())
    }

    #[test]
    fn failure_a_random_source_that_fails_makes_no_delivery() {
        let failing = |_: usize| Err("no entropy".to_string());
        assert_eq!(
            seal_batch(keys(1).current(), &two_lines(), &failing),
            Err("no entropy".to_string()),
            "failure a random source that fails makes no delivery"
        );
    }

    #[test]
    fn failure_bytes_after_the_end_of_a_delivery_are_refused() -> TestResult {
        let mut bytes = sealed_two()?;
        bytes.extend([0, 0, 0, 40, 1, 2, 3]);
        assert_eq!(
            open_batch(&bytes, &keys(1)).err(),
            Some(SealError::Truncated),
            "failure bytes after the end of a delivery are refused"
        );
        Ok(())
    }

    #[test]
    fn success_the_facts_of_a_call_come_from_its_end_and_its_diagnosis() {
        use crate::rtp::diagnosis::MediaDiagnosis;
        let clean = MediaDiagnosis::default();
        assert_eq!(
            CallFacts::of(false, &clean),
            CallFacts::default(),
            "success the facts of a call come from its end and its diagnosis"
        );
        assert_eq!(
            CallFacts::of(true, &clean),
            facts(|f| f.failed = true),
            "success the facts of a call come from its end and its diagnosis"
        );
        let media = MediaDiagnosis {
            one_way_audio: true,
            no_media: true,
            nat_mismatch: true,
            hints: vec!["a".to_string(), "b".to_string()],
            ..MediaDiagnosis::default()
        };
        let want = CallFacts {
            one_way_audio: true,
            no_media: true,
            nat_mismatch: true,
            findings: 2,
            ..CallFacts::default()
        };
        assert_eq!(
            CallFacts::of(false, &media),
            want,
            "success the facts of a call come from its end and its diagnosis"
        );
    }

    #[test]
    fn success_each_asymmetry_and_late_media_are_facts_of_a_call() {
        use crate::rtp::diagnosis::{
            CodecAsymmetry, DurationAsymmetry, LateMedia, MediaDiagnosis, PayloadTypeAsymmetry,
            PtimeAsymmetry,
        };
        let cases: [fn(&mut MediaDiagnosis); 4] = [
            |d| {
                d.codec_asymmetry = Some(CodecAsymmetry {
                    a_codec: "PCMU".to_string(),
                    b_codec: "PCMA".to_string(),
                });
            },
            |d| {
                d.ptime_asymmetry = Some(PtimeAsymmetry {
                    a_ptime_ms: 20,
                    b_ptime_ms: 30,
                })
            },
            |d| d.payload_type_asymmetry = Some(PayloadTypeAsymmetry { a_pt: 0, b_pt: 8 }),
            |d| {
                d.duration_asymmetry = Some(DurationAsymmetry {
                    a_duration_sec: 10.0,
                    b_duration_sec: 2.0,
                    delta_sec: 8.0,
                });
            },
        ];
        for (index, set) in cases.iter().enumerate() {
            let mut diagnosis = MediaDiagnosis::default();
            set(&mut diagnosis);
            assert_eq!(
                CallFacts::of(false, &diagnosis),
                facts(|f| f.asymmetry = true),
                "case {index}"
            );
        }
        let late = MediaDiagnosis {
            late_media: Some(LateMedia {
                leg: "a".to_string(),
                delay_after_200_ok_ms: 900,
            }),
            ..MediaDiagnosis::default()
        };
        assert_eq!(
            CallFacts::of(false, &late),
            facts(|f| f.late_media = true),
            "success each asymmetry and late media are facts of a call"
        );
    }

    /// One SIP message of the call `call_id`, seen at `seen`.
    fn sip(
        first_line: &str,
        call_id: &str,
        cseq: &str,
        seen: DateTime<Utc>,
    ) -> crate::sip::SipMessage {
        let raw = crate::test_utils::build_sip_message(
            first_line,
            &[
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1",
                "From: <sip:+12025550101@example.com>;tag=a",
                "To: <sip:+12025550102@example.com>;tag=b",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq}"),
                "Content-Length: 0",
            ],
            b"",
        );
        let peer = std::net::IpAddr::from([192, 0, 2, 10]);
        crate::sip::parser::parse_sip(
            &raw,
            seen,
            peer,
            peer,
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .unwrap_or_else(|e| unreachable!("the test's own message parses: {e:?}"))
    }

    /// How a test call ends.
    #[derive(Clone, Copy)]
    enum End {
        /// `486 Busy Here`.
        Busy,
        /// `200`, then `BYE` and its `200`.
        Answered,
        /// No answer yet.
        Ringing,
    }

    /// A dialog store holding `calls`, each begun at `at(0)`.
    fn store(calls: &[(&str, End)]) -> crate::sip::dialog_store::DialogStore {
        let mut store = crate::sip::dialog_store::DialogStore::new(100, false);
        for (call_id, end) in calls {
            let invite = "INVITE sip:+12025550102@example.com SIP/2.0";
            store.process_message(sip(invite, call_id, "1 INVITE", at(0)));
            match end {
                End::Busy => {
                    store.process_message(sip("SIP/2.0 486 Busy Here", call_id, "1 INVITE", at(1)));
                }
                End::Answered => {
                    store.process_message(sip("SIP/2.0 200 OK", call_id, "1 INVITE", at(1)));
                    let bye = "BYE sip:+12025550102@example.com SIP/2.0";
                    store.process_message(sip(bye, call_id, "2 BYE", at(2)));
                    store.process_message(sip("SIP/2.0 200 OK", call_id, "2 BYE", at(3)));
                }
                End::Ringing => {
                    store.process_message(sip("SIP/2.0 180 Ringing", call_id, "1 INVITE", at(1)));
                }
            }
        }
        store
    }

    /// Two looks of `pusher` at `dialogs`, a minute after the calls and one
    /// settle time later, with no streams: what both selected.
    fn look(
        pusher: &mut CallPusher,
        dialogs: &crate::sip::dialog_store::DialogStore,
    ) -> Vec<Selected> {
        let streams = crate::rtp::stream_store::StreamStore::new(10);
        let first = pusher.look(dialogs, &streams, at(60), ms(0), SETTLE);
        let second = pusher.look(dialogs, &streams, at(65), ms(0), SETTLE);
        [first, second].concat()
    }

    /// The Call-IDs of `selected`, in order.
    fn ids(selected: &[Selected]) -> Vec<&str> {
        selected
            .iter()
            .filter_map(|s| s.call["call_id"].as_str())
            .collect()
    }

    #[test]
    fn success_a_failed_call_is_selected_with_the_answer_the_rest_api_gives() -> TestResult {
        let dialogs = store(&[("busy@example.com", End::Busy)]);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        let got = look(&mut pusher, &dialogs);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(
            got[0].selected_by, "failed",
            "success a failed call is selected with the answer the rest api gives"
        );
        let dialog = dialogs.get("busy@example.com").ok_or("the dialog")?;
        let streams = crate::rtp::stream_store::StreamStore::new(10);
        let rest: serde_json::Value = serde_json::from_str(&crate::output::api::dialog_answer(
            dialog,
            "busy@example.com",
            &streams,
        ))?;
        assert_eq!(
            got[0].call, rest,
            "the record is the REST answer, field for field"
        );
        assert_eq!(
            pusher.counts().selected,
            1,
            "success a failed call is selected with the answer the rest api gives"
        );
        Ok(())
    }

    #[test]
    fn failure_a_call_that_has_not_ended_is_not_selected() {
        let dialogs = store(&[("ringing@example.com", End::Ringing)]);
        let mut pusher = CallPusher::new(CallPush::All, 10);
        assert_eq!(
            look(&mut pusher, &dialogs),
            Vec::new(),
            "failure a call that has not ended is not selected"
        );
    }

    #[test]
    fn failure_a_call_is_not_selected_by_a_second_look() {
        let dialogs = store(&[("busy@example.com", End::Busy)]);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        assert_eq!(
            look(&mut pusher, &dialogs).len(),
            1,
            "failure a call is not selected by a second look"
        );
        assert_eq!(
            look(&mut pusher, &dialogs),
            Vec::new(),
            "failure a call is not selected by a second look"
        );
        assert_eq!(
            pusher.counts().selected,
            1,
            "failure a call is not selected by a second look"
        );
    }

    #[test]
    fn failure_the_exceptions_rule_passes_over_an_answered_call() {
        let dialogs = store(&[
            ("ok@example.com", End::Answered),
            ("busy@example.com", End::Busy),
        ]);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        assert_eq!(
            ids(&look(&mut pusher, &dialogs)),
            vec!["busy@example.com"],
            "failure the exceptions rule passes over an answered call"
        );
    }

    #[test]
    fn success_the_rule_all_selects_every_ended_call_in_the_stores_order() {
        let dialogs = store(&[
            ("ok@example.com", End::Answered),
            ("ringing@example.com", End::Ringing),
            ("busy@example.com", End::Busy),
        ]);
        let mut pusher = CallPusher::new(CallPush::All, 10);
        let got = look(&mut pusher, &dialogs);
        assert_eq!(
            ids(&got),
            vec!["ok@example.com", "busy@example.com"],
            "success the rule all selects every ended call in the stores order"
        );
        assert!(got.iter().all(|s| s.selected_by == "all"), "{got:?}");
    }

    #[test]
    fn edge_exceptions_over_the_cap_are_counted_and_not_tried_again() {
        let dialogs = store(&[
            ("a@example.com", End::Busy),
            ("b@example.com", End::Busy),
            ("c@example.com", End::Busy),
        ]);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 1);
        assert_eq!(
            ids(&look(&mut pusher, &dialogs)),
            vec!["a@example.com"],
            "edge exceptions over the cap are counted and not tried again"
        );
        let want = CallCounts {
            selected: 1,
            dropped_by_cap: 2,
            ..CallCounts::default()
        };
        assert_eq!(
            pusher.counts(),
            want,
            "edge exceptions over the cap are counted and not tried again"
        );
        let streams = crate::rtp::stream_store::StreamStore::new(10);
        let later = pusher.look(&dialogs, &streams, at(120), ms(60_000), SETTLE);
        assert_eq!(later, Vec::new(), "a refused call is not pushed late");
        assert_eq!(
            pusher.counts(),
            want,
            "edge exceptions over the cap are counted and not tried again"
        );
    }

    #[test]
    fn edge_the_rule_all_is_not_capped() {
        let dialogs = store(&[
            ("a@example.com", End::Busy),
            ("b@example.com", End::Answered),
        ]);
        let mut pusher = CallPusher::new(CallPush::All, 0);
        let got = look(&mut pusher, &dialogs);
        assert_eq!(got.len(), 2, "edge the rule all is not capped");
        assert!(got.iter().all(|s| s.selected_by == "all"), "{got:?}");
        assert_eq!(
            pusher.counts().dropped_by_cap,
            0,
            "edge the rule all is not capped"
        );
    }

    #[test]
    fn edge_a_call_inside_its_settle_time_waits_for_a_later_look() {
        let dialogs = store(&[("busy@example.com", End::Busy)]);
        let streams = crate::rtp::stream_store::StreamStore::new(10);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        assert_eq!(
            pusher.look(&dialogs, &streams, at(3), ms(0), SETTLE),
            Vec::new(),
            "edge a call inside its settle time waits for a later look"
        );
        assert_eq!(
            pusher.look(&dialogs, &streams, at(7), ms(4000), SETTLE),
            Vec::new(),
            "seen for 4 s"
        );
        assert_eq!(
            pusher
                .look(&dialogs, &streams, at(8), ms(5000), SETTLE)
                .len(),
            1,
            "edge a call inside its settle time waits for a later look"
        );
    }

    #[test]
    fn edge_a_call_that_ends_after_a_look_is_selected_by_the_next() {
        let mut dialogs = store(&[("late@example.com", End::Ringing)]);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        assert_eq!(
            look(&mut pusher, &dialogs),
            Vec::new(),
            "edge a call that ends after a look is selected by the next"
        );
        dialogs.process_message(sip(
            "SIP/2.0 486 Busy Here",
            "late@example.com",
            "1 INVITE",
            at(9),
        ));
        assert_eq!(
            ids(&look(&mut pusher, &dialogs)),
            vec!["late@example.com"],
            "edge a call that ends after a look is selected by the next"
        );
    }

    #[test]
    fn edge_calls_the_store_dropped_are_forgotten() {
        let mut dialogs = store(&[
            ("a@example.com", End::Busy),
            ("b@example.com", End::Answered),
        ]);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        look(&mut pusher, &dialogs);
        assert_eq!(
            pusher.tracked(),
            2,
            "the pushed call and the one passed over"
        );
        dialogs.clear();
        look(&mut pusher, &dialogs);
        assert_eq!(
            pusher.tracked(),
            0,
            "edge calls the store dropped are forgotten"
        );
    }

    #[test]
    fn success_spooled_and_left_out_calls_are_counted() {
        let mut pusher = CallPusher::new(CallPush::All, 10);
        pusher.spooled(5, 1);
        pusher.spooled(2, 0);
        let want = CallCounts {
            spooled: 7,
            left_out: 1,
            ..CallCounts::default()
        };
        assert_eq!(
            pusher.counts(),
            want,
            "success spooled and left out calls are counted"
        );
    }

    #[test]
    fn failure_a_call_first_seen_as_it_stands_within_the_settle_time_is_not_due() {
        // Its own time is long past, as in a capture read from a file: what
        // counts is how long this member has seen it unchanged.
        let seen = Pushed::default().seen_since_at("a@example.com", at(0), at(86_400));
        assert_eq!(seen, at(86_400), "first seen now");
        assert!(
            !call_due_seen(true, at(0), seen, at(86_400), SETTLE, None),
            "failure a call first seen as it stands within the settle time is not due"
        );
        assert!(
            !call_due_seen(true, at(0), seen, at(86_404), SETTLE, None),
            "failure a call first seen as it stands within the settle time is not due"
        );
        assert!(
            call_due_seen(true, at(0), seen, at(86_405), SETTLE, None),
            "failure a call first seen as it stands within the settle time is not due"
        );
    }

    #[test]
    fn edge_a_call_that_changes_is_seen_anew_and_one_that_does_not_keeps_its_time() {
        let mut pushed = Pushed::default();
        assert_eq!(
            pushed.see("a@example.com", at(0), at(100)),
            at(100),
            "edge a call that changes is seen anew and one that does not keeps its time"
        );
        assert_eq!(
            pushed.see("a@example.com", at(0), at(105)),
            at(100),
            "unchanged"
        );
        assert_eq!(
            pushed.see("a@example.com", at(1), at(107)),
            at(107),
            "it changed"
        );
        pushed.prune(|_| false);
        assert_eq!(
            pushed.see("a@example.com", at(1), at(200)),
            at(200),
            "forgotten with the call"
        );
    }

    #[test]
    fn failure_a_call_from_a_capture_file_is_not_pushed_at_the_first_look() {
        let dialogs = store(&[("busy@example.com", End::Busy)]);
        let streams = crate::rtp::stream_store::StreamStore::new(10);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        let first = pusher.look(&dialogs, &streams, at(86_400), ms(0), SETTLE);
        assert_eq!(
            first,
            Vec::new(),
            "it may still be changing as the file is read"
        );
        let second = pusher.look(&dialogs, &streams, at(86_405), ms(5000), SETTLE);
        assert_eq!(
            ids(&second),
            vec!["busy@example.com"],
            "failure a call from a capture file is not pushed at the first look"
        );
    }

    #[test]
    fn edge_a_call_that_changed_between_two_looks_is_pushed_once_as_it_ended() {
        // The 486 is read, a look happens, then the rest of the file is read.
        let mut dialogs = store(&[("late@example.com", End::Ringing)]);
        dialogs.process_message(sip(
            "SIP/2.0 486 Busy Here",
            "late@example.com",
            "1 INVITE",
            at(2),
        ));
        let streams = crate::rtp::stream_store::StreamStore::new(10);
        let mut pusher = CallPusher::new(CallPush::Exceptions, 10);
        assert_eq!(
            pusher.look(&dialogs, &streams, at(86_400), ms(0), SETTLE),
            Vec::new(),
            "edge a call that changed between two looks is pushed once as it ended"
        );
        let ack = "ACK sip:+12025550102@example.com SIP/2.0";
        dialogs.process_message(sip(ack, "late@example.com", "1 ACK", at(3)));
        let mut pushed = 0;
        for step in 1..=4 {
            let now = at(86_400 + 5 * step);
            pushed += pusher
                .look(&dialogs, &streams, now, ms(5000 * step as u64), SETTLE)
                .len();
        }
        assert_eq!(
            pushed, 1,
            "edge a call that changed between two looks is pushed once as it ended"
        );
        assert_eq!(
            pusher.counts().selected,
            1,
            "edge a call that changed between two looks is pushed once as it ended"
        );
    }

    #[test]
    fn edge_two_lines_that_fill_a_delivery_exactly_share_it() {
        let (got, left_out) = batches(vec!["a".repeat(5), "b".repeat(5), "c".repeat(5)], 100, 10);
        let sizes: Vec<usize> = got.iter().map(Vec::len).collect();
        assert_eq!(
            (sizes, left_out),
            (vec![2, 1], 0),
            "two lines of 5 bytes fill 10"
        );
    }

    #[test]
    fn failure_the_rule_none_selects_nothing_at_any_look() {
        let dialogs = store(&[("busy@example.com", End::Busy)]);
        let mut pusher = CallPusher::new(CallPush::None, 10);
        assert_eq!(look(&mut pusher, &dialogs), Vec::new(), "the rule none");
        assert_eq!(
            pusher.counts(),
            CallCounts::default(),
            "and nothing is counted"
        );
    }
}
