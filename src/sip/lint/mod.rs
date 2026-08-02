// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP conformance linting: what the signalling promised, and what the wire did.
//!
//! # The rule class only this tool can run
//!
//! Every other SIP linter reads text against a grammar. It can tell you the
//! `Contact` header is missing its angle brackets. It cannot tell you that the
//! SDP offered PCMU on payload type 0 and the far end then sent payload type 8,
//! because it never sees the RTP. sipnab holds signalling and media in one
//! process, so the [`media`] rules compare the declaration against the
//! observation — a class of defect that is invisible to a grammar and obvious
//! on a capture.
//!
//! The classic syntactic and dialog-semantic rules are here too ([`message`],
//! [`dialog`]), because a carrier ticket wants both. They are not the reason
//! this module exists.
//!
//! # Conformance is not outcome
//!
//! [`crate::sip::diagnosis`] answers "why did this call fail". This module
//! answers "does this traffic obey the specification". A call can complete
//! perfectly over messages that break four MUSTs, and a fully conformant call
//! can fail on a busy signal. Conflating the two questions produces an answer
//! to neither.
//!
//! # What a finding carries
//!
//! [`Finding`] holds `rfc` and `section` as data rather than as prose inside a
//! sentence, so a citation can be checked, linked and sorted. See [`finding`]
//! for why that mattered enough to build first.
//!
//! # Example
//!
//! ```
//! use sipnab::sip::lint::{LintConfig, Linter, Ruleset};
//!
//! // Fail CI on broken MUSTs, and stay quiet about everything else.
//! let config = LintConfig::new()
//!     .with_ruleset(Ruleset::Must)
//!     .suppress("SIP-3261-8.1.1.7-BRANCH-COOKIE");
//! let linter = Linter::new(config);
//! assert!(linter.config().enabled(&sipnab::sip::lint::MAX_FORWARDS_MISSING));
//! ```

pub mod dialog;
pub mod finding;
pub mod media;
pub mod message;

pub use finding::{
    ACK_CSEQ_MISMATCH, ANSWER_DIRECTION_ILLEGAL, ANSWER_EXTRA_FORMAT, ANSWER_NO_COMMON_FORMAT,
    BRANCH_COOKIE, Basis, CONTENT_LENGTH_MISMATCH, CSEQ_MALFORMED, CSEQ_METHOD_MISMATCH,
    DIRECTION_UNMET, FRAME_SIZE_IMPOSSIBLE, Finding, HEADER_CONTROL_BYTE, HOLD_CONNECTION_ZERO,
    MANDATORY_HEADER_MISSING, MAX_FORWARDS_MISSING, MAX_FORWARDS_RANGE, MEDIA_PORT_MISMATCH,
    PT_UNDECLARED, PTIME_MISMATCH, RTCP_MUX_UNANSWERED, RULES, RuleMeta, Scope, Severity,
    TO_TAG_IN_INITIAL_REQUEST, URI_BRACKETS, rule_by_id,
};
pub use media::{ObservedMedia, ObservedRtcp, ObservedStream};
pub use message::malformation_reasons;

use crate::sip::dialog::SipDialog;
use crate::sip::message::SipMessage;

/// A named subset of the catalogue.
///
/// Selecting by name is what lets one repository run `must` in CI and
/// `observation` in a triage session without maintaining two suppression lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ruleset {
    /// Every rule.
    #[default]
    All,
    /// Only violations of an RFC MUST. The set that can be defended in a
    /// carrier ticket without argument.
    Must,
    /// Everything an RFC requires or recommends — MUST and SHOULD — and
    /// nothing else. Excludes the vendor heuristics and the media rules.
    Rfc,
    /// Only the "this breaks real equipment" heuristics.
    Interop,
    /// Only the declaration-versus-observation rules.
    Observation,
    /// Only the rules that read a single message with no dialog context.
    Syntax,
}

impl Ruleset {
    /// Lowercase name, for configuration files and CLI flags.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Must => "must",
            Self::Rfc => "rfc",
            Self::Interop => "interop",
            Self::Observation => "observation",
            Self::Syntax => "syntax",
        }
    }

    /// Parse a ruleset name, case-insensitively.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "all" => Some(Self::All),
            "must" => Some(Self::Must),
            "rfc" => Some(Self::Rfc),
            "interop" => Some(Self::Interop),
            "observation" | "obs" => Some(Self::Observation),
            "syntax" => Some(Self::Syntax),
            _ => None,
        }
    }

    /// Every selectable name, for help text and for the docs drift test.
    #[must_use]
    pub fn names() -> &'static [&'static str] {
        &["all", "must", "rfc", "interop", "observation", "syntax"]
    }

    /// Whether `rule` belongs to this set.
    #[must_use]
    pub fn contains(self, rule: &RuleMeta) -> bool {
        match self {
            Self::All => true,
            Self::Must => rule.basis == Basis::Must,
            Self::Rfc => matches!(rule.basis, Basis::Must | Basis::Should),
            Self::Interop => rule.basis == Basis::Interop,
            Self::Observation => rule.basis == Basis::Observation,
            Self::Syntax => rule.scope() == Scope::Message,
        }
    }
}

/// Default cap on how many findings one rule may raise for one dialog.
///
/// A dialog retransmitting an `INVITE` eleven times trips a message rule eleven
/// times, and every one of them is true. Printing all eleven buries the other
/// ten rules, which is how a linter gets switched off in week one. The cap
/// keeps the first [`DEFAULT_MAX_PER_RULE`] as evidence and drops the tail.
pub const DEFAULT_MAX_PER_RULE: usize = 25;

/// Which rules run, how loud they have to be, and what to stay quiet about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintConfig {
    /// The selected subset of the catalogue.
    ruleset: Ruleset,
    /// Findings quieter than this are dropped.
    min_severity: Severity,
    /// Suppression patterns: an exact rule identifier, or a prefix ending `*`.
    suppressions: Vec<String>,
    /// Cap on findings per rule per dialog.
    max_per_rule: usize,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            ruleset: Ruleset::All,
            min_severity: Severity::Info,
            suppressions: Vec::new(),
            max_per_rule: DEFAULT_MAX_PER_RULE,
        }
    }
}

impl LintConfig {
    /// Every rule, every severity, nothing suppressed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Select a named subset of the catalogue.
    #[must_use]
    pub fn with_ruleset(mut self, ruleset: Ruleset) -> Self {
        self.ruleset = ruleset;
        self
    }

    /// Drop findings quieter than `severity`.
    #[must_use]
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Cap findings per rule per dialog. Zero disables the cap.
    #[must_use]
    pub fn with_max_per_rule(mut self, max: usize) -> Self {
        self.max_per_rule = max;
        self
    }

    /// Suppress one rule identifier, or every identifier under a prefix when
    /// the pattern ends in `*` — `OBS-*` silences every observation rule.
    #[must_use]
    pub fn suppress(mut self, pattern: impl Into<String>) -> Self {
        self.suppressions.push(pattern.into());
        self
    }

    /// Suppress a comma-, space- or newline-separated list of patterns, the
    /// shape a CLI flag or a `.sipnab-lintignore` file carries.
    ///
    /// Blank entries are skipped, and a `#` starts a comment to the end of the
    /// line so the file can say why a rule is off.
    #[must_use]
    pub fn suppress_list(mut self, list: &str) -> Self {
        for line in list.lines() {
            let line = line.split('#').next().unwrap_or("");
            for pattern in line.split([',', ' ', '\t']) {
                let pattern = pattern.trim();
                if !pattern.is_empty() {
                    self.suppressions.push(pattern.to_string());
                }
            }
        }
        self
    }

    /// The selected ruleset.
    #[must_use]
    pub fn ruleset(&self) -> Ruleset {
        self.ruleset
    }

    /// The minimum severity reported.
    #[must_use]
    pub fn min_severity(&self) -> Severity {
        self.min_severity
    }

    /// The per-rule, per-dialog cap. Zero means uncapped.
    #[must_use]
    pub fn max_per_rule(&self) -> usize {
        self.max_per_rule
    }

    /// The suppression patterns, in the order supplied.
    #[must_use]
    pub fn suppressions(&self) -> &[String] {
        &self.suppressions
    }

    /// Whether `rule` runs and reports under this configuration.
    #[must_use]
    pub fn enabled(&self, rule: &RuleMeta) -> bool {
        if !self.ruleset.contains(rule) {
            return false;
        }
        if rule.severity < self.min_severity {
            return false;
        }
        !self
            .suppressions
            .iter()
            .any(|p| suppression_matches(p, rule.id))
    }

    /// Every rule this configuration would run.
    #[must_use]
    pub fn active_rules(&self) -> Vec<&'static RuleMeta> {
        RULES.iter().filter(|r| self.enabled(r)).collect()
    }
}

/// Whether a suppression pattern silences a rule identifier.
///
/// Exact match, or prefix match when the pattern ends in `*`. Deliberately not
/// a glob: a suppression file is read by whoever inherits the pipeline, and
/// `SIP-3261-*-CSEQ-*` is a puzzle where `SIP-3261-8.1.1.5-CSEQ-METHOD-MISMATCH`
/// is a statement.
fn suppression_matches(pattern: &str, rule_id: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => rule_id.starts_with(prefix),
        None => pattern == rule_id,
    }
}

/// Collects findings, applying the configuration as they arrive.
///
/// Rules push through this rather than into a bare `Vec` so suppression and the
/// per-rule cap cannot be forgotten by one rule and honoured by the rest.
pub(crate) struct FindingSink<'a> {
    /// The configuration deciding what survives.
    config: &'a LintConfig,
    /// Findings accepted so far.
    findings: Vec<Finding>,
    /// How many findings each rule has already contributed, by identifier.
    counts: Vec<(&'static str, usize)>,
}

impl<'a> FindingSink<'a> {
    /// An empty sink bound to `config`.
    pub(crate) fn new(config: &'a LintConfig) -> Self {
        Self {
            config,
            findings: Vec::new(),
            counts: Vec::new(),
        }
    }

    /// Whether a rule is worth evaluating at all.
    ///
    /// Rules call this before doing work a suppressed rule would waste — the
    /// media rules in particular walk every observed stream.
    pub(crate) fn wants(&self, rule: &RuleMeta) -> bool {
        if !self.config.enabled(rule) {
            return false;
        }
        self.config.max_per_rule == 0 || self.count_of(rule.id) < self.config.max_per_rule
    }

    /// How many findings `id` has already contributed.
    fn count_of(&self, id: &str) -> usize {
        self.counts
            .iter()
            .find(|(k, _)| *k == id)
            .map_or(0, |(_, n)| *n)
    }

    /// Record a finding, unless the configuration rejects it.
    pub(crate) fn push(
        &mut self,
        rule: &RuleMeta,
        message_index: usize,
        observed: impl Into<String>,
        expected: impl Into<String>,
        explanation: impl Into<String>,
    ) {
        if !self.wants(rule) {
            return;
        }
        match self.counts.iter_mut().find(|(k, _)| *k == rule.id) {
            Some((_, n)) => *n += 1,
            None => self.counts.push((rule.id, 1)),
        }
        self.findings.push(Finding::new(
            rule,
            message_index,
            observed,
            expected,
            explanation,
        ));
    }

    /// The collected findings, ordered by message index then rule identifier.
    pub(crate) fn finish(mut self) -> Vec<Finding> {
        self.findings.sort_by(|a, b| {
            a.message_index
                .cmp(&b.message_index)
                .then(a.rule_id.cmp(b.rule_id))
        });
        self.findings
    }
}

/// The conformance linter.
///
/// Holds a [`LintConfig`] and runs the catalogue against a message, a dialog,
/// or a dialog and the media observed for it.
#[derive(Debug, Clone, Default)]
pub struct Linter {
    /// Which rules run and what they report.
    config: LintConfig,
}

impl Linter {
    /// A linter running `config`.
    #[must_use]
    pub fn new(config: LintConfig) -> Self {
        Self { config }
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> &LintConfig {
        &self.config
    }

    /// Run the message-scoped rules against one message.
    ///
    /// `message_index` is echoed into every finding, so a caller walking a
    /// dialog can pass the position and a caller linting a lone message can
    /// pass `0`. Dialog- and media-scoped rules do not run: they have nothing
    /// to read.
    #[must_use]
    pub fn lint_message(&self, msg: &SipMessage, message_index: usize) -> Vec<Finding> {
        let mut sink = FindingSink::new(&self.config);
        message::lint(msg, message_index, &mut sink);
        sink.finish()
    }

    /// Run every rule that does not need media against a dialog.
    #[must_use]
    pub fn lint_dialog(&self, dialog: &SipDialog) -> Vec<Finding> {
        let mut sink = FindingSink::new(&self.config);
        self.run_signalling(dialog, &mut sink);
        sink.finish()
    }

    /// Run every rule, including the declaration-versus-observation ones.
    ///
    /// `media` carries what was actually seen on the wire for this dialog. An
    /// empty [`ObservedMedia`] is not the same as no call: a dialog that
    /// negotiated media and carried none is exactly what
    /// [`DIRECTION_UNMET`] exists to report.
    #[must_use]
    pub fn lint_dialog_with_media(
        &self,
        dialog: &SipDialog,
        media: &ObservedMedia,
    ) -> Vec<Finding> {
        let mut sink = FindingSink::new(&self.config);
        self.run_signalling(dialog, &mut sink);
        media::lint(dialog, media, &mut sink);
        sink.finish()
    }

    /// The message- and dialog-scoped half, shared by both dialog entry points.
    fn run_signalling(&self, dialog: &SipDialog, sink: &mut FindingSink<'_>) {
        for (index, msg) in dialog.messages.iter().enumerate() {
            message::lint(msg, index, sink);
        }
        dialog::lint(dialog, sink);
    }
}

/// Tests for ruleset selection, suppression and the sink.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every ruleset name parses back to the variant it names, and
    /// `Ruleset::names` lists all of them.
    #[test]
    fn ruleset_names_round_trip() {
        for name in Ruleset::names() {
            let set = Ruleset::from_name(name).unwrap_or_else(|| panic!("{name} does not parse"));
            assert_eq!(set.as_str(), *name);
        }
        assert_eq!(Ruleset::from_name("OBS"), Some(Ruleset::Observation));
        assert_eq!(Ruleset::from_name("nonsense"), None);
    }

    /// `Ruleset::names` and the parser agree on the full set — a variant added
    /// without a name would silently be unselectable from a CLI flag.
    #[test]
    fn every_ruleset_variant_has_a_name() {
        let all = [
            Ruleset::All,
            Ruleset::Must,
            Ruleset::Rfc,
            Ruleset::Interop,
            Ruleset::Observation,
            Ruleset::Syntax,
        ];
        for set in all {
            assert!(
                Ruleset::names().contains(&set.as_str()),
                "{} missing from Ruleset::names",
                set.as_str()
            );
        }
        assert_eq!(Ruleset::names().len(), all.len());
    }

    /// The `must` ruleset holds only MUST violations, and the `interop` set
    /// holds none of them.
    ///
    /// This is the separation the whole `Basis` axis exists for: a CI job
    /// running `must` must never fail on a vendor heuristic.
    #[test]
    fn must_and_interop_do_not_overlap() {
        for rule in RULES {
            assert!(
                !(Ruleset::Must.contains(rule) && Ruleset::Interop.contains(rule)),
                "{} is in both must and interop",
                rule.id
            );
        }
        assert!(Ruleset::Must.contains(&BRANCH_COOKIE));
        assert!(!Ruleset::Must.contains(&ANSWER_EXTRA_FORMAT));
        assert!(Ruleset::Interop.contains(&ANSWER_EXTRA_FORMAT));
    }

    /// The `observation` ruleset is exactly the media-scoped rules.
    #[test]
    fn observation_ruleset_is_the_media_rules() {
        let selected: Vec<&str> = RULES
            .iter()
            .filter(|r| Ruleset::Observation.contains(r))
            .map(|r| r.id)
            .collect();
        assert!(!selected.is_empty());
        for id in &selected {
            assert!(id.starts_with("OBS-"), "{id} is not an observation rule");
        }
    }

    /// An exact suppression silences one rule and leaves its neighbours alone.
    #[test]
    fn exact_suppression_silences_one_rule() {
        let config = LintConfig::new().suppress(BRANCH_COOKIE.id);
        assert!(!config.enabled(&BRANCH_COOKIE));
        assert!(config.enabled(&MAX_FORWARDS_MISSING));
    }

    /// A trailing `*` suppresses every identifier under the prefix.
    #[test]
    fn prefix_suppression_silences_a_family() {
        let config = LintConfig::new().suppress("OBS-*");
        for rule in RULES {
            assert_eq!(
                config.enabled(rule),
                !rule.id.starts_with("OBS-"),
                "{}",
                rule.id
            );
        }
    }

    /// A suppression list parses commas, whitespace, newlines and comments.
    #[test]
    fn suppression_lists_parse_files_and_flags() {
        let config = LintConfig::new().suppress_list(
            "OBS-*, SIP-3261-20-URI-BRACKETS  # carrier rewrites these\n\
             \n\
             SIP-3261-8.1.1.7-BRANCH-COOKIE\n",
        );
        assert_eq!(config.suppressions().len(), 3);
        assert!(!config.enabled(&URI_BRACKETS));
        assert!(!config.enabled(&BRANCH_COOKIE));
        assert!(!config.enabled(&PT_UNDECLARED));
        assert!(config.enabled(&MAX_FORWARDS_MISSING));
    }

    /// A comment introduced by `#` never becomes a suppression pattern.
    #[test]
    fn suppression_comments_are_not_patterns() {
        let config = LintConfig::new().suppress_list("# everything off\nSIP-3261-20-URI-BRACKETS");
        assert_eq!(config.suppressions(), ["SIP-3261-20-URI-BRACKETS"]);
    }

    /// A minimum severity drops the quieter rules.
    #[test]
    fn min_severity_filters_by_loudness() {
        let config = LintConfig::new().with_min_severity(Severity::Error);
        for rule in RULES {
            assert_eq!(config.enabled(rule), rule.severity == Severity::Error);
        }
    }

    /// The sink honours the per-rule cap and reports nothing beyond it.
    #[test]
    fn sink_caps_repeated_findings() {
        let config = LintConfig::new().with_max_per_rule(2);
        let mut sink = FindingSink::new(&config);
        for i in 0..10 {
            sink.push(&BRANCH_COOKIE, i, "o", "e", "x");
        }
        assert_eq!(sink.finish().len(), 2);
    }

    /// A zero cap means uncapped.
    #[test]
    fn sink_cap_of_zero_is_unlimited() {
        let config = LintConfig::new().with_max_per_rule(0);
        let mut sink = FindingSink::new(&config);
        for i in 0..10 {
            sink.push(&BRANCH_COOKIE, i, "o", "e", "x");
        }
        assert_eq!(sink.finish().len(), 10);
    }

    /// The sink drops a suppressed rule, and says so through `wants` before the
    /// rule does any work.
    #[test]
    fn sink_drops_suppressed_rules() {
        let config = LintConfig::new().suppress(BRANCH_COOKIE.id);
        let mut sink = FindingSink::new(&config);
        assert!(!sink.wants(&BRANCH_COOKIE));
        sink.push(&BRANCH_COOKIE, 0, "o", "e", "x");
        assert!(sink.finish().is_empty());
    }

    /// Findings come back ordered by message index, then by rule identifier —
    /// stable output a golden test or a diff can rely on.
    #[test]
    fn findings_sort_by_index_then_rule() {
        let config = LintConfig::new();
        let mut sink = FindingSink::new(&config);
        sink.push(&MAX_FORWARDS_MISSING, 2, "o", "e", "x");
        sink.push(&BRANCH_COOKIE, 1, "o", "e", "x");
        sink.push(&URI_BRACKETS, 1, "o", "e", "x");
        let out = sink.finish();
        let ids: Vec<_> = out.iter().map(|f| (f.message_index, f.rule_id)).collect();
        // Within one message index the order is the identifier's own, which is
        // lexicographic: `SIP-3261-20-` sorts above `SIP-3261-8.1.1.7-` because
        // section numbers are text here, not numbers.
        assert_eq!(
            ids,
            [
                (1, URI_BRACKETS.id),
                (1, BRANCH_COOKIE.id),
                (2, MAX_FORWARDS_MISSING.id),
            ]
        );
    }

    /// `active_rules` reports exactly what a configuration would run.
    #[test]
    fn active_rules_reflects_the_configuration() {
        let config = LintConfig::new()
            .with_ruleset(Ruleset::Observation)
            .suppress(PT_UNDECLARED.id);
        let active: Vec<&str> = config.active_rules().iter().map(|r| r.id).collect();
        assert!(!active.contains(&PT_UNDECLARED.id));
        assert!(active.contains(&MEDIA_PORT_MISMATCH.id));
        assert!(!active.contains(&BRANCH_COOKIE.id));
    }
}
