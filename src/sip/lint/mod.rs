// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP conformance linting: what the signaling promised, and what the wire did.
//!
//! # The rule class only this tool can run
//!
//! Every other SIP linter reads text against a grammar. It can tell you the
//! `Contact` header is missing its angle brackets. It cannot tell you that the
//! SDP offered PCMU on payload type 0 and the far end then sent payload type 8,
//! because it never sees the RTP. sipnab holds signaling and media in one
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

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::sip::dialog::SipDialog;
use crate::sip::message::SipMessage;

/// The file a project keeps its lint suppressions in.
pub const SUPPRESSION_FILENAME: &str = ".sipnablint";

/// How far above a capture the search for [`SUPPRESSION_FILENAME`] may climb.
///
/// A capture can sit anywhere — a corpus mount, `/tmp`, a colleague's home —
/// and silently adopting a suppression list belonging to an unrelated tree
/// would switch rules off that nobody in this project turned off. The cap is a
/// backstop behind the project-root rule in [`SuppressionFile::discover`],
/// which is the real bound.
const MAX_DISCOVERY_DEPTH: usize = 8;

/// A `.sipnablint` that was found and read.
///
/// Carries the path as well as the patterns because "3 findings suppressed" is
/// unactionable when discovery walked up four directories to get there — the
/// operator has to know *which* file to edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionFile {
    /// Where the patterns came from.
    path: PathBuf,
    /// The patterns, in file order.
    patterns: Vec<String>,
}

impl SuppressionFile {
    /// Read a suppression list from an explicit path.
    ///
    /// # Errors
    ///
    /// Propagates the read error. A named file that cannot be read is an
    /// error rather than an empty list: a caller that pointed at a file has
    /// stated an intent, and quietly linting with every rule on would be the
    /// opposite of what they asked for.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let config = LintConfig::new().suppress_list(&text);
        Ok(Self {
            path: path.to_path_buf(),
            patterns: config.suppressions().to_vec(),
        })
    }

    /// The suppression list governing a run: the named file, or the
    /// discovered one, or nothing.
    ///
    /// One function so the CLI and the MCP tools cannot drift into two answers
    /// about the same file on disk. An explicit name wins outright and never
    /// falls back to discovery — a caller that pointed at a file has stated an
    /// intent, and a full-catalog run would be read as "my suppressions matched
    /// nothing" rather than as the failure it is.
    ///
    /// `capture_dir` is the directory holding the capture, and only a file
    /// replay has one: a live interface is not a path, so discovery does not
    /// run there.
    ///
    /// # Errors
    ///
    /// Propagates the read error from [`Self::load`], for the named file and
    /// for a discovered one alike. A discovered file that cannot be read is
    /// reported rather than skipped: it is on disk, and whoever checked it in
    /// believes it applies.
    pub fn resolve(
        explicit: Option<&str>,
        capture_dir: Option<&Path>,
    ) -> std::io::Result<Option<Self>> {
        if let Some(name) = explicit {
            return Self::load(name).map(Some);
        }
        let Some(found) = capture_dir.and_then(Self::discover) else {
            return Ok(None);
        };
        Self::load(found).map(Some)
    }

    /// Find the `.sipnablint` that governs a capture, or `None`.
    ///
    /// `start` is the directory holding the capture. That directory always
    /// counts. Above it the search climbs only while still inside a project —
    /// the nearest ancestor holding a `.git` — so a capture in a corpus mount
    /// that belongs to no project adopts nothing from above itself.
    #[must_use]
    pub fn discover(start: &Path) -> Option<PathBuf> {
        let here = start.join(SUPPRESSION_FILENAME);
        if here.is_file() {
            return Some(here);
        }
        // No project above this capture means no upward search at all.
        let root = Self::project_root(start)?;
        let mut dir = start.parent();
        while let Some(d) = dir {
            let candidate = d.join(SUPPRESSION_FILENAME);
            if candidate.is_file() {
                return Some(candidate);
            }
            if d == root {
                break;
            }
            dir = d.parent();
        }
        None
    }

    /// The nearest ancestor of `start` (inclusive) holding a `.git`.
    fn project_root(start: &Path) -> Option<PathBuf> {
        let mut dir = start;
        for _ in 0..MAX_DISCOVERY_DEPTH {
            if dir.join(".git").exists() {
                return Some(dir.to_path_buf());
            }
            dir = dir.parent()?;
        }
        None
    }

    /// Where the patterns came from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The patterns, in file order.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

/// Why the configuration withheld a finding a rule actually raised.
///
/// Kept as three values rather than one boolean because they answer different
/// operator questions — "you asked me not to see this", "there was too much of
/// it", "it was below your floor" — and a single "hidden" count says something
/// was withheld without saying why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withheld {
    /// A suppression pattern matched the rule identifier.
    Suppressed,
    /// The rule is quieter than the configured minimum severity.
    BelowSeverity,
    /// The rule already contributed [`LintConfig::max_per_rule`] findings.
    Capped,
}

/// How many findings each reason withheld from one run.
///
/// Always reported, including when every field is zero. A response carrying no
/// counts and a response carrying zeroes must not be the same bytes: the first
/// says nothing about whether anything was hidden, and the second says nothing
/// was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WithheldCounts {
    /// Findings a suppression pattern silenced.
    pub suppressed: usize,
    /// Findings dropped for sitting below the minimum severity.
    pub below_severity: usize,
    /// Findings dropped by the per-rule, per-dialog cap.
    ///
    /// A lower bound, and the only one of the three that is: a rule may also
    /// stop evaluating once it has hit the cap, and nothing can count the
    /// findings it then never raises. The other two counts are exact, because
    /// suppression and the severity floor deliberately do not short-circuit.
    pub capped: usize,
}

impl WithheldCounts {
    /// Whether anything at all was withheld.
    #[must_use]
    pub fn any(&self) -> bool {
        self.suppressed > 0 || self.below_severity > 0 || self.capped > 0
    }
}

/// The findings of one run, and what the configuration kept back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintOutcome {
    /// What survived the configuration.
    pub findings: Vec<Finding>,
    /// What did not, by reason.
    pub withheld: WithheldCounts,
}

/// A named subset of the catalog.
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
    /// The selected subset of the catalog.
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

    /// Select a named subset of the catalog.
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

    /// Adopt every pattern from a loaded [`SuppressionFile`].
    #[must_use]
    pub fn with_suppression_file(mut self, file: &SuppressionFile) -> Self {
        self.suppressions.extend(file.patterns().iter().cloned());
        self
    }

    /// Whether the selected ruleset contains `rule` at all.
    ///
    /// Separate from [`Self::withheld_reason`] because the two are different
    /// facts. A rule outside the selected ruleset was never asked for, so its
    /// findings are not "withheld" from anybody and must not be counted as
    /// though something were being kept back.
    #[must_use]
    pub fn selected(&self, rule: &RuleMeta) -> bool {
        self.ruleset.contains(rule)
    }

    /// Why a finding from `rule` would be withheld, ignoring the per-rule cap.
    ///
    /// Suppression is tested before severity so a rule that is both explicitly
    /// suppressed and below the floor reports as suppressed — the more
    /// actionable of the two answers, because it names something the operator
    /// wrote down.
    #[must_use]
    pub fn withheld_reason(&self, rule: &RuleMeta) -> Option<Withheld> {
        if self
            .suppressions
            .iter()
            .any(|p| suppression_matches(p, rule.id))
        {
            return Some(Withheld::Suppressed);
        }
        if rule.severity < self.min_severity {
            return Some(Withheld::BelowSeverity);
        }
        None
    }

    /// Whether `rule` runs and reports under this configuration.
    #[must_use]
    pub fn enabled(&self, rule: &RuleMeta) -> bool {
        self.selected(rule) && self.withheld_reason(rule).is_none()
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
/// per-rule cap cannot be forgotten by one rule and honored by the rest.
pub(crate) struct FindingSink<'a> {
    /// The configuration deciding what survives.
    config: &'a LintConfig,
    /// Findings accepted so far.
    findings: Vec<Finding>,
    /// How many findings each rule has already contributed, by identifier.
    counts: Vec<(&'static str, usize)>,
    /// What the configuration kept back, by reason.
    withheld: WithheldCounts,
}

impl<'a> FindingSink<'a> {
    /// An empty sink bound to `config`.
    pub(crate) fn new(config: &'a LintConfig) -> Self {
        Self {
            config,
            findings: Vec::new(),
            counts: Vec::new(),
            withheld: WithheldCounts::default(),
        }
    }

    /// Whether a rule is worth evaluating at all.
    ///
    /// Deliberately does **not** short-circuit on suppression or on the
    /// severity floor, though it once did. Skipping a suppressed rule saves
    /// the work of evaluating it and destroys the only thing that could have
    /// counted its findings: a rule that never runs raises nothing, so
    /// `suppressed: 3` cannot be reconstructed afterwards from anything. The
    /// count is the whole point of the disclosure, so the rule runs and
    /// [`Self::push`] drops and counts the result.
    ///
    /// What still short-circuits is the pair that costs nothing to report:
    /// a rule outside the selected ruleset, which was never asked for, and a
    /// rule already at its cap, whose overflow is unbounded by construction.
    pub(crate) fn wants(&self, rule: &RuleMeta) -> bool {
        if !self.config.selected(rule) {
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

    /// Record a finding, or count the reason the configuration rejected it.
    ///
    /// Every rejection increments exactly one counter. A rejection that
    /// returns without counting is the defect this whole path exists to
    /// prevent — it hands the caller a short finding list with nothing to say
    /// the list is short.
    pub(crate) fn push(
        &mut self,
        rule: &RuleMeta,
        message_index: usize,
        observed: impl Into<String>,
        expected: impl Into<String>,
        explanation: impl Into<String>,
    ) {
        // Never asked for: not withheld from anyone, so not counted.
        if !self.config.selected(rule) {
            return;
        }
        if let Some(reason) = self.config.withheld_reason(rule) {
            match reason {
                Withheld::Suppressed => self.withheld.suppressed += 1,
                Withheld::BelowSeverity => self.withheld.below_severity += 1,
                // `withheld_reason` never returns this; the cap is per-sink
                // state and is handled below.
                Withheld::Capped => self.withheld.capped += 1,
            }
            return;
        }
        if self.config.max_per_rule != 0 && self.count_of(rule.id) >= self.config.max_per_rule {
            self.withheld.capped += 1;
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

    /// The findings and the counts, ordered by message index then rule id.
    pub(crate) fn finish_outcome(self) -> LintOutcome {
        let withheld = self.withheld;
        LintOutcome {
            findings: self.finish(),
            withheld,
        }
    }

    /// The collected findings, ordered by message index then rule identifier.
    pub(crate) fn finish(mut self) -> Vec<Finding> {
        crate::sort::sort_by_dyn(&mut self.findings, &mut |a, b| {
            a.message_index
                .cmp(&b.message_index)
                .then(a.rule_id.cmp(b.rule_id))
        });
        self.findings
    }
}

/// The conformance linter.
///
/// Holds a [`LintConfig`] and runs the catalog against a message, a dialog,
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

    /// Run the message-scoped rules against one message, keeping the counts.
    #[must_use]
    pub fn lint_message_detailed(&self, msg: &SipMessage, message_index: usize) -> LintOutcome {
        let mut sink = FindingSink::new(&self.config);
        message::lint(msg, message_index, &mut sink);
        sink.finish_outcome()
    }

    /// Run every rule against a dialog and its media, keeping the counts.
    ///
    /// The counts are the reason this exists beside
    /// [`Self::lint_dialog_with_media`]: a caller that reports findings to a
    /// human or an agent has to be able to say what it did not report.
    #[must_use]
    pub fn lint_dialog_with_media_detailed(
        &self,
        dialog: &SipDialog,
        media: &ObservedMedia,
    ) -> LintOutcome {
        let mut sink = FindingSink::new(&self.config);
        self.run_signalling(dialog, &mut sink);
        media::lint(dialog, media, &mut sink);
        sink.finish_outcome()
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

    /// Run every rule that does not need media against a dialog, keeping the
    /// counts.
    ///
    /// The signaling-only twin of [`Self::lint_dialog_with_media_detailed`],
    /// and it exists for the surface that needs it most. A CI run reading a
    /// capture file has no RTP attributed to it on the batch path, so the
    /// media entry point is the wrong one — and a gate that reports a short
    /// finding list without saying a `.sipnablint` shortened it is a gate
    /// reporting green for a reason nobody in the pipeline can see.
    #[must_use]
    pub fn lint_dialog_detailed(&self, dialog: &SipDialog) -> LintOutcome {
        let mut sink = FindingSink::new(&self.config);
        self.run_signalling(dialog, &mut sink);
        sink.finish_outcome()
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

    /// An exact suppression silences one rule and leaves its neighbors alone.
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

    /// The sink honors the per-rule cap and reports nothing beyond it.
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
    fn sink_drops_suppressed_rules_and_counts_every_one() {
        let config = LintConfig::new().suppress(BRANCH_COOKIE.id);
        let mut sink = FindingSink::new(&config);

        // `wants` deliberately still says yes. It used to say no, which saved
        // the work of evaluating a suppressed rule and destroyed the only
        // thing that could count its findings — the rule never ran, so there
        // was nothing to count and `suppressed: 3` could not be reconstructed
        // from anything afterwards.
        assert!(
            sink.wants(&BRANCH_COOKIE),
            "a suppressed rule must still evaluate, or its findings cannot be \
             counted and the caller is handed a short list with nothing saying \
             it is short"
        );

        for i in 0..3 {
            sink.push(&BRANCH_COOKIE, i, "o", "e", "x");
        }
        let outcome = sink.finish_outcome();
        assert!(
            outcome.findings.is_empty(),
            "suppressed findings are dropped"
        );
        assert_eq!(
            outcome.withheld.suppressed, 3,
            "every dropped finding is counted, not just the first"
        );
        assert_eq!(outcome.withheld.below_severity, 0);
        assert_eq!(outcome.withheld.capped, 0);
    }

    /// The three reasons are counted apart, because they mean different things.
    ///
    /// "You asked me not to see this", "there was too much of it" and "it was
    /// below your floor" send an operator to three different places. One
    /// combined `hidden` count would say something was withheld without saying
    /// why, which is only marginally better than saying nothing.
    #[test]
    fn withheld_reasons_are_counted_separately() {
        // MAX_FORWARDS_RANGE is a Notice, below a Warning floor.
        let config = LintConfig::new()
            .with_min_severity(Severity::Warning)
            .suppress(BRANCH_COOKIE.id)
            .with_max_per_rule(1);
        let mut sink = FindingSink::new(&config);

        sink.push(&BRANCH_COOKIE, 0, "o", "e", "x"); // suppressed
        sink.push(&MAX_FORWARDS_RANGE, 1, "o", "e", "x"); // below floor
        sink.push(&MAX_FORWARDS_MISSING, 2, "o", "e", "x"); // kept
        sink.push(&MAX_FORWARDS_MISSING, 3, "o", "e", "x"); // capped

        let outcome = sink.finish_outcome();
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.withheld.suppressed, 1);
        assert_eq!(outcome.withheld.below_severity, 1);
        assert_eq!(outcome.withheld.capped, 1);
        assert!(outcome.withheld.any());
    }

    /// A clean run reports zeroes rather than nothing.
    #[test]
    fn a_run_that_withheld_nothing_still_reports_counts() {
        let config = LintConfig::new();
        let mut sink = FindingSink::new(&config);
        sink.push(&BRANCH_COOKIE, 0, "o", "e", "x");
        let outcome = sink.finish_outcome();
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.withheld, WithheldCounts::default());
        assert!(!outcome.withheld.any());
    }

    /// A scratch directory tree for the discovery tests, removed on drop.
    struct Tree(std::path::PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("sipnab-lintdisc-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            Self(dir)
        }
        fn mkdir(&self, rel: &str) -> std::path::PathBuf {
            let d = self.0.join(rel);
            std::fs::create_dir_all(&d).expect("mkdir");
            d
        }
        fn touch(&self, rel: &str) {
            let f = self.0.join(rel);
            if let Some(parent) = f.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(&f, "SIP-3261-20-URI-BRACKETS\n").expect("write");
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A `.sipnablint` beside the capture is found.
    #[test]
    fn discovery_finds_the_file_beside_the_capture() {
        let t = Tree::new("beside");
        let caps = t.mkdir("caps");
        t.touch("caps/.sipnablint");
        assert_eq!(
            SuppressionFile::discover(&caps),
            Some(caps.join(SUPPRESSION_FILENAME))
        );
    }

    /// Inside a project, discovery climbs to the project root and stops there.
    #[test]
    fn discovery_climbs_to_the_project_root() {
        let t = Tree::new("climb");
        t.mkdir("proj/.git");
        let caps = t.mkdir("proj/captures/today");
        t.touch("proj/.sipnablint");
        assert_eq!(
            SuppressionFile::discover(&caps),
            Some(t.0.join("proj").join(SUPPRESSION_FILENAME))
        );
    }

    /// A capture in a directory that belongs to no project adopts nothing from
    /// above it.
    ///
    /// The case that matters: a corpus mount, `/tmp`, or a colleague's share.
    /// Silently inheriting somebody else's suppression list would switch rules
    /// off that nobody in this project turned off, and the run would look
    /// clean for a reason found four directories away.
    #[test]
    fn discovery_refuses_to_climb_out_of_an_unrelated_tree() {
        let t = Tree::new("unrelated");
        // A suppression file above the capture, and no `.git` anywhere.
        t.touch(".sipnablint");
        let caps = t.mkdir("corpus/vendor-drop");
        assert_eq!(
            SuppressionFile::discover(&caps),
            None,
            "no project above the capture means no upward search"
        );
    }

    /// The file nearest the capture wins over one higher up.
    #[test]
    fn discovery_prefers_the_closest_file() {
        let t = Tree::new("closest");
        t.mkdir("proj/.git");
        let caps = t.mkdir("proj/captures");
        t.touch("proj/.sipnablint");
        t.touch("proj/captures/.sipnablint");
        assert_eq!(
            SuppressionFile::discover(&caps),
            Some(caps.join(SUPPRESSION_FILENAME))
        );
    }

    /// Loading reads the patterns and remembers where they came from.
    #[test]
    fn a_loaded_file_remembers_its_own_path() {
        let t = Tree::new("load");
        let caps = t.mkdir("caps");
        std::fs::write(
            caps.join(SUPPRESSION_FILENAME),
            "# carrier rewrites these\nOBS-*, SIP-3261-20-URI-BRACKETS\n",
        )
        .expect("write");
        let file = SuppressionFile::load(caps.join(SUPPRESSION_FILENAME)).expect("load");
        assert_eq!(file.path(), caps.join(SUPPRESSION_FILENAME));
        assert_eq!(file.patterns(), ["OBS-*", "SIP-3261-20-URI-BRACKETS"]);

        let config = LintConfig::new().with_suppression_file(&file);
        assert!(!config.enabled(&PT_UNDECLARED));
        assert!(!config.enabled(&URI_BRACKETS));
        assert!(config.enabled(&MAX_FORWARDS_MISSING));
    }

    /// A named file that cannot be read is an error, never an empty list.
    #[test]
    fn a_missing_named_suppression_file_is_an_error() {
        let t = Tree::new("missing");
        assert!(SuppressionFile::load(t.0.join("nope.sipnablint")).is_err());
    }

    /// A rule outside the selected ruleset is not "withheld" from anybody.
    ///
    /// Counting it would report a media rule as suppressed on a `syntax` run,
    /// which reads as "something was hidden from you" when the caller simply
    /// did not ask for it.
    #[test]
    fn a_rule_outside_the_ruleset_is_not_counted_as_withheld() {
        let config = LintConfig::new().with_ruleset(Ruleset::Syntax);
        let mut sink = FindingSink::new(&config);
        sink.push(&PT_UNDECLARED, 0, "o", "e", "x");
        let outcome = sink.finish_outcome();
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.withheld, WithheldCounts::default());
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
