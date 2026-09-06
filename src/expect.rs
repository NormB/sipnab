// SPDX-License-Identifier: MIT OR Apache-2.0

//! Expectations: thresholds a capture is asserted to meet, evaluated as a gate.
//!
//! Every other analysis surface in this crate answers a question an operator
//! asked during an incident. This one answers a question nobody is present for:
//! a checked-in file states what the traffic must look like, a run compares the
//! capture against it, and the result is a verdict — not a report someone has
//! to read.
//!
//! # Why the evaluator lives here and not in the MCP server
//!
//! A gate that runs in CI needs an exit code and a gate an agent reasons about
//! needs a structured answer, and those must be the SAME judgement. The filter
//! parser is already shared across TUI, CLI, JSON and MCP for the same reason:
//! two implementations of "did this capture pass" would eventually disagree,
//! and the one that disagreed quietly would be the one CI was running.
//!
//! So this module owns the rules, the metrics and the verdict, and knows
//! nothing about MCP, JSON-RPC or `clap`. [`Report::exit_code`] is the shape a
//! command line consumes; [`Report`] serializes for everything else.
//!
//! The MCP tool `evaluate_expectations` is the only caller today. The command
//! line is NOT wired yet: [`Suite::from_toml_str`] and [`Report::exit_code`]
//! are the two halves it needs and they are tested, but no flag reaches them,
//! so a checked-in `sipnab.expect.toml` cannot yet fail a build on its own.
//!
//! # A gate that cannot report failure is worse than no gate
//!
//! Three failure modes get a gate deleted rather than fixed, and each one is
//! answered explicitly here:
//!
//! - **Passing on data it never judged.** A MOS threshold applied to a capture
//!   of AMR-WB scores every stream off a placeholder impairment value
//!   ([`crate::rtp::quality::mos_is_grounded`]), so the gate reports green
//!   having measured nothing. An empty population is therefore
//!   [`Verdict::Fail`], not a quiet pass — see [`ExpectRule::min_sample`] for
//!   the one way to ask for something else, in writing.
//! - **Failing on a sample too small to mean anything.** A three-call smoke
//!   test trips an ASR threshold, and on a Friday afternoon the gate gets
//!   deleted. `min_sample` is the declared floor below which a rule reports
//!   [`Verdict::Skipped`] instead of a verdict it cannot support.
//! - **Lying about coverage.** A suite where every rule skipped is not a pass;
//!   it is [`SuiteVerdict::NotEvaluated`], with its own exit code, because a
//!   file full of rules that never run is exactly the thing that stays in the
//!   repository claiming to check something.

use serde::{Deserialize, Serialize};

use crate::rtp::diagnosis::CaptureMedia;
use crate::rtp::quality::{MosDelay, mos_is_grounded};
use crate::rtp::stream::RtpStream;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog::SipDialog;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::{AliasThresholds, FilterExpr, expand_alias};
use crate::sip::lint::{LintConfig, Linter, ObservedMedia, Severity, SuppressionFile};
use crate::sip::method::SipMethod;

/// Version stamped on every [`Report`], so a consumer can tell an older
/// answer's shape from a newer one without guessing from the fields present.
pub const SCHEMA_VERSION: u32 = 1;

/// Every metric name a rule may ask for, in the spelling the file uses.
///
/// Listed once and used by both the parser and the refusal message, so a name
/// can never be accepted without being offered or offered without being
/// accepted — the same discipline `aggregate_dialogs` applies to its groupable
/// keys.
pub const METRIC_NAMES: &[&str] = &["count", "asr", "lint_errors", "mos_p<N>"];

/// The comparison a rule applies between the observed value and its threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum Op {
    /// Observed value must be at least the threshold.
    #[serde(rename = ">=")]
    Ge,
    /// Observed value must exceed the threshold.
    #[serde(rename = ">")]
    Gt,
    /// Observed value must be at most the threshold.
    #[serde(rename = "<=")]
    Le,
    /// Observed value must be below the threshold.
    #[serde(rename = "<")]
    Lt,
    /// Observed value must equal the threshold exactly.
    #[serde(rename = "==")]
    Eq,
    /// Observed value must differ from the threshold.
    #[serde(rename = "!=")]
    Ne,
}

impl Op {
    /// The operator as it is written in a rule file.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ge => ">=",
            Self::Gt => ">",
            Self::Le => "<=",
            Self::Lt => "<",
            Self::Eq => "==",
            Self::Ne => "!=",
        }
    }

    /// Whether `observed` satisfies this comparison against `threshold`.
    ///
    /// `==` and `!=` compare exactly. Counts are integers and compare cleanly;
    /// a ratio or a percentile almost never lands on a decimal fraction a human
    /// would write, so [`Verdict`] carries the observed value at full precision
    /// and the reason string quotes it — an equality that surprises its author
    /// is at least diagnosable from the answer.
    #[must_use]
    fn holds(self, observed: f64, threshold: f64) -> bool {
        match self {
            Self::Ge => observed >= threshold,
            Self::Gt => observed > threshold,
            Self::Le => observed <= threshold,
            Self::Lt => observed < threshold,
            Self::Eq => observed == threshold,
            Self::Ne => observed != threshold,
        }
    }
}

/// One expectation: a metric, a comparison, a threshold, and what it applies to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ExpectRule {
    /// Optional label carried through to the outcome, so a failing rule can be
    /// named in a CI log without quoting its whole definition back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What to measure: `count`, `asr`, `lint_errors`, or `mos_p<N>` for a
    /// percentile of the estimated MOS (`mos_p0` is the worst stream,
    /// `mos_p100` the best).
    pub metric: String,
    /// The comparison the observed value must satisfy.
    pub op: Op,
    /// The threshold the observed value is compared against.
    pub value: f64,
    /// What the rule applies to: `filter:<alias-or-DSL-expression>` to narrow
    /// by dialog, or `severity:<info|notice|warning|error>` to set the floor a
    /// `lint_errors` rule counts from. Omitted means the whole capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Observations below which this rule reports [`Verdict::Skipped`] rather
    /// than a verdict.
    ///
    /// A floor of 1 or more is also the only way to ask that an EMPTY
    /// population be tolerated: without one, a rule that measured nothing
    /// fails. That asymmetry is the point — a gate goes quiet only where its
    /// author wrote down that it may, and `min_sample: 0` declares no floor at
    /// all, so it leaves the empty case failing exactly as an absent one does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_sample: Option<u64>,
    /// Whether a MOS metric may only read streams whose codec has a real
    /// impairment value. Defaults to `true`; setting it `false` admits the
    /// placeholder score and stamps a caveat on the outcome.
    ///
    /// Rejected on any metric that is not a MOS percentile, because a knob that
    /// parses and does nothing is indistinguishable from one that works.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grounded_only: Option<bool>,
}

/// A checked-in set of expectations — the contents of a `sipnab.expect.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Suite {
    /// The rules, evaluated in the order written.
    #[serde(default)]
    pub rules: Vec<ExpectRule>,
}

impl Suite {
    /// Parse a suite from the text of a rule file.
    ///
    /// TOML rather than the YAML the design note sketched: this crate already
    /// parses TOML for `sipnabrc`, and a gate is not worth a new parser
    /// dependency in the supply chain of a packet-capture tool.
    ///
    /// # Errors
    ///
    /// The TOML parse error, unchanged — it names the line.
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

/// Why a suite could not be evaluated at all.
///
/// Every variant is a defect in the RULES, not in the capture. They are hard
/// errors rather than per-rule failures on purpose: a misspelled metric that
/// evaluated to "fail" would be indistinguishable from traffic that genuinely
/// broke the threshold, and one that evaluated to "pass" would be a gate that
/// checks nothing while looking green.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// The suite had no rules in it.
    #[error(
        "an expectation suite must contain at least one rule; an empty suite \
         passes every capture and reports nothing"
    )]
    NoRules,
    /// The metric name is not one this evaluator computes.
    #[error(
        "rule {index}: unknown metric '{metric}'. Known metrics: {}. \
         A percentile is spelled mos_p10, mos_p50, mos_p90 and so on, from \
         mos_p0 (worst stream) to mos_p100 (best)",
        METRIC_NAMES.join(", ")
    )]
    UnknownMetric {
        /// Position of the offending rule in the suite.
        index: usize,
        /// The name as written.
        metric: String,
    },
    /// The scope string carried no recognized prefix.
    #[error(
        "rule {index}: scope '{scope}' must start with 'filter:' (a dialog \
         alias or DSL expression) or 'severity:' (info, notice, warning, error)"
    )]
    UnknownScopeKind {
        /// Position of the offending rule in the suite.
        index: usize,
        /// The scope as written.
        scope: String,
    },
    /// The `filter:` half of a scope was neither an alias nor parseable.
    #[error("rule {index}: invalid filter '{filter}': {reason}")]
    BadFilter {
        /// Position of the offending rule in the suite.
        index: usize,
        /// The expression as written.
        filter: String,
        /// What the DSL parser said.
        reason: String,
    },
    /// The `severity:` half of a scope named no known severity.
    #[error("rule {index}: unknown severity '{name}'. Valid values: info, notice, warning, error")]
    UnknownSeverity {
        /// Position of the offending rule in the suite.
        index: usize,
        /// The severity as written.
        name: String,
    },
    /// A severity scope was applied to a metric that reads no findings.
    #[error(
        "rule {index}: metric '{metric}' has no severities to select on; \
         'severity:' scopes apply to lint_errors only"
    )]
    SeverityScopeOnNonLintMetric {
        /// Position of the offending rule in the suite.
        index: usize,
        /// The metric as written.
        metric: String,
    },
    /// `grounded_only` was set on a metric that reads no MOS.
    #[error(
        "rule {index}: grounded_only applies to the mos_p<N> metrics only, and \
         metric '{metric}' reads no MOS. Remove it rather than leaving a \
         setting that parses and does nothing"
    )]
    GroundedOnlyOnNonMosMetric {
        /// Position of the offending rule in the suite.
        index: usize,
        /// The metric as written.
        metric: String,
    },
    /// A percentile outside 0..=100 was asked for.
    #[error("rule {index}: '{metric}' asks for percentile {percentile}; valid range is 0 to 100")]
    PercentileOutOfRange {
        /// Position of the offending rule in the suite.
        index: usize,
        /// The metric as written.
        metric: String,
        /// The number parsed out of it.
        percentile: u32,
    },
}

/// What a metric reads, once its name has been parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Metric {
    /// Dialogs matching the scope, counted.
    Count,
    /// Answer-seizure ratio over the dialogs in scope.
    Asr,
    /// Lint findings at or above the severity floor, counted.
    LintErrors,
    /// A percentile of the estimated MOS across the streams in scope.
    MosPercentile(u8),
}

impl Metric {
    /// Parse a metric name, or `None` when it is not one this evaluator knows.
    fn parse(name: &str) -> Option<Result<Self, u32>> {
        match name {
            "count" => Some(Ok(Self::Count)),
            "asr" => Some(Ok(Self::Asr)),
            "lint_errors" => Some(Ok(Self::LintErrors)),
            other => {
                let digits = other.strip_prefix("mos_p")?;
                // A percentile is what follows `mos_p`, and nothing else may:
                // `mos_p10x` and `mos_p ` are misspellings, not percentiles.
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let n: u32 = digits.parse().ok()?;
                Some(
                    u8::try_from(n)
                        .ok()
                        .filter(|p| *p <= 100)
                        .map_or(Err(n), |p| Ok(Self::MosPercentile(p))),
                )
            }
        }
    }

    /// Whether this metric summarizes RTP streams rather than dialogs.
    fn reads_streams(self) -> bool {
        matches!(self, Self::MosPercentile(_))
    }

    /// The unit the observed value is expressed in.
    ///
    /// Published on every outcome rather than left to documentation, because a
    /// threshold of `0.99` means "99%" under one reading and "1%" under the
    /// other, and a unit beside the number is what stops that being a silent
    /// misconfiguration.
    ///
    /// This comment used to say `asr` is "a RATIO here and a PERCENT in
    /// `group_dialogs`", three lines above the match arm returning `"percent"`.
    /// The tool description repeated the same error, so a client was told to
    /// write `0.95` for a 95% gate -- which passes at 0.95 percent. Measured on
    /// `sip-problem-call.pcap`: `asr >= 0.95` returned `observed: 20.0,
    /// verdict: "pass", exit_code: 0`. **`asr` is a PERCENT, here and
    /// everywhere.**
    fn unit(self) -> &'static str {
        match self {
            Self::Count => "dialogs",
            Self::Asr => "percent",
            Self::LintErrors => "findings",
            Self::MosPercentile(_) => "mos (1.0-5.0)",
        }
    }

    /// The unit the observed value carries, for the reason string.
    fn population_noun(self) -> &'static str {
        match self {
            Self::Count | Self::LintErrors => "dialog",
            Self::Asr => "seizure",
            Self::MosPercentile(_) => "scored stream",
        }
    }
}

/// What a rule applies to, once its scope string has been compiled.
#[derive(Debug)]
enum Scope {
    /// The whole capture.
    All,
    /// The dialogs a DSL expression selects.
    Filter(Box<FilterExpr>),
    /// The severity floor a lint count starts at.
    MinSeverity(Severity),
}

/// One rule, validated and ready to run.
#[derive(Debug)]
struct CompiledRule<'a> {
    /// Position in the suite, echoed into the outcome.
    index: usize,
    /// The rule as written.
    spec: &'a ExpectRule,
    /// What it measures.
    metric: Metric,
    /// What it measures over.
    scope: Scope,
}

/// The verdict on one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The observed value satisfied the comparison.
    Pass,
    /// It did not, or there was nothing to judge and the rule did not say that
    /// was acceptable.
    Fail,
    /// The population was below the floor the rule declared.
    Skipped,
}

/// The verdict on the suite as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiteVerdict {
    /// Every rule that ran passed, and at least one ran.
    Pass,
    /// At least one rule failed.
    Fail,
    /// Nothing ran. Distinct from [`Self::Pass`] on purpose: a suite whose
    /// every rule skipped has checked nothing, and reporting that as success is
    /// how a gate ends up in a repository lying about its coverage.
    NotEvaluated,
}

/// What one rule observed and what that means.
#[derive(Debug, Clone, Serialize)]
pub struct RuleOutcome {
    /// Position in the suite, so a failure can be traced to a line.
    pub index: usize,
    /// The rule's label, when it declared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The metric, as written.
    pub metric: String,
    /// The unit `observed` and `threshold` are both expressed in.
    pub unit: &'static str,
    /// The comparison, as written.
    pub op: &'static str,
    /// The threshold, as written.
    pub threshold: f64,
    /// The scope, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// What the capture showed. `None` when there was nothing to measure.
    pub observed: Option<f64>,
    /// How many observations the value was computed from.
    pub sample: u64,
    /// The floor the rule declared, when it declared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_sample: Option<u64>,
    /// Streams a MOS metric could not judge because their codec has no
    /// published impairment value. Present on MOS rules only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ungrounded_excluded: Option<u64>,
    /// The verdict.
    pub verdict: Verdict,
    /// One sentence saying what happened, quoting the numbers.
    pub reason: String,
    /// Anything true of this answer that the verdict alone does not say.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// The result of evaluating a suite against one capture.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Shape version — see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The verdict on the suite.
    pub verdict: SuiteVerdict,
    /// The process exit status a command line would carry — see
    /// [`Report::exit_code`].
    pub exit_code: i32,
    /// Rules in the suite.
    pub rules_total: usize,
    /// Rules that produced a verdict (passed plus failed).
    pub evaluated: usize,
    /// Rules that passed.
    pub passed: usize,
    /// Rules that failed.
    pub failed: usize,
    /// Rules skipped for want of a large enough population.
    pub skipped: usize,
    /// Dialogs the capture held when the suite ran.
    pub dialogs_in_capture: usize,
    /// RTP streams the capture held when the suite ran.
    pub streams_in_capture: usize,
    /// Whether a lint suppression file was in force for the `lint_errors`
    /// rules, so a count of zero cannot be mistaken for one taken with every
    /// rule armed.
    pub suppressions_applied: bool,
    /// One entry per rule, in suite order.
    pub results: Vec<RuleOutcome>,
}

impl Report {
    /// The exit status a command line reports.
    ///
    /// `0` every rule that ran passed, `1` at least one failed, `2` nothing
    /// ran. The third code exists because CI must be able to tell a green run
    /// from a run that judged nothing, and a shell script comparing against `0`
    /// cannot.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self.verdict {
            SuiteVerdict::Pass => 0,
            SuiteVerdict::Fail => 1,
            SuiteVerdict::NotEvaluated => 2,
        }
    }
}

/// Everything one evaluation reads beyond the rules themselves.
pub struct Inputs<'a> {
    /// The dialogs the capture holds.
    pub dialogs: &'a DialogStore,
    /// The RTP streams the capture holds.
    pub streams: &'a StreamStore,
    /// The figures the diagnostic filter aliases compare against, so a suite
    /// and the operator's tuned `[diagnosis]` section agree.
    pub thresholds: &'a AliasThresholds,
    /// The suppression file in force, when one applies.
    ///
    /// The gate honors it for the same reason `lint_dialog` does: a rule an
    /// operator has silenced in writing must not be the reason a build stays
    /// red, or the gate is unfixable and gets removed.
    pub suppressions: Option<&'a SuppressionFile>,
}

/// Evaluate a suite of rules against one capture.
///
/// # Errors
///
/// [`RuleError`] when the suite itself is malformed — an unknown metric, an
/// unparseable filter, a scope or a setting that does not apply to the metric
/// it was written on. A malformed suite is never evaluated in part: half a gate
/// reporting green is the outcome this refuses to produce.
pub fn evaluate(rules: &[ExpectRule], inputs: &Inputs<'_>) -> Result<Report, RuleError> {
    if rules.is_empty() {
        return Err(RuleError::NoRules);
    }

    let mut compiled = Vec::with_capacity(rules.len());
    for (index, spec) in rules.iter().enumerate() {
        compiled.push(compile(index, spec, inputs.thresholds)?);
    }

    // Group streams by Call-ID once. `streams_for` walks the whole stream store
    // per dialog, and a suite runs several rules over every dialog in the
    // capture — the same reason `dialog_page` groups rather than re-scanning.
    let mut by_call: std::collections::HashMap<&str, Vec<&RtpStream>> =
        std::collections::HashMap::new();
    for s in inputs.streams.iter() {
        if let Some(id) = s.associated_dialog.as_deref() {
            by_call.entry(id).or_default().push(s);
        }
    }
    let no_streams: Vec<&RtpStream> = Vec::new();
    let capture = CaptureMedia::of_store(inputs.streams);
    let delay = MosDelay::from_capture(inputs.streams);

    let mut results = Vec::with_capacity(compiled.len());
    for rule in &compiled {
        let measured = measure(rule, inputs, &by_call, &no_streams, capture, delay);
        results.push(judge(rule, measured));
    }

    let passed = results
        .iter()
        .filter(|r| r.verdict == Verdict::Pass)
        .count();
    let failed = results
        .iter()
        .filter(|r| r.verdict == Verdict::Fail)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.verdict == Verdict::Skipped)
        .count();
    let evaluated = passed + failed;
    let verdict = if failed > 0 {
        SuiteVerdict::Fail
    } else if evaluated == 0 {
        SuiteVerdict::NotEvaluated
    } else {
        SuiteVerdict::Pass
    };

    let mut report = Report {
        schema_version: SCHEMA_VERSION,
        verdict,
        exit_code: 0,
        rules_total: rules.len(),
        evaluated,
        passed,
        failed,
        skipped,
        dialogs_in_capture: inputs.dialogs.len(),
        streams_in_capture: inputs.streams.len(),
        suppressions_applied: inputs.suppressions.is_some(),
        results,
    };
    report.exit_code = report.exit_code();
    Ok(report)
}

/// Validate one rule and compile its scope.
fn compile<'a>(
    index: usize,
    spec: &'a ExpectRule,
    thresholds: &AliasThresholds,
) -> Result<CompiledRule<'a>, RuleError> {
    let metric = match Metric::parse(&spec.metric) {
        Some(Ok(m)) => m,
        Some(Err(percentile)) => {
            return Err(RuleError::PercentileOutOfRange {
                index,
                metric: spec.metric.clone(),
                percentile,
            });
        }
        None => {
            return Err(RuleError::UnknownMetric {
                index,
                metric: spec.metric.clone(),
            });
        }
    };

    if spec.grounded_only.is_some() && !metric.reads_streams() {
        return Err(RuleError::GroundedOnlyOnNonMosMetric {
            index,
            metric: spec.metric.clone(),
        });
    }

    let scope = match spec.scope.as_deref() {
        None => Scope::All,
        Some(raw) => {
            if let Some(expr) = raw.strip_prefix("filter:") {
                let expanded = expand_alias(expr, thresholds);
                let text = expanded.as_deref().unwrap_or(expr);
                Scope::Filter(Box::new(FilterExpr::parse(text).map_err(|e| {
                    RuleError::BadFilter {
                        index,
                        filter: expr.to_string(),
                        reason: e.to_string(),
                    }
                })?))
            } else if let Some(name) = raw.strip_prefix("severity:") {
                if metric != Metric::LintErrors {
                    return Err(RuleError::SeverityScopeOnNonLintMetric {
                        index,
                        metric: spec.metric.clone(),
                    });
                }
                Scope::MinSeverity(Severity::from_name(name).ok_or_else(|| {
                    RuleError::UnknownSeverity {
                        index,
                        name: name.to_string(),
                    }
                })?)
            } else {
                return Err(RuleError::UnknownScopeKind {
                    index,
                    scope: raw.to_string(),
                });
            }
        }
    };

    Ok(CompiledRule {
        index,
        spec,
        metric,
        scope,
    })
}

/// What one rule read off the capture, before any verdict is applied.
struct Measured {
    /// The value, or `None` when nothing could be measured.
    value: Option<f64>,
    /// How many observations it rests on.
    sample: u64,
    /// Streams a MOS rule could not judge. `None` on every other metric.
    ungrounded_excluded: Option<u64>,
    /// Anything true of the measurement the numbers do not say.
    notes: Vec<String>,
}

/// Run one rule's metric over the capture.
fn measure(
    rule: &CompiledRule<'_>,
    inputs: &Inputs<'_>,
    by_call: &std::collections::HashMap<&str, Vec<&RtpStream>>,
    no_streams: &Vec<&RtpStream>,
    capture: CaptureMedia,
    delay: MosDelay<'_>,
) -> Measured {
    let filter = match &rule.scope {
        Scope::Filter(f) => Some(f.as_ref()),
        Scope::All | Scope::MinSeverity(_) => None,
    };
    let selected: Vec<&SipDialog> = inputs
        .dialogs
        .iter()
        .filter(|d| {
            filter.is_none_or(|f| {
                let streams = by_call.get(d.call_id.as_str()).unwrap_or(no_streams);
                f.matches_dialog(d, streams, capture, delay)
            })
        })
        .collect();

    match rule.metric {
        // The population is the whole capture, not the selection: "no call was
        // rejected with 488" is a real and passing answer on a capture full of
        // healthy calls, and only an EMPTY capture leaves that claim resting on
        // nothing.
        Metric::Count => Measured {
            value: Some(selected.len() as f64),
            sample: inputs.dialogs.len() as u64,
            ungrounded_excluded: None,
            notes: Vec::new(),
        },
        Metric::Asr => measure_asr(&selected),
        Metric::LintErrors => measure_lint(rule, inputs, &selected, by_call, no_streams),
        Metric::MosPercentile(p) => measure_mos(rule, inputs, filter, &selected, by_call, delay, p),
    }
}

/// Answered calls over seized calls, across the selected dialogs.
fn measure_asr(selected: &[&SipDialog]) -> Measured {
    let mut seizures = 0u64;
    let mut answered = 0u64;
    let mut undecided = 0u64;
    for d in selected {
        if d.method != SipMethod::Invite {
            continue;
        }
        // A call still ringing has not been answered AND has not been refused.
        // Counting it in the denominator would drive ASR toward zero on a live
        // capture simply because calls are in progress.
        let Some(code) = d.final_status_code() else {
            undecided += 1;
            continue;
        };
        seizures += 1;
        if (200..300).contains(&code) {
            answered += 1;
        }
    }
    let mut notes = Vec::new();
    if undecided > 0 {
        notes.push(format!(
            "{undecided} INVITE dialog(s) had no final response yet and are in \
             neither the numerator nor the denominator"
        ));
    }
    Measured {
        // PERCENT, not a ratio. ASR is a percentage everywhere it is used in
        // telecom -- ITU-T reporting, carrier scorecards, and `group_dialogs`,
        // which is the tool an operator reads before writing a rule about what
        // they saw. Two surfaces meaning different things by one word is how a
        // threshold gets copied between them and lands wrong by 100x, so both
        // are percent. The backlog's illustrative `value: 0.99` predates either
        // implementation and would be `99` here.
        value: (seizures > 0).then(|| (answered as f64 / seizures as f64) * 100.0),
        sample: seizures,
        ungrounded_excluded: None,
        notes,
    }
}

/// Conformance findings at or above the rule's severity floor.
fn measure_lint(
    rule: &CompiledRule<'_>,
    inputs: &Inputs<'_>,
    selected: &[&SipDialog],
    by_call: &std::collections::HashMap<&str, Vec<&RtpStream>>,
    no_streams: &Vec<&RtpStream>,
) -> Measured {
    // `error` unless the rule named a floor: the metric is called lint_errors,
    // and a default that counted every info finding would make the obvious
    // `lint_errors == 0` rule unsatisfiable on any real capture.
    let min_severity = match &rule.scope {
        Scope::MinSeverity(s) => *s,
        Scope::All | Scope::Filter(_) => Severity::Error,
    };
    let mut config = LintConfig::new().with_min_severity(min_severity);
    if let Some(file) = inputs.suppressions {
        config = config.with_suppression_file(file);
    }
    let linter = Linter::new(config);

    let mut findings = 0u64;
    for d in selected {
        let streams = by_call.get(d.call_id.as_str()).unwrap_or(no_streams);
        let media = ObservedMedia::from_streams(streams.iter().copied());
        findings += linter
            .lint_dialog_with_media_detailed(d, &media)
            .findings
            .len() as u64;
    }
    Measured {
        value: Some(findings as f64),
        sample: selected.len() as u64,
        ungrounded_excluded: None,
        notes: vec![format!(
            "counted findings at severity {} and above",
            min_severity.as_str()
        )],
    }
}

/// A percentile of the estimated MOS across the streams in scope.
fn measure_mos(
    rule: &CompiledRule<'_>,
    inputs: &Inputs<'_>,
    filter: Option<&FilterExpr>,
    selected: &[&SipDialog],
    by_call: &std::collections::HashMap<&str, Vec<&RtpStream>>,
    delay: MosDelay<'_>,
    percentile: u8,
) -> Measured {
    let grounded_only = rule.spec.grounded_only.unwrap_or(true);
    let mut notes = Vec::new();

    // With no filter the population is every stream the capture holds, orphans
    // included — a stream with no dialog is what one-way audio looks like from
    // the media side, and a MOS gate that could not see one would be blind to
    // the fault it exists to catch. A filter selects DIALOGS, so it can only
    // reach the streams attributed to them.
    let population: Vec<&RtpStream> = match filter {
        None => inputs.streams.iter().collect(),
        Some(_) => {
            notes.push(
                "a filter scope selects dialogs, so orphaned streams — those \
                 attributed to no call — are outside this rule"
                    .to_string(),
            );
            selected
                .iter()
                .filter_map(|d| by_call.get(d.call_id.as_str()))
                .flatten()
                .copied()
                .collect()
        }
    };

    let mut ungrounded = 0u64;
    let mut scores: Vec<f64> = Vec::with_capacity(population.len());
    for s in population {
        if grounded_only && !mos_is_grounded(s.codec.as_deref()) {
            ungrounded += 1;
            continue;
        }
        scores.push(delay.score(s));
    }
    if grounded_only && ungrounded > 0 {
        notes.push(format!(
            "{ungrounded} stream(s) were excluded: their codec has no published \
             impairment value, so any MOS for them is a placeholder"
        ));
    }
    if !grounded_only {
        notes.push(
            "grounded_only is off, so streams whose codec has no published \
             impairment value contributed a placeholder score to this \
             percentile"
                .to_string(),
        );
    }

    crate::sort::sort_by_dyn(&mut scores, &mut |a: &f64, b: &f64| a.total_cmp(b));
    Measured {
        value: nearest_rank(&scores, percentile),
        sample: scores.len() as u64,
        ungrounded_excluded: Some(ungrounded),
        notes,
    }
}

/// The nearest-rank percentile of an ascending slice.
///
/// Nearest rank rather than an interpolated one because every value it can
/// return is a MOS some stream actually scored. An interpolated p10 on a
/// two-stream capture reports a number no call experienced, which is the wrong
/// thing to fail a build on.
fn nearest_rank(sorted: &[f64], percentile: u8) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let n = sorted.len();
    // p0 is the minimum: rank 0 does not exist, so it clamps to the first
    // element rather than to nothing.
    let rank = (f64::from(percentile) / 100.0 * n as f64).ceil() as usize;
    sorted.get(rank.clamp(1, n) - 1).copied()
}

/// Turn a measurement into a verdict.
fn judge(rule: &CompiledRule<'_>, measured: Measured) -> RuleOutcome {
    let spec = rule.spec;
    let noun = rule.metric.population_noun();
    let mut outcome = RuleOutcome {
        index: rule.index,
        name: spec.name.clone(),
        metric: spec.metric.clone(),
        unit: rule.metric.unit(),
        op: spec.op.as_str(),
        threshold: spec.value,
        scope: spec.scope.clone(),
        observed: measured.value,
        sample: measured.sample,
        min_sample: spec.min_sample,
        ungrounded_excluded: measured.ungrounded_excluded,
        verdict: Verdict::Fail,
        reason: String::new(),
        notes: measured.notes,
    };

    if let Some(floor) = spec.min_sample
        && measured.sample < floor
    {
        outcome.verdict = Verdict::Skipped;
        outcome.reason = format!(
            "skipped: {} {noun}(s) is below the declared min_sample of {floor}",
            measured.sample
        );
        return outcome;
    }

    // Tested on the SAMPLE, not on whether a value came back. `count` always
    // produces one — zero matches is zero — so a check on the value alone let
    // `count == 0` report a pass on a capture holding no dialogs at all, which
    // is the exact "green on data it never judged" this module exists to
    // prevent. An integration test over a fixture with four RTP streams and no
    // dialogs is what caught it.
    if measured.sample == 0 || measured.value.is_none() {
        outcome.verdict = Verdict::Fail;
        outcome.reason = format!(
            "unevaluable: no {noun} was in scope, so '{} {} {}' rests on \
             nothing. Declare a min_sample of 1 or more to accept an empty \
             population in writing; a gate does not pass on data it never \
             judged",
            spec.metric,
            spec.op.as_str(),
            spec.value
        );
        return outcome;
    }
    let Some(value) = measured.value else {
        // Unreachable given the check above, and left as a refusal rather than
        // a default because the alternative is inventing a number to compare.
        outcome.verdict = Verdict::Fail;
        outcome.reason = "unevaluable: the metric produced no value".to_string();
        return outcome;
    };

    if spec.op.holds(value, spec.value) {
        outcome.verdict = Verdict::Pass;
        outcome.reason = format!(
            "{} is {} {} over {} {noun}(s)",
            format_value(value),
            spec.op.as_str(),
            format_value(spec.value),
            measured.sample
        );
    } else {
        outcome.verdict = Verdict::Fail;
        outcome.reason = format!(
            "{} is NOT {} {} over {} {noun}(s)",
            format_value(value),
            spec.op.as_str(),
            format_value(spec.value),
            measured.sample
        );
    }
    outcome
}

/// Render a measured value without trailing noise.
///
/// A count reads as `3` rather than `3.0000000000` and a ratio keeps enough
/// digits to explain a near miss, because the reason string is what an operator
/// reads before deciding whether the gate or the traffic is wrong.
fn format_value(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{v:.0}")
    } else {
        format!("{v:.4}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule with only the required fields set.
    fn rule(metric: &str, op: Op, value: f64) -> ExpectRule {
        ExpectRule {
            name: None,
            metric: metric.to_string(),
            op,
            value,
            scope: None,
            min_sample: None,
            grounded_only: None,
        }
    }

    /// A compiled rule around a spec, for the verdict tests below.
    fn compiled<'a>(spec: &'a ExpectRule, metric: Metric) -> CompiledRule<'a> {
        CompiledRule {
            index: 0,
            spec,
            metric,
            scope: Scope::All,
        }
    }

    /// A measurement with a value and a sample behind it.
    fn measured(value: Option<f64>, sample: u64) -> Measured {
        Measured {
            value,
            sample,
            ungrounded_excluded: None,
            notes: Vec::new(),
        }
    }

    /// A rule whose population is empty FAILS, and says it judged nothing.
    ///
    /// This is the defect the module exists to prevent, recorded in its own
    /// comment: `count == 0` always produces a value, so a check on the value
    /// alone let a `count == 0` rule report a pass against a capture holding
    /// no dialogs at all. The test is on the SAMPLE for that reason.
    #[test]
    fn a_rule_with_nothing_in_scope_fails_rather_than_passing_on_no_data() {
        let spec = rule("count", Op::Eq, 0.0);
        let out = judge(&compiled(&spec, Metric::Count), measured(Some(0.0), 0));
        assert_eq!(
            out.verdict,
            Verdict::Fail,
            "a gate must not pass on data it never judged: {}",
            out.reason
        );
        assert!(
            out.reason.contains("unevaluable") && out.reason.contains("rests on"),
            "and it must say the population was empty: {}",
            out.reason
        );
        assert!(
            out.reason.contains("min_sample"),
            "and name the way to accept an empty population deliberately: {}",
            out.reason
        );
    }

    /// A sample below the declared floor is SKIPPED, not failed.
    ///
    /// Skipped and failed are different answers: a suite that turned a thin
    /// capture into a red build would train its readers to ignore red.
    #[test]
    fn a_sample_below_min_sample_is_skipped_not_failed() {
        let mut spec = rule("asr", Op::Ge, 90.0);
        spec.min_sample = Some(50);
        let out = judge(&compiled(&spec, Metric::Asr), measured(Some(10.0), 7));
        assert_eq!(out.verdict, Verdict::Skipped);
        assert!(
            out.reason.contains("7") && out.reason.contains("50"),
            "the reason names both the sample it had and the floor it wanted: {}",
            out.reason
        );
    }

    /// The floor is a minimum, so a sample exactly at it is judged.
    #[test]
    fn a_sample_exactly_at_min_sample_is_judged() {
        let mut spec = rule("asr", Op::Ge, 90.0);
        spec.min_sample = Some(5);
        let out = judge(&compiled(&spec, Metric::Asr), measured(Some(95.0), 5));
        assert_eq!(
            out.verdict,
            Verdict::Pass,
            "min_sample is a minimum, not a threshold to exceed: {}",
            out.reason
        );
    }

    /// A measurement that produced no value is unevaluable, never a pass.
    #[test]
    fn a_metric_that_produced_no_value_is_unevaluable() {
        let spec = rule("mos_p10", Op::Ge, 3.5);
        let out = judge(
            &compiled(&spec, Metric::MosPercentile(10)),
            measured(None, 4),
        );
        assert_eq!(out.verdict, Verdict::Fail);
        assert!(out.reason.contains("unevaluable"), "reason: {}", out.reason);
    }

    /// A satisfied comparison passes and carries what it observed.
    #[test]
    fn a_satisfied_rule_passes_and_reports_the_observation() {
        let spec = rule("asr", Op::Ge, 90.0);
        let out = judge(&compiled(&spec, Metric::Asr), measured(Some(97.5), 40));
        assert_eq!(out.verdict, Verdict::Pass);
        assert_eq!(out.observed, Some(97.5));
        assert_eq!(out.sample, 40);
        assert_eq!(out.threshold, 90.0);
    }

    /// An unsatisfied comparison fails, and the outcome still carries the
    /// observation rather than only the verdict.
    #[test]
    fn an_unsatisfied_rule_fails_and_still_reports_what_it_saw() {
        let spec = rule("asr", Op::Ge, 90.0);
        let out = judge(&compiled(&spec, Metric::Asr), measured(Some(42.0), 40));
        assert_eq!(out.verdict, Verdict::Fail);
        assert_eq!(
            out.observed,
            Some(42.0),
            "a failing rule that hid its observation would leave a reader \
             unable to tell a near miss from a collapse"
        );
    }

    /// Notes on the measurement survive into the outcome.
    ///
    /// The notes carry what the numbers do not say -- which streams were
    /// excluded and why. Dropping them at the verdict would leave a percentile
    /// looking like it covered a population it did not.
    #[test]
    fn measurement_notes_reach_the_outcome() {
        let spec = rule("mos_p10", Op::Ge, 3.0);
        let m = Measured {
            value: Some(4.1),
            sample: 3,
            ungrounded_excluded: Some(2),
            notes: vec!["2 stream(s) were excluded".to_string()],
        };
        let out = judge(&compiled(&spec, Metric::MosPercentile(10)), m);
        assert_eq!(out.ungrounded_excluded, Some(2));
        assert_eq!(out.notes, vec!["2 stream(s) were excluded".to_string()]);
    }

    /// A whole number prints without a decimal tail; anything else gets four
    /// places.
    ///
    /// A count rendered as `12.0000` reads as a measurement with precision it
    /// does not have, and a MOS rendered as `4` hides the difference between
    /// 4.0 and 4.4999.
    #[test]
    fn values_print_as_counts_or_as_measurements() {
        assert_eq!(format_value(12.0), "12");
        assert_eq!(format_value(0.0), "0");
        assert_eq!(format_value(-3.0), "-3");
        assert_eq!(format_value(4.25), "4.2500");
        assert_eq!(format_value(97.5), "97.5000");
    }

    /// The nearest rank is a real observation at every percentile, including
    /// the ends.
    ///
    /// Interpolation would answer with a MOS no stream scored, which is the
    /// wrong thing to fail a build on.
    #[test]
    fn nearest_rank_returns_an_observed_value_at_both_ends() {
        let sorted = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(nearest_rank(&sorted, 0), Some(1.0), "p0 is the lowest");
        assert_eq!(nearest_rank(&sorted, 100), Some(4.0), "p100 is the highest");
        for p in [0, 10, 25, 50, 75, 90, 100] {
            let v = nearest_rank(&sorted, p).expect("a value at every percentile");
            assert!(
                sorted.contains(&v),
                "p{p} returned {v}, which no observation produced"
            );
        }
        assert_eq!(nearest_rank(&[], 50), None, "no data, no percentile");
        assert_eq!(
            nearest_rank(&[7.0], 50),
            Some(7.0),
            "one observation is every percentile of itself"
        );
    }

    /// `mos_p<N>` parses across the whole range and rejects everything else.
    #[test]
    fn percentile_metric_names_parse_only_when_they_are_percentiles() {
        assert_eq!(Metric::parse("mos_p0"), Some(Ok(Metric::MosPercentile(0))));
        assert_eq!(
            Metric::parse("mos_p10"),
            Some(Ok(Metric::MosPercentile(10)))
        );
        assert_eq!(
            Metric::parse("mos_p100"),
            Some(Ok(Metric::MosPercentile(100)))
        );
        assert_eq!(Metric::parse("mos_p101"), Some(Err(101)));
        assert_eq!(Metric::parse("mos_p"), None);
        assert_eq!(Metric::parse("mos_p10x"), None);
        assert_eq!(Metric::parse("mos"), None);
    }

    /// Nearest rank returns a value the data actually contains, at both ends.
    #[test]
    fn nearest_rank_picks_a_real_observation() {
        let sorted = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(nearest_rank(&sorted, 0), Some(1.0), "p0 is the minimum");
        assert_eq!(nearest_rank(&sorted, 100), Some(5.0), "p100 is the maximum");
        assert_eq!(nearest_rank(&sorted, 20), Some(1.0));
        assert_eq!(nearest_rank(&sorted, 50), Some(3.0));
        assert_eq!(nearest_rank(&[], 50), None, "no data, no percentile");
    }

    /// Every operator compares in the direction its symbol reads.
    #[test]
    fn operators_compare_in_the_direction_they_are_written() {
        assert!(Op::Ge.holds(1.0, 1.0) && !Op::Gt.holds(1.0, 1.0));
        assert!(Op::Le.holds(1.0, 1.0) && !Op::Lt.holds(1.0, 1.0));
        assert!(Op::Eq.holds(1.0, 1.0) && !Op::Ne.holds(1.0, 1.0));
        assert!(Op::Gt.holds(2.0, 1.0) && !Op::Lt.holds(2.0, 1.0));
    }

    /// A suite file round-trips through TOML with the operators as symbols.
    #[test]
    fn a_toml_suite_parses_with_symbolic_operators() {
        let suite = Suite::from_toml_str(
            r#"
            [[rules]]
            name = "no 488s"
            metric = "count"
            op = "=="
            value = 0
            scope = "filter:response_code == 488"

            [[rules]]
            metric = "asr"
            op = ">="
            value = 0.99
            min_sample = 50
            "#,
        )
        .expect("suite parses");
        assert_eq!(suite.rules.len(), 2);
        assert_eq!(suite.rules[0].op, Op::Eq);
        assert_eq!(suite.rules[0].name.as_deref(), Some("no 488s"));
        assert_eq!(suite.rules[1].op, Op::Ge);
        assert_eq!(suite.rules[1].min_sample, Some(50));
    }

    /// `Report::exit_code` distinguishes the three suite outcomes.
    #[test]
    fn exit_codes_separate_green_red_and_unjudged() {
        let mut report = Report {
            schema_version: SCHEMA_VERSION,
            verdict: SuiteVerdict::Pass,
            exit_code: 0,
            rules_total: 1,
            evaluated: 1,
            passed: 1,
            failed: 0,
            skipped: 0,
            dialogs_in_capture: 1,
            streams_in_capture: 0,
            suppressions_applied: false,
            results: Vec::new(),
        };
        assert_eq!(report.exit_code(), 0);
        report.verdict = SuiteVerdict::Fail;
        assert_eq!(report.exit_code(), 1);
        report.verdict = SuiteVerdict::NotEvaluated;
        assert_eq!(
            report.exit_code(),
            2,
            "a suite that judged nothing must not report success"
        );
    }

    /// Compiling rejects a metric it cannot compute, naming the vocabulary.
    #[test]
    fn an_unknown_metric_is_refused_by_name() {
        let t = AliasThresholds::default();
        let err = compile(0, &rule("acd", Op::Ge, 1.0), &t).expect_err("unknown metric must error");
        let text = err.to_string();
        assert!(text.contains("acd"), "names the offender: {text}");
        assert!(text.contains("lint_errors"), "names the vocabulary: {text}");
    }

    /// A setting that does not apply to the metric is refused rather than
    /// silently ignored.
    #[test]
    fn grounded_only_is_refused_on_a_metric_that_reads_no_mos() {
        let t = AliasThresholds::default();
        let mut r = rule("count", Op::Eq, 0.0);
        r.grounded_only = Some(true);
        let err = compile(0, &r, &t).expect_err("grounded_only on count must error");
        assert!(
            err.to_string().contains("grounded_only"),
            "{}",
            err.to_string()
        );
    }

    /// A severity scope on a metric with no findings to select is refused.
    #[test]
    fn a_severity_scope_is_refused_on_a_metric_with_no_findings() {
        let t = AliasThresholds::default();
        let mut r = rule("asr", Op::Ge, 0.9);
        r.scope = Some("severity:error".to_string());
        let err = compile(0, &r, &t).expect_err("severity scope on asr must error");
        assert!(err.to_string().contains("lint_errors"), "{err}");
    }

    /// A scope with no recognized prefix names both prefixes.
    #[test]
    fn an_unprefixed_scope_is_refused() {
        let t = AliasThresholds::default();
        let mut r = rule("count", Op::Eq, 0.0);
        r.scope = Some("dst.ip == '203.0.113.9'".to_string());
        let err = compile(0, &r, &t).expect_err("bare expression must error");
        let text = err.to_string();
        assert!(
            text.contains("filter:") && text.contains("severity:"),
            "{text}"
        );
    }

    // ── Evaluation over a populated store ───────────────────────────

    /// A fixed timestamp, so nothing in these fixtures depends on the clock.
    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 6, 15, 12, 0, 0)
            .single()
            .unwrap_or_default()
    }

    /// Parse `raw` as SIP between two localhost endpoints.
    fn parse_at(raw: &[u8]) -> crate::sip::SipMessage {
        let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        crate::sip::parser::parse_sip(
            raw,
            ts(),
            local,
            local,
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("fixture parses as SIP")
    }

    /// A minimal INVITE for `call_id`.
    fn invite(call_id: &str) -> crate::sip::SipMessage {
        parse_at(&crate::test_utils::build_sip_message(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        ))
    }

    /// A final response to `call_id`'s INVITE.
    fn response(call_id: &str, code: u16, reason: &str) -> crate::sip::SipMessage {
        parse_at(&crate::test_utils::build_sip_message(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Contact: <sip:bob@127.0.0.1>",
                "Content-Length: 0",
            ],
            b"",
        ))
    }

    /// A store holding one INVITE per `(call_id, final code)`, with `None`
    /// leaving the call in progress.
    fn store(calls: &[(&str, Option<u16>)]) -> DialogStore {
        let mut ds = DialogStore::new(64, false);
        for (id, code) in calls {
            ds.process_message(invite(id));
            if let Some(c) = code {
                ds.process_message(response(id, *c, "Done"));
            }
        }
        ds
    }

    /// Evaluate `rules` against a store built from `calls`.
    fn run(calls: &[(&str, Option<u16>)], rules: &[ExpectRule]) -> Report {
        let ds = store(calls);
        let ss = StreamStore::new(64);
        let t = AliasThresholds::default();
        evaluate(
            rules,
            &Inputs {
                dialogs: &ds,
                streams: &ss,
                thresholds: &t,
                suppressions: None,
            },
        )
        .expect("these rules compile")
    }

    /// A count rule passes when the capture satisfies it and FAILS when it does
    /// not — the direction a gate exists for, asserted in both directions on the
    /// same rule so a verdict stuck on one value cannot pass this.
    #[test]
    fn a_count_rule_fails_the_capture_that_violates_it() {
        let calls = [("a@x", Some(200)), ("b@x", Some(488)), ("c@x", Some(200))];
        let mut r = rule("count", Op::Eq, 0.0);
        r.scope = Some("filter:response_code == 488".to_string());

        let bad = run(&calls, std::slice::from_ref(&r));
        assert_eq!(bad.verdict, SuiteVerdict::Fail, "{:?}", bad.results);
        assert_eq!(bad.exit_code, 1);
        assert_eq!(bad.results[0].verdict, Verdict::Fail);
        assert_eq!(bad.results[0].observed, Some(1.0), "one call was rejected");
        assert_eq!(bad.results[0].sample, 3, "judged against the whole capture");

        // The SAME rule against a capture holding no 488.
        let good = run(&[("a@x", Some(200)), ("c@x", Some(200))], &[r]);
        assert_eq!(good.verdict, SuiteVerdict::Pass);
        assert_eq!(good.exit_code, 0);
        assert_eq!(good.results[0].observed, Some(0.0));
    }

    /// ASR is answered over seized, and a call still ringing is in neither.
    #[test]
    fn asr_counts_answered_over_seized_and_excludes_calls_in_progress() {
        let calls = [
            ("a@x", Some(200)),
            ("b@x", Some(200)),
            ("c@x", Some(486)),
            ("d@x", None),
        ];
        let report = run(&calls, &[rule("asr", Op::Ge, 99.0)]);
        let o = &report.results[0];
        assert_eq!(o.sample, 3, "the ringing call is not a seizure: {o:?}");
        // Percent, matching `group_dialogs`. A rule an operator writes should
        // carry the number they read in a report, not that number divided by a
        // hundred -- the two surfaces used to disagree, and a threshold copied
        // between them was wrong by 100x in the direction that always passes.
        assert!(
            (o.observed.expect("two of three seizures answered") - 200.0 / 3.0).abs() < 1e-9,
            "expected ~66.67 percent, got {:?}",
            o.observed
        );
        assert_eq!(o.verdict, Verdict::Fail, "66.7% is not >= 99%");
        assert_eq!(o.unit, "percent");

        let passing = run(&calls, &[rule("asr", Op::Ge, 60.0)]);
        assert_eq!(passing.results[0].verdict, Verdict::Pass);
    }

    /// A rule with nothing to measure FAILS. This is the whole point: a green
    /// build on a capture the gate never judged is the outcome that gets a gate
    /// trusted and then betrayed.
    #[test]
    fn a_rule_with_an_empty_population_fails_rather_than_passing_quietly() {
        // 1200 REGISTER-shaped dialogs would be a busy capture; here it is
        // enough that no INVITE reached a final response, so ASR has no
        // denominator.
        let report = run(&[("a@x", None)], &[rule("asr", Op::Ge, 99.0)]);
        let o = &report.results[0];
        assert_eq!(o.verdict, Verdict::Fail, "unevaluable must not pass: {o:?}");
        assert_eq!(o.observed, None);
        assert_eq!(o.sample, 0);
        assert!(
            o.reason.contains("unevaluable"),
            "the reason must say why: {}",
            o.reason
        );
        assert_eq!(report.verdict, SuiteVerdict::Fail);
        assert_eq!(report.exit_code, 1);
    }

    /// Declaring min_sample is what turns that failure into a skip, and a suite
    /// where everything skipped is NOT a pass.
    #[test]
    fn min_sample_downgrades_an_unjudgeable_rule_to_skipped_not_to_passed() {
        let mut r = rule("asr", Op::Ge, 99.0);
        r.min_sample = Some(50);
        let report = run(&[("a@x", None)], &[r]);
        let o = &report.results[0];
        assert_eq!(o.verdict, Verdict::Skipped, "{o:?}");
        assert!(o.reason.contains("min_sample"), "{}", o.reason);
        assert_eq!(report.passed, 0, "a skip is not a pass");
        assert_eq!(report.evaluated, 0);
        assert_eq!(
            report.verdict,
            SuiteVerdict::NotEvaluated,
            "a suite that judged nothing reports so"
        );
        assert_eq!(report.exit_code, 2);
    }

    /// A sample at the declared floor is judged; one below it is not.
    #[test]
    fn min_sample_is_a_floor_the_sample_may_sit_on() {
        let calls = [("a@x", Some(486)), ("b@x", Some(486))];
        let mut at_floor = rule("asr", Op::Ge, 99.0);
        at_floor.min_sample = Some(2);
        assert_eq!(
            run(&calls, &[at_floor]).results[0].verdict,
            Verdict::Fail,
            "two seizures meets a floor of two, so the threshold applies"
        );

        let mut above_floor = rule("asr", Op::Ge, 99.0);
        above_floor.min_sample = Some(3);
        assert_eq!(
            run(&calls, &[above_floor]).results[0].verdict,
            Verdict::Skipped
        );
    }

    /// A count of zero over an empty capture is unevaluable, not a pass.
    ///
    /// The one metric whose value exists whatever the population is, and the
    /// reason the emptiness test reads the SAMPLE rather than the value.
    #[test]
    fn a_count_of_zero_over_no_dialogs_fails_rather_than_passing() {
        let mut r = rule("count", Op::Eq, 0.0);
        r.scope = Some("filter:state == 'Failed'".to_string());
        let report = run(&[], std::slice::from_ref(&r));
        assert_eq!(report.results[0].observed, Some(0.0));
        assert_eq!(
            report.results[0].verdict,
            Verdict::Fail,
            "zero failures out of zero dialogs is a claim about nothing: {:?}",
            report.results[0]
        );

        // The same rule over one dialog that satisfies it does pass, so the
        // failure above is emptiness and not a rule that can never hold.
        let populated = run(&[("a@x", Some(200))], &[r]);
        assert_eq!(populated.results[0].verdict, Verdict::Pass);
    }

    /// A declared floor of zero declares nothing, and leaves the empty case
    /// failing exactly as an absent one does.
    #[test]
    fn a_min_sample_of_zero_does_not_silence_an_empty_population() {
        let mut r = rule("asr", Op::Ge, 99.0);
        r.min_sample = Some(0);
        assert_eq!(run(&[], &[r]).results[0].verdict, Verdict::Fail);
    }

    /// One failing rule fails the suite even when the others pass.
    #[test]
    fn one_failing_rule_fails_the_whole_suite() {
        let calls = [("a@x", Some(200)), ("b@x", Some(488))];
        let mut violated = rule("count", Op::Eq, 0.0);
        violated.scope = Some("filter:response_code == 488".to_string());
        let report = run(&calls, &[rule("count", Op::Ge, 1.0), violated]);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.verdict, SuiteVerdict::Fail);
    }

    /// An empty suite is refused: it would pass every capture.
    #[test]
    fn an_empty_suite_is_refused() {
        let ds = DialogStore::new(16, false);
        let ss = StreamStore::new(16);
        let t = AliasThresholds::default();
        let err = evaluate(
            &[],
            &Inputs {
                dialogs: &ds,
                streams: &ss,
                thresholds: &t,
                suppressions: None,
            },
        )
        .expect_err("an empty suite must error");
        assert!(matches!(err, RuleError::NoRules));
    }
}
