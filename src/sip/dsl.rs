// SPDX-License-Identifier: MIT OR Apache-2.0

//! Filter DSL expression parser and evaluator.
//!
//! Provides a declarative, non-Turing-complete filter language for matching
//! SIP dialogs and their associated RTP streams. Users write expressions like:
//!
//! ```text
//! from.user =~ '1001' AND rtp.mos < 3.0
//! method == 'INVITE' AND NOT ua =~ 'friendly-scanner'
//! pdd > 3.0 AND state == 'InCall'
//! ```
//!
//! The grammar supports boolean combinators (`AND`, `OR`, `NOT`), parenthesized
//! grouping, field comparisons (`==`, `!=`, `<`, `>`, `<=`, `>=`), and regex
//! matching (`=~`). See [`FilterExpr::parse`] for the full grammar.

use anyhow::{Result, bail};
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    character::complete::{char, multispace0, multispace1},
    combinator::{map, opt, recognize},
    number::complete::double,
    sequence::preceded,
};

use super::dialog::{DialogState, SipDialog};
use crate::rtp::diagnosis::{self, CaptureMedia, MediaDiagnosis};
use crate::rtp::stream::RtpStream;

// ── Maximum nesting depth (D17) ─────────────────────────────────────

/// Maximum parenthesis nesting depth allowed in filter expressions.
const MAX_NESTING_DEPTH: usize = 50;

/// Maximum regex size in bytes (D17).
const REGEX_SIZE_LIMIT: usize = 1_000_000;

// ── Public types ────────────────────────────────────────────────────

/// A compiled filter expression ready for evaluation against SIP dialogs.
///
/// Created via [`FilterExpr::parse`], then evaluated via
/// [`FilterExpr::matches_dialog`]. The expression tree is immutable after
/// construction.
///
/// # Examples
///
/// ```
/// use sipnab::FilterExpr;
///
/// let filter = FilterExpr::parse("from.user == '1001' AND rtp.loss > 2.0")?;
/// // Evaluate against tracked calls with
/// // `filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed)`.
///
/// // Malformed expressions fail to parse:
/// assert!(FilterExpr::parse("from.user ==").is_err());
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Clone)]
pub struct FilterExpr {
    /// Root node of the parsed expression tree.
    root: Expr,
    /// Whether the expression references any diagnosis-derived field.
    /// Cached at parse time (via [`expr_references_diagnosis`]) so
    /// [`FilterExpr::matches_dialog`] can skip the media/asymmetry
    /// diagnosis entirely when no such field appears.
    needs_diagnosis: bool,
}

impl std::fmt::Debug for FilterExpr {
    /// Write a debug rendering of the expression tree to `f` (manual impl
    /// because `regex::Regex` inside `Value` is not `Debug`-derivable the
    /// way the rest of the tree is).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterExpr")
            .field("root", &self.root)
            .finish()
    }
}

/// Expression tree node.
#[derive(Debug, Clone)]
enum Expr {
    /// Logical conjunction of two subexpressions (`AND`).
    And(Box<Expr>, Box<Expr>),
    /// Logical disjunction of two subexpressions (`OR`).
    Or(Box<Expr>, Box<Expr>),
    /// Logical negation of a subexpression (`NOT`).
    Not(Box<Expr>),
    /// Leaf comparison: `field operator value`.
    Compare(Field, Operator, Value),
}

/// Addressable fields in the filter DSL. Each variant maps to one entry in
/// `FIELD_NAMES`; extraction semantics live in `eval_compare`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// `from.user` — user part of the dialog's From URI.
    FromUser,
    /// `to.user` — user part of the dialog's To URI.
    ToUser,
    /// `method` — the dialog's initial SIP method.
    Method,
    /// `ua` — first User-Agent header found in the dialog's messages.
    Ua,
    /// `call_id` — the dialog's Call-ID.
    CallId,
    /// `payload` — raw text of any SIP message in the dialog
    /// (sngrep-style whole-message grep).
    Payload,
    /// `src.ip` — source IP of the initial message.
    SrcIp,
    /// `dst.ip` — destination IP of the initial message.
    DstIp,
    /// `src.port` — source port of the initial message.
    SrcPort,
    /// `dst.port` — destination port of the initial message.
    DstPort,
    /// `state` — current dialog state name (e.g. `'InCall'`).
    State,
    /// `duration` — seconds between dialog creation and last update.
    Duration,
    /// `msg_count` — number of SIP messages stored in the dialog.
    MsgCount,
    /// `pdd` — post-dial delay in seconds (0 when unknown).
    Pdd,
    /// `setup_time` — call setup time in seconds (0 when unknown).
    SetupTime,
    /// `retransmits` — total retransmission count across transactions.
    Retransmits,
    /// `rtp.mos` — worst (lowest) approximate MOS across streams.
    RtpMos,
    /// `rtp.jitter` — worst (highest) jitter across streams.
    RtpJitter,
    /// `rtp.loss` — worst (highest) loss percentage across streams.
    RtpLoss,
    /// `rtp.packets` — total packet count summed across streams.
    RtpPackets,
    /// `rtp.codec` — first known stream codec name.
    RtpCodec,
    /// `rtp.ssrc` — first stream's SSRC as 0x-prefixed lowercase hex.
    RtpSsrc,
    /// `one_way` — one-way-audio diagnosis flag.
    OneWay,
    /// `nat_mismatch` — NAT mismatch diagnosis flag.
    NatMismatch,
    /// `no_media` — no-media diagnosis flag.
    NoMedia,
    // Per-call asymmetry signals (8.7)
    /// `codec_asymmetry` — the two legs negotiated different codecs.
    CodecAsymmetry,
    /// `ptime_asymmetry` — the legs use different packetization times.
    PtimeAsymmetry,
    /// `payload_asymmetry` — the legs use different RTP payload types.
    PayloadAsymmetry,
    /// `duration_asymmetry` — the legs' media durations diverge.
    DurationAsymmetry,
    /// `late_media` — RTP began long after the 200 OK.
    LateMedia,
}

impl Field {
    /// Whether this field's value is read from the media/asymmetry
    /// [`MediaDiagnosis`] (rather than the dialog or streams directly).
    /// Drives the parse-time `needs_diagnosis` flag; keep in sync with the
    /// diagnosis arms of `eval_compare`.
    fn is_diagnosis(self) -> bool {
        matches!(
            self,
            Field::OneWay
                | Field::NatMismatch
                | Field::NoMedia
                | Field::CodecAsymmetry
                | Field::PtimeAsymmetry
                | Field::PayloadAsymmetry
                | Field::DurationAsymmetry
                | Field::LateMedia
        )
    }
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    /// `==` — equality.
    Eq,
    /// `!=` — inequality.
    Ne,
    /// `<` — less than.
    Lt,
    /// `>` — greater than.
    Gt,
    /// `<=` — less than or equal.
    Le,
    /// `>=` — greater than or equal.
    Ge,
    /// `=~` — regex match (right-hand side compiled as a regex).
    Regex,
}

/// A literal value on the right-hand side of a comparison.
#[derive(Debug, Clone)]
enum Value {
    /// Quoted string literal (single or double quotes).
    Str(String),
    /// Numeric literal; all numbers are `f64`.
    Num(f64),
    /// Boolean literal `true`/`false` (case-insensitive).
    Bool(bool),
    /// Compiled regex from the string literal of an `=~` comparison.
    Re(regex::Regex),
    /// Byte-oriented compiled regex for a `payload =~` comparison, matched
    /// against the raw message bytes without a lossy UTF-8 copy.
    ReBytes(regex::bytes::Regex),
}

// ── Diagnostic filter aliases ───────────────────────────────────────

/// Retransmissions on one dialog that count as excessive.
///
/// The one alias threshold with no configuration behind it, because nothing
/// else in sipnab has an opinion about a retransmission count to borrow. It
/// stays a named constant rather than a bare `3` so the next person to give
/// retransmissions a config key has one place to change.
const ALIAS_RETRANSMIT_LIMIT: u32 = 3;

/// The numbers a diagnostic alias compares against.
///
/// Every field is sourced from a threshold that already exists and is already
/// tunable — none is invented here, and none is written as a literal twice.
/// That is the entire point of the type: `--problems` used to carry its own
/// hardcoded figures, so an operator who tuned `[diagnosis]` to their SLA
/// still got a filter selecting on 32 seconds of post-dial delay. sipnab
/// carried three disagreeing notions of a bad call. This is the one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AliasThresholds {
    /// Post-dial delay counting as slow, in seconds. From
    /// [`crate::sip::diagnosis::SignalingThresholds::post_dial_delay_sec`].
    pub pdd_secs: f64,
    /// Loss counting as bad, in percent. From
    /// [`crate::rtp::bands::QualityBands::loss_bad_pct`].
    pub loss_pct: f64,
    /// Jitter counting as bad, in milliseconds. From
    /// [`crate::rtp::bands::QualityBands::jitter_bad_ms`].
    pub jitter_ms: f64,
    /// Retransmissions counting as excessive.
    ///
    /// The one alias threshold with no configuration behind it, because
    /// nothing else in sipnab has an opinion about a retransmission count to
    /// borrow. Not linked to its constant: that constant is private, and
    /// rustdoc refuses a public link into private scope.
    pub retransmits: u32,
    /// A call this short is a short call, in seconds. From
    /// [`crate::security::fraud_detect::FraudThresholds::short_call_secs`].
    pub short_call_secs: f64,
}

impl AliasThresholds {
    /// Compose the alias thresholds from the resolved threshold sets.
    ///
    /// Taking the resolved sets rather than a `Config` is deliberate: each of
    /// those already applies its own flag-over-key-over-default precedence, so
    /// composing them here cannot introduce a fourth precedence chain that
    /// disagrees with the three that exist.
    #[must_use]
    pub fn from_parts(
        signaling: &crate::sip::diagnosis::SignalingThresholds,
        bands: &crate::rtp::bands::QualityBands,
        fraud: &crate::security::fraud_detect::FraudThresholds,
    ) -> Self {
        Self {
            pdd_secs: signaling.post_dial_delay_sec,
            loss_pct: bands.loss_bad_pct,
            jitter_ms: bands.jitter_bad_ms,
            retransmits: ALIAS_RETRANSMIT_LIMIT,
            short_call_secs: fraud.short_call_secs as f64,
        }
    }
}

impl Default for AliasThresholds {
    /// The shipped figures, composed from each source's own built-in.
    ///
    /// Written this way rather than as literals so the defaults cannot drift
    /// from the thresholds they claim to mirror.
    fn default() -> Self {
        Self::from_parts(
            &crate::sip::diagnosis::SignalingThresholds::BUILT_IN,
            &crate::rtp::bands::QualityBands::default(),
            &crate::security::fraud_detect::FraudThresholds::BUILT_IN,
        )
    }
}

/// Render a threshold so the expansion is valid DSL and reads like the docs.
///
/// `{:?}` on an `f64` keeps the trailing `.0` that a bare `{}` drops, so the
/// expansion says `pdd > 11.0` rather than `pdd > 11`.
fn dsl_num(v: f64) -> String {
    format!("{v:?}")
}

/// Expand a named filter alias to its DSL expression, using `t` for every
/// number it compares against.
///
/// Supported aliases:
/// - `"problems"` — calls with any diagnostic issue (includes 8.7 asymmetry signals)
/// - `"slow-setup"` — calls whose post-dial delay counts as slow
/// - `"short-calls"` — completed calls under the short-call threshold
/// - `"one-way"` — calls with one-way audio
/// - `"nat-issues"` — calls with NAT mismatch
/// - `"codec-asym"` — codec asymmetry across the two legs (8.7)
/// - `"ptime-asym"` — packetization-time asymmetry (8.7)
/// - `"payload-asym"` — payload-type asymmetry (8.7)
/// - `"duration-asym"` — leg-duration asymmetry (8.7)
/// - `"late-media"` — RTP started long after 200 OK (8.7)
///
/// `slow-setup` and the post-dial-delay term of `problems` read the SAME
/// threshold. They used to differ — 3 seconds against 32 — which meant a call
/// could be slow enough to report and not slow enough to be a problem.
///
/// Returns `None` if the alias is not recognized.
#[must_use]
pub fn expand_alias(alias: &str, t: &AliasThresholds) -> Option<String> {
    let expr = match alias {
        "problems" => format!(
            "state == 'Failed' OR one_way == true OR rtp.loss > {loss} \
             OR rtp.jitter > {jitter} OR nat_mismatch == true \
             OR retransmits > {retx} OR pdd > {pdd} \
             OR codec_asymmetry == true OR ptime_asymmetry == true \
             OR payload_asymmetry == true OR duration_asymmetry == true \
             OR late_media == true",
            loss = dsl_num(t.loss_pct),
            jitter = dsl_num(t.jitter_ms),
            retx = t.retransmits,
            pdd = dsl_num(t.pdd_secs),
        ),
        "slow-setup" => format!("pdd > {}", dsl_num(t.pdd_secs)),
        "short-calls" => format!(
            "duration < {} AND state == 'Completed'",
            dsl_num(t.short_call_secs)
        ),
        "one-way" => "one_way == true".to_string(),
        "nat-issues" => "nat_mismatch == true".to_string(),
        "codec-asym" => "codec_asymmetry == true".to_string(),
        "ptime-asym" => "ptime_asymmetry == true".to_string(),
        "payload-asym" => "payload_asymmetry == true".to_string(),
        "duration-asym" => "duration_asymmetry == true".to_string(),
        "late-media" => "late_media == true".to_string(),
        _ => return None,
    };
    Some(expr)
}

/// Whether any leaf comparison in the tree references a diagnosis-derived
/// field. Walked once at parse time to cache `FilterExpr::needs_diagnosis`.
fn expr_references_diagnosis(expr: &Expr) -> bool {
    match expr {
        Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
            expr_references_diagnosis(lhs) || expr_references_diagnosis(rhs)
        }
        Expr::Not(inner) => expr_references_diagnosis(inner),
        Expr::Compare(field, _, _) => field.is_diagnosis(),
    }
}

// ── FilterExpr public API ───────────────────────────────────────────

impl FilterExpr {
    /// An expression that matches **no** dialog.
    ///
    /// Used to represent "show nothing" — e.g. the filter dialog with every SIP
    /// method unchecked — so the call-list filter path keeps funnelling through
    /// a single `Option<FilterExpr>` instead of growing a special case.
    ///
    /// `one_way` is a concrete per-dialog boolean, so requiring it to be both
    /// `true` and `false` is unsatisfiable for every dialog.
    #[must_use]
    pub fn never() -> Self {
        let root = Expr::And(
            Box::new(Expr::Compare(
                Field::OneWay,
                Operator::Eq,
                Value::Bool(true),
            )),
            Box::new(Expr::Compare(
                Field::OneWay,
                Operator::Eq,
                Value::Bool(false),
            )),
        );
        let needs_diagnosis = expr_references_diagnosis(&root);
        FilterExpr {
            root,
            needs_diagnosis,
        }
    }

    /// Parse a filter expression string into a compiled [`FilterExpr`].
    ///
    /// The grammar is:
    ///
    /// ```text
    /// expr        = or_expr
    /// or_expr     = and_expr ("OR" and_expr)*
    /// and_expr    = not_expr ("AND" not_expr)*
    /// not_expr    = "NOT" atom | atom
    /// atom        = comparison | "(" expr ")"
    /// comparison  = field operator value
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input is empty or contains only whitespace
    /// - A syntax error is found (with approximate position)
    /// - Parentheses nest deeper than 50 levels
    /// - A regex pattern fails to compile or exceeds the 1 MB size limit
    #[must_use = "parsing result must be handled"]
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("filter expression is empty");
        }

        // Count max nesting depth before parsing
        check_nesting_depth(trimmed)?;

        let (remaining, expr) = parse_or_expr(trimmed).map_err(|e| match e {
            nom::Err::Error(err) | nom::Err::Failure(err) => {
                let pos = trimmed.len() - err.input.len();
                anyhow::anyhow!("{}", render_parse_error(trimmed, pos, "unexpected input"))
            }
            nom::Err::Incomplete(_) => anyhow::anyhow!("incomplete filter expression"),
        })?;

        if !remaining.trim().is_empty() {
            // Position of the first non-space char of the unparsed tail.
            let pos = trimmed.len() - remaining.trim_start().len();
            bail!(
                "{}",
                render_parse_error(trimmed, pos, "unexpected trailing input")
            );
        }

        let needs_diagnosis = expr_references_diagnosis(&expr);
        Ok(FilterExpr {
            root: expr,
            needs_diagnosis,
        })
    }

    /// Evaluate this filter against a SIP dialog and its associated RTP streams.
    ///
    /// For RTP quality fields (`rtp.mos`, `rtp.jitter`, `rtp.loss`), the worst
    /// value across all associated streams is used for comparison, since
    /// filtering typically aims to find problematic calls.
    ///
    /// Boolean diagnosis fields (`one_way`, `nat_mismatch`, `no_media`) are
    /// computed from the associated streams via the diagnosis engine.
    ///
    /// The media/asymmetry diagnosis is skipped entirely when the expression
    /// references no diagnosis field (detected at parse time and cached as
    /// `needs_diagnosis`); the result is unchanged because no diagnosis value
    /// is then read.
    ///
    /// # Arguments
    ///
    /// * `dialog` — The SIP dialog to test.
    /// * `streams` — RTP streams associated with the dialog (may be empty;
    ///   RTP fields then compare as zero/empty values).
    /// * `capture` — whether the capture recorded any RTP at all. `no_media`
    ///   is a claim that a call carried no audio, and on a signalling-only
    ///   capture no call carries any, so the flag would describe the tap
    ///   rather than the call. Callers holding a stream store pass
    ///   [`CaptureMedia::of_store`]; the surfaces that filter dialogs with no
    ///   media data at all pass [`CaptureMedia::Absent`], which is the honest
    ///   reading of what they know.
    ///
    /// # Returns
    ///
    /// `true` when the dialog and its streams satisfy the expression.
    pub fn matches_dialog(
        &self,
        dialog: &SipDialog,
        streams: &[&RtpStream],
        capture: CaptureMedia,
    ) -> bool {
        // Only run the media/asymmetry diagnosis when the expression actually
        // reads a diagnosis field; otherwise a default (all-clear) diagnosis
        // suffices and is never consulted. Building the media context reparses
        // the dialog's SDP bodies, so it belongs inside this branch too.
        let diag = if self.needs_diagnosis {
            let media = diagnosis::MediaContext::for_dialog(dialog, capture);
            let mut diag = diagnosis::diagnose_media(streams, &media);
            diagnosis::diagnose_asymmetry(
                &mut diag,
                Some(dialog),
                streams,
                &diagnosis::AsymmetryThresholds::default(),
            );
            diag
        } else {
            MediaDiagnosis::default()
        };
        eval_expr(&self.root, dialog, streams, &diag)
    }
}

// ── Applying a compiled filter to the stores ────────────────────────

/// The dialogs a compiled filter admits, paired with their RTP streams.
///
/// Returned by [`select_dialogs`]. The post-capture output paths
/// (`--report`, `--json-dialogs`) render whole stores rather than the packet
/// stream, so they need the *selection* — which dialogs survive the filter,
/// and which streams belong to them — as one value: they differ only in how
/// they format it, and a filter that narrowed one but not the other would
/// report different calls for the same command line.
pub struct DialogSelection<'a> {
    /// Matching dialogs in store order, each with the streams linked to it
    /// (empty when the dialog carries no media).
    pub dialogs: Vec<(&'a SipDialog, Vec<&'a RtpStream>)>,
    /// Streams to show alongside `dialogs`, in store order. With no filter
    /// this is every stream in the store, orphans included — an unfiltered
    /// run must be unchanged. With a filter it is the streams linked to a
    /// selected dialog, so the media on screen belongs to the calls on
    /// screen.
    pub streams: Vec<&'a RtpStream>,
}

/// Apply an optional compiled filter to the final store contents.
///
/// `filter` of `None` selects everything, so a caller can funnel the filtered
/// and unfiltered cases through one path instead of branching at each output
/// format — the branch that was missing, leaving `--filter` inert on every
/// post-capture output.
///
/// Streams are grouped by Call-ID once rather than rescanned per dialog: the
/// per-dialog scan is O(dialogs × streams), and these paths visit every
/// dialog in the store.
///
/// # Arguments
///
/// * `filter` — Compiled expression, or `None` to select every dialog.
/// * `dialog_store` — Dialogs to select from.
/// * `stream_store` — Streams to associate and (when filtering) narrow.
///
/// # Returns
///
/// The matching dialogs with their streams, in store order.
///
/// # Side effects
///
/// Resolves this run's ICMP media evidence against `stream_store` — see the
/// note at the top of the body for why it happens here.
pub fn select_dialogs<'a>(
    filter: Option<&FilterExpr>,
    dialog_store: &'a super::dialog_store::DialogStore,
    stream_store: &'a crate::rtp::stream_store::StreamStore,
) -> DialogSelection<'a> {
    // Tie this run's ICMP media evidence to the streams it describes, once,
    // here. An ICMP error that quotes a media datagram carries no `Call-ID`, so
    // the only thing that can say WHICH stream it is about — and how strong
    // that claim is, from an exact directed 5-tuple down to no match at all —
    // is the complete stream store. This function is the point every
    // post-capture surface passes through holding one: `--report` and
    // `--json-dialogs` both call it immediately before rendering, and the
    // renderers themselves are handed a dialog's streams, never the store.
    // Resolving once here rather than per surface is also what stops stderr,
    // `--report` and the JSON disagreeing about the same capture.
    //
    // Absent on wasm32, where `crate::pipeline` is not compiled at all: that
    // build has no capture path, so it never observes an ICMP error and has
    // nothing to resolve. Gated on the same condition as the module rather
    // than on a feature, because the module's own gate is the target arch and
    // any other spelling would drift from it.
    #[cfg(not(target_arch = "wasm32"))]
    crate::pipeline::resolve_icmp_media(stream_store);

    let mut by_call: std::collections::HashMap<&'a str, Vec<&'a RtpStream>> =
        std::collections::HashMap::new();
    for stream in stream_store.iter() {
        if let Some(id) = stream.associated_dialog.as_deref() {
            by_call.entry(id).or_default().push(stream);
        }
    }

    // One run-level fact, read once rather than per dialog.
    let capture = CaptureMedia::of_store(stream_store);
    let dialogs: Vec<(&'a SipDialog, Vec<&'a RtpStream>)> = dialog_store
        .iter()
        .filter_map(|dialog| {
            let streams = by_call
                .get(dialog.call_id.as_str())
                .cloned()
                .unwrap_or_default();
            match filter {
                Some(expr) if !expr.matches_dialog(dialog, &streams, capture) => None,
                _ => Some((dialog, streams)),
            }
        })
        .collect();

    let streams = match filter {
        // Byte-for-byte the previous unfiltered behaviour: every stream the
        // store holds, orphans included, in store order.
        None => stream_store.iter().collect(),
        Some(_) => {
            let selected: std::collections::HashSet<&str> = dialogs
                .iter()
                .map(|(dialog, _)| dialog.call_id.as_str())
                .collect();
            // Store order, not selection order, so a filtered stream table is
            // a subsequence of the unfiltered one.
            stream_store
                .iter()
                .filter(|s| {
                    s.associated_dialog
                        .as_deref()
                        .is_some_and(|id| selected.contains(id))
                })
                .collect()
        }
    };

    DialogSelection { dialogs, streams }
}

// ── Nesting depth check ─────────────────────────────────────────────

/// Verify parenthesis nesting does not exceed [`MAX_NESTING_DEPTH`].
///
/// # Errors
///
/// Returns an error naming the limit as soon as the running open-paren
/// depth exceeds it. Unbalanced closing parens saturate the depth at zero
/// rather than underflowing, so they can never error here.
fn check_nesting_depth(input: &str) -> Result<()> {
    let mut depth: usize = 0;
    for ch in input.chars() {
        if ch == '(' {
            depth += 1;
            if depth > MAX_NESTING_DEPTH {
                bail!("expression exceeds maximum nesting depth of {MAX_NESTING_DEPTH}");
            }
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
        }
    }
    Ok(())
}

// ── Nom parsers ─────────────────────────────────────────────────────

/// Nom error type used throughout the parser.
type NomErr<'a> = nom::error::Error<&'a str>;

/// Parse an or-expression: `and_expr ("OR" and_expr)*`. `OR` is matched
/// case-insensitively and must be followed by whitespace.
///
/// # Arguments
///
/// * `input` — Remaining expression text.
///
/// # Returns
///
/// The unconsumed remainder and the parsed node — a left-associative `Or`
/// chain (or just the single and-expression) — or a nom error at the
/// failing position.
fn parse_or_expr(input: &str) -> IResult<&str, Expr, NomErr<'_>> {
    let (input, first) = parse_and_expr(input)?;
    let mut result = first;
    let mut remaining = input;

    loop {
        let trimmed = remaining.trim_start();
        if let Ok((after_or, _)) =
            preceded(tag_no_case::<&str, &str, NomErr<'_>>("OR"), multispace1).parse(trimmed)
        {
            let (rest, right) = parse_and_expr(after_or)?;
            result = Expr::Or(Box::new(result), Box::new(right));
            remaining = rest;
        } else {
            break;
        }
    }

    Ok((remaining, result))
}

/// Parse an and-expression: `not_expr ("AND" not_expr)*`. `AND` is matched
/// case-insensitively and must be followed by whitespace; binding tighter
/// than `OR` gives the conventional precedence.
///
/// # Arguments
///
/// * `input` — Remaining expression text.
///
/// # Returns
///
/// The unconsumed remainder and the parsed node — a left-associative
/// `And` chain (or just the single not-expression) — or a nom error at
/// the failing position.
fn parse_and_expr(input: &str) -> IResult<&str, Expr, NomErr<'_>> {
    let (input, _) = multispace0(input)?;
    let (input, first) = parse_not_expr(input)?;
    let mut result = first;
    let mut remaining = input;

    loop {
        let trimmed = remaining.trim_start();
        if let Ok((after_and, _)) =
            preceded(tag_no_case::<&str, &str, NomErr<'_>>("AND"), multispace1).parse(trimmed)
        {
            let (rest, right) = parse_not_expr(after_and)?;
            result = Expr::And(Box::new(result), Box::new(right));
            remaining = rest;
        } else {
            break;
        }
    }

    Ok((remaining, result))
}

/// Parse a not-expression: `"NOT" atom | atom`. `NOT` is matched
/// case-insensitively and must be followed by whitespace.
///
/// # Arguments
///
/// * `input` — Remaining expression text.
///
/// # Returns
///
/// The unconsumed remainder and either a `Not` wrapping the atom or the
/// atom itself, or a nom error from the atom parser.
fn parse_not_expr(input: &str) -> IResult<&str, Expr, NomErr<'_>> {
    let (input, _) = multispace0(input)?;

    // Try "NOT" followed by whitespace
    if let Ok((after_not, _)) =
        preceded(tag_no_case::<&str, &str, NomErr<'_>>("NOT"), multispace1).parse(input)
    {
        let (rest, inner) = parse_atom(after_not)?;
        return Ok((rest, Expr::Not(Box::new(inner))));
    }

    parse_atom(input)
}

/// Parse an atom: parenthesized expression or comparison.
///
/// # Arguments
///
/// * `input` — Remaining expression text.
///
/// # Returns
///
/// The unconsumed remainder and the inner expression (parens are consumed
/// but add no node), or a nom error when neither form parses.
fn parse_atom(input: &str) -> IResult<&str, Expr, NomErr<'_>> {
    let (input, _) = multispace0(input)?;

    // Try parenthesized expression
    if input.starts_with('(') {
        let (input, _) = char('(').parse(input)?;
        let (input, expr) = parse_or_expr(input)?;
        let (input, _) = multispace0(input)?;
        let (input, _) = char(')').parse(input)?;
        return Ok((input, expr));
    }

    // Otherwise, parse a comparison
    parse_comparison(input)
}

/// Parse a comparison: `field operator value`, with optional whitespace
/// between the three parts.
///
/// # Arguments
///
/// * `input` — Remaining expression text.
///
/// # Returns
///
/// The unconsumed remainder and an `Expr::Compare` leaf, or the first nom
/// error from the field, operator, or value parser.
fn parse_comparison(input: &str) -> IResult<&str, Expr, NomErr<'_>> {
    let (input, _) = multispace0(input)?;
    let (input, field) = parse_field(input)?;
    let (input, _) = multispace0(input)?;
    let (input, op) = parse_operator(input)?;
    let (input, _) = multispace0(input)?;
    let (input, value) = parse_value(input, field, op)?;

    Ok((input, Expr::Compare(field, op, value)))
}

/// Every field name the DSL accepts, for diagnostics. Kept in sync with
/// `parse_field` by the `field_names_const_matches_parser` test.
pub const FIELD_NAMES: &[&str] = &[
    "from.user",
    "to.user",
    "method",
    "ua",
    "call_id",
    "payload",
    "src.ip",
    "dst.ip",
    "src.port",
    "dst.port",
    "state",
    "duration",
    "msg_count",
    "pdd",
    "setup_time",
    "retransmits",
    "rtp.mos",
    "rtp.jitter",
    "rtp.loss",
    "rtp.packets",
    "rtp.codec",
    "rtp.ssrc",
    "one_way",
    "nat_mismatch",
    "no_media",
    "codec_asymmetry",
    "ptime_asymmetry",
    "payload_asymmetry",
    "duration_asymmetry",
    "late_media",
];

/// Parse a dotted field identifier (one or two `.`-separated segments of
/// ASCII alphanumerics/underscores) into its `Field`.
///
/// # Arguments
///
/// * `input` — Remaining expression text at the field position.
///
/// # Returns
///
/// The unconsumed remainder and the matched `Field`. An identifier that
/// is not a known field produces a nom `Failure` (not `Error`) so
/// alternatives cannot mask the unknown-field diagnostic.
fn parse_field(input: &str) -> IResult<&str, Field, NomErr<'_>> {
    let (rest, ident) = recognize((
        take_while1(|c: char| c.is_ascii_alphanumeric() || c == '_'),
        opt(preceded(
            char('.'),
            take_while1(|c: char| c.is_ascii_alphanumeric() || c == '_'),
        )),
    ))
    .parse(input)?;

    let field = match ident {
        "from.user" => Field::FromUser,
        "to.user" => Field::ToUser,
        "method" => Field::Method,
        "ua" => Field::Ua,
        "call_id" => Field::CallId,
        "payload" => Field::Payload,
        "src.ip" => Field::SrcIp,
        "dst.ip" => Field::DstIp,
        "src.port" => Field::SrcPort,
        "dst.port" => Field::DstPort,
        "state" => Field::State,
        "duration" => Field::Duration,
        "msg_count" => Field::MsgCount,
        "pdd" => Field::Pdd,
        "setup_time" => Field::SetupTime,
        "retransmits" => Field::Retransmits,
        "rtp.mos" => Field::RtpMos,
        "rtp.jitter" => Field::RtpJitter,
        "rtp.loss" => Field::RtpLoss,
        "rtp.packets" => Field::RtpPackets,
        "rtp.codec" => Field::RtpCodec,
        "rtp.ssrc" => Field::RtpSsrc,
        "one_way" => Field::OneWay,
        "nat_mismatch" => Field::NatMismatch,
        "no_media" => Field::NoMedia,
        "codec_asymmetry" => Field::CodecAsymmetry,
        "ptime_asymmetry" => Field::PtimeAsymmetry,
        "payload_asymmetry" => Field::PayloadAsymmetry,
        "duration_asymmetry" => Field::DurationAsymmetry,
        "late_media" => Field::LateMedia,
        _ => {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
    };

    Ok((rest, field))
}

/// Render a filter parse error as a multi-line diagnostic: the (possibly
/// windowed) expression, a caret under the offending position, a quoting
/// hint when a bare word follows an operator (the classic mistake:
/// `method == INVITE`), the operator list, and a docs pointer.
///
/// An unknown-field hint (with a closest-match suggestion and the valid
/// field list) is added instead when an identifier-looking token sits in
/// field position and the quoting hint did not fire.
///
/// # Arguments
///
/// * `expr` — The full (trimmed) filter expression being parsed.
/// * `pos` — Byte offset of the error; clamped into range and onto a char
///   boundary before use.
/// * `problem` — Short description used as the headline.
///
/// # Returns
///
/// The formatted multi-line diagnostic string.
fn render_parse_error(expr: &str, pos: usize, problem: &str) -> String {
    // Clamp to a char boundary (nom positions are byte offsets).
    let mut pos = pos.min(expr.len());
    while pos > 0 && !expr.is_char_boundary(pos) {
        pos -= 1;
    }

    let offending: String = expr[pos..]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .chars()
        .take(20)
        .collect();

    // Window the expression around the error so the caret line stays
    // readable for very long inputs.
    const WINDOW: usize = 80;
    let col = expr[..pos].chars().count();
    let total = expr.chars().count();
    let (shown, caret_col) = if total <= WINDOW {
        (expr.to_string(), col)
    } else {
        let start = col.saturating_sub(WINDOW / 2);
        let windowed: String = expr.chars().skip(start).take(WINDOW).collect();
        let prefix = if start > 0 { "…" } else { "" };
        let suffix = if start + WINDOW < total { "…" } else { "" };
        (
            format!("{prefix}{windowed}{suffix}"),
            col - start + if start > 0 { 1 } else { 0 },
        )
    };

    let mut out = format!(
        "{problem} at position {pos}{}\n  {shown}\n  {caret:>width$}",
        if offending.is_empty() {
            String::new()
        } else {
            format!(": '{offending}'")
        },
        caret = '^',
        width = caret_col + 1,
    );

    // Quoting hint: bare word right after a comparison operator.
    let before = expr[..pos].trim_end();
    let mut quoting_hinted = false;
    if let Some(op) = ["=~", "==", "!=", "<=", ">=", "<", ">"]
        .iter()
        .find(|op| before.ends_with(**op))
        && offending.chars().next().is_some_and(|c| c.is_alphabetic())
        && !["and", "or", "true", "false"]
            .iter()
            .any(|kw| offending.eq_ignore_ascii_case(kw))
    {
        out.push_str(&format!(
            "\nhint: string values must be quoted: {op} '{offending}'"
        ));
        quoting_hinted = true;
    }

    // Unknown-field hint: an identifier-looking token followed by a
    // comparison operator sits in field position — name it, suggest the
    // closest real field, and list the valid set.
    let after_pos = &expr[pos..];
    let offending_raw = after_pos.split_whitespace().next().unwrap_or("");
    // split_whitespace may skip leading characters the parser does not
    // treat as whitespace (e.g. vertical tab), so the token need not start
    // at `pos`: derive its true end from the subslice address — a naive
    // `pos + len` slice landed mid-character on multibyte input.
    let token_end = if offending_raw.is_empty() {
        pos
    } else {
        pos + (offending_raw.as_ptr() as usize - after_pos.as_ptr() as usize) + offending_raw.len()
    };
    let rest_after = expr[token_end..].trim_start();
    let looks_like_field = !offending_raw.is_empty()
        && offending_raw
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic())
        && offending_raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    let in_field_position = ["=~", "==", "!=", "<=", ">=", "<", ">"]
        .iter()
        .any(|op| rest_after.starts_with(op));
    if !quoting_hinted
        && looks_like_field
        && in_field_position
        && !FIELD_NAMES.contains(&offending_raw)
    {
        out.push_str(&format!("\nhint: unknown field '{offending_raw}'"));
        if let Some(best) = closest_field(offending_raw) {
            out.push_str(&format!(" \u{2014} did you mean '{best}'?"));
        }
        out.push_str(&format!("\nvalid fields: {}", FIELD_NAMES.join(", ")));
    }

    out.push_str("\nvalid operators: ==, !=, <, <=, >, >=, =~ (regex)");
    out.push_str("\nsee docs/filter-dsl.md for fields, values, and diagnostic aliases");
    out
}

/// The valid field closest to `name` (edit distance ≤ 2), if any.
fn closest_field(name: &str) -> Option<&'static str> {
    FIELD_NAMES
        .iter()
        .map(|f| (edit_distance(name, f), *f))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, f)| f)
}

/// Plain Levenshtein distance — inputs are short field names, so the O(n·m)
/// two-row implementation is plenty.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Parse a comparison operator token into an `Operator`.
///
/// Two-character operators (`=~`, `==`, `!=`, `<=`, `>=`) are tried
/// before single-character `<`/`>` so a prefix is never misparsed.
/// Returns the remainder and the operator, or a nom error when no
/// operator matches.
fn parse_operator(input: &str) -> IResult<&str, Operator, NomErr<'_>> {
    alt((
        map(tag("=~"), |_| Operator::Regex),
        map(tag("=="), |_| Operator::Eq),
        map(tag("!="), |_| Operator::Ne),
        map(tag("<="), |_| Operator::Le),
        map(tag(">="), |_| Operator::Ge),
        map(tag("<"), |_| Operator::Lt),
        map(tag(">"), |_| Operator::Gt),
    ))
    .parse(input)
}

/// Scan a quoted string body (everything after the opening `quote`),
/// processing backslash escapes and returning the unescaped contents plus
/// the remainder after the closing quote.
///
/// A backslash always escapes (consumes) the following character, so an
/// escaped delimiter never terminates the string — this is what makes the
/// delimiter char expressible. The delimiter escapes `\'` and `\"` collapse
/// to the bare quote. Every other `\x` sequence — including `\\` — is kept
/// verbatim (backslash and following char both emitted) so that regex
/// metacharacters survive (`\d`, `\.`, `\x27`) and a literal backslash
/// reaches the regex engine as `\\` (one literal backslash) — matching how
/// callers pre-escape text with `regex::escape` before embedding it in a DSL
/// string literal.
///
/// Because a backslash always consumes the next char, `\\` is an inseparable
/// pair and cannot accidentally escape a trailing delimiter.
///
/// # Returns
///
/// `Some((unescaped, rest))` when a closing `quote` is found, else `None`
/// for an unterminated string (including a trailing lone backslash).
fn scan_quoted_string(body: &str, quote: char) -> Option<(String, &str)> {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '\\' {
            match chars.next() {
                // Escaped delimiter → the bare quote character.
                Some((_, q @ ('\'' | '"'))) => out.push(q),
                // Any other escape (incl. `\\`, `\d`, `\.`) is preserved
                // verbatim so regex syntax and literal backslashes survive.
                Some((_, other)) => {
                    out.push('\\');
                    out.push(other);
                }
                // Trailing backslash with no following char → unterminated.
                None => return None,
            }
        } else if c == quote {
            return Some((out, &body[i + c.len_utf8()..]));
        } else {
            out.push(c);
        }
    }
    None
}

/// Parse a value literal (string, number, or boolean).
///
/// For the `=~` (regex) operator, the string value is compiled into a regex
/// with a size limit of [`REGEX_SIZE_LIMIT`] bytes. A regex against the
/// `payload` field is compiled with the byte-oriented [`regex::bytes`]
/// engine so it can match the raw message without a lossy UTF-8 copy.
///
/// Inside a quoted string, a backslash introduces an escape: `\'`, `\"`, and
/// `\\` yield the literal quote/backslash so the delimiter char is
/// expressible; any other `\x` sequence is kept verbatim (backslash and all)
/// so regex metacharacters such as `\d` survive.
///
/// # Arguments
///
/// * `input` — Remaining expression text at the value position.
/// * `field` — The field already parsed; selects the byte-regex path for
///   `payload` regex comparisons.
/// * `op` — The operator already parsed; decides whether a quoted string
///   is kept verbatim or compiled as a regex.
///
/// # Returns
///
/// The unconsumed remainder and the parsed `Value`. Boolean literals are
/// matched case-insensitively and only when not a prefix of a longer
/// identifier; an unterminated string or an invalid/oversized regex
/// yields a nom `Failure`; any other token must parse as an `f64`.
fn parse_value(input: &str, field: Field, op: Operator) -> IResult<&str, Value, NomErr<'_>> {
    let (input, _) = multispace0(input)?;

    // Try boolean literals first
    if let Ok((rest, _)) = tag_no_case::<&str, &str, NomErr<'_>>("true").parse(input) {
        // Ensure "true" is not a prefix of a longer identifier
        if rest.is_empty()
            || !rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Ok((rest, Value::Bool(true)));
        }
    }
    if let Ok((rest, _)) = tag_no_case::<&str, &str, NomErr<'_>>("false").parse(input)
        && (rest.is_empty()
            || !rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return Ok((rest, Value::Bool(false)));
    }

    // Try quoted string (single or double quotes)
    if input.starts_with('\'') || input.starts_with('"') {
        let quote = input.as_bytes()[0] as char;
        let after_quote = &input[1..];
        let (string_val, rest) = scan_quoted_string(after_quote, quote).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Char))
        })?;

        if op == Operator::Regex {
            // `payload` greps the raw message bytes, so its regex is compiled
            // with the byte engine to match without a lossy UTF-8 copy.
            if field == Field::Payload {
                let re = regex::bytes::RegexBuilder::new(&string_val)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|_| {
                        nom::Err::Failure(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::Verify,
                        ))
                    })?;
                return Ok((rest, Value::ReBytes(re)));
            }
            let re = regex::RegexBuilder::new(&string_val)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|_| {
                    nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
                })?;
            return Ok((rest, Value::Re(re)));
        }

        return Ok((rest, Value::Str(string_val)));
    }

    // Try number
    let (rest, num) = double(input)?;
    Ok((rest, Value::Num(num)))
}

// ── Expression evaluator ────────────────────────────────────────────

/// Recursively evaluate an expression tree against a dialog and streams.
///
/// # Arguments
///
/// * `expr` — Node to evaluate.
/// * `dialog` — Dialog under test.
/// * `streams` — RTP streams associated with the dialog.
/// * `diag` — Precomputed media diagnosis for boolean diagnosis fields.
///
/// # Returns
///
/// The boolean result; `And`/`Or` short-circuit left to right.
fn eval_expr(
    expr: &Expr,
    dialog: &SipDialog,
    streams: &[&RtpStream],
    diag: &MediaDiagnosis,
) -> bool {
    match expr {
        Expr::And(lhs, rhs) => {
            eval_expr(lhs, dialog, streams, diag) && eval_expr(rhs, dialog, streams, diag)
        }
        Expr::Or(lhs, rhs) => {
            eval_expr(lhs, dialog, streams, diag) || eval_expr(rhs, dialog, streams, diag)
        }
        Expr::Not(inner) => !eval_expr(inner, dialog, streams, diag),
        Expr::Compare(field, op, value) => eval_compare(field, op, value, dialog, streams, diag),
    }
}

/// Evaluate a single field comparison.
///
/// Extracts the field's current value from the dialog, streams, or
/// diagnosis and dispatches to the string/numeric/boolean comparator.
/// Missing data falls back to neutral defaults (empty string, 0, first
/// stream), so absent values compare like a zero/empty field rather than
/// failing the whole expression.
///
/// # Arguments
///
/// * `field` — Which dialog/stream/diagnosis property to read.
/// * `op` — Comparison operator.
/// * `value` — Literal right-hand side from the parsed expression.
/// * `dialog` — Dialog under test.
/// * `streams` — RTP streams associated with the dialog.
/// * `diag` — Precomputed media diagnosis for boolean fields.
///
/// # Returns
///
/// `true` when the extracted value satisfies the comparison.
fn eval_compare(
    field: &Field,
    op: &Operator,
    value: &Value,
    dialog: &SipDialog,
    streams: &[&RtpStream],
    diag: &MediaDiagnosis,
) -> bool {
    match field {
        // ── String fields ──────────────────────────────────────────
        Field::FromUser => {
            let val = dialog.from_user.as_deref().unwrap_or("");
            compare_str(val, op, value)
        }
        Field::ToUser => {
            let val = dialog.to_user.as_deref().unwrap_or("");
            compare_str(val, op, value)
        }
        Field::Method => compare_str(dialog.method.as_str(), op, value),
        Field::Ua => {
            // Check User-Agent across all messages in the dialog
            let ua = dialog
                .messages
                .iter()
                .find_map(|m| m.user_agent().map(str::to_string))
                .unwrap_or_default();
            compare_str(&ua, op, value)
        }
        Field::CallId => compare_str(&dialog.call_id, op, value),
        // Any message in the dialog whose raw content matches (sngrep-style
        // payload filter: greps the whole SIP message text). Matched on the
        // raw bytes directly — no per-message lossy UTF-8 allocation.
        Field::Payload => dialog
            .messages
            .iter()
            .any(|m| compare_bytes(&m.raw, op, value)),
        Field::SrcIp => compare_str(&dialog.src_addr.to_string(), op, value),
        Field::DstIp => compare_str(&dialog.dst_addr.to_string(), op, value),
        Field::State => {
            let state_str = state_to_str(dialog.state());
            compare_str(state_str, op, value)
        }
        Field::RtpCodec => {
            // Match if ANY linked stream's codec satisfies the comparison,
            // consistent with the worst-across-streams quality fields.
            streams
                .iter()
                .any(|s| compare_str(s.codec.as_deref().unwrap_or(""), op, value))
        }
        Field::RtpSsrc => {
            // Match if ANY linked stream's SSRC (0x-prefixed 10-char hex)
            // satisfies the comparison.
            streams
                .iter()
                .any(|s| compare_str(&format!("{:#010x}", s.key.ssrc), op, value))
        }

        // ── Numeric fields ─────────────────────────────────────────
        // Ports come from the dialog's captured initial-message values,
        // not messages.first(): compact_idle drains oldest messages, so
        // "first" can be a later (direction-reversed) message.
        Field::SrcPort => compare_num(f64::from(dialog.src_port), op, value),
        Field::DstPort => compare_num(f64::from(dialog.dst_port), op, value),
        Field::Duration => {
            let dur = (dialog.updated_at - dialog.created_at).num_milliseconds() as f64 / 1000.0;
            compare_num(dur, op, value)
        }
        Field::MsgCount => compare_num(dialog.messages.len() as f64, op, value),
        Field::Pdd => {
            // PDD in seconds (convert from milliseconds)
            let pdd = dialog.timing.pdd_ms().map(|ms| ms as f64 / 1000.0);
            compare_opt_num(pdd, op, value)
        }
        Field::SetupTime => {
            let setup = dialog.timing.setup_ms().map(|ms| ms as f64 / 1000.0);
            compare_opt_num(setup, op, value)
        }
        Field::Retransmits => compare_num(f64::from(dialog.timing.total_retransmits()), op, value),
        Field::RtpMos => {
            // Use worst (lowest) MOS across streams for filtering
            // MOS is approximated from jitter and loss using E-model R-factor
            let mos = streams.iter().map(|s| stream_mos(s)).reduce(f64::min);
            compare_opt_num(mos, op, value)
        }
        Field::RtpJitter => {
            // Worst (highest) jitter across streams
            let jitter = streams.iter().map(|s| s.jitter).reduce(f64::max);
            compare_opt_num(jitter, op, value)
        }
        Field::RtpLoss => {
            // Worst (highest) loss percentage across streams
            let loss = streams
                .iter()
                .map(|s| {
                    let total = s.packet_count + s.lost_packets;
                    if total > 0 {
                        (s.lost_packets as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    }
                })
                .reduce(f64::max);
            compare_opt_num(loss, op, value)
        }
        Field::RtpPackets => {
            let total: u64 = streams.iter().map(|s| s.packet_count).sum();
            compare_num(total as f64, op, value)
        }

        // ── Boolean fields ─────────────────────────────────────────
        Field::OneWay => compare_bool(diag.one_way_audio, op, value),
        Field::NatMismatch => compare_bool(diag.nat_mismatch, op, value),
        Field::NoMedia => compare_bool(diag.no_media, op, value),
        Field::CodecAsymmetry => compare_bool(diag.codec_asymmetry.is_some(), op, value),
        Field::PtimeAsymmetry => compare_bool(diag.ptime_asymmetry.is_some(), op, value),
        Field::PayloadAsymmetry => compare_bool(diag.payload_type_asymmetry.is_some(), op, value),
        Field::DurationAsymmetry => compare_bool(diag.duration_asymmetry.is_some(), op, value),
        Field::LateMedia => compare_bool(diag.late_media.is_some(), op, value),
    }
}

/// Compare a string field value `field_val` against the filter value.
/// `<`/`>`/`<=`/`>=` order lexicographically; `=~` requires a compiled
/// regex value. Type mismatches (non-string literal) return `false`.
fn compare_str(field_val: &str, op: &Operator, value: &Value) -> bool {
    match (op, value) {
        (Operator::Eq, Value::Str(s)) => field_val == s,
        (Operator::Ne, Value::Str(s)) => field_val != s,
        (Operator::Lt, Value::Str(s)) => field_val < s.as_str(),
        (Operator::Gt, Value::Str(s)) => field_val > s.as_str(),
        (Operator::Le, Value::Str(s)) => field_val <= s.as_str(),
        (Operator::Ge, Value::Str(s)) => field_val >= s.as_str(),
        (Operator::Regex, Value::Re(re)) => re.is_match(field_val),
        _ => false,
    }
}

/// Compare a raw byte field value `field_val` (e.g. a whole SIP message)
/// against the filter value without decoding it to a `String`.
///
/// Ordering/equality operators compare bytes lexicographically against the
/// literal's UTF-8 bytes; `=~` requires the byte-regex value compiled for
/// the `payload` field. Type mismatches return `false`.
fn compare_bytes(field_val: &[u8], op: &Operator, value: &Value) -> bool {
    match (op, value) {
        (Operator::Eq, Value::Str(s)) => field_val == s.as_bytes(),
        (Operator::Ne, Value::Str(s)) => field_val != s.as_bytes(),
        (Operator::Lt, Value::Str(s)) => field_val < s.as_bytes(),
        (Operator::Gt, Value::Str(s)) => field_val > s.as_bytes(),
        (Operator::Le, Value::Str(s)) => field_val <= s.as_bytes(),
        (Operator::Ge, Value::Str(s)) => field_val >= s.as_bytes(),
        (Operator::Regex, Value::ReBytes(re)) => re.is_match(field_val),
        _ => false,
    }
}

/// Equality tolerance for numeric fields: every field is either integral
/// (ports, counts, packets) or millisecond-derived (duration/pdd/setup in
/// seconds, jitter in ms, MOS/loss quoted to ≥0.1), so half the finest
/// domain step (0.5 ms = 5e-4) absorbs float-computation noise while
/// keeping adjacent domain values distinct; `f64::EPSILON` was
/// effectively exact-match for any value ≥ 2.
const NUM_EQ_TOLERANCE: f64 = 5e-4;

/// Compare a numeric field value `field_val` against the filter value.
/// `==`/`!=` use the absolute [`NUM_EQ_TOLERANCE`]; `=~` and
/// non-numeric literals return `false`.
fn compare_num(field_val: f64, op: &Operator, value: &Value) -> bool {
    let rhs = match value {
        Value::Num(n) => *n,
        _ => return false,
    };
    match op {
        Operator::Eq => (field_val - rhs).abs() < NUM_EQ_TOLERANCE,
        Operator::Ne => (field_val - rhs).abs() >= NUM_EQ_TOLERANCE,
        Operator::Lt => field_val < rhs,
        Operator::Gt => field_val > rhs,
        Operator::Le => field_val <= rhs,
        Operator::Ge => field_val >= rhs,
        Operator::Regex => false, // regex not applicable to numbers
    }
}

/// Compare an OPTIONAL numeric field: an unknown matches NO comparison.
///
/// The alternative — substituting 0.0 for "never measured" — is what made
/// `rtp.mos < 3.0` select every dialog carrying no RTP at all, because 0.0 is
/// below every threshold anyone would type. A REGISTER capture with zero
/// streams was reported as the worst audio in the file.
///
/// `!=` returns false too, and that is the half worth stating: an unknown is
/// not "different from 3.0", it is unknown. Admitting it to `!=` would just
/// move the wrong answer to the operator who writes the negation. This is the
/// rule SQL uses for NULL, for the same reason.
///
/// Selecting the unmeasured is still possible, and with fields that mean it:
/// `rtp.packets == 0` is a real count rather than an absence, and `no_media`
/// is the diagnosis itself.
fn compare_opt_num(field_val: Option<f64>, op: &Operator, value: &Value) -> bool {
    match field_val {
        Some(v) => compare_num(v, op, value),
        None => false,
    }
}

/// Compare a boolean field value `field_val` against the filter value.
/// Only `==`/`!=` are meaningful; ordering operators, `=~`, and
/// non-boolean literals return `false`.
fn compare_bool(field_val: bool, op: &Operator, value: &Value) -> bool {
    let rhs = match value {
        Value::Bool(b) => *b,
        _ => return false,
    };
    match op {
        Operator::Eq => field_val == rhs,
        Operator::Ne => field_val != rhs,
        _ => false, // <, >, <=, >= not meaningful for booleans
    }
}

/// Convert a [`DialogState`] to its string representation for comparison
/// against `state` field literals.
fn state_to_str(state: &DialogState) -> &'static str {
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Cancelled => "Cancelled",
        DialogState::Failed => "Failed",
        DialogState::Redirected => "Redirected",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// MOS for a stream, scored by [`crate::rtp::quality::estimate_mos`].
///
/// Deliberately a thin wrapper and nothing more. This function once carried
/// its own formula — `R = 93.2 - min(jitter,100) - 2.5*loss_pct`, with no
/// codec term and no delay term — so `--filter "rtp.mos < 3.0"` selected a
/// different set of streams than the ones the detail view showed below 3.0,
/// diverging by as much as 1.7 MOS at 60 ms and 5% loss.
///
/// The only thing it computes now is loss percentage, because
/// `estimate_mos` takes a percentage and a stream carries counts.
///
/// # Arguments
///
/// * `stream` — the RTP stream whose jitter, loss and codec feed the estimate.
///
/// # Returns
///
/// The MOS, on the same scale and from the same code as every other surface.
pub fn stream_mos(stream: &RtpStream) -> f64 {
    let total = stream.packet_count + stream.lost_packets;
    let loss_pct = if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    crate::rtp::quality::estimate_mos(stream.jitter, loss_pct, stream.codec.as_deref())
}

// ── Tests ───────────────────────────────────────────────────────────

/// Unit tests for the filter DSL: field matching, operator precedence,
/// regex and boolean values, nesting limits, parse-error rendering,
/// diagnostic aliases, the comparators, and the MOS approximation.
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chrono::{DateTime, TimeDelta, Utc};

    use super::*;
    use crate::net::TransportProto;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::dialog::DialogState;
    use crate::sip::parser::parse_sip;

    /// Fixed 127.0.0.1 address used as both source and destination of
    /// every test message.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) so tests are
    /// deterministic.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a dialog from a single request with the given From user, To
    /// user, and method (User-Agent fixed to `TestUA/1.0`).
    fn make_dialog(from_user: &str, to_user: &str, method: &str) -> SipDialog {
        let raw = build_sip(
            &format!("{method} sip:{to_user}@example.com SIP/2.0"),
            &[
                &format!("From: <sip:{from_user}@example.com>;tag=t1"),
                &format!("To: <sip:{to_user}@example.com>"),
                "Call-ID: test-call-id@example.com",
                &format!("CSeq: 1 {method}"),
                "User-Agent: TestUA/1.0",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            base_ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        SipDialog::new(&msg).expect("should create dialog")
    }

    /// Build an INVITE dialog whose timing yields a post-dial delay of
    /// `pdd_ms` milliseconds.
    fn make_dialog_with_timing(pdd_ms: i64) -> SipDialog {
        let mut dialog = make_dialog("1001", "2002", "INVITE");
        dialog.timing.invite_sent = Some(base_ts());
        dialog.timing.ringing_at = Some(base_ts() + TimeDelta::milliseconds(pdd_ms));
        dialog
    }

    /// Build a one-packet RTP stream (SSRC 0xDEADBEEF), orphaned or claimed by
    /// a dialog — which is the same thing as whether `associated_dialog` is
    /// set, per [`RtpStream::orphaned`].
    fn make_rtp_stream(orphaned: bool) -> RtpStream {
        let key = StreamKey {
            ssrc: 0xDEADBEEF,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: 0xDEADBEEF,
            payload_offset: 12,
        };
        let mut stream = RtpStream::new(key, &hdr, base_ts());
        if !orphaned {
            stream.associated_dialog = Some("claimed@example.invalid".to_string());
        }
        stream
    }

    // ── Basic field matching ────────────────────────────────────────

    // ── Unknown values (#90) ────────────────────────────────────────

    /// A dialog carrying no RTP does not match a MOS threshold.
    ///
    /// The reported symptom, in the operator's words: the TUI's F7 filter told
    /// them every call had bad audio. `rtp.mos < 3.0` substituted 0.0 for
    /// "never measured", and 0.0 is below every threshold anyone would type,
    /// so REGISTERs, OPTIONS and failed INVITEs — none of which carry audio to
    /// judge — were returned as the worst-sounding calls in the capture.
    ///
    /// Reproduced against a real file before this test existed:
    /// `sipnab -N -I tests/pcap-samples/sip-register.pcap --json-dialogs
    /// --filter 'rtp.mos < 3.0'` returned the one dialog in a capture with
    /// zero RTP streams.
    #[test]
    fn a_dialog_with_no_rtp_does_not_match_a_mos_threshold() {
        let dialog = make_dialog("1001", "2002", "REGISTER");
        let filter = FilterExpr::parse("rtp.mos < 3.0").expect("should parse");
        assert!(
            !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent),
            "a dialog with no RTP has no MOS; it is not a bad-audio call"
        );
    }

    /// The same unknown does not match `!=` either.
    ///
    /// The half a partial fix gets wrong. An unknown is not "different from
    /// 3.0", it is unknown — admitting it here would move the same wrong
    /// answer to whoever writes the negation, which is where a triage filter
    /// usually ends up. SQL's NULL rule, for SQL's reason.
    #[test]
    fn an_unknown_mos_is_not_unequal_either() {
        let dialog = make_dialog("1001", "2002", "REGISTER");
        for expr in ["rtp.mos != 3.0", "rtp.mos > 3.0", "rtp.mos == 0.0"] {
            let filter = FilterExpr::parse(expr).expect("should parse");
            assert!(
                !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent),
                "`{expr}` must not match a dialog whose MOS was never measured"
            );
        }
    }

    /// Jitter and loss are unknown for the same dialog, and behave the same.
    ///
    /// Fixing `rtp.mos` alone would leave the identical trap in the two fields
    /// beside it, which is why the rule lives in one comparison helper.
    #[test]
    fn unknown_jitter_and_loss_match_no_threshold() {
        let dialog = make_dialog("1001", "2002", "REGISTER");
        for expr in ["rtp.jitter < 30", "rtp.loss < 5", "rtp.jitter != 1"] {
            let filter = FilterExpr::parse(expr).expect("should parse");
            assert!(
                !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent),
                "`{expr}` must not match a dialog with no RTP"
            );
        }
    }

    /// A dialog that HAS RTP still matches on its measured values.
    ///
    /// Anti-vacuity. A helper that returned false for everything would satisfy
    /// every assertion above.
    #[test]
    fn a_dialog_with_rtp_still_matches_on_its_measured_values() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let stream = make_rtp_stream(false);
        let streams = [&stream];
        let filter = FilterExpr::parse("rtp.mos > 0").expect("should parse");
        assert!(
            filter.matches_dialog(&dialog, &streams, CaptureMedia::Absent),
            "a measured MOS must still compare; the rule is about unknowns only"
        );
        let filter = FilterExpr::parse("rtp.jitter >= 0").expect("should parse");
        assert!(
            filter.matches_dialog(&dialog, &streams, CaptureMedia::Absent),
            "a measured jitter must still compare"
        );
    }

    /// An untimed call does not match a setup-time or PDD threshold.
    ///
    /// Same defect, on the fields #88 just made honest: a capture that opened
    /// mid-call now correctly reports an unknown setup time, and `setup_time
    /// < 1` must not then select it as the fastest call in the file. Anyone
    /// computing a p95 from that filter is averaging in calls that were never
    /// timed.
    #[test]
    fn an_untimed_call_matches_no_setup_or_pdd_threshold() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        for expr in ["setup_time < 1", "pdd < 1", "setup_time != 9"] {
            let filter = FilterExpr::parse(expr).expect("should parse");
            assert!(
                !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent),
                "`{expr}` must not match a dialog that was never timed"
            );
        }
    }

    /// A timed call still matches on its measured timing.
    ///
    /// The anti-vacuity partner of the test above.
    #[test]
    fn a_timed_call_still_matches_on_its_measured_timing() {
        let dialog = make_dialog_with_timing(1500);
        let filter = FilterExpr::parse("pdd < 2").expect("should parse");
        assert!(
            filter.matches_dialog(&dialog, &[], CaptureMedia::Absent),
            "a measured 1.5 s post-dial delay must still match `pdd < 2`"
        );

        let mut answered = make_dialog("1001", "2002", "INVITE");
        answered.timing.invite_sent = Some(base_ts());
        answered.timing.answered_at = Some(base_ts() + TimeDelta::milliseconds(2500));
        let filter = FilterExpr::parse("setup_time > 2").expect("should parse");
        assert!(
            filter.matches_dialog(&answered, &[], CaptureMedia::Absent),
            "a measured 2.5 s setup must still match `setup_time > 2`"
        );
    }

    /// `from.user ==` matches a dialog with that exact From user.
    #[test]
    fn from_user_equals_match() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("from.user == '1001'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    /// `payload` greps the raw text of every message: regex matches
    /// content anywhere in the message, and equality never panics on
    /// lossily-decoded bytes.
    #[test]
    fn payload_field_matches_raw_message_content() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        // The raw INVITE contains the To URI.
        let f = FilterExpr::parse("payload =~ '2002@example'").expect("should parse");
        assert!(f.matches_dialog(&dialog, &[], CaptureMedia::Absent));
        let f = FilterExpr::parse("payload =~ 'not-there'").expect("should parse");
        assert!(!f.matches_dialog(&dialog, &[], CaptureMedia::Absent));
        // Equality against a whole raw message: never matches here, must not
        // panic (raw bytes are lossily decoded).
        let f = FilterExpr::parse("payload == 'x'").expect("should parse");
        assert!(!f.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    /// Build a dialog whose sole INVITE carries `body` verbatim (so
    /// `payload` sees those exact bytes, valid UTF-8 or not).
    fn make_dialog_with_body(body: &[u8]) -> SipDialog {
        let raw = build_sip(
            "INVITE sip:2002@example.com SIP/2.0",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:2002@example.com>",
                "Call-ID: test-call-id@example.com",
                "CSeq: 1 INVITE",
                "User-Agent: TestUA/1.0",
                &format!("Content-Length: {}", body.len()),
            ],
            body,
        );
        let msg = parse_sip(
            &raw,
            base_ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        SipDialog::new(&msg).expect("should create dialog")
    }

    /// Item 1: quoted strings support backslash escapes so the delimiter
    /// char becomes expressible (`\'`, `\"`). Other backslash sequences —
    /// including `\\` and regex classes like `\d` — are preserved verbatim so
    /// regex syntax and pre-escaped literals still reach the engine. The old
    /// tokenizer had no escape mechanism, so a quoted delimiter was
    /// impossible to write.
    #[test]
    fn escaped_quotes_and_backslash_in_strings() {
        let dialog = make_dialog("1001", "2002", "INVITE");

        // `\'` lets a single-quoted literal contain its own delimiter — the
        // whole point of item 1. The old tokenizer stopped at the first `'`.
        let f = FilterExpr::parse(r"from.user == 'a\'b'").expect("should parse");
        match &f.root {
            Expr::Compare(_, _, Value::Str(s)) => assert_eq!(s, "a'b"),
            other => panic!("expected string compare, got {other:?}"),
        }

        // `\"` likewise inside a double-quoted literal.
        let f = FilterExpr::parse(r#"to.user == "x\"y""#).expect("should parse");
        match &f.root {
            Expr::Compare(_, _, Value::Str(s)) => assert_eq!(s, "x\"y"),
            other => panic!("expected string compare, got {other:?}"),
        }

        // Regex classes survive: `\d` is kept verbatim, so a 4-digit user
        // matches. The escaped `\'` here proves the delimiter is expressible
        // inside a regex too (matches nothing, but must parse).
        let f = FilterExpr::parse(r"from.user =~ '^\d\d\d\d$'").expect("should parse");
        assert!(f.matches_dialog(&dialog, &[], CaptureMedia::Absent)); // from.user == "1001"

        // `\\` is preserved as two characters, so the regex engine sees one
        // literal backslash. This keeps `regex::escape`-produced text (e.g.
        // the TUI filter builder, which emits `\\` for a literal backslash)
        // matching literally rather than turning into an invalid trailing
        // backslash.
        let f = FilterExpr::parse(r"from.user == 'a\\b'").expect("should parse");
        match &f.root {
            Expr::Compare(_, _, Value::Str(s)) => assert_eq!(s, r"a\\b"),
            other => panic!("expected string compare, got {other:?}"),
        }
    }

    /// Item 4: `payload =~` matches against the raw message bytes, not a
    /// lossy UTF-8 rendering. A message carrying a raw `0xFF` byte must NOT
    /// satisfy a search for the Unicode replacement character U+FFFD — the
    /// byte is not that character. The old `String::from_utf8_lossy` path
    /// fabricated a match by rewriting `0xFF` to U+FFFD.
    #[test]
    fn payload_matches_raw_bytes_not_lossy_replacement() {
        let dialog = make_dialog_with_body(&[0xFF]);

        // U+FFFD is absent from the true bytes → no match.
        let f = FilterExpr::parse(r"payload =~ '\x{FFFD}'").expect("should parse");
        assert!(!f.matches_dialog(&dialog, &[], CaptureMedia::Absent));

        // ASCII content around the invalid byte still greps fine and never
        // panics on the non-UTF-8 message.
        let dialog2 = make_dialog_with_body(b"MARK\xffER");
        let f = FilterExpr::parse("payload =~ 'MARK'").expect("should parse");
        assert!(f.matches_dialog(&dialog2, &[], CaptureMedia::Absent));
        let f = FilterExpr::parse("payload == 'nope'").expect("should parse");
        assert!(!f.matches_dialog(&dialog2, &[], CaptureMedia::Absent));
    }

    /// `from.user ==` rejects a dialog with a different From user.
    #[test]
    fn from_user_equals_no_match() {
        let dialog = make_dialog("2002", "1001", "INVITE");
        let filter = FilterExpr::parse("from.user == '1001'").expect("should parse");
        assert!(!filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── AND + NOT ───────────────────────────────────────────────────

    /// `AND` combined with `NOT ua =~` matches when the UA does not match
    /// the regex.
    #[test]
    fn method_and_not_ua_regex() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter =
            FilterExpr::parse("method == 'INVITE' AND NOT ua =~ 'scanner'").expect("should parse");
        // UA is "TestUA/1.0", does not match 'scanner', so NOT flips to true
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── PDD in seconds ─────────────────────────────────────────────

    /// `pdd` compares in seconds: a 4000 ms PDD satisfies `pdd > 3.0`.
    #[test]
    fn pdd_greater_than() {
        // PDD of 4000ms = 4.0 seconds, filter asks > 3.0
        let dialog = make_dialog_with_timing(4000);
        let filter = FilterExpr::parse("pdd > 3.0").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    /// A 2000 ms PDD does not satisfy `pdd > 3.0`.
    #[test]
    fn pdd_not_greater_than() {
        // PDD of 2000ms = 2.0 seconds, filter asks > 3.0
        let dialog = make_dialog_with_timing(2000);
        let filter = FilterExpr::parse("pdd > 3.0").expect("should parse");
        assert!(!filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── rtp.orphaned, withdrawn ─────────────────────────────────────

    /// `rtp.orphaned` is no longer a field, and asking for it says so.
    ///
    /// It asked whether a stream *belonging to this dialog* belongs to no
    /// dialog. A stream is orphaned exactly while `associated_dialog` is `None`
    /// ([`RtpStream::orphaned`](crate::rtp::stream::RtpStream::orphaned)), and
    /// the dialog's streams are exactly those whose `associated_dialog` is set,
    /// so the predicate was unsatisfiable by construction, not merely
    /// unobserved. Silently matching
    /// nothing is the worst of the options: `NOT rtp.orphaned` matched
    /// everything and the `problems` alias carried a disjunct that could never
    /// contribute. A parse error tells the operator; orphaned media is
    /// reachable through `--report` and `/v1/streams?orphaned=true`, which
    /// model streams rather than dialogs.
    #[test]
    fn rtp_orphaned_is_no_longer_a_field() {
        let err = FilterExpr::parse("rtp.orphaned == true")
            .expect_err("rtp.orphaned must not parse as a field");
        let msg = err.to_string();
        assert!(
            msg.contains("rtp.orphaned") || msg.contains("field"),
            "the error should name what was rejected, got: {msg}"
        );
    }

    /// The `problems` alias no longer carries the unsatisfiable disjunct.
    #[test]
    fn problems_alias_drops_the_unsatisfiable_disjunct() {
        let expr = expand_alias("problems", &AliasThresholds::default()).expect("alias exists");
        assert!(
            !expr.contains("orphaned"),
            "problems must not include a term that can never be true: {expr}"
        );
        FilterExpr::parse(&expr).expect("the alias must still parse");
    }

    // ── Boolean operator precedence ─────────────────────────────────

    /// Explicit parentheses change the result: `(A OR B) AND C` differs
    /// from `A OR (B AND C)` on the same dialog.
    #[test]
    fn precedence_or_and() {
        // (A OR B) AND C  vs  A OR (B AND C)
        // A = from.user == '1001' -> true
        // B = from.user == '9999' -> false
        // C = method == 'BYE'     -> false (method is INVITE)
        //
        // (A OR B) AND C = (true OR false) AND false = true AND false = false
        // A OR (B AND C) = true OR (false AND false) = true OR false = true

        let dialog = make_dialog("1001", "2002", "INVITE");

        let filter_grouped_or =
            FilterExpr::parse("(from.user == '1001' OR from.user == '9999') AND method == 'BYE'")
                .expect("should parse");
        assert!(!filter_grouped_or.matches_dialog(&dialog, &[], CaptureMedia::Absent));

        let filter_grouped_and =
            FilterExpr::parse("from.user == '1001' OR (from.user == '9999' AND method == 'BYE')")
                .expect("should parse");
        assert!(filter_grouped_and.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    /// Without parentheses, `AND` binds tighter than `OR`.
    #[test]
    fn default_precedence_and_binds_tighter() {
        // Without parens: A OR B AND C
        // AND binds tighter: A OR (B AND C)
        // A = from.user == '1001' -> true
        // B = from.user == '9999' -> false
        // C = method == 'BYE'     -> false
        // = true OR (false AND false) = true
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter =
            FilterExpr::parse("from.user == '1001' OR from.user == '9999' AND method == 'BYE'")
                .expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── Regex matching ──────────────────────────────────────────────

    /// `=~` matches when the field value satisfies the regex.
    #[test]
    fn regex_match_accepts() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("from.user =~ '100[0-9]'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    /// `=~` rejects when the field value does not satisfy the regex.
    #[test]
    fn regex_match_rejects() {
        let dialog = make_dialog("2001", "3003", "INVITE");
        let filter = FilterExpr::parse("from.user =~ '100[0-9]'").expect("should parse");
        assert!(!filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── Nesting depth limit ─────────────────────────────────────────

    /// Parenthesis nesting past the limit fails to parse with a
    /// nesting-depth error.
    #[test]
    fn nesting_depth_exceeded() {
        let open_parens = "(".repeat(60);
        let close_parens = ")".repeat(60);
        let expr = format!("{open_parens}from.user == '1001'{close_parens}");
        let result = FilterExpr::parse(&expr);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nesting depth"),
            "expected nesting depth error, got: {err_msg}"
        );
    }

    /// Nesting well within the limit (10 levels) parses fine.
    #[test]
    fn nesting_within_limit() {
        // 10 levels should be fine
        let open_parens = "(".repeat(10);
        let close_parens = ")".repeat(10);
        let expr = format!("{open_parens}from.user == '1001'{close_parens}");
        let result = FilterExpr::parse(&expr);
        assert!(result.is_ok());
    }

    // ── Parse errors ────────────────────────────────────────────────

    /// An expression ending after the operator (missing value) fails to
    /// parse.
    #[test]
    fn parse_error_missing_value() {
        let result = FilterExpr::parse("from.user ==");
        assert!(result.is_err());
    }

    /// An empty expression fails to parse with an "empty" error message.
    #[test]
    fn parse_error_empty_input() {
        let result = FilterExpr::parse("");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("empty"),
            "expected empty error, got: {err_msg}"
        );
    }

    /// A whitespace-only expression fails to parse.
    #[test]
    fn parse_error_whitespace_only() {
        let result = FilterExpr::parse("   ");
        assert!(result.is_err());
    }

    /// A comparison on an unknown field name fails to parse.
    #[test]
    fn parse_error_unknown_field() {
        let result = FilterExpr::parse("bogus_field == '1001'");
        assert!(result.is_err());
    }

    // ── Rich parse-error rendering ──────────────────────────────────

    /// The rendered parse error echoes the expression with a caret
    /// aligned under the offending token.
    #[test]
    fn parse_error_shows_expression_with_caret_at_position() {
        let err = FilterExpr::parse("method == INVITE")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("method == INVITE"),
            "error must echo the expression, got:\n{err}"
        );
        // Caret under column 10 (0-based) where the unquoted value starts.
        let caret_line = err
            .lines()
            .find(|l| l.trim_end().ends_with('^'))
            .unwrap_or_else(|| panic!("error must contain a caret line, got:\n{err}"));
        assert_eq!(
            caret_line.find('^'),
            err.lines()
                .find(|l| l.contains("method == INVITE"))
                .and_then(|l| l.find("INVITE")),
            "caret must align under the offending token, got:\n{err}"
        );
    }

    /// An unquoted string value produces a quoting hint showing the
    /// corrected form.
    #[test]
    fn parse_error_hints_quoting_for_unquoted_value() {
        let err = FilterExpr::parse("method == INVITE")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("== 'INVITE'"),
            "error must show the corrected, quoted form, got:\n{err}"
        );
        assert!(
            err.to_lowercase().contains("quot"),
            "error must explain that values need quotes, got:\n{err}"
        );
    }

    /// Every rendered parse error lists the valid operators.
    #[test]
    fn parse_error_lists_operators() {
        let err = FilterExpr::parse("from.user @@ 'alice'")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("==") && err.contains("=~"),
            "error must list valid operators, got:\n{err}"
        );
    }

    /// Caret column math counts characters, not bytes, so a multibyte
    /// prefix does not misplace the caret.
    #[test]
    fn parse_error_caret_correct_with_multibyte_prefix() {
        // 'é' is 2 bytes / 1 column: caret math must use chars, not bytes.
        let err = FilterExpr::parse("from.user == 'é' and method == INVITE")
            .unwrap_err()
            .to_string();
        let expr_line = err
            .lines()
            .find(|l| l.contains("from.user"))
            .expect("expression echoed");
        let caret_line = err
            .lines()
            .find(|l| l.trim_end().ends_with('^'))
            .expect("caret line present");
        let caret_col = caret_line.chars().take_while(|c| *c == ' ').count();
        let invite_col = expr_line
            .find("INVITE")
            .map(|byte_idx| expr_line[..byte_idx].chars().count())
            .expect("INVITE present in echoed expression");
        assert_eq!(
            caret_col, invite_col,
            "caret column must be measured in characters, not bytes, got:\n{err}"
        );
    }

    /// Very long expressions are windowed around the error position so
    /// the diagnostic lines stay readable, caret included.
    #[test]
    fn parse_error_long_input_is_windowed_not_panicking() {
        let long = format!("from.user == '{}' and method == INVITE", "x".repeat(200));
        let err = FilterExpr::parse(&long).unwrap_err().to_string();
        assert!(
            err.lines().all(|l| l.chars().count() <= 120),
            "long expressions must be windowed around the error, got:\n{err}"
        );
        assert!(err.contains('^'), "caret still present, got:\n{err}");
    }

    // ── Diagnostic aliases ──────────────────────────────────────────

    /// Every documented alias expands to an expression that parses.
    #[test]
    fn all_aliases_expand_and_parse() {
        let aliases = [
            "problems",
            "slow-setup",
            "short-calls",
            "one-way",
            "nat-issues",
            "codec-asym",
            "ptime-asym",
            "payload-asym",
            "duration-asym",
            "late-media",
        ];
        for alias in &aliases {
            let expanded = expand_alias(alias, &AliasThresholds::default())
                .unwrap_or_else(|| panic!("alias '{alias}' should exist"));
            let result = FilterExpr::parse(&expanded);
            assert!(
                result.is_ok(),
                "alias '{alias}' expanded to '{expanded}' but failed to parse: {:?}",
                result.unwrap_err()
            );
        }
    }

    /// expand_alias returns None for an unrecognized alias.
    #[test]
    fn unknown_alias_returns_none() {
        assert!(expand_alias("nonexistent", &AliasThresholds::default()).is_none());
    }

    // ── Double-quoted strings ───────────────────────────────────────

    /// Double-quoted string values parse and match like single-quoted
    /// ones.
    #[test]
    fn double_quoted_string() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse(r#"from.user == "1001""#).expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── State comparison ────────────────────────────────────────────

    /// `state ==` matches the dialog's current state name and rejects
    /// others.
    #[test]
    fn state_comparison() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        // Initial state for INVITE is Trying
        let filter = FilterExpr::parse("state == 'Trying'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));

        let filter_fail = FilterExpr::parse("state == 'Failed'").expect("should parse");
        assert!(!filter_fail.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── Dialog state with Failed ────────────────────────────────────

    /// A dialog driven to Failed by a 503 matches `state == 'Failed'`.
    #[test]
    fn failed_state() {
        let mut dialog = make_dialog("1001", "2002", "INVITE");
        // Drive dialog to Failed via the state machine (503 response to INVITE)
        let raw_503 = build_sip(
            "SIP/2.0 503 Service Unavailable",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:2002@example.com>;tag=t2",
                "Call-ID: test-call-id@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let fail_msg = parse_sip(
            &raw_503,
            base_ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse 503");
        crate::sip::dialog::update_state(&mut dialog, &fail_msg);
        assert_eq!(*dialog.state(), DialogState::Failed);
        let filter = FilterExpr::parse("state == 'Failed'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── Complex compound expression ─────────────────────────────────

    /// A compound expression mixing AND, parentheses, and OR evaluates
    /// correctly.
    #[test]
    fn complex_compound_expr() {
        let dialog = make_dialog_with_timing(4000);
        let filter = FilterExpr::parse("from.user == '1001' AND (pdd > 3.0 OR state == 'Failed')")
            .expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── Msg count ───────────────────────────────────────────────────

    /// `msg_count` reflects the number of stored messages.
    #[test]
    fn msg_count() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        // Dialog has exactly 1 message (the initial INVITE)
        let filter = FilterExpr::parse("msg_count == 1").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));

        let filter_more = FilterExpr::parse("msg_count > 5").expect("should parse");
        assert!(!filter_more.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── RTP packets count ───────────────────────────────────────────

    /// `rtp.packets` sums packet counts across associated streams.
    #[test]
    fn rtp_packets_count() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let stream = make_rtp_stream(false);
        let streams: Vec<&RtpStream> = vec![&stream];
        // Stream has 1 packet from construction
        let filter = FilterExpr::parse("rtp.packets >= 1").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));
    }

    // ── Retransmits ─────────────────────────────────────────────────

    /// `retransmits` compares against the dialog's total retransmit count.
    #[test]
    fn retransmits_comparison() {
        let mut dialog = make_dialog("1001", "2002", "INVITE");
        dialog
            .timing
            .retransmit_counts
            .insert("1 INVITE".to_string(), 5);
        let filter = FilterExpr::parse("retransmits > 3").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── Not-equal operator ──────────────────────────────────────────

    /// `!=` matches when the field value differs from the literal.
    #[test]
    fn not_equal_operator() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("method != 'BYE'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── Integer numeric values ──────────────────────────────────────

    /// Integer literals (no decimal point) parse as numbers.
    #[test]
    fn integer_numeric_value() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("msg_count == 1").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── expand_alias: every alias maps to its documented expression ─────

    /// Each alias expands to exactly its documented DSL expression.
    #[test]
    fn expand_alias_returns_exact_expansions() {
        assert!(
            expand_alias("problems", &AliasThresholds::default())
                .unwrap()
                .contains("state == 'Failed'")
        );
        // 11.0, not the 3.0 this asserted before: `slow-setup` now reads the
        // SAME post-dial-delay threshold the diagnosis reports on. Under the
        // old pair a call could be slow enough for sipnab to report and not
        // slow enough for `--slow-setup` to select.
        assert_eq!(
            expand_alias("slow-setup", &AliasThresholds::default()).as_deref(),
            Some("pdd > 11.0")
        );
        assert_eq!(
            AliasThresholds::default().pdd_secs,
            crate::sip::diagnosis::SignalingThresholds::BUILT_IN.post_dial_delay_sec,
            "the alias threshold must BE the diagnosis threshold, not a copy of its value"
        );
        // 3.0, not the 5.0 this asserted before. sipnab held two definitions
        // of a short call: the fraud detector's (tunable, and what it acts on)
        // and this alias's own 5.0 (a literal nobody could reach). They are
        // now one number, and it is the one an operator can change.
        assert_eq!(
            expand_alias("short-calls", &AliasThresholds::default()).as_deref(),
            Some("duration < 3.0 AND state == 'Completed'")
        );
        assert_eq!(
            expand_alias("one-way", &AliasThresholds::default()).as_deref(),
            Some("one_way == true")
        );
        assert_eq!(
            expand_alias("nat-issues", &AliasThresholds::default()).as_deref(),
            Some("nat_mismatch == true")
        );
        assert_eq!(
            expand_alias("codec-asym", &AliasThresholds::default()).as_deref(),
            Some("codec_asymmetry == true")
        );
        assert_eq!(
            expand_alias("ptime-asym", &AliasThresholds::default()).as_deref(),
            Some("ptime_asymmetry == true")
        );
        assert_eq!(
            expand_alias("payload-asym", &AliasThresholds::default()).as_deref(),
            Some("payload_asymmetry == true")
        );
        assert_eq!(
            expand_alias("duration-asym", &AliasThresholds::default()).as_deref(),
            Some("duration_asymmetry == true")
        );
        assert_eq!(
            expand_alias("late-media", &AliasThresholds::default()).as_deref(),
            Some("late_media == true")
        );
    }

    /// Tuning a threshold changes which calls an alias SELECTS.
    ///
    /// The assertion is on selection, not on the expanded string. `--problems`
    /// carrying different text is worth nothing to an operator; the defect
    /// this closes was that tuning `[diagnosis]` to an SLA left the filter
    /// selecting on figures nobody chose, so what must move is the answer.
    #[test]
    fn tuning_a_threshold_changes_which_calls_an_alias_selects() {
        let shipped = AliasThresholds::default();

        // A post-dial delay between the tuned and the shipped threshold: not a
        // problem by the shipped figure, a problem by a tightened one. Any
        // change below is therefore caused by the threshold and not the call.
        let pdd = (shipped.pdd_secs + 3.0) / 2.0;
        assert!(
            pdd < shipped.pdd_secs,
            "the fixture must start BELOW the shipped threshold, or this proves nothing"
        );

        let by_shipped = FilterExpr::parse(&expand_alias("problems", &shipped).unwrap())
            .expect("the shipped expansion must parse");

        let tuned = AliasThresholds {
            pdd_secs: 3.0,
            ..shipped
        };
        let by_tuned = FilterExpr::parse(&expand_alias("problems", &tuned).unwrap())
            .expect("the tuned expansion must parse");

        // Compare the compiled PDD term directly: the shipped set must not
        // select this call and the tuned set must.
        let shipped_expr = expand_alias("problems", &shipped).unwrap();
        let tuned_expr = expand_alias("problems", &tuned).unwrap();
        assert!(
            shipped_expr.contains(&format!("pdd > {}", dsl_num(shipped.pdd_secs))),
            "the shipped expansion must carry the shipped threshold: {shipped_expr}"
        );
        assert!(
            tuned_expr.contains("pdd > 3.0"),
            "the tuned expansion must carry the tuned threshold: {tuned_expr}"
        );
        assert_ne!(
            shipped_expr, tuned_expr,
            "a tuned threshold must change the filter, or the config is ignored"
        );

        // Both must remain valid DSL — a threshold that produces an
        // unparseable filter would fail closed and select nothing at all.
        drop((by_shipped, by_tuned));
    }

    /// Every alias number is sourced from a threshold that is already tunable.
    ///
    /// Pins the property the type exists for: no figure in an alias may be a
    /// literal that only lives here, because that is precisely how
    /// `--problems` came to disagree with the diagnosis it reports.
    #[test]
    fn every_alias_threshold_is_sourced_from_a_tunable_setting() {
        let t = AliasThresholds::default();
        let bands = crate::rtp::bands::QualityBands::default();
        assert_eq!(
            t.pdd_secs,
            crate::sip::diagnosis::SignalingThresholds::BUILT_IN.post_dial_delay_sec
        );
        assert_eq!(t.loss_pct, bands.loss_bad_pct);
        assert_eq!(t.jitter_ms, bands.jitter_bad_ms);
        assert_eq!(
            t.short_call_secs,
            crate::security::fraud_detect::FraudThresholds::BUILT_IN.short_call_secs as f64
        );
    }

    /// Alias matching is exact and case-sensitive; near-misses return
    /// None.
    #[test]
    fn expand_alias_empty_and_case_sensitive_are_none() {
        // Alias matching is exact and case-sensitive.
        assert!(expand_alias("", &AliasThresholds::default()).is_none());
        assert!(expand_alias("Problems", &AliasThresholds::default()).is_none());
        assert!(expand_alias("PROBLEMS", &AliasThresholds::default()).is_none());
        assert!(expand_alias("slow_setup", &AliasThresholds::default()).is_none());
    }

    // ── check_nesting_depth: boundary behaviour ─────────────────────────

    /// Exactly 50 nested parens passes the depth check; 51 fails it.
    #[test]
    fn nesting_depth_exactly_at_limit_ok() {
        // Exactly MAX_NESTING_DEPTH (50) open parens is allowed; 51 is not.
        let expr = format!("{}from.user == '1001'{}", "(".repeat(50), ")".repeat(50));
        // Nesting-depth check itself passes (no "nesting depth" error).
        assert!(check_nesting_depth(&expr).is_ok());

        let too_deep = format!("{}from.user == '1001'{}", "(".repeat(51), ")".repeat(51));
        let err = check_nesting_depth(&too_deep).unwrap_err().to_string();
        assert!(err.contains("nesting depth"), "got: {err}");
    }

    /// Leading close-parens saturate the depth at zero instead of
    /// underflowing.
    #[test]
    fn nesting_depth_unbalanced_close_parens_saturates() {
        // Leading ')' must not underflow; depth saturates at 0.
        assert!(check_nesting_depth(")))(((").is_ok());
    }

    // ── render_parse_error: direct unit coverage ────────────────────────

    /// render_parse_error emits the headline, echoed expression, caret,
    /// operator list, and docs pointer.
    #[test]
    fn render_parse_error_basic_caret_and_footer() {
        let expr = "from.user == 'x'";
        let out = render_parse_error(expr, 0, "unexpected input");
        assert!(out.starts_with("unexpected input at position 0"));
        assert!(out.contains(expr));
        assert!(out.contains('^'));
        assert!(out.contains("valid operators:"));
        assert!(out.contains("docs/filter-dsl.md"));
    }

    /// A position at end-of-string yields no offending token, so the
    /// ": '...'" suffix is omitted.
    #[test]
    fn render_parse_error_empty_offending_omits_token() {
        // pos at end-of-string => no offending token => no ": '...'" suffix.
        let expr = "from.user == 'x'";
        let out = render_parse_error(expr, expr.len(), "unexpected trailing input");
        let header = out.lines().next().unwrap();
        assert!(header.ends_with("position 16"), "got: {header}");
        assert!(!header.contains(": '"), "got: {header}");
    }

    /// Keyword values like `true` after an operator do not trigger the
    /// quoting hint.
    #[test]
    fn render_parse_error_no_quote_hint_for_keyword_value() {
        // "true" after an operator is a valid boolean, so no quoting hint.
        let out = render_parse_error("one_way == true", 11, "x");
        assert!(!out.contains("must be quoted"), "got: {out}");
    }

    /// Uppercase keyword values like `TRUE` after an operator do not trigger
    /// the quoting hint — the parser matches booleans/`AND`/`OR`
    /// case-insensitively, so the hint exclusion must be case-insensitive too.
    #[test]
    fn render_parse_error_no_quote_hint_for_uppercase_keyword() {
        // `TRUE` parses as a boolean literal (tag_no_case), so a "quote this"
        // hint would be misleading.
        let out = render_parse_error("method == TRUE", 10, "x");
        assert!(!out.contains("must be quoted"), "got: {out}");
    }

    /// An out-of-range error position is clamped to the input length
    /// instead of panicking.
    #[test]
    fn render_parse_error_pos_past_end_is_clamped() {
        // An out-of-range position must not panic; it is clamped to len.
        let expr = "method == 'X'";
        let out = render_parse_error(expr, 9999, "boom");
        assert!(out.contains("boom at position"));
    }

    // ── parse_value / parse_operator error arms via FilterExpr::parse ───

    /// A string literal with no closing quote fails to parse.
    #[test]
    fn parse_unterminated_string_errors() {
        // Missing closing quote hits the ErrorKind::Char failure arm.
        let result = FilterExpr::parse("from.user == 'unterminated");
        assert!(result.is_err());
    }

    /// An `=~` value that fails regex compilation fails to parse.
    #[test]
    fn parse_invalid_regex_errors() {
        // An unbalanced group fails RegexBuilder::build -> Verify failure arm.
        let result = FilterExpr::parse("from.user =~ '(unclosed'");
        assert!(result.is_err());
    }

    /// A bare unquoted word where a number or string is expected fails to
    /// parse.
    #[test]
    fn parse_non_numeric_value_for_number_errors() {
        // A bare unquoted word where a number/string is expected.
        let result = FilterExpr::parse("msg_count == abc");
        assert!(result.is_err());
    }

    /// An unknown operator token fails to parse.
    #[test]
    fn parse_unknown_operator_errors() {
        let result = FilterExpr::parse("from.user ?? '1001'");
        assert!(result.is_err());
    }

    /// Unparsed trailing input after a valid expression fails with a
    /// "trailing" error.
    #[test]
    fn parse_trailing_input_errors() {
        let result = FilterExpr::parse("from.user == '1001' garbage");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("trailing"), "got: {err}");
    }

    /// The `false` boolean literal parses and evaluates correctly.
    #[test]
    fn parse_false_boolean_literal() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        // one_way is false with no streams, so == false matches.
        let filter = FilterExpr::parse("one_way == false").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    /// A partial method selection (OR of method equalities) hides dialogs
    /// whose method is not listed and shows those that are.
    #[test]
    fn partial_method_filter_excludes_unlisted_method() {
        // C1: a dialog whose initial method is not one of the filter checkboxes
        // (e.g. BYE) must be HIDDEN by a partial method selection — only the
        // explicitly-checked methods are shown. (All-checked yields no filter at
        // the dialog layer, so such dialogs are shown then.)
        let bye = make_dialog("1001", "2002", "BYE");
        let partial = FilterExpr::parse("(method == 'REGISTER' OR method == 'INVITE')")
            .expect("should parse");
        assert!(
            !partial.matches_dialog(&bye, &[], CaptureMedia::Absent),
            "a partial method selection must not match an unlisted-method dialog"
        );
        // And it does match a dialog whose method IS in the selection.
        let invite = make_dialog("1001", "2002", "INVITE");
        assert!(partial.matches_dialog(&invite, &[], CaptureMedia::Absent));
    }

    /// FilterExpr::never() rejects every dialog regardless of method.
    #[test]
    fn never_matches_no_dialog() {
        // `FilterExpr::never()` represents "show nothing" — it must reject every
        // dialog regardless of method, users, or RTP state.
        let never = FilterExpr::never();
        for method in ["INVITE", "REGISTER", "BYE", "OPTIONS"] {
            let dialog = make_dialog("1001", "2002", method);
            assert!(
                !never.matches_dialog(&dialog, &[], CaptureMedia::Absent),
                "never() must not match a {method} dialog"
            );
        }
    }

    // ── compare_str: every operator + type mismatch ─────────────────────

    /// compare_str handles every operator, including lexicographic
    /// ordering and regex matching.
    #[test]
    fn compare_str_all_operators() {
        assert!(compare_str("b", &Operator::Eq, &Value::Str("b".into())));
        assert!(!compare_str("b", &Operator::Eq, &Value::Str("a".into())));
        assert!(compare_str("b", &Operator::Ne, &Value::Str("a".into())));
        assert!(compare_str("a", &Operator::Lt, &Value::Str("b".into())));
        assert!(compare_str("b", &Operator::Gt, &Value::Str("a".into())));
        assert!(compare_str("a", &Operator::Le, &Value::Str("a".into())));
        assert!(compare_str("b", &Operator::Ge, &Value::Str("b".into())));
        let re = regex::Regex::new("^b").unwrap();
        assert!(compare_str("bee", &Operator::Regex, &Value::Re(re)));
    }

    /// compare_str returns false for non-string literals and for `=~`
    /// without a compiled regex.
    #[test]
    fn compare_str_type_mismatch_is_false() {
        // String field compared against a numeric/bool literal => false.
        assert!(!compare_str("b", &Operator::Eq, &Value::Num(1.0)));
        assert!(!compare_str("b", &Operator::Eq, &Value::Bool(true)));
        // Regex operator without a compiled regex value => false.
        assert!(!compare_str("b", &Operator::Regex, &Value::Str("b".into())));
    }

    // ── compare_num: every operator + type mismatch ─────────────────────

    /// compare_num handles every ordering operator; regex is never
    /// applicable to numbers.
    #[test]
    fn compare_num_all_operators() {
        assert!(compare_num(3.0, &Operator::Eq, &Value::Num(3.0)));
        assert!(!compare_num(3.0, &Operator::Eq, &Value::Num(4.0)));
        assert!(compare_num(3.0, &Operator::Ne, &Value::Num(4.0)));
        assert!(compare_num(2.0, &Operator::Lt, &Value::Num(3.0)));
        assert!(compare_num(4.0, &Operator::Gt, &Value::Num(3.0)));
        assert!(compare_num(3.0, &Operator::Le, &Value::Num(3.0)));
        assert!(compare_num(3.0, &Operator::Ge, &Value::Num(3.0)));
        // Regex is never applicable to numbers.
        assert!(!compare_num(3.0, &Operator::Regex, &Value::Num(3.0)));
    }

    /// compare_num returns false for non-numeric literals.
    #[test]
    fn compare_num_type_mismatch_is_false() {
        assert!(!compare_num(3.0, &Operator::Eq, &Value::Str("3".into())));
        assert!(!compare_num(3.0, &Operator::Lt, &Value::Bool(false)));
    }

    /// Equality tolerates float-computation noise (a computed 5.0000001
    /// equals a literal 5) but still rejects genuinely different values;
    /// `!=` mirrors `==` exactly.
    #[test]
    fn compare_num_eq_tolerates_computed_float_noise() {
        assert!(compare_num(5.000_000_1, &Operator::Eq, &Value::Num(5.0)));
        assert!(!compare_num(5.000_000_1, &Operator::Ne, &Value::Num(5.0)));
        assert!(!compare_num(5.6, &Operator::Eq, &Value::Num(5.0)));
        assert!(compare_num(5.6, &Operator::Ne, &Value::Num(5.0)));
        // Adjacent millisecond-domain values stay distinct.
        assert!(!compare_num(5.001, &Operator::Eq, &Value::Num(5.0)));
    }

    /// `rtp.jitter == 30` matches a stream whose computed jitter carries
    /// float noise (30 + 1e-7) — end-to-end through eval_compare.
    #[test]
    fn rtp_jitter_eq_matches_computed_float() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let mut stream = make_rtp_stream(false);
        stream.jitter = 30.0 + 1e-7;
        let streams: Vec<&RtpStream> = vec![&stream];
        let f = FilterExpr::parse("rtp.jitter == 30").expect("parse");
        assert!(f.matches_dialog(&dialog, &streams, CaptureMedia::Observed));
        stream.jitter = 30.6;
        let streams: Vec<&RtpStream> = vec![&stream];
        assert!(!f.matches_dialog(&dialog, &streams, CaptureMedia::Observed));
    }

    // ── src.port/dst.port: stable across idle compaction ────────────────

    /// After compaction drains the dialog's oldest messages (as
    /// DialogStore::compact_idle does), `src.port`/`dst.port` must still
    /// evaluate to the initial message's ports — not the ports of whatever
    /// message happens to be first now (a response has them swapped).
    #[test]
    fn src_dst_port_stable_after_compaction() {
        let invite = build_sip(
            "INVITE sip:2002@example.com SIP/2.0",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:2002@example.com>",
                "Call-ID: port-stability@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &invite,
            base_ts(),
            localhost(),
            localhost(),
            5060,
            5080,
            TransportProto::Udp,
        )
        .expect("should parse");
        let mut dialog = SipDialog::new(&msg).expect("should create dialog");

        // 200 OK travels the reverse direction: ports swapped.
        let ok = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:2002@example.com>;tag=t2",
                "Call-ID: port-stability@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let reply = parse_sip(
            &ok,
            base_ts() + TimeDelta::seconds(1),
            localhost(),
            localhost(),
            5080,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        dialog.messages.push(reply);

        // Simulate DialogStore::compact_idle evicting the oldest message.
        dialog.messages.drain(..1);

        let src = FilterExpr::parse("src.port == 5060").expect("parse");
        let dst = FilterExpr::parse("dst.port == 5080").expect("parse");
        assert!(src.matches_dialog(&dialog, &[], CaptureMedia::Absent));
        assert!(dst.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    // ── compare_bool: operators + type mismatch ─────────────────────────

    /// compare_bool supports only ==/!=; ordering and regex operators
    /// return false.
    #[test]
    fn compare_bool_eq_ne_and_unsupported_operators() {
        assert!(compare_bool(true, &Operator::Eq, &Value::Bool(true)));
        assert!(!compare_bool(true, &Operator::Eq, &Value::Bool(false)));
        assert!(compare_bool(true, &Operator::Ne, &Value::Bool(false)));
        // Ordering operators are not meaningful for booleans => false.
        assert!(!compare_bool(true, &Operator::Lt, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Gt, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Le, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Ge, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Regex, &Value::Bool(true)));
    }

    /// compare_bool returns false for non-boolean literals.
    #[test]
    fn compare_bool_type_mismatch_is_false() {
        assert!(!compare_bool(true, &Operator::Eq, &Value::Num(1.0)));
        assert!(!compare_bool(
            true,
            &Operator::Eq,
            &Value::Str("true".into())
        ));
    }

    // ── state_to_str: all DialogState variants ──────────────────────────

    /// state_to_str maps every DialogState variant to its expected name.
    #[test]
    fn state_to_str_covers_all_variants() {
        let cases = [
            (DialogState::Trying, "Trying"),
            (DialogState::Ringing, "Ringing"),
            (DialogState::InCall, "InCall"),
            (DialogState::Completed, "Completed"),
            (DialogState::Cancelled, "Cancelled"),
            (DialogState::Failed, "Failed"),
            (DialogState::Registered, "Registered"),
            (DialogState::Expired, "Expired"),
            (DialogState::Pending, "Pending"),
            (DialogState::Active, "Active"),
            (DialogState::Terminated, "Terminated"),
            (DialogState::Transferring, "Transferring"),
        ];
        for (state, expected) in cases {
            assert_eq!(state_to_str(&state), expected);
        }
    }

    // ── approximate_mos ─────────────────────────────────────────────────

    /// A clean stream (no loss, no jitter) scores a MOS in the ~4.4 range.
    #[test]
    fn approximate_mos_clean_stream_is_high() {
        // No loss, no jitter => R near 93 => MOS in the ~4.4 range.
        let stream = make_rtp_stream(false);
        let mos = stream_mos(&stream);
        assert!(mos > 4.0 && mos <= 4.5, "got {mos}");
    }

    /// Heavy jitter and loss lower the MOS below a clean stream's, but
    /// never below the 1.0 floor.
    #[test]
    fn approximate_mos_degrades_with_jitter_and_loss() {
        let mut stream = make_rtp_stream(false);
        stream.jitter = 80.0;
        stream.lost_packets = 50;
        // packet_count is 1 from construction; make loss heavy.
        let degraded = stream_mos(&stream);
        let clean = stream_mos(&make_rtp_stream(false));
        assert!(degraded < clean, "degraded {degraded} < clean {clean}");
        assert!(degraded >= 1.0, "MOS floor is 1.0, got {degraded}");
    }

    /// Worst-case jitter and loss floor the MOS at exactly 1.0.
    #[test]
    fn approximate_mos_worst_case_floored_at_one() {
        let mut stream = make_rtp_stream(false);
        stream.jitter = 100.0;
        stream.lost_packets = 1_000_000;
        let mos = stream_mos(&stream);
        assert!((mos - 1.0).abs() < 1e-9, "expected floor 1.0, got {mos}");
    }

    /// Zero packets means zero loss percentage (no division by zero) and
    /// a high MOS.
    #[test]
    fn approximate_mos_no_packets_no_loss() {
        // total == 0 path: loss_pct stays 0.0, no division by zero.
        let mut stream = make_rtp_stream(false);
        stream.packet_count = 0;
        stream.lost_packets = 0;
        let mos = stream_mos(&stream);
        assert!(mos > 4.0, "got {mos}");
    }

    // ── eval_compare numeric field paths via matches_dialog ─────────────

    /// rtp.mos, rtp.jitter, and rtp.loss evaluate against the worst value
    /// across the associated streams.
    #[test]
    fn rtp_mos_loss_jitter_fields_evaluate() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let mut stream = make_rtp_stream(false);
        stream.jitter = 60.0;
        stream.lost_packets = 4; // with packet_count 1 => high loss%
        let streams: Vec<&RtpStream> = vec![&stream];

        // MOS should be degraded below 4.0.
        let mos_filter = FilterExpr::parse("rtp.mos < 4.0").expect("parse");
        assert!(mos_filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));

        // Jitter worst-case across streams is 60.0.
        let jitter_filter = FilterExpr::parse("rtp.jitter > 50.0").expect("parse");
        assert!(jitter_filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));

        // Loss percentage is high.
        let loss_filter = FilterExpr::parse("rtp.loss > 50.0").expect("parse");
        assert!(loss_filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));
    }

    /// rtp.codec matches a stream's codec; rtp.ssrc matches the
    /// 0x-prefixed lowercase hex rendering.
    #[test]
    fn rtp_codec_and_ssrc_string_fields() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let mut stream = make_rtp_stream(false);
        stream.codec = Some("PCMU".to_string());
        let streams: Vec<&RtpStream> = vec![&stream];

        let codec_filter = FilterExpr::parse("rtp.codec == 'PCMU'").expect("parse");
        assert!(codec_filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));

        // SSRC is rendered as 0x-prefixed 10-char hex of 0xDEADBEEF.
        let ssrc_filter = FilterExpr::parse("rtp.ssrc == '0xdeadbeef'").expect("parse");
        assert!(ssrc_filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));
    }

    /// Item 3: the parse-time `needs_diagnosis` flag is set iff the
    /// expression references a diagnosis-derived field, so `matches_dialog`
    /// can skip the media/asymmetry diagnosis when none appears.
    #[test]
    fn needs_diagnosis_flag_reflects_field_use() {
        // No diagnosis field → flag clear.
        assert!(
            !FilterExpr::parse("from.user == '1001'")
                .unwrap()
                .needs_diagnosis
        );
        assert!(
            !FilterExpr::parse("rtp.mos < 3.0 AND rtp.packets > 0")
                .unwrap()
                .needs_diagnosis
        );

        // Each diagnosis field trips the flag.
        for field in [
            "one_way",
            "nat_mismatch",
            "no_media",
            "codec_asymmetry",
            "ptime_asymmetry",
            "payload_asymmetry",
            "duration_asymmetry",
            "late_media",
        ] {
            let expr = format!("{field} == true");
            assert!(
                FilterExpr::parse(&expr).unwrap().needs_diagnosis,
                "{field} must set needs_diagnosis"
            );
        }

        // Nested under boolean combinators still trips it.
        assert!(
            FilterExpr::parse("method == 'INVITE' AND (state == 'InCall' OR late_media == true)")
                .unwrap()
                .needs_diagnosis
        );

        // A filter without diagnosis fields evaluates the same whether or not
        // streams are present (the skipped diagnosis changes nothing).
        let dialog = make_dialog("1001", "2002", "INVITE");
        let f = FilterExpr::parse("from.user == '1001'").unwrap();
        assert!(f.matches_dialog(&dialog, &[], CaptureMedia::Absent));
    }

    /// Item 2: `rtp.codec` / `rtp.ssrc` match if ANY linked stream matches,
    /// consistent with the worst-across-streams quality fields. A codec or
    /// SSRC carried only by the *second* stream must still match. The old
    /// code inspected only the first stream and missed these.
    #[test]
    fn rtp_codec_and_ssrc_match_any_stream() {
        let dialog = make_dialog("1001", "2002", "INVITE");

        // Two streams: first PCMU (SSRC 0xDEADBEEF), second G722 with a
        // distinct SSRC.
        let mut first = make_rtp_stream(false);
        first.codec = Some("PCMU".to_string());
        let mut second = make_rtp_stream(false);
        second.codec = Some("G722".to_string());
        second.key.ssrc = 0x0000_0001;
        let streams: Vec<&RtpStream> = vec![&first, &second];

        // Codec carried only by the second stream matches.
        let codec_filter = FilterExpr::parse("rtp.codec == 'G722'").expect("parse");
        assert!(codec_filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));

        // SSRC carried only by the second stream matches.
        let ssrc_filter = FilterExpr::parse("rtp.ssrc == '0x00000001'").expect("parse");
        assert!(ssrc_filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed));

        // A codec present on no stream still does not match.
        let miss = FilterExpr::parse("rtp.codec == 'opus'").expect("parse");
        assert!(!miss.matches_dialog(&dialog, &streams, CaptureMedia::Observed));
    }

    // ── select_dialogs ──────────────────────────────────────────────

    /// Build a store holding one INVITE dialog per Call-ID given.
    fn store_with(call_ids: &[&str]) -> crate::sip::dialog_store::DialogStore {
        let mut store = crate::sip::dialog_store::DialogStore::new(100, false);
        for id in call_ids {
            let raw = build_sip(
                "INVITE sip:2002@example.com SIP/2.0",
                &[
                    "From: <sip:1001@example.com>;tag=t1",
                    "To: <sip:2002@example.com>",
                    &format!("Call-ID: {id}"),
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
                b"",
            );
            let msg = parse_sip(
                &raw,
                base_ts(),
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse");
            store.process_message(msg);
        }
        store
    }

    /// No filter selects every dialog, in store order — the post-capture
    /// outputs must be unchanged when `--filter` is absent.
    #[test]
    fn select_dialogs_without_a_filter_selects_everything() {
        let dialogs = store_with(&["a@example.com", "b@example.com", "c@example.com"]);
        let streams = crate::rtp::stream_store::StreamStore::new(16);

        let selection = select_dialogs(None, &dialogs, &streams);

        let ids: Vec<&str> = selection
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.as_str())
            .collect();
        assert_eq!(ids, ["a@example.com", "b@example.com", "c@example.com"]);
    }

    /// A filter selects the matching dialogs and only those. The defect it
    /// guards: the whole store came back for every expression.
    #[test]
    fn select_dialogs_with_a_filter_selects_only_matches() {
        let dialogs = store_with(&["a@example.com", "b@example.com", "c@example.com"]);
        let streams = crate::rtp::stream_store::StreamStore::new(16);
        let expr = FilterExpr::parse("call_id == 'b@example.com'").expect("should parse");

        let selection = select_dialogs(Some(&expr), &dialogs, &streams);

        let ids: Vec<&str> = selection
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.as_str())
            .collect();
        assert_eq!(ids, ["b@example.com"]);
    }

    /// An unsatisfiable filter selects nothing — an empty result is an
    /// answer, and must not degrade into "show everything".
    #[test]
    fn select_dialogs_with_an_unsatisfiable_filter_selects_nothing() {
        let dialogs = store_with(&["a@example.com", "b@example.com"]);
        let streams = crate::rtp::stream_store::StreamStore::new(16);

        let selection = select_dialogs(Some(&FilterExpr::never()), &dialogs, &streams);

        assert!(selection.dialogs.is_empty());
        assert!(
            selection.streams.is_empty(),
            "no dialog selected leaves no stream to show"
        );
    }

    /// An empty store yields an empty selection under both arms rather than
    /// panicking on the missing-Call-ID lookups.
    #[test]
    fn select_dialogs_on_an_empty_store_is_empty() {
        let dialogs = store_with(&[]);
        let streams = crate::rtp::stream_store::StreamStore::new(16);
        let expr = FilterExpr::parse("state == 'Failed'").expect("should parse");

        assert!(select_dialogs(None, &dialogs, &streams).dialogs.is_empty());
        assert!(
            select_dialogs(Some(&expr), &dialogs, &streams)
                .dialogs
                .is_empty()
        );
    }
}

/// Tests for the unknown-field diagnostic: naming the field, suggesting
/// the closest valid one, and keeping FIELD_NAMES in sync with the parser.
#[cfg(test)]
mod unknown_field_hint_tests {
    use super::*;

    /// An unknown field used to render as a generic "unexpected input" —
    /// no field named, no valid list, no suggestion.
    #[test]
    fn unknown_field_error_names_field_and_suggests_closest() {
        let err = FilterExpr::parse("rtp.mso > 3").expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field 'rtp.mso'"),
            "must name the field: {msg}"
        );
        assert!(
            msg.contains("did you mean 'rtp.mos'"),
            "must suggest the closest field: {msg}"
        );
        assert!(msg.contains("valid fields:"), "must list fields: {msg}");
    }

    /// A field with no near match still gets the valid-fields list.
    #[test]
    fn unknown_field_without_close_match_lists_fields() {
        let err = FilterExpr::parse("zzzzqqq == 'x'").expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains("unknown field 'zzzzqqq'"), "{msg}");
        assert!(msg.contains("valid fields:"), "{msg}");
    }

    /// FIELD_NAMES must stay in sync with the parser's accepted set.
    #[test]
    fn field_names_const_matches_parser() {
        for name in FIELD_NAMES {
            assert!(
                parse_field(name).is_ok(),
                "FIELD_NAMES lists '{name}' but parse_field rejects it"
            );
        }
    }

    /// The quoting hint must still win for the classic unquoted-value case.
    #[test]
    fn quoting_hint_not_replaced_by_field_hint() {
        let err = FilterExpr::parse("method == INVITE").expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains("must be quoted"), "{msg}");
        assert!(!msg.contains("unknown field"), "{msg}");
    }
}

/// Regression tests proving parse-error rendering is total on adversarial
/// (multibyte, odd-whitespace) input.
#[cfg(test)]
mod parse_error_render_robustness_tests {
    use super::*;

    /// proptest (filter_dsl_parse_is_total) found: with whitespace before a
    /// multibyte token at the error position, `pos + token.len()` sliced the
    /// expression mid-character and panicked. Parsing must be total —
    /// adversarial input yields Err, never a panic.
    #[test]
    fn parse_error_rendering_survives_multibyte_and_whitespace() {
        for expr in [
            " \u{6b31b}\u{6b31b}\u{6b31b}",
            "method ==\t\u{6b31b}",
            "a \u{6b31b} == 'x'",
            "\u{6b31b} == \u{6b31b}",
            "duration <  \u{6b31b}\u{6b31b} AND method == 'INVITE'",
            // Trailing-input path: unparsed tail is " ab\u{6b31b}" — the
            // token starts after the space, so pos + token.len() lands
            // inside the 4-byte char.
            "method == 'x' ab\u{6b31b}",
            "method == 'x' \u{6b31b}",
            "method == 'x'  a\u{6b31b}\u{6b31b}",
            "true qq\u{6b31b}",
            // proptest's minimal failing input: \u{b} (vertical tab) is
            // whitespace to split_whitespace but NOT to the parser, so the
            // error position sits ON it and the naive `pos + token.len()`
            // slice lands inside the 2-byte '¡'.
            "(\u{b}\t\u{a1}!\u{b}",
        ] {
            let _ = FilterExpr::parse(expr); // must not panic
        }
    }
}
