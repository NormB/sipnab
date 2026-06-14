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
use crate::rtp::diagnosis::{self, MediaDiagnosis};
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
/// ```ignore
/// let filter = FilterExpr::parse("from.user == '1001' AND rtp.loss > 2.0")?;
/// let matches = filter.matches_dialog(&dialog, &streams);
/// ```
#[derive(Clone)]
pub struct FilterExpr {
    root: Expr,
}

impl std::fmt::Debug for FilterExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterExpr")
            .field("root", &self.root)
            .finish()
    }
}

/// Expression tree node.
#[derive(Debug, Clone)]
enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Compare(Field, Operator, Value),
}

/// Addressable fields in the filter DSL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    FromUser,
    ToUser,
    Method,
    Ua,
    CallId,
    SrcIp,
    DstIp,
    SrcPort,
    DstPort,
    State,
    Duration,
    MsgCount,
    Pdd,
    SetupTime,
    Retransmits,
    RtpMos,
    RtpJitter,
    RtpLoss,
    RtpPackets,
    RtpOrphaned,
    RtpCodec,
    RtpSsrc,
    OneWay,
    NatMismatch,
    NoMedia,
    // Phase 8.7 — per-call asymmetry signals
    CodecAsymmetry,
    PtimeAsymmetry,
    PayloadAsymmetry,
    DurationAsymmetry,
    LateMedia,
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Regex,
}

/// A literal value on the right-hand side of a comparison.
#[derive(Debug, Clone)]
enum Value {
    Str(String),
    Num(f64),
    Bool(bool),
    Re(regex::Regex),
}

// ── Diagnostic filter aliases ───────────────────────────────────────

/// Expand a named filter alias to its DSL expression.
///
/// Supported aliases:
/// - `"problems"` — calls with any diagnostic issue (includes 8.7 asymmetry signals)
/// - `"slow-setup"` — calls with PDD > 3 seconds
/// - `"short-calls"` — completed calls under 5 seconds
/// - `"one-way"` — calls with one-way audio
/// - `"nat-issues"` — calls with NAT mismatch
/// - `"codec-asym"` — codec asymmetry across the two legs (8.7)
/// - `"ptime-asym"` — packetization-time asymmetry (8.7)
/// - `"payload-asym"` — payload-type asymmetry (8.7)
/// - `"duration-asym"` — leg-duration asymmetry (8.7)
/// - `"late-media"` — RTP started long after 200 OK (8.7)
///
/// Returns `None` if the alias is not recognized.
pub fn expand_alias(alias: &str) -> Option<&'static str> {
    match alias {
        "problems" => Some(
            "state == 'Failed' OR one_way == true OR rtp.loss > 2.0 \
             OR rtp.jitter > 50.0 OR nat_mismatch == true \
             OR retransmits > 3 OR pdd > 32.0 OR rtp.orphaned == true \
             OR codec_asymmetry == true OR ptime_asymmetry == true \
             OR payload_asymmetry == true OR duration_asymmetry == true \
             OR late_media == true",
        ),
        "slow-setup" => Some("pdd > 3.0"),
        "short-calls" => Some("duration < 5.0 AND state == 'Completed'"),
        "one-way" => Some("one_way == true"),
        "nat-issues" => Some("nat_mismatch == true"),
        "codec-asym" => Some("codec_asymmetry == true"),
        "ptime-asym" => Some("ptime_asymmetry == true"),
        "payload-asym" => Some("payload_asymmetry == true"),
        "duration-asym" => Some("duration_asymmetry == true"),
        "late-media" => Some("late_media == true"),
        _ => None,
    }
}

// ── FilterExpr public API ───────────────────────────────────────────

impl FilterExpr {
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

        Ok(FilterExpr { root: expr })
    }

    /// Evaluate this filter against a SIP dialog and its associated RTP streams.
    ///
    /// For RTP quality fields (`rtp.mos`, `rtp.jitter`, `rtp.loss`), the worst
    /// value across all associated streams is used for comparison, since
    /// filtering typically aims to find problematic calls.
    ///
    /// Boolean diagnosis fields (`one_way`, `nat_mismatch`, `no_media`) are
    /// computed from the associated streams via the diagnosis engine.
    pub fn matches_dialog(&self, dialog: &SipDialog, streams: &[&RtpStream]) -> bool {
        let mut diag = diagnosis::diagnose_media(streams, None);
        diagnosis::diagnose_asymmetry(
            &mut diag,
            Some(dialog),
            streams,
            &diagnosis::AsymmetryThresholds::default(),
        );
        eval_expr(&self.root, dialog, streams, &diag)
    }
}

// ── Nesting depth check ─────────────────────────────────────────────

/// Verify parenthesis nesting does not exceed [`MAX_NESTING_DEPTH`].
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

/// Parse an or-expression: `and_expr ("OR" and_expr)*`.
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

/// Parse an and-expression: `not_expr ("AND" not_expr)*`.
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

/// Parse a not-expression: `"NOT" atom | atom`.
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

/// Parse a comparison: `field operator value`.
fn parse_comparison(input: &str) -> IResult<&str, Expr, NomErr<'_>> {
    let (input, _) = multispace0(input)?;
    let (input, field) = parse_field(input)?;
    let (input, _) = multispace0(input)?;
    let (input, op) = parse_operator(input)?;
    let (input, _) = multispace0(input)?;
    let (input, value) = parse_value(input, op)?;

    Ok((input, Expr::Compare(field, op, value)))
}

/// Parse a dotted field identifier.
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
        "rtp.orphaned" => Field::RtpOrphaned,
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
    if let Some(op) = ["=~", "==", "!=", "<=", ">=", "<", ">"]
        .iter()
        .find(|op| before.ends_with(**op))
        && offending.chars().next().is_some_and(|c| c.is_alphabetic())
        && !["and", "or", "true", "false"].contains(&offending.as_str())
    {
        out.push_str(&format!(
            "\nhint: string values must be quoted: {op} '{offending}'"
        ));
    }

    out.push_str("\nvalid operators: ==, !=, <, <=, >, >=, =~ (regex)");
    out.push_str("\nsee docs/filter-dsl.md for fields, values, and diagnostic aliases");
    out
}

/// Parse a comparison operator.
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

/// Parse a value literal (string, number, or boolean).
///
/// For the `=~` (regex) operator, the string value is compiled into a regex
/// with a size limit of [`REGEX_SIZE_LIMIT`] bytes.
fn parse_value(input: &str, op: Operator) -> IResult<&str, Value, NomErr<'_>> {
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
        let end = after_quote.find(quote).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Char))
        })?;
        let string_val = &after_quote[..end];
        let rest = &after_quote[end + 1..];

        if op == Operator::Regex {
            let re = regex::RegexBuilder::new(string_val)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|_| {
                    nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
                })?;
            return Ok((rest, Value::Re(re)));
        }

        return Ok((rest, Value::Str(string_val.to_string())));
    }

    // Try number
    let (rest, num) = double(input)?;
    Ok((rest, Value::Num(num)))
}

// ── Expression evaluator ────────────────────────────────────────────

/// Recursively evaluate an expression tree against a dialog and streams.
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
        Field::SrcIp => compare_str(&dialog.src_addr.to_string(), op, value),
        Field::DstIp => compare_str(&dialog.dst_addr.to_string(), op, value),
        Field::State => {
            let state_str = state_to_str(dialog.state());
            compare_str(state_str, op, value)
        }
        Field::RtpCodec => {
            // Use the first stream's codec
            let codec = streams
                .iter()
                .find_map(|s| s.codec.as_deref())
                .unwrap_or("");
            compare_str(codec, op, value)
        }
        Field::RtpSsrc => {
            // Format as hex for comparison
            let ssrc = streams
                .first()
                .map(|s| format!("{:#010x}", s.key.ssrc))
                .unwrap_or_default();
            compare_str(&ssrc, op, value)
        }

        // ── Numeric fields ─────────────────────────────────────────
        Field::SrcPort => compare_num(
            f64::from(dialog.messages.first().map_or(0, |m| m.src_port)),
            op,
            value,
        ),
        Field::DstPort => compare_num(
            f64::from(dialog.messages.first().map_or(0, |m| m.dst_port)),
            op,
            value,
        ),
        Field::Duration => {
            let dur = (dialog.updated_at - dialog.created_at).num_milliseconds() as f64 / 1000.0;
            compare_num(dur, op, value)
        }
        Field::MsgCount => compare_num(dialog.messages.len() as f64, op, value),
        Field::Pdd => {
            // PDD in seconds (convert from milliseconds)
            let pdd = dialog
                .timing
                .pdd_ms()
                .map(|ms| ms as f64 / 1000.0)
                .unwrap_or(0.0);
            compare_num(pdd, op, value)
        }
        Field::SetupTime => {
            let setup = dialog
                .timing
                .setup_ms()
                .map(|ms| ms as f64 / 1000.0)
                .unwrap_or(0.0);
            compare_num(setup, op, value)
        }
        Field::Retransmits => compare_num(f64::from(dialog.timing.total_retransmits()), op, value),
        Field::RtpMos => {
            // Use worst (lowest) MOS across streams for filtering
            // MOS is approximated from jitter and loss using E-model R-factor
            let mos = streams.iter().map(|s| approximate_mos(s)).reduce(f64::min);
            compare_num(mos.unwrap_or(0.0), op, value)
        }
        Field::RtpJitter => {
            // Worst (highest) jitter across streams
            let jitter = streams.iter().map(|s| s.jitter).reduce(f64::max);
            compare_num(jitter.unwrap_or(0.0), op, value)
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
            compare_num(loss.unwrap_or(0.0), op, value)
        }
        Field::RtpPackets => {
            let total: u64 = streams.iter().map(|s| s.packet_count).sum();
            compare_num(total as f64, op, value)
        }

        // ── Boolean fields ─────────────────────────────────────────
        Field::RtpOrphaned => {
            let orphaned = streams.iter().any(|s| s.orphaned);
            compare_bool(orphaned, op, value)
        }
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

/// Compare a string field value against the filter value.
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

/// Compare a numeric field value against the filter value.
fn compare_num(field_val: f64, op: &Operator, value: &Value) -> bool {
    let rhs = match value {
        Value::Num(n) => *n,
        _ => return false,
    };
    match op {
        Operator::Eq => (field_val - rhs).abs() < f64::EPSILON,
        Operator::Ne => (field_val - rhs).abs() >= f64::EPSILON,
        Operator::Lt => field_val < rhs,
        Operator::Gt => field_val > rhs,
        Operator::Le => field_val <= rhs,
        Operator::Ge => field_val >= rhs,
        Operator::Regex => false, // regex not applicable to numbers
    }
}

/// Compare a boolean field value against the filter value.
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

/// Convert a [`DialogState`] to its string representation for comparison.
fn state_to_str(state: &DialogState) -> &'static str {
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Cancelled => "Cancelled",
        DialogState::Failed => "Failed",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// Approximate MOS score from jitter and loss using the E-model R-factor.
///
/// This is a simplified ITU-T G.107 approximation for narrowband codecs:
/// - R = 93.2 - jitter_penalty - loss_penalty
/// - jitter_penalty = jitter_ms (capped contribution)
/// - loss_penalty = 2.5 * loss_pct
/// - MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6 (for R > 0)
fn approximate_mos(stream: &RtpStream) -> f64 {
    let total = stream.packet_count + stream.lost_packets;
    let loss_pct = if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let jitter_penalty = stream.jitter.min(100.0);
    let loss_penalty = 2.5 * loss_pct;

    let r = (93.2 - jitter_penalty - loss_penalty).clamp(0.0, 100.0);

    if r < 1.0 {
        1.0
    } else {
        1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chrono::{DateTime, TimeDelta, Utc};

    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::dialog::DialogState;
    use crate::sip::parser::parse_sip;

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

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

    fn make_dialog_with_timing(pdd_ms: i64) -> SipDialog {
        let mut dialog = make_dialog("1001", "2002", "INVITE");
        dialog.timing.invite_sent = Some(base_ts());
        dialog.timing.ringing_at = Some(base_ts() + TimeDelta::milliseconds(pdd_ms));
        dialog
    }

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
        stream.orphaned = orphaned;
        stream
    }

    // ── Basic field matching ────────────────────────────────────────

    #[test]
    fn from_user_equals_match() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("from.user == '1001'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    #[test]
    fn from_user_equals_no_match() {
        let dialog = make_dialog("2002", "1001", "INVITE");
        let filter = FilterExpr::parse("from.user == '1001'").expect("should parse");
        assert!(!filter.matches_dialog(&dialog, &[]));
    }

    // ── AND + NOT ───────────────────────────────────────────────────

    #[test]
    fn method_and_not_ua_regex() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter =
            FilterExpr::parse("method == 'INVITE' AND NOT ua =~ 'scanner'").expect("should parse");
        // UA is "TestUA/1.0", does not match 'scanner', so NOT flips to true
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── PDD in seconds ─────────────────────────────────────────────

    #[test]
    fn pdd_greater_than() {
        // PDD of 4000ms = 4.0 seconds, filter asks > 3.0
        let dialog = make_dialog_with_timing(4000);
        let filter = FilterExpr::parse("pdd > 3.0").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    #[test]
    fn pdd_not_greater_than() {
        // PDD of 2000ms = 2.0 seconds, filter asks > 3.0
        let dialog = make_dialog_with_timing(2000);
        let filter = FilterExpr::parse("pdd > 3.0").expect("should parse");
        assert!(!filter.matches_dialog(&dialog, &[]));
    }

    // ── RTP orphaned boolean ────────────────────────────────────────

    #[test]
    fn rtp_orphaned_true() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let stream = make_rtp_stream(true);
        let streams: Vec<&RtpStream> = vec![&stream];
        let filter = FilterExpr::parse("rtp.orphaned == true").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &streams));
    }

    #[test]
    fn rtp_orphaned_false() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let stream = make_rtp_stream(false);
        let streams: Vec<&RtpStream> = vec![&stream];
        let filter = FilterExpr::parse("rtp.orphaned == true").expect("should parse");
        assert!(!filter.matches_dialog(&dialog, &streams));
    }

    // ── Boolean operator precedence ─────────────────────────────────

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
        assert!(!filter_grouped_or.matches_dialog(&dialog, &[]));

        let filter_grouped_and =
            FilterExpr::parse("from.user == '1001' OR (from.user == '9999' AND method == 'BYE')")
                .expect("should parse");
        assert!(filter_grouped_and.matches_dialog(&dialog, &[]));
    }

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
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── Regex matching ──────────────────────────────────────────────

    #[test]
    fn regex_match_accepts() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("from.user =~ '100[0-9]'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    #[test]
    fn regex_match_rejects() {
        let dialog = make_dialog("2001", "3003", "INVITE");
        let filter = FilterExpr::parse("from.user =~ '100[0-9]'").expect("should parse");
        assert!(!filter.matches_dialog(&dialog, &[]));
    }

    // ── Nesting depth limit ─────────────────────────────────────────

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

    #[test]
    fn parse_error_missing_value() {
        let result = FilterExpr::parse("from.user ==");
        assert!(result.is_err());
    }

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

    #[test]
    fn parse_error_whitespace_only() {
        let result = FilterExpr::parse("   ");
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_unknown_field() {
        let result = FilterExpr::parse("bogus_field == '1001'");
        assert!(result.is_err());
    }

    // ── Rich parse-error rendering ──────────────────────────────────

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
            let expanded =
                expand_alias(alias).unwrap_or_else(|| panic!("alias '{alias}' should exist"));
            let result = FilterExpr::parse(expanded);
            assert!(
                result.is_ok(),
                "alias '{alias}' expanded to '{expanded}' but failed to parse: {:?}",
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn unknown_alias_returns_none() {
        assert!(expand_alias("nonexistent").is_none());
    }

    // ── Double-quoted strings ───────────────────────────────────────

    #[test]
    fn double_quoted_string() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse(r#"from.user == "1001""#).expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── State comparison ────────────────────────────────────────────

    #[test]
    fn state_comparison() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        // Initial state for INVITE is Trying
        let filter = FilterExpr::parse("state == 'Trying'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));

        let filter_fail = FilterExpr::parse("state == 'Failed'").expect("should parse");
        assert!(!filter_fail.matches_dialog(&dialog, &[]));
    }

    // ── Dialog state with Failed ────────────────────────────────────

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
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── Complex compound expression ─────────────────────────────────

    #[test]
    fn complex_compound_expr() {
        let dialog = make_dialog_with_timing(4000);
        let filter = FilterExpr::parse("from.user == '1001' AND (pdd > 3.0 OR state == 'Failed')")
            .expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── Msg count ───────────────────────────────────────────────────

    #[test]
    fn msg_count() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        // Dialog has exactly 1 message (the initial INVITE)
        let filter = FilterExpr::parse("msg_count == 1").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));

        let filter_more = FilterExpr::parse("msg_count > 5").expect("should parse");
        assert!(!filter_more.matches_dialog(&dialog, &[]));
    }

    // ── RTP packets count ───────────────────────────────────────────

    #[test]
    fn rtp_packets_count() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let stream = make_rtp_stream(false);
        let streams: Vec<&RtpStream> = vec![&stream];
        // Stream has 1 packet from construction
        let filter = FilterExpr::parse("rtp.packets >= 1").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &streams));
    }

    // ── Retransmits ─────────────────────────────────────────────────

    #[test]
    fn retransmits_comparison() {
        let mut dialog = make_dialog("1001", "2002", "INVITE");
        dialog
            .timing
            .retransmit_counts
            .insert("1 INVITE".to_string(), 5);
        let filter = FilterExpr::parse("retransmits > 3").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── Not-equal operator ──────────────────────────────────────────

    #[test]
    fn not_equal_operator() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("method != 'BYE'").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── Integer numeric values ──────────────────────────────────────

    #[test]
    fn integer_numeric_value() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let filter = FilterExpr::parse("msg_count == 1").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── expand_alias: every alias maps to its documented expression ─────

    #[test]
    fn expand_alias_returns_exact_expansions() {
        assert!(expand_alias("problems").unwrap().contains("state == 'Failed'"));
        assert_eq!(expand_alias("slow-setup"), Some("pdd > 3.0"));
        assert_eq!(
            expand_alias("short-calls"),
            Some("duration < 5.0 AND state == 'Completed'")
        );
        assert_eq!(expand_alias("one-way"), Some("one_way == true"));
        assert_eq!(expand_alias("nat-issues"), Some("nat_mismatch == true"));
        assert_eq!(expand_alias("codec-asym"), Some("codec_asymmetry == true"));
        assert_eq!(expand_alias("ptime-asym"), Some("ptime_asymmetry == true"));
        assert_eq!(
            expand_alias("payload-asym"),
            Some("payload_asymmetry == true")
        );
        assert_eq!(
            expand_alias("duration-asym"),
            Some("duration_asymmetry == true")
        );
        assert_eq!(expand_alias("late-media"), Some("late_media == true"));
    }

    #[test]
    fn expand_alias_empty_and_case_sensitive_are_none() {
        // Alias matching is exact and case-sensitive.
        assert!(expand_alias("").is_none());
        assert!(expand_alias("Problems").is_none());
        assert!(expand_alias("PROBLEMS").is_none());
        assert!(expand_alias("slow_setup").is_none());
    }

    // ── check_nesting_depth: boundary behaviour ─────────────────────────

    #[test]
    fn nesting_depth_exactly_at_limit_ok() {
        // Exactly MAX_NESTING_DEPTH (50) open parens is allowed; 51 is not.
        let expr = format!(
            "{}from.user == '1001'{}",
            "(".repeat(50),
            ")".repeat(50)
        );
        // Nesting-depth check itself passes (no "nesting depth" error).
        assert!(check_nesting_depth(&expr).is_ok());

        let too_deep = format!(
            "{}from.user == '1001'{}",
            "(".repeat(51),
            ")".repeat(51)
        );
        let err = check_nesting_depth(&too_deep).unwrap_err().to_string();
        assert!(err.contains("nesting depth"), "got: {err}");
    }

    #[test]
    fn nesting_depth_unbalanced_close_parens_saturates() {
        // Leading ')' must not underflow; depth saturates at 0.
        assert!(check_nesting_depth(")))(((").is_ok());
    }

    // ── render_parse_error: direct unit coverage ────────────────────────

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

    #[test]
    fn render_parse_error_empty_offending_omits_token() {
        // pos at end-of-string => no offending token => no ": '...'" suffix.
        let expr = "from.user == 'x'";
        let out = render_parse_error(expr, expr.len(), "unexpected trailing input");
        let header = out.lines().next().unwrap();
        assert!(header.ends_with("position 16"), "got: {header}");
        assert!(!header.contains(": '"), "got: {header}");
    }

    #[test]
    fn render_parse_error_no_quote_hint_for_keyword_value() {
        // "true" after an operator is a valid boolean, so no quoting hint.
        let out = render_parse_error("one_way == true", 11, "x");
        assert!(!out.contains("must be quoted"), "got: {out}");
    }

    #[test]
    fn render_parse_error_pos_past_end_is_clamped() {
        // An out-of-range position must not panic; it is clamped to len.
        let expr = "method == 'X'";
        let out = render_parse_error(expr, 9999, "boom");
        assert!(out.contains("boom at position"));
    }

    // ── parse_value / parse_operator error arms via FilterExpr::parse ───

    #[test]
    fn parse_unterminated_string_errors() {
        // Missing closing quote hits the ErrorKind::Char failure arm.
        let result = FilterExpr::parse("from.user == 'unterminated");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_regex_errors() {
        // An unbalanced group fails RegexBuilder::build -> Verify failure arm.
        let result = FilterExpr::parse("from.user =~ '(unclosed'");
        assert!(result.is_err());
    }

    #[test]
    fn parse_non_numeric_value_for_number_errors() {
        // A bare unquoted word where a number/string is expected.
        let result = FilterExpr::parse("msg_count == abc");
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_operator_errors() {
        let result = FilterExpr::parse("from.user ?? '1001'");
        assert!(result.is_err());
    }

    #[test]
    fn parse_trailing_input_errors() {
        let result = FilterExpr::parse("from.user == '1001' garbage");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("trailing"), "got: {err}");
    }

    #[test]
    fn parse_false_boolean_literal() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        // one_way is false with no streams, so == false matches.
        let filter = FilterExpr::parse("one_way == false").expect("should parse");
        assert!(filter.matches_dialog(&dialog, &[]));
    }

    // ── compare_str: every operator + type mismatch ─────────────────────

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

    #[test]
    fn compare_str_type_mismatch_is_false() {
        // String field compared against a numeric/bool literal => false.
        assert!(!compare_str("b", &Operator::Eq, &Value::Num(1.0)));
        assert!(!compare_str("b", &Operator::Eq, &Value::Bool(true)));
        // Regex operator without a compiled regex value => false.
        assert!(!compare_str("b", &Operator::Regex, &Value::Str("b".into())));
    }

    // ── compare_num: every operator + type mismatch ─────────────────────

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

    #[test]
    fn compare_num_type_mismatch_is_false() {
        assert!(!compare_num(3.0, &Operator::Eq, &Value::Str("3".into())));
        assert!(!compare_num(3.0, &Operator::Lt, &Value::Bool(false)));
    }

    // ── compare_bool: operators + type mismatch ─────────────────────────

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

    #[test]
    fn compare_bool_type_mismatch_is_false() {
        assert!(!compare_bool(true, &Operator::Eq, &Value::Num(1.0)));
        assert!(!compare_bool(true, &Operator::Eq, &Value::Str("true".into())));
    }

    // ── state_to_str: all DialogState variants ──────────────────────────

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

    #[test]
    fn approximate_mos_clean_stream_is_high() {
        // No loss, no jitter => R near 93 => MOS in the ~4.4 range.
        let stream = make_rtp_stream(false);
        let mos = approximate_mos(&stream);
        assert!(mos > 4.0 && mos <= 4.5, "got {mos}");
    }

    #[test]
    fn approximate_mos_degrades_with_jitter_and_loss() {
        let mut stream = make_rtp_stream(false);
        stream.jitter = 80.0;
        stream.lost_packets = 50;
        // packet_count is 1 from construction; make loss heavy.
        let degraded = approximate_mos(&stream);
        let clean = approximate_mos(&make_rtp_stream(false));
        assert!(degraded < clean, "degraded {degraded} < clean {clean}");
        assert!(degraded >= 1.0, "MOS floor is 1.0, got {degraded}");
    }

    #[test]
    fn approximate_mos_worst_case_floored_at_one() {
        let mut stream = make_rtp_stream(false);
        stream.jitter = 100.0;
        stream.lost_packets = 1_000_000;
        let mos = approximate_mos(&stream);
        assert!((mos - 1.0).abs() < 1e-9, "expected floor 1.0, got {mos}");
    }

    #[test]
    fn approximate_mos_no_packets_no_loss() {
        // total == 0 path: loss_pct stays 0.0, no division by zero.
        let mut stream = make_rtp_stream(false);
        stream.packet_count = 0;
        stream.lost_packets = 0;
        let mos = approximate_mos(&stream);
        assert!(mos > 4.0, "got {mos}");
    }

    // ── eval_compare numeric field paths via matches_dialog ─────────────

    #[test]
    fn rtp_mos_loss_jitter_fields_evaluate() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let mut stream = make_rtp_stream(false);
        stream.jitter = 60.0;
        stream.lost_packets = 4; // with packet_count 1 => high loss%
        let streams: Vec<&RtpStream> = vec![&stream];

        // MOS should be degraded below 4.0.
        let mos_filter = FilterExpr::parse("rtp.mos < 4.0").expect("parse");
        assert!(mos_filter.matches_dialog(&dialog, &streams));

        // Jitter worst-case across streams is 60.0.
        let jitter_filter = FilterExpr::parse("rtp.jitter > 50.0").expect("parse");
        assert!(jitter_filter.matches_dialog(&dialog, &streams));

        // Loss percentage is high.
        let loss_filter = FilterExpr::parse("rtp.loss > 50.0").expect("parse");
        assert!(loss_filter.matches_dialog(&dialog, &streams));
    }

    #[test]
    fn rtp_codec_and_ssrc_string_fields() {
        let dialog = make_dialog("1001", "2002", "INVITE");
        let mut stream = make_rtp_stream(false);
        stream.codec = Some("PCMU".to_string());
        let streams: Vec<&RtpStream> = vec![&stream];

        let codec_filter = FilterExpr::parse("rtp.codec == 'PCMU'").expect("parse");
        assert!(codec_filter.matches_dialog(&dialog, &streams));

        // SSRC is rendered as 0x-prefixed 10-char hex of 0xDEADBEEF.
        let ssrc_filter = FilterExpr::parse("rtp.ssrc == '0xdeadbeef'").expect("parse");
        assert!(ssrc_filter.matches_dialog(&dialog, &streams));
    }
}
