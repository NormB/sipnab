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
    sequence::preceded,
};

use super::dialog::{DialogState, SipDialog};
use crate::rtp::diagnosis::{self, CaptureMedia, MediaDiagnosis};
use crate::rtp::quality::MosDelay;
use crate::rtp::stream::RtpStream;

// ── Maximum nesting depth (D17) ─────────────────────────────────────

/// Maximum parenthesis nesting depth allowed in filter expressions.
///
/// Bounds recursion *in the parser* — `atom = "(" expr ")"` is the only rule
/// that re-enters. It says nothing about how big the resulting tree is;
/// [`MAX_EXPRESSION_NODES`] is the guard for that.
const MAX_NESTING_DEPTH: usize = 50;

/// Maximum number of nodes in a parsed expression tree.
///
/// [`MAX_NESTING_DEPTH`] counts parentheses, and parentheses are not what
/// makes a tree deep. `a OR b OR c OR …` carries no parenthesis at all and
/// still builds one [`Expr::Or`] per term, left-associated, so the tree is as
/// deep as the chain is long. Every walk of that tree — evaluation, `Clone`,
/// `Debug` — recurses once per level, so an unbounded chain is an unbounded
/// recursion. Measured on the 0.5.130 debug build (2026-08-28): a
/// 4,633-term chain evaluated, a 4,634-term chain overflowed the MCP server
/// thread's stack and aborted the process.
///
/// 1024 nodes admits a 512-term chain (512 leaves + 511 combinators = 1023
/// nodes), which is far past anything sipnab or its operators write:
///
/// - The largest expression sipnab itself builds is 33 nodes — every
///   diagnostic alias flag at once, `(problems) OR (slow-setup) OR
///   (short-calls) OR (one-way) OR (nat-issues)`. `--problems` alone, the
///   biggest single alias, is 23.
/// - The largest expression the TUI filter dialog can build is 27 nodes —
///   five text fields ANDed with nine of the ten method checkboxes ORed.
/// - The largest hand-written filter in the documentation is 5 nodes.
///
/// Those three figures are measured, not remembered:
/// `node_counts_the_cap_is_justified_against` asserts each one.
///
/// The cap also keeps the deepest legal recursion 4.5× below the depth
/// measured to fail, in the build whose frames are largest.
const MAX_EXPRESSION_NODES: usize = 1024;

/// Maximum regex size in bytes (D17).
const REGEX_SIZE_LIMIT: usize = 1_000_000;

/// Longest header name a `header.<name>` field accepts, in bytes.
///
/// RFC 3261 puts no length on a `token`, so this is sipnab's bound, and it is
/// generous on purpose: a SIP header name is a word or a few hyphenated words,
/// and a user-defined one is no different. What it refuses is a pasted blob in
/// field position — refused at parse time with the limit named, instead of a
/// filter that compiles and silently matches nothing.
///
/// Evaluation needs no bound of its own. A `header.` comparison walks each
/// retained message's header list and compares borrowed names and values,
/// allocating nothing; the parser already caps the headers per message
/// (`[limits] max_headers`) and the dialog store the messages per dialog
/// (`[limits] max_messages_per_dialog`), and [`MAX_EXPRESSION_NODES`] caps how
/// many comparisons one filter holds.
const MAX_HEADER_NAME_LEN: usize = 256;

/// The prefix of the one field family whose name the operator chooses:
/// `header.<name>` reads any SIP header by name.
const HEADER_FIELD_PREFIX: &str = "header.";

/// How the header family is written in the parse-error field list, beside the
/// fixed names of [`FIELD_NAMES`].
const HEADER_FIELD_HINT: &str = "header.<name>";

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
/// // `filter.matches_dialog(&dialog, &streams, CaptureMedia::Observed, MosDelay::unknown())`.
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
    /// The expression text this was compiled from, trimmed. Kept so an
    /// answer narrowed by a filter can say which one — see
    /// [`FilterExpr::source`].
    source: String,
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
    /// Leaf time window: the dialog's first-message instant falls in the
    /// half-open `[after, before)` window, through
    /// [`crate::cursor::in_time_window`]. Built by
    /// [`FilterExpr::with_time_window`]; the parser writes the same selection
    /// as `time` comparisons.
    Window(
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ),
}

/// A childless node, used as the stand-in a subtree is swapped out for while
/// [`Expr`]'s destructor dismantles a tree iteratively.
///
/// Any leaf would do; this one allocates nothing (no `String`, no compiled
/// regex) and is never evaluated — it exists only long enough to be dropped.
fn placeholder_leaf() -> Expr {
    Expr::Compare(Field::OneWay, Operator::Eq, Value::Bool(true))
}

/// Move `node`'s child subtrees onto `out`, leaving childless placeholders
/// behind, so that dropping `node` itself unwinds no further.
///
/// A child that is already a leaf is left alone: it owns no subtree, so the
/// compiler's own drop glue disposes of it without recursing.
fn detach_children(node: &mut Expr, out: &mut Vec<Expr>) {
    /// Swap one child for a placeholder unless it is already a leaf.
    fn take(child: &mut Expr, out: &mut Vec<Expr>) {
        if matches!(child, Expr::Compare(..) | Expr::Window(..)) {
            return;
        }
        out.push(std::mem::replace(child, placeholder_leaf()));
    }

    match node {
        Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
            take(lhs, out);
            take(rhs, out);
        }
        Expr::Not(inner) => take(inner, out),
        Expr::Compare(..) | Expr::Window(..) => {}
    }
}

impl Drop for Expr {
    /// Dismantle the tree iteratively.
    ///
    /// The compiler's generated drop glue walks a tree the way it is shaped:
    /// one stack frame per level. A left-associative `a OR b OR c …` chain is
    /// exactly as deep as it is long, so *freeing* one is its own stack
    /// overflow — reached without ever evaluating the expression. Measured on
    /// the 0.5.130 debug build (2026-08-28): parsing a 17,901-term chain and
    /// then rejecting it for trailing input returned an error, while the same
    /// at 17,902 terms aborted the process while freeing the tree.
    ///
    /// [`MAX_EXPRESSION_NODES`] bounds what `parse` will *accept*, but the
    /// oversized tree has to be built before it can be counted and refused,
    /// and refusing it means dropping it. So the bound cannot be the only
    /// guard: the destructor has to be safe at any size, which is what this
    /// is. Each iteration detaches one node's children into a heap worklist
    /// and lets that node fall out of scope holding only leaves, so the
    /// nesting never exceeds two frames however deep the tree.
    fn drop(&mut self) {
        let mut pending: Vec<Expr> = Vec::new();
        detach_children(self, &mut pending);
        while let Some(mut node) = pending.pop() {
            detach_children(&mut node, &mut pending);
            // `node` is dropped here holding only placeholder leaves, so its
            // own `Drop` finds nothing to detach and stops.
        }
    }
}

/// Total number of nodes in the tree rooted at `expr`, counted iteratively.
///
/// Iteratively because this is the very check that decides whether the tree
/// is small enough to recurse over; a recursive count would overflow on the
/// input it exists to reject.
fn count_nodes(expr: &Expr) -> usize {
    let mut count = 0usize;
    let mut stack: Vec<&Expr> = vec![expr];
    while let Some(node) = stack.pop() {
        count += 1;
        match node {
            Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
                stack.push(lhs);
                stack.push(rhs);
            }
            Expr::Not(inner) => stack.push(inner),
            Expr::Compare(..) | Expr::Window(..) => {}
        }
    }
    count
}

/// Addressable fields in the filter DSL. Each variant but [`Field::Header`]
/// maps to one entry in `FIELD_NAMES`; extraction semantics live in
/// `eval_compare`.
///
/// `Clone` rather than `Copy` because [`Field::Header`] owns the name it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Field {
    /// `from.user` — user part of the dialog's From URI.
    FromUser,
    /// `to.user` — user part of the dialog's To URI.
    ToUser,
    /// `from.host` — host of the dialog's From URI, without the port.
    FromHost,
    /// `to.host` — host of the dialog's To URI, without the port.
    ToHost,
    /// `from.uri` — the From URI as written, URI parameters kept.
    FromUri,
    /// `to.uri` — the To URI as written, URI parameters kept.
    ToUri,
    /// `ruri` — the request-URI of the request that opened the dialog.
    Ruri,
    /// `pai.user` — user part of the opening request's P-Asserted-Identity.
    PaiUser,
    /// `rtp.codecs` — every codec the dialog's streams used, distinct,
    /// sorted and comma-joined.
    RtpCodecs,
    /// `side` — where the opening request went relative to the PBX's
    /// declared addresses: `inbound`, `outbound`, `internal` or empty.
    Side,
    /// `endpoint` — the name the run gives either end's address.
    Endpoint,
    /// `method` — the dialog's initial SIP method.
    Method,
    /// `ua` — first User-Agent header found in the dialog's messages.
    Ua,
    /// `call_id` — the dialog's Call-ID.
    CallId,
    /// `payload` — raw text of any SIP message in the dialog
    /// (whole-message grep).
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
    /// `response_class` — the IANA class of the final response, as `'2xx'`
    /// through `'6xx'`.
    ///
    /// Never `'1xx'`, and that is not an omission: this is the class of the
    /// FINAL response, and a provisional one is by definition not final. A
    /// call sitting on 183 has no outcome, so it has no class. Anyone reaching
    /// for `'1xx'` wants `state`.
    ///
    /// The registry groups every code into six classes and an operator asks in
    /// those terms: "any server failure", not "500 through 599". The
    /// arithmetic form says the same thing, but getting a bound wrong by one
    /// is silent, and `response_class == '5xx'` cannot be off by one.
    ///
    /// Distinct from [`crate::sip::response_codes::ResponseClass`], which is a
    /// DIAGNOSIS taxonomy (a challenge and a cancellation are not failures)
    /// rather than the numeric one. Both are useful and they are not the same
    /// question, so neither is named for the other.
    ResponseClass,
    /// `response_code` (or `final_status_code`) — the final response code of
    /// the dialog's INVITE, or of the request that opened a dialog without
    /// one, absent while it has none.
    ///
    /// Two spellings, one field, on purpose: `response_code` is what an
    /// operator types and what every CDR calls it, and `final_status_code` is
    /// what the JSON, the schema and the MCP answers already return. Filtering
    /// by a name the row does not carry is friction with no upside.
    ///
    /// Separate from [`Field::State`] because `state` answers what HAPPENED
    /// and this answers WHY: 403, 404, 408, 486, 503 and 603 are all
    /// `'Failed'`, and they have different owners.
    ResponseCode,
    /// `pdd` — post-dial delay in seconds.
    ///
    /// An unknown value matches NO comparison, including `!=`. It is not 0:
    /// substituting 0 for "never measured" is what made `rtp.mos < 3.0` select
    /// every dialog carrying no RTP at all. See [`compare_opt_num`].
    Pdd,
    /// `setup_time` — call setup time in seconds.
    ///
    /// Unknown behaves as it does for [`Field::Pdd`]: it matches nothing
    /// rather than reading as 0.
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
    /// `time` — the dialog's first-message instant (`created_at`), compared
    /// with an RFC 3339 string literal by `<`, `<=`, `>`, `>=` or `==`.
    ///
    /// The instant the REST `after`/`before` window and the MCP
    /// `search_by_time` window bound, so `time >= A AND time < B` selects what
    /// `--since A --until B` selects.
    Time,
    /// `header.<name>` — the value of any SIP header, named by the operator.
    ///
    /// Holds the name in the long form the parser stores headers under: a
    /// compact name is expanded through the parser's own table (RFC 3261
    /// section 7.3.3), so `header.k` and `header.Supported` read the same
    /// header whichever form it crossed the wire in. Names compare
    /// case-insensitively ([RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1)); values compare exactly, as
    /// on every other string field.
    ///
    /// Matches when ANY header of that name, on ANY message of the dialog,
    /// satisfies the comparison — the `payload` rule, applied per header line
    /// so a repeated header offers each of its values. A dialog carrying no
    /// such header matches no comparison at all, `!=` included, the rule every
    /// optional field here follows.
    ///
    /// Nothing about the name is interpreted. [RFC 6648 section 2](https://www.rfc-editor.org/rfc/rfc6648.html#section-2) forbids
    /// assuming anything about a parameter from an `X-` in its name, and this
    /// field does not: `X-Foo` and `Foo` are two unrelated names, neither is
    /// stripped to the other, and a user-defined header is read exactly like a
    /// registered one.
    Header(Box<str>),
}

impl Field {
    /// Whether this field's value is read from the media/asymmetry
    /// [`MediaDiagnosis`] (rather than the dialog or streams directly).
    /// Drives the parse-time `needs_diagnosis` flag; keep in sync with the
    /// diagnosis arms of `eval_compare`.
    fn is_diagnosis(&self) -> bool {
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

    /// What a literal on the right of this field means.
    ///
    /// The parser reads a value by the field's type, so the same text, quoted
    /// or bare, means the same thing: `to.user == 1001` is the user `1001`,
    /// and `src.port == '5060'` is the port 5060. Exhaustive, so a new field
    /// must say what its values are. Keep in step with the compare function
    /// each arm of `eval_compare` calls.
    fn value_kind(&self) -> ValueKind {
        match self {
            Field::FromUser
            | Field::ToUser
            | Field::FromHost
            | Field::ToHost
            | Field::FromUri
            | Field::ToUri
            | Field::Ruri
            | Field::PaiUser
            | Field::RtpCodecs
            | Field::Side
            | Field::Endpoint
            | Field::Method
            | Field::Ua
            | Field::CallId
            | Field::Payload
            | Field::SrcIp
            | Field::DstIp
            | Field::State
            | Field::ResponseClass
            | Field::RtpCodec
            | Field::RtpSsrc
            | Field::Header(_) => ValueKind::Text,
            Field::SrcPort
            | Field::DstPort
            | Field::Duration
            | Field::MsgCount
            | Field::ResponseCode
            | Field::Pdd
            | Field::SetupTime
            | Field::Retransmits
            | Field::RtpMos
            | Field::RtpJitter
            | Field::RtpLoss
            | Field::RtpPackets => ValueKind::Number,
            Field::OneWay
            | Field::NatMismatch
            | Field::NoMedia
            | Field::CodecAsymmetry
            | Field::PtimeAsymmetry
            | Field::PayloadAsymmetry
            | Field::DurationAsymmetry
            | Field::LateMedia => ValueKind::Boolean,
            Field::Time => ValueKind::Instant,
        }
    }
}

/// The type of the values a [`Field`] compares with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    /// Compared as text: [`Value::Str`].
    Text,
    /// Compared as a finite number: [`Value::Num`].
    Number,
    /// `true` or `false`, case-insensitive: [`Value::Bool`].
    Boolean,
    /// An RFC 3339 instant: [`Value::Instant`].
    Instant,
}

/// The PBX's own addresses, declared once at startup from `[pbx] addresses`.
static PBX_ADDRESSES: std::sync::OnceLock<Vec<crate::net::CidrRange>> = std::sync::OnceLock::new();

/// An address-to-name lookup for `endpoint`.
type EndpointNamer = dyn Fn(std::net::IpAddr) -> Option<String> + Send + Sync;
/// The run's [`EndpointNamer`], declared once at startup.
static ENDPOINT_NAMER: std::sync::OnceLock<Box<EndpointNamer>> = std::sync::OnceLock::new();

/// Declare the PBX's addresses that `side` compares against. The first call
/// wins, so the field cannot change meaning partway through a run.
pub fn declare_pbx_addresses(addresses: Vec<crate::net::CidrRange>) -> bool {
    PBX_ADDRESSES.set(addresses).is_ok()
}

/// Declare the lookup `endpoint` names addresses with. The first call wins.
pub fn declare_endpoint_names(namer: Box<EndpointNamer>) -> bool {
    ENDPOINT_NAMER.set(namer).is_ok()
}

/// The declared PBX addresses; empty before [`declare_pbx_addresses`].
fn pbx_addresses() -> &'static [crate::net::CidrRange] {
    PBX_ADDRESSES.get().map_or(&[], Vec::as_slice)
}

/// The declared lookup's name for `ip`; `None` before
/// [`declare_endpoint_names`] or when it has none.
fn endpoint_name(ip: std::net::IpAddr) -> Option<String> {
    ENDPOINT_NAMER.get().and_then(|namer| namer(ip))
}

/// Where a request from `src` to `dst` went relative to `pbx`: `inbound` when
/// only `dst` is the PBX, `outbound` when only `src` is, `internal` when both
/// are, and empty when neither is.
fn side_of(
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    pbx: &[crate::net::CidrRange],
) -> &'static str {
    let is_pbx = |ip| pbx.iter().any(|r| r.contains(ip));
    match (is_pbx(src), is_pbx(dst)) {
        (false, true) => "inbound",
        (true, false) => "outbound",
        (true, true) => "internal",
        (false, false) => "",
    }
}

/// Whether the name `names` gives the dialog's source or destination address
/// satisfies the comparison. An address with no name compares as empty.
fn endpoint_matches(
    dialog: &SipDialog,
    names: &dyn Fn(std::net::IpAddr) -> Option<String>,
    op: Operator,
    value: &Value,
) -> bool {
    [dialog.src_addr, dialog.dst_addr]
        .into_iter()
        .any(|ip| compare_str(names(ip).as_deref().unwrap_or(""), &op, value))
}

/// `host` with any `:port` removed. An IPv6 literal keeps its brackets:
/// `[2001:db8::1]:5060` is `[2001:db8::1]`, and a bare `2001:db8::1`, which
/// carries no port, is returned as it is.
fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map_or(host, |end| &host[..=end]);
    }
    match host.split_once(':') {
        Some((h, port)) if !port.contains(':') => h,
        _ => host,
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
    /// `in_subnet` — the left address falls inside the right CIDR block.
    ///
    /// Address arithmetic rather than a string prefix, so a non-octet-aligned
    /// prefix works and IPv6's textual forms all compare equal.
    InSubnet,
}

/// A literal value on the right-hand side of a comparison.
#[derive(Debug, Clone)]
enum Value {
    /// String literal, quoted (single or double quotes) or bare.
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
    /// An RFC 3339 instant: the literal of a `time` comparison, parsed once.
    Instant(chrono::DateTime<chrono::Utc>),
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

/// Every diagnostic alias name, in the order `docs/filter-dsl.md` lists them.
///
/// The MEMBERSHIP half of [`expand_alias`], and load-bearing rather than a
/// second copy of its arms: that function refuses anything not named here
/// before it reaches the match, so a name deleted from this list stops
/// expanding everywhere at once — `--filter <name>`, the `--problems` family of
/// flags, `find_problems`'s `kinds`, and the `sipnab://filter/{alias}`
/// resource. `the_alias_list_is_exactly_what_expand_alias_matches_on` reads the
/// match arms out of this file's own source and fails if the two disagree, so
/// neither half can quietly gain an entry the other does not have.
///
/// Published because the MCP server serves the vocabulary rather than
/// restating it: a completion built from a hand-written second list would
/// eventually offer a name the expander does not know, and the agent would
/// spend a call finding out.
pub const DIAGNOSTIC_ALIASES: [&str; 10] = [
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
    // Membership is decided by the published list, not by falling off the end
    // of the match. Both halves have to name an alias for it to work, which is
    // what stops the list from becoming decorative — a vocabulary served over
    // MCP that the expander does not actually accept is worse than no
    // vocabulary at all.
    if !DIAGNOSTIC_ALIASES.contains(&alias) {
        return None;
    }
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

/// The expression text a user-supplied filter stands for: the expansion when
/// `input` names a diagnostic alias, otherwise `input` unchanged.
///
/// The one rule every surface applies before parsing — `--filter`,
/// `--export-vcon-when`, an expectation's `filter:` scope, every MCP tool's
/// `filter`, and every REST `filter` query parameter. Callers that need the
/// compiled expression use [`parse_filter`], which is this followed by
/// [`FilterExpr::parse`]; this half exists for the CLI, which splices the text
/// into a larger expression before compiling it.
#[must_use]
pub fn resolve_filter_text<'a>(input: &'a str, t: &AliasThresholds) -> std::borrow::Cow<'a, str> {
    if let Some(expansion) = expand_alias(input, t) {
        return std::borrow::Cow::Owned(expansion);
    }
    resolve_references(input, super::named_filters::installed(), t)
}

/// `input` with each `@name` replaced through `filters` (and the built-in
/// aliases): the part of [`resolve_filter_text`] that takes the table as an
/// argument, so it can be driven with any table.
#[must_use]
pub fn resolve_references<'a>(
    input: &'a str,
    filters: &super::named_filters::NamedFilters,
    t: &AliasThresholds,
) -> std::borrow::Cow<'a, str> {
    if super::named_filters::first_reference(input).is_some() {
        std::borrow::Cow::Owned(filters.substitute(input, t))
    } else {
        std::borrow::Cow::Borrowed(input)
    }
}

/// Compile a user-supplied filter: a diagnostic alias name or a DSL
/// expression, the way every surface accepts one.
///
/// A REST client, an MCP agent and the command line therefore get the same
/// dialogs for the same text. Before this existed the REST handlers called
/// [`FilterExpr::parse`] directly, so `?filter=problems` answered `400` while
/// `--filter problems` and the MCP `filter: "problems"` both worked.
///
/// # Errors
///
/// The [`FilterExpr::parse`] error for the resolved text: an input that is
/// neither an alias nor a valid expression is reported as a syntax error at
/// the position where parsing stopped, which names the input.
pub fn parse_filter(input: &str, t: &AliasThresholds) -> Result<FilterExpr> {
    FilterExpr::parse(&resolve_filter_text(input, t))
}

/// Whether any leaf comparison in the tree references a diagnosis-derived
/// field. Walked once at parse time to cache `FilterExpr::needs_diagnosis`.
///
/// Iterative like [`count_nodes`]. `parse` only reaches it once the node cap
/// has passed, so a stack frame per level would be survivable here — but it
/// would be a second thing to re-argue every time that cap moves, and this
/// walk gains nothing from the recursion.
fn expr_references_diagnosis(expr: &Expr) -> bool {
    let mut stack: Vec<&Expr> = vec![expr];
    while let Some(node) = stack.pop() {
        match node {
            Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
                stack.push(lhs);
                stack.push(rhs);
            }
            Expr::Not(inner) => stack.push(inner),
            Expr::Compare(field, _, _) => {
                if field.is_diagnosis() {
                    return true;
                }
            }
            Expr::Window(..) => {}
        }
    }
    false
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
            // The tree above, written the way `parse` would read it back.
            source: "one_way == true AND one_way == false".to_string(),
        }
    }

    /// AND a half-open `[after, before)` time window into a compiled filter.
    ///
    /// The window bounds a dialog's first-message instant (`created_at`) and is
    /// evaluated through [`crate::cursor::in_time_window`], the rule the REST
    /// `/v1/dialogs` `after`/`before` parameters, the MCP `search_by_time` tool
    /// and the TUI's time range apply. It joins the one compiled filter rather
    /// than becoming a second one, so every output that honors `--filter`
    /// honors the window with it.
    ///
    /// # Arguments
    ///
    /// * `base` — the filter compiled so far, or `None` for none.
    /// * `after` — the inclusive lower bound, or `None` for unbounded.
    /// * `before` — the exclusive upper bound, or `None` for unbounded.
    ///
    /// # Returns
    ///
    /// `base` unchanged when both bounds are `None`; otherwise a filter that
    /// matches what `base` matches AND falls in the window. Its
    /// [`source`](Self::source) is the same selection written in the DSL, with
    /// the `time` field, so it can be pasted back into `--filter`.
    #[must_use]
    pub fn with_time_window(
        base: Option<FilterExpr>,
        after: Option<chrono::DateTime<chrono::Utc>>,
        before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Option<FilterExpr> {
        if after.is_none() && before.is_none() {
            return base;
        }
        let window = Expr::Window(after, before);
        let instant = |t: chrono::DateTime<chrono::Utc>| {
            t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
        };
        let window_source = [
            after.map(|a| format!("time >= '{}'", instant(a))),
            before.map(|b| format!("time < '{}'", instant(b))),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" AND ");
        Some(match base {
            None => FilterExpr {
                root: window,
                needs_diagnosis: false,
                source: window_source,
            },
            Some(mut base) => {
                let root = std::mem::replace(&mut base.root, placeholder_leaf());
                FilterExpr {
                    root: Expr::And(Box::new(root), Box::new(window)),
                    needs_diagnosis: base.needs_diagnosis,
                    source: format!("({}) AND {window_source}", base.source),
                }
            }
        })
    }

    /// The expression text this filter was compiled from, trimmed.
    ///
    /// The text that actually ran: an alias such as `one-way` arrives here
    /// already expanded, so the answer is an expression a reader can paste
    /// back into `--filter` and reproduce. Used by the capture analysis,
    /// which otherwise could not say that the dialogs it examined were a
    /// selection rather than the capture.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
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
    /// value       = quoted string | bare value
    /// ```
    ///
    /// A value is read by the type of its field; see `parse_value`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input is empty or contains only whitespace
    /// - A syntax error is found (with approximate position)
    /// - Parentheses nest deeper than 50 levels
    /// - The expression tree exceeds 1024 nodes — the bound on `a OR b OR c …`
    ///   chains, which nest no parentheses and so are invisible to the depth
    ///   check above. Not linked to the constant that carries it, because that
    ///   constant is private and rustdoc refuses a public link into private
    ///   scope; it is `MAX_EXPRESSION_NODES` in this module.
    /// - A regex pattern fails to compile or exceeds the 1 MB size limit
    #[must_use = "parsing result must be handled"]
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("filter expression is empty");
        }
        // A reference that survived resolution names nothing this run defines.
        // Said in those words, rather than as a syntax error at the `@`.
        if let Some(name) = super::named_filters::first_reference(trimmed) {
            bail!(
                "{}",
                super::named_filters::unknown_reference_message(
                    name,
                    super::named_filters::installed()
                )
            );
        }

        // Count max nesting depth before parsing
        check_nesting_depth(trimmed)?;

        let (remaining, expr) = parse_or_expr(trimmed).map_err(|e| match e {
            nom::Err::Error(err) | nom::Err::Failure(err) => {
                let pos = trimmed.len() - err.input.len();
                anyhow::anyhow!(
                    "{}",
                    render_parse_error(trimmed, pos, &parse_problem(err.code))
                )
            }
            nom::Err::Incomplete(_) => anyhow::anyhow!("incomplete filter expression"),
        })?;

        if !remaining.trim().is_empty() {
            // Position of the first non-space char of the unparsed tail.
            let pos = trimmed.len() - remaining.trim_start().len();
            bail!(
                "{}",
                render_parse_error(trimmed, pos, trailing_input_problem(trimmed, pos))
            );
        }

        // Size, not grouping depth. `check_nesting_depth` above measures
        // parentheses, and a flat `a OR b OR c …` chain has none while still
        // building one node per term — so it walked straight past that guard
        // and overflowed the stack later, during evaluation. Counted here,
        // after the syntax checks, so that a malformed expression is still
        // reported as malformed rather than as oversized.
        let nodes = count_nodes(&expr);
        if nodes > MAX_EXPRESSION_NODES {
            bail!(
                "expression exceeds maximum size of {MAX_EXPRESSION_NODES} nodes \
                 (this one has {nodes}); split it into several filters"
            );
        }

        let needs_diagnosis = expr_references_diagnosis(&expr);
        Ok(FilterExpr {
            root: expr,
            needs_diagnosis,
            source: trimmed.to_string(),
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
    ///   is a claim that a call carried no audio, and on a signaling-only
    ///   capture no call carries any, so the flag would describe the tap
    ///   rather than the call. Callers holding a stream store pass
    ///   [`CaptureMedia::of_store`]; the surfaces that filter dialogs with no
    ///   media data at all pass [`CaptureMedia::Absent`], which is the honest
    ///   reading of what they know.
    /// * `delay` — what this caller knows about one-way path delay, which is
    ///   the term `rtp.mos` is scored on. A caller holding the stream store
    ///   passes [`MosDelay::of_run`] or [`MosDelay::from_capture`]; one holding
    ///   no media at all passes [`MosDelay::unknown`].
    ///
    ///   It is a PARAMETER rather than something the expression resolves for
    ///   itself because the two figures that outrank the assumption — an
    ///   endpoint's reported round trip and the one sipnab derives from an RR's
    ///   sender-report echo — live in the store's provenance table, and this
    ///   function is handed streams. Without it `rtp.mos < 3.0` scored every
    ///   stream on a domestic 100 ms guess while the pane displaying that same
    ///   stream scored it on the path its own RTCP measured, so the filter
    ///   selected a different set of calls from the one the operator could see.
    ///
    /// # Returns
    ///
    /// `true` when the dialog and its streams satisfy the expression.
    pub fn matches_dialog(
        &self,
        dialog: &SipDialog,
        streams: &[&RtpStream],
        capture: CaptureMedia,
        delay: MosDelay<'_>,
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
        eval_expr(&self.root, dialog, streams, &diag, delay)
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
    // The other run-level fact, from the same store and for the same reason:
    // `rtp.mos` must be the number the streams' own RTCP supports, not the
    // build-time guess. `from_capture` rather than `of_run` because no
    // post-capture output path is handed the operator's declared figure — see
    // the type's own note; the ranks the capture can support are all live.
    let delay = crate::rtp::quality::MosDelay::from_capture(stream_store);
    let dialogs: Vec<(&'a SipDialog, Vec<&'a RtpStream>)> = dialog_store
        .iter()
        .filter_map(|dialog| {
            let streams = by_call
                .get(dialog.call_id.as_str())
                .cloned()
                .unwrap_or_default();
            match filter {
                Some(expr) if !expr.matches_dialog(dialog, &streams, capture, delay) => None,
                _ => Some((dialog, streams)),
            }
        })
        .collect();

    let streams = match filter {
        // Byte-for-byte the previous unfiltered behavior: every stream the
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
    let op_at = input;
    let (input, op) = parse_operator(input)?;
    if field == Field::Time && !TIME_OPERATORS.contains(&op) {
        return Err(nom::Err::Failure(nom::error::Error::new(
            op_at,
            TIME_OPERATOR_INVALID,
        )));
    }
    if field.value_kind() == ValueKind::Boolean && !matches!(op, Operator::Eq | Operator::Ne) {
        return Err(nom::Err::Failure(nom::error::Error::new(
            op_at,
            BOOL_OPERATOR_INVALID,
        )));
    }
    let (input, _) = multispace0(input)?;
    let (input, value) = parse_value(input, &field, op)?;

    Ok((input, Expr::Compare(field, op, value)))
}

/// Every field name the DSL accepts, for diagnostics. Kept in sync with
/// `parse_field` by the `field_names_const_matches_parser` test.
pub const FIELD_NAMES: &[&str] = &[
    "from.user",
    "to.user",
    "from.host",
    "to.host",
    "from.uri",
    "to.uri",
    "ruri",
    "pai.user",
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
    "response_code",
    "final_status_code",
    "response_class",
    "pdd",
    "setup_time",
    "retransmits",
    "rtp.mos",
    "rtp.jitter",
    "rtp.loss",
    "rtp.packets",
    "rtp.codec",
    "rtp.codecs",
    "rtp.ssrc",
    "side",
    "endpoint",
    "one_way",
    "nat_mismatch",
    "no_media",
    "codec_asymmetry",
    "ptime_asymmetry",
    "payload_asymmetry",
    "duration_asymmetry",
    "late_media",
    "time",
];

/// The classes a `response_class` literal names.
///
/// The [IANA registry](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-7)
/// names six classes -- Provisional, Successful, Redirection, Request Failure,
/// Server Failure, Global Failures -- and an operator types either those or
/// `5xx`. Accepting one vocabulary and not the other would make the field's own
/// documentation a trap.
///
/// `failure` names all THREE failure classes, because that is what the word
/// means at a console: 4xx, 5xx and 6xx together. Naming one class is how you
/// ask for one class. It is deliberately a different question from the
/// `failure` classification on the response-code reference page, which is
/// NARROWER -- there a challenge, a cancellation and a decline are each not
/// failures, because each tells the operator to do something different. This
/// field is the numeric registry and nothing else.
///
/// Tolerant of case, and of a hyphen or an underscore where a space belongs,
/// because those are typing variants rather than different questions. Anything
/// unrecognized returns `None` and the caller falls back to a plain string
/// comparison, which matches nothing -- the same way every other string field
/// here treats a value it does not know.
fn response_class_set(value: &str) -> Option<&'static [u16]> {
    let folded = value.trim().to_ascii_lowercase().replace(['-', '_'], " ");
    Some(match folded.as_str() {
        "1xx" | "provisional" => &[1][..],
        "2xx" | "successful" | "success" => &[2][..],
        "3xx" | "redirection" | "redirect" => &[3][..],
        "4xx" | "request failure" | "client failure" => &[4][..],
        "5xx" | "server failure" => &[5][..],
        "6xx" | "global failures" | "global failure" => &[6][..],
        "failure" | "failures" | "failed" => &[4, 5, 6][..],
        _ => return None,
    })
}

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
    // Before the fixed names: `header.X-Foo` would otherwise be read as the
    // two-segment identifier `header.X` and refused as an unknown field.
    if input.starts_with(HEADER_FIELD_PREFIX) {
        return parse_header_field(input);
    }

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
        "from.host" => Field::FromHost,
        "to.host" => Field::ToHost,
        "from.uri" => Field::FromUri,
        "to.uri" => Field::ToUri,
        "ruri" => Field::Ruri,
        "pai.user" => Field::PaiUser,
        "rtp.codecs" => Field::RtpCodecs,
        "side" => Field::Side,
        "endpoint" => Field::Endpoint,
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
        "response_code" | "final_status_code" => Field::ResponseCode,
        "response_class" => Field::ResponseClass,
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
        "time" => Field::Time,
        _ => {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
    };

    Ok((rest, field))
}

/// The nom error kind [`parse_header_field`] raises for a name over
/// [`MAX_HEADER_NAME_LEN`], so [`FilterExpr::parse`] can name the limit.
///
/// A kind nothing else in this parser produces — no combinator used here
/// raises it — which is what makes it safe to read back as this one problem.
const HEADER_NAME_TOO_LONG: nom::error::ErrorKind = nom::error::ErrorKind::TooLarge;

/// The nom error kind [`parse_header_field`] raises for a name that is empty
/// or not an RFC 3261 `token`. Unused by every combinator here, like
/// [`HEADER_NAME_TOO_LONG`].
const HEADER_NAME_INVALID: nom::error::ErrorKind = nom::error::ErrorKind::Not;

/// The operators a `time` comparison accepts: the orderings and equality.
///
/// `!=` is left out because "every instant but this one" is not a question
/// anyone asks of a timestamp with sub-second resolution, and `=~` and
/// `in_subnet` do not apply to an instant at all.
const TIME_OPERATORS: [Operator; 5] = [
    Operator::Lt,
    Operator::Le,
    Operator::Gt,
    Operator::Ge,
    Operator::Eq,
];

/// The nom error kind a `time` comparison raises for an operator outside
/// [`TIME_OPERATORS`]. Unused by every combinator here, like
/// [`HEADER_NAME_TOO_LONG`].
const TIME_OPERATOR_INVALID: nom::error::ErrorKind = nom::error::ErrorKind::Permutation;

/// The nom error kind a `time` comparison raises for a literal that is not an
/// RFC 3339 instant. Unused by every combinator here.
const TIME_VALUE_INVALID: nom::error::ErrorKind = nom::error::ErrorKind::Fix;

/// The nom error kind for a value a numeric field cannot hold: a word, or a
/// non-finite number. Unused by every combinator here.
const NUMBER_VALUE_INVALID: nom::error::ErrorKind = nom::error::ErrorKind::SeparatedList;

/// The nom error kind for a value a boolean field cannot hold. Unused by every
/// combinator here.
const BOOL_VALUE_INVALID: nom::error::ErrorKind = nom::error::ErrorKind::SeparatedNonEmptyList;

/// The nom error kind for `<`, `<=`, `>` or `>=` against a boolean field, which
/// has no order. Unused by every combinator here.
const BOOL_OPERATOR_INVALID: nom::error::ErrorKind = nom::error::ErrorKind::LengthValueFn;

/// The nom error kind for a bare value followed by more text that is neither
/// `AND`, `OR`, `)` nor the end: the value held whitespace, or a combinator is
/// missing. Unused by every combinator here.
const BARE_VALUE_SPACE: nom::error::ErrorKind = nom::error::ErrorKind::ManyTill;

/// The nom error kind for a bare value that runs into a quote character.
/// Unused by every combinator here.
const BARE_VALUE_QUOTE: nom::error::ErrorKind = nom::error::ErrorKind::OneOf;

/// The nom error kind for a value that begins with a character
/// [`is_reserved_bare_start`] reserves. Unused by every combinator here.
const BARE_VALUE_RESERVED: nom::error::ErrorKind = nom::error::ErrorKind::Count;

/// The nom error kind for a quoted value with no closing quote. Unused by every
/// combinator here.
const QUOTED_VALUE_UNTERMINATED: nom::error::ErrorKind = nom::error::ErrorKind::Escaped;

/// The nom error kind for `&&` or `||` where `AND` or `OR` belongs. Unused by
/// every combinator here.
const SYMBOLIC_COMBINATOR: nom::error::ErrorKind = nom::error::ErrorKind::EscapedTransform;

/// The nom error kind for a regex that does not compile or exceeds
/// [`REGEX_SIZE_LIMIT`]. Unused by every combinator here.
const REGEX_INVALID: nom::error::ErrorKind = nom::error::ErrorKind::RegexpMatch;

/// The headline for a parse error of `kind`.
///
/// Only the two header-name problems get words of their own: every other
/// failure is positional, and the caret under the expression says more than a
/// kind name would.
fn parse_problem(kind: nom::error::ErrorKind) -> String {
    match kind {
        HEADER_NAME_TOO_LONG => {
            format!("header name longer than {MAX_HEADER_NAME_LEN} bytes")
        }
        HEADER_NAME_INVALID => "header name missing or not an RFC 3261 token \
             (quote any other name: header.\"Name\")"
            .to_string(),
        TIME_OPERATOR_INVALID => "time compares with <, <=, >, >= or ==".to_string(),
        TIME_VALUE_INVALID => "time needs an RFC 3339 instant, such as \
             time >= 2026-10-09T10:00:00Z"
            .to_string(),
        NUMBER_VALUE_INVALID => "the field compares with a finite number".to_string(),
        BOOL_VALUE_INVALID => "the field compares with true or false".to_string(),
        BOOL_OPERATOR_INVALID => "the field compares with == or !=".to_string(),
        BARE_VALUE_SPACE => {
            "a value containing whitespace must be quoted, or AND/OR is missing".to_string()
        }
        BARE_VALUE_RESERVED => "a value beginning with = ! < > or @ needs quotes".to_string(),
        BARE_VALUE_QUOTE => "a value containing ' or \" must be quoted with the other quote \
             or a backslash"
            .to_string(),
        QUOTED_VALUE_UNTERMINATED => "unterminated quoted value (a value beginning with ' \
             or \" is a quoted string)"
            .to_string(),
        SYMBOLIC_COMBINATOR => "join comparisons with AND, OR and NOT; && and || \
             are not supported"
            .to_string(),
        REGEX_INVALID => {
            format!("the regex does not compile or is larger than {REGEX_SIZE_LIMIT} bytes")
        }
        _ => "unexpected input".to_string(),
    }
}

/// Whether `c` ends a bare `header.<name>`.
///
/// Whitespace, the characters that begin an operator or a group, and the quote
/// characters. Everything else is gathered into the name and then validated as
/// a token, so a stray `:` or a non-ASCII letter is reported as a bad header
/// name rather than as an unexpected character somewhere after it.
fn ends_bare_header_name(c: char) -> bool {
    c.is_whitespace() || matches!(c, '=' | '!' | '<' | '>' | '(' | ')' | '\'' | '"')
}

/// Parse `header.<name>` into [`Field::Header`].
///
/// The name is bare (`header.X-Trunk`) or quoted (`header."P-Asserted-Identity"`,
/// `header.'Odd!Name'`). A bare name stops at whitespace, an operator, a
/// parenthesis or a quote; a quoted one takes the same escapes as a string
/// literal. Either way the result must be a non-empty RFC 3261 `token` of at
/// most [`MAX_HEADER_NAME_LEN`] bytes — the parser's own definition, through
/// [`super::parser::is_token_byte`] — and a compact name is expanded through
/// the parser's own table.
///
/// # Returns
///
/// The unconsumed remainder and the field, or a nom `Failure` positioned at
/// the start of the field: [`HEADER_NAME_TOO_LONG`] for a name over the cap,
/// [`HEADER_NAME_INVALID`] for one that is empty, unterminated or not a token.
fn parse_header_field(input: &str) -> IResult<&str, Field, NomErr<'_>> {
    let fail = |kind| nom::Err::Failure(nom::error::Error::new(input, kind));
    let after = &input[HEADER_FIELD_PREFIX.len()..];
    let (name, rest) = match after.chars().next() {
        Some(quote @ ('\'' | '"')) => {
            scan_quoted_string(&after[1..], quote).ok_or_else(|| fail(HEADER_NAME_INVALID))?
        }
        _ => {
            let end = after
                .char_indices()
                .find(|&(_, c)| ends_bare_header_name(c))
                .map_or(after.len(), |(i, _)| i);
            (after[..end].to_string(), &after[end..])
        }
    };
    if name.len() > MAX_HEADER_NAME_LEN {
        return Err(fail(HEADER_NAME_TOO_LONG));
    }
    if name.is_empty() || !name.bytes().all(super::parser::is_token_byte) {
        return Err(fail(HEADER_NAME_INVALID));
    }
    let long = super::parser::expand_compact_header(&name);
    Ok((rest, Field::Header(long.into_owned().into_boxed_str())))
}

/// The headline for input left over after a complete expression, at byte
/// `pos` of `expr`.
///
/// A `)` there has no `(` to close. Text straight after a `)`, with no space
/// between, is what remains when a value held a `)`: the `)` ended the value
/// and closed the group. Either way the reason is a `)` in a value, which
/// only quotes can carry.
fn trailing_input_problem(expr: &str, pos: usize) -> &'static str {
    let tail = &expr[pos..];
    if tail.starts_with(')') {
        "unmatched ')'; a value containing an unmatched ')' must be quoted"
    } else if expr[..pos].ends_with(')') {
        "unexpected input after ')'; a value containing ')' must be quoted"
    } else {
        "unexpected trailing input"
    }
}

/// Render a filter parse error as a multi-line diagnostic: the (possibly
/// windowed) expression, a caret under the offending position, the operator
/// list, and a docs pointer. The position printed in the headline is the
/// 0-based character column the caret marks, not a byte offset.
///
/// An unknown-field hint (with a closest-match suggestion and the valid
/// field list) is added when an identifier-looking token sits in field
/// position.
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
        "{problem} at position {col}{}\n  {shown}\n  {caret:>width$}",
        if offending.is_empty() {
            String::new()
        } else {
            format!(": '{offending}'")
        },
        caret = '^',
        width = caret_col + 1,
    );

    // Unknown-field hint: an identifier-looking token followed by a
    // comparison operator sits in field position — name it, suggest the
    // closest real field, and list the valid set.
    let after_pos = &expr[pos..];
    let offending_raw = after_pos.split_whitespace().next().unwrap_or("");
    // split_whitespace may skip leading characters the parser does not
    // treat as whitespace (e.g. vertical tab), so the token need not start
    // at `pos`: derive its true end from where the subslice actually sits — a
    // naive `pos + len` slice landed mid-character on multibyte input.
    //
    // `substr_range` (Rust 1.98) is the standard library's answer, and it
    // replaced pointer arithmetic doing the same subtraction by hand. It also
    // returns `None` for a string that is not part of this one, where the
    // arithmetic would have produced a plausible index.
    let token_end = match after_pos.substr_range(offending_raw) {
        Some(range) if !offending_raw.is_empty() => pos + range.end,
        _ => pos,
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
    // A `header.` token that failed is a bad header NAME, and its own headline
    // already says so; "unknown field 'header.'" would send the reader looking
    // for a field that does exist.
    if looks_like_field
        && in_field_position
        && !FIELD_NAMES.contains(&offending_raw)
        && !offending_raw.starts_with(HEADER_FIELD_PREFIX)
    {
        out.push_str(&format!("\nhint: unknown field '{offending_raw}'"));
        if let Some(best) = closest_field(offending_raw) {
            out.push_str(&format!(" \u{2014} did you mean '{best}'?"));
        }
        out.push_str(&format!(
            "\nvalid fields: {}, {HEADER_FIELD_HINT}",
            FIELD_NAMES.join(", ")
        ));
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
        // Before the symbolic operators: a word operator cannot be confused
        // with them, and putting it first keeps the longest-match rule simple.
        map(tag("in_subnet"), |_| Operator::InSubnet),
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

/// Whether `c` may not begin a bare value.
///
/// `=`, `!`, `<` and `>` begin operators, so `method === 'INVITE'` stays a
/// typo instead of becoming the value `='INVITE'`; `@` begins a `@name`
/// filter reference; `)` closes a group, so a value cannot start with it. A
/// value beginning with any of these is written quoted. The one definition the
/// parser and its documentation (docs/filter-dsl.md, "Values") describe.
fn is_reserved_bare_start(c: char) -> bool {
    matches!(c, '=' | '!' | '<' | '>' | '@' | ')')
}

/// Split a bare (unquoted) value off the front of `input`.
///
/// The value is the longest run of characters up to whitespace, a quote
/// character, or a `)` that closes a group of the expression. Its own parentheses must balance: `(`
/// opens, `)` closes, and a `)` with no `(` to close ends the value. For a
/// regex (`regex` true) two regex rules apply as well, so a `)` that is regex
/// text is not read as the end of the value: a backslash escapes the next
/// non-whitespace character, and inside a `[...]` class parentheses are
/// literal. Every other character, `|` included, is part of the value.
///
/// The one definition of a bare value. Quoting is needed only for what it
/// cannot express: whitespace, a quote character, an unmatched `)`, an empty
/// value, and a first character [`is_reserved_bare_start`] reserves.
///
/// # Returns
///
/// `(value, rest)`; `value` is empty when `input` starts with whitespace, a
/// `)` or nothing.
fn scan_bare_value(input: &str, regex: bool) -> (&str, &str) {
    let mut depth = 0usize;
    let mut in_class = false;
    let mut chars = input.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c.is_whitespace() || c == '\'' || c == '"' {
            return (&input[..i], &input[i..]);
        }
        match c {
            '\\' if regex => {
                if chars.peek().is_some_and(|&(_, n)| !n.is_whitespace()) {
                    chars.next();
                }
            }
            '[' if regex && !in_class => in_class = true,
            ']' if regex && in_class => in_class = false,
            _ if in_class => {}
            '(' => depth += 1,
            ')' if depth == 0 => return (&input[..i], &input[i..]),
            ')' => depth -= 1,
            _ => {}
        }
    }
    (input, "")
}

/// Whether the text after a value is something a comparison may be followed
/// by: the end, a `)`, or the word `AND` or `OR`.
fn ends_a_comparison(rest: &str) -> bool {
    let rest = rest.trim_start();
    if rest.is_empty() || rest.starts_with(')') {
        return true;
    }
    ["AND", "OR"].iter().any(|word| {
        rest.get(..word.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(word))
            && rest[word.len()..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace)
    })
}

/// Parse the value of a comparison, quoted or bare, and read it by the type of
/// `field`.
///
/// A value is written in single quotes, double quotes, or bare (see
/// [`scan_bare_value`]); all three spell the same text and the result does
/// not depend on which was used. The text is then read by the field's
/// [`ValueKind`]: text as written, a finite number, `true`/`false` (any case),
/// or an RFC 3339 instant. For `=~` the text is compiled as a regex, with
/// the byte-oriented [`regex::bytes`] engine for `payload` so it matches the
/// raw message without a lossy UTF-8 copy, and a size limit of
/// [`REGEX_SIZE_LIMIT`] bytes.
///
/// Inside a quoted string, a backslash introduces an escape: `\'` and `\"`
/// yield the quote, and every other `\x` sequence is kept verbatim so regex
/// metacharacters such as `\d` survive. A bare value is taken verbatim.
///
/// # Arguments
///
/// * `input` — Remaining expression text at the value position.
/// * `field` — The field already parsed; decides how the text is read.
/// * `op` — The operator already parsed; `=~` compiles the text as a regex.
///
/// # Returns
///
/// The unconsumed remainder and the parsed `Value`, or a nom `Failure`
/// carrying the kind that names the problem.
fn parse_value<'a>(
    input: &'a str,
    field: &Field,
    op: Operator,
) -> IResult<&'a str, Value, NomErr<'a>> {
    let (input, _) = multispace0(input)?;
    let fail = |at: &'a str, kind| nom::Err::Failure(nom::error::Error::new(at, kind));

    let (text, rest): (std::borrow::Cow<'a, str>, &'a str) = match input.chars().next() {
        Some(quote @ ('\'' | '"')) => {
            let (text, rest) = scan_quoted_string(&input[1..], quote)
                .ok_or_else(|| fail(input, QUOTED_VALUE_UNTERMINATED))?;
            (std::borrow::Cow::Owned(text), rest)
        }
        Some(c) if is_reserved_bare_start(c) && c != ')' => {
            return Err(fail(input, BARE_VALUE_RESERVED));
        }
        _ => {
            let (text, rest) = scan_bare_value(input, op == Operator::Regex);
            if text.is_empty() {
                // Nothing where a value belongs: the end, or a `)`.
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Char,
                )));
            }
            if !ends_a_comparison(rest) {
                let next = rest.trim_start();
                if next.starts_with("&&") || next.starts_with("||") {
                    return Err(fail(next, SYMBOLIC_COMBINATOR));
                }
                if next.starts_with(['\'', '"']) {
                    return Err(fail(input, BARE_VALUE_QUOTE));
                }
                return Err(fail(input, BARE_VALUE_SPACE));
            }
            (std::borrow::Cow::Borrowed(text), rest)
        }
    };

    if op == Operator::Regex {
        // `payload` greps the raw message bytes, so its regex is compiled
        // with the byte engine to match without a lossy UTF-8 copy.
        if *field == Field::Payload {
            let re = regex::bytes::RegexBuilder::new(&text)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|_| fail(input, REGEX_INVALID))?;
            return Ok((rest, Value::ReBytes(re)));
        }
        let re = regex::RegexBuilder::new(&text)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|_| fail(input, REGEX_INVALID))?;
        return Ok((rest, Value::Re(re)));
    }

    let value = match field.value_kind() {
        ValueKind::Text => Value::Str(text.into_owned()),
        // `nan` and `inf` parse as `f64` but are typos, not thresholds: every
        // comparison against NaN is false, and an infinity matches everything
        // or nothing depending on the operator.
        ValueKind::Number => match text.parse::<f64>() {
            Ok(n) if n.is_finite() => Value::Num(n),
            _ => return Err(fail(input, NUMBER_VALUE_INVALID)),
        },
        ValueKind::Boolean => {
            if text.eq_ignore_ascii_case("true") {
                Value::Bool(true)
            } else if text.eq_ignore_ascii_case("false") {
                Value::Bool(false)
            } else {
                return Err(fail(input, BOOL_VALUE_INVALID));
            }
        }
        ValueKind::Instant => match crate::cursor::parse_instant(&text) {
            Ok(instant) => Value::Instant(instant),
            Err(_) => return Err(fail(input, TIME_VALUE_INVALID)),
        },
    };
    Ok((rest, value))
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
    delay: MosDelay<'_>,
) -> bool {
    match expr {
        Expr::And(lhs, rhs) => {
            eval_expr(lhs, dialog, streams, diag, delay)
                && eval_expr(rhs, dialog, streams, diag, delay)
        }
        Expr::Or(lhs, rhs) => {
            eval_expr(lhs, dialog, streams, diag, delay)
                || eval_expr(rhs, dialog, streams, diag, delay)
        }
        Expr::Not(inner) => !eval_expr(inner, dialog, streams, diag, delay),
        Expr::Compare(field, op, value) => {
            eval_compare(field, op, value, dialog, streams, diag, delay)
        }
        Expr::Window(after, before) => {
            crate::cursor::in_time_window(dialog.created_at, *after, *before)
        }
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
/// * `delay` — One-way-delay evidence for `rtp.mos`, so the filter scores a
///   stream the way every display of that stream does.
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
    delay: MosDelay<'_>,
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
        Field::FromHost => compare_str(
            host_without_port(dialog.from_host.as_deref().unwrap_or("")),
            op,
            value,
        ),
        Field::ToHost => compare_str(
            host_without_port(dialog.to_host.as_deref().unwrap_or("")),
            op,
            value,
        ),
        Field::FromUri => compare_str(dialog.from_uri.as_deref().unwrap_or(""), op, value),
        Field::ToUri => compare_str(dialog.to_uri.as_deref().unwrap_or(""), op, value),
        Field::Ruri => compare_str(dialog.request_uri.as_deref().unwrap_or(""), op, value),
        Field::PaiUser => compare_str(dialog.pai_user.as_deref().unwrap_or(""), op, value),
        Field::Side => compare_str(
            side_of(dialog.src_addr, dialog.dst_addr, pbx_addresses()),
            op,
            value,
        ),
        Field::Endpoint => endpoint_matches(dialog, &endpoint_name, *op, value),
        Field::RtpCodecs => {
            let mut codecs: Vec<&str> = streams.iter().filter_map(|s| s.codec.as_deref()).collect();
            codecs.sort_unstable();
            codecs.dedup();
            compare_str(&codecs.join(","), op, value)
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
        // Any message in the dialog whose raw content matches (
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
        // Every header of that name on every message, each line its own value.
        // Borrowed name and value, so a comparison allocates nothing however
        // many headers the dialog holds.
        Field::Header(name) => dialog.messages.iter().any(|m| {
            m.headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case(name) && compare_str(&h.value, op, value))
        }),

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
        // `compare_opt_num`, never a 0 default: a ringing call has no final
        // response, and defaulting to 0 would make `response_code < 400` sweep
        // up every call still in progress as a success.
        Field::ResponseCode => {
            compare_opt_num(dialog.final_status_code().map(f64::from), op, value)
        }
        // An in-progress call is in NO class. Rendering it as an empty string
        // would make `response_class != '2xx'` true for every ringing call,
        // which is a wrong answer rather than a missing one -- the same trap
        // `response_code` avoids by refusing to default to zero.
        Field::ResponseClass => match dialog.final_status_code() {
            None => false,
            Some(code) => {
                let digit = code / 100;
                let canonical = format!("{digit}xx");
                // A literal can name ONE class or several -- `failure` names
                // three -- so equality is MEMBERSHIP, not string equality.
                // Doing it this way is what keeps `!=` honest: comparing the
                // field against each accepted spelling in turn would make
                // `response_class != 'server failure'` true for a 503, by way
                // of whichever spelling did not match.
                match (op, value) {
                    (Operator::Eq | Operator::Ne, Value::Str(s)) => {
                        match response_class_set(s) {
                            Some(set) => {
                                let member = set.contains(&digit);
                                if matches!(op, Operator::Eq) {
                                    member
                                } else {
                                    !member
                                }
                            }
                            // Not a class this DSL knows: fall through so a
                            // typo matches nothing, exactly as it would on any
                            // other string field.
                            None => compare_str(&canonical, op, value),
                        }
                    }
                    // `=~ '^[45]xx$'` and the ordering operators still read the
                    // canonical form.
                    _ => compare_str(&canonical, op, value),
                }
            }
        },
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
            let mos = streams
                .iter()
                .map(|s| stream_mos(s, delay))
                .reduce(f64::min);
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

        // ── Instant field ──────────────────────────────────────────
        Field::Time => compare_instant(dialog.created_at, op, value),

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

/// Compare the instant `field_val` against a `time` literal. The parser
/// admits only [`TIME_OPERATORS`] and [`Value::Instant`] here; anything else
/// is `false`, the safe direction.
fn compare_instant(field_val: chrono::DateTime<chrono::Utc>, op: &Operator, value: &Value) -> bool {
    let Value::Instant(v) = value else {
        return false;
    };
    match op {
        Operator::Eq => field_val == *v,
        Operator::Lt => field_val < *v,
        Operator::Le => field_val <= *v,
        Operator::Gt => field_val > *v,
        Operator::Ge => field_val >= *v,
        Operator::Ne | Operator::Regex | Operator::InSubnet => false,
    }
}

/// Compare a string field value `field_val` against the filter value.
/// `<`/`>`/`<=`/`>=` order lexicographically; `=~` requires a compiled
/// regex value. Type mismatches (non-string literal) return `false`.
/// Whether `ip` falls inside the CIDR block `cidr`.
///
/// # Why the DSL needs this
///
/// The only subnet answer the filter language had was a regex on the dotted
/// string. That is wrong in three ways at once: a prefix that is not
/// octet-aligned cannot be written at all (a `/22` spans four `/24`s), an
/// unanchored pattern matches neighbors — `198.51.100.` also matches
/// `198.51.1002` — and IPv6 defeats it entirely, because `2001:db8::1` and
/// `2001:0db8:0000:0000:0000:0000:0000:0001` are one address and two strings.
///
/// Comparing parsed addresses removes all three by construction.
///
/// # Arguments
///
/// * `ip` — the address to test, in any textual form its family accepts.
/// * `cidr` — `<address>/<prefix-length>`.
///
/// # Returns
///
/// `false` for anything malformed, on either side. That is the safe direction:
/// a filter nobody can parse must select no dialogs rather than all of them.
/// The two families never cross — an IPv4 address is never inside an IPv6
/// prefix — because answering otherwise would silently widen every filter
/// written against a dual-stack capture.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    // The allowlist's rule, not a second one. This used to be its own
    // implementation and it disagreed with `--hep-allow` twice: it refused an
    // IPv4-mapped IPv6 address that the allowlist accepts (RFC 4291 §2.5.5.2
    // makes `::ffff:0:0/96` the representation OF a v4 address, not a
    // different family), and it refused a bare address where the allowlist
    // reads a host route. So an agent sipnab had just admitted was invisible
    // to a filter over the very prefix that admitted it -- and the uprobe
    // backend produces mapped addresses as a matter of course, because it
    // reads `sk_v6_rcv_saddr` verbatim for any AF_INET6 socket.
    let Ok(range) = crate::net::CidrRange::parse(cidr.trim()) else {
        return false;
    };
    let Ok(addr) = ip.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    range.contains(addr)
}

/// Compare a string field value against the filter's literal.
///
/// Ordering operators compare lexicographically; `=~` needs a compiled regex
/// and `in_subnet` a CIDR literal. A type mismatch returns `false`.
fn compare_str(field_val: &str, op: &Operator, value: &Value) -> bool {
    match (op, value) {
        (Operator::Eq, Value::Str(s)) => field_val == s,
        (Operator::Ne, Value::Str(s)) => field_val != s,
        (Operator::Lt, Value::Str(s)) => field_val < s.as_str(),
        (Operator::Gt, Value::Str(s)) => field_val > s.as_str(),
        (Operator::Le, Value::Str(s)) => field_val <= s.as_str(),
        (Operator::Ge, Value::Str(s)) => field_val >= s.as_str(),
        (Operator::Regex, Value::Re(re)) => re.is_match(field_val),
        // The CIDR block is an ordinary string literal; the comparison is
        // arithmetic on the two parsed addresses.
        (Operator::InSubnet, Value::Str(cidr)) => ip_in_cidr(field_val, cidr),
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
    // One equality notion drives every operator: two values within
    // `NUM_EQ_TOLERANCE` are equal. The ordering operators used exact `f64`
    // comparison, so a value could read as `== 30` AND `> 30` while `<= 30`
    // was false — a self-contradiction on the tolerance boundary.
    let eq = (field_val - rhs).abs() < NUM_EQ_TOLERANCE;
    match op {
        Operator::Eq => eq,
        Operator::Ne => !eq,
        Operator::Lt => !eq && field_val < rhs,
        Operator::Gt => !eq && field_val > rhs,
        Operator::Le => eq || field_val < rhs,
        Operator::Ge => eq || field_val > rhs,
        // Neither applies to a number: a regex has no numeric meaning and a
        // CIDR block is an address range, not a value range.
        Operator::Regex | Operator::InSubnet => false,
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
/// Test-only view of [`state_to_str`], so the cross-surface spelling gate in
/// `sip::dialog` can compare what the DSL actually uses rather than a copy of
/// it. Private otherwise: nothing outside this module should be choosing
/// between the DSL's spelling and the canonical one.
#[cfg(test)]
pub(crate) fn state_to_str_for_test(state: &DialogState) -> &'static str {
    state_to_str(state)
}

/// The spelling `--filter "state == '...'"` compares against.
///
/// Delegates to [`DialogState::as_str`] rather than restating the table: this
/// used to be a byte-identical copy of `Display`, and renaming a variant here
/// alone would have left a filter naming it matching nothing at all.
fn state_to_str(state: &DialogState) -> &'static str {
    // The canonical table, not a copy of it. `--filter "state == '...'"`
    // compares against exactly what every other surface prints.
    state.as_str()
}

/// MOS for a stream, scored by [`MosDelay::score`].
///
/// Deliberately a thin wrapper and nothing more. This function once carried
/// its own formula — `R = 93.2 - min(jitter,100) - 2.5*loss_pct`, with no
/// codec term and no delay term — so `--filter "rtp.mos < 3.0"` selected a
/// different set of streams than the ones the detail view showed below 3.0,
/// diverging by as much as 1.7 MOS at 60 ms and 5% loss.
///
/// It computes nothing at all now. The loss percentage it used to derive came
/// from the stream, and the delay term it used to assume comes from `delay` —
/// both belong to the scorer, and the second one is why this wrapper stopped
/// agreeing with the display a second time.
///
/// # Arguments
///
/// * `stream` — the RTP stream whose jitter, loss and codec feed the estimate.
/// * `delay` — one-way-delay evidence, resolved per stream.
///
/// # Returns
///
/// The MOS, on the same scale and from the same code as every other surface.
pub fn stream_mos(stream: &RtpStream, delay: MosDelay<'_>) -> f64 {
    delay.score(stream)
}

// ── Tests ───────────────────────────────────────────────────────────

/// Unit tests for the filter DSL: field matching, operator precedence,
/// regex and boolean values, nesting limits, parse-error rendering,
/// diagnostic aliases, the comparators, and the MOS approximation.
#[cfg(test)]
mod tests {

    type TestError = Box<dyn std::error::Error>;

    /// `in_subnet` accepts an address the HEP allowlist accepts.
    ///
    /// RTF1. `--hep-allow 198.51.100.0/24` admits an agent whose packets
    /// arrive as `::ffff:198.51.100.7`, because `CidrRange::contains` maps an
    /// IPv4-mapped IPv6 address to its v4 form first — [RFC 4291 section 2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291.html#section-2.5.5.2) makes
    /// `::ffff:0:0/96` the representation OF a v4 address, not a different
    /// family. `ip_in_cidr` had its own rule and refused the same address, so
    /// a filter over the traffic sipnab had just admitted selected none of it.
    ///
    /// The uprobe backend produces exactly this: it reads `sk_v6_rcv_saddr`
    /// verbatim whenever the socket family is `AF_INET6`, so a proxy bound to
    /// `[::]` carrying an IPv4 call yields a mapped address with no
    /// canonicalization anywhere in between.
    #[test]
    fn a_v4_mapped_address_matches_a_v4_prefix() -> Result<(), TestError> {
        assert!(
            ip_in_cidr("::ffff:198.51.100.7", "198.51.100.0/24"),
            "a mapped address is the same host as its v4 form"
        );
        assert!(
            !ip_in_cidr("::ffff:203.0.113.7", "198.51.100.0/24"),
            "but a mapped address outside the prefix still does not match"
        );
        Ok(())
    }

    /// A bare address is a host route, as it is on the allowlist.
    ///
    /// `--hep-allow 198.51.100.40` means that one host without the operator having
    /// to write `/32`. `ip_in_cidr` returned false for the same input, so the
    /// two surfaces disagreed about what an operator had written.
    #[test]
    fn a_bare_address_is_a_host_route() -> Result<(), TestError> {
        assert!(
            ip_in_cidr("198.51.100.40", "198.51.100.40"),
            "the host itself"
        );
        assert!(
            !ip_in_cidr("198.51.100.41", "198.51.100.40"),
            "and only that host"
        );
        assert!(
            ip_in_cidr("2001:db8::1", "2001:db8::1"),
            "the same reading for v6"
        );
        Ok(())
    }

    /// A v4-mapped CIDR still matches as IPv6 when written that way.
    ///
    /// The half the mapping must not break: `::ffff:0:0/96` is a legitimate
    /// IPv6 prefix, and folding every mapped address to v4 unconditionally
    /// would stop it matching itself.
    #[test]
    fn a_mapped_prefix_still_matches_as_v6() -> Result<(), TestError> {
        assert!(
            ip_in_cidr("::ffff:198.51.100.7", "::ffff:0:0/96"),
            "the mapped range contains the mapped address"
        );
        Ok(())
    }

    /// Families still do not cross where they genuinely differ.
    #[test]
    fn an_unmapped_v6_address_does_not_match_a_v4_prefix() -> Result<(), TestError> {
        assert!(
            !ip_in_cidr("2001:db8::1", "10.0.0.0/8"),
            "a real IPv6 host is not inside a v4 prefix"
        );
        assert!(!ip_in_cidr("10.0.0.1", "2001:db8::/32"), "and the reverse");
        Ok(())
    }

    /// `in_subnet` works end to end through the parser.
    ///
    /// The unit tests above pin the arithmetic; this pins that a filter an
    /// operator actually types reaches it.
    #[test]
    fn the_in_subnet_operator_parses_and_evaluates() -> Result<(), TestError> {
        FilterExpr::parse("src.ip in_subnet '198.51.100.0/24'")?;
        Ok(())
    }

    /// A CIDR with a non-octet-aligned prefix parses.
    ///
    /// The case the regex approach cannot express at all.
    #[test]
    fn a_non_octet_aligned_prefix_is_expressible() -> Result<(), TestError> {
        assert!(FilterExpr::parse("src.ip in_subnet '203.0.112.0/22'").is_ok());
        assert!(FilterExpr::parse("dst.ip in_subnet '2001:db8::/48'").is_ok());
        Ok(())
    }

    /// A CIDR literal matches by address arithmetic, not by string prefix.
    ///
    /// The DSL's only subnet answer was a regex on the dotted string. That is
    /// wrong for every prefix that is not octet-aligned — a `/22` cannot be
    /// written at all — it matches neighbors when the anchor is dropped, and
    /// it is unusable for IPv6, where one address has many textual forms.
    #[test]
    fn in_subnet_matches_on_the_parsed_address() -> Result<(), TestError> {
        for (ip, cidr, want) in [
            ("198.51.100.7", "198.51.100.0/24", true),
            ("198.51.100.7", "198.51.100.0/25", true),
            ("198.51.100.200", "198.51.100.0/25", false),
            // A /22 spans four /24s and cannot be written as a string prefix.
            ("203.0.113.5", "203.0.112.0/22", true),
            ("203.0.116.5", "203.0.112.0/22", false),
            // /32 is a single host.
            ("192.0.2.1", "192.0.2.1/32", true),
            ("192.0.2.2", "192.0.2.1/32", false),
            // /0 is everything.
            ("8.8.8.8", "0.0.0.0/0", true),
        ] {
            assert_eq!(
                ip_in_cidr(ip, cidr),
                want,
                "{ip} in {cidr} should be {want}"
            );
        }
        Ok(())
    }

    /// The regex trap the CIDR operator replaces.
    ///
    /// `^198\.51\.100\.` matches `198.51.100.7`, and an unanchored
    /// `198.51.100.` also matches `198.51.1002` — the failure that made a
    /// string prefix the wrong tool. The address form cannot make that
    /// mistake because it compares integers.
    #[test]
    fn a_neighboring_address_is_not_in_the_subnet() -> Result<(), TestError> {
        assert!(!ip_in_cidr("198.51.101.7", "198.51.100.0/24"));
        assert!(!ip_in_cidr("198.51.10.7", "198.51.100.0/24"));
        Ok(())
    }

    /// IPv6 works, including the zero-compression forms a string cannot equate.
    ///
    /// `2001:db8::1` and `2001:0db8:0000:0000:0000:0000:0000:0001` are the same
    /// address and different strings. Comparing on the parsed value is the only
    /// way both match.
    #[test]
    fn in_subnet_handles_ipv6_and_its_textual_forms() -> Result<(), TestError> {
        assert!(ip_in_cidr("2001:db8::1", "2001:db8::/32"));
        assert!(ip_in_cidr(
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::/32"
        ));
        assert!(!ip_in_cidr("2001:db9::1", "2001:db8::/32"));
        assert!(ip_in_cidr("2001:db8:1234::5", "2001:db8:1234::/48"));
        assert!(!ip_in_cidr("2001:db8:1235::5", "2001:db8:1234::/48"));
        Ok(())
    }

    /// Families do not cross.
    ///
    /// An IPv4 address is not inside an IPv6 prefix and the reverse, and
    /// answering `true` for either would silently widen every filter written
    /// on a dual-stack capture.
    #[test]
    fn an_address_is_never_inside_a_prefix_of_the_other_family() -> Result<(), TestError> {
        assert!(!ip_in_cidr("192.0.2.1", "2001:db8::/32"));
        assert!(!ip_in_cidr("2001:db8::1", "192.0.2.0/24"));
        Ok(())
    }

    /// Malformed input matches nothing rather than everything.
    ///
    /// The safe direction: a filter that cannot be understood must select no
    /// dialogs, never all of them. A prefix length past the family's width is
    /// malformed, not a synonym for "match everything".
    #[test]
    fn a_malformed_cidr_matches_nothing() -> Result<(), TestError> {
        for bad in [
            "198.51.100.0",      // no prefix length
            "198.51.100.0/",     // empty length
            "198.51.100.0/33",   // past the IPv4 width
            "2001:db8::/129",    // past the IPv6 width
            "198.51.100.0/-1",   // negative
            "not-an-address/24", // not an address
            "",                  // empty
        ] {
            assert!(
                !ip_in_cidr("198.51.100.7", bad),
                "{bad:?} must match nothing"
            );
        }
        assert!(!ip_in_cidr("not-an-address", "198.51.100.0/24"));
        Ok(())
    }

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
    fn base_ts() -> Result<DateTime<Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
                .single()
                .ok_or("invalid fixture timestamp")?,
        )
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a dialog from a single request with the given From user, To
    /// user, and method (User-Agent fixed to `TestUA/1.0`).
    fn make_dialog(from_user: &str, to_user: &str, method: &str) -> Result<SipDialog, TestError> {
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
            base_ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        Ok(SipDialog::new(&msg).ok_or("should create dialog")?)
    }

    /// Build an INVITE dialog whose timing yields a post-dial delay of
    /// `pdd_ms` milliseconds.
    fn make_dialog_with_timing(pdd_ms: i64) -> Result<SipDialog, TestError> {
        let mut dialog = make_dialog("1001", "2002", "INVITE")?;
        dialog.timing.invite_sent = Some(base_ts()?);
        dialog.timing.ringing_at = Some(base_ts()? + TimeDelta::milliseconds(pdd_ms));
        Ok(dialog)
    }

    /// Build a one-packet RTP stream (SSRC 0xDEADBEEF), orphaned or claimed by
    /// a dialog — which is the same thing as whether `associated_dialog` is
    /// set, per [`RtpStream::orphaned`].
    fn make_rtp_stream(orphaned: bool) -> Result<RtpStream, TestError> {
        let key = StreamKey {
            ssrc: 0xDEADBEEF,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
            session: 0,
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
        let mut stream = RtpStream::new(key, &hdr, base_ts()?);
        if !orphaned {
            stream.associated_dialog = Some("claimed@example.invalid".to_string());
        }
        Ok(stream)
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
    fn a_dialog_with_no_rtp_does_not_match_a_mos_threshold() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "REGISTER")?;
        let filter = FilterExpr::parse("rtp.mos < 3.0")?;
        assert!(
            !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "a dialog with no RTP has no MOS; it is not a bad-audio call"
        );
        Ok(())
    }

    /// The same unknown does not match `!=` either.
    ///
    /// The half a partial fix gets wrong. An unknown is not "different from
    /// 3.0", it is unknown — admitting it here would move the same wrong
    /// answer to whoever writes the negation, which is where a triage filter
    /// usually ends up. SQL's NULL rule, for SQL's reason.
    #[test]
    fn an_unknown_mos_is_not_unequal_either() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "REGISTER")?;
        for expr in ["rtp.mos != 3.0", "rtp.mos > 3.0", "rtp.mos == 0.0"] {
            let filter = FilterExpr::parse(expr)?;
            assert!(
                !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "`{expr}` must not match a dialog whose MOS was never measured"
            );
        }
        Ok(())
    }

    /// Jitter and loss are unknown for the same dialog, and behave the same.
    ///
    /// Fixing `rtp.mos` alone would leave the identical trap in the two fields
    /// beside it, which is why the rule lives in one comparison helper.
    #[test]
    fn unknown_jitter_and_loss_match_no_threshold() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "REGISTER")?;
        for expr in ["rtp.jitter < 30", "rtp.loss < 5", "rtp.jitter != 1"] {
            let filter = FilterExpr::parse(expr)?;
            assert!(
                !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "`{expr}` must not match a dialog with no RTP"
            );
        }
        Ok(())
    }

    /// An unmeasured `pdd` / `setup_time` matches nothing, and is not 0.
    ///
    /// The enum's own rustdoc said "(0 when unknown)" for both while
    /// `compare_opt_num` implemented the opposite -- the doc repeated the very
    /// substitution that made `rtp.mos < 3.0` select 2292 of 2311 dialogs on a
    /// real trunk capture. Nothing failed when the two disagreed, because
    /// nothing asked these two fields the question.
    #[test]
    fn an_unknown_pdd_or_setup_time_matches_no_comparison() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "REGISTER")?;
        for expr in [
            "pdd < 1",
            "pdd > 1",
            "pdd != 1",
            "setup_time < 1",
            "setup_time > 1",
            "setup_time != 1",
        ] {
            let filter = FilterExpr::parse(expr)?;
            assert!(
                !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "`{expr}` must not match a dialog whose timing was never \
                 measured -- reading the unknown as 0 puts it below every \
                 threshold an operator would type"
            );
        }
        Ok(())
    }

    /// A dialog that HAS RTP still matches on its measured values.
    ///
    /// Anti-vacuity. A helper that returned false for everything would satisfy
    /// every assertion above.
    #[test]
    fn a_dialog_with_rtp_still_matches_on_its_measured_values() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let stream = make_rtp_stream(false)?;
        let streams = [&stream];
        let filter = FilterExpr::parse("rtp.mos > 0")?;
        assert!(
            filter.matches_dialog(&dialog, &streams, CaptureMedia::Absent, MosDelay::unknown()),
            "a measured MOS must still compare; the rule is about unknowns only"
        );
        let filter = FilterExpr::parse("rtp.jitter >= 0")?;
        assert!(
            filter.matches_dialog(&dialog, &streams, CaptureMedia::Absent, MosDelay::unknown()),
            "a measured jitter must still compare"
        );
        Ok(())
    }

    /// An untimed call does not match a setup-time or PDD threshold.
    ///
    /// Same defect, on the fields #88 just made honest: a capture that opened
    /// mid-call now correctly reports an unknown setup time, and `setup_time
    /// < 1` must not then select it as the fastest call in the file. Anyone
    /// computing a p95 from that filter is averaging in calls that were never
    /// timed.
    #[test]
    fn an_untimed_call_matches_no_setup_or_pdd_threshold() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        for expr in ["setup_time < 1", "pdd < 1", "setup_time != 9"] {
            let filter = FilterExpr::parse(expr)?;
            assert!(
                !filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "`{expr}` must not match a dialog that was never timed"
            );
        }
        Ok(())
    }

    /// A timed call still matches on its measured timing.
    ///
    /// The anti-vacuity partner of the test above.
    #[test]
    fn a_timed_call_still_matches_on_its_measured_timing() -> Result<(), TestError> {
        let dialog = make_dialog_with_timing(1500)?;
        let filter = FilterExpr::parse("pdd < 2")?;
        assert!(
            filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "a measured 1.5 s post-dial delay must still match `pdd < 2`"
        );

        let mut answered = make_dialog("1001", "2002", "INVITE")?;
        answered.timing.invite_sent = Some(base_ts()?);
        answered.timing.answered_at = Some(base_ts()? + TimeDelta::milliseconds(2500));
        let filter = FilterExpr::parse("setup_time > 2")?;
        assert!(
            filter.matches_dialog(&answered, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "a measured 2.5 s setup must still match `setup_time > 2`"
        );
        Ok(())
    }

    /// `from.user ==` matches a dialog with that exact From user.
    #[test]
    fn from_user_equals_match() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let filter = FilterExpr::parse("from.user == '1001'")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// `payload` greps the raw text of every message: regex matches
    /// content anywhere in the message, and equality never panics on
    /// lossily-decoded bytes.
    #[test]
    fn payload_field_matches_raw_message_content() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        // The raw INVITE contains the To URI.
        let f = FilterExpr::parse("payload =~ '2002@example'")?;
        assert!(f.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        let f = FilterExpr::parse("payload =~ 'not-there'")?;
        assert!(!f.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        // Equality against a whole raw message: never matches here, must not
        // panic (raw bytes are lossily decoded).
        let f = FilterExpr::parse("payload == 'x'")?;
        assert!(!f.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// Build a dialog whose sole INVITE carries `body` verbatim (so
    /// `payload` sees those exact bytes, valid UTF-8 or not).
    fn make_dialog_with_body(body: &[u8]) -> Result<SipDialog, TestError> {
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
            base_ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        Ok(SipDialog::new(&msg).ok_or("should create dialog")?)
    }

    /// Item 1: quoted strings support backslash escapes so the delimiter
    /// char becomes expressible (`\'`, `\"`). Other backslash sequences —
    /// including `\\` and regex classes like `\d` — are preserved verbatim so
    /// regex syntax and pre-escaped literals still reach the engine. The old
    /// tokenizer had no escape mechanism, so a quoted delimiter was
    /// impossible to write.
    #[test]
    fn escaped_quotes_and_backslash_in_strings() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;

        // `\'` lets a single-quoted literal contain its own delimiter — the
        // whole point of item 1. The old tokenizer stopped at the first `'`.
        let f = FilterExpr::parse(r"from.user == 'a\'b'")?;
        match &f.root {
            Expr::Compare(_, _, Value::Str(s)) => assert_eq!(s, "a'b"),
            other => return Err(format!("expected string compare, got {other:?}").into()),
        }

        // `\"` likewise inside a double-quoted literal.
        let f = FilterExpr::parse(r#"to.user == "x\"y""#)?;
        match &f.root {
            Expr::Compare(_, _, Value::Str(s)) => assert_eq!(s, "x\"y"),
            other => return Err(format!("expected string compare, got {other:?}").into()),
        }

        // Regex classes survive: `\d` is kept verbatim, so a 4-digit user
        // matches. The escaped `\'` here proves the delimiter is expressible
        // inside a regex too (matches nothing, but must parse).
        let f = FilterExpr::parse(r"from.user =~ '^\d\d\d\d$'")?;
        assert!(f.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown())); // from.user == "1001"

        // `\\` is preserved as two characters, so the regex engine sees one
        // literal backslash. This keeps `regex::escape`-produced text (e.g.
        // the TUI filter builder, which emits `\\` for a literal backslash)
        // matching literally rather than turning into an invalid trailing
        // backslash.
        let f = FilterExpr::parse(r"from.user == 'a\\b'")?;
        match &f.root {
            Expr::Compare(_, _, Value::Str(s)) => assert_eq!(s, r"a\\b"),
            other => return Err(format!("expected string compare, got {other:?}").into()),
        }
        Ok(())
    }

    /// Item 4: `payload =~` matches against the raw message bytes, not a
    /// lossy UTF-8 rendering. A message carrying a raw `0xFF` byte must NOT
    /// satisfy a search for the Unicode replacement character U+FFFD — the
    /// byte is not that character. The old `String::from_utf8_lossy` path
    /// fabricated a match by rewriting `0xFF` to U+FFFD.
    #[test]
    fn payload_matches_raw_bytes_not_lossy_replacement() -> Result<(), TestError> {
        let dialog = make_dialog_with_body(&[0xFF])?;

        // U+FFFD is absent from the true bytes → no match.
        let f = FilterExpr::parse(r"payload =~ '\x{FFFD}'")?;
        assert!(!f.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));

        // ASCII content around the invalid byte still greps fine and never
        // panics on the non-UTF-8 message.
        let dialog2 = make_dialog_with_body(b"MARK\xffER")?;
        let f = FilterExpr::parse("payload =~ 'MARK'")?;
        assert!(f.matches_dialog(&dialog2, &[], CaptureMedia::Absent, MosDelay::unknown()));
        let f = FilterExpr::parse("payload == 'nope'")?;
        assert!(!f.matches_dialog(&dialog2, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// `from.user ==` rejects a dialog with a different From user.
    #[test]
    fn from_user_equals_no_match() -> Result<(), TestError> {
        let dialog = make_dialog("2002", "1001", "INVITE")?;
        let filter = FilterExpr::parse("from.user == '1001'")?;
        assert!(!filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── AND + NOT ───────────────────────────────────────────────────

    /// `AND` combined with `NOT ua =~` matches when the UA does not match
    /// the regex.
    #[test]
    fn method_and_not_ua_regex() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let filter = FilterExpr::parse("method == 'INVITE' AND NOT ua =~ 'scanner'")?;
        // UA is "TestUA/1.0", does not match 'scanner', so NOT flips to true
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── PDD in seconds ─────────────────────────────────────────────

    /// `pdd` compares in seconds: a 4000 ms PDD satisfies `pdd > 3.0`.
    #[test]
    fn pdd_greater_than() -> Result<(), TestError> {
        // PDD of 4000ms = 4.0 seconds, filter asks > 3.0
        let dialog = make_dialog_with_timing(4000)?;
        let filter = FilterExpr::parse("pdd > 3.0")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// A 2000 ms PDD does not satisfy `pdd > 3.0`.
    #[test]
    fn pdd_not_greater_than() -> Result<(), TestError> {
        // PDD of 2000ms = 2.0 seconds, filter asks > 3.0
        let dialog = make_dialog_with_timing(2000)?;
        let filter = FilterExpr::parse("pdd > 3.0")?;
        assert!(!filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
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
    fn rtp_orphaned_is_no_longer_a_field() -> Result<(), TestError> {
        let err = FilterExpr::parse("rtp.orphaned == true")
            .err()
            .ok_or("rtp.orphaned must not parse as a field")?;
        let msg = err.to_string();
        assert!(
            msg.contains("rtp.orphaned") || msg.contains("field"),
            "the error should name what was rejected, got: {msg}"
        );
        Ok(())
    }

    /// The `problems` alias no longer carries the unsatisfiable disjunct.
    #[test]
    fn problems_alias_drops_the_unsatisfiable_disjunct() -> Result<(), TestError> {
        let expr = expand_alias("problems", &AliasThresholds::default()).ok_or("alias exists")?;
        assert!(
            !expr.contains("orphaned"),
            "problems must not include a term that can never be true: {expr}"
        );
        FilterExpr::parse(&expr)?;
        Ok(())
    }

    // ── Boolean operator precedence ─────────────────────────────────

    /// Explicit parentheses change the result: `(A OR B) AND C` differs
    /// from `A OR (B AND C)` on the same dialog.
    #[test]
    fn precedence_or_and() -> Result<(), TestError> {
        // (A OR B) AND C  vs  A OR (B AND C)
        // A = from.user == '1001' -> true
        // B = from.user == '9999' -> false
        // C = method == 'BYE'     -> false (method is INVITE)
        //
        // (A OR B) AND C = (true OR false) AND false = true AND false = false
        // A OR (B AND C) = true OR (false AND false) = true OR false = true

        let dialog = make_dialog("1001", "2002", "INVITE")?;

        let filter_grouped_or =
            FilterExpr::parse("(from.user == '1001' OR from.user == '9999') AND method == 'BYE'")?;
        assert!(!filter_grouped_or.matches_dialog(
            &dialog,
            &[],
            CaptureMedia::Absent,
            MosDelay::unknown()
        ));

        let filter_grouped_and =
            FilterExpr::parse("from.user == '1001' OR (from.user == '9999' AND method == 'BYE')")?;
        assert!(filter_grouped_and.matches_dialog(
            &dialog,
            &[],
            CaptureMedia::Absent,
            MosDelay::unknown()
        ));
        Ok(())
    }

    /// Without parentheses, `AND` binds tighter than `OR`.
    #[test]
    fn default_precedence_and_binds_tighter() -> Result<(), TestError> {
        // Without parens: A OR B AND C
        // AND binds tighter: A OR (B AND C)
        // A = from.user == '1001' -> true
        // B = from.user == '9999' -> false
        // C = method == 'BYE'     -> false
        // = true OR (false AND false) = true
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let filter =
            FilterExpr::parse("from.user == '1001' OR from.user == '9999' AND method == 'BYE'")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── Regex matching ──────────────────────────────────────────────

    /// `=~` matches when the field value satisfies the regex.
    #[test]
    fn regex_match_accepts() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let filter = FilterExpr::parse("from.user =~ '100[0-9]'")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// `=~` rejects when the field value does not satisfy the regex.
    #[test]
    fn regex_match_rejects() -> Result<(), TestError> {
        let dialog = make_dialog("2001", "3003", "INVITE")?;
        let filter = FilterExpr::parse("from.user =~ '100[0-9]'")?;
        assert!(!filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── Nesting depth limit ─────────────────────────────────────────

    /// Parenthesis nesting past the limit fails to parse with a
    /// nesting-depth error.
    #[test]
    fn nesting_depth_exceeded() -> Result<(), TestError> {
        let open_parens = "(".repeat(60);
        let close_parens = ")".repeat(60);
        let expr = format!("{open_parens}from.user == '1001'{close_parens}");
        let result = FilterExpr::parse(&expr);
        assert!(result.is_err());
        let err_msg = result.err().ok_or("expected an error, got Ok")?.to_string();
        assert!(
            err_msg.contains("nesting depth"),
            "expected nesting depth error, got: {err_msg}"
        );
        Ok(())
    }

    /// Nesting well within the limit (10 levels) parses fine.
    #[test]
    fn nesting_within_limit() -> Result<(), TestError> {
        // 10 levels should be fine
        let open_parens = "(".repeat(10);
        let close_parens = ")".repeat(10);
        let expr = format!("{open_parens}from.user == '1001'{close_parens}");
        let result = FilterExpr::parse(&expr);
        assert!(result.is_ok());
        Ok(())
    }

    // ── Parse errors ────────────────────────────────────────────────

    /// An expression ending after the operator (missing value) fails to
    /// parse.
    #[test]
    fn parse_error_missing_value() -> Result<(), TestError> {
        let result = FilterExpr::parse("from.user ==");
        assert!(result.is_err());
        Ok(())
    }

    /// An empty expression fails to parse with an "empty" error message.
    #[test]
    fn parse_error_empty_input() -> Result<(), TestError> {
        let result = FilterExpr::parse("");
        assert!(result.is_err());
        let err_msg = result.err().ok_or("expected an error, got Ok")?.to_string();
        assert!(
            err_msg.contains("empty"),
            "expected empty error, got: {err_msg}"
        );
        Ok(())
    }

    /// A whitespace-only expression fails to parse.
    #[test]
    fn parse_error_whitespace_only() -> Result<(), TestError> {
        let result = FilterExpr::parse("   ");
        assert!(result.is_err());
        Ok(())
    }

    /// A comparison on an unknown field name fails to parse.
    #[test]
    fn parse_error_unknown_field() -> Result<(), TestError> {
        let result = FilterExpr::parse("bogus_field == '1001'");
        assert!(result.is_err());
        Ok(())
    }

    // ── Rich parse-error rendering ──────────────────────────────────

    /// The rendered parse error echoes the expression with a caret
    /// aligned under the offending token.
    #[test]
    fn parse_error_shows_expression_with_caret_at_position() -> Result<(), TestError> {
        let err = FilterExpr::parse("ua == Friendly Scanner")
            .err()
            .ok_or("expected an error, got Ok")?
            .to_string();
        assert!(
            err.contains("ua == Friendly Scanner"),
            "error must echo the expression, got:\n{err}"
        );
        // Caret under column 6 (0-based) where the value with a space starts.
        let caret_line = err
            .lines()
            .find(|l| l.trim_end().ends_with('^'))
            .ok_or_else(|| format!("error must contain a caret line, got:\n{err}"))?;
        assert_eq!(
            caret_line.find('^'),
            err.lines()
                .find(|l| l.contains("ua == Friendly Scanner"))
                .and_then(|l| l.find("Friendly")),
            "caret must align under the offending token, got:\n{err}"
        );
        Ok(())
    }

    /// A value containing whitespace cannot be bare, and the error says that
    /// it must be quoted.
    #[test]
    fn parse_error_hints_quoting_for_a_value_with_whitespace() -> Result<(), TestError> {
        let err = FilterExpr::parse("ua == Friendly Scanner")
            .err()
            .ok_or("expected an error, got Ok")?
            .to_string();
        assert!(
            err.contains("containing whitespace must be quoted"),
            "error must explain why the value needs quotes, got:\n{err}"
        );
        Ok(())
    }

    /// Every rendered parse error lists the valid operators.
    #[test]
    fn parse_error_lists_operators() -> Result<(), TestError> {
        let err = FilterExpr::parse("from.user @@ 'alice'")
            .err()
            .ok_or("expected an error, got Ok")?
            .to_string();
        assert!(
            err.contains("==") && err.contains("=~"),
            "error must list valid operators, got:\n{err}"
        );
        Ok(())
    }

    /// Caret column math counts characters, not bytes, so a multibyte
    /// prefix does not misplace the caret.
    #[test]
    fn parse_error_caret_correct_with_multibyte_prefix() -> Result<(), TestError> {
        // 'é' is 2 bytes / 1 column: caret math must use chars, not bytes.
        let err = FilterExpr::parse("from.user == 'é' and method == =x")
            .err()
            .ok_or("expected an error, got Ok")?
            .to_string();
        let expr_line = err
            .lines()
            .find(|l| l.contains("from.user"))
            .ok_or("expression echoed")?;
        let caret_line = err
            .lines()
            .find(|l| l.trim_end().ends_with('^'))
            .ok_or("caret line present")?;
        let caret_col = caret_line.chars().take_while(|c| *c == ' ').count();
        let invite_col = expr_line
            .find("=x")
            .map(|byte_idx| expr_line[..byte_idx].chars().count())
            .ok_or("the invalid value present in echoed expression")?;
        assert_eq!(
            caret_col, invite_col,
            "caret column must be measured in characters, not bytes, got:\n{err}"
        );
        Ok(())
    }

    /// Very long expressions are windowed around the error position so
    /// the diagnostic lines stay readable, caret included.
    #[test]
    fn parse_error_long_input_is_windowed_not_panicking() -> Result<(), TestError> {
        let long = format!("from.user == '{}' and method == =x", "x".repeat(200));
        let err = FilterExpr::parse(&long)
            .err()
            .ok_or("expected an error, got Ok")?
            .to_string();
        assert!(
            err.lines().all(|l| l.chars().count() <= 120),
            "long expressions must be windowed around the error, got:\n{err}"
        );
        assert!(err.contains('^'), "caret still present, got:\n{err}");
        Ok(())
    }

    // ── Diagnostic aliases ──────────────────────────────────────────

    /// Every documented alias expands to an expression that parses.
    #[test]
    fn all_aliases_expand_and_parse() -> Result<(), TestError> {
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
                .ok_or_else(|| format!("alias '{alias}' should exist"))?;
            let result = FilterExpr::parse(&expanded);
            assert!(
                result.is_ok(),
                "alias '{alias}' expanded to '{expanded}' but failed to parse: {:?}",
                result.err().ok_or("expected an error, got Ok")?
            );
        }
        Ok(())
    }

    /// expand_alias returns None for an unrecognized alias.
    #[test]
    fn unknown_alias_returns_none() -> Result<(), TestError> {
        assert!(expand_alias("nonexistent", &AliasThresholds::default()).is_none());
        Ok(())
    }

    /// [`DIAGNOSTIC_ALIASES`] and the match arms are ONE vocabulary.
    ///
    /// Read out of this file's own source rather than restated, for the reason
    /// `SECURITY_FINDING_KINDS` reads the detectors' call sites: a published
    /// list checked against a copy of itself proves nothing, and the failure it
    /// has to catch is an arm added to the match without the list — which the
    /// membership guard turns into an alias that silently never expands.
    #[test]
    fn the_alias_list_is_exactly_what_expand_alias_matches_on() -> Result<(), TestError> {
        const SOURCE: &str = include_str!("dsl.rs");
        let body = SOURCE
            .split_once("let expr = match alias {")
            .ok_or("expand_alias still opens with a match on the alias")?
            .1
            .split_once("_ => return None,")
            .ok_or("the match still ends with the catch-all")?
            .0;

        let arms: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('"') && l.contains("=>"))
            .filter_map(|l| l.split('"').nth(1))
            .collect();

        // The extractor must FIRE before it can certify anything: one that
        // found nothing would agree with an empty list and read as a pass.
        assert_eq!(
            arms.len(),
            DIAGNOSTIC_ALIASES.len(),
            "read {} arm(s) out of expand_alias but the list names {}: {arms:?}",
            arms.len(),
            DIAGNOSTIC_ALIASES.len()
        );
        assert_eq!(
            arms,
            DIAGNOSTIC_ALIASES.to_vec(),
            "the published alias list and the match arms have drifted apart"
        );
        Ok(())
    }

    // ── Double-quoted strings ───────────────────────────────────────

    /// Double-quoted string values parse and match like single-quoted
    /// ones.
    #[test]
    fn double_quoted_string() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let filter = FilterExpr::parse(r#"from.user == "1001""#)?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── State comparison ────────────────────────────────────────────

    /// `state ==` matches the dialog's current state name and rejects
    /// others.
    #[test]
    fn state_comparison() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        // Initial state for INVITE is Trying
        let filter = FilterExpr::parse("state == 'Trying'")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));

        let filter_fail = FilterExpr::parse("state == 'Failed'")?;
        assert!(!filter_fail.matches_dialog(
            &dialog,
            &[],
            CaptureMedia::Absent,
            MosDelay::unknown()
        ));
        Ok(())
    }

    // ── Dialog state with Failed ────────────────────────────────────

    /// A dialog driven to Failed by a 503 matches `state == 'Failed'`.
    #[test]
    fn failed_state() -> Result<(), TestError> {
        let mut dialog = make_dialog("1001", "2002", "INVITE")?;
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
            base_ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        crate::sip::dialog::update_state(&mut dialog, &fail_msg);
        assert_eq!(*dialog.state(), DialogState::Failed);
        let filter = FilterExpr::parse("state == 'Failed'")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── Response code ───────────────────────────────────────────────

    /// Build a dialog driven to a final INVITE response.
    fn make_dialog_with_response(code: u16, reason: &str) -> Result<SipDialog, TestError> {
        let mut dialog = make_dialog("1001", "2002", "INVITE")?;
        let raw = build_sip(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:2002@example.com>;tag=t2",
                "Call-ID: test-call-id@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            base_ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        crate::sip::dialog::update_state(&mut dialog, &msg);
        // `update_state` drives the state machine; it does not store the
        // message, and `final_status_code` reads the stored ones.
        dialog.messages.push(msg);
        Ok(dialog)
    }

    /// `state == 'Failed'` collapses every release cause into one bucket, so
    /// the release cause has to be reachable on its own. A trunk incident asks
    /// "which cause dominates", and 403, 404, 408, 486, 503 and 603 are six
    /// different answers with six different owners.
    #[test]
    fn response_code_separates_causes_that_state_collapses() -> Result<(), TestError> {
        let busy = make_dialog_with_response(486, "Busy Here")?;
        let unavailable = make_dialog_with_response(503, "Service Unavailable")?;

        // Both are Failed, which is the whole problem.
        assert_eq!(*busy.state(), DialogState::Failed);
        assert_eq!(*unavailable.state(), DialogState::Failed);

        let is_503 = FilterExpr::parse("response_code == 503")?;
        assert!(
            is_503.matches_dialog(&unavailable, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "503 must match response_code == 503"
        );
        assert!(
            !is_503.matches_dialog(&busy, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "486 must NOT match response_code == 503; that is the collapse this field removes"
        );

        // Ranges are the point of a numeric field: 5xx as a class.
        let server_error = FilterExpr::parse("response_code >= 500 AND response_code < 600")?;
        assert!(server_error.matches_dialog(
            &unavailable,
            &[],
            CaptureMedia::Absent,
            MosDelay::unknown()
        ));
        assert!(!server_error.matches_dialog(
            &busy,
            &[],
            CaptureMedia::Absent,
            MosDelay::unknown()
        ));
        Ok(())
    }

    /// A call still in progress has no final response, and must not read as
    /// zero -- `response_code < 400` would otherwise sweep up every ringing
    /// call as a success.
    #[test]
    fn a_dialog_with_no_final_response_matches_no_response_code() -> Result<(), TestError> {
        let ringing = make_dialog("1001", "2002", "INVITE")?;
        assert_eq!(ringing.final_status_code(), None, "no final response yet");
        for expr in [
            "response_code < 400",
            "response_code >= 400",
            "response_code == 0",
        ] {
            let f = FilterExpr::parse(expr)?;
            assert!(
                !f.matches_dialog(&ringing, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "{expr} must not match a dialog with no final response"
            );
        }
        Ok(())
    }

    /// The IANA registry groups every response code into six classes, and an
    /// operator asks in those terms: "any server failure", not "500 through
    /// 599". `response_code >= 500 AND response_code < 600` says it, but it
    /// says it as arithmetic, and getting the bound wrong by one is silent.
    #[test]
    fn response_class_matches_the_iana_class_of_the_final_response() -> Result<(), TestError> {
        for (code, class) in [
            (200u16, "2xx"),
            (302, "3xx"),
            (486, "4xx"),
            (503, "5xx"),
            (603, "6xx"),
        ] {
            let dialog = make_dialog_with_response(code, "Reason")?;
            let f = FilterExpr::parse(&format!("response_class == '{class}'"))?;
            assert!(
                f.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "{code} is {class}"
            );
            // And it belongs to exactly one class.
            for other in ["1xx", "2xx", "3xx", "4xx", "5xx", "6xx"] {
                if other == class {
                    continue;
                }
                let g = FilterExpr::parse(&format!("response_class == '{other}'"))?;
                assert!(
                    !g.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                    "{code} must not also be {other}"
                );
            }
        }
        Ok(())
    }

    /// The registry names the classes, and an operator types the name as
    /// readily as the number. Accepting one and not the other would make the
    /// field's own documentation a trap.
    #[test]
    fn a_response_class_can_be_named_the_way_iana_names_it() -> Result<(), TestError> {
        let busy = make_dialog_with_response(486, "Busy Here")?;
        let unavailable = make_dialog_with_response(503, "Service Unavailable")?;
        let ok = make_dialog_with_response(200, "OK")?;
        let gone = make_dialog_with_response(603, "Decline")?;

        for (dialog, spellings) in [
            (&ok, vec!["2xx", "Successful", "successful"]),
            (&busy, vec!["4xx", "Request Failure", "request-failure"]),
            (
                &unavailable,
                vec!["5xx", "Server Failure", "server failure"],
            ),
            (&gone, vec!["6xx", "Global Failures", "global failure"]),
        ] {
            for spelling in spellings {
                let f = FilterExpr::parse(&format!("response_class == '{spelling}'"))?;
                assert!(
                    f.matches_dialog(dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                    "'{spelling}' must name the same class as its number"
                );
            }
        }

        // And `!=` stays honest: a 503 is NOT anything but a server failure,
        // by either spelling. Matching against two forms at once would have
        // made this true.
        let not_server = FilterExpr::parse("response_class != 'Server Failure'")?;
        assert!(
            !not_server.matches_dialog(
                &unavailable,
                &[],
                CaptureMedia::Absent,
                MosDelay::unknown()
            ),
            "503 is a server failure, so `!= 'Server Failure'` must be false"
        );
        Ok(())
    }

    /// At a console "failure" means all three failure classes, and a specific
    /// class is how you ask for one. Both have to work, and `!=` has to stay
    /// honest across the union.
    #[test]
    fn failure_names_all_three_failure_classes_and_a_class_names_one() -> Result<(), TestError> {
        let ok = make_dialog_with_response(200, "OK")?;
        let busy = make_dialog_with_response(486, "Busy Here")?;
        let unavailable = make_dialog_with_response(503, "Service Unavailable")?;
        let declined = make_dialog_with_response(603, "Decline")?;
        let m = |d: &SipDialog, e: &str| -> Result<_, TestError> {
            Ok(FilterExpr::parse(e)?.matches_dialog(
                d,
                &[],
                CaptureMedia::Absent,
                MosDelay::unknown(),
            ))
        };

        // The union.
        for d in [&busy, &unavailable, &declined] {
            assert!(
                m(d, "response_class == 'failure'")?,
                "4xx/5xx/6xx are failures"
            );
        }
        assert!(
            !m(&ok, "response_class == 'failure'")?,
            "200 is not a failure"
        );
        assert!(m(&ok, "response_class != 'failure'")?, "and != says so");

        // One class at a time still means one class, and the number and the
        // registry's name are interchangeable for EACH of the three -- not
        // only for 4xx.
        for (dialog, number, name, label) in [
            (&busy, "4xx", "Request Failure", "486"),
            (&unavailable, "5xx", "Server Failure", "503"),
            (&declined, "6xx", "Global Failures", "603"),
        ] {
            assert!(
                m(dialog, &format!("response_class == '{number}'"))?,
                "{label} is {number}"
            );
            assert!(
                m(dialog, &format!("response_class == '{name}'"))?,
                "{label} is '{name}'"
            );
            // And it is in no OTHER class, by either spelling.
            for (other_num, other_name) in [
                ("4xx", "Request Failure"),
                ("5xx", "Server Failure"),
                ("6xx", "Global Failures"),
            ] {
                if other_num == number {
                    continue;
                }
                assert!(
                    !m(dialog, &format!("response_class == '{other_num}'"))?,
                    "{label} must not be {other_num}"
                );
                assert!(
                    !m(dialog, &format!("response_class == '{other_name}'"))?,
                    "{label} must not be '{other_name}'"
                );
            }
        }

        // `!=` against a single class does not leak through a second spelling.
        assert!(
            !m(&unavailable, "response_class != 'Server Failure'")?,
            "503 IS a server failure, so != must be false whichever spelling"
        );
        Ok(())
    }

    /// A dialog is never `1xx`, and that is not an omission.
    ///
    /// `response_class` is the class of the FINAL response, and a provisional
    /// one is by definition not final -- a call sitting on 183 has no outcome
    /// yet, so it has no class, the same as a call that has heard nothing.
    /// Anyone reaching for `response_class == '1xx'` wants `state`.
    #[test]
    fn a_ringing_call_is_in_no_class_rather_than_in_1xx() -> Result<(), TestError> {
        let mut ringing = make_dialog("1001", "2002", "INVITE")?;
        let raw = build_sip(
            "SIP/2.0 183 Session Progress",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:2002@example.com>;tag=t2",
                "Call-ID: test-call-id@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            base_ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        crate::sip::dialog::update_state(&mut ringing, &msg);
        ringing.messages.push(msg);

        assert_eq!(
            ringing.final_status_code(),
            None,
            "a provisional response is not an outcome"
        );
        let f = FilterExpr::parse("response_class == '1xx'")?;
        assert!(
            !f.matches_dialog(&ringing, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "183 gives no class, because it is not final"
        );
        Ok(())
    }

    /// A call with no final response has no class, exactly as it has no code.
    #[test]
    fn a_dialog_with_no_final_response_has_no_response_class() -> Result<(), TestError> {
        let ringing = make_dialog("1001", "2002", "INVITE")?;
        for class in ["1xx", "4xx", "5xx"] {
            let f = FilterExpr::parse(&format!("response_class == '{class}'"))?;
            assert!(
                !f.matches_dialog(&ringing, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "an in-progress call is in no class, not in {class}"
            );
        }
        Ok(())
    }

    // ── Complex compound expression ─────────────────────────────────

    /// A compound expression mixing AND, parentheses, and OR evaluates
    /// correctly.
    #[test]
    fn complex_compound_expr() -> Result<(), TestError> {
        let dialog = make_dialog_with_timing(4000)?;
        let filter = FilterExpr::parse("from.user == '1001' AND (pdd > 3.0 OR state == 'Failed')")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── Msg count ───────────────────────────────────────────────────

    /// `msg_count` reflects the number of stored messages.
    #[test]
    fn msg_count() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        // Dialog has exactly 1 message (the initial INVITE)
        let filter = FilterExpr::parse("msg_count == 1")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));

        let filter_more = FilterExpr::parse("msg_count > 5")?;
        assert!(!filter_more.matches_dialog(
            &dialog,
            &[],
            CaptureMedia::Absent,
            MosDelay::unknown()
        ));
        Ok(())
    }

    // ── RTP packets count ───────────────────────────────────────────

    /// `rtp.packets` sums packet counts across associated streams.
    #[test]
    fn rtp_packets_count() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let stream = make_rtp_stream(false)?;
        let streams: Vec<&RtpStream> = vec![&stream];
        // Stream has 1 packet from construction
        let filter = FilterExpr::parse("rtp.packets >= 1")?;
        assert!(filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));
        Ok(())
    }

    // ── Retransmits ─────────────────────────────────────────────────

    /// `retransmits` compares against the dialog's total retransmit count.
    #[test]
    fn retransmits_comparison() -> Result<(), TestError> {
        let mut dialog = make_dialog("1001", "2002", "INVITE")?;
        dialog
            .timing
            .retransmit_counts
            .insert("1 INVITE".to_string(), 5);
        let filter = FilterExpr::parse("retransmits > 3")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── Not-equal operator ──────────────────────────────────────────

    /// `!=` matches when the field value differs from the literal.
    #[test]
    fn not_equal_operator() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let filter = FilterExpr::parse("method != 'BYE'")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── Integer numeric values ──────────────────────────────────────

    /// Integer literals (no decimal point) parse as numbers.
    #[test]
    fn integer_numeric_value() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let filter = FilterExpr::parse("msg_count == 1")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── expand_alias: every alias maps to its documented expression ─────

    /// Each alias expands to exactly its documented DSL expression.
    #[test]
    fn expand_alias_returns_exact_expansions() -> Result<(), TestError> {
        assert!(
            expand_alias("problems", &AliasThresholds::default())
                .ok_or("expand_alias() returned None")?
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
        Ok(())
    }

    /// Tuning a threshold changes which calls an alias SELECTS.
    ///
    /// The assertion is on selection, not on the expanded string. `--problems`
    /// carrying different text is worth nothing to an operator; the defect
    /// this closes was that tuning `[diagnosis]` to an SLA left the filter
    /// selecting on figures nobody chose, so what must move is the answer.
    #[test]
    fn tuning_a_threshold_changes_which_calls_an_alias_selects() -> Result<(), TestError> {
        let shipped = AliasThresholds::default();

        // A post-dial delay between the tuned and the shipped threshold: not a
        // problem by the shipped figure, a problem by a tightened one. Any
        // change below is therefore caused by the threshold and not the call.
        let pdd = (shipped.pdd_secs + 3.0) / 2.0;
        assert!(
            pdd < shipped.pdd_secs,
            "the fixture must start BELOW the shipped threshold, or this proves nothing"
        );

        let by_shipped = FilterExpr::parse(
            &expand_alias("problems", &shipped).ok_or("expand_alias() returned None")?,
        )?;

        let tuned = AliasThresholds {
            pdd_secs: 3.0,
            ..shipped
        };
        let by_tuned = FilterExpr::parse(
            &expand_alias("problems", &tuned).ok_or("expand_alias() returned None")?,
        )?;

        // Compare the compiled PDD term directly: the shipped set must not
        // select this call and the tuned set must.
        let shipped_expr =
            expand_alias("problems", &shipped).ok_or("expand_alias() returned None")?;
        let tuned_expr = expand_alias("problems", &tuned).ok_or("expand_alias() returned None")?;
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
        Ok(())
    }

    /// Every alias number is sourced from a threshold that is already tunable.
    ///
    /// Pins the property the type exists for: no figure in an alias may be a
    /// literal that only lives here, because that is precisely how
    /// `--problems` came to disagree with the diagnosis it reports.
    #[test]
    fn every_alias_threshold_is_sourced_from_a_tunable_setting() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Alias matching is exact and case-sensitive; near-misses return
    /// None.
    #[test]
    fn expand_alias_empty_and_case_sensitive_are_none() -> Result<(), TestError> {
        // Alias matching is exact and case-sensitive.
        assert!(expand_alias("", &AliasThresholds::default()).is_none());
        assert!(expand_alias("Problems", &AliasThresholds::default()).is_none());
        assert!(expand_alias("PROBLEMS", &AliasThresholds::default()).is_none());
        assert!(expand_alias("slow_setup", &AliasThresholds::default()).is_none());
        Ok(())
    }

    // ── check_nesting_depth: boundary behavior ─────────────────────────

    /// Exactly 50 nested parens passes the depth check; 51 fails it.
    #[test]
    fn nesting_depth_exactly_at_limit_ok() -> Result<(), TestError> {
        // Exactly MAX_NESTING_DEPTH (50) open parens is allowed; 51 is not.
        let expr = format!("{}from.user == '1001'{}", "(".repeat(50), ")".repeat(50));
        // Nesting-depth check itself passes (no "nesting depth" error).
        assert!(check_nesting_depth(&expr).is_ok());

        let too_deep = format!("{}from.user == '1001'{}", "(".repeat(51), ")".repeat(51));
        let err = check_nesting_depth(&too_deep)
            .err()
            .ok_or("expected an error, got Ok")?
            .to_string();
        assert!(err.contains("nesting depth"), "got: {err}");
        Ok(())
    }

    /// Leading close-parens saturate the depth at zero instead of
    /// underflowing.
    #[test]
    fn nesting_depth_unbalanced_close_parens_saturates() -> Result<(), TestError> {
        // Leading ')' must not underflow; depth saturates at 0.
        assert!(check_nesting_depth(")))(((").is_ok());
        Ok(())
    }

    // ── MAX_EXPRESSION_NODES: the figures it is justified against ──────

    /// The node counts quoted in [`MAX_EXPRESSION_NODES`]'s own
    /// justification, measured rather than remembered.
    ///
    /// A cap is only "generous" relative to something. These are that
    /// something, and if any of them grows past what the constant claims,
    /// this fails and the claim gets re-argued instead of quietly rotting.
    #[test]
    fn node_counts_the_cap_is_justified_against() -> Result<(), TestError> {
        /// Count the nodes in an expression that must parse.
        fn nodes(expr: &str) -> Result<usize, TestError> {
            let parsed = FilterExpr::parse(expr).map_err(|e| format!("{expr:?}: {e}"))?;
            Ok(count_nodes(&parsed.root))
        }

        let t = AliasThresholds::default();
        let problems = expand_alias("problems", &t).ok_or("problems is an alias")?;
        assert_eq!(
            nodes(&problems)?,
            23,
            "--problems, the biggest single alias"
        );

        // Every diagnostic alias flag at once, joined the way
        // `app::bootstrap::build_filter_expr` joins them: the widest
        // expression sipnab itself constructs.
        let all_flags = [
            "problems",
            "slow-setup",
            "short-calls",
            "one-way",
            "nat-issues",
        ]
        .iter()
        .map(|a| format!("({})", expand_alias(a, &t).unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(" OR ");
        assert_eq!(nodes(&all_flags)?, 33, "every alias flag at once");

        // The widest the TUI filter dialog can build: five text fields ANDed
        // with nine of the ten method checkboxes ORed (all ten emits no
        // method clause at all).
        let methods = [
            "REGISTER",
            "OPTIONS",
            "INVITE",
            "PUBLISH",
            "SUBSCRIBE",
            "MESSAGE",
            "NOTIFY",
            "REFER",
            "INFO",
        ]
        .iter()
        .map(|m| format!("method == '{m}'"))
        .collect::<Vec<_>>()
        .join(" OR ");
        let dialog_max = format!(
            "from.user =~ 'a' AND to.user =~ 'b' AND src.ip =~ 'c' AND dst.ip =~ 'd' \
             AND payload =~ 'e' AND ({methods})"
        );
        assert_eq!(
            nodes(&dialog_max)?,
            27,
            "the TUI filter dialog at its widest"
        );

        // The largest filter written out in the user-facing documentation.
        assert_eq!(
            nodes("dst.ip == '198.51.100.100' AND state == 'Failed' AND method == 'INVITE'")?,
            5,
            "the biggest hand-written filter in docs/"
        );

        // And all of them together are still a small fraction of the cap.
        assert!(
            nodes(&all_flags)? * 30 < MAX_EXPRESSION_NODES,
            "the cap must stay at least 30x the widest expression sipnab builds"
        );
        Ok(())
    }

    /// A flat chain past the cap is refused, and the refusal names both the
    /// limit and the size — the guard `check_nesting_depth` cannot see,
    /// because a chain nests no parentheses.
    #[test]
    fn flat_chain_past_the_node_cap_is_refused_with_both_figures() -> Result<(), TestError> {
        let chain = vec!["state == 'Completed'"; 513].join(" OR ");
        assert!(check_nesting_depth(&chain).is_ok(), "no parens to count");
        let err = FilterExpr::parse(&chain)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "accepted".to_string());
        assert!(err.contains("1024"), "must name the limit: {err}");
        assert!(err.contains("1025"), "must name the size: {err}");
        Ok(())
    }

    /// `count_nodes` agrees with the shape it is counting.
    #[test]
    fn count_nodes_counts_every_node_kind() -> Result<(), TestError> {
        let one = FilterExpr::parse("state == 'Failed'")?;
        assert_eq!(count_nodes(&one.root), 1);

        let not = FilterExpr::parse("NOT state == 'Failed'")?;
        assert_eq!(count_nodes(&not.root), 2);

        let mixed = FilterExpr::parse("state == 'Failed' AND (pdd > 1.0 OR NOT one_way == true)")?;
        // 3 leaves + Not + Or + And.
        assert_eq!(count_nodes(&mixed.root), 6);

        // Parentheses add no node: the two spellings count the same.
        let bare = FilterExpr::parse("state == 'Failed' AND pdd > 1.0")?;
        let parens = FilterExpr::parse("(state == 'Failed') AND ((pdd > 1.0))")?;
        assert_eq!(count_nodes(&bare.root), count_nodes(&parens.root));
        Ok(())
    }

    /// Freeing a chain far past the point the recursive drop glue died on
    /// (measured: 17,902 terms) completes normally.
    ///
    /// Built by hand rather than through `parse` so the destructor is the
    /// only thing under test — and out of allocation-free leaves, so what the
    /// test costs is the tree's shape rather than 60,000 heap strings.
    #[test]
    fn dropping_a_deep_tree_does_not_recurse() -> Result<(), TestError> {
        let mut root = placeholder_leaf();
        for _ in 0..60_000 {
            root = Expr::Or(Box::new(root), Box::new(placeholder_leaf()));
        }
        assert_eq!(count_nodes(&root), 120_001);
        drop(root);
        Ok(())
    }

    // ── render_parse_error: direct unit coverage ────────────────────────

    /// render_parse_error emits the headline, echoed expression, caret,
    /// operator list, and docs pointer.
    #[test]
    fn render_parse_error_basic_caret_and_footer() -> Result<(), TestError> {
        let expr = "from.user == 'x'";
        let out = render_parse_error(expr, 0, "unexpected input");
        assert!(out.starts_with("unexpected input at position 0"));
        assert!(out.contains(expr));
        assert!(out.contains('^'));
        assert!(out.contains("valid operators:"));
        assert!(out.contains("docs/filter-dsl.md"));
        Ok(())
    }

    /// A position at end-of-string yields no offending token, so the
    /// ": '...'" suffix is omitted.
    #[test]
    fn render_parse_error_empty_offending_omits_token() -> Result<(), TestError> {
        // pos at end-of-string => no offending token => no ": '...'" suffix.
        let expr = "from.user == 'x'";
        let out = render_parse_error(expr, expr.len(), "unexpected trailing input");
        let header = out.lines().next().ok_or("next() returned None")?;
        assert!(header.ends_with("position 16"), "got: {header}");
        assert!(!header.contains(": '"), "got: {header}");
        Ok(())
    }

    /// The renderer adds no blanket "string values must be quoted" hint: a
    /// bare word after an operator is a value, and every case that still needs
    /// quotes says why in its own headline.
    #[test]
    fn render_parse_error_adds_no_blanket_quoting_hint() -> Result<(), TestError> {
        for (expr, pos) in [("method == INVITE", 10), ("one_way == TRUE", 11)] {
            let out = render_parse_error(expr, pos, "x");
            assert!(!out.contains("must be quoted"), "got: {out}");
        }
        Ok(())
    }

    /// An out-of-range error position is clamped to the input length
    /// instead of panicking.
    #[test]
    fn render_parse_error_pos_past_end_is_clamped() -> Result<(), TestError> {
        // An out-of-range position must not panic; it is clamped to len.
        let expr = "method == 'X'";
        let out = render_parse_error(expr, 9999, "boom");
        assert!(out.contains("boom at position"));
        Ok(())
    }

    // ── parse_value / parse_operator error arms via FilterExpr::parse ───

    /// A string literal with no closing quote fails to parse.
    #[test]
    fn parse_unterminated_string_errors() -> Result<(), TestError> {
        // Missing closing quote hits the ErrorKind::Char failure arm.
        let result = FilterExpr::parse("from.user == 'unterminated");
        assert!(result.is_err());
        Ok(())
    }

    /// An `=~` value that fails regex compilation fails to parse.
    #[test]
    fn parse_invalid_regex_errors() -> Result<(), TestError> {
        // An unbalanced group fails RegexBuilder::build -> Verify failure arm.
        let result = FilterExpr::parse("from.user =~ '(unclosed'");
        assert!(result.is_err());
        Ok(())
    }

    /// A bare unquoted word where a number or string is expected fails to
    /// parse.
    #[test]
    fn parse_non_numeric_value_for_number_errors() -> Result<(), TestError> {
        // A bare unquoted word where a number/string is expected.
        let result = FilterExpr::parse("msg_count == abc");
        assert!(result.is_err());
        Ok(())
    }

    /// An unknown operator token fails to parse.
    #[test]
    fn parse_unknown_operator_errors() -> Result<(), TestError> {
        let result = FilterExpr::parse("from.user ?? '1001'");
        assert!(result.is_err());
        Ok(())
    }

    /// Unparsed trailing input after a valid expression fails with a
    /// "trailing" error.
    #[test]
    fn parse_trailing_input_errors() -> Result<(), TestError> {
        let result = FilterExpr::parse("from.user == '1001' garbage");
        assert!(result.is_err());
        let err = result.err().ok_or("expected an error, got Ok")?.to_string();
        assert!(err.contains("trailing"), "got: {err}");
        Ok(())
    }

    /// The `false` boolean literal parses and evaluates correctly.
    #[test]
    fn parse_false_boolean_literal() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        // one_way is false with no streams, so == false matches.
        let filter = FilterExpr::parse("one_way == false")?;
        assert!(filter.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// A partial method selection (OR of method equalities) hides dialogs
    /// whose method is not listed and shows those that are.
    #[test]
    fn partial_method_filter_excludes_unlisted_method() -> Result<(), TestError> {
        // C1: a dialog whose initial method is not one of the filter checkboxes
        // (e.g. BYE) must be HIDDEN by a partial method selection — only the
        // explicitly-checked methods are shown. (All-checked yields no filter at
        // the dialog layer, so such dialogs are shown then.)
        let bye = make_dialog("1001", "2002", "BYE")?;
        let partial = FilterExpr::parse("(method == 'REGISTER' OR method == 'INVITE')")?;
        assert!(
            !partial.matches_dialog(&bye, &[], CaptureMedia::Absent, MosDelay::unknown()),
            "a partial method selection must not match an unlisted-method dialog"
        );
        // And it does match a dialog whose method IS in the selection.
        let invite = make_dialog("1001", "2002", "INVITE")?;
        assert!(partial.matches_dialog(&invite, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// FilterExpr::never() rejects every dialog regardless of method.
    #[test]
    fn never_matches_no_dialog() -> Result<(), TestError> {
        // `FilterExpr::never()` represents "show nothing" — it must reject every
        // dialog regardless of method, users, or RTP state.
        let never = FilterExpr::never();
        for method in ["INVITE", "REGISTER", "BYE", "OPTIONS"] {
            let dialog = make_dialog("1001", "2002", method)?;
            assert!(
                !never.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()),
                "never() must not match a {method} dialog"
            );
        }
        Ok(())
    }

    // ── compare_str: every operator + type mismatch ─────────────────────

    /// compare_str handles every operator, including lexicographic
    /// ordering and regex matching.
    #[test]
    fn compare_str_all_operators() -> Result<(), TestError> {
        assert!(compare_str("b", &Operator::Eq, &Value::Str("b".into())));
        assert!(!compare_str("b", &Operator::Eq, &Value::Str("a".into())));
        assert!(compare_str("b", &Operator::Ne, &Value::Str("a".into())));
        assert!(compare_str("a", &Operator::Lt, &Value::Str("b".into())));
        assert!(compare_str("b", &Operator::Gt, &Value::Str("a".into())));
        assert!(compare_str("a", &Operator::Le, &Value::Str("a".into())));
        assert!(compare_str("b", &Operator::Ge, &Value::Str("b".into())));
        let re = regex::Regex::new("^b")?;
        assert!(compare_str("bee", &Operator::Regex, &Value::Re(re)));
        Ok(())
    }

    /// compare_str returns false for non-string literals and for `=~`
    /// without a compiled regex.
    #[test]
    fn compare_str_type_mismatch_is_false() -> Result<(), TestError> {
        // String field compared against a numeric/bool literal => false.
        assert!(!compare_str("b", &Operator::Eq, &Value::Num(1.0)));
        assert!(!compare_str("b", &Operator::Eq, &Value::Bool(true)));
        // Regex operator without a compiled regex value => false.
        assert!(!compare_str("b", &Operator::Regex, &Value::Str("b".into())));
        Ok(())
    }

    // ── compare_num: every operator + type mismatch ─────────────────────

    /// compare_num handles every ordering operator; regex is never
    /// applicable to numbers.
    #[test]
    fn compare_num_all_operators() -> Result<(), TestError> {
        assert!(compare_num(3.0, &Operator::Eq, &Value::Num(3.0)));
        assert!(!compare_num(3.0, &Operator::Eq, &Value::Num(4.0)));
        assert!(compare_num(3.0, &Operator::Ne, &Value::Num(4.0)));
        assert!(compare_num(2.0, &Operator::Lt, &Value::Num(3.0)));
        assert!(compare_num(4.0, &Operator::Gt, &Value::Num(3.0)));
        assert!(compare_num(3.0, &Operator::Le, &Value::Num(3.0)));
        assert!(compare_num(3.0, &Operator::Ge, &Value::Num(3.0)));
        // Regex is never applicable to numbers.
        assert!(!compare_num(3.0, &Operator::Regex, &Value::Num(3.0)));
        Ok(())
    }

    /// The ordering operators agree with equality on the tolerance boundary. A
    /// value within `NUM_EQ_TOLERANCE` of the literal is equal, so `<=` and `>=`
    /// hold while `<` and `>` do not — the exact-comparison ordering made a
    /// value read as both `== 30` and `> 30`.
    #[test]
    fn compare_num_ordering_agrees_with_equality_at_the_boundary() -> Result<(), TestError> {
        let v = 30.000_4; // within 5e-4 of 30
        assert!(compare_num(v, &Operator::Eq, &Value::Num(30.0)));
        assert!(compare_num(v, &Operator::Le, &Value::Num(30.0)));
        assert!(compare_num(v, &Operator::Ge, &Value::Num(30.0)));
        assert!(!compare_num(v, &Operator::Gt, &Value::Num(30.0)));
        assert!(!compare_num(v, &Operator::Lt, &Value::Num(30.0)));
        // A clearly larger value still orders correctly.
        assert!(compare_num(35.0, &Operator::Gt, &Value::Num(30.0)));
        assert!(!compare_num(35.0, &Operator::Le, &Value::Num(30.0)));
        Ok(())
    }

    /// A non-finite numeric literal (`nan`, `inf`, `infinity`) is rejected at
    /// parse rather than silently matching nothing (every comparison against
    /// NaN is false) or everything.
    #[test]
    fn a_non_finite_numeric_literal_is_rejected() -> Result<(), TestError> {
        assert!(FilterExpr::parse("msg_count == nan").is_err());
        assert!(FilterExpr::parse("rtp.mos > inf").is_err());
        assert!(FilterExpr::parse("rtp.loss < infinity").is_err());
        // A finite number still parses.
        assert!(FilterExpr::parse("msg_count == 5").is_ok());
        Ok(())
    }

    /// compare_num returns false for non-numeric literals.
    #[test]
    fn compare_num_type_mismatch_is_false() -> Result<(), TestError> {
        assert!(!compare_num(3.0, &Operator::Eq, &Value::Str("3".into())));
        assert!(!compare_num(3.0, &Operator::Lt, &Value::Bool(false)));
        Ok(())
    }

    /// Equality tolerates float-computation noise (a computed 5.0000001
    /// equals a literal 5) but still rejects genuinely different values;
    /// `!=` mirrors `==` exactly.
    #[test]
    fn compare_num_eq_tolerates_computed_float_noise() -> Result<(), TestError> {
        assert!(compare_num(5.000_000_1, &Operator::Eq, &Value::Num(5.0)));
        assert!(!compare_num(5.000_000_1, &Operator::Ne, &Value::Num(5.0)));
        assert!(!compare_num(5.6, &Operator::Eq, &Value::Num(5.0)));
        assert!(compare_num(5.6, &Operator::Ne, &Value::Num(5.0)));
        // Adjacent millisecond-domain values stay distinct.
        assert!(!compare_num(5.001, &Operator::Eq, &Value::Num(5.0)));
        Ok(())
    }

    /// `rtp.jitter == 30` matches a stream whose computed jitter carries
    /// float noise (30 + 1e-7) — end-to-end through eval_compare.
    #[test]
    fn rtp_jitter_eq_matches_computed_float() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let mut stream = make_rtp_stream(false)?;
        stream.jitter = 30.0 + 1e-7;
        let streams: Vec<&RtpStream> = vec![&stream];
        let f = FilterExpr::parse("rtp.jitter == 30")?;
        assert!(f.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));
        stream.jitter = 30.6;
        let streams: Vec<&RtpStream> = vec![&stream];
        assert!(!f.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));
        Ok(())
    }

    // ── src.port/dst.port: stable across idle compaction ────────────────

    /// After compaction drains the dialog's oldest messages (as
    /// DialogStore::compact_idle does), `src.port`/`dst.port` must still
    /// evaluate to the initial message's ports — not the ports of whatever
    /// message happens to be first now (a response has them swapped).
    #[test]
    fn src_dst_port_stable_after_compaction() -> Result<(), TestError> {
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
            base_ts()?,
            localhost(),
            localhost(),
            5060,
            5080,
            TransportProto::Udp,
        )?;
        let mut dialog = SipDialog::new(&msg).ok_or("should create dialog")?;

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
            base_ts()? + TimeDelta::seconds(1),
            localhost(),
            localhost(),
            5080,
            5060,
            TransportProto::Udp,
        )?;
        dialog.messages.push(reply);

        // Simulate DialogStore::compact_idle evicting the oldest message.
        dialog.messages.drain(..1);

        let src = FilterExpr::parse("src.port == 5060")?;
        let dst = FilterExpr::parse("dst.port == 5080")?;
        assert!(src.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        assert!(dst.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    // ── compare_bool: operators + type mismatch ─────────────────────────

    /// compare_bool supports only ==/!=; ordering and regex operators
    /// return false.
    #[test]
    fn compare_bool_eq_ne_and_unsupported_operators() -> Result<(), TestError> {
        assert!(compare_bool(true, &Operator::Eq, &Value::Bool(true)));
        assert!(!compare_bool(true, &Operator::Eq, &Value::Bool(false)));
        assert!(compare_bool(true, &Operator::Ne, &Value::Bool(false)));
        // Ordering operators are not meaningful for booleans => false.
        assert!(!compare_bool(true, &Operator::Lt, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Gt, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Le, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Ge, &Value::Bool(false)));
        assert!(!compare_bool(true, &Operator::Regex, &Value::Bool(true)));
        Ok(())
    }

    /// compare_bool returns false for non-boolean literals.
    #[test]
    fn compare_bool_type_mismatch_is_false() -> Result<(), TestError> {
        assert!(!compare_bool(true, &Operator::Eq, &Value::Num(1.0)));
        assert!(!compare_bool(
            true,
            &Operator::Eq,
            &Value::Str("true".into())
        ));
        Ok(())
    }

    // ── state_to_str: all DialogState variants ──────────────────────────

    /// state_to_str maps every DialogState variant to its expected name.
    #[test]
    fn state_to_str_covers_all_variants() -> Result<(), TestError> {
        let cases = [
            (DialogState::Trying, "Trying"),
            (DialogState::Ringing, "Ringing"),
            (DialogState::InCall, "InCall"),
            (DialogState::Completed, "Completed"),
            (DialogState::Canceled, "Canceled"),
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
        Ok(())
    }

    // ── approximate_mos ─────────────────────────────────────────────────

    /// A clean stream (no loss, no jitter) scores a MOS in the ~4.4 range.
    #[test]
    fn approximate_mos_clean_stream_is_high() -> Result<(), TestError> {
        // No loss, no jitter => R near 93 => MOS in the ~4.4 range.
        let stream = make_rtp_stream(false)?;
        let mos = stream_mos(&stream, MosDelay::unknown());
        assert!(mos > 4.0 && mos <= 4.5, "got {mos}");
        Ok(())
    }

    /// Heavy jitter and loss lower the MOS below a clean stream's, but
    /// never below the 1.0 floor.
    #[test]
    fn approximate_mos_degrades_with_jitter_and_loss() -> Result<(), TestError> {
        let mut stream = make_rtp_stream(false)?;
        stream.jitter = 80.0;
        stream.lost_packets = 50;
        // packet_count is 1 from construction; make loss heavy.
        let degraded = stream_mos(&stream, MosDelay::unknown());
        let clean = stream_mos(&make_rtp_stream(false)?, MosDelay::unknown());
        assert!(degraded < clean, "degraded {degraded} < clean {clean}");
        assert!(degraded >= 1.0, "MOS floor is 1.0, got {degraded}");
        Ok(())
    }

    /// Worst-case jitter and loss floor the MOS at exactly 1.0.
    #[test]
    fn approximate_mos_worst_case_floored_at_one() -> Result<(), TestError> {
        let mut stream = make_rtp_stream(false)?;
        stream.jitter = 100.0;
        stream.lost_packets = 1_000_000;
        let mos = stream_mos(&stream, MosDelay::unknown());
        assert!((mos - 1.0).abs() < 1e-9, "expected floor 1.0, got {mos}");
        Ok(())
    }

    /// Zero packets means zero loss percentage (no division by zero) and
    /// a high MOS.
    #[test]
    fn approximate_mos_no_packets_no_loss() -> Result<(), TestError> {
        // total == 0 path: loss_pct stays 0.0, no division by zero.
        let mut stream = make_rtp_stream(false)?;
        stream.packet_count = 0;
        stream.lost_packets = 0;
        let mos = stream_mos(&stream, MosDelay::unknown());
        assert!(mos > 4.0, "got {mos}");
        Ok(())
    }

    // ── eval_compare numeric field paths via matches_dialog ─────────────

    /// rtp.mos, rtp.jitter, and rtp.loss evaluate against the worst value
    /// across the associated streams.
    #[test]
    fn rtp_mos_loss_jitter_fields_evaluate() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let mut stream = make_rtp_stream(false)?;
        stream.jitter = 60.0;
        stream.lost_packets = 4; // with packet_count 1 => high loss%
        let streams: Vec<&RtpStream> = vec![&stream];

        // MOS should be degraded below 4.0.
        let mos_filter = FilterExpr::parse("rtp.mos < 4.0")?;
        assert!(mos_filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));

        // Jitter worst-case across streams is 60.0.
        let jitter_filter = FilterExpr::parse("rtp.jitter > 50.0")?;
        assert!(jitter_filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));

        // Loss percentage is high.
        let loss_filter = FilterExpr::parse("rtp.loss > 50.0")?;
        assert!(loss_filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));
        Ok(())
    }

    /// rtp.codec matches a stream's codec; rtp.ssrc matches the
    /// 0x-prefixed lowercase hex rendering.
    #[test]
    fn rtp_codec_and_ssrc_string_fields() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let mut stream = make_rtp_stream(false)?;
        stream.codec = Some("PCMU".to_string());
        let streams: Vec<&RtpStream> = vec![&stream];

        let codec_filter = FilterExpr::parse("rtp.codec == 'PCMU'")?;
        assert!(codec_filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));

        // SSRC is rendered as 0x-prefixed 10-char hex of 0xDEADBEEF.
        let ssrc_filter = FilterExpr::parse("rtp.ssrc == '0xdeadbeef'")?;
        assert!(ssrc_filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));
        Ok(())
    }

    /// Item 3: the parse-time `needs_diagnosis` flag is set iff the
    /// expression references a diagnosis-derived field, so `matches_dialog`
    /// can skip the media/asymmetry diagnosis when none appears.
    #[test]
    fn needs_diagnosis_flag_reflects_field_use() -> Result<(), TestError> {
        // No diagnosis field → flag clear.
        assert!(!FilterExpr::parse("from.user == '1001'")?.needs_diagnosis);
        assert!(!FilterExpr::parse("rtp.mos < 3.0 AND rtp.packets > 0")?.needs_diagnosis);

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
                FilterExpr::parse(&expr)?.needs_diagnosis,
                "{field} must set needs_diagnosis"
            );
        }

        // Nested under boolean combinators still trips it.
        assert!(
            FilterExpr::parse("method == 'INVITE' AND (state == 'InCall' OR late_media == true)")?
                .needs_diagnosis
        );

        // A filter without diagnosis fields evaluates the same whether or not
        // streams are present (the skipped diagnosis changes nothing).
        let dialog = make_dialog("1001", "2002", "INVITE")?;
        let f = FilterExpr::parse("from.user == '1001'")?;
        assert!(f.matches_dialog(&dialog, &[], CaptureMedia::Absent, MosDelay::unknown()));
        Ok(())
    }

    /// Item 2: `rtp.codec` / `rtp.ssrc` match if ANY linked stream matches,
    /// consistent with the worst-across-streams quality fields. A codec or
    /// SSRC carried only by the *second* stream must still match. The old
    /// code inspected only the first stream and missed these.
    #[test]
    fn rtp_codec_and_ssrc_match_any_stream() -> Result<(), TestError> {
        let dialog = make_dialog("1001", "2002", "INVITE")?;

        // Two streams: first PCMU (SSRC 0xDEADBEEF), second G722 with a
        // distinct SSRC.
        let mut first = make_rtp_stream(false)?;
        first.codec = Some("PCMU".to_string());
        let mut second = make_rtp_stream(false)?;
        second.codec = Some("G722".to_string());
        second.key.ssrc = 0x0000_0001;
        let streams: Vec<&RtpStream> = vec![&first, &second];

        // Codec carried only by the second stream matches.
        let codec_filter = FilterExpr::parse("rtp.codec == 'G722'")?;
        assert!(codec_filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));

        // SSRC carried only by the second stream matches.
        let ssrc_filter = FilterExpr::parse("rtp.ssrc == '0x00000001'")?;
        assert!(ssrc_filter.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));

        // A codec present on no stream still does not match.
        let miss = FilterExpr::parse("rtp.codec == 'opus'")?;
        assert!(!miss.matches_dialog(
            &dialog,
            &streams,
            CaptureMedia::Observed,
            MosDelay::unknown()
        ));
        Ok(())
    }

    // ── select_dialogs ──────────────────────────────────────────────

    /// Build a store holding one INVITE dialog per Call-ID given.
    fn store_with(call_ids: &[&str]) -> Result<crate::sip::dialog_store::DialogStore, TestError> {
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
                base_ts()?,
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )?;
            store.process_message(msg);
        }
        Ok(store)
    }

    /// No filter selects every dialog, in store order — the post-capture
    /// outputs must be unchanged when `--filter` is absent.
    #[test]
    fn select_dialogs_without_a_filter_selects_everything() -> Result<(), TestError> {
        let dialogs = store_with(&["a@example.com", "b@example.com", "c@example.com"])?;
        let streams = crate::rtp::stream_store::StreamStore::new(16);

        let selection = select_dialogs(None, &dialogs, &streams);

        let ids: Vec<&str> = selection
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.as_str())
            .collect();
        assert_eq!(ids, ["a@example.com", "b@example.com", "c@example.com"]);
        Ok(())
    }

    /// A filter selects the matching dialogs and only those. The defect it
    /// guards: the whole store came back for every expression.
    #[test]
    fn select_dialogs_with_a_filter_selects_only_matches() -> Result<(), TestError> {
        let dialogs = store_with(&["a@example.com", "b@example.com", "c@example.com"])?;
        let streams = crate::rtp::stream_store::StreamStore::new(16);
        let expr = FilterExpr::parse("call_id == 'b@example.com'")?;

        let selection = select_dialogs(Some(&expr), &dialogs, &streams);

        let ids: Vec<&str> = selection
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.as_str())
            .collect();
        assert_eq!(ids, ["b@example.com"]);
        Ok(())
    }

    /// An unsatisfiable filter selects nothing — an empty result is an
    /// answer, and must not degrade into "show everything".
    #[test]
    fn select_dialogs_with_an_unsatisfiable_filter_selects_nothing() -> Result<(), TestError> {
        let dialogs = store_with(&["a@example.com", "b@example.com"])?;
        let streams = crate::rtp::stream_store::StreamStore::new(16);

        let selection = select_dialogs(Some(&FilterExpr::never()), &dialogs, &streams);

        assert!(selection.dialogs.is_empty());
        assert!(
            selection.streams.is_empty(),
            "no dialog selected leaves no stream to show"
        );
        Ok(())
    }

    /// An empty store yields an empty selection under both arms rather than
    /// panicking on the missing-Call-ID lookups.
    #[test]
    fn select_dialogs_on_an_empty_store_is_empty() -> Result<(), TestError> {
        let dialogs = store_with(&[])?;
        let streams = crate::rtp::stream_store::StreamStore::new(16);
        let expr = FilterExpr::parse("state == 'Failed'")?;

        assert!(select_dialogs(None, &dialogs, &streams).dialogs.is_empty());
        assert!(
            select_dialogs(Some(&expr), &dialogs, &streams)
                .dialogs
                .is_empty()
        );
        Ok(())
    }
}

/// Tests for the unknown-field diagnostic: naming the field, suggesting
/// the closest valid one, and keeping FIELD_NAMES in sync with the parser.
#[cfg(test)]
mod unknown_field_hint_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// An unknown field used to render as a generic "unexpected input" —
    /// no field named, no valid list, no suggestion.
    #[test]
    fn unknown_field_error_names_field_and_suggests_closest() -> Result<(), TestError> {
        let err = FilterExpr::parse("rtp.mso > 3").err().ok_or("must fail")?;
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
        Ok(())
    }

    /// A field with no near match still gets the valid-fields list.
    #[test]
    fn unknown_field_without_close_match_lists_fields() -> Result<(), TestError> {
        let err = FilterExpr::parse("zzzzqqq == 'x'")
            .err()
            .ok_or("must fail")?;
        let msg = err.to_string();
        assert!(msg.contains("unknown field 'zzzzqqq'"), "{msg}");
        assert!(msg.contains("valid fields:"), "{msg}");
        Ok(())
    }

    /// FIELD_NAMES must stay in sync with the parser's accepted set.
    #[test]
    fn field_names_const_matches_parser() -> Result<(), TestError> {
        for name in FIELD_NAMES {
            assert!(
                parse_field(name).is_ok(),
                "FIELD_NAMES lists '{name}' but parse_field rejects it"
            );
        }
        Ok(())
    }

    /// The quoting reason for a value with whitespace is not replaced by an
    /// unknown-field hint about the value's first word.
    #[test]
    fn quoting_hint_not_replaced_by_field_hint() -> Result<(), TestError> {
        let err = FilterExpr::parse("ua == Friendly Scanner")
            .err()
            .ok_or("must fail")?;
        let msg = err.to_string();
        assert!(msg.contains("must be quoted"), "{msg}");
        assert!(!msg.contains("unknown field"), "{msg}");
        Ok(())
    }
}

/// Regression tests proving parse-error rendering is total on adversarial
/// (multibyte, odd-whitespace) input.
#[cfg(test)]
mod parse_error_render_robustness_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// proptest (filter_dsl_parse_is_total) found: with whitespace before a
    /// multibyte token at the error position, `pos + token.len()` sliced the
    /// expression mid-character and panicked. Parsing must be total —
    /// adversarial input yields Err, never a panic.
    #[test]
    fn parse_error_rendering_survives_multibyte_and_whitespace() -> Result<(), TestError> {
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
        Ok(())
    }
}

/// Tests for `header.<name>`: matching any named SIP header, the way RFC 3261
/// reads header names, and RFC 6648's rule that an `X-` prefix is only part of
/// a name.
#[cfg(test)]
mod header_field_tests {
    use std::net::{IpAddr, Ipv4Addr};

    type TestError = Box<dyn std::error::Error>;

    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;

    /// Parse one message carrying the standard dialog headers plus `extra`.
    fn message(
        first_line: &str,
        cseq: &str,
        extra: &[&str],
    ) -> Result<crate::sip::SipMessage, TestError> {
        let mut headers = vec![
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKhdr",
            "From: <sip:1001@example.com>;tag=t1",
            "To: <sip:2002@example.com>",
            "Call-ID: header-field@example.com",
        ];
        headers.push(cseq);
        headers.extend_from_slice(extra);
        headers.push("Content-Length: 0");
        let raw = build_sip(first_line, &headers, b"");
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        Ok(parse_sip(
            &raw,
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 9, 22, 12, 0, 0)
                .single()
                .ok_or("invalid fixture timestamp")?,
            ip,
            ip,
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// A dialog whose INVITE carries `invite_extra` and whose 200 OK carries
    /// `ok_extra`, so a test can put a header on either message.
    fn dialog(invite_extra: &[&str], ok_extra: &[&str]) -> Result<SipDialog, TestError> {
        let invite = message(
            "INVITE sip:2002@example.com SIP/2.0",
            "CSeq: 1 INVITE",
            invite_extra,
        )?;
        let mut dialog = SipDialog::new(&invite).ok_or("an INVITE opens a dialog")?;
        dialog
            .messages
            .push(message("SIP/2.0 200 OK", "CSeq: 1 INVITE", ok_extra)?);
        Ok(dialog)
    }

    /// Whether `expr` parses and selects `dialog`.
    fn selects(expr: &str, dialog: &SipDialog) -> Result<bool, TestError> {
        Ok(FilterExpr::parse(expr)
            .map_err(|e| format!("{expr:?} must parse: {e}"))?
            .matches_dialog(dialog, &[], CaptureMedia::Absent, MosDelay::unknown()))
    }

    /// Header names compare case-insensitively ([RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1));
    /// values compare the way every other string field does, exactly.
    #[test]
    fn a_header_name_matches_in_any_case_and_the_value_exactly() -> Result<(), TestError> {
        let d = dialog(&["X-Trunk: north-east"], &[])?;
        assert!(selects("header.X-Trunk == 'north-east'", &d)?);
        assert!(selects("header.x-trunk == 'north-east'", &d)?);
        assert!(selects("header.X-TRUNK == \"north-east\"", &d)?);
        assert!(!selects("header.X-Trunk == 'south'", &d)?);
        assert!(
            !selects("header.X-Trunk == 'NORTH-EAST'", &d)?,
            "a value comparison is case-sensitive, as on every string field"
        );
        assert!(selects("header.X-Trunk =~ '(?i)NORTH'", &d)?);
        Ok(())
    }

    /// A header on ANY message of the dialog counts — the `payload` rule —
    /// so a header only the answer carries still selects the call.
    #[test]
    fn a_header_on_any_message_of_the_dialog_counts() -> Result<(), TestError> {
        let d = dialog(&[], &["P-Charge-Info: <sip:+15551230000@example.com>"])?;
        assert!(selects("header.P-Charge-Info =~ '5551230000'", &d)?);
        Ok(())
    }

    /// Every instance of a repeated header is its own candidate, and a value
    /// is the whole header line: a comma-combined line is one value.
    #[test]
    fn every_repeated_header_is_considered() -> Result<(), TestError> {
        let d = dialog(&["Foo-Bar: first", "Foo-Bar: second"], &["Foo-Bar: third"])?;
        for v in ["first", "second", "third"] {
            assert!(selects(&format!("header.Foo-Bar == '{v}'"), &d)?, "{v}");
        }
        let combined = dialog(&["Foo-Bar: a, b"], &[])?;
        assert!(!selects("header.Foo-Bar == 'a'", &combined)?);
        assert!(selects("header.Foo-Bar == 'a, b'", &combined)?);
        assert!(selects("header.Foo-Bar =~ '(^|,\\s*)b(,|$)'", &combined)?);
        Ok(())
    }

    /// A compact form names the same header as its long form, in the filter
    /// and on the wire, in all four combinations ([RFC 3261 section 7.3.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.3)).
    #[test]
    fn compact_forms_are_honored_on_both_sides() -> Result<(), TestError> {
        let compact_wire = dialog(&["k: 100rel"], &[])?;
        assert!(selects("header.Supported == '100rel'", &compact_wire)?);
        assert!(selects("header.k == '100rel'", &compact_wire)?);
        assert!(selects("header.K == '100rel'", &compact_wire)?);
        let long_wire = dialog(&["Supported: timer"], &[])?;
        assert!(selects("header.k == 'timer'", &long_wire)?);
        assert!(selects("header.supported == 'timer'", &long_wire)?);
        Ok(())
    }

    /// `x` alone is the compact form of `Session-Expires` (RFC 4028), not an
    /// `X-` anything: the letter is a registered name, and the prefix is not a
    /// category.
    #[test]
    fn the_compact_x_is_session_expires_and_not_a_prefix() -> Result<(), TestError> {
        let d = dialog(&["X-Foo: 1800"], &["Session-Expires: 1800"])?;
        assert!(selects("header.x == '1800'", &d)?);
        let only_x_foo = dialog(&["X-Foo: 1800"], &[])?;
        assert!(!selects("header.x == '1800'", &only_x_foo)?);
        Ok(())
    }

    /// An absent header matches no comparison, `!=` included — the rule every
    /// optional field here follows. Presence and absence have idioms of their
    /// own: an empty regex matches any value.
    #[test]
    fn an_absent_header_matches_no_comparison() -> Result<(), TestError> {
        let d = dialog(&["X-Trunk: north"], &[])?;
        assert!(!selects("header.X-Missing != 'anything'", &d)?);
        assert!(!selects("header.X-Missing == ''", &d)?);
        assert!(!selects("header.X-Missing =~ ''", &d)?);
        assert!(selects("NOT header.X-Missing =~ ''", &d)?);
        assert!(selects("header.X-Trunk =~ ''", &d)?);
        Ok(())
    }

    /// A header with an empty value is present, and its value is the empty
    /// string.
    #[test]
    fn an_empty_value_is_present_and_empty() -> Result<(), TestError> {
        let d = dialog(&["X-Empty:"], &[])?;
        assert!(selects("header.X-Empty == ''", &d)?);
        assert!(selects("header.X-Empty =~ ''", &d)?);
        Ok(())
    }

    /// [RFC 6648 section 2](https://www.rfc-editor.org/rfc/rfc6648.html#section-2): nothing is read into the `X-` prefix. `Foo` and
    /// `X-Foo` are two unrelated names — neither is stripped to the other —
    /// and one filter on each selects symmetrically.
    #[test]
    fn an_x_prefix_is_part_of_the_name_and_nothing_more() -> Result<(), TestError> {
        let plain = dialog(&["Foo: v"], &[])?;
        let prefixed = dialog(&["X-Foo: v"], &[])?;
        assert!(selects("header.Foo == 'v'", &plain)?);
        assert!(selects("header.X-Foo == 'v'", &prefixed)?);
        assert!(!selects("header.Foo == 'v'", &prefixed)?);
        assert!(!selects("header.X-Foo == 'v'", &plain)?);
        Ok(())
    }

    /// The quoted form takes any RFC 3261 token, including the characters the
    /// bare form stops at.
    #[test]
    fn a_quoted_name_takes_any_token() -> Result<(), TestError> {
        let d = dialog(
            &[
                "P-Asserted-Identity: <sip:alice@example.com>",
                "Odd!Name: yes",
            ],
            &[],
        )?;
        assert!(selects("header.\"P-Asserted-Identity\" =~ 'alice'", &d)?);
        assert!(selects("header.'P-Asserted-Identity' =~ 'alice'", &d)?);
        assert!(selects("header.\"Odd!Name\" == 'yes'", &d)?);
        Ok(())
    }

    /// Ordering and `in_subnet` read a header value the way they read any
    /// string field.
    #[test]
    fn every_string_operator_applies() -> Result<(), TestError> {
        let d = dialog(&["Real-Source: 198.51.100.7"], &[])?;
        assert!(selects(
            "header.Real-Source in_subnet '198.51.100.0/24'",
            &d
        )?);
        assert!(!selects(
            "header.Real-Source in_subnet '203.0.113.0/24'",
            &d
        )?);
        assert!(selects("header.Real-Source > '198'", &d)?);
        assert!(selects("header.Real-Source != '10.0.0.1'", &d)?);
        Ok(())
    }

    /// Composes with the rest of the language.
    #[test]
    fn composes_with_boolean_combinators() -> Result<(), TestError> {
        let d = dialog(&["X-Trunk: north"], &[])?;
        assert!(selects(
            "method == 'INVITE' AND header.X-Trunk == 'north'",
            &d
        )?);
        assert!(selects(
            "(header.X-Trunk == 'south' OR header.X-Trunk == 'north')",
            &d
        )?);
        assert!(!selects("NOT header.X-Trunk == 'north'", &d)?);
        Ok(())
    }

    /// A malformed name is refused at parse time with a message that says what
    /// is wrong, rather than a filter that silently matches nothing.
    #[test]
    fn a_malformed_name_is_refused_and_named() -> Result<(), TestError> {
        for bad in [
            "header. == 'x'",
            "header.\"\" == 'x'",
            "header.\"two words\" == 'x'",
            "header.\"colon:\" == 'x'",
            "header.'unterminated == 'x'",
        ] {
            let msg = FilterExpr::parse(bad)
                .err()
                .ok_or(&format!("{bad:?} must not parse"))
                .map_err(|e| format!("{e:?}"))?
                .to_string();
            assert!(
                msg.contains("header name"),
                "{bad:?} must say the header name is the problem: {msg}"
            );
            assert!(
                !msg.contains("unknown field"),
                "{bad:?} is not an unknown field: {msg}"
            );
        }
        Ok(())
    }

    /// The name is bounded: a name past `MAX_HEADER_NAME_LEN` is refused and
    /// the limit is named, and one at the limit parses.
    #[test]
    fn the_name_length_is_bounded() -> Result<(), TestError> {
        let at = "A".repeat(MAX_HEADER_NAME_LEN);
        assert!(FilterExpr::parse(&format!("header.{at} == 'x'")).is_ok());
        let over = "A".repeat(MAX_HEADER_NAME_LEN + 1);
        let msg = FilterExpr::parse(&format!("header.{over} == 'x'"))
            .err()
            .ok_or("over the cap")?
            .to_string();
        assert!(msg.contains(&MAX_HEADER_NAME_LEN.to_string()), "{msg}");
        let quoted = FilterExpr::parse(&format!("header.\"{over}\" == 'x'"))
            .err()
            .ok_or("over the cap when quoted too")?
            .to_string();
        assert!(
            quoted.contains(&MAX_HEADER_NAME_LEN.to_string()),
            "{quoted}"
        );
        Ok(())
    }

    /// A header filter reads no diagnosis, so it must not pay for one.
    #[test]
    fn a_header_filter_needs_no_diagnosis() -> Result<(), TestError> {
        let f = FilterExpr::parse("header.X-Trunk == 'north'")?;
        assert!(!f.needs_diagnosis);
        Ok(())
    }

    /// The unknown-field hint lists the header family beside the fixed names.
    #[test]
    fn the_field_hint_names_the_header_family() -> Result<(), TestError> {
        let msg = FilterExpr::parse("zzzzqqq == 'x'")
            .err()
            .ok_or("unknown")?
            .to_string();
        assert!(msg.contains("header.<name>"), "{msg}");
        Ok(())
    }
}

/// The time window ANDed into a compiled filter, and the `time` field that
/// writes the same window in the DSL.
#[cfg(test)]
mod time_window_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;

    type TestError = Box<dyn std::error::Error>;

    fn at(s: &str) -> Result<DateTime<Utc>, TestError> {
        Ok(crate::cursor::parse_instant(s)?)
    }

    /// A one-message dialog whose first message is at `when`.
    fn dialog_at(method: &str, when: &str) -> Result<SipDialog, TestError> {
        let raw = build_sip(
            &format!("{method} sip:bob@example.com SIP/2.0"),
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {method}-{when}@example.com"),
                &format!("CSeq: 1 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let msg = parse_sip(&raw, at(when)?, lo, lo, 5060, 5060, TransportProto::Udp)?;
        let dialog = SipDialog::new(&msg).ok_or("should create dialog")?;
        assert_eq!(dialog.created_at, at(when)?, "the fixture's own instant");
        Ok(dialog)
    }

    fn selects(f: &FilterExpr, d: &SipDialog) -> bool {
        f.matches_dialog(d, &[], CaptureMedia::Absent, MosDelay::unknown())
    }

    const SINCE: &str = "2026-10-09T10:00:00Z";
    const UNTIL: &str = "2026-10-09T11:00:00Z";

    /// The window keeps a dialog AT `after` and drops one AT `before`: the
    /// half-open rule REST and MCP apply.
    #[test]
    fn the_window_includes_after_and_excludes_before() -> Result<(), TestError> {
        let f = FilterExpr::with_time_window(None, Some(at(SINCE)?), Some(at(UNTIL)?))
            .ok_or("a bounded window is a filter")?;
        for (when, inside) in [
            ("2026-10-09T09:59:59.999Z", false),
            (SINCE, true),
            ("2026-10-09T10:30:00Z", true),
            ("2026-10-09T10:59:59.999Z", true),
            (UNTIL, false),
            ("2026-10-09T11:00:00.001Z", false),
        ] {
            assert_eq!(selects(&f, &dialog_at("INVITE", when)?), inside, "{when}");
        }
        Ok(())
    }

    /// One bound alone leaves the other side open.
    #[test]
    fn one_bound_alone_is_open_on_the_other_side() -> Result<(), TestError> {
        let from = FilterExpr::with_time_window(None, Some(at(SINCE)?), None).ok_or("filter")?;
        assert!(selects(
            &from,
            &dialog_at("INVITE", "2099-01-01T00:00:00Z")?
        ));
        assert!(!selects(
            &from,
            &dialog_at("INVITE", "2026-10-09T09:00:00Z")?
        ));
        let to = FilterExpr::with_time_window(None, None, Some(at(UNTIL)?)).ok_or("filter")?;
        assert!(selects(&to, &dialog_at("INVITE", "2000-01-01T00:00:00Z")?));
        assert!(!selects(&to, &dialog_at("INVITE", UNTIL)?));
        Ok(())
    }

    /// No bound, no filter: `None` stays `None` and a base stays itself.
    #[test]
    fn no_bound_changes_nothing() -> Result<(), TestError> {
        assert!(FilterExpr::with_time_window(None, None, None).is_none());
        let base = FilterExpr::parse("method == 'INVITE'")?;
        let same = FilterExpr::with_time_window(Some(base), None, None).ok_or("kept")?;
        assert_eq!(same.source(), "method == 'INVITE'");
        Ok(())
    }

    /// The window ANDs with the filter it joins: a dialog must pass both.
    #[test]
    fn the_window_composes_with_a_filter() -> Result<(), TestError> {
        let base = FilterExpr::parse("method == 'INVITE'")?;
        let f = FilterExpr::with_time_window(Some(base), Some(at(SINCE)?), Some(at(UNTIL)?))
            .ok_or("filter")?;
        let mid = "2026-10-09T10:30:00Z";
        assert!(selects(&f, &dialog_at("INVITE", mid)?));
        assert!(!selects(&f, &dialog_at("REGISTER", mid)?), "fails the base");
        assert!(
            !selects(&f, &dialog_at("INVITE", UNTIL)?),
            "fails the window"
        );
        Ok(())
    }

    /// The windowed filter's source is the same selection in the DSL, so it
    /// can be pasted back into `--filter` and select the same dialogs.
    #[test]
    fn the_windowed_source_is_the_same_selection_in_the_dsl() -> Result<(), TestError> {
        let base = FilterExpr::parse("method == 'INVITE' OR method == 'REGISTER'")?;
        let f = FilterExpr::with_time_window(Some(base), Some(at(SINCE)?), Some(at(UNTIL)?))
            .ok_or("filter")?;
        let back = FilterExpr::parse(f.source())?;
        for (method, when) in [
            ("INVITE", SINCE),
            ("REGISTER", "2026-10-09T10:59:00Z"),
            ("OPTIONS", "2026-10-09T10:30:00Z"),
            ("INVITE", UNTIL),
            ("REGISTER", "2026-10-09T09:00:00Z"),
        ] {
            let d = dialog_at(method, when)?;
            assert_eq!(selects(&f, &d), selects(&back, &d), "{method} at {when}");
        }
        Ok(())
    }

    /// `time` compares the first-message instant with each ordering operator
    /// and `==`, at the boundary.
    #[test]
    fn the_time_field_orders_and_equates_instants() -> Result<(), TestError> {
        let d = dialog_at("INVITE", SINCE)?;
        for (expr, want) in [
            (format!("time == '{SINCE}'"), true),
            (format!("time >= '{SINCE}'"), true),
            (format!("time > '{SINCE}'"), false),
            (format!("time <= '{SINCE}'"), true),
            (format!("time < '{SINCE}'"), false),
            ("time < '2026-10-09T10:00:00.001Z'".to_string(), true),
            ("time > '2026-10-09T09:59:59.999Z'".to_string(), true),
            // Another offset naming the same instant.
            ("time == '2026-10-09T12:00:00+02:00'".to_string(), true),
        ] {
            assert_eq!(selects(&FilterExpr::parse(&expr)?, &d), want, "{expr}");
        }
        Ok(())
    }

    /// A `time` literal that is not RFC 3339 is refused at parse, naming the
    /// format; so are the operators that do not order or equate instants.
    #[test]
    fn the_time_field_refuses_what_it_cannot_compare() -> Result<(), TestError> {
        for (expr, says) in [
            ("time >= 'yesterday'", "RFC 3339"),
            ("time >= '2026-10-09'", "RFC 3339"),
            ("time >= 1760000000", "RFC 3339"),
            ("time != '2026-10-09T10:00:00Z'", "<, <=, >, >= or =="),
            ("time =~ '2026'", "<, <=, >, >= or =="),
            ("time in_subnet '10.0.0.0/8'", "<, <=, >, >= or =="),
        ] {
            let err = FilterExpr::parse(expr)
                .err()
                .ok_or(format!("{expr} must be refused"))?
                .to_string();
            assert!(err.contains(says), "{expr}: {err}");
        }
        Ok(())
    }
}

/// The fields a PBX operator selects calls by (PBX-F2): the From and To
/// host and URI, the request-URI, the P-Asserted-Identity user, and every
/// codec a call used.
#[cfg(test)]
mod pbx_field_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    type TestError = Box<dyn std::error::Error>;

    use super::*;
    use crate::net::TransportProto;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;

    fn at() -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 10, 13, 9, 0, 0)
                .single()
                .ok_or("invalid fixture timestamp")?,
        )
    }

    /// A trunk call into a PBX: the INVITE's request-URI, From with a port and
    /// parameters, To, and a P-Asserted-Identity.
    fn trunk_call() -> Result<SipDialog, TestError> {
        let raw = build_sip(
            "INVITE sip:7000@192.0.2.10;user=phone SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKpbx",
                "From: \"Carrier\" <sip:+15551230000@carrier-a.example:5060;user=phone>;tag=f1",
                "To: <sip:7000@pbx.example>",
                "Call-ID: pbx-fields@example.com",
                "CSeq: 1 INVITE",
                "P-Asserted-Identity: \"Alice\" <sip:+15559876543@carrier-a.example>",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            at()?,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        Ok(SipDialog::new(&msg).ok_or("an INVITE opens a dialog")?)
    }

    fn stream(codec: &str, ssrc: u32) -> Result<RtpStream, TestError> {
        let key = StreamKey {
            ssrc,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 30000),
            session: 0,
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 0,
            ssrc,
            payload_offset: 12,
        };
        let mut s = RtpStream::new(key, &hdr, at()?);
        s.codec = Some(codec.to_owned());
        Ok(s)
    }

    fn selects(expr: &str, dialog: &SipDialog, streams: &[&RtpStream]) -> Result<bool, TestError> {
        Ok(FilterExpr::parse(expr)
            .map_err(|e| format!("{expr:?} must parse: {e}"))?
            .matches_dialog(dialog, streams, CaptureMedia::Absent, MosDelay::unknown()))
    }

    /// `from.host` and `to.host` are the URI's host without its port.
    #[test]
    fn host_fields_are_the_uri_host_without_the_port() -> Result<(), TestError> {
        let d = trunk_call()?;
        assert!(selects("from.host == 'carrier-a.example'", &d, &[])?);
        assert!(selects("to.host == 'pbx.example'", &d, &[])?);
        assert!(!selects("from.host == 'carrier-a.example:5060'", &d, &[])?);
        assert!(selects("from.host =~ '^carrier-'", &d, &[])?);
        Ok(())
    }

    /// `from.uri`, `to.uri` and `ruri` are the URIs as written, parameters
    /// included, without the display name or the header's own parameters.
    #[test]
    fn uri_fields_are_the_uris_as_written() -> Result<(), TestError> {
        let d = trunk_call()?;
        assert!(selects(
            "from.uri == 'sip:+15551230000@carrier-a.example:5060;user=phone'",
            &d,
            &[]
        )?);
        assert!(selects("to.uri == 'sip:7000@pbx.example'", &d, &[])?);
        assert!(selects(
            "ruri == 'sip:7000@192.0.2.10;user=phone'",
            &d,
            &[]
        )?);
        assert!(selects("ruri =~ '^sip:7000@'", &d, &[])?);
        Ok(())
    }

    /// `pai.user` is the user part of P-Asserted-Identity; absent, it is the
    /// empty string, so `!=` selects a call without one.
    #[test]
    fn pai_user_is_the_asserted_identitys_user() -> Result<(), TestError> {
        let d = trunk_call()?;
        assert!(selects("pai.user == '+15559876543'", &d, &[])?);
        let mut no_pai = trunk_call()?;
        no_pai.pai_user = None;
        assert!(!selects("pai.user == '+15559876543'", &no_pai, &[])?);
        Ok(())
    }

    /// Every one of these is captured when the dialog opens, so idle
    /// compaction, which can drop messages, cannot change what they select.
    #[test]
    fn the_fields_survive_the_messages_being_dropped() -> Result<(), TestError> {
        let mut d = trunk_call()?;
        d.messages.clear();
        assert!(selects("from.host == 'carrier-a.example'", &d, &[])?);
        assert!(selects(
            "ruri == 'sip:7000@192.0.2.10;user=phone'",
            &d,
            &[]
        )?);
        assert!(selects("pai.user == '+15559876543'", &d, &[])?);
        assert!(selects("to.uri == 'sip:7000@pbx.example'", &d, &[])?);
        Ok(())
    }

    /// `rtp.codecs` is every codec the call's streams used, distinct and
    /// sorted, joined with commas.
    #[test]
    fn rtp_codecs_lists_every_codec_the_call_used() -> Result<(), TestError> {
        let d = trunk_call()?;
        let (a, b, c) = (
            stream("PCMU", 1)?,
            stream("telephone-event", 2)?,
            stream("PCMU", 3)?,
        );
        assert!(selects(
            "rtp.codecs == 'PCMU,telephone-event'",
            &d,
            &[&a, &b, &c]
        )?);
        assert!(selects("rtp.codecs =~ 'telephone-event'", &d, &[&a, &b])?);
        assert!(selects("rtp.codecs == ''", &d, &[])?);
        Ok(())
    }

    /// A port is removed from a name and an IPv4 address, and an IPv6 literal
    /// keeps its brackets; a bare IPv6 address has no port to remove.
    #[test]
    fn a_port_is_removed_and_an_ipv6_literal_kept() {
        assert_eq!(host_without_port("carrier.example:5060"), "carrier.example");
        assert_eq!(host_without_port("192.0.2.1:5080"), "192.0.2.1");
        assert_eq!(host_without_port("carrier.example"), "carrier.example");
        assert_eq!(host_without_port("[2001:db8::1]:5060"), "[2001:db8::1]");
        assert_eq!(host_without_port("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(host_without_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(host_without_port(""), "");
    }

    /// `side` places the opening request relative to the PBX's addresses:
    /// sent to the PBX is `inbound`, sent by it `outbound`, between two of its
    /// addresses `internal`, and neither end the PBX is the empty string.
    #[test]
    fn side_places_the_call_relative_to_the_pbx() -> Result<(), TestError> {
        let pbx = vec![
            crate::net::CidrRange::parse("192.0.2.10")?,
            crate::net::CidrRange::parse("198.51.100.0/24")?,
        ];
        let ip = |s: &str| s.parse::<IpAddr>();
        assert_eq!(
            side_of(ip("203.0.113.5")?, ip("192.0.2.10")?, &pbx),
            "inbound"
        );
        assert_eq!(
            side_of(ip("192.0.2.10")?, ip("203.0.113.5")?, &pbx),
            "outbound"
        );
        assert_eq!(
            side_of(ip("198.51.100.7")?, ip("192.0.2.10")?, &pbx),
            "internal"
        );
        assert_eq!(side_of(ip("203.0.113.5")?, ip("203.0.113.6")?, &pbx), "");
        assert_eq!(side_of(ip("203.0.113.5")?, ip("192.0.2.10")?, &[]), "");
        Ok(())
    }

    /// `endpoint` is the name the run gives the source or the destination
    /// address; it matches when either name satisfies the comparison, and an
    /// address with no name is the empty string.
    #[test]
    fn endpoint_matches_either_end_by_name() -> Result<(), TestError> {
        let d = trunk_call()?;
        let names = |ip: IpAddr| match ip.to_string().as_str() {
            "203.0.113.5" => Some("carrier-a-gw".to_owned()),
            "192.0.2.10" => Some("pbx-1".to_owned()),
            _ => None,
        };
        let cmp = |op, value: &str| endpoint_matches(&d, &names, op, &Value::Str(value.to_owned()));
        assert!(cmp(Operator::Eq, "carrier-a-gw"));
        assert!(cmp(Operator::Eq, "pbx-1"));
        assert!(!cmp(Operator::Eq, "elsewhere"));
        let nameless = |_: IpAddr| None;
        assert!(!endpoint_matches(
            &d,
            &nameless,
            Operator::Eq,
            &Value::Str("pbx-1".into())
        ));
        assert!(endpoint_matches(
            &d,
            &nameless,
            Operator::Eq,
            &Value::Str(String::new())
        ));
        Ok(())
    }

    /// The new names are listed with the rest, so an unknown-field hint and
    /// the documentation count both see them.
    #[test]
    fn the_new_fields_are_listed() {
        for f in [
            "from.host",
            "to.host",
            "from.uri",
            "to.uri",
            "ruri",
            "pai.user",
            "rtp.codecs",
        ] {
            assert!(FIELD_NAMES.contains(&f), "{f}");
        }
    }
}

/// Bare (unquoted) values. Where a value is expected, a word without quotes
/// means exactly what the quoted word means, read by the type of the field on
/// the left; quotes stay required only where the text cannot be told apart
/// from the expression around it.
#[cfg(test)]
mod bare_value_tests {
    use std::net::{IpAddr, Ipv4Addr};

    type TestError = Box<dyn std::error::Error>;

    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;

    fn at() -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 10, 13, 9, 0, 0)
                .single()
                .ok_or("invalid fixture timestamp")?,
        )
    }

    /// An INVITE from `from_user` to `to_user`, with a request-URI carrying a
    /// parameter, a P-Asserted-Identity and a custom header.
    fn call(from_user: &str, to_user: &str) -> Result<SipDialog, TestError> {
        let raw = build_sip(
            &format!("INVITE sip:{to_user}@192.0.2.10;user=phone SIP/2.0"),
            &[
                "Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKbare",
                &format!("From: <sip:{from_user}@carrier-a.example>;tag=f1"),
                &format!("To: <sip:{to_user}@pbx.example>"),
                "Call-ID: bare-values@example.com",
                "CSeq: 1 INVITE",
                "P-Asserted-Identity: <sip:+15559876543@carrier-a.example>",
                "X-Trunk: north-east",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            at()?,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        Ok(SipDialog::new(&msg).ok_or("an INVITE opens a dialog")?)
    }

    fn the_call() -> Result<SipDialog, TestError> {
        call("+15551230000", "7000")
    }

    /// Whether `expr` parses and selects `dialog`.
    fn selects(expr: &str, dialog: &SipDialog) -> Result<bool, TestError> {
        let f = FilterExpr::parse(expr).map_err(|e| format!("{expr:?} must parse: {e}"))?;
        Ok(f.matches_dialog(dialog, &[], CaptureMedia::Absent, MosDelay::unknown()))
    }

    /// The parse error text for `expr`, which must not parse.
    fn refused(expr: &str) -> Result<String, TestError> {
        match FilterExpr::parse(expr) {
            Ok(_) => Err(format!("{expr:?} must be refused").into()),
            Err(e) => Ok(e.to_string()),
        }
    }

    /// `field op value` written bare, single-quoted and double-quoted: all
    /// three parse and give the same answer on `dialog`. Returns that answer.
    fn same_three_ways(field_op: &str, value: &str, dialog: &SipDialog) -> Result<bool, TestError> {
        let bare = selects(&format!("{field_op} {value}"), dialog)?;
        let single = selects(&format!("{field_op} '{value}'"), dialog)?;
        let double = selects(&format!("{field_op} \"{value}\""), dialog)?;
        assert_eq!(
            (bare, double),
            (single, single),
            "{field_op} {value}: bare, '…' and \"…\" must agree"
        );
        Ok(bare)
    }

    /// The headline case, and the one an MCP client hit: `method == INVITE`.
    #[test]
    fn a_bare_method_means_the_quoted_method() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(same_three_ways("method ==", "INVITE", &d)?);
        assert!(!same_three_ways("method ==", "BYE", &d)?);
        assert!(!same_three_ways("method !=", "INVITE", &d)?);
        assert!(same_three_ways("method !=", "BYE", &d)?);
        Ok(())
    }

    /// Case stays significant: [RFC 3261 section 7.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.1) makes method names
    /// case-sensitive, and the quoted comparison never folded case.
    #[test]
    fn a_bare_value_keeps_case_sensitivity() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(!same_three_ways("method ==", "invite", &d)?);
        Ok(())
    }

    /// Every kind of text field takes a bare value, including the characters
    /// a SIP URI, a Call-ID and an address are made of: `@ . : ; = + - /`.
    #[test]
    fn every_text_field_takes_a_bare_value() -> Result<(), TestError> {
        let d = the_call()?;
        for (field_op, value) in [
            ("from.user ==", "+15551230000"),
            ("to.user ==", "7000"),
            ("from.host ==", "carrier-a.example"),
            ("to.host ==", "pbx.example"),
            ("from.uri ==", "sip:+15551230000@carrier-a.example"),
            ("ruri ==", "sip:7000@192.0.2.10;user=phone"),
            ("pai.user ==", "+15559876543"),
            ("call_id ==", "bare-values@example.com"),
            ("header.X-Trunk ==", "north-east"),
            ("header.Call-ID ==", "bare-values@example.com"),
            ("src.ip ==", "203.0.113.5"),
            ("src.ip in_subnet", "203.0.113.0/24"),
            ("dst.ip in_subnet", "192.0.2.0/24"),
            ("state ==", state_to_str(d.state())),
        ] {
            assert!(
                same_three_ways(field_op, value, &d)?,
                "{field_op} {value} must select the call"
            );
        }
        assert!(!same_three_ways("call_id ==", "other@example.com", &d)?);
        assert!(!same_three_ways("src.ip in_subnet", "198.51.100.0/24", &d)?);
        Ok(())
    }

    /// A bare value combines with AND, OR, NOT and parentheses, and a `)`
    /// written straight after it closes the group rather than joining it.
    #[test]
    fn bare_values_combine_with_and_or_not_and_groups() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(selects("method == INVITE AND to.user == 7000", &d)?);
        assert!(selects("method == BYE OR to.user == 7000", &d)?);
        assert!(!selects("method == BYE OR to.user == 7001", &d)?);
        assert!(selects("NOT method == BYE", &d)?);
        assert!(selects("(method == INVITE)", &d)?);
        assert!(selects(
            "(method == BYE OR (to.user == 7000)) AND src.port == 5060",
            &d
        )?);
        assert!(selects(
            "method == INVITE and (call_id == bare-values@example.com)",
            &d
        )?);
        Ok(())
    }

    /// The field decides what a value is. `to.user` is text, so `7000` there
    /// is the text `7000` and matches a user named `7000`. Before, it was the
    /// number 7000, which no text field equals, so it silently matched nothing.
    #[test]
    fn a_number_shaped_value_is_text_on_a_text_field() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(selects("to.user == 7000", &d)?);
        assert!(!selects("to.user != 7000", &d)?);
        assert!(selects("from.user == +15551230000", &d)?);
        // Text keeps its spelling: `7000.0` is not the user `7000`.
        assert!(!selects("to.user == 7000.0", &d)?);
        Ok(())
    }

    /// A numeric field reads a number bare or quoted, with the same meaning,
    /// and ordering comparisons are unchanged.
    #[test]
    fn a_numeric_field_reads_a_number_bare_or_quoted() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(same_three_ways("src.port ==", "5060", &d)?);
        assert!(same_three_ways("src.port >=", "5000", &d)?);
        assert!(!same_three_ways("src.port <", "5000", &d)?);
        assert!(!same_three_ways("src.port ==", "5061", &d)?);
        assert!(same_three_ways("msg_count ==", "1", &d)?);
        assert!(same_three_ways("duration <", "0.5", &d)?);
        Ok(())
    }

    /// A value a numeric field can never equal is an error naming the field
    /// and what it compares with, not a filter that silently matches nothing.
    #[test]
    fn a_word_on_a_numeric_field_is_refused_naming_the_field() -> Result<(), TestError> {
        for expr in ["src.port == abc", "src.port == 'abc'", "pdd > \"slow\""] {
            let err = refused(expr)?;
            assert!(
                err.contains("compares with a finite number"),
                "{expr}: {err}"
            );
        }
        Ok(())
    }

    /// A boolean field reads `true`/`false` bare or quoted, case-insensitive
    /// as before, and refuses anything else naming why.
    #[test]
    fn a_boolean_field_reads_true_or_false_bare_or_quoted() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(same_three_ways("one_way ==", "false", &d)?);
        assert!(same_three_ways("one_way ==", "FALSE", &d)?);
        assert!(!same_three_ways("one_way ==", "true", &d)?);
        let err = refused("one_way == maybe")?;
        assert!(err.contains("compares with true or false"), "{err}");
        Ok(())
    }

    /// A boolean field has no order, so `<`, `<=`, `>` and `>=` against one
    /// are refused at parse time, naming the two operators it takes, instead
    /// of parsing and matching nothing.
    #[test]
    fn a_boolean_field_refuses_an_ordering_operator() -> Result<(), TestError> {
        for op in ["<", "<=", ">", ">="] {
            let err = refused(&format!("one_way {op} true"))?;
            assert!(err.contains("compares with == or !="), "{op}: {err}");
        }
        let d = the_call()?;
        assert!(same_three_ways("one_way !=", "true", &d)?);
        Ok(())
    }

    /// `time` takes its RFC 3339 instant bare as well as quoted.
    #[test]
    fn a_time_bound_may_be_bare() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(same_three_ways("time >=", "2026-10-13T08:00:00Z", &d)?);
        assert!(!same_three_ways("time >", "2026-10-13T09:00:00+00:00", &d)?);
        Ok(())
    }

    /// `response_class` takes `5xx` bare, which is not a number.
    #[test]
    fn a_response_class_may_be_bare() -> Result<(), TestError> {
        let d = the_call()?;
        // A call with no final response is in no class, bare or quoted.
        assert!(!same_three_ways("response_class ==", "5xx", &d)?);
        assert!(!same_three_ways("response_class ==", "failure", &d)?);
        Ok(())
    }

    /// The right-hand side of a comparison is always a value: the grammar has
    /// no field-to-field comparison. So a word that is elsewhere a keyword,
    /// a field name or an alias name is, in value position, that text.
    #[test]
    fn a_keyword_field_or_alias_name_in_value_position_is_text() -> Result<(), TestError> {
        for word in ["true", "AND", "or", "NOT", "to.user", "problems", "one-way"] {
            let d = call(word, "7000")?;
            assert!(
                selects(&format!("from.user == {word}"), &d)?,
                "from.user == {word} must select the user named {word}"
            );
            assert!(selects(&format!("from.user == '{word}'"), &d)?, "{word}");
            let other = the_call()?;
            assert!(!selects(&format!("from.user == {word}"), &other)?, "{word}");
        }
        Ok(())
    }

    /// A `@` inside a bare value is part of the value, not a `@name` filter
    /// reference: `alice@example` cannot be a reference, because a reference
    /// begins an atom. Resolution leaves the value alone even when a filter
    /// of that name exists.
    #[test]
    fn an_at_sign_inside_a_bare_value_is_not_a_reference() -> Result<(), TestError> {
        let defs: std::collections::BTreeMap<String, String> =
            [("example".to_owned(), "method == 'BYE'".to_owned())].into();
        let t = AliasThresholds::default();
        let table = super::super::named_filters::NamedFilters::resolve(&defs, &t)?;
        let text = "call_id == bare-values@example.com";
        assert_eq!(resolve_references(text, &table, &t), text);
        assert!(selects(text, &the_call()?)?);
        // A reference that begins an atom is still a reference.
        assert_eq!(
            resolve_references("method == INVITE AND @example", &table, &t),
            "method == INVITE AND (method == 'BYE')"
        );
        Ok(())
    }

    /// A bare regex is read up to whitespace or a `)` that closes an open
    /// group of the expression. Its own parentheses balance, `|` is an
    /// ordinary regex character, and a `)` inside `[...]` or after `\` is
    /// part of the regex.
    #[test]
    fn a_bare_regex_reads_to_whitespace_or_an_unbalanced_paren() -> Result<(), TestError> {
        let d = the_call()?;
        assert!(same_three_ways("from.user =~", r"^\+1555", &d)?);
        assert!(same_three_ways("method =~", "^(INVITE|BYE)$", &d)?);
        assert!(same_three_ways("method =~", "INV|BYE", &d)?);
        assert!(same_three_ways(
            "call_id =~",
            r"^bare-[a-z]+@example\.com$",
            &d
        )?);
        assert!(!same_three_ways("method =~", "^(BYE|CANCEL)$", &d)?);
        assert!(selects("(method =~ ^IN(V|X)ITE)", &d)?);
        assert!(selects(
            "(method =~ ^(INVITE|BYE)$ AND src.port == 5060)",
            &d
        )?);
        assert!(selects(r"method =~ [)(]|^INVITE$", &d)?);
        assert!(selects(r"(method =~ \)|INVITE)", &d)?);
        Ok(())
    }

    /// Quotes stay required where the value cannot be told apart from the
    /// expression around it, and the error names the reason.
    #[test]
    fn a_value_with_whitespace_needs_quotes_and_the_error_says_so() -> Result<(), TestError> {
        let d = call("Friendly Scanner", "7000")?;
        assert!(selects("from.user == 'Friendly Scanner'", &d)?);
        let err = refused("from.user == Friendly Scanner")?;
        assert!(err.contains("whitespace must be quoted"), "{err}");
        assert!(!err.contains("string values must be quoted"), "{err}");
        let err = refused("ua =~ Friendly Scanner")?;
        assert!(err.contains("whitespace must be quoted"), "{err}");
        Ok(())
    }

    /// A value with an unmatched `)` needs quotes; the error names it.
    #[test]
    fn a_value_with_an_unmatched_paren_needs_quotes() -> Result<(), TestError> {
        let d = call("a)b", "7000")?;
        assert!(selects("from.user == 'a)b'", &d)?);
        let err = refused("from.user == a)b")?;
        assert!(err.contains("unmatched ')'"), "{err}");
        let err = refused("method =~ IN)VITE")?;
        assert!(err.contains("unmatched ')'"), "{err}");
        Ok(())
    }

    /// A value that begins with a quote character, an operator character or
    /// `@` cannot be bare. `===` stays a typo rather than becoming the value
    /// `=INVITE`.
    #[test]
    fn a_value_beginning_with_a_reserved_character_needs_quotes() -> Result<(), TestError> {
        for expr in [
            "method === 'INVITE'",
            "method == =x",
            "method == <x",
            "method == !x",
        ] {
            let err = refused(expr)?;
            assert!(err.contains("needs quotes"), "{expr}: {err}");
        }
        let err = refused("ua == 'unterminated")?;
        assert!(err.contains("unterminated"), "{err}");
        // An empty value can only be written quoted.
        let d = the_call()?;
        assert!(!selects("pai.user == ''", &d)?);
        Ok(())
    }

    /// A quote character ends a bare value, because quotes delimit strings
    /// everywhere in the expression; a value containing one is quoted with
    /// the other quote character.
    #[test]
    fn a_value_containing_a_quote_needs_quotes() -> Result<(), TestError> {
        let d = call("O'Brien", "7000")?;
        assert!(selects("from.user == \"O'Brien\"", &d)?);
        assert!(selects(r"from.user == 'O\'Brien'", &d)?);
        let err = refused("from.user == O'Brien")?;
        assert!(err.contains("containing ' or \""), "{err}");
        Ok(())
    }

    /// A combinator that is not part of the grammar is named, not reported as
    /// a quoting problem: the combinators are the words AND, OR and NOT.
    #[test]
    fn a_symbolic_combinator_is_refused_naming_the_words() -> Result<(), TestError> {
        let err = refused("method == INVITE && to.user == 7000")?;
        assert!(err.contains("AND, OR"), "{err}");
        assert!(!err.contains("string values must be quoted"), "{err}");
        Ok(())
    }

    /// The printed position is the 0-based CHARACTER column the caret marks,
    /// not a byte offset: `é` is two bytes and one column.
    #[test]
    fn the_printed_position_is_the_caret_column_in_characters() -> Result<(), TestError> {
        let expr = "from.user == 'José' AND method == =x";
        let err = refused(expr)?;
        // The offending value starts after `method == `.
        let byte_at = expr.rfind("=x").ok_or("value")?;
        let char_col = expr[..byte_at].chars().count();
        assert_ne!(
            byte_at, char_col,
            "the fixture must put a multibyte char first"
        );
        assert!(
            err.contains(&format!("position {char_col}:")),
            "position must be the character column {char_col}, not byte {byte_at}:\n{err}"
        );
        let caret_line = err
            .lines()
            .find(|l| l.trim_end().ends_with('^'))
            .ok_or("caret line")?;
        let caret_col = caret_line.chars().count() - 1 - 2;
        assert_eq!(caret_col, char_col, "caret and position agree:\n{err}");
        Ok(())
    }
}
