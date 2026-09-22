// SPDX-License-Identifier: MIT OR Apache-2.0

//! The capture analysis as YANG: one node table, every rendering derived.
//!
//! [`crate::analysis::CaptureAnalysis`] is published in two encodings. The
//! plain JSON one is its serde serialization (`--json-analyze`,
//! `GET /v1/report`, MCP `get_capture_report`). The other is RFC 7951 JSON,
//! validated against the YANG 1.1 module `sipnab-diagnosis`
//! (`--yang-analyze`, `GET /v1/report?format=yang-json`,
//! `get_capture_report {"format": "yang-json"}`).
//!
//! Three things have to agree for that to be true, and each is derived here
//! from the same table rather than written three times:
//!
//! * **the module text** — [`module_text`] renders `sipnab-diagnosis` from
//!   [`CAPTURE_ANALYSIS`] and from the two identity tables the analysis
//!   already has, [`FindingKind::ALL`] and [`CountLabel::ALL`]. The committed
//!   file under `yang/` is this function's output, blessed the way the
//!   OpenAPI document is, so a kind added to the analysis and not to the
//!   module fails a test instead of a consumer;
//! * **the encoder** — [`encode`] walks the same table over the plain JSON,
//!   so the two encodings are one value written twice, never two values;
//! * **the decoder** — [`decode`] is the inverse, strict, and exists so that
//!   claim can be tested: a document decoded back must equal the plain JSON of
//!   the same run.
//!
//! # What the RFC 7951 encoding changes, and why
//!
//! Nothing about the value. Only how it is written:
//!
//! * [RFC 7951 section 4](https://www.rfc-editor.org/rfc/rfc7951#section-4): the one top-level member is namespace-qualified,
//!   `"sipnab-diagnosis:capture-analysis"`;
//! * [RFC 7951 section 6.1](https://www.rfc-editor.org/rfc/rfc7951#section-6.1): every `uint64` is a JSON **string**, because a JSON
//!   number cannot carry 64 bits in every parser. `uint32` stays a number;
//! * names are hyphenated (`frames_read` becomes `frames-read`), the YANG
//!   convention of [RFC 9907 section 4.3.1](https://www.rfc-editor.org/rfc/rfc9907#section-4.3.1) — but identity names keep the analysis's
//!   own ids (`one_way_audio`), so a consumer joins the two encodings on one
//!   string;
//! * a JSON array's order has no YANG equivalent for state data —
//!   [RFC 7950 section 7.7.7](https://www.rfc-editor.org/rfc/rfc7950#section-7.7.7) ignores `ordered-by` there — so the ranking the plain JSON carries
//!   by position is carried by an explicit `rank`, and each evidence row by
//!   an `index`, both counted from 1;
//! * `counts`, a JSON object used as a map, becomes a list keyed by `name`;
//! * an empty collection is absent, since a list has no empty-array form.
//!
//! Nothing is added that the analysis does not hold. `rank` and `index` are
//! the positions the plain JSON already states; every other leaf is a field of
//! the model. A new fact lands in [`crate::analysis::CaptureAnalysis`] first
//! and reaches both encodings, which is the only way the two can stay one.

use serde_json::{Map, Value};

use super::{CaptureAnalysis, CountLabel, FindingKind, Severity};

/// The module's current revision, as a literal so `include_str!` can name the
/// committed file. Written once here; [`REVISION`] and [`REVISIONS`] read it.
macro_rules! revision {
    () => {
        "2026-09-21"
    };
}

/// The module name, which [RFC 7951 section 4](https://www.rfc-editor.org/rfc/rfc7951#section-4) also makes the member qualifier.
pub const MODULE: &str = "sipnab-diagnosis";

/// The module namespace. [RFC 7950 section 5.3](https://www.rfc-editor.org/rfc/rfc7950#section-5.3) leaves a private namespace to its
/// owner, and this one is under the project's own domain. It names the module;
/// nothing is served at it.
pub const NAMESPACE: &str = "https://sipnab.com/ns/yang/sipnab-diagnosis";

/// The module prefix.
pub const PREFIX: &str = "snd";

/// The top-level container, the one data node the module defines.
pub const TOP: &str = "capture-analysis";

/// The current revision date.
pub const REVISION: &str = revision!();

/// The committed module, byte for byte: what `--print-yang-module` prints.
///
/// Included rather than regenerated, so the text a user is handed is the one
/// file the repository publishes, and `tests/yang_module_test.rs` holds that
/// file equal to [`module_text`].
///
/// A literal path, not one assembled from [`REVISION`] with `concat!`:
/// `tests/crate_package_test.rs` finds every embedded file by reading
/// `include_str!("...")` literals, and an assembled path is invisible to it —
/// the published crate would build without `yang/` and fail on crates.io. The
/// date is therefore written twice, and `print_yang_module_prints_the_committed_file`
/// fails the moment the two name different revisions.
pub const MODULE_TEXT: &str = include_str!("../../yang/sipnab-diagnosis@2026-09-21.yang");

/// The committed module's file name under `yang/`. [RFC 7950 section 5.2](https://www.rfc-editor.org/rfc/rfc7950#section-5.2) names a
/// module file `name@revision.yang`.
#[must_use]
pub fn module_file_name() -> String {
    format!("{MODULE}@{REVISION}.yang")
}

/// One `revision` statement.
#[derive(Debug, Clone, Copy)]
pub struct Revision {
    /// `YYYY-MM-DD`.
    pub date: &'static str,
    /// What changed.
    pub description: &'static str,
}

/// Every revision, newest first, as [RFC 7950 section 7.1.9](https://www.rfc-editor.org/rfc/rfc7950#section-7.1.9) orders them.
///
/// A published revision is never edited. Changing the module — a new finding
/// kind or count label included — means a new entry here with a new date, the
/// previous file kept beside the new one under `yang/`, and
/// `pyang --check-update-from` holding the change to [RFC 7950 section 11](https://www.rfc-editor.org/rfc/rfc7950#section-11).
pub const REVISIONS: &[Revision] = &[Revision {
    date: revision!(),
    description: "Initial revision: the capture analysis sipnab computes, its finding \
                  kinds and its evidence count labels.",
}];

/// A YANG type, as the table uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    /// `uint32`: a JSON number in both encodings.
    Uint32,
    /// `uint64`: a JSON number in the plain encoding, and a decimal string in
    /// the RFC 7951 one ([RFC 7951 section 6.1](https://www.rfc-editor.org/rfc/rfc7951#section-6.1)).
    Uint64,
    /// `boolean`.
    Boolean,
    /// `string`.
    String,
    /// `yang:date-and-time`, from `ietf-yang-types`.
    DateAndTime,
    /// The module's `severity` enumeration, from [`Severity::ALL`].
    Severity,
    /// `identityref` with base `finding-kind`, from [`FindingKind::ALL`].
    FindingKind,
    /// `identityref` with base `count-label`, from [`CountLabel::ALL`].
    CountLabel,
}

impl Type {
    /// The type as the module writes it, on one line or as a block body.
    fn yang(self) -> &'static str {
        match self {
            Self::Uint32 => "uint32",
            Self::Uint64 => "uint64",
            Self::Boolean => "boolean",
            Self::String => "string",
            Self::DateAndTime => "yang:date-and-time",
            Self::Severity => "severity",
            Self::FindingKind => "identityref {\n  base finding-kind;\n}",
            Self::CountLabel => "identityref {\n  base count-label;\n}",
        }
    }
}

/// Where a node's value comes from in the plain JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The serialized field of this name on the corresponding Rust struct.
    Field(&'static str),
    /// The entry's position in the plain JSON array that holds it, from 1.
    /// Not a field: the plain encoding states it by position.
    Position,
}

/// Whether the plain JSON writes an empty collection or leaves it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenEmpty {
    /// `[]` or `{}` is written (a `Vec` with no `skip_serializing_if`).
    Written,
    /// The field is absent (`skip_serializing_if = "…is_empty"`).
    Omitted,
}

/// The shape of a node.
#[derive(Debug, Clone, Copy)]
pub enum Body {
    /// One value.
    Leaf {
        /// Its type.
        ty: Type,
        /// Always present. A key leaf is not marked: RFC 7950 makes it so.
        mandatory: bool,
    },
    /// An ordered sequence of values, from a JSON array.
    LeafList {
        /// The element type.
        ty: Type,
        /// How the plain JSON writes an empty sequence.
        when_empty: WhenEmpty,
    },
    /// A keyed list, from a JSON array of objects.
    List {
        /// The key leaf's name, which must be one of `children`.
        key: &'static str,
        /// The entry's nodes.
        children: &'static [Node],
        /// How the plain JSON writes an empty array.
        when_empty: WhenEmpty,
    },
    /// A keyed list from a JSON object used as a map: each member becomes an
    /// entry holding the member's name as the key and its value beside it.
    Map {
        /// The key leaf.
        key: &'static str,
        /// The key leaf's type.
        key_ty: Type,
        /// The key leaf's description.
        key_description: &'static str,
        /// The value leaf.
        value: &'static str,
        /// The value leaf's type.
        value_ty: Type,
        /// The value leaf's description.
        value_description: &'static str,
        /// How the plain JSON writes an empty map.
        when_empty: WhenEmpty,
    },
}

/// One data node of the module.
#[derive(Debug, Clone, Copy)]
pub struct Node {
    /// The YANG identifier: the serde name with `_` written `-`.
    pub name: &'static str,
    /// Where the value comes from.
    pub origin: Origin,
    /// The node's shape.
    pub body: Body,
    /// The `description` statement.
    pub description: &'static str,
}

/// Shorthand for a leaf read from a field.
const fn leaf(
    name: &'static str,
    field: &'static str,
    ty: Type,
    mandatory: bool,
    description: &'static str,
) -> Node {
    Node {
        name,
        origin: Origin::Field(field),
        body: Body::Leaf { ty, mandatory },
        description,
    }
}

/// The nodes of one evidence row: [`crate::analysis::Evidence`].
pub const EVIDENCE: &[Node] = &[
    Node {
        name: "index",
        origin: Origin::Position,
        body: Body::Leaf {
            ty: Type::Uint32,
            mandatory: false,
        },
        description: "This row's position in the finding's evidence, counting from 1. \
                      The plain JSON encoding states it by array position; RFC 7950 \
                      section 7.7.7 gives state data no order, so it is carried here.",
    },
    leaf(
        "call-id",
        "call_id",
        Type::String,
        false,
        "The Call-ID of the dialog this instance belongs to. Absent for a \
         capture-level finding that belongs to no call: a STUN probe, an \
         undecodable frame, an ICMP quote too short to name a Call-ID.",
    ),
    Node {
        name: "endpoint",
        origin: Origin::Field("endpoints"),
        body: Body::LeafList {
            ty: Type::String,
            when_empty: WhenEmpty::Omitted,
        },
        description: "The addresses involved, most specific first, as display text \
                      with the role written in (\"SDP 192.0.2.1\", \"reported by \
                      198.51.100.1\") rather than as bare addresses. The encoding \
                      keeps the order; RFC 7950 section 7.7.7 means a YANG tool need \
                      not.",
    },
    leaf(
        "at",
        "at",
        Type::DateAndTime,
        false,
        "When it happened, in UTC, when a single timestamp describes it.",
    ),
    Node {
        name: "count",
        origin: Origin::Field("counts"),
        body: Body::Map {
            key: "name",
            key_ty: Type::CountLabel,
            key_description: "What the number counts. One of the count-label identities, \
                              whose names are the labels the plain JSON uses as keys.",
            value: "value",
            value_ty: Type::Uint64,
            value_description: "The count.",
            when_empty: WhenEmpty::Omitted,
        },
        description: "Named integer counts: packets, streams, messages, errors, status \
                      codes.",
    },
    leaf(
        "note",
        "note",
        Type::String,
        false,
        "The part of the evidence that is not an integer: codec names, a reason \
         phrase, a router's own words.",
    ),
];

/// The nodes of one finding: [`crate::analysis::Finding`].
pub const FINDING: &[Node] = &[
    leaf(
        "kind",
        "kind",
        Type::FindingKind,
        false,
        "Which problem this is. At most one finding per kind: the analysis \
         aggregates every occurrence of a kind into one entry.",
    ),
    Node {
        name: "rank",
        origin: Origin::Position,
        body: Body::Leaf {
            ty: Type::Uint32,
            mandatory: true,
        },
        description: "This finding's place in the ranking, 1 being the worst: severity \
                      first, then occurrences, highest first, then the kind's place on \
                      the ladder. The plain JSON encoding states it by array position; \
                      RFC 7950 section 7.7.7 gives state data no order, so it is \
                      carried here.",
    },
    leaf(
        "severity",
        "severity",
        Type::Severity,
        true,
        "How bad it is. Carried on every finding so a consumer can sort without \
         the identity table.",
    ),
    leaf(
        "occurrences",
        "occurrences",
        Type::Uint64,
        true,
        "How many times it was observed, in units of 'unit'. Exact, and not the \
         number of evidence entries, which is capped.",
    ),
    leaf(
        "unit",
        "unit",
        Type::String,
        true,
        "What one occurrence is: call, frame, message, transaction and so on.",
    ),
    leaf(
        "evidence-omitted",
        "evidence_omitted",
        Type::Uint64,
        true,
        "Evidence rows the cap of ten kept out. Counted, not derived from \
         'occurrences', because one row often stands for many occurrences.",
    ),
    Node {
        name: "evidence",
        origin: Origin::Field("evidence"),
        body: Body::List {
            key: "index",
            children: EVIDENCE,
            when_empty: WhenEmpty::Written,
        },
        description: "Up to ten verifiable instances, each pointing back at the \
                      capture.",
    },
];

/// The nodes of the top-level container: [`crate::analysis::CaptureAnalysis`].
pub const CAPTURE_ANALYSIS: &[Node] = &[
    leaf(
        "schema-version",
        "schema_version",
        Type::Uint32,
        true,
        "The version of the plain JSON encoding's shape this analysis was \
         produced under.",
    ),
    leaf(
        "filter",
        "filter",
        Type::String,
        false,
        "The filter expression that selected the dialogs examined, after alias \
         expansion. Absent when every dialog was examined. Capture-level \
         findings are never narrowed by it.",
    ),
    leaf(
        "frames-read",
        "frames_read",
        Type::Uint64,
        true,
        "Frames handed to the parser: the denominator every other number is \
         read against.",
    ),
    leaf(
        "dialogs-examined",
        "dialogs_examined",
        Type::Uint64,
        true,
        "Dialogs the analysis looked at, after any filter.",
    ),
    leaf(
        "streams-examined",
        "streams_examined",
        Type::Uint64,
        true,
        "RTP streams linked to those dialogs.",
    ),
    leaf(
        "complete",
        "complete",
        Type::Boolean,
        true,
        "Whether sipnab read all of its input. False whenever a finding of \
         severity 'blind' is present, and then every count is a floor and the \
         absence of a finding is not evidence of the absence of a problem.",
    ),
    Node {
        name: "finding",
        origin: Origin::Field("findings"),
        body: Body::List {
            key: "kind",
            children: FINDING,
            when_empty: WhenEmpty::Written,
        },
        description: "Every finding, one per kind. The entries are written worst \
                      first; 'rank' states the order.",
    },
];

/// The top-level container's description.
const TOP_DESCRIPTION: &str = "Everything sipnab's capture analysis found, ranked, with the \
                               denominators it was found in. Every fact here was already \
                               computed by a per-dialog or capture-level diagnosis; the \
                               analysis aggregates and ranks them and adds no judgement of \
                               its own.";

/// Why an RFC 7951 document could not be produced or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CodecError {}

/// Shorthand for a [`CodecError`] result.
fn fail<T>(msg: impl Into<String>) -> Result<T, CodecError> {
    Err(CodecError(msg.into()))
}

/// The analysis, RFC 7951-encoded against `sipnab-diagnosis`.
///
/// Computed from the analysis's own serialization, so it is the plain JSON
/// value written the other way and never a second reading of the model.
///
/// # Errors
///
/// Only if the serialization and [`CAPTURE_ANALYSIS`] disagree — a field the
/// table does not know, a value of the wrong type. That is a defect in this
/// module, and the census tests below exist so it cannot ship.
pub fn to_rfc7951(analysis: &CaptureAnalysis) -> Result<Value, CodecError> {
    let plain = serde_json::to_value(analysis)
        .map_err(|e| CodecError(format!("the analysis did not serialize: {e}")))?;
    encode(&plain)
}

/// A document as one line of JSON, newline-terminated: how `--yang-analyze`
/// prints it, one line per run like `--json-analyze`.
///
/// # Errors
///
/// Only if `doc` does not serialize, which a `Value` always does.
pub fn to_line(doc: &Value) -> Result<String, CodecError> {
    let mut line = serde_json::to_string(doc)
        .map_err(|e| CodecError(format!("the document did not serialize: {e}")))?;
    line.push('\n');
    Ok(line)
}

/// The plain JSON encoding of an analysis, RFC 7951-encoded.
///
/// # Errors
///
/// When `plain` is not an analysis this table describes: an unknown or
/// missing member, or a value of the wrong JSON type.
pub fn encode(plain: &Value) -> Result<Value, CodecError> {
    let Value::Object(obj) = plain else {
        return fail("the analysis is not a JSON object");
    };
    let body = encode_object(obj, CAPTURE_ANALYSIS, None, TOP)?;
    let mut doc = Map::new();
    doc.insert(format!("{MODULE}:{TOP}"), Value::Object(body));
    Ok(Value::Object(doc))
}

/// An RFC 7951 document, decoded back into the plain JSON encoding.
///
/// Strict: an unknown member, a `uint64` written as a number, a `uint32`
/// written as a string, an identity the module does not define, a duplicate
/// key or a gap in `rank` or `index` is refused rather than repaired. The
/// test that proves the two encodings carry one value depends on that.
///
/// # Errors
///
/// When `doc` is not a `sipnab-diagnosis` document this table describes.
pub fn decode(doc: &Value) -> Result<Value, CodecError> {
    let Value::Object(top) = doc else {
        return fail("the document is not a JSON object");
    };
    let qualified = format!("{MODULE}:{TOP}");
    if top.len() != 1 {
        let names: Vec<&String> = top.keys().collect();
        return fail(format!(
            "the document must hold exactly one member, `{qualified}`; it holds {names:?}"
        ));
    }
    let Some(Value::Object(body)) = top.get(&qualified) else {
        return fail(format!("the document holds no `{qualified}` container"));
    };
    Ok(Value::Object(decode_object(body, CAPTURE_ANALYSIS, TOP)?))
}

/// Encode one plain JSON object through `nodes`.
///
/// `position` is the entry's 1-based place in its array, for a
/// [`Origin::Position`] node; `None` at the top level, where there is none.
fn encode_object(
    obj: &Map<String, Value>,
    nodes: &[Node],
    position: Option<usize>,
    at: &str,
) -> Result<Map<String, Value>, CodecError> {
    for name in obj.keys() {
        if !nodes
            .iter()
            .any(|n| matches!(n.origin, Origin::Field(f) if f == name))
        {
            return fail(format!("{at}: `{name}` has no node in the module"));
        }
    }
    let mut out = Map::new();
    for node in nodes {
        let path = format!("{at}/{}", node.name);
        let value = match node.origin {
            Origin::Position => match position {
                Some(p) => Some(Value::from(p)),
                None => return fail(format!("{path}: a position node outside a list")),
            },
            Origin::Field(field) => obj.get(field).cloned(),
        };
        let Some(value) = value else {
            if matches!(
                node.body,
                Body::Leaf {
                    mandatory: true,
                    ..
                }
            ) {
                return fail(format!("{path}: mandatory and absent"));
            }
            continue;
        };
        if let Some(encoded) = encode_node(node, &value, &path)? {
            out.insert(node.name.to_string(), encoded);
        }
    }
    Ok(out)
}

/// Encode one node's value. `None` for an empty collection, which RFC 7951
/// has no way to write for a list.
fn encode_node(node: &Node, value: &Value, path: &str) -> Result<Option<Value>, CodecError> {
    match node.body {
        Body::Leaf { ty, .. } => encode_scalar(ty, value, path).map(Some),
        Body::LeafList { ty, .. } => {
            let items = as_array(value, path)?;
            if items.is_empty() {
                return Ok(None);
            }
            let out = items
                .iter()
                .map(|v| encode_scalar(ty, v, path))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(Value::Array(out)))
        }
        Body::List { children, .. } => {
            let items = as_array(value, path)?;
            if items.is_empty() {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let Value::Object(entry) = item else {
                    return fail(format!("{path}[{i}]: not an object"));
                };
                let at = format!("{path}[{}]", i + 1);
                out.push(Value::Object(encode_object(
                    entry,
                    children,
                    Some(i + 1),
                    &at,
                )?));
            }
            Ok(Some(Value::Array(out)))
        }
        Body::Map {
            key,
            key_ty,
            value: value_name,
            value_ty,
            ..
        } => {
            let Value::Object(map) = value else {
                return fail(format!("{path}: not an object"));
            };
            if map.is_empty() {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(map.len());
            for (name, v) in map {
                let mut entry = Map::new();
                entry.insert(
                    key.to_string(),
                    encode_scalar(key_ty, &Value::String(name.clone()), path)?,
                );
                entry.insert(value_name.to_string(), encode_scalar(value_ty, v, path)?);
                out.push(Value::Object(entry));
            }
            Ok(Some(Value::Array(out)))
        }
    }
}

/// The array `value` must be.
fn as_array<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>, CodecError> {
    match value {
        Value::Array(items) => Ok(items),
        other => fail(format!("{path}: expected an array, found {other}")),
    }
}

/// Encode one scalar from its plain JSON form.
fn encode_scalar(ty: Type, value: &Value, path: &str) -> Result<Value, CodecError> {
    match (ty, value) {
        (Type::Uint32, Value::Number(n)) => match n.as_u64() {
            Some(v) if u32::try_from(v).is_ok() => Ok(Value::from(v)),
            _ => fail(format!("{path}: {n} is not a uint32")),
        },
        // RFC 7951 section 6.1: a 64-bit integer is a JSON string.
        (Type::Uint64, Value::Number(n)) => match n.as_u64() {
            Some(v) => Ok(Value::String(v.to_string())),
            None => fail(format!("{path}: {n} is not a uint64")),
        },
        (Type::Boolean, Value::Bool(b)) => Ok(Value::Bool(*b)),
        (Type::String, Value::String(s)) => Ok(Value::String(yang_string(s))),
        (Type::DateAndTime, Value::String(s)) => Ok(Value::String(s.clone())),
        (Type::Severity | Type::FindingKind | Type::CountLabel, Value::String(s)) => {
            check_enumerated(ty, s, path)?;
            Ok(Value::String(s.clone()))
        }
        _ => fail(format!("{path}: {value} is not a {ty:?}")),
    }
}

/// Whether YANG's `string` type can carry `c`.
///
/// [RFC 7950 section 9.4](https://www.rfc-editor.org/rfc/rfc7950#section-9.4) admits the characters XML does: tab, carriage return, line
/// feed, and everything from U+0020 up except U+FFFE and U+FFFF (a Rust `char`
/// is never a surrogate). libyang enforces it — a note holding U+001B fails
/// validation outright.
#[must_use]
pub fn yang_string_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= '\u{20}' && c != '\u{FFFE}' && c != '\u{FFFF}')
}

/// `s` with every character YANG's `string` cannot carry written as U+FFFD.
///
/// The one place the two encodings of an analysis can differ, and it is
/// forced rather than chosen: evidence carries text from the wire — a reason
/// phrase, a Call-ID — and nothing guarantees a capture keeps control
/// characters out of it. The alternatives were worse. Refusing the export
/// would let one hostile packet take the RFC 7951 door down for the whole
/// capture, and emitting the character would publish a document every YANG
/// validator rejects. U+FFFD is the character Unicode reserves for exactly
/// this, and it stays visible where the substitution happened.
#[must_use]
pub fn yang_string(s: &str) -> String {
    if s.chars().all(yang_string_char) {
        return s.to_string();
    }
    s.chars()
        .map(|c| if yang_string_char(c) { c } else { '\u{FFFD}' })
        .collect()
}

/// Refuse a severity, kind or label the module does not define.
fn check_enumerated(ty: Type, s: &str, path: &str) -> Result<(), CodecError> {
    let known = match ty {
        Type::Severity => Severity::ALL.iter().any(|v| v.as_str() == s),
        Type::FindingKind => FindingKind::ALL.iter().any(|v| v.meta().id == s),
        Type::CountLabel => CountLabel::ALL.iter().any(|v| v.as_str() == s),
        _ => true,
    };
    if known {
        Ok(())
    } else {
        fail(format!("{path}: `{s}` is not a {ty:?} the module defines"))
    }
}

/// Decode one RFC 7951 object through `nodes`, dropping position nodes.
fn decode_object(
    obj: &Map<String, Value>,
    nodes: &[Node],
    at: &str,
) -> Result<Map<String, Value>, CodecError> {
    for name in obj.keys() {
        if !nodes.iter().any(|n| n.name == name) {
            return fail(format!("{at}: `{name}` is not a node of the module"));
        }
    }
    let mut out = Map::new();
    for node in nodes {
        let path = format!("{at}/{}", node.name);
        let Origin::Field(field) = node.origin else {
            // A position is consumed by the list that holds this entry.
            continue;
        };
        match obj.get(node.name) {
            Some(value) => {
                out.insert(field.to_string(), decode_node(node, value, &path)?);
            }
            None => match node.body {
                Body::Leaf {
                    mandatory: true, ..
                } => {
                    return fail(format!("{path}: mandatory and absent"));
                }
                Body::List {
                    when_empty: WhenEmpty::Written,
                    ..
                }
                | Body::LeafList {
                    when_empty: WhenEmpty::Written,
                    ..
                } => {
                    out.insert(field.to_string(), Value::Array(Vec::new()));
                }
                Body::Map {
                    when_empty: WhenEmpty::Written,
                    ..
                } => {
                    out.insert(field.to_string(), Value::Object(Map::new()));
                }
                _ => {}
            },
        }
    }
    Ok(out)
}

/// Decode one node's RFC 7951 value into its plain JSON form.
fn decode_node(node: &Node, value: &Value, path: &str) -> Result<Value, CodecError> {
    match node.body {
        Body::Leaf { ty, .. } => decode_scalar(ty, value, path),
        Body::LeafList { ty, .. } => {
            let items = as_array(value, path)?;
            if items.is_empty() {
                return fail(format!("{path}: an empty leaf-list is written as absent"));
            }
            Ok(Value::Array(
                items
                    .iter()
                    .map(|v| decode_scalar(ty, v, path))
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        }
        Body::List { key, children, .. } => {
            let items = as_array(value, path)?;
            if items.is_empty() {
                return fail(format!("{path}: an empty list is written as absent"));
            }
            let position = children
                .iter()
                .find(|n| n.origin == Origin::Position)
                .map(|n| n.name);
            let mut keyed: Vec<(u64, Map<String, Value>)> = Vec::with_capacity(items.len());
            let mut keys = std::collections::BTreeSet::new();
            for (i, item) in items.iter().enumerate() {
                let Value::Object(entry) = item else {
                    return fail(format!("{path}[{i}]: not an object"));
                };
                let Some(key_value) = entry.get(key) else {
                    return fail(format!("{path}[{i}]: no `{key}`"));
                };
                if !keys.insert(key_value.to_string()) {
                    return fail(format!("{path}: `{key}` {key_value} appears twice"));
                }
                let place = match position {
                    Some(p) => match entry.get(p).and_then(Value::as_u64) {
                        Some(v) => v,
                        None => return fail(format!("{path}[{i}]: no numeric `{p}`")),
                    },
                    None => (i + 1) as u64,
                };
                keyed.push((
                    place,
                    decode_object(entry, children, &format!("{path}[{i}]"))?,
                ));
            }
            keyed.sort_by_key(|(place, _)| *place);
            for (i, (place, _)) in keyed.iter().enumerate() {
                if *place != (i + 1) as u64 {
                    return fail(format!(
                        "{path}: positions must run 1..={} without a gap; found {place} at {}",
                        keyed.len(),
                        i + 1
                    ));
                }
            }
            Ok(Value::Array(
                keyed.into_iter().map(|(_, e)| Value::Object(e)).collect(),
            ))
        }
        Body::Map {
            key,
            key_ty,
            value: value_name,
            value_ty,
            ..
        } => {
            let items = as_array(value, path)?;
            if items.is_empty() {
                return fail(format!("{path}: an empty list is written as absent"));
            }
            let mut out = Map::new();
            for (i, item) in items.iter().enumerate() {
                let Value::Object(entry) = item else {
                    return fail(format!("{path}[{i}]: not an object"));
                };
                if entry.len() != 2 {
                    return fail(format!("{path}[{i}]: expected `{key}` and `{value_name}`"));
                }
                let name = match entry.get(key).map(|k| decode_scalar(key_ty, k, path)) {
                    Some(Ok(Value::String(name))) => name,
                    Some(Err(e)) => return Err(e),
                    _ => return fail(format!("{path}[{i}]: no `{key}`")),
                };
                let Some(v) = entry.get(value_name) else {
                    return fail(format!("{path}[{i}]: no `{value_name}`"));
                };
                if out
                    .insert(name.clone(), decode_scalar(value_ty, v, path)?)
                    .is_some()
                {
                    return fail(format!("{path}: `{name}` appears twice"));
                }
            }
            Ok(Value::Object(out))
        }
    }
}

/// Decode one scalar back into its plain JSON form.
fn decode_scalar(ty: Type, value: &Value, path: &str) -> Result<Value, CodecError> {
    match (ty, value) {
        (Type::Uint32, Value::Number(n)) => match n.as_u64() {
            Some(v) if u32::try_from(v).is_ok() => Ok(Value::from(v)),
            _ => fail(format!("{path}: {n} is not a uint32")),
        },
        (Type::Uint64, Value::String(s)) => {
            // RFC 7950 section 9.2.1 lexical form, restricted to what this
            // module writes: decimal digits, no sign, no leading zero.
            let canonical = !s.is_empty()
                && s.bytes().all(|b| b.is_ascii_digit())
                && (s == "0" || !s.starts_with('0'));
            match s.parse::<u64>() {
                Ok(v) if canonical => Ok(Value::from(v)),
                _ => fail(format!("{path}: \"{s}\" is not a uint64 string")),
            }
        }
        (Type::Boolean, Value::Bool(b)) => Ok(Value::Bool(*b)),
        (Type::String | Type::DateAndTime, Value::String(s)) => Ok(Value::String(s.clone())),
        (Type::Severity | Type::FindingKind | Type::CountLabel, Value::String(s)) => {
            check_enumerated(ty, s, path)?;
            Ok(Value::String(s.clone()))
        }
        _ => fail(format!(
            "{path}: {value} is not the RFC 7951 form of a {ty:?}"
        )),
    }
}

// ── The module text ────────────────────────────────────────────────────

/// Escape a string for a YANG double-quoted string ([RFC 7950 section 6.1.3](https://www.rfc-editor.org/rfc/rfc7950#section-6.1.3)).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// The maximum line length the renderer wraps prose to.
const WIDTH: usize = 72;

/// One argument statement whose string goes on the following lines, wrapped
/// and indented the way `pyang -f yang` writes it:
///
/// ```text
///   description
///     "First line of the text, wrapped at the page width and
///      continued one column in, under the opening quote.";
/// ```
///
/// [RFC 7950 section 6.1.3](https://www.rfc-editor.org/rfc/rfc7950#section-6.1.3) strips the continuation indentation up to the column
/// after the opening quote, so the text reads back with single spaces where
/// the lines break.
fn text_statement(out: &mut String, indent: usize, keyword: &str, text: &str) {
    let pad = " ".repeat(indent);
    out.push_str(&pad);
    out.push_str(keyword);
    out.push('\n');
    let words: Vec<String> = quote(text).split_whitespace().map(str::to_string).collect();
    let first = format!("{pad}  \"");
    let cont = format!("{pad}   ");
    let mut line = first.clone();
    let mut at_start = true;
    for word in &words {
        // Two columns held back for the `";` that closes the last line.
        if !at_start && line.chars().count() + 1 + word.chars().count() > WIDTH - 2 {
            out.push_str(&line);
            out.push('\n');
            line = cont.clone();
            at_start = true;
        }
        if !at_start {
            line.push(' ');
        }
        line.push_str(word);
        at_start = false;
    }
    line.push_str("\";\n");
    out.push_str(&line);
}

/// A `type` statement, one line or a block.
fn type_statement(out: &mut String, indent: usize, ty: Type) {
    let pad = " ".repeat(indent);
    let mut lines = ty.yang().lines();
    let first = lines.next().unwrap_or_default();
    out.push_str(&format!("{pad}type {first}"));
    let rest: Vec<&str> = lines.collect();
    if rest.is_empty() {
        out.push_str(";\n");
    } else {
        out.push('\n');
        for l in rest {
            out.push_str(&format!("{pad}{l}\n"));
        }
    }
}

/// Render one node and its children.
fn render_node(out: &mut String, indent: usize, node: &Node) {
    let pad = " ".repeat(indent);
    match node.body {
        Body::Leaf { ty, mandatory } => {
            out.push_str(&format!("{pad}leaf {} {{\n", node.name));
            type_statement(out, indent + 2, ty);
            if mandatory {
                out.push_str(&format!("{pad}  mandatory true;\n"));
            }
            text_statement(out, indent + 2, "description", node.description);
        }
        Body::LeafList { ty, .. } => {
            out.push_str(&format!("{pad}leaf-list {} {{\n", node.name));
            type_statement(out, indent + 2, ty);
            text_statement(out, indent + 2, "description", node.description);
        }
        Body::List { key, children, .. } => {
            out.push_str(&format!("{pad}list {} {{\n", node.name));
            out.push_str(&format!("{pad}  key \"{key}\";\n"));
            text_statement(out, indent + 2, "description", node.description);
            for child in children {
                render_node(out, indent + 2, child);
            }
        }
        Body::Map {
            key,
            key_ty,
            key_description,
            value,
            value_ty,
            value_description,
            ..
        } => {
            out.push_str(&format!("{pad}list {} {{\n", node.name));
            out.push_str(&format!("{pad}  key \"{key}\";\n"));
            text_statement(out, indent + 2, "description", node.description);
            render_node(
                out,
                indent + 2,
                &Node {
                    name: key,
                    origin: Origin::Position,
                    body: Body::Leaf {
                        ty: key_ty,
                        mandatory: false,
                    },
                    description: key_description,
                },
            );
            render_node(
                out,
                indent + 2,
                &Node {
                    name: value,
                    origin: Origin::Position,
                    body: Body::Leaf {
                        ty: value_ty,
                        mandatory: true,
                    },
                    description: value_description,
                },
            );
        }
    }
    out.push_str(&format!("{pad}}}\n"));
}

/// The description of one finding-kind identity: the kind's own title and
/// detail from [`FindingKind::meta`], and its severity and unit.
fn kind_description(kind: FindingKind) -> String {
    let meta = kind.meta();
    format!(
        "{}. {} Severity: {}. Unit: {}.",
        meta.title,
        meta.detail,
        meta.severity.as_str(),
        meta.unit
    )
}

/// The description of one severity value.
fn severity_description(severity: Severity) -> &'static str {
    match severity {
        Severity::Blind => {
            "This analysis is incomplete: sipnab did not read part of its input, \
             so every count is a floor and a zero means unknown. Ranks above \
             every call fault, because it qualifies every other finding and every \
             absence of one."
        }
        Severity::Critical => {
            "Nobody could hear: media was negotiated and none arrived, arrived in \
             one direction only, or was addressed somewhere the network says it \
             could not be delivered."
        }
        Severity::Major => {
            "The call failed or the media path is provably damaged, but audio was \
             not proven absent."
        }
        Severity::Minor => {
            "Measurable degradation, or an outcome that is frequently normal and \
             is listed so it can be ruled out."
        }
    }
}

/// The `sipnab-diagnosis` module, rendered from the tables.
///
/// The committed file under `yang/` is this function's output, and
/// `SIPNAB_BLESS_YANG=1 cargo test --features full --test yang_module_test`
/// rewrites it.
#[must_use]
pub fn module_text() -> String {
    let mut out = String::with_capacity(48 * 1024);
    out.push_str(&format!("module {MODULE} {{\n"));
    out.push_str("  yang-version 1.1;\n");
    out.push_str(&format!("  namespace \"{NAMESPACE}\";\n"));
    out.push_str(&format!("  prefix {PREFIX};\n\n"));

    out.push_str("  import ietf-yang-types {\n    prefix yang;\n");
    text_statement(&mut out, 4, "reference", "RFC 9911: Common YANG Data Types");
    out.push_str("  }\n\n");

    text_statement(&mut out, 2, "organization", "sipnab");
    text_statement(&mut out, 2, "contact", "https://github.com/NormB/sipnab");
    text_statement(
        &mut out,
        2,
        "description",
        "The capture-level analysis sipnab computes for a packet capture: \
         every problem it already diagnosed, one dialog or one capture at a \
         time, aggregated by kind and ranked worst first, with the denominators \
         it was found in. This module describes that analysis as state data so \
         a file or an HTTP body carrying it can be validated and processed by \
         YANG tools. It is generated from the tables the analysis itself uses; \
         the identities are the catalog of finding kinds and evidence count \
         labels. No server implements it as a datastore: sipnab exports \
         documents that conform to it.",
    );
    out.push('\n');

    for rev in REVISIONS {
        out.push_str(&format!("  revision {} {{\n", rev.date));
        text_statement(&mut out, 4, "description", rev.description);
        text_statement(
            &mut out,
            4,
            "reference",
            "https://sipnab.com/docs/output-formats/",
        );
        out.push_str("  }\n\n");
    }

    out.push_str("  identity finding-kind {\n");
    text_statement(
        &mut out,
        4,
        "description",
        "Base identity of every problem the analysis can report. Each derived \
         identity is named with the analysis's own stable id, the value the \
         plain JSON encoding carries as 'kind'.",
    );
    out.push_str("  }\n\n");
    for kind in FindingKind::ALL {
        out.push_str(&format!("  identity {} {{\n", kind.meta().id));
        out.push_str("    base finding-kind;\n");
        text_statement(&mut out, 4, "description", &kind_description(kind));
        out.push_str("  }\n\n");
    }

    out.push_str("  identity count-label {\n");
    text_statement(
        &mut out,
        4,
        "description",
        "Base identity of every named count an evidence row can carry. Each \
         derived identity is named with the label the plain JSON encoding uses \
         as a key of 'counts'.",
    );
    out.push_str("  }\n\n");
    for label in CountLabel::ALL {
        out.push_str(&format!("  identity {} {{\n", label.as_str()));
        out.push_str("    base count-label;\n");
        text_statement(&mut out, 4, "description", label.description());
        out.push_str("  }\n\n");
    }

    out.push_str("  typedef severity {\n    type enumeration {\n");
    for (i, severity) in Severity::ALL.iter().enumerate() {
        out.push_str(&format!("      enum {} {{\n", severity.as_str()));
        out.push_str(&format!("        value {};\n", i + 1));
        text_statement(&mut out, 8, "description", severity_description(*severity));
        out.push_str("      }\n");
    }
    out.push_str("    }\n");
    text_statement(
        &mut out,
        4,
        "description",
        "How bad a finding is, as a ladder: blind, then critical, then major, \
         then minor, worst first. The values state the order. This is not the \
         severity of RFC 8632: an alarm there requires corrective action, while \
         'minor' here includes outcomes listed only so they can be ruled out, \
         and 'blind' describes the analysis rather than the network.",
    );
    out.push_str("  }\n\n");

    out.push_str(&format!("  container {TOP} {{\n"));
    out.push_str("    config false;\n");
    text_statement(&mut out, 4, "description", TOP_DESCRIPTION);
    for node in CAPTURE_ANALYSIS {
        render_node(&mut out, 4, node);
    }
    out.push_str("  }\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::Value;

    use super::*;
    use crate::analysis::{CAPTURE_ANALYSIS_SCHEMA_VERSION, Evidence, Finding};

    /// An analysis with every optional field present and every collection
    /// non-empty, so every node has something to encode.
    ///
    /// Struct literals throughout, never `..Default::default()`: a field added
    /// to any of the three structs is a compile error here until it is
    /// populated, and then a census failure below until it has a node.
    fn populated() -> CaptureAnalysis {
        let at = chrono::DateTime::from_timestamp_millis(1_700_000_000_123).expect("valid");
        CaptureAnalysis {
            schema_version: CAPTURE_ANALYSIS_SCHEMA_VERSION,
            filter: Some("one_way == true".to_string()),
            // Above 2^32, so a uint64 carried as a uint32 anywhere would show.
            frames_read: 5_000_000_000,
            dialogs_examined: 3,
            streams_examined: 4,
            complete: false,
            findings: vec![
                Finding {
                    kind: FindingKind::UndecodableFrames,
                    severity: Severity::Blind,
                    occurrences: 49,
                    unit: "frame",
                    evidence: vec![Evidence {
                        call_id: None,
                        endpoints: Vec::new(),
                        at: None,
                        counts: BTreeMap::from([
                            (CountLabel::Frames, 49),
                            (CountLabel::FramesRead, 5_000_000_000),
                        ]),
                        note: Some("unsupported link type 0 (49)".to_string()),
                    }],
                    evidence_omitted: 0,
                },
                Finding {
                    kind: FindingKind::OneWayAudio,
                    severity: Severity::Critical,
                    occurrences: 12,
                    unit: "call",
                    evidence: vec![
                        Evidence {
                            call_id: Some("a@192.0.2.1".to_string()),
                            endpoints: vec![
                                "192.0.2.1:5060 -> 192.0.2.2".to_string(),
                                "SDP 192.0.2.1".to_string(),
                            ],
                            at: Some(at),
                            counts: BTreeMap::from([
                                (CountLabel::RtpPackets, 425),
                                (CountLabel::Streams, 1),
                            ]),
                            note: Some("nothing came back the other way".to_string()),
                        },
                        Evidence {
                            call_id: Some("b@192.0.2.1".to_string()),
                            endpoints: vec!["192.0.2.3:5060 -> 192.0.2.4".to_string()],
                            at: Some(at),
                            counts: BTreeMap::from([(CountLabel::RtpPackets, 7)]),
                            note: None,
                        },
                    ],
                    evidence_omitted: 10,
                },
            ],
        }
    }

    /// The serialized field names a node table claims.
    fn fields(nodes: &[Node]) -> BTreeSet<&'static str> {
        nodes
            .iter()
            .filter_map(|n| match n.origin {
                Origin::Field(f) => Some(f),
                Origin::Position => None,
            })
            .collect()
    }

    /// The member names of a JSON object.
    fn keys(v: &Value) -> BTreeSet<&str> {
        v.as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect()
    }

    /// Every serialized field has a node, and every node a field, for all
    /// three structs.
    ///
    /// Driven from a serialized value rather than the source text, so a
    /// `#[serde(rename)]` is compared as it appears on the wire.
    #[test]
    fn every_serialized_field_has_a_node_and_every_node_a_field() {
        let plain = serde_json::to_value(populated()).expect("serializes");
        let finding = &plain["findings"][1];
        let evidence = &finding["evidence"][0];
        for (what, nodes, value) in [
            ("CaptureAnalysis", CAPTURE_ANALYSIS, &plain),
            ("Finding", FINDING, finding),
            ("Evidence", EVIDENCE, evidence),
        ] {
            assert_eq!(
                fields(nodes),
                keys(value),
                "{what}: the node table and the serialization disagree"
            );
        }
    }

    /// `WhenEmpty` says what serde really does with an empty collection, and
    /// an optional leaf is absent when `None` while a mandatory one never is.
    ///
    /// The decoder restores an absent collection from `WhenEmpty`, so a wrong
    /// marker would make every decoded empty analysis differ from the plain
    /// JSON in exactly the case the fixtures are least likely to exercise.
    #[test]
    fn the_table_describes_what_serde_writes_for_empty_and_absent_values() {
        let empty = CaptureAnalysis {
            filter: None,
            findings: vec![Finding {
                kind: FindingKind::NoMedia,
                severity: Severity::Critical,
                occurrences: 1,
                unit: "call",
                evidence: vec![Evidence::default()],
                evidence_omitted: 0,
            }],
            ..CaptureAnalysis::default()
        };
        let mut sparse_finding = empty.findings[0].clone();
        sparse_finding.evidence.clear();
        let sparse = CaptureAnalysis {
            findings: vec![sparse_finding],
            ..empty.clone()
        };
        let no_findings = CaptureAnalysis {
            findings: Vec::new(),
            ..empty.clone()
        };
        let plain = |a: &CaptureAnalysis| serde_json::to_value(a).expect("serializes");
        // With the key of the list each entry belongs to: a key leaf is
        // always present, and RFC 7950 makes it so without `mandatory`.
        let cases = [
            (CAPTURE_ANALYSIS, plain(&no_findings), None),
            (FINDING, plain(&sparse)["findings"][0].clone(), Some("kind")),
            (
                EVIDENCE,
                plain(&empty)["findings"][0]["evidence"][0].clone(),
                Some("index"),
            ),
        ];
        let mut checked = 0;
        for (nodes, value, key) in &cases {
            for node in *nodes {
                let Origin::Field(field) = node.origin else {
                    continue;
                };
                let present = value.get(field).is_some();
                let expected = match node.body {
                    Body::Leaf { mandatory, .. } => mandatory || *key == Some(node.name),
                    Body::LeafList { when_empty, .. }
                    | Body::List { when_empty, .. }
                    | Body::Map { when_empty, .. } => when_empty == WhenEmpty::Written,
                };
                assert_eq!(
                    present,
                    expected,
                    "`{field}` is {} when empty or None, and the table says otherwise",
                    if present { "written" } else { "absent" }
                );
                checked += 1;
            }
        }
        assert!(checked >= 15, "only {checked} fields checked");
    }

    /// Identity names are unique across both families, and neither family
    /// reuses a base's name.
    #[test]
    fn identity_names_are_unique_across_both_families() {
        let mut seen = BTreeSet::from(["finding-kind", "count-label"]);
        for name in FindingKind::ALL
            .iter()
            .map(|k| k.meta().id)
            .chain(CountLabel::ALL.iter().map(|l| l.as_str()))
        {
            assert!(seen.insert(name), "`{name}` is defined twice");
        }
    }

    /// Every list names one of its own children as its key, holds at most
    /// one position leaf, and no two siblings share a name.
    #[test]
    fn every_list_is_keyed_by_its_own_child() {
        fn walk(nodes: &[Node], at: &str) -> usize {
            let mut names = BTreeSet::new();
            let mut lists = 0;
            for n in nodes {
                assert!(names.insert(n.name), "{at}: `{}` twice", n.name);
                if let Body::List { key, children, .. } = n.body {
                    lists += 1;
                    assert!(
                        children.iter().any(|c| c.name == key),
                        "{at}/{}: key `{key}` is not a child",
                        n.name
                    );
                    assert!(
                        children
                            .iter()
                            .filter(|c| c.origin == Origin::Position)
                            .count()
                            <= 1,
                        "{at}/{}: two position leaves",
                        n.name
                    );
                    lists += walk(children, &format!("{at}/{}", n.name));
                }
            }
            lists
        }
        assert_eq!(walk(CAPTURE_ANALYSIS, ""), 2, "finding and evidence");
    }

    /// The rendered module names every identity, every node and the revision.
    ///
    /// The committed file is compared to this text by
    /// `tests/yang_module_test.rs`; this is the cheaper check that the text
    /// says what the tables say before anyone blesses it.
    #[test]
    fn the_module_text_renders_every_table() {
        let text = module_text();
        assert!(text.starts_with("module sipnab-diagnosis {\n"));
        assert!(text.contains(&format!("revision {REVISION} {{")));
        for kind in FindingKind::ALL {
            assert!(
                text.contains(&format!(
                    "identity {} {{\n    base finding-kind;",
                    kind.meta().id
                )),
                "{:?} has no identity",
                kind
            );
        }
        for label in CountLabel::ALL {
            assert!(
                text.contains(&format!(
                    "identity {} {{\n    base count-label;",
                    label.as_str()
                )),
                "{label} has no identity"
            );
        }
        for (i, s) in Severity::ALL.iter().enumerate() {
            assert!(text.contains(&format!("enum {} {{\n        value {};", s.as_str(), i + 1)));
        }
        fn names(nodes: &[Node], out: &mut Vec<&'static str>) {
            for n in nodes {
                out.push(n.name);
                if let Body::List { children, .. } = n.body {
                    names(children, out);
                }
            }
        }
        let mut all = Vec::new();
        names(CAPTURE_ANALYSIS, &mut all);
        for name in all {
            assert!(
                text.contains(&format!(" {name} {{\n")),
                "node `{name}` is not rendered"
            );
        }
        assert!(
            text.lines()
                .all(|l| l.chars().count() <= WIDTH || !l.contains(' ')),
            "a line runs past the page width"
        );
    }

    /// The one member of an RFC 7951 document.
    fn body(doc: &Value) -> &Value {
        &doc["sipnab-diagnosis:capture-analysis"]
    }

    /// [RFC 7951 section 6.1](https://www.rfc-editor.org/rfc/rfc7951#section-6.1): every `uint64` is a JSON string and every
    /// `uint32` stays a number.
    #[test]
    fn a_uint64_is_a_string_and_a_uint32_is_a_number() {
        let doc = to_rfc7951(&populated()).expect("encodes");
        let top = body(&doc);
        assert_eq!(top["frames-read"], Value::from("5000000000"));
        assert_eq!(top["dialogs-examined"], Value::from("3"));
        assert_eq!(top["streams-examined"], Value::from("4"));
        assert_eq!(top["schema-version"], Value::from(1));
        let finding = &top["finding"][1];
        assert_eq!(finding["occurrences"], Value::from("12"));
        assert_eq!(finding["evidence-omitted"], Value::from("10"));
        assert_eq!(finding["rank"], Value::from(2));
        let evidence = &finding["evidence"][0];
        assert_eq!(evidence["index"], Value::from(1));
        assert_eq!(
            evidence["count"],
            serde_json::json!([
                {"name": "rtp_packets", "value": "425"},
                {"name": "streams", "value": "1"}
            ])
        );
    }

    /// [RFC 7951 section 4](https://www.rfc-editor.org/rfc/rfc7951#section-4): the top-level member is qualified by the module
    /// name, and nothing below it is.
    #[test]
    fn only_the_top_level_member_is_qualified() {
        let doc = to_rfc7951(&populated()).expect("encodes");
        assert_eq!(
            keys(&doc),
            BTreeSet::from(["sipnab-diagnosis:capture-analysis"])
        );
        fn no_colon_below(v: &Value, at: &str) {
            match v {
                Value::Object(map) => {
                    for (k, child) in map {
                        assert!(!k.contains(':'), "{at}/{k} is qualified");
                        no_colon_below(child, &format!("{at}/{k}"));
                    }
                }
                Value::Array(items) => items.iter().for_each(|i| no_colon_below(i, at)),
                _ => {}
            }
        }
        no_colon_below(body(&doc), "");
        // An identity in the same module takes the simple form (RFC 7951
        // section 6.8), which is the plain JSON's own string.
        assert_eq!(body(&doc)["finding"][0]["kind"], "undecodable_frames");
    }

    /// The document decodes back to the plain JSON it was encoded from.
    #[test]
    fn decode_inverts_encode() {
        for analysis in [populated(), CaptureAnalysis::default()] {
            let plain = serde_json::to_value(&analysis).expect("serializes");
            let doc = to_rfc7951(&analysis).expect("encodes");
            assert_eq!(decode(&doc).expect("decodes"), plain);
        }
    }

    /// The decoder refuses what RFC 7951 and the module forbid, rather than
    /// repairing it: the mirror test is only as strong as this.
    #[test]
    fn the_decoder_refuses_what_the_encoding_forbids() {
        let good = to_rfc7951(&populated()).expect("encodes");
        /// What the case breaks, and how.
        type Corruption = (&'static str, fn(&mut Value));
        let corrupt: [Corruption; 9] = [
            ("a uint64 as a number", |d| {
                d["sipnab-diagnosis:capture-analysis"]["frames-read"] = Value::from(5);
            }),
            ("a uint32 as a string", |d| {
                d["sipnab-diagnosis:capture-analysis"]["schema-version"] = Value::from("1");
            }),
            ("an unqualified top-level member", |d| {
                let v = d
                    .as_object_mut()
                    .and_then(|m| m.remove("sipnab-diagnosis:capture-analysis"))
                    .unwrap_or_default();
                d["capture-analysis"] = v;
            }),
            ("a second top-level member", |d| {
                d["source_exhausted"] = Value::Bool(true);
            }),
            ("an unknown member", |d| {
                d["sipnab-diagnosis:capture-analysis"]["surprise"] = Value::from(1);
            }),
            ("an unknown identity", |d| {
                d["sipnab-diagnosis:capture-analysis"]["finding"][0]["kind"] =
                    Value::from("no_such_kind");
            }),
            ("a gap in rank", |d| {
                d["sipnab-diagnosis:capture-analysis"]["finding"][1]["rank"] = Value::from(3);
            }),
            ("a missing mandatory leaf", |d| {
                if let Some(m) = d["sipnab-diagnosis:capture-analysis"].as_object_mut() {
                    m.remove("complete");
                }
            }),
            ("a uint64 with a leading zero", |d| {
                d["sipnab-diagnosis:capture-analysis"]["frames-read"] = Value::from("05");
            }),
        ];
        assert!(decode(&good).is_ok(), "sanity: the document itself decodes");
        for (what, f) in corrupt {
            let mut bad = good.clone();
            f(&mut bad);
            assert!(decode(&bad).is_err(), "the decoder accepted {what}");
        }
    }

    /// The ranking survives the trip even when a consumer reorders the list.
    ///
    /// [RFC 7950 section 7.7.7](https://www.rfc-editor.org/rfc/rfc7950#section-7.7.7) lets a YANG tool reorder state data, so the
    /// decoder must restore order from `rank` and `index` and never from
    /// array position.
    #[test]
    fn the_decoder_orders_by_rank_and_index_not_by_position() {
        let plain = serde_json::to_value(populated()).expect("serializes");
        let mut doc = to_rfc7951(&populated()).expect("encodes");
        let top = &mut doc["sipnab-diagnosis:capture-analysis"];
        if let Some(findings) = top["finding"].as_array_mut() {
            findings.reverse();
        }
        if let Some(evidence) = top["finding"][0]["evidence"].as_array_mut() {
            evidence.reverse();
        }
        assert_eq!(decode(&doc).expect("decodes"), plain);
    }

    /// A character YANG's string type cannot carry is written as U+FFFD, and
    /// nothing else about the string changes.
    #[test]
    fn a_character_yang_cannot_carry_becomes_the_replacement_character() {
        assert_eq!(yang_string("a\u{1b}[31mb"), "a\u{FFFD}[31mb");
        assert_eq!(yang_string("x\u{FFFE}y\u{FFFF}"), "x\u{FFFD}y\u{FFFD}");
        let kept = "tab\tcr\rlf\n del\u{7f} nel\u{85} \u{10FFFD}";
        assert_eq!(yang_string(kept), kept, "legal characters are untouched");

        let mut analysis = populated();
        analysis.findings[1].evidence[0].note = Some("bell\u{7}".to_string());
        let doc = to_rfc7951(&analysis).expect("encodes");
        assert_eq!(
            body(&doc)["finding"][1]["evidence"][0]["note"],
            "bell\u{FFFD}"
        );
    }
}
