// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The one reader of the JSON request bodies the REST API takes.
//!
//! Every route that changes state takes a small, flat JSON object: a boolean,
//! an address, a lifetime, an action id. This module reads such a body against
//! the list of fields its route declares and builds nothing the list does not
//! name. The rules, in the order the reader applies them:
//!
//! - The body is UTF-8 text holding exactly one JSON object
//!   ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html)), with nothing
//!   after it but whitespace. A JSON array is refused: a derived
//!   `Deserialize` would have read `[true]` as `{"enabled": true}`.
//! - Each key is one the route declares, and appears once. An unknown key is
//!   refused before its value is read, and so is a second copy of a key:
//!   [RFC 8259 section 4](https://www.rfc-editor.org/rfc/rfc8259.html#section-4) leaves the meaning of a repeated name to each parser,
//!   so `{"enabled": false, "enabled": true}` could close the gate for a proxy
//!   that reads the first copy and open it for a reader that keeps the last.
//! - Each value is a single scalar of the declared kind. An object or an
//!   array as a value is refused without being read, so no body nests deeper
//!   than one level and the reader never recurses.
//! - A field the route marks required is present and not `null`; an optional
//!   field may be absent or `null`, which mean the same thing.
//!
//! The body's size is bounded before this reader runs, by the router's
//! request body limit. The reader keeps one value per declared field, so what
//! it allocates is bounded by the body and by the route's field list, and a
//! body cannot make it build a tree.

use std::fmt;

/// The kind of value a field holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `true` or `false`.
    Bool,
    /// A JSON string.
    String,
    /// A whole number from `0` to `u64::MAX`, written without a sign, a
    /// fraction or an exponent.
    WholeNumber,
}

impl Kind {
    /// The kind as a refusal names it.
    fn describe(self) -> &'static str {
        match self {
            Self::Bool => "true or false",
            Self::String => "a string",
            Self::WholeNumber => "a whole number from 0 to 18446744073709551615",
        }
    }
}

/// One field a route's body may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Field {
    /// The key, as the body spells it.
    pub(crate) name: &'static str,
    /// The kind of value the key holds.
    pub(crate) kind: Kind,
    /// Whether the body must carry the key with a value other than `null`.
    pub(crate) required: bool,
}

impl Field {
    /// A field the body must carry.
    pub(crate) const fn required(name: &'static str, kind: Kind) -> Self {
        Self {
            name,
            kind,
            required: true,
        }
    }

    /// A field the body may leave out or set to `null`.
    pub(crate) const fn optional(name: &'static str, kind: Kind) -> Self {
        Self {
            name,
            kind,
            required: false,
        }
    }
}

/// One value the reader kept.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Scalar {
    /// A [`Kind::Bool`] value.
    Bool(bool),
    /// A [`Kind::String`] value, unescaped.
    String(String),
    /// A [`Kind::WholeNumber`] value.
    WholeNumber(u64),
}

/// Why a body was refused. Its text is the `detail` of the `400` the route
/// answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BodyRefusal {
    /// The body is not UTF-8.
    NotUtf8,
    /// The body is not one JSON object: empty, an array, a scalar or text.
    NotAnObject,
    /// The body starts as an object and is not valid JSON.
    Malformed,
    /// The body has a key the route does not declare.
    UnknownKey {
        /// The keys the route declares.
        allowed: &'static [Field],
    },
    /// A declared key appears more than once.
    DuplicateKey(&'static str),
    /// A declared key holds an object or an array.
    Nested(&'static str),
    /// A declared key holds a value of another kind.
    WrongType(&'static str, Kind),
    /// A required key is absent or `null`.
    Missing(&'static str),
    /// Text other than whitespace follows the object.
    TrailingContent,
}

impl fmt::Display for BodyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str("the body is not UTF-8 text"),
            Self::NotAnObject => f.write_str("the body must be one JSON object"),
            Self::Malformed => f.write_str("the body is not valid JSON"),
            Self::UnknownKey { allowed } => {
                f.write_str("the body takes only these keys: ")?;
                for (i, field) in allowed.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(field.name)?;
                }
                Ok(())
            }
            Self::DuplicateKey(name) => write!(f, "the key `{name}` appears more than once"),
            Self::Nested(name) => {
                write!(f, "`{name}` must be one value, not an object or an array")
            }
            Self::WrongType(name, kind) => write!(f, "`{name}` must be {}", kind.describe()),
            Self::Missing(name) => write!(f, "the body has no `{name}`"),
            Self::TrailingContent => f.write_str("the body has text after its JSON object"),
        }
    }
}

/// A body read against its route's fields: at most one value per field.
#[derive(Debug)]
pub(crate) struct ClosedObject {
    /// The route's fields, in the order of `values`.
    fields: &'static [Field],
    /// One slot per field: `None` when the body left it out or set `null`.
    values: Vec<Option<Scalar>>,
}

impl ClosedObject {
    /// The slot of the field named `name`, if the route declares one.
    fn slot(&self, name: &str) -> Option<usize> {
        self.fields.iter().position(|f| f.name == name)
    }

    /// The boolean `name` holds, or `None` when it is absent, `null`, or not
    /// a declared boolean field.
    pub(crate) fn bool(&self, name: &str) -> Option<bool> {
        match self.slot(name).and_then(|i| self.values[i].as_ref()) {
            Some(Scalar::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// The whole number `name` holds, or `None` when it is absent, `null`, or
    /// not a declared whole-number field.
    pub(crate) fn whole_number(&self, name: &str) -> Option<u64> {
        match self.slot(name).and_then(|i| self.values[i].as_ref()) {
            Some(Scalar::WholeNumber(n)) => Some(*n),
            _ => None,
        }
    }

    /// The string `name` holds, moved out, or `None` when it is absent,
    /// `null`, or not a declared string field.
    pub(crate) fn take_string(&mut self, name: &str) -> Option<String> {
        let i = self.slot(name)?;
        match self.values[i].take() {
            Some(Scalar::String(s)) => Some(s),
            other => {
                self.values[i] = other;
                None
            }
        }
    }
}

/// A request body type that the reader builds from its declared fields.
pub(crate) trait ClosedBody: Sized {
    /// The fields the body may carry. The published OpenAPI schema of the
    /// type lists the same ones.
    const FIELDS: &'static [Field];

    /// Build the value from a body the reader accepted.
    ///
    /// # Errors
    ///
    /// [`BodyRefusal::Missing`] when a required field is not there, which the
    /// reader has already refused, so only a field list and a constructor that
    /// disagree reach it.
    fn from_object(object: ClosedObject) -> Result<Self, BodyRefusal>;
}

/// Read `bytes` as the body type `T`.
///
/// # Errors
///
/// The [`BodyRefusal`] that says why the body is not a `T`.
pub(crate) fn read_body<T: ClosedBody>(bytes: &[u8]) -> Result<T, BodyRefusal> {
    T::from_object(read_closed_object(bytes, T::FIELDS)?)
}

/// Read `bytes` as one JSON object that carries only `fields`.
///
/// # Errors
///
/// The [`BodyRefusal`] that says why the body is refused; the module
/// documentation lists the rules.
pub(crate) fn read_closed_object(
    bytes: &[u8],
    fields: &'static [Field],
) -> Result<ClosedObject, BodyRefusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| BodyRefusal::NotUtf8)?;
    let mut reader = Reader {
        s: text.as_bytes(),
        i: 0,
    };
    let mut object = ClosedObject {
        fields,
        values: vec![None; fields.len()],
    };
    let mut seen = vec![false; fields.len()];

    reader.skip_ws();
    if reader.peek() != Some(b'{') {
        return Err(BodyRefusal::NotAnObject);
    }
    reader.i += 1;
    reader.skip_ws();
    if reader.peek() == Some(b'}') {
        reader.i += 1;
    } else {
        loop {
            reader.skip_ws();
            if reader.peek() != Some(b'"') {
                return Err(BodyRefusal::Malformed);
            }
            reader.i += 1;
            let key = reader.string()?;
            let slot = fields
                .iter()
                .position(|f| f.name == key)
                .ok_or(BodyRefusal::UnknownKey { allowed: fields })?;
            let field = fields[slot];
            if seen[slot] {
                return Err(BodyRefusal::DuplicateKey(field.name));
            }
            seen[slot] = true;
            reader.skip_ws();
            if reader.peek() != Some(b':') {
                return Err(BodyRefusal::Malformed);
            }
            reader.i += 1;
            reader.skip_ws();
            object.values[slot] = reader.value(field)?;
            reader.skip_ws();
            match reader.peek() {
                Some(b',') => reader.i += 1,
                Some(b'}') => {
                    reader.i += 1;
                    break;
                }
                _ => return Err(BodyRefusal::Malformed),
            }
        }
    }
    reader.skip_ws();
    if reader.peek().is_some() {
        return Err(BodyRefusal::TrailingContent);
    }
    for (field, value) in fields.iter().zip(&object.values) {
        if field.required && value.is_none() {
            return Err(BodyRefusal::Missing(field.name));
        }
    }
    Ok(object)
}

/// A cursor over the body's bytes, which are known to be UTF-8.
struct Reader<'a> {
    /// The whole body.
    s: &'a [u8],
    /// The index of the next byte to read.
    i: usize,
}

impl Reader<'_> {
    /// The next byte, or `None` at the end of the body.
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// Skip the four whitespace bytes [RFC 8259 section 2](https://www.rfc-editor.org/rfc/rfc8259.html#section-2) allows.
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    /// Consume `word` exactly, or refuse the body.
    fn literal(&mut self, word: &[u8]) -> Result<(), BodyRefusal> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(BodyRefusal::Malformed)
        }
    }

    /// The value of `field`, the cursor on its first byte: `None` for `null`.
    fn value(&mut self, field: Field) -> Result<Option<Scalar>, BodyRefusal> {
        let wrong = BodyRefusal::WrongType(field.name, field.kind);
        let scalar = match self.peek() {
            Some(b'{' | b'[') => return Err(BodyRefusal::Nested(field.name)),
            Some(b't') => {
                self.literal(b"true")?;
                Scalar::Bool(true)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Scalar::Bool(false)
            }
            Some(b'n') => {
                self.literal(b"null")?;
                return if field.required { Err(wrong) } else { Ok(None) };
            }
            Some(b'"') => {
                self.i += 1;
                Scalar::String(self.string()?)
            }
            Some(b'-' | b'0'..=b'9') => match self.number()? {
                Some(n) => Scalar::WholeNumber(n),
                None => return Err(wrong),
            },
            _ => return Err(BodyRefusal::Malformed),
        };
        let kind = match scalar {
            Scalar::Bool(_) => Kind::Bool,
            Scalar::String(_) => Kind::String,
            Scalar::WholeNumber(_) => Kind::WholeNumber,
        };
        if kind == field.kind {
            Ok(Some(scalar))
        } else {
            Err(wrong)
        }
    }

    /// A number token by the [RFC 8259 section 6](https://www.rfc-editor.org/rfc/rfc8259.html#section-6) grammar: `Some` when it is a
    /// whole number that fits a `u64`, `None` for any other valid number.
    fn number(&mut self) -> Result<Option<u64>, BodyRefusal> {
        let start = self.i;
        let mut whole = true;
        if self.peek() == Some(b'-') {
            whole = false;
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(BodyRefusal::Malformed),
        }
        if self.peek() == Some(b'.') {
            whole = false;
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(BodyRefusal::Malformed);
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            whole = false;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(BodyRefusal::Malformed);
            }
            self.digits();
        }
        if !whole {
            return Ok(None);
        }
        let token =
            std::str::from_utf8(&self.s[start..self.i]).map_err(|_| BodyRefusal::Malformed)?;
        Ok(token.parse::<u64>().ok())
    }

    /// Skip a run of ASCII digits.
    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
    }

    /// The rest of a string whose opening quote is consumed, unescaped.
    fn string(&mut self) -> Result<String, BodyRefusal> {
        let mut out = String::new();
        let mut run = self.i;
        loop {
            match self.peek() {
                None => return Err(BodyRefusal::Malformed),
                Some(b'"') => {
                    out.push_str(self.run(run)?);
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    out.push_str(self.run(run)?);
                    self.i += 1;
                    out.push(self.escape()?);
                    run = self.i;
                }
                // RFC 8259 section 7: the control characters must be escaped.
                Some(0x00..=0x1f) => return Err(BodyRefusal::Malformed),
                Some(_) => self.i += 1,
            }
        }
    }

    /// The text from `start` to the cursor. Both ends sit next to an ASCII
    /// byte, so the slice is whole UTF-8.
    fn run(&self, start: usize) -> Result<&str, BodyRefusal> {
        std::str::from_utf8(&self.s[start..self.i]).map_err(|_| BodyRefusal::Malformed)
    }

    /// One escape, the cursor past its backslash.
    fn escape(&mut self) -> Result<char, BodyRefusal> {
        let c = match self.peek() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{08}',
            Some(b'f') => '\u{0c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.i += 1;
                let unit = self.hex4()?;
                return match unit {
                    0xd800..=0xdbff => {
                        self.literal(b"\\u")?;
                        let low = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(BodyRefusal::Malformed);
                        }
                        let code = 0x1_0000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                        char::from_u32(code).ok_or(BodyRefusal::Malformed)
                    }
                    0xdc00..=0xdfff => Err(BodyRefusal::Malformed),
                    _ => char::from_u32(unit).ok_or(BodyRefusal::Malformed),
                };
            }
            _ => return Err(BodyRefusal::Malformed),
        };
        self.i += 1;
        Ok(c)
    }

    /// Four hex digits, as a UTF-16 code unit.
    fn hex4(&mut self) -> Result<u32, BodyRefusal> {
        let digits = self
            .s
            .get(self.i..self.i + 4)
            .ok_or(BodyRefusal::Malformed)?;
        let mut unit = 0;
        for &d in digits {
            let v = char::from(d).to_digit(16).ok_or(BodyRefusal::Malformed)?;
            unit = unit * 16 + v;
        }
        self.i += 4;
        Ok(unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The persistence gate's one field.
    const GATE: &[Field] = &[Field::required("enabled", Kind::Bool)];
    /// A ban's two fields.
    const BAN: &[Field] = &[
        Field::required("ip", Kind::String),
        Field::optional("ttl_secs", Kind::WholeNumber),
    ];
    /// A revert's two optional fields.
    const REVERT: &[Field] = &[
        Field::optional("id", Kind::String),
        Field::optional("all", Kind::Bool),
    ];

    fn read(body: &str, fields: &'static [Field]) -> Result<ClosedObject, BodyRefusal> {
        read_closed_object(body.as_bytes(), fields)
    }

    fn refusal(body: &str, fields: &'static [Field]) -> Option<BodyRefusal> {
        read(body, fields).err()
    }

    fn string_of(body: &str, fields: &'static [Field], name: &str) -> Option<String> {
        read(body, fields).ok()?.take_string(name)
    }

    // ── Success ────────────────────────────────────────────────────

    #[test]
    fn a_required_bool_true_is_read() {
        let got = read(r#"{"enabled":true}"#, GATE).map(|o| o.bool("enabled"));
        assert_eq!(got, Ok(Some(true)), "the gate body with true");
    }

    #[test]
    fn a_required_bool_false_is_read() {
        let got = read(r#"{"enabled":false}"#, GATE).map(|o| o.bool("enabled"));
        assert_eq!(got, Ok(Some(false)), "the gate body with false");
    }

    #[test]
    fn a_string_and_a_whole_number_are_read() -> Result<(), BodyRefusal> {
        let mut o = read(r#"{"ip":"192.0.2.7","ttl_secs":3600}"#, BAN)?;
        assert_eq!(o.take_string("ip").as_deref(), Some("192.0.2.7"), "ip");
        assert_eq!(o.whole_number("ttl_secs"), Some(3600), "ttl_secs");
        Ok(())
    }

    #[test]
    fn an_optional_field_may_be_absent() -> Result<(), BodyRefusal> {
        let o = read(r#"{"ip":"192.0.2.7"}"#, BAN)?;
        assert_eq!(
            o.whole_number("ttl_secs"),
            None,
            "an absent ttl_secs is None"
        );
        Ok(())
    }

    #[test]
    fn null_for_an_optional_field_reads_as_absent() -> Result<(), BodyRefusal> {
        let o = read(r#"{"ip":"192.0.2.7","ttl_secs":null}"#, BAN)?;
        assert_eq!(o.whole_number("ttl_secs"), None, "a null ttl_secs is None");
        Ok(())
    }

    #[test]
    fn whitespace_of_all_four_kinds_is_allowed_around_every_token() {
        let body = " \t\r\n{ \t\r\n\"enabled\" \t\r\n: \t\r\ntrue \t\r\n} \t\r\n";
        let got = read(body, GATE).map(|o| o.bool("enabled"));
        assert_eq!(got, Ok(Some(true)), "whitespace around every token");
    }

    #[test]
    fn keys_may_come_in_any_order() -> Result<(), BodyRefusal> {
        let mut o = read(r#"{"ttl_secs":60,"ip":"192.0.2.8"}"#, BAN)?;
        assert_eq!(o.take_string("ip").as_deref(), Some("192.0.2.8"), "ip");
        assert_eq!(o.whole_number("ttl_secs"), Some(60), "ttl_secs");
        Ok(())
    }

    #[test]
    fn every_short_escape_is_decoded() {
        let body = "{\"id\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\"}";
        assert_eq!(
            body.matches('\\').count(),
            10,
            "the body carries its escapes: {body}"
        );
        let got = string_of(body, REVERT, "id");
        assert_eq!(
            got.as_deref(),
            Some("\"\\/\u{8}\u{c}\n\r\tA"),
            "the eight short escapes and one \\u escape"
        );
    }

    #[test]
    fn a_surrogate_pair_decodes_to_one_character() {
        let body = "{\"id\":\"\\ud83d\\ude00\"}";
        assert!(body.is_ascii(), "the pair is written as escapes: {body}");
        let got = string_of(body, REVERT, "id");
        assert_eq!(
            got.as_deref(),
            Some("\u{1f600}"),
            "U+1F600 from its UTF-16 pair"
        );
    }

    #[test]
    fn a_key_written_with_an_escape_names_its_field() {
        let body = "{\"en\\u0061bled\":true}";
        assert!(
            !body.contains("enabled"),
            "the key is written with an escape: {body}"
        );
        let got = read(body, GATE).map(|o| o.bool("enabled"));
        assert_eq!(got, Ok(Some(true)), "en\\u0061bled is the key enabled");
    }

    #[test]
    fn utf8_text_in_a_string_is_kept() {
        let got = string_of("{\"id\":\"a-\u{fc}-\u{4e2d}\"}", REVERT, "id");
        assert_eq!(
            got.as_deref(),
            Some("a-\u{fc}-\u{4e2d}"),
            "two- and three-byte UTF-8"
        );
    }

    #[test]
    fn zero_and_the_largest_u64_are_whole_numbers() {
        let zero = read(r#"{"ip":"x","ttl_secs":0}"#, BAN).map(|o| o.whole_number("ttl_secs"));
        assert_eq!(zero, Ok(Some(0)), "0");
        let max = read(r#"{"ip":"x","ttl_secs":18446744073709551615}"#, BAN)
            .map(|o| o.whole_number("ttl_secs"));
        assert_eq!(max, Ok(Some(u64::MAX)), "u64::MAX");
    }

    #[test]
    fn an_empty_object_is_read_when_every_field_is_optional() -> Result<(), BodyRefusal> {
        let o = read("{}", REVERT)?;
        assert_eq!(o.bool("all"), None, "no all");
        Ok(())
    }

    #[test]
    fn read_body_builds_a_type_through_its_constructor() {
        struct Gate {
            enabled: bool,
        }
        impl ClosedBody for Gate {
            const FIELDS: &'static [Field] = GATE;
            fn from_object(object: ClosedObject) -> Result<Self, BodyRefusal> {
                Ok(Self {
                    enabled: object
                        .bool("enabled")
                        .ok_or(BodyRefusal::Missing("enabled"))?,
                })
            }
        }
        let got = read_body::<Gate>(br#"{"enabled":true}"#).map(|g| g.enabled);
        assert_eq!(
            got.ok(),
            Some(true),
            "read_body reads through FIELDS and from_object"
        );
    }

    // ── Failure ────────────────────────────────────────────────────

    #[test]
    fn a_repeated_key_is_refused() {
        assert_eq!(
            refusal(r#"{"enabled":false,"enabled":true}"#, GATE),
            Some(BodyRefusal::DuplicateKey("enabled")),
            "two copies of enabled, false then true"
        );
    }

    #[test]
    fn a_repeated_key_with_the_same_value_is_refused() {
        assert_eq!(
            refusal(r#"{"ip":"192.0.2.1","ip":"192.0.2.1"}"#, BAN),
            Some(BodyRefusal::DuplicateKey("ip")),
            "the same key twice, even with one value"
        );
    }

    #[test]
    fn an_unknown_key_is_refused_naming_the_allowed_keys() {
        let got = refusal(r#"{"enabled":true,"enable":false}"#, GATE);
        assert_eq!(
            got,
            Some(BodyRefusal::UnknownKey { allowed: GATE }),
            "enable is not a key"
        );
        assert_eq!(
            got.map(|r| r.to_string()).as_deref(),
            Some("the body takes only these keys: enabled"),
            "the refusal lists the route's keys"
        );
    }

    #[test]
    fn an_array_body_is_not_an_object() {
        for body in ["[true]", "[]", r#"[{"enabled":true}]"#] {
            assert_eq!(
                refusal(body, GATE),
                Some(BodyRefusal::NotAnObject),
                "body {body:?}"
            );
        }
    }

    #[test]
    fn scalar_text_and_empty_bodies_are_not_objects() {
        for body in ["", "   ", "true", "1", "\"enabled\"", "null", "not json"] {
            assert_eq!(
                refusal(body, GATE),
                Some(BodyRefusal::NotAnObject),
                "body {body:?}"
            );
        }
    }

    #[test]
    fn an_object_as_a_value_is_refused() {
        assert_eq!(
            refusal(r#"{"enabled":{"value":true}}"#, GATE),
            Some(BodyRefusal::Nested("enabled")),
            "an object where a bool goes"
        );
    }

    #[test]
    fn an_array_as_a_value_is_refused() {
        assert_eq!(
            refusal(r#"{"ip":["192.0.2.1"]}"#, BAN),
            Some(BodyRefusal::Nested("ip")),
            "an array where a string goes"
        );
    }

    #[test]
    fn a_string_where_a_bool_goes_is_refused() {
        assert_eq!(
            refusal(r#"{"enabled":"true"}"#, GATE),
            Some(BodyRefusal::WrongType("enabled", Kind::Bool)),
            "\"true\" is a string"
        );
    }

    #[test]
    fn a_number_or_bool_where_another_kind_goes_is_refused() {
        assert_eq!(
            refusal(r#"{"enabled":1}"#, GATE),
            Some(BodyRefusal::WrongType("enabled", Kind::Bool)),
            "1 is not a bool"
        );
        assert_eq!(
            refusal(r#"{"ip":true}"#, BAN),
            Some(BodyRefusal::WrongType("ip", Kind::String)),
            "true is not a string"
        );
        assert_eq!(
            refusal(r#"{"ip":"x","ttl_secs":"60"}"#, BAN),
            Some(BodyRefusal::WrongType("ttl_secs", Kind::WholeNumber)),
            "\"60\" is not a number"
        );
    }

    #[test]
    fn a_missing_required_field_is_refused() {
        assert_eq!(
            refusal("{}", GATE),
            Some(BodyRefusal::Missing("enabled")),
            "{{}}"
        );
        assert_eq!(
            refusal(r#"{"ttl_secs":60}"#, BAN),
            Some(BodyRefusal::Missing("ip")),
            "a ban without ip"
        );
    }

    #[test]
    fn null_for_a_required_field_is_refused() {
        assert_eq!(
            refusal(r#"{"enabled":null}"#, GATE),
            Some(BodyRefusal::WrongType("enabled", Kind::Bool)),
            "null is not true or false"
        );
    }

    #[test]
    fn text_after_the_object_is_refused() {
        for body in [
            r#"{"enabled":true} x"#,
            r#"{"enabled":true}{"enabled":false}"#,
            "{\"enabled\":true}\u{0}",
        ] {
            assert_eq!(
                refusal(body, GATE),
                Some(BodyRefusal::TrailingContent),
                "body {body:?}"
            );
        }
    }

    #[test]
    fn a_body_that_is_not_utf8_is_refused() {
        assert_eq!(
            read_closed_object(b"{\"id\":\"\xff\"}", REVERT).err(),
            Some(BodyRefusal::NotUtf8),
            "a lone 0xFF byte"
        );
    }

    #[test]
    fn a_raw_control_character_in_a_string_is_refused() {
        assert_eq!(
            refusal("{\"id\":\"a\nb\"}", REVERT),
            Some(BodyRefusal::Malformed),
            "a raw newline inside a string"
        );
    }

    #[test]
    fn a_trailing_comma_is_refused() {
        assert_eq!(
            refusal(r#"{"enabled":true,}"#, GATE),
            Some(BodyRefusal::Malformed),
            "trailing comma"
        );
    }

    #[test]
    fn an_unterminated_string_or_object_is_refused() {
        for body in [
            r#"{"all":true"#,
            r#"{"id":"abc"#,
            r#"{"al"#,
            "{",
            r#"{"id":"#,
        ] {
            assert_eq!(
                refusal(body, REVERT),
                Some(BodyRefusal::Malformed),
                "body {body:?}"
            );
        }
    }

    #[test]
    fn a_missing_colon_or_unquoted_key_is_refused() {
        for body in [
            r#"{"enabled" true}"#,
            "{enabled:true}",
            r#"{"enabled":true "x":1}"#,
        ] {
            assert_eq!(
                refusal(body, GATE),
                Some(BodyRefusal::Malformed),
                "body {body:?}"
            );
        }
    }

    // ── Edge ───────────────────────────────────────────────────────

    #[test]
    fn a_repeat_spelled_with_an_escape_is_still_a_repeat() {
        let body = "{\"enabled\":false,\"en\\u0061bled\":true}";
        assert_eq!(
            body.matches("enabled").count(),
            1,
            "the second key is escaped: {body}"
        );
        assert_eq!(
            refusal(body, GATE),
            Some(BodyRefusal::DuplicateKey("enabled")),
            "the decoded key is what repeats"
        );
    }

    #[test]
    fn an_unknown_key_is_refused_before_its_value_is_read() {
        let deep = format!(r#"{{"other":{}"#, "[".repeat(100_000));
        assert_eq!(
            refusal(&deep, GATE),
            Some(BodyRefusal::UnknownKey { allowed: GATE }),
            "the unknown key decides, not its 100000-deep value"
        );
    }

    #[test]
    fn deep_nesting_in_a_value_is_refused_without_reading_it() {
        let deep = format!(r#"{{"enabled":{}"#, "[".repeat(100_000));
        assert_eq!(
            refusal(&deep, GATE),
            Some(BodyRefusal::Nested("enabled")),
            "100000-deep value"
        );
    }

    #[test]
    fn deep_nesting_as_the_body_is_not_an_object() {
        let deep = "[".repeat(100_000);
        assert_eq!(
            refusal(&deep, GATE),
            Some(BodyRefusal::NotAnObject),
            "100000-deep array body"
        );
    }

    #[test]
    fn a_fraction_or_an_exponent_is_not_a_whole_number() {
        for n in ["1.0", "1e3", "1E+3", "3600.5", "1e-0"] {
            let body = format!(r#"{{"ip":"x","ttl_secs":{n}}}"#);
            assert_eq!(
                refusal(&body, BAN),
                Some(BodyRefusal::WrongType("ttl_secs", Kind::WholeNumber)),
                "ttl_secs {n}"
            );
        }
    }

    #[test]
    fn a_negative_number_and_minus_zero_are_not_whole_numbers() {
        for n in ["-1", "-0", "-3600"] {
            let body = format!(r#"{{"ip":"x","ttl_secs":{n}}}"#);
            assert_eq!(
                refusal(&body, BAN),
                Some(BodyRefusal::WrongType("ttl_secs", Kind::WholeNumber)),
                "ttl_secs {n}"
            );
        }
    }

    #[test]
    fn a_number_past_u64_max_is_not_a_whole_number() {
        let body = r#"{"ip":"x","ttl_secs":18446744073709551616}"#;
        assert_eq!(
            refusal(body, BAN),
            Some(BodyRefusal::WrongType("ttl_secs", Kind::WholeNumber)),
            "u64::MAX + 1"
        );
    }

    #[test]
    fn a_number_outside_the_grammar_is_malformed() {
        for n in ["01", "1.", "-", "1e", "1e+", ".5", "+1", "0x10"] {
            let body = format!(r#"{{"ip":"x","ttl_secs":{n}}}"#);
            assert_eq!(
                refusal(&body, BAN),
                Some(BodyRefusal::Malformed),
                "ttl_secs {n}"
            );
        }
    }

    #[test]
    fn an_unpaired_surrogate_is_malformed() {
        // `\ue000` is the first unit past the low surrogates: paired with a
        // high one it would still make a valid character if the range were
        // not checked.
        for s in [
            "\\udc00",
            "\\ud83d",
            "\\ud83dx",
            "\\ud83d\\u0041",
            "\\ud83d\\ue000",
        ] {
            assert!(
                s.starts_with('\\') && s.is_ascii(),
                "written as escapes: {s}"
            );
            let body = format!(r#"{{"id":"{s}"}}"#);
            assert_eq!(
                refusal(&body, REVERT),
                Some(BodyRefusal::Malformed),
                "string {s}"
            );
        }
    }

    #[test]
    fn an_escape_outside_the_grammar_is_malformed() {
        for s in [r"\x41", r"\u12", r"\u12G4", r"\'", "\\"] {
            let body = format!(r#"{{"id":"{s}"}}"#);
            assert_eq!(
                refusal(&body, REVERT),
                Some(BodyRefusal::Malformed),
                "string {s}"
            );
        }
    }

    #[test]
    fn a_byte_order_mark_is_not_an_object() {
        assert_eq!(
            refusal("\u{feff}{\"enabled\":true}", GATE),
            Some(BodyRefusal::NotAnObject),
            "RFC 8259 section 8.1: a BOM is not added, and a parser may refuse one"
        );
    }

    #[test]
    fn a_literal_cut_short_or_run_on_is_malformed() {
        // Each literal less its last byte, then with one byte too many.
        for v in [&"true"[..3], &"false"[..4], &"null"[..3], "truex", "nulls"] {
            let body = format!(r#"{{"all":{v}}}"#);
            assert_eq!(
                refusal(&body, REVERT),
                Some(BodyRefusal::Malformed),
                "value {v}"
            );
        }
    }

    #[test]
    fn a_long_string_is_read_whole() {
        let long = "a".repeat(900_000);
        let got = string_of(&format!(r#"{{"id":"{long}"}}"#), REVERT, "id");
        assert_eq!(got.map(|s| s.len()), Some(900_000), "a 900000-byte string");
    }

    #[test]
    fn an_accessor_of_another_kind_or_name_answers_none() -> Result<(), BodyRefusal> {
        let mut o = read(r#"{"ip":"192.0.2.9","ttl_secs":5}"#, BAN)?;
        assert_eq!(o.bool("ip"), None, "ip is not a bool");
        assert_eq!(o.whole_number("ip"), None, "ip is not a number");
        assert_eq!(o.take_string("ttl_secs"), None, "ttl_secs is not a string");
        assert_eq!(
            o.whole_number("ttl_secs"),
            Some(5),
            "a failed take leaves the value"
        );
        assert_eq!(o.take_string("nope"), None, "nope is not a field");
        assert_eq!(
            o.take_string("ip").as_deref(),
            Some("192.0.2.9"),
            "first take"
        );
        assert_eq!(o.take_string("ip"), None, "a string is taken once");
        Ok(())
    }

    #[test]
    fn every_refusal_says_what_is_wrong() {
        let cases = [
            (BodyRefusal::NotUtf8, "the body is not UTF-8 text"),
            (BodyRefusal::NotAnObject, "the body must be one JSON object"),
            (BodyRefusal::Malformed, "the body is not valid JSON"),
            (
                BodyRefusal::UnknownKey { allowed: BAN },
                "the body takes only these keys: ip, ttl_secs",
            ),
            (
                BodyRefusal::DuplicateKey("ip"),
                "the key `ip` appears more than once",
            ),
            (
                BodyRefusal::Nested("ip"),
                "`ip` must be one value, not an object or an array",
            ),
            (
                BodyRefusal::WrongType("enabled", Kind::Bool),
                "`enabled` must be true or false",
            ),
            (
                BodyRefusal::WrongType("ip", Kind::String),
                "`ip` must be a string",
            ),
            (
                BodyRefusal::WrongType("ttl_secs", Kind::WholeNumber),
                "`ttl_secs` must be a whole number from 0 to 18446744073709551615",
            ),
            (BodyRefusal::Missing("ip"), "the body has no `ip`"),
            (
                BodyRefusal::TrailingContent,
                "the body has text after its JSON object",
            ),
        ];
        for (r, want) in cases {
            assert_eq!(r.to_string(), want, "text of {r:?}");
        }
    }
}
