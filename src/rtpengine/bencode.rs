// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bencode decoding, for rtpengine's `ng` control protocol.
//!
//! An `ng` message is a cookie, a space, and a bencoded dictionary. Bencode
//! itself is four types: integers `i<n>e`, byte strings `<len>:<bytes>`, lists
//! `l...e` and dictionaries `d<key><value>...e`.
//!
//! **Dictionary keys are NOT assumed to be sorted.** The format's own
//! specification requires lexicographic order, and rtpengine does not emit it
//! — a live `offer` captured from rtpengine 12.5.1 arrives as `command`,
//! `call-id`, `from-tag`, `sdp`, which is not sorted. A decoder that rejected
//! unsorted keys, or that binary-searched them, would fail on every real
//! message. Keys are therefore kept in arrival order and looked up by scan;
//! the dictionaries here are a handful of entries, so the scan is not worth
//! replacing with a map.
//!
//! Values borrow from the input. An `sdp` value is the largest thing in a
//! message and it is handed straight to the SDP parser, so copying it would be
//! pure waste on a path that runs per control message.
//!
//! **This parser is hostile-input-facing** — over HEP the bytes come from
//! another host, and under [`crate::rtpengine`]'s passive path they come off
//! the wire. Every length is bounds-checked before use, recursion is depth-
//! limited, and anything malformed is an error rather than a partial value.
//! A truncated dictionary is not a dictionary with fewer keys.

use anyhow::{Result, bail, ensure};

/// Deepest nesting accepted before a message is called malformed.
///
/// rtpengine's own replies reach four (`d` → `tags` → tag → `medias` → list →
/// media → `streams`), so this is roughly four times the deepest real message.
/// The limit exists because [`Value`] is a recursive type and decoding it
/// recurses: without a bound, `llll...` in a hostile datagram is a stack
/// overflow, which is a crash rather than a parse error.
pub const MAX_DEPTH: usize = 16;

/// One bencode value, borrowing from the buffer it was decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// `i<n>e`.
    Int(i64),
    /// `<len>:<bytes>` — a byte string, which bencode does not define as text.
    Bytes(&'a [u8]),
    /// `l<values>e`.
    List(Vec<Value<'a>>),
    /// `d<key><value>...e`, in ARRIVAL order (see the module note).
    Dict(Vec<(&'a [u8], Value<'a>)>),
}

impl<'a> Value<'a> {
    /// The value stored under `key`, or `None`.
    ///
    /// A linear scan, which is also what makes arrival order safe to keep.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&Value<'a>> {
        match self {
            Self::Dict(entries) => entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value under `key` when it is a byte string.
    #[must_use]
    pub fn get_bytes(&self, key: &[u8]) -> Option<&'a [u8]> {
        match self.get(key) {
            Some(Self::Bytes(b)) => Some(b),
            _ => None,
        }
    }

    /// The value under `key` as UTF-8, lossily.
    ///
    /// Lossy on purpose: a Call-ID with one bad byte in it is still the join
    /// key for every stream in that call, and dropping the whole message over
    /// it would turn a cosmetic defect into an unattributable capture.
    #[must_use]
    pub fn get_str(&self, key: &[u8]) -> Option<String> {
        self.get_bytes(key)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// The value under `key` when it is an integer.
    #[must_use]
    pub fn get_int(&self, key: &[u8]) -> Option<i64> {
        match self.get(key) {
            Some(Self::Int(i)) => Some(*i),
            _ => None,
        }
    }
}

/// Decode one complete bencode value, which must consume the whole input.
///
/// # Errors
///
/// Returns an error for a truncated value, a malformed length or integer,
/// duplicate dictionary keys, nesting past [`MAX_DEPTH`], or trailing bytes
/// after the value ends. Trailing bytes are an error rather than an ignored
/// tail because an `ng` datagram carries exactly one dictionary: bytes after
/// it mean the message was not understood, and silently keeping the prefix
/// would attribute a call from a message nobody can vouch for.
pub fn decode(input: &[u8]) -> Result<Value<'_>> {
    let (value, rest) = decode_value(input, 0)?;
    ensure!(
        rest.is_empty(),
        "bencode: {} trailing byte(s) after the top-level value",
        rest.len()
    );
    Ok(value)
}

/// Decode one value, returning it and the unconsumed remainder.
fn decode_value(input: &[u8], depth: usize) -> Result<(Value<'_>, &[u8])> {
    ensure!(
        depth <= MAX_DEPTH,
        "bencode: nested deeper than {MAX_DEPTH}"
    );
    let Some(&tag) = input.first() else {
        bail!("bencode: unexpected end of input where a value was expected");
    };
    match tag {
        b'i' => decode_int(input),
        b'l' => decode_list(input, depth),
        b'd' => decode_dict(input, depth),
        b'0'..=b'9' => decode_bytes(input),
        other => bail!(
            "bencode: {:?} does not begin any bencode value",
            other as char
        ),
    }
}

/// `i<n>e`.
fn decode_int(input: &[u8]) -> Result<(Value<'_>, &[u8])> {
    let body = &input[1..];
    let Some(end) = body.iter().position(|&b| b == b'e') else {
        bail!("bencode: integer has no terminating 'e'");
    };
    let digits = &body[..end];
    ensure!(!digits.is_empty(), "bencode: empty integer");
    let text = std::str::from_utf8(digits)
        .map_err(|_| anyhow::anyhow!("bencode: integer is not ASCII"))?;
    // Canonical form only. `i03e` and `i-0e` are forbidden by the format, and
    // accepting them would mean two spellings of one number -- which matters
    // here because these values are compared, not just displayed.
    ensure!(
        text == "0" || !text.starts_with('0') && !text.starts_with("-0"),
        "bencode: non-canonical integer {text:?}"
    );
    let value: i64 = text
        .parse()
        .map_err(|_| anyhow::anyhow!("bencode: integer {text:?} is out of range"))?;
    Ok((Value::Int(value), &body[end + 1..]))
}

/// `<len>:<bytes>`.
fn decode_bytes(input: &[u8]) -> Result<(Value<'_>, &[u8])> {
    let Some(colon) = input.iter().position(|&b| b == b':') else {
        bail!("bencode: byte string has no ':' after its length");
    };
    let digits = &input[..colon];
    let text = std::str::from_utf8(digits)
        .map_err(|_| anyhow::anyhow!("bencode: byte-string length is not ASCII"))?;
    ensure!(
        text == "0" || !text.starts_with('0'),
        "bencode: non-canonical byte-string length {text:?}"
    );
    let len: usize = text
        .parse()
        .map_err(|_| anyhow::anyhow!("bencode: byte-string length {text:?} is not a number"))?;
    let start = colon + 1;
    // Checked against the REMAINING input, so a huge declared length is a
    // parse error and never an allocation or a slice past the end.
    let end = start
        .checked_add(len)
        .filter(|&e| e <= input.len())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "bencode: byte string declares {len} bytes but only {} remain",
                input.len().saturating_sub(start)
            )
        })?;
    Ok((Value::Bytes(&input[start..end]), &input[end..]))
}

/// `l<values>e`.
fn decode_list(input: &[u8], depth: usize) -> Result<(Value<'_>, &[u8])> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    loop {
        match rest.first() {
            None => bail!("bencode: list has no terminating 'e'"),
            Some(b'e') => return Ok((Value::List(items), &rest[1..])),
            Some(_) => {
                let (value, tail) = decode_value(rest, depth + 1)?;
                items.push(value);
                rest = tail;
            }
        }
    }
}

/// `d<key><value>...e`.
fn decode_dict(input: &[u8], depth: usize) -> Result<(Value<'_>, &[u8])> {
    let mut rest = &input[1..];
    let mut entries: Vec<(&[u8], Value<'_>)> = Vec::new();
    loop {
        match rest.first() {
            None => bail!("bencode: dictionary has no terminating 'e'"),
            Some(b'e') => return Ok((Value::Dict(entries), &rest[1..])),
            Some(_) => {
                let (key, tail) = decode_bytes(rest)?;
                let Value::Bytes(key) = key else {
                    bail!("bencode: dictionary key is not a byte string");
                };
                // Duplicates are rejected rather than resolved. Last-wins and
                // first-wins are both silent, and a message with two `call-id`
                // keys is one whose call cannot be named with confidence.
                ensure!(
                    !entries.iter().any(|(k, _)| *k == key),
                    "bencode: duplicate dictionary key {:?}",
                    String::from_utf8_lossy(key)
                );
                let (value, tail) = decode_value(tail, depth + 1)?;
                entries.push((key, value));
                rest = tail;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_four_bencode_types() {
        assert_eq!(decode(b"i42e").expect("int"), Value::Int(42));
        assert_eq!(decode(b"i-7e").expect("negative"), Value::Int(-7));
        assert_eq!(decode(b"5:offer").expect("bytes"), Value::Bytes(b"offer"));
        assert_eq!(decode(b"0:").expect("empty bytes"), Value::Bytes(b""));
        assert_eq!(
            decode(b"li1ei2ee").expect("list"),
            Value::List(vec![Value::Int(1), Value::Int(2)])
        );
        assert_eq!(
            decode(b"d3:keyi1ee").expect("dict"),
            Value::Dict(vec![(&b"key"[..], Value::Int(1))])
        );
    }

    /// The format requires sorted keys; rtpengine does not produce them. A
    /// decoder that enforced the rule would reject every real `offer`.
    #[test]
    fn accepts_dictionary_keys_out_of_lexicographic_order() {
        let v = decode(b"d7:command5:offer7:call-id2:abe").expect("unsorted keys decode");
        assert_eq!(v.get_bytes(b"command"), Some(&b"offer"[..]));
        assert_eq!(v.get_bytes(b"call-id"), Some(&b"ab"[..]));
    }

    #[test]
    fn rejects_duplicate_dictionary_keys() {
        let err = decode(b"d7:call-id1:a7:call-id1:be").expect_err("duplicate must fail");
        assert!(
            err.to_string().contains("duplicate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_a_truncated_value_rather_than_returning_a_short_one() {
        assert!(
            decode(b"d7:command5:offe").is_err(),
            "truncated byte string"
        );
        assert!(decode(b"d7:command5:offer").is_err(), "unterminated dict");
        assert!(decode(b"i42").is_err(), "unterminated int");
        assert!(decode(b"li1e").is_err(), "unterminated list");
    }

    /// A declared length far past the buffer must be a parse error, never an
    /// allocation and never a slice past the end.
    #[test]
    fn rejects_a_length_larger_than_the_input() {
        let err = decode(b"99999999:x").expect_err("oversized length must fail");
        assert!(err.to_string().contains("declares"), "unexpected: {err}");
        assert!(decode(b"18446744073709551615:x").is_err(), "usize overflow");
    }

    #[test]
    fn rejects_trailing_bytes_after_the_top_level_value() {
        let err = decode(b"i1eXX").expect_err("trailing bytes must fail");
        assert!(err.to_string().contains("trailing"), "unexpected: {err}");
    }

    /// Unbounded recursion on hostile input is a crash, not a parse failure.
    #[test]
    fn rejects_nesting_past_the_depth_limit() {
        let deep: Vec<u8> = std::iter::repeat_n(b'l', MAX_DEPTH + 4).collect();
        let err = decode(&deep).expect_err("deep nesting must fail");
        assert!(
            err.to_string().contains("nested deeper"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_non_canonical_numbers() {
        assert!(decode(b"i03e").is_err(), "leading zero");
        assert!(decode(b"i-0e").is_err(), "negative zero");
        assert!(decode(b"01:a").is_err(), "leading zero in a length");
        assert_eq!(decode(b"i0e").expect("plain zero is fine"), Value::Int(0));
    }

    /// Shaped like the live `offer` in `tests/fixtures/rtpengine-ng-hep.pcap`
    /// (rtpengine 12.5.1): keys unsorted, and an SDP body containing CRLF.
    ///
    /// The SDP's length prefix is COMPUTED rather than typed. Writing it by
    /// hand is how this test first failed -- a miscount produced a message no
    /// rtpengine would ever emit, so the test was asserting against the
    /// author's arithmetic instead of against the format.
    #[test]
    fn decodes_a_real_rtpengine_offer() {
        let sdp = "v=0\r\nm=audio 40001 RTP/AVP 0";
        let msg = format!(
            "d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp{}:{sdp}e",
            sdp.len()
        );
        let msg = msg.as_bytes();
        let v = decode(msg).expect("real offer decodes");
        assert_eq!(v.get_str(b"command").as_deref(), Some("offer"));
        assert_eq!(v.get_str(b"call-id").as_deref(), Some("km-670bd208@sipnab"));
        assert_eq!(v.get_str(b"from-tag").as_deref(), Some("ftag1"));
        assert!(
            v.get_bytes(b"sdp").expect("sdp").starts_with(b"v=0\r\n"),
            "SDP must survive byte-exact, CRLF included"
        );
    }

    #[test]
    fn get_helpers_return_none_for_the_wrong_shape() {
        let v = decode(b"d3:oneli1eee").expect("dict of list");
        assert_eq!(v.get_bytes(b"one"), None, "a list is not a byte string");
        assert_eq!(v.get_int(b"one"), None, "a list is not an int");
        assert_eq!(v.get(b"absent"), None);
        assert_eq!(Value::Int(1).get(b"any"), None, "a non-dict has no keys");
    }
}
