// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hash tokens the vCon extension drafts bind content with.
//!
//! [Section 4.3 of draft-howe-vcon-provenance-00](https://datatracker.ietf.org/doc/html/draft-howe-vcon-provenance-00#section-4.3):
//! every hash token "uses the same form as the content_hash parameter" of
//! the core draft, "the hash algorithm name, a hyphen, and the base64url
//! encoding (without padding) of the digest", SHA-512 recommended, and JSON
//! material is canonicalized "with the JSON Canonicalization Scheme
//! \[RFC8785\] before hashing, so that independent parties compute the same
//! digest".

/// The `sha512-` token of `bytes`.
#[must_use]
pub fn token(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    format!(
        "{}{}",
        crate::output::vcon::CONTENT_HASH_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha512::digest(bytes))
    )
}

/// The `sha512-` token of `value` in its RFC 8785 canonical form.
#[must_use]
pub fn json_token(value: &serde_json::Value) -> String {
    token(jcs(value).as_bytes())
}

/// `value` serialized by the JSON Canonicalization Scheme,
/// [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html).
#[must_use]
pub fn jcs(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_jcs(value, &mut out);
    out
}

/// Append `value`'s canonical form to `out`.
///
/// - Literals and strings serialize as `serde_json` writes them, which escapes
///   exactly what
///   [RFC 8785 section 3.2.2.2](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.2.2)
///   escapes: `"`, `\\`, and the control characters, with `\\b`, `\\t`,
///   `\\n`, `\\f`, `\\r` or a lowercase `\\u00xx`.
/// - Numbers serialize by [`number`].
/// - Object members sort by the UTF-16 code units of their names
///   ([section 3.2.3](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.3)).
fn write_jcs(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Number(n) => out.push_str(&number(n)),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let mut members: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (name, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(name.clone()).to_string());
                out.push(':');
                write_jcs(item, out);
            }
            out.push('}');
        }
        literal => out.push_str(&literal.to_string()),
    }
}

/// A number as ECMAScript's `Number.prototype.toString` writes it, which
/// [RFC 8785 section 3.2.2.3](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.2.3)
/// requires: the shortest digits that read back as the same double, plain
/// from 1e-6 up to 1e21, and `d.ddde+n` or `d.ddde-n` outside that range.
fn number(n: &serde_json::Number) -> String {
    let Some(x) = n.as_f64() else {
        return n.to_string();
    };
    if x == 0.0 {
        return "0".to_owned();
    }
    let size = x.abs();
    if (1e-6..1e21).contains(&size) {
        // Rust's `Display` writes the shortest round-trip digits, never an
        // exponent, and no `.0` on a whole number.
        return format!("{x}");
    }
    let text = format!("{x:e}");
    match text.split_once('e') {
        Some((digits, exp)) if !exp.starts_with('-') => format!("{digits}e+{exp}"),
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The example of
    /// [RFC 8785 section 3.2.3](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.3),
    /// input and output as the RFC prints them.
    #[test]
    fn the_rfc_8785_example_canonicalizes_as_printed() -> Result<(), TestError> {
        let input: serde_json::Value = serde_json::from_str(
            r#"{
              "numbers": [333333333.33333329, 1E30, 4.50,
                          2e-3, 0.000000000000000000000000001],
              "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
              "literals": [null, true, false]
            }"#,
        )?;
        assert_eq!(
            jcs(&input),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
        Ok(())
    }

    /// Members sort by their UTF-16 code units, the order of
    /// [RFC 8785 section 3.2.3](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.3)'s
    /// sorting example: an emoji's surrogate pair sorts before U+FB33.
    #[test]
    fn members_sort_by_utf16_code_units() -> Result<(), TestError> {
        let input: serde_json::Value = serde_json::from_str(
            r#"{"\u20ac": "Euro Sign", "\r": "Carriage Return",
                "\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",
                "\ud83d\ude00": "Emoji: Grinning Face", "\u0080": "Control",
                "\u00f6": "Latin Small Letter O With Diaeresis"}"#,
        )?;
        let order: Vec<String> = jcs(&input)
            .split("\":\"")
            .skip(1)
            .map(|part| part.split('"').next().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(
            order,
            [
                "Carriage Return",
                "One",
                "Control",
                "Latin Small Letter O With Diaeresis",
                "Euro Sign",
                "Emoji: Grinning Face",
                "Hebrew Letter Dalet With Dagesh",
            ]
        );
        Ok(())
    }

    /// Numbers serialize as ECMAScript does: plain from 1e-6 up to 1e21,
    /// an exponent outside that, integers without a fraction, and -0 as 0.
    #[test]
    fn numbers_serialize_as_ecmascript_does() -> Result<(), TestError> {
        for (text, want) in [
            ("1e21", "1e+21"),
            ("1e20", "100000000000000000000"),
            ("0.000001", "0.000001"),
            ("1e-7", "1e-7"),
            ("-0.0", "0"),
            ("100", "100"),
            ("-5", "-5"),
            ("4.0", "4"),
            ("1.5e-9", "1.5e-9"),
        ] {
            let value: serde_json::Value = serde_json::from_str(text)?;
            assert_eq!(jcs(&value), want, "{text}");
        }
        Ok(())
    }

    /// The token is `sha512-` and the unpadded base64url SHA-512 digest.
    #[test]
    fn a_token_is_sha512_base64url() {
        assert_eq!(
            token(b"abc"),
            "sha512-3a81oZNherrMQXNJriBBMRLm-k6JqX6iCp7u5ktV05ohkpkqJ0_BqDa6PCOj_uu9RU1EI2Q86A4qmslPpUyknw"
        );
        assert_eq!(
            json_token(&serde_json::json!({"b": 1, "a": "x"})),
            token(br#"{"a":"x","b":1}"#)
        );
    }
}
