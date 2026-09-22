// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nothing sipnab SENDS is named with an `X-` prefix (RFC 6648).
//!
//! [RFC 6648](https://www.rfc-editor.org/rfc/rfc6648) section 3 tells creators
//! of new parameters they "SHOULD NOT prefix their parameter names with 'X-'
//! or similar constructs", because a name that starts life as a private
//! experiment is the name everyone ends up depending on. Norm's instruction on
//! 2026-09-22 was the same: "sipnab should not by default use x- headers".
//!
//! # What this gate reads, and what it deliberately does not
//!
//! Two directions, and only one of them is sipnab's choice:
//!
//! - **Sent.** Response headers on the REST surface, and the security headers
//!   the site publishes. Those names are sipnab's to pick, so `X-` is refused
//!   here.
//! - **Read.** The SIP headers a capture carries — `X-Asterisk-HangupCause`,
//!   an SBC's `X-CID`, anything an operator's proxy invented. RFC 6648 section
//!   2 forbids treating those differently for their prefix, so sipnab names
//!   them wherever it must understand them. `src/sip/` is therefore not
//!   scanned, and `tests/no_x_prefixed_headers_test.rs` says so rather than
//!   leaving a silent hole.
//!
//! # The one allowed exception
//!
//! `X-Content-Type-Options: nosniff` stays. The WHATWG Fetch Standard defines
//! it under that name, there is no alternative spelling, and dropping it
//! re-enables MIME sniffing. Norm chose to keep it as the single documented
//! exception, so it is listed by name: anything else with an `X-` prefix
//! fails, including a second exception nobody discussed.

#![cfg(feature = "full")]

use std::path::PathBuf;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The only `X-` name sipnab may send, lower-cased for comparison.
const ALLOWED: &[&str] = &["x-content-type-options"];

/// Every `X-`-prefixed header name a piece of source or a headers file would
/// send, lower-cased, with the allowed exception removed.
///
/// Pure, so the shapes it must catch are driven from fixtures below rather
/// than from whatever the tree happens to contain today.
///
/// Two shapes are recognized:
///
/// - a Rust string literal that is a header name, as the REST surface writes
///   it: `("x-sipnab-audio-partial", ...)` or `HeaderName::from_static("x-…")`;
/// - a header line in a `_headers` file or a Python dict of headers:
///   `X-Frame-Options: DENY` and `"X-Frame-Options": "DENY"`.
fn x_prefixed_sent_names(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for raw in text.split('"').skip(1).step_by(2) {
        let name = raw.trim();
        if name.len() > 2
            && name.to_ascii_lowercase().starts_with("x-")
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            found.push(name.to_ascii_lowercase());
        }
    }
    for line in text.lines() {
        let line = line.trim();
        if let Some((name, _)) = line.split_once(':')
            && name.to_ascii_lowercase().starts_with("x-")
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            found.push(name.to_ascii_lowercase());
        }
    }
    found.retain(|n| !ALLOWED.contains(&n.as_str()));
    found.sort();
    found.dedup();
    found
}

/// A Rust file's production half: everything before its `#[cfg(test)]`.
///
/// A test names the headers a CAPTURE carries — `X-Added-Later` in
/// `src/mcp/tools/provenance.rs` builds a message to read back — and those are
/// reads, which RFC 6648 section 2 protects. Only what ships can send a
/// header, so only what ships is scanned.
fn production_half(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    }
}

/// The files whose header names sipnab chooses: the wire surfaces it answers
/// on, and the site's published headers.
fn sending_sources() -> Vec<PathBuf> {
    let mut out = vec![
        repo().join("src/output/api.rs"),
        repo().join("src/output/prometheus_server.rs"),
        repo().join("website/static/_headers"),
        repo().join("ops/cloudflare/refresh_csp_hashes.py"),
    ];
    let mcp = repo().join("src/mcp");
    if mcp.is_dir() {
        let mut stack = vec![mcp];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
    }
    out.retain(|p| p.exists());
    out
}

/// The fixture shapes: what the matcher must see, and what it must not.
#[test]
fn the_matcher_reads_both_shapes_and_honors_the_exception() {
    let rust = r#"
        Ok((StatusCode::OK, [("content-type", "audio/wav".to_string()),
            ("x-sipnab-audio-partial", flag.to_string())], body))
    "#;
    assert_eq!(x_prefixed_sent_names(rust), vec!["x-sipnab-audio-partial"]);

    let headers_file = "/*\n  X-Frame-Options: DENY\n  X-Content-Type-Options: nosniff\n";
    assert_eq!(x_prefixed_sent_names(headers_file), vec!["x-frame-options"]);

    let python = r#"    headers = {"X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}"#;
    assert_eq!(x_prefixed_sent_names(python), vec!["x-frame-options"]);

    let renamed = r#"("sipnab-audio-partial", flag.to_string())"#;
    assert!(x_prefixed_sent_names(renamed).is_empty());

    // The allowed exception, in both shapes.
    assert!(x_prefixed_sent_names("  X-Content-Type-Options: nosniff\n").is_empty());
    assert!(x_prefixed_sent_names(r#""X-Content-Type-Options": "nosniff""#).is_empty());

    // A capture's header named in a test is a READ, not a send.
    let with_tests = "fn send() { (\"content-type\", v) }\n#[cfg(test)]\nmod tests { let h = \"X-Added-Later\"; }";
    assert!(x_prefixed_sent_names(production_half(with_tests)).is_empty());
    assert_eq!(x_prefixed_sent_names(with_tests), vec!["x-added-later"]);

    // Prose about a header a capture carries is not a header sipnab sends;
    // it is not quoted as a bare name, so it does not match.
    assert!(x_prefixed_sent_names("// reads X-Asterisk-HangupCause from the capture").is_empty());
}

/// Nothing this project sends carries an `X-` name.
#[test]
fn sipnab_sends_no_x_prefixed_header() {
    let mut offenders: Vec<String> = Vec::new();
    for path in sending_sources() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let text = if path.extension().is_some_and(|x| x == "rs") {
            production_half(&text).to_string()
        } else {
            text
        };
        for name in x_prefixed_sent_names(&text) {
            offenders.push(format!(
                "{}: {name}",
                path.strip_prefix(repo()).unwrap_or(&path).display()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "RFC 6648 section 3: a name sipnab sends may not start with `X-`. \
         Rename it (a `Sipnab-` prefix, or the registered name) or, for a \
         security header with no alternative spelling, add it to ALLOWED here \
         with the reason:\n  {}",
        offenders.join("\n  ")
    );
}

/// The headers a CAPTURE carries are read by name, prefix and all, and this
/// gate must never push anyone to stop reading them (RFC 6648 section 2).
#[test]
fn headers_read_from_captures_are_out_of_scope() {
    let scanned = sending_sources();
    assert!(
        !scanned
            .iter()
            .any(|p| p.starts_with(repo().join("src/sip"))),
        "src/sip/ names the headers sipnab READS; scanning it would read \
         RFC 6648 backwards"
    );
    let termination = std::fs::read_to_string(repo().join("src/sip/termination.rs"))
        .expect("src/sip/termination.rs is in the tree");
    assert!(
        termination.contains("X-Asterisk-HangupCause"),
        "sipnab must keep understanding the vendor headers real captures carry"
    );
}
