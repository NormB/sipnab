// SPDX-License-Identifier: MIT OR Apache-2.0

//! No literal may be handed to anything named like cryptographic material.
//!
//! # Byte arrays, the shape the string rules missed
//!
//! Until 0.5.220 this gate read string and byte-string literals only. CodeQL
//! alert 465 was `let master_key = vec![0x11u8; 16];` in `src/app/batch.rs`,
//! an array of byte literals bound to a key and passed to an SRTP packet
//! builder. It was the last of 36 alerts of this rule dismissed as "used
//! in tests". The gate now also reports a literal byte array bound
//! to a material name and any literal handed straight to a material parameter
//! of a crate function or a library key constructor; see
//! [`offending_lines_with`] for the rules and for the shapes only data flow
//! can see.
//!
//! # The defect this exists for
//!
//! CodeQL's `rust/hard-coded-cryptographic-value` raised nine alerts on `main`
//! in one commit: nine test fixtures in `src/security/digest_leak.rs` built a
//! 401 challenge with a literal `nonce` argument. Production code takes nonces
//! from the wire and was clean, but nothing local looked for the shape, the
//! alerts sat on the security tab, and three releases were tagged past them.
//! This is the local half of the fix: the same shape CodeQL flags, checked in
//! seconds before a commit, in production code AND in tests -- a fixture nonce
//! is derived, never pasted, so the scanner has nothing to say.

use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Names that make a literal argument or assignment cryptographic material.
const MATERIAL: &[&str] = &[
    "nonce",
    "key",
    "secret",
    "iv",
    "salt",
    "password",
    "passphrase",
    "cnonce",
];

/// Splits a Rust file into (production, tests) at its `#[cfg(test)]` module.
fn split_cfg_test(src: &str) -> (&str, &str) {
    match src.find("#[cfg(test)]") {
        Some(i) => (&src[..i], &src[i..]),
        None => (src, ""),
    }
}

/// The one permitted exception: a line ending in `// material: fixture -- <why>`
/// names a literal that IS the test's subject (a parser that must accept these
/// bytes), with its reason beside it. Every exception is named, none is silent.
const EXCEPTION: &str = "// material: fixture --";

/// Lines where a string literal is handed to something named like material:
/// `nonce = "..."`, `nonce: "..."`, `let nonce = "..."`, and the call-site
/// shape CodeQL flagged, a literal `"n-…"` argument. `key` alone is matched
/// only as an assignment (`let key = "…"`, `key = "…"`): a struct field named
/// `key` is usually a lookup key, and `key: "jitter_warn_ms"` is not material.
fn offending_lines(src: &str) -> Vec<(usize, String)> {
    offending_lines_in(src, false)
}

/// As [`offending_lines`], and with `seeds` also reporting a numeric literal
/// that seeds the value inside a function named for material
/// (`fn nonce_for`, `fn key_for`, ...): the shape CodeQL flagged after the
/// string literals were gone, because derived from a constant is still
/// constant. Test fixtures get that rule; production crypto keeps its
/// RFC-fixed labels and CodeQL's own judgment of them.
fn offending_lines_in(src: &str, seeds: bool) -> Vec<(usize, String)> {
    offending_lines_with(src, seeds, &Signatures::of(&[src]))
}

/// As [`offending_lines_in`], with the parameters of every function the scan
/// may meet a call to taken from `sigs` (the whole crate, for a repo scan).
///
/// The literal rules read one line at a time. Two further rules read the
/// byte-array shapes CodeQL reports and the string rules cannot see:
///
/// * [`array_binding_is_material`]: a literal byte array (`[0x11u8; 16]`,
///   `vec![0u8; 16]`, `[0x2B, 0x7E, ..]`, written on one line or opened with
///   `[` and continued) bound by `let`, `const`, `static`, an assignment or a
///   struct field to a name carrying a material token.
/// * [`call_hits`]: a literal handed straight to a parameter named for
///   material, in a function declared in the crate or in a library key
///   constructor listed in [`LIBRARY_SINKS`].
///
/// # What only data flow can see
///
/// CodeQL follows a value from the literal to the cipher; these rules see a
/// literal and the NAME it is given. Three shapes are therefore out of reach,
/// and each is written down here rather than left to be rediscovered:
///
/// 1. A literal bound to a name that says nothing (`let a = [1u8; 16];`)
///    and passed on later. The rules catch it only where it meets a material
///    parameter in a single call.
/// 2. A literal that reaches the key through a value built in another
///    expression, such as a struct field set from a closure parameter
///    (`|mk: u8| Material { master_key: vec![mk; 16] }`). The call rule
///    catches the literal at the closure's call (`km(0x11)`) only because
///    the closure's parameter is named `mk` and typed `u8`.
/// 3. A zero-filled `let mut` buffer that later lines overwrite
///    (`let mut iv = [0u8; 16];` then `copy_from_slice`). CodeQL has reported
///    it three times in production code and all three were dismissed as false
///    positives; telling it from a constant key needs the overwrite, so the
///    gate does not report it at all.
fn offending_lines_with(src: &str, seeds: bool, sigs: &Signatures) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_material_fn = false;
    let lines: Vec<&str> = src.lines().collect();
    for (n, line) in lines.iter().enumerate() {
        let l = line.trim();
        if l.starts_with("fn ") || l.starts_with("pub fn ") {
            let name = l.trim_start_matches("pub ").trim_start_matches("fn ");
            let name = name.split('(').next().unwrap_or("");
            // Whole tokens of the name: `iv` must not match `derive` or `receive`.
            // ... and only a function that RETURNS a value: a `#[test] fn` binds
            // counters and timestamps; `fn nonce_for(..) -> String` returns material.
            // A test that returns `Result<(), _>` returns no value either: its
            // `Ok` carries the unit type, so its counters are not material.
            in_material_fn = l.contains("->")
                && !l.contains("-> Result<(),")
                && name.split('_').any(|tok| MATERIAL.contains(&tok));
        }
        if seeds
            && in_material_fn
            && !l.starts_with("//")
            && !l.contains(EXCEPTION)
            && binds_numeric_literal(l)
        {
            out.push((n + 1, l.to_string()));
            continue;
        }
        if l.starts_with("//") || l.contains(EXCEPTION) {
            continue;
        }
        // Both spellings of a string literal. A BYTE string is the one this
        // matcher missed: ten `rust/hard-coded-cryptographic-value` alerts
        // reached CI on 2026-09-09 written as `b"..."`, and every one of them
        // walked past a scan that only knew `"`. A gate that reads one
        // spelling of the thing it watches reports green on every other.
        let quoted = ["\"", "b\""];
        let material = MATERIAL.iter().filter(|m| **m != "key").any(|m| {
            quoted.iter().any(|q| {
                l.contains(&format!("{m} = {q}"))
                    || l.contains(&format!("{m}: {q}"))
                    || l.contains(&format!("let {m} = {q}"))
            })
        });
        let key_assigned = quoted
            .iter()
            .any(|q| l.contains(&format!("let key = {q}")) || l.starts_with(&format!("key = {q}")));
        // A `const`/`static` DECLARATION whose name is material AND whose value
        // is a BYTE string. The other half of the same miss: `const KEY:
        // &[u8] = b"..."` is neither an assignment nor a call argument, and
        // the names are upper-case, so nothing above sees it.
        //
        // The byte string is what separates cryptographic material from a
        // lookup key, and it is not a guess: accepting any string literal here
        // reported `const TRUNCATED_KEY: &str = "truncated"` in
        // `src/mcp/completeness.rs`, a JSON field name. CodeQL flags neither,
        // and a gate that predicts CodeQL has to agree with it in BOTH
        // directions -- a false red is how a gate stops being read.
        let declared = declared_material_name(l) && l.contains("= b\"");
        let nonce_arg = l.contains("\"n-") && l.contains('(');
        // The first line of code below, past any comment lines. rustfmt moves
        // a comment written after an opening `[` onto the array's first line,
        // so a named exception there belongs to this binding.
        let below: Vec<&str> = lines[n + 1..]
            .iter()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .take_while(|x| x.starts_with("//"))
            .collect();
        let next = lines[n + 1..]
            .iter()
            .map(|x| x.trim())
            .find(|x| !x.is_empty() && !x.starts_with("//"));
        let excepted_below = l.ends_with('[') && below.iter().any(|x| x.contains(EXCEPTION));
        let array = !excepted_below && array_binding_is_material(l, next);
        if material || key_assigned || declared || nonce_arg || array {
            out.push((n + 1, l.to_string()));
        }
    }
    for hit in call_hits(src, sigs) {
        if !out.iter().any(|(n, _)| *n == hit.0) {
            out.push(hit);
        }
    }
    out.sort();
    out
}

/// Abbreviations of key material seen in the crate's tests (`mk` for a master
/// key, `psk` for a pre-shared key), matched in names alongside [`MATERIAL`].
const ABBREVIATED: &[&str] = &["mk", "psk"];

/// Name tokens that make a material-looking name something else: a size, a
/// position or a label (`key_len` is a number of bytes, `key_label` a
/// string), an object identifier or a public key (`EC_PUBLIC_KEY_OID`, which
/// is published by definition), or a WebSocket masking key (`mask_key`, RFC
/// 6455 section 5.3, which the protocol sends in the clear beside the frame).
const NOT_MATERIAL: &[&str] = &[
    "len", "length", "size", "count", "idx", "index", "id", "label", "name", "path", "file", "env",
    "cmd", "command", "oid", "public", "mask",
];

/// Whether an identifier carries a material token and nothing that makes it a
/// length or a label. `with_key` decides whether the bare token `key` counts:
/// it does for bytes, and not for a string, which is usually a lookup key.
fn is_material_name(name: &str, with_key: bool) -> bool {
    let lower = name.trim_start_matches('_').to_ascii_lowercase();
    let toks: Vec<&str> = lower.split('_').collect();
    toks.iter()
        .any(|t| (MATERIAL.contains(t) && (with_key || *t != "key")) || ABBREVIATED.contains(t))
        && !toks.iter().any(|t| NOT_MATERIAL.contains(t))
}

/// A Rust integer literal, with an optional integer suffix: `7`, `0x11u8`,
/// `0xCAFE_BABE`, `16usize`.
fn is_numeric_literal(s: &str) -> bool {
    let t = s.trim();
    if !t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return false;
    }
    let (body, suffix) = match t.find(['u', 'i']) {
        Some(i) => t.split_at(i),
        None => (t, ""),
    };
    let suffixes = [
        "", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
    ];
    if !suffixes.contains(&suffix) {
        return false;
    }
    if let Some(hex) = body.strip_prefix("0x") {
        !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit() || c == '_')
    } else if let Some(bin) = body.strip_prefix("0b") {
        !bin.is_empty() && bin.chars().all(|c| c == '0' || c == '1' || c == '_')
    } else {
        body.chars().all(|c| c.is_ascii_digit() || c == '_')
    }
}

/// How an initializer reads as a literal byte array.
#[derive(Debug, PartialEq)]
enum ArrayLiteral {
    /// Not a literal array.
    No,
    /// `[x; n]` or `vec![x; n]` with a literal element `x`; `zero` when it is 0.
    Filled { zero: bool },
    /// `[a, b, ..]` with every element a literal, or an array opened with `[`
    /// whose next line starts with a literal.
    Listed,
}

/// Reads `init` (and, for an array opened at the end of the line, the first
/// line of its body) as a literal byte array.
fn array_literal(init: &str, next: Option<&str>) -> ArrayLiteral {
    let t = init.trim().trim_end_matches([';', ',']).trim();
    let t = t.trim_start_matches("&mut ").trim_start_matches('&');
    let t = t.strip_prefix("vec!").unwrap_or(t);
    if t == "[" {
        let first = next.and_then(|x| x.split(',').next()).unwrap_or("");
        return if is_numeric_literal(first) {
            ArrayLiteral::Listed
        } else {
            ArrayLiteral::No
        };
    }
    let Some(inner) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) else {
        return ArrayLiteral::No;
    };
    if let Some((elem, count)) = inner.split_once(';') {
        if is_numeric_literal(elem) && !count.trim().is_empty() {
            let body = elem.trim().split(['u', 'i']).next().unwrap_or("");
            let body = body.trim_start_matches("0x").trim_start_matches("0b");
            let zero = body.chars().all(|c| c == '0' || c == '_');
            return ArrayLiteral::Filled { zero };
        }
        return ArrayLiteral::No;
    }
    let items: Vec<&str> = inner
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .collect();
    if !items.is_empty() && items.iter().all(|x| is_numeric_literal(x)) {
        ArrayLiteral::Listed
    } else {
        ArrayLiteral::No
    }
}

/// A literal byte array bound to a material name: `let [mut] NAME[: T] =`,
/// `const NAME: T =`, `static NAME: T =`, `NAME =` or a struct field
/// `NAME: <array>`. `next` is the following non-blank line, read when the
/// array opens at the end of this one.
fn array_binding_is_material(l: &str, next: Option<&str>) -> bool {
    let l = without_comment(l);
    let next = next.map(without_comment);
    let decl = l
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub ");
    let (name, init, mutable) = if let Some(rest) = decl.strip_prefix("let ") {
        let mutable = rest.starts_with("mut ");
        let rest = rest.trim_start_matches("mut ");
        let Some((lhs, init)) = rest.split_once(" = ") else {
            return false;
        };
        (lhs.split(':').next().unwrap_or("").trim(), init, mutable)
    } else if let Some(rest) = decl
        .strip_prefix("const ")
        .or_else(|| decl.strip_prefix("static "))
    {
        let Some((lhs, init)) = rest.split_once(" = ") else {
            return false;
        };
        (lhs.split(':').next().unwrap_or("").trim(), init, false)
    } else if let Some((lhs, init)) = l.split_once(" = ").or_else(|| l.split_once(": ")) {
        (lhs.trim(), init, false)
    } else {
        return false;
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    if !is_material_name(name, true) {
        return false;
    }
    match array_literal(init, next) {
        ArrayLiteral::No => false,
        // The overwritten scratch buffer: see `offending_lines_with`, item 3.
        ArrayLiteral::Filled { zero: true } if mutable => false,
        _ => true,
    }
}

/// `l` without a trailing `//` comment (one outside any string literal).
fn without_comment(l: &str) -> &str {
    let code = code_mask(l);
    match l
        .match_indices("//")
        // A comment starts in code; `"//` is a string's opening quote
        // (code) followed by its contents.
        .find(|(i, _)| *i == 0 || (code[*i - 1] && !l[..*i].ends_with('"')))
    {
        Some((i, _)) => l[..i].trim_end(),
        None => l,
    }
}

/// Library key constructors and the argument positions that are key, IV or
/// nonce, for calls whose declaration is outside the crate. Matched on the
/// end of the called path, so `hmac::Key::new` matches `Key::new`.
const LIBRARY_SINKS: &[(&str, &[usize])] = &[
    // hmac (RustCrypto): `HmacSha256::new_from_slice(key)`.
    ("new_from_slice", &[0]),
    // cbc / ctr (RustCrypto KeyIvInit): `Aes128CbcEnc::new_from_slices(key, iv)`.
    ("new_from_slices", &[0, 1]),
    // ring.
    ("UnboundKey::new", &[1]),
    ("hmac::Key::new", &[1]),
    ("Nonce::assume_unique_for_key", &[0]),
    ("Nonce::try_assume_unique_for_key", &[0]),
];

/// One parameter of a declared function or closure.
#[derive(Debug, Clone)]
struct Param {
    name: String,
    ty: String,
}

/// Every function and closure declaration the scan knows, by name.
#[derive(Default, Clone)]
struct Signatures {
    by_name: std::collections::HashMap<String, Vec<Vec<Param>>>,
}

impl Signatures {
    /// The declarations in `srcs`: `fn NAME(..)` (generic or not, the
    /// receiver dropped, so a method call's arguments line up) and
    /// `let NAME = [move] |..|` closures.
    fn of(srcs: &[&str]) -> Self {
        let mut s = Signatures::default();
        for src in srcs {
            s.add_fns(src);
            s.add_closures(src);
        }
        s
    }

    /// The `fn` declarations in `src`.
    fn add_fns(&mut self, src: &str) {
        let s = self;
        {
            let code = code_mask(src);
            for (i, _) in src.match_indices("fn ") {
                if !code[i] || (i > 0 && is_ident_char(src.as_bytes()[i - 1])) {
                    continue;
                }
                let rest = &src[i + 3..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if name.is_empty() {
                    continue;
                }
                let mut j = i + 3 + name.len();
                if src[j..].starts_with('<') {
                    j = match close_of(src, &code, j, b'<', b'>') {
                        Some(e) => e + 1,
                        None => continue,
                    };
                }
                if !src[j..].starts_with('(') {
                    continue;
                }
                let Some(end) = close_of(src, &code, j, b'(', b')') else {
                    continue;
                };
                let params = split_top_level(src, &code, j + 1, end)
                    .into_iter()
                    .filter_map(|(a, b)| param_of(&src[a..b]))
                    .collect();
                s.by_name.entry(name).or_default().push(params);
            }
        }
    }

    /// The `let NAME = |..|` closures in `src`. A closure is local to its
    /// file, so a repo scan adds only the scanned file's closures to the
    /// crate's functions.
    fn add_closures(&mut self, src: &str) {
        let s = self;
        {
            let code = code_mask(src);
            for (i, _) in src.match_indices("let ") {
                if !code[i] {
                    continue;
                }
                let rest = &src[i + 4..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                let after = rest[name.len()..].trim_start();
                let Some(after) = after.strip_prefix('=') else {
                    continue;
                };
                let after = after.trim_start();
                let after = after.strip_prefix("move ").unwrap_or(after).trim_start();
                let Some(body) = after.strip_prefix('|') else {
                    continue;
                };
                let Some(close) = body.find('|') else {
                    continue;
                };
                let params = body[..close].split(',').filter_map(param_of).collect();
                s.by_name.entry(name).or_default().push(params);
            }
        }
    }

    /// The argument positions of a call to `callee` with `arity` arguments
    /// that receive material: a position counts when EVERY declaration of
    /// that name with that many parameters names it as material, so one
    /// `fn new(key: ..)` does not make every other `new` a key constructor.
    fn material_params(&self, callee: &str, arity: usize) -> Vec<Option<Param>> {
        let last = callee.rsplit("::").next().unwrap_or(callee);
        let mut out: Vec<Option<Param>> = vec![None; arity];
        if let Some(decls) = self.by_name.get(last) {
            let fitting: Vec<&Vec<Param>> = decls.iter().filter(|d| d.len() == arity).collect();
            for (pos, slot) in out.iter_mut().enumerate() {
                // A declaration that names no parameter here (`_`, a mock's
                // `_: &[u8]`) says nothing about it and casts no vote.
                let voters: Vec<&&Vec<Param>> = fitting
                    .iter()
                    .filter(|d| !d[pos].name.trim_start_matches('_').is_empty())
                    .collect();
                if !voters.is_empty() && voters.iter().all(|d| param_is_material(last, d, pos)) {
                    *slot = Some(voters[0][pos].clone());
                }
            }
        }
        for (path, positions) in LIBRARY_SINKS {
            if callee == *path || callee.ends_with(&format!("::{path}")) {
                for &p in *positions {
                    if p < arity && out[p].is_none() {
                        out[p] = Some(Param {
                            name: "key".to_string(),
                            ty: "&[u8]".to_string(),
                        });
                    }
                }
            }
        }
        out
    }
}

/// Function-name tokens that make a parameter named just `key` a lookup key:
/// the bencode dictionary's `get_str(key: &[u8])` in `src/rtpengine/` takes
/// byte strings such as `b"address"`, and they are field names.
const LOOKUP_VERBS: &[&str] = &[
    "get", "contains", "remove", "lookup", "find", "entry", "insert", "has",
];

/// Whether parameter `pos` of `fn name(params)` receives material: its name
/// carries a material token, and a parameter named only `key` belongs to a
/// function that is not a lookup ([`LOOKUP_VERBS`]).
fn param_is_material(name: &str, params: &[Param], pos: usize) -> bool {
    let p = &params[pos].name;
    if !is_material_name(p, true) {
        return false;
    }
    if p.trim_start_matches('_') != "key" {
        return true;
    }
    !name
        .to_ascii_lowercase()
        .split('_')
        .any(|t| LOOKUP_VERBS.contains(&t))
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// A parameter from its source text, or `None` for a receiver (`self`,
/// `&self`, `&mut self`) or a pattern that names nothing.
fn param_of(text: &str) -> Option<Param> {
    let t = text.trim();
    let (pat, ty) = match t.split_once(':') {
        Some((p, ty)) => (p.trim(), ty.trim()),
        None => (t, ""),
    };
    let pat = pat.trim_start_matches("mut ").trim();
    if pat.is_empty() || pat.ends_with("self") {
        return None;
    }
    Some(Param {
        name: pat.to_string(),
        ty: ty.to_string(),
    })
}

/// For each byte of `src`, whether it is code: false inside a comment, a
/// string literal or a character literal, so a `(` in a string is not a call
/// and a `"` in a character literal does not open a string.
fn code_mask(src: &str) -> Vec<bool> {
    let b = src.as_bytes();
    let mut mask = vec![true; b.len()];
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            i += 2;
            while i < b.len() && !b[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else if b[i] == b'r'
            && (b[i..].starts_with(b"r\"") || b[i..].starts_with(b"r#"))
            && (i == 0 || !is_ident_char(b[i - 1]) || b[i - 1] == b'b')
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                j += 1;
                while j < b.len() && !b[j..].starts_with(&close) {
                    j += 1;
                }
                i = (j + close.len()).min(b.len());
            } else {
                i += 1;
                continue;
            }
        } else if b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(b.len());
        } else if b[i] == b'\'' {
            // A character literal, or a lifetime (`'a`), which is code.
            if i + 1 < b.len() && b[i + 1] == b'\\' {
                i += 2;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                i = (i + 1).min(b.len());
            } else if let Some(c) = src[i + 1..].chars().next()
                && src[i + 1 + c.len_utf8()..].starts_with('\'')
            {
                i += 2 + c.len_utf8();
            } else {
                i += 1;
                continue;
            }
        } else {
            i += 1;
            continue;
        }
        // A string keeps its opening quote as code so `b"` and `"` stay
        // visible to the argument reader; only the contents are masked.
        for m in mask.iter_mut().take(i).skip(start + 1) {
            *m = false;
        }
        if b[start] == b'/' {
            mask[start] = false;
        }
    }
    mask
}

/// The index of the bracket closing the one at `open`, counting only code.
fn close_of(src: &str, code: &[bool], open: usize, o: u8, c: u8) -> Option<usize> {
    let b = src.as_bytes();
    let mut depth = 0usize;
    for (k, &ch) in b.iter().enumerate().skip(open) {
        if !code[k] {
            continue;
        }
        // `->` inside generics is an arrow, not a closing bracket.
        if ch == b'>' && k > 0 && b[k - 1] == b'-' {
            continue;
        }
        if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

/// The byte ranges of the comma-separated items in `src[from..to]`, splitting
/// only at commas outside nested brackets.
fn split_top_level(src: &str, code: &[bool], from: usize, to: usize) -> Vec<(usize, usize)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = from;
    for k in from..to {
        if !code[k] {
            continue;
        }
        match b[k] {
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'>' if k > 0 && b[k - 1] != b'-' => depth -= 1,
            b',' if depth == 0 => {
                out.push((start, k));
                start = k + 1;
            }
            _ => {}
        }
    }
    if src[start..to].trim().is_empty() {
        return out;
    }
    out.push((start, to));
    out
}

/// Literals handed straight to a material parameter: each call in `src` is
/// matched against `sigs` and [`LIBRARY_SINKS`], and each argument that is a
/// literal reaching a parameter named for material is reported on the line
/// it starts. The parameter's declared type must hold what the literal is:
/// a byte array or byte string reaches a parameter whose type mentions `u8`
/// (`&[u8]`, `[u8; 16]`, `Vec<u8>`), a string literal a `str` or `String`
/// one not named only `key` (a lookup key), and an integer a `u8`, the byte
/// a key is filled from. The type is what keeps a generic `key: K` (the LRU
/// cache's) and a name shared with a standard method (`insert`) out.
fn call_hits(src: &str, sigs: &Signatures) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let code = code_mask(src);
    let lines: Vec<&str> = src.lines().collect();
    let line_of = |off: usize| src[..off].matches('\n').count();
    let mut out: Vec<(usize, String)> = Vec::new();
    for (open, _) in src.match_indices('(') {
        if !code[open] {
            continue;
        }
        let mut s = open;
        while s > 0 && (is_ident_char(b[s - 1]) || b[s - 1] == b':') {
            s -= 1;
        }
        let callee = &src[s..open];
        if callee.is_empty()
            || callee.ends_with(':')
            || !callee.starts_with(|c: char| !c.is_ascii_digit())
        {
            continue;
        }
        // A declaration, not a call.
        if src[..s].trim_end().ends_with("fn") {
            continue;
        }
        let Some(close) = close_of(src, &code, open, b'(', b')') else {
            continue;
        };
        let args = split_top_level(src, &code, open + 1, close);
        let params = sigs.material_params(callee, args.len());
        for ((a, e), param) in args.iter().zip(params) {
            let Some(param) = param else {
                continue;
            };
            let arg = src[*a..*e].trim();
            let lead = src[*a..*e].len() - src[*a..*e].trim_start().len();
            let bare = arg.trim_start_matches("&mut ").trim_start_matches('&');
            let start = *e - bare.len() - (src[*a..*e].len() - src[*a..*e].trim_end().len());
            // The whole argument is the literal: `"x".into()` is a call on
            // one, and its quotes do not close at the argument's end.
            let whole_string = |open: usize| {
                bare.ends_with('"')
                    && bare.len() > open
                    && (start + open..start + bare.len() - 1).all(|k| !code[k])
            };
            let bytes_param = param.ty.contains("u8");
            let literal = if (bare.starts_with("b\"") && whole_string(2))
                || array_literal(bare, None) != ArrayLiteral::No
            {
                bytes_param && is_material_name(&param.name, true)
            } else if bare.starts_with('"') && whole_string(1) {
                (param.ty.contains("str") || param.ty.contains("String"))
                    && is_material_name(&param.name, false)
            } else if is_numeric_literal(bare) {
                param.ty == "u8" && is_material_name(&param.name, true)
            } else {
                false
            };
            if !literal {
                continue;
            }
            let n = line_of(a + lead);
            let text = lines.get(n).map_or("", |x| x.trim());
            if text.starts_with("//") || text.contains(EXCEPTION) {
                continue;
            }
            if !out.iter().any(|(m, _)| *m == n + 1) {
                out.push((n + 1, text.to_string()));
            }
        }
    }
    out
}

/// `const NAME: ... =` or `static NAME: ... =` where `NAME` carries a material
/// token, in either case.
///
/// Tokens, not substrings: `MONKEY` must not match `key`, and `KEY_A` must.
fn declared_material_name(l: &str) -> bool {
    let rest = l
        .trim_start_matches("pub ")
        .trim_start_matches("pub(crate) ");
    let Some(rest) = rest
        .strip_prefix("const ")
        .or_else(|| rest.strip_prefix("static "))
    else {
        return false;
    };
    let name = rest.split(':').next().unwrap_or("").trim();
    name.to_ascii_lowercase()
        .split('_')
        .any(|tok| MATERIAL.contains(&tok))
}

/// The 1-based line on which `part` begins inside `whole`, for absolute numbers.
fn first_line_of(whole: &str, part: &str) -> usize {
    let off = part.as_ptr() as usize - whole.as_ptr() as usize;
    whole[..off].matches('\n').count() + 1
}

/// `let [mut] name[: type] = <numeric literal>;` -- a fresh binding whose whole
/// initializer is a number. `x ^= 0xff`, `h[0] = 0x44` and `let seed =
/// randoms.concat()` are not this shape and are not material seeds.
fn binds_numeric_literal(l: &str) -> bool {
    let Some(rest) = l.strip_prefix("let ") else {
        return false;
    };
    let Some((_, init)) = rest.split_once(" = ") else {
        return false;
    };
    let init = init.trim_end_matches(';').trim();
    let digits = init
        .trim_start_matches("0x")
        .trim_end_matches(|c: char| c.is_ascii_alphabetic());
    !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_hexdigit() || c == '_')
        && (init.starts_with("0x") || init.chars().next().is_some_and(|c| c.is_ascii_digit()))
}

fn rust_sources() -> Result<Vec<PathBuf>, TestError> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), TestError> {
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut v = Vec::new();
    walk(&repo().join("src"), &mut v)?;
    v.sort();
    Ok(v)
}

/// Every `fn` declared under `src/`, so a test's literal is matched against
/// the parameter it reaches in production code as well as in its own module.
fn crate_functions() -> Result<Signatures, TestError> {
    let mut sigs = Signatures::default();
    for p in rust_sources()? {
        sigs.add_fns(&std::fs::read_to_string(&p)?);
    }
    Ok(sigs)
}

#[test]
fn production_code_hands_no_literal_to_cryptographic_material() -> Result<(), TestError> {
    let mut bad = Vec::new();
    let fns = crate_functions()?;
    for p in rust_sources()? {
        let src = std::fs::read_to_string(&p)?;
        let (prod, _) = split_cfg_test(&src);
        let mut sigs = fns.clone();
        sigs.add_closures(&src);
        for (n, l) in offending_lines_with(prod, false, &sigs) {
            let n = n + first_line_of(&src, prod) - 1;
            bad.push(format!("{}:{n}: {l}", p.strip_prefix(repo())?.display()));
        }
    }
    assert!(
        bad.is_empty(),
        "literal cryptographic material in production code:\n{}",
        bad.join("\n")
    );
    Ok(())
}

/// Test fixtures too: CodeQL scans them, and a pasted nonce is what it flagged.
/// A fixture derives its nonce (see `digest_leak::tests::nonce_for`).
#[test]
fn test_fixtures_derive_their_nonces_rather_than_paste_them() -> Result<(), TestError> {
    let mut bad = Vec::new();
    let fns = crate_functions()?;
    for p in rust_sources()? {
        let src = std::fs::read_to_string(&p)?;
        let (_, tests) = split_cfg_test(&src);
        let mut sigs = fns.clone();
        sigs.add_closures(&src);
        for (n, l) in offending_lines_with(tests, true, &sigs) {
            let n = n + first_line_of(&src, tests) - 1;
            bad.push(format!("{}:{n}: {l}", p.strip_prefix(repo())?.display()));
        }
    }
    assert!(
        bad.is_empty(),
        "test code hands a literal to cryptographic material (CodeQL will flag each):\n{}",
        bad.join("\n")
    );
    Ok(())
}

/// POSITIVE CONTROL: the matcher sees every shape it claims to.
#[test]
fn the_matcher_reports_each_literal_material_shape() -> Result<(), TestError> {
    let src = "let nonce = \"abc\";\nlet a = Auth { secret: \"x\" };\nchallenge(\"a\", 1, \"b\", \"n-shared\");\n";
    let hits: Vec<usize> = offending_lines(src).into_iter().map(|(n, _)| n).collect();
    assert_eq!(hits, [1, 2, 3]);
    Ok(())
}

/// The two shapes that walked past this matcher into CI.
///
/// Ten `rust/hard-coded-cryptographic-value` alerts opened on 2026-09-09, all
/// of them one of these: a BYTE-string literal, which the matcher only knew as
/// `"`, and a `const` DECLARATION, which is neither an assignment nor a call
/// argument. This test is the shape of the miss, not of the fix.
#[test]
fn the_matcher_reports_byte_strings_and_const_declarations() -> Result<(), TestError> {
    let src = concat!(
        "const KEY_A: &[u8] = b\"signing-key-alpha\";\n",
        "static SIGNING_KEY: &[u8] = b\"x\";\n",
        "let key = b\"router-signing-key\";\n",
        "let nonce = b\"abc\";\n",
    );
    let hits: Vec<usize> = offending_lines(src).into_iter().map(|(n, _)| n).collect();
    assert_eq!(hits, [1, 2, 3, 4], "every one of these reached CI");
    Ok(())
}

/// Every shape CodeQL's `rust/hard-coded-cryptographic-value` reported in
/// test code on the default branch, each copied from the alert's line.
///
/// Thirty-six alerts of this rule were dismissed as "used in tests" before this
/// test existed, the last of them alert 465, `let master_key = vec![0x11u8; 16];`
/// in `src/app/batch.rs`: a BYTE ARRAY, which no string-literal rule sees.
/// The helper signatures at the end are the parameters the literals reach,
/// as they are declared in the crate (`src/crypto.rs`, `src/rtp/srtp.rs`,
/// `src/capture/hep.rs`).
#[test]
fn the_matcher_reports_every_shape_codeql_flagged_in_tests() -> Result<(), TestError> {
    let src = concat!(
        // 1. alert 465, and 295/304/306/307: repeat-filled vec bound to a key.
        "let master_key = vec![0x11u8; 16];\n",
        // 2. alerts 459/460: repeat-filled array bound to a nonce.
        "let nonce_bytes = [0x01u8; 12];\n",
        // 3. alerts 318/319: an IV.
        "let iv = [0xDDu8; 16];\n",
        // 4. alerts 296/297/298: `mk`, the master key abbreviated.
        "let mk = vec![0x33u8; 16];\n",
        // 5. alert 302: a key named for its role in the test.
        "let wrong_key = vec![0xFF; 16];\n",
        // 6. alerts 299/305: a struct field.
        "    master_key: vec![0u8; 16],\n",
        // 7. alert 103: a const declaration of a repeat-filled array.
        "const NONCE: [u8; 16] = [7u8; 16];\n",
        // 8. alerts 323/324: a multi-line array of byte literals.
        "let session_key = [\n",
        "    0x2B, 0x7E, 0x15, 0x16,\n",
        "];\n",
        // 11. alerts 320/461: literal arrays handed to a crypto backend method.
        "let result = backend.aes_cbc_decrypt(&[0u8; 16], &[0u8; 16], &[0u8; 15]);\n",
        // 12. alert 317.
        "let result = backend.aes_gcm_decrypt(&[0u8; 24], &[0u8; 12], b\"\", b\"ct\");\n",
        // 13. alerts 340/341: a test helper whose third parameter is a nonce.
        "let a = signed(b\"INVITE sip:a SIP/2.0\\r\\n\", NOW, &[1u8; 16]);\n",
        // 14. alert 462: a helper whose first two parameters are key and salt.
        "build_valid_srtp_packet(&[0x33u8; 16], &[0x44u8; 14], 0xCAFE, 7, 0, b\"payload\")?;\n",
        // 15-16. alerts 457/458: a byte seed handed to a closure that fills a key.
        "let km = |mk: u8| Material { master_key: vec![mk; 16] };\n",
        "let km_a = km(0x11);\n",
        // 17-19. the same helper, called the way rustfmt writes a long call.
        "let p = build_valid_srtp_packet(\n",
        "    &[0x33u8; 16],\n",
        "    &salt,\n",
        "    1, 2, 0, b\"x\")?;\n",
        // 21-22. library key constructors, called directly.
        "let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &[9u8; 20]);\n",
        "let mac = HmacSha256::new_from_slice(&[9u8; 32]);\n",
        // The declarations the calls above resolve to.
        "fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;\n",
        // A mock that names no parameter (src/capture/decrypt.rs) says
        // nothing about them, and must not outvote the trait.
        "fn aes_cbc_decrypt(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {\n",
        "fn aes_gcm_decrypt(\n",
        "    &self,\n",
        "    key: &[u8],\n",
        "    nonce: &[u8],\n",
        "    aad: &[u8],\n",
        "    ciphertext: &[u8],\n",
        ") -> Result<Vec<u8>>;\n",
        "fn signed(payload: &[u8], ts: u64, nonce: &[u8; 16]) -> Vec<u8> {\n",
        "fn build_valid_srtp_packet(\n",
        "    master_key: &[u8],\n",
        "    master_salt: &[u8],\n",
        "    ssrc: u32,\n",
        "    seq: u16,\n",
        "    roc: u32,\n",
        "    plaintext: &[u8],\n",
        ") -> Result<Vec<u8>, TestError> {\n",
    );
    let hits: Vec<usize> = offending_lines_in(src, true)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        hits,
        [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 16, 18, 21, 22],
        "each line is a shape CodeQL reported: {:?}",
        offending_lines_in(src, true)
    );
    Ok(())
}

/// A comment after the literal does not hide it. The first draft of the
/// byte-array rule read `vec![0x11u8; 32], // 32 bytes -> AES-128-GCM` (in
/// `src/capture/decrypt.rs`) as an initializer ending in a comment, which is
/// not an array, and passed it.
#[test]
fn a_literal_followed_by_a_comment_is_reported() -> Result<(), TestError> {
    let src = concat!(
        "    secret: vec![0x11u8; 32], // 32 bytes -> AES-128-GCM\n",
        "let key = [0xAAu8; 16]; // the key\n",
    );
    let hits: Vec<usize> = offending_lines_in(src, true)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(hits, [1, 2]);
    Ok(())
}

/// The byte-array rules stop where the material does.
///
/// A zero-filled `let mut` buffer that the next lines overwrite is how the
/// production code builds an IV or a nonce from wire bytes (`src/rtp/srtp.rs`
/// `srtp_cipher_iv`, `src/capture/hep.rs` and `src/capture/decrypt.rs`).
/// CodeQL reported three of those, and all three were dismissed as false
/// positives: the value is overwritten before use, which only data flow can
/// see. The gate does not report the shape, so it never demands a rewrite of
/// correct code.
#[test]
fn a_byte_array_that_is_not_material_is_not_reported() -> Result<(), TestError> {
    let src = concat!(
        // An overwritten scratch buffer (the dismissed false positives).
        "let mut nonce = [0u8; 12];\n",
        "let mut iv = [0u8; 16];\n",
        // A payload, an expected value, a header: not material by name.
        "let payload = vec![0xFFu8; 160];\n",
        "let expected: [u8; 32] = [\n",
        "    0xE0, 0x3E, 0xAD, 0x09,\n",
        "];\n",
        // A type, not a value.
        "    master_key: [u8; 16],\n",
        "fn signed(payload: &[u8], ts: u64, nonce: &[u8; 16]) -> Vec<u8> {\n",
        // A literal in a parameter that is not material.
        "let s = signed(&[1u8; 4], 5, &nonce);\n",
        // A length is not material, though its name says `key`.
        "fn pad(key_len: usize) -> usize {\n",
        "let n = pad(16);\n",
        // A lookup key passed as a string, as in `key: \"jitter_warn_ms\"`.
        "fn lookup(key: &str) -> u32 {\n",
        "let v = lookup(\"jitter_warn_ms\");\n",
        // A runtime-derived key into the same constructor.
        "let mac = HmacSha256::new_from_slice(&derived);\n",
        // A dictionary lookup by a byte-string field name (src/rtpengine/).
        "fn get_str(&self, key: &[u8]) -> Option<String> {\n",
        "let addr = d.get_str(b\"address\")?;\n",
        // A generic lookup key, and a method name a standard map shares.
        "fn insert(&mut self, key: K, value: V) -> Option<V> {\n",
        "m.insert(&[1u8; 4], \"x\");\n",
        // An object identifier that names a key type (src/output/vcon_jose.rs).
        "const EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2A, 0x86];\n",
        // A WebSocket masking key, RFC 6455 section 5.3: framing, not secrecy.
        "let mask_key = [0x37, 0xFA, 0x21, 0x3D];\n",
    );
    assert!(
        offending_lines_in(src, true).is_empty(),
        "{:?}",
        offending_lines_in(src, true)
    );
    Ok(())
}

/// A declaration whose name merely CONTAINS a material word, or whose value is
/// a plain string rather than bytes, is not material.
#[test]
fn a_declaration_that_is_not_material_is_not_reported() -> Result<(), TestError> {
    let src = concat!(
        "const KEY_ORDER: &[&str] = &[\"a\"];\n",
        "const MONKEY: &str = \"m\";\n",
        "const TIMEOUT: u64 = 5;\n",
        // A JSON field name, real, from src/mcp/completeness.rs -- and
        // reported by the first draft of the declaration rule.
        "const TRUNCATED_KEY: &str = \"truncated\";\n",
    );
    assert!(
        offending_lines(src).is_empty(),
        "{:?}",
        offending_lines(src)
    );
    Ok(())
}

/// A literal that is not material -- a Via branch, a display name -- is not reported.
#[test]
fn a_literal_that_is_not_material_is_not_reported() -> Result<(), TestError> {
    let src = "let branch = \"z9hG4bK-a1\";\nlet name = \"alice\";\nlet nonce = extract_param(h, \"nonce\");\n";
    assert!(
        offending_lines(src).is_empty(),
        "{:?}",
        offending_lines(src)
    );
    Ok(())
}

/// The splitter really separates production from tests, or the production
/// scan is silently reading fixtures and the fixture scan is reading nothing.
#[test]
fn the_cfg_test_splitter_keeps_fixtures_out_of_the_production_scan() -> Result<(), TestError> {
    let src =
        "fn real() {}\n#[cfg(test)]\nmod tests {\n    fn f() { let nonce = \"pasted\"; }\n}\n";
    let (prod, tests) = split_cfg_test(src);
    assert!(
        offending_lines(prod).is_empty(),
        "production half must not see the fixture"
    );
    assert_eq!(offending_lines(tests).len(), 1, "the fixture half must");
    let (all, none) = split_cfg_test("fn only() {}\n");
    assert!(
        !all.is_empty() && none.is_empty(),
        "no test module: everything is production"
    );
    Ok(())
}

/// A struct field named `key` holding a lookup name is not material.
#[test]
fn a_lookup_key_field_is_not_material() -> Result<(), TestError> {
    let src = "Row { key: \"jitter_warn_ms\", .. }\nlet key = \"k3y\";\n";
    let hits: Vec<usize> = offending_lines(src).into_iter().map(|(n, _)| n).collect();
    assert_eq!(hits, [2], "only the assignment is material");
    Ok(())
}

/// The named exception is honored, and only in its exact form with a reason.
#[test]
fn a_named_fixture_exception_is_honored_and_a_bare_one_is_not() -> Result<(), TestError> {
    let ok = "let key = \"k3y\"; // material: fixture -- the parser must accept these bytes\n";
    assert!(
        offending_lines(ok).is_empty(),
        "a named exception with its reason is skipped"
    );
    let bare = "let key = \"k3y\"; // fixture\n";
    assert_eq!(
        offending_lines(bare).len(),
        1,
        "an unexplained comment is not an exception"
    );
    // rustfmt moves a comment written after an opening `[` to the first line
    // of the array, so there it names the exception for the binding above.
    let known_answer = "let master_key = [\n    // material: fixture -- RFC 3711 appendix B.3 vector\n    0xE1, 0xF9,\n];\n";
    assert!(
        offending_lines(known_answer).is_empty(),
        "{:?}",
        offending_lines(known_answer)
    );
    let unexplained = "let master_key = [\n    // fixture\n    0xE1, 0xF9,\n];\n";
    assert_eq!(offending_lines(unexplained).len(), 1);
    Ok(())
}

/// The shape CodeQL flagged after the string literals were gone: a hash of
/// the label seeded with a constant, inside `fn nonce_for`. Derived from a
/// constant is still constant, to the query and to a reviewer.
#[test]
fn a_constant_seed_inside_a_material_function_is_reported() -> Result<(), TestError> {
    let src = "fn nonce_for(label: &str) -> String {\n    let mut h: u64 = 0xcbf2_9ce4_8422_2325;\n    format!(\"{h:x}\")\n}\n";
    let hits: Vec<usize> = offending_lines_in(src, true)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(hits, [2], "the seed line");
    // Wrapped in a `Result`, the returned value is still material.
    let src = "fn key_for(label: &str) -> Result<String, TestError> {\n    let mut h: u64 = 0xcbf2_9ce4_8422_2325;\n    Ok(format!(\"{h:x}\"))\n}\n";
    let hits: Vec<usize> = offending_lines_in(src, true)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        hits,
        [2],
        "the seed line of a Result-returning material function"
    );
    Ok(())
}

/// The runtime-minted form is not: no constant, only the clock and a count.
/// Nor is a function that returns no value: a test returning
/// `Result<(), TestError>` binds counters, and its name (`..._exit_key_...`)
/// does not make a counter material.
#[test]
fn a_runtime_minted_material_function_is_not_reported() -> Result<(), TestError> {
    let src = "fn nonce_for(label: &str) -> String {\n    let nanos = now();\n    let distinct = minted.len() as u64;\n    format!(\"{:016x}\", nanos ^ distinct)\n}\nfn receive_frame() -> u64 {\n    let mut h: u64 = 0x1234;\n    tampered[last] ^= 0xff;\n    h\n}\nfn every_popup_renders_its_exit_key_in_full() -> Result<(), TestError> {\n    let mut checked = 0;\n    Ok(())\n}\nfn a_key_is_refused() -> Result<(), Box<dyn std::error::Error>> {\n    let mut seen = 0;\n    Ok(())\n}\n";
    assert!(
        offending_lines_in(src, true).is_empty(),
        "{:?}",
        offending_lines_in(src, true)
    );
    Ok(())
}
