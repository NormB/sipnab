//! No hard-coded cryptographic material outside `#[cfg(test)]`.
//!
//! On 2026-08-28 all 44 open CodeQL alerts were dismissed, and 41 of them were
//! `rust/hard-coded-cryptographic-value` or `rust/cleartext-logging` findings
//! inside `#[cfg(test)]` modules -- RFC test vectors and assertion messages.
//! Dismissing them was right: a conformance test that generated its own key
//! would verify nothing, so the published vector IS the oracle, and rewriting
//! it would destroy the test rather than harden it.
//!
//! **But a dismissal is a promise about the future, and nothing was keeping
//! it.** The reasoning "these are only in tests" stops being true the moment
//! someone binds a literal key in production code, and the next reader of the
//! security tab would see a tidy zero and no reason to look. This gate is what
//! makes the dismissal safe: the claim is now checked on every run, on the
//! machine doing the pushing, rather than re-argued from a settings page.
//!
//! The rule distinguishes a KEY from a BUFFER. `[0u8; 12]` zero-initializes
//! storage that the next lines overwrite -- that is what `decrypt.rs` does with
//! the GCM nonce, and CodeQL flagged it as critical. A literal carrying
//! non-zero constant bytes under a cryptographic name is the real thing.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo().join("src"), &mut out);
    out.sort();
    out
}

/// Line numbers (1-based) that sit inside a `#[cfg(test)]` module.
///
/// Brace-counted from the `#[cfg(test)]` attribute rather than assumed to run
/// to end-of-file: several files here put a test module in the middle and
/// continue with production code after it, so "everything below the attribute"
/// would excuse real findings.
fn test_line_span(text: &str) -> Vec<bool> {
    let lines: Vec<&str> = text.lines().collect();
    let mut in_test = vec![false; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
            // Find the module's opening brace, then match it.
            let mut depth = 0usize;
            let mut started = false;
            let mut j = i;
            while j < lines.len() {
                for c in lines[j].chars() {
                    if c == '{' {
                        depth += 1;
                        started = true;
                    } else if c == '}' && depth > 0 {
                        depth -= 1;
                    }
                }
                in_test[j] = true;
                j += 1;
                if started && depth == 0 {
                    break;
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    in_test
}

/// Does this line bind a cryptographic name to a literal with non-zero bytes?
fn is_hardcoded_secret(line: &str) -> bool {
    let l = line.trim();
    if l.starts_with("//") || l.starts_with("///") {
        return false;
    }
    // `nonce` and `iv` are here deliberately. They were missing, and their
    // absence made the buffer assertion below VACUOUS: it passed because the
    // name never matched, not because the zero-initialized value was excused,
    // so the branch meant to protect `capture/decrypt.rs` decided nothing and
    // mutating it changed no verdict. That file's GCM nonce is the one
    // critical production finding CodeQL reported, so a gate claiming to cover
    // it had better be able to see it.
    let names = [
        "key",
        "secret",
        "password",
        "passwd",
        "token",
        "salt",
        "seed",
        "master_key",
        "session_key",
        "private",
        "nonce",
        "iv",
    ];
    // Must bind a name that reads as cryptographic material.
    let binds_crypto_name = names.iter().any(|n| {
        l.contains(&format!("let {n}"))
            || l.contains(&format!("let mut {n}"))
            || l.contains(&format!("_{n} ="))
            || l.contains(&format!("{n} = ["))
            || l.contains(&format!("{n}: &[u8] = "))
            || l.contains(&format!("const {}", n.to_uppercase()))
    });
    if !binds_crypto_name {
        return false;
    }
    // The literal must BE the right-hand side, not merely appear on the line.
    //
    // Requiring only "a crypto name and a string somewhere" caught three
    // production lines that are not secrets, and each is a distinct way to be
    // wrong: `hkdf_expand_label_info(b"key", ..)` passes the RFC 8446 label
    // "key" as an argument, `let cseq_key = msg.cseq().map(..)` is a map key
    // with no crypto in it, and `key_b64.context("Missing 'key=' ..")` is an
    // error message. All three COMPUTE their value; a hard-coded secret is
    // written down.
    let Some((_, rhs)) = l.split_once('=') else {
        return false;
    };
    let rhs = rhs.trim_start();
    let is_literal_rhs = rhs.starts_with('[') || rhs.starts_with('"') || rhs.starts_with("b\"");
    if !is_literal_rhs {
        return false;
    }
    // Distinguish a repeat expression from a list. `[0u8; 12]` allocates
    // storage; `[0xAA; 16]` writes down a key sixteen times. Splitting on the
    // semicolon is what makes the zero check LOAD-BEARING -- an earlier version
    // exempted `[0u8;` and then also required hex further down, so the
    // exemption decided nothing and removing it changed no verdict. A branch
    // that cannot alter the outcome is not protecting anything; it just reads
    // as though it is.
    if rhs.starts_with('[') {
        let body = rhs.trim_start_matches('[');
        let body = body.split(']').next().unwrap_or("");
        if let Some((value, _count)) = body.split_once(';') {
            // Repeat expression: the VALUE decides, never the length. The
            // length is why an earlier version flagged every zero buffer in
            // the tree -- `[0u8; 12]` has an `8` in its TYPE SUFFIX, so
            // "contains a non-zero digit" read `0u8` as material and reported
            // five healthy production lines as hard-coded keys.
            return literal_is_nonzero(value);
        }
        // List of bytes: any non-zero constant element makes it material.
        return body.split(',').any(literal_is_nonzero);
    }
    // Actual constant bytes in a string form: hex, escapes, or a non-empty
    // string literal.
    rhs.contains("0x")
        || rhs.contains("\\x")
        || (rhs.starts_with('"') && !rhs.starts_with("\"\""))
        || (rhs.starts_with("b\"") && !rhs.starts_with("b\"\""))
}

/// Is this array element a non-zero constant?
///
/// Strips the Rust type suffix first. `0u8` is zero written with its type, not
/// the number eight, and reading the suffix as data is what made the zero
/// check report buffers as keys.
fn literal_is_nonzero(value: &str) -> bool {
    let mut v = value.trim();
    for suffix in [
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
    ] {
        if let Some(stripped) = v.strip_suffix(suffix) {
            v = stripped;
            break;
        }
    }
    let v = v.trim();
    if v.is_empty() {
        return false;
    }
    // Zero in any base, however it is spelled: 0, 0x00, 0b0000, 0o0.
    let digits = v
        .trim_start_matches("0x")
        .trim_start_matches("0b")
        .trim_start_matches("0o")
        .replace('_', "");
    if digits.is_empty() {
        return false;
    }
    // It must actually BE a numeric literal. Without this, an identifier in an
    // array of slices -- `[label, seed].concat()`, `[client_random.as_slice(),
    // ..]` -- has no character equal to '0', so "not all zeros" read it as
    // material and four correct TLS/DTLS key-derivation lines were reported as
    // hard-coded secrets. A concatenation of runtime values is the OPPOSITE of
    // a hard-coded one.
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    !digits.chars().all(|c| c == '0')
}

/// 1. No production line binds a cryptographic name to a literal secret.
#[test]
fn no_production_code_hard_codes_cryptographic_material() {
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    for f in source_files() {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let in_test = test_line_span(&text);
        for (i, line) in text.lines().enumerate() {
            scanned += 1;
            if in_test.get(i).copied().unwrap_or(false) {
                continue;
            }
            if is_hardcoded_secret(line) {
                let rel = f.strip_prefix(repo()).unwrap_or(&f).display();
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        scanned > 10_000,
        "only {scanned} lines scanned; the walk found almost nothing and this \
         gate would pass on an empty tree"
    );
    assert!(
        offenders.is_empty(),
        "these production lines bind a cryptographic name to a literal. The \
         44 CodeQL alerts dismissed on 2026-08-28 were dismissed BECAUSE every \
         such literal was a test vector; a production one makes that reasoning \
         false and the security tab misleading.\n\n{}",
        offenders.join("\n")
    );
}

/// 2. The scanner can actually tell a test module from production code.
///
/// Without this, `test_line_span` returning all-true would excuse every
/// finding and gate 1 would pass by examining nothing -- the failure mode this
/// repository keeps hitting, where a check that cannot fire looks like one that
/// passed.
#[test]
fn the_test_module_detector_distinguishes_test_from_production() {
    let sample = "fn prod_one() {}\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                      fn inside() {}\n\
                  }\n\
                  fn prod_two() {}\n";
    let span = test_line_span(sample);
    assert_eq!(span.len(), 6, "line count changed: {span:?}");
    assert!(!span[0], "line 1 is production, marked as test");
    assert!(
        span[1] && span[2] && span[3] && span[4],
        "the module body must be marked: {span:?}"
    );
    assert!(
        !span[5],
        "production code AFTER a test module must not be excused -- this is \
         what makes 'everything below the attribute' wrong: {span:?}"
    );
}

/// 3. The secret detector fires on a real literal and not on a buffer.
#[test]
fn the_secret_detector_separates_a_key_from_a_buffer() {
    assert!(
        is_hardcoded_secret("let master_key = [0x01, 0x02, 0x03];"),
        "a literal key with constant bytes must be caught"
    );
    assert!(
        is_hardcoded_secret(r#"let secret = "hunter2";"#),
        "a string-literal secret must be caught"
    );
    assert!(
        !is_hardcoded_secret("let mut nonce = [0u8; 12];"),
        "a zero-initialized buffer is storage, not a key -- this exact line in \
         capture/decrypt.rs was CodeQL's one critical production finding and it \
         is overwritten on the next two lines"
    );
    assert!(
        !is_hardcoded_secret("// let master_key = [0x01, 0x02];"),
        "a commented-out line is not code"
    );
    assert!(
        !is_hardcoded_secret("let count = [0x01, 0x02];"),
        "a non-cryptographic name must not be swept in, or the gate becomes \
         noise and gets disabled"
    );

    // The three shapes that made the first version of this gate fire on
    // healthy production code. Each is a different way to look like a secret
    // without being one, and each is a line this repository actually contains.
    assert!(
        !is_hardcoded_secret(
            r#"let key_info = hkdf_expand_label_info(b"key", &[], suite.key_len() as u16);"#
        ),
        "capture/decrypt.rs passes the RFC 8446 HKDF-Expand-Label label \"key\" \
         as an ARGUMENT. The label is public and specified; treating it as a \
         secret would make the gate demand that a conformant implementation \
         stop being conformant"
    );
    assert!(
        !is_hardcoded_secret("let cseq_key = msg.cseq().map(|(n, m)| format!(\"{n} {m}\"));"),
        "output/call_report.rs builds a CSeq MAP key. `key` in a name does not \
         mean cryptography, and a gate that assumes it does gets turned off"
    );
    assert!(
        !is_hardcoded_secret(
            r#"let key_b64 = key_b64.context("Missing 'key=' in SRTP key line")?;"#
        ),
        "rtp/srtp.rs writes an ERROR MESSAGE that mentions key=. The literal is \
         diagnostic text, and the value itself is computed"
    );
    assert!(
        !is_hardcoded_secret(r#"let secret = "";"#),
        "an empty string is not a secret"
    );

    // Shapes that only became reachable once `nonce` and `iv` joined the name
    // list, and each of which the detector got WRONG at first. They are locked
    // in here because every one is a real line in this tree.
    assert!(
        !is_hardcoded_secret("let mut iv = [0u8; 16];"),
        "rtp/srtp.rs allocates a 16-byte IV buffer. `0u8` is zero written with \
         its type -- reading the 8 in the suffix as data reported five healthy \
         production lines as hard-coded keys"
    );
    assert!(
        !is_hardcoded_secret(
            "let seed = [client_random.as_slice(), server_random.as_slice()].concat();"
        ),
        "capture/dtls.rs concatenates two RUNTIME randoms. An array of \
         identifiers is the opposite of a hard-coded value, and treating any \
         non-'0' character as material flagged four correct key-derivation lines"
    );
    assert!(
        is_hardcoded_secret("let iv = [0xAA; 16];"),
        "a repeat expression with a NON-zero value writes a key down sixteen \
         times; only the value decides, never the length"
    );
    assert!(
        is_hardcoded_secret("let nonce = [1, 2, 3, 4];"),
        "a decimal byte list is still material -- requiring hex would let the \
         same key through written in base ten"
    );

    // These two exist because mutation testing found the branches they cover
    // were decided by something else, so removing either changed no verdict.
    // A branch nothing distinguishes is not protecting anything.
    assert!(
        is_hardcoded_secret("let iv = [0xAAu8; 16];"),
        "a hex literal carrying its TYPE SUFFIX must still be caught. Without \
         stripping the suffix, `0xAAu8` fails the hex-digit test on the `u` and \
         a real key walks through spelled the way Rust usually spells one"
    );
    assert!(
        !is_hardcoded_secret(r#"let secret = load_from_vault(config, "0xAA");"#),
        "a COMPUTED value whose arguments merely mention hex is not hard-coded. \
         Without the literal-right-hand-side rule, `contains(\"0x\")` alone \
         flags every call that passes a hex string -- which is how a secret \
         fetched properly from a vault gets reported as one written down"
    );
}
