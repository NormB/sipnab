// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every CLI flag must reach code that reads it.
//!
//! This repository keeps rediscovering one defect: a flag that parses,
//! validates, documents itself, and then does nothing. `--alert` was declared
//! as a channel and consumed as a rule. The `[limits]` config keys were parsed
//! and never read. Half the filter DSL was inert. `--exec-rate-limit` never
//! reached `--alert-exec`. Each cost an investigation, and each looked
//! configured from the outside — which is worse than an absent flag, because
//! an operator builds a runbook on it.
//!
//! The `[limits]` fix came with a gate asserting every key is read. This is
//! that gate extended to flags, which is what closes the family.
//!
//! The check is deliberately textual rather than semantic: a field consumed
//! only inside `cli.rs` by a helper that nothing calls would still pass. It
//! catches the blunt case — a flag nothing anywhere mentions — which is the
//! case that has actually shipped, repeatedly.

use std::collections::BTreeSet;
use std::path::Path;

/// Flags that legitimately have no reader, each with the reason.
///
/// Adding an entry is a deliberate act. If a flag lands here because it is
/// unimplemented, its help text and its documentation must say so too —
/// otherwise this list becomes the place where a lie is kept tidy.
const ACCEPTED_WITHOUT_A_READER: &[(&str, &str)] = &[(
    "_sngrep_r",
    "sngrep compatibility: -r is accepted and ignored on purpose, so a \
         muscle-memory invocation does not fail. The leading underscore marks it, \
         and CLI_REFERENCE documents it as a no-op.",
)];

/// Read a repo file relative to the manifest directory.
fn repo_file(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `pub <field>:` declared on the `Cli` struct.
fn cli_fields(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let t = line.trim_start();
        // Struct fields sit at one indent level; `pub fn` and nested types do not.
        if !line.starts_with("    pub ") || t.starts_with("pub fn") || !t.contains(':') {
            continue;
        }
        let Some(name) = t
            .strip_prefix("pub ")
            .and_then(|r| r.split(':').next())
            .map(str::trim)
        else {
            continue;
        };
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            out.push(name.to_string());
        }
    }
    out
}

#[test]
fn every_cli_flag_reaches_something_that_reads_it() {
    /// Fewest Cli fields the parser must still find.
    const MIN_CLI_FIELDS: usize = 140;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let cli_src = repo_file("src/cli.rs");
    let fields: BTreeSet<String> = cli_fields(&cli_src).into_iter().collect();

    // Pinned. A parser that silently stops matching would make this gate pass
    // while checking nothing, which is the failure mode it exists to prevent.
    assert!(
        fields.len() >= MIN_CLI_FIELDS,
        "found only {} Cli fields, expected at least {MIN_CLI_FIELDS} — the \
         field parser \
         stopped matching and this gate is checking less than it claims",
        fields.len()
    );

    // Collect every .rs file under src/ except cli.rs itself.
    let mut sources = String::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let p = entry.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs")
                && p.file_name().is_some_and(|n| n != "cli.rs")
            {
                sources.push_str(&std::fs::read_to_string(&p).expect("read"));
                sources.push('\n');
            }
        }
    }

    // A flag consumed by a `cli.rs` helper that callers use is genuinely read,
    // so `cli.rs` counts — but only its non-test half. `--rtp-interval` was the
    // reason that distinction matters: its sole reference was a unit test
    // asserting its default value, which made a dead flag look tested. It has
    // since been removed rather than kept; the distinction stays, because the
    // next such flag will look exactly the same from here.
    let cli_non_test = match cli_src.find("\nmod tests") {
        Some(i) => &cli_src[..i],
        None => &cli_src[..],
    };

    let accepted: BTreeSet<&str> = ACCEPTED_WITHOUT_A_READER.iter().map(|(f, _)| *f).collect();
    let mut unread = Vec::new();
    for f in &fields {
        if accepted.contains(f.as_str()) {
            continue;
        }
        // `.field` covers the overwhelmingly common access form; a bare match
        // would hit unrelated identifiers and make the gate useless.
        let needle = format!(".{f}");
        if !sources.contains(&needle) && !cli_non_test.contains(&needle) {
            unread.push(f.clone());
        }
    }

    assert!(
        unread.is_empty(),
        "these CLI flags are declared but nothing outside src/cli.rs reads them: {unread:?}\n\
         A flag that parses and does nothing is worse than a missing flag, because \
         an operator builds a runbook on it. Wire it, remove it, or add it to \
         ACCEPTED_WITHOUT_A_READER with a reason — and if the reason is \
         'unimplemented', say so in its help text and its documentation too."
    );
}

#[test]
fn accepted_flags_still_exist_and_carry_a_reason() {
    let cli_src = repo_file("src/cli.rs");
    let fields: BTreeSet<String> = cli_fields(&cli_src).into_iter().collect();

    for (flag, reason) in ACCEPTED_WITHOUT_A_READER {
        assert!(
            fields.contains(*flag),
            "{flag} is on the accepted list but is no longer a Cli field — \
             remove the entry rather than leaving a stale exemption"
        );
        assert!(
            reason.len() > 40,
            "{flag}'s exemption reason is too short to be a reason: {reason:?}"
        );
    }
}
