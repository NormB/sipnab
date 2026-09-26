// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every declared client language has a program for each lifecycle step, or
//! a gap that says so (backlog EX1).
//!
//! sipnab's examples are declared in six languages. Without a matrix, "Go has
//! examples" hid that every Go program reads data and none issues a command,
//! and C and C++ were implied by three fences that quote libpcap, not sipnab.
//! Here each (language, step) cell is either a program, with a string its
//! source must contain to show it does that step, or a declared gap. The
//! gaps are counted, so closing one is a visible change of a pinned number,
//! and the table in `docs/client-examples.md` is held to the matrix cell for
//! cell, so the page cannot claim a program the repository does not have.

use std::collections::BTreeSet;
use std::path::Path;

/// The declared client languages, as the page names them. TypeScript counts
/// as JavaScript: the same runtime, and its programs sit beside the `.mjs`.
const LANGUAGES: &[&str] = &["Rust", "Python", "Go", "JavaScript", "C", "C++"];

/// The lifecycle an operator's program walks through, in order.
///
/// - `configure`: starts sipnab from a configuration it writes or chooses.
/// - `capture`: starts sipnab on a capture source and takes its output.
/// - `read`: reads captured data from a running sipnab.
/// - `command`: changes something through sipnab (a write, not a read).
/// - `process`: turns what it read into an answer the operator acts on.
/// - `stop`: stops a running sipnab through its own interface.
const STEPS: &[&str] = &["configure", "capture", "read", "command", "process", "stop"];

/// (language, step, program, a string the program's source must contain).
const PROGRAMS: &[(&str, &str, &str, &str)] = &[
    (
        "Rust",
        "read",
        "clients/rust/src/main.rs",
        r#"&["v1", "dialogs"]"#,
    ),
    (
        "Python",
        "capture",
        "clients/python/agent_triage.py",
        "mcp_calls.stdio(",
    ),
    (
        "Python",
        "read",
        "clients/python/list_dialogs.py",
        "/v1/dialogs",
    ),
    (
        "Python",
        "command",
        "clients/python/scanner_ban.py",
        r#"call("POST", "/v1/tfps/ban""#,
    ),
    (
        "Python",
        "process",
        "clients/python/failed_calls.py",
        r#"get("/v1/aggregate""#,
    ),
    (
        "Go",
        "read",
        "clients/go/list-dialogs/main.go",
        "/v1/dialogs",
    ),
    (
        "JavaScript",
        "read",
        "clients/javascript/list-dialogs.mjs",
        "/v1/dialogs",
    ),
];

/// (language, step, why there is no program yet).
const EXPECTED_GAPS: &[(&str, &str, &str)] = &[
    (
        "Rust",
        "configure",
        "no client starts sipnab from a configuration",
    ),
    (
        "Rust",
        "capture",
        "the Rust client reads a running sipnab only",
    ),
    ("Rust", "command", "the Rust client issues no write"),
    ("Rust", "process", "the Rust client prints what it reads"),
    (
        "Rust",
        "stop",
        "no client stops sipnab through its interface",
    ),
    (
        "Python",
        "configure",
        "no client starts sipnab from a configuration",
    ),
    (
        "Python",
        "stop",
        "no client stops sipnab through its interface",
    ),
    (
        "Go",
        "configure",
        "no client starts sipnab from a configuration",
    ),
    (
        "Go",
        "capture",
        "the Go programs read a running sipnab only",
    ),
    ("Go", "command", "the Go programs issue no write"),
    ("Go", "process", "the Go programs print what they read"),
    ("Go", "stop", "no client stops sipnab through its interface"),
    (
        "JavaScript",
        "configure",
        "no client starts sipnab from a configuration",
    ),
    (
        "JavaScript",
        "capture",
        "the JavaScript programs read a running sipnab only",
    ),
    (
        "JavaScript",
        "command",
        "the JavaScript programs issue no write",
    ),
    (
        "JavaScript",
        "process",
        "the JavaScript programs print what they read",
    ),
    (
        "JavaScript",
        "stop",
        "no client stops sipnab through its interface",
    ),
    ("C", "configure", "no C client exists"),
    ("C", "capture", "no C client exists"),
    ("C", "read", "no C client exists"),
    ("C", "command", "no C client exists"),
    ("C", "process", "no C client exists"),
    ("C", "stop", "no C client exists"),
    ("C++", "configure", "no C++ client exists"),
    ("C++", "capture", "no C++ client exists"),
    ("C++", "read", "no C++ client exists"),
    ("C++", "command", "no C++ client exists"),
    ("C++", "process", "no C++ client exists"),
    ("C++", "stop", "no C++ client exists"),
];

/// How many cells are gaps. Closing one lowers this, in the same commit that
/// adds the program; raising it means a program was dropped.
const GAP_COUNT: usize = 29;

/// What the page writes in a cell that is a gap.
const GAP_CELL: &str = "Not yet";

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn every_language_has_every_step_as_a_program_or_a_declared_gap() {
    let mut problems = Vec::new();
    for lang in LANGUAGES {
        for step in STEPS {
            let programs = PROGRAMS
                .iter()
                .filter(|p| p.0 == *lang && p.1 == *step)
                .count();
            let gaps = EXPECTED_GAPS
                .iter()
                .filter(|g| g.0 == *lang && g.1 == *step)
                .count();
            if programs + gaps != 1 {
                problems.push(format!(
                    "{lang} / {step}: {programs} program(s) and {gaps} gap(s); \
                     each cell is exactly one of the two"
                ));
            }
        }
    }
    for (lang, step, ..) in PROGRAMS.iter() {
        if !LANGUAGES.contains(lang) || !STEPS.contains(step) {
            problems.push(format!("program cell {lang} / {step} is not in the matrix"));
        }
    }
    for (lang, step, why) in EXPECTED_GAPS {
        if !LANGUAGES.contains(lang) || !STEPS.contains(step) {
            problems.push(format!("gap cell {lang} / {step} is not in the matrix"));
        }
        if why.trim().is_empty() {
            problems.push(format!("gap {lang} / {step} gives no reason"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert_eq!(
        EXPECTED_GAPS.len(),
        GAP_COUNT,
        "the gap count moved; lower GAP_COUNT when a program closes a gap"
    );
}

#[test]
fn each_program_exists_and_does_its_step() {
    let mut problems = Vec::new();
    for (lang, step, path, evidence) in PROGRAMS {
        match std::fs::read_to_string(repo().join(path)) {
            Err(e) => problems.push(format!("{lang} / {step}: {path}: {e}")),
            Ok(src) if !src.contains(evidence) => problems.push(format!(
                "{lang} / {step}: {path} no longer contains `{evidence}`, the call that \
                 makes it the {step} program"
            )),
            Ok(_) => {}
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The cell the matrix says the page should show for (language, step).
fn expected_cell(lang: &str, step: &str) -> String {
    match PROGRAMS.iter().find(|p| p.0 == lang && p.1 == step) {
        Some((_, _, path, _)) => {
            let name = Path::new(path)
                .strip_prefix("clients")
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.to_string());
            format!("[{name}](../{path})")
        }
        None => GAP_CELL.to_string(),
    }
}

#[test]
fn the_examples_page_shows_the_matrix() {
    let page = std::fs::read_to_string(repo().join("docs/client-examples.md"))
        .expect("read docs/client-examples.md");
    let header = format!("| Language | {} |", STEPS.join(" | "));
    let start = page.find(&header).unwrap_or_else(|| {
        panic!("docs/client-examples.md has no lifecycle table headed `{header}`")
    });
    let rows: Vec<Vec<String>> = page[start..]
        .lines()
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(|l| {
            l.trim_matches('|')
                .split(" | ")
                .map(|c| c.trim().to_string())
                .collect()
        })
        .collect();
    let shown: BTreeSet<&str> = rows.iter().map(|r| r[0].as_str()).collect();
    let declared: BTreeSet<&str> = LANGUAGES.iter().copied().collect();
    assert_eq!(
        shown, declared,
        "the table's languages (left) differ from LANGUAGES (right)"
    );
    let mut problems = Vec::new();
    for row in &rows {
        for (i, step) in STEPS.iter().enumerate() {
            let want = expected_cell(&row[0], step);
            let got = row.get(i + 1).map(String::as_str).unwrap_or("");
            if got != want {
                problems.push(format!(
                    "{} / {step}: the page shows `{got}`, want `{want}`",
                    row[0]
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
