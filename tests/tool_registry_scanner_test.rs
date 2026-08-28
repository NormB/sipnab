//! The registry scanner must see EVERY tool name, including ones with digits.
//!
//! `generate_fail2ban_rule` was live and answering calls while
//! `docs_drift_test`'s registry scanner reported 49 registered tools. Its
//! character class was `[a-z_]+`, so the `2` in `fail2ban` ended the match and
//! the tool did not exist as far as every count derived from it was concerned
//! -- the documented total, the annotation check, and the prose counts in
//! three files.
//!
//! A gate blind to a CLASS of name is worse than a gate that is merely wrong
//! once: it stays green as more of that class arrives, and the number it
//! reports looks measured. This repository has now hit the excludes-digits
//! character class twice -- the first was a site monitor counting note slugs,
//! which under-reported seven notes as six because `what-0-5-128-...` starts
//! with a digit it would not match.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/mcp/`.
fn mcp_sources() -> String {
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
    let mut files = Vec::new();
    walk(&repo().join("src/mcp"), &mut files);
    files.sort();
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

/// 1. A narrow character class must not be able to see fewer tools than a wide
///    one.
///
/// This compares the scanner's own alphabet against a permissive one. If a
/// registered name contains a character the gates do not accept, that name is
/// invisible to every count in the repository and this says so by name.
#[test]
fn no_registered_tool_name_is_invisible_to_the_registry_scanner() {
    let text = mcp_sources();
    let narrow: std::collections::BTreeSet<String> = regex::Regex::new(r#"name = "([a-z0-9_]+)""#)
        .expect("regex")
        .captures_iter(&text)
        .map(|c| c[1].to_string())
        .collect();
    // Deliberately permissive: anything that could plausibly be a tool name.
    let wide: std::collections::BTreeSet<String> = regex::Regex::new(r#"name = "([^"]+)""#)
        .expect("regex")
        .captures_iter(&text)
        .map(|c| c[1].to_string())
        // "Plausible tool name" means an ASCII identifier. Without the ASCII
        // requirement this matched `name = "…"` out of a doc comment and
        // reported an ellipsis as an uncounted tool -- a false alarm from the
        // detector rather than a finding about the code.
        .filter(|n: &String| {
            n.len() >= 3
                && n.is_ascii()
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
        .collect();

    assert!(
        narrow.len() >= 20,
        "only {} tool names matched; the scan is not reaching src/mcp and this \
         gate would pass on an empty tree",
        narrow.len()
    );
    let missed: Vec<&String> = wide.difference(&narrow).collect();
    assert!(
        missed.is_empty(),
        "these registered names are invisible to the `[a-z0-9_]` class the \
         doc-drift gates scan with, so every count derived from it is short by \
         one per name and stays green as more arrive: {missed:?}"
    );
}

/// 2. The scanner's alphabet actually accepts a digit.
///
/// Gate 1 compares two regexes; if BOTH excluded digits it would pass while
/// both were blind. This pins the alphabet itself against a literal.
#[test]
fn the_scanner_alphabet_accepts_a_digit_in_a_tool_name() {
    let sample = r#"    name = "generate_fail2ban_rule","#;
    let found: Vec<String> = regex::Regex::new(r#"name = "([a-z0-9_]+)""#)
        .expect("regex")
        .captures_iter(sample)
        .map(|c| c[1].to_string())
        .collect();
    assert_eq!(
        found,
        vec!["generate_fail2ban_rule".to_string()],
        "the class must match a name containing a digit in full. `[a-z_]` stops \
         at the 2 and yields nothing, which is how a live tool went uncounted"
    );

    // And it must not have become so wide that it swallows neighbouring text.
    let noisy = r#"name = "a_tool", description = "not a name""#;
    let found: Vec<String> = regex::Regex::new(r#"name = "([a-z0-9_]+)""#)
        .expect("regex")
        .captures_iter(noisy)
        .map(|c| c[1].to_string())
        .collect();
    assert_eq!(
        found,
        vec!["a_tool".to_string()],
        "widening the class must not make it match past the closing quote"
    );
}
