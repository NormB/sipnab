// SPDX-License-Identifier: MIT OR Apache-2.0

//! No `<placeholder>` inside a shell block in the user documentation.
//!
//! A reader copies a shell block and pastes it. `--call-report <call-id>` does
//! not fail with "fill this in": the shell reads `<call-id>` as "redirect stdin
//! from a file named call-id" and answers `No such file or directory`, which
//! sends the reader looking for a file nobody mentioned. `v<version>` inside a
//! URL is worse, because `curl` takes the redirect half and fetches nothing.
//!
//! The copy-safe form sets a shell variable on its own line and uses it:
//!
//! ```text
//! CALL_ID='a84b4c76e66710@pc33.atlanta.example.com'
//! sipnab -N -I capture.pcap --call-report "$CALL_ID"
//! ```
//!
//! # What this reads
//!
//! `README.md` and every top-level `docs/*.md` page: the pages a user reads.
//! `docs/design/`, `docs/internals/` and the other planning trees are written
//! for maintainers and are not scanned.
//!
//! Inside a fenced block tagged `bash`, `sh`, `shell` or `console`, a
//! placeholder is `<` followed by a letter, then letters, digits and
//! `_ - . : @ /`, then `>` — one word in angle brackets. What is NOT one:
//!
//! - shell syntax that starts with `<`: `< file`, `<(cmd)`, `<<EOF`;
//! - the body of a here-document, which is data the shell does not parse;
//! - a SIP or tel URI in angle brackets, `<sip:alice@example.com>`, which is
//!   literal message content rather than something to substitute.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Fence languages the reader runs in a shell.
const SHELL_FENCES: &[&str] = &["bash", "sh", "shell", "console"];

/// URI schemes whose angle-bracket form is message content, not a placeholder.
const LITERAL_SCHEMES: &[&str] = &["sip:", "sips:", "tel:", "http:", "https:", "urn:"];

/// The language tag of a fence line, or `None` when the line is not a fence.
fn fence_lang(line: &str) -> Option<&str> {
    let t = line.trim_start();
    t.strip_prefix("```").map(str::trim)
}

/// The terminator word of a here-document opened on this line, if any.
///
/// `cat <<EOF`, `cat <<-'EOF'` and `cat << "EOF"` all open one. A here-string
/// (`<<<`) does not.
fn heredoc_terminator(line: &str) -> Option<String> {
    let i = line.find("<<")?;
    let rest = &line[i + 2..];
    if rest.starts_with('<') {
        return None;
    }
    let rest = rest.strip_prefix('-').unwrap_or(rest).trim_start();
    let word: String = rest
        .chars()
        .filter(|c| *c != '\'' && *c != '"')
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if word.is_empty() { None } else { Some(word) }
}

/// Every `<word>` placeholder on one line of shell.
fn placeholders_on_line(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let after_lt = i > 0 && bytes[i - 1] == b'<';
        let Some(&first) = bytes.get(i + 1) else {
            break;
        };
        if after_lt || !first.is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || b"_-.:@/".contains(&bytes[j]))
        {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'>' {
            let inner = &line[i + 1..j];
            let lower = inner.to_ascii_lowercase();
            if !LITERAL_SCHEMES.iter().any(|s| lower.starts_with(s)) {
                out.push(format!("<{inner}>"));
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Every placeholder inside a shell block, as `(1-based line, token)`.
///
/// Pure over the page text so the shapes it must catch and must pass are
/// driven by the fixtures below rather than by whatever the tree holds today.
fn placeholders_in_shell_blocks(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_fence = false;
    let mut shell = false;
    let mut heredoc: Option<String> = None;
    for (n, line) in text.lines().enumerate() {
        if let Some(lang) = fence_lang(line) {
            if in_fence {
                in_fence = false;
                shell = false;
                heredoc = None;
            } else {
                in_fence = true;
                shell = SHELL_FENCES.contains(&lang);
            }
            continue;
        }
        if !in_fence || !shell {
            continue;
        }
        if let Some(word) = &heredoc {
            if line.trim() == word {
                heredoc = None;
            }
            continue;
        }
        for token in placeholders_on_line(line) {
            out.push((n + 1, token));
        }
        heredoc = heredoc_terminator(line);
    }
    out
}

/// The pages a user reads: the README and the top level of `docs/`.
fn user_pages() -> Vec<PathBuf> {
    let mut pages: Vec<PathBuf> = std::fs::read_dir(repo().join("docs"))
        .expect("docs/ is readable")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    pages.push(repo().join("README.md"));
    pages.sort();
    pages
}

#[test]
fn the_matcher_flags_placeholders_in_shell_blocks_only() {
    let page = "\
Prose may say <call-id> freely.

```bash
sipnab -N -I capture.pcap --call-report <call-id>
```

```text
INVITE <call-id> is output, not a command
```
";
    assert_eq!(
        placeholders_in_shell_blocks(page),
        vec![(4, "<call-id>".to_string())]
    );
}

#[test]
fn the_matcher_reads_every_shell_fence_and_indented_fences() {
    let page = "\
1. Download it:

   ```sh
   curl -LO https://example.com/v<version>/sipnab-<version>.tar.gz
   ```

```console
$ sipnab --api <bind-address>
```

```shell
V=<version>
```
";
    assert_eq!(
        placeholders_in_shell_blocks(page),
        vec![
            (4, "<version>".to_string()),
            (4, "<version>".to_string()),
            (8, "<bind-address>".to_string()),
            (12, "<version>".to_string()),
        ]
    );
}

#[test]
fn the_matcher_passes_shell_syntax_uris_and_heredoc_bodies() {
    let page = "\
```bash
sipnab -N -I capture.pcap --filter \"rtp.mos < 3.5\"
wc -l < calls.txt
diff <(sipnab -N -I a.pcap) <(sipnab -N -I b.pcap)
sipnab -N -I capture.pcap 2>&1 | head
printf 'From: <sip:alice@example.com>\\r\\n'
cat > scenario.xml <<'EOF'
<scenario name=\"uac\">
<send>
EOF
cat <<< \"plain\"
CALL_ID='a84b4c76e66710@pc33.atlanta.example.com'
sipnab -N -I capture.pcap --call-report \"$CALL_ID\"
```
";
    assert!(
        placeholders_in_shell_blocks(page).is_empty(),
        "{:?}",
        placeholders_in_shell_blocks(page)
    );
}

#[test]
fn a_heredoc_ends_at_its_terminator() {
    // After the terminator the block is shell again, and a placeholder there
    // is a placeholder.
    let page = "\
```bash
cat <<EOF
<not-shell>
EOF
sipnab --call-report <call-id>
```
";
    assert_eq!(
        placeholders_in_shell_blocks(page),
        vec![(5, "<call-id>".to_string())]
    );
}

#[test]
fn no_user_page_puts_a_placeholder_in_a_shell_block() {
    let pages = user_pages();
    assert!(
        pages.len() >= 20,
        "only {} page(s) read — the walk is not reading the tree",
        pages.len()
    );
    let mut found = Vec::new();
    for page in &pages {
        let text = std::fs::read_to_string(page).expect("a readable page");
        let rel = page
            .strip_prefix(repo())
            .unwrap_or(page)
            .display()
            .to_string();
        for (line, token) in placeholders_in_shell_blocks(&text) {
            found.push(format!("{rel}:{line}: {token}"));
        }
    }
    assert!(
        found.is_empty(),
        "{} placeholder(s) inside shell blocks. The shell reads `<word>` as a \
         redirection, so the pasted command fails with a file-not-found error. \
         Set a shell variable on its own line and use \"$VAR\" instead:\n  {}",
        found.len(),
        found.join("\n  ")
    );
}
