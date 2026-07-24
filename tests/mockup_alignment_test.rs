// SPDX-License-Identifier: MIT OR Apache-2.0

//! Guards the terminal mockups (`<pre class="terminal-body">` blocks) in the
//! website content against box-drawing/ladder misalignment.
//!
//! Regression context: the keybindings-page call-flow ladder and the
//! Save/Settings dialogs shipped measurably misaligned for months because
//! nothing gated them; they were realigned by hand in #142. This test makes
//! that class of drift impossible to reintroduce.
//!
//! Invariants per mockup block (display columns, after stripping HTML tags
//! and unescaping entities):
//! - Unicode box outlines: `┌`/`┐` corner columns must equal `└`/`┘`, and
//!   every interior line must carry `│` at exactly both border columns.
//!   Interior `│` (e.g. `PCAP │ PCAP-NG │ TXT` separators) are ignored.
//! - ASCII-pipe ladders: every `|` must sit on a lifeline column — the
//!   column set of the line with the most pipes.

use std::fmt::Write as _;
use unicode_width::UnicodeWidthChar;

/// Strip HTML tags and unescape the entities the mockups use, so column
/// positions reflect what the browser renders.
fn strip_html(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '<' => {
                for t in chars.by_ref() {
                    if t == '>' {
                        break;
                    }
                }
            }
            '&' => {
                let mut ent = String::new();
                let mut terminated = false;
                while let Some(&e) = chars.peek() {
                    if e == ';' {
                        chars.next();
                        terminated = true;
                        break;
                    }
                    if !e.is_ascii_alphanumeric() && e != '#' {
                        break;
                    }
                    ent.push(e);
                    chars.next();
                }
                if terminated {
                    match ent.as_str() {
                        "lt" => out.push('<'),
                        "gt" => out.push('>'),
                        "amp" => out.push('&'),
                        "quot" => out.push('"'),
                        "#39" | "apos" => out.push('\''),
                        _ => {
                            // Unknown entity: keep verbatim so drift is visible.
                            let _ = write!(out, "&{ent};");
                        }
                    }
                } else {
                    out.push('&');
                    out.push_str(&ent);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Extract every `<pre class="terminal-body">...</pre>` block as
/// (1-based start line, rendered lines).
fn extract_terminal_blocks(text: &str) -> Vec<(usize, Vec<String>)> {
    let re = regex::Regex::new(r#"(?s)<pre class="terminal-body">(.*?)</pre>"#).unwrap();
    re.captures_iter(text)
        .map(|cap| {
            let m = cap.get(0).unwrap();
            let start_line = text[..m.start()].lines().count() + 1;
            let lines = cap[1].lines().map(strip_html).collect();
            (start_line, lines)
        })
        .collect()
}

/// Display-column positions of `needles` occurrences in a rendered line.
///
/// # Arguments
/// * `line` — rendered (tag-stripped) mockup line.
/// * `needles` — characters to locate.
///
/// # Returns
/// `(char, display_column)` pairs in order of appearance.
fn columns_of(line: &str, needles: &[char]) -> Vec<(char, usize)> {
    let mut col = 0;
    let mut hits = Vec::new();
    for c in line.chars() {
        if needles.contains(&c) {
            hits.push((c, col));
        }
        col += c.width().unwrap_or(0);
    }
    hits
}

/// The Unicode box-drawing characters the alignment checker tracks.
const BOX_CHARS: &[char] = &['┌', '┐', '└', '┘', '│', '├', '┤'];

/// Check one rendered mockup block; returns human-readable violations.
///
/// # Arguments
/// * `lines` — the block's rendered lines.
///
/// # Returns
/// One message per box-outline or pipe-ladder alignment violation; empty when
/// the block is aligned.
fn check_block(lines: &[String]) -> Vec<String> {
    let mut violations = Vec::new();
    let hits: Vec<Vec<(char, usize)>> = lines.iter().map(|l| columns_of(l, BOX_CHARS)).collect();

    // --- Unicode box outlines -------------------------------------------
    let mut i = 0;
    while i < lines.len() {
        let top: Vec<_> = hits[i]
            .iter()
            .filter(|(c, _)| *c == '┌' || *c == '┐')
            .collect();
        let (left, right) = match (
            top.iter().find(|(c, _)| *c == '┌'),
            top.iter().rev().find(|(c, _)| *c == '┐'),
        ) {
            (Some(&&(_, l)), Some(&&(_, r))) => (l, r),
            _ => {
                i += 1;
                continue;
            }
        };
        // Find the matching bottom border.
        let Some(bottom) = (i + 1..lines.len()).find(|&j| hits[j].iter().any(|(c, _)| *c == '└'))
        else {
            violations.push(format!("line {}: box has no bottom border", i + 1));
            i += 1;
            continue;
        };
        for (j, line_hits) in hits.iter().enumerate().take(bottom).skip(i + 1) {
            let verticals: Vec<usize> = line_hits
                .iter()
                .filter(|(c, _)| *c == '│' || *c == '├' || *c == '┤')
                .map(|&(_, col)| col)
                .collect();
            if !verticals.contains(&left) || !verticals.contains(&right) {
                violations.push(format!(
                    "line {}: interior line lacks '│' at box borders (cols {left}/{right}), has {verticals:?}",
                    j + 1
                ));
            }
        }
        let bl = hits[bottom]
            .iter()
            .find(|(c, _)| *c == '└')
            .map(|&(_, c)| c);
        let br = hits[bottom]
            .iter()
            .rev()
            .find(|(c, _)| *c == '┘')
            .map(|&(_, c)| c);
        if bl != Some(left) || br != Some(right) {
            violations.push(format!(
                "line {}: bottom corners at {bl:?}/{br:?} but top at {left}/{right}",
                bottom + 1
            ));
        }
        i = bottom + 1;
    }

    // --- ASCII-pipe ladders ---------------------------------------------
    // Only blocks that are pipe-ladders (>=3 lines with '|', no Unicode box
    // art — dialogs use '│' interior separators that are not lifelines).
    let has_box_art = hits.iter().any(|h| !h.is_empty());
    let pipe_cols: Vec<Vec<usize>> = lines
        .iter()
        .map(|l| columns_of(l, &['|']).into_iter().map(|(_, c)| c).collect())
        .collect();
    let pipe_lines = pipe_cols.iter().filter(|c| !c.is_empty()).count();
    if !has_box_art && pipe_lines >= 3 {
        let reference = pipe_cols
            .iter()
            .max_by_key(|c| c.len())
            .cloned()
            .unwrap_or_default();
        for (j, cols) in pipe_cols.iter().enumerate() {
            for col in cols {
                if !reference.contains(col) {
                    violations.push(format!(
                        "line {}: '|' at col {col} is off the lifeline columns {reference:?}",
                        j + 1
                    ));
                }
            }
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// Fixture tests — the checker must accept aligned art and reject misaligned.
// ---------------------------------------------------------------------------

/// Renders a fixture block: splits into lines and strips HTML like the
/// real extractor does.
fn render(block: &str) -> Vec<String> {
    block.lines().map(strip_html).collect()
}

/// `strip_html` drops tags, unescapes known entities, keeps unknown/unterminated ones verbatim, and handles empty input.
#[test]
fn strip_html_removes_tags_and_unescapes_entities() {
    assert_eq!(
        strip_html(r#"<span class="t-good">|--- INVITE ---&gt;|</span>"#),
        "|--- INVITE --->|"
    );
    assert_eq!(
        strip_html("&lt;sip:bob&gt; &amp; &quot;x&quot;"),
        "<sip:bob> & \"x\""
    );
    // Adversarial: bare '&', unterminated entity, empty line.
    assert_eq!(strip_html("a & b &incomplete"), "a & b &incomplete");
    assert_eq!(strip_html(""), "");
    // Unknown-but-terminated entity survives verbatim.
    assert_eq!(strip_html("&nbsp;"), "&nbsp;");
}

// NOTE: fixtures are flush-left because Rust's `"\` continuation strips the
// following line's leading whitespace (only the first line is affected —
// which silently shifts a box's top border).

/// A correctly aligned Unicode box (with interior pipes and HTML tags) yields no violations.
#[test]
fn aligned_box_passes() {
    let block = "\
┌───── Title ─────┐
│  content        │
│ x │ pipes │  yy │
│ <span>zz</span>              │
└─────────────────┘";
    let v = check_block(&render(block));
    assert!(v.is_empty(), "expected no violations, got: {v:?}");
}

/// A right border shifted by one column is reported as a violation.
#[test]
fn box_with_shifted_right_border_fails() {
    let block = "\
┌───── Title ─────┐
│  content         │
└─────────────────┘";
    assert!(
        !check_block(&render(block)).is_empty(),
        "shifted right border must be reported"
    );
}

/// A bottom-left corner off the top corner's column is reported.
#[test]
fn box_with_mismatched_bottom_corner_fails() {
    let block = "\
┌───── Title ─────┐
│  content        │
 └─────────────────┘";
    assert!(
        !check_block(&render(block)).is_empty(),
        "shifted bottom-left corner must be reported"
    );
}

/// An interior line missing its box-border verticals is reported.
#[test]
fn box_interior_line_missing_border_fails() {
    let block = "\
┌───── Title ─────┐
│  content        │
   no borders here
└─────────────────┘";
    assert!(
        !check_block(&render(block)).is_empty(),
        "interior line without borders must be reported"
    );
}

/// An HTML entity (`&gt;`) counts as one display column, so the box still aligns.
#[test]
fn entity_width_counts_one_column() {
    // `&gt;` renders as one column; treating it as 4 shifts the border.
    let block = "\
┌───────┐
│ ---&gt;  │
└───────┘";
    let v = check_block(&render(block));
    assert!(v.is_empty(), "entity must count 1 column, got: {v:?}");
}

/// An ASCII pipe ladder with all pipes on lifeline columns yields no violations.
#[test]
fn aligned_ladder_passes() {
    let block = "\
a               b               c
|               |               |
|--- INVITE --->|               |
|               |--- INVITE --->|
|               |               |";
    let v = check_block(&render(block));
    assert!(v.is_empty(), "expected no violations, got: {v:?}");
}

/// A pipe one column off the lifelines is reported.
#[test]
fn ladder_with_off_column_pipe_fails() {
    let block = "\
a               b               c
|               |               |
|--- INVITE ---> |              |
|               |               |";
    assert!(
        !check_block(&render(block)).is_empty(),
        "off-lifeline pipe must be reported"
    );
}

/// CJK glyphs count 2 display columns, so a line using them still lands the borders correctly.
#[test]
fn wide_glyphs_count_two_columns() {
    // CJK '実' is width 2 — a line using it must still land borders on the
    // same display columns as an all-ASCII line.
    let block = "\
┌──────┐
│ 実実 │
│ xxxx │
└──────┘";
    let v = check_block(&render(block));
    assert!(v.is_empty(), "wide glyphs must count 2 columns, got: {v:?}");
}

/// Blocks with no box art and fewer than 3 pipe lines (tables, raw SIP) pass unchecked.
#[test]
fn plain_text_block_has_no_violations() {
    // Blocks with no box chars and <3 pipe lines (tables, raw SIP) pass.
    let block = "\
INVITE sip:bob@10.0.0.2:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK
 #  SSRC        Codec   MOS";
    assert!(check_block(&render(block)).is_empty());
}

// ---------------------------------------------------------------------------
// Real content — every terminal-body mockup shipped on the site.
// ---------------------------------------------------------------------------

/// Every terminal-body mockup shipped on the site passes `check_block`, and at least 8 blocks are found (extractor liveness check).
#[test]
fn website_terminal_mockups_are_aligned() {
    let sources: &[(&str, &str)] = &[
        (
            "website/content/docs/keybindings.md",
            include_str!("../website/content/docs/keybindings.md"),
        ),
        (
            "website/content/docs/theme.md",
            include_str!("../website/content/docs/theme.md"),
        ),
        (
            "website/templates/index.html",
            include_str!("../website/templates/index.html"),
        ),
    ];
    let mut violations = Vec::new();
    let mut blocks_seen = 0;
    for (path, text) in sources {
        for (start, lines) in extract_terminal_blocks(text) {
            blocks_seen += 1;
            for v in check_block(&lines) {
                violations.push(format!("{path}:{start}: {v}"));
            }
        }
    }
    // The keybindings page alone ships 8 mockups; if extraction ever finds
    // none, the gate is silently dead — fail loudly instead.
    assert!(
        blocks_seen >= 8,
        "expected >=8 terminal-body blocks, found {blocks_seen} — extractor broken?"
    );
    assert!(
        violations.is_empty(),
        "misaligned terminal mockups:\n{}",
        violations.join("\n")
    );
}
