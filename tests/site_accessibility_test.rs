// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Accessibility rules a test can read from the source, without a browser.
//!
//! `e2e/tests/accessibility.spec.js` runs axe-core over the built site. It
//! measures what needs a rendered page: contrast, target size, keyboard reach.
//! It runs in CI only, on one page per template. The rules here hold on every
//! Markdown page and every template, and run with the rest of the suite.
//!
//! Each rule was a finding of the 2026-11-10 audit, which ran axe-core over
//! all 145 built pages:
//!
//! - `/docs/metrics/` went from its `h1` to `h3` headings, with no `h2`
//!   (WCAG 2.2 success criterion 1.3.1, axe `heading-order`).
//! - Nine pages had a table whose header row held an empty cell (axe
//!   `empty-table-header`): a screen reader announces a column with no name.
//! - The button that opens the navigation on a narrow screen did not say
//!   whether the navigation was open (success criterion 4.1.2).
//! - The search field had a placeholder and no label (success criteria 3.3.2
//!   and 4.1.2).
//! - The pages have one dark theme and did not say so, so a browser drew its
//!   own controls and scrollbars for a light page.
//! - Code blocks on the notes pages scroll sideways and could not be reached
//!   from the keyboard (success criterion 2.1.1): the docs template gave each
//!   block a copy button, and the notes template did not.
//! - Two controls had a label that did not hold their visible text (success
//!   criterion 2.5.3, axe `label-content-name-mismatch`): the analyzer's drop
//!   zone, and the diagram viewer's buttons, whose visible text is a symbol.
//!   A speech-input user says what the control shows, and the name must
//!   match. axe-core 4.14 reports both once the WCAG 2.1 rules run.

use std::path::{Path, PathBuf};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

const BASE: &str = include_str!("../website/templates/base.html");
const PAGE: &str = include_str!("../website/templates/page.html");
const NOTE: &str = include_str!("../website/templates/note.html");
const CODE_COPY: &str = "website/static/js/code-copy.js";
const ANALYZE: &str = include_str!("../website/templates/analyze.html");
const DIAGRAM_VIEWER: &str = include_str!("../website/static/js/diagram-viewer.js");
const STYLE: &str = include_str!("../website/sass/style.scss");

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every Markdown file under `dir`, recursively, sorted.
fn markdown_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            markdown_under(&path, out);
        } else if path.extension().is_some_and(|x| x == "md")
            && !path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(".local.md"))
        {
            out.push(path);
        }
    }
}

/// The pages a visitor reads: the docs sources, the site's own content (which
/// holds the generated copies of the docs and the notes) and the README.
fn pages() -> Vec<PathBuf> {
    let mut out = Vec::new();
    markdown_under(&repo().join("docs"), &mut out);
    markdown_under(&repo().join("website/content"), &mut out);
    out.push(repo().join("README.md"));
    out.sort();
    out
}

/// A page's path relative to the repository, for a failure message.
fn rel(path: &Path) -> String {
    path.strip_prefix(repo())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// The lines of a Markdown document outside fenced code blocks, with their
/// 1-based line numbers. A fence opens with three backticks or three tildes,
/// indented or not, and closes with the same character.
fn prose_lines(md: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut fence: Option<char> = None;
    for (i, line) in md.lines().enumerate() {
        let trimmed = line.trim_start();
        let opener = ['`', '~']
            .into_iter()
            .find(|c| trimmed.starts_with(&c.to_string().repeat(3)));
        match (fence, opener) {
            (None, Some(c)) => fence = Some(c),
            (Some(open), Some(c)) if open == c => fence = None,
            (None, None) => out.push((i + 1, line)),
            _ => {}
        }
    }
    out
}

/// The cells of one table row, without the outer pipes.
fn cells(row: &str) -> Vec<&str> {
    let row = row.trim();
    let row = row.strip_prefix('|').unwrap_or(row);
    let row = row.strip_suffix('|').unwrap_or(row);
    row.split('|').map(str::trim).collect()
}

/// Whether a line is a table's delimiter row: cells of dashes, with optional
/// colons for alignment.
fn is_delimiter_row(line: &str) -> bool {
    let line = line.trim();
    line.contains('-')
        && line.contains('|')
        && cells(line)
            .iter()
            .all(|c| !c.is_empty() && c.contains('-') && c.chars().all(|ch| ch == '-' || ch == ':'))
}

/// The line numbers of table header rows that hold an empty cell.
///
/// A header row is the line directly above a delimiter row. Body rows may
/// hold empty cells: an empty data cell says "nothing", while an empty header
/// cell leaves a column without a name.
fn empty_header_cells(md: &str) -> Vec<usize> {
    let lines = prose_lines(md);
    let mut out = Vec::new();
    for pair in lines.windows(2) {
        let (n, header) = pair[0];
        let (next_n, next) = pair[1];
        if next_n == n + 1
            && is_delimiter_row(next)
            && header.contains('|')
            && cells(header).iter().any(|c| c.is_empty())
        {
            out.push(n);
        }
    }
    out
}

/// A heading level that was skipped: the line, the level before it and the
/// level it has.
#[derive(Debug, PartialEq, Eq)]
struct Skip {
    line: usize,
    from: usize,
    to: usize,
}

/// The level of an ATX heading line, or `None` when the line is not one. A
/// `#` needs a space after it: `#main` is a fragment, not a heading.
fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    ((1..=6).contains(&hashes) && line[hashes..].starts_with(' ')).then_some(hashes)
}

/// Every heading that is more than one level below the heading before it.
///
/// # Arguments
/// * `md` - The Markdown body.
/// * `above` - The level of the heading the body sits under: `0` for a file
///   that supplies its own `h1`, `1` for a site page whose template writes
///   the `h1` from the title.
fn heading_skips(md: &str, above: usize) -> Vec<Skip> {
    let mut out = Vec::new();
    let mut prev = above;
    for (line, text) in prose_lines(md) {
        let Some(level) = heading_level(text) else {
            continue;
        };
        if level > prev + 1 {
            out.push(Skip {
                line,
                from: prev,
                to: level,
            });
        }
        prev = level;
    }
    out
}

/// A site content page's body and the level its headings sit under. A page
/// with `+++` front matter gets its `h1` from the template; any other file
/// writes its own.
fn body_and_level(md: &str) -> (&str, usize) {
    if let Some(rest) = md.strip_prefix("+++")
        && let Some(end) = rest.find("\n+++")
    {
        return (&rest[end + 4..], 1);
    }
    (md, 0)
}

/// The opening tag of the element with this `id`, or `None`.
fn opening_tag<'a>(html: &'a str, id: &str) -> Option<&'a str> {
    let at = html.find(&format!("id=\"{id}\""))?;
    let start = html[..at].rfind('<')?;
    let end = at + html[at..].find('>')?;
    Some(&html[start..=end])
}

/// A template with its Tera comments removed, so a rule reads markup and
/// script only, never a comment that describes them.
fn without_tera_comments(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(start) = rest.find("{#") {
        out.push_str(&rest[..start]);
        match rest[start..].find("#}") {
            Some(end) => rest = &rest[start + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------- tables

#[test]
fn no_table_on_any_page_has_an_empty_header_cell() -> Result<(), TestError> {
    let mut problems = Vec::new();
    let pages = pages();
    assert!(
        pages.len() > 150,
        "read {} Markdown pages; the walk has stopped seeing the docs",
        pages.len()
    );
    for path in pages {
        let text = std::fs::read_to_string(&path)?;
        for line in empty_header_cells(&text) {
            problems.push(format!("{}:{line}", rel(&path)));
        }
    }
    assert!(
        problems.is_empty(),
        "{} table header row(s) hold an empty cell. A screen reader announces \
         that column with no name. Name the column, for example the row \
         label's kind:\n{}",
        problems.len(),
        problems.join("\n")
    );
    Ok(())
}

#[test]
fn an_empty_first_header_cell_is_reported() {
    let md = "intro\n\n| | Debian | Ubuntu |\n|---|---|---|\n| a | b | c |\n";
    assert_eq!(
        empty_header_cells(md),
        [3],
        "the corner cell of a table with row labels is the usual empty one"
    );
}

#[test]
fn an_empty_middle_or_last_header_cell_is_reported() {
    assert_eq!(
        empty_header_cells("| a |  | c |\n|---|---|---|\n"),
        [1],
        "an empty cell between two named ones"
    );
    assert_eq!(
        empty_header_cells("| a | b | |\n|---|---|---|\n"),
        [1],
        "an empty last cell"
    );
}

#[test]
fn a_header_row_of_only_empty_cells_is_reported() {
    assert_eq!(
        empty_header_cells("|  | |\n|---|---|\n| x | y |\n"),
        [1],
        "a table used for layout, with no header text at all"
    );
}

#[test]
fn a_full_header_row_is_not_reported() {
    let md = "| Symptom | Fix |\n|:---|---:|\n| a |  |\n|  | b |\n";
    assert!(
        empty_header_cells(md).is_empty(),
        "empty cells in body rows are data, not column names"
    );
}

#[test]
fn a_header_without_outer_pipes_is_read() {
    assert!(
        empty_header_cells("a | b\n---|---\n1 | 2\n").is_empty(),
        "a full header written without outer pipes"
    );
    assert_eq!(
        empty_header_cells("a |  | c\n---|---|---\n"),
        [1],
        "an empty cell in a header written without outer pipes"
    );
}

#[test]
fn a_table_inside_a_code_fence_is_not_read() {
    let md = "```text\n| | x |\n|---|---|\n```\n\n~~~\n| | y |\n|---|---|\n~~~\n";
    assert!(
        empty_header_cells(md).is_empty(),
        "a table drawn inside a backtick or a tilde fence is sample text"
    );
}

#[test]
fn an_indented_fence_closes_and_the_table_after_it_is_read() {
    let md = "- item\n\n  ```bash\n  ls | wc\n  ```\n\n| | x |\n|---|---|\n";
    assert_eq!(
        empty_header_cells(md),
        [7],
        "a fence indented under a list item must close, or the rest of the \
         page is read as code"
    );
}

#[test]
fn a_rule_or_a_dash_list_is_not_a_delimiter_row() {
    assert!(!is_delimiter_row("---"), "a horizontal rule has no pipe");
    assert!(
        !is_delimiter_row("- a | b"),
        "a list item that holds a pipe is not a row of dashes"
    );
    assert!(
        is_delimiter_row("|---|:--:|"),
        "colons mark alignment in a delimiter row"
    );
    assert!(
        is_delimiter_row("---|---"),
        "a delimiter row needs no outer pipes"
    );
    assert!(
        empty_header_cells("a | \n\n---\n").is_empty(),
        "a rule two lines below a line with a pipe makes no table"
    );
}

// -------------------------------------------------------------- headings

#[test]
fn no_page_skips_a_heading_level() -> Result<(), TestError> {
    let mut problems = Vec::new();
    for path in pages() {
        let text = std::fs::read_to_string(&path)?;
        let (body, above) = body_and_level(&text);
        let offset = text[..text.len() - body.len()].lines().count();
        for skip in heading_skips(body, above) {
            problems.push(format!(
                "{}:{}: h{} follows h{}",
                rel(&path),
                skip.line + offset,
                skip.to,
                skip.from
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{} heading(s) skip a level. A reader who moves by heading meets a \
         section with no parent, and the page's table of contents, built \
         from the second level, leaves it out:\n{}",
        problems.len(),
        problems.join("\n")
    );
    Ok(())
}

#[test]
fn a_third_level_heading_directly_under_the_title_is_reported() {
    let md = "# Title\n\ntext\n\n### Deep\n";
    assert_eq!(
        heading_skips(md, 0),
        [Skip {
            line: 5,
            from: 1,
            to: 3
        }],
        "the shape docs/prometheus-metrics.md had"
    );
}

#[test]
fn a_fourth_level_heading_under_a_second_is_reported() {
    let md = "# T\n## A\n#### B\n";
    assert_eq!(
        heading_skips(md, 0),
        [Skip {
            line: 3,
            from: 2,
            to: 4
        }],
        "a skip below the second level counts too"
    );
}

#[test]
fn a_file_that_opens_below_the_first_level_is_reported() {
    assert_eq!(
        heading_skips("## Starts here\n", 0),
        [Skip {
            line: 1,
            from: 0,
            to: 2
        }],
        "a file that supplies its own title starts at the first level"
    );
}

#[test]
fn headings_that_step_down_one_level_and_climb_any_number_pass() {
    let md = "# T\n## A\n### B\n#### C\n## D\n### E\n# F\n## G\n";
    assert!(
        heading_skips(md, 0).is_empty(),
        "closing several levels at once is not a skip"
    );
}

#[test]
fn a_site_page_starts_at_the_second_level() {
    assert!(
        heading_skips("## First\n### Second\n", 1).is_empty(),
        "the template writes the first level from the title"
    );
    assert_eq!(
        heading_skips("### First\n", 1),
        [Skip {
            line: 1,
            from: 1,
            to: 3
        }],
        "a site page that opens at the third level skips the second"
    );
}

#[test]
fn a_hash_inside_a_code_fence_is_not_a_heading() {
    let md = "# T\n\n```bash\n### not a heading\n# HELP sipnab_x\n```\n\n## Next\n";
    assert!(
        heading_skips(md, 0).is_empty(),
        "a shell comment or a Prometheus HELP line in a code block is not a \
         heading"
    );
}

#[test]
fn a_hash_without_a_space_and_seven_hashes_are_not_headings() {
    assert_eq!(heading_level("#main"), None, "a fragment, not a heading");
    assert_eq!(
        heading_level("####### seven"),
        None,
        "Markdown has six heading levels"
    );
    assert_eq!(heading_level("### three"), Some(3), "a third-level heading");
    assert_eq!(
        heading_level(" ## indented"),
        None,
        "the scan reads headings that start the line, as the docs write them"
    );
    assert_eq!(heading_level(""), None, "an empty line");
}

#[test]
fn front_matter_is_not_part_of_the_body() {
    let page = "+++\ntitle = \"T\"\n# not a heading\n+++\n\n## Body\n";
    let (body, above) = body_and_level(page);
    assert_eq!(
        above, 1,
        "a page with front matter gets its title from the template"
    );
    assert!(
        heading_skips(body, above).is_empty(),
        "a TOML comment in the front matter is not a heading"
    );
    assert_eq!(
        body_and_level("# Own title\n"),
        ("# Own title\n", 0),
        "a file without front matter supplies its own title"
    );
}

// ------------------------------------------------------------- templates

#[test]
fn the_navigation_button_says_whether_the_navigation_is_open() -> Result<(), TestError> {
    let tag = opening_tag(BASE, "nav-toggle").ok_or("base.html has no #nav-toggle")?;
    assert!(
        tag.contains("aria-expanded=\"false\""),
        "the button that opens the navigation on a narrow screen must start \
         with aria-expanded=\"false\": {tag}"
    );
    assert!(
        tag.contains("aria-controls=\"nav-links\""),
        "the navigation button must name the element it opens: {tag}"
    );
    assert!(
        opening_tag(BASE, "nav-links").is_some(),
        "aria-controls names #nav-links, which base.html no longer has"
    );
    Ok(())
}

#[test]
fn the_navigation_script_updates_the_open_state() -> Result<(), TestError> {
    let script = without_tera_comments(BASE);
    let at = script
        .find("getElementById('nav-toggle')")
        .ok_or("base.html no longer wires #nav-toggle")?;
    let end = script[at..]
        .find("// Docs dropdown")
        .ok_or("the block after the navigation toggle moved")?;
    let block = &script[at..at + end];
    assert!(
        block.contains("setAttribute('aria-expanded'"),
        "the click handler opens the navigation and never updates \
         aria-expanded, so the button always says closed:\n{block}"
    );
    Ok(())
}

#[test]
fn the_search_field_has_a_label() -> Result<(), TestError> {
    let tag = opening_tag(BASE, "search-input").ok_or("base.html has no #search-input")?;
    assert!(
        tag.contains("aria-label=\"Search documentation\""),
        "a placeholder is not a label: it disappears when the reader types. \
         Give the field aria-label: {tag}"
    );
    Ok(())
}

#[test]
fn the_pages_declare_their_one_dark_theme() {
    let head = without_tera_comments(BASE);
    assert!(
        head.contains("<meta name=\"color-scheme\" content=\"dark\">"),
        "the site has one dark theme. Without a color-scheme declaration a \
         browser draws scrollbars and form controls for a light page"
    );
}

#[test]
fn the_opening_tag_reader_finds_one_element() {
    let html = "<div><button class=\"a\" id=\"x\" aria-expanded=\"false\">t</button></div>";
    assert_eq!(
        opening_tag(html, "x"),
        Some("<button class=\"a\" id=\"x\" aria-expanded=\"false\">"),
        "the tag from its `<` to its `>`, attributes before and after the id"
    );
    assert_eq!(opening_tag(html, "missing"), None, "an id the page lacks");
    assert_eq!(
        opening_tag("id=\"x\"", "x"),
        None,
        "an id with no tag around it"
    );
}

#[test]
fn tera_comments_are_removed_and_an_open_one_ends_the_text() {
    assert_eq!(
        without_tera_comments("a{# b #}c{#- d -#}e"),
        "ace",
        "both comment forms, with and without the whitespace dash"
    );
    assert_eq!(
        without_tera_comments("a{# never closed"),
        "a",
        "an unclosed comment hides everything after it, as Tera reads it"
    );
    assert_eq!(without_tera_comments("plain"), "plain", "no comment at all");
}

// ----------------------------------------------------------- code blocks

#[test]
fn docs_and_notes_pages_load_the_one_copy_button_script() -> Result<(), TestError> {
    let script =
        std::fs::read_to_string(repo().join(CODE_COPY)).map_err(|e| format!("{CODE_COPY}: {e}"))?;
    assert!(
        script.contains(".doc-content pre:not(.mermaid)"),
        "{CODE_COPY} must give every code block of a docs or notes page a \
         button, and leave diagrams alone"
    );
    for (name, template) in [("page.html", PAGE), ("note.html", NOTE)] {
        let markup = without_tera_comments(template);
        assert!(
            markup.contains("get_url(path='js/code-copy.js', cachebust=true)"),
            "{name} does not load {CODE_COPY}. A code block that scrolls \
             sideways and holds nothing focusable cannot be reached from the \
             keyboard; the copy button is what makes it reachable"
        );
        assert!(
            !markup.contains("doc-copy-btn"),
            "{name} builds copy buttons inline again. One script builds \
             them, {CODE_COPY}, so the two templates cannot differ"
        );
    }
    Ok(())
}

#[test]
fn the_copy_button_script_names_its_button_for_a_screen_reader() -> Result<(), TestError> {
    let script =
        std::fs::read_to_string(repo().join(CODE_COPY)).map_err(|e| format!("{CODE_COPY}: {e}"))?;
    for needle in [
        "\"aria-label\", \"Copy code\"",
        "btn.type = \"button\"",
        "doc-copy-btn",
    ] {
        assert!(script.contains(needle), "{CODE_COPY} lost `{needle}`");
    }
    Ok(())
}

// ---------------------------------------------------------- label in name

/// The names of the diagram viewer's button variables whose face is a symbol.
const SYMBOL_BUTTONS: &[&str] = &[
    "grip", "zoomOut", "zoomIn", "resetBtn", "collapse", "reopen",
];

/// The symbol buttons that still carry their symbol as text content.
fn buttons_with_text(script: &str) -> Vec<&'static str> {
    SYMBOL_BUTTONS
        .iter()
        .copied()
        .filter(|name| script.contains(&format!("{name}.textContent =")))
        .collect()
}

/// The symbol buttons that draw no symbol at all.
fn buttons_without_symbol(script: &str) -> Vec<&'static str> {
    SYMBOL_BUTTONS
        .iter()
        .copied()
        .filter(|name| !script.contains(&format!("{name}.dataset.glyph =")))
        .collect()
}

#[test]
fn the_diagram_buttons_draw_their_symbol_outside_the_text() {
    assert_eq!(
        buttons_with_text(DIAGRAM_VIEWER),
        [] as [&str; 0],
        "these diagram buttons hold a symbol as text and a label in words. \
         The visible text is then not part of the name (WCAG 2.5.3). Set \
         `dataset.glyph`; the stylesheet draws it"
    );
    assert_eq!(
        buttons_without_symbol(DIAGRAM_VIEWER),
        [] as [&str; 0],
        "these diagram buttons have no `dataset.glyph`, so they draw nothing"
    );
    assert!(
        STYLE.contains("content: attr(data-glyph);"),
        "the stylesheet no longer draws `data-glyph`, so the diagram buttons \
         are blank"
    );
}

#[test]
fn every_diagram_button_keeps_a_label_in_words() {
    for label in [
        "Move diagram controls",
        "Zoom out",
        "Zoom in",
        "Reset zoom and position",
        "Hide diagram controls",
        "Show diagram controls",
    ] {
        assert!(
            DIAGRAM_VIEWER.contains(&format!("setAttribute(\"aria-label\", \"{label}\")")),
            "a diagram button lost its label \"{label}\"; a symbol alone \
             names nothing for a screen reader"
        );
    }
}

#[test]
fn the_symbol_button_readers_tell_text_from_a_glyph() {
    let old = "grip.textContent = \"x\";\nzoomIn.dataset.glyph = \"+\";";
    assert_eq!(
        buttons_with_text(old),
        ["grip"],
        "a button whose symbol is text content"
    );
    assert_eq!(
        buttons_without_symbol(old),
        ["grip", "zoomOut", "resetBtn", "collapse", "reopen"],
        "every button but the one that sets a glyph"
    );
    assert!(
        buttons_with_text("zoomLabel.textContent = \"100%\";").is_empty(),
        "the zoom readout is text, not a button"
    );
    assert!(
        buttons_with_text("var shown = grip.textContent;").is_empty(),
        "reading a button's text is not setting it"
    );
}

#[test]
fn the_drop_zone_is_named_by_the_text_it_shows() -> Result<(), TestError> {
    let tag = opening_tag(ANALYZE, "dropzone-box").ok_or("analyze.html has no #dropzone-box")?;
    assert!(
        tag.contains("aria-labelledby=\"dropzone-title dropzone-box\""),
        "the drop zone is a button that shows text. Its name must hold that \
         text (WCAG 2.5.3): the heading above it, then its own content: {tag}"
    );
    assert!(
        !tag.contains("aria-label="),
        "an aria-label replaces the visible text as the name: {tag}"
    );
    let title = opening_tag(ANALYZE, "dropzone-title").ok_or("no #dropzone-title")?;
    assert!(
        title.starts_with("<h2"),
        "#dropzone-title is the heading above the drop zone: {title}"
    );
    Ok(())
}
