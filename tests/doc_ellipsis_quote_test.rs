// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A message the documentation quotes is quoted in full.
//!
//! When a page quotes something sipnab or a peer prints (an error, a log
//! line, a refusal, a summary line, help text, command output), the quote is
//! the exact text, as `src/` produces it or as a recorded run shows it. An
//! ellipsis inside the quote (`No SIP signaling found, but ...`) misstates
//! what the tool says: a reader who searches a log for it finds nothing, and
//! a reader who wants to know what the message means learns half of it.
//!
//! This gate reads every line of the user-facing text and fails on any line
//! holding `...` or `…` that is not on [`ALLOWED`]. Each entry there names one
//! file and one exact line, with the reason the ellipsis is part of the text
//! rather than a gap in it: clap's notation for an argument that repeats, a
//! marker sipnab itself prints when it shortens a value, and the like.
//!
//! An entry matches one line. Two identical lines need two entries, so a
//! copied line is caught as well as a new one. An entry that matches no line
//! fails the gate too, so the list cannot keep a reason for text that has
//! gone.
//!
//! The files read are those the reader sees: `README.md`, `CONTRIBUTING.md`,
//! `SECURITY.md`, `CHANGELOG.md`, every `docs/**/*.md` except `docs/design/`
//! and `docs/research/` (internal notes), `man/sipnab.1`, the clap
//! definitions in `src/cli.rs` and `src/cli/` (the `--help` text), and every
//! file under `examples/`, and the site pages written by hand: every
//! `website/content/**/*.md` without the generator's banner and every
//! `website/templates/*.html`. The pages with the banner, and
//! `website/static/llms-full.txt`, are generated from `docs/` by
//! `scripts/build-site-pages.py` and `scripts/build-site-internals.py`, whose
//! drift checks hold them to their sources; they are not read again here.
//!
//! The root is read from `CARGO_MANIFEST_DIR` at run time rather than compile
//! time, so the built test can be pointed at another tree, such as the
//! commit before a fix, to show it red against the defect it exists for.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The ellipses that are part of the text. `(file, exact line, reason)`.
///
/// The line is the whole line as it stands in the file, without its line
/// break. Keep the list sorted by file, then by position in the file.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "CHANGELOG.md",
        r#"- **`--find-in-files <PATH>...` finds which capture files hold the dialogs the run's filter selects**: `--filter`, a diagnostic alias such as `--problems`, and `--since`/`--until`. A directory stands for the capture files directly in it. It prints each file with a match, the count and the first matching Call-ID, and every file it could not read, and says whether it read every file: it exits 0 when it did and 1 when it did not, and 2 with no filter. Under `--json` it prints the `sweep` the MCP `find_in_captures` tool reports, from the same sweep. See [Find the files that hold a call](docs/cli-reference.md#find-the-files-that-hold-a-call)."#,
        r#"clap's notation for a value that repeats, as `--help` prints `--find-in-files <PATH>...`"#,
    ),
    (
        "docs/cli-reference.md",
        r#"| `--find-in-files` | `<PATH>...` | | 0.5.231 | Find which capture files hold the dialogs the run's filter selects (`--filter`, a diagnostic alias, `--since`/`--until`). A directory stands for the capture files directly in it. Exits 0 when it read every file and 1 when it could not; with no filter it exits 2. `--json` prints the `sweep` the MCP tool `find_in_captures` reports |"#,
        r#"clap's notation for a value that repeats, as `--help` prints `--find-in-files <PATH>...`"#,
    ),
    (
        "man/sipnab.1",
        r#"\fB\-\-find\-in\-files\fR \fIPATH\fR\&..."#,
        r#"clap's notation for a value that repeats, as `--help` prints `--find-in-files <PATH>...`"#,
    ),
    (
        "CHANGELOG.md",
        r#"  - A line 3 wider than the terminal now ends in `…` instead of stopping at"#,
        r#"sipnab's own cut marker: a status line wider than the terminal ends in U+2026 (`fit_spans_to_cols` in src/tui/render/status.rs)"#,
    ),
    (
        "CHANGELOG.md",
        r#"  - `--vcon-fetch <UUID>...` reads each container from the store at `--vcon-fetch-url`."#,
        r#"clap's notation for a value that repeats, as `--help` prints `--vcon-fetch <UUID>...`"#,
    ),
    (
        "CHANGELOG.md",
        r#"- **`--fraud-destination <ISO,...>`: the fraud detector knows where a call is"#,
        r#"the clap value name `ISO,...`, a comma-separated list, as `--help` prints `--fraud-destination <ISO,...>`"#,
    ),
    (
        "CHANGELOG.md",
        r#"    ("Saving capture.pcap…" or "Decoding audio…") actually painted."#,
        r#"the TUI status texts sipnab prints, verbatim: `Saving {path}…` (src/tui/controllers/save_dialog.rs), `Decoding audio…` (src/tui/controllers/stream.rs) and `Loading {file}… {packets} packets` (src/tui/controllers/file_open.rs)"#,
    ),
    (
        "CHANGELOG.md",
        r#"  line such as "Loading capture.pcap… 50000 packets"."#,
        r#"the TUI status texts sipnab prints, verbatim: `Saving {path}…` (src/tui/controllers/save_dialog.rs), `Decoding audio…` (src/tui/controllers/stream.rs) and `Loading {file}… {packets} packets` (src/tui/controllers/file_open.rs)"#,
    ),
    (
        "CHANGELOG.md",
        r#"    "Saving capture.pcap…" or "Decoding audio…" status."#,
        r#"the TUI status texts sipnab prints, verbatim: `Saving {path}…` (src/tui/controllers/save_dialog.rs), `Decoding audio…` (src/tui/controllers/stream.rs) and `Loading {file}… {packets} packets` (src/tui/controllers/file_open.rs)"#,
    ),
    (
        "docs/asterisk-sipnab.md",
        r#"37e58306-c14d-4a0f-9fa1-41a...   sipp           -              Completed    200    9s         6      0.0s     -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "docs/cli-reference.md",
        r#"| `<BPF_FILTER>...` | positional | -- | 0.3.0 | BPF capture filter expression (trailing positional args), handed to libpcap as typed. Not the display filter (`--filter`). Replaces the filter sipnab would otherwise generate from `--portrange`. `--bpf-file` takes precedence, and either one replaces `[capture] bpf_filter`. The filter applies to `-I` capture files as well as live capture. When `[capture] bpf_filter` filters a file run, sipnab prints a warning naming the key, so a file whose calls fall outside the filter does not look empty. Unlike `sngrep` and `sipgrep`, sipnab takes no match expression here; match SIP text with `-e`. A filter typed here that does not compile says so, and sipnab refuses a lone argument that names an existing file, naming the `-I` it was missing. Config: `[capture] bpf_filter` |"#,
        r#"clap's notation for trailing positional arguments, as `--help` prints `[BPF_FILTER]...`"#,
    ),
    (
        "docs/cli-reference.md",
        r#"| `--fraud-destination` | `<ISO,...>` | off | 0.5.147 | Destination countries `--fraud-detect` reports an INVITE to, as ISO 3166-1 alpha-2 codes (`DO,VG,MA`). sipnab reads numbers through the common international prefixes (`+`, `00`, `011`) and resolves them by longest calling code, so `+1 809` is `DO`, not `US`; a number with no prefix is domestic and never matches. Every fraud finding also names the resolved destination. Absent: nothing changes. Config: `[security] fraud_destination` |"#,
        r#"the clap value name `ISO,...`, a comma-separated list, as `--help` prints `--fraud-destination <ISO,...>`"#,
    ),
    (
        "docs/cli-reference.md",
        r#"| `--vcon-fetch` | `<UUID>...` | -- | 0.5.209 | Read the container with each uuid from the store and write it to `<uuid>.vcon.json` in `--vcon-fetch-out`. `-` reads more uuids from standard input, one per line, and passes over blank lines and lines starting with `#`. The fetcher asks once for a uuid given twice. A uuid is 1 to 64 characters, each a letter, a digit or `-`. Exit `0` when the fetcher wrote every container and the schema accepts each, `1` when it wrote none for some uuid (`404`, another status, a size or shape refusal, a file that exists) or the schema refuses one, `2` when sipnab refuses the settings, `3` when the store answered `401` or `403`: the fetcher then asks for nothing more. Needs a URL and a credential, each from its flag or its `[vcon_fetch]` key; without one sipnab refuses the run with exit `2`, naming both |"#,
        r#"clap's notation for a value that repeats, as `--help` prints `--vcon-fetch <UUID>...`"#,
    ),
    (
        "docs/errors.md",
        r#"### `[theme] {key} = {v:?} is not a color: give a name (red, dark_gray, reset, ...) or #rrggbb`"#,
        r#"the message sipnab prints holds the ellipsis itself (the `[theme]` color check in src/config.rs)"#,
    ),
    (
        "docs/filter-dsl.md",
        r#"auth-fail-register-synth@20...   alice          alice          Failed       403    0s         4      -        -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "docs/filter-dsl.md",
        r#"auth-fail-subscribe-synth@2...   alice          alice          Terminated   403    0s         4      -        -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "docs/first-cli-triage.md",
        r#"From:       "Alice" <sip:alice@...>"#,
        r#"`--call-report` prints the From and To user with the host written as `...`; this is the line sipnab prints (src/output/call_report.rs)"#,
    ),
    (
        "docs/first-cli-triage.md",
        r#"To:         <sip:bob@...>"#,
        r#"`--call-report` prints the From and To user with the host written as `...`; this is the line sipnab prints (src/output/call_report.rs)"#,
    ),
    (
        "docs/install.md",
        r#"M2NhZDAwZmYwZGNkYmZjYzQzYmY...   10009          10009          Registered   200    0s         4      -        -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "docs/install.md",
        r#"6255692e34af33dd022daf7f531...   asterisk       10009          Completed    200    0s         2      -        -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "docs/internals/build-ci-release.md",
        r#"  - The gate runs the suite and prints `corpus: N test binaries against <dir> ... VALIDATED`."#,
        r#"the pre-push hook's own `printf` prints ` ... ` between the corpus directory and the verdict (.githooks/pre-push)"#,
    ),
    (
        "docs/internals/build-ci-release.md",
        r#"  - That happened, twice, with a `test <name> ... FAILED` line that no run of the real corpus had ever produced."#,
        r#"libtest prints each result as `test <name> ... FAILED`"#,
    ),
    (
        "docs/internals/mcp.md",
        r#"  line. It cuts an id over 64 characters and marks it `…(truncated)` (`CAP` in"#,
        r#"`…(truncated)` is the marker sipnab appends to an id over 64 characters (src/mcp/server.rs)"#,
    ),
    (
        "docs/internals/postmortems.md",
        r#"256 bytes ([`src/mcp/shape.rs`](../../src/mcp/shape.rs)). A capped value ends with `…[truncated]`, and"#,
        r#"`…[truncated]` is the marker the MCP shaper appends to a capped field (src/mcp/shape.rs)"#,
    ),
    (
        "docs/keybindings.md",
        r#"  - A line wider than the terminal ends in `…`."#,
        r#"sipnab's own cut marker: a status line wider than the terminal ends in U+2026 (`fit_spans_to_cols` in src/tui/render/status.rs)"#,
    ),
    (
        "docs/mcp-protocol.md",
        r#"  `…(truncated)`."#,
        r#"`…(truncated)` is the marker sipnab appends to an id over 64 characters (src/mcp/server.rs)"#,
    ),
    (
        "docs/mcp-protocol.md",
        r#"**A field caps at 256 bytes**, marked `…[truncated]` when the cap fires. No"#,
        r#"`…[truncated]` is the marker the MCP shaper appends to a capped field (src/mcp/shape.rs)"#,
    ),
    (
        "docs/mcp-tools-signaling.md",
        r#"      "expected": "branch=z9hG4bK...","#,
        r#"the lint rule's expected value is literally `branch=z9hG4bK...` (src/sip/lint/message.rs)"#,
    ),
    (
        "docs/real-world-captures.md",
        r#"From:       <sip:redacted-user@...>"#,
        r#"`--call-report` prints the From and To user with the host written as `...`; this is the line sipnab prints (src/output/call_report.rs)"#,
    ),
    (
        "docs/sip-lint-rules.md",
        r#"warning: SIP-3261-8.1.1.7-BRANCH-COOKIE [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] §8.1.1.7 makes every compliant branch begin with z9hG4bK, so its absence identifies a stack predating RFC 3261 in one field. Transaction matching then falls back to the RFC 2543 rules, and CANCEL and ACK correlation stop being reliable. (RFC 3261 §8.1.1.7) observed=top Via branch without the z9hG4bK prefix expected=branch=z9hG4bK..."#,
        r#"the lint rule's expected value is literally `branch=z9hG4bK...` (src/sip/lint/message.rs)"#,
    ),
    (
        "docs/sip-lint-rules.md",
        r#"warning: SIP-3261-8.1.1.7-BRANCH-COOKIE [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] §8.1.1.7 makes every compliant branch begin with z9hG4bK, so its absence identifies a stack predating RFC 3261 in one field. Transaction matching then falls back to the RFC 2543 rules, and CANCEL and ACK correlation stop being reliable. (RFC 3261 §8.1.1.7) observed=top Via branch without the z9hG4bK prefix expected=branch=z9hG4bK..."#,
        r#"the lint rule's expected value is literally `branch=z9hG4bK...` (src/sip/lint/message.rs)"#,
    ),
    (
        "docs/sip-lint-rules.md",
        r#"warning: SIP-3261-8.1.1.7-BRANCH-COOKIE [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] §8.1.1.7 makes every compliant branch begin with z9hG4bK, so its absence identifies a stack predating RFC 3261 in one field. Transaction matching then falls back to the RFC 2543 rules, and CANCEL and ACK correlation stop being reliable. (RFC 3261 §8.1.1.7) observed=top Via branch without the z9hG4bK prefix expected=branch=z9hG4bK..."#,
        r#"the lint rule's expected value is literally `branch=z9hG4bK...` (src/sip/lint/message.rs)"#,
    ),
    (
        "docs/theme-guide.md",
        r#"invalid config value: [theme] background = "bogus" is not a color: give a name (red, dark_gray, reset, ...) or #rrggbb"#,
        r#"the message sipnab prints holds the ellipsis itself (the `[theme]` color check in src/config.rs)"#,
    ),
    (
        "man/sipnab.1",
        r#"\fB\-\-fraud\-destination\fR \fIISO,...\fR"#,
        r#"the clap value name `ISO,...`, a comma-separated list, as `--help` prints `--fraud-destination <ISO,...>`"#,
    ),
    (
        "man/sipnab.1",
        r#"\fB\-\-vcon\-fetch\fR \fIUUID\fR\&..."#,
        r#"clap's notation for a value that repeats, as `--help` prints `--vcon-fetch <UUID>...`"#,
    ),
    (
        "src/cli.rs",
        r#"        value_name = "ISO,...""#,
        r#"the clap value name `ISO,...`, a comma-separated list, as `--help` prints `--fraud-destination <ISO,...>`"#,
    ),
    (
        "website/content/docs/api-clients.md",
        r#"    all.push(...page.dialogs);"#,
        r#"JavaScript spread syntax in a code sample"#,
    ),
    (
        "website/content/docs/api-clients.md",
        r#"		all = append(all, page.Dialogs...)"#,
        r#"Go's syntax for passing a slice to a variadic function, in a code sample"#,
    ),
    (
        "website/content/notes/a-finding-is-a-floor-not-a-verdict.md",
        r#"00000000  02 00 00 00 00 01 02 00  00 00 00 02 08 00 45 00  |..............E.|"#,
        r#"the ASCII column of a hex dump prints each byte that is not printable as a full stop"#,
    ),
    (
        "website/content/notes/a-finding-is-a-floor-not-a-verdict.md",
        r#"00000010  02 0e 00 00 40 00 40 11  b4 98 c0 00 02 1e c0 00  |....@.@.........|"#,
        r#"the ASCII column of a hex dump prints each byte that is not printable as a full stop"#,
    ),
    (
        "website/content/notes/a-finding-is-a-floor-not-a-verdict.md",
        r#"00000020  02 28 13 c4 13 c4 01 fa  00 00 49 4e 56 49 54 45  |.(........INVITE|"#,
        r#"the ASCII column of a hex dump prints each byte that is not printable as a full stop"#,
    ),
    (
        "website/content/notes/a-finding-is-a-floor-not-a-verdict.md",
        r#"00000160  6e 67 74 68 3a 20 31 36  36 0d 0a 0d 0a 76 3d 30  |ngth: 166....v=0|"#,
        r#"the ASCII column of a hex dump prints each byte that is not printable as a full stop"#,
    ),
    (
        "website/content/notes/one-filter-language-every-door.md",
        r#"options-ping-a-synth@192.16...   keepalive      keepalive      Completed    200    0s         2      -        -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "website/content/notes/one-filter-language-every-door.md",
        r#"options-ping-b-synth@192.16...   keepalive      keepalive      Completed    200    0s         2      -        -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "website/content/notes/one-filter-language-every-door.md",
        r#"options-ping-c-synth@198.51...   ping           probe          Completed    200    0s         2      -        -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "website/content/notes/rule-out-the-relay-before-the-nat.md",
        r#"stun-sdp-mismatch-1@192.168...   alice          bob            Completed    200    7s         7      0.2s     -"#,
        r#"the dialog table cuts a Call-ID longer than its 32-column cell and ends it with `...`; this is the row sipnab prints (`truncate_str` in src/output/dialog_report.rs)"#,
    ),
    (
        "website/content/notes/three-surfaces-and-three-different-calls.md",
        r#"From:       "Alice" <sip:alice@...>"#,
        r#"`--call-report` prints the From and To user with the host written as `...`; this is the line sipnab prints (src/output/call_report.rs)"#,
    ),
    (
        "website/content/notes/three-surfaces-and-three-different-calls.md",
        r#"To:         <sip:bob@...>"#,
        r#"`--call-report` prints the From and To user with the host written as `...`; this is the line sipnab prints (src/output/call_report.rs)"#,
    ),
    (
        "website/templates/base.html",
        r#"        bodySpan.textContent = (doc.body || '').substring(0, 150) + '...';"#,
        r#"site search code that marks a shortened page preview with `...`; it quotes nothing"#,
    ),
];

/// The banner `scripts/build-site-pages.py` and
/// `scripts/build-site-internals.py` put on every page they write.
const GENERATED_BANNER: &str = "Generated by scripts/build-site-";

/// Whether a line holds an ellipsis: three full stops in a row, or U+2026.
fn has_ellipsis(line: &str) -> bool {
    line.contains("...") || line.contains('\u{2026}')
}

type TestError = Box<dyn std::error::Error>;

/// `p` relative to `root`, with `/` separators.
fn relative(root: &Path, p: &Path) -> Result<String, TestError> {
    Ok(p.strip_prefix(root)?.to_string_lossy().replace('\\', "/"))
}

/// Every file the gate reads, relative to `root`, with `/` separators,
/// sorted.
fn documents(root: &Path) -> Result<Vec<String>, TestError> {
    let mut out: Vec<String> = [
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "README.md",
        "SECURITY.md",
        "man/sipnab.1",
        "src/cli.rs",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (dir, ext) in [
        ("docs", Some("md")),
        ("src/cli", Some("rs")),
        ("examples", None),
    ] {
        for p in walk(&root.join(dir))? {
            let rel = relative(root, &p)?;
            if rel.starts_with("docs/design/") || rel.starts_with("docs/research/") {
                continue;
            }
            if let Some(ext) = ext
                && p.extension().and_then(|e| e.to_str()) != Some(ext)
            {
                continue;
            }
            out.push(rel);
        }
    }
    // The site pages written by hand. A page carrying the generator's banner
    // is a copy of a `docs/` page, read there.
    for (dir, ext) in [("website/content", "md"), ("website/templates", "html")] {
        for p in walk(&root.join(dir))? {
            if p.extension().and_then(|e| e.to_str()) != Some(ext) {
                continue;
            }
            if std::fs::read_to_string(&p)?.contains(GENERATED_BANNER) {
                continue;
            }
            out.push(relative(root, &p)?);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Every file under `dir`, at any depth.
fn walk(dir: &Path) -> Result<Vec<PathBuf>, TestError> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| format!("read_dir {}: {e}", d.display()))? {
            let p = e?.path();
            if p.is_dir() {
                todo.push(p);
            } else {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// `(file, 1-based line number, line)` for every line with an ellipsis.
fn ellipsis_lines(file: &str, text: &str) -> Vec<(String, usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| has_ellipsis(l))
        .map(|(i, l)| (file.to_string(), i + 1, l.to_string()))
        .collect()
}

/// The lines no entry allows, and the entries no line used.
///
/// Each entry is used by at most one line: the first line, in file order,
/// with its exact text.
fn judge(
    found: &[(String, usize, String)],
    allowed: &[(&str, &str, &str)],
) -> (Vec<String>, Vec<String>) {
    let mut unused: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (f, l, _) in allowed {
        *unused.entry((f, l)).or_default() += 1;
    }
    let mut bad = Vec::new();
    for (file, n, line) in found {
        match unused.get_mut(&(file.as_str(), line.as_str())) {
            Some(left) if *left > 0 => *left -= 1,
            _ => bad.push(format!("{file}:{n}: {line}")),
        }
    }
    let stale = unused
        .into_iter()
        .filter(|(_, left)| *left > 0)
        .map(|((f, l), left)| format!("{f} ({left} unmatched): {l}"))
        .collect();
    (bad, stale)
}

fn root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

fn scan(root: &Path) -> Result<Vec<(String, usize, String)>, TestError> {
    let mut found = Vec::new();
    for file in documents(root)? {
        let text =
            std::fs::read_to_string(root.join(&file)).map_err(|e| format!("read {file}: {e}"))?;
        found.extend(ellipsis_lines(&file, &text));
    }
    Ok(found)
}

#[test]
fn no_user_facing_line_holds_an_unlisted_ellipsis() -> Result<(), TestError> {
    let (bad, _) = judge(&scan(&root())?, ALLOWED);
    assert!(
        bad.is_empty(),
        "{} line(s) in user-facing text hold an ellipsis. Never shorten a \
         quoted message: quote the full text from src/ or from a recorded run, \
         or restructure so the page does not quote it. Rewrite a prose \
         ellipsis as a complete sentence. Only if the ellipsis is part of the \
         text itself (clap's repeat notation, a marker sipnab prints) add the \
         exact line to ALLOWED in tests/doc_ellipsis_quote_test.rs with the \
         reason:\n{}",
        bad.len(),
        bad.join("\n")
    );
    Ok(())
}

#[test]
fn every_allowlist_entry_still_matches_a_line() -> Result<(), TestError> {
    let (_, stale) = judge(&scan(&root())?, ALLOWED);
    assert!(
        stale.is_empty(),
        "ALLOWED entries in tests/doc_ellipsis_quote_test.rs that match no \
         line any more; delete them:\n{}",
        stale.join("\n")
    );
    Ok(())
}

#[test]
fn every_allowlist_entry_gives_a_reason_and_holds_an_ellipsis() {
    for (f, l, why) in ALLOWED {
        assert!(!why.trim().is_empty(), "{f}: {l}: no reason given");
        assert!(has_ellipsis(l), "{f}: {l}: holds no ellipsis to allow");
    }
}

#[test]
fn the_gate_reads_every_kind_of_file_it_names() -> Result<(), TestError> {
    let docs = documents(&root())?;
    for want in [
        "CHANGELOG.md",
        "README.md",
        "man/sipnab.1",
        "src/cli.rs",
        "docs/cli-reference.md",
        "docs/internals/README.md",
        "website/content/docs/benchmarks.md",
        "website/templates/base.html",
    ] {
        assert!(docs.iter().any(|d| d == want), "{want} is not read");
    }
    assert!(
        docs.iter().any(|d| d.starts_with("src/cli/")),
        "src/cli/ is not read"
    );
    assert!(
        docs.iter().any(|d| d.starts_with("examples/")),
        "examples/ is not read"
    );
    assert!(
        !docs
            .iter()
            .any(|d| d.starts_with("docs/design/") || d.starts_with("docs/research/")),
        "internal notes are read"
    );
    assert!(
        !docs.iter().any(|d| d == "website/content/docs/vcon.md"),
        "a generated site page is read beside its source"
    );
    Ok(())
}

#[test]
fn an_entry_allows_one_line_and_a_copy_is_caught() {
    let found = ellipsis_lines("a.md", "x\n`<UUID>...`\nplain\n`<UUID>...`\nsays `but …`\n");
    assert_eq!(
        found.iter().map(|(_, n, _)| *n).collect::<Vec<_>>(),
        vec![2, 4, 5],
        "both spellings are found, and only on their own lines"
    );
    let (bad, stale) = judge(&found, &[("a.md", "`<UUID>...`", "notation")]);
    assert_eq!(bad, vec!["a.md:4: `<UUID>...`", "a.md:5: says `but …`"]);
    assert!(stale.is_empty());
    let (bad, stale) = judge(
        &found[..1],
        &[
            ("a.md", "`<UUID>...`", "notation"),
            ("a.md", "gone ...", "was here"),
        ],
    );
    assert!(bad.is_empty());
    assert_eq!(stale, vec!["a.md (1 unmatched): gone ..."]);
    let (_, stale) = judge(&found[..1], &[("b.md", "`<UUID>...`", "other file")]);
    assert_eq!(stale.len(), 1, "an entry is bound to its file");
}
