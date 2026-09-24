// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every Go, JavaScript, Python and TypeScript snippet in the REST, metrics
//! and MCP deployment references is cut from a program CI compiles and runs.
//!
//! The references showed the same request in several languages, and nothing
//! compiled any of them. The Go ones were fragments that discarded every
//! error with `_`, so an operator who pasted one got a program that printed a
//! zero value when the token was wrong. A snippet nobody compiles is a claim,
//! not an example.
//!
//! Each such fence is now preceded by a marker naming its source,
//!
//! ```text
//! <!-- snippet: clients/go/health/main.go#health -->
//! ```
//!
//! and that file holds the fence's text between `snippet:start health` and
//! `snippet:end health` comment lines. The fence must equal the region byte
//! for byte once both lose their common indentation. `.github/workflows/ci.yml`
//! formats, vets, builds and type-checks those programs and runs every one of
//! them against a sipnab serving a committed capture, so the text a reader
//! copies is text that ran.
//!
//! When a fence and its region disagree, the failure prints the region: the
//! program is the side CI runs, so the fix is to paste that into the page.

#[path = "support/markdown.rs"]
mod markdown;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The pages whose client snippets are held to their programs.
const DOCS: &[&str] = &[
    "docs/rest-api.md",
    "docs/prometheus-metrics.md",
    "docs/mcp-deploy.md",
];

/// Fence labels that mean a client language. The short aliases are here so a
/// fence cannot escape the gate by being relabeled `js` or `py`.
const CLIENT_LANGS: &[&str] = &[
    "go",
    "golang",
    "javascript",
    "js",
    "mjs",
    "node",
    "python",
    "py",
    "python3",
    "typescript",
    "ts",
];

/// The directories whose programs carry regions.
const CLIENT_TREES: &[&str] = &[
    "clients/go",
    "clients/javascript",
    "clients/python",
    "clients/typescript",
];

const MARKER_OPEN: &str = "<!-- snippet: ";
const MARKER_CLOSE: &str = " -->";

fn read(rel: &str) -> String {
    std::fs::read_to_string(markdown::repo_root().join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// One client-language fence, with the marker line that precedes it.
#[derive(Debug)]
struct ClientFence {
    doc: &'static str,
    line: usize,
    lang: String,
    body: String,
    /// `(file, region)` from the marker directly above the fence.
    source: Option<(String, String)>,
}

/// Parse a marker line: `<!-- snippet: path#region -->`.
fn parse_marker(line: &str) -> Option<(String, String)> {
    let inner = line
        .trim()
        .strip_prefix(MARKER_OPEN)?
        .strip_suffix(MARKER_CLOSE)?;
    let (file, region) = inner.trim().split_once('#')?;
    Some((file.trim().to_string(), region.trim().to_string()))
}

/// Every client-language fence in `text`, with its marker if it has one.
fn client_fences(doc: &'static str, text: &str) -> Vec<ClientFence> {
    let lines: Vec<&str> = text.lines().collect();
    markdown::fences(text)
        .into_iter()
        .filter(|f| CLIENT_LANGS.contains(&f.lang.as_str()))
        .map(|f| ClientFence {
            doc,
            line: f.line,
            lang: f.lang.clone(),
            body: dedent(&f.body),
            // `line` is 1-based, so the line above the fence is `line - 2`.
            source: f
                .line
                .checked_sub(2)
                .and_then(|i| lines.get(i))
                .and_then(|l| parse_marker(l)),
        })
        .collect()
}

/// A marker line: where it is, what it names, and what it sits above.
struct Marker {
    /// 1-based line number.
    line: usize,
    /// `(file, region)`, or `None` when the line is not a well-formed marker.
    source: Option<(String, String)>,
    /// The label of the fence that opens on the next line, if one does.
    next_fence: Option<String>,
}

/// Every marker line in `text`, well-formed or not.
fn markers(text: &str) -> Vec<Marker> {
    let opens: BTreeMap<usize, String> = markdown::fences(text)
        .into_iter()
        .map(|f| (f.line, f.lang))
        .collect();
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.trim_start().starts_with(MARKER_OPEN.trim_end()))
        .map(|(i, l)| Marker {
            line: i + 1,
            source: parse_marker(l),
            next_fence: opens.get(&(i + 2)).cloned(),
        })
        .collect()
}

/// Remove the leading whitespace every non-blank line shares. Blank lines
/// become empty. Each line keeps a trailing newline, as fence bodies do.
fn dedent(text: &str) -> String {
    let prefix = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| &l[..l.len() - l.trim_start().len()])
        .reduce(|a, b| {
            let n = a
                .chars()
                .zip(b.chars())
                .take_while(|(x, y)| x == y)
                .map(|(x, _)| x.len_utf8())
                .sum();
            &a[..n]
        })
        .unwrap_or("");
    text.lines()
        .map(|l| {
            if l.trim().is_empty() {
                "\n".to_string()
            } else {
                format!("{}\n", &l[prefix.len()..])
            }
        })
        .collect()
}

/// The directive a line carries, if it is a `//` or `#` comment holding one:
/// `("start", name)` or `("end", name)`.
fn directive(line: &str) -> Option<(&str, &str)> {
    let t = line.trim();
    let comment = t.strip_prefix("//").or_else(|| t.strip_prefix('#'))?.trim();
    let rest = comment.strip_prefix("snippet:")?;
    let (kind, name) = rest.split_once(' ')?;
    matches!(kind, "start" | "end").then_some((kind, name.trim()))
}

/// The dedented text of region `name` in `source`, or why there is none.
fn region(source: &str, name: &str) -> Result<String, String> {
    let lines: Vec<&str> = source.lines().collect();
    let find = |kind: &str| -> Vec<usize> {
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| directive(l) == Some((kind, name)))
            .map(|(i, _)| i)
            .collect()
    };
    let (starts, ends) = (find("start"), find("end"));
    match (starts.as_slice(), ends.as_slice()) {
        ([], _) => Err(format!("no `snippet:start {name}` line")),
        (_, []) => Err(format!("no `snippet:end {name}` line")),
        ([s], [e]) if s < e => {
            let body: String = lines[s + 1..*e].iter().map(|l| format!("{l}\n")).collect();
            if lines[s + 1..*e].iter().any(|l| directive(l).is_some()) {
                return Err(format!("region {name} contains another snippet directive"));
            }
            Ok(dedent(&body))
        }
        ([_], [_]) => Err(format!("`snippet:end {name}` comes before its start")),
        _ => Err(format!(
            "region {name} is declared {} time(s) and closed {} time(s); it must be exactly once",
            starts.len(),
            ends.len()
        )),
    }
}

/// Every region name declared in the client trees, as `(file, region)`.
fn declared_regions() -> BTreeSet<(String, String)> {
    let root = markdown::repo_root();
    let mut out = BTreeSet::new();
    for tree in CLIENT_TREES {
        walk(&root.join(tree), &mut |path| {
            let Ok(text) = std::fs::read_to_string(path) else {
                return;
            };
            let rel = path
                .strip_prefix(root)
                .expect("walk stays under the root")
                .to_string_lossy()
                .replace('\\', "/");
            for line in text.lines() {
                if let Some(("start", name)) = directive(line) {
                    out.insert((rel.clone(), name.to_string()));
                }
            }
        });
    }
    out
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        // Installed dependencies and caches are not ours to hold to a doc.
        if matches!(
            name.to_str(),
            Some("node_modules" | "__pycache__" | ".venv" | "dist")
        ) {
            continue;
        }
        if path.is_dir() {
            walk(&path, f);
        } else {
            f(&path);
        }
    }
}

fn all_client_fences() -> Vec<ClientFence> {
    DOCS.iter()
        .flat_map(|doc| client_fences(doc, &read(doc)))
        .collect()
}

// ── the gates ─────────────────────────────────────────────────────────────

/// A client fence with no marker is text nothing compiles.
#[test]
fn every_client_fence_names_the_program_it_is_cut_from() {
    let unmarked: Vec<String> = all_client_fences()
        .iter()
        .filter(|f| f.source.is_none())
        .map(|f| format!("  {}:{} ```{}", f.doc, f.line, f.lang))
        .collect();
    assert!(
        unmarked.is_empty(),
        "{} client snippet(s) have no `{MARKER_OPEN}clients/<lang>/<file>#<region>{MARKER_CLOSE}` \
         line directly above the fence, so no compiler ever sees them. Move each into a program \
         under clients/<lang>/, mark the part the page shows with `snippet:start <region>` / \
         `snippet:end <region>` comments, and name it above the fence:\n{}",
        unmarked.len(),
        unmarked.join("\n")
    );
}

/// The fence is the region, byte for byte after dedent.
#[test]
fn every_client_fence_is_its_program_region_byte_for_byte() {
    let mut drift = Vec::new();
    for f in all_client_fences() {
        let Some((file, name)) = &f.source else {
            continue;
        };
        let Ok(source) = std::fs::read_to_string(markdown::repo_root().join(file)) else {
            continue; // every_snippet_marker_resolves_to_one_region reports it
        };
        let Ok(expected) = region(&source, name) else {
            continue;
        };
        if f.body != expected {
            let first = f
                .body
                .lines()
                .zip(expected.lines())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| f.body.lines().count().min(expected.lines().count()));
            drift.push(format!(
                "  {}:{} differs from {file}#{name} at fence body line {}.\n  \
                 The program is what CI runs; replace the fence body with:\n{}",
                f.doc,
                f.line,
                first + 1,
                expected
            ));
        }
    }
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

/// A marker that names a missing file or region, or that sits above no
/// client fence, points a reader at nothing.
#[test]
fn every_snippet_marker_resolves_to_one_region() {
    let mut bad = Vec::new();
    for doc in DOCS {
        for Marker {
            line,
            source: parsed,
            next_fence: next,
        } in markers(&read(doc))
        {
            let Some((file, name)) = parsed else {
                bad.push(format!(
                    "  {doc}:{line}: not `{MARKER_OPEN}<file>#<region>{MARKER_CLOSE}`"
                ));
                continue;
            };
            match next {
                Some(lang) if CLIENT_LANGS.contains(&lang.as_str()) => {}
                other => bad.push(format!(
                    "  {doc}:{line}: marker for {file}#{name} is not directly above a client \
                     fence (next line opens {other:?})"
                )),
            }
            if !CLIENT_TREES
                .iter()
                .any(|t| file.starts_with(&format!("{t}/")))
            {
                bad.push(format!(
                    "  {doc}:{line}: {file} is outside {CLIENT_TREES:?}, where CI builds clients"
                ));
            }
            match std::fs::read_to_string(markdown::repo_root().join(&file)) {
                Err(e) => bad.push(format!("  {doc}:{line}: {file}: {e}")),
                Ok(source) => {
                    if let Err(why) = region(&source, &name) {
                        bad.push(format!("  {doc}:{line}: {file}: {why}"));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// A region no page shows is a program the pages have stopped describing, or a
/// marker typo that left the fence pointing elsewhere.
#[test]
fn every_client_region_is_shown_on_a_page() {
    let shown: BTreeSet<(String, String)> = all_client_fences()
        .into_iter()
        .filter_map(|f| f.source)
        .collect();
    let declared = declared_regions();
    let orphans: Vec<String> = declared
        .difference(&shown)
        .map(|(f, r)| format!("  {f}#{r}"))
        .collect();
    assert!(
        orphans.is_empty(),
        "these regions are declared in clients/ but no page in {DOCS:?} shows them:\n{}",
        orphans.join("\n")
    );
}

/// The inventory measured when the gate was written. If the reader stopped
/// seeing fences, every gate above would pass on nothing; a count that moves
/// must be moved here on purpose.
#[test]
fn the_reader_sees_every_client_fence_the_pages_hold() {
    let mut counts: BTreeMap<(&str, String), usize> = BTreeMap::new();
    for f in all_client_fences() {
        *counts.entry((f.doc, f.lang)).or_default() += 1;
    }
    let expected: BTreeMap<(&str, String), usize> = [
        ("docs/rest-api.md", "go", 7),
        ("docs/rest-api.md", "javascript", 7),
        ("docs/rest-api.md", "python", 7),
        ("docs/prometheus-metrics.md", "go", 1),
        ("docs/prometheus-metrics.md", "javascript", 1),
        ("docs/prometheus-metrics.md", "python", 1),
        ("docs/mcp-deploy.md", "python", 2),
        ("docs/mcp-deploy.md", "typescript", 1),
    ]
    .into_iter()
    .map(|(d, l, n)| ((d, l.to_string()), n))
    .collect();
    assert_eq!(counts, expected);
}

/// The bar each language is held to lives in CI. These are the commands that
/// make the programs load-bearing; losing one turns its language back into
/// claims.
#[test]
fn ci_holds_every_client_language_to_its_bar() {
    let ci = read(".github/workflows/ci.yml");
    let missing: Vec<&str> = [
        "gofmt -l .",
        "go vet ./...",
        "go build ./...",
        "node --check",
        "python3 -m compileall -q clients/python",
        "npx --no-install tsc --noEmit",
        "scripts/smoke-clients.sh",
    ]
    .into_iter()
    .filter(|cmd| !ci.contains(cmd))
    .collect();
    assert!(
        missing.is_empty(),
        ".github/workflows/ci.yml no longer runs: {missing:?}"
    );
}

// ── the reader itself ─────────────────────────────────────────────────────

#[test]
fn the_region_reader_finds_regions_under_either_comment_style() {
    let go = "func run() error {\n\t// snippet:start a\n\tx := 1\n\n\tif x > 0 {\n\t\treturn nil\n\t}\n\t// snippet:end a\n\treturn nil\n}\n";
    assert_eq!(
        region(go, "a").unwrap(),
        "x := 1\n\nif x > 0 {\n\treturn nil\n}\n"
    );
    let py = "def f():\n    # snippet:start b\n    return 1\n    # snippet:end b\n";
    assert_eq!(region(py, "b").unwrap(), "return 1\n");
}

#[test]
fn the_region_reader_refuses_missing_duplicate_and_inverted_regions() {
    assert!(
        region("x\n", "a")
            .unwrap_err()
            .contains("no `snippet:start a`")
    );
    assert!(
        region("# snippet:start a\n", "a")
            .unwrap_err()
            .contains("no `snippet:end a`")
    );
    assert!(
        region("# snippet:end a\n# snippet:start a\n", "a")
            .unwrap_err()
            .contains("before its start")
    );
    assert!(
        region(
            "# snippet:start a\n# snippet:end a\n# snippet:start a\n# snippet:end a\n",
            "a"
        )
        .unwrap_err()
        .contains("exactly once")
    );
    // A name is matched whole: region `a` is not region `ab`.
    assert!(region("# snippet:start ab\n# snippet:end ab\n", "a").is_err());
}

#[test]
fn the_fence_reader_takes_the_marker_directly_above_only() {
    let doc = "<!-- snippet: clients/go/x/main.go#x -->\n```go\nx\n```\n\n\
               <!-- snippet: clients/go/y/main.go#y -->\n\n```go\ny\n```\n";
    let fences = client_fences("t.md", doc);
    assert_eq!(fences.len(), 2);
    assert_eq!(
        fences[0].source,
        Some(("clients/go/x/main.go".into(), "x".into()))
    );
    // A blank line between marker and fence detaches them.
    assert_eq!(fences[1].source, None);
    let m = markers(doc);
    assert_eq!(m[0].next_fence.as_deref(), Some("go"));
    assert_eq!(m[1].next_fence, None);
}

#[test]
fn dedent_strips_only_the_shared_prefix() {
    assert_eq!(dedent("    a\n      b\n\n    c\n"), "a\n  b\n\nc\n");
    assert_eq!(dedent("\ta\n\t\tb\n"), "a\n\tb\n");
    // Mixed tabs and spaces share no prefix, so nothing is removed.
    assert_eq!(dedent("\ta\n  b\n"), "\ta\n  b\n");
}
