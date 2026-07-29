// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drift guards for the developer documentation under `docs/internals/`.
//!
//! These pages cite code by path and symbol. Unguarded, they rot silently
//! into the next refactor: a moved file or a renamed function leaves prose
//! that reads authoritatively and is wrong. The project already gates the
//! user-facing docs this way (`docs_drift_test`, `link_integrity_test`);
//! this is the same contract for the developer tree.
//!
//! Conventions enforced here (see
//! `docs/superpowers/specs/2026-07-25-developer-documentation-design.md`):
//!
//! 1. cited repo paths exist,
//! 2. symbols named in link text — `()`-suffixed — resolve to a definition,
//! 3. every page is registered for wiki publication,
//! 4. every mermaid fence is a `sequenceDiagram`,
//! 5. no markdown-link syntax inside a mermaid fence (`build-wiki.py`
//!    rewrites links with no fence awareness),
//! 6. every mermaid fence is preceded by prose, so the page reads where
//!    mermaid does not render,
//! 7. every page is published to the website, and the committed site mirror
//!    under `website/content/docs/internals/` is byte-identical to what
//!    `scripts/build-site-internals.py` produces today,
//! 8. every mirrored page carrying a diagram declares `has_diagrams`, and the
//!    page template loads the mermaid bundle on exactly that flag.

use std::path::{Path, PathBuf};

#[path = "support/markdown.rs"]
mod markdown;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: impl AsRef<Path>) -> String {
    let p = repo().join(rel.as_ref());
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `.md` under `docs/internals/`, recursively, as repo-relative paths.
///
/// This walk feeds eight gates — code links resolve, named symbols exist, the
/// page is registered for the wiki and for the site, and the mermaid
/// conventions hold. It used to read only the top level, which made the
/// directory depth a proxy for "is a developer page": the first
/// `docs/internals/rtp/pipeline.md` would have been published nowhere, with
/// unresolvable code links and arbitrary mermaid, while
/// `every_internals_page_is_registered_for_the_wiki` reported that every page
/// was registered. Demonstrated: such a page with three separate hard
/// failures passed 59 tests.
fn internals_pages() -> Vec<PathBuf> {
    let dir = repo().join("docs/internals");
    let mut out = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", d.display()))
            .flatten()
        {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(p.strip_prefix(repo()).expect("under repo").to_path_buf());
            }
        }
    }
    assert!(
        !out.is_empty(),
        "no markdown found under docs/internals/ — the walk is reading nothing \
         and every gate built on it passes vacuously"
    );
    out.sort();
    out
}

/// Every markdown link on a page as `(link_text, target)`.
fn links(text: &str) -> Vec<(String, String)> {
    let re = regex::Regex::new(r"\[([^\]]*)\]\(([^)\s]+)\)").expect("link regex");
    re.captures_iter(text)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect()
}

/// Links that point into the code rather than at another document. Anchored
/// on the repository's actual top-level trees so an ordinary
/// `../fault-model.md` doc link and an external URL are both excluded.
///
/// The tree list is derived from `git ls-files`, not typed out here. The typed
/// version listed thirteen names and disk had nineteen: `bench`, `packaging`,
/// `docker` and `website` were missing, so a link into any of them was not
/// classified as a code link at all and its existence was never checked. A
/// citation to `../../bench/scaling-DELETED.sh` passed every suite and shipped
/// to the live site. `generators_agree_on_the_code_tree_set` keeps the three
/// generators' copies of the same list from drifting away from it again.
fn code_links(text: &str) -> Vec<(String, String)> {
    links(text)
        .into_iter()
        .filter(|(_, target)| {
            if target.ends_with(".md") || target.starts_with('#') {
                return false;
            }
            // An absolute link into THIS repo is a code link written the wrong
            // way, and must be reported. An absolute link anywhere else (an
            // RFC, a crate doc) is an ordinary external reference — not ours.
            if target.starts_with("http") {
                return target.contains("github.com/NormB/sipnab");
            }
            markdown::is_code_tree_path(target)
        })
        .collect()
}

/// The three generators rewrite code links into blob URLs using their own
/// inline copy of the tree list, and all three had drifted apart:
/// `build-wiki.py` knew `bench`, `build-site-pages.py` knew `packaging`,
/// `build-site-internals.py` knew neither, and none knew `docker` or
/// `website`. A tree missing from a generator's alternation is a link that
/// silently publishes as a relative path into a wiki or a site that has no such
/// file.
///
/// They cannot import the Rust helper, so this asserts their regexes still
/// spell the derived set. Adding a top-level directory to the repository now
/// fails here until all three learn about it.
#[test]
fn generators_agree_on_the_code_tree_set() {
    let derived = markdown::code_trees();
    // Concatenate the adjacent string literals of the CODE_LINK_RE assignment
    // the way Python does, then read the alternation out of the resulting
    // pattern. Stripping quote characters from the raw file instead looks
    // simpler and is wrong: the first draft of this test also stripped the `r`
    // raw-string prefix with a blanket replace and reported `crates` as
    // `cates`, `src` as `sc` — a gate whose own extraction is a proxy.
    let literal = regex::Regex::new(r#"r?"([^"]*)""#).expect("literal regex");
    let alt = regex::Regex::new(r"\(\?:((?:[A-Za-z0-9_.\\]+\|)+[A-Za-z0-9_.\\]+)\)")
        .expect("alternation regex");
    let mut wrong = Vec::new();
    for script in [
        "scripts/build-wiki.py",
        "scripts/build-site-pages.py",
        "scripts/build-site-internals.py",
    ] {
        let src = read(script);
        let Some(start) = src.find("CODE_LINK_RE = re.compile(") else {
            wrong.push(format!("{script}: no CODE_LINK_RE assignment"));
            continue;
        };
        let block = &src[start..];
        let end = block.find("\n)").unwrap_or(block.len());
        let pattern: String = literal
            .captures_iter(&block[..end])
            .map(|c| c[1].to_string())
            .collect();
        let Some(c) = alt.captures(&pattern) else {
            wrong.push(format!(
                "{script}: no CODE_LINK_RE tree alternation found — the rewrite \
                 is not doing what this gate believes it does"
            ));
            continue;
        };
        let listed: std::collections::BTreeSet<String> = c[1]
            .split('|')
            .map(|t| t.replace("\\.", ".").trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        // A parse that yields a couple of names means the extraction broke,
        // and every "missing" below would be an artifact of that rather than a
        // real divergence.
        assert!(
            listed.len() >= 10,
            "{script}: extracted only {} tree names from CODE_LINK_RE ({listed:?}) — \
             the extraction is broken, not the generator",
            listed.len()
        );
        let missing: Vec<&String> = derived.iter().filter(|d| !listed.contains(*d)).collect();
        let extra: Vec<&String> = listed.iter().filter(|l| !derived.contains(*l)).collect();
        if !missing.is_empty() || !extra.is_empty() {
            wrong.push(format!(
                "{script}: CODE_LINK_RE missing {missing:?}, has stale {extra:?}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "generator code-tree lists disagree with the repository's actual \
         top-level directories:\n  {}",
        wrong.join("\n  ")
    );
}

/// No generator rewrites a link that a reader sees as code.
///
/// A bare `CODE_LINK_RE.sub()` has no idea what a code span is, so a page that
/// *documents* link syntax gets its example rewritten. `testing.md` carries the
/// literal `` `](../bench/)` `` in a code span; the moment `bench` joined the
/// tree list, all three generators turned that example into
/// `](…/blob/main/docs/bench)` — prose mangled, and a dead URL besides, since
/// `docs/bench` does not exist.
///
/// Two things are checked, because either alone is a proxy. That the
/// substitution goes through `sub_outside_code` — a direct `.sub()` is the
/// bypass — and that `sub_outside_code` actually distinguishes the cases,
/// including a `~~~` fence containing a ``` ``` ``` line, which is what every
/// single-`bool` fence scanner in this repository got wrong.
#[test]
fn generators_do_not_rewrite_links_inside_code() {
    let mut bypassing = Vec::new();
    for script in [
        "scripts/build-wiki.py",
        "scripts/build-site-pages.py",
        "scripts/build-site-internals.py",
    ] {
        let src = read(script);
        if src.contains("CODE_LINK_RE.sub(") {
            bypassing.push(script);
        }
        assert!(
            src.contains("sub_outside_code(CODE_LINK_RE"),
            "{script} does not route its link rewrite through sub_outside_code"
        );
    }
    assert!(
        bypassing.is_empty(),
        "these generators call CODE_LINK_RE.sub() directly, which rewrites \
         inside code spans and fences: {bypassing:?}"
    );

    // The helper itself, on the cases that distinguish a real fence lexer from
    // a boolean toggle. Each probe is (document, must the link be rewritten?).
    let probes: [(&str, bool); 5] = [
        ("prose [x](../bench/x.sh) here", true),
        ("a `](../bench/x.sh)` span", false),
        ("```\n](../bench/x.sh)\n```\n", false),
        ("~~~\n```\n](../bench/x.sh)\n~~~\n", false),
        ("```txt\n](../bench/x.sh)\n```\n[y](../bench/x.sh)\n", true),
    ];
    for (doc, must_change) in probes {
        let out = std::process::Command::new("python3")
            .arg("-c")
            .arg(
                "import sys, re\n\
                 sys.path.insert(0, 'scripts')\n\
                 from lib_markdown import sub_outside_code\n\
                 rx = re.compile(r'\\]\\(\\.\\./bench/x\\.sh\\)')\n\
                 print(sub_outside_code(rx, ']( REWRITTEN )', sys.stdin.read()), end='')",
            )
            .current_dir(repo())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin
                    .as_mut()
                    .expect("stdin")
                    .write_all(doc.as_bytes())
                    .and_then(|()| c.wait_with_output())
            })
            .expect("run sub_outside_code");
        assert!(out.status.success(), "probe failed: {doc:?}");
        let got = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            got != doc,
            must_change,
            "sub_outside_code on {doc:?} gave {got:?}; expected it to \
             {} the link",
            if must_change { "rewrite" } else { "leave" }
        );
    }
}

/// The `()`-suffixed symbol inside a link's text, if any: `` `foo()` ``,
/// `` `Type::method()` ``. The final identifier is what must resolve.
fn symbol_in(link_text: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)\(\)")
        .expect("symbol regex");
    re.captures(link_text).map(|c| c[1].to_string())
}

/// Resolve a page-relative link target to a repo-relative path.
fn resolve(page: &Path, target: &str) -> PathBuf {
    let dir = page.parent().expect("page has a parent");
    let mut out = dir.to_path_buf();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p),
        }
    }
    out
}

#[test]
fn linked_code_targets_exist() {
    let mut missing = Vec::new();
    let mut seen = 0;
    for page in internals_pages() {
        for (text, target) in code_links(&read(&page)) {
            if target.starts_with("http") {
                continue; // reported by linked_code_uses_relative_paths
            }
            seen += 1;
            if !repo().join(resolve(&page, &target)).exists() {
                missing.push(format!(
                    "{}: [{text}]({target}) points at nothing",
                    page.display()
                ));
            }
        }
    }
    // Exact, not a floor. A round number under the truth cannot see the
    // extraction narrow: this read 40 while 265 links existed, so a regex that
    // stopped matching 200 of them would still have passed. Bump when the
    // corpus grows; never lower it to make a build pass.
    assert_eq!(
        seen, 269,
        "code-link extraction found {seen} links, expected 269. More links is \
         fine — bump this. FEWER means the extractor stopped matching, and \
         every assertion below it silently narrowed."
    );
    assert!(
        missing.is_empty(),
        "developer docs link to code that has moved or been deleted:\n  {}",
        missing.join("\n  ")
    );
}

/// Every `.rs` file at or under a resolved link target.
///
/// A link may name a file (`../../src/parallel.rs`) or a subsystem directory
/// (`../../src/capture`); a symbol claim against either has to be checked
/// where the link actually sends the reader.
fn rust_files_under(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            vec![path.to_path_buf()]
        } else {
            Vec::new()
        };
    }
    let mut out = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn linked_symbols_resolve_to_a_definition() {
    // A definition boundary, not a substring. `source.contains("fn run_offline_paral")`
    // was satisfied by `fn run_offline_parallel`, so a doc could name a function
    // that has never existed and resolve against a real one whose name merely
    // starts the same way — and `src/parallel.rs` really does carry the
    // `run_offline_parallel` / `run_offline_parallel_file` pair, so renaming the
    // shorter one would have left the docs green.
    let def = |sym: &str| {
        regex::Regex::new(&format!(r"\bfn\s+{}\s*[(<]", regex::escape(sym))).expect("def regex")
    };
    let mut missing = Vec::new();
    let mut seen = 0;
    for page in internals_pages() {
        for (text, target) in code_links(&read(&page)) {
            let Some(sym) = symbol_in(&text) else {
                continue; // a plain file/subsystem link carries no symbol claim
            };
            seen += 1;
            // Resolved against the file the link points at, not the whole
            // concatenated workspace. `classify_packet()` cited against
            // `src/auth.rs` used to pass while that file contained no such
            // function: the link target was never consulted, so the doc could
            // send a reader to a file that does not mention the symbol it
            // promised, and only a symbol absent from every file in the
            // workspace was reported.
            let resolved = repo().join(resolve(&page, &target));
            let files = rust_files_under(&resolved);
            if files.is_empty() {
                missing.push(format!(
                    "{}: [{text}]({target}) — the target holds no Rust source, so \
                     the `{sym}()` claim resolves against nothing",
                    page.display()
                ));
                continue;
            }
            let re = def(&sym);
            let found = files
                .iter()
                .any(|f| re.is_match(&std::fs::read_to_string(f).unwrap_or_default()));
            if !found {
                missing.push(format!(
                    "{}: [{text}]({target}) — no `fn {sym}` defined in {}",
                    page.display(),
                    target
                ));
            }
        }
    }
    assert_eq!(
        seen, 50,
        "symbol extraction found {seen} claims, expected 50. Bump when the \
         developer docs cite more symbols; a drop means the `()`-suffix pattern \
         stopped matching and unresolvable symbols pass unseen."
    );
    assert!(
        missing.is_empty(),
        "developer docs name functions that no longer exist:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn linked_code_uses_relative_paths() {
    // An absolute blob URL pins a branch and goes stale silently; the relative
    // form is what build-wiki.py rewrites into a blob URL for the wiki.
    let mut offenders = Vec::new();
    for page in internals_pages() {
        for (text, target) in code_links(&read(&page)) {
            if target.starts_with("http") {
                offenders.push(format!(
                    "{}: [{text}]({target}) — use a relative path",
                    page.display()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "code links must be repo-relative:\n  {}",
        offenders.join("\n  ")
    );
}

/// Run a snippet of Python against the generator registries and parse its JSON.
///
/// The registries are imported, not read as text. Every gate below used to
/// grep the generator source, which made "the string appears twice in the file"
/// the proxy for "the page is registered" — and a commented-out entry
/// (`# "internals/threading.md",`), the single most likely way a nav entry
/// disappears, satisfies the count while registering nothing.
fn registries(expr: &str) -> serde_json::Value {
    let script = format!(
        "import importlib.util as u, json\n\
         def load(p, n):\n\
         \x20   s = u.spec_from_file_location(n, p); m = u.module_from_spec(s); \
         s.loader.exec_module(m); return m\n\
         w = load('scripts/build-wiki.py', 'w')\n\
         i = load('scripts/build-site-internals.py', 'i')\n\
         p = load('scripts/build-site-pages.py', 'p')\n\
         print(json.dumps({expr}))"
    );
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(&script)
        .current_dir(repo())
        .output()
        .expect("run python3 against the generator registries");
    assert!(
        out.status.success(),
        "could not import the generator registries: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("generator registries as JSON")
}

#[test]
fn every_internals_page_is_registered_for_the_wiki() {
    // PAGES maps a docs-relative key to a wiki page name; GROUPS places that
    // key in the sidebar. A page in PAGES but not GROUPS publishes and is
    // reachable from nowhere — the exact failure this test's message names,
    // and one the old textual count could not see, because commenting the
    // GROUPS entry out left the string in the file.
    let reg = registries(
        "{'pages': list(w.PAGES), 'groups': [s for _t, srcs in w.GROUPS for s in srcs]}",
    );
    let listed = |key: &str, which: &str| -> bool {
        reg[which]
            .as_array()
            .expect("registry list")
            .iter()
            .any(|v| v.as_str() == Some(key))
    };
    assert!(
        reg["pages"].as_array().map_or(0, Vec::len) >= 10,
        "read {} PAGES entries — the registry import is broken and this gate \
         is checking nothing",
        reg["pages"].as_array().map_or(0, Vec::len)
    );

    let mut unregistered = Vec::new();
    for page in internals_pages() {
        // Keyed on the path under docs/, not the basename. A basename key
        // makes docs/internals/rtp/threading.md match the top-level
        // threading.md's registration, so a nested page reports as registered
        // while publishing nowhere — demonstrated.
        let key = page
            .strip_prefix("docs/")
            .expect("under docs/")
            .to_string_lossy()
            .into_owned();
        // Checked independently, because the two failures differ: absent from
        // PAGES means it never publishes; absent from GROUPS means it
        // publishes and nothing links to it.
        if !listed(&key, "pages") {
            unregistered.push(format!(
                "{key} — not in build-wiki.py PAGES (never publishes)"
            ));
        } else if !listed(&key, "groups") {
            unregistered.push(format!(
                "{key} — in PAGES but not in any GROUPS entry (publishes, and \
                 the sidebar links to it from nowhere)"
            ));
        }
    }
    assert!(
        unregistered.is_empty(),
        "docs/internals pages are not registered for the wiki:\n  {}",
        unregistered.join("\n  ")
    );
}

/// Fenced mermaid blocks as `(line_index_of_opening_fence, body)`.
///
/// Delegates to the shared CommonMark lexer. The version that matched
/// ` ```mermaid ` textually made the backtick the proxy for "is a diagram": a
/// `~~~mermaid` fence — valid CommonMark, rendered by GitHub and by the site —
/// was invisible to all five mermaid conventions *at once*, so one fence could
/// open with `graph TD`, use `;` separators, carry a markdown link in a node
/// label and sit under no prose, and every suite stayed green while
/// `build-site-internals.py` shipped it to the site as raw diagram source with
/// the in-fence link rewritten.
fn mermaid_fences(text: &str) -> Vec<(usize, String)> {
    markdown::fences(text)
        .into_iter()
        .filter(|f| f.lang == "mermaid")
        .map(|f| (f.line - 1, f.body))
        .collect()
}

#[test]
fn every_mermaid_block_is_a_sequence_diagram() {
    let mut offenders = Vec::new();
    for page in internals_pages() {
        for (line, body) in mermaid_fences(&read(&page)) {
            let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            if first.trim() != "sequenceDiagram" && !first.trim().starts_with("sequenceDiagram") {
                offenders.push(format!(
                    "{}:{}: mermaid block opens with {first:?}, not sequenceDiagram",
                    page.display(),
                    line + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "developer docs use sequenceDiagram only:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn no_markdown_links_inside_mermaid_blocks() {
    // scripts/build-wiki.py applies LINK_RE.sub() to the whole page body with
    // no fence awareness, so a link inside a diagram label gets rewritten into
    // a wiki link and corrupts the diagram source.
    let link = regex::Regex::new(r"\]\([^)\s]+\.md").expect("link regex");
    let mut offenders = Vec::new();
    for page in internals_pages() {
        for (line, body) in mermaid_fences(&read(&page)) {
            if link.is_match(&body) {
                offenders.push(format!(
                    "{}:{}: markdown link inside a mermaid block",
                    page.display(),
                    line + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "build-wiki.py rewrites links without fence awareness:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn every_mermaid_block_is_introduced_by_prose() {
    // A diagram must never carry meaning the prose does not, so the page still
    // reads in a plain-text viewer, a diff, or a renderer without mermaid.
    let mut offenders = Vec::new();
    for page in internals_pages() {
        let text = read(&page);
        let lines: Vec<&str> = text.lines().collect();
        for (line, _) in mermaid_fences(&text) {
            let prev = lines[..line]
                .iter()
                .rev()
                .find(|l| !l.trim().is_empty())
                .copied()
                .unwrap_or("");
            let t = prev.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with("```") || t.starts_with('|') {
                offenders.push(format!(
                    "{}:{}: mermaid block is preceded by {t:?}, not a prose sentence",
                    page.display(),
                    line + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "every diagram needs a one-sentence prose summary above it:\n  {}",
        offenders.join("\n  ")
    );
}

/// build-wiki.py must rewrite code links to blob URLs. A relative code link
/// that reaches the flat wiki resolves to nothing — the wiki has no repo tree.
///
/// This used to assert only that the string `CODE_LINK_RE` appeared in the
/// script, which is true whether or not the rewriting works — and it did pass
/// while `](../bench/)` published to the wiki dead, because `bench` was not in
/// the regex's list of top-level trees. Inspecting a generator's source is not
/// a test of its output.
#[test]
fn build_wiki_leaves_no_relative_links_in_the_output() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::env::temp_dir().join(format!("sipnab-wiki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);

    let run = std::process::Command::new("python3")
        .arg(repo.join("scripts/build-wiki.py"))
        .arg(&out)
        .current_dir(repo)
        .output()
        .expect("run scripts/build-wiki.py — python3 must be on PATH");
    assert!(
        run.status.success(),
        "build-wiki.py failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let link = regex::Regex::new(r"\]\(([^)]+)\)").unwrap();
    let mut leaked: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&out).expect("wiki output dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let page = path.file_name().unwrap().to_string_lossy().to_string();
        let raw = std::fs::read_to_string(&path).expect("wiki page");
        // Scan prose, not bytes. A page that documents link syntax carries the
        // literal `](../bench/)` inside a code span — quoted, never rendered as
        // a link, and correctly left alone by the generator. Reading raw bytes
        // reported that example as a link that had escaped rewriting.
        let body = markdown::linkable_prose(&raw);
        for cap in link.captures_iter(&body) {
            let target = cap[1].trim();
            // Valid on a flat wiki: an absolute URL, a pure anchor, or a wiki
            // page name. Anything else carrying a path separator is a repo-
            // relative link that resolves to nothing once published.
            let ok = target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || target.starts_with('#')
                || !target.contains('/');
            if !ok {
                leaked.push(format!("{page}: ]({target})"));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&out);

    assert!(
        leaked.is_empty(),
        "relative links reached the generated wiki, where they resolve to \
         nothing — add the tree to CODE_LINK_RE in build-wiki.py, or write the \
         link as an absolute URL:\n  {}",
        leaked.join("\n  ")
    );
}

/// The developer docs carry a designed diagram set; losing them silently
/// would strip the pages of half their meaning.
#[test]
fn developer_docs_carry_their_diagram_set() {
    let total: usize = internals_pages()
        .iter()
        .map(|p| mermaid_fences(&read(p)).len())
        .sum();
    assert!(
        total >= 17,
        "expected at least 17 sequence diagrams across docs/internals, found {total}"
    );
}

/// Mermaid syntax hazards that render as a *silently broken* diagram.
///
/// Both of these shipped, and both survived every existing gate: the fences
/// were well-formed markdown, started with `sequenceDiagram`, and carried no
/// markdown links, so nothing here looked wrong until the diagrams were put
/// in front of a real mermaid parser.
///
/// 1. `;` is a statement separator in mermaid. A semicolon in note or message
///    text ends the statement there, and the remainder is parsed as a new
///    statement — which fails, taking the whole diagram with it.
/// 2. An actor id that spells a mermaid keyword (`Loop`, `End`, `Alt`, …)
///    tokenizes as that keyword when it appears as a message target, so
///    `Term-->>Loop: ...` is a parse error even though `Loop->>Term: ...`
///    parses.
#[test]
fn mermaid_fences_avoid_syntax_hazards() {
    // Keywords the sequence-diagram lexer claims, lowercased.
    const KEYWORDS: &[&str] = &[
        "loop",
        "alt",
        "else",
        "opt",
        "par",
        "and",
        "end",
        "rect",
        "note",
        "over",
        "activate",
        "deactivate",
        "critical",
        "option",
        "break",
        "box",
        "autonumber",
        "participant",
        "actor",
        "create",
        "destroy",
        "link",
        "links",
        "title",
    ];

    let mut problems = Vec::new();
    for page in internals_pages() {
        let text = read(&page);
        for (line_idx, body) in mermaid_fences(&text) {
            let at = format!("{}:{}", page.display(), line_idx + 1);
            for (n, line) in body.lines().enumerate() {
                if line.contains(';') {
                    problems.push(format!(
                        "{at} (+{n}): `;` is a mermaid statement separator and \
                         truncates the text — use an em dash:\n      {}",
                        line.trim()
                    ));
                }
            }
            for line in body.lines() {
                let t = line.trim();
                let Some(rest) = t
                    .strip_prefix("participant ")
                    .or_else(|| t.strip_prefix("actor "))
                else {
                    continue;
                };
                // `participant Loop as TUI event loop` — the id is the first
                // word; everything after `as` is the display label and may
                // say anything.
                let id = rest.split_whitespace().next().unwrap_or("");
                if KEYWORDS.contains(&id.to_ascii_lowercase().as_str()) {
                    problems.push(format!(
                        "{at}: actor id `{id}` collides with the mermaid \
                         keyword `{}` — it parses as that keyword when used \
                         as a message target",
                        id.to_ascii_lowercase()
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "mermaid fences with syntax hazards (these render as a broken diagram, \
         on the site and on the wiki):\n  {}",
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Site mirror: website/content/docs/internals/ is generated, not written
// ---------------------------------------------------------------------------

/// `docs/internals/<name>.md` -> the site file it generates.
fn site_mirror_name(page: &Path) -> String {
    // The path under docs/internals/, not the basename: two READMEs at
    // different depths both mapped to `_index.md`, so a nested page was
    // reported as published by matching the top-level page's mirror.
    let rel = page
        .strip_prefix("docs/internals/")
        .expect("under docs/internals/")
        .to_string_lossy()
        .into_owned();
    match rel.strip_suffix("README.md") {
        Some(dir) => format!("{dir}_index.md"),
        None => rel,
    }
}

/// Every developer page reaches the website, and no orphan mirror survives a
/// renamed source. The wiki gate above is the same contract for the wiki;
/// without this one a new page publishes to the wiki and silently never
/// appears on sipnab.com.
#[test]
fn every_internals_page_is_published_to_the_site() {
    let dir = repo().join("website/content/docs/internals");
    let expected: Vec<String> = internals_pages()
        .iter()
        .map(|p| site_mirror_name(p))
        .collect();

    let mut missing = Vec::new();
    for name in &expected {
        if !dir.join(name).is_file() {
            missing.push(name.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "docs/internals pages with no site mirror (run \
         `python3 scripts/build-site-internals.py`):\n  {}",
        missing.join("\n  ")
    );

    let mut orphans: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".md") && !expected.contains(n))
        .collect();
    orphans.sort();
    assert!(
        orphans.is_empty(),
        "site pages under website/content/docs/internals with no source in \
         docs/internals (a renamed source left these behind):\n  {}",
        orphans.join("\n  ")
    );
}

/// The committed mirror equals what the generator produces today.
///
/// The mirror is committed so the Zola build needs nothing but Zola, which
/// means it is exactly the kind of generated-but-checked-in artifact that
/// goes stale the first time someone edits the source and forgets the
/// script. Regenerate into a temp dir and compare byte-for-byte.
#[test]
fn site_internals_mirror_is_current() {
    let tmp = std::env::temp_dir().join(format!(
        "sipnab-site-internals-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&tmp);

    let out = std::process::Command::new("python3")
        .arg(repo().join("scripts/build-site-internals.py"))
        .arg(&tmp)
        .current_dir(repo())
        .output()
        .expect(
            "run scripts/build-site-internals.py — python3 must be on PATH \
             (CI installs it; wiki-sync.yml already depends on it)",
        );
    assert!(
        out.status.success(),
        "build-site-internals.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let committed = repo().join("website/content/docs/internals");
    let mut stale = Vec::new();
    for page in internals_pages() {
        let name = site_mirror_name(&page);
        let fresh = std::fs::read_to_string(tmp.join(&name)).expect("generated page");
        let have = std::fs::read_to_string(committed.join(&name)).unwrap_or_default();
        if fresh != have {
            stale.push(name);
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        stale.is_empty(),
        "website/content/docs/internals is stale — regenerate with \
         `python3 scripts/build-site-internals.py` and commit:\n  {}",
        stale.join("\n  ")
    );
}

/// A mirrored page with a diagram declares `has_diagrams`, and `page.html`
/// loads the mermaid bundle on exactly that flag.
///
/// Two ways this breaks silently: a page gains a diagram and never loads
/// mermaid (the reader sees raw `sequenceDiagram` source), or the template
/// stops gating on the flag and every doc page pays 3.4 MB.
#[test]
fn pages_with_diagrams_load_the_mermaid_bundle() {
    let committed = repo().join("website/content/docs/internals");
    let mut wrong = Vec::new();
    let mut with_diagrams = 0;
    for page in internals_pages() {
        let name = site_mirror_name(&page);
        let mirrored = std::fs::read_to_string(committed.join(&name)).unwrap_or_default();
        let source_has = !mermaid_fences(&read(&page)).is_empty();
        let declares = mirrored.contains("has_diagrams = true");
        let rendered = mirrored.contains("<pre class=\"mermaid\">");
        if source_has {
            with_diagrams += 1;
        }
        if source_has != declares || source_has != rendered {
            wrong.push(format!(
                "{name}: source diagrams={source_has}, has_diagrams={declares}, \
                 rendered <pre class=\"mermaid\">={rendered}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "site mirror diagram flags disagree with the source pages:\n  {}",
        wrong.join("\n  ")
    );
    assert!(
        with_diagrams >= 6,
        "expected at least 6 developer pages to carry diagrams, found {with_diagrams}"
    );

    // Tera never renders `{# … #}`, so the template is read with comments
    // blanked. Reading raw bytes could not tell a live `{% if %}` guard from
    // the same words parked in a comment — and page.html opens with a comment
    // that explains the flag by name, so deleting the guard and keeping the
    // explanation left this green while every doc page unconditionally pulled
    // a 3.4 MB bundle.
    let tpl = markdown::blank_tera_comments(&read("website/templates/page.html"));
    let guard = "{% if page.extra.has_diagrams %}";
    let open = tpl.find(guard).unwrap_or_else(|| {
        panic!("page.html must gate the mermaid bundle on {guard}");
    });
    let close = tpl[open..]
        .find("{% endif %}")
        .map(|n| open + n)
        .unwrap_or_else(|| panic!("page.html has {guard} with no {{% endif %}}"));

    for asset in ["js/mermaid.min.js", "js/diagram-viewer.js"] {
        assert!(
            repo().join("website/static").join(asset).is_file(),
            "website/static/{asset} is missing but page.html references it"
        );
        // Inside the guard, and nowhere outside it. "Appears somewhere in the
        // file" is satisfied by a bundle loaded unconditionally, which is the
        // second failure mode this test's doc comment names and the one the
        // substring check could not distinguish from the first.
        let inside = tpl[open..close].contains(asset);
        let outside = tpl[..open].contains(asset) || tpl[close..].contains(asset);
        assert!(
            inside,
            "page.html does not load {asset} inside {guard} — the diagrams \
             would render as raw mermaid source"
        );
        assert!(
            !outside,
            "page.html loads {asset} outside {guard}, so every page pays for \
             the mermaid bundle whether or not it has a diagram"
        );
    }
}

/// Every mirrored page is reachable from the Docs dropdown.
///
/// The gap that started this: the developer docs shipped and the dropdown
/// never learned about them, so the only way to the pages was a direct URL.
#[test]
fn every_site_internals_page_is_in_the_docs_dropdown() {
    // Comments blanked first: replacing the Threading Model `<a>` with a Tera
    // comment containing the same path left this green, while the text never
    // reached rendered HTML and the page was reachable only by direct URL —
    // precisely the gap the doc comment above says started this test.
    let base = markdown::blank_tera_comments(&read("website/templates/base.html"));
    let mut missing = Vec::new();
    for page in internals_pages() {
        let path = format!("@/docs/internals/{}", site_mirror_name(&page));
        // The path has to appear in an anchor's href, not merely somewhere in
        // the file: a mention in a `<script>`, an attribute or leftover markup
        // is not a link a reader can follow.
        let linked = base.lines().any(|l| {
            l.contains(&path) && l.contains("<a ") && l.contains("href=") && l.contains("get_url")
        });
        if !linked {
            missing.push(path);
        }
    }
    assert!(
        missing.is_empty(),
        "developer pages have no anchor in the Docs dropdown in base.html:\n  {}",
        missing.join("\n  ")
    );
}

/// The workflow-inventory heading counts the workflows. Keep it honest.
///
/// `build-ci-release.md` opens its inventory with "The N workflows" and then
/// tables them. The count is spelled out in the heading, so adding a workflow
/// silently makes the heading wrong — and a table missing a row reads as
/// "these are all of them" rather than as an omission. Nothing checked either
/// half until `scorecard.yml` became the ninth.
#[test]
fn workflow_inventory_heading_counts_the_workflows() {
    const WORDS: [&str; 16] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    ];
    let dir = repo().join(".github/workflows");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("workflows dir")
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "yml" || x == "yaml")
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    let n = names.len();
    let word = WORDS
        .get(n)
        .unwrap_or_else(|| panic!("{n} workflows — extend WORDS"));

    let doc = read("docs/internals/build-ci-release.md");
    let heading = format!("## The {word} workflows");
    assert!(
        doc.contains(&heading),
        "docs/internals/build-ci-release.md should say \"{heading}\" — \
         there are {n} workflow files: {names:?}"
    );
    // Every workflow must appear in the TABLE under that heading — which is
    // what the sentence above used to claim and the code did not do. Searching
    // the whole page let a deleted table row pass because the workflow's name
    // still appeared in a mermaid diagram 150 lines below: the heading read
    // "The nine workflows", there really were nine files, and `docker.yml` was
    // described nowhere. `ci.yml`, `release.yml` and `quality.yml` had the same
    // slack.
    let start = doc.find(&heading).expect("heading located above");
    let body = &doc[start + heading.len()..];
    let end = body.find("\n## ").unwrap_or(body.len());
    let table: String = body[..end]
        .lines()
        .filter(|l| l.trim_start().starts_with('|'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        table.lines().count() >= n,
        "the inventory table under \"{heading}\" has {} rows for {n} workflows \
         — the table slice is not reading what this gate believes it is",
        table.lines().count()
    );
    let missing: Vec<&String> = names
        .iter()
        .filter(|f| !table.contains(f.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "workflows counted by the heading but absent from the table under it: \
         {missing:?}"
    );
}

/// Site pages generated from `docs/` must match what the generator produces.
///
/// Every page under `scripts/build-site-pages.py` was maintained by hand on
/// both sides and drifted badly. The cookbook: 740 lines on the site against
/// 122 in `docs/`, sharing 2 of their 36 commands. The REST API page: 893
/// against 430, each side holding sections the other did not have. The wiki
/// renders from `docs/`, so wiki readers got whichever copy was thinner, shown
/// as though it were the whole page. Nothing was broken, nothing was stale,
/// and nothing could have noticed.
///
/// Regenerate into a temp dir and compare byte-for-byte, then check that no
/// page has fallen out of the registry — see the comment on `orphaned` for
/// why the count of generated pages cannot answer that question.
#[test]
fn site_pages_mirror_is_current() {
    let tmp = std::env::temp_dir().join(format!(
        "sipnab-site-pages-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("temp dir");

    let out = std::process::Command::new("python3")
        .arg(repo().join("scripts/build-site-pages.py"))
        .arg(&tmp)
        .current_dir(repo())
        .output()
        .expect("run scripts/build-site-pages.py — python3 must be on PATH");
    assert!(
        out.status.success(),
        "build-site-pages.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut produced = Vec::new();
    let mut stale = Vec::new();
    for entry in std::fs::read_dir(&tmp).expect("generated pages").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        produced.push(name.clone());
        let fresh = std::fs::read_to_string(entry.path()).expect("generated page");
        let have = read(format!("website/content/docs/{name}"));
        if fresh != have {
            stale.push(name);
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    // A count of the pages produced cannot see the registry shrink: drop a page
    // from PAGES and the generator simply stops writing it, so the count drops
    // with it and any floor below the real number still passes. The mirror,
    // meanwhile, stays on disk — still stamped "do not edit", no longer
    // regenerated, quietly back to being the hand-maintained copy this merge
    // existed to end. The banner the generator stamped is the witness that does
    // not move, and needs no number kept in sync with PAGES.
    const BANNER_MARK: &str = "Generated by scripts/build-site-pages.py";
    let mut orphaned = Vec::new();
    for entry in std::fs::read_dir(repo().join("website/content/docs"))
        .expect("read website/content/docs")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".md") || produced.contains(&name) {
            continue;
        }
        if read(format!("website/content/docs/{name}")).contains(BANNER_MARK) {
            orphaned.push(name);
        }
    }

    assert!(
        !produced.is_empty(),
        "build-site-pages.py generated no pages at all — PAGES is empty, or the \
         script stopped writing to the output directory it was given"
    );
    assert!(
        orphaned.is_empty(),
        "these site pages carry the build-site-pages.py banner but the generator no \
         longer writes them — they were dropped from PAGES in \
         scripts/build-site-pages.py and are hand-maintained copies again. \
         Re-register the page in PAGES, or delete the file if the page is gone:\n  {}",
        orphaned.join("\n  ")
    );
    assert!(
        stale.is_empty(),
        "these site pages are stale — regenerate with \
         `python3 scripts/build-site-pages.py` and commit:\n  {}",
        stale.join("\n  ")
    );
}

/// `DOCS_TO_SITE` must map every docs page that has a site page, and nothing
/// else.
///
/// The map decides link rewriting: a docs page absent from it has its links
/// rewritten to a GitHub blob URL. So an omission sends readers past a site
/// page that exists — silently, because a blob URL resolves fine. That already
/// happened once with `tui-walkthrough.md`.
///
/// Both directions are checked, because only one of them was:
///   - every VALUE names a file that exists under `website/content/docs/`,
///     or the rewrite points at a page Zola will 404 on;
///   - every page either generator writes appears as a value, or links to it
///     become blob URLs while a site page sits there unused.
///
/// The map is read from the generator itself rather than restated here.
#[test]
fn docs_to_site_map_is_complete() {
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(
            "import importlib.util as u, json, sys\n\
             def load(p, n):\n\
             \x20   s = u.spec_from_file_location(n, p); m = u.module_from_spec(s); s.loader.exec_module(m); return m\n\
             i = load('scripts/build-site-internals.py', 'i')\n\
             p = load('scripts/build-site-pages.py', 'p')\n\
             print(json.dumps({\n\
             \x20 'map': i.DOCS_TO_SITE,\n\
             \x20 'pages': [t[1] for t in p.PAGES],\n\
             \x20 'internals': [t[1] for t in i.PAGES],\n\
             }))",
        )
        .current_dir(repo())
        .output()
        .expect("run generators");
    assert!(
        out.status.success(),
        "could not read the generator registries: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = String::from_utf8_lossy(&out.stdout);

    // Minimal extraction — the values are flat string lists and a flat map.
    let grab = |key: &str| -> Vec<String> {
        let at = json.find(&format!("\"{key}\":")).expect("key present");
        let rest = &json[at..];
        let open = rest.find(['[', '{']).expect("open");
        let close = rest[open..].find([']', '}']).expect("close");
        rest[open..open + close]
            .split(',')
            .filter_map(|t| t.rsplit(':').next())
            .filter_map(|t| t.trim().trim_matches('"').to_string().into())
            .filter(|t: &String| t.ends_with(".md"))
            .collect()
    };

    let mapped = grab("map");
    let generated: Vec<String> = grab("pages").into_iter().chain(grab("internals")).collect();
    assert!(
        mapped.len() >= 10 && !generated.is_empty(),
        "read {} mapped and {} generated pages — the registry extraction stopped \
         matching and this gate is checking nothing",
        mapped.len(),
        generated.len()
    );

    let mut problems = Vec::new();
    for site in &mapped {
        if !repo().join("website/content/docs").join(site).is_file() {
            problems.push(format!(
                "DOCS_TO_SITE points at website/content/docs/{site}, which does not exist — \
                 links to it rewrite to a page Zola will 404 on"
            ));
        }
    }
    for site in &generated {
        // Only pages the generator writes into website/content/docs/ itself;
        // build-site-internals writes into a subdirectory with its own link
        // form, so a name that resolves to no file there is not this map's job.
        if !mapped.iter().any(|m| m == site)
            && repo().join("website/content/docs").join(site).is_file()
        {
            problems.push(format!(
                "a generator writes website/content/docs/{site} but DOCS_TO_SITE does not \
                 list it — links to that docs page become blob URLs, sending readers to \
                 GitHub past the site page that exists"
            ));
        }
    }
    // The direction the generator lists could not supply. Every entry above is
    // derived from what a generator WRITES, so the one site page no generator
    // writes — `benchmarks.md`, hand-maintained on both sides on purpose — had
    // its map entry guarded by nothing at all. Deleting it would send readers
    // to GitHub past a site page that exists: the identical `tui-walkthrough.md`
    // regression the comment above this map memorializes.
    //
    // Disk answers it. A `docs/X.md` that has a same-named site page is a page
    // with two copies, and a link to it must reach the site copy.
    let docs_dir = repo().join("docs");
    let site_dir = repo().join("website/content/docs");
    let mut paired = 0;
    for entry in std::fs::read_dir(&docs_dir).expect("read docs/") {
        let p = entry.expect("dir entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = p
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        if !site_dir.join(&name).is_file() {
            continue;
        }
        paired += 1;
        if !json.contains(&format!("\"{name}\"")) {
            problems.push(format!(
                "docs/{name} and website/content/docs/{name} both exist, but \
                 DOCS_TO_SITE has no entry for it — links to that docs page \
                 become blob URLs, sending readers to GitHub past the site \
                 page that exists"
            ));
        }
    }
    assert!(
        paired >= 5,
        "found only {paired} docs pages with a same-named site page — the \
         pairing walk is reading nothing and this direction passes vacuously"
    );

    // And the reverse, with the exemption derived rather than listed. A site
    // page needs no map entry only if nothing under docs/ could produce it:
    // `_index.md` is Zola's section landing page, and `api-clients.md`,
    // `build.md` and `integrations.md` are written for the site alone. Naming
    // them in a hand-kept allowlist would be one more list to drift; asking
    // disk whether a source exists cannot drift.
    let mut exempt = Vec::new();
    for entry in std::fs::read_dir(&site_dir).expect("read website/content/docs/") {
        let p = entry.expect("dir entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = p
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        if mapped.contains(&name) || name == "_index.md" {
            continue;
        }
        if docs_dir.join(&name).is_file() {
            problems.push(format!(
                "website/content/docs/{name} is not a DOCS_TO_SITE value even \
                 though docs/{name} exists"
            ));
        } else {
            exempt.push(name);
        }
    }
    assert!(
        exempt.len() <= 5,
        "{} site pages claim to have no docs/ source ({exempt:?}) — that many \
         means the pairing rule has stopped matching, not that the site grew",
        exempt.len()
    );

    assert!(
        problems.is_empty(),
        "DOCS_TO_SITE disagrees with what is on disk:\n  {}",
        problems.join("\n  ")
    );
}
