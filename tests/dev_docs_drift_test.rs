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

/// The shared code-tree list still describes this repository.
///
/// `.config/code-trees.txt` is the one list; nothing derives it from `git
/// ls-files` at read time any more, because four consumers need it and two of
/// them are Python scripts that would each have re-derived it differently.
/// Deriving it once, here, and failing on a mismatch is what keeps a new
/// top-level directory from silently changing what every documentation gate
/// believes a code link is.
///
/// `docs/` is excluded on both sides: a link into it is a document link.
#[test]
fn code_tree_list_matches_the_repository() {
    let listed = markdown::code_trees();
    let tracked = markdown::tracked_top_level_dirs();
    let missing: Vec<&String> = tracked.iter().filter(|d| !listed.contains(*d)).collect();
    let stale: Vec<&String> = listed.iter().filter(|d| !tracked.contains(*d)).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "{} disagrees with the repository's tracked top-level directories: \
         missing {missing:?}, stale {stale:?}. Every documentation gate and \
         both link fixers read that file, so a directory absent from it is a \
         tree whose links nothing rewrites and nothing checks.",
        markdown::CODE_TREES_FILE
    );
}

/// Every consumer of the code-tree list behaves as the list says.
///
/// The list was spelled out six times — once in `tests/support/markdown.rs`,
/// once as a Rust array in `doc_link_hygiene_test`, once per generator as a
/// regex alternation, and once as a `ROOTS` tuple in
/// `scripts/link-repo-paths.py` — and the copies drifted:
/// `build-wiki.py` knew `bench`, `build-site-pages.py` knew `packaging`,
/// `build-site-internals.py` knew neither, none knew `docker` or `website`,
/// and the fixer knew none of the four. A tree missing from a generator's
/// alternation is a link that silently publishes as a relative path into a
/// wiki or a site that has no such file; a tree missing from the fixer is a
/// link the gate demands and the fixer cannot write.
///
/// This asserts the BEHAVIOR, not the spelling. An earlier version read the
/// alternation back out of each script's source, which is a proxy: it says
/// what the file contains, not what the compiled pattern matches. Each
/// generator's live `CODE_LINK_RE` is probed against every tree in the list,
/// in both the `tree/path` and bare-`tree` forms the generators must rewrite,
/// and against a name that is not a tree at all.
#[test]
fn generators_agree_on_the_code_tree_set() {
    let probe = registries(
        "{'trees': sorted(lm.code_trees()), \
          'fixer': sorted(l.WIKI_TREES), \
          'fixer_roots': sorted(l.ROOTS), \
          'generators': {n: { \
              'accepts': sorted(t for t in lm.code_trees() \
                  if g.CODE_LINK_RE.search('](%s/x.rs)' % t) \
                  and g.CODE_LINK_RE.search('](../../%s)' % t)), \
              'rejects_unknown': not g.CODE_LINK_RE.search('](notatree/x.rs)'), \
              'rejects_docs': not g.CODE_LINK_RE.search('](../design/notes.md)')} \
            for n, g in (('build-wiki.py', w), \
                         ('build-site-internals.py', i), \
                         ('build-site-pages.py', p))}}",
    );

    let strings = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .expect("json array")
            .iter()
            .map(|s| s.as_str().expect("json string").to_string())
            .collect()
    };
    let expected: Vec<String> = markdown::code_trees().iter().cloned().collect();

    // The Rust gates parse the file with `include_str!`, the scripts read it
    // at run time. Two parsers, one grammar: prove they agree before trusting
    // anything below, or a comment-stripping difference makes every other
    // assertion here compare a set with itself.
    assert_eq!(
        strings(&probe["trees"]),
        expected,
        "{} parses differently in Python and in Rust",
        markdown::CODE_TREES_FILE
    );

    let mut wrong = Vec::new();
    for (name, g) in probe["generators"]
        .as_object()
        .expect("generator probe map")
        .iter()
    {
        let accepts = strings(&g["accepts"]);
        if accepts != expected {
            let missing: Vec<&String> = expected.iter().filter(|t| !accepts.contains(t)).collect();
            wrong.push(format!(
                "{name}: CODE_LINK_RE does not rewrite links into {missing:?}"
            ));
        }
        if g["rejects_unknown"] != serde_json::Value::Bool(true) {
            wrong.push(format!(
                "{name}: CODE_LINK_RE rewrites `](notatree/x.rs)`, so a bare \
                 filename in prose is being taken for a repo path"
            ));
        }
        if g["rejects_docs"] != serde_json::Value::Bool(true) {
            wrong.push(format!(
                "{name}: CODE_LINK_RE rewrites a link into docs/, which is a \
                 document link and must map to a wiki or site page instead"
            ));
        }
    }

    // The fixer's two lists are different questions and both matter. WIKI_TREES
    // is the shared list, and decides what it may link under docs/internals/ —
    // it must equal the list exactly, or it writes a link the wiki cannot
    // rewrite (too wide) or refuses one the gate demands (too narrow). ROOTS is
    // what a code span may be anchored on, which includes `docs` precisely
    // because `docs/install.md` IS a tracked file the gate wants linked.
    if strings(&probe["fixer"]) != expected {
        wrong.push(format!(
            "scripts/link-repo-paths.py: WIKI_TREES is {:?}, the list is {expected:?}",
            strings(&probe["fixer"])
        ));
    }
    let roots = strings(&probe["fixer_roots"]);
    for t in expected.iter().chain(std::iter::once(&"docs".to_string())) {
        if !roots.contains(t) {
            wrong.push(format!(
                "scripts/link-repo-paths.py: ROOTS omits `{t}`, so a code span \
                 naming a file there is one the gate demands and the fixer \
                 cannot write"
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "consumers of {} disagree with it:\n  {}",
        markdown::CODE_TREES_FILE,
        wrong.join("\n  ")
    );
}

/// Nobody has pasted the tree list back into a script.
///
/// The behavior probe above catches a re-hardcoded copy only once it has
/// already drifted. This catches the paste itself, in the exact shape the
/// three generators shipped for months: `a|b|c` spelled out in a regex
/// literal. Adjacent tree names joined by `|` appear nowhere else in this
/// repository, so the pattern is specific to the mistake.
#[test]
fn no_script_respells_the_code_tree_alternation() {
    // Both spellings a Python regex literal uses: bare, and with the leading
    // dot escaped (`\.githooks`).
    // A set, not a Vec: for a tree with no dot the two spellings are the same
    // string, and the duplicate reported one paste four times.
    let variants: std::collections::BTreeSet<String> = markdown::code_trees()
        .iter()
        .flat_map(|t| [t.clone(), t.replace('.', "\\.")])
        .collect();
    let mut offenders = std::collections::BTreeSet::new();
    let mut scanned = 0usize;
    let mut stack = vec![repo().join("scripts"), repo().join("tests")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("read_dir").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let ext = p.extension().and_then(|s| s.to_str());
            if ext != Some("py") && ext != Some("rs") {
                continue;
            }
            scanned += 1;
            let src = std::fs::read_to_string(&p).expect("read source");
            // Anchored on each `|` rather than testing every ordered pair of
            // names against the whole file: the pair sweep is 676 substring
            // searches per source and took 37 seconds across the tree.
            // `|` is one byte, so the split is always on a char boundary.
            for (idx, _) in src.match_indices('|') {
                let (before, after) = (&src[..idx], &src[idx + 1..]);
                let a = variants.iter().find(|v| before.ends_with(v.as_str()));
                let b = variants.iter().find(|v| after.starts_with(v.as_str()));
                if let (Some(a), Some(b)) = (a, b) {
                    offenders.insert(format!(
                        "{}: spells `{a}|{b}` — build the pattern from {} instead",
                        p.strip_prefix(repo()).expect("under repo").display(),
                        markdown::CODE_TREES_FILE
                    ));
                }
            }
        }
    }
    assert!(
        scanned > 20,
        "scanned only {scanned} sources — the walk broke, so this gate is \
         checking nothing"
    );
    assert!(
        offenders.is_empty(),
        "the code-tree alternation is spelled out again ({}):\n  {}",
        offenders.len(),
        offenders.iter().cloned().collect::<Vec<_>>().join("\n  ")
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
    // Raised 283 -> 290 by the capture-tuning docs pass: +6 code links in
    // internals/invariants.md (the §2 lock-discipline rewrite) and +1 in
    // internals/threading.md. Growth, not a loosening — every one of the 7 was
    // attributed before this pin moved.
    // Raised 290 -> 294 by the `LK1` sub-rule appended to internals/invariants.md
    // §2 ("decide under the guard, perform after it"): +4 code links, all in
    // that one page.
    // Raised 294 -> 295 by the domain primer's link to `session_id.rs`, added
    // with the four-strategy correlation table. One link, one page.
    // Raised 295 -> 298 by naming the three spawn sites in internals/threading.md
    // (`start_servers`, `build_resolver`, `spawn_scanner_kill_worker`). The page
    // had drawn all four auxiliary threads as children of the TUI event loop,
    // which is where `--metrics` being TUI-only hid in plain sight; citing who
    // actually spawns each is the correction. Three links, one page.
    // Raised 298 -> 300 by the stale-documentation sweep: internals/walkthroughs.md
    // now cites `tests/mcp_tool_descriptions_test.rs` (it had claimed the D22
    // description rule was unenforced and cited a shell script that does not
    // exist), and internals/README.md cites `src/sip/dsl.rs` (its annotation had
    // the field count backwards). Two links, two pages — both replacing a claim
    // with the artifact that settles it.
    // Raised 300 -> 301 by the non-Linux pre-push gate: internals/build-ci-release.md
    // now cites `scripts/check-non-linux.sh`, which is where the four rejected
    // alternatives and the evidence against each are written down. One link, one page.
    // Raised 301 -> 340 by the doc-link pass: every tracked repo path in these
    // pages became a link rather than text to retype, and the line citations
    // gained the `#L` fragment their labels had always promised. The links here
    // stay RELATIVE — build-wiki.py rewrites them, and an absolute blob URL
    // pins a branch and goes stale silently, which is what the sibling gate
    // `linked_code_uses_relative_paths` exists to catch.
    // LOWERED 340 -> 339, the only time this pin has moved down, and the
    // attribution is the whole justification: internals/README.md dropped ONE
    // link, `[src/main.rs:428](../../src/main.rs)`. The citation was stale —
    // main.rs is 171 lines long, so the label promised a line that cannot
    // exist — and the annotation now names the symbols instead. A link removed
    // because it pointed at nothing is not the extraction narrowing, which is
    // what this pin guards; the per-file diff was checked before this number
    // moved, and no other page changed.
    // Interpolated, never typed twice. `link_integrity_test` records the same
    // trap: a previous bump there moved the number and not the sentence, so
    // the gate asserted one figure while its message named another and sent
    // the next reader hunting a discrepancy that did not exist. Lowering this
    // pin to 339 reproduced it immediately — the message still said 340.
    // Raised 339 -> 341 by #113: the "add a detector" walkthrough gained two
    // links, to `SECURITY_FINDING_KINDS` in `mcp/server.rs` and
    // `DetectionEngines::armed_kinds` in `batch.rs`. A new rule name has to
    // reach both or `security_findings` refuses to filter on it, and the
    // walkthrough is where someone adding one is reading. Attributed per file:
    // `docs/internals/walkthroughs.md` +2, every other internals page
    // unchanged.
    // Raised 341 -> 342 by #114: the domain primer's "MOS is an estimate"
    // section gained one link, to `MosDelay` in `rtp/quality.rs`, because the
    // delay term became an input every surface must supply rather than a
    // constant the model assumed. The `estimate_mos()` link in the same
    // paragraph was RE-POINTED to `estimate_mos_with_delay()`, not added, so
    // it is not part of the +1. Attributed per file:
    // `docs/internals/domain-primer.md` +1, every other internals page
    // unchanged.
    // Raised 342 -> 343 by #34: the gate roster's `site_journey_test` row
    // gained one link, to `demos/gen-mcp-examples.sh`, because that test now
    // holds the homepage's MCP examples to the files that script generates and
    // a reader of the row needs to know which script regenerates them. The
    // `site_journey_test` and `mockup_alignment_test` links in the same row
    // were already there — the row was rewritten whole, so a diff shows all
    // three as added, and only one of them is. Attributed per file:
    // `docs/internals/testing.md` +1, every other internals page unchanged.
    // Raised 343 -> 346 by the uprobe capture page: three links into
    // src/capture/uprobe/ and src/capture/resolve.rs.
    // Raised 348 -> 349 by the rustdoc half of the non-Linux gate:
    // `internals/build-ci-release.md` gained one link, to
    // `src/capture/native.rs`, naming the file whose `capture::uprobe`
    // intra-doc links were green in CI forever and blocked every push from a
    // Mac. The paragraph explains why `scripts/check-non-linux.sh` now runs
    // `cargo doc` over the inverted tree and CI cannot substitute for it
    // (`ci.yml`'s Docs step is `if: runner.os == 'Linux'`), so the reader
    // needs the file the defect lived in. Added by
    // `scripts/link-repo-paths.py --apply`, which is what
    // `repo_paths_in_docs_are_clickable` demands. Attributed per file:
    // `docs/internals/build-ci-release.md` +1, every other internals page
    // unchanged.
    // Raised 349 -> 350 by the SBOM/notices paragraph in
    // `internals/build-ci-release.md`, which gained one link, to
    // `scripts/build-third-party-notices.py`. The paragraph now names the
    // generator because the feature set the notices are built from lives there
    // as `RELEASE_FEATURES`, and a reader asking why the SBOM says
    // `--features full,bpf` needs the other half of that pair. Attributed per
    // file: `docs/internals/build-ci-release.md` +1, every other internals page
    // unchanged.
    // Raised 350 -> 352 by the per-file reader threads in
    // `internals/threading.md`: the new thread-table row links `parallel.rs`,
    // and the new channel row links `shard_set_parallel()` in the same file.
    // Attributed per file: `docs/internals/threading.md` +2, every other
    // internals page unchanged.
    // Raised 352 -> 353 by the multi-file benchmark recipe in
    // `internals/profiling.md`, whose one link `scripts/link-repo-paths.py`
    // added to `bench/scaling.sh` — the recipe names the harness, and
    // `repo_paths_in_docs_are_clickable` demands a tracked path be a link
    // rather than something a reader retypes. Attributed per file:
    // `docs/internals/profiling.md` +1.
    //
    // 353 -> 354: correcting `docs/internals/testing.md`'s description of the
    // deleted WASM-bundle gate left a bare `wasm-pack` recipe path, which
    // `repo_paths_in_docs_are_clickable` then required as a link. One file,
    // one link, same mechanism as the entry above.
    // 354 -> 365: `docs/internals/rtpengine-control-plane.md`, one new page.
    // Four links are the module's own files plus
    // `pipeline::apply_relay_control_links`; the other seven came from
    // `scripts/link-repo-paths.py --apply`, which the sibling gate
    // `repo_paths_in_docs_are_clickable` demands for the fixtures, the test
    // file and the fuzz target the page names. Attributed per file before the
    // number moved: `docs/internals/rtpengine-control-plane.md` +11.
    // 365 -> 367: the prose gates moved into pre-commit and the hooks section
    // gained links to `scripts/prose-gates.sh` and `scripts/preflight.sh`.
    // Attributed by measurement before the number moved:
    // `docs/internals/build-ci-release.md` went 35 -> 37, and it is the only
    // page the change touched. Three link texts, two new targets -- the
    // `.githooks/pre-commit` link replaced a bare mention that was already
    // linked earlier on the page.
    // 367 -> 369: RE4 gave `src/rtpengine/` two more modules, and the module
    // layout table on `docs/internals/rtpengine-control-plane.md` names them:
    // `control.rs` (the two read-only requests and the client) and
    // `reconcile.rs` (the triggers, the port index and the bounds). Attributed
    // by measurement before the number moved: that page went 11 -> 13, and it
    // is the only page this change added a link to -- the other docs touched
    // had `#L` anchors re-pointed by `scripts/fix-line-anchors.py --apply`,
    // which moves citations without adding any.
    // 369 -> 378: RE4's active half reached the developer docs. Attributed by
    // measurement before the number moved, and only two pages moved:
    // `docs/internals/rtpengine-control-plane.md` 13 -> 19, which gained a
    // section on asking the relay plus a module-table row for
    // `src/app/relay_reconciler.rs`; and `docs/internals/threading.md`
    // 36 -> 39, which had claimed to list every long-lived thread while the
    // reconciler thread had no row, and claimed scanner-kill was the only
    // thread allowed to send.
    // 378 -> 377, DOWN by one, which this gate treats as suspicious and is
    // right to. Attributed by measurement: `docs/internals/build-ci-release.md`
    // went 37 -> 36 and is the only page that moved. The lost link is
    // `src/wasm.rs`, which that page cited while listing "a refusal to commit a
    // staged src/wasm.rs without a rebuilt bundle beside it" among the
    // pre-commit gates. That gate does not exist: hook section 7 is a
    // removal-rationale comment and runs nothing. The page named the right
    // COUNT of gates and the wrong eleven -- it also carried the removed 5c
    // man-page check and omitted 3b, the live privilege-drop gate. Dropping a
    // link to a file the prose no longer has a reason to mention is the
    // deletion working, not the extractor narrowing.
    // 377 -> 397: `docs/internals/vcon.md`, the vCon exporter page. Attributed
    // by measurement before the number moved: that page carries exactly 20
    // links into `src/` and `tests/`, and no other developer page gained one.
    // Fourteen of them point at `src/output/vcon.rs` itself -- the section
    // table names the builder for every vCon object, and a reader following one
    // row lands on the function rather than on the file's first line.
    // 397 -> 400: the conformance section of `docs/internals/vcon.md`, which
    // cites `json_text()`, the vendored working-group schema
    // (`tests/schemas/vcon.schema.json`) and the gate that validates against it
    // (`tests/vcon_ingest_contract_test.rs`). Attributed by measurement before
    // the number moved: that page gained exactly three links into `src/` and
    // `tests/`, and no other developer page gained one.
    // 400 -> 401 by one link: the section table in `internals/vcon.md` now has
    // a `parties[].tel` row, and it names `tel_uri()` as the builder rather
    // than restating the narrow rule the function documents. One row, one link,
    // one page.
    // 401 -> 402 by one link: the rtpengine control-plane page now names
    // `tests/hep_listen_ng_test.rs` while recording that `--hep-listen`
    // decoded nothing until 0.5.125, and the repo-path fixer linked it.
    // Attributed per file: `internals/rtpengine-control-plane.md` +1, every
    // other developer page unchanged.
    //
    // Then 402 -> 404 on the rebase: `internals/build-ci-release.md` now names
    // the feature-matrix gate and the workflow it reads its combos and flags
    // from. Both were bare code spans until `scripts/link-repo-paths.py
    // --apply` linked them, which is the fixer `repo_paths_in_docs_are_clickable`
    // names — one rule, one fixer. Two links, one page.
    //
    // Both branches bumped this and the values conflicted, so NEITHER side was
    // right: the merged tree carries both sets of links. The number below came
    // from re-running the gate on the merged tree, not from adding the two.
    // 404 -> 407: exactly three, all rows added to the file table in
    // `rtpengine-control-plane.md` -- `src/relay/mod.rs`, `src/relay/types.rs`
    // and `src/app/servers.rs`, the seam's declaration, vocabulary and
    // composition root.
    // 407 -> 408: one link, `internals/invariants.md` section 4 naming
    // `src/security/digest_leak.rs` for the nonce map's bound.
    // 408 -> 409: one more in the same section, `src/lru.rs`, the map the
    // detectors' per-source caps now evict through.
    const EXPECTED_CODE_LINKS: usize = 409;
    assert_eq!(
        seen, EXPECTED_CODE_LINKS,
        "code-link extraction found {seen} links, expected {EXPECTED_CODE_LINKS}. \
         More links is fine — bump this. FEWER means the extractor stopped \
         matching, and every assertion below it silently narrowed."
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
    /// Symbol claims the developer docs are expected to cite.
    // 66 -> 68: both from `docs/internals/threading.md`, which now cites
    // `relay_reconciler::spawn()` and `orphan_channel()` -- the spawn site and
    // the bounded hand-off it reads from. Both resolve to a definition, which
    // is what the assertion below this one checks.
    // 68 -> 86: `docs/internals/vcon.md` again, and the same 20 links -- 18 of
    // them carry a `()` symbol claim, because the page names the function that
    // builds each vCon section rather than describing it. Attributed by
    // measurement before the number moved: no other developer page gained a
    // claim. The two links without one are the module itself and
    // `tests/vcon_export_test.rs`.
    // Raised 86 -> 87 by the conformance section of `internals/vcon.md` naming
    // `json_text()` as the function that encodes every structured body to text,
    // so the paragraph states who enforces the spec's String rule rather than
    // leaving it to the reader to find. The other two functions that section
    // names, `dialog_object()` and `export_dialog_at()`, the page already
    // cited. Attributed per file: `internals/vcon.md` +1, every other developer
    // page unchanged.
    // Raised 87 -> 88 by that same `tel_uri()` citation — the only symbol the
    // developer docs gained. Attributed per file: `internals/vcon.md` +1, every
    // other developer page unchanged.
    const EXPECTED_SYMBOL_CLAIMS: usize = 88;
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
    // Raised 58 -> 62 by the `LK1` sub-rule in internals/invariants.md §2: all
    // four of its code links carry a `()` symbol claim
    // (`DeferredEffects::drain`, `EventExecEngine::dispatch_pending`,
    // `TumblingWindow::allows_with_reserved`, `process_parsed_packet`).
    // Raised 62 -> 65 by internals/threading.md naming the three spawn sites of
    // its auxiliary threads (`start_servers`, `build_resolver`,
    // `spawn_scanner_kill_worker`), so the page states who starts each thread
    // instead of implying the TUI event loop starts all of them.
    // Raised 65 -> 66 by the same page naming `shard_set_parallel()` as the
    // owner of the per-file reader queues, so the channel row says which
    // function bounds them. Attributed per file: `internals/threading.md` +1,
    // every other developer page unchanged.
    assert_eq!(
        seen, EXPECTED_SYMBOL_CLAIMS,
        "symbol extraction found {seen} claims, expected {EXPECTED_SYMBOL_CLAIMS}. \
         Bump when the \
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

/// Run a snippet of Python against the generators and parse its JSON.
///
/// Bound names: `w` build-wiki, `i` build-site-internals, `p` build-site-pages,
/// `l` link-repo-paths (the fixer), `lm` lib_markdown (the shared library).
///
/// They are imported, not read as text. Every gate below used to grep the
/// generator source, which made "the string appears twice in the file" the
/// proxy for "the page is registered" — and a commented-out entry
/// (`# "internals/threading.md",`), the single most likely way a nav entry
/// disappears, satisfies the count while registering nothing. Importing also
/// means a probe sees the pattern the script actually compiled, not the
/// characters its source happens to contain.
fn registries(expr: &str) -> serde_json::Value {
    let script = format!(
        "import importlib.util as u, json\n\
         def load(p, n):\n\
         \x20   s = u.spec_from_file_location(n, p); m = u.module_from_spec(s); \
         s.loader.exec_module(m); return m\n\
         w = load('scripts/build-wiki.py', 'w')\n\
         i = load('scripts/build-site-internals.py', 'i')\n\
         p = load('scripts/build-site-pages.py', 'p')\n\
         l = load('scripts/link-repo-paths.py', 'l')\n\
         lm = load('scripts/lib_markdown.py', 'lm')\n\
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
    /// Fewest sequence diagrams docs/internals may carry.
    const MIN_SEQUENCE_DIAGRAMS: usize = 17;
    let total: usize = internals_pages()
        .iter()
        .map(|p| mermaid_fences(&read(p)).len())
        .sum();
    assert!(
        total >= MIN_SEQUENCE_DIAGRAMS,
        "expected at least {MIN_SEQUENCE_DIAGRAMS} sequence diagrams across \
         docs/internals, found {total}"
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

/// Every OPERATOR page the generator writes is reachable from EVERY docs nav.
///
/// The sibling test above covers `docs/internals/` only, and the gap it leaves
/// is the same one it was written to close. Registering
/// `docs/sip-lint-rules.md` in `build-site-pages.py` produced a published page
/// that no anchor pointed at: `site_pages_mirror_is_current` was green, the
/// file existed, Zola rendered it, and the only route to it was a URL nobody
/// had. A page shipped where no reader can reach it is the defect this
/// repository keeps finding in its own code — a capability built, tested,
/// documented and not connected.
///
/// THREE navs, not one. The first version of this test read `base.html` alone
/// and passed while `sip-lint-rules.md` was missing from the sidebar in
/// `page.html` and `section.html` — the nav every reader actually uses once
/// they are inside the docs. A gate that checks one of two routes reports the
/// page as reachable and is worse than no gate, because it is believed. The
/// two navs are spelled differently on purpose here: the dropdown carries
/// `@/docs/<page>` anchors, the sidebar passes bare filenames to
/// `macros::nav_group(paths=[…])`, and matching one shape against the other
/// would silently find nothing.
///
/// Ground truth is `PAGES` in the generator, read out of the script rather
/// than restated, so a page added there has to appear in every nav or fail
/// here.
#[test]
fn every_site_operator_page_is_in_every_docs_nav() {
    let script = read("scripts/build-site-pages.py");
    // The site filename is the SECOND string of each PAGES tuple, on the line
    // after the `"docs/….md",` source path. Keyed off the source path so a
    // description mentioning a filename cannot be mistaken for an entry.
    let re =
        regex::Regex::new(r#""docs/[a-z0-9-]+\.md",\s*\n\s*"([a-z0-9-]+\.md)","#).expect("regex");
    let pages: Vec<String> = re
        .captures_iter(&script)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        pages.len() >= 18,
        "found only {} entries in build-site-pages.py PAGES — the tuple shape \
         changed and this gate is no longer reading the registry",
        pages.len()
    );

    // Nav 1: the header dropdown, one `<a>` per page.
    let base = markdown::blank_tera_comments(&read("website/templates/base.html"));
    let mut missing = Vec::new();
    for page in &pages {
        let path = format!("@/docs/{page}");
        let linked = base.lines().any(|l| {
            l.contains(&path) && l.contains("<a ") && l.contains("href=") && l.contains("get_url")
        });
        if !linked {
            missing.push(format!("base.html dropdown: {path}"));
        }
    }

    // Navs 2 and 3: the in-page sidebar, built from `nav_group(paths=[…])`
    // lists of bare filenames. Both templates carry their own copy of the
    // list, so a page added to one and not the other is reachable from a
    // section index and not from a page, or the reverse.
    // Both compiled once, outside the loop: `clippy::regex_creation_in_loops`
    // is denied by `--all-targets`, which the pre-commit clippy run does not
    // pass and CI does.
    let group_re = regex::Regex::new(r#"nav_group\([^)]*paths\s*=\s*\[([^\]]*)\]"#).expect("regex");
    let name_re = regex::Regex::new(r#""([a-z0-9-]+\.md)""#).expect("regex");
    for template in [
        "website/templates/page.html",
        "website/templates/section.html",
    ] {
        let src = markdown::blank_tera_comments(&read(template));
        let listed: std::collections::BTreeSet<String> = group_re
            .captures_iter(&src)
            .flat_map(|c| {
                name_re
                    .captures_iter(&c[1])
                    .map(|m| m[1].to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            listed.len() >= 18,
            "{template} yielded only {} sidebar entries — the nav_group call \
             shape changed and this gate is no longer reading the sidebar",
            listed.len()
        );
        for page in &pages {
            if !listed.contains(page) {
                missing.push(format!("{template} sidebar: {page}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "these generated operator pages are unreachable from a docs nav, so a \
         reader gets to them only by a URL they do not have. Add the page to \
         the dropdown in base.html AND to the matching nav_group in both \
         page.html and section.html:\n  {}",
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

/// The release-artifact counts must come from the build matrix.
///
/// `build-ci-release.md` described a tag as publishing "eight artifacts" and the
/// `noaudio` builds as a `.deb`-only variant. A release publishes twenty-three
/// assets, fourteen of them installable, and the `noaudio` builds ship an `.rpm`
/// too. Neither number had drifted: `noaudio` landed 2026-07-07 and gained `.rpm`
/// 2026-07-09, while the `.deb`-only sentence was written 2026-07-25 and the
/// artifact count 2026-07-29. Both were wrong on the day they were typed, by
/// counting matrix rows and calling the result artifacts.
///
/// Eight is the matrix. It stopped equalling the tarball count the moment a build
/// existed that produces packages and no tarball, and nothing connected the two
/// facts, so the prose was free to be confidently wrong. Derive them instead:
///
///   builds   — every `- target:` in the matrix
///   tarballs — those the `Package (tar.gz + checksum)` step does not skip
///   deb/rpm  — those whose target matches the packaging steps' `if`
///
/// Both packaging steps gate on the target alone, NOT on the variant, which is
/// precisely why the `noaudio` jobs ship both package formats. Reading their
/// conditions rather than assuming keeps this gate honest if that ever changes.
#[test]
fn release_artifact_counts_match_the_build_matrix() {
    // The doc spells these out, so the gate reads its words and compares
    // numbers. The first version did the reverse — formatted each derived count
    // into a word and string-matched it — which meant a count landing outside
    // the word list panicked about the list instead of naming the stale
    // sentence. Adding one build was enough: it takes the asset total to 25.
    // Parsing this direction, an unlisted word is the doc's problem to state
    // differently, and every failure names the number that is wrong.
    const WORDS: [&str; 21] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];
    // "twenty-three" and friends, so the doc can keep house style past twenty.
    let parse_word = |w: &str| -> Option<usize> {
        if let Some(n) = WORDS.iter().position(|x| *x == w) {
            return Some(n);
        }
        let (tens, units) = w.split_once('-')?;
        let tens = match tens {
            "twenty" => 20,
            "thirty" => 30,
            "forty" => 40,
            _ => return None,
        };
        let units = WORDS.iter().position(|x| *x == units).filter(|u| *u < 10)?;
        Some(tens + units)
    };

    let yaml = read(".github/workflows/release.yml");

    // The matrix block: `include:` up to the blank line before `steps:`.
    let block = yaml
        .split_once("      matrix:\n        include:\n")
        .expect("release.yml has no build matrix")
        .1;
    let block = &block[..block.find("\n\n").unwrap_or(block.len())];

    // One entry per `- target:`. Splitting on the marker drops the text before
    // the first one, which is empty by construction here.
    let entries: Vec<&str> = block.split("- target: ").skip(1).collect();
    assert!(
        entries.len() >= 4,
        "parsed only {} matrix entries — the matrix layout changed and this gate \
         is no longer reading it:\n{block}",
        entries.len()
    );

    let target_of = |e: &str| e.lines().next().unwrap_or("").trim().to_string();
    let is_noaudio = |e: &&str| e.contains("variant: noaudio");

    // Tarballs come from every build the packaging step does not skip.
    let pkg = yaml
        .split_once("      - name: Package (tar.gz + checksum)\n")
        .expect("release.yml no longer has the tar.gz packaging step")
        .1;
    let pkg_if = pkg.lines().next().unwrap_or("").trim();
    assert_eq!(
        pkg_if, "if: matrix.variant != 'noaudio'",
        "the tar.gz step's condition changed to `{pkg_if}` — this gate assumes \
         it skips exactly the noaudio builds"
    );

    // Packages come from the gnu targets, both variants: the condition names
    // targets and never mentions `variant`.
    let deb_if = yaml
        .split_once("      - name: Build .deb (gnu Linux targets)\n")
        .expect("release.yml no longer builds .deb")
        .1
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let rpm_if = yaml
        .split_once("      - name: Build .rpm (gnu Linux targets)\n")
        .expect("release.yml no longer builds .rpm")
        .1
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    assert_eq!(
        deb_if, rpm_if,
        "the .deb and .rpm steps no longer share a condition, so the doc cannot \
         state one count for both"
    );
    assert!(
        !deb_if.contains("variant"),
        "the packaging condition now mentions `variant` (`{deb_if}`) — the \
         noaudio builds may no longer ship packages, and the doc's claim that \
         they ship a .deb and an .rpm needs rewriting, not just recounting"
    );
    let pkg_targets: Vec<&str> = deb_if
        .split("matrix.target == ")
        .skip(1)
        .filter_map(|s| s.split('\'').nth(1))
        .collect();
    assert!(
        !pkg_targets.is_empty(),
        "could not read any target out of the packaging condition `{deb_if}`"
    );

    let builds = entries.len();
    let tarballs = entries.iter().filter(|e| !is_noaudio(e)).count();
    let packages = entries
        .iter()
        .filter(|e| pkg_targets.contains(&target_of(e).as_str()))
        .count();
    // Every tarball carries a sibling .sha256; then SHA256SUMS.txt and 2 SBOMs.
    let installable = tarballs + packages * 2;
    let assets = tarballs * 2 + packages * 2 + 1 + 2;

    // Normalize: the prose is hard-wrapped, so every claim spans line breaks.
    // Lowercased too — these counts appear mid-sentence and at sentence starts,
    // and a gate that fails on a capital letter teaches people to reword rather
    // than recount.
    let doc = read("docs/internals/build-ci-release.md");
    let flat = doc
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    // (what it counts, pattern whose captures are number words, expected)
    let w = r"([a-z]+(?:-[a-z]+)?)";
    let claims: &[(&str, String, Vec<usize>)] = &[
        (
            "builds in the matrix",
            format!(r"a matrix of {w} builds"),
            vec![builds],
        ),
        (
            "the artifact breakdown",
            format!(r"{w} installable artifacts \({w} `\.tar\.gz`, {w} `\.deb`, {w} `\.rpm`\)"),
            vec![installable, tarballs, packages, packages],
        ),
        (
            "the asset total",
            format!(r"{w} release assets in all"),
            vec![assets],
        ),
        (
            "the builds-vs-tarballs contrast",
            format!(r"{w} builds, {w} tarballs"),
            vec![builds, tarballs],
        ),
    ];

    for (what, pattern, expected) in claims {
        let re = regex::Regex::new(pattern).expect("claim pattern");
        let caps = re.captures(&flat).unwrap_or_else(|| {
            panic!(
                "docs/internals/build-ci-release.md no longer states {what} in the \
                 form this gate reads (/{pattern}/). The matrix has {builds} builds \
                 producing {tarballs} tarballs and {packages} of each package format \
                 — {installable} installable, {assets} assets. Restate it or update \
                 the pattern; do not delete the claim."
            )
        });
        let found: Vec<usize> = (1..=expected.len())
            .map(|i| {
                let word = caps.get(i).map(|m| m.as_str()).unwrap_or("");
                parse_word(word).unwrap_or_else(|| {
                    panic!(
                        "docs/internals/build-ci-release.md writes \"{word}\" in \
                         {what}, which is not a number word this gate can read. \
                         Expected {expected:?} for that sentence."
                    )
                })
            })
            .collect();
        assert_eq!(
            &found, expected,
            "docs/internals/build-ci-release.md states {found:?} for {what}, but \
             release.yml's matrix produces {expected:?} — {builds} builds, \
             {tarballs} tarballs, {packages} of each package format, \
             {installable} installable, {assets} assets"
        );
    }
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

/// A line citation still points at the code its sentence names.
///
/// The two sibling gates check weaker things and both pass while a citation is
/// wrong. `linked_code_targets_exist` proves the FILE exists;
/// `cited_line_numbers_link_to_the_line` proves the link carries an `#L`
/// fragment so the click lands somewhere specific. Neither reads the line. So
/// `maintainability-perf-spec.md` could cite `src/main.rs:1996` in a file 172
/// lines long, and `icid-correlation.md` could send a reader to
/// `find_correlated_scored` at :935 when it sat at :981 — a precise, confident
/// link to unrelated code, which is worse than no link at all. The reader has
/// no reason to doubt it.
///
/// # Why this shells out instead of reimplementing the rule
///
/// `scripts/check-line-drift.py` is the single implementation, and it is also
/// the fixer (`--apply`). Writing the check again in Rust would create two
/// statements of one rule that agree today, which is exactly the divergence
/// found between `repo_paths_in_docs_are_clickable` and
/// `scripts/link-repo-paths.py`: the fixer there would have produced 33 links
/// the gate never asked for, because each had its own idea of the rule. A gate
/// and its fixer must derive from one rule; the cheapest way to guarantee that
/// is for there to be only one.
#[test]
fn line_citations_point_at_the_code_they_name() {
    let out = std::process::Command::new("python3")
        .arg("scripts/check-line-drift.py")
        .current_dir(repo())
        .output()
        .expect("run scripts/check-line-drift.py");
    let report = String::from_utf8_lossy(&out.stdout);

    // Anti-vacuity. The checker only examines citations whose prose names a
    // symbol DEFINED in the cited file, and that filter is deliberately narrow
    // — an earlier version matched any nearby word and reported `src`, `cli`
    // and `to_vec` as drifted symbols. Narrow can become empty, and an empty
    // checker exits 0 forever, so the count is pinned rather than trusted.
    let checked: usize = report
        .lines()
        .find_map(|l| {
            l.strip_prefix("checked ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("the checker must report how many citations it checked");
    // Exact, not a floor — the same rule `linked_code_targets_exist` learned
    // above, and for the same reason. A floor of 40 sat so far under the truth
    // that it could not see the checker go blind: it read 59 while 296
    // citations existed. The other 237 were not all uncheckable — 138 were
    // dropped because the LABEL is a basename (`dialog_store.rs:595`) or a
    // path relative to `src/` (`tui/mod.rs:145`), neither of which resolves
    // from the repo root. Nothing else covered them: `linked_code_targets_exist`
    // skips any `http` target and these are absolute `blob/` URLs. Resolving a
    // citation through its LINK instead (`source_for` in
    // scripts/check-line-drift.py) took this 59 -> 140 and immediately found 63
    // drifted citations across eleven design pages — `export_capture` cited at
    // server.rs:2136 while it lives at 5018 — all repaired in the same change.
    //
    // Two attribution bugs had to be fixed before any of that could be trusted,
    // and both were found by re-reading what the fixer had written rather than
    // by the gate going red. Ranking candidate symbols by raw distance let the
    // NEXT citation's subject win and rewrote correct citations; the subject
    // always precedes its citation, so `before` now wins outright. And reading
    // only the first segment of `Type::member` pointed the fix at the type —
    // `HepSender::send` would have moved from a wrong 1741 to a wrong 1860
    // instead of 2035. Bump when the corpus grows; never lower it to make a
    // build pass.
    //
    // 140 -> 141 on 2026-08-14, attributed per file before moving: the whole
    // increase is ONE citation in docs/design/backlog.md, from the new `TK`
    // section (TLS key acquisition without the daemon's cooperation) and its
    // `CFG1` neighbor. No other file's count changed, and the checker resolves
    // the new citation cleanly — measured by running scripts/check-line-drift.py
    // with and without that edit stashed: 141 against 140.
    // Raised 141 -> 190 by docs/design/simultaneous-capture-sources.md, the
    // SRC1 design, which is the only file that grew. Attributed by counting:
    // 190 - 49 = 141 exactly, and every one of the 49 is in that document.
    // It cites the capture sources, the SDP correlation path and the transmit
    // guard heavily on purpose — the design's central claim is that the
    // correlation SRC1 calls the hard part is already implemented, and a claim
    // like that is only checkable if it names the code making it true.
    // Raised 190 -> 192 by TWO independent citations landing in the same
    // release, one per branch, each of which measured +1 on its own:
    //
    //   * docs/design/live-fanout.md §6 cites `shard_for` at src/parallel.rs:72
    //     while recording that the OFFLINE engine shards on the address pair and
    //     therefore never had the SIP/media split CT11 was written to fix.
    //   * docs/design/simultaneous-capture-sources.md §8.1 cites
    //     `resolve_from_sdp`, added because the SRC1 measurement produced a
    //     caveat about matching BOTH ends of a stream's socket pair, and the
    //     claim "sipnab already does this" is only checkable if it names the
    //     function that does.
    //
    // Both branches wrote 191 and both were right in isolation. Merged, 191 is
    // wrong -- and two identical bumps are exactly the kind that reconcile
    // without a conflict and leave a gate certifying a count nobody holds. This
    // one is re-MEASURED on the merged tree (scripts/check-line-drift.py), not
    // added up from the two claims.
    //
    // The number is bound rather than written twice. It used to appear as a
    // pinned count in the assert and a stale 141 in the message under it, so the
    // gate's own explanation named a count that had not been true for two
    // moves -- the reader most in need of it is the one who just made it wrong.
    //
    // 192 -> 193 on 2026-08-26, attributed by measurement before the number
    // moved: 192 with the edit stashed and 193 with it, and the edit is ONE
    // sentence in docs/design/simultaneous-capture-sources.md. That sentence
    // cited src/pipeline.rs:2165 -- unrelated code, ~200 lines from the truth
    // and stale long before the move that exposed it -- and named no symbol the
    // checker could resolve, so it was SKIPPED rather than reported. The
    // nearest identifier before it was `media`, out of `(ip, port, call_id,
    // media)`, which pipeline.rs does not define. Naming `process_packet` and
    // citing its definition is what makes the claim checkable from here on: the
    // corpus grew by one because a citation stopped being invisible, not
    // because a page did.
    // 198 -> 199: the PB batch. One added citation names a symbol this checker
    // resolves; the rest of the batch's new links point at files or line
    // numbers rather than at a resolvable symbol, which this gate deliberately
    // does not count.
    // 197 -> 198: closing SRC1, SRC2 and REL1 in the backlog. Attributed by
    // differential measurement, not by counting links: with HEAD's backlog.md
    // in place the checker examines 197 and with the new one 198, and removing
    // each candidate citation in turn identifies the single one that moved it.
    // Three line citations were added -- `src/app/bootstrap.rs:539`,
    // `src/sip/diagnosis.rs:443` and `src/output/call_report.rs:209` -- and
    // exactly ONE counts. Line 443 is `pub agreed: usize`, a field this checker
    // resolves; the other two name local bindings inside function bodies
    // (`let composite = ...` and `if let Some(s) = ...`), which it deliberately
    // does not resolve. So the delta is +1, not +3, and a +3 here would have
    // meant the symbol extraction had WIDENED rather than that the corpus grew.
    // 193 -> 197: the conditional-content-persistence design. Attributed by
    // measurement rather than by counting links: with that file moved aside
    // this gate passes at 193 and with it present it examines 197, so the
    // document accounts for the whole delta. It carries six line citations,
    // four of which name a symbol this checker can resolve -- the other two
    // cite a line without naming anything at it, which is exactly the shape
    // the comment above says gets SKIPPED rather than reported.
    // 199 -> 200: the 0.5.131 batch. Attributed by differential measurement,
    // and the first measurement was WRONG in an instructive way. The obvious
    // suspect was the new backlog entries, which add line citations of their
    // own -- but swapping HEAD's backlog.md in and out leaves the count at 200
    // both ways, and restoring ALL 22 changed docs to HEAD still yields 200.
    // No doc change moved it.
    //
    // The delta is a SOURCE change. This gate counts citations that name a
    // symbol it can resolve, so adding a symbol makes a citation that already
    // existed start counting. The batch adds 237 symbols across src/, many
    // named by citations HEAD's docs already carried. The corpus of resolvable
    // citations grew without a single new link being written, which is a shape
    // worth remembering: "attribute the new citations" can have the answer
    // "there are none, and the count is still right".
    // 200 -> 201: one citation, added by `scripts/link-repo-paths.py --apply`
    // rather than by hand. The VAL5 backlog entry named `src/expect.rs:334` as
    // a bare code span, which `repo_paths_in_docs_are_clickable` correctly
    // refuses; the fixer turned it into a link, and a link naming a symbol is
    // what this gate counts. So one gate's fix is another gate's new corpus
    // entry, and running the two fixers in either order leaves this number to
    // be moved by hand afterwards.
    // 201 -> 203: two citations written by hand into the DOC section, both
    // naming a symbol this checker resolves — `src/output/api.rs:1118`
    // (`decode_dialog_audio`, the call that contradicts the "no media" promise
    // on the REST page) and `src/privilege.rs:44` (`is_root`, the precondition
    // that makes `--user` a no-op). Unlike the 199 -> 200 move, these really
    // are new citations: the DOC entries cite the source lines that contradict
    // the documentation, which is the whole point of the entries.
    //
    // 203 -> 204 -> 203: REG1 added `src/sip/dialog.rs:72` when it was filed,
    // and closing it removed the citation again — the entry no longer needs to
    // point at `DialogState::Registered` because the premise it rested on was
    // wrong. `Expired` existed all along; nothing could reach it. Attributed
    // against HEAD both times.
    // 203 -> 204: FLT1 cites both halves of the filter-vocabulary split it
    // reports -- `src/app/bootstrap.rs:2157`, where `--filter` expands an
    // alias, and `src/app/batch.rs:5434`, where `--export-vcon-when` parses
    // raw. TWO citations were added and the count moves by ONE, which is this
    // checker working as documented: it counts a citation only where it can
    // resolve the line to a symbol, and one of the two lands on a line inside
    // a function body rather than at one it extracts. Attributed against
    // HEAD: the staged diff adds exactly these two `#L` anchors and removes
    // none.
    let expected = 204;
    assert_eq!(
        checked, expected,
        "the drift checker examined {checked} citations, not the {expected} \
         this tree holds. FEWER means its resolution or symbol-extraction \
         narrowed and the gate is proving less than it claims — fix that rather \
         than moving this number. MORE means the corpus grew: attribute the new \
         citations, then raise it.\n{report}"
    );

    assert!(
        out.status.success(),
        "a documented line citation no longer points at the code it names.\n{report}\n\
         Run `python3 scripts/check-line-drift.py --apply` to re-point the ones \
         with a single unambiguous definition; the rest name a symbol that has \
         moved, been deleted, or has two definitions, and need a person."
    );
}

/// One page of citations, written where `--apply` may rewrite it.
///
/// A fixture, never a repo page: `--apply` EDITS what it is given, and a test
/// that hands it `docs/` would repair the tree as a side effect of running --
/// leaving the gate green because the test fixed it, which is the shape of a
/// gate proving nothing. The cited source resolves against the repository, so
/// the fixture still names real code at a real line.
fn citation_fixture(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let page = dir.join(name);
    std::fs::write(&page, body).expect("write the citation fixture");
    page
}

/// Run the checker over named pages and return (exit ok, stdout).
fn drift_check(pages: &[&std::path::Path], apply: bool) -> (bool, String) {
    let mut cmd = std::process::Command::new("python3");
    cmd.arg("scripts/check-line-drift.py").current_dir(repo());
    if apply {
        cmd.arg("--apply");
    }
    for p in pages {
        cmd.arg(p);
    }
    let out = cmd.output().expect("run scripts/check-line-drift.py");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

/// What `--apply` writes, the gate accepts.
///
/// The gate half of this script is exercised on every commit; the FIXER half
/// was exercised by nobody. That is the arrangement this repo has already been
/// bitten by -- `repo_paths_in_docs_are_clickable` against
/// `scripts/link-repo-paths.py`, where the fixer produced 33 links the gate
/// never asked for -- and "one implementation" is an argument that they cannot
/// diverge, not evidence that the fixer works at all. A fixer whose output the
/// gate rejects is unfixable by design, and the only way to know is to run the
/// repair and then re-run the check over the same page.
///
/// Break the `_repoint` rewrite of either the label or the `#L` fragment and
/// the second check below fails: the two must move together or the link and
/// the text it labels disagree.
#[test]
fn what_the_fixer_writes_the_gate_accepts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let page = citation_fixture(
        dir.path(),
        "drifted.md",
        "`process_packet` ([`src/pipeline.rs:1`](https://github.com/NormB/sipnab/blob/main/src/pipeline.rs#L1)) applies one packet.\n",
    );

    let (ok, report) = drift_check(&[&page], false);
    assert!(
        !ok,
        "a citation 2000 lines from its symbol must be reported, not passed:\n{report}"
    );
    assert!(
        report.contains("process_packet"),
        "the report must name the symbol whose citation drifted:\n{report}"
    );

    let (_, applied) = drift_check(&[&page], true);
    assert!(
        applied.contains("re-pointed 1 citation(s)"),
        "the fixer must repair a citation with one unambiguous definition:\n{applied}"
    );

    let repaired = std::fs::read_to_string(&page).expect("read the repaired page");
    let (ok, report) = drift_check(&[&page], false);
    assert!(
        ok,
        "the gate rejected what its own fixer wrote:\n{report}\n{repaired}"
    );
    assert!(
        !repaired.contains("src/pipeline.rs:1`") && !repaired.contains("#L1)"),
        "the label and the link fragment must BOTH move, or they disagree \
         about the same citation:\n{repaired}"
    );
}

/// A citation past the end of its file is reported as that, not as drift.
///
/// The out-of-range branch answers a different question from the drift one --
/// "this file is not that long" rather than "the symbol is elsewhere" -- and it
/// is the branch that catches a citation into a file that SHRANK, which is what
/// `maintainability-perf-spec.md` did when it cited `src/main.rs:1996` in a
/// file of 172 lines. Nothing exercised it: every citation in the tree happens
/// to be in range, so the branch could have been deleted and the suite would
/// not have noticed.
#[test]
fn a_citation_past_the_end_of_the_file_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let page = citation_fixture(
        dir.path(),
        "beyond-eof.md",
        "`process_packet` ([`src/pipeline.rs:999999`](https://github.com/NormB/sipnab/blob/main/src/pipeline.rs#L999999)) applies one packet.\n",
    );

    let (ok, report) = drift_check(&[&page], false);
    assert!(!ok, "a citation past EOF must fail the gate:\n{report}");
    assert!(
        report.contains("but that file has") && report.contains("lines"),
        "the report must say the file is not that long, rather than reporting \
         it as ordinary drift -- they send the reader to different places:\n{report}"
    );
}
