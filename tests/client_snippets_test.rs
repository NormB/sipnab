// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every Go, JavaScript, Python, Rust and TypeScript snippet in the REST,
//! metrics and MCP deployment references, and on the site's own client page,
//! is cut from a program CI compiles and runs.
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
    "docs/client-examples.md",
    // Written for the site alone: no docs/ page generates it, so the page
    // itself is the source (tests/dev_docs_drift_test.rs derives that).
    "website/content/docs/api-clients.md",
];

/// Fences a page still shows that no program holds yet, as `(doc, lang)`.
/// The Python examples on the client page import `requests` and `httpx`,
/// which nothing in CI installs, and two of them poll forever; holding them
/// means pinning those libraries by hash or rewriting the examples, which
/// is its own backlog item. The inventory test below still counts them, so
/// a new fence here cannot join them unnoticed.
const NOT_YET_HELD: &[(&str, &str)] = &[];

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
    "rust",
    "rs",
    "typescript",
    "ts",
];

/// The directories whose programs carry regions.
const CLIENT_TREES: &[&str] = &[
    "clients/go",
    "clients/javascript",
    "clients/python",
    "clients/rust",
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
        .filter(|f| !NOT_YET_HELD.contains(&(f.doc, f.lang.as_str())))
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
        // The capability examples: leg_correlate.py's join, vcon_validate.py's
        // check and hep_senders.py's roster. Then one region from each of the
        // five operator-task programs. Then the four AI-task regions (EX7):
        // agent_triage.py's verdict, mcp_calls.py's signed HTTP session,
        // evidence_handoff.py's package check and aggregate_for_model.py's
        // bound.
        ("docs/client-examples.md", "python", 12),
        // The site's client page (EX4b): one whole program per language, the
        // Go, TypeScript and Rust ones held to clients/, and the four Python
        // ones NOT_YET_HELD names.
        ("website/content/docs/api-clients.md", "go", 1),
        ("website/content/docs/api-clients.md", "python", 4),
        ("website/content/docs/api-clients.md", "rust", 1),
        ("website/content/docs/api-clients.md", "typescript", 1),
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
        // Rust: clients/rust is a workspace member, so the Clippy step
        // compiles it with every warning an error, and the audit job's
        // `cargo deny check` and `cargo audit` read the one Cargo.lock that
        // pins its dependencies.
        "cargo clippy --workspace --all-features --all-targets -- -D warnings",
        "cargo deny check",
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

/// The site's client page: each program it shows in full, and how
/// scripts/smoke-clients.sh runs it against the replayed capture.
const SITE_CLIENTS: &[(&str, &str)] = &[
    ("clients/go/sipnab-client/main.go", "$WORK/go/sipnab-client"),
    (
        "clients/typescript/sipnab-client.ts",
        "clients/typescript/sipnab-client.ts",
    ),
    ("clients/rust/src/main.rs", "--package sipnab-client"),
];

/// Every program the site's client page shows is marked on it, and the smoke
/// run starts each one. A program that compiles but never meets a server
/// could still print a zero value on a wrong token.
#[test]
fn every_site_client_runs_against_a_replayed_capture() {
    let smoke: String = read("scripts/smoke-clients.sh")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    let page = read("website/content/docs/api-clients.md");
    let mut missing = Vec::new();
    for (program, run) in SITE_CLIENTS {
        if !page.contains(&format!("{MARKER_OPEN}{program}#")) {
            missing.push(format!(
                "website/content/docs/api-clients.md shows no region of {program}"
            ));
        }
        if !contains_token(&smoke, run) {
            missing.push(format!(
                "scripts/smoke-clients.sh does not run {program} ({run})"
            ));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

/// The Rust program is a member of the workspace, which is what puts it under
/// the Clippy step, cargo-deny and cargo-audit, and the dependencies its
/// region tells a reader to add are the ones its manifest declares. The page
/// once listed three crates and the program used five.
#[test]
fn the_rust_client_is_a_workspace_member_and_its_region_names_its_dependencies() {
    let root = read("Cargo.toml");
    let members = root
        .lines()
        .find(|l| l.starts_with("members = "))
        .expect("the root Cargo.toml lists its workspace members");
    assert!(
        members.contains("\"clients/rust\""),
        "clients/rust is not a workspace member: {members}"
    );
    let manifest = read("clients/rust/Cargo.toml");
    let deps: BTreeSet<String> = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("clients/rust/Cargo.toml has a [dependencies] table")
        .lines()
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| l.trim().to_string())
        .collect();
    let program = region(&read("clients/rust/src/main.rs"), "sipnab-client")
        .expect("clients/rust/src/main.rs has the sipnab-client region");
    let shown: BTreeSet<String> = program
        .lines()
        .take_while(|l| l.starts_with("//"))
        .filter_map(|l| l.strip_prefix("//   "))
        .map(|l| l.trim().to_string())
        .collect();
    assert_eq!(
        shown, deps,
        "the dependency lines at the top of the region must be \
         clients/rust/Cargo.toml's [dependencies], one per `//   ` line"
    );
}

/// Whether `needle` occurs in `text` as a whole token: not followed by a
/// character that would make it a longer flag or path, so `--hep-send` is not
/// found in `--hep-sendX` or `--hep-send-transport`.
fn contains_token(text: &str, needle: &str) -> bool {
    text.match_indices(needle).any(|(at, _)| {
        !text[at + needle.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    })
}

/// The capability examples: what sipnab does that a generic SIP tool does
/// not, each run end to end in CI rather than described. Leg correlation
/// needs two sipnabs, HEP fan-in a collector and its agents, vCon validation
/// the publisher's schema file, and TLS without keys the BPF record decode.
/// Each line here is a piece that, removed from the smoke run or the build,
/// turns its example back into a claim.
#[test]
fn every_capability_example_runs_in_ci() {
    // Code only: a comment naming a flag is not a command running it.
    let smoke: String = read("scripts/smoke-clients.sh")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    let missing: Vec<&str> = [
        // Leg correlation: one call, the proxy's capture and the relay's.
        "clients/python/leg_correlate.py",
        "tests/fixtures/opensips-proxy-signaling.pcap",
        "tests/fixtures/rtpengine-opensips-ng.pcap",
        // vCon validated against the publisher's file.
        "clients/python/vcon_validate.py",
        "--export-vcon",
        "tests/schemas/publisher/vcon_json_schema.json",
        // HEP fan-in: a collector and agents sending to it.
        "--hep-listen",
        "--hep-send",
        "clients/python/hep_senders.py",
        // TLS without keys: the analysis half.
        "examples/tls_plaintext_records",
    ]
    .into_iter()
    .filter(|needle| !contains_token(&smoke, needle))
    .collect();
    assert!(
        missing.is_empty(),
        "scripts/smoke-clients.sh no longer runs: {missing:?}"
    );
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("cargo build --all-features --bins --examples"),
        "ci.yml's Build step must build the examples, or the smoke run has no \
         tls_plaintext_records to run"
    );
    let page = read("docs/client-examples.md");
    for program in [
        "leg_correlate.py",
        "vcon_validate.py",
        "hep_senders.py",
        "tls_plaintext_records.rs",
    ] {
        assert!(
            page.contains(program),
            "docs/client-examples.md does not tell an operator about {program}"
        );
    }
}

/// The operator tasks: one program per multi-step cookbook recipe, each
/// linked from the recipes it carries out and run end to end in CI. `anchor`
/// is the program's section of docs/client-examples.md, and `recipes` the
/// numbered sections of docs/examples.md that point at it.
const OPERATOR_TASKS: &[(&str, &str, &[u32])] = &[
    (
        "clients/python/triage.py",
        "triage-a-capture-to-one-verdict",
        &[1, 16],
    ),
    (
        "clients/python/failed_calls.py",
        "group-failed-calls-by-response-code",
        &[3, 30],
    ),
    (
        "clients/python/one_way_audio.py",
        "diagnose-one-way-audio-and-whose-loss-it-is",
        &[4, 11, 22],
    ),
    (
        "clients/python/scanner_ban.py",
        "ban-a-scanner-through-tfps-and-verify-it",
        &[10, 23],
    ),
    (
        "clients/python/customer_export.py",
        "export-the-calls-of-one-customer-from-rotated-captures",
        &[39, 32, 40],
    ),
];

/// The text of cookbook section `n`: from its `## n.` heading to the next
/// second-level heading, subsections included.
fn cookbook_section(cookbook: &str, n: u32) -> Option<String> {
    let heading = format!("## {n}. ");
    let start = cookbook.lines().position(|l| l.starts_with(&heading))?;
    let body: Vec<&str> = cookbook
        .lines()
        .skip(start + 1)
        .take_while(|l| !l.starts_with("## "))
        .collect();
    Some(body.join("\n"))
}

/// Each operator task is a program CI runs against committed captures, a
/// section on the runnable-examples page, and a pointer from every recipe it
/// carries out. Removing any of the three turns the task back into a claim:
/// a program nobody runs, a program nobody finds, or a recipe that stops at
/// the first command.
#[test]
fn every_operator_task_runs_in_ci_and_is_linked_from_its_recipes() {
    let smoke: String = read("scripts/smoke-clients.sh")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    let mut missing: Vec<String> = [
        // The captures the tasks run against, beside the older ones.
        "tests/fixtures/sip-answered-never-acked.pcap",
        "tests/fixtures/sip-scanner-and-register-flood.pcap",
        "tests/pcap-samples/sip-problem-call.pcap",
        "tests/fixtures/stun_sdp_mismatch.pcap",
        // Recipe 30's timer, which the answered-never-acked capture needs.
        "--ack-timeout",
        // The TFPS peer the ban is relayed to, and the fake standing in for it.
        "--tfps-ctl",
        "clients/python/tests/fake_tfps_ctl.py",
        // Recipe 40: the export opened by Wireshark's own engine.
        "capinfos",
        "tshark",
    ]
    .into_iter()
    .filter(|needle| !contains_token(&smoke, needle))
    .map(str::to_string)
    .collect();
    for (program, _, _) in OPERATOR_TASKS {
        if !contains_token(&smoke, program) {
            missing.push((*program).to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "scripts/smoke-clients.sh no longer runs: {missing:?}"
    );

    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("packages: tshark"),
        "ci.yml must install tshark before the smoke run, or recipe 40's check has \
         nothing to open the export with"
    );

    let page = read("docs/client-examples.md");
    let cookbook = read("docs/examples.md");
    let mut unlinked = Vec::new();
    for (program, anchor, recipes) in OPERATOR_TASKS {
        let name = program.rsplit('/').next().expect("a file name");
        let heading_slug_present = page
            .lines()
            .filter(|l| l.starts_with("### "))
            .any(|l| markdown_slug(l.trim_start_matches('#').trim()) == *anchor);
        if !heading_slug_present || !page.contains(name) {
            unlinked.push(format!(
                "docs/client-examples.md has no `### ` section slugged {anchor} describing {name}"
            ));
        }
        let link = format!("client-examples.md#{anchor}");
        for n in *recipes {
            match cookbook_section(&cookbook, *n) {
                None => unlinked.push(format!("docs/examples.md has no recipe {n}")),
                Some(text) if !text.contains(&link) => unlinked.push(format!(
                    "docs/examples.md recipe {n} does not link {link} ({name})"
                )),
                Some(_) => {}
            }
        }
    }
    assert!(unlinked.is_empty(), "{}", unlinked.join("\n"));
}

/// The AI tasks: what an agent does with sipnab over MCP, each a program CI
/// runs against committed captures. `anchor` is the program's section of
/// docs/client-examples.md, which docs/mcp.md links so a reader of the MCP
/// guide finds the program that exercises it. `agent_triage.py` has two
/// sections, one per transport, because the HTTP one is a separate check.
const AI_TASKS: &[(&str, &str)] = &[
    (
        "clients/python/agent_triage.py",
        "triage-a-capture-over-mcp-as-an-agent",
    ),
    (
        "clients/python/agent_triage.py",
        "reach-a-production-box-over-http-with-a-signed-token",
    ),
    (
        "clients/python/evidence_handoff.py",
        "hand-an-agent-an-evidence-package-and-a-repro-script",
    ),
    (
        "clients/python/aggregate_for_model.py",
        "aggregate-dialogs-into-bounded-json-for-a-model",
    ),
];

/// Each AI task runs in CI, has its section, and is linked from the MCP
/// guide. The flags are the pieces that make the checks what they claim:
/// an HTTP server with a signing key and a token minted from it (the shape
/// recipe 55 deploys), and a file root for the evidence package. Without
/// them the HTTP check would be a stdio check with a different name.
#[test]
fn every_ai_task_runs_in_ci_and_is_linked_from_the_mcp_guide() {
    let smoke: String = read("scripts/smoke-clients.sh")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    let mut missing: Vec<String> = [
        "--mcp-transport",
        "--mcp-signing-key-file",
        "--mint-token",
        // evidence_handoff.py's root, which it passes on as --mcp-file-root.
        "--file-root",
    ]
    .into_iter()
    .filter(|needle| !contains_token(&smoke, needle))
    .map(str::to_string)
    .collect();
    for (program, _) in AI_TASKS {
        if !contains_token(&smoke, program) {
            missing.push((*program).to_string());
        }
    }
    if !read("clients/python/evidence_handoff.py").contains("\"--mcp-file-root\"") {
        missing.push("evidence_handoff.py starting sipnab with --mcp-file-root".to_string());
    }
    missing.dedup();
    assert!(
        missing.is_empty(),
        "scripts/smoke-clients.sh no longer runs: {missing:?}"
    );

    let page = read("docs/client-examples.md");
    let guide = read("docs/mcp.md");
    let mut unlinked = Vec::new();
    for (program, anchor) in AI_TASKS {
        let name = program.rsplit('/').next().expect("a file name");
        let section_present = page
            .lines()
            .filter(|l| l.starts_with("### "))
            .any(|l| markdown_slug(l.trim_start_matches('#').trim()) == *anchor);
        if !section_present || !page.contains(name) {
            unlinked.push(format!(
                "docs/client-examples.md has no `### ` section slugged {anchor} describing {name}"
            ));
        }
        let link = format!("client-examples.md#{anchor}");
        if !guide.contains(&link) {
            unlinked.push(format!("docs/mcp.md does not link {link} ({name})"));
        }
    }
    assert!(unlinked.is_empty(), "{}", unlinked.join("\n"));
}

/// The anchor a heading gets: lowercase, spaces to hyphens, and every other
/// character that is not alphanumeric, `-` or `_` dropped.
fn markdown_slug(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
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
fn a_token_is_matched_whole() {
    assert!(contains_token("x --hep-send 127.0.0.1", "--hep-send"));
    assert!(contains_token("ends with --hep-send", "--hep-send"));
    assert!(!contains_token("x --hep-sendX y", "--hep-send"));
    assert!(!contains_token("x --hep-send-transport tcp", "--hep-send"));
    assert!(contains_token("a/b.pcap\"", "a/b.pcap"));
    assert!(!contains_token("a/b.pcapng", "a/b.pcap"));
}

#[test]
fn a_heading_slugs_the_way_the_page_anchors_it() {
    assert_eq!(
        markdown_slug("Export one customer's calls, whole"),
        "export-one-customers-calls-whole"
    );
    assert_eq!(
        markdown_slug("Ban a scanner through TFPS, and verify it"),
        "ban-a-scanner-through-tfps-and-verify-it"
    );
}

#[test]
fn a_cookbook_section_runs_to_the_next_second_level_heading() {
    let doc = "## 9. Nine\nnine\n## 10. Ten\nten\n### 10a. Sub\nsub\n## 11. Eleven\n";
    assert_eq!(
        cookbook_section(doc, 10).as_deref(),
        Some("ten\n### 10a. Sub\nsub")
    );
    assert_eq!(cookbook_section(doc, 1), None);
}

#[test]
fn dedent_strips_only_the_shared_prefix() {
    assert_eq!(dedent("    a\n      b\n\n    c\n"), "a\n  b\n\nc\n");
    assert_eq!(dedent("\ta\n\t\tb\n"), "a\n\tb\n");
    // Mixed tabs and spaces share no prefix, so nothing is removed.
    assert_eq!(dedent("\ta\n  b\n"), "\ta\n  b\n");
}
