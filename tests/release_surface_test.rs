// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What each release added to sipnab's surface, read from the git tags, and
//! the two documents that must agree with it.
//!
//! # The surface, release by release
//!
//! Three lists make up what a user can name: the command-line flags
//! (`src/cli.rs`), the MCP tools (`#[tool(...)]` under `src/mcp/`) and the REST
//! routes (`.route("...")` in `src/output/api.rs`). Each is read from the
//! source at every `vX.Y.Z` tag reachable from `HEAD`, through one `git
//! cat-file --batch`, and from the working tree for what is not released yet.
//! The extractors are text rules, so each is held to the running program on
//! the working tree: the flags to clap's own list, the tools to the router's.
//! A rule that agrees with the program today is the same rule that read every
//! tag.
//!
//! # The changelog names what each release added
//!
//! `every_addition_is_named_in_the_release_notes`: a flag, tool or route that
//! is in release R and not in the release before it must be named in R's
//! section of `CHANGELOG.md` or a later one. What the working tree adds over
//! the last tag must be named in `[Unreleased]` (or in a section for a version
//! not tagged yet). The changelog never named `--vcon-forward-interval` or
//! `--vcon-forward-timeout`, both added in 0.5.205, and nothing could see it.
//!
//! # A guide's "Tested on" names a release that has its flags
//!
//! `every_guide_states_a_release_that_carries_its_flags`: a guide whose
//! `## Tested on` section says it ran with `sipnab X.Y.Z` cannot use, in a
//! sipnab command it shows, a flag that first shipped after X.Y.Z. That
//! release could not have run it. `docs/tfps-sipnab.md` said 0.5.194 and used
//! `--allow-action`, `--journal-show` and `--revert-actions`, all from 0.5.196.
//!
//! A section that ran somewhere else says so: the `Tested on` sentence names
//! it, by link, after the word "except", and the section itself links back to
//! `#tested-on` in a statement of where it ran. That section is then held to
//! the version its own statement names, or to none when it ran on a build
//! that is not a release.

#![cfg(feature = "full")]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use clap::CommandFactory;

#[path = "support/markdown.rs"]
mod markdown;

type TestError = Box<dyn std::error::Error>;

/// A release number, `(major, minor, patch)`.
type Version = (u32, u32, u32);

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The file the flags are read from.
const CLI_SOURCE: &str = "src/cli.rs";
/// The file the REST routes are read from.
const API_SOURCE: &str = "src/output/api.rs";
/// The tree the MCP tools are read from.
const MCP_TREE: &str = "src/mcp";

// ── The three extractors ───────────────────────────────────────────────

/// The body of every `opener ... )]` attribute, balanced on parentheses and
/// aware of string literals, with the byte offset just past it.
fn attribute_bodies<'a>(src: &'a str, opener: &str) -> Vec<(&'a str, usize)> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut from = 0;
    while let Some(at) = src[from..].find(opener) {
        let start = from + at + opener.len();
        let mut depth = 1_usize;
        let mut in_string = false;
        let mut j = start;
        while depth > 0 && j < bytes.len() {
            match (in_string, bytes[j]) {
                (true, b'\\') => j += 1,
                (true, b'"') | (false, b'"') => in_string = !in_string,
                (false, b'(') => depth += 1,
                (false, b')') => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        out.push((&src[start..j.saturating_sub(1)], j));
        from = j;
    }
    out
}

/// Every long flag `src/cli.rs` declares.
///
/// `long = "name"` gives the name; a bare `long` derives it from the field
/// the attribute sits on, `snake_case` to `kebab-case`, the way clap does.
fn cli_longs(src: &str) -> Result<BTreeSet<String>, TestError> {
    let explicit = regex::Regex::new(r#"\blong\s*=\s*"([^"]+)""#)?;
    let strings = regex::Regex::new(r#""(?:[^"\\]|\\.)*""#)?;
    let bare = regex::Regex::new(r"(?:^|[\s,(])long\s*(?:,|$)")?;
    let field = regex::Regex::new(r"\n\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:")?;
    let mut out = BTreeSet::new();
    for (body, end) in attribute_bodies(src, "#[arg(") {
        if let Some(c) = explicit.captures(body) {
            out.insert(format!("--{}", &c[1]));
            continue;
        }
        if bare.is_match(&strings.replace_all(body, "\"\""))
            && let Some(c) = field.captures(&src[end..])
        {
            out.insert(format!("--{}", c[1].replace('_', "-")));
        }
    }
    Ok(out)
}

/// Every MCP tool name declared in these sources: `name = "..."` in the
/// `#[tool(...)]` attribute, or else the name of the function it sits on.
fn tool_names<'a>(
    sources: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, TestError> {
    let named = regex::Regex::new(r#"(?:^|[\s,(])name\s*=\s*"([^"]+)""#)?;
    let func = regex::Regex::new(r"\bfn\s+([a-z_][a-z0-9_]*)")?;
    let mut out = BTreeSet::new();
    for src in sources {
        for (body, end) in attribute_bodies(src, "#[tool(") {
            if let Some(c) = named.captures(body) {
                out.insert(c[1].to_owned());
            } else if let Some(c) = func.captures(&src[end..]) {
                out.insert(c[1].to_owned());
            }
        }
    }
    Ok(out)
}

/// Every REST route `src/output/api.rs` registers.
fn rest_routes(src: &str) -> Result<BTreeSet<String>, TestError> {
    let route = regex::Regex::new(r#"\.route\(\s*"(/[^"]*)""#)?;
    Ok(route.captures_iter(src).map(|c| c[1].to_owned()).collect())
}

/// What a user can name, at one point in history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Surface {
    flags: BTreeSet<String>,
    tools: BTreeSet<String>,
    routes: BTreeSet<String>,
}

// ── Reading the tags ───────────────────────────────────────────────────

/// `vX.Y.Z` as a version; anything else (a pre-release tag) is `None`.
fn tag_version(tag: &str) -> Option<Version> {
    let mut it = tag.strip_prefix('v')?.split('.');
    let v = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    it.next().is_none().then_some(v)
}

/// Run git in the repository and return its stdout.
fn git(args: &[&str]) -> Result<String, TestError> {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo())
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// Every release tag reachable from `HEAD`, oldest first.
fn release_tags() -> Result<Vec<(Version, String)>, TestError> {
    let mut tags: Vec<(Version, String)> = git(&["tag", "--merged", "HEAD", "--list", "v*"])?
        .lines()
        .filter_map(|t| tag_version(t).map(|v| (v, t.to_owned())))
        .collect();
    tags.sort();
    assert!(
        tags.len() >= 100,
        "only {} release tag(s) reachable from HEAD. This gate reads the \
         surface at every tag; a checkout without tags (actions/checkout's \
         default) cannot answer, so fetch them: `git fetch --tags`, or \
         `fetch-tags: true` with `fetch-depth: 0`",
        tags.len()
    );
    Ok(tags)
}

/// The contents of every blob id given, through one `git cat-file --batch`.
fn read_blobs(ids: &BTreeSet<String>) -> Result<HashMap<String, String>, TestError> {
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(repo())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let request: String = ids.iter().map(|id| format!("{id}\n")).collect();
    // Written from a thread, so a large answer cannot block the request.
    let writer = std::thread::spawn(move || stdin.write_all(request.as_bytes()));
    let mut raw = Vec::new();
    child
        .stdout
        .take()
        .ok_or("no stdout")?
        .read_to_end(&mut raw)?;
    writer
        .join()
        .map_err(|_| "the cat-file writer panicked")??;
    if !child.wait()?.success() {
        return Err("git cat-file --batch failed".into());
    }
    let mut out = HashMap::new();
    let mut at = 0;
    while at < raw.len() {
        let nl = raw[at..]
            .iter()
            .position(|b| *b == b'\n')
            .ok_or("truncated cat-file header")?;
        let header = std::str::from_utf8(&raw[at..at + nl])?;
        let mut parts = header.split(' ');
        let id = parts.next().ok_or("no id")?.to_owned();
        let size: usize = parts.nth(1).ok_or("no size")?.parse()?;
        let body = at + nl + 1;
        out.insert(
            id,
            String::from_utf8_lossy(&raw[body..body + size]).into_owned(),
        );
        at = body + size + 1;
    }
    Ok(out)
}

/// The surface at every release tag, oldest first.
///
/// Each tag's files are listed with `git ls-tree`; a blob shared by many tags
/// is fetched and parsed once.
fn release_surfaces() -> Result<&'static Vec<(Version, String, Surface)>, TestError> {
    static SURFACES: OnceLock<Vec<(Version, String, Surface)>> = OnceLock::new();
    if let Some(s) = SURFACES.get() {
        return Ok(s);
    }
    let mut listings = Vec::new();
    let mut ids = BTreeSet::new();
    for (version, tag) in release_tags()? {
        let mut files = Vec::new();
        for line in git(&[
            "ls-tree", "-r", &tag, "--", CLI_SOURCE, API_SOURCE, MCP_TREE,
        ])?
        .lines()
        {
            // `<mode> blob <id>\t<path>`
            let (meta, path) = line.split_once('\t').ok_or("odd ls-tree line")?;
            let id = meta.split(' ').nth(2).ok_or("odd ls-tree line")?.to_owned();
            if path.ends_with(".rs") {
                ids.insert(id.clone());
                files.push((id, path.to_owned()));
            }
        }
        listings.push((version, tag, files));
    }
    let blobs = read_blobs(&ids)?;
    let mut out = Vec::new();
    for (version, tag, files) in listings {
        let text = |id: &String| blobs.get(id).map(String::as_str).unwrap_or("");
        let mut surface = Surface::default();
        let mut mcp = Vec::new();
        for (id, path) in &files {
            match path.as_str() {
                CLI_SOURCE => surface.flags = cli_longs(text(id))?,
                API_SOURCE => surface.routes = rest_routes(text(id))?,
                p if p.starts_with(MCP_TREE) => mcp.push(text(id)),
                _ => {}
            }
        }
        surface.tools = tool_names(mcp)?;
        out.push((version, tag, surface));
    }
    Ok(SURFACES.get_or_init(|| out))
}

/// The surface the working tree declares, read from disk.
fn working_tree_surface() -> Result<Surface, TestError> {
    let mut mcp = Vec::new();
    let mut stack = vec![repo().join(MCP_TREE)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                mcp.push(std::fs::read_to_string(&p)?);
            }
        }
    }
    Ok(Surface {
        flags: cli_longs(&std::fs::read_to_string(repo().join(CLI_SOURCE))?)?,
        tools: tool_names(mcp.iter().map(String::as_str))?,
        routes: rest_routes(&std::fs::read_to_string(repo().join(API_SOURCE))?)?,
    })
}

// ── The extractors agree with the program ──────────────────────────────

/// The flag rule finds exactly the long flags clap builds, and the tool rule
/// exactly the tools the router registers.
#[test]
fn the_extractors_agree_with_the_running_program() -> Result<(), TestError> {
    let tree = working_tree_surface()?;
    let clap: BTreeSet<String> = sipnab::cli::Cli::command()
        .get_arguments()
        .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
        .collect();
    assert_eq!(
        tree.flags, clap,
        "the source rule and clap disagree on the long flags"
    );
    let registered: BTreeSet<String> = sipnab::mcp::SipnabMcp::new(
        std::sync::Arc::new(parking_lot::RwLock::new(
            sipnab::sip::dialog_store::DialogStore::new(64, false),
        )),
        std::sync::Arc::new(parking_lot::RwLock::new(
            sipnab::rtp::stream_store::StreamStore::new(64),
        )),
    )
    .registered_tool_names()
    .into_iter()
    .collect();
    assert_eq!(
        tree.tools, registered,
        "the source rule and the MCP router disagree on the tools"
    );
    assert!(
        tree.routes.len() >= 40
            && tree.routes.contains("/v1/dialogs/{call_id}")
            && tree.routes.contains("/v1/tfps/ban"),
        "the route rule found {:?}",
        tree.routes
    );
    Ok(())
}

// ── The changelog names every addition ─────────────────────────────────

/// Whether `text` names `name` as a whole token: the characters on either
/// side are not ones a flag, tool or path could continue with.
fn names_token(text: &str, name: &str) -> bool {
    let continues = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    text.match_indices(name).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + name.len()..].chars().next();
        !before.is_some_and(continues) && !after.is_some_and(continues)
    })
}

/// Whether `text` names the REST route `route`. A `{param}` segment matches
/// any parameter name in braces, `:name` or `<name>`, because the notes write
/// all three.
fn names_route(text: &str, route: &str) -> Result<bool, TestError> {
    let param = regex::Regex::new(r"\{[^}/]+\}")?;
    let mut pattern = String::from(r"(?:^|[^A-Za-z0-9_/])");
    let mut last = 0;
    for m in param.find_iter(route) {
        pattern.push_str(&regex::escape(&route[last..m.start()]));
        pattern.push_str(r"(?:\{[^}/\s]+\}|:[A-Za-z_]+|<[^>/\s]+>)");
        last = m.end();
    }
    pattern.push_str(&regex::escape(&route[last..]));
    pattern.push_str(r"(?:$|[^A-Za-z0-9_/{:<-])");
    Ok(regex::Regex::new(&pattern)?.is_match(text))
}

/// What `after` adds over `before` that `notes` never names, as readable
/// lines.
fn unnamed_additions(
    before: &Surface,
    after: &Surface,
    notes: &str,
) -> Result<Vec<String>, TestError> {
    let mut out = Vec::new();
    for flag in after.flags.difference(&before.flags) {
        if !names_token(notes, flag) {
            out.push(format!("flag {flag}"));
        }
    }
    for tool in after.tools.difference(&before.tools) {
        if !names_token(notes, tool) {
            out.push(format!("MCP tool {tool}"));
        }
    }
    for route in after.routes.difference(&before.routes) {
        if !names_route(notes, route)? {
            out.push(format!("REST route {route}"));
        }
    }
    Ok(out)
}

/// The part of `release` the working tree still has.
fn still_present(release: &Surface, current: &Surface) -> Surface {
    Surface {
        flags: release
            .flags
            .intersection(&current.flags)
            .cloned()
            .collect(),
        tools: release
            .tools
            .intersection(&current.tools)
            .cloned()
            .collect(),
        routes: release
            .routes
            .intersection(&current.routes)
            .cloned()
            .collect(),
    }
}

/// A removed addition is not owed a release note; a kept one still is.
#[test]
fn only_additions_the_tree_still_has_are_owed_a_note() {
    let set = |xs: &[&str]| xs.iter().map(|x| (*x).to_owned()).collect::<BTreeSet<_>>();
    let release = Surface {
        flags: set(&["--kept", "--removed"]),
        tools: set(&["kept_tool", "gone_tool"]),
        routes: set(&["/v1/kept"]),
    };
    let current = Surface {
        flags: set(&["--kept", "--newer"]),
        tools: set(&["kept_tool"]),
        routes: BTreeSet::new(),
    };
    let kept = still_present(&release, &current);
    assert_eq!(kept.flags, set(&["--kept"]));
    assert_eq!(kept.tools, set(&["kept_tool"]));
    assert!(kept.routes.is_empty());
}

/// Everything in the changelog above the section for `version`: that
/// section's successors, and `[Unreleased]`.
///
/// A release with no section of its own (none since 0.3.0 lacks one) falls
/// back to the newest older section, so the text is never shorter than it
/// should be.
fn notes_after(changelog: &str, version: Version) -> &str {
    let heading = regex::Regex::new(r"(?m)^## \[(\d+)\.(\d+)\.(\d+)\]").ok();
    let Some(heading) = heading else {
        return changelog;
    };
    for c in heading.captures_iter(changelog) {
        let v: Version = (
            c[1].parse().unwrap_or(0),
            c[2].parse().unwrap_or(0),
            c[3].parse().unwrap_or(0),
        );
        if v <= version {
            return &changelog[..c.get(0).map_or(0, |m| m.start())];
        }
    }
    changelog
}

/// Every flag, MCP tool and REST route a release added is named in its
/// release notes or a later section, and what the working tree adds over the
/// last tag is named above that tag's section.
#[test]
fn every_addition_is_named_in_the_release_notes() -> Result<(), TestError> {
    let changelog = std::fs::read_to_string(repo().join("CHANGELOG.md"))?;
    let releases = release_surfaces()?;
    let current = working_tree_surface()?;
    let mut gaps = Vec::new();
    let mut additions = 0_usize;
    for pair in releases.windows(2) {
        let ((prev, _, before), (_, tag, after)) = (&pair[0], &pair[1]);
        additions += after.flags.difference(&before.flags).count();
        // Only what this tree still has must be named. A flag, tool or route
        // a later release removed may be left out of the notes on purpose:
        // --vcon-forward-compat (0.5.205) was removed in 0.5.211, with every
        // mention of it, at the maintainer's decision.
        let kept = still_present(after, &current);
        for gap in unnamed_additions(before, &kept, notes_after(&changelog, *prev))? {
            gaps.push(format!("{tag}: {gap}"));
        }
    }
    let (last, last_tag, released) = releases.last().ok_or("no releases")?;
    for gap in unnamed_additions(released, &current, notes_after(&changelog, *last))? {
        gaps.push(format!("since {last_tag}: {gap}"));
    }
    assert!(
        additions >= 200,
        "only {additions} flag addition(s) found across every release: the \
         history is not being read"
    );
    assert!(
        gaps.is_empty(),
        "{} addition(s) are named in no release note from the release that \
         added them onward. Name each in that release's section, or, for a \
         released section, in [Unreleased] with the release it shipped in:\n  {}",
        gaps.len(),
        gaps.join("\n  ")
    );
    Ok(())
}

/// The addition check reports an unnamed flag, tool and route, and accepts
/// each once a note names it, whatever the note calls a path parameter.
#[test]
fn an_unnamed_addition_is_reported_and_a_named_one_is_not() -> Result<(), TestError> {
    let before = Surface {
        flags: BTreeSet::from(["--input".to_owned()]),
        tools: BTreeSet::from(["list_dialogs".to_owned()]),
        routes: BTreeSet::from(["/v1/dialogs".to_owned()]),
    };
    let after = Surface {
        flags: BTreeSet::from(["--input".to_owned(), "--vcon-forward-interval".to_owned()]),
        tools: BTreeSet::from(["list_dialogs".to_owned(), "relay_stats".to_owned()]),
        routes: BTreeSet::from([
            "/v1/dialogs".to_owned(),
            "/v1/dialogs/{call_id}/vcon".to_owned(),
        ]),
    };
    let silent = "- `--vcon-forward-interval-secs` and `relay_stats_names` and `/v1/dialogs`.";
    assert_eq!(
        unnamed_additions(&before, &after, silent)?,
        vec![
            "flag --vcon-forward-interval",
            "MCP tool relay_stats",
            "REST route /v1/dialogs/{call_id}/vcon",
        ],
        "a longer name that merely starts with the new one is not a mention"
    );
    let named = "- `--vcon-forward-interval`, the `relay_stats` tool and \
                 `GET /v1/dialogs/:id/vcon`.";
    assert!(unnamed_additions(&before, &after, named)?.is_empty());
    let changelog = "# Changelog\n\n## [Unreleased]\n\nnew\n\n## [0.5.206] - x\n\nsix\n\n## [0.5.205] - x\n\nfive\n";
    assert_eq!(
        notes_after(changelog, (0, 5, 205)),
        "# Changelog\n\n## [Unreleased]\n\nnew\n\n## [0.5.206] - x\n\nsix\n\n"
    );
    assert!(notes_after(changelog, (0, 5, 206)).ends_with("new\n\n"));
    Ok(())
}

// ── A guide's Tested on names a release that has its flags ─────────────

/// The first release that declared each flag.
fn first_releases() -> Result<BTreeMap<String, Version>, TestError> {
    let mut first = BTreeMap::new();
    for (version, _, surface) in release_surfaces()? {
        for flag in &surface.flags {
            first.entry(flag.clone()).or_insert(*version);
        }
    }
    Ok(first)
}

/// `0.5.194` from `(0, 5, 194)`.
fn dotted(v: Version) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// The first `sipnab X.Y.Z` in `text`; a line break may sit between the two.
fn stated_release(text: &str) -> Result<Option<Version>, TestError> {
    let re = regex::Regex::new(r"\bsipnab\s+(\d+)\.(\d+)\.(\d+)")?;
    Ok(re.captures(text).map(|c| {
        (
            c[1].parse().unwrap_or(0),
            c[2].parse().unwrap_or(0),
            c[3].parse().unwrap_or(0),
        )
    }))
}

/// The GitHub anchor of a heading's text.
fn slug(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| *c != '`')
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// One heading-delimited part of a page: its anchor, and its lines as
/// `[start, end)` line indices, subsections included.
struct Section {
    anchor: String,
    start: usize,
    end: usize,
}

/// Every `##`-or-deeper section of a page, fenced lines ignored.
fn sections(lines: &[&str], fenced: &[bool]) -> Vec<Section> {
    let heads: Vec<(usize, usize, String)> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| !fenced[*i])
        .filter_map(|(i, l)| {
            let level = l.chars().take_while(|c| *c == '#').count();
            (level >= 2 && l[level..].starts_with(' ')).then(|| (i, level, slug(l[level..].trim())))
        })
        .collect();
    heads
        .iter()
        .enumerate()
        .map(|(n, (start, level, anchor))| {
            let end = heads[n + 1..]
                .iter()
                .find(|(_, l, _)| l <= level)
                .map_or(lines.len(), |(i, _, _)| *i);
            Section {
                anchor: anchor.clone(),
                start: *start,
                end,
            }
        })
        .collect()
}

/// Per line, whether it is inside a fence (markers included).
fn fence_mask(text: &str) -> Vec<bool> {
    let lines = text.lines().count();
    let mut mask = vec![false; lines];
    for f in markdown::fences(text) {
        let body_lines = f.body.lines().count();
        let last = (f.line + body_lines).min(lines);
        for m in mask.iter_mut().take(last).skip(f.line - 1) {
            *m = true;
        }
    }
    mask
}

/// Every flag on a sipnab command line in a fence that starts within
/// `[start, end)`, with the line it is on.
fn sipnab_flags_in(
    text: &str,
    start: usize,
    end: usize,
) -> Result<Vec<(usize, String)>, TestError> {
    let invokes = regex::Regex::new(r"(?:^|[\s/=])sipnab(?:\s|$)")?;
    let flag = regex::Regex::new(r"(?:^|\s)(--[a-z][a-z0-9-]*[a-z0-9])")?;
    let mut out = Vec::new();
    for f in markdown::fences(text) {
        if f.line <= start || f.line > end {
            continue;
        }
        let mut logical = String::new();
        let mut first = f.body_line;
        for (n, line) in f.body.lines().enumerate() {
            if logical.is_empty() {
                first = f.body_line + n;
            }
            let t = line.trim();
            if let Some(head) = t.strip_suffix('\\') {
                logical.push_str(head);
                logical.push(' ');
                continue;
            }
            logical.push_str(t);
            if invokes.is_match(&logical) {
                for c in flag.captures_iter(&logical) {
                    out.push((first, c[1].to_owned()));
                }
            }
            logical.clear();
        }
    }
    Ok(out)
}

/// Why one guide's `Tested on` cannot be true, one line per reason.
///
/// `known` is every flag sipnab has; anything else on a sipnab line (a
/// systemd or curl option in the same block) is not sipnab's to date.
fn tested_on_findings(
    page: &str,
    text: &str,
    first: &BTreeMap<String, Version>,
    known: &BTreeSet<String>,
) -> Result<Vec<String>, TestError> {
    let lines: Vec<&str> = text.lines().collect();
    let fenced = fence_mask(text);
    let all = sections(&lines, &fenced);
    let Some(tested) = all.iter().find(|s| s.anchor == "tested-on") else {
        return Ok(Vec::new());
    };
    let statement = lines[tested.start..tested.end].join("\n");
    let Some(version) = stated_release(&statement)? else {
        return Ok(Vec::new());
    };
    // Sections the statement leaves out: the in-page links between "except"
    // and the "ran" that ends the clause ("Every block on this page except
    // those under [X](#x) ran as written ..."). A heading such as `2. Act` has
    // a full stop in it, so the clause is not cut at sentence punctuation.
    let except = regex::Regex::new(r"(?s)\bexcept\b(.*?)\bran\b")?;
    let link = regex::Regex::new(r"\]\(#([^)\s]+)\)")?;
    let excluded: BTreeSet<String> = except
        .captures_iter(&statement)
        .flat_map(|c| {
            link.captures_iter(c.get(1).map_or("", |m| m.as_str()))
                .map(|l| l[1].to_owned())
                .collect::<Vec<_>>()
        })
        .collect();
    let mut findings = Vec::new();
    let mut held: Vec<(usize, usize, Option<Version>, String)> = Vec::new();
    for anchor in &excluded {
        let Some(s) = all.iter().find(|s| &s.anchor == anchor) else {
            findings.push(format!(
                "{page}: Tested on leaves out #{anchor}, which is not a section of the page"
            ));
            continue;
        };
        let own = lines[s.start..s.end]
            .iter()
            .enumerate()
            .filter(|(i, _)| !fenced[s.start + i])
            .map(|(_, l)| *l)
            .collect::<Vec<_>>()
            .join("\n");
        if !own.contains("](#tested-on)") {
            findings.push(format!(
                "{page}: Tested on leaves out #{anchor}, and that section does not say \
                 where it ran (no link back to #tested-on)"
            ));
        }
        held.push((s.start, s.end, stated_release(&own)?, format!("#{anchor}")));
    }
    let in_excluded = |line: usize| {
        held.iter()
            .any(|(a, b, _, _)| (*a..*b).contains(&(line - 1)))
    };
    for (line, flag) in sipnab_flags_in(text, 0, lines.len())? {
        if !known.contains(&flag) || in_excluded(line) {
            continue;
        }
        match first.get(&flag) {
            Some(since) if *since <= version => {}
            Some(since) => findings.push(format!(
                "{page}:{line}: Tested on names sipnab {}, but {flag} first shipped in {}",
                dotted(version),
                dotted(*since)
            )),
            None => findings.push(format!(
                "{page}:{line}: Tested on names sipnab {}, but {flag} is in no release yet",
                dotted(version)
            )),
        }
    }
    for (start, end, own_version, anchor) in &held {
        let Some(own_version) = own_version else {
            continue;
        };
        for (line, flag) in sipnab_flags_in(text, *start, *end)? {
            if let Some(since) = first.get(&flag).filter(|s| *s > own_version) {
                findings.push(format!(
                    "{page}:{line}: {anchor} says it ran with sipnab {}, but {flag} first \
                     shipped in {}",
                    dotted(*own_version),
                    dotted(*since)
                ));
            }
        }
    }
    Ok(findings)
}

/// Every guide's `Tested on` release carries every flag its sipnab commands
/// use, outside the sections it says ran elsewhere.
#[test]
fn every_guide_states_a_release_that_carries_its_flags() -> Result<(), TestError> {
    let first = first_releases()?;
    let known: BTreeSet<String> = working_tree_surface()?.flags;
    let mut pages: Vec<_> = std::fs::read_dir(repo().join("docs"))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    pages.sort();
    let mut findings = Vec::new();
    let mut attested = 0_usize;
    for page in pages {
        let text = std::fs::read_to_string(&page)?;
        let name = page.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        if text.contains("\n## Tested on") && stated_release(&text)?.is_some() {
            attested += 1;
        }
        findings.extend(tested_on_findings(name, &text, &first, &known)?);
    }
    assert!(
        attested >= 9,
        "only {attested} guide(s) state a sipnab release under Tested on"
    );
    assert!(
        findings.is_empty(),
        "{} guide claim(s) name a release that could not have run the page:\n  {}",
        findings.len(),
        findings.join("\n  ")
    );
    Ok(())
}

/// The Tested on check reads versions, exclusions and their own statements
/// the way the guides write them.
#[test]
fn the_tested_on_check_reads_what_the_guides_write() -> Result<(), TestError> {
    let first = BTreeMap::from([
        ("--input".to_owned(), (0, 5, 0)),
        ("--allow-action".to_owned(), (0, 5, 196)),
        ("--vcon-forward".to_owned(), (0, 5, 205)),
    ]);
    let known: BTreeSet<String> = first.keys().cloned().collect();
    let page = |tested_on: &str, elsewhere: &str| {
        format!(
            "# Guide\n\n## Tested on\n\n{tested_on}\n\n## 1. Read\n\n```bash\nsipnab -N --input x.pcap\n```\n\n\
             ## 2. Act\n\n```bash\nsudo systemctl enable --now sipnab\nsipnab --allow-action ban \\\n  --input x.pcap\n```\n\n\
             ## Or forward\n\n{elsewhere}\n\n```bash\nsipnab --vcon-forward spool\n```\n"
        )
    };
    let stale = page("Every block ran with sipnab 0.5.194.", "Ran elsewhere.");
    let got = tested_on_findings("g.md", &stale, &first, &known)?;
    assert_eq!(
        got,
        vec![
            "g.md:17: Tested on names sipnab 0.5.194, but --allow-action first shipped in 0.5.196",
            "g.md:26: Tested on names sipnab 0.5.194, but --vcon-forward first shipped in 0.5.205",
        ],
        "`--now` is systemctl's, not a sipnab flag, so it is not dated"
    );
    let scoped = page(
        "Every block except those in [2. Act](#2-act) and [Or forward](#or-forward) ran with sipnab 0.5.194.",
        "This section ran on another day, not as in [Tested on](#tested-on), with sipnab built from source.",
    );
    let got = tested_on_findings("g.md", &scoped, &first, &known)?;
    assert_eq!(
        got,
        vec![
            "g.md: Tested on leaves out #2-act, and that section does not say where it ran (no link back to #tested-on)"
        ],
    );
    let held = page(
        "Every block except those in [Or forward](#or-forward) ran with sipnab 0.5.196.",
        "This section ran as in [Tested on](#tested-on) but with sipnab 0.5.200.",
    );
    assert_eq!(
        tested_on_findings("g.md", &held, &first, &known)?,
        vec![
            "g.md:26: #or-forward says it ran with sipnab 0.5.200, but --vcon-forward first shipped in 0.5.205"
        ],
        "an excluded section is held to the release its own statement names"
    );
    Ok(())
}
