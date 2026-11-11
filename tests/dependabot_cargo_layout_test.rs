// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The cargo entries of `.github/dependabot.yml` fit the way Dependabot reads
//! a directory.
//!
//! Two defects, both found on 2026-11-09 and 2026-11-10.
//!
//! **One pull request for the two lockfiles that must agree.** `Cargo.lock`
//! and `fuzz/Cargo.lock` resolve the same crates, and
//! `scripts/check-lockfile-drift.py` fails a tree where they disagree. With
//! one entry per directory Dependabot moved each lockfile in a pull request of
//! its own, so each of them failed that check and a person had to combine
//! them: #722 to #728 were replaced by the hand-made batch #733. One entry
//! that lists both directories puts a group's updates for both in one pull
//! request.
//!
//! **A directory must resolve from the files Dependabot fetches.** For `/bpf`
//! it fetches that directory and the manifests of its path dependencies, not
//! the repository root. `crates/sipnab-bpf-types` inherited its lints from the
//! root workspace (`[lints] workspace = true`), so cargo ended every `/bpf`
//! run with "failed to find a workspace root" (run 42694599982). A path
//! dependency of a Dependabot directory therefore inherits nothing from a
//! workspace it is not the root of. The shared crate states its lints itself,
//! and a test here holds them equal to the workspace table.

#[path = "../src/test_scratch.rs"]
mod test_scratch;

use std::path::{Path, PathBuf};
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repository file, naming the path on failure.
fn read(rel: &str) -> Result<String, TestError> {
    let p = repo().join(rel);
    Ok(std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?)
}

/// Parse a manifest, naming it on failure.
fn manifest(rel: &str) -> Result<toml::Table, TestError> {
    Ok(toml::from_str(&read(rel)?).map_err(|e| format!("{rel}: {e}"))?)
}

// ── Reading dependabot.yml ──────────────────────────────────────────

/// One `cargo` entry of `dependabot.yml`: its directories and its text.
#[derive(Debug, Clone, PartialEq)]
struct CargoEntry {
    /// Every directory the entry names, as written.
    dirs: Vec<String>,
    /// The entry's lines, comments removed.
    block: String,
}

/// The text between the first pair of double quotes on a line.
fn quoted(line: &str) -> Option<String> {
    let mut parts = line.split('"');
    parts.next()?;
    parts.next().map(str::to_string)
}

/// The `cargo` entries of a `dependabot.yml`.
///
/// Comment lines are dropped first: the file's comments quote configuration
/// that is not in effect.
fn cargo_entries(yml: &str) -> Vec<CargoEntry> {
    let live: String = yml
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    live.split("- package-ecosystem:")
        .skip(1)
        .filter(|b| quoted(b.lines().next().unwrap_or("")).as_deref() == Some("cargo"))
        .map(|b| {
            let mut dirs = Vec::new();
            let mut in_list = false;
            for line in b.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("directory:") {
                    dirs.extend(quoted(rest));
                    in_list = false;
                } else if t == "directories:" {
                    in_list = true;
                } else if in_list && t.starts_with("- ") {
                    dirs.extend(quoted(t));
                } else if !t.is_empty() {
                    in_list = false;
                }
            }
            CargoEntry {
                dirs,
                block: b.to_string(),
            }
        })
        .collect()
}

/// The entries that name `dir`.
fn entries_for<'a>(entries: &'a [CargoEntry], dir: &str) -> Vec<&'a CargoEntry> {
    entries
        .iter()
        .filter(|e| e.dirs.iter().any(|d| d == dir))
        .collect()
}

/// How many `groups:` an entry declares: the keys one level under `groups:`.
fn group_names(block: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut indent = None;
    for line in block.lines() {
        let depth = line.len() - line.trim_start().len();
        let t = line.trim();
        match indent {
            None if t == "groups:" => indent = Some(depth),
            Some(g) if !t.is_empty() && depth <= g => break,
            Some(g) if depth == g + 2 && t.ends_with(':') => {
                names.push(t.trim_end_matches(':').to_string());
            }
            _ => {}
        }
    }
    names
}

// ── Reading manifests ───────────────────────────────────────────────

/// Every key path in a manifest that inherits from a workspace: a table
/// holding `workspace = true`. The `[workspace]` table itself is not one.
fn inherited(table: &toml::Table) -> Vec<String> {
    fn walk(prefix: &str, table: &toml::Table, out: &mut Vec<String>) {
        for (key, value) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if prefix.is_empty() && key == "workspace" {
                continue;
            }
            if let toml::Value::Table(inner) = value {
                if inner.get("workspace") == Some(&toml::Value::Boolean(true)) {
                    out.push(path.clone());
                }
                walk(&path, inner, out);
            }
        }
    }
    let mut out = Vec::new();
    walk("", table, &mut out);
    out
}

/// Whether a manifest is a workspace root, so that what it inherits it
/// inherits from itself.
fn is_workspace_root(table: &toml::Table) -> bool {
    table.get("workspace").is_some_and(toml::Value::is_table)
}

/// Whether `path` is a member of the workspace `root` declares. Dependabot
/// fetches the directory's own manifest, so a member finds its root.
fn is_member(root: &toml::Table, path: &str) -> bool {
    root.get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .is_some_and(|m| m.iter().any(|v| v.as_str() == Some(path)))
}

/// A repository-relative directory without `.` and `..` segments; the
/// repository root is the empty string. `None` when the path leaves the
/// repository.
fn lexical(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// `dir/rel`, where the repository root is the empty string.
fn join(dir: &str, rel: &str) -> String {
    if dir.is_empty() {
        rel.to_string()
    } else {
        format!("{dir}/{rel}")
    }
}

/// The manifests, of those Dependabot fetches for one directory, that cargo
/// cannot load: each inherits from a workspace, is not a workspace root
/// itself, and is a member of no workspace root among the fetched manifests.
///
/// `fetched` pairs each manifest's directory (see [`lexical`]) with its
/// content. The answer pairs a directory with the keys it inherits.
fn unresolvable(fetched: &[(String, toml::Table)]) -> Vec<(String, Vec<String>)> {
    let mut lost = Vec::new();
    for (dir, table) in fetched {
        let keys = inherited(table);
        if keys.is_empty() || is_workspace_root(table) {
            continue;
        }
        let has_root = fetched.iter().any(|(root_dir, root)| {
            let rel = if root_dir.is_empty() {
                Some(dir.as_str())
            } else {
                dir.strip_prefix(root_dir.as_str())
                    .and_then(|r| r.strip_prefix('/'))
            };
            is_workspace_root(root) && rel.is_some_and(|rel| is_member(root, rel))
        });
        if !has_root {
            lost.push((dir.clone(), keys));
        }
    }
    lost
}

/// The `path` of every path dependency a manifest declares, in any
/// dependency table, target-specific ones included.
fn path_dependencies(table: &toml::Table) -> Vec<String> {
    fn from(deps: Option<&toml::Value>, out: &mut Vec<String>) {
        let Some(toml::Value::Table(deps)) = deps else {
            return;
        };
        for spec in deps.values() {
            if let Some(toml::Value::String(p)) = spec.get("path") {
                out.push(p.clone());
            }
        }
    }
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let mut out = Vec::new();
    for kind in KINDS {
        from(table.get(kind), &mut out);
    }
    if let Some(toml::Value::Table(targets)) = table.get("target") {
        for target in targets.values() {
            for kind in KINDS {
                from(target.get(kind), &mut out);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether cargo can load the manifest in `dir` with nothing above it.
///
/// `cargo metadata --no-deps` reads the manifest and its workspace and no
/// registry, so it answers offline. The output is returned for the message.
fn loads_alone(dir: &Path) -> Result<(bool, String), TestError> {
    let out = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .arg("--manifest-path")
        .arg(dir.join("Cargo.toml"))
        .current_dir(dir)
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// A scratch directory holding a one-file crate with the given manifest.
fn scratch_crate(name: &str, manifest: &str) -> Result<test_scratch::ScratchDir, TestError> {
    let dir = test_scratch::ScratchDir::new(&format!("sipnab-dependabot-{name}-"))?;
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(dir.join("src/lib.rs"), "")?;
    std::fs::write(dir.join("Cargo.toml"), manifest)?;
    Ok(dir)
}

// ── The repository ──────────────────────────────────────────────────

/// One entry names `/` and `/fuzz` together, so a group's updates to both
/// lockfiles arrive in one pull request.
#[test]
fn one_cargo_entry_updates_both_lockfiles_that_must_agree() -> Result<(), TestError> {
    let entries = cargo_entries(&read(".github/dependabot.yml")?);
    let root = entries_for(&entries, "/");
    let fuzz = entries_for(&entries, "/fuzz");
    assert_eq!(
        root.len(),
        1,
        "`/` is named by {} cargo entries",
        root.len()
    );
    assert_eq!(
        fuzz.len(),
        1,
        "`/fuzz` is named by {} cargo entries",
        fuzz.len()
    );
    assert_eq!(
        root, fuzz,
        "`/` and `/fuzz` are in separate entries: Dependabot then moves each lockfile \
         in a pull request of its own, and each fails scripts/check-lockfile-drift.py"
    );
    Ok(())
}

/// The entry for both lockfiles has one group, for minor and patch updates,
/// and runs weekly. Two groups would be two pull requests again.
#[test]
fn the_shared_entry_has_one_weekly_minor_and_patch_group() -> Result<(), TestError> {
    let entries = cargo_entries(&read(".github/dependabot.yml")?);
    let shared = entries_for(&entries, "/fuzz");
    let entry = shared.first().ok_or("no cargo entry names /fuzz")?;
    assert_eq!(
        group_names(&entry.block),
        ["cargo-minor-patch"],
        "the entry for both lockfiles must have exactly this group"
    );
    for needle in ["- \"minor\"", "- \"patch\"", "interval: \"weekly\""] {
        assert!(
            entry.block.contains(needle),
            "the entry for both lockfiles lacks `{needle}`"
        );
    }
    Ok(())
}

/// The eBPF workspace keeps an entry of its own: its lockfile shares nothing
/// that `check-lockfile-drift.py` compares.
#[test]
fn the_bpf_workspace_keeps_its_own_entry() -> Result<(), TestError> {
    let entries = cargo_entries(&read(".github/dependabot.yml")?);
    let bpf = entries_for(&entries, "/bpf");
    assert_eq!(
        bpf.len(),
        1,
        "`/bpf` is named by {} cargo entries",
        bpf.len()
    );
    assert_eq!(
        bpf[0].dirs,
        ["/bpf"],
        "the /bpf entry names other directories too"
    );
    Ok(())
}

/// No directory is named by two cargo entries: Dependabot would open two
/// pull requests for one lockfile.
#[test]
fn no_directory_is_in_two_cargo_entries() -> Result<(), TestError> {
    let entries = cargo_entries(&read(".github/dependabot.yml")?);
    let mut seen = std::collections::BTreeSet::new();
    for dir in entries.iter().flat_map(|e| &e.dirs) {
        assert!(seen.insert(dir), "{dir} is named by two cargo entries");
    }
    assert!(
        seen.len() >= 3,
        "expected /, /fuzz and /bpf at least, read {seen:?}: a reader that finds \
         nothing passes every check above"
    );
    Ok(())
}

/// Every path dependency of a Dependabot cargo directory loads from the files
/// Dependabot fetches: it inherits nothing, or it is the workspace root it
/// inherits from, or it is a member of the workspace the directory's own
/// manifest is the root of.
#[test]
fn path_dependencies_of_a_dependabot_directory_inherit_nothing() -> Result<(), TestError> {
    let entries = cargo_entries(&read(".github/dependabot.yml")?);
    let mut checked = 0;
    for dir in entries.iter().flat_map(|e| &e.dirs) {
        let own_dir = lexical(dir.trim_matches('/')).ok_or("a directory outside the repository")?;
        let own = manifest(&join(&own_dir, "Cargo.toml"))?;
        let mut fetched = Vec::new();
        for dep in path_dependencies(&own) {
            let dep_dir = lexical(&join(&own_dir, &dep))
                .ok_or_else(|| format!("{dir}: the path dependency {dep} leaves the repository"))?;
            fetched.push((dep_dir.clone(), manifest(&join(&dep_dir, "Cargo.toml"))?));
            checked += 1;
        }
        fetched.push((own_dir, own));
        let lost = unresolvable(&fetched);
        assert!(
            lost.is_empty(),
            "a Dependabot run for {dir} fetches that directory and its path dependencies. \
             These inherit from a workspace root that is not among them, so cargo ends the \
             run with \"failed to find a workspace root\": {lost:?}"
        );
    }
    assert!(
        checked >= 3,
        "read {checked} path dependencies; /, /fuzz and /bpf have one or more each"
    );
    Ok(())
}

/// The shared record crate loads with nothing above it, as it does in a
/// Dependabot run for `/bpf`.
#[test]
fn the_shared_record_crate_loads_without_the_repository_root() -> Result<(), TestError> {
    let dir = scratch_crate("types", &read("crates/sipnab-bpf-types/Cargo.toml")?)?;
    std::fs::write(dir.join("README.md"), "")?;
    let (ok, stderr) = loads_alone(&dir)?;
    assert!(
        ok,
        "cargo cannot load crates/sipnab-bpf-types/Cargo.toml on its own:\n{stderr}"
    );
    Ok(())
}

/// The lints the shared record crate states are the workspace's lints. It
/// cannot inherit them, so this test is what keeps the two tables one rule.
#[test]
fn the_shared_record_crate_states_the_workspace_lints() -> Result<(), TestError> {
    let root = manifest("Cargo.toml")?;
    let workspace = root
        .get("workspace")
        .and_then(|w| w.get("lints"))
        .ok_or("Cargo.toml has no [workspace.lints]")?;
    let types = manifest("crates/sipnab-bpf-types/Cargo.toml")?;
    let own = types
        .get("lints")
        .ok_or("crates/sipnab-bpf-types/Cargo.toml has no [lints]")?;
    assert_eq!(
        own, workspace,
        "crates/sipnab-bpf-types/Cargo.toml [lints] differs from [workspace.lints] in \
         Cargo.toml: copy the workspace table, the crate cannot inherit it"
    );
    Ok(())
}

/// Every other workspace member still inherits, so the copy above is the one
/// exception and the workspace table stays the rule.
#[test]
fn every_other_workspace_member_inherits_its_lints() -> Result<(), TestError> {
    let root = manifest("Cargo.toml")?;
    let members = root
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or("Cargo.toml has no workspace members")?;
    let mut inheriting = 0;
    for member in members.iter().filter_map(toml::Value::as_str) {
        if member == "crates/sipnab-bpf-types" {
            continue;
        }
        let rel = if member == "." {
            "Cargo.toml".to_string()
        } else {
            format!("{member}/Cargo.toml")
        };
        let table = manifest(&rel)?;
        if inherited(&table).iter().any(|k| k == "lints") {
            inheriting += 1;
        }
    }
    assert!(
        inheriting >= 3,
        "{inheriting} workspace members inherit their lints; the root, the audio crate \
         and the G.729 crate did"
    );
    Ok(())
}

// ── The probe detects the defect ────────────────────────────────────

/// A crate that inherits its lints and has no workspace above it does not
/// load. This is the `/bpf` failure, reproduced.
#[test]
fn a_crate_that_inherits_lints_does_not_load_alone() -> Result<(), TestError> {
    let dir = scratch_crate(
        "inherits",
        "[package]\nname = \"p\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[lints]\nworkspace = true\n",
    )?;
    let (ok, stderr) = loads_alone(&dir)?;
    assert!(!ok, "cargo loaded a crate that inherits from no workspace");
    assert!(
        stderr.contains("workspace"),
        "cargo refused for another reason:\n{stderr}"
    );
    Ok(())
}

/// The same crate with its lints stated loads.
#[test]
fn a_crate_that_states_its_lints_loads_alone() -> Result<(), TestError> {
    let dir = scratch_crate(
        "states",
        "[package]\nname = \"p\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[lints.clippy]\nptr_arg = \"deny\"\n",
    )?;
    let (ok, stderr) = loads_alone(&dir)?;
    assert!(ok, "cargo cannot load a self-contained crate:\n{stderr}");
    Ok(())
}

/// A crate that inherits its version does not load alone either: the rule is
/// about every inherited key, not lints only.
#[test]
fn a_crate_that_inherits_its_version_does_not_load_alone() -> Result<(), TestError> {
    let dir = scratch_crate(
        "version",
        "[package]\nname = \"p\"\nversion.workspace = true\nedition = \"2021\"\n",
    )?;
    let (ok, _) = loads_alone(&dir)?;
    assert!(
        !ok,
        "cargo loaded a crate whose version comes from no workspace"
    );
    Ok(())
}

// ── The readers ─────────────────────────────────────────────────────

const TWO_ENTRIES: &str = "version: 2\nupdates:\n  - package-ecosystem: \"cargo\"\n    directory: \"/\"\n    groups:\n      a-group:\n        update-types:\n          - \"minor\"\n  - package-ecosystem: \"cargo\"\n    directory: \"/fuzz\"\n";

const ONE_ENTRY: &str = "version: 2\nupdates:\n  - package-ecosystem: \"cargo\"\n    directories:\n      - \"/\"\n      - \"/fuzz\"\n    schedule:\n      interval: \"weekly\"\n    groups:\n      both:\n        update-types:\n          - \"minor\"\n          - \"patch\"\n  - package-ecosystem: \"npm\"\n    directory: \"/e2e\"\n";

#[test]
fn the_reader_finds_a_directory_per_entry() {
    let e = cargo_entries(TWO_ENTRIES);
    assert_eq!(e.len(), 2, "two cargo entries were written");
    assert_eq!(e[0].dirs, ["/"], "the first entry names the root");
    assert_eq!(e[1].dirs, ["/fuzz"], "the second entry names /fuzz");
}

#[test]
fn the_reader_finds_a_directories_list() {
    let e = cargo_entries(ONE_ENTRY);
    assert_eq!(e.len(), 1, "the npm entry is not a cargo entry");
    assert_eq!(e[0].dirs, ["/", "/fuzz"], "both list items are directories");
}

#[test]
fn separate_entries_are_told_from_a_shared_one() {
    let two = cargo_entries(TWO_ENTRIES);
    assert_ne!(
        entries_for(&two, "/"),
        entries_for(&two, "/fuzz"),
        "two entries read as one"
    );
    let one = cargo_entries(ONE_ENTRY);
    assert_eq!(
        entries_for(&one, "/"),
        entries_for(&one, "/fuzz"),
        "one entry read as two"
    );
}

#[test]
fn a_commented_entry_is_not_an_entry() {
    let yml = "updates:\n  # - package-ecosystem: \"cargo\"\n  #   directory: \"/old\"\n  - package-ecosystem: \"cargo\"\n    directory: \"/\"\n";
    let e = cargo_entries(yml);
    assert_eq!(e.len(), 1, "the commented entry was read");
    assert_eq!(e[0].dirs, ["/"], "the commented directory was read");
}

#[test]
fn a_commented_directory_inside_an_entry_is_not_read() {
    let yml = "  - package-ecosystem: \"cargo\"\n    directories:\n      - \"/\"\n      # - \"/gone\"\n      - \"/fuzz\"\n";
    assert_eq!(
        cargo_entries(yml)[0].dirs,
        ["/", "/fuzz"],
        "a commented list item was read as a directory"
    );
}

#[test]
fn a_list_under_another_key_is_not_a_directory() {
    let yml = "  - package-ecosystem: \"cargo\"\n    directories:\n      - \"/\"\n    ignore:\n      - \"/not-a-directory\"\n";
    assert_eq!(
        cargo_entries(yml)[0].dirs,
        ["/"],
        "an item of another list was read as a directory"
    );
}

#[test]
fn another_ecosystem_is_not_a_cargo_entry() {
    let yml = "  - package-ecosystem: \"npm\"\n    directory: \"/\"\n  - package-ecosystem: \"cargo-vet\"\n    directory: \"/\"\n";
    assert!(
        cargo_entries(yml).is_empty(),
        "an entry of another ecosystem was read as cargo"
    );
}

#[test]
fn a_file_with_no_entries_has_none() {
    assert!(
        cargo_entries("version: 2\nupdates: []\n").is_empty(),
        "an empty list of updates has no entries"
    );
    assert!(cargo_entries("").is_empty(), "an empty file has no entries");
}

#[test]
fn an_entry_with_no_directory_has_none() {
    let e = cargo_entries(
        "  - package-ecosystem: \"cargo\"\n    schedule:\n      interval: \"weekly\"\n",
    );
    assert_eq!(e.len(), 1, "the entry itself is read");
    assert!(e[0].dirs.is_empty(), "a directory was invented");
}

#[test]
fn groups_are_the_keys_under_groups() {
    let e = cargo_entries(ONE_ENTRY);
    assert_eq!(
        group_names(&e[0].block),
        ["both"],
        "the group key is the name"
    );
    let two = "    groups:\n      first:\n        patterns:\n          - \"*\"\n      second:\n        update-types:\n          - \"patch\"\n    commit-message:\n      prefix: \"deps\"\n";
    assert_eq!(
        group_names(two),
        ["first", "second"],
        "nested keys and later keys are not groups"
    );
}

#[test]
fn an_entry_without_groups_has_no_group() {
    assert!(
        group_names("    directory: \"/\"\n    schedule:\n      interval: \"weekly\"\n").is_empty(),
        "a group was invented"
    );
}

#[test]
fn quoted_takes_the_first_quoted_text() {
    assert_eq!(
        quoted(" \"/a\" # \"/b\"").as_deref(),
        Some("/a"),
        "the first quoted text is the value, not a later one"
    );
    assert_eq!(
        quoted("- \"\"").as_deref(),
        Some(""),
        "an empty string is a value"
    );
    assert_eq!(
        quoted("no quotes"),
        None,
        "text without quotes has no value"
    );
    assert_eq!(quoted(""), None, "an empty line has no value");
}

fn table(text: &str) -> Result<toml::Table, TestError> {
    Ok(toml::from_str(text)?)
}

#[test]
fn inherited_lints_are_found() -> Result<(), TestError> {
    let t = table("[package]\nname = \"p\"\n\n[lints]\nworkspace = true\n")?;
    assert_eq!(inherited(&t), ["lints"], "the lints table inherits");
    Ok(())
}

#[test]
fn inherited_package_keys_and_dependencies_are_found() -> Result<(), TestError> {
    let t = table(
        "[package]\nname = \"p\"\nversion.workspace = true\n\n[dependencies]\nserde = { workspace = true }\nlibc = \"1\"\n",
    )?;
    assert_eq!(
        inherited(&t),
        ["dependencies.serde", "package.version"],
        "every table holding workspace = true is listed"
    );
    Ok(())
}

#[test]
fn stated_lints_inherit_nothing() -> Result<(), TestError> {
    let t = table("[package]\nname = \"p\"\n\n[lints.clippy]\nptr_arg = \"deny\"\n")?;
    assert!(
        inherited(&t).is_empty(),
        "a stated table was read as inherited"
    );
    Ok(())
}

#[test]
fn workspace_false_inherits_nothing() -> Result<(), TestError> {
    let t = table("[package]\nname = \"p\"\n\n[lints]\nworkspace = false\n")?;
    assert!(
        inherited(&t).is_empty(),
        "workspace = false was read as inheriting"
    );
    Ok(())
}

#[test]
fn the_workspace_table_itself_is_not_inheritance() -> Result<(), TestError> {
    let t =
        table("[workspace]\nmembers = [\".\"]\n\n[workspace.lints.clippy]\nptr_arg = \"deny\"\n")?;
    assert!(
        inherited(&t).is_empty(),
        "the [workspace] table was read as inheriting"
    );
    assert!(
        is_workspace_root(&t),
        "a manifest with [workspace] is a root"
    );
    Ok(())
}

#[test]
fn a_package_alone_is_no_workspace_root() -> Result<(), TestError> {
    assert!(
        !is_workspace_root(&table("[package]\nname = \"p\"\n")?),
        "a manifest without [workspace] was read as a root"
    );
    assert!(
        !is_workspace_root(&table("workspace = true\n")?),
        "a `workspace` key that is no table was read as a root"
    );
    Ok(())
}

#[test]
fn a_root_that_inherits_from_itself_is_a_root() -> Result<(), TestError> {
    let t = table(
        "[workspace]\n\n[workspace.lints.clippy]\nptr_arg = \"deny\"\n\n[package]\nname = \"p\"\n\n[lints]\nworkspace = true\n",
    )?;
    assert_eq!(inherited(&t), ["lints"], "the package inherits");
    assert!(is_workspace_root(&t), "and it is the root it inherits from");
    Ok(())
}

#[test]
fn a_listed_member_is_a_member() -> Result<(), TestError> {
    let t = table("[workspace]\nmembers = [\".\", \"crates/a\"]\nexclude = [\"bpf\"]\n")?;
    assert!(is_member(&t, "crates/a"), "a listed member was not found");
    assert!(
        !is_member(&t, "bpf"),
        "an excluded directory was read as a member"
    );
    assert!(
        !is_member(&t, "crates/b"),
        "an unlisted directory was read as a member"
    );
    Ok(())
}

#[test]
fn a_manifest_without_a_workspace_has_no_member() -> Result<(), TestError> {
    assert!(
        !is_member(&table("[package]\nname = \"p\"\n")?, "crates/a"),
        "a member was found with no workspace"
    );
    assert!(
        !is_member(&table("[workspace]\nexclude = [\"x\"]\n")?, "x"),
        "a workspace with no member list has no member"
    );
    Ok(())
}

#[test]
fn the_bpf_workspace_excludes_the_shared_crate() -> Result<(), TestError> {
    assert!(
        !is_member(&manifest("bpf/Cargo.toml")?, "sipnab-bpf-types"),
        "the shared crate became a member of the bpf workspace: see bpf/Cargo.toml \
         for why it must stay a member of the root workspace"
    );
    Ok(())
}

#[test]
fn path_dependencies_are_found_in_every_table() -> Result<(), TestError> {
    let t = table(
        "[dependencies]\na = { path = \"../a\" }\nserde = \"1\"\n\n[dev-dependencies]\nb = { path = \"b\" }\n\n[build-dependencies]\nc = { path = \"c\", version = \"1\" }\n\n[target.'cfg(unix)'.dependencies]\nd = { path = \"d\" }\n",
    )?;
    assert_eq!(
        path_dependencies(&t),
        ["../a", "b", "c", "d"],
        "a path dependency in one of the tables was missed"
    );
    Ok(())
}

#[test]
fn registry_dependencies_are_not_path_dependencies() -> Result<(), TestError> {
    let t = table(
        "[dependencies]\nserde = \"1\"\naya = { version = \"0.16\", optional = true }\ng = { git = \"https://example.invalid/g\" }\n",
    )?;
    assert!(
        path_dependencies(&t).is_empty(),
        "a registry or git dependency was read as a path dependency"
    );
    Ok(())
}

#[test]
fn a_manifest_without_dependencies_has_no_path_dependency() -> Result<(), TestError> {
    assert!(
        path_dependencies(&table("[package]\nname = \"p\"\n")?).is_empty(),
        "a path dependency was invented"
    );
    Ok(())
}

#[test]
fn a_path_named_twice_is_listed_once() -> Result<(), TestError> {
    let t = table(
        "[dependencies]\na = { path = \"x\" }\n\n[dev-dependencies]\na = { path = \"x\" }\n",
    )?;
    assert_eq!(path_dependencies(&t), ["x"], "one path was listed twice");
    Ok(())
}

#[test]
fn the_real_bpf_manifest_depends_on_the_shared_crate_by_path() -> Result<(), TestError> {
    assert_eq!(
        path_dependencies(&manifest("bpf/Cargo.toml")?),
        ["sipnab-bpf-types"],
        "bpf/Cargo.toml's path dependencies changed: the tests above read them"
    );
    Ok(())
}

// ── Which fetched manifests cargo cannot load ───────────────────────

const ROOT: &str = "[workspace]\nmembers = [\".\", \"crates/a\"]\nexclude = [\"fuzz\", \"bpf\"]\n\n[workspace.lints.clippy]\nptr_arg = \"deny\"\n\n[package]\nname = \"root\"\n\n[lints]\nworkspace = true\n";
const INHERITS: &str = "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n";
const STATES: &str = "[package]\nname = \"a\"\n\n[lints.clippy]\nptr_arg = \"deny\"\n";
const OWN_ROOT: &str = "[package]\nname = \"bpf\"\n\n[workspace]\nexclude = [\"types\"]\n";

fn fetched(items: &[(&str, &str)]) -> Result<Vec<(String, toml::Table)>, TestError> {
    items
        .iter()
        .map(|(dir, text)| Ok(((*dir).to_string(), table(text)?)))
        .collect()
}

/// The `/fuzz` shape: the member's root is fetched as another path
/// dependency, so the member loads.
#[test]
fn a_member_loads_when_its_root_is_fetched_beside_it() -> Result<(), TestError> {
    let f = fetched(&[
        ("", ROOT),
        ("crates/a", INHERITS),
        ("fuzz", "[package]\nname = \"f\"\n"),
    ])?;
    assert!(
        unresolvable(&f).is_empty(),
        "a member whose root is fetched was reported: {:?}",
        unresolvable(&f)
    );
    Ok(())
}

/// The `/bpf` shape before the fix: the directory is its own root and
/// excludes the crate, and the crate's real root is not fetched.
#[test]
fn a_member_of_a_root_that_is_not_fetched_does_not_load() -> Result<(), TestError> {
    let f = fetched(&[("bpf", OWN_ROOT), ("bpf/types", INHERITS)])?;
    assert_eq!(
        unresolvable(&f),
        [("bpf/types".to_string(), vec!["lints".to_string()])],
        "the crate that inherits from an unfetched root was not reported"
    );
    Ok(())
}

/// The `/bpf` shape after the fix.
#[test]
fn a_crate_that_states_its_lints_loads_under_any_root() -> Result<(), TestError> {
    let f = fetched(&[("bpf", OWN_ROOT), ("bpf/types", STATES)])?;
    assert!(
        unresolvable(&f).is_empty(),
        "a self-contained crate was reported"
    );
    Ok(())
}

#[test]
fn a_root_that_inherits_from_itself_loads() -> Result<(), TestError> {
    let f = fetched(&[("", ROOT)])?;
    assert!(
        unresolvable(&f).is_empty(),
        "the workspace root was reported"
    );
    Ok(())
}

#[test]
fn a_crate_the_fetched_root_does_not_list_does_not_load() -> Result<(), TestError> {
    let f = fetched(&[("", ROOT), ("crates/b", INHERITS)])?;
    assert_eq!(
        unresolvable(&f).len(),
        1,
        "a crate that is no member of the fetched root was not reported"
    );
    Ok(())
}

#[test]
fn a_directory_whose_name_starts_like_the_root_is_not_inside_it() -> Result<(), TestError> {
    let root = "[workspace]\nmembers = [\"x\"]\n";
    let f = fetched(&[("bpf", root), ("bpf-other/x", INHERITS)])?;
    assert_eq!(
        unresolvable(&f).len(),
        1,
        "bpf-other/x was read as bpf's member x"
    );
    let inside = fetched(&[("bpf", root), ("bpf/x", INHERITS)])?;
    assert!(unresolvable(&inside).is_empty(), "bpf/x is bpf's member x");
    Ok(())
}

#[test]
fn nothing_fetched_means_nothing_lost() {
    assert!(unresolvable(&[]).is_empty(), "a manifest was invented");
}

#[test]
fn every_lost_manifest_is_reported() -> Result<(), TestError> {
    let f = fetched(&[("bpf", OWN_ROOT), ("bpf/a", INHERITS), ("bpf/b", INHERITS)])?;
    assert_eq!(
        unresolvable(&f).len(),
        2,
        "one of two lost manifests was dropped"
    );
    Ok(())
}

#[test]
fn lexical_paths_drop_dot_segments() {
    assert_eq!(
        lexical("fuzz/../crates/g729").as_deref(),
        Some("crates/g729"),
        "`..` removes the segment before it"
    );
    assert_eq!(
        lexical("fuzz/..").as_deref(),
        Some(""),
        "the root is the empty string"
    );
    assert_eq!(
        lexical("./bpf//types/").as_deref(),
        Some("bpf/types"),
        "`.` and empty segments are dropped"
    );
    assert_eq!(
        lexical("").as_deref(),
        Some(""),
        "an empty path is the root"
    );
}

#[test]
fn a_path_that_leaves_the_repository_has_no_lexical_form() {
    assert_eq!(
        lexical(".."),
        None,
        "`..` from the root leaves the repository"
    );
    assert_eq!(
        lexical("a/../../b"),
        None,
        "one `..` too many leaves the repository"
    );
}

#[test]
fn join_treats_the_empty_directory_as_the_root() {
    assert_eq!(
        join("", "Cargo.toml"),
        "Cargo.toml",
        "the root adds no separator"
    );
    assert_eq!(join("fuzz", ".."), "fuzz/..", "join does not resolve");
    assert_eq!(
        join("bpf", "Cargo.toml"),
        "bpf/Cargo.toml",
        "a directory and a name are joined with one separator"
    );
}
