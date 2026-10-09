// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hosted cargo caches stay resident in the repository's 10 GB.
//!
//! GitHub keeps at most 10 GB of `actions/cache` entries per repository and
//! evicts the least recently used entry past that. Measured on 2026-10-09: the
//! active entries totaled 15.1 GB in 36 entries, 35 of them saved from main
//! between 04:03 and 04:24 UTC, during the runs of one push. The `Check (macos-latest)` cargo cache missed on 12 of
//! 14 runs (PR and main) and the `Check (ubuntu-latest)` cache on 11 of 14,
//! while the Cargo.lock hash in their keys never changed. Each miss rebuilt
//! and saved the entry again, which evicted another. Three causes:
//!
//! - Pull request runs saved caches. An entry saved by a pull request run is
//!   readable only by runs of that pull request, yet it counts against the
//!   same 10 GB as main's entries.
//! - One main push saved more than 10 GB, 5.0 GB of it the Coverage job's
//!   instrumented target directory. Coverage with an exact hit took 15.3 to
//!   21.2 minutes and with a miss 15.8 to 20.1 minutes: the restore and save
//!   cost what the hit saved.
//! - Keys named `runner.os` without `runner.arch`, and restore-keys fell back
//!   to other jobs' entries. The x86_64 Coverage, Benchmarks and Clippy SARIF
//!   jobs restored the aarch64 Check leg's 4.4 GB `Linux-cargo-` entry, whose
//!   target directory they cannot use; Benchmarks after that fallback took
//!   12.5 to 13.8 minutes, against 7.5 to 11.7 on a clean miss.
//!
//! The policy these tests hold:
//!
//! - A cargo cache is restored with `actions/cache/restore` and saved with
//!   `actions/cache/save`, never with `actions/cache`, whose post step saves
//!   from any ref.
//! - The save runs only on `refs/heads/main`, only after a miss, and only
//!   after `scripts/ci-cache-prune.sh` has removed the workspace's own
//!   executables, which every change to the sources rebuilds anyway.
//! - The key names the OS, the architecture, the toolchain and Cargo.lock,
//!   and every restore-key is a prefix of the job's own key.
//! - The set of cargo cache families is the named list below.

use std::path::{Path, PathBuf};
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

const PRUNE_SCRIPT: &str = "scripts/ci-cache-prune.sh";

/// The `if:` clause every cargo cache save carries: main only, after a miss.
const SAVE_ON_MAIN: &str = "github.ref == 'refs/heads/main'";
const SAVE_ON_MISS: &str = "cache-hit != 'true'";

/// Every cargo cache family, as the text of its key before the first `-${{`.
///
/// Each family is one entry per runner OS, architecture, toolchain and
/// Cargo.lock (and target, for the symbol split). A family is added here
/// only with the measurement that shows its hit pays for its share of the
/// 10 GB. Sizes are the entries present on 2026-10-09, before the prune:
///
/// - `cargo-check`: Linux aarch64 4.4 GB, macOS 1.8 GB. Check is the
///   slowest required job.
/// - `cargo-symbol-split`: 0.27 GB and 0.20 GB.
/// - `cargo-features`: self-hosted only, where the step is skipped, so no
///   entry exists.
/// - `cargo-bench`: 0.87 GB.
/// - `cargo-clippy-sarif`: 0.35 GB; a median of 3.7 minutes over 5 runs with
///   a hit, 5.5 over 7 with a miss.
/// - `cargo-pages-wasm`: 0.30 GB, saved by main pushes only.
const CARGO_CACHE_FAMILIES: &[&str] = &[
    "cargo-bench",
    "cargo-check",
    "cargo-clippy-sarif",
    "cargo-features",
    "cargo-pages-wasm",
    "cargo-symbol-split",
];

/// One step that uses an `actions/cache` action.
#[derive(Debug)]
struct CacheStep {
    /// `<file>:<job id>`, or the action file for a composite action.
    origin: String,
    /// The text after `actions/cache`: `@`, `/restore@` or `/save@`.
    variant: String,
    id: Option<String>,
    cond: Option<String>,
    path: String,
    key: Option<String>,
    restore_keys: Vec<String>,
    /// The full text of the job the step is in.
    job_body: String,
    /// The step's own text.
    text: String,
}

impl CacheStep {
    /// A cargo build cache: it holds a target directory or `~/.cargo`.
    fn is_cargo(&self) -> bool {
        self.path.lines().any(|l| {
            let t = l.trim();
            t == "target" || t.starts_with("target/") || t.contains(".cargo")
        })
    }
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The value of `field:` among a step's top-level lines, joined with its
/// block lines when it is a `|` block.
fn field(step: &[&str], dash: usize, name: &str) -> Option<String> {
    let want = format!("{name}:");
    for (i, line) in step.iter().enumerate() {
        let t = line.trim_start();
        let t = t.strip_prefix("- ").unwrap_or(t);
        if !t.starts_with(&want) {
            continue;
        }
        // A top-level field of the step sits at dash+2, or follows the dash.
        let ind = indent(line);
        let on_dash = line.trim_start().starts_with("- ");
        let in_with = ind > dash + 2;
        if !on_dash && ind != dash + 2 && !in_with {
            continue;
        }
        let rest = t[want.len()..].trim();
        if rest == "|" || rest.is_empty() {
            let mut out = String::new();
            for next in &step[i + 1..] {
                if next.trim().is_empty() {
                    continue;
                }
                if indent(next) <= ind {
                    break;
                }
                out.push_str(next.trim());
                out.push('\n');
            }
            return Some(out);
        }
        return Some(rest.to_string());
    }
    None
}

/// Every `actions/cache` step in `text`, with the job it belongs to.
fn cache_steps(file: &str, text: &str) -> Vec<CacheStep> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with('#') {
            continue;
        }
        let Some(at) = t.find("uses: actions/cache") else {
            continue;
        };
        let after = &t[at + "uses: actions/cache".len()..];
        let variant = after.split('@').next().unwrap_or("").to_string() + "@";
        // The step starts at the nearest `- ` at or above this line.
        let Some(start) = (0..=i)
            .rev()
            .find(|&j| lines[j].trim_start().starts_with("- ") && indent(lines[j]) <= indent(line))
        else {
            continue;
        };
        let dash = indent(lines[start]);
        let mut end = i + 1;
        while end < lines.len() {
            let l = lines[end];
            if !l.trim().is_empty() && !l.trim_start().starts_with('#') && indent(l) <= dash {
                break;
            }
            end += 1;
        }
        let step = &lines[start..end];
        // The enclosing job: the last two-space key above the step.
        let job_start = (0..start)
            .rev()
            .find(|&j| {
                let l = lines[j];
                l.starts_with("  ")
                    && !l.starts_with("   ")
                    && !l.trim_start().starts_with('#')
                    && l.trim_end().ends_with(':')
            })
            .unwrap_or(0);
        let job_end = (start..lines.len())
            .find(|&j| {
                let l = lines[j];
                (l.starts_with("  ")
                    && !l.starts_with("   ")
                    && !l.trim_start().starts_with('#')
                    && l.trim_end().ends_with(':')
                    && j > job_start)
                    || (!l.starts_with(' ') && !l.trim().is_empty() && !l.starts_with('#'))
            })
            .unwrap_or(lines.len());
        let job_id = lines[job_start].trim().trim_end_matches(':');
        out.push(CacheStep {
            origin: format!("{file}:{job_id}"),
            variant,
            id: field(step, dash, "id"),
            cond: field(step, dash, "if"),
            path: field(step, dash, "path").unwrap_or_default(),
            key: field(step, dash, "key"),
            restore_keys: field(step, dash, "restore-keys")
                .map(|v| v.lines().map(str::to_string).collect())
                .unwrap_or_default(),
            job_body: lines[job_start..job_end].join("\n"),
            text: step.join("\n"),
        });
    }
    out
}

/// Every cache step in every workflow and composite action.
fn all_cache_steps() -> Result<Vec<CacheStep>, TestError> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(repo().join(".github/workflows"))? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) == Some("yml") {
            files.push(p);
        }
    }
    for entry in std::fs::read_dir(repo().join(".github/actions"))? {
        let p = entry?.path().join("action.yml");
        if p.exists() {
            files.push(p);
        }
    }
    files.sort();
    let mut out = Vec::new();
    for p in files {
        let rel = p
            .strip_prefix(repo())
            .map_err(|e| format!("{}: {e}", p.display()))?
            .display()
            .to_string();
        out.extend(cache_steps(&rel, &std::fs::read_to_string(&p)?));
    }
    Ok(out)
}

fn cargo_steps() -> Result<Vec<CacheStep>, TestError> {
    let steps: Vec<CacheStep> = all_cache_steps()?
        .into_iter()
        .filter(CacheStep::is_cargo)
        .collect();
    assert!(
        steps.len() >= 6,
        "only {} cargo cache step(s) found; the step scan is wrong and these \
         gates prove nothing: {steps:#?}",
        steps.len()
    );
    Ok(steps)
}

/// The text of a key before its first `${{` expression, without the dash.
fn family(key: &str) -> &str {
    key.split("${{").next().unwrap_or("").trim_end_matches('-')
}

/// No cargo cache uses `actions/cache` itself: its post step saves from
/// whatever ref the run is on, a pull request's included.
#[test]
fn no_cargo_cache_uses_the_action_that_saves_from_any_ref() -> Result<(), TestError> {
    let defects: Vec<String> = cargo_steps()?
        .iter()
        .filter(|s| s.variant != "/restore@" && s.variant != "/save@")
        .map(|s| {
            format!(
                "{}: uses actions/cache{}; restore with actions/cache/restore and \
                 save with actions/cache/save under `if: {SAVE_ON_MAIN}`",
                s.origin, s.variant
            )
        })
        .collect();
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// Every cargo cache save runs on main only, after a miss of the restore in
/// the same job, with the restore's key and path, after the prune.
#[test]
fn every_cargo_cache_save_is_main_only_after_a_miss_and_a_prune() -> Result<(), TestError> {
    let steps = cargo_steps()?;
    let mut defects = Vec::new();
    let mut saves = 0;
    for save in steps.iter().filter(|s| s.variant == "/save@") {
        saves += 1;
        let cond = save.cond.clone().unwrap_or_default();
        if !cond.contains(SAVE_ON_MAIN) {
            defects.push(format!(
                "{}: the save's `if:` lacks `{SAVE_ON_MAIN}`, so a pull request \
                 run saves an entry no other pull request can read",
                save.origin
            ));
        }
        if !cond.contains(SAVE_ON_MISS) {
            defects.push(format!(
                "{}: the save's `if:` lacks `{SAVE_ON_MISS}`",
                save.origin
            ));
        }
        let restore = steps.iter().find(|r| {
            r.variant == "/restore@"
                && r.origin == save.origin
                && r.id.as_deref().is_some_and(|id| {
                    save.key.as_deref()
                        == Some(&format!("${{{{ steps.{id}.outputs.cache-primary-key }}}}"))
                        && cond.contains(&format!("steps.{id}.outputs.{SAVE_ON_MISS}"))
                })
        });
        match restore {
            None => defects.push(format!(
                "{}: the save's key is not `${{{{ steps.<restore id>.outputs.cache-primary-key }}}}` \
                 of a restore in the same job, or its `if:` does not test that \
                 restore's cache-hit",
                save.origin
            )),
            Some(r) if r.path != save.path => defects.push(format!(
                "{}: the save's path differs from the restore's",
                save.origin
            )),
            Some(_) => {}
        }
        let save_at = save.job_body.find(&save.text);
        let prune_at = save.job_body.find(PRUNE_SCRIPT);
        match (prune_at, save_at) {
            (Some(p), Some(s)) if p < s => {}
            _ => defects.push(format!(
                "{}: no `{PRUNE_SCRIPT}` step before the save",
                save.origin
            )),
        }
    }
    for restore in steps.iter().filter(|s| s.variant == "/restore@") {
        if !steps
            .iter()
            .any(|s| s.variant == "/save@" && s.origin == restore.origin)
        {
            defects.push(format!(
                "{}: restores a cargo cache that nothing in the job saves",
                restore.origin
            ));
        }
    }
    assert!(
        saves > 0,
        "no cargo cache save step exists, so no entry is ever written"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// Every cargo cache key names the OS, the architecture, the toolchain the
/// job installed and Cargo.lock, and every restore-key is a prefix of the
/// job's own key, so no job restores another job's or another architecture's
/// target directory.
#[test]
fn every_cargo_cache_key_names_os_arch_toolchain_and_lockfile() -> Result<(), TestError> {
    let mut defects = Vec::new();
    // Every step that looks an entry up: a restore, and the combined action.
    for s in cargo_steps()?.iter().filter(|s| s.variant != "/save@") {
        let Some(key) = s.key.as_deref() else {
            defects.push(format!("{}: no key", s.origin));
            continue;
        };
        for part in ["runner.os", "runner.arch", "hashFiles('**/Cargo.lock')"] {
            if !key.contains(part) {
                defects.push(format!("{}: key `{key}` lacks `{part}`", s.origin));
            }
        }
        // The toolchain: the `cachekey` output of the job's
        // dtolnay/rust-toolchain step, by that step's id.
        let toolchain_id = key
            .find(".outputs.cachekey")
            .and_then(|at| key[..at].rsplit("steps.").next());
        match toolchain_id {
            None => defects.push(format!(
                "{}: key `{key}` lacks the toolchain step's `outputs.cachekey`",
                s.origin
            )),
            Some(id) => {
                // The `id:` and the `uses:` are adjacent lines of one step.
                let declared = s.job_body.lines().collect::<Vec<_>>().windows(2).any(|w| {
                    w.iter()
                        .any(|l| l.contains("uses: dtolnay/rust-toolchain@"))
                        && w.iter().any(|l| {
                            let t = l.trim();
                            t.strip_prefix("- ").unwrap_or(t) == format!("id: {id}")
                        })
                });
                if !declared {
                    defects.push(format!(
                        "{}: no dtolnay/rust-toolchain step with `id: {id}` in the job",
                        s.origin
                    ));
                }
            }
        }
        for rk in &s.restore_keys {
            if !key.starts_with(rk.as_str()) {
                defects.push(format!(
                    "{}: restore-key `{rk}` is not a prefix of the key `{key}`, so \
                     the job can restore an entry another job or architecture saved",
                    s.origin
                ));
            }
        }
    }
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// The cargo cache families are exactly the named list. A new family, or the
/// return of one that was removed (Coverage's 5.0 GB), fails here until the
/// list and its measurement say why it pays for its share of the 10 GB.
#[test]
fn the_cargo_cache_families_are_the_named_set() -> Result<(), TestError> {
    let mut found: Vec<String> = cargo_steps()?
        .iter()
        .filter_map(|s| s.key.as_deref().map(family).map(str::to_string))
        .filter(|f| !f.is_empty())
        .collect();
    found.sort();
    found.dedup();
    let named: Vec<String> = CARGO_CACHE_FAMILIES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        found, named,
        "the cargo cache key families differ from CARGO_CACHE_FAMILIES"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// scripts/ci-cache-prune.sh, driven for real on temporary directories.
// ---------------------------------------------------------------------------

fn prune(args: &[&str]) -> Result<i32, TestError> {
    let out = Command::new("bash")
        .arg(repo().join(PRUNE_SCRIPT))
        .args(args)
        .output()?;
    out.status
        .code()
        .ok_or_else(|| "the prune script was killed by a signal".into())
}

fn write(path: &Path, executable: bool) -> Result<(), TestError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, b"x")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn arg(p: &Path) -> Result<&str, TestError> {
    p.to_str().ok_or_else(|| "non-UTF-8 temp path".into())
}

/// The files a dependency build leaves, which a later build reuses.
const KEPT: &[(&str, bool)] = &[
    ("debug/deps/libserde-0a1b.rlib", false),
    ("debug/deps/libserde-0a1b.rmeta", false),
    ("debug/deps/serde-0a1b.d", false),
    ("debug/deps/libserde_derive-2c3d.so", true),
    ("debug/deps/libserde_derive-2c3d.dylib", true),
    ("debug/build/ring-4e5f/build-script-build", true),
    ("debug/build/ring-4e5f/out/libring_core.a", false),
    ("debug/.fingerprint/serde-0a1b/lib-serde", false),
    (
        "aarch64-apple-darwin/release/deps/libtokio-6a7b.rlib",
        false,
    ),
];

/// The workspace's own executables, which a change to its sources rebuilds.
const REMOVED: &[&str] = &[
    "debug/deps/sipnab-1111",
    "debug/deps/ci_cache_policy_test-2222",
    "debug/sipnab",
    "debug/examples/hep_send-3333",
    "debug/incremental/sipnab-4444/s-abc/dep-graph.bin",
    "profiling/deps/capture_bench-5555",
    "aarch64-apple-darwin/release/deps/sipnab-6666",
    "aarch64-apple-darwin/release/sipnab",
];

#[test]
fn the_prune_removes_workspace_executables_and_keeps_dependencies() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let t = tmp.path().join("target");
    for (rel, exec) in KEPT {
        write(&t.join(rel), *exec)?;
    }
    for rel in REMOVED {
        write(&t.join(rel), !rel.contains("/incremental/"))?;
    }
    let rc = prune(&[arg(&t)?])?;
    assert_eq!(rc, 0, "the prune must exit 0");
    for (rel, _) in KEPT {
        assert!(
            t.join(rel).exists(),
            "the prune removed {rel}, which a later build reuses"
        );
    }
    for rel in REMOVED {
        assert!(!t.join(rel).exists(), "the prune kept {rel}");
    }
    Ok(())
}

#[test]
fn the_prune_of_a_missing_directory_is_not_an_error() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let rc = prune(&[arg(&tmp.path().join("never-built"))?])?;
    assert_eq!(rc, 0, "a job that built nothing has no target directory");
    Ok(())
}

#[test]
fn the_prune_refuses_bad_arguments_with_exit_2() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let t = tmp.path().join("target");
    write(&t.join("debug/deps/sipnab-1111"), true)?;
    let d = arg(&t)?;
    for args in [
        vec![],
        vec![d, d],
        vec!["relative/target"],
        vec![""],
        vec!["/"],
    ] {
        let rc = prune(&args)?;
        assert_eq!(rc, 2, "arguments {args:?} must be refused with exit 2");
    }
    assert!(
        t.join("debug/deps/sipnab-1111").exists(),
        "a refused invocation removed something"
    );
    Ok(())
}
