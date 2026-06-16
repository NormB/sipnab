use std::path::Path;
use std::process::Command;

fn main() {
    // Re-run when HEAD moves so the embedded commit hash stays in sync with the
    // working tree. Watching `.git/HEAD` alone misses commits on the *current*
    // branch (HEAD keeps pointing at the same ref); watching the resolved ref
    // file and `packed-refs` covers both loose and packed refs.
    emit_git_rerun_triggers();

    let commit = git(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_default();
    let tag = git(&["describe", "--tags", "--exact-match", "HEAD"]).unwrap_or_default();
    // "-dirty" reflects only TRACKED modifications. `--untracked-files=no` keeps
    // untracked scratch paths (e.g. the `harness/` integration harness or the
    // Zola-generated `website/public/`) from marking an otherwise-clean build
    // dirty; only edits to checked-in files count.
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .map(|s| if s.is_empty() { "" } else { "-dirty" })
        .unwrap_or("");

    println!("cargo:rustc-env=SIPNAB_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=SIPNAB_GIT_TAG={tag}");
    println!("cargo:rustc-env=SIPNAB_GIT_DIRTY={dirty}");

    // The `audio` feature no longer links libasound into the binary: device
    // output lives in the `sipnab-audio` cdylib plugin, which the binary
    // dlopen's lazily. The binary thus starts fine without libasound — only
    // live playback needs it — so no build-time runtime-dependency warning is
    // required for the `audio` feature anymore.
}

/// Emit `cargo:rerun-if-changed` lines so a new commit (on any branch) forces
/// the build script to re-run and re-capture the commit hash.
///
/// `.git/HEAD` catches branch switches; the resolved ref file catches commits
/// on the current branch when refs are loose; `packed-refs` catches them when
/// refs have been packed (e.g. after `git gc`). Falls back gracefully when the
/// `.git` directory is absent (building from a published tarball).
fn emit_git_rerun_triggers() {
    let git_dir = Path::new(".git");
    if !git_dir.exists() {
        return;
    }
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/packed-refs");

    // Resolve the ref HEAD points at (e.g. "ref: refs/heads/main") and watch
    // that loose ref file directly.
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD"))
        && let Some(ref_path) = head.strip_prefix("ref:").map(str::trim)
    {
        println!("cargo:rerun-if-changed=.git/{ref_path}");
    }
}

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
