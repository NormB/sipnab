// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build script: embeds git/version metadata for `sipnab --version`.

use std::path::Path;
use std::process::Command;

fn main() {
    // Re-run when HEAD moves so the embedded commit hash stays in sync with the
    // working tree. Watching `.git/HEAD` alone misses commits on the *current*
    // branch (HEAD keeps pointing at the same ref); watching the resolved ref
    // file and `packed-refs` covers both loose and packed refs.
    emit_git_rerun_triggers();

    // `sipnab_tsan` is set by `.github/workflows/sanitizers.yml` (and by any
    // local ThreadSanitizer build) to swap mimalloc for the system allocator --
    // see the comment on the `#[global_allocator]` in src/main.rs. Declaring it
    // here is what keeps `unexpected_cfgs` quiet on every ordinary build, so a
    // typo in the flag name stays a lint error instead of silently never
    // matching.
    println!("cargo::rustc-check-cfg=cfg(sipnab_tsan)");

    // The eBPF capture backend's kernel half. Behind the feature so that a
    // stock `cargo build` never reaches it: it needs a nightly toolchain and
    // `bpf-linker`, and this crate pins stable 1.97.1.
    build_bpf();

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

/// Run `git` with the given arguments and return trimmed stdout.
///
/// Returns `None` when git is unavailable, exits non-zero, or emits
/// non-UTF-8 output, so the build falls back to placeholder values.
fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Build `bpf/` for `bpfel-unknown-none` and put the object where the loader's
/// `include_bytes!` can find it.
///
/// **A separate package, on purpose.** `bpf/` carries its own empty
/// `[workspace]` table and sits in the root manifest's `exclude` list, so a
/// host build never resolves its dependencies or its nightly toolchain file.
/// Pulling it into the workspace would make a stock `cargo build` demand a
/// toolchain most contributors do not have.
#[cfg(feature = "bpf")]
fn build_bpf() {
    use std::process::Stdio;

    println!("cargo:rerun-if-changed=bpf/src");
    println!("cargo:rerun-if-changed=bpf/Cargo.toml");
    println!("cargo:rerun-if-changed=crates/sipnab-bpf-types/src");

    let out_dir = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR for build scripts"),
    );
    // Its own target directory: cargo takes a lock per target dir, and the
    // inner build runs while the outer one holds ours.
    let target_dir = out_dir.join("bpf-target");

    // `bpfel` on a little-endian host, `bpfeb` on a big-endian one. Derived
    // rather than assumed, because the BPF object's byte order has to match the
    // machine that will load it.
    let endian = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
    let prefix = match endian.as_str() {
        "big" => "bpfeb",
        "little" => "bpfel",
        other => panic!("cannot build BPF for an unknown target endianness: {other:?}"),
    };
    let bpf_target = format!("{prefix}-unknown-none");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // `--manifest-path`, NOT `--package`. The kernel crate is deliberately
    // excluded from this workspace, so cargo cannot resolve it by name from
    // here — `aya-build` builds that way and fails with a package-not-found
    // that says nothing about the cause.
    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--manifest-path",
            "bpf/Cargo.toml",
            "-Z",
            "build-std=core",
            "--bins",
            "--release",
            "--target",
            &bpf_target,
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        // Debug info carries the BTF the loader needs to describe its maps.
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!("--cfg=bpf_target_arch=\"{arch}\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf"),
        )
        // The outer build's wrappers point at the stable toolchain; the inner
        // one must use nightly's own.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("could not run `rustup`, which the eBPF build needs to select nightly");

    assert!(
        status.success(),
        "building the eBPF programs failed. This needs a nightly toolchain and \
         bpf-linker, and bpf-linker must match the LLVM installed on this host \
         (0.9.13 pairs with LLVM 19; 0.11 wants LLVM 23.1)"
    );

    let built = target_dir
        .join(&bpf_target)
        .join("release")
        .join("sipnab-bpf");
    let dest = out_dir.join("sipnab-bpf");
    std::fs::copy(&built, &dest).unwrap_or_else(|e| {
        panic!(
            "the eBPF build reported success but produced no object at {}: {e}",
            built.display()
        )
    });
}

/// Without the feature there is nothing to build, and nothing to require.
#[cfg(not(feature = "bpf"))]
fn build_bpf() {}
