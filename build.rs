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
#[cfg(all(feature = "bpf", target_os = "linux"))]
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
    // ONE rule, TWO explicitly chosen modes.
    //
    // Default (`SIPNAB_BPF_REQUIRED` unset): a prerequisite this machine does
    // not have degrades. `--all-features` is the pre-push clippy gate, the
    // rustdoc gate and every contributor's habit, and it sweeps up every
    // feature including this one; exploding here would mean a contributor
    // without nightly or bpf-linker cannot build sipnab at all.
    //
    // `SIPNAB_BPF_REQUIRED=1`: the same prerequisites are hard errors. Set by
    // `.github/workflows/release.yml` on the targets that ship `bpf`. The
    // degrading path embeds an EMPTY placeholder object, so the binary
    // advertises `bpf` in `--version` and refuses at runtime on every host it
    // reaches -- the right trade for one contributor's laptop and exactly the
    // wrong one for an artefact thousands of people install.
    //
    // This used to be one-sided: a missing bpf-linker warned, a missing nightly
    // panicked. Which prerequisite is absent is not a property anyone chose,
    // and it is the wrong thing for the strictness to depend on.
    println!("cargo:rerun-if-env-changed=SIPNAB_BPF_REQUIRED");
    let required = std::env::var("SIPNAB_BPF_REQUIRED").is_ok_and(|v| v == "1");

    // Degrade, or refuse, depending on the mode. Never a silent no-op: the
    // placeholder is empty and the loader checks for it and refuses by name.
    let degrade_or_die = |reason: &str| {
        assert!(
            !required,
            "SIPNAB_BPF_REQUIRED=1 and the eBPF kernel programs cannot be built: \
             {reason}. A published binary must not advertise `bpf` in --version \
             and then refuse at runtime. Install a nightly toolchain \
             (`rustup toolchain install nightly`) and bpf-linker, matched to the \
             LLVM installed on this host (0.9.13 pairs with LLVM 19; 0.11 wants \
             LLVM 23.1)."
        );
        println!(
            "cargo:warning={reason}, so the `bpf` feature is compiled WITHOUT its \
             kernel programs. sipnab builds and every other backend works; \
             --uprobe-backend bpf will refuse at runtime rather than capture \
             nothing. Install a nightly toolchain and bpf-linker (0.9.13 pairs \
             with LLVM 19; 0.11 wants LLVM 23.1), or set SIPNAB_BPF_REQUIRED=1 to \
             turn this into a build failure."
        );
        std::fs::write(out_dir.join("sipnab-bpf"), b"")
            .expect("could not write the placeholder BPF object");
    };

    let have_linker = Command::new("bpf-linker")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !have_linker {
        degrade_or_die("bpf-linker not found");
        return;
    }

    let spawned = Command::new("rustup")
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
        .status();

    // Two distinguishable outcomes, both routed through the SAME rule:
    // `rustup` is absent (or nightly is not installed, which it reports as a
    // non-zero exit), and the kernel crate failed to compile. Neither can
    // produce an object, and a build that cannot produce one must not pretend
    // it did.
    match spawned {
        Err(e) => {
            degrade_or_die(&format!("could not run `rustup` to select nightly ({e})"));
            return;
        }
        Ok(status) if !status.success() => {
            degrade_or_die(
                "the nightly build of the eBPF programs failed (missing nightly \
                 toolchain, missing rust-src, or a bpf-linker that does not match \
                 this host's LLVM)",
            );
            return;
        }
        Ok(_) => {}
    }

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

/// Without the feature — or off Linux, where the programs could never load —
/// there is nothing to build and nothing to require.
#[cfg(not(all(feature = "bpf", target_os = "linux")))]
fn build_bpf() {}
