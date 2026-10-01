// SPDX-License-Identifier: MIT OR Apache-2.0

//! The release binary is bit-for-bit reproducible, and these tests hold the
//! pieces that make it so.
//!
//! OpenSSF Silver `build_repeatable` (a MUST at that level): the project must
//! be able to repeat the build of a release from its sources and get exactly
//! the same bytes. Measured on 2026-09-30, two release builds of one commit in
//! two directories were NOT identical: the embedded eBPF object carried the
//! absolute checkout path and the nightly toolchain's `rust-src` path in its
//! BTF, and the linker's build ID hashes the DWARF, where every C object from
//! `ring` and `mimalloc` names the builder's `$CARGO_HOME`. The nightly that
//! compiles the eBPF half was also whatever `nightly` meant on the day, so a
//! rebuild a week later compiled it with a different compiler.
//!
//! `scripts/reproducible-build.sh` is the
//! one rule: `release.yml` builds through it and the scheduled check in
//! `reproducible.yml` builds twice through it and compares. A second copy of
//! the flags anywhere is the drift these tests exist to refuse.
//!
//! The two full builds themselves are the CI job's work (two LTO builds are
//! tens of minutes each), so here the script is driven with a stub `cargo`
//! that records what it was asked to run, and the pure pieces of `build.rs`
//! are called directly through `#[path]`, the way `build_git_triggers_test.rs`
//! drives the git-trigger rule.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../build_script/bpf_flags.rs"]
mod bpf_flags;

const SCRIPT: &str = "scripts/reproducible-build.sh";

fn repo() -> PathBuf {
    // Canonical: rustc sees the directory cargo was started in as the kernel
    // reports it, with symlinks resolved, so that is the prefix to remap.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("canonicalize the checkout")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn text(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Run the script from the checkout with `CARGO_HOME` set to `cargo_home`.
fn script(args: &[&str], cargo_home: &str) -> Output {
    Command::new("bash")
        .arg(repo().join(SCRIPT))
        .args(args)
        .current_dir(repo())
        .env("CARGO_HOME", cargo_home)
        .output()
        .expect("run reproducible-build.sh")
}

fn stdout(out: &Output) -> String {
    assert!(out.status.success(), "{}", text(out));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The remaps name the two prefixes that vary between builders: where the
/// checkout is, and where cargo keeps its registry sources. The checkout's
/// prefix covers the eBPF crate and the build's own `target/`.
#[test]
fn the_rustflags_remap_the_checkout_and_the_cargo_home() {
    let flags = stdout(&script(&["--rustflags"], "/opt/some-cargo-home"));
    let root = repo().display().to_string();
    for want in [
        format!("--remap-path-prefix={root}=/sipnab"),
        "--remap-path-prefix=/opt/some-cargo-home=/cargo".to_string(),
    ] {
        assert!(
            flags.split_whitespace().any(|f| f == want),
            "--rustflags lacks {want}:\n{flags}"
        );
    }
}

/// C objects carry the same paths in their DWARF, and rustc's remap does not
/// reach the C compiler. The C flags must map the SAME prefixes to the SAME
/// names: two lists would agree today and drift apart silently.
#[test]
fn the_cflags_map_the_same_prefixes_as_the_rustflags() {
    let rust = stdout(&script(&["--rustflags"], "/opt/some-cargo-home"));
    let c = stdout(&script(&["--cflags"], "/opt/some-cargo-home"));
    let pairs = |s: &str, prefix: &str| -> Vec<String> {
        s.split_whitespace()
            .filter_map(|f| f.strip_prefix(prefix).map(str::to_string))
            .collect()
    };
    let r = pairs(&rust, "--remap-path-prefix=");
    let m = pairs(&c, "-ffile-prefix-map=");
    assert!(!r.is_empty(), "no remaps at all:\n{rust}");
    assert_eq!(r, m, "the Rust remaps and the C prefix maps disagree");
}

/// A path with whitespace cannot travel in RUSTFLAGS, which cargo splits on
/// whitespace. Refused by name rather than silently split into two flags.
#[test]
fn a_cargo_home_with_whitespace_is_refused() {
    let out = script(&["--rustflags"], "/opt/cargo home");
    assert!(
        !out.status.success(),
        "accepted a split path:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("whitespace"),
        "the refusal does not say why:\n{}",
        text(&out)
    );
}

/// `build` runs the release's cargo command with the split flags AND the
/// remaps appended to an ambient RUSTFLAGS, the C prefix maps in CFLAGS,
/// `--locked`, and the feature set it was given. A stub `cargo` on PATH
/// records the invocation instead of compiling.
#[test]
fn build_runs_the_release_command_with_every_flag() {
    let dir = tempfile::tempdir().expect("stub dir");
    let log = dir.path().join("cargo.log");
    let stub = dir.path().join("cargo");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\n{{ echo \"ARGS $*\"; echo \"RUSTFLAGS $RUSTFLAGS\"; \
             echo \"CFLAGS $CFLAGS\"; echo \"SDE $SOURCE_DATE_EPOCH\"; }} > '{}'\n",
            log.display()
        ),
    )
    .expect("write stub");
    let mut perms = std::fs::metadata(&stub).expect("stat").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&stub, perms).expect("chmod");

    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("bash")
        .arg(repo().join(SCRIPT))
        .args(["build", "x86_64-unknown-linux-gnu", "full,bpf"])
        .current_dir(repo())
        .env("PATH", path)
        .env("CARGO_HOME", "/opt/some-cargo-home")
        .env("RUSTFLAGS", "-Dwarnings")
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .expect("run build");
    assert!(out.status.success(), "{}", text(&out));
    let rec = std::fs::read_to_string(&log).expect("the stub cargo was never run");

    let args = rec
        .lines()
        .find_map(|l| l.strip_prefix("ARGS "))
        .unwrap_or("");
    for want in [
        "build",
        "--release",
        "--locked",
        "--target x86_64-unknown-linux-gnu",
        "--no-default-features",
        "--features full,bpf",
        "--bin sipnab",
    ] {
        assert!(args.contains(want), "cargo was not given {want}:\n{rec}");
    }
    let rustflags = rec
        .lines()
        .find_map(|l| l.strip_prefix("RUSTFLAGS "))
        .unwrap_or("");
    assert!(
        rustflags.starts_with("-Dwarnings "),
        "an ambient RUSTFLAGS must be appended to, not replaced:\n{rec}"
    );
    for want in [
        "-C strip=none",
        "--remap-path-prefix=/opt/some-cargo-home=/cargo",
    ] {
        assert!(rustflags.contains(want), "RUSTFLAGS lacks {want}:\n{rec}");
    }
    let cflags = rec
        .lines()
        .find_map(|l| l.strip_prefix("CFLAGS "))
        .unwrap_or("");
    assert!(
        cflags.contains("-ffile-prefix-map=/opt/some-cargo-home=/cargo"),
        "CFLAGS lacks the cargo-home map:\n{rec}"
    );
    // mimalloc's options.c prints `__DATE__` and `__TIME__`, which put the
    // wall-clock time of the build into the binary: the one difference left
    // after the remaps, measured. GCC takes both from SOURCE_DATE_EPOCH when
    // it is set, and the commit's own time is the one every rebuild agrees on.
    let commit_time = Command::new("git")
        .args(["log", "-1", "--format=%ct", "HEAD"])
        .current_dir(repo())
        .output()
        .expect("git log");
    let want = String::from_utf8_lossy(&commit_time.stdout)
        .trim()
        .to_string();
    let sde = rec
        .lines()
        .find_map(|l| l.strip_prefix("SDE "))
        .unwrap_or("");
    assert!(!want.is_empty(), "git gave no commit time");
    assert_eq!(
        sde, want,
        "SOURCE_DATE_EPOCH must be the commit time of the checkout:\n{rec}"
    );
}

/// `compare` is the verdict of the check: identical files pass, and differing
/// ones fail with evidence (where they first differ) rather than a bare no.
#[test]
fn compare_passes_identical_files_and_fails_differing_ones_with_evidence() {
    let dir = tempfile::tempdir().expect("dir");
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    let c = dir.path().join("c");
    std::fs::write(&a, b"same bytes /sipnab/src/main.rs").unwrap();
    std::fs::write(&b, b"same bytes /sipnab/src/main.rs").unwrap();
    std::fs::write(&c, b"same bytes /home/xx/src/main.rs").unwrap();
    let run = |x: &Path, y: &Path| {
        Command::new("bash")
            .arg(repo().join(SCRIPT))
            .arg("compare")
            .arg(x)
            .arg(y)
            .output()
            .expect("run compare")
    };
    let same = run(&a, &b);
    assert!(same.status.success(), "{}", text(&same));
    let diff = run(&a, &c);
    assert!(
        !diff.status.success(),
        "differing files passed:\n{}",
        text(&diff)
    );
    let all = text(&diff);
    assert!(
        all.contains("differ") && all.contains("/home/xx"),
        "the failure shows no evidence of what differs:\n{all}"
    );
}

/// The eBPF object is built by `build.rs` in a nested cargo that sets its own
/// `CARGO_ENCODED_RUSTFLAGS`, so the outer build's flags never reached it.
/// The remaps must: the checkout path lands in the object's BTF.
/// Everything else in the outer flags (`-Dwarnings`, `-C strip=none`) stays
/// out, because it is not what the kernel crate is built with.
#[test]
fn the_bpf_build_takes_the_outer_remaps_and_nothing_else() {
    let outer = [
        "-Dwarnings",
        "-C",
        "strip=none",
        "--remap-path-prefix=/work/sipnab=/sipnab",
        "--remap-path-prefix",
        "/home/u/.cargo=/cargo",
    ]
    .join("\x1f");
    let inner = bpf_flags::inner_rustflags("x86_64", &outer, Some("/home/u/.rustup/toolchains/n"));
    let flags: Vec<&str> = inner.split('\x1f').collect();
    for want in [
        "--cfg=bpf_target_arch=\"x86_64\"",
        "-Cdebuginfo=2",
        "-Clink-arg=--btf",
        "--remap-path-prefix=/work/sipnab=/sipnab",
        "--remap-path-prefix=/home/u/.cargo=/cargo",
        "--remap-path-prefix=/home/u/.rustup/toolchains/n=/rustc-sysroot",
    ] {
        assert!(flags.contains(&want), "inner flags lack {want}: {flags:?}");
    }
    for unwanted in ["-Dwarnings", "strip=none", "-C"] {
        assert!(
            !flags.contains(&unwanted),
            "inner flags carry {unwanted} from the outer build: {flags:?}"
        );
    }
    // A contributor build: no outer remaps, no sysroot known. The flags the
    // loader needs are all still there, and nothing empty is emitted.
    let plain = bpf_flags::inner_rustflags("aarch64", "", None);
    assert_eq!(
        plain,
        "--cfg=bpf_target_arch=\"aarch64\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf"
    );
}

/// The eBPF half is compiled by a nightly. `nightly` alone names a different
/// compiler every day, so a release could not be rebuilt a week later: the
/// channel is a dated nightly, and build.rs reads it from the toolchain file.
#[test]
fn the_bpf_nightly_is_pinned_to_a_date_and_read_from_one_file() {
    let toml = read("bpf/rust-toolchain.toml");
    let channel = bpf_flags::toolchain_channel(&toml)
        .unwrap_or_else(|| panic!("no channel in bpf/rust-toolchain.toml:\n{toml}"));
    let date = channel
        .strip_prefix("nightly-")
        .unwrap_or_else(|| panic!("channel {channel:?} is not a dated nightly"));
    assert!(
        date.len() == 10
            && date.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 {
                c == '-'
            } else {
                c.is_ascii_digit()
            }),
        "channel {channel:?} is not nightly-YYYY-MM-DD"
    );
    let build_rs = read("build.rs");
    assert!(
        build_rs.contains("toolchain_channel") && !build_rs.contains("\"nightly\","),
        "build.rs must run the channel bpf/rust-toolchain.toml names, not a \
         literal `nightly`"
    );
    let release = read(".github/workflows/release.yml");
    assert!(
        !release.contains("rustup toolchain install nightly"),
        "release.yml installs a floating nightly instead of the pinned one"
    );
}

/// The shape of the channel parser: the `channel` key under `[toolchain]`,
/// comments and other keys ignored.
#[test]
fn the_toolchain_channel_parser_reads_only_the_channel_key() {
    let toml = "# nightly is mentioned here\n[toolchain]\ncomponents = [\"rust-src\"]\n\
                channel = \"nightly-2026-08-09\"\n";
    assert_eq!(
        bpf_flags::toolchain_channel(toml).as_deref(),
        Some("nightly-2026-08-09")
    );
    assert_eq!(bpf_flags::toolchain_channel("[toolchain]\n"), None);
}

/// Release and check build through the same script, so the check proves the
/// build the release performs and not a neighbor of it.
#[test]
fn the_release_and_the_check_build_through_the_same_script() {
    let release = read(".github/workflows/release.yml");
    for step in ["- name: Build (native)", "- name: Build (cross)"] {
        let at = release
            .find(step)
            .unwrap_or_else(|| panic!("release.yml has no {step:?} step"));
        let rest = &release[at + step.len()..];
        let end = rest.find("\n      - ").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("bash scripts/reproducible-build.sh build"),
            "{step} does not build through the script:\n{body}"
        );
    }

    let check = read(".github/workflows/reproducible.yml");
    assert!(
        check.contains("bash scripts/reproducible-build.sh check"),
        "reproducible.yml does not run the script's check"
    );
    // The check builds with `build`, the same entry point release.yml uses:
    // the `build` of the clone's own copy of the script, so a check of an
    // older tag builds the way that tag's release did.
    let script_text = read(SCRIPT);
    let check_fn = script_text
        .find("cmd_check()")
        .map(|i| &script_text[i..])
        .expect("the script has no cmd_check");
    let check_fn = &check_fn[..check_fn.find("\n}\n").unwrap_or(check_fn.len())];
    assert!(
        check_fn.contains("/scripts/reproducible-build.sh\" build "),
        "cmd_check does not build through the script's `build`:\n{check_fn}"
    );
}

/// The check job follows the repository's rules for jobs: bounded, read-only,
/// on a schedule, and on pull requests that touch what the build reads.
#[test]
fn the_check_workflow_is_bounded_read_only_and_triggered_by_build_inputs() {
    let wf = read(".github/workflows/reproducible.yml");
    assert!(
        wf.contains("timeout-minutes:"),
        "the check job is unbounded"
    );
    assert!(
        wf.contains("permissions:\n  contents: read"),
        "workflow-level permissions must be read-only"
    );
    assert!(wf.contains("schedule:"), "no scheduled run");
    assert!(wf.contains("pull_request:"), "no pull-request trigger");
    for path in [
        "Cargo.lock",
        "build.rs",
        "build_script/**",
        "bpf/**",
        "scripts/reproducible-build.sh",
        "scripts/split-debuginfo.sh",
        ".github/workflows/reproducible.yml",
    ] {
        assert!(
            wf.contains(&format!("'{path}'")),
            "a change to {path} does not run the check"
        );
    }
}

/// Inside a container job the checkout belongs to the runner's user, not the
/// container's root, so git refuses the repository ("dubious ownership") and
/// `reproducible-build.sh` finds no commit time for `SOURCE_DATE_EPOCH`. Every
/// Linux gnu release build failed exactly that way in a build-only Release run
/// (36789365791) before this step existed; the musl and macOS builds, which run
/// on the host, passed. The step must mark the workspace safe, in the build
/// job, before either build step runs.
#[test]
fn container_builds_mark_the_checkout_safe_before_building() {
    let wf = read(".github/workflows/release.yml");
    let job = &wf[wf.find("\n  build:").expect("release.yml has a build job")..];
    let job = &job[..job.find("\n  release:").unwrap_or(job.len())];
    let safe = job
        .find("safe.directory")
        .expect("the build job marks the checkout as a git safe.directory");
    for step in ["- name: Build (cross)", "- name: Build (native)"] {
        let at = job.find(step).unwrap_or_else(|| panic!("no `{step}` step"));
        assert!(
            safe < at,
            "safe.directory must be set before `{step}`, or the container \
             build cannot read the commit time"
        );
    }
    assert!(
        job.contains("\"$GITHUB_WORKSPACE\"") || job.contains("${{ github.workspace }}"),
        "mark the actual workspace safe, not `*`"
    );
}
