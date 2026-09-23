// SPDX-License-Identifier: MIT OR Apache-2.0

//! The release publishes a symbol file beside every stripped binary.
//!
//! A user who sends a crash report sends frame addresses from a stripped
//! binary. Those addresses mean nothing without the symbols the same build
//! produced, and a rebuild does not reproduce them byte for byte. So
//! `release.yml` keeps the line tables through the build, splits them into
//! `sipnab-<version>-<target>.debug` (Linux) or `…​.dSYM.zip` (macOS) with
//! `scripts/split-debuginfo.sh`, strips what it ships, and publishes both.
//!
//! The workflow runs only on a tag, so this file checks what can be checked on
//! every commit: the steps exist, they run in an order where every gate after
//! the build sees the STRIPPED binary, the release uploads and checksums the
//! symbol files, and the gates that measure the shipped binary still measure
//! only it. Where a step's shell can run on this host, it is executed rather
//! than read.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

#[path = "support/dbgsym.rs"]
mod dbgsym;

use dbgsym::{repo, text};

const RELEASE: &str = ".github/workflows/release.yml";

/// The step that splits the symbols out of the binary the release ships.
const SPLIT_STEP: &str = "Split the debug symbols from the shipped binary";

/// Read a repo-relative file.
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Every `- name:` in the workflow, in file order.
fn step_names() -> Vec<String> {
    read(RELEASE)
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- name: "))
        .map(|s| s.trim().to_string())
        .collect()
}

/// Position of the one step called `name`. Panics when missing or duplicated:
/// a scan that takes the first of two identically named steps can be pointed
/// at a decoy.
fn position(name: &str) -> usize {
    let names = step_names();
    let hits: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, n)| n.as_str() == name)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{RELEASE} has {} steps named {name:?}; expected exactly one",
        hits.len()
    );
    hits[0]
}

/// The full text of the step called `name`, from its `- name:` line to the
/// next item at the same indentation.
fn step_block(name: &str) -> Vec<String> {
    step_block_in(RELEASE, name)
}

/// [`step_block`] for any workflow file. Panics unless exactly one step has
/// that name, so a decoy cannot shadow the real step.
fn step_block_in(workflow: &str, name: &str) -> Vec<String> {
    let text = read(workflow);
    let lines: Vec<&str> = text.lines().collect();
    let needle = format!("- name: {name}");
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{workflow} has {} steps named {name:?}; expected exactly one",
        hits.len()
    );
    let start = hits[0];
    let indent = lines[start].len() - lines[start].trim_start().len();
    let mut body = vec![lines[start].to_string()];
    for l in &lines[start + 1..] {
        let t = l.trim_start();
        if t.is_empty() {
            body.push(l.to_string());
            continue;
        }
        let ind = l.len() - t.len();
        if ind < indent || (ind == indent && t.starts_with("- ")) {
            break;
        }
        body.push(l.to_string());
    }
    body
}

/// The dedented `run:` script of the step called `name`.
fn step_script(name: &str) -> String {
    step_script_in(RELEASE, name)
}

/// [`step_script`] for any workflow file.
fn step_script_in(workflow: &str, name: &str) -> String {
    let body = step_block_in(workflow, name);
    let run_at = body
        .iter()
        .position(|l| l.trim_start().starts_with("run:"))
        .unwrap_or_else(|| panic!("step {name:?} has no `run:` block"));
    let run_line = body[run_at].trim_start();
    if let Some(inline) = run_line.strip_prefix("run:")
        && !inline.trim().is_empty()
        && inline.trim() != "|"
    {
        return inline.trim().to_string();
    }
    let run_indent = body[run_at].len() - body[run_at].trim_start().len();
    let block: Vec<&String> = body[run_at + 1..]
        .iter()
        .take_while(|l| {
            let t = l.trim_start();
            t.is_empty() || l.len() - t.len() > run_indent
        })
        .collect();
    let dedent = block
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let script = block
        .iter()
        .map(|l| {
            if l.len() >= dedent {
                &l[dedent..]
            } else {
                l.as_str()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !script.trim().is_empty(),
        "step {name:?}: extracted an empty script"
    );
    script
}

/// The step's `if:` condition, if it has one.
fn step_if(name: &str) -> Option<String> {
    step_block(name)
        .iter()
        .find_map(|l| l.trim().strip_prefix("if: ").map(str::to_string))
}

/// Every `(target, variant)` the build matrix produces.
fn matrix() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in read(RELEASE).lines() {
        let t = line.trim();
        if let Some(target) = t.strip_prefix("- target: ") {
            out.push((target.trim().to_string(), String::new()));
        } else if let Some(v) = t.strip_prefix("variant: ")
            && let Some(last) = out.last_mut()
        {
            last.1 = v.trim().to_string();
        }
    }
    assert!(
        out.len() >= 8,
        "matrix scan found only {} entries",
        out.len()
    );
    out
}

/// Run `split-debuginfo.sh --cargo-config <target>`.
fn cargo_config(target: &str) -> std::process::Output {
    Command::new("bash")
        .arg(dbgsym::script())
        .args(["--cargo-config", target])
        .output()
        .expect("run split-debuginfo.sh --cargo-config")
}

/// Both build steps keep the line tables, by asking the split script for the
/// cargo setting instead of restating it, and the script answers correctly
/// for every target the matrix builds.
///
/// Linux appends `-C strip=none` so the linker leaves the symbols for the
/// split. macOS keeps rustc's own strip and asks it for a packed `.dSYM`,
/// which rustc writes with `dsymutil` before stripping.
#[test]
fn the_build_keeps_the_symbols_the_split_needs() {
    for step in ["Build (native)", "Build (cross)"] {
        let script = step_script(step);
        assert!(
            script.contains("--config \"$(bash scripts/split-debuginfo.sh --cargo-config"),
            "{step} must take its symbol setting from split-debuginfo.sh \
             --cargo-config; without it the linker strips the symbols before \
             the split can keep them:\n{script}"
        );
    }
    let mut seen = BTreeSet::new();
    for (target, _) in matrix() {
        if !seen.insert(target.clone()) {
            continue;
        }
        let out = cargo_config(&target);
        assert!(out.status.success(), "{target}:\n{}", text(&out));
        let cfg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // rustflags, NOT `profile.release.*`: cargo hashes the profile into
        // every crate's `-C metadata`, which reseeds symbol hashes and moved
        // 8,064 bytes of `.text` in a measured aarch64 build. Cargo keeps
        // rustflags out of that hash, and rustc takes the last `-C strip`,
        // so this build's code is byte-identical to the linker-stripped one.
        let want = if target.contains("-apple-darwin") {
            "build.rustflags=[\"-C\",\"split-debuginfo=packed\"]"
        } else {
            "build.rustflags=[\"-C\",\"strip=none\"]"
        };
        assert_eq!(cfg, want, "--cargo-config for {target}");
    }
    let bad = cargo_config("riscv64gc-unknown-none-elf");
    assert!(
        !bad.status.success(),
        "an unknown target must be refused, not given a guess:\n{}",
        text(&bad)
    );
}

/// The toolchain carries `llvm-objcopy`, which the split needs for the
/// binaries built for an architecture other than the runner's.
#[test]
fn the_toolchain_install_carries_llvm_tools() {
    let block = step_block("Install Rust").join("\n");
    assert!(
        block.contains("components: llvm-tools"),
        "Install Rust must add llvm-tools; the host's GNU objcopy cannot read \
         a foreign-architecture binary:\n{block}"
    );
}

/// (d) The split runs for EVERY matrix entry, after the build and before
/// anything reads, measures, runs or packages the binary. A gate placed
/// before it would examine the unstripped build instead of the shipped file.
#[test]
fn the_split_runs_for_every_build_before_the_binary_is_examined() {
    let split = position(SPLIT_STEP);
    assert_eq!(
        step_if(SPLIT_STEP),
        None,
        "the split must run for every target and variant; the noaudio builds \
         ship in the .deb and .rpm and need their own symbol files"
    );
    for before in ["Build (native)", "Build (cross)"] {
        assert!(
            position(before) < split,
            "{before} must come before the split"
        );
    }
    for after in [
        "Verify the binary is stripped",
        "Smoke test the built binary",
        "Record the capture backends this artifact carries",
        "Enforce glibc floor (gnu Linux targets)",
        "Enforce published binary size (musl targets)",
        "Package (tar.gz + checksum)",
        "Build .deb (gnu Linux targets)",
        "Build .rpm (gnu Linux targets)",
        "Upload artifact",
    ] {
        assert!(
            split < position(after),
            "{after:?} must come after the split, or it sees the unstripped build"
        );
    }
}

/// Every matrix entry publishes a symbol file under a distinct name, and each
/// name is the stem the tarball or package of that entry already uses plus
/// `.debug` or `.dSYM.zip`.
#[test]
fn every_build_publishes_a_distinctly_named_symbol_file() {
    let script = step_script(SPLIT_STEP);
    assert!(
        script.contains("bash scripts/split-debuginfo.sh"),
        "{SPLIT_STEP} does not run the split script:\n{script}"
    );
    let mut names = BTreeSet::new();
    let mut linux = 0;
    let mut mac = 0;
    for (target, variant) in matrix() {
        let suffix = if variant.is_empty() {
            String::new()
        } else {
            format!("-{variant}")
        };
        let ext = if target.contains("-apple-darwin") {
            mac += 1;
            "dSYM.zip"
        } else {
            linux += 1;
            "debug"
        };
        names.insert(format!("sipnab-1.2.3-{target}{suffix}.{ext}"));
    }
    assert_eq!(
        linux, 6,
        "six Linux builds: gnu, gnu-noaudio and musl on two architectures"
    );
    assert_eq!(mac, 2, "two macOS builds");
    assert_eq!(names.len(), 8, "symbol file names collide: {names:?}");
    assert!(
        script.contains("dist/sipnab-${version}-${TARGET}${SUFFIX}"),
        "the split must write dist/sipnab-<version>-<target><suffix>, the \
         same stem as the tarball, so the release job picks it up:\n{script}"
    );
}

/// (d) Executed: the split step's own shell, run on this host against a real
/// optimized binary, leaves a stripped binary where every later step looks
/// and a matching `.debug` in `dist/`. Then "Verify the binary is stripped"
/// passes on that binary, and fails on an unstripped one, so the verify step
/// is still live and still reads the shipped file.
#[test]
#[cfg(target_os = "linux")]
fn the_split_step_and_the_strip_check_run_on_a_real_binary() {
    let host = dbgsym::host_triple();
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path();
    let rel = work.join("target").join(&host).join("release");
    std::fs::create_dir_all(&rel).unwrap();
    let fixture = dbgsym::build_fixture(work, None, true).expect("host fixture");
    let bin = rel.join("sipnab");
    std::fs::copy(&fixture, &bin).unwrap();
    std::fs::create_dir_all(work.join("scripts")).unwrap();
    std::fs::copy(dbgsym::script(), work.join("scripts/split-debuginfo.sh")).unwrap();

    let verify =
        step_script("Verify the binary is stripped").replace("${{ matrix.target }}", &host);
    let unstripped = Command::new("bash")
        .arg("-c")
        .arg(&verify)
        .current_dir(work)
        .output()
        .unwrap();
    assert!(
        !unstripped.status.success(),
        "the strip check passed an unstripped binary:\n{}",
        text(&unstripped)
    );

    let split = step_script(SPLIT_STEP);
    let out = Command::new("bash")
        .arg("-c")
        .arg(&split)
        .current_dir(work)
        .env("TARGET", &host)
        .env("SUFFIX", "")
        .env("GITHUB_REF_NAME", "v1.2.3")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the split step failed:\n{}",
        text(&out)
    );
    let debug = work.join(format!("dist/sipnab-1.2.3-{host}.debug"));
    assert!(debug.is_file(), "no {}:\n{}", debug.display(), text(&out));
    assert_eq!(dbgsym::build_id(&bin), dbgsym::build_id(&debug));

    let stripped = Command::new("bash")
        .arg("-c")
        .arg(&verify)
        .current_dir(work)
        .output()
        .unwrap();
    assert!(
        stripped.status.success(),
        "the strip check refused the split binary:\n{}",
        text(&stripped)
    );
}

/// (d) The release job publishes, checksums and attests the symbol files.
#[test]
fn the_release_publishes_checksums_and_attests_the_symbol_files() {
    let files = step_block("Create GitHub Release").join("\n");
    let sums = step_script("Generate combined checksums");
    let attest = step_block("Attest build provenance").join("\n");
    for pattern in ["artifacts/*.debug", "artifacts/*.dSYM.zip"] {
        assert!(
            files.contains(pattern),
            "the release does not upload {pattern}:\n{files}"
        );
        assert!(
            attest.contains(pattern),
            "provenance does not cover {pattern}:\n{attest}"
        );
    }
    for glob in ["*.debug", "*.dSYM.zip"] {
        assert!(
            sums.split_whitespace().any(|w| w == glob),
            "SHA256SUMS.txt does not cover {glob}:\n{sums}"
        );
    }
}

/// (e) The size gate measures the shipped binary and nothing else: a symbol
/// file far over the ceiling beside a small binary passes, and the same gate
/// fails a binary over the ceiling, so it is not passing by measuring nothing.
#[test]
#[cfg(target_os = "linux")]
fn the_size_gate_measures_only_the_shipped_binary() {
    let target = "x86_64-unknown-linux-musl";
    let gate = step_script("Enforce published binary size (musl targets)")
        .replace("${{ matrix.target }}", target);
    assert!(
        !gate.contains(".debug") && !gate.contains("dSYM"),
        "the size gate must not read a symbol file:\n{gate}"
    );
    let ceiling_mb: u64 = read("website/config.toml")
        .lines()
        .find_map(|l| l.strip_prefix("binary_size_ceiling_mb = "))
        .map(|v| v.trim().trim_matches('"').parse().unwrap())
        .expect("binary_size_ceiling_mb");
    let over = (ceiling_mb + 1) * 1024 * 1024;

    let run = |bin_len: u64| {
        let dir = tempfile::tempdir().unwrap();
        let w = dir.path();
        std::fs::create_dir_all(w.join("website")).unwrap();
        std::fs::copy(
            repo().join("website/config.toml"),
            w.join("website/config.toml"),
        )
        .unwrap();
        let rel = w.join("target").join(target).join("release");
        std::fs::create_dir_all(&rel).unwrap();
        std::fs::create_dir_all(w.join("dist")).unwrap();
        // Sparse: set_len allocates nothing, so "over the ceiling" costs no disk.
        std::fs::File::create(rel.join("sipnab"))
            .unwrap()
            .set_len(bin_len)
            .unwrap();
        std::fs::File::create(w.join(format!("dist/sipnab-1.2.3-{target}.debug")))
            .unwrap()
            .set_len(over)
            .unwrap();
        Command::new("bash")
            .arg("-c")
            .arg(&gate)
            .current_dir(w)
            .output()
            .unwrap()
    };

    let small = run(1024);
    assert!(
        small.status.success(),
        "a 1 KiB binary failed the size gate, so it measured something else:\n{}",
        text(&small)
    );
    let big = run(over);
    assert!(
        !big.status.success(),
        "a binary over the ceiling passed, so the gate is not measuring it:\n{}",
        text(&big)
    );
}

/// The check is anchored to a real file: the matrix, the step list and the
/// ceiling this file reads all exist in the tree.
#[test]
fn the_workflow_scan_reads_the_real_workflow() {
    assert!(Path::new(&repo().join(RELEASE)).is_file());
    assert!(step_names().len() > 20, "step scan found too few steps");
    assert!(matrix().iter().any(|(t, _)| t == "aarch64-apple-darwin"));
}

// ---------------------------------------------------------------------------
// Ordinary CI proves the split before a tag depends on it.
// ---------------------------------------------------------------------------

const CI: &str = ".github/workflows/ci.yml";
const CI_BUILD_STEP: &str = "Build the release profile with the release's symbol flags";
const CI_PROVE_STEP: &str = "Prove the release symbol split";

/// The ci.yml job that holds `step`: the text from the job's two-space key to
/// the next one.
fn ci_job_holding(step: &str) -> String {
    let text = read(CI);
    let needle = format!("- name: {step}");
    let at = text
        .find(&needle)
        .unwrap_or_else(|| panic!("{CI} has no step {step:?}"));
    let is_job_key = |l: &str| {
        l.len() > 2 && l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':')
    };
    let mut start = 0;
    let mut offset = 0;
    for line in text.lines() {
        if offset > at {
            break;
        }
        if is_job_key(line) {
            start = offset;
        }
        offset += line.len() + 1;
    }
    let rest = &text[start..];
    let mut end = rest.len();
    let mut off = 0;
    for (i, line) in rest.lines().enumerate() {
        if i > 0 && is_job_key(line) {
            end = off;
            break;
        }
        off += line.len() + 1;
    }
    rest[..end].to_string()
}

/// The macOS half of the split exists only on the release's darwin runners,
/// which run at tag time, when a failure costs a published tag. So ordinary
/// CI, on every push, builds the release profile with the SAME symbol flags
/// (taken from `split-debuginfo.sh --cargo-config`, as release.yml does) on
/// one Linux x86_64 and one macOS runner, runs the split, and checks what the
/// release relies on.
#[test]
fn ci_proves_the_split_on_linux_and_macos_before_a_tag() {
    let job = ci_job_holding(CI_PROVE_STEP);
    assert_eq!(
        job,
        ci_job_holding(CI_BUILD_STEP),
        "the build and the proof must be one job, or the proof reads nothing"
    );
    assert!(
        job.contains("os: ubuntu-latest") && job.contains("target: x86_64-unknown-linux-gnu"),
        "the split job must run x86_64 Linux on ubuntu-latest:\n{job}"
    );
    assert!(
        job.contains("os: macos-latest") && job.contains("target: aarch64-apple-darwin"),
        "the split job must run aarch64 macOS on macos-latest:\n{job}"
    );
    assert!(
        job.contains("components: llvm-tools"),
        "the split needs llvm-objcopy from llvm-tools:\n{job}"
    );
    assert!(
        job.contains("timeout-minutes:"),
        "an unbounded job holds its concurrency group:\n{job}"
    );

    let build = step_script_in(CI, CI_BUILD_STEP);
    assert!(
        build.contains("cargo build --release")
            && build.contains("--config \"$(bash scripts/split-debuginfo.sh --cargo-config"),
        "CI must build the RELEASE profile with the flags release.yml takes \
         from the script, or it proves a different build:\n{build}"
    );
    let build_pos = position_in(CI, CI_BUILD_STEP);
    let prove_pos = position_in(CI, CI_PROVE_STEP);
    assert!(build_pos < prove_pos, "the proof must run after the build");

    let prove = step_script_in(CI, CI_PROVE_STEP);
    for needle in [
        "bash scripts/split-debuginfo.sh",
        "Build ID",
        ".symtab",
        ".gnu_debuglink",
        "dwarfdump --uuid",
        ".dSYM.zip",
    ] {
        assert!(
            prove.contains(needle),
            "{CI_PROVE_STEP} does not check {needle:?}:\n{prove}"
        );
    }
}

/// Position of the step called `name` among `workflow`'s steps.
fn position_in(workflow: &str, name: &str) -> usize {
    read(workflow)
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- name: "))
        .position(|n| n.trim() == name)
        .unwrap_or_else(|| panic!("{workflow} has no step {name:?}"))
}

/// How [`the_ci_proof_step_catches_what_it_must`] prepares its tree.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq)]
enum ProofCase {
    /// A real binary with symbols and the real split script.
    Good,
    /// The binary stripped at link time, as a build without the flag leaves it.
    StrippedFirst,
    /// A split script that copies the unstripped binary to the `.debug` path
    /// and succeeds: the build IDs match, so only the step's own `.symtab`
    /// check can catch it.
    LyingScript,
    /// A split script that strips the binary and links it to an EMPTY
    /// `.debug`: only the step's build-ID comparison can catch it.
    EmptyDebug,
    /// A split script that strips the binary and writes a matching `.debug`
    /// but adds no debug link: only the step's `.gnu_debuglink` check can
    /// catch it.
    NoDebuglink,
}

/// Executed: the CI proof step's own shell passes a real split, fails a
/// binary the linker already stripped, and fails a split script that lies
/// about having stripped. The last case matters because the real script
/// would refuse the first two by itself, so without it the step's own checks
/// could be deleted and this test would stay green.
#[test]
#[cfg(target_os = "linux")]
fn the_ci_proof_step_catches_what_it_must() {
    let host = dbgsym::host_triple();
    let prove = step_script_in(CI, CI_PROVE_STEP);
    let run = |case: ProofCase| {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        let rel = work.join("target").join(&host).join("release");
        std::fs::create_dir_all(&rel).unwrap();
        let fixture = dbgsym::build_fixture(&work, None, true).expect("host fixture");
        let bin = rel.join("sipnab");
        std::fs::copy(&fixture, &bin).unwrap();
        std::fs::create_dir_all(work.join("scripts")).unwrap();
        let script = work.join("scripts/split-debuginfo.sh");
        let stub = match case {
            ProofCase::LyingScript => Some("cp \"$1\" \"$2.debug\""),
            ProofCase::EmptyDebug => Some(
                ": > \"$2.debug\"; strip \"$1\"; \
                 objcopy --add-gnu-debuglink=\"$2.debug\" \"$1\"",
            ),
            ProofCase::NoDebuglink => {
                Some("objcopy --only-keep-debug \"$1\" \"$2.debug\"; strip \"$1\"")
            }
            ProofCase::Good | ProofCase::StrippedFirst => None,
        };
        match stub {
            Some(body) => std::fs::write(
                &script,
                format!("set -e\nmkdir -p \"$(dirname \"$2\")\"\n{body}\n"),
            )
            .unwrap(),
            None => {
                std::fs::copy(dbgsym::script(), &script).unwrap();
            }
        }
        if case == ProofCase::StrippedFirst {
            let s = Command::new("strip").arg(&bin).status().expect("strip");
            assert!(s.success());
        }
        let out = Command::new("bash")
            .arg("-c")
            .arg(&prove)
            .current_dir(&work)
            .env("TARGET", &host)
            .output()
            .unwrap();
        (out, dir)
    };
    let (good, _d1) = run(ProofCase::Good);
    assert!(
        good.status.success(),
        "the proof failed a good split:\n{}",
        text(&good)
    );
    let (stripped, _d2) = run(ProofCase::StrippedFirst);
    assert!(
        !stripped.status.success(),
        "the proof passed a binary stripped before the split:\n{}",
        text(&stripped)
    );
    let (lying, _d3) = run(ProofCase::LyingScript);
    assert!(
        !lying.status.success(),
        "the proof passed a binary that still has its .symtab:\n{}",
        text(&lying)
    );
    assert!(
        String::from_utf8_lossy(&lying.stdout).contains(".symtab"),
        "the refusal must come from the step's own .symtab check:\n{}",
        text(&lying)
    );
    let (empty, _d4) = run(ProofCase::EmptyDebug);
    assert!(
        !empty.status.success()
            && String::from_utf8_lossy(&empty.stdout).contains("build ID mismatch"),
        "the step's build-ID comparison did not catch an empty .debug:\n{}",
        text(&empty)
    );
    let (nolink, _d5) = run(ProofCase::NoDebuglink);
    assert!(
        !nolink.status.success()
            && String::from_utf8_lossy(&nolink.stdout).contains(".gnu_debuglink"),
        "the step's .gnu_debuglink check did not catch a missing link:\n{}",
        text(&nolink)
    );
}

/// Executed: the CI proof step's macOS branch, run on this host with stub
/// `dwarfdump` and split scripts standing in for Xcode's tools. It passes a
/// zip beside a bundle whose UUID matches the binary, and fails a missing zip
/// or a mismatched UUID. The real tools run on the macOS CI leg; this proves
/// the step's own logic can go red, which reading its text cannot.
#[test]
#[cfg(unix)]
fn the_ci_proof_step_macos_branch_checks_the_zip_and_the_uuid() {
    let prove = step_script_in(CI, CI_PROVE_STEP);
    let target = "aarch64-apple-darwin";
    let run = |make_zip: bool, dsym_uuid: &str| {
        let dir = tempfile::tempdir().unwrap();
        let w = dir.path().to_path_buf();
        let rel = w.join("target").join(target).join("release");
        std::fs::create_dir_all(rel.join("sipnab.dSYM")).unwrap();
        std::fs::write(rel.join("sipnab"), b"stand-in").unwrap();
        std::fs::create_dir_all(w.join("scripts")).unwrap();
        let split = if make_zip {
            "mkdir -p \"$(dirname \"$2\")\"; echo zip > \"$2.dSYM.zip\"\n"
        } else {
            "exit 0\n"
        };
        std::fs::write(w.join("scripts/split-debuginfo.sh"), split).unwrap();
        let bin = w.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let stub = format!(
            "#!/bin/sh\ncase \"$2\" in\n  *.dSYM) echo \"UUID: {dsym_uuid} (arm64) $2\" ;;\n  \
             *) echo \"UUID: AAAA-1111 (arm64) $2\" ;;\nesac\n"
        );
        let dd = bin.join("dwarfdump");
        std::fs::write(&dd, stub).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = Command::new("bash")
            .arg("-c")
            .arg(&prove)
            .current_dir(&w)
            .env("TARGET", target)
            .env("PATH", path)
            .output()
            .unwrap();
        (out, dir)
    };
    let (good, _a) = run(true, "AAAA-1111");
    assert!(
        good.status.success(),
        "the macOS proof failed a good split:\n{}",
        text(&good)
    );
    let (nozip, _b) = run(false, "AAAA-1111");
    assert!(
        !nozip.status.success() && String::from_utf8_lossy(&nozip.stdout).contains(".dSYM.zip"),
        "the macOS proof passed with no .dSYM.zip:\n{}",
        text(&nozip)
    );
    let (mismatch, _c) = run(true, "BBBB-2222");
    assert!(
        !mismatch.status.success()
            && String::from_utf8_lossy(&mismatch.stdout).contains("UUID mismatch"),
        "the macOS proof passed a .dSYM whose UUID is not the binary's:\n{}",
        text(&mismatch)
    );
}
