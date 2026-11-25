// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The fuzzing integration describes the fuzz targets that actually exist.
//!
//! # The defect class this exists for
//!
//! A fuzz target that is built, committed and never fuzzed looks exactly like
//! one that is fuzzed and finds nothing. Both are silent. The only difference
//! is whether anything was ever pointed at it, and nothing in a green suite
//! can tell you which you have.
//!
//! This repository has already paid for that shape once: the eBPF object built
//! on every release, the suite was green, and the program did not load on any
//! kernel, because building was the only half anything covered.
//!
//! So the rules here are about the SEAM, not the fuzzing: the target list must
//! be derived rather than restated, every seed corpus must belong to a target
//! that still exists, and the image the fuzzers build in must carry what they
//! link against.
//!
//! # Three consumers, one build
//!
//! - `.clusterfuzzlite/` is what runs today, on GitHub Actions.
//! - `.github/workflows/fuzz.yml` runs the same targets weekly under plain
//!   `cargo fuzz`, with no container and no accumulated corpus.
//! - `ops/oss-fuzz/` is the submission for `google/oss-fuzz`, held ready but
//!   not submitted. Its `build.sh` is a two-line shim that execs the
//!   ClusterFuzzLite one, so the build logic has a single home.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
}

/// Every `[[bin]]` name in `fuzz/Cargo.toml`, which is what `cargo fuzz list`
/// reads.
fn fuzz_targets() -> Result<BTreeSet<String>, TestError> {
    let manifest = read("fuzz/Cargo.toml")?;
    let mut out = BTreeSet::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let l = line.trim();
        if l == "[[bin]]" {
            in_bin = true;
            continue;
        }
        if l.starts_with('[') {
            in_bin = false;
        }
        if in_bin && let Some(rest) = l.strip_prefix("name = ") {
            out.insert(rest.trim().trim_matches('"').to_string());
        }
    }
    assert!(
        !out.is_empty(),
        "parsed no [[bin]] names out of fuzz/Cargo.toml; every test here would \
         then pass by checking nothing"
    );
    Ok(out)
}

/// The shell lines of a script, with comments dropped.
///
/// A comment explaining the corpus naming with one target as the example is
/// documentation, not a restated list, and forbidding it would push the
/// explanation out of the file that needs it.
fn code_lines(body: &str) -> String {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The build script must DERIVE its target list, never restate it.
///
/// A hardcoded list is the whole defect: adding a `[[bin]]` would leave a
/// target that compiles, passes CI and is never fuzzed. `cargo fuzz list`
/// reads the manifest, so the two cannot disagree.
#[test]
fn the_fuzz_build_derives_its_target_list() -> Result<(), TestError> {
    let build = read(".clusterfuzzlite/build.sh")?;
    assert!(
        build.contains("cargo fuzz list"),
        ".clusterfuzzlite/build.sh must enumerate targets with `cargo fuzz \
         list`; a restated list silently drops the next target added"
    );
    let code = code_lines(&build);
    for target in fuzz_targets()? {
        assert!(
            !code.contains(&target),
            ".clusterfuzzlite/build.sh names the target {target} in code. It \
             derives the list already; a second copy is what drifts."
        );
    }
    Ok(())
}

/// Every seed corpus belongs to a target that still exists.
///
/// The directory drops the `fuzz_` prefix the binary carries, and the build
/// script relies on exactly that. A renamed target leaves its seeds behind
/// under the old name, where they are copied into no archive and fuzz nothing
/// — an absence with no symptom.
#[test]
fn every_seed_corpus_belongs_to_a_live_target() -> Result<(), TestError> {
    let targets = fuzz_targets()?;
    let dir: PathBuf = repo().join("fuzz/corpus");
    let mut orphans = Vec::new();
    let mut seen = 0usize;
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read fuzz/corpus: {e}"))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        if !entry
            .file_type()
            .map_err(|e| format!("file type: {e}"))?
            .is_dir()
        {
            continue;
        }
        seen += 1;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !targets
            .iter()
            .any(|t| t.strip_prefix("fuzz_") == Some(name.as_str()))
        {
            orphans.push(name);
        }
    }
    orphans.sort();
    assert!(
        orphans.is_empty(),
        "these seed corpora match no fuzz target: {orphans:?}. Either the \
         target was renamed and the seeds were left behind, or the directory \
         is misspelled — both fuzz nothing and say nothing."
    );
    assert!(
        seen > 0,
        "found no corpus directories at all; the walk stopped matching and \
         this gate is checking nothing"
    );
    Ok(())
}

/// One build script, not one per consumer.
///
/// The OSS-Fuzz submission is a shim on purpose. Two real build scripts agree
/// on the day they are written and drift the first time a target is added,
/// silently, because nothing compares them.
#[test]
fn there_is_exactly_one_fuzz_build_script() -> Result<(), TestError> {
    let shim = read("ops/oss-fuzz/build.sh.shim")?;
    assert!(
        shim.contains(".clusterfuzzlite/build.sh"),
        "the shim held ready for google/oss-fuzz must exec the ClusterFuzzLite \
         build script, or the build logic exists twice"
    );
    assert!(
        !repo().join("ops/oss-fuzz/build.sh").exists(),
        "ops/oss-fuzz/build.sh is a second real build script; the shim exists \
         so there is only ever one"
    );
    for f in [
        ".clusterfuzzlite/build.sh",
        ".clusterfuzzlite/Dockerfile",
        ".clusterfuzzlite/project.yaml",
        "ops/oss-fuzz/build.sh.shim",
        "ops/oss-fuzz/Dockerfile",
        "ops/oss-fuzz/project.yaml",
    ] {
        assert!(repo().join(f).is_file(), "{f} is missing");
    }
    assert!(
        read(".clusterfuzzlite/project.yaml")?.contains("language: rust"),
        "project.yaml must declare the language the builder image is chosen by"
    );
    Ok(())
}

/// The ClusterFuzzLite image fuzzes the tree under test, not whatever is on
/// main.
///
/// This is the difference between the two integrations, and it is not
/// cosmetic. `ops/oss-fuzz/Dockerfile` clones, because OSS-Fuzz rebuilds from
/// the public repository daily. ClusterFuzzLite copies, because it fuzzes the
/// checkout it was handed — a branch, a pull request, an unpushed commit.
///
/// Cloning here is the failure this test was written after: the build ran, the
/// shim exec'd, and the script it wanted did not exist in the clone because it
/// had not been pushed yet. A clone that succeeds is worse, because it fuzzes
/// code the run never saw and reports on it as though it had.
#[test]
fn the_clusterfuzzlite_image_copies_the_tree_under_test() -> Result<(), TestError> {
    let dockerfile = read(".clusterfuzzlite/Dockerfile")?;
    let code = code_lines(&dockerfile);
    assert!(
        code.contains("COPY . $SRC/sipnab"),
        ".clusterfuzzlite/Dockerfile must COPY the checkout it was handed"
    );
    assert!(
        !code.contains("git clone"),
        ".clusterfuzzlite/Dockerfile clones the repository. It would then fuzz \
         main rather than the tree under test, and report the result as though \
         it were about this commit."
    );
    assert!(
        code.contains(".clusterfuzzlite/build.sh $SRC/build.sh"),
        "the runner executes $SRC/build.sh; the Dockerfile must put it there"
    );
    Ok(())
}

/// The image carries what the fuzz targets link against.
///
/// Derived, not restated: the dependency features in `fuzz/Cargo.toml` decide
/// which system libraries the build needs. `native` is the libpcap-backed
/// capture path, and without the headers `cargo fuzz build` fails at link time
/// inside a container nobody is watching.
#[test]
fn the_clusterfuzzlite_image_installs_what_the_fuzz_targets_link() -> Result<(), TestError> {
    let manifest = read("fuzz/Cargo.toml")?;
    let sipnab_dep = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("sipnab = "))
        .ok_or("fuzz/Cargo.toml must depend on sipnab")?;
    if !sipnab_dep.contains("\"native\"") {
        // not a prerequisite: fuzz targets without `native` link no libpcap to install
        return Ok(());
    }
    let dockerfile = read(".clusterfuzzlite/Dockerfile")?;
    assert!(
        dockerfile.contains("libpcap-dev"),
        "the fuzz targets pull in sipnab's `native` feature, which links \
         libpcap, but .clusterfuzzlite/Dockerfile installs no headers for it:\n\
         {sipnab_dep}"
    );
    Ok(())
}

fn workflow(name: &str) -> Result<String, TestError> {
    read(&format!(".github/workflows/{name}"))
}

fn workflow_names() -> Result<Vec<String>, TestError> {
    let dir = repo().join(".github/workflows");
    let mut out: Vec<String> = Vec::new();
    for e in std::fs::read_dir(&dir).map_err(|e| format!("read .github/workflows: {e}"))? {
        let n = e
            .map_err(|e| format!("dir entry: {e}"))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if n.ends_with(".yml") || n.ends_with(".yaml") {
            out.push(n);
        }
    }
    out.sort();
    Ok(out)
}

/// The weekly matrix fuzzes every target, and only targets that exist.
///
/// `fuzz.yml` restates the list, because a GitHub Actions matrix cannot be
/// computed from a file without a job to compute it. That is a legitimate
/// reason to keep the copy and no reason at all to let it drift: a target
/// missing from the matrix is never fuzzed, and a target that is only in the
/// matrix fails the job every week for a reason that reads like a build break.
#[test]
fn the_weekly_matrix_fuzzes_every_target() -> Result<(), TestError> {
    let body = workflow("fuzz.yml")?;
    let listed: BTreeSet<String> = body
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("- fuzz_"))
        .map(|rest| format!("fuzz_{rest}"))
        .collect();
    let targets = fuzz_targets()?;
    let missing: Vec<&String> = targets.difference(&listed).collect();
    let extra: Vec<&String> = listed.difference(&targets).collect();
    assert!(
        missing.is_empty(),
        "fuzz.yml's matrix does not fuzz these targets: {missing:?}. They \
         compile in CI and nothing ever runs them."
    );
    assert!(
        extra.is_empty(),
        "fuzz.yml's matrix names targets that fuzz/Cargo.toml does not build: \
         {extra:?}. Those jobs fail weekly with a message about a missing \
         binary, which reads like a broken build rather than a stale list."
    );
    Ok(())
}

/// Batch fuzzing without pruning grows a corpus nobody minimizes.
///
/// Upstream states the pairing as a requirement: an unpruned corpus keeps
/// every input batch fuzzing ever kept, so each run spends more of its budget
/// replaying inputs that cover nothing new. The workflow that adds the first
/// half must not be able to land without the second.
#[test]
fn batch_fuzzing_is_paired_with_corpus_pruning() -> Result<(), TestError> {
    let mut batch = Vec::new();
    let mut prune = Vec::new();
    for name in workflow_names()? {
        let body = workflow(&name)?;
        if body.contains("mode: 'batch'") {
            batch.push(name.clone());
        }
        if body.contains("mode: 'prune'") {
            prune.push(name);
        }
    }
    if batch.is_empty() {
        // not a prerequisite: with no batch fuzzing there is nothing to pair with pruning
        return Ok(());
    }
    assert!(
        !prune.is_empty(),
        "{batch:?} runs ClusterFuzzLite batch fuzzing, but no workflow prunes \
         the corpus it accumulates"
    );
    Ok(())
}

/// Every ClusterFuzzLite step declares the language the builder image is
/// chosen by.
///
/// The action defaults to `c++`. A step that omits `language` builds sipnab
/// with the C++ base image, where `cargo` does not exist — a failure whose
/// message is about a missing binary rather than a missing input.
#[test]
fn every_clusterfuzzlite_build_step_declares_rust() -> Result<(), TestError> {
    let mut checked = 0usize;
    for name in workflow_names()? {
        let body = workflow(&name)?;
        for chunk in body.split("- name:") {
            if !chunk.contains("clusterfuzzlite/actions/build_fuzzers") {
                continue;
            }
            checked += 1;
            assert!(
                chunk.contains("language: rust"),
                "a build_fuzzers step in {name} does not set `language: rust`; \
                 the action defaults to c++ and would build in an image with \
                 no cargo"
            );
        }
    }
    assert!(
        checked > 0,
        "found no build_fuzzers steps; ClusterFuzzLite is configured in \
         .clusterfuzzlite/ but nothing runs it"
    );
    Ok(())
}

/// One workflow, three schedules, and each job guarded by the cron that is
/// meant to start it.
///
/// The three ClusterFuzzLite tasks run on different days at different times,
/// so they cannot share a trigger, and GitHub gives a workflow one `jobs:`
/// block for all of its crons. The guard is `github.event.schedule`, compared
/// against a literal — which means the cron string is written twice, in the
/// trigger and in the `if:`.
///
/// That is the pinned-value shape this repository keeps paying for. Change the
/// cron, miss the `if:`, and the job simply never runs: no error, no red
/// check, just fuzzing that quietly stopped. Nothing else would notice, which
/// is why this compares the two lists rather than trusting them to match.
#[test]
fn every_clusterfuzzlite_schedule_starts_exactly_one_job() -> Result<(), TestError> {
    let body = workflow("clusterfuzzlite.yml")?;
    let mut crons: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("- cron:"))
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
        .collect();
    let mut guarded: Vec<String> = body
        .lines()
        .filter_map(|l| l.split_once("github.event.schedule == '"))
        .filter_map(|(_, rest)| rest.split_once('\''))
        .map(|(v, _)| v.to_string())
        .collect();
    assert!(
        !crons.is_empty(),
        "parsed no cron lines out of clusterfuzzlite.yml; this gate is \
         comparing two empty lists"
    );
    crons.sort();
    guarded.sort();
    assert_eq!(
        crons, guarded,
        "clusterfuzzlite.yml's schedules and its per-job guards disagree. A \
         cron with no job runs nothing; a guard naming a cron that no longer \
         exists is a job that never runs again, silently."
    );

    // The manual trigger is the other half of the same duplication: a `mode`
    // the dispatch input does not offer is a job nobody can start by hand.
    let options = body
        .lines()
        .find_map(|l| l.trim().strip_prefix("options: ["))
        .and_then(|v| v.split_once(']'))
        .map(|(v, _)| v.to_string())
        .ok_or("clusterfuzzlite.yml must offer a `mode` choice on workflow_dispatch")?;
    let offered: Vec<&str> = options.split(',').map(str::trim).collect();
    let mut dispatched = 0usize;
    for line in body.lines() {
        let Some((_, rest)) = line.split_once("inputs.mode == '") else {
            continue;
        };
        let Some((mode, _)) = rest.split_once('\'') else {
            continue;
        };
        dispatched += 1;
        assert!(
            offered.contains(&mode),
            "a job runs on `inputs.mode == '{mode}'`, which the workflow_dispatch \
             input does not offer ({offered:?}) — nobody can start it by hand"
        );
    }
    assert_eq!(
        dispatched,
        crons.len(),
        "every scheduled job should also be startable by hand; {dispatched} of \
         {} are",
        crons.len()
    );
    Ok(())
}

/// The seed corpora reach the image the fuzzers are built in.
///
/// `.clusterfuzzlite/Dockerfile` copies the checkout, so `.dockerignore`
/// decides what the build can see — and it excluded `fuzz/corpus/` and
/// `*.pcap` for the release image, where neither belongs. In the fuzzing image
/// that exclusion is invisible: the build script looks for
/// `fuzz/corpus/<target>/`, finds nothing, packs no seed archive, and reports
/// success. Every target would then start from an empty corpus on every run,
/// which is exactly what the tracked seeds exist to prevent.
#[test]
fn the_seed_corpora_are_not_excluded_from_the_build_context() -> Result<(), TestError> {
    let ignore = read(".dockerignore")?;
    let negations: Vec<&str> = ignore
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('!'))
        .collect();
    assert!(
        negations.iter().any(|l| l.contains("fuzz/corpus")),
        ".dockerignore does not re-include fuzz/corpus, so the seeds never \
         reach the fuzzing image and every target starts from nothing:\n{ignore}"
    );

    // The re-inclusion has to come AFTER every pattern that would exclude a
    // seed, because the last matching pattern wins. A `!fuzz/corpus/**` above
    // `*.pcap` leaves `fuzz/corpus/pcap_reader/sip-register.pcap` excluded and
    // nothing else about the file looks wrong.
    let lines: Vec<&str> = ignore.lines().map(str::trim).collect();
    let last_exclusion = lines
        .iter()
        .rposition(|l| !l.starts_with('!') && !l.starts_with('#') && !l.is_empty())
        .ok_or("`.dockerignore` has no exclusion patterns at all")?;
    let first_negation = lines
        .iter()
        .position(|l| l.starts_with('!'))
        .ok_or("checked above")?;
    assert!(
        first_negation > last_exclusion,
        ".dockerignore re-includes the fuzz seeds at line {} but goes on \
         excluding at line {}; the later pattern wins, so some seeds are still \
         dropped",
        first_negation + 1,
        last_exclusion + 1
    );
    Ok(())
}

// ── Owed: five failures the containerized build found, two tests each ────────
//
// Every one of these was a green local suite and a build that died inside a
// container. None of them could have been caught by reading the Dockerfile,
// which is exactly why they are gates now rather than care.

/// The image must install its own Rust, and say which one, by environment.
///
/// FAILURE 1: `gcr.io/oss-fuzz-base/base-builder-rust` ships
/// `nightly-2025-09-05` — rustc 1.91.0-nightly, a year behind this crate's
/// `rust-version` of 1.98. The build stopped at dependency resolution with
/// "rustc 1.91.0-nightly is not supported by the following packages" before
/// compiling anything.
///
/// FAILURE 2, found while fixing 1: `rustup default <toolchain>` reported
/// success, wrote `settings.toml`, and changed nothing, because the base image
/// exports `RUSTUP_TOOLCHAIN` and an environment override beats the default.
/// rustup said so in its own output and the build still came back with 1.91.
#[test]
fn the_fuzzing_image_selects_its_toolchain_by_environment() -> Result<(), TestError> {
    let dockerfile = read(".clusterfuzzlite/Dockerfile")?;
    let code = code_lines(&dockerfile);
    assert!(
        code.contains("rustup toolchain install"),
        ".clusterfuzzlite/Dockerfile installs no toolchain, so it inherits the \
         builder image's — which is a year older than this crate's \
         rust-version and cannot resolve the dependency graph"
    );
    assert!(
        code.contains("ENV RUSTUP_TOOLCHAIN"),
        "the toolchain is selected with `rustup default` alone. The base image \
         exports RUSTUP_TOOLCHAIN, which overrides the default, so the install \
         succeeds and the old compiler still runs. Set ENV RUSTUP_TOOLCHAIN."
    );
    Ok(())
}

/// The toolchain the image installs and the one it selects are one value.
///
/// Second half of the pair. Two literals would agree the day they are written
/// and diverge the first time one is bumped — installing a toolchain and then
/// running a different one, which fails with a message about neither.
#[test]
fn the_installed_toolchain_and_the_selected_one_are_the_same_value() -> Result<(), TestError> {
    let dockerfile = read(".clusterfuzzlite/Dockerfile")?;
    let arg = dockerfile
        .lines()
        .find_map(|l| l.trim().strip_prefix("ARG RUST_NIGHTLY="))
        .ok_or("the Dockerfile must name the toolchain in one ARG")?
        .trim()
        .trim_matches('"')
        .to_string();

    // Date-pinned. A bare `nightly` resolves at image-build time, so the image
    // holds a different compiler every day and a crash report cannot be tied
    // to the compiler that produced it.
    assert!(
        arg.starts_with("nightly-") && arg.len() == "nightly-YYYY-MM-DD".len(),
        "RUST_NIGHTLY is {arg:?}, not a date-pinned nightly; the image would \
         build with a different compiler every day"
    );

    for directive in ["rustup toolchain install", "ENV RUSTUP_TOOLCHAIN"] {
        let line = dockerfile
            .lines()
            .find(|l| l.contains(directive))
            .ok_or_else(|| format!("no {directive} line"))?;
        assert!(
            line.contains("$RUST_NIGHTLY"),
            "{directive} does not read $RUST_NIGHTLY: {line:?}. Two literals \
             drift, and the failure is a build that installs one toolchain and \
             runs another."
        );
    }
    Ok(())
}

/// The toolchain must carry the standard library source.
///
/// FAILURE 3: `--profile minimal` is not enough. OSS-Fuzz's own `compile`
/// copies the std source out of the active toolchain so a sanitizer report can
/// name a line inside std, and without it the build dies at
/// `cp: cannot stat '.../lib/rustlib/src/rust/library/'` — after the image is
/// built, after every flag is right, and with a message that names a path
/// nothing in this repository mentions.
#[test]
fn the_fuzzing_image_installs_the_standard_library_source() -> Result<(), TestError> {
    let dockerfile = read(".clusterfuzzlite/Dockerfile")?;
    let install = dockerfile
        .lines()
        .find(|l| l.contains("rustup toolchain install"))
        .ok_or("the Dockerfile must install a toolchain")?;
    assert!(
        install.contains("--component rust-src"),
        "the toolchain is installed without rust-src: {install:?}. OSS-Fuzz \
         copies the std source out of it during compile."
    );
    Ok(())
}

/// A missing seed corpus fails the build instead of passing quietly.
///
/// Second half of the `.dockerignore` pair. The gate above proves the seeds
/// are in the build context; this proves the build refuses to continue if they
/// somehow are not — an empty corpus is indistinguishable from a corpus that
/// has found nothing, and the tracked seeds exist precisely so no run starts
/// from zero.
#[test]
fn the_fuzz_build_refuses_when_no_seed_corpus_was_packed() -> Result<(), TestError> {
    let build = read(".clusterfuzzlite/build.sh")?;
    let code = code_lines(&build);
    assert!(
        code.contains("seeded=0") && code.contains("seeded + 1"),
        ".clusterfuzzlite/build.sh does not count the seed archives it packs, \
         so it cannot notice packing none"
    );
    assert!(
        code.contains(r#"if [ "$seeded" -eq 0 ]"#) && code.contains("exit 1"),
        ".clusterfuzzlite/build.sh counts seed archives but does not refuse \
         when the count is zero. This repository tracks seed corpora; zero \
         means they never reached the image."
    );
    Ok(())
}

/// The build ships the shared libraries its targets need.
///
/// FAILURE 4, the expensive one: the builder image has libpcap and the runner
/// image does not. All eighteen targets built, copied, and then failed
/// `bad_build_check` with "error while loading shared libraries:
/// libpcap.so.0.8" — a hundred percent broken, from a build that exited zero.
///
/// The rpath has to be `$ORIGIN`-relative because the checker MOVES `$OUT`
/// elsewhere before running anything, specifically to catch a build that
/// hardcoded its own directory.
#[test]
fn the_fuzz_build_ships_the_libraries_its_targets_link() -> Result<(), TestError> {
    let build = read(".clusterfuzzlite/build.sh")?;
    let code = code_lines(&build);
    assert!(
        code.contains("ldd "),
        ".clusterfuzzlite/build.sh never asks what its targets link. The \
         runner image is not the builder image, and a target that links \
         anything the base runner lacks cannot start there."
    );
    assert!(
        code.contains(r#"mkdir -p "$OUT/lib""#),
        "the build never creates $OUT/lib. Only what is under $OUT travels \
         with the targets, so a directory made anywhere else is a copy the \
         runner will not find."
    );
    assert!(
        code.contains(r#""$OUT/lib/""#),
        "nothing is copied into $OUT/lib, so a library present only in the \
         builder image never travels with the binary that needs it"
    );
    assert!(
        code.contains("patchelf --set-rpath '$ORIGIN/lib'"),
        "the targets get no $ORIGIN-relative rpath, so shipping the libraries \
         changes nothing: the loader still looks only where the builder had \
         them. An absolute rpath fails too — the checker relocates $OUT."
    );
    Ok(())
}

/// What ships is derived from the binary, and the skip list is the C runtime.
///
/// Second half of the pair, and the part that keeps the fix from rotting. The
/// libraries copied come from `ldd` on the built target, so a new system
/// dependency travels without anyone remembering this file. The only thing
/// named by hand is the glibc/toolchain set the runner already provides —
/// which is a property of the base images, not of sipnab. A project library
/// appearing in that list would be silently dropped from every run.
#[test]
fn the_shipped_libraries_are_derived_and_only_the_c_runtime_is_skipped() -> Result<(), TestError> {
    let build = read(".clusterfuzzlite/build.sh")?;
    let code = code_lines(&build);

    // Derived: no library named in code. `libpcap` in a comment explaining the
    // failure is documentation; in code it is a list that stops being true.
    assert!(
        !code.contains("libpcap"),
        ".clusterfuzzlite/build.sh names libpcap in code. It reads `ldd` \
         already; a second, hand-kept copy is what drifts when the crate gains \
         another system dependency."
    );

    let case = code
        .split_once("runtime_provided()")
        .and_then(|(_, rest)| rest.split_once("esac"))
        .map(|(body, _)| body.to_string())
        .ok_or("build.sh must classify which libraries the runner provides")?;
    const C_RUNTIME: [&str; 9] = [
        "libc.so.",
        "libm.so.",
        "libdl.so.",
        "libpthread.so.",
        "librt.so.",
        "libgcc_s.so.",
        "libstdc++.so.",
        "ld-linux",
        "linux-vdso.so.",
    ];
    let named: Vec<String> = case
        .split(|c: char| c.is_whitespace() || c == '|' || c == ')' || c == '\\')
        .filter(|t| t.starts_with("lib") || t.starts_with("ld-linux"))
        .map(str::to_string)
        .collect();
    assert!(
        !named.is_empty(),
        "parsed no library patterns out of the skip list; this gate is \
         checking nothing"
    );
    let unexpected: Vec<&String> = named
        .iter()
        .filter(|n| !C_RUNTIME.iter().any(|c| n.starts_with(c)))
        .collect();
    assert!(
        unexpected.is_empty(),
        "these are skipped as \"the runner provides it\" but are not part of \
         the C runtime: {unexpected:?}. Anything else in that list is a \
         library sipnab needs and will not ship."
    );
    Ok(())
}

/// Both fuzzing images install the same system packages.
///
/// The libpcap fix had to be made twice — once in `.clusterfuzzlite/` and once
/// in `ops/oss-fuzz/` — because the two Dockerfiles build the same targets in
/// the same base image and differ only in how the source arrives. Fixing one
/// and not the other leaves a submission that fails the day it is accepted,
/// months after the change that broke it.
#[test]
fn both_fuzzing_images_install_the_same_system_packages() -> Result<(), TestError> {
    fn packages(dockerfile: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for line in dockerfile.lines() {
            let t = line.trim();
            if t.starts_with('#') || !t.contains("apt-get install") {
                continue;
            }
            for tok in t.split_whitespace() {
                if tok.starts_with('-') || tok.contains("apt-get") || tok == "install" {
                    continue;
                }
                if tok.ends_with("-dev") || tok.starts_with("lib") {
                    out.insert(tok.trim_end_matches('\\').to_string());
                }
            }
        }
        out
    }
    let cfl = packages(&read(".clusterfuzzlite/Dockerfile")?);
    let oss = packages(&read("ops/oss-fuzz/Dockerfile")?);
    assert!(
        !cfl.is_empty(),
        "parsed no packages out of .clusterfuzzlite/Dockerfile; this gate \
         would pass however far the two drifted"
    );
    assert_eq!(
        cfl, oss,
        "the two fuzzing images install different system packages. They build \
         the same targets from the same base image; a package one needs the \
         other needs."
    );
    Ok(())
}

/// Both fuzzing images build on the same base image, pinned identically.
///
/// Second half of that pair. Same reasoning, different axis: a base image
/// bumped in one file and not the other means the submission is built by a
/// compiler nobody tested against, and the divergence is a single line that no
/// review would look twice at.
#[test]
fn both_fuzzing_images_pin_the_same_base() -> Result<(), TestError> {
    fn from_line(dockerfile: &str) -> Result<String, TestError> {
        Ok(dockerfile
            .lines()
            .find(|l| l.starts_with("FROM "))
            .ok_or("every Dockerfile has a FROM")?
            .to_string())
    }
    assert_eq!(
        from_line(&read(".clusterfuzzlite/Dockerfile")?)?,
        from_line(&read("ops/oss-fuzz/Dockerfile")?)?,
        "the two fuzzing images are built from different bases; whichever is \
         behind is testing a toolchain the other one is not"
    );
    Ok(())
}

/// Nothing turns off the check that caught the broken targets.
///
/// Second half of the libpcap pair, and the one that matters longest. The
/// build exited zero with all eighteen targets unable to start; the only thing
/// that said so was OSS-Fuzz's `bad_build_check`, which the action runs by
/// default and a single input can disable.
///
/// Disabling it is the obvious way to make a red fuzzing workflow green, and
/// it works: the build goes green, the targets stay broken, and the fuzzing
/// reports nothing found for the rest of the project's life. That outcome is
/// indistinguishable from fuzzing that is working.
#[test]
fn no_workflow_disables_the_bad_build_check() -> Result<(), TestError> {
    let mut disabled = Vec::new();
    for name in workflow_names()? {
        let body = workflow(&name)?;
        for chunk in body.split("- name:") {
            if !chunk.contains("clusterfuzzlite/actions/build_fuzzers") {
                continue;
            }
            if chunk
                .lines()
                .map(str::trim)
                .any(|l| l.starts_with("bad-build-check:") && !l.contains("true"))
            {
                disabled.push(name.clone());
            }
        }
    }
    assert!(
        disabled.is_empty(),
        "{disabled:?} turns off OSS-Fuzz's bad-build check. That check is the \
         only thing standing between a build that exits zero and eighteen fuzz \
         targets that cannot start — which reads as fuzzing that has found \
         nothing."
    );
    Ok(())
}

/// What `ops/oss-fuzz/project.yaml` must say about its own state.
///
/// `gh api repos/google/oss-fuzz/contents/projects/sipnab` answered 404 on
/// 2026-11-24, while that file's header said "Submitted to google/oss-fuzz".
/// The continuous fuzzing that runs is ClusterFuzzLite in this repository's CI.
/// When OSS-Fuzz accepts sipnab, this phrase and the docs change together.
const OSS_FUZZ_STATE: &str = "Not submitted";

/// Text that, right before "submitted" on the same line, makes it a
/// statement that the submission has not happened ("un" for "unsubmitted").
const SUBMISSION_NEGATIONS: &[&str] = &["not ", "never ", "not yet ", "not been ", "un"];

/// The 1-based numbers of the lines of `text` that say sipnab was submitted to
/// OSS-Fuzz: a line holding "submitted" (any case, also inside a longer word
/// such as "resubmitted") with no negation right before it, and "oss-fuzz" on
/// that line or the one before or after.
fn oss_fuzz_submission_claims(text: &str) -> Vec<usize> {
    let lower: Vec<String> = text.lines().map(str::to_lowercase).collect();
    let mentions = |i: usize| {
        let from = i.saturating_sub(1);
        let to = (i + 1).min(lower.len().saturating_sub(1));
        (from..=to).any(|j| lower[j].contains("oss-fuzz"))
    };
    let mut out = Vec::new();
    for (i, line) in lower.iter().enumerate() {
        let claims = line.match_indices("submitted").any(|(at, _)| {
            let before = &line[..at];
            !SUBMISSION_NEGATIONS.iter().any(|n| before.ends_with(n))
        });
        if claims && mentions(i) {
            out.push(i + 1);
        }
    }
    out
}

/// Every text file the OSS-Fuzz claim rule reads: the root Markdown files,
/// and every file under `docs/`, `website/content/`, `ops/` and
/// `.clusterfuzzlite/`. Private `*.local.md` files are not tracked and are
/// skipped.
fn oss_fuzz_doc_files() -> Result<Vec<PathBuf>, TestError> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), TestError> {
        for e in std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
            let p = e.map_err(|e| format!("dir entry: {e}"))?.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else if !p.to_string_lossy().ends_with(".local.md") {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(repo()).map_err(|e| format!("read repo: {e}"))? {
        let p = e.map_err(|e| format!("dir entry: {e}"))?.path();
        if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
    for d in ["docs", "website/content", "ops", ".clusterfuzzlite"] {
        walk(&repo().join(d), &mut out)?;
    }
    out.sort();
    Ok(out)
}

#[test]
fn no_doc_claims_an_oss_fuzz_submission_that_did_not_happen() -> Result<(), TestError> {
    let files = oss_fuzz_doc_files()?;
    assert!(
        files
            .iter()
            .any(|p| p.ends_with("ops/oss-fuzz/project.yaml")),
        "the scan must read ops/oss-fuzz/project.yaml, or it passes vacuously"
    );
    let mut claims = Vec::new();
    for p in &files {
        let Ok(text) = std::fs::read_to_string(p) else {
            continue; // not UTF-8 text: no prose to check
        };
        for n in oss_fuzz_submission_claims(&text) {
            claims.push(format!(
                "{}:{n}",
                p.strip_prefix(repo()).unwrap_or(p).display()
            ));
        }
    }
    assert!(
        claims.is_empty(),
        "these lines say sipnab was submitted to OSS-Fuzz; it was not (fuzzing \
         runs in CI under ClusterFuzzLite): {claims:?}"
    );
    Ok(())
}

#[test]
fn the_oss_fuzz_project_file_and_the_testing_doc_state_the_truth() -> Result<(), TestError> {
    let project = read("ops/oss-fuzz/project.yaml")?;
    let header: String = project
        .lines()
        .take_while(|l| l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        header.contains(OSS_FUZZ_STATE) && header.contains("ClusterFuzzLite"),
        "the header of ops/oss-fuzz/project.yaml must say {OSS_FUZZ_STATE:?} and \
         name ClusterFuzzLite as what runs; it says:\n{header}"
    );
    let testing = read("docs/internals/testing.md")?;
    assert!(
        testing
            .lines()
            .any(|l| l.contains("OSS-Fuzz") && l.contains(OSS_FUZZ_STATE)),
        "docs/internals/testing.md must state on one line that sipnab is \
         {OSS_FUZZ_STATE:?} to OSS-Fuzz"
    );
    Ok(())
}

#[test]
fn the_submission_claim_rule_accepts_true_statements() {
    let cases = [
        "# Not submitted to google/oss-fuzz.",
        "Not submitted: fuzzing runs in CI via ClusterFuzzLite (oss-fuzz is a later step).",
        "The OSS-Fuzz project files are held ready but not submitted.",
        "OSS-Fuzz: never submitted.",
        "OSS-Fuzz: not yet submitted; see the backlog.",
        "The OSS-Fuzz project has not been submitted.",
        "Fill these in before submitting to OSS-Fuzz.",
        "ops/oss-fuzz/ is the submission for google/oss-fuzz.",
        "Reports submitted through GitHub are private.",
        "This is the file that goes in google/oss-fuzz as projects/sipnab/build.sh.",
        "The OSS-Fuzz application is not submitted.",
        "OSS-Fuzz builds the targets.\n\nLater paragraph: a patch was submitted upstream.",
    ];
    assert!(
        cases.len() >= 12,
        "at least 12 success cases, got {}",
        cases.len()
    );
    for text in cases {
        assert_eq!(
            oss_fuzz_submission_claims(text),
            Vec::<usize>::new(),
            "{text:?} is true and must not count as a claim"
        );
    }
}

#[test]
fn the_submission_claim_rule_finds_false_statements() {
    let cases: [(&str, Vec<usize>); 12] = [
        (
            "# Submitted to google/oss-fuzz as projects/sipnab/project.yaml.",
            vec![1],
        ),
        (
            "The image OSS-Fuzz builds in. Submitted to\ngoogle/oss-fuzz as projects/sipnab/Dockerfile.",
            vec![1],
        ),
        ("Submitted to\ngoogle/oss-fuzz.", vec![1]),
        ("sipnab was\nsubmitted to OSS-Fuzz on 2026-11-01.", vec![2]),
        ("SUBMITTED TO OSS-FUZZ", vec![1]),
        (
            "The shim submitted to google/oss-fuzz execs the build.",
            vec![1],
        ),
        ("OSS-Fuzz project: submitted.", vec![1]),
        ("We submitted sipnab to oss-fuzz.", vec![1]),
        ("The project was resubmitted to OSS-Fuzz.", vec![1]),
        ("OSS-Fuzz\nsubmitted\nnext", vec![2]),
        (
            "a\nb\nsubmitted to oss-fuzz\nc\nsubmitted to oss-fuzz",
            vec![3, 5],
        ),
        (
            "Not submitted to OSS-Fuzz, then submitted to OSS-Fuzz.",
            vec![1],
        ),
    ];
    let claims = cases.iter().filter(|(_, want)| !want.is_empty()).count();
    assert!(claims >= 12, "at least 12 claim cases, got {claims}");
    for (text, want) in &cases {
        assert_eq!(
            &oss_fuzz_submission_claims(text),
            want,
            "{text:?}: claim lines differ"
        );
    }
}

#[test]
fn the_submission_claim_rule_edges() {
    let cases: [(&str, Vec<usize>); 12] = [
        ("", vec![]),
        ("submitted", vec![]),
        ("oss-fuzz", vec![]),
        ("submitted\n\noss-fuzz", vec![]),
        ("oss-fuzz\nsubmitted", vec![2]),
        ("submitted\noss-fuzz", vec![1]),
        ("unsubmitted to OSS-Fuzz", vec![]),
        ("submittedness of OSS-Fuzz", vec![1]),
        ("OSS-Fuzz (submitted)", vec![1]),
        ("OSS-Fuzz \u{2014} submitted", vec![1]),
        ("OSS-Fuzz:\r\nsubmitted\r\n", vec![2]),
        (
            "is not submitted to OSS-Fuzz, never submitted, not yet submitted",
            vec![],
        ),
    ];
    for (text, want) in &cases {
        assert_eq!(
            &oss_fuzz_submission_claims(text),
            want,
            "{text:?}: claim lines differ"
        );
    }
}
