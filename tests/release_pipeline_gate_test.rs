// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the published binaries actually carry, and what proves it before a tag.
//!
//! Two defects of the same shape live here.
//!
//! The first: `--uprobe-tls` has two backends and only one of them can name the
//! peer a TLS session went out to. `tracefs` sees no socket, so its dialogs name
//! a process; `bpf` pairs each write with its `tcp_sendmsg` and recovers the
//! real addresses. `bpf` sat outside the `full` feature set while
//! `release.yml` built every target with `--features full`, so no published
//! binary could produce addressed output and `--uprobe-backend bpf` refused on
//! every one of them. Nothing noticed, because nothing compared what the
//! workflow compiles against what the tool advertises.
//!
//! The second: the artefact-describing steps that trail the build —
//! `THIRD-PARTY-NOTICES.md` and the CycloneDX SBOM — name their feature set by
//! hand. The notices generator is also what the drift gate compares against, so
//! generator and gate can agree with each other while both disagree with the
//! shipped binary. A gate that stays green while the artefact carries unlisted
//! dependencies is worse than no gate: it certifies the gap.
//!
//! Everything here DERIVES the answer by running `release.yml`'s own
//! feature-computing step rather than restating what it is believed to say. A
//! new target, a new variant, or a changed `case` arm is covered the day it
//! lands.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repo-relative file, panicking with the path on failure.
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The dedented `run:` script of one named workflow step.
///
/// Panics when the step is missing or duplicated: a scan that takes the first
/// of two identically named steps reads whichever an author put first, and the
/// real one can be neutered behind a decoy.
fn step_script(workflow: &str, step_name: &str) -> String {
    let text = read(workflow);
    let lines: Vec<&str> = text.lines().collect();
    let needle = format!("- name: {step_name}");
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        starts.len(),
        1,
        "{workflow} has {} steps named {step_name:?}; expected exactly one",
        starts.len()
    );
    let start = starts[0];
    let indent = lines[start].len() - lines[start].trim_start().len();
    let mut body: Vec<&str> = vec![lines[start]];
    for l in &lines[start + 1..] {
        let t = l.trim_start();
        if t.is_empty() {
            body.push(l);
            continue;
        }
        let ind = l.len() - t.len();
        if ind < indent || (ind == indent && t.starts_with("- ")) {
            break;
        }
        body.push(l);
    }

    let run_at = body
        .iter()
        .position(|l| l.trim_start().starts_with("run:"))
        .unwrap_or_else(|| panic!("{workflow} step {step_name:?} has no `run:` block"));
    let run_indent = body[run_at].len() - body[run_at].trim_start().len();
    let block: Vec<&str> = body[run_at + 1..]
        .iter()
        .take_while(|l| {
            let t = l.trim_start();
            t.is_empty() || l.len() - t.len() > run_indent
        })
        .copied()
        .collect();
    let dedent = block
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let script = block
        .iter()
        .map(|l| if l.len() >= dedent { &l[dedent..] } else { *l })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !script.trim().is_empty(),
        "{workflow} step {step_name:?}: extracted an empty script — this gate \
         would be executing nothing"
    );
    script
}

/// Every `(target, variant)` pair `release.yml`'s build matrix produces.
///
/// `variant` is the empty string for the ordinary entries, matching what
/// GitHub substitutes for an unset matrix key.
fn release_matrix() -> Vec<(String, String)> {
    let text = read(".github/workflows/release.yml");
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(target) = t.strip_prefix("- target: ") {
            out.push((target.trim().to_string(), String::new()));
        } else if let Some(variant) = t.strip_prefix("variant: ")
            && let Some(last) = out.last_mut()
        {
            last.1 = variant.trim().to_string();
        }
    }
    assert!(
        out.len() >= 8,
        "release matrix extraction found {} entries — the regex or the matrix \
         shape changed, and every assertion below would be checking nothing",
        out.len()
    );
    out
}

/// Run `release.yml`'s "Compute feature set" step for one matrix entry and
/// return the `$GITHUB_OUTPUT` it wrote.
///
/// Executing the step is the point. Every text-level check on a `case` arm
/// stays true through the ways of getting the arm wrong — a missing `;;`, an
/// arm ordered after the catch-all, a variable assigned and never read.
fn feature_step_outputs(target: &str, variant: &str) -> BTreeMap<String, String> {
    let script = step_script(".github/workflows/release.yml", "Compute feature set")
        .replace("${{ matrix.target }}", target)
        .replace("${{ matrix.variant }}", variant);

    // Unique per CALL, not per (target, variant): two tests in this file run
    // the step for the same matrix entry concurrently, and a shared path meant
    // one test's cleanup deleted the other's output between write and read.
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sipnab-featstep-{}-{}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        target,
        if variant.is_empty() { "plain" } else { variant }
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let out_file = dir.join("github_output");
    std::fs::write(&out_file, "").expect("seed GITHUB_OUTPUT");

    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        .current_dir(&dir)
        .env("GITHUB_OUTPUT", &out_file)
        .output()
        .expect("run the feature-computing step");
    let written = std::fs::read_to_string(&out_file).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success(),
        "the feature-computing step failed for target={target} variant={variant:?}\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let map: BTreeMap<String, String> = written
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert!(
        map.contains_key("features"),
        "the feature-computing step wrote no `features=` output for \
         target={target} variant={variant:?}; it wrote:\n{written}"
    );
    map
}

/// `Cargo.toml`'s `[features]` table as name -> direct members, with `dep:`
/// and `crate/feature` entries dropped (they name packages, not features).
fn feature_table() -> BTreeMap<String, Vec<String>> {
    let toml = read("Cargo.toml");
    let mut map = BTreeMap::new();
    let mut in_features = false;
    for line in toml.lines() {
        if line.starts_with('[') {
            in_features = line.trim() == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        let Some((name, rest)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        let members: Vec<String> = rest
            .split('"')
            .skip(1)
            .step_by(2)
            .filter(|s| !s.starts_with("dep:") && !s.contains('/'))
            .map(str::to_string)
            .collect();
        map.insert(name.to_string(), members);
    }
    assert!(
        map.contains_key("full") && map.contains_key("bpf"),
        "could not parse [features] from Cargo.toml — got {:?}",
        map.keys().collect::<Vec<_>>()
    );
    map
}

/// Expand a comma-separated cargo feature list into the leaf features it
/// enables, following `full` and friends transitively.
fn expand(list: &str, table: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<String> = list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    while let Some(f) = stack.pop() {
        if !out.insert(f.clone()) {
            continue;
        }
        if let Some(children) = table.get(&f) {
            stack.extend(children.iter().cloned());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// UPR1: the uprobe backend that can name a peer must reach the people who
// install a release.
// ---------------------------------------------------------------------------

/// Every published `*-linux-gnu` binary carries the `bpf` uprobe backend.
///
/// These are the artefacts a SIP operator installs on a server: the two gnu
/// tarballs and the `.deb`/`.rpm` built from the `noaudio` variants of the same
/// targets. `bpf` is orthogonal to `audio`, so the headless packages — the ones
/// most likely to be pointed at a TLS-terminating proxy — must carry it too.
#[test]
fn every_published_linux_gnu_binary_carries_the_bpf_uprobe_backend() {
    let table = feature_table();
    let mut checked = 0usize;
    for (target, variant) in release_matrix() {
        if !target.ends_with("-linux-gnu") {
            continue;
        }
        let outputs = feature_step_outputs(&target, &variant);
        let features = &outputs["features"];
        assert!(
            expand(features, &table).contains("bpf"),
            "release.yml builds {target} (variant {variant:?}) with \
             `--features {features}`, which does not enable `bpf`. That binary \
             ships an --uprobe-tls that cannot name a peer, and \
             `--uprobe-backend bpf` refuses on it."
        );
        checked += 1;
    }
    assert_eq!(
        checked, 4,
        "expected the four *-linux-gnu matrix entries (two architectures x \
         plain/noaudio), examined {checked}. Fewer means the scan went blind, \
         not that the gnu builds stopped shipping."
    );
}

/// No musl or macOS artefact pays for `bpf`.
///
/// Not a preference. Measured on the published 0.5.117 x86_64 musl binary:
/// 12,252,424 bytes against the 12 MB (12,582,912-byte) ceiling `release.yml`
/// enforces from `website/config.toml`, i.e. 330,488 bytes of headroom, while
/// `bpf` costs +589,952. Enabling it there turns every release red at the
/// size gate. macOS is excluded for a different reason: `aya` is declared
/// under `[target.'cfg(target_os = "linux")'.dependencies]`, so the feature
/// would compile to nothing but still be advertised by `--version`.
#[test]
fn no_musl_or_macos_artifact_pays_for_the_bpf_backend() {
    let table = feature_table();
    let mut checked = 0usize;
    for (target, variant) in release_matrix() {
        if target.ends_with("-linux-gnu") {
            continue;
        }
        let outputs = feature_step_outputs(&target, &variant);
        let features = &outputs["features"];
        assert!(
            !expand(features, &table).contains("bpf"),
            "release.yml builds {target} (variant {variant:?}) with \
             `--features {features}`, which enables `bpf`. musl has no room \
             under the published size ceiling and macOS cannot load a BPF \
             program at all."
        );
        checked += 1;
    }
    assert!(
        checked >= 4,
        "expected at least the two musl and two macOS entries, examined {checked}"
    );
}

/// The notices and the SBOM are generated from a feature set that covers every
/// binary the same workflow publishes.
///
/// `THIRD-PARTY-NOTICES.md` ships inside every artefact, and MIT and Apache-2.0
/// both require it to travel with the binary. It is generated by
/// `scripts/build-third-party-notices.py`, and `third_party_notices_are_current`
/// compares the committed file against THAT SAME generator — so if the
/// generator names a narrower feature set than the release builds, the gate is
/// green precisely while the shipped artefact carries dependencies the notices
/// omit. The SBOM has the identical coupling and an in-file comment claiming it
/// "over-covers rather than under-covers every sipnab binary published here",
/// which is a claim about the release matrix that nothing checked.
#[test]
fn the_notices_and_sbom_cover_every_released_feature_set() {
    let table = feature_table();

    let mut shipped: BTreeSet<String> = BTreeSet::new();
    for (target, variant) in release_matrix() {
        let outputs = feature_step_outputs(&target, &variant);
        shipped.extend(expand(&outputs["features"], &table));
    }
    assert!(
        shipped.contains("bpf"),
        "no released feature set enables `bpf`, so this gate cannot tell a \
         covering generator from a lucky one"
    );

    let notices_src = read("scripts/build-third-party-notices.py");
    let declared = notices_src
        .lines()
        .find_map(|l| l.trim().strip_prefix("RELEASE_FEATURES = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect(
            "scripts/build-third-party-notices.py declares no RELEASE_FEATURES — \
             the feature set it walks must be named in one place this gate can read",
        );
    let covered = expand(&declared, &table);
    let missing: Vec<&String> = shipped.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "the release publishes binaries built with {missing:?}, which \
         `scripts/build-third-party-notices.py` (RELEASE_FEATURES = \
         {declared:?}) does not walk. THIRD-PARTY-NOTICES.md ships inside those \
         artefacts and would omit their dependencies, while the drift gate — \
         which compares against this same generator — stays green."
    );

    let release = read(".github/workflows/release.yml");
    let sbom_features = release
        .lines()
        .find(|l| l.contains("cargo cyclonedx"))
        .and_then(|l| l.split("--features ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("release.yml has no `cargo cyclonedx ... --features` invocation")
        .to_string();
    let sbom_covered = expand(&sbom_features, &table);
    let sbom_missing: Vec<&String> = shipped.difference(&sbom_covered).collect();
    assert!(
        sbom_missing.is_empty(),
        "the SBOM is generated with `--features {sbom_features}`, which omits \
         {sbom_missing:?} — features the same workflow compiles into published \
         binaries. A vulnerability scan of that document under-covers the \
         artefact it claims to describe."
    );
}

/// `sipnab --version` names every feature the crate can be built with.
///
/// The runtime refusal for a `tracefs`-only binary says "this binary does not
/// carry it", and until `compiled_features()` listed `bpf` there was no way to
/// check which build you held. `plugins` had the same hole. Derived from
/// `Cargo.toml` rather than from a list here, so the next feature is covered
/// the day it is declared.
#[test]
fn compiled_features_names_every_feature_cargo_declares() {
    let table = feature_table();
    let cli = read("src/cli.rs");
    let start = cli
        .find("fn compiled_features()")
        .expect("src/cli.rs has no compiled_features()");
    let body = &cli[start..];
    let end = body
        .find("\n}\n")
        .expect("compiled_features() body is not delimited");
    let body = &body[..end];

    let mut missing = Vec::new();
    for name in table.keys() {
        // `default` and `full` are aggregates: reporting them would say nothing
        // about what is compiled in, because their members are already listed.
        if name == "default" || name == "full" {
            continue;
        }
        if !body.contains(&format!("cfg!(feature = \"{name}\")"))
            || !body.contains(&format!("out.push(\"{name}\")"))
        {
            missing.push(name.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "compiled_features() omits {missing:?}, so `sipnab --version` cannot \
         tell an operator whether the binary they hold carries them"
    );
}

/// CI compiles the `bpf` combination, with its test files.
///
/// The reduced-combination matrix exists because `--all-features` alone let
/// `#[cfg]`-gating rot. `--tests` is what makes it real: without it no test
/// file is built and the leg passes over nothing.
#[test]
fn the_feature_matrix_compiles_the_bpf_combo_with_its_tests() {
    let ci = read(".github/workflows/ci.yml");
    // The JOB is also called `features`, so anchoring on `trim() == "features:"`
    // alone stops at the job header and reads nothing. The matrix key is
    // nested; require the indent.
    let combos: Vec<String> = ci
        .lines()
        .skip_while(|l| l.trim() != "features:" || l.len() - l.trim_start().len() < 6)
        .skip(1)
        .take_while(|l| l.trim_start().starts_with("- ") || l.trim_start().starts_with('#'))
        .filter_map(|l| l.trim().strip_prefix("- "))
        .map(|s| s.trim().trim_matches(['"', '\'']).to_string())
        .collect();
    assert!(
        combos.len() >= 11,
        "found {} feature combinations in ci.yml ({combos:?}) — the matrix \
         scan went blind",
        combos.len()
    );
    assert!(
        combos.iter().any(|c| c.split(',').any(|f| f == "bpf")),
        "ci.yml's feature matrix has no `bpf` combination ({combos:?}), so the \
         only build of the backend published binaries now carry happens on a \
         release tag — the shape that shipped 0.5.113's .rpm broken"
    );
    assert!(
        ci.contains(r#"--features "${{ matrix.features }}" --tests"#),
        "the feature-matrix check no longer passes `--tests`, so no test file \
         is compiled and every leg is green over nothing"
    );
}

// ---------------------------------------------------------------------------
// UPR1: build.rs has two explicitly chosen modes, and a release picks the
// strict one.
// ---------------------------------------------------------------------------

/// Compile `build.rs` standalone with `--cfg feature="bpf"` and run it with a
/// prepared `PATH`, returning `(exit ok, stdout, stderr)`.
///
/// Running the real build script is the only way to test the degrade/refuse
/// decision: a build script cannot be called from an integration test, and a
/// full `cargo build --features bpf` costs minutes. It has no dependencies, so
/// `rustc build.rs` is enough.
///
/// # Arguments
/// * `path` — the `PATH` the script runs with; controls whether `bpf-linker`
///   and `rustup` appear to exist.
/// * `required` — sets `SIPNAB_BPF_REQUIRED=1` when true.
#[cfg(target_os = "linux")]
fn run_build_script(path: &str, required: bool) -> (bool, String) {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sipnab-buildrs-{}-{}-{required}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let exe = dir.join("build_script");

    let compile = std::process::Command::new("rustc")
        .args(["--edition", "2024", "--cfg", r#"feature="bpf""#, "-o"])
        .arg(&exe)
        .arg(repo().join("build.rs"))
        .current_dir(&dir)
        .output()
        .expect("compile build.rs with rustc");
    assert!(
        compile.status.success(),
        "could not compile build.rs standalone:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).expect("OUT_DIR");
    let mut cmd = std::process::Command::new(&exe);
    cmd.current_dir(&dir)
        .env_clear()
        .env("PATH", path)
        .env("OUT_DIR", &out_dir)
        .env("CARGO_CFG_TARGET_ENDIAN", "little")
        .env("CARGO_CFG_TARGET_ARCH", "x86_64");
    if required {
        cmd.env("SIPNAB_BPF_REQUIRED", "1");
    }
    let run = cmd.output().expect("run the compiled build script");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let ok = run.status.success();
    let _ = std::fs::remove_dir_all(&dir);
    (ok, combined)
}

/// A `PATH` holding only the stubs this test creates, plus optionally a fake
/// `bpf-linker` that answers `--version`.
#[cfg(target_os = "linux")]
fn stub_path(with_linker: bool) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("stub dir");
    if with_linker {
        let p = dir.path().join("bpf-linker");
        std::fs::write(&p, "#!/bin/sh\necho 'fake bpf-linker 0.11.0'\n").expect("write stub");
        let mut perms = std::fs::metadata(&p).expect("stat stub").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&p, perms).expect("chmod stub");
    }
    let path = dir.path().display().to_string();
    (dir, path)
}

/// Without the opt-in, a machine that cannot build the kernel half still
/// builds sipnab.
///
/// `cargo build --all-features` is the pre-push clippy gate, the rustdoc gate
/// and every contributor's habit, and it sweeps up `bpf`. Exploding there would
/// mean a contributor without nightly or `bpf-linker` cannot build sipnab at
/// all, which is the degrade this default exists for. Both prerequisites must
/// degrade the same way: it used to warn for a missing `bpf-linker` and panic
/// for a missing nightly, which is one rule applied to one side.
#[test]
#[cfg(target_os = "linux")]
fn a_contributor_build_degrades_when_either_bpf_prerequisite_is_missing() {
    let (_keep, no_tools) = stub_path(false);
    let (ok, out) = run_build_script(&no_tools, false);
    assert!(
        ok,
        "build.rs failed without bpf-linker in the default mode; a contributor \
         who runs `cargo build --all-features` can no longer build sipnab.\n{out}"
    );
    assert!(
        out.contains("cargo:warning") && out.contains("bpf-linker"),
        "the degrade is silent — nothing told the builder the kernel programs \
         are absent.\n{out}"
    );

    let (_keep2, linker_only) = stub_path(true);
    let (ok, out) = run_build_script(&linker_only, false);
    assert!(
        ok,
        "build.rs failed with bpf-linker present but no nightly toolchain, in \
         the default mode. Missing prerequisites degrade; that is the whole \
         rule, and it must not depend on WHICH one is missing.\n{out}"
    );
    assert!(
        out.contains("cargo:warning"),
        "the missing-toolchain degrade is silent.\n{out}"
    );
}

/// With `SIPNAB_BPF_REQUIRED=1`, a build that cannot produce the kernel
/// programs fails instead of shipping a binary that refuses at runtime.
///
/// The degrading default embeds an EMPTY placeholder object, so the binary
/// advertises `bpf` in `--version` and `--uprobe-backend bpf` refuses on every
/// host. That is the right trade for a contributor and exactly the wrong one
/// for a release: the artefact reaches thousands of machines claiming a
/// capability it does not have. `release.yml` sets the variable.
#[test]
#[cfg(target_os = "linux")]
fn a_release_build_refuses_to_ship_without_the_kernel_programs() {
    let (_keep, no_tools) = stub_path(false);
    let (ok, out) = run_build_script(&no_tools, true);
    assert!(
        !ok,
        "SIPNAB_BPF_REQUIRED=1 with no bpf-linker on PATH still succeeded. The \
         release would publish a binary whose `bpf` backend refuses on every \
         host.\n{out}"
    );
    assert!(
        out.contains("bpf-linker"),
        "the refusal does not name the missing tool.\n{out}"
    );

    let (_keep2, linker_only) = stub_path(true);
    let (ok, out) = run_build_script(&linker_only, true);
    assert!(
        !ok,
        "SIPNAB_BPF_REQUIRED=1 with bpf-linker present but no nightly toolchain \
         still succeeded — the same empty placeholder, reached down the other \
         branch.\n{out}"
    );
}

/// The release workflow asks for the strict mode on the targets that ship
/// `bpf`, and only there.
#[test]
fn the_release_build_opts_into_the_strict_bpf_mode() {
    let release = read(".github/workflows/release.yml");
    assert!(
        release.contains("SIPNAB_BPF_REQUIRED"),
        "release.yml never sets SIPNAB_BPF_REQUIRED, so a release built on a \
         runner without bpf-linker would publish the empty-placeholder binary \
         with nothing failing"
    );
    // Derived from the same step the other gates run, so the two cannot drift.
    let table = feature_table();
    for (target, variant) in release_matrix() {
        let outputs = feature_step_outputs(&target, &variant);
        if !expand(&outputs["features"], &table).contains("bpf") {
            continue;
        }
        assert_eq!(
            outputs.get("bpf_required").map(String::as_str),
            Some("1"),
            "release.yml compiles {target} (variant {variant:?}) with `bpf` but \
             its feature step did not export bpf_required=1, so the build script \
             stays in the degrading mode"
        );
    }
}

// ---------------------------------------------------------------------------
// PKG1: the Homebrew generator must meet real input before a tag, not on one.
// ---------------------------------------------------------------------------

/// The formula generator is exercised against a real release manifest in CI,
/// and the checker that does it is not decoration.
///
/// `test-update-formula.sh` has 21 assertions and CI runs them on every push —
/// against a FIXTURE. The generator only ever meets the real `SHA256SUMS.txt`
/// on a tag, so a failure that depends on real input (a new artefact name, a
/// platform that did not build, a change in asset count or ordering) is
/// discovered while the workflow is already publishing. This is the shape that
/// shipped 0.5.113's `.rpm` broken.
///
/// Two claims, checked separately: that CI runs the real-input checker, and
/// that the checker actually fails on input it should reject. The second is
/// what stops it becoming a step that downloads a file and exits 0.
#[test]
fn the_homebrew_generator_meets_a_real_sums_file_in_ci() {
    let checker = repo().join("packaging/homebrew/test-real-sums.sh");
    assert!(
        checker.is_file(),
        "packaging/homebrew/test-real-sums.sh is missing — the generator still \
         meets real input for the first time on a release tag"
    );

    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("packaging/homebrew/test-real-sums.sh"),
        "no CI job runs the real-input check, so it exists and proves nothing"
    );
    // Comments in ci.yml discuss `continue-on-error` at length (it was removed
    // from a job for exactly this reason), so the scan has to read code.
    assert!(
        !ci.lines()
            .any(|l| !l.trim_start().starts_with('#') && l.contains("continue-on-error")),
        "a live `continue-on-error` appeared in ci.yml; a step whose conclusion \
         is rewritten to success gates nothing"
    );

    // Mutation: real input, one platform missing. A generator that emitted a
    // blank checksum here would publish a formula every `brew install` rejects.
    let dir = tempfile::tempdir().expect("temp dir");
    let full = "\
3aff883c628f9e4205a5e8ce114da485f6059658f98f431b781802279367322d  sipnab-9.9.9-aarch64-apple-darwin.tar.gz
b2c6195d628599ad947401346bf826c987271ee3f3b7253e52ed06223e9774dd  sipnab-9.9.9-aarch64-unknown-linux-gnu.tar.gz
2e9d6587f02e3413966175c7a47d59dbeaf098a0acd109c5a9b02559ec64602d  sipnab-9.9.9-aarch64-unknown-linux-musl.tar.gz
aea6ea76045bd1f5f72ca95e70d6316b594a25d3d348a5b0f430a15505861c09  sipnab-9.9.9-x86_64-apple-darwin.tar.gz
bda7a1463b6a85f5ad40cd74aa6be51b7dc7a8d9321d22fedc288b0da4512aa7  sipnab-9.9.9-x86_64-unknown-linux-gnu.tar.gz
b4b0b321622cf35c8eda402f9f54c27a0ccd70889ec5c8149478224cf6bdf670  sipnab-9.9.9-x86_64-unknown-linux-musl.tar.gz
9e9b22af848487637d9805d4b961f5e6491dd7960161ffc971fc08f2d96c21ec  sipnab_9.9.9_amd64-noaudio.deb
1b7fca4e880a9ffefe5f7a7265521f72b0da6db8e2fcbdb8d817028df50e41fe  sipnab_9.9.9_amd64.deb
b20bde02b03ad3ca92b6cbb3b1aeac3bde10ec6ed2b7d056fcda7ccf462cbfcb  sipnab_9.9.9_arm64-noaudio.deb
6b4e27595d46124835a76079184fce153aa09b6cfc2b7c70b84452ff1f043eb2  sipnab_9.9.9_arm64.deb
179531bf404c4088c450535dfdda5b38dc3af0fbb520c4aec2ddc247d3041870  sipnab-9.9.9-1.aarch64-noaudio.rpm
506dbf804bd799331100fbe65e6372c3d33d76811b61d7514d6878ca63bcff53  sipnab-9.9.9-1.aarch64.rpm
9f22739d4989b26cb3e765764f5d3497c106bf5293866cd683255dbe59f708b1  sipnab-9.9.9-1.x86_64-noaudio.rpm
3ad4a343cebb105b78fc8656e4a27572219d2fef6b21d0ded359b1b3f0b668ed  sipnab-9.9.9-1.x86_64.rpm
a593140488b02315cdf326d12768de38c93b775e17e3a05a8748f4ed82f6ecb7  sipnab-9.9.9.cdx.json
ee5cc4e74838d322291a815c511c790723a4bfd37ac548cbed78640e4b2bb2a6  sipnab-audio-9.9.9.cdx.json
";
    let good = dir.path().join("SHA256SUMS.txt");
    std::fs::write(&good, full).expect("write sums");
    let run = |file: &std::path::Path| {
        std::process::Command::new("bash")
            .arg(repo().join("packaging/homebrew/test-real-sums.sh"))
            .arg(file)
            .arg("9.9.9")
            .current_dir(repo())
            .output()
            .expect("run test-real-sums.sh")
    };

    let out = run(&good);
    assert!(
        out.status.success(),
        "the real-input checker rejected a manifest with the exact shape the \
         release publishes\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let missing_platform: String = full
        .lines()
        .filter(|l| !l.contains("x86_64-unknown-linux-gnu"))
        .collect::<Vec<_>>()
        .join("\n");
    let broken = dir.path().join("missing.txt");
    std::fs::write(&broken, missing_platform).expect("write sums");
    let out = run(&broken);
    assert!(
        !out.status.success(),
        "a release manifest missing the x86_64 Linux tarball was accepted. That \
         is a platform that did not build, and the formula would carry a blank \
         or wrong checksum for it.\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Mutation: the four tarballs alone. This is what a stub or a truncated
    // download looks like, and accepting it is how "the fetch succeeded"
    // becomes indistinguishable from "the fetch returned nothing real".
    let stub = dir.path().join("stub.txt");
    std::fs::write(
        &stub,
        full.lines()
            .filter(|l| l.contains(".tar.gz") && !l.contains("musl"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("write sums");
    let out = run(&stub);
    assert!(
        !out.status.success(),
        "a four-line stub passed as a real release manifest, so a truncated or \
         empty download would read as a successful check\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Mutation: a whole ARTIFACT KIND absent, with the line count still high
    // enough that only the kind check can catch it. Removing the four `.rpm`
    // rows leaves twelve entries — the exact shape of a release where the rpm
    // build failed. Without this case the kind check could be deleted and the
    // three cases above would all still fail for other reasons, which is how a
    // check ends up unwatched inside a watched script.
    let no_rpm = dir.path().join("no-rpm.txt");
    std::fs::write(
        &no_rpm,
        full.lines()
            .filter(|l| !l.ends_with(".rpm"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("write sums");
    let out = run(&no_rpm);
    assert!(
        !out.status.success(),
        "a manifest with no .rpm at all was accepted as a real release. \
         release.yml checksums *.tar.gz *.deb *.rpm *.cdx.json into one file, \
         so a missing kind means a build leg failed.\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
