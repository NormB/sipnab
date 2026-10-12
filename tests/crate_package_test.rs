// SPDX-License-Identifier: MIT OR Apache-2.0
//! The crate that `cargo publish` would upload, checked with cargo's own rule.
//!
//! sipnab was advertised as `cargo install sipnab` in seven places for months
//! while `cargo package` refused to run: `sipnab-bpf-types` was a path
//! dependency with no `version` and `publish = false`, and the file set cargo
//! would have shipped compressed to 10,452,860 bytes, 32,900 under crates.io's
//! 10,485,760-byte limit. Nothing noticed, because nothing ever packaged it.
//!
//! This gate runs `cargo package --no-verify` itself instead of re-deriving
//! cargo's include rules, so it cannot disagree with what a publish would
//! build. It stays fast by not compiling; the `crate-package` CI job runs the
//! verifying `cargo package`, which builds the unpacked crate from its own
//! files alone.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

/// crates.io's default `max_upload_size` for a `.crate` file.
const CRATES_IO_MAX_UPLOAD_BYTES: u64 = 10 * 1024 * 1024;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `sipnab-bpf-types`' own version, read from its manifest.
fn bpf_types_version() -> Result<String, TestError> {
    let manifest = std::fs::read_to_string(repo().join("crates/sipnab-bpf-types/Cargo.toml"))?;
    Ok(manifest
        .lines()
        .find_map(|l| {
            let v = l.strip_prefix("version = \"")?;
            Some(v.trim_end_matches('"').to_string())
        })
        .ok_or("sipnab-bpf-types declares a version")?)
}

/// Package both publishable crates, once per test run, into a directory of
/// this test's own and return where the `.crate` files landed.
///
/// A separate target directory, because `cargo test` holds the lock on the
/// normal one while this runs. The git hook's variables are removed so a run
/// under `.githooks/pre-commit` packages this checkout, not the hook's idea
/// of one.
fn package() -> Result<PathBuf, TestError> {
    static PACKAGED: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    Ok(PACKAGED
        .get_or_init(|| package_now().map_err(|e| e.to_string()))
        .clone()?)
}

fn package_now() -> Result<PathBuf, TestError> {
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("crate-package");
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "package",
            "-p",
            "sipnab-bpf-types",
            "-p",
            "sipnab",
            "--no-verify",
            "--allow-dirty",
            "--offline",
        ])
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .current_dir(repo())
        .output()?;
    assert!(
        out.status.success(),
        "`cargo package -p sipnab-bpf-types -p sipnab` fails, so `cargo publish` \
         would too:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(target.join("package"))
}

fn crate_file(dir: &Path, name: &str, version: &str) -> PathBuf {
    let path = dir.join(format!("{name}-{version}.crate"));
    assert!(path.is_file(), "no {} after cargo package", path.display());
    path
}

/// Paths inside the `.crate`, without the `name-version/` prefix.
fn crate_entries(crate_path: &Path) -> Result<BTreeSet<String>, TestError> {
    let out = Command::new("tar").arg("-tzf").arg(crate_path).output()?;
    assert!(out.status.success(), "tar -tzf {}", crate_path.display());
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once('/').map(|(_, rest)| rest.to_string()))
        .filter(|l| !l.is_empty())
        .collect())
}

/// One file read out of the `.crate`.
fn crate_member(crate_path: &Path, prefix: &str, member: &str) -> Result<String, TestError> {
    let out = Command::new("tar")
        .arg("-xzOf")
        .arg(crate_path)
        .arg(format!("{prefix}/{member}"))
        .output()?;
    assert!(out.status.success(), "tar could not read {member}");
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Lexically resolve `rel` against the directory of `file`, both repo-relative.
fn resolve(file: &str, rel: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let base = Path::new(file).parent().unwrap_or(Path::new(""));
    for c in base.join(rel).components() {
        match c {
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            _ => {}
        }
    }
    parts.join("/")
}

/// Every file the tracked sources pull in with `include_str!`/`include_bytes!`
/// or a `#[path = "..."]` module from outside `src/` -- the files a build of
/// the unpacked crate needs and the `include` allowlist has to name one by one.
/// (`build.rs` shares `build_script/git_triggers.rs` with a test that way.)
/// Only sources the crate ships are scanned: an excluded one, like
/// `src/bin/gen_fixture.rs`, is never built from the crate.
fn embedded_files_outside_src(shipped: &BTreeSet<String>) -> Result<BTreeSet<String>, TestError> {
    let listed = Command::new("git")
        .args(["ls-files", "-z", "--", ":(glob)src/**/*.rs", "build.rs"])
        .current_dir(repo())
        .output()?;
    assert!(listed.status.success(), "git ls-files failed");
    let mut found = BTreeSet::new();
    for file in String::from_utf8_lossy(&listed.stdout).split('\0') {
        if file.is_empty() || !shipped.contains(file) {
            continue;
        }
        let text = std::fs::read_to_string(repo().join(file)).unwrap_or_default();
        for macro_name in ["include_str!(\"", "include_bytes!(\"", "#[path = \""] {
            let mut rest = text.as_str();
            while let Some(at) = rest.find(macro_name) {
                rest = &rest[at + macro_name.len()..];
                let Some(end) = rest.find('"') else { break };
                let target = resolve(file, &rest[..end]);
                if !target.starts_with("src/") {
                    found.insert(target);
                }
            }
        }
    }
    Ok(found)
}

#[test]
fn both_crates_package_and_the_main_one_fits_the_upload_limit() -> Result<(), TestError> {
    let dir = package()?;
    crate_file(&dir, "sipnab-bpf-types", &bpf_types_version()?);
    let main = crate_file(&dir, "sipnab", env!("CARGO_PKG_VERSION"));
    let size = std::fs::metadata(&main)?.len();
    assert!(
        size <= CRATES_IO_MAX_UPLOAD_BYTES,
        "{} is {size} bytes; crates.io refuses anything over \
         {CRATES_IO_MAX_UPLOAD_BYTES}. Trim the `include` list in Cargo.toml.",
        main.display()
    );
    Ok(())
}

#[test]
fn every_file_the_code_embeds_is_in_the_crate() -> Result<(), TestError> {
    let main = crate_file(&package()?, "sipnab", env!("CARGO_PKG_VERSION"));
    let entries = crate_entries(&main)?;
    let embedded = embedded_files_outside_src(&entries)?;
    assert!(
        embedded.len() >= 10,
        "found only {} embedded files outside src/; the scan has stopped \
         matching and this gate proves nothing",
        embedded.len()
    );
    let missing: Vec<&String> = embedded.iter().filter(|f| !entries.contains(*f)).collect();
    assert!(
        missing.is_empty(),
        "the code embeds these files but the published crate would not contain \
         them, so a build from crates.io fails: {missing:?}. Add them to \
         `include` in Cargo.toml."
    );
    Ok(())
}

#[test]
fn cargo_install_puts_only_sipnab_on_the_path() -> Result<(), TestError> {
    let version = env!("CARGO_PKG_VERSION");
    let main = crate_file(&package()?, "sipnab", version);
    assert!(
        !crate_entries(&main)?.contains("src/bin/gen_fixture.rs"),
        "the test-fixture generator is in the published crate, so \
         `cargo install sipnab` installs it beside sipnab"
    );
    let manifest = crate_member(&main, &format!("sipnab-{version}"), "Cargo.toml")?;
    let bins: Vec<&str> = manifest
        .split("[[bin]]")
        .skip(1)
        .filter_map(|block| {
            block
                .lines()
                .find_map(|l| l.strip_prefix("name = \""))
                .map(|n| n.trim_end_matches('"'))
        })
        .collect();
    assert_eq!(
        bins,
        ["sipnab"],
        "the published manifest declares these binaries; `cargo install sipnab` \
         installs every one of them"
    );
    Ok(())
}

/// crates.io shows a crate's README as its page, and a crate without one as
/// "appears to have no README.md file". `sipnab-bpf-types` 0.1.0 went up that
/// way on 2026-09-18, and nothing here asked. Every published crate also
/// carries both license texts: the manifest names "MIT OR Apache-2.0", and
/// the MIT terms ask for the notice to travel with every copy.
#[test]
fn every_published_crate_ships_its_readme_and_both_licenses() -> Result<(), TestError> {
    let dir = package()?;
    for (name, version) in [
        ("sipnab", env!("CARGO_PKG_VERSION").to_string()),
        ("sipnab-bpf-types", bpf_types_version()?),
    ] {
        let path = crate_file(&dir, name, &version);
        let entries = crate_entries(&path)?;
        for file in ["README.md", "LICENSE-MIT", "LICENSE-APACHE"] {
            assert!(
                entries.contains(file),
                "{name} {version} would be published without {file}"
            );
        }
        let manifest = crate_member(&path, &format!("{name}-{version}"), "Cargo.toml")?;
        assert!(
            manifest.lines().any(|l| l == "readme = \"README.md\""),
            "{name}'s published manifest does not name its README, so crates.io \
             shows none"
        );
    }
    // One license text, not two that drift: the crate's copies are the root's.
    for file in ["LICENSE-MIT", "LICENSE-APACHE"] {
        let root = std::fs::read(repo().join(file))?;
        let copy =
            std::fs::read(repo().join("crates/sipnab-bpf-types").join(file)).unwrap_or_default();
        assert!(
            root == copy,
            "crates/sipnab-bpf-types/{file} differs from the root {file}"
        );
    }
    Ok(())
}

/// The license expression the root manifest declares, read from `Cargo.toml`.
fn manifest_license() -> Result<String, TestError> {
    let manifest = std::fs::read_to_string(repo().join("Cargo.toml"))?;
    Ok(manifest
        .lines()
        .find_map(|l| {
            let v = l.strip_prefix("license = \"")?;
            Some(v.trim_end_matches('"').to_string())
        })
        .ok_or("Cargo.toml declares a license")?)
}

/// Every `// SPDX-License-Identifier:` comment line in `body` whose expression
/// is not `expected`, as `path:line: expression`. Only a line that is the
/// comment counts, so a string literal quoting one is not a header.
///
/// A source file that names a license names the terms a reader may take it
/// under. When that disagrees with the manifest, the file and the crate offer
/// two different licenses for one piece of code.
fn spdx_mismatches(path: &str, body: &str, expected: &str) -> Vec<String> {
    body.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let rest = line
                .trim_start()
                .strip_prefix("// SPDX-License-Identifier:")?;
            let expression = rest.trim();
            (expression != expected).then(|| format!("{path}:{}: {expression}", i + 1))
        })
        .collect()
}

/// Every tracked Rust file that carries an SPDX header carries the license
/// the manifest declares. Two files said `GPL-3.0-or-later` while the crate
/// is published as `MIT OR Apache-2.0`.
#[test]
fn every_spdx_header_in_rust_source_names_the_manifest_license() -> Result<(), TestError> {
    let expected = manifest_license()?;
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", "*.rs"])
        .current_dir(repo())
        .output()?;
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listing = String::from_utf8(out.stdout)?;
    let mut checked = 0usize;
    let mut wrong = Vec::new();
    for path in listing.split('\0').filter(|p| !p.is_empty()) {
        let Ok(body) = std::fs::read_to_string(repo().join(path)) else {
            continue;
        };
        checked += 1;
        wrong.extend(spdx_mismatches(path, &body, &expected));
    }
    assert!(checked > 0, "git ls-files listed no Rust files to check");
    assert!(
        wrong.is_empty(),
        "these SPDX headers do not name the manifest license {expected:?}:\n{}",
        wrong.join("\n")
    );
    Ok(())
}

/// The predicate reports a header that differs, and passes one that matches
/// and a file with no header at all.
#[test]
fn the_spdx_predicate_reports_only_a_differing_expression() -> Result<(), TestError> {
    let expected = "MIT OR Apache-2.0";
    assert_eq!(
        spdx_mismatches(
            "a.rs",
            "// SPDX-License-Identifier: GPL-3.0-or-later\n",
            expected
        ),
        ["a.rs:1: GPL-3.0-or-later"]
    );
    assert!(
        spdx_mismatches(
            "b.rs",
            "// SPDX-License-Identifier: MIT OR Apache-2.0\n",
            expected
        )
        .is_empty()
    );
    assert!(spdx_mismatches("c.rs", "//! no header\nfn f() {}\n", expected).is_empty());
    assert!(
        spdx_mismatches(
            "e.rs",
            "let s = \"// SPDX-License-Identifier: GPL-3.0-or-later\";\n",
            expected
        )
        .is_empty()
    );
    assert_eq!(
        spdx_mismatches(
            "d.rs",
            "//! doc\n// SPDX-License-Identifier: MIT\n",
            expected
        ),
        ["d.rs:2: MIT"]
    );
    Ok(())
}
