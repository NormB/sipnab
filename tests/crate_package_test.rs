// SPDX-License-Identifier: MIT OR Apache-2.0
//! The crate that `cargo publish` would upload, checked with cargo's own rule.
//!
//! sipnab was advertised as `cargo install sipnab` in seven places for months
//! while `cargo package` refused to run: `sipnab-bpf-types` was a path
//! dependency with no `version` and `publish = false`, and the file set cargo
//! would have shipped compressed to 10,499,471 bytes against crates.io's
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

/// crates.io's default `max_upload_size` for a `.crate` file.
const CRATES_IO_MAX_UPLOAD_BYTES: u64 = 10 * 1024 * 1024;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `sipnab-bpf-types`' own version, read from its manifest.
fn bpf_types_version() -> String {
    let manifest = std::fs::read_to_string(repo().join("crates/sipnab-bpf-types/Cargo.toml"))
        .expect("read crates/sipnab-bpf-types/Cargo.toml");
    manifest
        .lines()
        .find_map(|l| {
            let v = l.strip_prefix("version = \"")?;
            Some(v.trim_end_matches('"').to_string())
        })
        .expect("sipnab-bpf-types declares a version")
}

/// Package both publishable crates, once per test run, into a directory of
/// this test's own and return where the `.crate` files landed.
///
/// A separate target directory, because `cargo test` holds the lock on the
/// normal one while this runs. The git hook's variables are removed so a run
/// under `.githooks/pre-commit` packages this checkout, not the hook's idea
/// of one.
fn package() -> PathBuf {
    static PACKAGED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PACKAGED.get_or_init(package_now).clone()
}

fn package_now() -> PathBuf {
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
        .output()
        .expect("run cargo package");
    assert!(
        out.status.success(),
        "`cargo package -p sipnab-bpf-types -p sipnab` fails, so `cargo publish` \
         would too:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    target.join("package")
}

fn crate_file(dir: &Path, name: &str, version: &str) -> PathBuf {
    let path = dir.join(format!("{name}-{version}.crate"));
    assert!(path.is_file(), "no {} after cargo package", path.display());
    path
}

/// Paths inside the `.crate`, without the `name-version/` prefix.
fn crate_entries(crate_path: &Path) -> BTreeSet<String> {
    let out = Command::new("tar")
        .arg("-tzf")
        .arg(crate_path)
        .output()
        .expect("run tar -tzf");
    assert!(out.status.success(), "tar -tzf {}", crate_path.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once('/').map(|(_, rest)| rest.to_string()))
        .filter(|l| !l.is_empty())
        .collect()
}

/// One file read out of the `.crate`.
fn crate_member(crate_path: &Path, prefix: &str, member: &str) -> String {
    let out = Command::new("tar")
        .arg("-xzOf")
        .arg(crate_path)
        .arg(format!("{prefix}/{member}"))
        .output()
        .expect("run tar -xzOf");
    assert!(out.status.success(), "tar could not read {member}");
    String::from_utf8_lossy(&out.stdout).into_owned()
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
/// from outside `src/` -- the files a build of the unpacked crate needs and
/// the `include` allowlist has to name one by one.
fn embedded_files_outside_src() -> BTreeSet<String> {
    let listed = Command::new("git")
        .args(["ls-files", "-z", "--", ":(glob)src/**/*.rs", "build.rs"])
        .current_dir(repo())
        .output()
        .expect("git ls-files src/");
    assert!(listed.status.success(), "git ls-files failed");
    let mut found = BTreeSet::new();
    for file in String::from_utf8_lossy(&listed.stdout).split('\0') {
        if file.is_empty() {
            continue;
        }
        let text = std::fs::read_to_string(repo().join(file)).unwrap_or_default();
        for macro_name in ["include_str!(\"", "include_bytes!(\""] {
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
    found
}

#[test]
fn both_crates_package_and_the_main_one_fits_the_upload_limit() {
    let dir = package();
    crate_file(&dir, "sipnab-bpf-types", &bpf_types_version());
    let main = crate_file(&dir, "sipnab", env!("CARGO_PKG_VERSION"));
    let size = std::fs::metadata(&main).expect("stat .crate").len();
    assert!(
        size <= CRATES_IO_MAX_UPLOAD_BYTES,
        "{} is {size} bytes; crates.io refuses anything over \
         {CRATES_IO_MAX_UPLOAD_BYTES}. Trim the `include` list in Cargo.toml.",
        main.display()
    );
}

#[test]
fn every_file_the_code_embeds_is_in_the_crate() {
    let embedded = embedded_files_outside_src();
    assert!(
        embedded.len() >= 10,
        "found only {} embedded files outside src/; the scan has stopped \
         matching and this gate proves nothing",
        embedded.len()
    );
    let main = crate_file(&package(), "sipnab", env!("CARGO_PKG_VERSION"));
    let entries = crate_entries(&main);
    let missing: Vec<&String> = embedded.iter().filter(|f| !entries.contains(*f)).collect();
    assert!(
        missing.is_empty(),
        "the code embeds these files but the published crate would not contain \
         them, so a build from crates.io fails: {missing:?}. Add them to \
         `include` in Cargo.toml."
    );
}

#[test]
fn cargo_install_puts_only_sipnab_on_the_path() {
    let version = env!("CARGO_PKG_VERSION");
    let main = crate_file(&package(), "sipnab", version);
    assert!(
        !crate_entries(&main).contains("src/bin/gen_fixture.rs"),
        "the test-fixture generator is in the published crate, so \
         `cargo install sipnab` installs it beside sipnab"
    );
    let manifest = crate_member(&main, &format!("sipnab-{version}"), "Cargo.toml");
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
}
