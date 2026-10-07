// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small optimized binary to split, and the ELF readers the split tests use.
//!
//! The fixture is compiled with the codegen settings of `[profile.release]`
//! (opt-level 3, fat LTO, one codegen unit, abort on panic, line tables only),
//! because a split that works on a debug build proves nothing about an
//! optimized one. A full sipnab release build takes many minutes; this takes
//! about a second and exercises the same toolchain path.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The error a fallible helper here returns: any error, boxed, so `?` works
/// on I/O and parse errors alike.
pub type TestError = Box<dyn std::error::Error>;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
pub fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// `scripts/split-debuginfo.sh`.
pub fn script() -> PathBuf {
    repo().join("scripts/split-debuginfo.sh")
}

/// Whether `tool` resolves on `PATH`.
pub fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool} >/dev/null 2>&1"))
        .status()
        .is_ok_and(|s| s.success())
}

/// The `rustc` to compile fixtures with.
pub fn rustc() -> String {
    std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string())
}

/// The host target triple, from `rustc -vV`.
pub fn host_triple() -> Result<String, TestError> {
    let out = Command::new(rustc()).arg("-vV").output()?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or("rustc -vV names no host")?
        .trim()
        .to_string())
}

/// The fixture program. `dbgsym_known_function` is the function the
/// symbolization test looks for; `main` prints its address relative to the
/// load base, which is exactly what a crash report records for a frame.
pub const FIXTURE: &str = r#"
#[inline(never)]
pub fn dbgsym_known_function(x: u64) -> u64 {
    std::hint::black_box(x).wrapping_mul(31) ^ 7
}

/// Start of the lowest mapping of this executable with file offset zero:
/// the load base of a position-independent executable.
fn load_base() -> Result<usize, Box<dyn std::error::Error>> {
    let exe = std::fs::read_link("/proc/self/exe")?;
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    for line in maps.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 6 && f[2] == "00000000" && std::path::Path::new(f[5]) == exe {
            let start = f[0].split('-').next().ok_or("range")?;
            return Ok(usize::from_str_radix(start, 16)?);
        }
    }
    Err(format!("no mapping of {} at offset 0", exe.display()).into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let f = dbgsym_known_function as fn(u64) -> u64 as usize;
    println!("offset=0x{:x}", f - load_base()?);
    println!("value={}", dbgsym_known_function(std::env::args().count() as u64));
    Ok(())
}
"#;

/// Compile [`FIXTURE`] into `dir/fixture` with the release profile's codegen
/// settings, leaving the symbols in (the release build now does the same and
/// lets the split strip them).
///
/// `target` is `Some((triple, linker))` to cross-compile. `build_id` false
/// passes `--build-id=none`, so the refusal path can be driven.
///
/// Returns `None`, after saying why on stderr, when this host cannot compile
/// for `target`. The host target must always compile.
pub fn build_fixture(
    dir: &Path,
    target: Option<(&str, &str)>,
    build_id: bool,
) -> std::io::Result<Option<PathBuf>> {
    let src = dir.join("fixture.rs");
    std::fs::write(&src, FIXTURE)?;
    let bin = dir.join("fixture");
    let mut cmd = Command::new(rustc());
    cmd.arg("--edition=2021")
        .args(["-C", "opt-level=3"])
        .args(["-C", "lto=fat"])
        .args(["-C", "codegen-units=1"])
        .args(["-C", "panic=abort"])
        .args(["-C", "debuginfo=line-tables-only"])
        .args(["-C", "strip=none"])
        .arg("-C")
        .arg(if build_id {
            "link-arg=-Wl,--build-id"
        } else {
            "link-arg=-Wl,--build-id=none"
        })
        .arg("-o")
        .arg(&bin)
        .arg(&src);
    if let Some((triple, linker)) = target {
        cmd.arg("--target")
            .arg(triple)
            .arg("-C")
            .arg(format!("linker={linker}"));
    }
    let out = cmd.output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(target.is_some(), "the host fixture must compile:\n{stderr}");
        eprintln!(
            "SKIPPED: cannot compile the fixture for {} on this host:\n{stderr}",
            target.map(|t| t.0).unwrap_or("host")
        );
        return Ok(None);
    }
    Ok(Some(bin))
}

/// Run the split script on `bin`, writing `<stem>.debug`.
pub fn split(bin: &Path, stem: &Path) -> std::io::Result<Output> {
    Command::new("bash")
        .arg(script())
        .arg(bin)
        .arg(stem)
        .output()
}

/// Status, stdout and stderr of `out`, for failure messages.
pub fn text(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `readelf` with `args` on `path`, as text. Fails when readelf cannot run
/// and asserts that it succeeded.
pub fn readelf(args: &[&str], path: &Path) -> std::io::Result<String> {
    let out = Command::new("readelf").args(args).arg(path).output()?;
    assert!(
        out.status.success(),
        "readelf {args:?} {} failed:\n{}",
        path.display(),
        text(&out)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The GNU build ID `readelf -n` reports for `path`, lowercase hex.
pub fn build_id(path: &Path) -> std::io::Result<Option<String>> {
    // `-W` puts the ID on the description line, without it on a line of its
    // own; splitting on the label reads both layouts.
    Ok(readelf(&["-n"], path)?
        .lines()
        .find_map(|l| l.split_once("Build ID: "))
        .map(|(_, id)| id.trim().to_ascii_lowercase()))
}

/// Section names in `path`'s section header table.
pub fn sections(path: &Path) -> std::io::Result<Vec<String>> {
    Ok(readelf(&["-S", "-W"], path)?
        .lines()
        .filter_map(|l| {
            let rest = l.trim_start().strip_prefix('[')?;
            let (_, after) = rest.split_once(']')?;
            after.split_whitespace().next().map(str::to_string)
        })
        .collect())
}

/// The strings in `path`'s `.gnu_debuglink` section.
pub fn debuglink(path: &Path) -> std::io::Result<String> {
    readelf(&["-p", ".gnu_debuglink", "-W"], path)
}

/// Resolve `address` against `file` with whichever symbolizer this host has,
/// preferring `llvm-symbolizer`. `None` when neither is installed.
pub fn symbolize(file: &Path, address: &str) -> std::io::Result<Option<String>> {
    symbolize_all(file, &[address])
}

/// Resolve every one of `addresses` against `file` in ONE symbolizer run,
/// answers in the order asked. `None` when neither symbolizer is installed.
///
/// One run, not one per address: each run loads the whole debug file, and
/// for the unoptimized test binary (184 MB) that load is the cost -- one
/// `addr2line` call took 6.3 s and a call with ten addresses 6.2 s, measured
/// on 2026-09-29. Resolving a crash report's frames one call apiece made
/// `crash_test` the slowest test binary in the suite, at 55.8 s.
pub fn symbolize_all(file: &Path, addresses: &[&str]) -> std::io::Result<Option<String>> {
    let mut cmd = if have("llvm-symbolizer") {
        let mut c = Command::new("llvm-symbolizer");
        c.arg("--obj").arg(file);
        c
    } else if have("addr2line") {
        let mut c = Command::new("addr2line");
        c.args(["-f", "-C", "-i", "-e"]).arg(file);
        c
    } else {
        return Ok(None);
    };
    let o = cmd.args(addresses).output()?;
    Ok(Some(String::from_utf8_lossy(&o.stdout).into_owned()))
}
