// SPDX-License-Identifier: MIT OR Apache-2.0

//! `scripts/split-debuginfo.sh`: the release step that turns one optimized
//! build into a stripped binary to ship and a symbol file to keep.
//!
//! Every published binary is stripped, so a crash report or a core dump from a
//! user's machine names no functions. The release keeps the line tables the
//! build already produces, moves them into `sipnab-<version>-<target>.debug`,
//! and strips the binary it ships. The two halves are matched by the GNU build
//! ID, a hash the linker writes into both.
//!
//! These tests drive the script on a real optimized binary, not on a
//! description of one (see `support/dbgsym.rs` for the fixture). The release
//! workflow cannot run on a commit, so this is where the script earns its trust
//! before a tag depends on it.
//!
//! Linux only: the fixture reads `/proc/self/maps` and the checks read ELF.
//! The macOS half of the script packages a `.dSYM` that only Xcode's tools
//! produce, and the release workflow's darwin legs are what exercise it.
#![cfg(target_os = "linux")]

use std::path::Path;

#[path = "support/dbgsym.rs"]
mod dbgsym;

use dbgsym::TestError;

use dbgsym::{build_fixture, build_id, debuglink, have, sections, split, symbolize, text};

#[path = "support/executable.rs"]
mod executable;

/// Assert everything a finished split must be, on any architecture: the
/// shipped binary has no symbols or DWARF, keeps its build ID, and links to
/// `debug` by name; `debug` has the line table and symbols under the same ID.
fn assert_split_is_complete(bin: &Path, debug: &Path) -> Result<(), TestError> {
    let bin_secs = sections(bin)?;
    assert!(
        !bin_secs.iter().any(|s| s == ".symtab"),
        "the shipped binary still carries .symtab: {bin_secs:?}"
    );
    // `.debug_gdb_scripts` is allocated (rustc's pointer to gdb's pretty
    // printers), so it is part of the loaded image and the linker's own strip
    // always left it in. Every other `.debug_*` section is DWARF.
    assert!(
        !bin_secs
            .iter()
            .any(|s| s.starts_with(".debug_") && s != ".debug_gdb_scripts"),
        "the shipped binary still carries DWARF: {bin_secs:?}"
    );
    assert!(
        bin_secs.iter().any(|s| s == ".note.gnu.build-id"),
        "the shipped binary lost .note.gnu.build-id, so nothing can match it to \
         its symbol file: {bin_secs:?}"
    );
    assert!(
        bin_secs.iter().any(|s| s == ".gnu_debuglink"),
        "the shipped binary has no .gnu_debuglink: {bin_secs:?}"
    );
    let name = debug
        .file_name()
        .ok_or("debug.file_name() was None")?
        .to_string_lossy()
        .into_owned();
    let link = debuglink(bin)?;
    assert!(
        link.contains(&name),
        ".gnu_debuglink must name {name}, the file published beside the \
         binary; readelf shows:\n{link}"
    );

    let dbg_secs = sections(debug)?;
    assert!(
        dbg_secs.iter().any(|s| s == ".debug_line"),
        "the symbol file carries no line table: {dbg_secs:?}"
    );
    assert!(
        dbg_secs.iter().any(|s| s == ".symtab"),
        "the symbol file carries no symbol table: {dbg_secs:?}"
    );

    let bin_id = build_id(bin)?.ok_or("stripped binary has a build ID")?;
    let dbg_id = build_id(debug)?.ok_or("symbol file has a build ID")?;
    assert!(bin_id.len() >= 32, "implausible build ID {bin_id:?}");
    assert_eq!(
        bin_id, dbg_id,
        "the symbol file's build ID must equal the shipped binary's"
    );
    Ok(())
}

/// (a) On the host architecture: the shipped binary loses its symbols but
/// keeps its build ID and gains a debug link, and the symbol file carries the
/// symbols under the same build ID.
#[test]
fn the_split_ships_a_stripped_binary_and_a_matching_symbol_file() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let bin = build_fixture(dir.path(), None, true)?.ok_or("host fixture")?;
    let before = build_id(&bin)?.ok_or("the linker wrote a build ID")?;
    let out = split(&bin, &dir.path().join("sipnab-dev-host"))?;
    assert!(out.status.success(), "split failed:\n{}", text(&out));
    let debug = dir.path().join("sipnab-dev-host.debug");
    assert!(
        debug.is_file(),
        "no {} after the split:\n{}",
        debug.display(),
        text(&out)
    );
    assert_split_is_complete(&bin, &debug)?;
    assert_eq!(
        build_id(&bin)?.as_deref(),
        Some(before.as_str()),
        "stripping must not change the build ID"
    );
    Ok(())
}

/// (a) Across architectures. The release splits aarch64 binaries on an x86_64
/// runner, which is exactly where the host `strip` the workflow used to call
/// failed on every release without anyone seeing it. Driven here with the
/// other 64-bit architecture's binary on whichever host runs the suite.
#[test]
fn the_split_handles_a_foreign_architecture() -> Result<(), TestError> {
    let (triple, linker) = if dbgsym::host_triple()?.starts_with("aarch64-") {
        ("x86_64-unknown-linux-gnu", "x86_64-linux-gnu-gcc")
    } else {
        ("aarch64-unknown-linux-gnu", "aarch64-linux-gnu-gcc")
    };
    if !have(linker) {
        eprintln!("SKIPPED: no {linker} on this host to link a {triple} fixture");
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let Some(bin) = build_fixture(dir.path(), Some((triple, linker)), true)? else {
        return Ok(());
    };
    let out = split(&bin, &dir.path().join(format!("sipnab-dev-{triple}")))?;
    assert!(out.status.success(), "split failed:\n{}", text(&out));
    assert_split_is_complete(&bin, &dir.path().join(format!("sipnab-dev-{triple}.debug")))?;
    Ok(())
}

/// A binary with no build ID cannot be matched to anything, so the split
/// refuses it instead of publishing a symbol file nobody can pair.
#[test]
fn the_split_refuses_a_binary_without_a_build_id() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let bin = build_fixture(dir.path(), None, false)?.ok_or("host fixture")?;
    assert_eq!(
        build_id(&bin)?,
        None,
        "fixture was meant to have no build ID"
    );
    let out = split(&bin, &dir.path().join("x"))?;
    assert!(
        !out.status.success(),
        "split accepted a binary with no build ID:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("build ID"),
        "the refusal must name the missing build ID:\n{}",
        text(&out)
    );
    Ok(())
}

/// A binary that is already stripped has nothing to split, and a symbol file
/// made from it would be empty. That is what a build that still strips at link
/// time produces, so it must stop the release.
#[test]
fn the_split_refuses_a_binary_with_no_line_tables() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let bin = build_fixture(dir.path(), None, true)?.ok_or("host fixture")?;
    let first = split(&bin, &dir.path().join("first"))?;
    assert!(
        first.status.success(),
        "first split failed:\n{}",
        text(&first)
    );
    let again = split(&bin, &dir.path().join("second"))?;
    assert!(
        !again.status.success(),
        "split accepted an already-stripped binary:\n{}",
        text(&again)
    );
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("line table"),
        "the refusal must say the line tables are missing:\n{}",
        text(&again)
    );
    Ok(())
}

/// (b) An address inside a known function of the STRIPPED binary symbolizes,
/// against the symbol file, to that function and its source file.
///
/// The address is the one the running binary reports for itself (function
/// address minus load base), which is what a crash report records. A copy of
/// the stripped binary with no symbol file beside it must NOT resolve it, so
/// the answers can only have come from the `.debug` file.
#[test]
fn an_address_from_the_stripped_binary_symbolizes_against_the_symbol_file() -> Result<(), TestError>
{
    if !have("llvm-symbolizer") && !have("addr2line") {
        eprintln!("SKIPPED: neither llvm-symbolizer nor addr2line is installed");
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let bin = build_fixture(dir.path(), None, true)?.ok_or("host fixture")?;
    let out = split(&bin, &dir.path().join("sipnab-dev-host"))?;
    assert!(out.status.success(), "split failed:\n{}", text(&out));
    let debug = dir.path().join("sipnab-dev-host.debug");

    let run = std::process::Command::new(&bin).output()?;
    assert!(run.status.success(), "fixture failed:\n{}", text(&run));
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let offset = stdout
        .lines()
        .find_map(|l| l.strip_prefix("offset="))
        .ok_or_else(|| format!("fixture printed no offset:\n{stdout}"))?
        .to_string();

    let answer = symbolize(&debug, &offset)?.ok_or("a symbolizer is installed")?;
    assert!(
        answer.contains("dbgsym_known_function"),
        "the symbolizer did not name the function at {offset} from the symbol file:\n{answer}"
    );
    assert!(
        answer.contains("fixture.rs"),
        "the symbolizer did not name the source file for {offset}:\n{answer}"
    );

    // Beside its symbol file, the stripped binary resolves too: the
    // symbolizer follows `.gnu_debuglink` to the file of that name in the same
    // directory. That is the "put the .debug next to the binary" path the
    // troubleshooting page gives users.
    let beside = symbolize(&bin, &offset)?.ok_or("a symbolizer is installed")?;
    assert!(
        beside.contains("dbgsym_known_function"),
        "the stripped binary did not find its symbol file through \
         .gnu_debuglink:\n{beside}"
    );

    // Alone, it must NOT resolve, or nothing above proves the symbol file did
    // anything.
    let alone_dir = dir.path().join("alone");
    std::fs::create_dir(&alone_dir)?;
    let alone = alone_dir.join("fixture");
    std::fs::copy(&bin, &alone)?;
    let bare = symbolize(&alone, &offset)?.ok_or("a symbolizer is installed")?;
    assert!(
        !bare.contains("dbgsym_known_function"),
        "the stripped binary resolved {offset} with no symbol file beside it, \
         so this test cannot tell whether the symbol file did anything:\n{bare}"
    );
    Ok(())
}

/// Stand-ins for the Xcode tools the macOS split uses, so the macOS branch of
/// the script runs on this host. They keep state in files: a binary's UUID
/// in `<bin>.uuid`, a bundle's in `<bundle>/uuid`, a strip in
/// `<bin>.stripped`. Every call is logged to `$TOOL_LOG`. `DSYM_UUID`
/// overrides the UUID dsymutil writes, and `KEEP_DEBUG_MAP` makes `nm` report
/// a debug map after the strip and `STRIPPED_AT_LINK` reports none at all,
/// to drive the refusals. `LARGE_OUTPUT` makes `nm` and `dwarfdump` print
/// the thousands of lines a real binary produces AFTER the line the script
/// looks for.
const XCODE_STANDINS: &[(&str, &str)] = &[
    (
        "dsymutil",
        "echo \"dsymutil $*\" >> \"$TOOL_LOG\"\nbin=\"$1\"; out=\"$3\"\n\
         mkdir -p \"$out/Contents/Resources/DWARF\"\n\
         echo \"${DSYM_UUID:-$(cat \"$bin.uuid\")}\" > \"$out/uuid\"\n",
    ),
    (
        "dwarfdump",
        "echo \"dwarfdump $*\" >> \"$TOOL_LOG\"\ncase \"$1\" in\n\
         --uuid) if [ -d \"$2\" ]; then u=$(cat \"$2/uuid\"); else u=$(cat \"$2.uuid\"); fi\n\
         echo \"UUID: $u (arm64) $2\" ;;\n\
         --debug-line) echo 'debug_line[0x00000000]'\n\
         if [ -n \"${LARGE_OUTPUT:-}\" ]; then i=0; while [ $i -lt 20000 ]; do echo \"0x$i 12 3 0 0 0 is_stmt\"; i=$((i+1)); done; fi ;;\nesac\n",
    ),
    (
        "ditto",
        "echo \"ditto $*\" >> \"$TOOL_LOG\"\nfor a; do last=$a; done\necho zip > \"$last\"\n",
    ),
    (
        "strip",
        "echo \"strip $*\" >> \"$TOOL_LOG\"\nfor a; do last=$a; done\n: > \"$last.stripped\"\n",
    ),
    (
        "nm",
        "echo \"nm $*\" >> \"$TOOL_LOG\"\nfor a; do last=$a; done\n\
         if [ -n \"${STRIPPED_AT_LINK:-}\" ]; then exit 0; fi\n\
         if [ ! -e \"$last.stripped\" ] || [ -n \"${KEEP_DEBUG_MAP:-}\" ]; then\n\
         echo '0000000000000000 - 00 0000    OSO /tmp/sipnab.o'\n\
         if [ -n \"${LARGE_OUTPUT:-}\" ]; then i=0; while [ $i -lt 20000 ]; do echo \"0000000100000000 - 01 0000    FUN _sym$i\"; i=$((i+1)); done; fi\nfi\n",
    ),
    (
        "codesign",
        "echo \"codesign $*\" >> \"$TOOL_LOG\"\nexit 0\n",
    ),
];

/// Run the script's macOS branch on a stand-in Mach-O binary with the
/// stand-in tools first on PATH. Returns the output, the tool log, and the
/// temp dir holding `sipnab` and `dist/`.
fn run_macos_split(
    env: &[(&str, &str)],
) -> Result<(std::process::Output, String, tempfile::TempDir), TestError> {
    let dir = tempfile::tempdir()?;
    let w = dir.path();
    let tools = w.join("tools");
    std::fs::create_dir_all(&tools)?;
    for (name, body) in XCODE_STANDINS {
        let p = tools.join(name);
        executable::write_executable(&p, &format!("#!/bin/sh\n{body}"))?;
    }
    let bin = w.join("sipnab");
    // MH_MAGIC_64, little-endian: the script picks its branch by magic.
    std::fs::write(&bin, [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0])?;
    std::fs::write(w.join("sipnab.uuid"), "AAAA-1111")?;
    let log = w.join("tools.log");
    let path = format!(
        "{}:{}",
        tools.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(dbgsym::script())
        .arg(&bin)
        .arg(w.join("dist/sipnab-dev-aarch64-apple-darwin"))
        .env("PATH", path)
        .env("TOOL_LOG", &log);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output()?;
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    Ok((out, log, dir))
}

/// macOS: the script makes the `.dSYM` itself with `dsymutil` from the
/// unstripped binary, checks its UUID is the binary's, zips it, strips the
/// binary in place, and checks the stripped binary kept its UUID and lost its
/// debug map. It no longer depends on rustc having left a `.dSYM` behind,
/// which rustc did not do on the first CI run.
#[test]
fn the_macos_split_makes_the_dsym_itself_then_strips() -> Result<(), TestError> {
    let (out, log, dir) = run_macos_split(&[])?;
    assert!(
        out.status.success(),
        "macOS split failed:\n{}\nlog:\n{log}",
        text(&out)
    );
    let bin = dir.path().join("sipnab");
    assert!(
        log.contains(&format!(
            "dsymutil {} -o {}.dSYM",
            bin.display(),
            bin.display()
        )),
        "the script must run dsymutil on the binary itself:\n{log}"
    );
    assert!(
        dir.path()
            .join("dist/sipnab-dev-aarch64-apple-darwin.dSYM.zip")
            .is_file(),
        "no .dSYM.zip:\n{log}"
    );
    assert!(
        dir.path().join("sipnab.stripped").exists(),
        "the binary was not stripped:\n{log}"
    );
    let dsym_at = log
        .find("dsymutil")
        .ok_or("log.find(\"dsymutil\") was None")?;
    let strip_at = log.find("strip ").ok_or("strip ran")?;
    assert!(
        dsym_at < strip_at,
        "dsymutil must read the binary before the strip:\n{log}"
    );
    assert!(log.contains("ditto"), "the bundle was not zipped:\n{log}");
    Ok(())
}

/// A `.dSYM` whose UUID is not the binary's cannot symbolize its reports.
#[test]
fn the_macos_split_refuses_a_dsym_with_another_uuid() -> Result<(), TestError> {
    let (out, log, _dir) = run_macos_split(&[("DSYM_UUID", "BBBB-2222")])?;
    assert!(
        !out.status.success(),
        "accepted a mismatched .dSYM:\nlog:\n{log}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("UUID mismatch"),
        "the refusal must name the mismatch:\n{}",
        text(&out)
    );
    Ok(())
}

/// A binary that still carries its debug map after the strip is not the
/// stripped binary the release promises.
#[test]
fn the_macos_split_refuses_a_binary_that_keeps_its_debug_map() -> Result<(), TestError> {
    let (out, log, _dir) = run_macos_split(&[("KEEP_DEBUG_MAP", "1")])?;
    assert!(
        !out.status.success(),
        "accepted an unstripped binary:\nlog:\n{log}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("debug map"),
        "the refusal must name the debug map:\n{}",
        text(&out)
    );
    Ok(())
}

/// A binary stripped at link time has no debug map, so there is nothing for
/// dsymutil to read. That is what a build without the split flags produces,
/// and it must stop the release rather than publish an empty bundle.
#[test]
fn the_macos_split_refuses_a_binary_stripped_at_link_time() -> Result<(), TestError> {
    let (out, log, _dir) = run_macos_split(&[("STRIPPED_AT_LINK", "1")])?;
    assert!(
        !out.status.success(),
        "accepted a link-stripped binary:\nlog:\n{log}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no debug map"),
        "the refusal must say there is no debug map:\n{}",
        text(&out)
    );
    assert!(
        !log.contains("dsymutil"),
        "dsymutil must not run on it:\n{log}"
    );
    Ok(())
}

/// Build a one-file cargo project whose `[profile.release]` strips at link
/// time the way sipnab's does, with `RUSTFLAGS` and extra cargo args, and
/// return its release binary.
fn cargo_build_stripping_project(
    dir: &Path,
    rustflags: &str,
    extra: &[&str],
) -> Result<std::path::PathBuf, TestError> {
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"dbgsym-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [workspace]\n\n[profile.release]\nstrip = true\ndebug = \"line-tables-only\"\n\
         panic = \"abort\"\n",
    )?;
    std::fs::write(
        dir.join("src/main.rs"),
        "fn main() { println!(\"probe\"); }\n",
    )?;
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args(["build", "--release", "--quiet"])
        .args(extra)
        .current_dir(dir)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .env("RUSTFLAGS", rustflags)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()?;
    assert!(out.status.success(), "probe build failed:\n{}", text(&out));
    Ok(dir.join("target/release/dbgsym-probe"))
}

/// What the workflows do, on a real cargo build: with `RUSTFLAGS=-Dwarnings`
/// already set (as ci.yml sets it), appending `--rustflags` keeps the line
/// tables through a profile that strips, and the split succeeds. The control
/// is what the first CI run did: the same flags only as `--config` lose to
/// the ambient RUSTFLAGS, and the binary comes out stripped.
#[test]
fn the_emitted_flags_survive_an_ambient_rustflags() -> Result<(), TestError> {
    let host = dbgsym::host_triple()?;
    let flags = String::from_utf8(
        std::process::Command::new("bash")
            .arg(dbgsym::script())
            .args(["--rustflags", &host])
            .output()?
            .stdout,
    )?;
    let config = String::from_utf8(
        std::process::Command::new("bash")
            .arg(dbgsym::script())
            .args(["--cargo-config", &host])
            .output()?
            .stdout,
    )?;

    let dir = tempfile::tempdir()?;
    let appended = format!("-Dwarnings {}", flags.trim());
    let bin = cargo_build_stripping_project(dir.path(), &appended, &[])?;
    assert!(
        sections(&bin)?.iter().any(|s| s == ".debug_line"),
        "RUSTFLAGS=\"-Dwarnings {}\" still stripped the line tables",
        flags.trim()
    );
    let out = split(&bin, &dir.path().join("probe"))?;
    assert!(out.status.success(), "split failed:\n{}", text(&out));

    let control = tempfile::tempdir()?;
    let lost =
        cargo_build_stripping_project(control.path(), "-Dwarnings", &["--config", config.trim()])?;
    assert!(
        !sections(&lost)?.iter().any(|s| s == ".debug_line"),
        "--config alone survived an ambient RUSTFLAGS, so this test no longer \
         shows why the workflows must append to RUSTFLAGS"
    );
    Ok(())
}

/// A real binary's `nm -ap` prints thousands of lines, and the debug map's
/// first `OSO` entry comes early. `grep -q` exits at that match, the tool
/// writing the rest dies of SIGPIPE, and under `set -o pipefail` the whole
/// pipeline reports failure: the script called a binary WITH a debug map
/// "stripped at link time". That is what failed CI's macOS leg twice, while
/// a one-line stand-in could never show it.
#[test]
fn the_macos_split_reads_a_large_debug_map_and_line_table() -> Result<(), TestError> {
    let (out, log, _dir) = run_macos_split(&[("LARGE_OUTPUT", "1")])?;
    assert!(
        out.status.success(),
        "the split refused a binary whose tools print a lot:\n{}\nlog:\n{log}",
        text(&out)
    );
    Ok(())
}

/// No `cmd | grep -q` in the script at all, not only in the two checks the
/// large-output test drives: `grep -q` exits at its first match, the writer
/// dies of SIGPIPE, and the script's `set -o pipefail` turns a found match
/// into a failure. Which commands print enough to lose that race depends on
/// the binary, so the pattern is refused everywhere.
#[test]
fn the_script_never_pipes_into_grep_q() -> Result<(), TestError> {
    let text = std::fs::read_to_string(dbgsym::script())?;
    let offenders: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with('#') && l.contains("grep -q"))
        .map(|(i, l)| (i + 1, l.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "split-debuginfo.sh pipes into `grep -q`, which under pipefail reports \
         a match as a failure when the writer is still printing: {offenders:?}"
    );
    Ok(())
}
