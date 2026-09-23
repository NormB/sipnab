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

use dbgsym::{build_fixture, build_id, debuglink, have, sections, split, symbolize, text};

/// Assert everything a finished split must be, on any architecture: the
/// shipped binary has no symbols or DWARF, keeps its build ID, and links to
/// `debug` by name; `debug` has the line table and symbols under the same ID.
fn assert_split_is_complete(bin: &Path, debug: &Path) {
    let bin_secs = sections(bin);
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
    let name = debug.file_name().unwrap().to_string_lossy().into_owned();
    let link = debuglink(bin);
    assert!(
        link.contains(&name),
        ".gnu_debuglink must name {name}, the file published beside the \
         binary; readelf shows:\n{link}"
    );

    let dbg_secs = sections(debug);
    assert!(
        dbg_secs.iter().any(|s| s == ".debug_line"),
        "the symbol file carries no line table: {dbg_secs:?}"
    );
    assert!(
        dbg_secs.iter().any(|s| s == ".symtab"),
        "the symbol file carries no symbol table: {dbg_secs:?}"
    );

    let bin_id = build_id(bin).expect("stripped binary has a build ID");
    let dbg_id = build_id(debug).expect("symbol file has a build ID");
    assert!(bin_id.len() >= 32, "implausible build ID {bin_id:?}");
    assert_eq!(
        bin_id, dbg_id,
        "the symbol file's build ID must equal the shipped binary's"
    );
}

/// (a) On the host architecture: the shipped binary loses its symbols but
/// keeps its build ID and gains a debug link, and the symbol file carries the
/// symbols under the same build ID.
#[test]
fn the_split_ships_a_stripped_binary_and_a_matching_symbol_file() {
    let dir = tempfile::tempdir().unwrap();
    let bin = build_fixture(dir.path(), None, true).expect("host fixture");
    let before = build_id(&bin).expect("the linker wrote a build ID");
    let out = split(&bin, &dir.path().join("sipnab-dev-host"));
    assert!(out.status.success(), "split failed:\n{}", text(&out));
    let debug = dir.path().join("sipnab-dev-host.debug");
    assert!(
        debug.is_file(),
        "no {} after the split:\n{}",
        debug.display(),
        text(&out)
    );
    assert_split_is_complete(&bin, &debug);
    assert_eq!(
        build_id(&bin).as_deref(),
        Some(before.as_str()),
        "stripping must not change the build ID"
    );
}

/// (a) Across architectures. The release splits aarch64 binaries on an x86_64
/// runner, which is exactly where the host `strip` the workflow used to call
/// failed on every release without anyone seeing it. Driven here with the
/// other 64-bit architecture's binary on whichever host runs the suite.
#[test]
fn the_split_handles_a_foreign_architecture() {
    let (triple, linker) = if dbgsym::host_triple().starts_with("aarch64-") {
        ("x86_64-unknown-linux-gnu", "x86_64-linux-gnu-gcc")
    } else {
        ("aarch64-unknown-linux-gnu", "aarch64-linux-gnu-gcc")
    };
    if !have(linker) {
        eprintln!("SKIPPED: no {linker} on this host to link a {triple} fixture");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let Some(bin) = build_fixture(dir.path(), Some((triple, linker)), true) else {
        return;
    };
    let out = split(&bin, &dir.path().join(format!("sipnab-dev-{triple}")));
    assert!(out.status.success(), "split failed:\n{}", text(&out));
    assert_split_is_complete(&bin, &dir.path().join(format!("sipnab-dev-{triple}.debug")));
}

/// A binary with no build ID cannot be matched to anything, so the split
/// refuses it instead of publishing a symbol file nobody can pair.
#[test]
fn the_split_refuses_a_binary_without_a_build_id() {
    let dir = tempfile::tempdir().unwrap();
    let bin = build_fixture(dir.path(), None, false).expect("host fixture");
    assert_eq!(
        build_id(&bin),
        None,
        "fixture was meant to have no build ID"
    );
    let out = split(&bin, &dir.path().join("x"));
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
}

/// A binary that is already stripped has nothing to split, and a symbol file
/// made from it would be empty. That is what a build that still strips at link
/// time produces, so it must stop the release.
#[test]
fn the_split_refuses_a_binary_with_no_line_tables() {
    let dir = tempfile::tempdir().unwrap();
    let bin = build_fixture(dir.path(), None, true).expect("host fixture");
    let first = split(&bin, &dir.path().join("first"));
    assert!(
        first.status.success(),
        "first split failed:\n{}",
        text(&first)
    );
    let again = split(&bin, &dir.path().join("second"));
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
}

/// (b) An address inside a known function of the STRIPPED binary symbolizes,
/// against the symbol file, to that function and its source file.
///
/// The address is the one the running binary reports for itself (function
/// address minus load base), which is what a crash report records. A copy of
/// the stripped binary with no symbol file beside it must NOT resolve it, so
/// the answers can only have come from the `.debug` file.
#[test]
fn an_address_from_the_stripped_binary_symbolizes_against_the_symbol_file() {
    if !have("llvm-symbolizer") && !have("addr2line") {
        eprintln!("SKIPPED: neither llvm-symbolizer nor addr2line is installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let bin = build_fixture(dir.path(), None, true).expect("host fixture");
    let out = split(&bin, &dir.path().join("sipnab-dev-host"));
    assert!(out.status.success(), "split failed:\n{}", text(&out));
    let debug = dir.path().join("sipnab-dev-host.debug");

    let run = std::process::Command::new(&bin)
        .output()
        .expect("run the stripped fixture");
    assert!(run.status.success(), "fixture failed:\n{}", text(&run));
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let offset = stdout
        .lines()
        .find_map(|l| l.strip_prefix("offset="))
        .unwrap_or_else(|| panic!("fixture printed no offset:\n{stdout}"))
        .to_string();

    let answer = symbolize(&debug, &offset).expect("a symbolizer is installed");
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
    let beside = symbolize(&bin, &offset).expect("a symbolizer is installed");
    assert!(
        beside.contains("dbgsym_known_function"),
        "the stripped binary did not find its symbol file through \
         .gnu_debuglink:\n{beside}"
    );

    // Alone, it must NOT resolve, or nothing above proves the symbol file did
    // anything.
    let alone_dir = dir.path().join("alone");
    std::fs::create_dir(&alone_dir).unwrap();
    let alone = alone_dir.join("fixture");
    std::fs::copy(&bin, &alone).unwrap();
    let bare = symbolize(&alone, &offset).expect("a symbolizer is installed");
    assert!(
        !bare.contains("dbgsym_known_function"),
        "the stripped binary resolved {offset} with no symbol file beside it, \
         so this test cannot tell whether the symbol file did anything:\n{bare}"
    );
}
