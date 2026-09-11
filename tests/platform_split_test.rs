// SPDX-License-Identifier: MIT OR Apache-2.0

//! A Linux-only libc symbol must sit inside a Linux `cfg`.
//!
//! # The failure this exists for
//!
//! `tests/sandbox_test.rs` shipped calling `libc::prctl` and naming
//! `libc::PR_SET_NO_NEW_PRIVS` with no `target_os` predicate anywhere in the
//! file. Neither exists in `libc` on macOS. The file is gated on `unix`, macOS
//! is unix, and CI's `Check (macos-latest)` failed to compile — after the
//! commit was pushed.
//!
//! **`scripts/check-non-linux.sh` should have caught it and structurally could
//! not.** That script rewrites every `target_os = "linux"` predicate to a
//! sentinel and compiles the inverted tree, which is exactly right for finding
//! a missing non-Linux arm. It is blind to code with no predicate at all:
//! there is nothing to invert, the file compiles unchanged on a Linux host,
//! and `libc::prctl` resolves because the real compilation target is still
//! Linux. A gate that inverts a split cannot see a split nobody wrote.
//!
//! So this reads the source instead. The rule is narrow on purpose: a curated
//! list of symbols that genuinely do not exist off Linux, each occurrence
//! required to sit under a `target_os = "linux"` cfg — on the file, or on the
//! item that contains it.

use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// `libc` items that do not exist on macOS.
///
/// Curated rather than pattern-matched, and each entry is a symbol whose
/// absence is a compile error rather than a behavior difference. `libc::open`
/// and `libc::close` are deliberately absent: they exist everywhere, and a
/// list that grew to "anything unixy" would report the whole tree and be
/// switched off within a week.
const LINUX_ONLY: [&str; 9] = [
    "libc::prctl",
    "libc::PR_SET_",
    "libc::PR_GET_",
    "libc::SYS_",
    "libc::gettid",
    "libc::memfd_create",
    // The two that broke the macOS build on 2026-09-10, in a unit test
    // comparing this crate's `SockFilter` against the kernel's. The types are
    // classic-BPF, which macOS's libc does not carry at all. Adding them here
    // is the cheap half of the fix; the structural half is phase 2 of
    // `scripts/check-non-linux.sh`, which compiles against a real non-Linux
    // libc and needs no list to maintain.
    "libc::sock_filter",
    "libc::sock_fprog",
    // Not libc: `std` carries a Linux-only namespace of its own, and it fails
    // the same way. `std::os::unix` is fine everywhere and is deliberately not
    // here; `std::os::linux` is the one that does not exist on macOS.
    "std::os::linux::",
];

/// Whether `line` gates on Linux.
fn is_linux_cfg(line: &str) -> bool {
    let t = line.trim();
    (t.starts_with("#[cfg") || t.starts_with("#![cfg") || t.starts_with("#[cfg_attr"))
        && t.contains("target_os = \"linux\"")
        && !t.contains("not(target_os = \"linux\")")
}

/// Whether the `mod` declaration that pulls `path` into the crate is gated on
/// Linux.
///
/// The idiom no single-file scan can see, and this gate's own first false
/// positive. `src/capture/uprobe/perf.rs` names `libc::SYS_perf_event_open`
/// with no cfg anywhere in the file, and it is correct: `src/capture/mod.rs`
/// carries `#[cfg(target_os = "linux")] pub mod uprobe;`, so the subtree never
/// compiles off Linux. Reporting it would have taught a reader to switch this
/// gate off, which is how a gate dies.
fn module_is_linux_gated(path: &Path) -> bool {
    let Some(dir) = path.parent() else {
        return false;
    };
    let Some(stem) = path.file_stem().map(|s| s.to_string_lossy().into_owned()) else {
        return false;
    };
    // `foo/mod.rs` is declared as `mod foo;` one directory up.
    let (decl_dir, name) = if stem == "mod" {
        match (dir.parent(), dir.file_name()) {
            (Some(p), Some(n)) => (p.to_path_buf(), n.to_string_lossy().into_owned()),
            _ => return false,
        }
    } else {
        (dir.to_path_buf(), stem)
    };
    for candidate in [
        decl_dir.join("mod.rs"),
        decl_dir.join("lib.rs"),
        decl_dir.with_extension("rs"),
    ] {
        let Ok(src) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        if declaration_is_linux_gated(&src, &name) {
            return true;
        }
        // The declaring module may itself be gated further up.
        if candidate.file_name().is_some_and(|n| n == "mod.rs") && module_is_linux_gated(&candidate)
        {
            return true;
        }
    }
    false
}

/// Whether `source` declares `mod name;` under a Linux cfg.
fn declaration_is_linux_gated(source: &str, name: &str) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let wanted = [format!("mod {name};"), format!("pub mod {name};")];
    for (i, line) in lines.iter().enumerate() {
        if !wanted.iter().any(|w| line.trim() == w) {
            continue;
        }
        let mut a = i;
        while a > 0 {
            a -= 1;
            let t = lines[a].trim();
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            if t.starts_with("#[") {
                if is_linux_cfg(lines[a]) {
                    return true;
                }
                continue;
            }
            break;
        }
    }
    false
}

/// Every ungated use of a Linux-only symbol in `source`, as `(line number,
/// symbol)`.
///
/// Pure, so the predicate has tests of its own rather than only a verdict
/// about the tree. A gate whose rule can only be exercised by the tree it
/// guards is one nobody can show discriminates.
fn ungated_uses(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    // A file-level `#![cfg(... linux ...)]` covers everything in it.
    if lines
        .iter()
        .take_while(|l| {
            let t = l.trim();
            t.is_empty() || t.starts_with("//") || t.starts_with("#!")
        })
        .any(|l| is_linux_cfg(l))
    {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        // A comment naming a symbol is documentation, not a call.
        if line.trim_start().starts_with("//") {
            continue;
        }
        let Some(sym) = LINUX_ONLY.iter().find(|s| line.contains(**s)) else {
            continue;
        };
        // Walk OUTWARD through the blocks that enclose this line, checking
        // each one's attributes, and stop at the file. Not "any Linux cfg
        // above": the first version of this gate did that, and a
        // `#[cfg(target_os = "linux")] use ...;` near the top of a file made
        // every use below it read as gated. Mutation caught it — un-gating the
        // very function whose absence broke CI did not make this fire.
        //
        // Going up, each `}` is a block that closed below us and whose
        // contents are not ours; each `{` either reopens one of those or is
        // the brace that opens OUR block, which makes the line it sits on the
        // header whose attributes govern us.
        let mut gated = false;
        let mut closed = 0usize;
        let mut up = i;
        while up > 0 {
            up -= 1;
            let t = lines[up].trim();
            if t.starts_with("//") {
                continue;
            }
            let mut header = false;
            for c in t.chars().rev() {
                match c {
                    '}' => closed += 1,
                    '{' => {
                        if closed == 0 {
                            header = true;
                        } else {
                            closed -= 1;
                        }
                    }
                    _ => {}
                }
            }
            if !header {
                continue;
            }
            // The contiguous attribute block above this header.
            let mut a = up;
            while a > 0 {
                a -= 1;
                let at = lines[a].trim();
                if at.is_empty() || at.starts_with("//") {
                    continue;
                }
                if at.starts_with("#[") {
                    if is_linux_cfg(lines[a]) {
                        gated = true;
                    }
                    continue;
                }
                break;
            }
            if gated {
                break;
            }
        }
        if !gated {
            out.push((i + 1, (*sym).to_string()));
        }
    }
    out
}

/// A Linux-only symbol with no cfg anywhere is reported.
#[test]
fn a_linux_only_symbol_outside_a_linux_cfg_is_reported() {
    let src = "use libc;\n\nfn helper() -> bool {\n    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1) == 0 }\n}\n";
    let found = ungated_uses(src);
    assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
    assert_eq!(found[0].0, 4, "the line number must name the use");
}

/// The same symbol under an item-level cfg is not.
///
/// The negative half, and the one that decides whether this gate is usable: a
/// rule that reported correctly gated code would be turned off the first week,
/// and the tree is full of correctly gated Linux code.
#[test]
fn a_linux_only_symbol_inside_a_linux_cfg_is_not_reported() {
    let item_level = "use libc;\n\n/// Doc.\n#[cfg(target_os = \"linux\")]\nfn helper() -> bool {\n    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1) == 0 }\n}\n";
    assert!(
        ungated_uses(item_level).is_empty(),
        "an item-level cfg must satisfy the rule: {:?}",
        ungated_uses(item_level)
    );

    let file_level = "// SPDX\n#![cfg(target_os = \"linux\")]\n\nfn helper() {\n    unsafe { libc::prctl(1, 1) };\n}\n";
    assert!(
        ungated_uses(file_level).is_empty(),
        "a file-level cfg must satisfy it too: {:?}",
        ungated_uses(file_level)
    );

    // And a NEGATED cfg does not count: `not(target_os = "linux")` is the
    // arm that runs where the symbol does not exist.
    let negated = "use libc;\n\n#[cfg(not(target_os = \"linux\"))]\nfn helper() {\n    unsafe { libc::prctl(1, 1) };\n}\n";
    assert_eq!(
        ungated_uses(negated).len(),
        1,
        "a not(linux) arm using a Linux-only symbol is the bug, not the fix"
    );
}

/// The rule reaches past `libc`, because the failure does.
///
/// `std::os::linux` does not exist on macOS either, and a use of it fails
/// exactly as `libc::prctl` did: at compile time, on a platform the developer
/// is not on. A list that stopped at one crate would have caught the failure
/// that happened and none of its siblings.
///
/// `std::os::unix` is deliberately absent: it exists on macOS, and a rule
/// reporting it would fire on most of this tree and be switched off.
#[test]
fn the_rule_reaches_past_libc_to_the_linux_only_std_namespace() {
    assert!(
        LINUX_ONLY.contains(&"std::os::linux::"),
        "the list stops at libc, so a Linux-only std path fails on macOS unseen"
    );
    assert!(
        !LINUX_ONLY.iter().any(|s| s.contains("std::os::unix")),
        "std::os::unix exists on macOS; listing it would report most of the tree"
    );

    let ungated = "use std::os::linux::fs::MetadataExt;\n\nfn ino() -> u64 {\n    std::os::linux::raw::ino_t::default()\n}\n";
    assert!(
        !ungated_uses(ungated).is_empty(),
        "an ungated std::os::linux use must be reported"
    );

    let gated = "#[cfg(target_os = \"linux\")]\nfn ino() -> u64 {\n    std::os::linux::raw::ino_t::default()\n}\n";
    assert!(
        ungated_uses(gated).is_empty(),
        "and a gated one must not: {:?}",
        ungated_uses(gated)
    );
}

/// The inverted-tree check still compiles TEST targets.
///
/// `--all-targets` is the flag that lets `scripts/check-non-linux.sh` see a
/// `#[cfg(test)]` module or a `tests/` binary at all. Without it the script
/// still runs, still reports OK, and inspects only the library — which is not
/// where the break that motivated this file lived. A flag dropped for speed
/// would restore the blind spot silently.
#[test]
fn the_inverted_tree_check_still_compiles_test_targets() {
    let script = std::fs::read_to_string(repo().join("scripts/check-non-linux.sh"))
        .expect("read scripts/check-non-linux.sh");
    let compiles: Vec<&str> = script
        .lines()
        .map(str::trim)
        // `cargo clippy --version` is an availability probe, not a compile of
        // the inverted tree, and demanding a target selector from it would
        // make this gate fail on a script that is correct.
        .filter(|l| !l.starts_with('#') && l.contains("cargo clippy") && !l.contains("--version"))
        .collect();
    assert!(
        !compiles.is_empty(),
        "the script no longer compiles the inverted tree at all"
    );
    for line in &compiles {
        assert!(
            line.contains("--all-targets"),
            "this invocation skips test targets, where the break that motivated \
             this file lived: {line}"
        );
    }
}

/// And the script says what it cannot see, beside the thing that can.
///
/// The blind spot is not a bug in that script: inverting a predicate is the
/// right technique for a missing arm, and it cannot be extended to code
/// carrying no predicate at all. What would be a bug is leaving the next
/// reader to discover it the way this one did — from a red CI run after a
/// push. A tool with a known limit states it where somebody is standing when
/// they rely on it.
#[test]
fn the_inverted_tree_check_records_the_class_it_cannot_see() {
    let script = std::fs::read_to_string(repo().join("scripts/check-non-linux.sh"))
        .expect("read scripts/check-non-linux.sh");
    assert!(
        script.contains("platform_split_test"),
        "the script does not name the gate that covers what it cannot: a reader \
         who trusts it alone repeats the failure it did not catch"
    );
    assert!(
        script.contains("no predicate"),
        "the script does not say WHICH class it is blind to, so the pointer \
         above reads as a suggestion rather than as a division of work"
    );
}

/// No file in the tree uses one outside a Linux cfg.
///
/// The verdict, with its own anti-vacuity check: this tree calls `prctl` and
/// names `SYS_` constants in several places, so a scan finding no occurrences
/// at all has stopped matching rather than found a clean tree.
#[test]
fn no_source_file_uses_a_linux_only_symbol_outside_a_linux_cfg() {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![repo().join("src"), repo().join("tests")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    assert!(files.len() > 50, "only {} sources found", files.len());

    let mut occurrences = 0usize;
    let mut problems = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        // This file names every symbol in a constant; it calls none.
        if f.file_name().is_some_and(|n| n == "platform_split_test.rs") {
            continue;
        }
        occurrences += LINUX_ONLY.iter().filter(|s| src.contains(**s)).count();
        if module_is_linux_gated(f) {
            continue;
        }
        for (line, sym) in ungated_uses(&src) {
            problems.push(format!(
                "{}:{line}: {sym} is Linux-only and sits under no `target_os = \"linux\"` cfg",
                f.strip_prefix(repo()).unwrap_or(f).display()
            ));
        }
    }
    assert!(
        occurrences > 0,
        "no file in this tree names a Linux-only symbol, which cannot be true \
         while src/privilege.rs calls prctl — the scan has stopped matching"
    );
    assert!(
        problems.is_empty(),
        "these uses would not compile on macOS, and the inverted-tree gate \
         cannot see them because there is no split to invert:\n  {}",
        problems.join("\n  ")
    );
}

// ── The three owed for breaking the macOS build on 2026-09-10 ───────────────

/// Every symbol that has actually broken a non-Linux build is on the list.
///
/// A regression list, not a wish list. Each entry cost a red main, and the
/// scanner's [`LINUX_ONLY`] is a hand-maintained set — exactly the kind that
/// looks complete right up until the next item is missing from it. Pinning the
/// ones that have already burned us means a rewrite of that array cannot
/// quietly drop one.
///
/// `libc::prctl` broke it first, in `tests/sandbox_test.rs`, which had no
/// `target_os` predicate at all. `libc::sock_filter` broke it again in a unit
/// test comparing this crate's `SockFilter` against the kernel's — the type is
/// classic BPF, which macOS's libc does not carry.
#[test]
fn the_scanner_knows_every_symbol_that_has_broken_this_build() {
    /// `(symbol, where it broke)`, appended to and never trimmed.
    const HAS_BROKEN_THE_BUILD: &[(&str, &str)] = &[
        (
            "libc::prctl",
            "tests/sandbox_test.rs, the Landlock child roles",
        ),
        (
            "libc::sock_filter",
            "src/seccomp.rs, the instruction-layout unit test",
        ),
        (
            "libc::sock_fprog",
            "src/seccomp.rs, beside sock_filter and absent for the same reason",
        ),
    ];
    for (sym, where_) in HAS_BROKEN_THE_BUILD {
        assert!(
            LINUX_ONLY.contains(sym),
            "{sym} has broken a non-Linux build once already ({where_}) and is \
             no longer in LINUX_ONLY, so it can break it again unnoticed"
        );
    }
}

/// The scan reaches inside `#[cfg(test)] mod tests`, which is where it broke.
///
/// Not a formality: the break was in a unit test, not in production code, and
/// a scanner that skipped test modules would have agreed with the tree while
/// macOS refused to compile it. `#[cfg(test)]` is not a platform predicate, so
/// the outward walk must not mistake it for one.
#[test]
fn a_linux_only_symbol_inside_a_test_module_is_still_reported() {
    // Built from parts, and the continuation deliberately does not START with
    // the marker: `fixture_isolation_test` counts any trimmed line beginning
    // `#[test]` as a real test, and a fixture laid out that way arms it. That
    // is instance six of a defect that file exists to pin, and reproducing it
    // here would have made this file report one more test than it has.
    let src = format!(
        "use libc;\n\n#[cfg(test)]\nmod tests {{\n    {}\n    fn t() {{\n{}\n    }}\n}}\n",
        "#[test]", "        assert_eq!(std::mem::size_of::<libc::sock_filter>(), 8);"
    );
    let src = src.as_str();
    let found = ungated_uses(src);
    assert_eq!(
        found.len(),
        1,
        "a Linux-only type inside `#[cfg(test)] mod tests` was not reported: {found:?}"
    );
    assert!(found[0].1.contains("sock_filter"), "{found:?}");

    // And the same module with a real platform predicate is clean, so the gate
    // is reporting the platform split rather than the word `mod`.
    let gated = format!(
        "use libc;\n\n#[cfg(all(test, target_os = \"linux\"))]\nmod tests {{\n    {}\n    \
         fn t() {{\n{}\n    }}\n}}\n",
        "#[test]", "        assert_eq!(std::mem::size_of::<libc::sock_filter>(), 8);"
    );
    let gated = gated.as_str();
    assert!(
        ungated_uses(gated).is_empty(),
        "a Linux-gated test module was reported: {:?}",
        ungated_uses(gated)
    );
}

/// The inverted-tree script says it cannot see an ABSENT libc item.
///
/// The two checks are a pair and the pairing is written down, because the
/// reason one cannot see this class is not obvious: `scripts/check-non-linux.sh`
/// recompiles the tree with `target_os` swapped, which changes what `cfg`
/// selects but NOT which `libc` is linked. A type that simply does not exist
/// elsewhere still resolves there. Anyone reading that script has to be told
/// so, or they will assume it covers what it does not.
#[test]
fn the_inverted_tree_check_says_it_cannot_see_an_absent_libc_item() {
    let script = std::fs::read_to_string(repo().join("scripts/check-non-linux.sh"))
        .expect("scripts/check-non-linux.sh is in the tree");
    let lower = script.to_lowercase();
    assert!(
        lower.contains("platform_split_test"),
        "the script does not name the check that covers what it cannot see"
    );
    for phrase in ["libc", "absent"] {
        assert!(
            lower.contains(phrase),
            "the script's blind-spot note never says {phrase:?}, so a reader \
             cannot tell that an item missing from another platform's libc is \
             invisible to it"
        );
    }
}

// ── Three owed for a constant that broke the non-Linux build ────────────────

/// The non-Linux check is run before every push, not only in CI.
///
/// Owed for `EXIT_ENFORCED_AND_SURVIVED`, a constant used only by Linux-gated
/// roles and declared unconditionally. Off Linux it is dead code, and dead code
/// is an error in this tree. It was the second break of that exact shape in a
/// day, and both were caught by this check — which is only worth anything if
/// the check actually runs before the push rather than after it in CI.
#[test]
fn the_non_linux_check_runs_before_every_push() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push"))
        .expect(".githooks/pre-push is in the tree");
    assert!(
        hook.contains("check-non-linux.sh"),
        "the push gate does not run the non-Linux check, so a platform split \
         written twice reaches CI before anything says so"
    );
    let unconditional = hook
        .lines()
        .any(|l| l.contains("check-non-linux.sh") && !l.trim_start().starts_with('#'));
    assert!(
        unconditional,
        "the non-Linux check appears only in a comment in the push gate"
    );
}

/// Dead code off Linux is an error there, not a warning.
///
/// The property that turns an unused constant into a failed build. A warning
/// would have let `EXIT_ENFORCED_AND_SURVIVED` through, and the break would
/// have surfaced as a red main instead of a refused push.
#[test]
fn the_non_linux_check_treats_dead_code_as_an_error() {
    let script = std::fs::read_to_string(repo().join("scripts/check-non-linux.sh"))
        .expect("the script is in the tree");
    assert!(
        script.contains("-D warnings") || script.contains("RUSTFLAGS"),
        "the non-Linux check does not promote warnings to errors, so an item \
         that is merely unused off Linux passes it"
    );
}

/// The class this check exists for is written down where a reader will find it.
///
/// Two breaks in one day, both "an item used only by Linux-gated code, declared
/// unconditionally". The check's own notes have to name that shape, or the next
/// person reads a failure about an unused constant and deletes the constant
/// rather than gating it.
#[test]
fn the_non_linux_check_names_the_shape_that_keeps_breaking() {
    let script = std::fs::read_to_string(repo().join("scripts/check-non-linux.sh"))
        .expect("the script is in the tree");
    let lower = script.to_lowercase();
    assert!(
        lower.contains("written twice") || lower.contains("one platform split"),
        "the script never names the defect class it catches, so its failures \
         read as unrelated compile errors"
    );
    assert!(
        lower.contains("dead code") || lower.contains("never used") || lower.contains("unused"),
        "the script does not mention that an item unused off Linux is the shape \
         it most often reports"
    );
}
