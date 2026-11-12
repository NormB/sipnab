// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Self-tests for the shared test-support `normalize()` helper (M1/T1.1), for
//! `source_scan::production_source()`, and for `ports::refused_tcp_port()`.
//!
//! TDD: these are written against a stubbed `normalize` (red), then the real
//! implementation makes them pass (green). Per the repo TDD rule, edge cases
//! cover empty input, backslashes, NUL bytes, and multiple tokens per line.

#[path = "support/mod.rs"]
mod support;

#[path = "support/source_scan.rs"]
mod source_scan;

#[path = "support/ports.rs"]
mod ports;

#[path = "support/tracked.rs"]
mod tracked;

use source_scan::production_source;
use support::normalize;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// An RFC3339 Z-suffixed timestamp is replaced with `<TS>`.
#[test]
fn scrubs_rfc3339_timestamp() -> Result<(), TestError> {
    assert_eq!(normalize("at 2024-06-15T12:00:00Z done")?, "at <TS> done");
    Ok(())
}

/// A timestamp with fractional seconds and a numeric offset is fully replaced with `<TS>`.
#[test]
fn scrubs_timestamp_with_fraction_and_offset() -> Result<(), TestError> {
    assert_eq!(normalize("2024-06-15T12:00:00.123456+02:00")?, "<TS>");
    Ok(())
}

/// A fail2ban-style space-separated timestamp is replaced with `<TS>`.
#[test]
fn scrubs_space_separated_timestamp() -> Result<(), TestError> {
    // fail2ban-style "%Y-%m-%d %H:%M:%S".
    assert_eq!(normalize("ban 2024-06-15 12:00:00 ip")?, "ban <TS> ip");
    Ok(())
}

/// Second and millisecond durations (with or without a space) become `<DUR>`.
#[test]
fn scrubs_durations_with_units() -> Result<(), TestError> {
    assert_eq!(
        normalize("setup 1.234s and 12.3 ms")?,
        "setup <DUR> and <DUR>"
    );
    Ok(())
}

/// A `/tmp/...` path is replaced with `<TMP>`.
#[test]
fn scrubs_temp_paths() -> Result<(), TestError> {
    assert_eq!(
        normalize("wrote /tmp/abc123/out.pcap ok")?,
        "wrote <TMP> ok"
    );
    Ok(())
}

/// ...and so is a path under the temp directory this platform ACTUALLY uses.
///
/// The case above is the only one that existed, and it is the one that works
/// everywhere, so it could never fail: on Linux `temp_dir()` IS `/tmp`, and on
/// macOS `$TMPDIR` is a per-user launchd directory under `/var/folders/` that
/// the `/tmp/`-only pattern did not match at all. A test binary writing to
/// `std::env::temp_dir()` -- which is what every helper in `support/mod.rs`
/// does, `discard_coverage_profile` included -- therefore had its paths pass
/// through `normalize()` untouched here while being scrubbed in CI.
///
/// Written against the platform's own answer rather than a literal so it
/// asserts the property ("whatever this platform hands out is scrubbed")
/// instead of re-stating one platform's answer, which is the defect it
/// replaces.
///
/// The pid in the file name is what `tests/temp_path_isolation_test.rs`
/// requires. Nothing here creates the file — it only formats the path into a
/// string — but the gate cannot see that, and a fixed name would be wrong the
/// moment someone added a write.
#[test]
fn scrubs_paths_under_the_platform_temp_directory() -> Result<(), TestError> {
    // Never created, only formatted, so one fixed name serves every process.
    let f = std::env::temp_dir().join("sipnab-selftest-unwritten.pcap");
    let line = format!("wrote {} ok", f.display());
    assert_eq!(
        normalize(&line)?,
        "wrote <TMP> ok",
        "normalize() left a real temp path in place; the determinism contract \
         does not hold on this platform. The path was {}",
        f.display()
    );
    Ok(())
}

/// `pid=N` and `PID: N` both normalize to `pid=<PID>`.
#[test]
fn scrubs_pids_any_case() -> Result<(), TestError> {
    assert_eq!(normalize("pid=12345")?, "pid=<PID>");
    assert_eq!(normalize("PID: 678")?, "pid=<PID>");
    Ok(())
}

/// Loopback IPv4/IPv6 ports become `<PORT>` while the host part is kept.
#[test]
fn scrubs_loopback_ports_keeping_host() -> Result<(), TestError> {
    assert_eq!(
        normalize("bound 127.0.0.1:54321")?,
        "bound 127.0.0.1:<PORT>"
    );
    assert_eq!(normalize("mcp [::1]:8731")?, "mcp [::1]:<PORT>");
    Ok(())
}

/// SIP URIs, version numbers, and codec clock-rates pass through unscrubbed.
#[test]
fn preserves_non_volatile_text() -> Result<(), TestError> {
    // SIP, version numbers, and codec clock-rates must NOT be scrubbed.
    let s = "INVITE sip:alice@example.com SIP/2.0 v0.4.2 PCMU/8000";
    assert_eq!(normalize(s)?, s);
    Ok(())
}

/// Normalizing an empty string yields an empty string.
#[test]
fn empty_input_is_empty() -> Result<(), TestError> {
    assert_eq!(normalize("")?, "");
    Ok(())
}

/// Backslashes (Windows paths) survive normalization unchanged.
#[test]
fn backslashes_are_preserved() -> Result<(), TestError> {
    let s = r"a\b\c windows\path";
    assert_eq!(normalize(s)?, s);
    Ok(())
}

/// An embedded NUL byte is preserved and does not panic the normalizer.
#[test]
fn nul_byte_is_preserved_without_panic() -> Result<(), TestError> {
    let out = normalize("a\u{0}b")?;
    assert!(out.contains('\u{0}'));
    assert_eq!(out, "a\u{0}b");
    Ok(())
}

/// `deterministic_env` stamps TZ=UTC, NO_COLOR=1, COLUMNS=120, LINES=40 onto a Command.
#[test]
fn deterministic_env_sets_contract_vars() -> Result<(), TestError> {
    use std::ffi::OsStr;
    let mut c = std::process::Command::new("true");
    support::deterministic_env(&mut c);
    let envs: std::collections::HashMap<_, _> = c
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
        .collect();
    assert_eq!(
        envs.get(OsStr::new("TZ"))
            .ok_or("envs.get(OsStr::new(\"TZ\")) is None")?,
        "UTC"
    );
    assert_eq!(
        envs.get(OsStr::new("NO_COLOR"))
            .ok_or("envs.get(OsStr::new(\"NO_COLOR\")) is None")?,
        "1"
    );
    assert_eq!(
        envs.get(OsStr::new("COLUMNS"))
            .ok_or("envs.get(OsStr::new(\"COLUMNS\")) is None")?,
        "120"
    );
    assert_eq!(
        envs.get(OsStr::new("LINES"))
            .ok_or("envs.get(OsStr::new(\"LINES\")) is None")?,
        "40"
    );
    Ok(())
}

/// All volatile token classes on one line are scrubbed together in a single pass.
#[test]
fn multiple_tokens_on_one_line() -> Result<(), TestError> {
    let input = "2024-06-15T12:00:00Z call took 0.05s via 127.0.0.1:5060 pid=42 -> /tmp/x";
    assert_eq!(
        normalize(input)?,
        "<TS> call took <DUR> via 127.0.0.1:<PORT> pid=<PID> -> <TMP>",
    );
    Ok(())
}

include!("support/timeout.rs");
include!("support/drain.rs");

/// `test_timeout` scales deadlines, and refuses a scale that would zero them.
///
/// One test rather than three, deliberately: `cargo test` runs a binary's
/// tests in parallel, so three tests mutating the same environment variable
/// would race each other and pass or fail on scheduling. That is the same
/// class of bug the sanitizer job exists to find, and writing it into the
/// sanitizer job's own self-test would be a poor advertisement.
#[test]
fn timeout_scaling_contract() -> Result<(), TestError> {
    // SAFETY: the only test in this binary that touches this variable, so no
    // other thread can be reading it concurrently.
    let set = |v: Option<&str>| unsafe {
        match v {
            Some(v) => std::env::set_var("SIPNAB_TEST_TIMEOUT_SCALE", v),
            None => std::env::remove_var("SIPNAB_TEST_TIMEOUT_SCALE"),
        }
    };
    let secs = |d: std::time::Duration| d.as_secs();

    // Unset: used as written.
    set(None);
    assert_eq!(secs(test_timeout(15)), 15);

    // Set: multiplied. This is what keeps the sanitizer job's red meaning
    // "there is a race" rather than "the runner was slow".
    set(Some("12"));
    assert_eq!(secs(test_timeout(15)), 180);

    // Garbage, empty and zero all fall back to 1. A scale that silently read
    // as zero would collapse every deadline to an instant timeout -- the same
    // defect in the opposite direction, and one that would look like a flood
    // of real failures.
    for bad in ["0", "", "  ", "nope", "-3", "1.5"] {
        set(Some(bad));
        assert_eq!(
            secs(test_timeout(5)),
            5,
            "scale {bad:?} must fall back to 1, not zero the deadline"
        );
    }
    set(None);
    Ok(())
}

// ── production_source: where a source scan must stop reading ─────────

/// The ordinary shape: production code, then a `#[cfg(test)] mod tests`.
/// Everything before the attribute is kept, everything from it is dropped.
#[test]
fn production_source_cuts_at_the_test_module() -> Result<(), TestError> {
    let src = r"
pub fn handle() -> char { 'k' }

#[cfg(test)]
mod tests {
    fn t() -> char { 'z' }
}
";
    let prod = production_source(src);
    assert!(
        prod.contains("'k'"),
        "production code must survive: {prod:?}"
    );
    assert!(!prod.contains("'z'"), "test module must be cut: {prod:?}");
    Ok(())
}

/// The defect this rule was written for. A COMMENT that spells the attribute
/// is prose, not a test module, and must not end the scan — `src/tui/
/// dashboard.rs` mentions it on line 17 and truncated a 375-line view to 17.
#[test]
fn production_source_ignores_the_attribute_written_in_a_comment() -> Result<(), TestError> {
    let src = r"
// fixtures -- deliberately there rather than as a #[cfg(test)] import
pub fn handle() -> char { 'k' }

#[cfg(test)]
mod tests {
    fn t() -> char { 'z' }
}
";
    let prod = production_source(src);
    assert!(
        prod.contains("'k'"),
        "a comment naming the attribute must not stop the scan: {prod:?}"
    );
    assert!(!prod.contains("'z'"));
    Ok(())
}

/// A real `#[cfg(test)]` guarding a test-only IMPORT is not the test module.
/// `src/tui/controllers/mod.rs` has one on line 23, which cut a 1662-line
/// file to 22 lines and hid every key its dispatcher handles.
#[test]
fn production_source_steps_over_an_attribute_on_a_use() -> Result<(), TestError> {
    let src = r"
#[cfg(test)]
use crate::tui::clipboard::spawn_clipboard_copy;

pub fn handle() -> char { 'k' }

#[cfg(test)]
mod tests {
    fn t() -> char { 'z' }
}
";
    let prod = production_source(src);
    assert!(
        prod.contains("'k'"),
        "an attribute on a `use` must not stop the scan: {prod:?}"
    );
    assert!(!prod.contains("'z'"));
    Ok(())
}

/// The attribute also guards single statements and `thread_local!` counters
/// INSIDE production functions (`src/tui/call_list.rs`, `stream_list.rs`).
/// Stopping there would discard the rest of the function around it.
#[test]
fn production_source_steps_over_an_attribute_inside_a_function() -> Result<(), TestError> {
    let src = r"
pub fn render() -> char {
    #[cfg(test)]
    CALLS.with(|c| c.set(c.get() + 1));
    'k'
}

#[cfg(test)]
mod tests {
    fn t() -> char { 'z' }
}
";
    let prod = production_source(src);
    assert!(
        prod.contains("'k'"),
        "an attribute on a statement must not stop the scan: {prod:?}"
    );
    assert!(!prod.contains("'z'"));
    Ok(())
}

/// `#[cfg(test)] mod tests;` — attribute and item on one line, the form used
/// when the tests live in their own file.
#[test]
fn production_source_cuts_at_a_one_line_module_declaration() -> Result<(), TestError> {
    let src = r"
pub fn handle() -> char { 'k' }
#[cfg(test)]
mod tests;
";
    assert!(production_source(src).contains("'k'"));
    assert!(!production_source(src).contains("mod tests;"));
    Ok(())
}

/// Restricted visibility and further attributes between `#[cfg(test)]` and
/// the `mod` are still the test module: `pub(crate) mod test_support` is how
/// `src/tui/controllers/mod.rs` spells it.
#[test]
fn production_source_cuts_at_a_restricted_visibility_module() -> Result<(), TestError> {
    for decl in [
        "pub(crate) mod test_support {",
        "pub(in crate::tui) mod test_support {",
        "pub mod test_support {",
    ] {
        let src = format!(
            "pub fn handle() {{}}\n\n#[cfg(test)]\n#[allow(dead_code)]\n/// doc\n{decl}\n    fn t() {{}}\n}}\n"
        );
        let prod = production_source(&src);
        assert!(
            !prod.contains("test_support"),
            "{decl} is a test module and must be cut: {prod:?}"
        );
        assert!(prod.contains("handle"), "{decl}: {prod:?}");
    }
    Ok(())
}

/// A file with no test module is returned whole — the anti-vacuity direction.
/// A rule that trims something here would silently shorten every scan.
#[test]
fn production_source_keeps_a_file_with_no_test_module() -> Result<(), TestError> {
    let src = "pub fn handle() -> char { 'k' }\n";
    assert_eq!(production_source(src), src);
    assert_eq!(production_source(""), "");
    Ok(())
}

/// The result is a PREFIX, so its line count is the index of the cut and
/// callers can slice their own line vector with it.
#[test]
fn production_source_line_count_is_the_cut_index() -> Result<(), TestError> {
    let src = "a\nb\nc\n#[cfg(test)]\nmod tests {}\n";
    let prod = production_source(src);
    assert!(src.starts_with(prod), "must be a prefix of the input");
    assert_eq!(prod.lines().count(), 3);
    let all: Vec<&str> = src.lines().collect();
    assert_eq!(&all[..prod.lines().count()], &["a", "b", "c"]);
    Ok(())
}

/// While the guard lives, a connection to its port never succeeds: nothing
/// listens there. Linux refuses it at once; macOS leaves the SYN unanswered,
/// so there the connect is bounded and must end in a timeout or a refusal.
#[test]
fn a_refused_port_refuses_a_connection() -> Result<(), TestError> {
    let held = ports::refused_tcp_port()?;
    let err = std::net::TcpStream::connect_timeout(&held.addr(), std::time::Duration::from_secs(3))
        .err()
        .ok_or("a connection to the held port must not succeed")?;
    if cfg!(target_os = "linux") {
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "connect to {}: {err}",
            held.addr()
        );
    } else {
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
            ),
            "connect to {}: {err}",
            held.addr()
        );
    }
    Ok(())
}

/// While the guard lives, nothing else can bind its port, so no test running
/// alongside can be handed the number and start listening on it. A helper
/// that reads a port and releases it fails here: that release is the race.
#[test]
fn a_refused_port_cannot_be_taken_while_held() -> Result<(), TestError> {
    let held = ports::refused_tcp_port()?;
    let taken = std::net::TcpListener::bind(held.addr());
    assert_eq!(
        taken.as_ref().err().map(std::io::Error::kind),
        Some(std::io::ErrorKind::AddrInUse),
        "another socket bound the held port {}: {taken:?}",
        held.addr()
    );
    Ok(())
}

/// The guard releases its port when it is dropped, and only then.
#[test]
fn a_refused_port_is_released_when_the_guard_drops() -> Result<(), TestError> {
    let held = ports::refused_tcp_port()?;
    let addr = held.addr();
    drop(held);
    let again = std::net::TcpListener::bind(addr)?;
    assert_eq!(again.local_addr()?, addr);
    Ok(())
}

// ── drain_closed ─────────────────────────────────────────────────────

/// A reader thread that forwards its lines late, then hangs up: the shape of a
/// child's output read back on a loaded host after the child has exited.
fn late_reader(delay: std::time::Duration) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        for line in ["first", "second"] {
            if tx.send(line.to_string()).is_err() {
                return;
            }
        }
    });
    rx
}

/// Lines that reach the channel after a quiet gap are still read, because the
/// drain waits for the reader to hang up rather than for a pause.
///
/// The defect this pays for: four harnesses stopped at the first 200 or 300 ms
/// with no line, so a reader thread that had not yet forwarded the output of a
/// child that had already exited read as no output at all. Under host load the
/// `--relay-holdings` end-to-end tests failed that way with "no stdout".
#[test]
fn drain_closed_reads_lines_that_arrive_after_a_quiet_gap() {
    let rx = late_reader(std::time::Duration::from_millis(800));
    assert_eq!(
        drain_closed(&rx, test_timeout(10)),
        ["first", "second"],
        "the lines that arrived after the quiet gap are read"
    );
}

/// A sender that never hangs up does not hold the drain past its bound.
#[test]
fn drain_closed_returns_by_its_bound_when_the_sender_stays_open() {
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let started = std::time::Instant::now();
    assert!(
        drain_closed(&rx, std::time::Duration::from_millis(400)).is_empty(),
        "a sender that sent nothing yields nothing"
    );
    let took = started.elapsed();
    drop(tx);
    assert!(
        took >= std::time::Duration::from_millis(400) && took < test_timeout(5),
        "returned after {took:?}"
    );
}

/// A sender that has already hung up is read at once: what it sent, and no
/// wait.
#[test]
fn drain_closed_returns_at_once_when_the_sender_has_hung_up() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send("only".to_string()).unwrap_or_default();
    drop(tx);
    let started = std::time::Instant::now();
    assert_eq!(
        drain_closed(&rx, test_timeout(10)),
        ["only"],
        "what the sender sent before hanging up is read"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "a hung-up sender is read at once, not after the bound: {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// `tracked`: the one reader of `git ls-files`. An unmerged path is listed once
// per index stage; the reader returns it once.
// ---------------------------------------------------------------------------

/// A listing without repeats comes back whole, in listing order.
#[test]
fn unique_paths_keeps_a_listing_without_repeats_in_order() {
    assert_eq!(
        tracked::unique_paths(b"docs/b.md\0README.md\0docs/a.md\0"),
        ["docs/b.md", "README.md", "docs/a.md"],
        "no path repeats, so none is removed and none is moved"
    );
}

/// An unmerged path is listed once per stage: three adjacent copies.
#[test]
fn unique_paths_returns_an_unmerged_path_once() {
    assert_eq!(
        tracked::unique_paths(b"README.md\0docs/a.md\0docs/a.md\0docs/a.md\0docs/b.md\0"),
        ["README.md", "docs/a.md", "docs/b.md"],
        "docs/a.md is listed for stages 1, 2 and 3 and is one path"
    );
}

/// Two unmerged pages: the 2026-11-08 count of 350 against a real 346.
#[test]
fn unique_paths_counts_two_unmerged_pages_as_two() {
    let listing = b"a.md\0a.md\0a.md\0b.md\0b.md\0b.md\0c.md\0";
    assert_eq!(
        tracked::unique_paths(listing).len(),
        3,
        "seven listed entries name three paths"
    );
}

/// A path deleted on one side has two stages; a repeat need not be a triple.
#[test]
fn unique_paths_returns_a_path_with_two_stages_once() {
    assert_eq!(
        tracked::unique_paths(b"gone.rs\0gone.rs\0kept.rs\0"),
        ["gone.rs", "kept.rs"],
        "a modify/delete conflict lists the path twice"
    );
}

/// The rule is "each path once", not "collapse neighbors": a listing joined
/// from two calls can repeat a path far from its first copy.
#[test]
fn unique_paths_removes_a_repeat_that_is_not_adjacent() {
    assert_eq!(
        tracked::unique_paths(b"x.rs\0y.rs\0x.rs\0z.rs\0y.rs\0"),
        ["x.rs", "y.rs", "z.rs"],
        "the first position of each path is the one kept"
    );
}

/// The empty listing, and the empty field after the final NUL.
#[test]
fn unique_paths_of_an_empty_listing_is_empty() {
    assert!(tracked::unique_paths(b"").is_empty(), "no bytes, no paths");
    assert!(
        tracked::unique_paths(b"\0\0").is_empty(),
        "empty fields are not paths"
    );
    assert_eq!(
        tracked::unique_paths(b"only.md"),
        ["only.md"],
        "a listing without a final NUL still ends its last path"
    );
}

/// `-z` output carries a path byte for byte: a space or a newline inside a
/// name does not split it, and names that differ only there stay distinct.
#[test]
fn unique_paths_keeps_whitespace_inside_a_name() {
    assert_eq!(
        tracked::unique_paths(b"docs/a b.md\0docs/a\nb.md\0docs/a b.md\0docs/ab.md\0"),
        ["docs/a b.md", "docs/a\nb.md", "docs/ab.md"],
        "only the NUL separates paths"
    );
}

/// Names that differ in case, or by a prefix, are different paths.
#[test]
fn unique_paths_does_not_merge_similar_names() {
    assert_eq!(
        tracked::unique_paths(b"Readme.md\0README.md\0README.md.orig\0docs\0docs/\0"),
        ["Readme.md", "README.md", "README.md.orig", "docs", "docs/"],
        "the comparison is exact"
    );
}

/// A name that is not UTF-8 is still one path, listed once.
#[test]
fn unique_paths_returns_a_non_utf8_name_once() {
    let listed = tracked::unique_paths(b"caf\xe9.md\0caf\xe9.md\0caf\xe9.md\0");
    assert_eq!(
        listed.len(),
        1,
        "three stages of one path, whatever its bytes: {listed:?}"
    );
}

/// A `git` for a repository the test builds, with every variable a hook
/// exports removed, so the child discovers `dir` and not the repository being
/// committed to.
fn fixture_git(dir: &std::path::Path) -> std::process::Command {
    let mut git = std::process::Command::new("git");
    git.current_dir(dir);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            git.env_remove(name);
        }
    }
    git
}

/// Runs `git <args>` in the fixture with `input` on stdin; returns stdout.
fn fixture_run(dir: &std::path::Path, args: &[&str], input: &str) -> Result<String, TestError> {
    use std::io::Write as _;
    let mut child = fixture_git(dir)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("the child has no stdin")?
        .write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// A repository whose index holds `conflict.md` at stages 1, 2 and 3 and
/// `clean.md` at stage 0: the index a conflicted merge leaves, written
/// directly, with no commit and no merge.
fn repository_with_an_unmerged_path() -> Result<tempfile::TempDir, TestError> {
    let dir = tempfile::tempdir()?;
    fixture_run(dir.path(), &["init", "-q"], "")?;
    let mut entries = String::new();
    for (stage, body) in [(1, "base\n"), (2, "ours\n"), (3, "theirs\n")] {
        let blob = fixture_run(dir.path(), &["hash-object", "-w", "--stdin"], body)?;
        entries.push_str(&format!("100644 {blob} {stage}\tconflict.md\n"));
    }
    let blob = fixture_run(dir.path(), &["hash-object", "-w", "--stdin"], "clean\n")?;
    entries.push_str(&format!("100644 {blob} 0\tclean.md\n"));
    fixture_run(dir.path(), &["update-index", "--index-info"], &entries)?;
    Ok(dir)
}

/// The fixture is the real condition: git itself lists the unmerged path
/// three times. Without this the next test could pass over a clean index.
#[test]
fn git_lists_an_unmerged_path_once_per_stage() -> Result<(), TestError> {
    let dir = repository_with_an_unmerged_path()?;
    let raw = fixture_run(dir.path(), &[concat!("ls-", "files")], "")?;
    assert_eq!(
        raw.lines().filter(|path| *path == "conflict.md").count(),
        3,
        "git lists one entry per stage: {raw:?}"
    );
    Ok(())
}

/// The reader, over that index, returns each path once.
#[test]
fn ls_files_returns_an_unmerged_path_once() -> Result<(), TestError> {
    let dir = repository_with_an_unmerged_path()?;
    let listed = tracked::ls_files_from(fixture_git(dir.path()), &[])?;
    assert_eq!(
        listed,
        ["clean.md", "conflict.md"],
        "conflict.md has three stages and is one tracked path"
    );
    Ok(())
}

/// A pathspec narrows the listing, and the unmerged path is still one path.
#[test]
fn ls_files_with_a_pathspec_returns_an_unmerged_path_once() -> Result<(), TestError> {
    let dir = repository_with_an_unmerged_path()?;
    let listed = tracked::ls_files_from(fixture_git(dir.path()), &["--", "conf*"])?;
    assert_eq!(
        listed,
        ["conflict.md"],
        "the pathspec selects the unmerged path alone"
    );
    Ok(())
}

/// A pathspec that matches nothing is an empty listing, not an error.
#[test]
fn ls_files_with_a_pathspec_that_matches_nothing_is_empty() -> Result<(), TestError> {
    let dir = repository_with_an_unmerged_path()?;
    let listed = tracked::ls_files_from(fixture_git(dir.path()), &["--", "*.rs"])?;
    assert!(listed.is_empty(), "no Rust file is tracked: {listed:?}");
    Ok(())
}

/// Outside a repository git fails, and the reader says so: an empty listing
/// there would let every gate that scans it pass over nothing.
#[test]
fn ls_files_outside_a_repository_is_an_error() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut git = fixture_git(dir.path());
    git.env("GIT_CEILING_DIRECTORIES", dir.path());
    let result = tracked::ls_files_from(git, &[]);
    let message = match result {
        Ok(listed) => return Err(format!("listed {listed:?} outside a repository").into()),
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains("git ls-files") && message.contains("failed"),
        "the error names the command that failed: {message}"
    );
    Ok(())
}

/// An option git does not know is an error, with git's own message in it.
#[test]
fn ls_files_with_an_unknown_option_is_an_error() -> Result<(), TestError> {
    let dir = repository_with_an_unmerged_path()?;
    let result = tracked::ls_files_from(fixture_git(dir.path()), &["--no-such-option"]);
    let message = match result {
        Ok(listed) => return Err(format!("listed {listed:?} for an unknown option").into()),
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains("no-such-option"),
        "the error carries the arguments: {message}"
    );
    Ok(())
}

/// The real repository lists something, and nothing twice.
#[test]
fn ls_files_over_this_repository_lists_no_path_twice() -> Result<(), TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let listed = tracked::ls_files(root, &[])?;
    let distinct: std::collections::BTreeSet<&String> = listed.iter().collect();
    assert!(
        listed.iter().any(|path| path == "Cargo.toml"),
        "the listing is of this repository"
    );
    assert_eq!(
        listed.len(),
        distinct.len(),
        "a path is listed more than once"
    );
    Ok(())
}

/// The scan that finds a direct call: what it reports and what it exempts.
#[test]
fn raw_listing_lines_reports_a_direct_call_and_exempts_stage_free_questions() {
    let call = concat!("\"ls-", "files\"");
    let src = format!(
        "let a = git.args([{call}, \"-z\"]);\n\
         let b = git.args([{call}, \"--error-unmatch\", rel]);\n\
         let c = git.args([{call}, \"--others\", \"--exclude-standard\"]);\n\
         let d = git.args([{call}, \"-s\", \"-z\"]);\n\
         let e = git.args([{call}, \"-o\"]);\n\
         // prose that says git ls-files is not a call\n\
         let f = git.args([{call}]);\n\
         let g = git.args([\n\
             {call},\n\
             \"--error-unmatch\",\n\
         ]);\n\
         let h = git.args([\n\
             {call},\n\
             \"-z\",\n\
             \"--others\",\n\
         ]);\n"
    );
    assert_eq!(
        tracked::raw_listing_lines(&src),
        [1, 7, 13],
        "lines 2 to 5 and 9 ask a question a repeated path cannot change; line 6 has no call; \
         the call on line 13 has its flag two lines down, outside the window"
    );
    assert!(
        tracked::raw_listing_lines("").is_empty(),
        "an empty file has no call"
    );
}

/// Direct calls that stay, each with the reason a repeat cannot reach it.
const RAW_LISTING_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "tests/support/tracked.rs",
        ".args([",
        "the shared reader itself",
    ),
    (
        "scripts/lib_tracked.py",
        "\"-z\", *args]",
        "the shared reader for the scripts",
    ),
    (
        "tests/staged_inputs_gate_test.rs",
        "!builds_its_own_repository(",
        "source text handed to a predicate, never run",
    ),
    (
        "scripts/tests/test_lib_tracked.py",
        "raw = _git(repo,",
        "counts the repeats on purpose: proves the fixture index is unmerged",
    ),
    (
        "scripts/tests/test_check_rustfmt_list.py",
        ".splitlines().count(",
        "counts the repeats on purpose: proves the fixture index is unmerged",
    ),
];

/// **The rule over the tree.** No test and no script lists tracked files with
/// a `git ls-files` call of its own. Each one that did read an unmerged path
/// once per stage; one reader per language removes the repeats in one place.
#[test]
fn no_test_or_script_lists_tracked_files_without_the_shared_reader() -> Result<(), TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = tracked::ls_files(root, &["--", "tests", "scripts", ".githooks"])?;
    let mut scanned = 0usize;
    let mut direct = Vec::new();
    for rel in files
        .iter()
        .filter(|rel| rel.ends_with(".rs") || rel.ends_with(".py"))
    {
        let Ok(src) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        scanned += 1;
        let lines: Vec<&str> = src.lines().collect();
        for number in tracked::raw_listing_lines(&src) {
            let line = lines.get(number - 1).copied().unwrap_or_default();
            let allowed = RAW_LISTING_ALLOWED
                .iter()
                .any(|(file, part, _)| file == rel && line.contains(part));
            if !allowed {
                direct.push(format!("{rel}:{number}: {}", line.trim()));
            }
        }
    }
    assert!(
        scanned > 300,
        "the scan read {scanned} files; the tree has more than 300 Rust tests and Python scripts"
    );
    assert!(
        direct.is_empty(),
        "{} direct `git ls-files` call(s). An unmerged path is listed once per stage; use \
         `tracked::ls_files` (tests/support/tracked.rs) or `lib_tracked.ls_files` \
         (scripts/lib_tracked.py), which return each path once:\n{}",
        direct.len(),
        direct.join("\n")
    );
    Ok(())
}

/// Every allowed direct call still exists: an entry for a line that is gone
/// would exempt whatever is written there next.
#[test]
fn every_allowed_direct_listing_call_still_exists() -> Result<(), TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, part, reason) in RAW_LISTING_ALLOWED {
        let src = std::fs::read_to_string(root.join(file))?;
        let lines: Vec<&str> = src.lines().collect();
        let found = tracked::raw_listing_lines(&src)
            .into_iter()
            .filter_map(|number| lines.get(number - 1))
            .any(|line| line.contains(part));
        assert!(
            found,
            "{file} no longer has a direct call on a line containing {part:?} ({reason}); \
             remove the entry"
        );
    }
    Ok(())
}
