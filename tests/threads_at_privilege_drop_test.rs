// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Which threads can exist when the process drops root, held as a census.
//!
//! glibc carries out `setgroups`, `setgid` and `setuid` for the whole
//! process: the calling thread signals every other thread, and each makes the
//! same call. A thread that is waiting in a call with a time limit at that
//! moment (`poll`, a socket read with a receive timeout) gets `EINTR`.
//! Measured on glibc 2.39: a `poll` with a 3 s limit returned
//! `EINTR` 0.30 s in, when another thread called `setgid`; a `read` with no
//! limit on an empty pipe was restarted and returned its byte.
//!
//! So every thread that can exist at the drop was read for the waits it
//! makes, and `docs/internals/threading.md` records the answer per start
//! path. That answer holds only while no other thread starts before the drop
//! and no other drop appears. The tests here fail when either changes:
//!
//! * every source file that starts a thread is in one of three lists, so a
//!   new one must be placed, and placing it means answering the question;
//! * the files whose threads can exist at the drop are the ones the page
//!   names;
//! * the calls that drop are the three that were read, and each start path
//!   keeps the order that was read.
//!
//! The tolerance of each wait is held where the wait is, by
//! `an_interrupted_poll_is_a_timeout_not_a_failure` (`src/capture/live.rs`),
//! `eintr_and_read_timeouts_are_transient_not_fatal` (`src/capture/hep.rs`)
//! and `an_interrupted_read_is_retried_rather_than_reported`
//! (`src/process_isolation.rs`).

#[path = "support/source_scan.rs"]
mod source_scan;
#[path = "support/tracked.rs"]
mod tracked;

use std::collections::BTreeSet;
use std::path::Path;

type TestError = Box<dyn std::error::Error>;

/// The spellings that start a thread, or a runtime that owns threads.
const THREAD_STARTS: [&str; 5] = [
    "thread::spawn(",
    "thread::Builder::new()",
    "thread::scope(",
    "runtime::Builder::new_",
    "Runtime::new(",
];

/// Files whose threads can exist when `privilege::drop_to` runs: the capture
/// thread and what it starts, and the parent's two threads beside the
/// scanner-kill worker. Each wait they make was read; the page lists them.
const AT_THE_DROP: [&str; 5] = [
    "src/capture/breaker.rs",
    "src/capture/hep.rs",
    "src/capture/live.rs",
    "src/capture/native.rs",
    "src/process_isolation.rs",
];

/// Files whose threads cannot exist at a drop. They start after it
/// (everything `batch::run` and `run_tui_mode` start, and what those start),
/// or in a process that has already dropped (the scanner-kill worker's
/// pumps), or in a command that makes no drop (`sipnab fleet`), or they are
/// joined before the capture starts (the archive password command's reader,
/// the relay snapshot's fan-out).
const AFTER_OR_WITHOUT_A_DROP: [&str; 25] = [
    "src/app/fleet.rs",
    "src/app/fleet_center.rs",
    "src/app/fleet_member.rs",
    "src/app/relay_poller.rs",
    "src/app/relay_reconciler.rs",
    "src/app/servers.rs",
    "src/app/tui_mode.rs",
    "src/app/vcon_enrich.rs",
    "src/capture/archive/password.rs",
    "src/capture/hep_delivery.rs",
    "src/mcp/load.rs",
    "src/mcp/sweep.rs",
    "src/mcp/tls_capture.rs",
    "src/names.rs",
    "src/output/prometheus_server.rs",
    "src/parallel.rs",
    "src/process_isolation/worker_process.rs",
    "src/relay/fan_out.rs",
    "src/security/actions/service.rs",
    "src/security/tfps.rs",
    "src/tui/clipboard.rs",
    "src/tui/controllers/file_open.rs",
    "src/tui/relay_sessions.rs",
    "src/tui/relay_stats.rs",
    "src/tui/tfps_observe.rs",
];

/// Files that hold only test code and no test module of their own.
const TEST_ONLY: [&str; 2] = ["src/test_engines.rs", "src/test_utils.rs"];

/// The heading of the page's section.
const SECTION: &str = "## Threads that exist at the privilege drop";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Whether the production part of `source` starts a thread: a spelling from
/// [`THREAD_STARTS`] on a line that is not a comment, above the test module.
fn starts_a_thread(source: &str) -> bool {
    source_scan::production_source(source)
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"))
        .any(|line| THREAD_STARTS.iter().any(|start| line.contains(start)))
}

/// Every tracked file under `src/` that starts a thread.
fn files_that_start_a_thread() -> Result<BTreeSet<String>, TestError> {
    let listed = tracked::ls_files(root(), &["--", "src/*.rs", "src/**/*.rs"])?;
    let mut found = BTreeSet::new();
    for rel in listed.iter().filter(|rel| !rel.is_empty()) {
        if starts_a_thread(&std::fs::read_to_string(root().join(rel))?) {
            found.insert(rel.clone());
        }
    }
    Ok(found)
}

/// The production part of one source file.
fn production(rel: &str) -> Result<String, TestError> {
    let text = std::fs::read_to_string(root().join(rel))?;
    Ok(source_scan::production_source(&text).to_string())
}

/// Where `needle` first occurs in `text`, or an error naming it.
fn position(text: &str, needle: &str, rel: &str) -> Result<usize, TestError> {
    text.find(needle).ok_or_else(|| {
        format!("{rel} no longer contains `{needle}`; this test read it there").into()
    })
}

/// How many lines of `text` that are not comments contain `needle`.
fn code_lines_with(text: &str, needle: &str) -> usize {
    text.lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//") && line.contains(needle))
        .count()
}

#[test]
fn every_file_that_starts_a_thread_is_placed_before_or_after_the_drop() -> Result<(), TestError> {
    let found = files_that_start_a_thread()?;
    let placed: BTreeSet<String> = AT_THE_DROP
        .iter()
        .chain(&AFTER_OR_WITHOUT_A_DROP)
        .chain(&TEST_ONLY)
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        placed.len(),
        AT_THE_DROP.len() + AFTER_OR_WITHOUT_A_DROP.len() + TEST_ONLY.len(),
        "a file is in two of the lists"
    );
    let unplaced: Vec<&String> = found.difference(&placed).collect();
    assert!(
        unplaced.is_empty(),
        "these files start a thread and are in none of this test's lists: \
         {unplaced:?}. Decide whether the thread can exist when \
         `privilege::drop_to` runs. If it can, read every wait it makes: a \
         wait with a time limit gets EINTR at the drop and must retry or \
         read it as an ordinary timeout; then add the file to AT_THE_DROP \
         and to the table in docs/internals/threading.md. If it cannot, add \
         it to AFTER_OR_WITHOUT_A_DROP."
    );
    let gone: Vec<&String> = placed.difference(&found).collect();
    assert!(
        gone.is_empty(),
        "these files are listed and no longer start a thread; remove them \
         from the list (and from the page, for AT_THE_DROP): {gone:?}"
    );
    Ok(())
}

#[test]
fn the_page_names_every_file_whose_threads_exist_at_the_drop() -> Result<(), TestError> {
    let page = std::fs::read_to_string(root().join("docs/internals/threading.md"))?;
    let after = page
        .split_once(SECTION)
        .ok_or("docs/internals/threading.md has no section on the threads at the drop")?
        .1;
    let section = after.split_once("\n## ").map_or(after, |(body, _)| body);
    for rel in AT_THE_DROP {
        assert!(
            section.contains(rel),
            "the section `{SECTION}` of docs/internals/threading.md does not \
             name {rel}, whose threads can exist at the drop"
        );
    }
    Ok(())
}

#[test]
fn the_calls_that_drop_are_the_three_that_were_read() -> Result<(), TestError> {
    let listed = tracked::ls_files(root(), &["--", "src/*.rs", "src/**/*.rs"])?;
    let mut sites = Vec::new();
    for rel in listed.iter().filter(|rel| !rel.is_empty()) {
        if rel == "src/privilege.rs" {
            continue; // the definitions, and `drop_privileges` calling `drop_to`
        }
        let text = production(rel)?;
        let calls = code_lines_with(&text, "privilege::drop_to(")
            + code_lines_with(&text, "privilege::drop_privileges(");
        if calls > 0 {
            sites.push((rel.clone(), calls));
        }
    }
    assert_eq!(
        sites,
        vec![
            ("src/app/bootstrap.rs".to_string(), 2),
            ("src/process_isolation/worker_process.rs".to_string(), 1),
        ],
        "the privilege drop is called from another place than the three \
         this test and docs/internals/threading.md describe \
         (`confine_after_capture_start`, `prepare_cores_inputs`, the \
         scanner-kill worker's `harden`). Read which threads exist at the \
         new call and what each waits in, then extend the page and this list."
    );
    Ok(())
}

#[test]
fn the_modes_that_start_servers_run_after_the_launch_that_drops() -> Result<(), TestError> {
    let rel = "src/main.rs";
    let main = production(rel)?;
    let launch = position(&main, "bootstrap::launch(", rel)?;
    for later in ["run_tui_mode(", "batch::run("] {
        let at = position(&main, later, rel)?;
        assert!(
            launch < at,
            "{rel} calls `{later}` before `bootstrap::launch(`: what that \
             mode starts (the API and MCP listeners, the fleet member, the \
             relay poller, the HEP sender) would then exist at the drop"
        );
    }
    Ok(())
}

#[test]
fn neither_main_nor_bootstrap_starts_a_thread_of_its_own() -> Result<(), TestError> {
    for rel in ["src/main.rs", "src/app/bootstrap.rs", "src/app/batch.rs"] {
        assert!(
            !starts_a_thread(&std::fs::read_to_string(root().join(rel))?),
            "{rel} starts a thread itself; place it against the drop as the \
             census test describes"
        );
    }
    Ok(())
}

#[test]
fn the_cores_run_drops_before_it_starts_its_readers() -> Result<(), TestError> {
    let rel = "src/app/batch.rs";
    let batch = production(rel)?;
    let body = batch
        .split_once("pub fn run_cores_file(")
        .ok_or("src/app/batch.rs has no `run_cores_file`")?
        .1;
    let drop = position(body, "prepare_cores_inputs(", rel)?;
    let read = position(body, "crate::parallel::run_offline_parallel_set(", rel)?;
    assert!(
        drop < read,
        "`run_cores_file` starts the parallel read before \
         `prepare_cores_inputs`, which makes the drop: the reader threads \
         would exist at it"
    );
    Ok(())
}

#[test]
fn the_kill_worker_process_drops_before_it_starts_its_pumps() -> Result<(), TestError> {
    let rel = "src/process_isolation/worker_process.rs";
    let worker = production(rel)?;
    let drop = position(&worker, "harden(&args.run_as)", rel)?;
    let serve = position(&worker, "serve(std::io::stdin()", rel)?;
    assert!(
        drop < serve,
        "the scanner-kill worker serves before it hardens itself: its two \
         pump threads would exist at its own privilege drop"
    );
    let start = position(&worker, "let sockets = match start(&args)", rel)?;
    assert!(
        start < serve,
        "the scanner-kill worker must call `start`, which hardens, before \
         `serve`"
    );
    Ok(())
}

#[test]
fn a_thread_start_in_a_comment_or_a_test_module_is_not_counted() {
    assert!(
        !starts_a_thread("fn a() {\n    // std::thread::spawn(|| {});\n}\n"),
        "a comment that spells a thread start is not one"
    );
    assert!(
        !starts_a_thread(
            "fn a() {}\n\n#[cfg(test)]\nmod tests {\n    fn t() { std::thread::spawn(|| {}); }\n}\n"
        ),
        "a test module's thread is not a production thread"
    );
    assert!(
        !starts_a_thread("fn a() { let spawn = 1; let _ = spawn; }\n"),
        "a name that contains `spawn` starts nothing"
    );
}

#[test]
fn each_spelling_of_a_thread_start_is_counted() {
    for line in [
        "let h = std::thread::spawn(move || work());",
        "let h = std::thread::Builder::new().name(n).spawn(f)?;",
        "std::thread::scope(|scope| { scope.spawn(f); });",
        "let rt = tokio::runtime::Builder::new_current_thread().build()?;",
        "let rt = tokio::runtime::Runtime::new()?;",
    ] {
        assert!(
            starts_a_thread(&format!("fn a() {{\n    {line}\n}}\n")),
            "this line starts a thread and must be counted: {line}"
        );
    }
}
