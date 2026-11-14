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
//! * the calls that drop are the four that were read, and each start path
//!   keeps the order that was read;
//! * every line of `src/main.rs` that ends the process is one that was
//!   read, and every way a run ends before the launch has a row in
//!   `sipnab::early_exit` that says what the run does with root
//!   (COMMANDS-KEEP-ROOT).
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
/// pumps), or in a command that drops before it starts one (`sipnab fleet`,
/// and the relay snapshot's fan-out of `--relay-holdings`), or they are
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
fn the_calls_that_drop_are_the_four_that_were_read() -> Result<(), TestError> {
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
            ("src/early_exit.rs".to_string(), 1),
            ("src/process_isolation/worker_process.rs".to_string(), 1),
        ],
        "the privilege drop is called from another place than the four \
         this test and docs/internals/threading.md describe \
         (`confine_after_capture_start`, `prepare_cores_inputs`, the \
         scanner-kill worker's `harden`, and `early_exit::confine` for the \
         commands that end before the launch). Read which threads exist at \
         the new call and what each waits in, then extend the page and this list."
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

// ---- Every way a run ends before the launch has a row (COMMANDS-KEEP-ROOT) ----

/// The spellings that end the process in `src/main.rs`. The last is put
/// together from two parts so that this file does not hold the call it
/// looks for (`tests/unwrap_ratchet_test.rs` counts those).
const EXIT_SPELLINGS: [&str; 4] = [
    "release_run_and_exit(",
    "std::process::exit(",
    ".exit()",
    concat!("panic", "!("),
];

/// Every line of `src/main.rs` that ends the process, in the file's order:
/// a text found on the line or on one of the three code lines above it, and
/// the rows of `sipnab::early_exit` that leave through it. The one exit
/// with no row is the end of a run that did launch.
const MAIN_EXITS: [(&str, &[&str]); 24] = [
    (
        "worker_process::run_if_requested()",
        &["--internal-kill-worker"],
    ),
    ("run_g729_command()", &["g729 install", "g729 status"]),
    (
        "run_fleet_command()",
        &["fleet inventory", "fleet keygen", "fleet serve"],
    ),
    ("bootstrap::apply_config(", &["config error"]),
    ("bootstrap::plan(", &["plan error"]),
    ("bootstrap::run_relay_holdings(", &["--relay-holdings"]),
    ("bootstrap::run_relay_sessions(", &["--relay-sessions"]),
    ("run_cores_file(&cli, &loaded, &plan)", &["--cores"]),
    ("launch_and_dispatch(cli, loaded, plan)", &[]),
    (
        "bootstrap::install_archive_passwords(",
        &["archive password error"],
    ),
    (
        "bootstrap::run_startup_commands(",
        &[
            "--completions",
            "--print-yang-module",
            "--setup-caps",
            "--show-frame",
            "--write-annotated",
            "--notes refusal",
            "--strip-secrets",
            "--vcon-validate",
            "--compare-captures",
            "--find-in-files",
        ],
    ),
    ("cli.validate()", &["validation error"]),
    ("run_provenance::write_record(", &["provenance error"]),
    ("bootstrap::run_mint_token(", &["--mint-token"]),
    ("bootstrap::run_vcon_forward(", &["--vcon-forward"]),
    ("bootstrap::run_vcon_fetch(", &["--vcon-fetch"]),
    (
        "bootstrap::run_vcon_spool_status(",
        &["--vcon-spool-status"],
    ),
    ("bootstrap::run_vcon_resign(", &["--vcon-resign"]),
    ("bootstrap::run_vcon_audio_fetch(", &["--vcon-audio-fetch"]),
    ("panic_selftest", &["--panic-selftest"]),
    ("bootstrap::refuse_invalid_config(", &["--dump-config"]),
    ("bootstrap::dump_config(", &["--dump-config"]),
    (
        "bootstrap::run_journal_command(",
        &["--journal-show", "--revert-actions"],
    ),
    ("bootstrap::uprobe_list(", &["--uprobe-list"]),
];

/// The rows that leave inside `Cli::parse_args()`, where clap ends the run.
const PARSER_EXITS: [&str; 3] = ["--help", "--version", "argument error"];

/// The commands that parse a file the caller named and still keep the
/// caller's privileges. The list is emptied by COMMANDS-PARSE-AS-ROOT.
const PARSE_AS_ROOT: [&str; 7] = [
    "--show-frame",
    "--write-annotated",
    "--strip-secrets",
    "--find-in-files",
    "--compare-captures",
    "--vcon-validate",
    "--vcon-resign",
];

/// The code lines of `text`: not blank, not a comment.
fn code_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect()
}

/// For each line of `text` that ends the process: that line with the three
/// code lines above it.
fn exit_sites(text: &str) -> Vec<String> {
    let lines = code_lines(text);
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| EXIT_SPELLINGS.iter().any(|s| line.contains(s)))
        .map(|(at, _)| lines[at.saturating_sub(3)..=at].join("\n"))
        .collect()
}

#[test]
fn every_exit_of_main_is_one_this_census_read() -> Result<(), TestError> {
    let sites = exit_sites(&production("src/main.rs")?);
    assert_eq!(
        sites.len(),
        MAIN_EXITS.len(),
        "src/main.rs ends the process at another number of places than this \
         census read. A new exit before `bootstrap::launch` keeps root unless \
         it is given a row in `sipnab::early_exit` and a plan: add the row, \
         then the line here. The places found:\n{}",
        sites.join("\n--\n")
    );
    for (site, (needle, _)) in sites.iter().zip(MAIN_EXITS) {
        assert!(
            site.contains(needle),
            "the exits of src/main.rs changed order or text: expected `{needle}` at:\n{site}"
        );
    }
    Ok(())
}

#[test]
fn every_exit_of_main_names_rows_that_exist() {
    for (needle, rows) in MAIN_EXITS {
        for name in rows {
            assert!(
                sipnab::early_exit::early_exit(name).is_some(),
                "`{needle}` leaves as `{name}`, which has no row in sipnab::early_exit"
            );
        }
    }
    for name in PARSER_EXITS {
        assert!(
            sipnab::early_exit::early_exit(name).is_some(),
            "the parser's exit `{name}` has no row in sipnab::early_exit"
        );
    }
}

#[test]
fn every_row_is_reached_from_an_exit_of_main() {
    let named: BTreeSet<&str> = MAIN_EXITS
        .iter()
        .flat_map(|(_, rows)| rows.iter().copied())
        .chain(PARSER_EXITS)
        .collect();
    for row in sipnab::early_exit::rows() {
        assert!(
            named.contains(row.name),
            "the row `{}` is left through no exit this census read",
            row.name
        );
    }
}

#[test]
fn the_startup_commands_are_the_ones_with_rows() -> Result<(), TestError> {
    let bootstrap = production("src/app/bootstrap.rs")?;
    let start = position(
        &bootstrap,
        "pub fn run_startup_commands(",
        "src/app/bootstrap.rs",
    )?;
    let body = &bootstrap[start..];
    let end = position(body, "\n}\n", "src/app/bootstrap.rs")?;
    assert_eq!(
        code_lines_with(&body[..end], "return Some("),
        8,
        "`run_startup_commands` returns for another number of commands than \
         the eight this census read (`--completions`, `--print-yang-module`, \
         `--setup-caps`, `--show-frame`, `--write-annotated`, the `--notes` \
         refusal, `--strip-secrets`, the file jobs). Give the new one a row \
         in sipnab::early_exit and a place in MAIN_EXITS."
    );
    let jobs = production("src/app/queries/b3.rs")?;
    let start = position(&jobs, "pub(super) fn startup(", "src/app/queries/b3.rs")?;
    let body = &jobs[start..];
    let end = position(body, "\n}\n", "src/app/queries/b3.rs")?;
    let dispatch: String = body[..end].split_whitespace().collect();
    assert!(
        dispatch.ends_with(
            "vcon_validate(cli).or_else(||compare_captures(cli)).or_else(||find_in_files(cli))"
        ),
        "the file jobs are no longer the three with rows (`--vcon-validate`, \
         `--compare-captures`, `--find-in-files`): {dispatch}"
    );
    Ok(())
}

#[test]
fn every_fleet_and_g729_command_has_a_row() -> Result<(), TestError> {
    for (rel, type_start, prefix, expected) in [
        (
            "src/cli/fleet_args.rs",
            "pub enum FleetCommand {",
            "fleet",
            vec!["Inventory", "Keygen", "Serve"],
        ),
        (
            "src/cli/g729_args.rs",
            "pub enum G729Command {",
            "g729",
            vec!["Install", "Status"],
        ),
    ] {
        let text = production(rel)?;
        let start = position(&text, type_start, rel)?;
        let body = &text[start..];
        let end = position(body, "\n}\n", rel)?;
        let variants: Vec<&str> = body[..end]
            .lines()
            .skip(1)
            .filter(|line| {
                line.starts_with("    ") && line[4..].starts_with(|c: char| c.is_ascii_uppercase())
            })
            .map(|line| {
                line.trim()
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .next()
                    .unwrap_or("")
            })
            .collect();
        assert_eq!(
            variants, expected,
            "{rel}: the commands of `sipnab {prefix}` changed; each needs a row in \
             sipnab::early_exit and a plan"
        );
        for variant in variants {
            let name = format!("{prefix} {}", variant.to_ascii_lowercase());
            assert!(
                sipnab::early_exit::early_exit(&name).is_some(),
                "`sipnab {name}` has no row in sipnab::early_exit"
            );
        }
    }
    Ok(())
}

#[test]
fn the_commands_that_still_parse_as_root_are_listed_with_their_backlog_entry()
-> Result<(), TestError> {
    use sipnab::early_exit::{PARSE_AS_ROOT_ENTRY, Plan, rows};
    let for_now: Vec<&str> = rows()
        .filter(|row| row.plan == Plan::KeepsForNow)
        .map(|row| row.name)
        .collect();
    assert_eq!(
        for_now, PARSE_AS_ROOT,
        "the commands that parse a named file as root changed. When a reader \
         takes an open handle and its command drops, remove it from both lists."
    );
    if !for_now.is_empty() {
        let table = production("src/early_exit.rs")?;
        assert!(
            table.contains(PARSE_AS_ROOT_ENTRY),
            "src/early_exit.rs no longer names the backlog entry its for-now rows wait for"
        );
        let page = std::fs::read_to_string(root().join("docs/least-privilege.md"))?;
        for name in for_now {
            assert!(
                page.contains(&format!("`{name}`")),
                "docs/least-privilege.md does not say that `{name}` still parses as root"
            );
            let row = sipnab::early_exit::early_exit(name).ok_or("row")?;
            assert!(
                row.reason.contains(PARSE_AS_ROOT_ENTRY),
                "the row `{name}` does not name {PARSE_AS_ROOT_ENTRY}"
            );
        }
    }
    Ok(())
}

/// For each row that drops in `early_exit::confine`: the file that carries
/// out its plan and the text that names the row there.
const CONFINE_SITES: [(&str, &str, &str); 7] = [
    ("fleet serve", "src/app/fleet_center.rs", "\"fleet serve\","),
    (
        "fleet inventory",
        "src/app/fleet.rs",
        "confine(\"fleet inventory\"",
    ),
    (
        "--vcon-forward",
        "src/app/bootstrap.rs",
        "confine_early_exit(cli, &loaded.config, \"--vcon-forward\"",
    ),
    (
        "--vcon-fetch",
        "src/app/bootstrap.rs",
        "confine_early_exit(cli, &loaded.config, \"--vcon-fetch\"",
    ),
    (
        "--vcon-audio-fetch",
        "src/app/bootstrap.rs",
        "confine_early_exit(cli, &loaded.config, \"--vcon-audio-fetch\"",
    ),
    (
        "--relay-holdings",
        "src/app/bootstrap.rs",
        "\"--relay-holdings\",",
    ),
    (
        "--relay-sessions",
        "src/app/bootstrap.rs",
        "\"--relay-sessions\",",
    ),
];

#[test]
fn every_row_that_drops_has_the_call_that_drops_it() -> Result<(), TestError> {
    let dropping: Vec<&str> = sipnab::early_exit::rows()
        .filter(|row| row.plan.drops_here())
        .map(|row| row.name)
        .collect();
    let sites: BTreeSet<&str> = CONFINE_SITES.iter().map(|(name, _, _)| *name).collect();
    assert_eq!(
        dropping.iter().copied().collect::<BTreeSet<_>>(),
        sites,
        "a row with a plan that drops has no call site this census read, or a site has no row"
    );
    for (name, rel, needle) in CONFINE_SITES {
        let text = production(rel)?;
        assert!(
            text.contains(needle),
            "{rel} no longer carries out the plan of `{name}` (`{needle}`)"
        );
    }
    let bootstrap = production("src/app/bootstrap.rs")?;
    assert!(
        bootstrap.contains("confine_early_exit(cli, config, flag, &[])"),
        "the relay listing no longer drops before it asks the relay"
    );
    Ok(())
}

#[test]
fn the_fleet_commands_drop_before_they_start_a_thread() -> Result<(), TestError> {
    let center = production("src/app/fleet_center.rs")?;
    let serve = &center[position(&center, "pub fn serve(", "src/app/fleet_center.rs")?..];
    assert!(
        position(serve, "match prepare(&args)", "src/app/fleet_center.rs")?
            < position(serve, "tokio::runtime::Builder", "src/app/fleet_center.rs")?,
        "`serve` must build its runtime after `prepare`, which drops"
    );
    let prepare = &center[position(&center, "\nfn prepare(", "src/app/fleet_center.rs")?..];
    let prepare = &prepare[..position(prepare, "\n}\n", "src/app/fleet_center.rs")?];
    let confine = position(prepare, "early_exit::confine(", "src/app/fleet_center.rs")?;
    assert!(
        position(prepare, "prepare_listener(", "src/app/fleet_center.rs")? < confine
            && position(prepare, "store_keys(args)", "src/app/fleet_center.rs")? < confine
            && position(prepare, "open_private_file(", "src/app/fleet_center.rs")? < confine,
        "the center reads its keys and binds before it drops"
    );
    assert!(
        confine < position(prepare, "Center::open(", "src/app/fleet_center.rs")?,
        "the center opens its store after it drops: a store opened before \
         would be created by root"
    );
    assert!(
        !starts_a_thread(prepare),
        "`prepare` starts a thread; the drop is no longer made by the only thread"
    );
    let fleet = production("src/app/fleet.rs")?;
    let main = &fleet[position(&fleet, "pub fn main(", "src/app/fleet.rs")?..];
    let confine = position(main, "early_exit::confine(", "src/app/fleet.rs")?;
    assert!(
        position(main, "map(read_files)", "src/app/fleet.rs")? < confine
            && confine < position(main, "std::thread::scope(", "src/app/fleet.rs")?,
        "`fleet inventory` reads every file, drops, then starts its request threads"
    );
    Ok(())
}

#[test]
fn an_exit_is_found_with_the_lines_above_it() {
    let sites = exit_sites(
        "fn main() {\n    // std::process::exit(9);\n    if let Some(code) = a() {\n\n        \
         release_run_and_exit(code);\n    }\n    b().exit();\n}\n",
    );
    assert_eq!(sites.len(), 2, "a comment is not an exit: {sites:?}");
    assert!(
        sites[0].contains("a()") && sites[1].contains("b().exit()"),
        "each exit carries the code above it: {sites:?}"
    );
}
