// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The checks and failure messages the how-to pages state, run against the
//! binary.
//!
//! `howto_sections_test.rs` holds each task page to a "Check that it worked"
//! and a "When something does not work" section. This file runs what those
//! sections say: each command a page gives as its check, and each message a
//! page quotes as a failure, against the same sample captures the page names.
//! A message whose wording changes in the code fails here until the page
//! changes with it.

// Every test runs the `sipnab` binary.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

const TRIAGE: &str = include_str!("../docs/first-cli-triage.md");
const WALKTHROUGH: &str = include_str!("../docs/tui-walkthrough.md");
const QUERIES: &str = include_str!("../docs/capture-queries.md");
const FOLLOW: &str = include_str!("../docs/follow-a-call.md");
const EXPECTATIONS: &str = include_str!("../docs/expectations.md");
const QUALITY: &str = include_str!("../docs/call-quality.md");
const INSTALL: &str = include_str!("../docs/install.md");
const INSTALLER: &str = include_str!("../website/static/install.sh");
const BOOTSTRAP: &str = include_str!("../src/app/bootstrap.rs");
const PRIVILEGE: &str = include_str!("../docs/least-privilege.md");
const PRIVILEGE_SOURCE: &str = include_str!("../src/privilege.rs");
const G729: &str = include_str!("../docs/g729.md");
const UPROBE: &str = include_str!("../docs/uprobe-walkthrough.md");
const TLS: &str = include_str!("../docs/tls-capture.md");
const TUNING: &str = include_str!("../docs/tuning-capture.md");
const LIVE: &str = include_str!("../src/capture/live.rs");
const THEME: &str = include_str!("../docs/theme-guide.md");
const SERVICE: &str = include_str!("../docs/run-as-a-service.md");
const REST: &str = include_str!("../docs/rest-api.md");
const MCP_DEPLOY: &str = include_str!("../docs/mcp-deploy.md");
const AUTH: &str = include_str!("../docs/auth.md");
const MCP: &str = include_str!("../docs/mcp.md");
const MCP_ESTATE: &str = include_str!("../docs/mcp-estate.md");
const INTEGRATIONS: &str = include_str!("../docs/integrations.md");
const FLEET: &str = include_str!("../docs/fleet.md");
const VCON: &str = include_str!("../docs/vcon.md");
const VCON_STORE: &str = include_str!("../docs/vcon-store.md");
const VCON_SIPNAB: &str = include_str!("../docs/vcon-sipnab.md");
const VCON_SERVER: &str = include_str!("../docs/vcon-server.md");
const VCON_HARNESS: &str = include_str!("../docs/vcon-harness.md");
const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const MANIFEST: &str = include_str!("../Cargo.toml");
const HARNESS_COMPOSE: &str = include_str!("../harness/docker-compose.yml");
const HARNESS_MAKEFILE: &str = include_str!("../harness/Makefile");
/// The two harness scripts the capture stack page names, by their paths from
/// the repository root. They are read when the test runs:
/// `every_cited_script_exists` resolves each script path a Rust file names
/// from the root, and a path relative to `tests/` would not resolve.
const HARNESS_SPEECH: &str = "harness/scripts/make-speech-pcaps.sh";
const HARNESS_E2E: &str = "harness/scripts/run-e2e.sh";

/// The troubleshooting heading of run-as-a-service.
const SERVICE_TROUBLESHOOT: &str = "## When the service does not start";

/// The troubleshooting heading of tls-capture.
const TLS_TROUBLESHOOT: &str = "## When decryption does not work";

const SAMPLE_CALL: &str = "website/static/demos/sample-call.pcap";
const PROBLEM_CALL: &str = "tests/pcap-samples/sip-problem-call.pcap";
const LOSSY_CALL: &str = "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap";
const SESSION_ID: &str = "tests/fixtures/session-id/opensips-4.0-th-session-id.pcap";

const CHECK: &str = "## Check that it worked";
const TROUBLESHOOT: &str = "## When something does not work";

// The TLS call the suite builds in code, with its keys: no capture checked in
// under `tests/` holds SIP over TLS.
#[cfg(feature = "tls")]
#[path = "support/encrypted_captures.rs"]
mod encrypted_captures;
#[cfg(feature = "tls")]
#[path = "support/pcap_build.rs"]
mod pcap_build;

// A REST API server started on a port the kernel picks, for the pages whose
// check sends a request.
#[cfg(all(unix, feature = "api"))]
#[path = "support/server.rs"]
mod server;

// The HTTP client and session helpers of the MCP tests, for the estate page
// whose check asks an MCP server over HTTP which HEP senders it admitted.
#[cfg(all(unix, feature = "mcp-http", feature = "hep"))]
#[path = "support/mcp.rs"]
mod mcp;

// A TCP port that refuses connections, for the pages that quote what the
// forwarder logs when nothing listens at the URL.
#[cfg(all(unix, feature = "vcon"))]
#[path = "support/ports.rs"]
mod ports;

// A `sipnab fleet serve` that ends with the test, for the fleet page's
// statements about a build without the history store.
#[cfg(all(unix, feature = "api", not(feature = "fleet-store")))]
#[path = "support/fleet_center.rs"]
mod fleet_center;

// `tied_to_test`, so that a server a test starts ends with the test.
include!("support/child_lifetime.rs");

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Runs sipnab from the repository root with no terminal and no config file.
fn sipnab(args: &[&str]) -> Result<Output, TestError> {
    sipnab_in(repo(), args)
}

fn sipnab_in(dir: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", dir.join("no-such-config-dir"))
        .stdin(Stdio::null())
        .output()?)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The JSON objects sipnab printed, one per line.
fn json_lines(output: &Output) -> Result<Vec<serde_json::Value>, TestError> {
    stdout(output)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

/// The text of the section of `doc` under the heading line `heading`, up to
/// the next heading of the same or a higher level.
fn section<'a>(doc: &'a str, heading: &str) -> Result<&'a str, TestError> {
    let level = heading.chars().take_while(|c| *c == '#').count();
    let at = doc
        .find(&format!("\n{heading}\n"))
        .ok_or_else(|| format!("no heading {heading:?}"))?;
    let body = doc
        .get(at + heading.len() + 2..)
        .ok_or("heading at the end")?;
    let end = body
        .match_indices("\n#")
        .find(|(index, _)| {
            body.get(index + 1..)
                .map(|rest| rest.chars().take_while(|c| *c == '#').count())
                .is_some_and(|hashes| hashes <= level)
        })
        .map_or(body.len(), |(index, _)| index);
    body.get(..end).ok_or_else(|| "section range".into())
}

/// A capture's path under the repository, checked to exist.
fn capture(relative: &str) -> Result<PathBuf, TestError> {
    let path = repo().join(relative);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("{relative} is not in the repository").into())
    }
}

/// Fails unless a page's section still holds `text`.
fn page_says(section_text: &str, text: &str, page: &str) {
    assert!(
        section_text.contains(text),
        "{page} no longer says {text:?}, which this test runs against the binary"
    );
}

/// Fails unless what sipnab printed holds `text`.
fn printed(output: &str, text: &str) {
    assert!(
        output.contains(text),
        "sipnab did not print {text:?}; it printed:\n{output}"
    );
}

/// Fails unless the run ended with `status`.
fn exited(run: &Output, status: i32) {
    assert_eq!(
        run.status.code(),
        Some(status),
        "the page states exit status {status}; stderr:\n{}",
        stderr(run)
    );
}

// --- docs/first-cli-triage.md ----------------------------------------------

#[test]
fn the_triage_check_counts_the_seven_dialogs_of_the_sample() -> Result<(), TestError> {
    capture(SAMPLE_CALL)?;
    let check = section(TRIAGE, CHECK)?;
    page_says(
        check,
        "--json-dialogs --no-cli-print | jq -s length",
        "first-cli-triage",
    );
    page_says(check, "```text\n7\n```", "first-cli-triage");
    let run = sipnab(&["-N", "-I", SAMPLE_CALL, "--json-dialogs", "--no-cli-print"])?;
    exited(&run, 0);
    let dialogs = json_lines(&run)?.len();
    assert_eq!(dialogs, 7, "the page says the sample holds seven dialogs");
    Ok(())
}

#[test]
fn the_triage_check_quotes_the_totals_line_sipnab_prints() -> Result<(), TestError> {
    let totals = "sipnab: 633 packets captured, 33 SIP messages, 600 RTP packets across 2 streams";
    page_says(section(TRIAGE, CHECK)?, totals, "first-cli-triage");
    let run = sipnab(&["-N", "-I", SAMPLE_CALL, "--json-dialogs", "--no-cli-print"])?;
    printed(&stderr(&run), totals);
    Ok(())
}

#[test]
fn a_capture_that_is_not_there_gives_the_message_the_pages_quote() -> Result<(), TestError> {
    let message = "-I/--input: 'sample-call.pcap' does not exist";
    page_says(section(TRIAGE, TROUBLESHOOT)?, message, "first-cli-triage");
    page_says(
        section(WALKTHROUGH, TROUBLESHOOT)?,
        message,
        "tui-walkthrough",
    );
    let dir = tempfile::tempdir()?;
    let run = sipnab_in(dir.path(), &["-N", "-I", "sample-call.pcap", "--report"])?;
    exited(&run, 1);
    printed(&stderr(&run), message);
    Ok(())
}

#[test]
fn a_file_that_is_not_a_capture_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    let message = "-I/--input: cannot read capture 'sample-call.pcap' named with -I: \
                   Failed to open pcap file 'sample-call.pcap': libpcap error: unknown file format";
    page_says(section(TRIAGE, TROUBLESHOOT)?, message, "first-cli-triage");
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("sample-call.pcap"), "<!DOCTYPE html>\n")?;
    let run = sipnab_in(dir.path(), &["-N", "-I", "sample-call.pcap", "--report"])?;
    exited(&run, 1);
    printed(&stderr(&run), message);
    Ok(())
}

#[test]
fn a_call_id_the_capture_lacks_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    let message = "Call-ID 'nosuch@example.com' not found in tracked dialogs";
    page_says(section(TRIAGE, TROUBLESHOOT)?, message, "first-cli-triage");
    let run = sipnab(&[
        "-N",
        "-I",
        SAMPLE_CALL,
        "--call-report",
        "nosuch@example.com",
        "--no-cli-print",
    ])?;
    exited(&run, 1);
    printed(&stderr(&run), message);
    Ok(())
}

#[test]
fn json_dialogs_without_no_cli_print_is_not_json_alone() -> Result<(), TestError> {
    // The page says jq reports a parse error because sipnab printed the
    // per-message lines among the JSON. The first line of such a run is a
    // message line.
    page_says(
        section(TRIAGE, TROUBLESHOOT)?,
        "Add `--no-cli-print`",
        "first-cli-triage",
    );
    let run = sipnab(&["-N", "-I", SAMPLE_CALL, "--json-dialogs"])?;
    let out = stdout(&run);
    let first = out.lines().next().ok_or("no output")?;
    assert!(
        serde_json::from_str::<serde_json::Value>(first).is_err(),
        "the first line parses as JSON, so jq would not fail on it: {first}"
    );
    printed(first, "REGISTER");
    Ok(())
}

#[test]
fn problems_on_the_clean_sample_prints_a_header_and_no_rows() -> Result<(), TestError> {
    page_says(
        section(TRIAGE, TROUBLESHOOT)?,
        "**The `--problems` table has a header and no rows.**",
        "first-cli-triage",
    );
    let run = sipnab(&[
        "-N",
        "-I",
        SAMPLE_CALL,
        "--problems",
        "--report",
        "--no-cli-print",
    ])?;
    exited(&run, 0);
    let out = stdout(&run);
    let lines: Vec<&str> = out.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "a header and its rule, no rows; output:\n{out}"
    );
    printed(lines.first().copied().unwrap_or_default(), "Call-ID");
    Ok(())
}

// --- docs/tui-walkthrough.md -----------------------------------------------

#[test]
fn the_walkthrough_requires_the_terminal_ui_feature() -> Result<(), TestError> {
    // Checked in every build, so the build without `tui` still reads the
    // page: the message test below needs the feature the page requires.
    page_says(
        section(WALKTHROUGH, "## Before you start")?,
        "**sipnab with the `tui` feature**",
        "tui-walkthrough",
    );
    Ok(())
}

// Only a build with `tui` has an interface that can fail to start. CI's
// feature matrix also builds sipnab without it: there `sipnab -I <file>`
// with no `-N` is the run `sipnab -N -I <file>` is, which the two tests after
// this one hold (NO-TUI-BUILD-SILENT).
#[cfg(feature = "tui")]
#[test]
fn the_terminal_ui_without_a_terminal_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    let troubleshoot = section(WALKTHROUGH, TROUBLESHOOT)?;
    let message = "sipnab: the terminal UI could not start: No such device or address \
                   (os error 6). It needs a terminal; add -N for a run without one.";
    page_says(troubleshoot, message, "tui-walkthrough");
    page_says(troubleshoot, "exited with status 1", "tui-walkthrough");
    // The test harness gives the child no terminal on its input. The page
    // quotes the Linux wording of the system error; the part sipnab words is
    // the same on every system.
    let run = sipnab(&["-I", SAMPLE_CALL])?;
    exited(&run, 1);
    let err = stderr(&run);
    printed(&err, "sipnab: the terminal UI could not start: ");
    printed(&err, "It needs a terminal; add -N for a run without one.");
    if cfg!(target_os = "linux") {
        printed(&err, message);
    }
    Ok(())
}

/// A build without `tui` has no terminal UI to start, so a run with no `-N`
/// reads the capture as a run with `-N` does: the same lines on standard
/// output, exit status 0. The build with the features
/// native,hep,api,mcp,mcp-http printed nothing and exited 0.
#[cfg(not(feature = "tui"))]
#[test]
fn a_build_without_the_terminal_ui_reads_a_capture_as_no_tui_does() -> Result<(), TestError> {
    capture(SAMPLE_CALL)?;
    let plain = sipnab(&["-I", SAMPLE_CALL])?;
    let headless = sipnab(&["-N", "-I", SAMPLE_CALL])?;
    exited(&headless, 0);
    exited(&plain, 0);
    let expected = stdout(&headless);
    assert!(
        expected.lines().count() > 1,
        "-N prints a line per SIP message and a totals line; it printed:\n{expected}"
    );
    assert_eq!(
        stdout(&plain),
        expected,
        "without -N a build with no terminal UI prints what -N prints; stderr:\n{}",
        stderr(&plain)
    );
    Ok(())
}

/// The same for an output flag: a build with `tui` refuses `--json` without
/// `-N`, because the terminal UI owns the screen. A build without `tui` has
/// nothing that owns it, so the flag needs no `-N`.
#[cfg(not(feature = "tui"))]
#[test]
fn a_build_without_the_terminal_ui_takes_an_output_flag_without_no_tui() -> Result<(), TestError> {
    let plain = sipnab(&["-I", SAMPLE_CALL, "--json"])?;
    let headless = sipnab(&["-N", "-I", SAMPLE_CALL, "--json"])?;
    exited(&headless, 0);
    exited(&plain, 0);
    let lines = json_lines(&plain)?;
    assert!(
        !lines.is_empty(),
        "--json prints an object per SIP message; stderr:\n{}",
        stderr(&plain)
    );
    assert_eq!(
        lines,
        json_lines(&headless)?,
        "without -N a build with no terminal UI prints the objects -N prints"
    );
    Ok(())
}

#[test]
fn the_walkthrough_check_shows_the_dialogs_the_sample_holds() -> Result<(), TestError> {
    // The screen itself needs a terminal, so the page's sample is checked
    // against the same capture read without one: seven dialogs, and each
    // row's state and message count.
    let check = section(WALKTHROUGH, CHECK)?;
    page_says(check, "Dialogs: 7 shown of 7", "tui-walkthrough");
    let run = sipnab(&["-N", "-I", SAMPLE_CALL, "--json-dialogs", "--no-cli-print"])?;
    let dialogs = json_lines(&run)?;
    assert_eq!(dialogs.len(), 7, "the page shows seven dialogs");
    let rows: Vec<&str> = check.lines().filter(|line| line.contains("[ ]")).collect();
    assert_eq!(rows.len(), 7, "the page's sample has one row per dialog");
    for dialog in &dialogs {
        let state = dialog
            .get("state")
            .and_then(|v| v.as_str())
            .ok_or("no state")?;
        let messages = dialog
            .get("msg_count")
            .and_then(serde_json::Value::as_u64)
            .ok_or("no msg_count")?
            .to_string();
        assert!(
            rows.iter().any(|row| {
                let cells: Vec<&str> = row.split_whitespace().collect();
                cells.contains(&state) && cells.contains(&messages.as_str())
            }),
            "the page has no row for a dialog in state {state} with {messages} messages"
        );
    }
    Ok(())
}

// --- docs/capture-queries.md -----------------------------------------------

#[test]
fn the_query_check_total_equals_the_dialog_count() -> Result<(), TestError> {
    capture(PROBLEM_CALL)?;
    let check = section(QUERIES, CHECK)?;
    assert_eq!(
        check.matches("```text\n5\n```").count(),
        2,
        "capture-queries states 5 for the query total and 5 for the dialogs"
    );
    let query = sipnab(&[
        "-I",
        PROBLEM_CALL,
        "--count-by",
        "response_code",
        "--json",
        "--no-cli-print",
        "--quiet",
    ])?;
    exited(&query, 0);
    let answer: serde_json::Value = serde_json::from_str(stdout(&query).trim())?;
    assert_eq!(
        answer
            .get("total_matched")
            .and_then(serde_json::Value::as_u64),
        Some(5),
        "total_matched of the query the page runs"
    );
    let dialogs = sipnab(&[
        "-N",
        "-I",
        PROBLEM_CALL,
        "--json-dialogs",
        "--no-cli-print",
        "--quiet",
    ])?;
    let count = json_lines(&dialogs)?.len();
    assert_eq!(count, 5, "the dialogs the page counts with jq -s length");
    Ok(())
}

// --- docs/follow-a-call.md -------------------------------------------------

#[test]
fn the_follow_check_shows_what_correlate_prints() -> Result<(), TestError> {
    capture(SESSION_ID)?;
    let check = section(FOLLOW, CHECK)?;
    let run = sipnab(&[
        "-I",
        SESSION_ID,
        "--correlate",
        "1-sid-call@example.com",
        "--no-cli-print",
        "--quiet",
    ])?;
    exited(&run, 0);
    let out = stdout(&run);
    assert!(
        out.lines().count() >= 4,
        "a count line, a header, a rule and one leg; output:\n{out}"
    );
    // The `TH` column says whether sipnab decoded a topology-hiding Call-ID,
    // which needs the `tls` feature. A build without it prints `-` there, and
    // the page says so.
    let no_tls = "A build without the `tls` feature prints `-` in the `TH` column.";
    page_says(check, no_tls, "follow-a-call");
    for line in out.lines() {
        let line = line.trim_end();
        if cfg!(feature = "tls") || !line.starts_with("DLGCH_") {
            page_says(check, line, "follow-a-call");
        } else {
            let stem = line.strip_suffix('-').ok_or_else(|| {
                format!("without tls the TH column was expected to read `-`: {line}")
            })?;
            page_says(check, &format!("{stem}no_secret"), "follow-a-call");
        }
    }
    Ok(())
}

// --- docs/expectations.md --------------------------------------------------

#[test]
fn the_expectations_check_states_the_exit_status_of_the_sample_suite() -> Result<(), TestError> {
    let check = section(EXPECTATIONS, "### Check that it worked")?;
    page_says(check, "```text\n3\n```", "expectations");
    let run = sipnab(&[
        "-I",
        PROBLEM_CALL,
        "--expect",
        "tests/fixtures/expect/sip-problem-call.expect.toml",
        "--no-cli-print",
        "--quiet",
    ])?;
    exited(&run, 3);
    printed(&stdout(&run), "Expectations: fail");
    Ok(())
}

// --- docs/call-quality.md --------------------------------------------------

/// (streams, streams with a `mos`) over every dialog of a capture.
fn scored(capture_path: &str) -> Result<(usize, usize), TestError> {
    capture(capture_path)?;
    let run = sipnab(&["-N", "-I", capture_path, "--json-dialogs", "--no-cli-print"])?;
    let mut streams = 0;
    let mut with_mos = 0;
    for dialog in json_lines(&run)? {
        for stream in dialog
            .get("streams")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            streams += 1;
            if stream.get("mos").is_some_and(|mos| !mos.is_null()) {
                with_mos += 1;
            }
        }
    }
    Ok((streams, with_mos))
}

#[test]
fn the_quality_check_counts_three_scored_streams() -> Result<(), TestError> {
    page_says(
        section(QUALITY, CHECK)?,
        "{\"streams\":3,\"scored\":3}",
        "call-quality",
    );
    let counts = scored(LOSSY_CALL)?;
    assert_eq!(counts, (3, 3), "(streams, scored) of {LOSSY_CALL}");
    Ok(())
}

#[test]
fn the_quality_check_names_a_capture_with_no_media() -> Result<(), TestError> {
    let check = section(QUALITY, CHECK)?;
    page_says(check, "{\"streams\":0,\"scored\":0}", "call-quality");
    page_says(check, PROBLEM_CALL, "call-quality");
    let counts = scored(PROBLEM_CALL)?;
    assert_eq!(counts, (0, 0), "(streams, scored) of {PROBLEM_CALL}");
    Ok(())
}

// --- docs/install.md -------------------------------------------------------

#[test]
fn the_install_page_quotes_the_permission_message_of_the_code() -> Result<(), TestError> {
    // Opening a device as an unprivileged user cannot be driven here: the
    // test may run as root, and a runner may have no device. The page is held
    // to the text `capture_open_failure` formats instead.
    let troubleshoot = section(INSTALL, TROUBLESHOOT)?;
    let source = BOOTSTRAP.split_whitespace().collect::<Vec<_>>().join(" ");
    printed(
        &source,
        "\"Permission denied on '{target}'. Grant capture capabilities once \\ (Linux), then re-run without sudo:\\n",
    );
    // The code words other causes too (a container, NoNewPrivs, the bounding
    // set). The install page quotes the general one and sends the reader to
    // the section that lists the rest.
    page_says(
        troubleshoot,
        "(troubleshooting.md#live-capture-says-permission-denied)",
        "install",
    );
    page_says(
        troubleshoot,
        "**`Permission denied on 'eth0'. Grant capture capabilities once (Linux), then re-run without sudo:`**",
        "install",
    );
    printed(&source, "sipnab --setup-caps\\n");
    page_says(troubleshoot, "`sipnab --setup-caps`", "install");
    Ok(())
}

#[test]
fn the_install_prerequisites_name_what_the_installer_requires() -> Result<(), TestError> {
    let before = section(INSTALL, "## Before you start")?;
    for (in_script, on_page) in [
        ("err \"curl is required\"", "`curl`"),
        ("err \"tar is required\"", "`tar`"),
        ("sha256sum", "`sha256sum`"),
        ("shasum", "`shasum`"),
        ("https://sipnab.com/install.sh", "`sipnab.com`"),
        ("https://api.github.com/repos/", "`api.github.com`"),
        (
            "https://github.com/${SIPNAB_REPO}/releases/download/",
            "`github.com`",
        ),
    ] {
        assert!(
            INSTALLER.contains(in_script),
            "install.sh no longer has {in_script}: re-read what it requires"
        );
        page_says(before, on_page, "install");
    }
    Ok(())
}

#[test]
fn the_install_page_says_what_the_installer_does_without_libpcap() -> Result<(), TestError> {
    // Since OPS batch 4 the installer looks for libpcap.so.0.8 and installs
    // the static musl build when the host has none. The prerequisites said
    // libpcap was required, and the troubleshooting entry named a Fedora
    // package that does not provide that library.
    for in_script in [
        "SIPNAB_GNU_PCAP_SONAME=\"libpcap.so.0.8\"",
        "$SIPNAB_GNU_PCAP_SONAME not found — using the static musl build",
        "libpcap0.8t64 (Debian 13, Ubuntu 24.04) or libpcap0.8 (Debian 12)",
        "on Fedora or RHEL install the .rpm package instead",
    ] {
        printed(INSTALLER, in_script);
    }
    let before = section(INSTALL, "## Before you start")?;
    page_says(before, "`libpcap.so.0.8`", "install");
    page_says(before, "static musl build", "install");
    let troubleshoot = section(INSTALL, TROUBLESHOOT)?;
    page_says(
        troubleshoot,
        "`libpcap0.8t64` (Debian 13, Ubuntu 24.04) or `libpcap0.8` (Debian 12)",
        "install",
    );
    for page_text in [before, troubleshoot] {
        assert!(
            !page_text.contains("`libpcap` (Fedora"),
            "Fedora and RHEL have no package that provides libpcap.so.0.8; \
             the page must not name one as the fix"
        );
    }
    Ok(())
}

#[test]
fn the_install_page_names_every_host_the_installer_contacts() -> Result<(), TestError> {
    // A host added to the script is a firewall change the page must state.
    let before = section(INSTALL, "## Before you start")?;
    let mut hosts: Vec<&str> = INSTALLER
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(|line| line.split("https://").skip(1))
        .filter_map(|rest| rest.split(['/', '"', '$', ' ']).next())
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    assert_eq!(
        hosts,
        vec!["api.github.com", "github.com"],
        "the hosts install.sh contacts changed: state the new ones under Before you start"
    );
    for host in hosts {
        page_says(before, &format!("`{host}`"), "install");
    }
    Ok(())
}

#[test]
fn the_install_troubleshooting_points_at_the_installer_table() -> Result<(), TestError> {
    let troubleshoot = section(INSTALL, TROUBLESHOOT)?;
    page_says(troubleshoot, "`sipnab-install: error:`", "install");
    printed(INSTALLER, "printf 'sipnab-install: error: %s\\n'");
    page_says(troubleshoot, "libpcap.so.0.8", "install");
    Ok(())
}

// --- docs/least-privilege.md -----------------------------------------------

#[test]
fn the_least_privilege_check_quotes_the_log_lines_of_the_code() -> Result<(), TestError> {
    // Dropping root cannot be driven here: a test does not run as root. The
    // page's check was run in a container (see the page); this holds its
    // quoted lines to the text `src/privilege.rs` formats.
    let check = section(PRIVILEGE, CHECK)?;
    for (in_source, on_page) in [
        (
            "\"Dropped privileges to user '{}' (uid={}, gid={})\"",
            "Dropped privileges to user 'nobody' (uid=65534, gid=65534)",
        ),
        ("\"Chrooted to {}\"", "Chrooted to /var/lib/sipnab/jail"),
        (
            "\"Privilege drop disabled (--no-priv-drop)\"",
            "Privilege drop disabled (--no-priv-drop)",
        ),
    ] {
        printed(PRIVILEGE_SOURCE, in_source);
        page_says(check, on_page, "least-privilege");
    }
    Ok(())
}

#[test]
fn the_least_privilege_check_reads_the_ids_and_capabilities_of_the_process() -> Result<(), TestError>
{
    let check = section(PRIVILEGE, CHECK)?;
    page_says(
        check,
        "grep -E '^(Uid|Gid|CapEff):' \"/proc/$(pidof sipnab)/status\"",
        "least-privilege",
    );
    // What the dropped run printed in the container, and what a run that
    // kept root printed.
    page_says(check, "Uid:\t65534\t65534\t65534\t65534", "least-privilege");
    page_says(check, "CapEff:\t0000000000000000", "least-privilege");
    page_says(check, "Uid:\t0\t0\t0\t0", "least-privilege");
    Ok(())
}

#[test]
fn the_least_privilege_prerequisites_say_which_system_changes() -> Result<(), TestError> {
    let before = section(PRIVILEGE, "## Before you start")?;
    page_says(before, "`setcap`", "least-privilege");
    page_says(before, "Nothing on any other system", "least-privilege");
    // `--setup-caps` runs setcap with the capabilities the page names.
    printed(BOOTSTRAP, "cap_net_raw,cap_net_admin+ep");
    Ok(())
}

// --- docs/g729.md ----------------------------------------------------------

/// Runs sipnab with `home` as `$HOME` and `$XDG_CONFIG_HOME`, so the default
/// table file is `home/sipnab/g729-tables.bin`.
#[cfg(feature = "g729")]
fn sipnab_at_home(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .current_dir(repo())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("SIPNAB_CONFIG")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()?)
}

#[cfg(feature = "g729")]
const G729_CALL: &str = "tests/pcap-samples/sip-rtp-g729a.pcap";

#[cfg(feature = "g729")]
#[test]
fn the_g729_check_says_not_installed_and_exits_1_without_tables() -> Result<(), TestError> {
    let check = section(G729, "## Check that sipnab finds the tables")?;
    let home = tempfile::tempdir()?;
    let run = sipnab_at_home(home.path(), &["g729", "status"])?;
    exited(&run, 1);
    for line in [
        "G.729 tables: not installed",
        "G.729 not decoded: codebook tables not installed; run sipnab g729 install",
    ] {
        printed(&stdout(&run), line);
        page_says(check, line, "g729");
    }
    page_says(check, "exits 0", "g729");
    page_says(check, "1 when it does not", "g729");
    Ok(())
}

#[cfg(feature = "g729")]
#[test]
fn the_g729_export_without_tables_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    capture(G729_CALL)?;
    let troubleshoot = section(G729, "## When a run does not find the tables")?;
    let home = tempfile::tempdir()?;
    let out = home.path().join("call.wav");
    let out_arg = out.to_str().ok_or("a UTF-8 path")?;
    let run = sipnab_at_home(
        home.path(),
        &[
            "-N",
            "-q",
            "--no-cli-print",
            "-I",
            G729_CALL,
            "--export-audio",
            "1-24411@10.0.2.20",
            "--export-audio-out",
            out_arg,
        ],
    )?;
    exited(&run, 1);
    let message =
        "--export-audio: No stream on this call carries a codec that decodes to WAV (found: G729).";
    printed(&stderr(&run), message);
    page_says(troubleshoot, message, "g729");
    assert!(!out.exists(), "no WAV file is written without the tables");
    Ok(())
}

#[cfg(feature = "g729")]
#[test]
fn the_g729_check_exports_the_sample_call_with_tables_installed() -> Result<(), TestError> {
    capture(G729_CALL)?;
    let check = section(G729, "## Check that sipnab finds the tables")?;
    let package = repo().join("crates/g729/test-vectors/itu-source");
    if !package.is_dir() {
        return Err(
            "the ITU-T G.729 package is not fetched: run `python3 scripts/fetch-g729-vectors.py`"
                .into(),
        );
    }
    let home = tempfile::tempdir()?;
    let package = package.to_str().ok_or("a UTF-8 path")?;
    let install = sipnab_at_home(
        home.path(),
        &["g729", "install", "--yes", "--no-config", "--from", package],
    )?;
    exited(&install, 0);
    let status = sipnab_at_home(home.path(), &["g729", "status"])?;
    exited(&status, 0);
    printed(&stdout(&status), "G.729 tables: installed");
    page_says(check, "`G.729 tables: installed`", "g729");

    let out = home.path().join("call.wav");
    let out_arg = out.to_str().ok_or("a UTF-8 path")?;
    let export = sipnab_at_home(
        home.path(),
        &[
            "-N",
            "-q",
            "--no-cli-print",
            "-I",
            G729_CALL,
            "--export-audio",
            "1-24411@10.0.2.20",
            "--export-audio-out",
            out_arg,
        ],
    )?;
    exited(&export, 0);
    let said = "Exported 8.5s of G.729 audio (425 frames, G729/8000Hz)";
    let both = format!("{}{}", stdout(&export), stderr(&export));
    printed(&both, said);
    page_says(check, said, "g729");
    page_says(check, "--export-audio 1-24411@10.0.2.20", "g729");
    assert!(out.is_file(), "the export writes the WAV file it names");
    Ok(())
}

#[test]
fn the_g729_prerequisites_name_the_download_host_and_the_feature() -> Result<(), TestError> {
    let before = section(G729, "## Before you start")?;
    page_says(before, "`g729`", "g729");
    page_says(
        before,
        "HTTPS access from the host to `www.itu.int`",
        "g729",
    );
    page_says(before, "other system", "g729");
    // The page's own quoted notice names the same host.
    printed(G729, "Source: https://www.itu.int/rec/dologin_pub.asp");
    Ok(())
}

// --- docs/uprobe-walkthrough.md --------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn the_uprobe_check_lists_libraries_or_says_none_is_mapped() -> Result<(), TestError> {
    // `--uprobe-list` installs nothing and needs no privilege. Attaching a
    // probe needs root and a process that speaks TLS, so the capture itself
    // is not run here.
    let check = section(UPROBE, CHECK)?;
    let header = "FLAVOR        INODE  PIDS  LIBRARY";
    let none = "No TLS library is mapped by any process sipnab can see.";
    page_says(check, "sipnab --uprobe-list", "uprobe-walkthrough");
    page_says(check, header, "uprobe-walkthrough");
    printed(UPROBE, none);
    let run = sipnab(&["--uprobe-list"])?;
    exited(&run, 0);
    let listed = stdout(&run);
    assert!(
        listed.starts_with(header) || listed.contains(none),
        "--uprobe-list printed neither the table nor the empty answer:\n{listed}"
    );
    Ok(())
}

#[test]
fn the_uprobe_check_quotes_the_mark_the_code_prints() -> Result<(), TestError> {
    let check = section(UPROBE, CHECK)?;
    page_says(check, "origin=uprobe", "uprobe-walkthrough");
    printed(
        include_str!("../src/capture/parse.rs"),
        "Self::Uprobe => Some(\" origin=uprobe\")",
    );
    Ok(())
}

#[test]
fn the_uprobe_prerequisites_say_which_system_changes() -> Result<(), TestError> {
    let before = section(UPROBE, "## Before you start")?;
    page_says(
        before,
        "(#can-your-system-run-this-at-all)",
        "uprobe-walkthrough",
    );
    page_says(before, "Nothing on any other system", "uprobe-walkthrough");
    page_says(before, "root", "uprobe-walkthrough");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn the_uprobe_capture_without_root_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    // Run only when the test is not root: as root this would attach probes
    // to the processes of the machine the suite runs on.
    let uid = std::fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next().map(str::to_owned))
        .ok_or("no Uid line in /proc/self/status")?;
    let message = "Permission denied attaching TLS probes (--uprobe-tls).";
    page_says(
        section(UPROBE, "## Troubleshooting")?,
        message,
        "uprobe-walkthrough",
    );
    if uid == "0" {
        return Ok(());
    }
    let listing = sipnab(&["--uprobe-list"])?;
    if !stdout(&listing).starts_with("FLAVOR") {
        // No library to probe: the run stops earlier, with another message.
        return Ok(());
    }
    let run = sipnab(&["-N", "--uprobe-tls", "--duration", "1"])?;
    exited(&run, 1);
    printed(&stderr(&run), message);
    printed(&stderr(&run), "sudo sipnab -N --uprobe-tls");
    assert!(
        !stderr(&run).contains("\n  sipnab --setup-caps"),
        "--setup-caps grants interface capture rights and cannot attach a probe: {}",
        stderr(&run)
    );
    Ok(())
}

// ── tls-capture ──────────────────────────────────────────────────────────

/// The TLS call of the suite and its key log, written under `dir`.
#[cfg(feature = "tls")]
fn tls_call(dir: &Path) -> Result<(String, String), TestError> {
    let capture = dir.join("tls-capture.pcap");
    let keys = dir.join("sip-keys.log");
    pcap_build::write_pcap(&capture, &encrypted_captures::tls_session_frames()?)?;
    std::fs::write(&keys, encrypted_captures::tls_keylog())?;
    Ok((capture.display().to_string(), keys.display().to_string()))
}

/// With the keys, the check of the page prints each decrypted message on a
/// line that ends in `TLS`, logs `TLS session decrypted` and counts the two
/// SIP messages of the call.
#[cfg(feature = "tls")]
#[test]
fn the_tls_check_shows_the_decrypted_messages_and_the_log_line() -> Result<(), TestError> {
    let check = section(TLS, CHECK)?;
    page_says(
        check,
        "sipnab -N -I tls-capture.pcap --keylog /tmp/sip-keys.log",
        "tls-capture",
    );
    for quoted in ["INVITE TLS", "TLS session decrypted", "2 SIP messages"] {
        page_says(check, quoted, "tls-capture");
    }
    let dir = tempfile::tempdir()?;
    let (capture, keys) = tls_call(dir.path())?;
    let run = sipnab(&["-N", "-I", &capture, "--keylog", &keys])?;
    exited(&run, 0);
    let lines: Vec<String> = stdout(&run).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 2, "an INVITE and a 180: {lines:?}");
    assert!(lines[0].ends_with(" INVITE TLS"), "{lines:?}");
    assert!(lines[1].ends_with(" 180 Ringing TLS"), "{lines:?}");
    printed(&stderr(&run), "TLS session decrypted");
    printed(&stderr(&run), "2 SIP messages");
    Ok(())
}

/// What a run with no TLS key prints about the two application-data records
/// of the test call. The page quotes it and the binary prints it.
#[cfg(feature = "tls")]
const NO_TLS_KEY: &str = "This capture holds at least 2 TLS application-data record(s) and this \
                          run was given no TLS key";

/// Without a TLS key sipnab decrypts no record: the run prints no message
/// line, counts the records it saw and names the flag that reads them. It
/// does not print the sentence of a capture that holds no SIP.
#[cfg(feature = "tls")]
#[test]
fn a_tls_capture_read_without_keys_names_the_records_and_the_flag() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (capture, _) = tls_call(dir.path())?;
    let run = sipnab(&["-N", "-I", &capture])?;
    exited(&run, 0);
    assert_eq!(stdout(&run), "", "nothing decrypted, so no message line");
    let printed_text = stderr(&run);
    printed(&printed_text, "0 SIP messages");
    printed(&printed_text, NO_TLS_KEY);
    printed(
        &printed_text,
        "this is not a finding that the capture contains no SIP",
    );
    printed(&printed_text, "--keylog keys.log");
    assert!(
        !printed_text.contains("No SIP traffic found."),
        "a capture with unread TLS records is not reported as holding no SIP:\n{printed_text}"
    );
    assert!(
        !printed_text.contains("--hexdump"),
        "the hexdump tip belongs to a capture with no TLS record:\n{printed_text}"
    );
    Ok(())
}

/// The troubleshooting table of the page quotes the message of a run with no
/// TLS key, in the words `a_tls_capture_read_without_keys_names_the_records_and_the_flag`
/// reads from the binary.
#[cfg(feature = "tls")]
#[test]
fn the_tls_page_quotes_the_message_of_a_run_without_keys() -> Result<(), TestError> {
    let table = section(TLS, TLS_TROUBLESHOOT)?;
    page_says(table, NO_TLS_KEY, "tls-capture");
    page_says(table, "0 SIP messages", "tls-capture");
    assert!(
        !table.contains("No SIP traffic found."),
        "the page still quotes the sentence a run without a TLS key no longer prints"
    );
    Ok(())
}

/// A capture with no TLS record and no SIP still gets the plain sentence:
/// the count of records is what selects the other message. Gated on `tls`
/// because the capture builder is compiled with that feature.
#[cfg(feature = "tls")]
#[test]
fn a_capture_with_no_tls_record_and_no_sip_keeps_the_plain_sentence() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let capture = dir.path().join("empty.pcap");
    pcap_build::write_pcap(&capture, &[])?;
    let run = sipnab(&["-N", "-I", &capture.display().to_string()])?;
    exited(&run, 0);
    let printed_text = stderr(&run);
    printed(&printed_text, "No SIP traffic found.");
    assert!(
        !printed_text.contains("TLS application-data"),
        "no TLS record is in the capture:\n{printed_text}"
    );
    Ok(())
}

/// A key log with no key line in it: sipnab counts the records it could not
/// read and says so in the words the page quotes.
#[cfg(feature = "tls")]
#[test]
fn a_key_log_with_no_key_line_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    let message = "sipnab could not decrypt 2 TLS application-data record(s): \
                   it holds no key material for any session in this capture";
    page_says(section(TLS, TLS_TROUBLESHOOT)?, message, "tls-capture");
    let dir = tempfile::tempdir()?;
    let (capture, _) = tls_call(dir.path())?;
    let empty = dir.path().join("empty-keys.log");
    std::fs::write(&empty, "# no key line\n")?;
    let run = sipnab(&[
        "-N",
        "-I",
        &capture,
        "--keylog",
        &empty.display().to_string(),
    ])?;
    exited(&run, 0);
    assert_eq!(stdout(&run), "", "nothing decrypted, so no message line");
    printed(&stderr(&run), message);
    Ok(())
}

/// A key log that holds a key of another connection: sipnab loads the line,
/// builds no session and says so in the words the page quotes.
#[cfg(feature = "tls")]
#[test]
fn a_key_log_of_another_connection_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    let message = "sipnab loaded 1 keylog line(s) and built no session from any of them";
    let cause = "No key in the key log belongs to a handshake in this capture";
    let remedy =
        "Use the key log that the endpoint of these connections wrote during this capture.";
    let rows = section(TLS, TLS_TROUBLESHOOT)?;
    for quoted in [message, cause, remedy] {
        page_says(rows, quoted, "tls-capture");
    }
    let dir = tempfile::tempdir()?;
    let (capture, _) = tls_call(dir.path())?;
    let other = dir.path().join("other-keys.log");
    std::fs::write(
        &other,
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            "11".repeat(32),
            "22".repeat(32)
        ),
    )?;
    let run = sipnab(&[
        "-N",
        "-I",
        &capture,
        "--keylog",
        &other.display().to_string(),
    ])?;
    exited(&run, 0);
    assert_eq!(stdout(&run), "", "nothing decrypted, so no message line");
    for quoted in [message, cause, remedy] {
        printed(&stderr(&run), quoted);
    }
    assert!(
        !stderr(&run).contains("The handshake is missing"),
        "the capture holds the handshake, so sipnab must not call it missing; it printed:\n{}",
        stderr(&run)
    );
    Ok(())
}

/// A capture that began after the connection opened holds no ClientHello and
/// no ServerHello: sipnab says the handshake is missing, in the words the
/// page quotes, and does not blame the key log.
#[cfg(feature = "tls")]
#[test]
fn a_capture_without_the_handshake_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    let message = "sipnab loaded 1 keylog line(s) and built no session from any of them";
    let cause = "The handshake is missing: this capture holds no ClientHello and no ServerHello.";
    let rows = section(TLS, TLS_TROUBLESHOOT)?;
    for quoted in [message, cause] {
        page_says(rows, quoted, "tls-capture");
    }
    let dir = tempfile::tempdir()?;
    let frames = encrypted_captures::tls_session_frames()?;
    assert_eq!(
        frames.len(),
        6,
        "the call is SYN, SYN-ACK, two hellos and two records"
    );
    let late: Vec<Vec<u8>> = frames
        .into_iter()
        .enumerate()
        .filter(|(index, _)| *index >= 4)
        .map(|(_, frame)| frame)
        .collect();
    let capture = dir.path().join("late-capture.pcap");
    pcap_build::write_pcap(&capture, &late)?;
    let keys = dir.path().join("one-key.log");
    std::fs::write(
        &keys,
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            "11".repeat(32),
            "22".repeat(32)
        ),
    )?;
    let run = sipnab(&[
        "-N",
        "-I",
        &capture.display().to_string(),
        "--keylog",
        &keys.display().to_string(),
    ])?;
    exited(&run, 0);
    assert_eq!(stdout(&run), "", "nothing decrypted, so no message line");
    for quoted in [message, cause] {
        printed(&stderr(&run), quoted);
    }
    assert!(
        !stderr(&run).contains("No key in the key log belongs"),
        "with no ClientHello in the capture sipnab cannot say whose key it is; it printed:\n{}",
        stderr(&run)
    );
    Ok(())
}

/// The call with the given frames left out, and its real key log.
#[cfg(feature = "tls")]
fn tls_call_without(dir: &Path, left_out: &[usize]) -> Result<(String, String), TestError> {
    let frames = encrypted_captures::tls_session_frames()?;
    assert_eq!(
        frames.len(),
        6,
        "the call is SYN, SYN-ACK, two hellos and two records"
    );
    let kept: Vec<Vec<u8>> = frames
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !left_out.contains(index))
        .map(|(_, frame)| frame)
        .collect();
    let capture = dir.join("gap-capture.pcap");
    let keys = dir.join("sip-keys.log");
    pcap_build::write_pcap(&capture, &kept)?;
    std::fs::write(&keys, encrypted_captures::tls_keylog())?;
    Ok((capture.display().to_string(), keys.display().to_string()))
}

/// A capture that holds the SYN and the SYN-ACK and lacks the two hello
/// segments has a gap at the start of each TCP stream. Read with the key log,
/// the run must not report the capture as one with no SIP in it.
#[cfg(feature = "tls")]
#[test]
fn a_gap_before_the_tls_records_read_with_keys_is_not_called_a_capture_without_sip()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (capture, keys) = tls_call_without(dir.path(), &[2, 3])?;
    let run = sipnab(&["-N", "-I", &capture, "--keylog", &keys])?;
    exited(&run, 0);
    assert!(
        !stderr(&run).contains("No SIP traffic found."),
        "two TLS records are in the capture, so the plain sentence has no basis; it printed:\n{}\nstdout:\n{}",
        stderr(&run),
        stdout(&run)
    );
    Ok(())
}

/// Fails unless the run printed the two decrypted messages of the call and
/// counted them.
#[cfg(feature = "tls")]
fn decrypted_both_messages(run: &Output) {
    exited(run, 0);
    for line in ["INVITE TLS", "180 Ringing TLS"] {
        printed(&stdout(run), line);
    }
    printed(&stderr(run), "2 SIP messages");
}

/// The same capture decrypts: the two records are behind the gap, whole, and
/// the key log holds their keys. The page states it under its troubleshooting
/// heading.
#[cfg(feature = "tls")]
#[test]
fn records_behind_a_gap_at_the_start_of_each_stream_are_decrypted() -> Result<(), TestError> {
    let rows = section(TLS, TLS_TROUBLESHOOT)?;
    let quality = "2 hole(s) in TCP streams";
    let resumed = "reading resumed at the next SIP message or TLS record behind each";
    for quoted in ["sipnab resumes at the next TLS record", quality, resumed] {
        page_says(rows, quoted, "tls-capture");
    }
    let dir = tempfile::tempdir()?;
    let (capture, keys) = tls_call_without(dir.path(), &[2, 3])?;
    let run = sipnab(&["-N", "-I", &capture, "--keylog", &keys])?;
    decrypted_both_messages(&run);
    for quoted in [quality, resumed] {
        printed(&stderr(&run), quoted);
    }
    Ok(())
}

/// A gap in one direction only: the ClientHello segment is missing and the
/// ServerHello is there. Both messages decrypt.
#[cfg(feature = "tls")]
#[test]
fn records_behind_a_gap_in_one_direction_are_decrypted() -> Result<(), TestError> {
    for missing in [2usize, 3] {
        let dir = tempfile::tempdir()?;
        let (capture, keys) = tls_call_without(dir.path(), &[missing])?;
        decrypted_both_messages(&sipnab(&["-N", "-I", &capture, "--keylog", &keys])?);
    }
    Ok(())
}

/// A capture that joined the connection after its handshake, with no SYN,
/// decrypts as before.
#[cfg(feature = "tls")]
#[test]
fn records_of_a_capture_that_joined_after_the_handshake_are_decrypted() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (capture, keys) = tls_call_without(dir.path(), &[0, 1, 2, 3])?;
    decrypted_both_messages(&sipnab(&["-N", "-I", &capture, "--keylog", &keys])?);
    Ok(())
}

/// The capture with the gap, read with no key: the run counts the two records
/// behind the gap and names the flag, as it does for a capture without a gap.
#[cfg(feature = "tls")]
#[test]
fn records_behind_a_gap_read_without_keys_are_counted() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (capture, _) = tls_call_without(dir.path(), &[2, 3])?;
    let run = sipnab(&["-N", "-I", &capture])?;
    exited(&run, 0);
    assert_eq!(stdout(&run), "", "nothing decrypted, so no message line");
    printed(&stderr(&run), NO_TLS_KEY);
    assert!(
        !stderr(&run).contains("No SIP traffic found."),
        "the records are in the capture; it printed:\n{}",
        stderr(&run)
    );
    Ok(())
}

/// The capture with the gap, read with a key log of another connection: the
/// run gives the lines it gives for a capture that lacks the handshake, and
/// not the plain sentence.
#[cfg(feature = "tls")]
#[test]
fn records_behind_a_gap_read_with_another_key_log_name_the_missing_handshake()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (capture, keys) = tls_call_without(dir.path(), &[2, 3])?;
    std::fs::write(
        &keys,
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            "11".repeat(32),
            "22".repeat(32)
        ),
    )?;
    let run = sipnab(&["-N", "-I", &capture, "--keylog", &keys])?;
    exited(&run, 0);
    assert_eq!(stdout(&run), "", "nothing decrypted, so no message line");
    for quoted in [
        "sipnab loaded 1 keylog line(s) and built no session from any of them",
        "The handshake is missing: this capture holds no ClientHello and no ServerHello.",
    ] {
        printed(&stderr(&run), quoted);
    }
    assert!(
        !stderr(&run).contains("No SIP traffic found."),
        "the records are in the capture; it printed:\n{}",
        stderr(&run)
    );
    Ok(())
}

/// An `OPTIONS` request over TLS with the given Call-ID.
#[cfg(feature = "tls")]
fn tls_options(call_id: &str) -> String {
    format!(
        "OPTIONS sips:bob@10.9.0.2 SIP/2.0\r\n\
         Via: SIP/2.0/TLS 10.9.0.1:40111;branch=z9hG4bK{call_id}\r\n\
         From: <sips:alice@10.9.0.1>;tag=ma\r\nTo: <sips:bob@10.9.0.2>\r\n\
         Call-ID: {call_id}\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

/// A hole in the middle of a TLS connection, where the capture holds the
/// first half of a record and not the second. The record before the hole and
/// the two behind it are read. The half record the TLS layer held is dropped
/// when the stream resumes: without that, the first record behind the hole is
/// taken for the missing half and neither record behind the hole is read.
#[cfg(feature = "tls")]
#[test]
fn records_behind_a_hole_that_cut_a_record_are_decrypted() -> Result<(), TestError> {
    cut_record_run(&["behind-hole-1", "behind-hole-2"])
}

/// The same hole with one record behind it, which is the last thing its
/// direction sends: the end of the capture releases it, and the half record
/// is dropped there too.
#[cfg(feature = "tls")]
#[test]
fn a_last_record_behind_a_hole_that_cut_a_record_is_decrypted() -> Result<(), TestError> {
    cut_record_run(&["behind-hole-1"])
}

/// Builds a TLS connection whose client sends a whole record, the first half
/// of a second one, and then one whole record for each Call-ID in `behind`;
/// reads it with the key log and checks which messages come out.
#[cfg(feature = "tls")]
fn cut_record_run(behind: &[&str]) -> Result<(), TestError> {
    use encrypted_captures::{CLIENT_SECRET, tls13_hellos, tls13_record};
    let (a, b) = ([10, 9, 0, 1], [10, 9, 0, 2]);
    let (client, server) = (40_111u16, 5061u16);
    let (client_hello, server_hello) = tls13_hellos();
    let mut frames = vec![
        pcap_build::tcp_frame(a, b, client, server, 1000, 0x02, b""),
        pcap_build::tcp_frame(b, a, server, client, 5000, 0x12, b""),
        pcap_build::tcp_frame(a, b, client, server, 1001, 0x18, &client_hello),
        pcap_build::tcp_frame(b, a, server, client, 5001, 0x18, &server_hello),
    ];
    let mut seq = 1001 + client_hello.len() as u32;
    let mut sent = vec!["before-hole", "cut-by-hole"];
    sent.extend_from_slice(behind);
    for (number, call_id) in sent.into_iter().enumerate() {
        let record = tls13_record(
            &CLIENT_SECRET,
            number as u64,
            tls_options(call_id).as_bytes(),
        )?;
        // The capture holds the first half of the second record alone.
        let held = if number == 1 {
            &record[..record.len() / 2]
        } else {
            &record[..]
        };
        frames.push(pcap_build::tcp_frame(a, b, client, server, seq, 0x18, held));
        seq += record.len() as u32;
    }
    let dir = tempfile::tempdir()?;
    let capture = dir.path().join("cut-record.pcap");
    let keys = dir.path().join("sip-keys.log");
    pcap_build::write_pcap(&capture, &frames)?;
    std::fs::write(&keys, encrypted_captures::tls_keylog())?;
    let run = sipnab(&[
        "-N",
        "--json",
        "-I",
        &capture.display().to_string(),
        "--keylog",
        &keys.display().to_string(),
    ])?;
    exited(&run, 0);
    let read = stdout(&run);
    for call_id in ["before-hole"].iter().chain(behind.iter()) {
        assert!(
            read.contains(call_id),
            "the message {call_id} is whole in the capture and was not read; stdout:\n{read}\nstderr:\n{}",
            stderr(&run)
        );
    }
    assert!(
        !read.contains("cut-by-hole"),
        "half of that record is not in the capture; stdout:\n{read}"
    );
    printed(&stderr(&run), "1 hole(s) in TCP streams");
    Ok(())
}

/// A `--keylog` path that is not there stops the run with exit status 1.
#[cfg(feature = "tls")]
#[test]
fn a_key_log_that_is_not_there_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    let message = "Failed to load --keylog";
    let rows = section(TLS, TLS_TROUBLESHOOT)?;
    page_says(rows, message, "tls-capture");
    page_says(rows, "exit 1", "tls-capture");
    let dir = tempfile::tempdir()?;
    let (capture, _) = tls_call(dir.path())?;
    let missing = dir.path().join("no-such-keys.log").display().to_string();
    let run = sipnab(&["-N", "-I", &capture, "--keylog", &missing])?;
    exited(&run, 1);
    printed(&stderr(&run), &format!("{message} {missing}"));
    printed(&stderr(&run), "No such file or directory");
    Ok(())
}

/// The prerequisites name the `tls` feature the way `--version` lists it and
/// quote the refusal of a build without it, as the code words it.
#[test]
fn the_tls_prerequisites_name_the_feature_and_its_refusal() -> Result<(), TestError> {
    let needs = section(TLS, "## Before you start")?;
    page_says(needs, "sipnab --version", "tls-capture");
    page_says(
        needs,
        "requires the 'tls' feature (not compiled in)",
        "tls-capture",
    );
    assert!(
        BOOTSTRAP.contains("--keylog-fd requires the 'tls' feature (not compiled in)"),
        "the refusal the page quotes is no longer in src/app/bootstrap.rs"
    );
    let version = sipnab(&["--version"])?;
    exited(&version, 0);
    let listed = stdout(&version);
    let features = listed
        .lines()
        .find_map(|line| line.split_once("features: ").map(|(_, list)| list))
        .ok_or("--version prints no `features:` list")?;
    assert_eq!(
        features.split(',').any(|name| name.trim() == "tls"),
        cfg!(feature = "tls"),
        "--version lists `tls` exactly when the build carries it: {features}"
    );
    Ok(())
}

/// The prerequisites say what changes on the system that ends the TLS
/// session, for each kind of method.
#[test]
fn the_tls_prerequisites_say_what_changes_on_the_other_system() -> Result<(), TestError> {
    let needs = section(TLS, "## Before you start")?;
    for named in ["other system", "SSLKEYLOGFILE", "root", "eCapture"] {
        page_says(needs, named, "tls-capture");
    }
    Ok(())
}

/// The page quotes the permission message of a probe run in the words of the
/// code, and no longer sends the reader to `--setup-caps` for it.
#[test]
fn the_tls_page_quotes_the_probe_permission_message_of_the_code() -> Result<(), TestError> {
    let message = "Permission denied attaching TLS probes (--uprobe-tls).";
    page_says(section(TLS, TLS_TROUBLESHOOT)?, message, "tls-capture");
    assert!(
        BOOTSTRAP.contains(message),
        "src/app/bootstrap.rs no longer holds the message the page quotes"
    );
    Ok(())
}

/// The listing the page gives as its first check prints the header the page
/// quotes, or the sentence for a host with no TLS library in view.
#[cfg(target_os = "linux")]
#[test]
fn the_tls_page_listing_prints_the_header_the_page_quotes() -> Result<(), TestError> {
    let check = section(TLS, CHECK)?;
    let header = "FLAVOR        INODE  PIDS  LIBRARY";
    let none = "No TLS library is mapped by any process sipnab can see.";
    page_says(check, "sipnab --uprobe-list", "tls-capture");
    page_says(check, header, "tls-capture");
    page_says(check, none, "tls-capture");
    let listing = sipnab(&["--uprobe-list"])?;
    exited(&listing, 0);
    let shown = stdout(&listing);
    assert!(
        shown.starts_with(header) || shown.contains(none),
        "neither the header nor the empty sentence: {shown}"
    );
    Ok(())
}

// ── tuning-capture ───────────────────────────────────────────────────────
//
// A live capture needs capture rights, which the suite does not have, so the
// lines of a live run are compared with the format strings in
// `src/capture/live.rs`. What stops before the capture opens is run.

/// The check quotes the last line of a live run in the words of the code,
/// for a run with no drops and for a run with drops.
#[test]
fn the_tuning_check_quotes_the_end_of_run_lines_of_the_code() -> Result<(), TestError> {
    let check = section(TUNING, CHECK)?;
    page_says(
        check,
        "sudo sipnab -N -d eth0 --duration 60",
        "tuning-capture",
    );
    page_says(
        check,
        "Live capture on 'eth0' finished: 0 packets, no drops",
        "tuning-capture",
    );
    page_says(check, "THIS ANALYSIS IS INCOMPLETE", "tuning-capture");
    for held in [
        "Live capture on '{device}' finished: {count} packets, no drops",
        "the interface — THIS ANALYSIS IS INCOMPLETE",
    ] {
        assert!(
            LIVE.contains(held),
            "src/capture/live.rs no longer holds {held:?}"
        );
    }
    Ok(())
}

/// The prerequisites name capture rights, the tool the interface steps use,
/// and say that no other system changes.
#[test]
fn the_tuning_prerequisites_name_rights_tools_and_no_other_system() -> Result<(), TestError> {
    let needs = section(TUNING, "## Before you start")?;
    for named in [
        "sipnab --setup-caps",
        "ethtool",
        "other system",
        "(install.md",
    ] {
        page_says(needs, named, "tuning-capture");
    }
    printed(TUNING, "sudo ethtool -K eth0");
    Ok(())
}

/// `-B 0` stops before any capture opens, with exit status 2 and the message
/// the troubleshooting table quotes.
#[test]
fn a_buffer_of_zero_gives_the_message_the_tuning_page_quotes() -> Result<(), TestError> {
    let message = "invalid value '0' for '--buffer <MIB>'";
    let rows = section(TUNING, TROUBLESHOOT)?;
    page_says(rows, message, "tuning-capture");
    page_says(rows, "exit 2", "tuning-capture");
    let run = sipnab(&["-N", "-d", "lo", "-B", "0"])?;
    exited(&run, 2);
    printed(&stderr(&run), message);
    Ok(())
}

/// A capture filter that does not compile stops the run with exit status 1
/// and the message the troubleshooting table quotes. Run on a capture file:
/// a file and an interface share the wording up to the filter text.
#[test]
fn a_filter_that_does_not_compile_gives_the_message_the_tuning_page_quotes() -> Result<(), TestError>
{
    let message = "Failed to compile BPF filter";
    page_says(section(TUNING, TROUBLESHOOT)?, message, "tuning-capture");
    assert!(
        LIVE.contains("\"Failed to compile BPF filter: {bpf}{}\""),
        "src/capture/live.rs no longer words a filter failure this way"
    );
    let sample = capture(SAMPLE_CALL)?.display().to_string();
    let run = sipnab(&["-N", "-I", &sample, "port port"])?;
    exited(&run, 1);
    printed(&stderr(&run), "Failed to compile BPF filter 'port port'");
    assert_eq!(stdout(&run), "", "no message of the sample is printed");
    Ok(())
}

/// The table quotes the permission message and the message for an interface
/// that is not there. An unprivileged run is refused before the kernel looks
/// the interface up, so that case is run only when the test is not root.
#[cfg(target_os = "linux")]
#[test]
fn the_tuning_page_quotes_the_two_messages_of_a_capture_that_does_not_open() -> Result<(), TestError>
{
    let rows = section(TUNING, TROUBLESHOOT)?;
    page_says(rows, "Permission denied on 'eth0'.", "tuning-capture");
    page_says(rows, "No such device exists", "tuning-capture");
    page_says(rows, "Available devices:", "tuning-capture");
    assert!(
        BOOTSTRAP.contains("\"Permission denied on '{target}'. Grant capture capabilities once"),
        "src/app/bootstrap.rs no longer words the permission message this way"
    );
    assert!(
        LIVE.contains("Available devices: {}"),
        "src/capture/live.rs no longer lists the devices"
    );
    let uid = std::fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next().map(str::to_owned))
        .ok_or("no Uid line in /proc/self/status")?;
    if uid == "0" {
        return Ok(());
    }
    let run = sipnab(&["-N", "-d", "sipnab-none0", "--duration", "1"])?;
    exited(&run, 1);
    let said = stderr(&run);
    assert!(
        said.contains("Permission denied on 'sipnab-none0'.")
            || said.contains("No such device exists"),
        "neither message of the table: {said}"
    );
    Ok(())
}

/// The page still warns that a smaller buffer was taken in the words of the
/// code, which the troubleshooting table points at.
#[test]
fn the_tuning_page_quotes_the_smaller_buffer_warning_of_the_code() -> Result<(), TestError> {
    let message = "the kernel refused a";
    page_says(section(TUNING, TROUBLESHOOT)?, message, "tuning-capture");
    assert!(
        LIVE.contains(message),
        "src/capture/live.rs no longer holds {message:?}"
    );
    Ok(())
}

// ── theme-guide ──────────────────────────────────────────────────────────

/// Runs sipnab with `[theme]` holding `lines`, in a config directory of its
/// own.
fn sipnab_with_theme(lines: &str, args: &[&str]) -> Result<Output, TestError> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("sipnab");
    std::fs::create_dir(&config)?;
    std::fs::write(config.join("sipnab.toml"), format!("[theme]\n{lines}"))?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .current_dir(repo())
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", dir.path())
        .env("HOME", dir.path())
        .stdin(Stdio::null())
        .output()?)
}

/// The check of the page: `--dump-config` prints the `[theme]` section with
/// the value the config file holds.
#[test]
fn the_theme_check_prints_the_value_the_config_holds() -> Result<(), TestError> {
    let check = section(THEME, CHECK)?;
    page_says(check, "sipnab --dump-config", "theme-guide");
    page_says(check, "header = \"#89b4fa\"", "theme-guide");
    page_says(check, "Loaded config from", "theme-guide");
    let run = sipnab_with_theme("header = \"#89b4fa\"\n", &["--dump-config"])?;
    exited(&run, 0);
    printed(&stdout(&run), "[theme]\nheader = \"#89b4fa\"\n");
    printed(&stderr(&run), "Loaded config from");
    Ok(())
}

/// With no config file the `[theme]` section of `--dump-config` is empty,
/// which the check gives as the sign that sipnab read another file or none.
#[test]
fn the_theme_check_is_empty_without_a_config_file() -> Result<(), TestError> {
    page_says(section(THEME, CHECK)?, "an empty `[theme]`", "theme-guide");
    let run = sipnab(&["--dump-config"])?;
    exited(&run, 0);
    printed(&stdout(&run), "[theme]\n\n");
    assert!(
        !stderr(&run).contains("Loaded config from"),
        "no config file is in reach of this run: {}",
        stderr(&run)
    );
    Ok(())
}

/// A value that is not a color stops the run with exit status 1 and the
/// message the troubleshooting table quotes. Only a build with the `tui`
/// feature, which the page's prerequisites name, parses colors
/// (`ThemeConfig::validate`); a build without it accepts the value.
#[cfg(feature = "tui")]
#[test]
fn a_value_that_is_not_a_color_gives_the_message_the_theme_page_quotes() -> Result<(), TestError> {
    let rows = section(THEME, TROUBLESHOOT)?;
    page_says(rows, "is not a color", "theme-guide");
    page_says(rows, "exit 1", "theme-guide");
    let run = sipnab_with_theme("header = \"bluish\"\n", &["--dump-config"])?;
    exited(&run, 1);
    printed(
        &stderr(&run),
        "invalid config value: [theme] header = \"bluish\" is not a color",
    );
    Ok(())
}

/// A misspelled slot is a warning, and the run goes on with the default.
#[test]
fn a_slot_that_does_not_exist_gives_the_warning_the_theme_page_quotes() -> Result<(), TestError> {
    let message = "Unknown config key: theme.headr";
    page_says(section(THEME, TROUBLESHOOT)?, message, "theme-guide");
    let run = sipnab_with_theme("headr = \"cyan\"\n", &["--dump-config"])?;
    exited(&run, 0);
    printed(&stderr(&run), message);
    Ok(())
}

/// The prerequisites name the feature that draws the terminal UI and say
/// which other system decides the colors of a remote session.
#[test]
fn the_theme_prerequisites_name_the_feature_and_the_other_system() -> Result<(), TestError> {
    let needs = section(THEME, "## Before you start")?;
    for named in ["`tui`", "sipnab --version", "other system", "true-color"] {
        page_says(needs, named, "theme-guide");
    }
    let version = sipnab(&["--version"])?;
    let listed = stdout(&version);
    let features = listed
        .lines()
        .find_map(|line| line.split_once("features: ").map(|(_, list)| list))
        .ok_or("--version prints no `features:` list")?;
    assert_eq!(
        features.split(',').any(|name| name.trim() == "tui"),
        cfg!(feature = "tui"),
        "--version lists `tui` exactly when the build carries it: {features}"
    );
    Ok(())
}

// ── run-as-a-service, rest-api, mcp-deploy ───────────────────────────────

/// Whether `--version` lists `feature`, with the list it printed.
fn version_lists(feature: &str) -> Result<(bool, String), TestError> {
    let version = sipnab(&["--version"])?;
    exited(&version, 0);
    let listed = stdout(&version);
    let features = listed
        .lines()
        .find_map(|line| line.split_once("features: ").map(|(_, list)| list))
        .ok_or("--version prints no `features:` list")?;
    Ok((
        features.split(',').any(|name| name.trim() == feature),
        features.to_owned(),
    ))
}

/// Runs sipnab with `--config` naming a file that holds `[capture]` and
/// `line`.
fn sipnab_with_capture_key(line: &str) -> Result<Output, TestError> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("sipnab.toml");
    std::fs::write(&config, format!("[capture]\n{line}\n"))?;
    sipnab(&["-D", "--config", &config.display().to_string()])
}

/// The troubleshooting section of the service page, up to the section after
/// it. [`section`] cannot take it: a `#` comment in one of its fenced blocks
/// reads as a heading there.
fn service_troubleshooting() -> Result<&'static str, TestError> {
    let from = SERVICE
        .find(&format!("\n{SERVICE_TROUBLESHOOT}\n"))
        .ok_or_else(|| format!("no heading {SERVICE_TROUBLESHOOT:?}"))?;
    let rest = SERVICE.get(from..).ok_or("section start")?;
    let end = rest
        .find("\n## Check that a running service is healthy\n")
        .ok_or("the section after the troubleshooting section moved")?;
    rest.get(..end).ok_or_else(|| "section range".into())
}

/// The service prerequisites say what changes on the other system, the SIP
/// server, and when nothing does.
#[test]
fn the_service_prerequisites_say_what_changes_on_the_other_system() -> Result<(), TestError> {
    let needs = section(SERVICE, "## Before you start")?;
    for named in ["other system", "HEP", "firewall", "systemd"] {
        page_says(needs, named, "run-as-a-service");
    }
    Ok(())
}

/// A key sipnab does not know is a warning, and `-D` goes on to print the
/// configuration: the check the service page gives after each edit.
#[test]
fn a_misspelled_key_gives_the_warning_the_service_page_quotes() -> Result<(), TestError> {
    let message = "Unknown config key: capture.snaplenn";
    let rows = service_troubleshooting()?;
    page_says(rows, message, "run-as-a-service");
    page_says(
        rows,
        "sipnab -D --config /etc/sipnab/sipnab.toml",
        "run-as-a-service",
    );
    let run = sipnab_with_capture_key("snaplenn = 1600")?;
    exited(&run, 0);
    printed(&stderr(&run), message);
    printed(&stdout(&run), "[capture]");
    Ok(())
}

/// A value sipnab refuses stops the run with exit status 1 and the message
/// the table of the service page quotes.
#[test]
fn a_refused_value_gives_the_message_and_status_the_service_page_quotes() -> Result<(), TestError> {
    let message = "invalid config value: [capture] snaplen must be > 0";
    let rows = service_troubleshooting()?;
    page_says(rows, &format!("| `{message}` | 1 |"), "run-as-a-service");
    let run = sipnab_with_capture_key("snaplen = 0")?;
    exited(&run, 1);
    printed(&stderr(&run), message);
    Ok(())
}

/// A port another process holds: sipnab prints the bind failure and exits 2,
/// as the service page and the REST page both state.
#[cfg(feature = "api")]
#[test]
fn an_api_port_in_use_gives_the_message_and_status_both_pages_quote() -> Result<(), TestError> {
    page_says(
        service_troubleshooting()?,
        "| `failed to bind API to 127.0.0.1:18081: Address already in use (os error 98)` | 2 |",
        "run-as-a-service",
    );
    page_says(
        section(REST, "### When it does not answer")?,
        "`server error: failed to bind API to 127.0.0.1:8080: Address already in use \
         (os error 98)` and exits `2`",
        "rest-api",
    );
    // Bound until the end of the test, so the port stays taken while sipnab
    // runs.
    let held = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = held.local_addr()?.to_string();
    let sample = capture(SAMPLE_CALL)?.display().to_string();
    let run = sipnab(&["-N", "-I", &sample, "--api", &address])?;
    exited(&run, 2);
    printed(
        &stderr(&run),
        &format!("server error: failed to bind API to {address}: Address already in use"),
    );
    Ok(())
}

/// The REST prerequisites name the feature as `--version` lists it, the
/// three tools the page's commands use, and what another system needs.
#[test]
fn the_rest_prerequisites_name_the_feature_the_tools_and_the_other_system() -> Result<(), TestError>
{
    let needs = section(REST, "### Before you start")?;
    for named in [
        "`api`",
        "sipnab --version",
        "`curl`",
        "`jq`",
        "`openssl`",
        "other system",
    ] {
        page_says(needs, named, "rest-api");
    }
    for used in ["curl -s", "| jq ", "openssl rand -hex 32"] {
        printed(REST, used);
    }
    let (listed, features) = version_lists("api")?;
    assert_eq!(
        listed,
        cfg!(feature = "api"),
        "--version lists `api` exactly when the build carries it: {features}"
    );
    Ok(())
}

/// The MCP deployment prerequisites name the two features as `--version`
/// lists them, the client, and the systems a remote setup changes.
#[test]
fn the_mcp_deploy_prerequisites_name_the_features_and_the_other_systems() -> Result<(), TestError> {
    let needs = section(MCP_DEPLOY, "## Before you start")?;
    for named in [
        "`mcp`",
        "`mcp-http`",
        "sipnab --version",
        "Claude Code",
        "other system",
        "SSH",
    ] {
        page_says(needs, named, "mcp-deploy");
    }
    for (feature, built) in [
        ("mcp", cfg!(feature = "mcp")),
        ("mcp-http", cfg!(feature = "mcp-http")),
    ] {
        let (listed, features) = version_lists(feature)?;
        assert_eq!(
            listed, built,
            "--version lists `{feature}` exactly when the build carries it: {features}"
        );
    }
    Ok(())
}

// ── auth ─────────────────────────────────────────────────────────────────

/// A signing key for the tests: any text serves.
#[cfg(all(unix, feature = "api"))]
const SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The token `sipnab --mint-token` prints for the REST API with `key` and
/// `extra` flags.
#[cfg(all(unix, feature = "api"))]
fn minted(key: &str, extra: &[&str]) -> Result<String, TestError> {
    let mut args = vec!["--mint-token", "--api-signing-key", key];
    args.extend_from_slice(extra);
    let run = sipnab(&args)?;
    exited(&run, 0);
    Ok(stdout(&run).trim().to_owned())
}

/// The check of the page: a server that holds the signing key answers 200 to
/// a token minted with it, 401 to a request with no token, and 200 to
/// `/health` with none.
#[cfg(all(unix, feature = "api"))]
#[test]
fn the_auth_check_gets_200_with_the_token_and_401_without() -> Result<(), TestError> {
    // Sliced by hand: the fenced blocks of the check hold `#` comments, which
    // `section` reads as headings.
    let from = AUTH
        .find(&format!("\n{CHECK}\n"))
        .ok_or_else(|| format!("no heading {CHECK:?}"))?;
    let rest = AUTH.get(from..).ok_or("section start")?;
    let end = rest
        .find(&format!("\n{TROUBLESHOOT}\n"))
        .ok_or_else(|| format!("no heading {TROUBLESHOOT:?} after the check"))?;
    let check = rest.get(..end).ok_or("section range")?;
    for quoted in [
        "sipnab --mint-token --api-signing-key \"$KEY\"",
        "--api-signing-key \"$KEY\"",
        "`200`",
        "`401`",
        "/health",
        "s2.",
    ] {
        page_says(check, quoted, "auth");
    }
    let token = minted(SIGNING_KEY, &[])?;
    assert!(token.starts_with("s2."), "a signed token: {token}");
    let api =
        server::ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]).map_err(|e| e.to_string())?;
    let with = api
        .get_bearer("/v1/dialogs", &token)
        .map_err(|e| e.to_string())?;
    assert_eq!(with.status, 200, "the minted token: {}", with.body);
    let without = api.get("/v1/dialogs").map_err(|e| e.to_string())?;
    assert_eq!(without.status, 401, "no token: {}", without.body);
    let health = api.get("/health").map_err(|e| e.to_string())?;
    assert_eq!(
        health.status, 200,
        "/health takes no token: {}",
        health.body
    );
    Ok(())
}

/// A token signed with a key the server does not hold gets 401, the first
/// row of the troubleshooting table.
#[cfg(all(unix, feature = "api"))]
#[test]
fn a_token_of_another_key_gets_the_401_the_auth_page_states() -> Result<(), TestError> {
    page_says(
        section(AUTH, TROUBLESHOOT)?,
        "a key the server does not hold",
        "auth",
    );
    let token = minted("another-key-another-key-another-key", &[])?;
    let api =
        server::ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]).map_err(|e| e.to_string())?;
    let got = api
        .get_bearer("/v1/dialogs", &token)
        .map_err(|e| e.to_string())?;
    assert_eq!(got.status, 401, "a token of another key: {}", got.body);
    Ok(())
}

/// A token whose id is in the file of `--api-revoked-file` gets 401, and a
/// token with another id from the same key gets 200.
#[cfg(all(unix, feature = "api"))]
#[test]
fn a_revoked_token_gets_the_401_the_auth_page_states() -> Result<(), TestError> {
    page_says(section(AUTH, TROUBLESHOOT)?, "--api-revoked-file", "auth");
    let dir = tempfile::tempdir()?;
    let revoked = dir.path().join("revoked.txt");
    std::fs::write(&revoked, "ci-runner-1\n")?;
    let listed = minted(SIGNING_KEY, &["--token-id", "ci-runner-1"])?;
    let other = minted(SIGNING_KEY, &["--token-id", "ci-runner-2"])?;
    let api = server::ApiServer::spawn(&[
        "--api-signing-key",
        SIGNING_KEY,
        "--api-revoked-file",
        &revoked.display().to_string(),
    ])
    .map_err(|e| e.to_string())?;
    let refused = api
        .get_bearer("/v1/dialogs", &listed)
        .map_err(|e| e.to_string())?;
    assert_eq!(refused.status, 401, "the listed id: {}", refused.body);
    let served = api
        .get_bearer("/v1/dialogs", &other)
        .map_err(|e| e.to_string())?;
    assert_eq!(served.status, 200, "an id the file lacks: {}", served.body);
    Ok(())
}

/// `--mint-token` with no signing key stops with exit status 2 and the
/// message the troubleshooting table quotes.
#[test]
fn minting_without_a_key_gives_the_message_the_auth_page_quotes() -> Result<(), TestError> {
    let message = "--mint-token requires at least one --api-signing-key/--api-signing-key-file \
                   or --mcp-signing-key/--mcp-signing-key-file";
    let rows = section(AUTH, TROUBLESHOOT)?;
    page_says(rows, message, "auth");
    page_says(rows, "exit 2", "auth");
    let run = sipnab(&["--mint-token"])?;
    if cfg!(any(feature = "api", feature = "mcp-http")) {
        exited(&run, 2);
        printed(&stderr(&run), message);
    }
    Ok(())
}

/// The prerequisites name the features, the tools of the page's commands and
/// what reaches the other system: the token, never the signing key.
#[test]
fn the_auth_prerequisites_name_the_features_the_tools_and_the_other_system() -> Result<(), TestError>
{
    let needs = section(AUTH, "## Before you start")?;
    for named in [
        "`api`",
        "`mcp-http`",
        "sipnab --version",
        "`openssl`",
        "`curl`",
        "other system",
        "signing key",
    ] {
        page_says(needs, named, "auth");
    }
    for used in [
        "openssl rand -hex 32",
        "curl -H \"Authorization: Bearer $TOKEN\"",
    ] {
        printed(AUTH, used);
    }
    Ok(())
}

// ── mcp ──────────────────────────────────────────────────────────────────

/// The text of `doc` from the heading line `heading` to the end of the page.
/// For a section whose fences hold shell comments, which end `section`.
fn from_heading<'a>(doc: &'a str, heading: &str) -> Result<&'a str, TestError> {
    let at = doc
        .find(&format!("\n{heading}\n"))
        .ok_or_else(|| format!("no heading {heading:?}"))?;
    doc.get(at..).ok_or_else(|| "heading range".into())
}

/// Runs `sipnab --mcp -N -I <capture> --quiet`, writes `lines` to its
/// standard input, closes it and returns each JSON message the server wrote.
/// The server exits when its input ends, as the MCP page says.
#[cfg(feature = "mcp")]
fn mcp_stdio(capture: &Path, lines: &[String]) -> Result<Vec<serde_json::Value>, TestError> {
    use std::io::Write as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["--mcp", "-N", "-I"])
        .arg(capture)
        .arg("--quiet")
        .current_dir(repo())
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", repo().join("no-such-config-dir"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .tied_to_test()
        .spawn()?;
    {
        let mut input = child.stdin.take().ok_or("the server has no stdin pipe")?;
        for line in lines {
            writeln!(input, "{line}")?;
        }
    }
    let output = child.wait_with_output()?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

/// The JSON-RPC messages a fence of `text` passes to `printf`: each line that
/// holds one message between single quotes.
#[cfg(feature = "mcp")]
fn quoted_messages(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| line.contains("'{\"jsonrpc\""))
        .filter_map(|line| {
            let start = line.find('\'')?;
            let end = line.rfind('\'')?;
            line.get(start + 1..end).map(str::to_owned)
        })
        .collect()
}

/// The answer among `answers` whose `id` is `id`.
#[cfg(feature = "mcp")]
fn answer_to(answers: &[serde_json::Value], id: i64) -> Result<&serde_json::Value, TestError> {
    answers
        .iter()
        .find(|message| message["id"] == serde_json::json!(id))
        .ok_or_else(|| format!("the server gave no answer to id {id}: {answers:?}").into())
}

/// The MCP prerequisites name the two features as `--version` lists them,
/// the tools the page's commands run, and what changes on another system.
#[test]
fn the_mcp_prerequisites_name_the_features_the_tools_and_the_other_system() -> Result<(), TestError>
{
    let needs = section(MCP, "## Before you start")?;
    for named in [
        "`mcp`",
        "`mcp-http`",
        "sipnab --version",
        "`jq`",
        "`curl`",
        "other system",
        "MCP client",
    ] {
        page_says(needs, named, "mcp");
    }
    for (feature, built) in [
        ("mcp", cfg!(feature = "mcp")),
        ("mcp-http", cfg!(feature = "mcp-http")),
    ] {
        let (listed, features) = version_lists(feature)?;
        assert_eq!(
            listed, built,
            "--version lists `{feature}` exactly when the build carries it: {features}"
        );
    }
    Ok(())
}

/// The check of the MCP page sends three messages and expects the server's
/// name and `true` for the tool `triage_call`. The test sends the messages
/// the page holds and compares what the page's `jq` filter reads.
#[cfg(feature = "mcp")]
#[test]
fn the_mcp_check_names_the_server_and_finds_the_tool() -> Result<(), TestError> {
    let check = section(MCP, CHECK)?;
    page_says(
        check,
        "| sipnab --mcp -N -I sip-problem-call.pcap --quiet",
        "mcp",
    );
    page_says(
        check,
        ".result.serverInfo.name else (.result.tools | map(.name) | index(\"triage_call\") != null)",
        "mcp",
    );
    page_says(check, "\"sipnab\"\ntrue\n", "mcp");
    let messages = quoted_messages(check);
    assert_eq!(
        messages.len(),
        3,
        "the check sends initialize, the initialized notification and tools/list: {messages:?}"
    );
    let answers = mcp_stdio(&capture(PROBLEM_CALL)?, &messages)?;
    assert_eq!(
        answer_to(&answers, 1)?["result"]["serverInfo"]["name"],
        "sipnab",
        "the first line the page expects"
    );
    let tools = answer_to(&answers, 2)?["result"]["tools"]
        .as_array()
        .ok_or("tools/list answered no tool array")?;
    assert!(
        tools.iter().any(|tool| tool["name"] == "triage_call"),
        "the second line the page expects is `true`: the list holds triage_call"
    );
    Ok(())
}

/// A flag that writes to standard output beside `--mcp` on stdio is refused
/// with the message and the exit status the page quotes.
#[cfg(feature = "mcp")]
#[test]
fn a_stdout_flag_beside_mcp_gives_the_message_the_mcp_page_quotes() -> Result<(), TestError> {
    let message = "--mcp uses stdout for the JSON-RPC wire and cannot be combined with \
                   stdout-writing flags (--json)";
    let table = section(MCP, TROUBLESHOOT)?;
    page_says(table, message, "mcp");
    page_says(table, "exit 2", "mcp");
    let run = sipnab(&[
        "--mcp",
        "-N",
        "-I",
        &capture(PROBLEM_CALL)?.display().to_string(),
        "--json",
    ])?;
    exited(&run, 2);
    printed(&stderr(&run), message);
    Ok(())
}

/// A capture path that does not exist stops the server with the message and
/// the exit status the page quotes, with the path of the page's own row.
#[cfg(feature = "mcp")]
#[test]
fn a_capture_that_is_not_there_gives_the_message_the_mcp_page_quotes() -> Result<(), TestError> {
    let message = "-I/--input: '/path/to/capture.pcap' does not exist";
    let table = section(MCP, TROUBLESHOOT)?;
    page_says(table, message, "mcp");
    page_says(table, "exit 1", "mcp");
    let run = sipnab(&["--mcp", "-N", "-I", "/path/to/capture.pcap"])?;
    exited(&run, 1);
    printed(&stderr(&run), message);
    Ok(())
}

/// A tool name the server does not register gets the error the page quotes:
/// the message, the reason, and a list of the names it does register.
#[cfg(feature = "mcp")]
#[test]
fn a_tool_the_server_lacks_gets_the_error_the_mcp_page_quotes() -> Result<(), TestError> {
    let table = section(MCP, TROUBLESHOOT)?;
    for quoted in ["`tool not found`", "`unknown_tool`", "`valid_values`"] {
        page_says(table, quoted, "mcp");
    }
    let mut messages = quoted_messages(section(MCP, CHECK)?);
    messages.truncate(2);
    messages.push(
        serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "no_such_tool", "arguments": {}}
        })
        .to_string(),
    );
    let answers = mcp_stdio(&capture(PROBLEM_CALL)?, &messages)?;
    let error = &answer_to(&answers, 7)?["error"];
    assert_eq!(error["message"], "tool not found", "the message: {error}");
    assert_eq!(
        error["data"]["reason"], "unknown_tool",
        "the reason: {error}"
    );
    let registered = error["data"]["valid_values"]
        .as_array()
        .ok_or("the error carries no valid_values list")?;
    assert!(
        registered.iter().any(|name| name == "triage_call"),
        "valid_values lists the tools the server registers: {error}"
    );
    Ok(())
}

/// A Call-ID the capture does not hold gets the error the page quotes.
#[cfg(feature = "mcp")]
#[test]
fn a_call_the_capture_lacks_gets_the_error_the_mcp_page_quotes() -> Result<(), TestError> {
    let table = section(MCP, TROUBLESHOOT)?;
    page_says(table, "`call_id '<id>' not found`", "mcp");
    page_says(table, "`not_found`", "mcp");
    let mut messages = quoted_messages(section(MCP, CHECK)?);
    messages.truncate(2);
    messages.push(
        serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "triage_call", "arguments": {"call_id": "absent@example.invalid"}}
        })
        .to_string(),
    );
    let answers = mcp_stdio(&capture(PROBLEM_CALL)?, &messages)?;
    let error = &answer_to(&answers, 7)?["error"];
    assert_eq!(
        error["message"], "call_id 'absent@example.invalid' not found",
        "the message: {error}"
    );
    assert_eq!(error["data"]["reason"], "not_found", "the reason: {error}");
    Ok(())
}

/// An HTTP bind on a routable address with no token is refused before the
/// server binds, with the message and the exit status the page quotes.
#[cfg(feature = "mcp-http")]
#[test]
fn a_routable_mcp_bind_without_a_token_gives_the_message_the_mcp_page_quotes()
-> Result<(), TestError> {
    let table = section(MCP, TROUBLESHOOT)?;
    page_says(
        table,
        "MCP HTTP refuses to start: --mcp-bind 192.0.2.1:8731 is non-loopback",
        "mcp",
    );
    let run = sipnab(&[
        "--mcp",
        "-N",
        "--mcp-transport",
        "http",
        "--mcp-bind",
        "192.0.2.1:8731",
        "-I",
        &capture(PROBLEM_CALL)?.display().to_string(),
    ])?;
    exited(&run, 2);
    printed(
        &stderr(&run),
        "MCP HTTP refuses to start: --mcp-bind 192.0.2.1:8731 is non-loopback but no \
         --mcp-token / --mcp-token-file / SIPNAB_MCP_TOKEN",
    );
    Ok(())
}

/// The page quotes the refusal of `--mcp` by a build without the feature. A
/// build without it prints that message and exits 2; a build with it holds
/// the same text in its source, where the refusal is defined.
#[test]
fn a_build_without_mcp_refuses_the_flag_with_the_message_the_mcp_page_quotes()
-> Result<(), TestError> {
    let message = "--mcp requires the 'mcp' feature (not compiled in)";
    page_says(section(MCP, TROUBLESHOOT)?, message, "mcp");
    printed(BOOTSTRAP, message);
    if cfg!(not(feature = "mcp")) {
        let run = sipnab(&[
            "--mcp",
            "-N",
            "-I",
            &capture(PROBLEM_CALL)?.display().to_string(),
        ])?;
        exited(&run, 2);
        printed(&stderr(&run), message);
    }
    Ok(())
}

// ── mcp-estate ───────────────────────────────────────────────────────────

/// The estate prerequisites name the features, the tools and the systems the
/// scenarios change: each proxy, the firewall and the laptop.
#[test]
fn the_estate_prerequisites_name_the_features_and_the_other_systems() -> Result<(), TestError> {
    let needs = section(MCP_ESTATE, "## Before you start")?;
    for named in [
        "`mcp-http`",
        "`hep`",
        "sipnab --version",
        "`curl`",
        "`jq`",
        "other system",
        "HEP",
        "firewall",
        "SSH",
    ] {
        page_says(needs, named, "mcp-estate");
    }
    for (feature, built) in [
        ("mcp-http", cfg!(feature = "mcp-http")),
        ("hep", cfg!(feature = "hep")),
    ] {
        let (listed, features) = version_lists(feature)?;
        assert_eq!(
            listed, built,
            "--version lists `{feature}` exactly when the build carries it: {features}"
        );
    }
    Ok(())
}

/// An MCP server over HTTP with a HEP listener, both on loopback ports the
/// kernel picks, as the check of the estate page starts one on fixed ports.
#[cfg(all(unix, feature = "mcp-http", feature = "hep"))]
struct CaptureHost {
    /// Stops the server when the test ends, on a panic too.
    _server: mcp::HttpServer,
    /// The address the MCP server bound.
    mcp: String,
    /// The address the HEP listener bound.
    hep: String,
}

#[cfg(all(unix, feature = "mcp-http", feature = "hep"))]
impl CaptureHost {
    /// Starts the server and reads both bound addresses from its log.
    fn start() -> Result<Self, TestError> {
        use std::io::BufRead as _;
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args([
                "--mcp",
                "-N",
                "--mcp-transport",
                "http",
                "--mcp-bind",
                "127.0.0.1:0",
                "-L",
                "127.0.0.1:0",
            ])
            .current_dir(repo())
            .env("NO_COLOR", "1")
            .env("SIPNAB_LOG", "info")
            .env("XDG_CONFIG_HOME", repo().join("no-such-config-dir"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .tied_to_test()
            .spawn()?;
        let log = child.stderr.take().ok_or("the server has no stderr pipe");
        let server = mcp::HttpServer::new(child);
        let (send, lines) = std::sync::mpsc::channel::<String>();
        let log = log?;
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(log).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let (mut mcp_addr, mut hep_addr) = (None, None);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while mcp_addr.is_none() || hep_addr.is_none() {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let line = lines
                .recv_timeout(left)
                .map_err(|e| format!("the server did not log both addresses: {e}"))?;
            if let Some(addr) = line.split("HEP listener started on ").nth(1) {
                hep_addr = Some(addr.trim().to_owned());
            } else if let Some(addr) = line.split("MCP HTTP server listening on ").nth(1) {
                mcp_addr = Some(addr.trim().to_owned());
            }
        }
        Ok(Self {
            _server: server,
            mcp: mcp_addr.ok_or("no MCP address")?,
            hep: hep_addr.ok_or("no HEP address")?,
        })
    }

    /// What `hep_senders` answers inside `session`.
    fn senders(&self, session: &str, id: i64) -> Result<serde_json::Value, TestError> {
        let answer = mcp::session_request(
            &self.mcp,
            session,
            id,
            "tools/call",
            serde_json::json!({"name": "hep_senders", "arguments": {}}),
        )?;
        Ok(answer["result"]["structuredContent"].clone())
    }
}

/// The check of the estate page: a second sipnab sends the sample capture to
/// the HEP listener, and `hep_senders` names it by the capture id it claims,
/// with the packet count the page quotes. Before the sender runs, the list is
/// empty, as the troubleshooting table says of a listener nothing reached.
#[cfg(all(unix, feature = "mcp-http", feature = "hep"))]
#[test]
fn the_estate_check_lists_the_sender_the_page_quotes() -> Result<(), TestError> {
    let check = from_heading(MCP_ESTATE, CHECK)?;
    for quoted in [
        "sipnab --mcp -N --mcp-transport http --mcp-bind 127.0.0.1:8731 -L 127.0.0.1:9063",
        "sipnab -N --no-cli-print --quiet -I sip-problem-call.pcap --hep-send 127.0.0.1:9063 --hep-id 102",
        "{\"name\":\"hep_senders\",\"arguments\":{}}",
        "{\"source\":\"hep:102@127.0.0.1\",\"packets\":23,\"silent\":false}",
    ] {
        page_says(check, quoted, "mcp-estate");
    }
    page_says(
        from_heading(MCP_ESTATE, TROUBLESHOOT)?,
        "`\"senders\":[]`",
        "mcp-estate",
    );
    let host = CaptureHost::start()?;
    let session = mcp::establish_session(&host.mcp)?;
    let before = host.senders(&session, 2)?;
    assert_eq!(
        before["senders"],
        serde_json::json!([]),
        "no sender has reached the listener yet: {before}"
    );
    let sender = sipnab(&[
        "-N",
        "--no-cli-print",
        "--quiet",
        "-I",
        &capture(PROBLEM_CALL)?.display().to_string(),
        "--hep-send",
        &host.hep,
        "--hep-id",
        "102",
    ])?;
    exited(&sender, 0);
    // The listener reads the datagrams after the sender exits: ask until it
    // has counted all 23, within a bound.
    let mut seen = serde_json::Value::Null;
    for id in 3..400 {
        seen = host.senders(&session, id)?;
        if seen["senders"][0]["packets"] == 23 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let first = &seen["senders"][0];
    assert_eq!(first["source"], "hep:102@127.0.0.1", "the source: {seen}");
    assert_eq!(first["packets"], 23, "the packets of the sample: {seen}");
    assert_eq!(first["silent"], false, "a sender heard just now: {seen}");
    Ok(())
}

/// A HEP listener on a routable address with no allowlist and no secret is
/// refused with the message and the exit status the estate page quotes.
#[cfg(feature = "hep")]
#[test]
fn a_routable_hep_listener_without_a_guard_gives_the_message_the_estate_page_quotes()
-> Result<(), TestError> {
    let table = from_heading(MCP_ESTATE, TROUBLESHOOT)?;
    let start = "HEP listener refuses to start: --hep-listen";
    let cause = "is non-loopback but neither a shared secret (--hep-auth / --hep-auth-file) \
                 nor a source allowlist (--hep-allow) was configured";
    page_says(table, start, "mcp-estate");
    page_says(table, cause, "mcp-estate");
    page_says(table, "exit 2", "mcp-estate");
    let run = sipnab(&["-N", "-L", "0.0.0.0:0"])?;
    exited(&run, 2);
    printed(&stderr(&run), start);
    printed(&stderr(&run), cause);
    Ok(())
}

/// The estate page sends a reader with the token refusal to the row of the
/// MCP page that quotes it.
#[test]
fn the_estate_page_points_at_the_token_refusal_of_the_mcp_page() -> Result<(), TestError> {
    page_says(
        from_heading(MCP_ESTATE, TROUBLESHOOT)?,
        "`MCP HTTP refuses to start`",
        "mcp-estate",
    );
    page_says(
        from_heading(MCP_ESTATE, TROUBLESHOOT)?,
        "(mcp.md#when-something-does-not-work)",
        "mcp-estate",
    );
    Ok(())
}

// ── integrations ─────────────────────────────────────────────────────────

/// Runs sipnab in `dir` with warnings logged, whatever the environment of
/// the test run holds.
fn sipnab_warning(dir: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("SIPNAB_LOG", "warn")
        .env("XDG_CONFIG_HOME", dir.join("no-such-config-dir"))
        .stdin(Stdio::null())
        .output()?)
}

/// The prerequisites name the shell that runs a hook, the daemons two of the
/// channels need, and that no other system changes.
#[test]
fn the_integrations_prerequisites_name_the_shell_the_daemons_and_the_other_system()
-> Result<(), TestError> {
    let needs = section(INTEGRATIONS, "## Before you start")?;
    for named in ["`sh`", "syslog", "fail2ban", "other system", "`nobody`"] {
        page_says(needs, named, "integrations");
    }
    Ok(())
}

/// The check of the page runs one hook per dialog event of the sample and
/// expects five distinct lines. The test runs the command of the page.
#[cfg(unix)]
#[test]
fn the_integrations_check_writes_one_line_per_dialog_state() -> Result<(), TestError> {
    let check = section(INTEGRATIONS, CHECK)?;
    let hook = "echo \"$SIPNAB_CALL_ID $SIPNAB_STATE\" >> sipnab-hook-check.log";
    page_says(
        check,
        &format!(
            "sipnab -N --no-cli-print --quiet -I tests/pcap-samples/sip-rtp-g711.pcap \
             --on-dialog-exec '{hook}' && sort -u sipnab-hook-check.log"
        ),
        "integrations",
    );
    let expected = "1-1966@10.0.2.20 Completed\n\
                    1-1966@10.0.2.20 InCall\n\
                    1-1966@10.0.2.20 Trying\n\
                    1-1968@10.0.2.20 InCall\n\
                    1-1968@10.0.2.20 Trying\n";
    page_says(check, expected, "integrations");
    let dir = tempfile::tempdir()?;
    let run = sipnab_in(
        dir.path(),
        &[
            "-N",
            "--no-cli-print",
            "--quiet",
            "-I",
            &capture("tests/pcap-samples/sip-rtp-g711.pcap")?
                .display()
                .to_string(),
            "--on-dialog-exec",
            hook,
        ],
    )?;
    exited(&run, 0);
    let written = std::fs::read_to_string(dir.path().join("sipnab-hook-check.log"))?;
    let mut lines: Vec<&str> = written.lines().collect();
    lines.sort_unstable();
    lines.dedup();
    assert_eq!(
        lines.join("\n") + "\n",
        expected,
        "the distinct lines the hook wrote"
    );
    Ok(())
}

/// A hook command that does not exist is reported with the status the page
/// quotes, and the run still exits 0.
#[cfg(unix)]
#[test]
fn a_hook_that_is_not_found_gives_the_message_the_integrations_page_quotes() -> Result<(), TestError>
{
    let message = "Event exec command failed (exit status: 127)";
    page_says(
        section(INTEGRATIONS, TROUBLESHOOT)?,
        message,
        "integrations",
    );
    let dir = tempfile::tempdir()?;
    let run = sipnab_warning(
        dir.path(),
        &[
            "-N",
            "--no-cli-print",
            "-I",
            &capture("tests/pcap-samples/sip-rtp-g711.pcap")?
                .display()
                .to_string(),
            "--on-dialog-exec",
            "/nonexistent/sipnab-hook.sh",
        ],
    )?;
    exited(&run, 0);
    printed(&stderr(&run), message);
    Ok(())
}

/// An alert channel and an alert rule that do not exist are each refused
/// with the message and the exit status the page quotes.
#[test]
fn an_unknown_alert_channel_or_rule_gives_the_messages_the_integrations_page_quotes()
-> Result<(), TestError> {
    let table = section(INTEGRATIONS, TROUBLESHOOT)?;
    page_says(table, "exit 2", "integrations");
    for (value, message) in [
        (
            "pager",
            "--alert: Unknown alert channel 'pager': expected one of syslog, json, exec, or a \
             rule written name:threshold/window",
        ),
        (
            "bogus:1/60s",
            "--alert: Unknown alert rule 'bogus': expected one of digest, fraud, reg_flood, \
             scanner (reg-flood is accepted for reg_flood)",
        ),
    ] {
        page_says(table, message, "integrations");
        let run = sipnab(&[
            "-N",
            "--no-cli-print",
            "-I",
            &capture(PROBLEM_CALL)?.display().to_string(),
            "--alert",
            value,
        ])?;
        exited(&run, 2);
        printed(&stderr(&run), message);
    }
    Ok(())
}

/// The JSON alert line and the fail2ban line format the page quotes are the
/// ones the scanner capture produces.
#[test]
fn the_integrations_page_quotes_the_alert_and_fail2ban_lines_of_the_capture()
-> Result<(), TestError> {
    let scanner = capture("tests/fixtures/sip-scanner-and-register-flood.pcap")?
        .display()
        .to_string();
    let alert = "{\"alert\":\"scanner\",\"detail\":\"method=\\\"OPTIONS\\\" \
                 ua=\\\"friendly-scanner\\\" detection=ua_pattern\",\"src\":\"203.0.113.42\",\
                 \"ts\":\"2023-11-14T22:13:21+00:00\"}";
    printed(INTEGRATIONS, alert);
    let run = sipnab(&[
        "-N",
        "--no-cli-print",
        "-I",
        &scanner,
        "--kill-scanner",
        "--alert-json",
    ])?;
    exited(&run, 0);
    printed(&stderr(&run), alert);

    for quoted in [
        "reg_flood src=198.51.100.77 count=6",
        "reg_flood src=198.51.100.77 count=7",
    ] {
        printed(INTEGRATIONS, quoted);
    }
    let run = sipnab(&[
        "-N",
        "-I",
        &scanner,
        "--reg-flood",
        "--reg-flood-threshold",
        "5",
        "--reg-flood-window",
        "60",
        "--fail2ban",
    ])?;
    exited(&run, 0);
    let lines: Vec<String> = stdout(&run).lines().take(2).map(str::to_owned).collect();
    assert_eq!(lines.len(), 2, "two fail2ban lines at least: {lines:?}");
    assert!(
        lines[0].ends_with(": reg_flood src=198.51.100.77 count=6"),
        "the first line the page quotes: {lines:?}"
    );
    assert!(
        lines[1].ends_with(": reg_flood src=198.51.100.77 count=7"),
        "the second line the page quotes: {lines:?}"
    );
    Ok(())
}

// ── vcon, vcon-store, vcon-sipnab, vcon-server, vcon-harness ─────────────

/// The capture of two calls with audio that the vCon pages export from.
const G711_CALLS: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
/// The call of that capture that ended with a `BYE`.
const G711_CALL_ID: &str = "1-1966@10.0.2.20";
/// The heading of the troubleshooting table of the vCon page.
const VCON_TROUBLESHOOT: &str = "## When an export does not work";

/// The feature list of the `-noaudio` packages and the static musl build, as
/// the release workflow sets it.
fn noaudio_features() -> Result<Vec<&'static str>, TestError> {
    let line = RELEASE_WORKFLOW
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("noaudio_set=\""))
        .ok_or("the release workflow no longer sets noaudio_set")?;
    Ok(line.trim_end_matches('"').split(',').collect())
}

/// The prerequisites of the vCon page name the feature, the packages that
/// carry it, the flag for audio and the other system. The package statement
/// follows the release workflow and the manifest: the `full` set holds
/// `vcon`, and the set of the `-noaudio` packages and the musl build does not.
#[test]
fn the_vcon_prerequisites_name_the_feature_the_packages_and_the_other_system()
-> Result<(), TestError> {
    let needs = section(VCON, "## Before you start")?;
    for named in [
        "`vcon` feature",
        "without a `-noaudio` suffix carry it",
        "The `-noaudio` packages and the static musl build do not carry it",
        "`--retain-audio`",
        "`--report`",
        "other system",
    ] {
        page_says(needs, named, "vcon");
    }
    let reduced = noaudio_features()?;
    assert!(
        !reduced.contains(&"vcon"),
        "the page says the -noaudio packages lack vcon; the workflow builds them with {reduced:?}"
    );
    for carried in ["api", "mcp"] {
        assert!(
            reduced.contains(&carried),
            "the page says every release package carries {carried}; the reduced set is {reduced:?}"
        );
    }
    let full = MANIFEST
        .lines()
        .find(|line| line.starts_with("full = ["))
        .ok_or("Cargo.toml no longer defines the full feature on one line")?;
    assert!(
        full.contains("\"vcon\""),
        "the page says the other packages carry vcon; full is {full}"
    );
    Ok(())
}

/// No statement that every release package carries `vcon` is left on the
/// vCon pages.
#[test]
fn no_vcon_page_says_every_release_package_carries_the_feature() {
    for (page, text) in [
        ("vcon", VCON),
        ("vcon-store", VCON_STORE),
        ("vcon-sipnab", VCON_SIPNAB),
    ] {
        for wrong in [
            "Every\n  release package carries the feature",
            "`vcon` features are in every release package",
            "Every release package carries both",
        ] {
            assert!(
                !text.contains(wrong),
                "{page} still says {wrong:?}, which the -noaudio packages contradict"
            );
        }
    }
}

/// The features of the `full` set that the `-noaudio` packages and the
/// static musl build lack, each with the words the pages use for it. A
/// feature that joins or leaves the difference fails here until the pages
/// and this table follow.
fn left_out_of_the_reduced_builds() -> Result<Vec<&'static str>, TestError> {
    let words = [
        ("audio", "live audio playback"),
        ("plugins", "WASM plugins"),
        ("vcon", "vCon export"),
        ("opus", "Ogg Opus"),
        ("fleet-store", "fleet history store"),
    ];
    let reduced = noaudio_features()?;
    let full = MANIFEST
        .lines()
        .find(|line| line.starts_with("full = ["))
        .ok_or("Cargo.toml no longer defines the full feature on one line")?;
    let lacking: Vec<&str> = full
        .trim_start_matches("full = [")
        .trim_end_matches(']')
        .split(',')
        .map(|name| name.trim().trim_matches('"'))
        .filter(|name| !name.is_empty() && !reduced.contains(name))
        .collect();
    let mut named = Vec::new();
    for feature in &lacking {
        let (_, phrase) = words
            .iter()
            .find(|(name, _)| name == feature)
            .ok_or_else(|| {
                format!("the reduced builds now lack {feature}: name it on the pages")
            })?;
        named.push(*phrase);
    }
    assert_eq!(
        named.len(),
        words.len(),
        "the reduced builds lack {lacking:?}; the pages name {words:?}"
    );
    Ok(named)
}

/// The rows of a Markdown table in `page` whose first cell holds `marker`.
fn table_rows<'a>(page: &'a str, marker: &str) -> Vec<&'a str> {
    page.lines()
        .filter(|line| line.starts_with('|'))
        .filter(|line| {
            line.split('|')
                .nth(1)
                .is_some_and(|cell| cell.contains(marker))
        })
        .collect()
}

/// The release-artifact table of the install page says, on each `-noaudio`
/// row and each musl row, every feature the release workflow builds that
/// file without. The musl rows also name the eBPF backend, which the
/// workflow adds to the gnu targets alone.
#[test]
fn the_install_table_names_what_each_reduced_build_leaves_out() -> Result<(), TestError> {
    let phrases = left_out_of_the_reduced_builds()?;
    let noaudio = table_rows(INSTALL, "-noaudio.");
    assert_eq!(noaudio.len(), 4, "two .deb and two .rpm rows: {noaudio:?}");
    let musl = table_rows(INSTALL, "-unknown-linux-musl.tar.gz");
    assert_eq!(musl.len(), 2, "two musl rows: {musl:?}");
    for row in noaudio.iter().chain(musl.iter()) {
        for phrase in &phrases {
            assert!(
                row.contains(phrase),
                "the row does not say the build lacks {phrase}: {row}"
            );
        }
    }
    for row in &musl {
        assert!(
            row.contains("eBPF uprobe backend"),
            "the musl row does not name the eBPF backend: {row}"
        );
    }
    assert!(
        RELEASE_WORKFLOW.contains("*-linux-gnu)\n              features=\"${features},bpf\""),
        "the workflow no longer adds bpf to the gnu targets alone"
    );
    Ok(())
}

/// The package sections of the install page, the installer's two messages,
/// the README and the standards page of the site say the same: no sentence
/// states that a reduced build differs by audio alone, or that every gnu
/// build carries the vCon export.
#[test]
fn no_page_says_a_reduced_build_differs_by_audio_alone() -> Result<(), TestError> {
    let phrases = left_out_of_the_reduced_builds()?;
    let readme = include_str!("../README.md");
    let standards = include_str!("../website/templates/standards.html");
    for (name, text, wrong) in [
        (
            "website/static/install.sh",
            INSTALLER,
            "otherwise identical",
        ),
        ("docs/install.md", INSTALL, "otherwise identical"),
        (
            "docs/install.md",
            INSTALL,
            "Everything else, WAV export included, works the same",
        ),
        (
            "docs/install.md",
            INSTALL,
            "Only live playback in the TUI is unavailable",
        ),
        ("README.md", readme, "It is in the gnu and macOS builds"),
        (
            "website/templates/standards.html",
            standards,
            "carry and the static musl builds do not",
        ),
        (
            "website/templates/index.html",
            include_str!("../website/templates/index.html"),
            "which carry the <code>vcon</code> feature).",
        ),
        (
            "website/content/features.md",
            include_str!("../website/content/features.md"),
            "feature (the gnu and macOS builds).",
        ),
        (
            "website/content/features.md",
            include_str!("../website/content/features.md"),
            "not the static musl builds).",
        ),
    ] {
        assert!(
            !text.contains(wrong),
            "{name} still says {wrong:?}; the reduced builds lack {phrases:?}"
        );
    }
    for section_heading in ["### Debian/Ubuntu (.deb)", "### RHEL/Fedora (.rpm)"] {
        // The sections hold shell comments, which end `section`: cut at the
        // next heading of the page instead.
        let text = from_heading(INSTALL, section_heading)?;
        let body = text
            .get(section_heading.len() + 2..)
            .ok_or("section range")?;
        let text = body.split("\n## ").next().unwrap_or(body);
        let text = text.split("\n### ").next().unwrap_or(text);
        for phrase in &phrases {
            assert!(
                text.contains(phrase),
                "{section_heading} does not say the -noaudio package lacks {phrase}"
            );
        }
    }
    let said =
        "no TUI audio, WASM plugins, vCon export, eBPF uprobe backend or fleet history store";
    assert_eq!(
        INSTALLER.matches(said).count(),
        2,
        "both messages of the installer about the musl build say what it lacks"
    );
    page_says(INSTALL, said, "install");
    page_says(readme, "`-noaudio` packages", "README");
    Ok(())
}

/// The prerequisites send the reader to `--report` for the Call-IDs of a
/// capture. The report of the sample names the call the page exports.
#[test]
fn the_report_lists_the_call_ids_as_the_vcon_prerequisites_say() -> Result<(), TestError> {
    let run = sipnab(&[
        "-N",
        "--no-cli-print",
        "--quiet",
        "-I",
        G711_CALLS,
        "--report",
    ])?;
    exited(&run, 0);
    printed(&stdout(&run), G711_CALL_ID);
    Ok(())
}

/// A binary without the feature refuses the export with exit status 2 and
/// the message the page quotes.
#[cfg(not(feature = "vcon"))]
#[test]
fn a_build_without_vcon_refuses_the_export_as_the_page_quotes() -> Result<(), TestError> {
    let message = "--export-vcon needs the 'vcon' Cargo feature, which this build does not carry.";
    page_says(section(VCON, VCON_TROUBLESHOOT)?, message, "vcon");
    let run = sipnab(&["-N", "-I", G711_CALLS, "--export-vcon", G711_CALL_ID])?;
    exited(&run, 2);
    printed(&stderr(&run), message);
    Ok(())
}

/// A Call-ID the capture lacks ends the run with exit status 1 and names
/// `--report`.
#[cfg(feature = "vcon")]
#[test]
fn an_export_of_a_call_id_the_capture_lacks_gives_the_message_the_page_quotes()
-> Result<(), TestError> {
    let message = "Call-ID 'nope@example.com' not found in tracked dialogs, so there is no \
                   dialog to export.";
    page_says(section(VCON, VCON_TROUBLESHOOT)?, message, "vcon");
    let run = sipnab(&[
        "-N",
        "--no-cli-print",
        "-I",
        G711_CALLS,
        "--export-vcon",
        "nope@example.com",
    ])?;
    exited(&run, 1);
    printed(&stderr(&run), message);
    printed(&stderr(&run), "--report lists the Call-IDs this run holds");
    assert_eq!(stdout(&run), "", "no container is printed");
    Ok(())
}

/// `--vcon-out` alone and `--export-vcon-when` alone are refused with exit
/// status 2, each naming the flag it lacks.
#[cfg(feature = "vcon")]
#[test]
fn an_export_flag_without_its_pair_gives_the_messages_the_page_quotes() -> Result<(), TestError> {
    let rows = section(VCON, VCON_TROUBLESHOOT)?;
    let refusal = "error: the following required arguments were not provided:";
    page_says(rows, refusal, "vcon");
    let dir = tempfile::tempdir()?;
    let sample = capture(G711_CALLS)?.display().to_string();
    let cases: [(&[&str], &str); 2] = [
        (&["--vcon-out", "out.json"], "--export-vcon <CALL-ID>"),
        (
            &["--export-vcon-when", "state == 'Completed'"],
            "--export-vcon-dir <DIR>",
        ),
    ];
    for (flags, lacking) in cases {
        page_says(rows, lacking, "vcon");
        let mut args = vec!["-N", "-I", sample.as_str()];
        args.extend_from_slice(flags);
        let run = sipnab_in(dir.path(), &args)?;
        exited(&run, 2);
        printed(&stderr(&run), refusal);
        printed(&stderr(&run), lacking);
    }
    assert!(
        !dir.path().join("out.json").exists(),
        "a refused run writes no container"
    );
    Ok(())
}

/// An expression that does not parse is refused with exit status 2, and the
/// message marks the position.
#[cfg(feature = "vcon")]
#[test]
fn an_export_expression_that_does_not_parse_gives_the_message_the_page_quotes()
-> Result<(), TestError> {
    let message = "--export-vcon-when is not a valid filter expression";
    page_says(section(VCON, VCON_TROUBLESHOOT)?, message, "vcon");
    let dir = tempfile::tempdir()?;
    let sample = capture(G711_CALLS)?.display().to_string();
    let run = sipnab_in(
        dir.path(),
        &[
            "-N",
            "-I",
            &sample,
            "--export-vcon-when",
            "state = = 'x'",
            "--export-vcon-dir",
            "spool",
        ],
    )?;
    exited(&run, 2);
    printed(&stderr(&run), message);
    printed(&stderr(&run), "unexpected input at position 6");
    assert!(
        !dir.path().join("spool").exists(),
        "a refused run creates no directory"
    );
    Ok(())
}

/// Writes the containers of the calls of `capture_path` that match `when`
/// into `spool` under `dir`, with `extra` flags, and returns the run.
#[cfg(feature = "vcon")]
fn export_by_rule(
    dir: &Path,
    capture_path: &str,
    when: &str,
    extra: &[&str],
) -> Result<Output, TestError> {
    let sample = capture(capture_path)?.display().to_string();
    let mut args = vec!["-N", "--no-cli-print", "-I", sample.as_str()];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--export-vcon-when", when, "--export-vcon-dir", "spool"]);
    sipnab_in(dir, &args)
}

/// The one container in `spool` under `dir`, parsed.
#[cfg(feature = "vcon")]
fn the_container(dir: &Path) -> Result<serde_json::Value, TestError> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir.join("spool"))? {
        let path = entry?.path();
        if path.is_file() {
            found.push(path);
        }
    }
    assert_eq!(found.len(), 1, "one container in the spool: {found:?}");
    Ok(serde_json::from_slice(&std::fs::read(&found[0])?)?)
}

/// An expression no call matches writes no container, prints the line the
/// page quotes and exits 0.
#[cfg(feature = "vcon")]
#[test]
fn an_expression_no_call_matches_writes_the_line_the_page_quotes() -> Result<(), TestError> {
    let line = "Wrote 0 vCon container(s) to 'spool'.";
    page_says(section(VCON, VCON_TROUBLESHOOT)?, line, "vcon");
    let dir = tempfile::tempdir()?;
    let run = export_by_rule(dir.path(), G711_CALLS, "state == 'Failed'", &[])?;
    exited(&run, 0);
    printed(&stderr(&run), line);
    Ok(())
}

/// Without `--retain-audio` the `recording` Dialog Object has no `body`, and
/// with it the object carries the audio.
#[cfg(feature = "vcon")]
#[test]
fn the_recording_has_a_body_only_with_retain_audio() -> Result<(), TestError> {
    page_says(
        section(VCON, VCON_TROUBLESHOOT)?,
        "The run had no `--retain-audio`",
        "vcon",
    );
    page_says(
        section(VCON, "## Before you start")?,
        "Without it the `recording` Dialog Object has no `body`",
        "vcon",
    );
    for (flags, expected) in [(&[][..], false), (&["--retain-audio"][..], true)] {
        let dir = tempfile::tempdir()?;
        let run = export_by_rule(dir.path(), G711_CALLS, "state == 'Completed'", flags)?;
        exited(&run, 0);
        printed(&stderr(&run), "Wrote 1 vCon container(s) to 'spool'.");
        let container = the_container(dir.path())?;
        let recording = container
            .pointer("/dialog/0")
            .ok_or("the container has no Dialog Object")?;
        assert_eq!(
            recording.get("type").and_then(|v| v.as_str()),
            Some("recording"),
            "the Dialog Object is a recording"
        );
        assert_eq!(
            recording.get("body").is_some(),
            expected,
            "with flags {flags:?} the body is present: {expected}"
        );
    }
    Ok(())
}

/// A capture with no RTP of the call gives a recording without a body, with
/// `--retain-audio` too.
#[cfg(feature = "vcon")]
#[test]
fn a_capture_without_rtp_gives_a_recording_without_a_body() -> Result<(), TestError> {
    page_says(
        section(VCON, VCON_TROUBLESHOOT)?,
        "or the capture holds no RTP of the call",
        "vcon",
    );
    let dir = tempfile::tempdir()?;
    let run = export_by_rule(
        dir.path(),
        "tests/fixtures/sip_call.pcap",
        "state == 'Completed'",
        &["--retain-audio"],
    )?;
    exited(&run, 0);
    let container = the_container(dir.path())?;
    assert!(
        container.pointer("/dialog/0/body").is_none(),
        "no RTP in the capture, so no audio in the container"
    );
    Ok(())
}

/// The container the page's validation example writes is refused with exit
/// status 3, as the troubleshooting row says.
#[cfg(feature = "vcon")]
#[test]
fn a_container_that_breaks_the_schema_exits_3_as_the_page_says() -> Result<(), TestError> {
    page_says(
        section(VCON, VCON_TROUBLESHOOT)?,
        "`--vcon-validate` exits 3",
        "vcon",
    );
    let example = r#"{"vcon":"0.0.2","uuid":"018f3a2b-4c5d-8e6f-9012-3456789abcde","created_at":"2026-09-01T12:00:00Z","parties":[{"tel":"+12025550100"},{"tel":"+12025550101"}],"dialog":[{"type":"transfer","parties":[0,1]}]}"#;
    assert!(
        VCON.contains(example),
        "the page no longer holds the container this test checks"
    );
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("rejected.vcon.json"), example)?;
    let run = sipnab_in(dir.path(), &["--vcon-validate", "rejected.vcon.json"])?;
    exited(&run, 3);
    printed(
        &stdout(&run),
        "rejected.vcon.json: invalid: 2 findings against",
    );
    Ok(())
}

/// What a stand-in store answers to one request, given the head of it.
#[cfg(all(unix, feature = "vcon"))]
type Answer = dyn Fn(&str) -> (u16, String) + Send + Sync;

/// A store on `127.0.0.1` that answers each request by a rule and keeps the
/// head of each request. The hosted services of the pages are not reachable
/// from a test, so the tests check what sipnab sends and what it does with
/// each answer.
#[cfg(all(unix, feature = "vcon"))]
struct StandInStore {
    addr: std::net::SocketAddr,
    heads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(all(unix, feature = "vcon"))]
impl StandInStore {
    /// Starts the store with `answer` as its rule.
    fn start(
        answer: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
    ) -> Result<Self, TestError> {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (log, halt) = (heads.clone(), stop.clone());
        let answer: Box<Answer> = Box::new(answer);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = stream {
                    let _ = Self::serve(stream, &log, answer.as_ref());
                }
            }
        });
        Ok(Self { addr, heads, stop })
    }

    /// Reads one request, keeps its head and answers it.
    fn serve(
        mut stream: std::net::TcpStream,
        log: &std::sync::Mutex<Vec<String>>,
        answer: &Answer,
    ) -> Result<(), TestError> {
        use std::io::{Read as _, Write as _};
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte)? == 0 {
                return Ok(());
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body)?;
        let (status, text) = answer(&head);
        log.lock()
            .map_err(|_| "the request log is poisoned")?
            .push(head);
        let reply = format!(
            "HTTP/1.1 {status} Stand-in\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{text}",
            text.len()
        );
        stream.write_all(reply.as_bytes())?;
        stream.flush()?;
        Ok(())
    }

    /// `http://127.0.0.1:<port>`.
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The head of each request so far.
    fn heads(&self) -> Result<Vec<String>, TestError> {
        Ok(self
            .heads
            .lock()
            .map_err(|_| "the request log is poisoned")?
            .clone())
    }
}

#[cfg(all(unix, feature = "vcon"))]
impl Drop for StandInStore {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake the accept loop so that it reads the flag and ends.
        let _ = std::net::TcpStream::connect(self.addr);
    }
}

/// A token for the tests, built at run time so that no scanner reads a
/// literal credential here.
#[cfg(all(unix, feature = "vcon"))]
fn store_token() -> String {
    format!("howto_{}", "5c1e7a90d2b4")
}

/// Writes `text` and a newline to `name` under `dir` with mode 0600.
#[cfg(all(unix, feature = "vcon"))]
fn private_file(dir: &Path, name: &str, text: &str) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, format!("{text}\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// A directory with the page's export in `spool` and the token in
/// `vcon-store.key`, mode 0600.
#[cfg(all(unix, feature = "vcon"))]
fn spool_with_one_call() -> Result<tempfile::TempDir, TestError> {
    let dir = tempfile::tempdir()?;
    let run = export_by_rule(
        dir.path(),
        G711_CALLS,
        "state == 'Completed'",
        &["--retain-audio"],
    )?;
    exited(&run, 0);
    printed(&stderr(&run), "Wrote 1 vCon container(s) to 'spool'.");
    private_file(dir.path(), "vcon-store.key", &store_token())?;
    Ok(dir)
}

/// Runs the forwarder of the vcon.store page once against `url`, with
/// `extra` flags.
#[cfg(all(unix, feature = "vcon"))]
fn forward_to_store(dir: &Path, url: &str, extra: &[&str]) -> Result<Output, TestError> {
    let mut args = vec![
        "--vcon-forward",
        "spool",
        "--vcon-forward-kind",
        "vcon-store",
        "--vcon-forward-url",
        url,
        "--vcon-forward-auth-file",
        "vcon-store.key",
        "--vcon-forward-once",
    ];
    args.extend_from_slice(extra);
    sipnab_in(dir, &args)
}

/// The `pending`, `delivered` and `failed` counts `--vcon-spool-status`
/// prints for `spool` under `dir`, and the whole answer.
#[cfg(all(unix, feature = "vcon"))]
fn spool_counts(dir: &Path) -> Result<((u64, u64, u64), serde_json::Value), TestError> {
    let run = sipnab_in(dir, &["--vcon-spool-status", "spool"])?;
    exited(&run, 0);
    let answer: serde_json::Value = serde_json::from_str(&stdout(&run))?;
    let count = |name: &str| {
        answer
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("the answer has no {name} count"))
    };
    let counts = (count("pending")?, count("delivered")?, count("failed")?);
    Ok((counts, answer))
}

/// The prerequisites of the vcon.store page name the feature, the builds
/// without it, the token, the host and the other system.
#[test]
fn the_store_prerequisites_name_the_feature_the_token_and_the_other_system() -> Result<(), TestError>
{
    let needs = section(VCON_STORE, "## Before you start")?;
    for named in [
        "`vcon` feature",
        "`-noaudio` release packages and the static musl",
        "other system",
        "`$VCON_STORE_TOKEN`",
        "`api.vcon.store`",
    ] {
        page_says(needs, named, "vcon-store");
    }
    Ok(())
}

/// The heading of the check of the vcon.store page.
#[cfg(all(unix, feature = "vcon"))]
const STORE_CHECK: &str = "## Check that the store accepted each container";

/// Before the forwarder runs, the check shows the written container under
/// `pending`.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn the_store_check_shows_a_written_container_as_pending() -> Result<(), TestError> {
    page_says(
        section(VCON_STORE, STORE_CHECK)?,
        "shows each written container\nunder `pending`",
        "vcon-store",
    );
    let dir = spool_with_one_call()?;
    let (counts, _) = spool_counts(dir.path())?;
    assert_eq!(counts, (1, 0, 0), "pending, delivered, failed");
    Ok(())
}

/// After a `201`, the check shows what the page says a delivery that worked
/// shows, the forwarder exits 0, and the request is the one the page
/// describes: a `POST` to `/v1/vcons` with the token as a bearer.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn the_store_check_shows_a_delivery_that_worked() -> Result<(), TestError> {
    let check = section(VCON_STORE, STORE_CHECK)?;
    for stated in [
        "`pending` is `0`",
        "`failed` is `0`",
        "`delivered` is the number",
    ] {
        page_says(check, stated, "vcon-store");
    }
    let store = StandInStore::start(|_| (201, "{}".to_string()))?;
    let dir = spool_with_one_call()?;
    let run = forward_to_store(dir.path(), &store.url(), &[])?;
    exited(&run, 0);
    printed(&stderr(&run), "answered 201; moved to 'spool/delivered'");
    assert!(
        !stderr(&run).contains(&store_token()),
        "the forwarder never prints the token"
    );
    let heads = store.heads()?;
    assert_eq!(heads.len(), 1, "one request for one container");
    assert!(
        heads[0].starts_with("POST /v1/vcons HTTP/1.1"),
        "the kind adds /v1/vcons to the base URL: {}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_lowercase()
            .contains(&format!("authorization: bearer {}", store_token())),
        "the token goes as a bearer"
    );
    let (counts, _) = spool_counts(dir.path())?;
    assert_eq!(counts, (0, 1, 0), "pending, delivered, failed");
    Ok(())
}

/// A `409` is a refusal: exit status 1, the container in `spool/failed`, and
/// the check lists the answer.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn a_409_from_the_store_is_the_refusal_the_page_describes() -> Result<(), TestError> {
    page_says(
        section(VCON_STORE, TROUBLESHOOT)?,
        "lands in `spool/failed` with status `409`",
        "vcon-store",
    );
    let store = StandInStore::start(|_| (409, r#"{"error": "vCon already exists"}"#.to_string()))?;
    let dir = spool_with_one_call()?;
    let run = forward_to_store(dir.path(), &store.url(), &[])?;
    exited(&run, 1);
    printed(
        &stderr(&run),
        "answered 409; moved to 'spool/failed' beside",
    );
    let ((pending, delivered, failed), answer) = spool_counts(dir.path())?;
    assert_eq!((pending, delivered, failed), (0, 0, 1), "one refusal");
    assert_eq!(
        answer
            .pointer("/failures/0/record/status")
            .and_then(serde_json::Value::as_u64),
        Some(409),
        "the check lists the answer of the store: {answer}"
    );
    Ok(())
}

/// With `--vcon-forward-replace-url`, a `409` is followed by a `PUT` to the
/// uuid of the container, and the delivery counts as done.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn a_409_with_a_replace_url_is_followed_by_the_put_the_page_describes() -> Result<(), TestError> {
    page_says(VCON_STORE, "--vcon-forward-replace-url", "vcon-store");
    let store = StandInStore::start(|head| {
        if head.starts_with("PUT ") {
            (200, "{}".to_string())
        } else {
            (409, r#"{"error": "vCon already exists"}"#.to_string())
        }
    })?;
    let dir = spool_with_one_call()?;
    let uuid = the_container(dir.path())?
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("the container has no uuid")?
        .to_string();
    let replace = format!("{}/v1/vcons/{{uuid}}", store.url());
    let run = forward_to_store(
        dir.path(),
        &store.url(),
        &["--vcon-forward-replace-url", &replace],
    )?;
    exited(&run, 0);
    let heads = store.heads()?;
    assert_eq!(heads.len(), 2, "a POST and then a PUT: {heads:?}");
    assert!(
        heads[1].starts_with(&format!("PUT /v1/vcons/{uuid} HTTP/1.1")),
        "the PUT names the uuid: {}",
        heads[1]
    );
    let (counts, _) = spool_counts(dir.path())?;
    assert_eq!(counts, (0, 1, 0), "pending, delivered, failed");
    Ok(())
}

/// A `401` stops the forwarder with exit status 3 and moves no file.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn a_401_from_the_store_stops_the_forwarder_as_the_page_says() -> Result<(), TestError> {
    let rows = section(VCON_STORE, TROUBLESHOOT)?;
    page_says(
        rows,
        "The forwarder exits `3` and logs `answered 401`",
        "vcon-store",
    );
    let stopped = "A 401 refuses the credentials or the client for every container alike";
    page_says(rows, stopped, "vcon-store");
    let store = StandInStore::start(|_| (401, r#"{"error":"unauthorized"}"#.to_string()))?;
    let dir = spool_with_one_call()?;
    let run = forward_to_store(dir.path(), &store.url(), &[])?;
    exited(&run, 3);
    printed(&stderr(&run), "answered 401");
    printed(&stderr(&run), stopped);
    let (counts, _) = spool_counts(dir.path())?;
    assert_eq!(counts, (1, 0, 0), "every container is still in the spool");
    Ok(())
}

/// A `500` keeps the container in the spool, and with `--vcon-forward-once`
/// the run exits 1.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn a_500_from_the_store_keeps_the_container_as_the_page_says() -> Result<(), TestError> {
    page_says(
        section(VCON_STORE, TROUBLESHOOT)?,
        "answered 500; will\n  retry",
        "vcon-store",
    );
    let store = StandInStore::start(|_| (500, "{}".to_string()))?;
    let dir = spool_with_one_call()?;
    let run = forward_to_store(dir.path(), &store.url(), &[])?;
    exited(&run, 1);
    printed(&stderr(&run), "answered 500; will retry");
    let (counts, _) = spool_counts(dir.path())?;
    assert_eq!(counts, (1, 0, 0), "the container waits in the spool");
    Ok(())
}

/// A token file that other users can read is refused with exit status 2 and
/// the message the page quotes, before any request.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn a_token_file_others_can_read_gives_the_message_the_page_quotes() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let message = "--vcon-forward-auth-file 'vcon-store.key' can be read or written by other \
                   users (mode 0644); chmod 600 it";
    page_says(VCON_STORE, message, "vcon-store");
    let store = StandInStore::start(|_| (201, "{}".to_string()))?;
    let dir = spool_with_one_call()?;
    std::fs::set_permissions(
        dir.path().join("vcon-store.key"),
        std::fs::Permissions::from_mode(0o644),
    )?;
    let run = forward_to_store(dir.path(), &store.url(), &[])?;
    exited(&run, 2);
    printed(&stderr(&run), message);
    assert!(store.heads()?.is_empty(), "nothing was sent");
    Ok(())
}

/// The fetcher reads `/v1/vcons/{uuid}` with the token as a bearer, removes
/// the `_meta` member and writes the container with mode 0600.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn the_fetcher_writes_the_container_alone_as_the_page_says() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let read_back = section(VCON_STORE, "## Read a stored vCon back")?;
    for stated in [
        "removes the `_meta` member",
        "mode 0600",
        "`/v1/vcons/{uuid}`",
    ] {
        page_says(read_back, stated, "vcon-store");
    }
    let dir = spool_with_one_call()?;
    let mut held = the_container(dir.path())?;
    let uuid = held
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("the container has no uuid")?
        .to_string();
    held.as_object_mut()
        .ok_or("the container is not an object")?
        .insert("_meta".to_string(), serde_json::json!({"stored": true}));
    let body = held.to_string();
    let store = StandInStore::start(move |_| (200, body.clone()))?;
    let run = sipnab_in(
        dir.path(),
        &[
            "--vcon-fetch",
            &uuid,
            "--vcon-fetch-kind",
            "vcon-store",
            "--vcon-fetch-url",
            &store.url(),
            "--vcon-fetch-auth-file",
            "vcon-store.key",
            "--vcon-fetch-out",
            "fetched",
        ],
    )?;
    exited(&run, 0);
    let heads = store.heads()?;
    assert_eq!(heads.len(), 1, "one request: {heads:?}");
    assert!(
        heads[0].starts_with(&format!("GET /v1/vcons/{uuid} HTTP/1.1")),
        "the kind reads /v1/vcons/<uuid>: {}",
        heads[0]
    );
    let written = dir.path().join("fetched").join(format!("{uuid}.vcon.json"));
    let fetched: serde_json::Value = serde_json::from_slice(&std::fs::read(&written)?)?;
    assert!(
        fetched.get("_meta").is_none(),
        "the store's member is removed"
    );
    assert_eq!(
        fetched.get("uuid").and_then(|v| v.as_str()),
        Some(uuid.as_str()),
        "the container of that uuid"
    );
    assert_eq!(
        std::fs::metadata(&written)?.permissions().mode() & 0o777,
        0o600,
        "the file is private"
    );
    Ok(())
}

/// The prerequisites of the vcon-sipnab page name the package, the change on
/// the vCon server and the system that does not change.
#[test]
fn the_vcon_sipnab_prerequisites_say_what_changes_on_the_other_system() -> Result<(), TestError> {
    let needs = section(VCON_SIPNAB, "## Before you start")?;
    for named in [
        "other system",
        "an ingress list named `sipnab`",
        "`vcons_observed`",
        "`conserver` and `api`",
        "without the `-noaudio` suffix",
        "`sipnab_<version>_amd64.deb`",
        "No change on the SIP server",
    ] {
        page_says(needs, named, "vcon-sipnab");
    }
    // The first step is where the page makes the change it announces.
    let step = from_heading(VCON_SIPNAB, "## Add an ingress list and a chain for sipnab")?;
    for made in [
        "table_name: vcons_observed",
        "docker compose restart conserver api",
    ] {
        page_says(step, made, "vcon-sipnab");
    }
    page_says(
        from_heading(VCON_SIPNAB, "## Install sipnab")?,
        "sipnab_${V}_amd64.deb",
        "vcon-sipnab",
    );
    Ok(())
}

/// The expression the check of the page gives, which leaves the recording
/// session out, is one sipnab accepts, and it writes the finished call of
/// the sample.
#[cfg(feature = "vcon")]
#[test]
fn the_vcon_sipnab_check_gives_an_expression_sipnab_accepts() -> Result<(), TestError> {
    let expression = "state == 'Completed' and dst.port != 5090";
    page_says(
        from_heading(
            VCON_SIPNAB,
            "## Check that a call's vCon reaches the server",
        )?,
        expression,
        "vcon-sipnab",
    );
    let dir = tempfile::tempdir()?;
    let run = export_by_rule(dir.path(), G711_CALLS, expression, &[])?;
    exited(&run, 0);
    printed(&stderr(&run), "Wrote 1 vCon container(s) to 'spool'.");
    let left_out = tempfile::tempdir()?;
    let run = export_by_rule(
        left_out.path(),
        G711_CALLS,
        "state == 'Completed' and dst.port != 5060",
        &[],
    )?;
    exited(&run, 0);
    printed(&stderr(&run), "Wrote 0 vCon container(s) to 'spool'.");
    Ok(())
}

/// A directory with one exported call in `spool` and the bare key in
/// `conserver.key`, mode 0600, as the conserver section of the page sets up.
#[cfg(all(unix, feature = "vcon"))]
fn conserver_demo() -> Result<tempfile::TempDir, TestError> {
    let dir = tempfile::tempdir()?;
    let run = export_by_rule(
        dir.path(),
        "tests/fixtures/sip_call.pcap",
        "state == 'Completed'",
        &[],
    )?;
    exited(&run, 0);
    printed(&stderr(&run), "Wrote 1 vCon container(s) to 'spool'.");
    private_file(dir.path(), "conserver.key", &store_token())?;
    Ok(dir)
}

/// Fails unless the one request the store received is the ingest request the
/// page describes, with the key in the conserver header.
#[cfg(all(unix, feature = "vcon"))]
fn posted_to_the_sipnab_list(store: &StandInStore) -> Result<(), TestError> {
    let heads = store.heads()?;
    assert_eq!(heads.len(), 1, "one request for one container: {heads:?}");
    assert!(
        heads[0].starts_with("POST /vcon/external-ingress?ingress_list=sipnab HTTP/1.1"),
        "the ingest path of the sipnab list: {}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_lowercase()
            .contains(&format!("x-conserver-api-token: {}", store_token())),
        "the key goes in the conserver header"
    );
    Ok(())
}

/// The conserver kind adds the ingest path of the `sipnab` list and sends a
/// bare key in the conserver header; a `204` is logged as delivered, the run
/// exits 0 and the file is in `spool/delivered`.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn the_conserver_kind_sends_what_the_vcon_sipnab_page_describes() -> Result<(), TestError> {
    // The section holds shell comments, which end `section`.
    let stated = from_heading(VCON_SIPNAB, "### The same delivery with the conserver kind")?;
    for text in [
        "`/vcon/external-ingress?ingress_list=sipnab`",
        "`x-conserver-api-token: <key>`",
        "the server's `204`",
    ] {
        page_says(stated, text, "vcon-sipnab");
    }
    let store = StandInStore::start(|_| (204, String::new()))?;
    let dir = conserver_demo()?;
    let run = sipnab_in(
        dir.path(),
        &[
            "--vcon-forward",
            "spool",
            "--vcon-forward-kind",
            "conserver",
            "--vcon-forward-url",
            &store.url(),
            "--vcon-forward-auth-file",
            "conserver.key",
            "--vcon-forward-once",
        ],
    )?;
    exited(&run, 0);
    printed(&stderr(&run), "answered 204; moved to 'spool/delivered'");
    posted_to_the_sipnab_list(&store)?;
    let delivered = std::fs::read_dir(dir.path().join("spool/delivered"))?.count();
    assert_eq!(delivered, 1, "the file is in spool/delivered");
    Ok(())
}

/// The first form of the page gives the whole URL and an auth file that
/// holds the header line. It sends the same request.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn the_whole_url_and_a_header_line_send_the_same_request() -> Result<(), TestError> {
    page_says(
        VCON_SIPNAB,
        "The auth file holds one line, `x-conserver-api-token: <key>`",
        "vcon-sipnab",
    );
    let store = StandInStore::start(|_| (204, String::new()))?;
    let dir = conserver_demo()?;
    private_file(
        dir.path(),
        "vcon-forward.auth",
        &format!("x-conserver-api-token: {}", store_token()),
    )?;
    let url = format!("{}/vcon/external-ingress?ingress_list=sipnab", store.url());
    let run = sipnab_in(
        dir.path(),
        &[
            "--vcon-forward",
            "spool",
            "--vcon-forward-url",
            &url,
            "--vcon-forward-auth-file",
            "vcon-forward.auth",
            "--vcon-forward-once",
        ],
    )?;
    exited(&run, 0);
    posted_to_the_sipnab_list(&store)?;
    Ok(())
}

/// Runs sipnab in `dir` with the key in `SIPNAB_VCON_FORWARD_AUTH`.
#[cfg(all(unix, feature = "vcon"))]
fn sipnab_with_key_in_environment(dir: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", dir.join("no-such-config-dir"))
        .env("SIPNAB_VCON_FORWARD_AUTH", store_token())
        .stdin(Stdio::null())
        .output()?)
}

/// The key in the environment variable sends the same request, and the
/// variable beside an auth file is refused with exit status 2.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn the_key_in_the_environment_works_and_is_refused_beside_a_file() -> Result<(), TestError> {
    page_says(
        VCON_SIPNAB,
        "sipnab refuses the variable beside an auth file",
        "vcon-sipnab",
    );
    let store = StandInStore::start(|_| (204, String::new()))?;
    let dir = conserver_demo()?;
    let url = store.url();
    let base = [
        "--vcon-forward",
        "spool",
        "--vcon-forward-kind",
        "conserver",
        "--vcon-forward-url",
        url.as_str(),
        "--vcon-forward-once",
    ];
    let mut both = base.to_vec();
    both.extend_from_slice(&["--vcon-forward-auth-file", "conserver.key"]);
    let refused = sipnab_with_key_in_environment(dir.path(), &both)?;
    exited(&refused, 2);
    assert!(store.heads()?.is_empty(), "a refused run sends nothing");
    let run = sipnab_with_key_in_environment(dir.path(), &base)?;
    exited(&run, 0);
    posted_to_the_sipnab_list(&store)?;
    Ok(())
}

/// The settings in a `[vcon_forward]` section, with the spool and
/// `--vcon-forward-once` on the command line, send the same request.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn the_settings_in_a_config_file_send_the_same_request() -> Result<(), TestError> {
    page_says(
        VCON_SIPNAB,
        "[vcon_forward]\nkind = \"conserver\"",
        "vcon-sipnab",
    );
    let store = StandInStore::start(|_| (204, String::new()))?;
    let dir = conserver_demo()?;
    std::fs::write(
        dir.path().join("forward.toml"),
        format!(
            "[vcon_forward]\nkind = \"conserver\"\nurl = \"{}\"\nauth_file = \"{}\"\n",
            store.url(),
            dir.path().join("conserver.key").display()
        ),
    )?;
    let run = sipnab_in(
        dir.path(),
        &[
            "--vcon-forward",
            "spool",
            "--config",
            "forward.toml",
            "--vcon-forward-once",
        ],
    )?;
    exited(&run, 0);
    posted_to_the_sipnab_list(&store)?;
    Ok(())
}

/// A `403` stops the forwarder with exit status 3, the log quotes the reason
/// of the server, and every container stays in the spool.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn a_403_from_the_vcon_server_stops_the_forwarder_as_the_page_says() -> Result<(), TestError> {
    let reason = r#"{"detail":"Invalid API Key for ingress list 'sipnab'"}"#;
    let rows = from_heading(VCON_SIPNAB, TROUBLESHOOT)?;
    page_says(
        rows,
        "`sipnab --vcon-forward` stops and exits `3`",
        "vcon-sipnab",
    );
    page_says(rows, reason, "vcon-sipnab");
    let store = StandInStore::start(move |_| (403, reason.to_string()))?;
    let dir = conserver_demo()?;
    let run = sipnab_in(
        dir.path(),
        &[
            "--vcon-forward",
            "spool",
            "--vcon-forward-kind",
            "conserver",
            "--vcon-forward-url",
            &store.url(),
            "--vcon-forward-auth-file",
            "conserver.key",
            "--vcon-forward-once",
        ],
    )?;
    exited(&run, 3);
    printed(&stderr(&run), "answered 403");
    printed(&stderr(&run), "Invalid API Key for ingress list 'sipnab'");
    let (counts, _) = spool_counts(dir.path())?;
    assert_eq!(counts, (1, 0, 0), "every container is still in the spool");
    Ok(())
}

/// With nothing listening at the URL the forwarder logs `not reached` and
/// the refusal of the connection, keeps the container, and with
/// `--vcon-forward-once` exits 1.
#[cfg(all(target_os = "linux", feature = "vcon"))]
#[test]
fn a_url_nothing_listens_at_gives_the_lines_the_vcon_sipnab_page_quotes() -> Result<(), TestError> {
    let rows = from_heading(VCON_SIPNAB, TROUBLESHOOT)?;
    let ending = "Connection refused (os error 111); will retry";
    page_says(rows, "logs `not reached`", "vcon-sipnab");
    page_says(rows, ending, "vcon-sipnab");
    let closed = ports::refused_tcp_port().map_err(|e| e.to_string())?;
    let dir = conserver_demo()?;
    let run = sipnab_in(
        dir.path(),
        &[
            "--vcon-forward",
            "spool",
            "--vcon-forward-kind",
            "conserver",
            "--vcon-forward-url",
            &format!("http://{}", closed.addr()),
            "--vcon-forward-auth-file",
            "conserver.key",
            "--vcon-forward-once",
        ],
    )?;
    exited(&run, 1);
    printed(&stderr(&run), "not reached");
    printed(&stderr(&run), ending);
    let (counts, _) = spool_counts(dir.path())?;
    assert_eq!(counts, (1, 0, 0), "the container stays in the spool");
    Ok(())
}

/// A `422` moves the container to `spool/failed` with a record of the reason
/// beside it, and `--vcon-spool-status` lists the refusal.
#[cfg(all(unix, feature = "vcon"))]
#[test]
fn a_422_from_the_vcon_server_lands_in_failed_as_the_page_says() -> Result<(), TestError> {
    let rows = from_heading(VCON_SIPNAB, TROUBLESHOOT)?;
    page_says(
        rows,
        "lands in `spool/failed` with `answered 422`",
        "vcon-sipnab",
    );
    let reason = r#"{"detail":[{"loc":["body","uuid"],"msg":"Field required"}]}"#;
    let store = StandInStore::start(move |_| (422, reason.to_string()))?;
    let dir = conserver_demo()?;
    let run = sipnab_in(
        dir.path(),
        &[
            "--vcon-forward",
            "spool",
            "--vcon-forward-kind",
            "conserver",
            "--vcon-forward-url",
            &store.url(),
            "--vcon-forward-auth-file",
            "conserver.key",
            "--vcon-forward-once",
        ],
    )?;
    exited(&run, 1);
    printed(&stderr(&run), "answered 422; moved to 'spool/failed'");
    let ((pending, delivered, failed), answer) = spool_counts(dir.path())?;
    assert_eq!((pending, delivered, failed), (0, 0, 1), "one refusal");
    let body = answer
        .pointer("/failures/0/record/body")
        .and_then(|v| v.as_str())
        .ok_or("the refusal has no recorded body")?;
    assert!(
        body.contains(r#""loc":["body","uuid"],"msg":"Field required""#),
        "the record holds the reason of the server: {body}"
    );
    Ok(())
}

/// The vCon server page runs no sipnab command, and its stack is not
/// reachable from a test. The test holds the prerequisites to the steps of
/// the page: each change they announce is made by a step that exists.
#[test]
fn the_vcon_server_prerequisites_say_what_changes_on_each_other_system() -> Result<(), TestError> {
    let needs = section(VCON_SERVER, "## Before you start: your SIP server")?;
    for named in [
        "other system",
        "Debian 13 or Ubuntu 24.04",
        "`sudo`",
        "It gains the `siprec` module",
        "replaces its configuration file",
        "sends a copy of each call's media to the recorder",
        "port 8000",
    ] {
        page_says(needs, named, "vcon-server");
    }
    for step in [
        "## Install OpenSIPS's recording module",
        "## Configure OpenSIPS to record every call",
        "## Build rtpengine",
        "## Put the parts on different machines",
        "## Tested on",
    ] {
        assert!(
            VCON_SERVER.contains(&format!("\n{step}\n")),
            "the prerequisites name the step {step:?}, which the page no longer has"
        );
    }
    for made in [
        "loadmodule \"siprec.so\"",
        "siprec_start_recording(\"sip:127.0.0.1:5090\")",
        "ports: [\"8000:8000\"]",
    ] {
        page_says(VCON_SERVER, made, "vcon-server");
    }
    Ok(())
}

/// The check of the vCon server page reads the recorder's log and the
/// table the recorder's chain writes, and states what the test call gives.
#[test]
fn the_vcon_server_check_reads_the_log_and_the_table() -> Result<(), TestError> {
    let check = from_heading(VCON_SERVER, "## Check that the call's vCon is in the store")?;
    let check = check
        .split("\n## Operate it\n")
        .next()
        .ok_or("the check has no text")?;
    for stated in [
        "docker compose logs --since 5m srs",
        "from vcons_recorded order by created_at desc limit 1",
        "2 parties",
        "2 recordings",
    ] {
        page_says(check, stated, "vcon-server");
    }
    page_says(VCON_SERVER, "table_name: vcons_recorded", "vcon-server");
    assert_eq!(
        VCON_SERVER
            .matches("\"Check that the call's vCon is in the store\"")
            .count(),
        2,
        "the section on different machines names the check twice"
    );
    assert!(
        !VCON_SERVER.contains("\"Find the call's vCon\""),
        "a step still refers to the check by its old name"
    );
    Ok(())
}

/// What the harness page says a host needs is what the files of the harness
/// use: the two `make` targets, the tools of the voice script, Python for
/// the test script, and a conserver that the stack does not start.
#[test]
fn the_harness_prerequisites_name_what_the_harness_files_use() -> Result<(), TestError> {
    let needs = section(VCON_HARNESS, "### What you need")?;
    for named in [
        "Docker and Docker Compose",
        "`make`",
        "`curl` and `jq`",
        "`python3`",
        "the Python `piper` module",
        "`sox` with `soxi`",
        "`PIPER_VOICES`",
        "other system",
        "The\n  harness does not start one",
        "an ingress list named `sipnab`",
    ] {
        page_says(needs, named, "vcon-harness");
    }
    for target in ["\nsigning-key:", "\napi-key:"] {
        assert!(
            HARNESS_MAKEFILE.contains(target),
            "the page runs `make {}`, which the Makefile lacks",
            target.trim().trim_end_matches(':')
        );
    }
    let speech = std::fs::read_to_string(repo().join(HARNESS_SPEECH))?;
    for used in ["from piper import", "soxi ", "sox ", "PIPER_VOICES"] {
        assert!(
            speech.contains(used),
            "the page says the voice script needs {used:?}, which the script does not use"
        );
    }
    assert!(
        std::fs::read_to_string(repo().join(HARNESS_E2E))?.contains("python3 "),
        "the page says the test script runs Python clients"
    );
    assert!(
        !HARNESS_COMPOSE.contains("conserver"),
        "the page says the harness starts no conserver, and the compose file names one"
    );
    for service in [
        "opensips-1:",
        "rtpengine:",
        "sipnab-proxy:",
        "sipnab-relay:",
        "sipp-uac:",
    ] {
        assert!(
            HARNESS_COMPOSE.contains(&format!("\n  {service}\n")),
            "the page says {service} runs in a container of the harness"
        );
    }
    // The page runs the two scripts from the `harness` directory.
    let speech_name = HARNESS_SPEECH.trim_start_matches("harness/");
    let e2e_name = HARNESS_E2E.trim_start_matches("harness/");
    for command in ["make signing-key", "make api-key", speech_name, e2e_name] {
        page_says(VCON_HARNESS, command, "vcon-harness");
    }
    Ok(())
}

/// The check of the harness page asks each node for `capture_identity` in
/// `/v1/stats`. A sipnab started with the REST API answers with that member
/// and a `node` in it.
#[cfg(all(unix, feature = "api"))]
#[test]
fn the_harness_check_reads_a_member_the_rest_api_answers_with() -> Result<(), TestError> {
    let check = section(VCON_HARNESS, "### Check that both nodes answer")?;
    for stated in [
        "/v1/stats | jq .capture_identity",
        "`capture_identity.node`",
    ] {
        page_says(check, stated, "vcon-harness");
    }
    let token = minted(SIGNING_KEY, &[])?;
    let api =
        server::ApiServer::spawn(&["--api-signing-key", SIGNING_KEY]).map_err(|e| e.to_string())?;
    let stats = api
        .get_bearer("/v1/stats", &token)
        .map_err(|e| e.to_string())?;
    assert_eq!(stats.status, 200, "the stats route: {}", stats.body);
    let answer = stats.json().map_err(|e| e.to_string())?;
    let node = answer
        .pointer("/capture_identity/node")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no capture_identity.node in {answer}"))?;
    assert!(!node.is_empty(), "the node has a name");
    Ok(())
}

// ── fleet: a center of a build without the history store ─────────────────

/// The line the fleet page shows for a center of a build without the history
/// store, with the level and the target in front as the page has it.
fn fleet_page_no_store_line() -> Result<&'static str, TestError> {
    FLEET
        .lines()
        .map(str::trim)
        .find(|line| {
            line.starts_with("WARN sipnab::app::fleet_center: fleet center: this build has no")
        })
        .ok_or_else(|| "docs/fleet.md no longer shows the line of a build without the store".into())
}

/// The text of that line after `fleet center: `, which is also the `detail`
/// of the `501` answer.
fn fleet_page_no_store_text() -> Result<&'static str, TestError> {
    fleet_page_no_store_line()?
        .split_once("fleet center: ")
        .map(|(_, text)| text)
        .ok_or_else(|| "the line has no text after `fleet center: `".into())
}

/// In every build with the REST API, the line of the page is the text the
/// code logs and answers with, whole.
#[cfg(feature = "api")]
#[test]
fn the_fleet_page_quotes_the_no_store_text_of_the_code() -> Result<(), TestError> {
    assert_eq!(
        fleet_page_no_store_text()?,
        sipnab::app::fleet_center::NO_HISTORY_STORE,
        "docs/fleet.md and NO_HISTORY_STORE in src/app/fleet_center.rs differ"
    );
    let rows = from_heading(FLEET, "### Keep call history at the center")?;
    for stated in [
        "**`501` and `this build has no history store`.**",
        "the route\n  answers `501`",
    ] {
        page_says(rows, stated, "fleet");
    }
    Ok(())
}

/// A center of a build without the history store, started as the page starts
/// one (over HTTP on loopback, as the run of the page was), logs the `WARN`
/// line the page shows, and `GET /v1/fleet/calls` answers `501` with the
/// same text as its `detail`.
#[cfg(all(unix, feature = "api", not(feature = "fleet-store")))]
#[test]
fn a_center_without_the_history_store_logs_and_answers_what_the_fleet_page_shows()
-> Result<(), TestError> {
    let page_line = fleet_page_no_store_line()?;
    let dir = tempfile::tempdir()?;
    let signing = "howto-claims-fleet-center-signing-key-0123456789";
    private_text(dir.path(), "center.signing", signing)?;
    let keygen = sipnab_in(dir.path(), &["fleet", "keygen", "--out", "center.storekey"])?;
    exited(&keygen, 0);
    let (store, store_key, signing_file) = (
        dir.path().join("center.store"),
        dir.path().join("center.storekey"),
        dir.path().join("center.signing"),
    );
    let center = fleet_center::Center::start(&[
        "--listen",
        "127.0.0.1:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        signing_file.to_str().ok_or("utf-8")?,
    ])
    .map_err(|e| e.to_string())?;
    let logged = center
        .early
        .iter()
        .find(|line| line.contains("this build has no history store"))
        .ok_or_else(|| format!("the center logged no such line: {:?}", center.early))?;
    assert!(
        logged.ends_with(page_line),
        "the center logged\n{logged}\nand the page shows\n{page_line}"
    );
    let token = sipnab::auth::mint(
        signing.as_bytes(),
        "ops",
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_FULL,
    );
    let (status, body) = fleet_center::http(&center.addr, "GET", "/v1/fleet/calls", &token, b"")
        .map_err(|e| e.to_string())?;
    assert_eq!(status, 501, "the page says the route answers 501: {body}");
    let answer: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        answer.get("detail").and_then(|v| v.as_str()),
        Some(fleet_page_no_store_text()?),
        "the answer carries the text of the line: {answer}"
    );
    assert_eq!(
        answer.get("status").and_then(serde_json::Value::as_u64),
        Some(501),
        "the problem document names the status: {answer}"
    );
    Ok(())
}

/// Writes `text` to `name` under `dir` with mode 0600.
#[cfg(all(unix, feature = "api", not(feature = "fleet-store")))]
fn private_text(dir: &Path, name: &str, text: &str) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, text)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

// ── install: WAV export in a build with and without the audio feature ────

/// `--export-audio` writes the WAV file of the sample call and prints the
/// summary the CLI reference quotes. The test runs in every feature set: in
/// a build without the `audio` feature, as the `-noaudio` packages and the
/// static musl build are, it is the check of what the install page says
/// about WAV export there.
#[test]
fn wav_export_writes_the_file_in_this_build() -> Result<(), TestError> {
    let summary = "Exported 8.5s of mu-law audio (425 frames, PCMU/8000Hz) to call.wav";
    page_says(
        include_str!("../docs/cli-reference.md"),
        summary,
        "cli-reference",
    );
    // What the install page and the README say of WAV export and the
    // `audio` feature. A run of this test in a build without `audio` is what
    // shows each of them.
    for stated in [
        "WAV export included, is in the binary and works without the plugin",
        "WAV export (`--export-audio`) works as in the standard package",
        "WAV export (`--export-audio`) does not need it",
    ] {
        page_says(INSTALL, stated, "install");
    }
    let readme = include_str!("../README.md");
    page_says(readme, "WAV export does not need it", "README");
    for (name, text) in [("docs/install.md", INSTALL), ("README.md", readme)] {
        for wrong in ["playback in the TUI + WAV export", "plugin, and WAV export"] {
            assert!(
                !text.contains(wrong),
                "{name} still lists WAV export as part of the audio feature: {wrong:?}"
            );
        }
    }
    let dir = tempfile::tempdir()?;
    let sample = capture(G711_CALLS)?.display().to_string();
    let run = sipnab_in(
        dir.path(),
        &[
            "-N",
            "-I",
            &sample,
            "--export-audio",
            G711_CALL_ID,
            "--export-audio-out",
            "call.wav",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    exited(&run, 0);
    let said = format!("{}{}", stdout(&run), stderr(&run));
    printed(&said, summary);
    let wav = std::fs::read(dir.path().join("call.wav"))?;
    assert!(
        wav.starts_with(b"RIFF") && wav.get(8..12) == Some(&b"WAVE"[..]),
        "call.wav is a WAV file"
    );
    assert!(
        wav.len() > 60_000,
        "8.5 s of 8 kHz audio is more than 60 kB, the file holds {} bytes",
        wav.len()
    );
    Ok(())
}
