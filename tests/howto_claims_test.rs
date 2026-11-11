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

const SAMPLE_CALL: &str = "website/static/demos/sample-call.pcap";
const PROBLEM_CALL: &str = "tests/pcap-samples/sip-problem-call.pcap";
const LOSSY_CALL: &str = "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap";
const SESSION_ID: &str = "tests/fixtures/session-id/opensips-4.0-th-session-id.pcap";

const CHECK: &str = "## Check that it worked";
const TROUBLESHOOT: &str = "## When something does not work";

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
// with no `-N` exits 0 and prints nothing (seen 2026-11-11 with the features
// native,hep,api,mcp,mcp-http). That is recorded as the defect
// NO-TUI-BUILD-SILENT, not stated on the page and not asserted here.
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
