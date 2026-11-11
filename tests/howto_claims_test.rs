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

/// Without `--keylog` sipnab looks at no TLS record: the run prints no
/// message and the sentence the page quotes.
#[cfg(feature = "tls")]
#[test]
fn a_tls_capture_read_without_keys_prints_what_the_page_quotes() -> Result<(), TestError> {
    let message = "No SIP traffic found.";
    page_says(section(TLS, TLS_TROUBLESHOOT)?, message, "tls-capture");
    let dir = tempfile::tempdir()?;
    let (capture, _) = tls_call(dir.path())?;
    let run = sipnab(&["-N", "-I", &capture])?;
    exited(&run, 0);
    assert_eq!(stdout(&run), "", "nothing decrypted, so no message line");
    printed(&stderr(&run), message);
    printed(&stderr(&run), "0 SIP messages");
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
    page_says(section(TLS, TLS_TROUBLESHOOT)?, message, "tls-capture");
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
    printed(&stderr(&run), message);
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
/// message the troubleshooting table quotes.
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
