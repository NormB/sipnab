// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--call-report` on a recorded call prints the SIPREC block.
//!
//! `docs/examples.md` recipe "See who is on a recorded call" shows `--call-report` printing who is on a
//! recorded call, and the 0.5.152 CHANGELOG entry says the CLI report carries
//! it. The block was added to `--report` only: `--call-report` printed it in
//! its JSON form and left it out of the text and Markdown forms.

#![cfg(feature = "native")]

use std::process::Command;

type TestError = Box<dyn std::error::Error>;

/// A SIPREC INVITE toward a recording server, from `tests/mcp_siprec_test.rs`.
const SIPREC: &str = "tests/pcap-samples/siprec-opensips-invite.pcap";

/// The Call-ID of the SIPREC dialog in [`SIPREC`].
const SIPREC_CALL: &str = "4f1c0a2e-siprec@172.28.0.31";

/// The block recipe "See who is on a recorded call" shows, for this capture's Call-ID.
const BLOCK: &str = "SIPREC recording (4f1c0a2e-siprec@172.28.0.31): session 4f1c0a2e, complete
  participant sip:alice@example.invalid (Alice)
  participant sip:bob@example.invalid
  stream label 0 -> sip:alice@example.invalid
  stream label 1 -> sip:alice@example.invalid
  stream label 2 -> sip:bob@example.invalid
";

/// `sipnab -N -I <SIPREC> --no-config --no-cli-print` plus `extra`; stdout.
fn run(extra: &[&str]) -> Result<String, TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", SIPREC, "--no-config", "--no-cli-print"])
        .args(extra)
        .output()?;
    assert!(out.status.success(), "the run must succeed: {out:?}");
    Ok(String::from_utf8(out.stdout)?)
}

/// The text call report carries the block, line for line as recipe "See who is on a recorded call" shows it.
#[test]
fn the_text_call_report_names_the_recording() -> Result<(), TestError> {
    let out = run(&["--call-report", SIPREC_CALL])?;
    assert!(
        out.contains(&format!("Call Report: {SIPREC_CALL}")),
        "positive control: this is the call report:\n{out}"
    );
    assert!(out.contains(BLOCK), "no SIPREC block:\n{out}");
    Ok(())
}

/// The Markdown call report carries the same block.
#[test]
fn the_markdown_call_report_names_the_recording() -> Result<(), TestError> {
    let out = run(&["--call-report", SIPREC_CALL, "--markdown"])?;
    assert!(
        out.contains(&format!("# Call Report: {SIPREC_CALL}")),
        "positive control: this is the Markdown call report:\n{out}"
    );
    assert!(out.contains(BLOCK), "no SIPREC block:\n{out}");
    Ok(())
}

/// `--report` prints the same block, so the two reports cannot drift apart.
#[test]
fn the_report_and_the_call_report_print_the_same_block() -> Result<(), TestError> {
    let out = run(&["--report"])?;
    assert!(out.contains(BLOCK), "no SIPREC block in --report:\n{out}");
    Ok(())
}
