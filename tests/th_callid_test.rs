// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! OpenSIPS `topology_hiding("C")`: the two legs of a hidden call, joined by
//! decoding the hidden Call-ID, on the CLI, REST and MCP.
//!
//! The captures in `tests/fixtures/th-callid/` were recorded from real
//! OpenSIPS by `harness/th-callid/capture.sh` on a private network using only
//! RFC 5737 TEST-NET-1 addresses and `example.com` Call-IDs. Each holds three
//! calls. The caller leg of call N is `N-th-call@example.com`; the callee leg
//! carries the encoded Call-ID OpenSIPS wrote, listed below as it appears on
//! the wire. These values come from OpenSIPS, not from sipnab's encoder, so
//! they pin the decoder to the C implementation.
//!
//! - `opensips-4.0-secret.pcap`: OpenSIPS 4.0.2, `th_callid_passwd` =
//!   [`SECRET`], default prefix.
//! - `opensips-4.0-secret-loop.pcap`: the same, with
//!   `th_callid_loop_protection = 1`, which appends `|<from-tag>`.
//! - `opensips-4.0-default.pcap`: OpenSIPS's default `th_callid_passwd`.
//! - `opensips-4.0-xcid.pcap`: the default secret, plus the documented
//!   `append_hf("X-CID: $ci\r\n")` on the callee leg.
//! - `opensips-3.6-secret.pcap`: OpenSIPS 3.6.9, [`SECRET`].

#![cfg(all(unix, feature = "full"))]

#[path = "support/surface_parity.rs"]
mod surface_parity;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use surface_parity::mcp::{McpSession, ok_payload};
use surface_parity::server::ApiServer;
use surface_parity::{CliRun, normalize_mcp};

type TestError = Box<dyn std::error::Error>;

/// The `th_callid_passwd` the secret captures were recorded with.
const SECRET: &str = "th-lab-secret-0100";

const FIX: &str = "tests/fixtures/th-callid";
const CALLER_1: &str = "1-th-call@example.com";
const HIDDEN_1_SECRET: &str = "DLGCH_RUVZBEwBTB8JIxcdFUBAXVUeFwdA";
const HIDDEN_1_LOOP: &str = "DLGCH_RUVZBEwBTB8JIxcdFUBAXVUeFwdAEFBTGEBcVEURHBw-";
const HIDDEN_1_DEFAULT: &str = "DLGCH_fl0RBn4qMT8jMAAWMiQgPypeBgE+";

/// A secret file and a config naming it, in a fresh directory.
struct Lab {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Lab {
    /// `[sip]` holding `sip_body`, plus a secret file holding `secret`
    /// (mode `mode`) that `sip_body` may name as `{secret_file}`.
    fn new(sip_body: &str, secret: &str, mode: u32) -> Result<Self, TestError> {
        let dir = tempfile::tempdir()?;
        let secret_path = dir.path().join("th.secret");
        std::fs::write(&secret_path, format!("{secret}\n"))?;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(mode))?;
        let config = dir.path().join("sipnab.toml");
        let body = sip_body.replace("{secret_file}", &secret_path.display().to_string());
        std::fs::write(&config, format!("[sip]\n{body}\n"))?;
        Ok(Self { dir, config })
    }

    /// A config whose secret file holds `secret`.
    fn with_secret(secret: &str) -> Result<Self, TestError> {
        Self::new("th_callid_secret_file = \"{secret_file}\"", secret, 0o600)
    }

    fn config(&self) -> &str {
        self.config.to_str().unwrap_or_default()
    }

    fn secret_dir(&self) -> &Path {
        self.dir.path()
    }
}

/// `sipnab -N -I <pcap> --config <config> <args>`, logging at trace so a
/// secret written to any log level would be caught.
fn cli(pcap: &str, config: Option<&str>, args: &[&str]) -> Result<CliRun, TestError> {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", pcap])
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .env("SIPNAB_LOG", "trace");
    if let Some(c) = config {
        cmd.args(["--config", c]);
    } else {
        cmd.args(["--config", "/dev/null"]);
    }
    let out = cmd.args(args).output()?;
    Ok(CliRun {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code(),
    })
}

/// `--correlate <call_id> --json`, which must exit 0.
fn correlate(
    pcap: &str,
    config: Option<&str>,
    call_id: &str,
) -> Result<serde_json::Value, TestError> {
    let run = cli(
        pcap,
        config,
        &[
            "--correlate",
            call_id,
            "--json",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(!run.stderr.contains(SECRET), "a log line shows the secret");
    assert!(!run.stdout.contains(SECRET), "the answer shows the secret");
    run.last_json()
}

/// The legs of a correlated answer whose `method` is `method`.
fn legs_by<'a>(v: &'a serde_json::Value, method: &str) -> Vec<&'a serde_json::Value> {
    v["legs"]
        .as_array()
        .map(|a| a.iter().filter(|l| l["method"] == method).collect())
        .unwrap_or_default()
}

/// T3 + T13, OpenSIPS 4.0.2: the hidden leg of each call joins its caller
/// leg, decoded, from either side; the other two calls are not joined to it.
#[test]
fn opensips_4_0_hidden_leg_joins_its_caller_by_decoding() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-4.0-secret.pcap");
    let lab = Lab::with_secret(SECRET)?;
    let v = correlate(&pcap, Some(lab.config()), HIDDEN_1_SECRET)?;
    let decoded = legs_by(&v, "decoded");
    assert_eq!(decoded.len(), 1, "{v}");
    assert_eq!(decoded[0]["call_id"], CALLER_1, "{v}");
    assert_eq!(decoded[0]["strategy"], "th_callid_decoded", "{v}");
    assert_eq!(decoded[0]["identifier_match"], true, "{v}");
    assert_eq!(decoded[0]["score"], 100, "{v}");
    assert_eq!(v["th_callid"], "decoded", "{v}");
    let v = correlate(&pcap, Some(lab.config()), CALLER_1)?;
    let decoded = legs_by(&v, "decoded");
    assert_eq!(decoded.len(), 1, "{v}");
    assert_eq!(decoded[0]["call_id"], HIDDEN_1_SECRET, "{v}");
    assert!(
        v["th_callid"].is_null(),
        "the caller leg is not hidden: {v}"
    );
    Ok(())
}

/// T3, OpenSIPS 3.6.9: the same scheme, decoded by the same code.
#[test]
fn opensips_3_6_hidden_leg_joins_its_caller_by_decoding() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-3.6-secret.pcap");
    let lab = Lab::with_secret(SECRET)?;
    let v = correlate(&pcap, Some(lab.config()), CALLER_1)?;
    let decoded = legs_by(&v, "decoded");
    assert_eq!(decoded.len(), 1, "{v}");
    assert_eq!(decoded[0]["call_id"], HIDDEN_1_SECRET, "{v}");
    Ok(())
}

/// T4, OpenSIPS 4.0.2 with loop protection: the appended tag is split off and
/// checked, and the leg still joins.
#[test]
fn loop_protection_capture_joins_by_decoding() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-4.0-secret-loop.pcap");
    let lab = Lab::with_secret(SECRET)?;
    let v = correlate(&pcap, Some(lab.config()), HIDDEN_1_LOOP)?;
    let decoded = legs_by(&v, "decoded");
    assert_eq!(decoded.len(), 1, "{v}");
    assert_eq!(decoded[0]["call_id"], CALLER_1, "{v}");
    assert_eq!(v["th_callid"], "decoded", "{v}");
    Ok(())
}

/// The explicit opt-in decodes a deployment that kept OpenSIPS's default
/// secret, and says at startup that the default is public.
#[test]
fn opensips_default_opt_in_decodes_and_warns() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-4.0-default.pcap");
    let lab = Lab::new("th_callid_secret = \"opensips-default\"", "unused", 0o600)?;
    let run = cli(
        &pcap,
        Some(lab.config()),
        &["--correlate", HIDDEN_1_DEFAULT, "--json", "--no-cli-print"],
    )?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("public"),
        "no warning that the default is public:\n{}",
        run.stderr
    );
    let v = run.last_json()?;
    assert_eq!(legs_by(&v, "decoded").len(), 1, "{v}");
    Ok(())
}

/// T6 + T8: a wrong secret and a missing secret each produce no decoded
/// join, and the answer says which. No leg of another call is claimed as an
/// identifier match: the only identifier left is the SDP origin, which this
/// proxy passes through unchanged, so it names the same call's caller leg.
/// The calls start a second apart, inside the two-second timing window, so
/// the other calls do appear, as the timing guesses they are; telling them
/// apart is what the decode is for.
///
/// A wrong secret that shares bytes with the right one decodes PART of the
/// Call-ID correctly, so the output can pass the Call-ID shape check. Such a
/// leg is `unmatched` rather than `undecodable`; either is a refusal.
#[test]
fn wrong_or_missing_secret_is_reported_and_never_joins() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-4.0-secret.pcap");
    let near = Lab::with_secret("not-the-secret-0100")?;
    let far = Lab::with_secret("0123456789")?;
    for (config, status) in [
        (Some(near.config()), "unmatched"),
        (Some(far.config()), "undecodable"),
        (None, "no_secret"),
    ] {
        let v = correlate(&pcap, config, HIDDEN_1_SECRET)?;
        assert!(legs_by(&v, "decoded").is_empty(), "{status}: {v}");
        for leg in v["legs"].as_array().ok_or("legs")? {
            if leg["identifier_match"] == true {
                assert_eq!(
                    leg["call_id"], CALLER_1,
                    "{status}: joined another call: {v}"
                );
            } else {
                assert_eq!(leg["method"], "timing", "{status}: {v}");
            }
        }
        assert_eq!(v["th_callid"], status, "{v}");
    }
    // The text report names the cause and the setting to check.
    let run = cli(
        &pcap,
        Some(far.config()),
        &["--correlate", HIDDEN_1_SECRET, "--no-cli-print", "--quiet"],
    )?;
    assert!(
        run.stdout.contains("Topology hiding: undecodable"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("th_callid_secret_file"),
        "{}",
        run.stdout
    );
    assert!(
        !run.stdout.contains("0123456789"),
        "the text report shows the wrong secret"
    );
    let run = cli(
        &pcap,
        Some(near.config()),
        &["--correlate", HIDDEN_1_SECRET, "--no-cli-print", "--quiet"],
    )?;
    assert!(
        run.stdout.contains("Topology hiding: unmatched"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("the secret is wrong"), "{}", run.stdout);
    assert!(
        !run.stdout.contains("not-the-secret-0100"),
        "the text report shows the wrong secret"
    );
    // The end of the run says it too, for the operator who asked about no
    // one leg: the caller legs were captured, so the secret is suspect.
    let run = cli(&pcap, Some(far.config()), &["--no-cli-print"])?;
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(
        run.stderr
            .contains("Topology hiding: 3 hidden Call-ID(s) did not decode"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("th_callid_secret_file"),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("0123456789"), "{}", run.stderr);
    // With the right secret every hidden leg joins, and nothing is said.
    let right = Lab::with_secret(SECRET)?;
    let run = cli(&pcap, Some(right.config()), &["--no-cli-print"])?;
    assert!(!run.stderr.contains("Topology hiding"), "{}", run.stderr);
    Ok(())
}

/// T9: a world-readable secret file stops the run, naming the file, never
/// the secret.
#[test]
fn world_readable_secret_file_fails_the_run() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-4.0-secret.pcap");
    let lab = Lab::new("th_callid_secret_file = \"{secret_file}\"", SECRET, 0o644)?;
    let run = cli(
        &pcap,
        Some(lab.config()),
        &["--correlate", CALLER_1, "--no-cli-print"],
    )?;
    assert_eq!(
        run.code,
        Some(1),
        "stdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert!(run.stderr.contains("world-readable"), "{}", run.stderr);
    assert!(
        run.stderr.contains("[sip] th_callid_secret_file"),
        "the refusal names the setting that points at the file: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&lab.secret_dir().display().to_string()),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains(SECRET), "{}", run.stderr);
    assert!(!run.stdout.contains(SECRET), "the run shows the secret");
    Ok(())
}

/// T14: the header approach. The documented `append_hf("X-CID: $ci\r\n")`
/// carries the caller-side Call-ID to the callee leg, and with
/// `xcid_headers = ["X-CID"]` and NO secret the legs join by header.
#[test]
fn xcid_header_capture_joins_by_header_without_a_secret() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-4.0-xcid.pcap");
    let lab = Lab::new("xcid_headers = [\"X-CID\"]", "unused", 0o600)?;
    let v = correlate(&pcap, Some(lab.config()), HIDDEN_1_DEFAULT)?;
    let header = legs_by(&v, "header");
    assert_eq!(header.len(), 1, "{v}");
    assert_eq!(header[0]["call_id"], CALLER_1, "{v}");
    assert_eq!(header[0]["strategy"], "x_call_id", "{v}");
    assert!(legs_by(&v, "decoded").is_empty(), "{v}");
    assert_eq!(v["th_callid"], "no_secret", "{v}");
    // With the secret as well, the decode is checked first and wins.
    let both = Lab::new(
        "xcid_headers = [\"X-CID\"]\nth_callid_secret = \"opensips-default\"",
        "unused",
        0o600,
    )?;
    let v = correlate(&pcap, Some(both.config()), HIDDEN_1_DEFAULT)?;
    assert_eq!(legs_by(&v, "decoded").len(), 1, "{v}");
    assert!(legs_by(&v, "header").is_empty(), "{v}");
    Ok(())
}

/// T13 on REST and MCP: the same capture, served, gives the same decoded
/// join on `/v1/dialogs/{id}/correlated`, `/v1/dialogs/{id}/tree`,
/// `find_correlated` and `get_call_tree`.
#[test]
fn rest_and_mcp_report_the_decoded_join() -> Result<(), TestError> {
    let pcap = format!("{FIX}/opensips-4.0-secret.pcap");
    let lab = Lab::with_secret(SECRET)?;
    let extra = ["--config", lab.config()];
    let rest = ApiServer::spawn_with_pcap(&pcap, &extra)?;
    let resp = rest.get(&format!("/v1/dialogs/{HIDDEN_1_SECRET}/correlated"))?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert!(
        !resp.body.contains(SECRET),
        "the REST answer shows the secret"
    );
    let v = resp.json()?;
    assert_eq!(legs_by(&v, "decoded").len(), 1, "{v}");
    assert_eq!(v["th_callid"], "decoded", "{v}");
    let tree = rest.get(&format!("/v1/dialogs/{CALLER_1}/tree"))?;
    assert_eq!(tree.status, 200, "{}", tree.body);
    let tree = tree.json()?;
    let edge = tree["legs"]
        .as_array()
        .and_then(|a| a.iter().find(|l| l["call_id"] == HIDDEN_1_SECRET))
        .ok_or("hidden leg in the REST tree")?;
    assert_eq!(edge["method"], "decoded", "{tree}");

    let mut mcp = McpSession::start(&pcap, &extra)?;
    let v = normalize_mcp(ok_payload(&mcp.call(
        "find_correlated",
        serde_json::json!({ "call_id": HIDDEN_1_SECRET }),
    )?)?);
    assert_eq!(legs_by(&v, "decoded").len(), 1, "{v}");
    assert_eq!(v["th_callid"], "decoded", "{v}");
    let t = normalize_mcp(ok_payload(
        &mcp.call("get_call_tree", serde_json::json!({ "call_id": CALLER_1 }))?,
    )?);
    let edge = t["legs"]
        .as_array()
        .and_then(|a| a.iter().find(|l| l["call_id"] == HIDDEN_1_SECRET))
        .ok_or("hidden leg in the MCP tree")?;
    assert_eq!(edge["method"], "decoded", "{t}");
    assert!(
        !v.to_string().contains(SECRET) && !t.to_string().contains(SECRET),
        "an MCP answer shows the secret"
    );
    Ok(())
}

/// The guide, `docs/opensips-sipnab.md`.
const GUIDE: &str = "docs/opensips-sipnab.md";

/// The fenced blocks of `md` whose opening fence is exactly `fence`.
fn fenced_blocks(md: &str, fence: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = md.lines();
    while let Some(line) = lines.next() {
        if line == fence {
            let body: Vec<&str> = lines.by_ref().take_while(|l| *l != "```").collect();
            out.push(body.join("\n"));
        }
    }
    out
}

/// The guide's OpenSIPS script lines are the ones the capture harness ran
/// against OpenSIPS 4.0.2 and 3.6.9, character for character, inside the
/// request route (one tab deeper). The harness switches the `append_hf`
/// line on with an empty `@XCID@` in its xcid mode.
#[test]
fn the_guides_opensips_lines_are_the_ones_the_harness_ran() -> Result<(), TestError> {
    let guide = std::fs::read_to_string(GUIDE)?;
    let script = fenced_blocks(&guide, "```text")
        .into_iter()
        .find(|b| b.contains("append_hf"))
        .ok_or("the guide shows the append_hf lines")?;
    let template =
        std::fs::read_to_string("harness/th-callid/opensips.cfg.tmpl")?.replace("@XCID@", "");
    let indented: Vec<String> = script.lines().map(|l| format!("\t{l}")).collect();
    assert!(
        template.contains(&indented.join("\n")),
        "the guide's block is not in the harness template:\n{script}"
    );
    Ok(())
}

/// The end-of-run warning the guide quotes is the line sipnab prints for a
/// wrong secret, word for word.
#[test]
fn the_guides_quoted_warning_is_what_sipnab_prints() -> Result<(), TestError> {
    let guide = std::fs::read_to_string(GUIDE)?;
    let quoted = fenced_blocks(&guide, "```text")
        .into_iter()
        .find(|b| b.starts_with("Topology hiding: "))
        .ok_or("the guide quotes the warning")?;
    let pcap = format!("{FIX}/opensips-4.0-secret.pcap");
    let far = Lab::with_secret("0123456789")?;
    let run = cli(&pcap, Some(far.config()), &["--no-cli-print"])?;
    assert!(
        run.stderr.contains(&quoted),
        "{quoted}\nnot in:\n{}",
        run.stderr
    );
    Ok(())
}
