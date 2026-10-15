// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--report` over a directory of stored vCon containers: one row per
//! container and the totals, in the text report and in the JSON line
//! `--report --json` writes, and the same report from the MCP tool
//! `vcon_directory_report`.
//!
//! The directory mixes every case the report must name: two unsigned
//! containers, one in the gzip format, one encrypted (read with
//! `--vcon-key`, skipped and the flag named without it), one from a public
//! dataset that stores no SIP, and one file that is not JSON at all.
#![cfg(all(feature = "native", feature = "vcon"))]

#[cfg(feature = "mcp")]
#[path = "support/mcp.rs"]
mod mcp;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestError = Box<dyn std::error::Error>;

const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const PROBLEM: &str = "tests/pcap-samples/sip-problem-call.pcap";
const JOSE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");
const DATASET: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/vcon-datasets/vcon-supreme-court-arguments/91-7094_23823.vcon.json"
);

/// Run the shipped binary from the repository root with `HOME` at `home`.
fn run(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()?)
}

/// Run, and fail with standard error when the run did not exit 0.
fn run_ok(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    let out = run(home, args)?;
    if !out.status.success() {
        return Err(format!(
            "{args:?} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(out)
}

fn utf8(p: &Path) -> Result<&str, TestError> {
    Ok(p.to_str().ok_or("utf-8 path")?)
}

/// Export one call of `capture` to `out` as an unsigned container.
fn export(home: &Path, capture: &str, call_id: &str, out: &Path) -> Result<(), TestError> {
    run_ok(
        home,
        &[
            "-N",
            "-I",
            capture,
            "--export-vcon",
            call_id,
            "--vcon-out",
            utf8(out)?,
            "--node-name",
            "tap-a",
            "--no-cli-print",
            "--quiet",
        ],
    )?;
    Ok(())
}

/// The fixture recipient key, mode 0600: sipnab refuses a key other users
/// can read, and git checks the fixture out 0644.
fn key(home: &Path) -> Result<PathBuf, TestError> {
    let path = home.join("recipient.key");
    std::fs::copy(format!("{JOSE}/fake_grp.key"), &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// Export `completed-9f8e7d@192.0.2.10` encrypted to the fixture certificate
/// and signed by its key, and move it to `out`.
fn export_sealed(home: &Path, out: &Path) -> Result<(), TestError> {
    let chain = home.join("chain.pem");
    let mut pem = String::new();
    for name in ["fake_grp.crt", "fake_div.crt", "fake_ca_root.crt"] {
        pem.push_str(&std::fs::read_to_string(format!("{JOSE}/{name}"))?);
    }
    std::fs::write(&chain, pem)?;
    let sealed_dir = home.join("sealed-out");
    let config = home.join("sealed.toml");
    std::fs::write(
        &config,
        format!(
            "[[vcon.rule]]\nname = \"sealed\"\nwhen = \"call_id == 'completed-9f8e7d@192.0.2.10'\"\n\
             dir = \"{}\"\nencrypt_to = \"{JOSE}/fake_grp.crt\"\nsign_key = \"{}\"\nsign_cert = \"{}\"\n",
            sealed_dir.display(),
            key(home)?.display(),
            chain.display()
        ),
    )?;
    run_ok(
        home,
        &[
            "-N",
            "-I",
            PROBLEM,
            "--no-cli-print",
            "--quiet",
            "--config",
            utf8(&config)?,
        ],
    )?;
    let written: Vec<PathBuf> = std::fs::read_dir(&sealed_dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    let [one] = written.as_slice() else {
        return Err(format!("{} sealed containers, not 1", written.len()).into());
    };
    std::fs::rename(one, out)?;
    Ok(())
}

/// The mixed directory, under `home/stored`:
///
/// | file | what it is |
/// |---|---|
/// | `a-invite.vcon.json` | unsigned, `1-1966@10.0.2.20`, 6 messages, 8 s |
/// | `b-invite.vcon.json` | unsigned, `1-1968@10.0.2.20`, 4 messages |
/// | `c-busy.vcon.json.gz` | the gzip format of `busy-3a2b1c@192.0.2.30`, a 486 |
/// | `d-sealed.vcon.json` | encrypted, `completed-9f8e7d@192.0.2.10` |
/// | `e-dataset.vcon.json` | a public dataset container with no SIP |
/// | `f-malformed.vcon.json` | a JSON object cut off after 30 bytes |
fn mixed_directory(home: &Path) -> Result<PathBuf, TestError> {
    let dir = home.join("stored");
    std::fs::create_dir_all(&dir)?;
    export(
        home,
        G711,
        "1-1966@10.0.2.20",
        &dir.join("a-invite.vcon.json"),
    )?;
    export(
        home,
        G711,
        "1-1968@10.0.2.20",
        &dir.join("b-invite.vcon.json"),
    )?;
    let busy = home.join("busy.vcon.json");
    export(home, PROBLEM, "busy-3a2b1c@192.0.2.30", &busy)?;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&std::fs::read(&busy)?)?;
    std::fs::write(dir.join("c-busy.vcon.json.gz"), gz.finish()?)?;
    export_sealed(home, &dir.join("d-sealed.vcon.json"))?;
    std::fs::copy(DATASET, dir.join("e-dataset.vcon.json"))?;
    std::fs::write(
        dir.join("f-malformed.vcon.json"),
        b"{\"vcon\": \"0.4.0\", \"parties\": [",
    )?;
    Ok(dir)
}

/// The text section `--report` prints after the dialog table: from its
/// heading to the end of the report.
fn section(stdout: &str) -> Result<&str, TestError> {
    let at = stdout
        .find("vCon containers:")
        .ok_or_else(|| format!("no vCon containers section in:\n{stdout}"))?;
    Ok(&stdout[at..])
}

/// The row of the text section that names `file`.
fn text_row<'a>(section: &'a str, file: &str) -> Result<&'a str, TestError> {
    section
        .lines()
        .find(|l| l.trim_end().ends_with(file))
        .ok_or_else(|| format!("no row for {file} in:\n{section}").into())
}

/// The `sipnab_vcon_containers` object of `--report --json`.
fn json_report(stdout: &str) -> Result<serde_json::Value, TestError> {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find_map(|v| v.get("sipnab_vcon_containers").cloned())
        .ok_or_else(|| format!("no sipnab_vcon_containers line in:\n{stdout}").into())
}

/// The JSON row whose `file` ends with `file`.
fn json_row<'a>(
    report: &'a serde_json::Value,
    file: &str,
) -> Result<&'a serde_json::Value, TestError> {
    report["containers"]
        .as_array()
        .ok_or("containers is an array")?
        .iter()
        .find(|r| r["file"].as_str().is_some_and(|f| f.ends_with(file)))
        .ok_or_else(|| format!("no JSON row for {file}").into())
}

/// The `--report` text of `-I dir` with `extra` flags.
fn report_text(home: &Path, dir: &Path, extra: &[&str]) -> Result<String, TestError> {
    let mut args = vec![
        "-N",
        "-I",
        utf8(dir)?,
        "--report",
        "--no-cli-print",
        "--quiet",
    ];
    args.extend_from_slice(extra);
    let out = run_ok(home, &args)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    Ok(String::from_utf8(out.stdout)?)
}

/// Without a key: three containers read, three skipped, each skip named
/// with its reason, and the totals add up. Nothing panics.
#[test]
fn the_report_names_every_container_and_totals_them() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = mixed_directory(home.path())?;
    let stdout = report_text(home.path(), &dir, &[])?;
    let sec = section(&stdout)?;

    let invite = text_row(sec, "a-invite.vcon.json")?;
    assert!(invite.starts_with("read "), "{invite}");
    assert!(invite.contains("unsigned"), "{invite}");
    assert!(invite.contains("Completed 1"), "{invite}");
    assert!(invite.contains(" 8s "), "{invite}");
    let busy = text_row(sec, "c-busy.vcon.json.gz")?;
    assert!(busy.starts_with("read "), "{busy}");
    assert!(busy.contains("gzip"), "{busy}");
    assert!(busy.contains("Failed 1"), "{busy}");
    let sealed = text_row(sec, "d-sealed.vcon.json")?;
    assert!(sealed.starts_with("skipped: no_key"), "{sealed}");
    assert!(sealed.contains("encrypted"), "{sealed}");
    let dataset = text_row(sec, "e-dataset.vcon.json")?;
    assert!(
        dataset.starts_with("skipped: no_sip_signaling"),
        "{dataset}"
    );
    let malformed = text_row(sec, "f-malformed.vcon.json")?;
    assert!(malformed.starts_with("skipped: not_json"), "{malformed}");

    // Each skip's reason, in full, below the table.
    assert!(sec.contains("--vcon-key"), "{sec}");
    assert!(sec.contains("no SIP signaling"), "{sec}");
    assert!(sec.contains("not JSON"), "{sec}");

    assert!(
        sec.contains("6 container(s): 3 read, 3 skipped"),
        "totals line missing:\n{sec}"
    );
    assert!(
        sec.contains("Skipped by reason: no_key 1, no_sip_signaling 1, not_json 1"),
        "{sec}"
    );
    assert!(
        sec.contains("Calls: 3 (Completed 1, Failed 1, InCall 1)"),
        "{sec}"
    );
    assert!(sec.contains("Total duration: 9s"), "{sec}");
    Ok(())
}

/// With `--vcon-key` the encrypted container is read: four read, two skipped.
#[test]
fn the_key_turns_the_encrypted_skip_into_a_read_row() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = mixed_directory(home.path())?;
    let key = key(home.path())?;
    let stdout = report_text(home.path(), &dir, &["--vcon-key", utf8(&key)?])?;
    let sec = section(&stdout)?;
    let sealed = text_row(sec, "d-sealed.vcon.json")?;
    assert!(sealed.starts_with("read "), "{sealed}");
    assert!(sealed.contains("encrypted"), "{sealed}");
    assert!(sealed.contains("Completed 1"), "{sealed}");
    assert!(sec.contains("6 container(s): 4 read, 2 skipped"), "{sec}");
    assert!(
        sec.contains("Skipped by reason: no_sip_signaling 1, not_json 1"),
        "{sec}"
    );
    assert!(sec.contains("Total duration: 29s"), "{sec}");
    Ok(())
}

/// The read rows of the mixed directory's JSON report.
fn assert_read_rows(report: &serde_json::Value) -> Result<(), TestError> {
    let invite = json_row(report, "a-invite.vcon.json")?;
    assert_eq!(invite["status"], "read");
    assert_eq!(invite["form"], "unsigned");
    assert_eq!(invite["calls_rebuilt"], 1);
    assert_eq!(invite["call_ids"], serde_json::json!(["1-1966@10.0.2.20"]));
    assert_eq!(invite["dispositions"], serde_json::json!({"Completed": 1}));
    assert_eq!(invite["duration_secs"], 8);
    assert_eq!(invite["validation_findings"], 0);
    assert!(invite["uuid"].is_string(), "{invite}");
    assert!(invite.get("skip_reason").is_none(), "{invite}");

    let busy = json_row(report, "c-busy.vcon.json.gz")?;
    assert_eq!(busy["form"], "gzip");
    assert_eq!(busy["dispositions"], serde_json::json!({"Failed": 1}));
    Ok(())
}

/// The skipped rows of the mixed directory's JSON report.
fn assert_skipped_rows(report: &serde_json::Value) -> Result<(), TestError> {
    let detail_has = |row: &serde_json::Value, text: &str| {
        row["skip_detail"]
            .as_str()
            .is_some_and(|r| r.contains(text))
    };
    let sealed = json_row(report, "d-sealed.vcon.json")?;
    assert_eq!(sealed["status"], "skipped");
    assert_eq!(sealed["form"], "encrypted");
    assert_eq!(sealed["skip_reason"], "no_key");
    assert!(detail_has(sealed, "--vcon-key"), "{sealed}");
    // Not opened, so not validated: null, never a count of zero.
    assert!(sealed["validation_findings"].is_null(), "{sealed}");
    assert_eq!(sealed["calls_rebuilt"], 0);

    let dataset = json_row(report, "e-dataset.vcon.json")?;
    assert_eq!(dataset["skip_reason"], "no_sip_signaling");
    assert_eq!(dataset["form"], "unsigned");
    assert!(dataset["uuid"].is_string(), "{dataset}");
    assert!(dataset["validation_findings"].is_u64(), "{dataset}");
    assert!(detail_has(dataset, "no SIP signaling"), "{dataset}");

    let malformed = json_row(report, "f-malformed.vcon.json")?;
    assert_eq!(malformed["skip_reason"], "not_json");
    assert!(malformed["validation_findings"].is_null(), "{malformed}");
    Ok(())
}

/// The totals of the mixed directory's JSON report; returns the number of
/// containers with a schema finding, counted from the rows.
fn assert_totals(report: &serde_json::Value) -> Result<usize, TestError> {
    let rows = report["containers"].as_array().ok_or("containers")?;
    let totals = &report["totals"];
    assert_eq!(totals["containers"], 6);
    assert_eq!(totals["read"], 3);
    assert_eq!(totals["skipped"], 3);
    assert_eq!(
        totals["skipped_by_reason"],
        serde_json::json!({"no_key": 1, "no_sip_signaling": 1, "not_json": 1})
    );
    assert_eq!(totals["calls"], 3);
    assert_eq!(
        totals["dispositions"],
        serde_json::json!({"Completed": 1, "Failed": 1, "InCall": 1})
    );
    assert_eq!(totals["duration_secs"], 9);
    let failed_validation = rows
        .iter()
        .filter(|r| r["validation_findings"].as_u64().is_some_and(|n| n > 0))
        .count();
    assert_eq!(totals["failed_validation"], failed_validation);
    Ok(failed_validation)
}

/// `--report --json` writes the same rows and totals as one JSON line, and
/// every row the text names is a row in the JSON with the same status.
#[test]
fn the_json_report_mirrors_the_text_report() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = mixed_directory(home.path())?;
    let text = report_text(home.path(), &dir, &[])?;
    let json = report_text(home.path(), &dir, &["--json"])?;
    let report = json_report(&json)?;
    assert_eq!(report["schema_version"], 1);
    let rows = report["containers"].as_array().ok_or("containers")?;
    assert_eq!(rows.len(), 6);
    assert_read_rows(&report)?;
    assert_skipped_rows(&report)?;
    let failed_validation = assert_totals(&report)?;

    // Mirror: the text names each JSON row, with the same status.
    let sec = section(&text)?;
    for row in rows {
        let file = row["file"].as_str().ok_or("file")?;
        let line = text_row(sec, file)?;
        let status = match row["skip_reason"].as_str() {
            Some(why) => format!("skipped: {why}"),
            None => "read".to_string(),
        };
        assert!(line.starts_with(&status), "{line} vs {row}");
    }
    assert!(
        sec.contains(&format!(
            "Failed validation: {failed_validation} container(s)"
        )),
        "{sec}"
    );
    Ok(())
}

/// A capture with no stored container prints no vCon section: the report a
/// pcap run prints is unchanged.
#[test]
fn a_pcap_report_has_no_vcon_section() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let out = run_ok(
        home.path(),
        &["-N", "-I", G711, "--report", "--no-cli-print", "--quiet"],
    )?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(!stdout.contains("vCon containers:"), "{stdout}");
    assert!(stdout.contains("1-1966@10.0.2.20"), "{stdout}");
    Ok(())
}

#[cfg(feature = "mcp")]
mod mcp_tool {
    use super::{TestError, mcp, mixed_directory, utf8};

    /// `vcon_directory_report` answers the rows and totals `--report --json`
    /// writes, for a directory inside the file root, and pages the rows.
    #[test]
    fn the_tool_reports_a_directory_in_the_file_root() -> Result<(), TestError> {
        let home = tempfile::tempdir()?;
        let root = home.path().join("root");
        std::fs::create_dir_all(&root)?;
        let dir = mixed_directory(home.path())?;
        std::fs::rename(&dir, root.join("stored"))?;
        let mut session = mcp::McpSession::start(
            "tests/fixtures/sip_call.pcap",
            &["--mcp-file-root", utf8(&root)?],
        )?;

        let report = session.ok(
            "vcon_directory_report",
            serde_json::json!({ "directory": "stored" }),
        )?;
        let rows = report["containers"].as_array().ok_or("containers")?;
        assert_eq!(rows.len(), 6, "{report}");
        let t = &report["totals"];
        assert_eq!(t["containers"], 6);
        assert_eq!(t["read"], 3);
        assert_eq!(
            t["skipped_by_reason"],
            serde_json::json!({"no_key": 1, "no_sip_signaling": 1, "not_json": 1})
        );
        assert_eq!(t["duration_secs"], 9);
        let sealed = rows
            .iter()
            .find(|r| r["file"] == "d-sealed.vcon.json")
            .ok_or("the sealed row, named by its file name")?;
        assert_eq!(sealed["skip_reason"], "no_key");
        assert_eq!(report["truncated"], false);

        // Paged: one row, a cursor, and totals still over the whole directory.
        let page = session.ok(
            "vcon_directory_report",
            serde_json::json!({ "directory": "stored", "limit": 1 }),
        )?;
        assert_eq!(page["containers"].as_array().map(Vec::len), Some(1));
        assert_eq!(page["truncated"], true);
        assert_eq!(page["totals"]["containers"], 6);
        let cursor = page["next_cursor"].as_str().ok_or("next_cursor")?;
        let next = session.ok(
            "vcon_directory_report",
            serde_json::json!({ "directory": "stored", "limit": 1, "cursor": cursor }),
        )?;
        assert_eq!(next["containers"][0]["file"], "b-invite.vcon.json");

        // The byte budget cuts whole rows and says so.
        let cut = session.ok(
            "vcon_directory_report",
            serde_json::json!({ "directory": "stored", "max_response_bytes": 2000 }),
        )?;
        assert_eq!(cut["truncated"], true, "{cut}");
        assert_eq!(cut["truncated_by"], "bytes", "{cut}");

        // A path is refused: the tool reads inside the file root only.
        let refused = session.call(
            "vcon_directory_report",
            serde_json::json!({ "directory": "../stored" }),
        )?;
        assert!(refused.get("error").is_some() || refused["result"]["isError"] == true);

        // `.` is the root itself, which holds a directory and no container.
        let root_report = session.ok(
            "vcon_directory_report",
            serde_json::json!({ "directory": "." }),
        )?;
        assert_eq!(root_report["totals"]["containers"], 0, "{root_report}");
        Ok(())
    }

    /// The declared output schema describes every kind of row: read, skipped
    /// with a `uuid` and a finding count, and skipped with neither.
    #[test]
    fn every_row_kind_matches_the_declared_output_schema() -> Result<(), TestError> {
        let home = tempfile::tempdir()?;
        let root = home.path().join("root");
        std::fs::create_dir_all(&root)?;
        let dir = mixed_directory(home.path())?;
        std::fs::rename(&dir, root.join("stored"))?;
        let mut session = mcp::McpSession::start(
            "tests/fixtures/sip_call.pcap",
            &["--mcp-file-root", utf8(&root)?, "--mcp-output-schemas"],
        )?;
        let schema = session
            .tool_definitions()?
            .into_iter()
            .find(|t| t["name"] == "vcon_directory_report")
            .and_then(|t| t.get("outputSchema").cloned())
            .ok_or("vcon_directory_report declares an output schema")?;
        let report = session.ok(
            "vcon_directory_report",
            serde_json::json!({ "directory": "stored" }),
        )?;
        let validator = jsonschema::validator_for(&schema)?;
        let errors: Vec<String> = validator
            .iter_errors(&report)
            .map(|e| format!("{}: {e}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{errors:?}\n{report}");
        Ok(())
    }
}
