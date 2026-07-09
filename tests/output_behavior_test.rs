//! Behavioral contracts of the machine-readable output flags: --json-pretty
//! must actually differ from --json, and --call-report must fail with a
//! non-zero exit when the requested Call-ID does not exist (a scripting
//! user checking a specific call must be able to trust the exit code).
#![cfg(feature = "native")]

use std::process::Command;

const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

fn run(args: &[&str]) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("SIPNAB_LOG", "error")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// --json-pretty was byte-identical to --json on the message stream; it must
/// pretty-print (and stay a parseable stream of JSON values).
#[test]
fn json_pretty_pretty_prints_the_message_stream() {
    let (compact, _, code) = run(&["-N", "-I", FIXTURE, "--json"]);
    assert_eq!(code, Some(0));
    let (pretty, _, code) = run(&["-N", "-I", FIXTURE, "--json-pretty"]);
    assert_eq!(code, Some(0));

    assert_ne!(
        compact, pretty,
        "--json-pretty must not be byte-identical to --json"
    );
    assert!(
        pretty.contains("\n  \""),
        "pretty output must contain indented keys:\n{pretty}"
    );

    // Same number of JSON values, all still parseable.
    let compact_count = compact.lines().filter(|l| l.starts_with('{')).count();
    let values: Vec<serde_json::Value> = serde_json::Deserializer::from_str(&pretty)
        .into_iter::<serde_json::Value>()
        .collect::<Result<_, _>>()
        .expect("pretty stream must stay parseable");
    let pretty_count = values.len();
    assert_eq!(compact_count, pretty_count, "same message count");
    assert!(pretty_count > 0, "fixture must produce messages");
}

/// An unknown --call-report Call-ID used to warn on stderr and exit 0 —
/// invisible to scripts. It must exit non-zero with a clear message.
#[test]
fn call_report_unknown_call_id_exits_nonzero() {
    let (_, stderr, code) = run(&[
        "-N",
        "-I",
        FIXTURE,
        "--no-cli-print",
        "--call-report",
        "does-not-exist@nowhere",
    ]);
    assert_eq!(
        code,
        Some(1),
        "unknown Call-ID must exit 1; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("not found"),
        "stderr must explain the failure:\n{stderr}"
    );
}
