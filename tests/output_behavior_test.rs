// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behavioral contracts of the machine-readable output flags: --json-pretty
//! must actually differ from --json, and --call-report must fail with a
//! non-zero exit when the requested Call-ID does not exist (a scripting
//! user checking a specific call must be able to trust the exit code).
#![cfg(feature = "native")]

type TestError = Box<dyn std::error::Error>;

#[path = "support/run.rs"]
mod run_support;

/// Crate-root-relative path to the 7-message SIP call fixture.
const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// Runs the `sipnab` binary from the crate root under the shared test baseline
/// (see [`run_support::run`]) with quiet logs (`SIPNAB_LOG=error`).
///
/// # Arguments
/// * `args` — CLI arguments to pass.
///
/// # Returns
/// `(stdout, stderr, exit_code)` of the finished process.
fn run(args: &[&str]) -> Result<(String, String, Option<i32>), TestError> {
    Ok(run_support::run(args, Some("error"))?)
}

/// --json-pretty was byte-identical to --json on the message stream; it must
/// pretty-print (and stay a parseable stream of JSON values).
#[test]
fn json_pretty_pretty_prints_the_message_stream() -> Result<(), TestError> {
    let (compact, _, code) = run(&["-N", "-I", FIXTURE, "--json"])?;
    assert_eq!(code, Some(0));
    let (pretty, _, code) = run(&["-N", "-I", FIXTURE, "--json-pretty"])?;
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
        .collect::<Result<_, _>>()?;
    let pretty_count = values.len();
    assert_eq!(compact_count, pretty_count, "same message count");
    assert!(pretty_count > 0, "fixture must produce messages");
    Ok(())
}

/// An unknown --call-report Call-ID used to warn on stderr and exit 0 —
/// invisible to scripts. It must exit non-zero with a clear message.
#[test]
fn call_report_unknown_call_id_exits_nonzero() -> Result<(), TestError> {
    let (_, stderr, code) = run(&[
        "-N",
        "-I",
        FIXTURE,
        "--no-cli-print",
        "--call-report",
        "does-not-exist@nowhere",
    ])?;
    assert_eq!(
        code,
        Some(1),
        "unknown Call-ID must exit 1; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("not found"),
        "stderr must explain the failure:\n{stderr}"
    );
    Ok(())
}

/// An `-O` output that cannot be created must say WHY. The writer wraps the
/// `io::Error` in a "Failed to create output file '<path>'" context, and the
/// report used to print only that outermost layer (`{e}` on an
/// `anyhow::Error`), so an operator on rtp03 saw the path and nothing about
/// the cause. The OS error text is the part that tells them what to fix.
#[test]
fn an_output_in_a_missing_directory_names_the_os_error() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("no-such-dir").join("out.pcap");
    let out_s = out.to_str().ok_or("utf-8 temp path")?;
    let (_, stderr, code) = run(&["-N", "-I", FIXTURE, "-O", out_s])?;
    assert_eq!(code, Some(1), "an unopenable -O exits 1; stderr:\n{stderr}");
    assert!(
        stderr.contains(out_s),
        "stderr must name the output path:\n{stderr}"
    );
    assert!(
        stderr.contains("No such file or directory"),
        "stderr must carry the OS error, not only the context:\n{stderr}"
    );
    Ok(())
}

/// The same defect with the cause an operator most often meets: a directory
/// the process may not write. A test running as root can write anywhere, so it
/// has nothing to observe and says so rather than passing vacuously.
#[test]
fn an_output_in_a_read_only_directory_names_permission_denied() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let ro = dir.path().join("ro");
    std::fs::create_dir(&ro)?;
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555))?;
    if std::fs::File::create(ro.join("probe")).is_ok() {
        eprintln!("skipped: this process can write a 0555 directory (root)");
        return Ok(());
    }
    let out = ro.join("out.pcap");
    let out_s = out.to_str().ok_or("utf-8 temp path")?;
    let (_, stderr, code) = run(&["-N", "-I", FIXTURE, "-O", out_s])?;
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755))?;
    assert_eq!(code, Some(1), "an unopenable -O exits 1; stderr:\n{stderr}");
    assert!(
        stderr.contains("Permission denied (os error 13)"),
        "stderr must carry the OS error:\n{stderr}"
    );
    assert!(
        !stderr.contains("dropped privileges"),
        "a run that never dropped privileges must not blame the drop:\n{stderr}"
    );
    Ok(())
}

/// Build a classic little-endian Ethernet pcap of `count` UDP frames of
/// `payload` bytes each, from 192.0.2.1:40000 to 192.0.2.2:40002 (documentation
/// addresses; the payload is zeros, so the file carries nothing private).
fn synthetic_udp_pcap(count: usize, payload: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&[0u8; 8]);
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    for i in 0..count {
        let udp_len = 8 + payload;
        let ip_len = 20 + udp_len;
        let mut f = Vec::with_capacity(14 + ip_len);
        f.extend_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&(ip_len as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&40002u16.to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.resize(14 + ip_len, 0);
        v.extend_from_slice(&(i as u32 + 1).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(&f);
    }
    v
}

/// A split file is created when the writer rotates, mid-run, and its failure
/// reached the operator as "Failed to write packet: Failed to create output
/// file '<split>'" with the cause dropped the same way. A directory standing
/// where the first split file goes makes that create fail on any account.
#[test]
fn a_split_file_that_cannot_be_created_names_the_os_error() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("in.pcap");
    // 900 x ~1.4 KB > the 1 MiB `filesize:1` threshold, so one rotation fires.
    std::fs::write(&input, synthetic_udp_pcap(900, 1400))?;
    let out = dir.path().join("out.pcap");
    std::fs::create_dir(dir.path().join("out_00001.pcap"))?;
    let (_, stderr, code) = run(&[
        "-N",
        "-I",
        input.to_str().ok_or("utf-8")?,
        "-O",
        out.to_str().ok_or("utf-8")?,
        "--split",
        "filesize:1",
    ])?;
    assert_eq!(
        code,
        Some(1),
        "a failed rotation exits 1; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("out_00001.pcap"),
        "stderr must name the split file:\n{stderr}"
    );
    assert!(
        stderr.contains("Is a directory"),
        "stderr must carry the OS error, not only the context:\n{stderr}"
    );
    Ok(())
}
