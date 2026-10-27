// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Feature-gate UX: a flag whose subsystem is not compiled in must fail fast
//! with a clear error and exit code 2 — never degrade into a silent no-op.
//! These tests run the real binary, so they exercise the same path a user
//! hits; each is cfg-gated to builds where the relevant feature is ABSENT.
//!
//! The refusal decides the exit code, so it must reach stderr whatever the
//! log filter says: with `SIPNAB_LOG=off` too, and exactly once with logging
//! on. A flag checked when the run starts must also be refused before the
//! capture opens, not after it has read the input.
#![cfg(feature = "native")]

#[cfg(any(
    not(feature = "mcp"),
    not(feature = "hep"),
    not(feature = "tls"),
    not(feature = "api"),
    not(feature = "vcon")
))]
mod gates {
    use std::process::Command;

    /// The error a test returns: any error, boxed, so `?` works on I/O,
    /// parse and JSON errors alike.
    pub(super) type TestError = Box<dyn std::error::Error>;

    /// Crate-root-relative path to the standard SIP call fixture.
    pub(super) const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

    /// Run the binary with `SIPNAB_LOG` set to `log`; return the exit code
    /// and stderr.
    ///
    /// # Side effects
    /// Spawns the compiled `sipnab` binary as a subprocess.
    fn run(args: &[&str], log: &str) -> Result<(Option<i32>, String), TestError> {
        let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(args)
            .env("SIPNAB_LOG", log)
            .env("NO_COLOR", "1")
            .output()?;
        Ok((
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    /// Assert that `args` exits 2 and prints `refusal` on stderr exactly
    /// once, with logging off, at `error` and at `info`, and that the run
    /// read no packet first.
    ///
    /// # Arguments
    /// * `args` — CLI arguments expected to trip a feature gate.
    /// * `refusal` — the whole refusal line.
    ///
    /// # Side effects
    /// Spawns the compiled `sipnab` binary three times.
    pub(super) fn assert_gate_failure(args: &[&str], refusal: &str) -> Result<(), TestError> {
        for log in ["off", "error", "info"] {
            let (code, stderr) = run(args, log)?;
            assert_eq!(
                code,
                Some(2),
                "SIPNAB_LOG={log} sipnab {args:?} must exit 2 (feature gate); stderr:\n{stderr}"
            );
            let lines = stderr.lines().filter(|l| l.contains(refusal)).count();
            assert_eq!(
                lines, 1,
                "SIPNAB_LOG={log} sipnab {args:?} must print '{refusal}' on stderr \
                 exactly once; stderr:\n{stderr}"
            );
            assert!(
                !stderr.contains("Reading from") && !stderr.contains("packets:"),
                "SIPNAB_LOG={log} sipnab {args:?} read the capture before refusing; \
                 stderr:\n{stderr}"
            );
        }
        Ok(())
    }
}

#[cfg(any(
    not(feature = "mcp"),
    not(feature = "hep"),
    not(feature = "tls"),
    not(feature = "api"),
    not(feature = "vcon")
))]
use gates::{FIXTURE, TestError, assert_gate_failure};

/// `--mcp` in a build without the mcp feature used to run a plain batch
/// capture — no server, no warning, per-message output on what the user
/// believes is the JSON-RPC channel.
#[cfg(not(feature = "mcp"))]
#[test]
fn mcp_flag_without_mcp_feature_fails_fast() -> Result<(), TestError> {
    assert_gate_failure(
        &["--mcp", "-N", "-I", FIXTURE],
        "--mcp requires the 'mcp' feature (not compiled in)",
    )
}

/// `--hep-listen` used to gate only at capture spawn, after config/privilege
/// setup; it must gate early beside --hep-send/--hep-parse with exit 2.
#[cfg(not(feature = "hep"))]
#[test]
fn hep_listen_without_hep_feature_fails_fast() -> Result<(), TestError> {
    assert_gate_failure(
        &["-N", "-L", "127.0.0.1:9060"],
        "--hep-listen requires the 'hep' feature (not compiled in)",
    )
}

/// `--hep-send` and `--hep-parse` without the hep feature.
#[cfg(not(feature = "hep"))]
#[test]
fn hep_send_and_parse_without_hep_feature_fail_fast() -> Result<(), TestError> {
    for flag in [&["--hep-send", "127.0.0.1:9060"][..], &["--hep-parse"][..]] {
        let args: Vec<&str> = ["-N", "-I", FIXTURE].iter().chain(flag).copied().collect();
        assert_gate_failure(&args, "HEP support requires --features hep")?;
    }
    Ok(())
}

/// Every TLS decryption flag without the tls feature.
#[cfg(not(feature = "tls"))]
#[test]
fn tls_flags_without_tls_feature_fail_fast() -> Result<(), TestError> {
    let cases: [(&[&str], &str); 6] = [
        (
            &["--tls-key", FIXTURE],
            "--tls-key requires the 'tls' feature (not compiled in)",
        ),
        (
            &["--keylog", FIXTURE],
            "--keylog requires the 'tls' feature (not compiled in)",
        ),
        (
            &["--keylog-watch"],
            "--keylog-watch requires the 'tls' feature (not compiled in)",
        ),
        (
            &["--srtp-keys", FIXTURE],
            "--srtp-keys requires the 'tls' feature (not compiled in)",
        ),
        (
            &["--keylog-fd", "3"],
            "--keylog-fd requires the 'tls' feature (not compiled in)",
        ),
        (
            &["--dtls-keylog", FIXTURE],
            "--dtls-keylog requires the 'tls' feature (not compiled in)",
        ),
    ];
    for (flag, refusal) in cases {
        let args: Vec<&str> = ["-N", "-I", FIXTURE].iter().chain(flag).copied().collect();
        assert_gate_failure(&args, refusal)?;
    }
    Ok(())
}

/// Every REST API flag without the api feature.
#[cfg(not(feature = "api"))]
#[test]
fn api_flags_without_api_feature_fail_fast() -> Result<(), TestError> {
    let cases: [(&[&str], &str); 3] = [
        (
            &["--api", "127.0.0.1:0"],
            "--api requires the 'api' feature (not compiled in)",
        ),
        (
            &["--api-key", "k"],
            "--api-key requires the 'api' feature (not compiled in)",
        ),
        (
            &["--api-tls-cert", FIXTURE, "--api-tls-key", FIXTURE],
            "--api-tls-cert requires the 'api' feature (not compiled in)",
        ),
    ];
    for (flag, refusal) in cases {
        let args: Vec<&str> = ["-N", "-I", FIXTURE].iter().chain(flag).copied().collect();
        assert_gate_failure(&args, refusal)?;
    }
    Ok(())
}

/// `--mint-token` without either feature that has a token signer.
#[cfg(not(any(feature = "api", feature = "mcp")))]
#[test]
fn mint_token_without_api_or_mcp_fails_fast() -> Result<(), TestError> {
    assert_gate_failure(
        &["--mint-token"],
        "--mint-token requires the 'api' or 'mcp' feature (not compiled in)",
    )
}

/// The vCon commands without the vcon feature.
#[cfg(not(feature = "vcon"))]
#[test]
fn vcon_commands_without_vcon_feature_fail_fast() -> Result<(), TestError> {
    let spool = tempfile::tempdir()?;
    let dir = spool.path().to_str().ok_or("temp dir is not UTF-8")?;
    let out = spool.path().join("out.json");
    let out = out.to_str().ok_or("temp path is not UTF-8")?;
    let cases: [(&[&str], &str); 6] = [
        (
            &["--vcon-forward", dir],
            "--vcon-forward requires the 'vcon' feature (not compiled in)",
        ),
        (
            &["--vcon-spool-status", dir],
            "--vcon-spool-status requires the 'vcon' feature (not compiled in)",
        ),
        (
            &["--vcon-fetch", "00000000-0000-0000-0000-000000000000"],
            "--vcon-fetch requires the 'vcon' feature (not compiled in)",
        ),
        (
            &[
                "--vcon-resign",
                FIXTURE,
                "--vcon-resign-key",
                FIXTURE,
                "--vcon-resign-cert",
                FIXTURE,
                "--vcon-resign-out",
                out,
            ],
            "--vcon-resign requires the 'vcon' feature (not compiled in)",
        ),
        (
            &["--vcon-audio-fetch", FIXTURE, "--vcon-audio-fetch-out", dir],
            "--vcon-audio-fetch requires the 'vcon' feature (not compiled in)",
        ),
        (
            &["--vcon-validate", FIXTURE],
            "--vcon-validate requires the 'vcon' feature (not compiled in)",
        ),
    ];
    for (args, refusal) in cases {
        assert_gate_failure(args, refusal)?;
    }
    Ok(())
}
