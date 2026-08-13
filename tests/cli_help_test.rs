// SPDX-License-Identifier: MIT OR Apache-2.0

//! UX contracts of the top-level CLI surface: --help must group its ~140
//! flags under section headings (one flat Options: list is unscannable),
//! and --completions must emit a usable shell completion script.
#![cfg(feature = "native")]

#[path = "support/run.rs"]
mod run_support;

#[path = "support/source_scan.rs"]
mod source_scan;

/// Runs the `sipnab` binary from the crate root under the shared test baseline
/// (see [`run_support::run`]); this surface asserts only on stdout and exit
/// codes, so it leaves `SIPNAB_LOG` unset (`None`).
///
/// # Arguments
/// * `args` — CLI arguments to pass.
///
/// # Returns
/// `(stdout, stderr, exit_code)` of the finished process.
fn run(args: &[&str]) -> (String, String, Option<i32>) {
    run_support::run(args, None)
}

/// --help must render section headings, not one flat Options: wall.
#[test]
fn help_groups_flags_under_headings() {
    let (stdout, _, code) = run(&["--help"]);
    assert_eq!(code, Some(0));
    for heading in [
        "Capture:",
        "Mode:",
        "Matching:",
        "Output:",
        "Security:",
        "TLS / Decryption:",
        "Config:",
    ] {
        assert!(
            stdout.contains(heading),
            "--help must contain the '{heading}' section heading:\n{stdout}"
        );
    }
}

/// --completions <shell> prints a completion script to stdout and exits 0.
#[test]
fn completions_emit_scripts_for_each_shell() {
    for shell in ["bash", "zsh", "fish"] {
        let (stdout, stderr, code) = run(&["--completions", shell]);
        assert_eq!(code, Some(0), "--completions {shell} failed:\n{stderr}");
        assert!(
            stdout.contains("sipnab"),
            "{shell} completion script must reference the binary:\n{stdout}"
        );
        assert!(
            stdout.len() > 200,
            "{shell} completion script suspiciously short ({} bytes)",
            stdout.len()
        );
    }
}

/// An unknown shell name is a usage error (exit 2), not a silent success.
#[test]
fn completions_reject_unknown_shell() {
    let (_, stderr, code) = run(&["--completions", "tcsh"]);
    assert_eq!(code, Some(2), "unknown shell must be a usage error");
    assert!(
        stderr.contains("tcsh"),
        "error should echo the bad value:\n{stderr}"
    );
}

/// `--stir-shaken` must not claim to validate anything it does not.
///
/// It used to read "Validate STIR/SHAKEN identity headers." sipnab decodes the
/// RFC 8224 PASSporT and reports the attestation the originator asserted; it
/// never fetches the referenced certificate and never checks a signature, so a
/// forged Identity header reports exactly like a genuine one. An operator
/// running this on fraud traffic and reading "Validate" would conclude the
/// opposite of the truth — the worst shape a security flag's help can take.
///
/// Both help surfaces are checked, because clap renders two: `-h` prints only
/// the summary line, `--help` prints the full doc comment.
///
/// The block has to be extracted rather than grepped for. clap puts the flag on
/// its own line and the description on the following lines, so the obvious
/// `lines().find(|l| l.contains("--stir-shaken"))` returns "      --stir-shaken"
/// — a line that can never contain "validate", making the assertion dead. It
/// was written that way first, and passed against the unfixed help text.
#[test]
fn stir_shaken_help_does_not_promise_verification_it_never_performs() {
    /// The flag's entry: its line plus every indented continuation line, up to
    /// the next flag.
    fn block(help: &str, flag: &str) -> String {
        let mut out = Vec::new();
        let mut in_block = false;
        for line in help.lines() {
            let is_flag_line = line.trim_start().starts_with("--")
                || line.trim_start().starts_with('-') && line.trim_start().len() > 1;
            if line.trim_start().starts_with(flag) {
                in_block = true;
                out.push(line);
                continue;
            }
            if in_block {
                if is_flag_line && !line.trim_start().starts_with(flag) {
                    break;
                }
                out.push(line);
            }
        }
        assert!(!out.is_empty(), "{flag} missing from help:\n{help}");
        out.join("\n")
    }

    for args in [vec!["-h"], vec!["--help"]] {
        let (stdout, _, code) = run(&args);
        assert_eq!(code, Some(0), "{args:?} must succeed");
        let entry = block(&stdout, "--stir-shaken");
        assert!(
            !entry.to_lowercase().contains("validate"),
            "`sipnab {}` claims --stir-shaken validates, which it never does:\n{entry}",
            args.join(" ")
        );
        // Not merely avoiding the word: silence would still leave a reader
        // assuming a security flag verifies what it reports.
        assert!(
            entry.contains("no signature verification")
                || entry.contains("does NOT verify the signature"),
            "`sipnab {}` must state plainly that no signature is verified, or \
             an operator reads an unverified claim as a checked one:\n{entry}",
            args.join(" ")
        );
    }
}

/// The other half of the same contract, and the one that makes it durable.
///
/// `VerificationStatus` has exactly two variants, `NotChecked` and `Expired`,
/// and both are reachable. There is deliberately no `Valid`: sipnab fetches no
/// certificate, so no code path could produce one. That is fine while the help
/// says no signature is checked. It stops being fine the moment someone
/// implements verification, because the natural change (add and construct
/// `Valid`) leaves the CLI help and docs describing the old behaviour, which is
/// how the original defect was born.
///
/// So this fails on the FIRST construction of `Valid`, and says what else to
/// update. It is a coupling gate, not a ban on implementing verification.
///
/// Note the gate is a source scan, not a type check — it stays meaningful
/// whether `Valid` is re-added as a variant or spelled some other way, because
/// what it watches for is production code *naming* it.
#[test]
fn implementing_signature_verification_must_also_update_the_claims() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sip/stir_shaken.rs"
    ))
    .expect("read stir_shaken.rs");

    // Production code only. What makes the help wrong is shipped behaviour,
    // not scaffolding: a test may name `Valid` to assert it is absent, or to
    // exercise a decoder, without sipnab verifying anything.
    //
    // Cut at the test MODULE, via the shared rule. This gate used to split the
    // raw text on `#[cfg(test)]`, which stops at the first line that merely
    // SPELLS the attribute — a comment, or the test-only `use` imports other
    // files in this crate put near the top. `stir_shaken.rs` happens to have
    // neither today, so the scan was reading all 255 of its production lines;
    // it was one comment away from reading none of them and still passing.
    let prod = source_scan::production_source(&src);

    assert!(
        !prod.contains("VerificationStatus::Valid"),
        "src/sip/stir_shaken.rs now constructs VerificationStatus::Valid, so \
         sipnab verifies signatures. That is welcome — but the claims that \
         were written for the non-verifying behaviour must move with it:\n\
         \x20 - src/cli.rs, the --stir-shaken help (says it does NOT verify)\n\
         \x20 - docs/cli-reference.md, the flag table row and the audit example\n\
         \x20 - docs/rest-api.md, which states the status is only NotChecked \
         or Expired\n\
         \x20 - src/sip/stir_shaken.rs's own module doc\n\
         Update those, then relax this gate."
    );
}
