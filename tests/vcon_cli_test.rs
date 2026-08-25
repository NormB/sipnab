// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

//! `--export-vcon`, driven the way an operator drives it: the real binary,
//! real arguments, a real capture.
//!
//! The exporter had unit tests from the day it was written and no caller at
//! all. That is the failure this file exists to catch — a `pub fn` returning a
//! correct container, reachable from nothing anyone can run. So every
//! assertion here goes through `Command`, and none of them reaches into the
//! crate.
//!
//! Three properties, and the third is the one that carries the weight:
//!
//! * a known Call-ID produces a container describing THAT dialog;
//! * every refusal — unknown Call-ID, unwritable path, a build with no
//!   exporter — exits non-zero and names the remedy, because a refusal that
//!   exits 0 is indistinguishable from a container nobody read;
//! * two different dialogs produce two different containers. Without that, a
//!   handler returning one constant satisfies everything above.
//!
//! Everything that needs an exporter sits in [`exporting`], gated on the
//! `vcon` feature. Without the gate those tests still PASSED on a build with
//! no exporter, for the wrong reason: the run exits non-zero because the flag
//! itself was refused, which satisfies every "this must fail" assertion here
//! while proving nothing about the failure it names.

use std::path::PathBuf;
use std::process::Output;

/// The capture both dialog tests read. Two INVITE dialogs, one completed and
/// one still in call, so "a different dialog" is a real second dialog out of
/// one file rather than a second file.
const SAMPLE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// A Call-ID `SAMPLE` holds.
const CALL_A: &str = "1-1966@10.0.2.20";

/// A temp directory unique to this PROCESS, so two harnesses running at once
/// do not delete each other's output mid-assertion.
fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sipnab-vcon-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run the real binary with `--export-vcon`, plus whatever else is given.
fn run(args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab")
}

/// Everything that needs a binary carrying the exporter.
///
/// Gated as a whole rather than test by test: a refusal assertion that
/// cannot tell "the export failed" from "the flag was refused" is worse
/// than no assertion, because it reports green either way.
#[cfg(feature = "vcon")]
mod exporting {
    use super::{CALL_A, SAMPLE, run, tmp_dir};
    use std::path::{Path, PathBuf};

    /// The OTHER Call-ID `SAMPLE` holds.
    const CALL_B: &str = "1-1968@10.0.2.20";

    /// Resolve a path against the repository root.
    fn repo(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    /// Export one Call-ID from `SAMPLE` to stdout and parse what came back.
    fn export_to_stdout(call_id: &str) -> serde_json::Value {
        let out = run(&["-N", "-I", SAMPLE, "--export-vcon", call_id, "--quiet"]);
        assert!(
            out.status.success(),
            "exporting a known Call-ID failed ({:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "--export-vcon wrote something that is not a vCon container: {e}\n{}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    // ── Success ─────────────────────────────────────────────────────────────

    /// A known Call-ID produces a container describing that dialog.
    ///
    /// The three fields checked are the three a consumer keys on: the syntax
    /// version it parses against, the parties it renders, and the `Call-ID` that
    /// ties the container back to a capture somebody still holds.
    #[test]
    fn a_known_call_id_exports_a_container_naming_that_dialog() {
        let v = export_to_stdout(CALL_A);

        assert_eq!(
            v["vcon"], "0.4.0",
            "the container must state the vCon syntax version it was written \
             against; a consumer parses against that string"
        );
        assert_eq!(
            v["dialog"][0]["sip_call_id"], CALL_A,
            "the container names a different dialog than the one asked for"
        );

        // Two observed parties, then the sipnab observer, and no `name` on any of
        // them: a From/To display name is what the sender wrote, not an identity.
        let parties = v["parties"].as_array().expect("parties is an array");
        assert_eq!(
            parties.len(),
            3,
            "expected the two observed parties plus the sipnab observer, got {}",
            parties.len()
        );
        assert_eq!(
            parties[2]["role"], "observer",
            "the last party must be the sipnab observer, or every attachment's \
             `party` index points at a caller"
        );
        for party in parties {
            assert_eq!(
                party["validation"], "none",
                "a party claims validation sipnab never performed: {party}"
            );
            assert!(
                party.get("name").is_none(),
                "a party carries a `name`, which reads as an established identity: {party}"
            );
        }

        // Signaling only, and unsigned. Both are refusals the design turns on, so
        // both are asserted rather than assumed.
        for banned in ["signatures", "payload", "protected", "consent", "subject"] {
            assert!(
                v.get(banned).is_none(),
                "an observer vCon must carry no {banned}"
            );
        }
    }

    /// `--vcon-out` writes the container to a file INSTEAD of stdout.
    ///
    /// "Instead" is the assertion. A path that also echoed the container to stdout
    /// would put a second copy into whatever pipe the operator was already
    /// watching, and the two would diverge the moment either surface changed.
    #[test]
    fn vcon_out_writes_the_container_to_the_named_path() {
        let dir = tmp_dir("out");
        let path = dir.join("call.vcon");
        let out = run(&[
            "-N",
            "-I",
            SAMPLE,
            "--export-vcon",
            CALL_A,
            "--vcon-out",
            path.to_str().expect("utf8 temp path"),
            // `--vcon-out` deliberately leaves the per-message stream alone -- the
            // container is not on stdout, so nothing there can corrupt it. Silence
            // it here so the emptiness assertion below means what it says.
            "--no-cli-print",
            "--quiet",
        ]);
        assert!(
            out.status.success(),
            "writing to a writable path failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let written = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("--export-vcon wrote no file at {}: {e}", path.display()));
        let v: serde_json::Value =
            serde_json::from_str(&written).expect("the written file is a JSON container");
        assert_eq!(v["dialog"][0]["sip_call_id"], CALL_A);
        assert_eq!(v["vcon"], "0.4.0");

        assert!(
            out.stdout.is_empty(),
            "--vcon-out named a file, so the container must not also reach stdout; \
             got: {}",
            String::from_utf8_lossy(&out.stdout)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Discrimination ──────────────────────────────────────────────────────

    /// Two different dialogs out of one capture produce two different containers.
    ///
    /// Without this, an exporter that ignored its argument and returned one fixed
    /// container would satisfy every other test on this page. The uuid is checked
    /// as well as the Call-ID: the identifier is what a consumer deduplicates on,
    /// so two conversations sharing one would silently collapse into one record.
    #[test]
    fn two_dialogs_export_two_different_containers() {
        let a = export_to_stdout(CALL_A);
        let b = export_to_stdout(CALL_B);

        assert_ne!(
            a["dialog"][0]["sip_call_id"], b["dialog"][0]["sip_call_id"],
            "two dialogs exported to containers naming one Call-ID — the exporter \
             is not reading its argument"
        );
        assert_eq!(a["dialog"][0]["sip_call_id"], CALL_A);
        assert_eq!(b["dialog"][0]["sip_call_id"], CALL_B);

        assert_ne!(
            a["uuid"], b["uuid"],
            "two conversations share one vCon uuid, so a consumer deduplicating on \
             it keeps whichever arrived first and discards the other"
        );

        assert_ne!(
            super::body_of(&a["attachments"][0])["sip_call_id"],
            super::body_of(&b["attachments"][0])["sip_call_id"],
            "the message trace describes the same call for both dialogs"
        );
    }

    /// Re-exporting one dialog out of one capture keeps its identifier.
    ///
    /// The opposite assertion to the one above, and the one that actually
    /// discriminates: an exporter minting a fresh uuid per call passes
    /// `two_dialogs_export_two_different_containers` and breaks every consumer
    /// that deduplicates.
    #[test]
    fn re_exporting_one_dialog_keeps_its_identifier() {
        let first = export_to_stdout(CALL_A);
        let second = export_to_stdout(CALL_A);
        assert_eq!(
            first["uuid"], second["uuid"],
            "two exports of one dialog from one capture minted two identifiers, so \
             a consumer accumulates copies of one conversation"
        );
    }

    // ── Refusals ────────────────────────────────────────────────────────────

    /// An unknown Call-ID exits non-zero and says what to run to find a real one.
    #[test]
    fn an_unknown_call_id_is_refused_and_names_the_remedy() {
        let out = run(&[
            "-N",
            "-I",
            SAMPLE,
            "--export-vcon",
            "no-such-call@nowhere",
            "--quiet",
        ]);
        assert!(
            !out.status.success(),
            "an unknown Call-ID exported nothing and exited 0, which a script \
             reads as a container it can go and open"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("no-such-call@nowhere"),
            "the refusal must quote the Call-ID that was not found: {stderr}"
        );
        assert!(
            stderr.contains("--report"),
            "the refusal must name what lists the Call-IDs this run holds: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "a refused export wrote {} bytes to stdout",
            out.stdout.len()
        );
    }

    /// An unwritable output path exits non-zero and names the path.
    #[test]
    fn an_unwritable_vcon_out_is_refused_and_names_the_path() {
        let dir = tmp_dir("unwritable");
        // A directory that does not exist, so `fs::write` cannot create the file
        // inside it. Deliberately not a permission trick: this suite runs as root
        // on the self-hosted runner, where a read-only mode bit proves nothing.
        let path = dir.join("no-such-directory").join("call.vcon");
        let out = run(&[
            "-N",
            "-I",
            SAMPLE,
            "--export-vcon",
            CALL_A,
            "--vcon-out",
            path.to_str().expect("utf8 temp path"),
            "--quiet",
        ]);
        assert!(
            !out.status.success(),
            "a vCon that could not be written exited 0, so an operator believes a \
             file is there"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("no-such-directory"),
            "the refusal must name the path it could not write: {stderr}"
        );
        assert!(
            !path.exists(),
            "the refusal reported a failure and left a file behind"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--vcon-out` naming a capture this run reads is refused before anything
    /// opens a writer.
    ///
    /// The container summarizes the capture, so writing it over that capture
    /// destroys the evidence it refers to — and `-O` reached exactly this mistake
    /// first. The assertion is on the input's BYTES, because "the run errored" is
    /// satisfied by a guard that fires after truncating the file.
    #[test]
    fn a_vcon_out_that_names_the_input_capture_is_refused() {
        let dir = tmp_dir("clobber");
        let input = dir.join("capture.pcap");
        std::fs::copy(repo(SAMPLE), &input).expect("copy the sample capture");
        let before = std::fs::read(&input).expect("read the copied capture");

        let out = run(&[
            "-N",
            "-I",
            input.to_str().expect("utf8 temp path"),
            "--export-vcon",
            CALL_A,
            "--vcon-out",
            input.to_str().expect("utf8 temp path"),
            "--quiet",
        ]);
        assert!(
            !out.status.success(),
            "sipnab agreed to write a vCon over the capture it was reading"
        );
        let after = std::fs::read(&input).expect("the input capture is gone");
        assert_eq!(
            before, after,
            "the input capture changed — the guard fired after opening the writer"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `--vcon-out` on its own is refused: it has nothing to write.
#[test]
fn vcon_out_without_export_vcon_is_refused() {
    let dir = tmp_dir("orphan");
    let path = dir.join("call.vcon");
    let out = run(&[
        "-N",
        "-I",
        SAMPLE,
        "--vcon-out",
        path.to_str().expect("utf8 temp path"),
        "--quiet",
    ]);
    assert!(
        !out.status.success(),
        "--vcon-out with no --export-vcon exited 0, so a typo'd Call-ID flag \
         leaves an operator waiting for a file nothing was going to write"
    );
    assert!(
        !path.exists(),
        "a run with nothing to export created an output file anyway"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── The feature gate ────────────────────────────────────────────────────

/// A build carrying the exporter accepts the flag.
///
/// The paired half of `a_build_without_the_vcon_feature_refuses_the_flag`.
/// Both arms are compiled in every build and each runs in the one it
/// describes, so neither can rot into an assertion nothing exercises.
#[cfg(feature = "vcon")]
#[test]
fn a_build_with_the_vcon_feature_accepts_the_flag() {
    let out = run(&["-N", "-I", SAMPLE, "--export-vcon", CALL_A, "--quiet"]);
    assert!(
        out.status.success(),
        "this build carries the vcon feature and still refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.stdout.is_empty(),
        "the flag was accepted and wrote nothing"
    );
}

/// A build without the exporter refuses the flag by name and exits 2.
///
/// Exit 2 rather than 1: a pipeline has to tell "sipnab broke" from "this
/// binary cannot do what you asked", and the responses differ completely —
/// the second one is answered by installing a different build.
#[cfg(not(feature = "vcon"))]
#[test]
fn a_build_without_the_vcon_feature_refuses_the_flag() {
    let out = run(&["-N", "-I", SAMPLE, "--export-vcon", CALL_A, "--quiet"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a flag this build cannot honor must exit 2, not 0 and not 1: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("vcon"),
        "the refusal must name the missing feature: {stderr}"
    );
    assert!(
        stderr.contains("--features"),
        "the refusal must name what produces a binary that can: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "a build with no exporter wrote {} bytes to stdout",
        out.stdout.len()
    );
}

/// A `json`-encoded body, parsed.
///
/// Gated on the ITEM rather than left bare: its only callers live in the
/// `#[cfg(feature = "vcon")]` module above, so a build without the feature
/// warns `never used`, and CI's feature matrix runs with warnings denied. The
/// local hook builds `--features full` and cannot see this.
///
/// §2.3.2 makes `body` a STRING, so every read of one goes through here rather
/// than indexing a `Value` that is not an object. The conserver's own model
/// says the same in a comment: a caller handing it a dict gets it JSON-encoded
/// before anything else touches the attachment.
#[cfg(feature = "vcon")]
fn body_of(node: &serde_json::Value) -> serde_json::Value {
    let text = node["body"]
        .as_str()
        .unwrap_or_else(|| panic!("a json body must be a string: {node}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("body must parse: {e}: {text}"))
}
