// SPDX-License-Identifier: MIT OR Apache-2.0
//! sipnab's TFPS readers against a real `tfps_ctl`, when one is named.
//!
//! `tfps_contract_test` holds the contract with fakes: shell scripts that
//! print fixtures, so it runs anywhere and needs no TFPS. This file runs the
//! same readers against the peer itself, because a fake can only agree with
//! what its author believed the peer prints. Set `SIPNAB_TFPS_CTL` to a
//! `tfps_ctl` binary to run it:
//!
//! ```text
//! SIPNAB_TFPS_CTL=/path/to/tfps_ctl cargo test --features full --test tfps_real_peer_test
//! ```
//!
//! Unset, each test prints how to run it and passes: CI has no TFPS, and a
//! test that needs one is opt-in rather than faked. Nothing here needs root
//! or touches a block map. `status` reads a database that need not exist, and
//! `dropped` fails before it reads anything.
//!
//! Point it at a `tfps_ctl` that has JSON mode: sippulse/tfps `master` at or
//! after `984577dc`, the merge of sippulse/tfps#6 that added `--json`. Run on
//! 2026-09-18 against that commit, both tests passed. Against v0.2.1, the
//! newest tag, both fail by design: it rejects `--json` before it reads the
//! subcommand, and the failure message carries the JSON-mode hint instead. By hand, with root and a throwaway pinned map, the same binary
//! also answered `ban`, `banned`, `unban` and `log` in exactly the keys of
//! `tests/fixtures/tfps-*-golden.json*`, including all three `ban` refusals
//! (`local`, `declared`, `kernel`) and `unban`'s `not-blocked`.
#![cfg(all(unix, feature = "native"))]

use std::path::PathBuf;

use sipnab::security::tfps::{DROPPED_HINT, Reply, TfpsLocator};

/// Names the `tfps_ctl` to test against.
const ENV_VAR: &str = "SIPNAB_TFPS_CTL";

/// The named binary, or `None` after saying how to name one.
fn real_ctl(test: &str) -> Option<PathBuf> {
    match std::env::var_os(ENV_VAR).map(PathBuf::from) {
        Some(p) if p.is_file() => Some(p),
        Some(p) => panic!("{ENV_VAR}={} is not a file", p.display()),
        None => {
            eprintln!(
                "{test}: skipped; set {ENV_VAR}=/path/to/tfps_ctl to run it against a real TFPS"
            );
            None
        }
    }
}

#[test]
fn a_real_peer_answers_status_in_the_shape_sipnab_reads() {
    let Some(ctl) = real_ctl("a_real_peer_answers_status_in_the_shape_sipnab_reads") else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("no-such.db");
    let reply = TfpsLocator::new(Some(ctl.clone()), Some(db.clone()))
        .status()
        .unwrap_or_else(|e| panic!("{} status --json: {e}", ctl.display()));
    let Reply::Answered { value, .. } = reply else {
        panic!("an explicitly named tfps_ctl was reported as not installed");
    };
    assert_eq!(
        value.db,
        db.display().to_string(),
        "status must name the database sipnab passed with --db"
    );
    assert!(
        !value.version.is_empty(),
        "status must carry the peer's version"
    );
}

#[test]
fn a_real_peer_asked_for_drops_says_no_tfps_has_them() {
    let Some(ctl) = real_ctl("a_real_peer_asked_for_drops_says_no_tfps_has_them") else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let err = TfpsLocator::new(Some(ctl), Some(dir.path().join("no-such.db")))
        .dropped()
        .expect_err("no TFPS build has a dropped subcommand");
    let msg = err.to_string();
    assert!(
        msg.contains(DROPPED_HINT),
        "the real peer's refusal must reach the operator with the hint: {msg}"
    );
}
