// SPDX-License-Identifier: MIT OR Apache-2.0

//! `[tfps] db` is documented the way sipnab actually passes it to `tfps_ctl`.
//!
//! The configuration reference said sipnab passes the database as
//! `--db=<path>`. It passes `--db` and the path as two arguments. `tfps_ctl`'s
//! parser takes either, so nothing broke, but a reader writing a `tfps_ctl`
//! wrapper script (as the TFPS guide's remote setup does) reads the argument
//! list from this page. Found 2026-09-25 (backlog TFPS-DOC-1).
#![cfg(feature = "native")]

use std::ffi::OsString;
use std::path::Path;

use sipnab::security::tfps::TfpsCommand;

#[test]
fn the_config_reference_describes_the_db_argument_as_sipnab_passes_it() {
    let db = Path::new("/var/lib/tfps/tfps.db");
    let argv = TfpsCommand::Status.argv(Some(db));
    let at = argv
        .iter()
        .position(|a| a == "--db")
        .expect("sipnab passes --db when a database is configured");
    assert_eq!(
        argv.get(at + 1),
        Some(&OsString::from(db.as_os_str())),
        "the path is the argument after --db: {argv:?}"
    );

    let page = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/config-reference.md"),
    )
    .expect("read docs/config-reference.md");
    let row = page
        .lines()
        .find(|l| l.starts_with("| `db` |"))
        .expect("the [tfps] db row");
    assert!(
        row.contains("`--db <path>`") && !row.contains("--db="),
        "the [tfps] db row must describe the two-argument form sipnab builds \
         ({argv:?}), not --db=<path>:\n{row}"
    );
}
