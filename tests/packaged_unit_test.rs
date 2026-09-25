// SPDX-License-Identifier: MIT OR Apache-2.0

//! The systemd unit the `.deb` and `.rpm` install must be able to start.
//!
//! Up to 0.5.190 it could not. `packaging/sipnab.service` ran
//! `/usr/local/bin/sipnab` while both packages install `/usr/bin/sipnab`, so
//! `systemctl start sipnab` failed with `status=203/EXEC` on every install.
//! It also passed `-d %i`, an instance specifier, in a unit that is not a
//! template, which systemd expands to an empty string. Found by running the
//! vCon guide on a clean Debian 13 VM on 2026-09-25.
//!
//! Nothing checked the unit because nothing ran it: the package tests assert
//! the file is present, not that it points at anything. These tests tie it
//! to the paths the two package builders actually write and to sipnab's own
//! argument parser.
#![cfg(feature = "native")]

use clap::Parser;
use sipnab::cli::Cli;
use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The unit's `ExecStart=` as one argument vector, continuation lines joined.
fn exec_start() -> Vec<String> {
    let unit = read("packaging/sipnab.service");
    let joined = unit.replace("\\\n", " ");
    let line = joined
        .lines()
        .find_map(|l| l.trim().strip_prefix("ExecStart="))
        .expect("packaging/sipnab.service has no ExecStart=");
    line.split_whitespace().map(str::to_owned).collect()
}

/// Where each package builder puts the binary, read from the builder itself.
fn installed_paths() -> Vec<(&'static str, String)> {
    let deb = read("packaging/deb/build-deb.sh");
    let rpm = read("packaging/rpm/build-rpm.sh");
    let deb_path = deb
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("cp \"$BIN_SRC\" \"$PKG_DIR")
                .and_then(|r| r.strip_suffix('"'))
        })
        .expect("build-deb.sh: no `cp \"$BIN_SRC\" \"$PKG_DIR...\"` line");
    let rpm_path = rpm
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("install -D -m 0755 %{bin_src} %{buildroot}")
        })
        .expect("build-rpm.sh: no `install ... %{bin_src} %{buildroot}...` line");
    vec![("deb", deb_path.to_owned()), ("rpm", rpm_path.to_owned())]
}

#[test]
fn the_unit_runs_the_binary_both_packages_install() {
    let argv = exec_start();
    for (pkg, path) in installed_paths() {
        assert_eq!(
            argv[0], path,
            "packaging/sipnab.service runs {} but the {pkg} installs {path}: \
             `systemctl start sipnab` would fail with status=203/EXEC",
            argv[0]
        );
    }
}

#[test]
fn a_unit_that_is_not_a_template_uses_no_instance_specifier() {
    // `sipnab.service` has no `@`, so systemd has no instance name to give
    // `%i`/`%I`, and expands them to the empty string.
    let unit = read("packaging/sipnab.service");
    let found: Vec<&str> = ["%i", "%I"]
        .into_iter()
        .filter(|s| unit.contains(s))
        .collect();
    assert!(
        found.is_empty(),
        "packaging/sipnab.service uses {found:?}, which expand to nothing in a non-template unit"
    );
}

#[test]
fn sipnab_accepts_every_argument_the_unit_passes() {
    let argv = exec_start();
    if let Err(e) = Cli::try_parse_from(&argv) {
        panic!("sipnab rejects the unit's ExecStart {argv:?}:\n{e}");
    }
}

#[test]
fn the_unit_does_not_open_the_rest_api_by_default() {
    // An install should not start listening for REST requests on every
    // interface with no key. Operators who want the API add it in a
    // drop-in on purpose, with the key in `SIPNAB_API_KEY`.
    let argv = exec_start();
    assert!(
        !argv.iter().any(|a| a == "--api" || a.starts_with("--api=")),
        "packaging/sipnab.service opens the REST API: {argv:?}"
    );
}

#[test]
fn the_unit_does_not_take_node_exporters_port() {
    // 9100 is node_exporter's port, and node_exporter runs on most hosts
    // that are monitored at all; the Debian 13 VM this was found on ran it.
    // A unit that binds it exits at startup with "Address already in use".
    let argv = exec_start();
    let taken: Vec<&String> = argv.iter().filter(|a| a.ends_with(":9100")).collect();
    assert!(
        taken.is_empty(),
        "packaging/sipnab.service binds node_exporter's port 9100: {taken:?}"
    );
}

#[test]
fn the_unit_does_not_stream_every_message_into_the_journal() {
    // `-N` prints each SIP message to stdout, and a service's stdout is the
    // journal. On a busy link that is the whole signaling stream written to
    // disk by journald, which is both noise and a copy of call data nobody
    // asked to keep. Alerts and summaries still reach syslog.
    let argv = exec_start();
    assert!(
        argv.iter().any(|a| a == "--no-cli-print"),
        "packaging/sipnab.service runs -N without --no-cli-print: {argv:?}"
    );
}
