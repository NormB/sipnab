// SPDX-License-Identifier: MIT OR Apache-2.0

//! The operator surface for uprobe TLS capture.
//!
//! What these hold to is the property that makes the feature safe to run at
//! all: **a uprobe capture that attached to nothing must say so.** Missing
//! plaintext is indistinguishable from a quiet trunk, so every route that
//! would end with an empty probe list is required to fail loudly instead.

#![cfg(all(target_os = "linux", feature = "native"))]

use clap::Parser;
use sipnab::capture::CaptureSource;
use sipnab::capture::uprobe::discover::{Flavour, PlannedTarget, parse_flavour, plan_targets};
use sipnab::cli::Cli;

/// `--uprobe-list` is the flag an operator is told to run first, so it must
/// parse on its own with no capture source named.
#[test]
fn uprobe_list_parses_alone() {
    let cli = Cli::try_parse_from(["sipnab", "--uprobe-list"]).expect("parse");
    assert!(cli.tls_args.uprobe_list);
    assert!(
        !cli.tls_args.uprobe_tls,
        "listing must not imply starting a capture"
    );
}

#[test]
fn uprobe_tls_selects_the_uprobe_capture_source() {
    let cli = Cli::try_parse_from([
        "sipnab",
        "-N",
        "--uprobe-tls",
        "--uprobe-library",
        "/usr/lib/libssl.so.3",
    ])
    .expect("parse");
    let config = sipnab::config::Config::default();
    let plan = sipnab::app::bootstrap::plan(&cli, &config).expect("plan");

    match plan.source {
        Some(CaptureSource::Uprobe { ref targets, .. }) => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].library, "/usr/lib/libssl.so.3");
            assert_eq!(
                targets[0].symbol, "SSL_write",
                "the symbol is inferred from the library's flavour"
            );
        }
        other => panic!("expected an uprobe source, got {other:?}"),
    }
}

/// Naming libraries is enough on its own: an operator who says which library
/// to probe has already said they want a uprobe capture.
#[test]
fn naming_a_library_is_enough_to_select_the_source() {
    let cli = Cli::try_parse_from([
        "sipnab",
        "-N",
        "--uprobe-library",
        "/usr/lib/libwolfssl.so.42",
    ])
    .expect("parse");
    let config = sipnab::config::Config::default();
    let plan = sipnab::app::bootstrap::plan(&cli, &config).expect("plan");
    match plan.source {
        Some(CaptureSource::Uprobe { ref targets, .. }) => {
            assert_eq!(targets[0].symbol, "wolfSSL_write");
        }
        other => panic!("expected an uprobe source, got {other:?}"),
    }
}

/// Repeatable, because a host running both flavours needs both probed.
#[test]
fn uprobe_library_is_repeatable_and_each_gets_its_own_symbol() {
    let cli = Cli::try_parse_from([
        "sipnab",
        "-N",
        "--uprobe-library",
        "/usr/lib/libssl.so.3",
        "--uprobe-library",
        "/usr/lib/libwolfssl.so.42",
    ])
    .expect("parse");
    assert_eq!(cli.tls_args.uprobe_library.len(), 2);

    let config = sipnab::config::Config::default();
    let plan = sipnab::app::bootstrap::plan(&cli, &config).expect("plan");
    match plan.source {
        Some(CaptureSource::Uprobe { ref targets, .. }) => {
            let symbols: Vec<&str> = targets.iter().map(|t| t.symbol.as_str()).collect();
            assert_eq!(
                symbols,
                vec!["SSL_write", "wolfSSL_write"],
                "OpenSSL and wolfSSL do not share a write symbol"
            );
        }
        other => panic!("expected an uprobe source, got {other:?}"),
    }
}

#[test]
fn uprobe_symbol_overrides_the_inferred_one() {
    let cli = Cli::try_parse_from([
        "sipnab",
        "-N",
        "--uprobe-library",
        "/usr/lib/libssl.so.3",
        "--uprobe-symbol",
        "SSL_write_ex",
    ])
    .expect("parse");
    let config = sipnab::config::Config::default();
    let plan = sipnab::app::bootstrap::plan(&cli, &config).expect("plan");
    match plan.source {
        Some(CaptureSource::Uprobe { ref targets, .. }) => {
            assert_eq!(targets[0].symbol, "SSL_write_ex");
        }
        other => panic!("expected an uprobe source, got {other:?}"),
    }
}

/// A library sipnab cannot classify has no inferable symbol, and guessing one
/// would install a probe that reads whatever the argument registers hold.
#[test]
fn an_unclassifiable_library_without_a_symbol_is_refused_with_the_fix() {
    let cli = Cli::try_parse_from([
        "sipnab",
        "-N",
        "--uprobe-library",
        "/opt/vendor/libcrypto-x.so",
    ])
    .expect("parse");
    let config = sipnab::config::Config::default();
    let err = sipnab::app::bootstrap::plan(&cli, &config)
        .err()
        .expect("must refuse rather than guess a symbol");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("--uprobe-symbol"),
        "the refusal must name the fix: {msg}"
    );
}

#[test]
fn uprobe_flavour_parses_both_and_is_repeatable() {
    let cli = Cli::try_parse_from([
        "sipnab",
        "--uprobe-list",
        "--uprobe-flavour",
        "openssl",
        "--uprobe-flavour",
        "wolfssl",
    ])
    .expect("parse");
    assert_eq!(cli.tls_args.uprobe_flavour, vec!["openssl", "wolfssl"]);
    assert_eq!(parse_flavour("openssl"), Ok(Flavour::OpenSsl));
    assert_eq!(parse_flavour("wolfssl"), Ok(Flavour::WolfSsl));
}

/// GnuTLS is mapped on ordinary hosts and is deliberately not probed: its
/// write function has a different signature, so a probe built for the OpenSSL
/// shape would read the wrong register.
#[test]
fn a_flavour_sipnab_does_not_probe_is_rejected_at_parse_time() {
    let err = Cli::try_parse_from(["sipnab", "--uprobe-list", "--uprobe-flavour", "gnutls"])
        .expect_err("clap must reject an unsupported flavour");
    let msg = err.to_string();
    assert!(
        msg.contains("openssl") && msg.contains("wolfssl"),
        "the error must list what IS supported: {msg}"
    );
}

/// The backend selector, and the refusal that keeps it honest.
#[test]
fn the_backend_defaults_to_tracefs_and_bpf_can_be_asked_for_by_name() {
    let cli = Cli::try_parse_from(["sipnab", "-N", "--uprobe-tls"]).expect("parse");
    assert_eq!(
        cli.tls_args.uprobe_backend, "tracefs",
        "the default must be the backend that works without BTF or nightly"
    );

    let chosen = Cli::try_parse_from([
        "sipnab",
        "-N",
        "--uprobe-tls",
        "--uprobe-backend",
        "bpf",
        "--uprobe-library",
        "/usr/lib/libssl.so.3",
    ])
    .expect("parse");
    assert_eq!(chosen.tls_args.uprobe_backend, "bpf");

    let config = sipnab::config::Config::default();
    let plan = sipnab::app::bootstrap::plan(&chosen, &config).expect("plan");
    match plan.source {
        Some(CaptureSource::Uprobe { backend, .. }) => {
            assert_eq!(backend, sipnab::capture::UprobeBackend::Bpf);
        }
        other => panic!("expected an uprobe source, got {other:?}"),
    }
}

/// A backend that does not exist is refused at parse time, with the two that do.
#[test]
fn an_unknown_backend_is_rejected_and_names_the_real_ones() {
    let err = Cli::try_parse_from(["sipnab", "-N", "--uprobe-tls", "--uprobe-backend", "ebpf"])
        .expect_err("only tracefs and bpf exist");
    let msg = err.to_string();
    assert!(
        msg.contains("tracefs") && msg.contains("bpf"),
        "the error must list what IS supported: {msg}"
    );
}

/// The property the whole surface exists to protect.
#[test]
fn a_capture_that_would_attach_to_nothing_is_refused() {
    let err = plan_targets(&[], None, &[], Vec::new())
        .expect_err("an empty probe list must never be returned as success");
    assert!(
        err.contains("--uprobe-library"),
        "the refusal must say how to proceed: {err}"
    );
}

/// Flavour narrowing applies to the plan, not just to the listing.
#[test]
fn narrowing_by_flavour_changes_what_would_be_probed() {
    let planned = plan_targets(
        &["/usr/lib/libwolfssl.so.42".to_string()],
        None,
        &[Flavour::WolfSsl],
        Vec::new(),
    )
    .expect("an explicit library needs no discovery");
    assert_eq!(
        planned,
        vec![PlannedTarget {
            library: "/usr/lib/libwolfssl.so.42".into(),
            symbol: "wolfSSL_write".to_string(),
        }]
    );
}
