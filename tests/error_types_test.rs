//! The library surface must return structured, matchable errors —
//! not `Result<_, String>`. Callers (and these tests) match on variants;
//! Display keeps the actionable message.
#![cfg(feature = "native")]

use sipnab::Error;

#[test]
fn config_missing_file_is_matchable() {
    let err = sipnab::config::Config::load(Some("/nonexistent/sipnab-test.toml"), false)
        .expect_err("missing explicit config must error");
    assert!(
        matches!(err, Error::ConfigNotFound { .. }),
        "expected ConfigNotFound, got: {err:?}"
    );
    assert!(
        err.to_string().contains("/nonexistent/sipnab-test.toml"),
        "message must name the path, got: {err}"
    );
}

#[test]
fn config_parse_error_is_matchable_and_names_path() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), "this is [not valid toml").expect("write");
    let err = sipnab::config::Config::load(tmp.path().to_str(), false)
        .expect_err("invalid TOML must error");
    assert!(
        matches!(err, Error::ConfigParse { .. }),
        "expected ConfigParse, got: {err:?}"
    );
}

#[cfg(feature = "hep")]
#[test]
fn invalid_cidr_is_matchable() {
    let err =
        sipnab::capture::hep::CidrRange::parse("not-a-cidr").expect_err("garbage CIDR must error");
    assert!(
        matches!(err, Error::InvalidCidr { .. }),
        "expected InvalidCidr, got: {err:?}"
    );
    assert!(
        err.to_string().contains("not-a-cidr"),
        "message must echo the input, got: {err}"
    );
}

#[test]
fn invalid_alert_rule_is_matchable() {
    let err = sipnab::security::alerting::AlertRule::parse("bogus-sink")
        .expect_err("unknown alert sink must error");
    assert!(
        matches!(err, Error::InvalidAlertRule { .. }),
        "expected InvalidAlertRule, got: {err:?}"
    );
}

#[cfg(feature = "api")]
#[test]
fn invalid_bind_addr_is_matchable() {
    let err = sipnab::output::api::parse_bind_addr("not-an-addr")
        .expect_err("garbage bind addr must error");
    assert!(
        matches!(err, Error::InvalidBindAddr { .. }),
        "expected InvalidBindAddr, got: {err:?}"
    );
}
