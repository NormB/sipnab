// SPDX-License-Identifier: MIT OR Apache-2.0

// The `mcp` feature gates the module under test, and `cli` comes with it. The
// feature matrix builds combinations like `--features tls` where neither
// exists, and an ungated file fails the whole combination at compile time —
// which is exactly what blocked this commit's push. Sibling MCP tests carry
// the same attribute.
#![cfg(feature = "mcp")]

//! The MCP response ceiling is an operator setting, not a build-time fact.
//!
//! `HARD_LIMIT` bounded every list-style MCP response at 1000 rows and could
//! only be changed by recompiling. It was reported by an operator who went
//! looking for the knob, found the number documented in three places, and
//! found no way to move it -- because there was none.
//!
//! The right value is not a property of sipnab. It is a property of the agent
//! on the other end: a model with a small context wants far fewer than 1000
//! rows, and a batch consumer piping to a file wants far more. A constant
//! cannot be right for both.
//!
//! Precedence follows every other numeric limit here -- flag, then config,
//! then default -- so there is one rule to learn rather than one per setting.

use sipnab::cli::Cli;
use sipnab::config::Config;
use sipnab::mcp::shape::{DEFAULT_LIMIT, HARD_LIMIT, resolve_limit, resolve_limit_with_cap};

/// The default is unchanged, so an operator who sets nothing sees no change.
#[test]
fn the_default_cap_is_still_the_old_constant() {
    assert_eq!(
        HARD_LIMIT, 1000,
        "the default ceiling moved; that is a behaviour change"
    );
    let cli = Cli::parse_from_args(["sipnab"]);
    assert_eq!(
        cli.mcp_row_cap(&Config::default()),
        HARD_LIMIT,
        "with no flag and no config, the cap must be the documented default"
    );
}

/// A request above the cap is clamped TO THE CAP, not to the old constant.
#[test]
fn a_request_over_the_cap_is_clamped_to_the_configured_cap() {
    assert_eq!(resolve_limit_with_cap(Some(99_999), 25), 25);
    assert_eq!(
        resolve_limit_with_cap(Some(10), 25),
        10,
        "under the cap passes through"
    );
    // A cap ABOVE the old constant must actually be honoured -- the point of
    // the setting is to allow more, not only less.
    assert_eq!(resolve_limit_with_cap(Some(5_000), 10_000), 5_000);
}

/// Zero and absent still mean "the default page size", independent of the cap.
#[test]
fn absent_and_zero_still_resolve_to_the_default_page_size() {
    assert_eq!(resolve_limit_with_cap(None, 25), DEFAULT_LIMIT.min(25));
    assert_eq!(resolve_limit_with_cap(Some(0), 25), DEFAULT_LIMIT.min(25));
    // ...and the default page size is itself bounded by a small cap, or a cap
    // of 10 would silently return 50 rows.
    assert_eq!(resolve_limit_with_cap(None, 10), 10);
}

/// The old entry point keeps working, so existing callers are unaffected.
#[test]
fn the_uncapped_helper_still_uses_the_default() {
    assert_eq!(resolve_limit(Some(99_999)), HARD_LIMIT);
    assert_eq!(resolve_limit(None), DEFAULT_LIMIT);
}

/// Flag beats config beats default -- the same rule as every other limit.
#[test]
fn the_flag_wins_over_config_which_wins_over_the_default() {
    let mut cfg = Config::default();
    cfg.limits.mcp_max_rows = Some(200);

    let from_config = Cli::parse_from_args(["sipnab"]);
    assert_eq!(
        from_config.mcp_row_cap(&cfg),
        200,
        "config must be honoured"
    );

    let from_flag = Cli::parse_from_args(["sipnab", "--mcp-max-rows", "75"]);
    assert_eq!(
        from_flag.mcp_row_cap(&cfg),
        75,
        "the explicit flag is the more specific instruction and must win"
    );
    assert_eq!(
        from_flag.mcp_row_cap(&Config::default()),
        75,
        "the flag must work with no config file at all"
    );
}

/// A cap of zero is rejected by name, the way dialog_limit is.
///
/// Silently treating 0 as "unlimited" would turn a typo into an unbounded
/// response; silently treating it as "default" would hide the mistake.
/// (TOML parsing lives in src/config.rs unit tests -- `toml` is not a
/// dev-dependency, so an integration test cannot build a Config from text.)
#[test]
fn a_zero_cap_is_rejected_and_names_the_key() {
    let mut cfg = Config::default();
    cfg.limits.mcp_max_rows = Some(0);
    let err = cfg.limits.validate().expect_err("0 must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("mcp_max_rows"),
        "the error must name the key an operator has to fix, got: {msg}"
    );
}
