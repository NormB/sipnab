//! `--mcp-sampling-budget` reaches the governor that enforces it.
//!
//! A flag that parses and reaches nothing is the failure this file exists for:
//! the operator sets a budget, sees no error, and believes sampling is on. It
//! is not, and nothing says so. `every_cli_flag_reaches_something_that_reads_it`
//! catches a flag no code mentions; it cannot catch one that is mentioned in a
//! builder nobody calls.
//!
//! The distinction these tests turn on is the refusal REASON. `Disabled` means
//! the operator never enabled sampling. `ClientCannotSample` means they did,
//! and the connected client did not advertise the capability. Both refuse, so
//! a test asserting only "no request went out" passes whether or not the flag
//! was ever read.

#![cfg(feature = "mcp")]

use parking_lot::RwLock;
use sipnab::mcp::SipnabMcp;
use sipnab::mcp::sampling::Refusal;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use std::sync::Arc;

fn server() -> SipnabMcp {
    SipnabMcp::new(
        Arc::new(RwLock::new(DialogStore::new(64, false))),
        Arc::new(RwLock::new(StreamStore::new(64))),
    )
}

/// Without the flag, sampling is off.
#[test]
fn a_server_built_without_the_flag_refuses_as_disabled() {
    let s = server();
    assert_eq!(
        s.may_sample("reg_flood@10.0.0.9"),
        Err(Refusal::Disabled),
        "a stock server must not send observations to any model"
    );
}

/// With a budget set, the refusal changes reason.
///
/// This exercises the BUILDER, not the command line. Mutation testing made the
/// difference concrete: deleting the wiring in `src/app/servers.rs` that calls
/// `with_sampling_budget` left this test green, because it calls the builder
/// itself. `the_cli_flag_is_wired_to_the_builder` below covers the half this
/// one cannot see.
#[test]
fn the_budget_builder_reaches_the_governor() {
    let s = server().with_sampling_budget(20);
    assert_eq!(
        s.may_sample("reg_flood@10.0.0.9"),
        Err(Refusal::ClientCannotSample),
        "the budget must reach the governor. Still refused -- no client here \
         advertised sampling -- but for a DIFFERENT reason, and that difference \
         is the only observable evidence the flag was read at all"
    );
}

/// The budget is shared across clones rather than copied.
///
/// `SipnabMcp` is `Clone`, and rmcp clones it per connection. A budget that
/// copied with the server would reset on every clone, so an hourly ceiling
/// would bound nothing: a caller reconnecting mints a fresh allowance.
#[test]
fn cloning_the_server_does_not_mint_a_fresh_budget() {
    let a = server()
        .with_sampling_budget(1)
        .with_client_sampling_for_test(true);
    let b = a.clone();
    assert!(
        a.may_sample("first").is_ok(),
        "the one request the budget allows"
    );
    assert_eq!(
        b.may_sample("second"),
        Err(Refusal::BudgetSpent { limit: 1 }),
        "the clone must see the budget already spent. If it does not, every \
         reconnect resets the ceiling and the limit is decorative"
    );
}

/// A zero budget refuses, and says the budget is what refused it.
#[test]
fn a_zero_budget_is_none_rather_than_unlimited() {
    let s = server()
        .with_sampling_budget(0)
        .with_client_sampling_for_test(true);
    assert_eq!(
        s.may_sample("anything"),
        Err(Refusal::BudgetSpent { limit: 0 }),
        "elsewhere in sipnab a zero limit means no ceiling. For one that spends \
         the operator's money the safe reading is the restrictive one, and the \
         refusal must name the budget so the operator can tell it from a client \
         that simply cannot sample"
    );
}

/// The command-line flag is actually connected to the builder.
///
/// The test above calls `with_sampling_budget` directly, so it stays green even
/// when nothing in the program ever calls it — which is the precise shape of
/// the defect that matters here: the operator sets a budget, gets no error, and
/// sampling is off. Reading the construction site is a weaker check than
/// driving a real process, and it is the one that fails when the wiring goes.
#[test]
fn the_cli_flag_is_wired_to_the_builder() {
    let servers =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/servers.rs"))
            .expect("read src/app/servers.rs");
    assert!(
        servers.contains("mcp_sampling_budget"),
        "src/app/servers.rs never reads cli.mcp_args.mcp_sampling_budget, so \
         --mcp-sampling-budget parses, reaches nothing, and leaves sampling off \
         while the operator believes they enabled it"
    );
    assert!(
        servers.contains("with_sampling_budget"),
        "src/app/servers.rs reads the flag but never calls \
         with_sampling_budget, so the value it read goes nowhere"
    );
}
