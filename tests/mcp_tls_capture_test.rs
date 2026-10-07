// SPDX-License-Identifier: MIT OR Apache-2.0

//! `start_tls_capture` / `stop_tls_capture`: the opt-in, and the refusals.
//!
//! This is the only tool on sipnab's MCP surface that creates **kernel state**,
//! and the only one that reads the plaintext of processes the agent does not
//! own. So what these tests hold to is not that a capture works — that needs a
//! privileged host — but that every route to one is closed unless the operator
//! opened it, and that each refusal says which wall the caller hit.

#![cfg(feature = "mcp")]

use std::sync::Arc;

use parking_lot::RwLock;
use sipnab::mcp::server::{SipnabMcp, StartTlsCaptureParams};
use sipnab::mcp::tls_capture::TlsCapture;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

fn server() -> SipnabMcp {
    SipnabMcp::new(
        Arc::new(RwLock::new(DialogStore::new(1000, false))),
        Arc::new(RwLock::new(StreamStore::new(1000))),
    )
}

fn no_params() -> StartTlsCaptureParams {
    StartTlsCaptureParams {
        flavors: Vec::new(),
        libraries: Vec::new(),
    }
}

/// **The default.** A stock server must refuse, and must name the flag — an
/// agent told only "denied" cannot tell a policy from a bug.
#[tokio::test]
async fn a_stock_server_refuses_to_install_probes_and_names_the_flag() -> Result<(), TestError> {
    let err = server()
        .start_tls_capture(rmcp::handler::server::wrapper::Parameters(no_params()))
        .await
        .err()
        .ok_or("installing kernel probes must be off by default")?;
    let msg = format!("{err:?}");
    assert!(
        msg.contains("--mcp-allow-tls-capture"),
        "the refusal must name the opt-in: {msg}"
    );
    assert!(
        msg.contains("plaintext") || msg.contains("kernel"),
        "and say what the opt-in permits, so an operator can judge it: {msg}"
    );
    Ok(())
}

/// The opt-in is separate from `--mcp-allow-open-capture` on purpose: one
/// reads a file from a directory, the other attaches probes to a live process.
#[tokio::test]
async fn permitting_open_capture_does_not_permit_installing_probes() -> Result<(), TestError> {
    let err = server()
        .with_open_capture()
        .start_tls_capture(rmcp::handler::server::wrapper::Parameters(no_params()))
        .await
        .err()
        .ok_or("open_capture's opt-in must not carry this one")?;
    assert!(
        format!("{err:?}").contains("--mcp-allow-tls-capture"),
        "still refused, still naming its own flag"
    );
    Ok(())
}

/// Reporting what a capture WOULD see needs no opt-in — only doing it does.
#[tokio::test]
async fn listing_libraries_needs_no_opt_in() -> Result<(), TestError> {
    server().list_tls_libraries().await?;
    Ok(())
}

/// Stopping nothing is not an error. An agent recovering from a disconnect
/// should be able to ask without risking a failure it must then explain.
#[tokio::test]
async fn stopping_when_nothing_runs_says_so_rather_than_failing() -> Result<(), TestError> {
    let out = server().stop_tls_capture().await?;
    let json = format!("{out:?}");
    assert!(
        json.contains("No TLS capture is running"),
        "the answer must say what happened: {json}"
    );
    Ok(())
}

/// The opt-in must be visible in `server_capabilities`, or an agent discovers
/// the setup by being refused mid-investigation.
#[tokio::test]
async fn the_opt_in_is_reported_before_an_agent_needs_it() -> Result<(), TestError> {
    let plain = format!("{:?}", server().server_capabilities().await?);
    assert!(
        plain.contains("mcp_allow_tls_capture"),
        "the flag must appear in capabilities: {plain}"
    );

    let opted = format!(
        "{:?}",
        server().with_tls_capture().server_capabilities().await?
    );
    assert_ne!(
        plain, opted,
        "turning the opt-in on must change what capabilities reports, or an \
         agent cannot tell an armed server from a stock one"
    );
    Ok(())
}

/// A stop is a request, not an act: the worker owns the probes and removes
/// them itself. Reporting `running: false` early would tell an agent the
/// kernel is clean while probes are still attached to a production library.
#[test]
fn a_stop_request_does_not_claim_the_probes_are_gone() -> Result<(), TestError> {
    let c = TlsCapture::new_for_test(vec!["/lib/libssl.so.3:SSL_write".to_string()], "cap-1");
    assert!(!c.finished());
    c.request_stop();
    assert!(
        !c.finished(),
        "probes are still installed until the worker removes them"
    );
    Ok(())
}
