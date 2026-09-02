// SPDX-License-Identifier: MIT OR Apache-2.0

//! Output formatting for SIP/RTP analysis results.
//!
//! This module provides multiple output backends:
//! - `cli_print` — colored terminal output
//! - `hexdump` — Raw hex+ASCII packet dump
//! - `json` — JSON/NDJSON structured output
//! - `model` — canonical compact dialog/stream projections (all surfaces)
//! - `persistence` — the runtime gate deciding whether content may still
//!   reach disk on this run
//! - `dialog_report` — Tabular dialog summary report
//! - `call_report` — Comprehensive single-call diagnosis report
//! - `fail2ban` — Fail2ban-compatible log format
//! - `event_exec` — External command hooks for events
//! - `api` — REST API daemon mode (feature-gated: `api`)
//! - `prometheus` — Prometheus exposition-format metric data model/formatting
//! - `run_integrity` — what this run could not deliver, in a form a machine
//!   can read: the exit-status predicate and the marker `--json-dialogs` and
//!   `--report` carry when the input was not read in full
//! - `redact` — keyed pseudonymization at the serialization boundary
//!   (feature-gated: available wherever `api`, `mcp` or `vcon` is, which is
//!   where a container or a response leaves this process)
//! - `prometheus_server` — standalone `/metrics` HTTP server (feature-gated:
//!   `metrics`; independent of `api` since it uses raw TCP, no axum/tokio)
//! - `sink` — buffered stdout sink for batch-mode per-message output
//! - `synthetic` — synthetic Ethernet/IPv4/UDP packet construction for pcap
//!   export
//! - `vcon` — one observed dialog as an unsigned, signaling-only vCon
//!   container (feature-gated: `vcon`)
//! - `vcon_schema` — a container checked against the vendored working-group
//!   schema, with the one deviation sipnab emits on purpose named rather than
//!   waved through (feature-gated: `vcon`)
//! - `wireshark` — filter-DSL → Wireshark display-filter translation and
//!   tshark command generation
//!
//! The `pub use` re-exports below form the module's stable convenience
//! surface for the rest of the crate.

pub mod analysis_report;
#[cfg(feature = "api")]
pub mod api;
pub mod call_report;
pub mod cli_print;
pub mod dialog_report;
pub mod event_exec;
pub mod fail2ban;
pub mod group;
pub mod hexdump;
pub mod json;
pub mod model;
pub mod persistence;
pub mod prometheus;
#[cfg(feature = "metrics")]
pub mod prometheus_server;
#[cfg(any(feature = "api", feature = "mcp", feature = "vcon"))]
pub mod redact;
pub mod run_integrity;
pub mod sink;
pub mod stun_report;
pub mod synthetic;
#[cfg(feature = "vcon")]
pub mod vcon;
#[cfg(feature = "vcon")]
pub mod vcon_schema;
pub mod wireshark;

pub use analysis_report::{print_analysis_report, print_analysis_report_as};
pub use call_report::{ReportFormat, generate_call_report};
pub use cli_print::{ColorMode, OutputOptions, print_sip_message};
pub use dialog_report::{print_dialog_report, print_dialog_report_as};
pub use event_exec::EventExecEngine;
pub use fail2ban::{format_reg_flood_event, format_scanner_event, render_absent};
pub use hexdump::hexdump;
pub use json::{dialog_to_json, dialog_to_ndjson, message_to_json, stream_to_json};
pub use sink::BatchSink;
pub use stun_report::{print_stun_report, print_stun_report_as, stun_report_ndjson};

/// Parse a CLI listen-address string into a `SocketAddr`, shared by the two
/// output backends that open a TCP listener — the REST API server (`api`
/// feature) and the standalone Prometheus metrics server (`metrics` feature).
///
/// Accepts a bare port (`"8080"`) or the `":port"` shorthand — both binding
/// `127.0.0.1` (the D18 default) — or any full `addr:port` pair.
///
/// `what` names the address in the failure reason (e.g. `"bind address"` or
/// `"metrics bind address"`) so each caller's diagnostics read naturally.
///
/// # Arguments
///
/// * `addr` — The listen-address string from the CLI.
/// * `what` — Human-readable address label spliced into the error reason.
///
/// # Errors
///
/// Returns `crate::Error::InvalidBindAddr` (carrying the input and a reason
/// string) when the input is neither a bare port, a `:port` shorthand, nor a
/// valid `addr:port` pair.
#[cfg(any(feature = "api", feature = "metrics"))]
pub(crate) fn parse_listen_addr(
    addr: &str,
    what: &str,
) -> Result<std::net::SocketAddr, crate::Error> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // Just a port number.
    if let Ok(port) = addr.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }

    // ":port" shorthand.
    if let Some(stripped) = addr.strip_prefix(':')
        && let Ok(port) = stripped.parse::<u16>()
    {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }

    // Full addr:port.
    addr.parse::<SocketAddr>()
        .map_err(|e| crate::Error::InvalidBindAddr {
            input: addr.to_string(),
            reason: format!("invalid {what} '{addr}': {e}"),
        })
}
