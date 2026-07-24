// SPDX-License-Identifier: MIT OR Apache-2.0

//! Output formatting for SIP/RTP analysis results.
//!
//! This module provides multiple output backends:
//! - `cli_print` — sipgrep-style colored terminal output
//! - `hexdump` — Raw hex+ASCII packet dump
//! - `json` — JSON/NDJSON structured output
//! - `model` — canonical compact dialog/stream projections (all surfaces)
//! - `dialog_report` — Tabular dialog summary report
//! - `call_report` — Comprehensive single-call diagnosis report
//! - `fail2ban` — Fail2ban-compatible log format
//! - `event_exec` — External command hooks for events
//! - `api` — REST API daemon mode (feature-gated: `api`)
//! - `prometheus` — Prometheus exposition-format metric data model/formatting
//! - `prometheus_server` — standalone `/metrics` HTTP server (feature-gated:
//!   `metrics`; independent of `api` since it uses raw TCP, no axum/tokio)
//! - `sink` — buffered stdout sink for batch-mode per-message output
//! - `synthetic` — synthetic Ethernet/IPv4/UDP packet construction for pcap
//!   export
//! - `wireshark` — filter-DSL → Wireshark display-filter translation and
//!   tshark command generation
//!
//! The `pub use` re-exports below form the module's stable convenience
//! surface for the rest of the crate.

#[cfg(feature = "api")]
pub mod api;
pub mod call_report;
pub mod cli_print;
pub mod dialog_report;
pub mod event_exec;
pub mod fail2ban;
pub mod hexdump;
pub mod json;
pub mod model;
pub mod prometheus;
#[cfg(feature = "metrics")]
pub mod prometheus_server;
pub mod sink;
pub mod synthetic;
pub mod wireshark;

pub use call_report::{ReportFormat, generate_call_report};
pub use cli_print::{ColorMode, OutputOptions, print_sip_message};
pub use dialog_report::print_dialog_report;
pub use event_exec::EventExecEngine;
pub use fail2ban::{format_reg_flood_event, format_scanner_event};
pub use hexdump::hexdump;
pub use json::{dialog_to_json, message_to_json, stream_to_json};
pub use sink::BatchSink;
