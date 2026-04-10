//! Output formatting for SIP/RTP analysis results.
//!
//! This module provides multiple output backends:
//! - [`cli_print`] — sipgrep-style colored terminal output
//! - [`hexdump`] — Raw hex+ASCII packet dump
//! - [`json`] — JSON/NDJSON structured output
//! - [`dialog_report`] — Tabular dialog summary report
//! - [`call_report`] — Comprehensive single-call diagnosis report
//! - [`fail2ban`] — Fail2ban-compatible log format
//! - [`event_exec`] — External command hooks for events
//! - [`api`] — REST API daemon mode (feature-gated: `api`)

#[cfg(feature = "api")]
pub mod api;
pub mod call_report;
pub mod cli_print;
pub mod dialog_report;
pub mod event_exec;
pub mod fail2ban;
pub mod hexdump;
pub mod json;
pub mod prometheus;
pub mod prometheus_server;

pub use call_report::{ReportFormat, generate_call_report};
pub use cli_print::{ColorMode, OutputOptions, print_sip_message};
pub use dialog_report::print_dialog_report;
pub use event_exec::EventExecEngine;
pub use fail2ban::{format_reg_flood_event, format_scanner_event};
pub use hexdump::hexdump;
pub use json::{dialog_to_json, message_to_json, stream_to_json};
