// SPDX-License-Identifier: MIT OR Apache-2.0

//! sipnab — SIP & RTP capture, analysis, and security library.
//!
//! Provides zero-copy SIP parsing, RTP quality metrics (MOS, jitter, loss),
//! dialog state tracking, a filter DSL for matching calls, and security
//! detection (scanners, fraud, digest leaks). Used by the sipnab CLI/TUI
//! tool and available as a library for custom VoIP analysis applications.
//!
//! # Quick Start
//!
//! ```no_run
//! use sipnab::PcapReader;
//! use sipnab::sip::parser::parse_sip;
//! use sipnab::capture::parse::parse_packet;
//!
//! let data = std::fs::read("capture.pcap").unwrap();
//! let reader = PcapReader::new(&data).unwrap();
//! for pkt in reader {
//!     // Process packets...
//! }
//! ```
//!
//! # Semver scope
//!
//! The documented public API is the semver contract. Modules marked
//! `#[doc(hidden)]` (`cli`, `tui`, `privilege`, `process_isolation`,
//! `signals`) exist so the `sipnab` binary can be built from this crate;
//! they are internal, carry **no** semver guarantee, and may change or
//! disappear in any release. Depend only on what appears in the rendered
//! rustdoc.

// Every item — public and private, down to fields and consts — must be
// documented, and unwrap/expect are banned on library production paths
// (tests are exempt via clippy.toml). These are crate attributes rather
// than workspace lints so test/bench crates are not covered — see the
// [workspace.lints] comment in Cargo.toml. CI runs clippy with
// `-D warnings`, so both doc lints are hard gates in practice.
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
#![warn(clippy::unwrap_used, clippy::expect_used)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod analysis;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod app;
#[cfg(any(feature = "api", feature = "mcp"))]
pub mod auth;
pub mod capture;
#[doc(hidden)]
#[cfg(feature = "native")]
pub mod cli;
pub mod config;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod crash;
pub mod crypto;
pub mod error;
pub mod llmnr;
pub mod names;
pub mod net;
#[cfg(not(target_arch = "wasm32"))]
pub mod pipeline;
pub mod stun;

/// WASM plugin host — third-party dialog detections.
///
/// Non-default feature: the stock build carries no interpreter at all.
#[cfg(feature = "plugins")]
pub mod plugin;
pub use error::{CaptureError, Error, ParseError};
pub mod clock;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "native")]
pub mod output;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod parallel;
#[doc(hidden)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod privilege;
#[doc(hidden)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod process_isolation;
pub mod provenance;
// One fixed-window limiter for every surface that meters a peer: the HEP
// receiver's packets and the MCP server's tool calls. Compiled when either is,
// so a build with neither carries no dead counter.
#[cfg(any(feature = "hep", feature = "mcp"))]
pub mod rate_limit;
pub mod rtp;
pub mod rtpengine;
pub mod security;
#[doc(hidden)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod signals;
pub mod sip;
pub mod text;

#[doc(hidden)]
#[cfg(feature = "tui")]
pub mod tui;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// Shared helpers for the test suite (fixtures and builders).
#[cfg(test)]
pub mod test_utils;

// Convenience re-exports for library consumers
pub use capture::pcap_reader::{PcapReader, decompress_capture};
pub use rtp::quality::estimate_mos;
pub use rtp::stream::{RtpStream, StreamKey};
pub use rtp::stream_store::StreamStore;
pub use sip::SipMethod;
pub use sip::dialog::{DialogState, SipDialog};
pub use sip::dialog_store::DialogStore;
pub use sip::dsl::FilterExpr;
pub use sip::message::SipMessage;
