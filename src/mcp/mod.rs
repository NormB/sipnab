// SPDX-License-Identifier: MIT OR Apache-2.0

//! Model Context Protocol (MCP) server mode for sipnab.
//!
//! This module exposes sipnab's analysis surface (dialogs, streams,
//! diagnostics, security findings, call reports) as MCP tools so a local AI
//! agent (Claude Code, Claude Desktop, or any MCP-capable client) can drive
//! sipnab as a debugging instrument against a live capture or pcap file.
//!
//! **No tool mutates a store.** That is the invariant, and it is narrower than
//! "read-only", which this doc used to claim: `export_capture` and
//! `export_audio` write files under `--mcp-file-root`, and `shutdown_server`
//! ends the run when `--mcp-allow-shutdown` permits it. What no tool can do is
//! alter the analysis an operator is reading while leaving them reading it.
//! Ending a session is not the hazard; silently rewriting the evidence
//! underneath someone mid-incident is. See `docs/internals/invariants.md` §7.
//!
//! # Output mode parity
//!
//! MCP is treated as a fourth output mode alongside the existing TUI, `-N`
//! CLI, and `--json` modes — not a new analysis subsystem. Tool handlers are
//! thin wrappers over functions that already exist in `output/`,
//! `sip::dialog_store`, and `rtp/`.
//!
//! # Lock discipline (Gotcha 3)
//!
//! Tool handlers MUST follow the existing `output::api` lock pattern:
//! acquire a read/write guard, snapshot/clone, drop the guard explicitly,
//! and only then `.await`. Holding a `parking_lot::RwLock` guard across
//! an `await` produces a three-way deadlock under concurrent tool calls.
//! The workspace-wide `clippy::await_holding_lock = "deny"` (Cargo.toml
//! `[workspace.lints]`) enforces this mechanically.

pub mod server;
pub mod shape;
pub mod transport;

pub use server::{CaptureContext, SipnabMcp};
