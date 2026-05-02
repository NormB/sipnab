//! Model Context Protocol (MCP) server mode for sipnab — Phase 8.1.
//!
//! This module exposes sipnab's read-only analysis surface (dialogs, streams,
//! diagnostics, security findings, call reports) as MCP tools so a local AI
//! agent (Claude Code, Claude Desktop, or any MCP-capable client) can drive
//! sipnab as a debugging instrument against a live capture or pcap file.
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
//! The module-level `#![deny(clippy::await_holding_lock)]` enforces this
//! mechanically.

#![deny(clippy::await_holding_lock)]

pub mod server;
pub mod shape;
pub mod transport;

pub use server::SipnabMcp;
