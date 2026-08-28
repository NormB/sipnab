// SPDX-License-Identifier: MIT OR Apache-2.0

//! Model Context Protocol (MCP) server mode for sipnab.
//!
//! This module exposes sipnab's analysis surface (dialogs, streams,
//! diagnostics, security findings, call reports) as MCP tools so a local AI
//! agent (Claude Code, Claude Desktop, or any MCP-capable client) can drive
//! sipnab as a debugging instrument against a live capture or pcap file.
//!
//! **No tool changes the analysis without changing its identity.** That is the
//! invariant, and it is narrower than "read-only", which this doc used to
//! claim: `export_capture` and `export_audio` write files under
//! `--mcp-file-root`, `shutdown_server` ends the run when
//! `--mcp-allow-shutdown` permits it, and `open_capture` replaces the loaded
//! capture when `--mcp-allow-open-capture` does. What no tool can do is edit
//! the analysis in place. Ending a session is not the hazard; silently
//! rewriting the evidence underneath someone mid-incident is, and a swap
//! rotates the capture instance every answer carries
//! ([`crate::provenance`]) so the rewrite cannot be silent. See
//! `docs/internals/invariants.md` §7.
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

// PRIVATE ON PURPOSE, and it is a guarantee rather than tidiness. `findings`
// holds what an LLM agent wrote through `save_findings`, and its types are
// `pub(in crate::mcp)` so nothing outside this module tree can name them. That
// is what makes "no analysis reads an annotation" a fact the compiler checks
// instead of a promise this comment makes. Publishing this module would
// dissolve it silently: everything would still build and every test would
// still pass.
mod findings;

pub mod audit;
pub mod load;
// No outer doc comment on a module whose file already carries a `//!` one. The
// two are concatenated, and rustdoc then resolves the WHOLE block in the parent
// scope: `metrics`'s own `[`MAX_TOOLS`]` stopped resolving the moment a summary
// line was added here. Every module below states its own summary in its file.
pub mod metrics;
/// Which tools a run registers: the `core` and `full` profiles.
pub mod profile;
pub mod progress;
pub mod prompts;
pub mod reference;
pub mod sampling;
pub mod server;
pub mod shape;
/// The release each MCP tool first shipped in, read from the changelog.
pub mod since;
pub mod structured;
/// Starting and stopping a uprobe TLS capture on an agent's request.
pub mod tls_capture;
pub mod tools;
pub mod transport;

pub use server::{CaptureContext, CaptureState, SipnabMcp};
