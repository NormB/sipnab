//! Tool groups that live outside [`crate::mcp::server`].
//!
//! `server.rs` is 13k lines and every tool the server has ever grown was added
//! to one `impl` block in it. That worked while tools arrived one at a time; it
//! stops working when a batch of them lands together, because every addition
//! edits the same region of the same file.
//!
//! `rmcp`'s [`ToolRouter`](rmcp::handler::server::router::tool::ToolRouter)
//! composes with `+`, so a group of tools can own its own file and its own
//! router and be merged at construction. The only shared line is the merge
//! itself, in `SipnabMcp::new`.
//!
//! A group is a THEME, not a dumping ground: tools that answer the same kind of
//! question, so a reader looking for "how does the server aggregate things"
//! opens one file rather than searching a large one.

pub mod aggregation;
pub mod await_condition;
pub mod compare;
pub mod endpoints;
pub mod expectations;
pub mod inspect;
pub mod provenance;
pub mod relay;
pub mod tfps;
// Only where the exporter exists. A tool in `tools/list` that can never run
// is worse than an absent one: an agent plans around it, calls it, and gets
// an error no argument it could have chosen would have avoided. What a build
// omits is `server_capabilities`' question to answer, and it names `vcon`.
// Both, and stated as both: the file is an MCP tool (it imports `rmcp`, which
// `mcp` supplies) that exports vCon containers (which needs `vcon`). The `mcp`
// half is implied by this tree already, and saying it anyway is what lets
// `scripts/check-feature-deps.py` see that `vcon` alone never compiles this
// file and so owes it nothing.
#[cfg(all(feature = "mcp", feature = "vcon"))]
pub mod vcon;
