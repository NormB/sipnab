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
pub mod compare;
pub mod endpoints;
pub mod expectations;
pub mod inspect;
pub mod provenance;
