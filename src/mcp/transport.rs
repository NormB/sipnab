//! Phase 8.1 — stdio transport for the MCP server.
//!
//! Stdio mode wires the JSON-RPC stream over `stdin`/`stdout`. Because
//! `stdout` is the protocol wire, **all log output must go to stderr**.
//! Phase 8.0b ensured this by routing tracing-subscriber to stderr; this
//! module documents the invariant and the entry point.

use super::server::SipnabMcp;
use rmcp::ServiceExt;

/// Run an MCP server over stdio. Returns when the client disconnects.
///
/// # Stdio invariant (Gotcha 1)
///
/// `stdout` is the JSON-RPC wire. Any `println!`/`eprintln!` or stray
/// non-tracing logging in this process would corrupt the protocol stream.
/// Phase 8.0b's tracing-subscriber initializer (`with_writer(stderr)`) is
/// the project-wide guarantee; the `tests/parse_path_test.rs` JSON
/// determinism check picks up regressions.
pub async fn serve_stdio(server: SipnabMcp) -> anyhow::Result<()> {
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let service = server.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}
