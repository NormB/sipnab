// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `fleet_inventory`: what this sipnab process is, for a fleet controller.
//!
//! [`crate::output::inventory::Inventory`], built by the one function
//! `GET /v1/inventory` calls, so the two surfaces cannot describe one process
//! differently. It holds versions, digests and counters and no byte of any
//! packet, so, like `runtime_stats`, it goes out without the untrusted content
//! note.

use crate::mcp::server::SipnabMcp;
use rmcp::handler::server::tool::schema_for_output;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_router};

#[tool_router(router = inventory_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// This process's fleet inventory record.
    ///
    /// # Errors
    ///
    /// Only if the record fails to serialize, which a struct of strings and
    /// integers cannot.
    #[tool(
        name = "fleet_inventory",
        description = "Returns what this sipnab process is, for managing many \
                       instances as one fleet: build, SHA-256 of the running \
                       binary, signature state (always unverified), \
                       configuration digests (never a value), uid and \
                       privilege drop, uptime, counters and HEP sender \
                       addresses. Every field is the process's own claim. \
                       Same document as GET /v1/inventory.",
        output_schema = schema_for_output::<crate::output::inventory::Inventory>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn fleet_inventory(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        // The builder `GET /v1/inventory` calls, over this server's meter,
        // interfaces and start time. Hashing the binary reads a file, so it
        // runs off the async workers.
        let meter = self.capture_meter.clone();
        let interfaces = self.capture_interfaces.clone();
        let uptime = self.started_at.elapsed().as_secs();
        let record = tokio::task::spawn_blocking(move || {
            crate::output::inventory::current(meter.as_ref(), &interfaces, uptime)
        })
        .await
        .map_err(|e| {
            rmcp::ErrorData::internal_error(format!("the inventory did not build: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::json(record)?]))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::RwLock;

    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    type TestError = Box<dyn std::error::Error>;

    /// Registered, and annotated read-only, so a `read`-scoped MCP token
    /// reaches it.
    #[test]
    fn fleet_inventory_is_registered_and_annotated_read_only() -> Result<(), TestError> {
        let router = SipnabMcp::inventory_router();
        let tool = router
            .get("fleet_inventory")
            .ok_or("fleet_inventory must be registered")?;
        let annotations = tool.annotations.as_ref().ok_or("annotations")?;
        assert_eq!(
            annotations.read_only_hint,
            Some(true),
            "a read token reaches only tools annotated read-only"
        );
        Ok(())
    }

    /// The tool answers with the shared record, for this server's interfaces.
    #[tokio::test]
    async fn fleet_inventory_returns_the_shared_record() -> Result<(), TestError> {
        let srv = SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(100, false))),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
        .with_capture_interfaces(vec!["lo".to_string()]);
        let result = srv
            .fleet_inventory()
            .await
            .map_err(|e| format!("the tool answers: {e:?}"))?;
        let text = result
            .content
            .iter()
            .find_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .ok_or("a JSON block")?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(v["schema_version"], 1, "{v}");
        assert_eq!(
            v["build"]["version_line"],
            crate::cli::build_version(),
            "{v}"
        );
        assert_eq!(v["interfaces"][0]["name"], "lo", "{v}");
        Ok(())
    }
}
