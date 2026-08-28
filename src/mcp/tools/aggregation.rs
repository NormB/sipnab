//! Aggregation tools: questions about a SET of dialogs rather than one.

use crate::mcp::server::SipnabMcp;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// Parameters for `timeline`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TimelineParams {
    /// Bucket width in seconds. Defaults to 60.
    #[serde(default)]
    pub bucket_seconds: Option<u64>,
}

#[tool_router(router = aggregation_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Call volume over time, in fixed-width buckets.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `bucket_seconds` is zero: a zero-width
    /// bucket has no meaning and dividing by it would panic rather than answer.
    #[tool(
        name = "timeline",
        description = "Call volume over time in fixed-width buckets. Returns one \
                       row per bucket with the count of dialogs that started in \
                       it, so a spike or a gap is visible without reading every \
                       dialog.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn timeline(
        &self,
        Parameters(params): Parameters<TimelineParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let width = params.bucket_seconds.unwrap_or(60);
        if width == 0 {
            return Err(rmcp::ErrorData::invalid_params(
                "bucket_seconds must be greater than zero: a zero-width bucket \
                 describes no interval, and every dialog would fall into all of \
                 them at once",
                None,
            ));
        }
        let rows = self.timeline_buckets(width);
        Ok(CallToolResult::success(vec![ContentBlock::json(rows)?]))
    }
}
