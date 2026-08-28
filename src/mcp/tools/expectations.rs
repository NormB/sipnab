//! PLACEHOLDER -- see the module doc added with the first tool in this group.

use crate::mcp::server::SipnabMcp;
use rmcp::tool_router;

#[tool_router(router = expectations_router, vis = "pub(crate)")]
impl SipnabMcp {}
