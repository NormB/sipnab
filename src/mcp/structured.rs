// SPDX-License-Identifier: MIT OR Apache-2.0

//! `structuredContent` on every tool result that has one to give (PB1).
//!
//! Before this, every payload reached a client as a JSON string inside
//! `result.content[0].text`, so every client parsed the envelope and then
//! parsed the payload out of a string inside it. MCP 2025-06-18 — the revision
//! this server negotiates — added `structuredContent` for exactly that: the
//! payload as JSON, beside the text rather than instead of it.
//!
//! # Why this is applied centrally
//!
//! [`attach`] runs once, in `SipnabMcp::call_tool`, on the way out. Fifty tools
//! build their results in fifty places, and a per-tool helper is a rule fifty
//! authors have to remember; the next tool registered would be the first one
//! without it, and nothing would say so. Applying it at the ONE point every
//! call already passes through — the same point that carries the audit line and
//! the scope check — makes coverage a property of the dispatch instead of a
//! habit.
//!
//! It also makes the two views impossible to disagree. `structuredContent` is
//! parsed FROM the text block rather than serialized a second time from the
//! same value, so there is no second serialization to drift: a client that
//! reads the text and a client that reads the structure are reading one
//! document. The cost is re-parsing a string this process just wrote, which is
//! bounded by `--mcp-max-rows` like every other response, and is the price of
//! that guarantee.
//!
//! # What does NOT get one, and why that is not a gap
//!
//! The MCP schema types `structuredContent` as a JSON **object**. A payload
//! that is a top-level array (`timeline`) or a rendered document
//! (`render_ladder`, and `get_capture_report` in its `markdown` and `text`
//! formats) has no object to publish, and wrapping one in a synthetic key
//! would put a shape in `structuredContent` that the text block does not have —
//! reintroducing the disagreement this exists to prevent. Those results are
//! left exactly as they were.

use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::Value;

/// Publish a result's JSON payload as `structuredContent`.
///
/// A no-op unless the result's FIRST content block is text holding a JSON
/// object. First rather than only: several tools append
/// [`untrusted_note`](crate::mcp::shape::untrusted_note) as a second block, and
/// the payload is still the first one.
///
/// Four cases are deliberately left untouched:
///
/// - a result that already carries `structuredContent`, because a tool that
///   set its own knows something this does not;
/// - an error result, whose content is a message rather than a payload;
/// - a payload that is not a JSON object, per the module doc; and
/// - a result with no content at all.
pub fn attach(result: &mut CallToolResult) {
    if result.structured_content.is_some() || result.is_error == Some(true) {
        return;
    }
    let Some(ContentBlock::Text(block)) = result.content.first() else {
        return;
    };
    let Some(object) = as_json_object(&block.text) else {
        return;
    };
    result.structured_content = Some(object);
}

/// `text` parsed as a JSON object, or `None` for anything else.
///
/// The leading-brace check is not an optimization for its own sake: it keeps
/// `render_ladder`-shaped results — kilobytes of drawn diagram — from being
/// handed to a JSON parser once per call to learn what their first character
/// already said.
fn as_json_object(text: &str) -> Option<Value> {
    if !text.trim_start().starts_with('{') {
        return None;
    }
    match serde_json::from_str::<Value>(text) {
        Ok(value @ Value::Object(_)) => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ContentBlock;

    /// A result whose only block is `json`.
    fn json_result(json: &str) -> CallToolResult {
        CallToolResult::success(vec![ContentBlock::text(json)])
    }

    /// The common shape: payload first, provenance note second.
    #[test]
    fn an_object_payload_is_published_as_structured_content() {
        let mut result = CallToolResult::success(vec![
            ContentBlock::text(r#"{"schema_version":1,"dialogs":3}"#),
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]);
        attach(&mut result);

        assert_eq!(
            result.structured_content,
            Some(serde_json::json!({"schema_version": 1, "dialogs": 3})),
            "the payload block is the first one; a trailing note must not hide it"
        );
    }

    /// The guarantee the module exists for: one document, two views.
    #[test]
    fn the_text_block_and_the_structured_content_are_the_same_document() {
        let mut result = json_result(r#"{"a":[1,2,{"b":null}],"c":"x"}"#);
        attach(&mut result);

        let ContentBlock::Text(block) = &result.content[0] else {
            panic!("the fixture's first block is text");
        };
        let from_text: Value = serde_json::from_str(&block.text).expect("fixture is JSON");
        assert_eq!(
            result.structured_content,
            Some(from_text),
            "structuredContent is parsed FROM the text, so they cannot differ"
        );
    }

    /// `timeline` returns a top-level array, which the MCP schema cannot carry
    /// in `structuredContent`. Wrapping it would invent a shape the text block
    /// does not have.
    #[test]
    fn an_array_payload_gets_no_structured_content() {
        let mut result = json_result(r#"[{"bucket":0,"dialogs":2}]"#);
        attach(&mut result);

        assert_eq!(
            result.structured_content, None,
            "structuredContent is typed as an object; an array has none to give"
        );
    }

    /// `render_ladder` and the non-JSON report formats return a document.
    #[test]
    fn a_rendered_document_gets_no_structured_content() {
        let mut result = json_result("alice -> bob  INVITE\nbob -> alice  200 OK\n");
        attach(&mut result);

        assert_eq!(result.structured_content, None);
    }

    /// Text that begins like an object but is not one must not become a
    /// half-parsed structure, and must not panic.
    #[test]
    fn truncated_json_gets_no_structured_content() {
        let mut result = json_result(r#"{"schema_version":1,"dialogs":"#);
        attach(&mut result);

        assert_eq!(result.structured_content, None);
    }

    /// A tool that set its own structure knows something this does not.
    #[test]
    fn a_structure_the_tool_set_is_not_overwritten() {
        let mut result = json_result(r#"{"from":"text"}"#);
        result.structured_content = Some(serde_json::json!({"from": "the tool"}));
        attach(&mut result);

        assert_eq!(
            result.structured_content,
            Some(serde_json::json!({"from": "the tool"}))
        );
    }

    /// An error result's content is a message, not a payload. Publishing it as
    /// `structuredContent` would offer it to a client validating against the
    /// tool's `outputSchema`, which describes the SUCCESS shape.
    #[test]
    fn an_error_result_is_left_alone() {
        let mut result = CallToolResult::error(vec![ContentBlock::text(r#"{"error":"nope"}"#)]);
        attach(&mut result);

        assert_eq!(result.structured_content, None);
    }

    /// A result with no content must not index past the end.
    #[test]
    fn an_empty_result_is_left_alone() {
        let mut result = CallToolResult::success(vec![]);
        attach(&mut result);

        assert_eq!(result.structured_content, None);
    }
}
