# MCP tool reference

This is the v0.4 sipnab MCP tool surface. All tools are read-only; all
responses are bounded by default (HARD_LIMIT = 1000). For the deployment
and security model, see [`mcp-overview.md`](./mcp-overview.md).

## `list_dialogs`

Returns dialog summaries from the live capture store.

**Parameters**

| Name | Type | Description |
|---|---|---|
| `filter` | string? | Diagnostic alias name (`problems`, `slow-setup`, `short-calls`, `one-way`, `nat-issues`, `codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media`) **or** a raw [filter DSL](./filter-dsl.md) expression. |
| `limit` | u32? | Max dialogs to return. Default 50, max 1000. |

**Returns** — array of `DialogSummary`:

```jsonc
[
  {
    "call_id": "abc@host",
    "state": "Completed",
    "method": "Invite",
    "from_user": "1001",
    "to_user": "1002",
    "created_at": "2026-05-02T14:02:11Z",
    "updated_at": "2026-05-02T14:03:42Z",
    "message_count": 7
  }
]
```

## `get_dialog_report`

Per-call diagnostic report for one Call-ID. Backed by
`output::generate_call_report` — same content as `--call-report`.

| Name | Type | Description |
|---|---|---|
| `call_id` | string | Required. |
| `format` | "json" \| "markdown" \| "text" | Default `"json"`. |

JSON output is a structured object; Markdown/text are returned as a
single text content. Unknown `call_id` returns invalid_params (-32602).

## `find_problems`

Convenience wrapper over `list_dialogs` that ORs each named alias.

| Name | Type | Description |
|---|---|---|
| `kinds` | string[]? | Aliases to OR. Default `["problems"]`. |
| `limit` | u32? | Default 50, max 1000. |

Unknown aliases return invalid_params (-32602) with the offending name.

## `get_dialog`

Paginated dialog with full SIP messages.

| Name | Type | Description |
|---|---|---|
| `call_id` | string | Required. |
| `max_messages` | u32? | Default 100, max 1000. |
| `cursor` | u32? | Index of first message to return. Default 0. |

Returns `{ dialog, messages, total_messages, next_cursor, complete }`.

## `get_message`

Single SIP message at a given zero-based index.

| Name | Type | Description |
|---|---|---|
| `call_id` | string | Required. |
| `index` | u32 | Required. |

Out-of-range indexes return invalid_params (-32602).

## `render_ladder`

Call-flow ladder for one Call-ID.

| Name | Type | Description |
|---|---|---|
| `call_id` | string | Required. |
| `format` | "markdown" \| "text" | Default `"markdown"`. |

Output is byte-identical to `sipnab --call-report <id> --markdown` /
`--call-report <id>` for the same dialog.

## `rtp_stats`

Per-stream RTP quality plus media diagnosis for the dialog.

| Name | Type | Description |
|---|---|---|
| `call_id` | string | Required. |

Returns `{ call_id, streams, diagnosis }` where `streams` is an array
of stream JSON objects (codec, MOS, jitter, loss%, packets, SSRC,
quality intervals) and `diagnosis` includes the standard one-way /
NAT-mismatch flags plus the Phase 8.7 asymmetry signals
(`codec_asymmetry`, `ptime_asymmetry`, `payload_type_asymmetry`,
`duration_asymmetry`, `late_media`).

## `search_messages`

Case-insensitive substring search over method, status, From, To,
User-Agent, and body across all dialogs.

| Name | Type | Description |
|---|---|---|
| `query` | string | Required, non-empty. |
| `limit` | u32? | Default 50, max 1000. |

Returns array of `{ call_id, message_index, snippet }`. Snippets are
capped at 4 KB.

## `tail_dialogs`

Incremental fetch by RFC 3339 cursor (updated_at strictly after).

| Name | Type | Description |
|---|---|---|
| `cursor` | string? | RFC 3339 timestamp. Omit on first call. |
| `limit` | u32? | Default 50, max 1000. |

Returns `{ dialogs, next_cursor, source_exhausted }`. The
`source_exhausted` flag is reserved for future capture-state
integration; in v0.4 it is always `false`.

## `security_findings`

Recent findings from active detection rules (scanner, fraud, digest,
reg-flood, etc.). Backed by the AlertEngine's bounded ring buffer
(default 1000 entries, kept in memory only).

| Name | Type | Description |
|---|---|---|
| `kinds` | string[]? | Filter to specific rule names. Empty = all kinds. |
| `since` | string? | RFC 3339; only findings strictly after. |
| `limit` | u32? | Default 50, max 1000. |

Returns array of `{ rule_name, src_ip, detail, timestamp }`. When the
AlertEngine isn't attached (no detection rules configured), returns an
empty array rather than erroring.

## `stats`

Aggregate counters across the active stores.

No parameters. Returns:

```jsonc
{
  "schema_version": 1,
  "dialog_count": 42,
  "stream_count": 18,
  "orphaned_stream_count": 2,
  "active_call_count": 5
}
```

## Error model

All tools return MCP errors via the JSON-RPC `error` object. The codes
sipnab uses:

| Code | Meaning |
|---|---|
| -32602 (`invalid_params`) | Unknown Call-ID, out-of-range index, malformed filter, unknown format, unknown alias, etc. |
| -32603 (`internal_error`) | Reserved; sipnab treats internal errors as bugs and never silently swallows them. |

Tools never panic; an unknown Call-ID always produces a structured
error rather than an empty result.

## Response bounding

| Limit | Value |
|---|---|
| Default `limit` for list-style tools | 50 |
| Maximum `limit` (clamps higher requests) | 1000 |
| Maximum SIP body / snippet bytes | 4096 |
| Maximum messages per `get_dialog` page | 1000 |

These are hard-coded to keep tool-call costs predictable for chatty
agents. Override via the per-call `limit` parameter where supported.
