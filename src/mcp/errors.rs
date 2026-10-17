// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structured `data` on the JSON-RPC errors this server sends.
//!
//! A JSON-RPC error carries a `code`, a `message`, and an optional `data`
//! member. Every refusal on this server used to send `data: null`, so a client
//! that wanted to act on an error (re-ask with a valid enum value, back off
//! before retrying, name the argument it got wrong) had to parse the prose of
//! `message`. The prose is written for a person and changes when its wording
//! improves.
//!
//! This module is the ONE place an `invalid_params` (-32602) error or an
//! at-capacity (-32000) error is built, and every such error carries one shape:
//!
//! ```json
//! {"reason": "invalid_choice", "param": "group_by", "valid_values": ["state", "..."]}
//! ```
//!
//! - `reason` — always present. A stable snake_case code from [`Reason`].
//! - `param` — the name of the argument that was refused, when one argument
//!   was the cause.
//! - `valid_values` — the allowed set, when the refusal is "not one of these".
//! - `retry_after_ms` — milliseconds until a retry can succeed, on an
//!   at-capacity refusal when the server knows that number.
//!
//! The `message` strings are unchanged. Clients and tests match on them, and
//! `data` is an addition beside them, not a replacement.
//!
//! The gate `no_invalid_params_site_is_built_outside_this_module` scans the
//! source tree so that a new refusal built directly with
//! `rmcp::ErrorData::invalid_params(.., None)` fails the build's tests rather
//! than shipping an error with no `data`.

use std::borrow::Cow;

use rmcp::ErrorData;
use rmcp::model::ErrorCode;
use serde_json::{Map, Value};

/// JSON-RPC error code for a call refused because the server is busy.
///
/// In the server-error range (-32000..=-32099) that JSON-RPC 2.0 reserves for
/// application-defined conditions: not a malformed request (that is
/// `INVALID_PARAMS`) and not a fault (`INTERNAL_ERROR`), but a transient limit
/// the caller should back off from and retry.
pub const AT_CAPACITY_CODE: i32 = -32000;

/// Why a request was refused: the `reason` member of the error's `data`.
///
/// The set is closed and each code is stable. A client may branch on it; the
/// wording of `message` is not a contract and this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// A named thing (a Call-ID, a rule, a finding, a prompt, a job) is not
    /// held by this server.
    NotFound,
    /// The value is not in the allowed set; `valid_values` lists the set.
    InvalidChoice,
    /// The value is malformed, empty, or outside its range.
    InvalidValue,
    /// A filter expression did not compile.
    InvalidFilter,
    /// A required argument, or one of a set of alternatives, was not given.
    MissingParam,
    /// Two arguments were given that may not be given together.
    ConflictingParams,
    /// The operator did not enable this on the server (an opt-in flag such as
    /// `--mcp-allow-shutdown`, `--mcp-file-root`, or `--allow-action`).
    NotEnabled,
    /// A filename or path was refused: not a bare name, outside the file
    /// root, or one of the capture's own inputs.
    PathRefused,
    /// The name asked for already exists, and this server does not overwrite.
    AlreadyExists,
    /// The server's current state refuses the request: a capture is still
    /// loading, a live capture is running, or the source has not finished.
    /// The same request can succeed later.
    NotReady,
    /// The request asks for more than a ceiling this server enforces.
    LimitExceeded,
    /// This build, platform, or process privilege cannot do this.
    Unsupported,
    /// The caller's token scope does not cover this tool.
    ScopeRefused,
    /// The person asked to confirm the request declined it, or no one could
    /// be asked.
    Declined,
    /// The named call holds nothing of the kind asked for (no messages, no
    /// RTP streams, no request to replay).
    NoData,
    /// The tool name is not registered on this server; `valid_values` lists
    /// the registered names.
    UnknownTool,
    /// An argument this server refuses whatever its value (a password-like
    /// argument name), or an `invalid_params` refusal the MCP SDK built
    /// without saying which argument.
    InvalidArguments,
    /// Too many tool calls are running at once (`--mcp-max-concurrent`).
    AtCapacity,
    /// This peer has used its per-second allowance
    /// (`--mcp-rate-limit-per-peer`).
    RateLimited,
}

impl Reason {
    /// Every reason, for the documentation gate.
    pub const ALL: &'static [Reason] = &[
        Reason::NotFound,
        Reason::InvalidChoice,
        Reason::InvalidValue,
        Reason::InvalidFilter,
        Reason::MissingParam,
        Reason::ConflictingParams,
        Reason::NotEnabled,
        Reason::PathRefused,
        Reason::AlreadyExists,
        Reason::NotReady,
        Reason::LimitExceeded,
        Reason::Unsupported,
        Reason::ScopeRefused,
        Reason::Declined,
        Reason::NoData,
        Reason::UnknownTool,
        Reason::InvalidArguments,
        Reason::AtCapacity,
        Reason::RateLimited,
    ];

    /// The stable snake_case code a client reads in `data.reason`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Reason::NotFound => "not_found",
            Reason::InvalidChoice => "invalid_choice",
            Reason::InvalidValue => "invalid_value",
            Reason::InvalidFilter => "invalid_filter",
            Reason::MissingParam => "missing_param",
            Reason::ConflictingParams => "conflicting_params",
            Reason::NotEnabled => "not_enabled",
            Reason::PathRefused => "path_refused",
            Reason::AlreadyExists => "already_exists",
            Reason::NotReady => "not_ready",
            Reason::LimitExceeded => "limit_exceeded",
            Reason::Unsupported => "unsupported",
            Reason::ScopeRefused => "scope_refused",
            Reason::Declined => "declined",
            Reason::NoData => "no_data",
            Reason::UnknownTool => "unknown_tool",
            Reason::InvalidArguments => "invalid_arguments",
            Reason::AtCapacity => "at_capacity",
            Reason::RateLimited => "rate_limited",
        }
    }
}

/// The `data` member, built in one place so every error has one shape.
///
/// Absent members are omitted rather than sent as `null`, so a client tests
/// for a key's presence and never has to tell "absent" from "null".
fn data(
    reason: Reason,
    param: Option<&str>,
    valid_values: Option<Vec<String>>,
    retry_after_ms: Option<u64>,
) -> Value {
    let mut map = Map::new();
    map.insert("reason".into(), Value::String(reason.code().to_string()));
    if let Some(param) = param {
        map.insert("param".into(), Value::String(param.to_string()));
    }
    if let Some(values) = valid_values {
        map.insert(
            "valid_values".into(),
            Value::Array(values.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(ms) = retry_after_ms {
        map.insert("retry_after_ms".into(), Value::from(ms));
    }
    Value::Object(map)
}

/// An `invalid_params` (-32602) error that no single argument caused.
#[must_use]
pub fn refuse(reason: Reason, message: impl Into<Cow<'static, str>>) -> ErrorData {
    ErrorData::invalid_params(message, Some(data(reason, None, None, None)))
}

/// An `invalid_params` (-32602) error caused by the argument named `param`.
#[must_use]
pub fn refuse_param(
    reason: Reason,
    param: &str,
    message: impl Into<Cow<'static, str>>,
) -> ErrorData {
    ErrorData::invalid_params(message, Some(data(reason, Some(param), None, None)))
}

/// An `invalid_params` (-32602) error for a value outside an allowed set,
/// carrying the set as `valid_values`.
#[must_use]
pub fn refuse_choice<I, S>(
    param: &str,
    valid_values: I,
    message: impl Into<Cow<'static, str>>,
) -> ErrorData
where
    I: IntoIterator<Item = S>,
    S: ToString,
{
    let values = valid_values.into_iter().map(|v| v.to_string()).collect();
    ErrorData::invalid_params(
        message,
        Some(data(Reason::InvalidChoice, Some(param), Some(values), None)),
    )
}

/// An at-capacity (-32000) refusal.
///
/// `retry_after` is how long until a retry can succeed, when the server knows
/// it. It is rounded UP to whole milliseconds and never sent as zero: a client
/// told "retry after 0 ms" would retry inside the window that refused it.
#[must_use]
pub fn at_capacity(
    reason: Reason,
    message: impl Into<Cow<'static, str>>,
    retry_after: Option<std::time::Duration>,
) -> ErrorData {
    let ms = retry_after.map(|d| {
        let micros = d.as_micros();
        u64::try_from(micros.div_ceil(1000))
            .unwrap_or(u64::MAX)
            .max(1)
    });
    ErrorData::new(
        ErrorCode(AT_CAPACITY_CODE),
        message,
        Some(data(reason, None, None, ms)),
    )
}

/// Give `data` to an `invalid_params` error the MCP SDK built itself.
///
/// An unknown tool name (`"tool not found"`) is refused inside `rmcp`, before
/// any sipnab code runs, so `call_tool` passes every refusal through this on
/// the way out. The message is left exactly as the SDK wrote it. Any other
/// SDK-built `invalid_params` error gets `invalid_arguments`, so no
/// `invalid_params` error leaves this server without a `reason`.
///
/// Arguments that do not deserialize do not arrive here: `rmcp` answers those
/// with a tool result carrying `isError: true`, which `call_tool` turns into
/// an error with [`sdk_argument_refusal`] first.
///
/// An error that already has `data`, or is not `invalid_params`, is returned
/// unchanged.
///
/// # Arguments
///
/// * `error` — the refusal, as dispatch returned it.
/// * `tool_names` — the registered tool names, read only when the refusal is
///   an unknown tool.
#[must_use]
pub fn describe_sdk_refusal(
    mut error: ErrorData,
    tool_names: impl FnOnce() -> Vec<String>,
) -> ErrorData {
    if error.code != ErrorCode::INVALID_PARAMS || error.data.is_some() {
        return error;
    }
    error.data = Some(if error.message == "tool not found" {
        data(Reason::UnknownTool, Some("name"), Some(tool_names()), None)
    } else {
        data(Reason::InvalidArguments, None, None, None)
    });
    error
}

/// The text `rmcp` puts in the tool result it returns for arguments that do
/// not match a tool's input schema: a wrong JSON type, a missing required key.
const SDK_ARGUMENT_PREFIX: &str = "failed to deserialize parameters: ";

/// The `invalid_params` error for a tool result `rmcp` built because the
/// arguments did not deserialize, or `None` for any other result.
///
/// The SDK answers those arguments with `isError: true`, where the MCP
/// specification lists invalid arguments among protocol errors and where every
/// other refusal of this server is an `invalid_params` error with a `reason`.
/// The message is kept as the SDK wrote it, because it names the field.
#[must_use]
pub fn sdk_argument_refusal(result: &rmcp::model::CallToolResult) -> Option<ErrorData> {
    if result.is_error != Some(true) {
        return None;
    }
    let [only] = result.content.as_slice() else {
        return None;
    };
    let text = &only.as_text()?.text;
    text.starts_with(SDK_ARGUMENT_PREFIX).then(|| {
        ErrorData::invalid_params(
            text.clone(),
            Some(data(Reason::InvalidArguments, None, None, None)),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The `data` member of `e`, or an error naming what was missing.
    fn data_of(e: &ErrorData) -> Result<&Value, TestError> {
        e.data
            .as_ref()
            .ok_or_else(|| format!("no data on {e:?}").into())
    }

    /// A tool result holding one text block, marked as an error or not.
    fn tool_result(text: &str, is_error: bool) -> rmcp::model::CallToolResult {
        let content = vec![rmcp::model::ContentBlock::text(text)];
        if is_error {
            rmcp::model::CallToolResult::error(content)
        } else {
            rmcp::model::CallToolResult::success(content)
        }
    }

    /// The SDK's answer to arguments that do not deserialize becomes an
    /// `invalid_params` error with `reason: invalid_arguments` and its text.
    #[test]
    fn the_sdk_argument_result_becomes_an_invalid_params_error() -> Result<(), TestError> {
        let text = "failed to deserialize parameters: missing field `call_id`";
        let e = sdk_argument_refusal(&tool_result(text, true)).ok_or("must convert")?;
        assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(e.message, text);
        assert_eq!(
            *data_of(&e)?,
            serde_json::json!({"reason": "invalid_arguments"})
        );
        Ok(())
    }

    /// A tool's own refusal, marked `isError` with its JSON body, is left as
    /// the tool wrote it.
    #[test]
    fn a_tool_s_own_error_result_is_left_alone() {
        let body = r#"{"refused":"not_enabled"}"#;
        assert!(sdk_argument_refusal(&tool_result(body, true)).is_none());
    }

    /// A successful result is never converted, whatever its text says.
    #[test]
    fn a_successful_result_is_left_alone() {
        let text = "failed to deserialize parameters: but this call succeeded";
        assert!(sdk_argument_refusal(&tool_result(text, false)).is_none());
    }

    #[test]
    fn a_refusal_carries_its_reason_and_keeps_its_message() -> Result<(), TestError> {
        let e = refuse(Reason::NotEnabled, "file tools are disabled");
        assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(e.message, "file tools are disabled");
        assert_eq!(*data_of(&e)?, serde_json::json!({"reason": "not_enabled"}));
        Ok(())
    }

    #[test]
    fn a_param_refusal_names_the_param() -> Result<(), TestError> {
        let e = refuse_param(Reason::NotFound, "call_id", "call_id 'x' not found");
        assert_eq!(
            *data_of(&e)?,
            serde_json::json!({"reason": "not_found", "param": "call_id"})
        );
        Ok(())
    }

    #[test]
    fn a_choice_refusal_lists_the_valid_values() -> Result<(), TestError> {
        let e = refuse_choice("group_by", ["state", "method"], "cannot group by 'x'");
        assert_eq!(
            *data_of(&e)?,
            serde_json::json!({
                "reason": "invalid_choice",
                "param": "group_by",
                "valid_values": ["state", "method"]
            })
        );
        Ok(())
    }

    #[test]
    fn at_capacity_rounds_retry_after_up_and_never_to_zero() -> Result<(), TestError> {
        let e = at_capacity(
            Reason::RateLimited,
            "retry shortly",
            Some(std::time::Duration::from_micros(1500)),
        );
        assert_eq!(e.code, ErrorCode(AT_CAPACITY_CODE));
        assert_eq!(data_of(&e)?["retry_after_ms"], serde_json::json!(2));
        let zero = at_capacity(Reason::RateLimited, "x", Some(std::time::Duration::ZERO));
        assert_eq!(data_of(&zero)?["retry_after_ms"], serde_json::json!(1));
        let unknown = at_capacity(Reason::AtCapacity, "x", None);
        assert_eq!(
            *data_of(&unknown)?,
            serde_json::json!({"reason": "at_capacity"})
        );
        Ok(())
    }

    #[test]
    fn every_reason_code_is_distinct_snake_case() -> Result<(), TestError> {
        let mut seen = std::collections::BTreeSet::new();
        for r in Reason::ALL {
            let code = r.code();
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{code} is not snake_case"
            );
            assert!(seen.insert(code), "{code} is used twice");
        }
        Ok(())
    }

    #[test]
    fn an_unknown_tool_lists_the_registered_names() -> Result<(), TestError> {
        let e = describe_sdk_refusal(ErrorData::invalid_params("tool not found", None), || {
            vec!["capture_status".into(), "list_dialogs".into()]
        });
        assert_eq!(e.message, "tool not found");
        assert_eq!(
            *data_of(&e)?,
            serde_json::json!({
                "reason": "unknown_tool",
                "param": "name",
                "valid_values": ["capture_status", "list_dialogs"]
            })
        );
        Ok(())
    }

    #[test]
    fn any_other_sdk_refusal_is_invalid_arguments() -> Result<(), TestError> {
        let message = "missing extension sipnab::Thing";
        let e = describe_sdk_refusal(ErrorData::invalid_params(message, None), Vec::new);
        assert_eq!(
            *data_of(&e)?,
            serde_json::json!({"reason": "invalid_arguments"})
        );
        assert_eq!(e.message, message, "the SDK's message is kept");
        Ok(())
    }

    #[test]
    fn an_error_that_already_has_data_or_another_code_is_left_alone() -> Result<(), TestError> {
        let mine = refuse_param(Reason::NotFound, "call_id", "x");
        let kept = describe_sdk_refusal(mine.clone(), Vec::new);
        assert_eq!(kept, mine);
        let internal = ErrorData::internal_error("boom", None);
        assert_eq!(describe_sdk_refusal(internal.clone(), Vec::new), internal);
        Ok(())
    }

    /// Every reason code is in the error table of the MCP tool reference, so
    /// a client author can read what each one means.
    #[test]
    fn every_reason_code_is_documented() -> Result<(), TestError> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let doc = std::fs::read_to_string(root.join("docs/mcp-tools.md"))?;
        let missing: Vec<&str> = Reason::ALL
            .iter()
            .map(|r| r.code())
            .filter(|code| !doc.contains(&format!("| `{code}` |")))
            .collect();
        assert!(
            missing.is_empty(),
            "reason codes with no row in docs/mcp-tools.md: {missing:?}"
        );
        Ok(())
    }

    /// Every line of `src` that builds an `invalid_params` or a raw
    /// `ErrorData::new` error, as `path:line`.
    ///
    /// Comment lines are skipped, so prose that names the constructor is not
    /// a site.
    fn direct_sites(path: &str, src: &str) -> Vec<String> {
        src.lines()
            .enumerate()
            .filter(|(_, line)| {
                let code = line.trim_start();
                !code.starts_with("//")
                    && (code.contains("ErrorData::invalid_params(")
                        || code.contains("ErrorData::new("))
            })
            .map(|(i, _)| format!("{path}:{}", i + 1))
            .collect()
    }

    /// Every `.rs` file under `dir`, recursively.
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                rust_files(&path, out)?;
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
        Ok(())
    }

    /// No refusal is built outside this module, so none can ship without
    /// `data`.
    ///
    /// A source scan, because the property is about construction sites: an
    /// on-the-wire test can only reach the refusals some fixture provokes, and
    /// the next one added would be the first one nobody provokes.
    #[test]
    fn no_invalid_params_site_is_built_outside_this_module() -> Result<(), TestError> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_files(&root.join("src"), &mut files)?;
        assert!(files.len() > 50, "only {} source files found", files.len());
        let me = root.join("src/mcp/errors.rs");
        let mut offenders = Vec::new();
        for file in files.iter().filter(|f| **f != me) {
            let src = std::fs::read_to_string(file)?;
            let rel = file
                .strip_prefix(root)
                .unwrap_or(file)
                .display()
                .to_string();
            offenders.extend(direct_sites(&rel, &src));
        }
        assert!(
            offenders.is_empty(),
            "{} error(s) built directly rather than through crate::mcp::errors, \
             so they carry no `data`:\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
        Ok(())
    }

    /// The string literals in Rust source, as `(line, content)`, with escapes
    /// left as written. Comments, raw strings, char and byte literals and
    /// lifetimes are skipped, so a quote inside one is not read as a string.
    fn string_literals(src: &str) -> Vec<(usize, String)> {
        let b = src.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        // Lines are counted as the walk advances, so a large file stays linear.
        let (mut line, mut counted) = (1usize, 0usize);
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let rest = &src[i..];
            if rest.starts_with("//") {
                i += rest.find('\n').unwrap_or(rest.len());
            } else if rest.starts_with("/*") {
                i += rest.find("*/").map_or(rest.len(), |j| j + 2);
            } else if (rest.starts_with('r') || rest.starts_with("br"))
                && (i == 0 || !ident(b[i - 1]))
                && {
                    let r = rest.trim_start_matches('b').trim_start_matches('r');
                    r.trim_start_matches('#').starts_with('"')
                }
            {
                let after_r = rest.find('r').unwrap_or(0) + 1;
                let hashes = rest[after_r..].bytes().take_while(|&c| c == b'#').count();
                let close = format!("\"{}", "#".repeat(hashes));
                let body = after_r + hashes + 1;
                i += rest[body..]
                    .find(&close)
                    .map_or(rest.len(), |j| body + j + close.len());
            } else if b[i] == b'\'' {
                if b.get(i + 1) == Some(&b'\\') {
                    i += src[i + 3..].find('\'').map_or(rest.len(), |j| j + 4);
                } else {
                    let len = rest[1..].chars().next().map_or(0, char::len_utf8);
                    i += if b.get(i + 1 + len) == Some(&b'\'') {
                        len + 2
                    } else {
                        1
                    };
                }
            } else if b[i] == b'"' {
                // Any prefix (`b"`, `c"`) is an identifier character the
                // walk has already stepped over.
                let start = i;
                let mut text = Vec::new();
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        text.extend_from_slice(&b[i..i + 2]);
                        i += 2;
                    } else {
                        text.push(b[i]);
                        i += 1;
                    }
                }
                i += 1;
                line += b[counted..start].iter().filter(|&&c| c == b'\n').count();
                counted = start;
                out.push((line, String::from_utf8_lossy(&text).into_owned()));
            } else {
                i += rest.chars().next().map_or(1, char::len_utf8);
            }
        }
        out
    }

    /// Whether a literal carries a line break that lost its `\` continuation.
    ///
    /// Two shapes reach the wire as a run of spaces in a message:
    ///
    /// - JOINED: the break was removed and the next line's indentation kept,
    ///   so a one-line literal holds a run of 12 or more spaces after a word
    ///   (`"... and 0                      bounds nothing"`, MCP-A5). Column
    ///   alignment follows a `:` or `|`, or sits in a literal with line
    ///   breaks, and is not matched.
    /// - UNJOINED: the break is still there with no `\`, so the literal holds
    ///   a newline and then the indentation. Checked for `src/` only, where no
    ///   literal is a YAML or text fixture.
    fn lost_continuation(content: &str, check_unjoined: bool) -> bool {
        let b = content.as_bytes();
        let run_after = |at: usize| b[at..].iter().take_while(|&&c| c == b' ').count();
        let multi_line = content.contains("\\n") || content.contains('\n');
        let joined = !multi_line
            && (1..b.len()).any(|i| {
                let prev = b[i - 1];
                b[i] == b' '
                    && !prev.is_ascii_whitespace()
                    && prev != b':'
                    && prev != b'|'
                    && run_after(i) >= 12
                    && b.get(i + run_after(i)).is_some()
            });
        let unjoined = check_unjoined
            && (1..b.len()).any(|i| {
                b[i] == b'\n'
                    && b[i - 1] != b'\\'
                    && !b[i - 1].is_ascii_whitespace()
                    && run_after(i + 1) >= 8
                    && b.get(i + 1 + run_after(i + 1))
                        .is_some_and(|c| !c.is_ascii_whitespace())
            });
        joined || unjoined
    }

    /// MCP-A5: `get_dialog {"max_messages": 0}` answered "... and 0" then 22
    /// spaces then "bounds nothing", because a string literal's line break
    /// had lost its `\`. Twelve other literals in `src/` and two in `tests/`
    /// carried the same break. No literal in either tree may carry one.
    ///
    /// A source scan, because an on-the-wire test reaches only the messages
    /// some fixture provokes, and the next literal broken this way would be
    /// one that no fixture provokes.
    #[test]
    fn no_string_literal_lost_its_line_continuation() -> Result<(), TestError> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        for tree in ["src", "tests"] {
            let mut files = Vec::new();
            rust_files(&root.join(tree), &mut files)?;
            for file in &files {
                let src = std::fs::read_to_string(file)?;
                let rel = file
                    .strip_prefix(root)
                    .unwrap_or(file)
                    .display()
                    .to_string();
                for (line, content) in string_literals(&src) {
                    scanned += 1;
                    if lost_continuation(&content, tree == "src") {
                        offenders.push(format!("{rel}:{line}"));
                    }
                }
            }
        }
        assert!(scanned > 10_000, "only {scanned} literals found");
        assert!(
            offenders.is_empty(),
            "{} string literal(s) hold a line break without its `\\` \
             continuation, so the message carries a run of spaces:\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
        Ok(())
    }

    /// The literal scan finds both broken shapes and passes the aligned,
    /// continued, commented, raw and char forms that look like them.
    #[test]
    fn the_literal_scan_finds_a_lost_continuation_and_passes_the_rest() -> Result<(), TestError> {
        let gap = " ".repeat(20);
        let q = '"';
        let src = format!(
            "fn f() {{\n    let c = '{q}'; let l: &'static str = {q}ok{q};\n    \
             // {q}in a comment and 0{gap}bounds{q}\n    \
             let r = r#{q}raw 0{gap}bounds{q}#;\n    \
             let a = {q}Time:{gap}x{q};\n    \
             let t = {q}row\\n{gap}x{q};\n    \
             let k = {q}continued \\\n{gap}fine{q};\n    \
             let z = c{q}cstr{q}; let y = b{q}bytes{q};\n    \
             let j = {q}and 0{gap}bounds{q};\n    \
             let u = {q}and 0\n{gap}bounds{q};\n}}\n"
        );
        let found: Vec<usize> = string_literals(&src)
            .into_iter()
            .filter(|(_, c)| lost_continuation(c, true))
            .map(|(l, _)| l)
            .collect();
        assert_eq!(found, vec![10, 11], "{src}");
        let unjoined_only: Vec<usize> = string_literals(&src)
            .into_iter()
            .filter(|(_, c)| lost_continuation(c, false))
            .map(|(l, _)| l)
            .collect();
        assert_eq!(unjoined_only, vec![10], "a tests/ fixture may break lines");
        Ok(())
    }

    /// The scan finds a planted site and skips a comment naming one.
    #[test]
    fn the_site_scan_finds_a_planted_site_and_skips_prose() -> Result<(), TestError> {
        let planted = "fn f() {\n    // ErrorData::invalid_params( in prose\n    \
                       Err(rmcp::ErrorData::invalid_params(\"x\", None))\n    \
                       rmcp::ErrorData::new(code, \"y\", None)\n}\n";
        assert_eq!(
            direct_sites("p.rs", planted),
            vec!["p.rs:3".to_string(), "p.rs:4".to_string()]
        );
        Ok(())
    }
}
