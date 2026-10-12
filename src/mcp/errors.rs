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
/// Arguments that do not deserialize do NOT arrive here: `rmcp` answers those
/// with a tool result carrying `isError: true`, not a JSON-RPC error.
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
