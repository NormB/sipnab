// SPDX-License-Identifier: MIT OR Apache-2.0

//! One capture, three surfaces: the CLI, REST and MCP asked the same question.
//!
//! A CLI query flag is a view of the core function the REST route and the MCP
//! tool already call (see `docs/design/par5-cli-queries.md`), so its parity
//! test asks all three the same question about the same capture and compares
//! the answers. This harness starts the two servers once per test and runs
//! the CLI binary as often as the test asks:
//!
//! - the CLI: `sipnab -N -I <pcap> <args>`, to its exit;
//! - REST: `sipnab -N -I <pcap> --api 127.0.0.1:0`, settled on the whole file
//!   (see [`server::ApiServer`]);
//! - MCP: `sipnab --mcp -N -I <pcap>`, loaded to the end of the file (see
//!   [`mcp::McpSession`]).
//!
//! MCP answers carry fields REST does not, because an agent needs them and a
//! script does not: the `capture_identity` a cursor is valid against, the
//! `timing_clock` a figure was measured on, a second content block holding the
//! untrusted-content note, and capture-derived text wrapped in the
//! untrusted-data fence. [`normalize_mcp`] removes exactly those, so what is
//! left compares to the REST shape.
//!
//! Consumers include it with
//! `#[path = "support/surface_parity.rs"] mod surface_parity;`. It brings its
//! own copies of `server.rs` and `mcp.rs` as submodules, so a test needs no
//! other support module for these three surfaces.
#![allow(dead_code)]

#[path = "mcp.rs"]
pub mod mcp;
#[path = "server.rs"]
pub mod server;

use std::process::Command;

/// The error a fallible helper here returns.
pub type TestError = Box<dyn std::error::Error>;

/// The keys only an MCP answer carries, removed at every depth by
/// [`normalize_mcp`].
pub const MCP_ONLY_KEYS: &[&str] = &["capture_identity", "timing_clock"];

/// The fence MCP wraps capture-derived text in.
const FENCE_OPEN: &str = "\u{27E6}untrusted-capture-data\u{27E7}";
/// The end of [`FENCE_OPEN`]'s run.
const FENCE_CLOSE: &str = "\u{27E6}/untrusted-capture-data\u{27E7}";

/// What one CLI run printed and how it exited.
pub struct CliRun {
    /// Everything written to stdout.
    pub stdout: String,
    /// Everything written to stderr.
    pub stderr: String,
    /// The exit code; `None` when a signal ended the process.
    pub code: Option<i32>,
}

impl CliRun {
    /// The JSON object on the last non-empty stdout line: where every query
    /// flag puts its `--json` answer.
    ///
    /// # Errors
    ///
    /// When stdout is empty or its last line is not JSON; the error carries
    /// both streams.
    pub fn last_json(&self) -> Result<serde_json::Value, TestError> {
        let line = self
            .stdout
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .ok_or_else(|| format!("no stdout\nstderr:\n{}", self.stderr))?;
        serde_json::from_str(line).map_err(|e| {
            format!(
                "last stdout line is not JSON: {e}\n{line}\nstderr:\n{}",
                self.stderr
            )
            .into()
        })
    }

    /// Every stdout line parsed as JSON, for the line-per-record outputs
    /// (`--json-dialogs`).
    ///
    /// # Errors
    ///
    /// When a non-empty line is not JSON.
    pub fn json_lines(&self) -> Result<Vec<serde_json::Value>, TestError> {
        self.stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .map_err(|e| format!("stdout line is not JSON: {e}\n{l}").into())
            })
            .collect()
    }
}

/// The three surfaces over one capture.
pub struct Surfaces {
    /// The capture, as given: relative to the crate root or absolute.
    pub pcap: String,
    /// The REST server over it.
    pub rest: server::ApiServer,
    /// The MCP session over it.
    pub mcp: mcp::McpSession,
}

impl Surfaces {
    /// Start REST and MCP over `pcap` and wait until both have read all of it.
    ///
    /// # Errors
    ///
    /// When either server fails to start or to finish loading the capture.
    pub fn start(pcap: &str) -> Result<Self, TestError> {
        Ok(Self {
            pcap: pcap.to_string(),
            rest: server::ApiServer::spawn_with_pcap(pcap, &[])?,
            mcp: mcp::McpSession::start(pcap, &[])?,
        })
    }

    /// Run `sipnab -N -I <pcap> <args>` to its exit.
    ///
    /// # Errors
    ///
    /// When the binary cannot be started.
    pub fn cli(&self, args: &[&str]) -> Result<CliRun, TestError> {
        run_cli(&self.pcap, args)
    }

    /// `GET path` on the REST server, which must answer 200 with JSON.
    ///
    /// # Errors
    ///
    /// Any other status, or a body that is not JSON.
    pub fn rest_json(&self, path: &str) -> Result<serde_json::Value, TestError> {
        let resp = self.rest.get(path)?;
        if resp.status != 200 {
            return Err(format!("GET {path}: {} {}", resp.status, resp.body).into());
        }
        resp.json()
    }

    /// Call an MCP tool, which must succeed, and return its answer normalized
    /// to the REST shape by [`normalize_mcp`].
    ///
    /// # Errors
    ///
    /// A refusal, or an answer that is not JSON.
    pub fn mcp_json(
        &mut self,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TestError> {
        let msg = self.mcp.call(tool, args)?;
        Ok(normalize_mcp(mcp::ok_payload(&msg)?))
    }
}

/// Run `sipnab -N -I <pcap> <args>` to its exit, without any server.
///
/// `pcap` is taken relative to the crate root unless absolute.
///
/// # Errors
///
/// When the binary cannot be started.
pub fn run_cli(pcap: &str, args: &[&str]) -> Result<CliRun, TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", pcap])
        .args(args)
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .output()?;
    Ok(CliRun {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code(),
    })
}

/// An MCP answer with the MCP-only parts removed: every key in
/// [`MCP_ONLY_KEYS`] at any depth, and the untrusted-data fence around any
/// string. (The untrusted-content note is a second content block, which
/// [`mcp::ok_payload`] already leaves out by reading only the first.)
#[must_use]
pub fn normalize_mcp(mut v: serde_json::Value) -> serde_json::Value {
    strip(&mut v);
    v
}

/// [`normalize_mcp`]'s walk, in place.
fn strip(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for key in MCP_ONLY_KEYS {
                map.remove(*key);
            }
            for child in map.values_mut() {
                strip(child);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
        serde_json::Value::String(s) => {
            if let Some(inner) = s
                .strip_prefix(FENCE_OPEN)
                .and_then(|r| r.strip_suffix(FENCE_CLOSE))
            {
                *s = inner.to_string();
            }
        }
        _ => {}
    }
}

/// The `call_id` of each object in the array under `key`, in order.
///
/// # Errors
///
/// When `key` is not an array or an element carries no string `call_id`.
pub fn call_ids(v: &serde_json::Value, key: &str) -> Result<Vec<String>, TestError> {
    v[key]
        .as_array()
        .ok_or_else(|| format!("no `{key}` array in {v}"))?
        .iter()
        .map(|d| {
            d["call_id"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("a `{key}` entry has no call_id: {d}").into())
        })
        .collect()
}

/// The normalizer is what makes an MCP answer comparable at all, so it is
/// tested on its own: what it removes, and that it removes nothing else.
#[cfg(test)]
mod normalize_tests {
    use super::*;

    /// The MCP-only keys go at every depth, the fence comes off, and every
    /// other field and value is untouched.
    #[test]
    fn normalize_removes_exactly_the_mcp_only_parts() {
        let fenced = format!("{FENCE_OPEN}abc@host{FENCE_CLOSE}");
        let raw = serde_json::json!({
            "capture_identity": "g1",
            "total_matched": 1,
            "dialogs": [{
                "call_id": fenced,
                "timing_clock": "capture",
                "state": "Completed",
                "inner": {"capture_identity": "g1", "kept": true},
            }],
        });
        assert_eq!(
            normalize_mcp(raw),
            serde_json::json!({
                "total_matched": 1,
                "dialogs": [{
                    "call_id": "abc@host",
                    "state": "Completed",
                    "inner": {"kept": true},
                }],
            })
        );
    }

    /// A string that only opens the fence is not unwrapped: a half-fenced
    /// value is a defect for the test to see, not to hide.
    #[test]
    fn a_half_fenced_string_is_left_alone() {
        let half = format!("{FENCE_OPEN}abc");
        assert_eq!(
            normalize_mcp(serde_json::json!({ "s": half.clone() })),
            serde_json::json!({ "s": half })
        );
    }
}
