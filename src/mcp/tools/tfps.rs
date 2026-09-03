// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the TFPS peer knows, and the two things an operator may ask it to do.
//!
//! # Why these exist
//!
//! sipnab publishes evidence and never bans anything. The toll-fraud
//! prevention system (TFPS) on the same host is the thing that condemns
//! sources, and until now an agent reading sipnab's findings could not see
//! what TFPS had done with them -- which sources are blocked right now, what
//! the enforcement has dropped, and what the verdict log says -- without a
//! shell on the box. Six tools close that: four that read, and two that relay
//! an OPERATOR's decision to ban or release a source.
//!
//! # The line this file does not cross
//!
//! `tfps_ban` is an operator action carried through sipnab. It is not sipnab
//! deciding: the address and the duration are the caller's, TFPS refuses its
//! host's own addresses and anything in its `ignoreip`, and the answer is
//! reported as given, refusal included. The automated path -- sipnab's own
//! findings reaching TFPS as they happen -- is a separate channel, and it
//! never comes through here.
//!
//! # TFPS is optional
//!
//! Every tool answers `installed: false` with a reason when there is no
//! `tfps_ctl` to ask. That is a result rather than an error, because it is the
//! ordinary case: a machine without TFPS runs sipnab unchanged, and an agent
//! that calls `tfps_status` there learns something true. See
//! [`crate::security::tfps`] for how the executable is found and why nothing
//! is probed at startup.
//!
//! # What is fenced
//!
//! `detail` on a ban or a label, and `last_request` on a drop, are the
//! sender's own text -- a `User-Agent` a scanner chose, a request line it
//! sent -- and arrive fenced the way `security_findings` fences its `detail`.
//! Addresses, rules, timestamps and TFPS's own words are returned verbatim.

use std::net::IpAddr;

use crate::mcp::server::SipnabMcp;
use crate::security::tfps::{
    TfpsActionAnswer, TfpsBanned, TfpsDropped, TfpsError, TfpsLabel, TfpsListAnswer, TfpsLocator,
    TfpsStatusAnswer,
};
use rmcp::handler::server::tool::schema_for_output;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::Deserialize;

/// Arguments for `tfps_labels`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TfpsLabelsParams {
    /// Rows TFPS returns, newest first. `0` or absent asks for the whole log,
    /// which is TFPS's own default for the export; the server's row cap
    /// (`--mcp-max-rows`) then bounds what comes back.
    pub limit: Option<u64>,
}

/// Arguments for `tfps_ban`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TfpsBanParams {
    /// The source to condemn, as an IPv4 address. TFPS's block map is IPv4;
    /// an IPv6 address is refused by TFPS as `invalid`, and that refusal is
    /// reported.
    pub ip: String,
    /// How long the ban lasts, in seconds; `0` is forever. Absent takes
    /// TFPS's default of an hour.
    pub ttl_secs: Option<u64>,
}

/// Arguments for `tfps_unban`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TfpsUnbanParams {
    /// The source to release.
    pub ip: String,
}

/// The peer's failure, as the MCP error a caller sees.
///
/// `internal_error`, not `invalid_params`: nothing the caller passed caused a
/// non-zero exit or unreadable output. The message is the peer's own stderr,
/// verbatim, because that is the only diagnosis there is.
fn peer_error(e: TfpsError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(e.to_string(), None)
}

/// Parse an address argument, refusing anything that is not one.
///
/// Refused before the peer is asked, so the positional slot of `tfps_ctl
/// ban` can only ever hold an address.
fn parse_ip(s: &str) -> Result<IpAddr, rmcp::ErrorData> {
    s.trim().parse().map_err(|_| {
        rmcp::ErrorData::invalid_params(
            format!("ip must be an IPv4 or IPv6 address, got {s:?}"),
            None,
        )
    })
}

/// Run one blocking question to the peer off the async runtime.
///
/// `tfps_ctl` is a child process waited on synchronously; on the runtime
/// thread that wait would stall every other session for its duration.
async fn ask<T, F>(locator: TfpsLocator, f: F) -> Result<T, rmcp::ErrorData>
where
    T: Send + 'static,
    F: FnOnce(&TfpsLocator) -> Result<T, TfpsError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || f(&locator))
        .await
        .map_err(|e| {
            rmcp::ErrorData::internal_error(format!("tfps_ctl worker did not finish: {e}"), None)
        })?
        .map_err(peer_error)
}

/// One JSON content block, with the provenance note after it when the
/// payload carries fenced text.
fn answer<T: serde::Serialize>(
    payload: &T,
    carries_capture_text: bool,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let value = serde_json::to_value(payload)
        .map_err(|e| rmcp::ErrorData::internal_error(format!("serialization failed: {e}"), None))?;
    let mut blocks = vec![ContentBlock::json(value)?];
    if carries_capture_text {
        blocks.push(ContentBlock::text(crate::mcp::shape::untrusted_note()));
    }
    Ok(CallToolResult::success(blocks))
}

/// Fence the sender-written field of every row that carries one.
///
/// `field` picks the text out of a row, or `None` for a row whose text is
/// `null` -- which is not text and is not fenced.
fn fence_rows<T>(answer: &mut TfpsListAnswer<T>, field: fn(&mut T) -> Option<&mut String>) {
    if let Some(rows) = answer.rows.as_mut() {
        for row in rows {
            if let Some(text) = field(row) {
                *text = crate::mcp::shape::fence_field(text);
            }
        }
    }
}

#[tool_router(router = tfps_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Whether TFPS is installed, and what it is doing.
    ///
    /// # Errors
    ///
    /// `internal_error` carrying `tfps_ctl`'s stderr when the peer exits
    /// non-zero or answers something other than the contract. An absent peer
    /// is an answer, not an error.
    #[tool(
        name = "tfps_status",
        description = "Whether the toll-fraud prevention system (TFPS) on this \
                       host is installed and enforcing, and what it reports: \
                       enforcement state, firewall mode, interface, how many \
                       sources are blocked right now, its database and \
                       version. Answers {installed: false, reason} on a \
                       machine without TFPS; that is a result, not an error.",
        output_schema = schema_for_output::<TfpsStatusAnswer>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn tfps_status(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let reply = ask(self.tfps.clone(), TfpsLocator::status).await?;
        answer(&TfpsStatusAnswer::from(reply), false)
    }

    /// Every source TFPS holds condemned right now.
    ///
    /// # Errors
    ///
    /// As `tfps_status`.
    #[tool(
        name = "tfps_banned",
        description = "The sources TFPS currently condemns: address, the rule \
                       that condemned it, what that rule saw, when the ban \
                       began and lapses, and whether the firewall holds it; \
                       null where TFPS does not know. Bounded by \
                       --mcp-max-rows; total and truncated say what was \
                       withheld. Answers {installed: false, reason} without \
                       TFPS.",
        output_schema = schema_for_output::<TfpsListAnswer<TfpsBanned>>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn tfps_banned(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let reply = ask(self.tfps.clone(), TfpsLocator::banned).await?;
        let mut page = TfpsListAnswer::bounded(reply, self.row_cap);
        fence_rows(&mut page, |r: &mut TfpsBanned| r.detail.as_mut());
        answer(&page, true)
    }

    /// What the enforcement has dropped, per source.
    ///
    /// # Errors
    ///
    /// As `tfps_status`.
    #[tool(
        name = "tfps_dropped",
        description = "Per condemned source, how many packets TFPS's \
                       enforcement has dropped, how many events it recorded, \
                       when it last saw the source, the rule behind the block \
                       and the last request line the source sent. Bounded by \
                       --mcp-max-rows. Answers {installed: false, reason} \
                       without TFPS.",
        output_schema = schema_for_output::<TfpsListAnswer<TfpsDropped>>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn tfps_dropped(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let reply = ask(self.tfps.clone(), TfpsLocator::dropped).await?;
        let mut page = TfpsListAnswer::bounded(reply, self.row_cap);
        fence_rows(&mut page, |r: &mut TfpsDropped| r.last_request.as_mut());
        answer(&page, true)
    }

    /// TFPS's verdict log: the labels the corpus harness scores against.
    ///
    /// # Errors
    ///
    /// As `tfps_status`.
    #[tool(
        name = "tfps_labels",
        description = "TFPS's verdict log, one row per decision about a \
                       source: blocked, would-block (observing only) or \
                       exempt, with the rule, what it saw, when, and whether \
                       an operator later lifted the block. The same export \
                       the label corpus harness scores sipnab's scanner \
                       detector against. limit caps the rows TFPS returns; \
                       0 or absent is the whole log. --mcp-max-rows bounds \
                       the page. Answers {installed: false, reason} without \
                       TFPS.",
        output_schema = schema_for_output::<TfpsListAnswer<TfpsLabel>>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn tfps_labels(
        &self,
        Parameters(params): Parameters<TfpsLabelsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // `0` means the default, as on every other tool on this surface --
        // and the export's default is everything, so no `--limit` is sent.
        let limit = params.limit.filter(|n| *n > 0);
        let reply = ask(self.tfps.clone(), move |l| l.labels(limit)).await?;
        let mut page = TfpsListAnswer::bounded(reply, self.row_cap);
        fence_rows(&mut page, |r: &mut TfpsLabel| Some(&mut r.detail));
        answer(&page, true)
    }

    /// Relay an operator's decision to condemn a source.
    ///
    /// # Errors
    ///
    /// `invalid_params` when `ip` is not an address; otherwise as
    /// `tfps_status`. A ban TFPS REFUSES is not an error: the answer says
    /// `applied: false` and why.
    #[tool(
        name = "tfps_ban",
        description = "Ask TFPS to condemn one source: an operator action \
                       relayed through sipnab, not a decision sipnab makes. \
                       TFPS refuses its host's own addresses and anything in \
                       its ignoreip, and answers with what it did -- applied, \
                       or refused and why -- which is reported as given. \
                       ttl_secs is optional; 0 is forever. Answers \
                       {installed: false, reason} without TFPS. The automated \
                       path from sipnab's own findings to TFPS is a separate \
                       channel, never this tool.",
        output_schema = schema_for_output::<TfpsActionAnswer>(),
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn tfps_ban(
        &self,
        Parameters(params): Parameters<TfpsBanParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ip = parse_ip(&params.ip)?;
        let ttl = params.ttl_secs;
        let reply = ask(self.tfps.clone(), move |l| l.ban(ip, ttl)).await?;
        answer(&TfpsActionAnswer::from(reply), false)
    }

    /// Relay an operator's decision to release a source.
    ///
    /// # Errors
    ///
    /// As `tfps_ban`.
    #[tool(
        name = "tfps_unban",
        description = "Ask TFPS to release one condemned source: an operator \
                       action relayed through sipnab. TFPS answers with what \
                       it did -- applied, or refused because the source was \
                       not blocked -- and the answer is reported as given. \
                       Answers {installed: false, reason} without TFPS.",
        output_schema = schema_for_output::<TfpsActionAnswer>(),
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn tfps_unban(
        &self,
        Parameters(params): Parameters<TfpsUnbanParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ip = parse_ip(&params.ip)?;
        let reply = ask(self.tfps.clone(), move |l| l.unban(ip)).await?;
        answer(&TfpsActionAnswer::from(reply), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use parking_lot::RwLock;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    const STATUS: &str = include_str!("../../../tests/fixtures/tfps-status-golden.json");
    const BANNED: &str = include_str!("../../../tests/fixtures/tfps-banned-golden.jsonl");
    const DROPPED: &str = include_str!("../../../tests/fixtures/tfps-dropped-golden.jsonl");
    const BAN: &str = include_str!("../../../tests/fixtures/tfps-ban-golden.jsonl");
    const UNBAN: &str = include_str!("../../../tests/fixtures/tfps-unban-golden.jsonl");
    const LABELS: &str = include_str!("../../../tests/fixtures/tfps-labels-golden.jsonl");

    /// Line `n` (1-based) of a JSON Lines fixture.
    fn line(text: &str, n: usize) -> &str {
        text.lines().nth(n - 1).expect("the fixture has that line")
    }

    /// A directory holding a fake `tfps_ctl`, or nothing.
    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        /// A `tfps_ctl` running `body` under `/bin/sh`.
        fn with_body(body: &str) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("tfps_ctl");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            Self { dir }
        }

        /// A `tfps_ctl` that prints `text`.
        fn echoing(text: &str) -> Self {
            Self::with_body(&format!("cat <<'SIPNAB_FIXTURE'\n{text}\nSIPNAB_FIXTURE"))
        }

        /// A `tfps_ctl` that prints `text`, records its argv, and exits 0.
        fn recording(text: &str) -> Self {
            Self::with_body(&format!(
                "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/argv\"\n\
                 cat <<'SIPNAB_FIXTURE'\n{text}\nSIPNAB_FIXTURE"
            ))
        }

        /// The argv the recording fake was last handed, one per line.
        fn argv(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("argv"))
                .expect("argv recorded")
                .lines()
                .map(str::to_string)
                .collect()
        }

        /// A server whose locator names this fake outright.
        fn server(&self) -> SipnabMcp {
            stock().with_tfps(TfpsLocator::new(
                Some(self.dir.path().join("tfps_ctl")),
                None,
            ))
        }
    }

    /// A server with empty stores.
    fn stock() -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(100, false))),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// A server on a machine with no TFPS: the search path is an empty dir.
    fn absent() -> (SipnabMcp, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let locator = TfpsLocator::new(None, None).with_search_path(dir.path().as_os_str());
        (stock().with_tfps(locator), dir)
    }

    /// The JSON payload of a successful result.
    fn payload(result: &CallToolResult) -> serde_json::Value {
        let text = result.content[0]
            .as_text()
            .map(|t| t.text.clone())
            .expect("first block is text");
        serde_json::from_str(&text).expect("payload is JSON")
    }

    // ── the absent peer: an answer, on every tool ─────────────────────

    #[tokio::test]
    async fn every_tool_answers_installed_false_on_a_bare_machine() {
        let (srv, _dir) = absent();
        let expect_absent = |r: CallToolResult| {
            assert_eq!(r.is_error, Some(false), "a result, not an error: {r:?}");
            let p = payload(&r);
            assert_eq!(
                p,
                serde_json::json!({
                    "installed": false,
                    "reason": crate::security::tfps::NOT_INSTALLED_REASON
                }),
                "installed:false carries the reason and nothing else"
            );
        };
        expect_absent(srv.tfps_status().await.expect("status"));
        expect_absent(srv.tfps_banned().await.expect("banned"));
        expect_absent(srv.tfps_dropped().await.expect("dropped"));
        expect_absent(
            srv.tfps_labels(Parameters(TfpsLabelsParams { limit: None }))
                .await
                .expect("labels"),
        );
        expect_absent(
            srv.tfps_ban(Parameters(TfpsBanParams {
                ip: "198.51.100.20".into(),
                ttl_secs: None,
            }))
            .await
            .expect("ban"),
        );
        expect_absent(
            srv.tfps_unban(Parameters(TfpsUnbanParams {
                ip: "198.51.100.20".into(),
            }))
            .await
            .expect("unban"),
        );
    }

    // ── the present peer: each contract shape reaches the caller ──────

    #[tokio::test]
    async fn status_reports_what_the_peer_said_and_which_executable_answered() {
        let fake = Fake::recording(STATUS);
        let p = payload(&fake.server().tfps_status().await.expect("status"));
        assert_eq!(p["installed"], true);
        assert_eq!(
            p["tfps_ctl"],
            fake.dir.path().join("tfps_ctl").display().to_string()
        );
        assert_eq!(p["status"]["enforcement"], "active");
        assert_eq!(p["status"]["blocked_now"], 3);
        assert_eq!(p["status"]["version"], "0.1.0");
        assert_eq!(fake.argv(), ["status", "--json"]);
    }

    #[tokio::test]
    async fn banned_rows_arrive_paged_with_the_senders_text_fenced() {
        let fake = Fake::echoing(BANNED);
        let r = fake.server().tfps_banned().await.expect("banned");
        let p = payload(&r);
        assert_eq!(p["installed"], true);
        assert_eq!(p["total"], 3);
        assert_eq!(p["returned"], 3);
        assert_eq!(p["truncated"], false);
        assert_eq!(
            p["rows"][0]["ip"], "198.51.100.10",
            "addresses stay verbatim"
        );
        assert_eq!(p["rows"][0]["rule"], "user-agent");
        let detail = p["rows"][0]["detail"].as_str().expect("detail");
        assert_eq!(
            detail,
            crate::mcp::shape::fence_field("pplsip"),
            "a User-Agent a scanner chose is sender-written text"
        );
        assert_eq!(
            p["rows"][2]["detail"],
            serde_json::Value::Null,
            "null is not text and is not fenced"
        );
        assert_eq!(
            r.content.len(),
            2,
            "the provenance note follows the payload: {r:?}"
        );
    }

    #[tokio::test]
    async fn dropped_rows_fence_the_last_request_line() {
        let fake = Fake::echoing(DROPPED);
        let p = payload(&fake.server().tfps_dropped().await.expect("dropped"));
        assert_eq!(p["rows"][0]["dropped"], 30);
        assert_eq!(
            p["rows"][0]["last_request"],
            crate::mcp::shape::fence_field("OPTIONS sip:100@198.51.100.1 SIP/2.0")
        );
        assert_eq!(p["rows"][1]["last_request"], serde_json::Value::Null);
    }

    /// `limit` is `--limit N` when given and nothing when absent or `0`,
    /// because the export's own default is the whole log. Proved on the
    /// wire: the fake records its argv.
    #[tokio::test]
    async fn labels_pass_a_limit_through_only_when_one_is_given() {
        let fake = Fake::recording(LABELS);
        let p = payload(
            &fake
                .server()
                .tfps_labels(Parameters(TfpsLabelsParams { limit: Some(250) }))
                .await
                .expect("labels"),
        );
        assert_eq!(p["total"], 5);
        assert_eq!(
            p["rows"][0]["detail"],
            crate::mcp::shape::fence_field("sipvicious")
        );
        assert_eq!(fake.argv(), ["log", "--json", "--limit", "250"]);

        for limit in [None, Some(0)] {
            let _ = fake
                .server()
                .tfps_labels(Parameters(TfpsLabelsParams { limit }))
                .await
                .expect("labels");
            assert_eq!(
                fake.argv(),
                ["log", "--json"],
                "{limit:?} is the whole log, which needs no --limit"
            );
        }
    }

    #[tokio::test]
    async fn a_list_is_bounded_by_the_row_cap() {
        let fake = Fake::echoing(LABELS);
        let srv = fake.server().with_row_cap(2);
        let p = payload(
            &srv.tfps_labels(Parameters(TfpsLabelsParams { limit: None }))
                .await
                .expect("labels"),
        );
        assert_eq!(p["total"], 5);
        assert_eq!(p["returned"], 2);
        assert_eq!(p["truncated"], true);
    }

    #[tokio::test]
    async fn ban_relays_the_operators_request_and_reports_what_tfps_did() {
        let fake = Fake::recording(line(BAN, 1));
        let p = payload(
            &fake
                .server()
                .tfps_ban(Parameters(TfpsBanParams {
                    ip: "198.51.100.20".into(),
                    ttl_secs: Some(86_400),
                }))
                .await
                .expect("ban"),
        );
        assert_eq!(p["installed"], true);
        assert_eq!(p["action"]["action"], "ban");
        assert_eq!(p["action"]["applied"], true);
        assert_eq!(p["action"]["source"], "operator");
        assert_eq!(
            fake.argv(),
            ["ban", "--json", "198.51.100.20", "--ttl", "86400"]
        );
    }

    /// TFPS signals a refusal with exit 1 and the same structured line. That
    /// is TFPS's answer, reported as given -- not turned into an error, which
    /// would hide the reason it gave.
    #[tokio::test]
    async fn a_refused_ban_is_reported_not_raised() {
        let fake = Fake::with_body(&format!(
            "cat <<'SIPNAB_FIXTURE'\n{}\nSIPNAB_FIXTURE\necho 'error: 1 of 1 refused' >&2\nexit 1",
            line(BAN, 3)
        ));
        let r = fake
            .server()
            .tfps_ban(Parameters(TfpsBanParams {
                ip: "192.0.2.1".into(),
                ttl_secs: None,
            }))
            .await
            .expect("a refusal is a result");
        let p = payload(&r);
        assert_eq!(p["action"]["applied"], false);
        assert_eq!(p["action"]["refused"], "self");
    }

    #[tokio::test]
    async fn unban_sends_the_agreed_argv() {
        let fake = Fake::recording(line(UNBAN, 1));
        let p = payload(
            &fake
                .server()
                .tfps_unban(Parameters(TfpsUnbanParams {
                    ip: "198.51.100.20".into(),
                }))
                .await
                .expect("unban"),
        );
        assert_eq!(p["action"]["action"], "unban");
        assert_eq!(fake.argv(), ["unban", "--json", "198.51.100.20"]);
    }

    // ── refusals and failures ─────────────────────────────────────────

    #[tokio::test]
    async fn an_address_that_is_not_one_is_refused_before_the_peer_is_asked() {
        // The fake would record any call; nothing must reach it.
        let fake = Fake::with_body(&format!(
            "touch \"$(dirname \"$0\")/called\"\n\
             cat <<'SIPNAB_FIXTURE'\n{}\nSIPNAB_FIXTURE",
            line(BAN, 1)
        ));
        for bad in ["not-an-ip", "", "-x", "198.51.100.20; rm -rf /"] {
            let err = fake
                .server()
                .tfps_ban(Parameters(TfpsBanParams {
                    ip: bad.into(),
                    ttl_secs: None,
                }))
                .await
                .expect_err("not an address");
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{bad:?}");
            let err = fake
                .server()
                .tfps_unban(Parameters(TfpsUnbanParams { ip: bad.into() }))
                .await
                .expect_err("not an address");
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{bad:?}");
        }
        assert!(
            !fake.dir.path().join("called").exists(),
            "the peer was asked with something that is not an address"
        );
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_an_error_carrying_stderr_verbatim() {
        let fake = Fake::with_body("echo 'tfps.db: database is locked' >&2; exit 3");
        let err = fake.server().tfps_status().await.expect_err("exit 3");
        assert_eq!(err.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(
            err.message.contains("tfps.db: database is locked"),
            "the peer's own words: {}",
            err.message
        );
        assert!(err.message.contains("status 3"), "{}", err.message);
    }

    #[tokio::test]
    async fn output_off_the_contract_is_an_error() {
        let fake = Fake::echoing("<html>not json</html>");
        let err = fake
            .server()
            .tfps_banned()
            .await
            .expect_err("not the contract");
        assert_eq!(err.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(err.message.contains("cannot read"), "{}", err.message);
    }

    // ── the promises the annotations make ─────────────────────────────

    #[test]
    fn the_read_tools_are_read_only_and_the_two_actions_are_not() {
        let router = SipnabMcp::tfps_router();
        for name in ["tfps_status", "tfps_banned", "tfps_dropped", "tfps_labels"] {
            let tool = router
                .get(name)
                .unwrap_or_else(|| panic!("{name} registered"));
            let a = tool.annotations.as_ref().expect("annotated");
            assert_eq!(a.read_only_hint, Some(true), "{name}");
            assert_eq!(a.open_world_hint, Some(false), "{name}");
        }
        for name in ["tfps_ban", "tfps_unban"] {
            let tool = router
                .get(name)
                .unwrap_or_else(|| panic!("{name} registered"));
            let a = tool.annotations.as_ref().expect("annotated");
            assert_eq!(
                a.read_only_hint,
                Some(false),
                "{name} changes another system"
            );
            assert_eq!(
                a.open_world_hint,
                Some(true),
                "{name} reaches past this process: a firewall rule a third party feels"
            );
            assert_eq!(a.idempotent_hint, Some(true), "{name}");
        }
        let ban = router.get("tfps_ban").expect("registered");
        assert_eq!(
            ban.annotations.as_ref().and_then(|a| a.destructive_hint),
            Some(true),
            "a ban cuts a source off; a host should confirm it"
        );
        let unban = router.get("tfps_unban").expect("registered");
        assert_eq!(
            unban.annotations.as_ref().and_then(|a| a.destructive_hint),
            Some(false),
            "a release restores; it destroys nothing"
        );
    }
}
