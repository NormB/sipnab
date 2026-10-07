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
use crate::security::actions::{ActionDone, ActionError, ActionService, Actions};
use crate::security::tfps::{
    TfpsBanned, TfpsDropped, TfpsError, TfpsLabel, TfpsListAnswer, TfpsLocator, TfpsStatusAnswer,
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
    /// Rows TFPS returns, newest first. `0` or absent is one page: the
    /// server's row cap (`--mcp-max-rows`), which also bounds a larger limit.
    pub limit: Option<u64>,
}

/// Arguments for `tfps_ban`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TfpsBanParams {
    /// The source to condemn, as an IPv4 address. TFPS's block map is IPv4,
    /// so an IPv6 address is `invalid_params` and TFPS is never asked.
    pub ip: String,
    /// How long the ban lasts, in seconds: an hour when absent, 7 days at
    /// most, and never `0`, TFPS's "forever", so a ban nobody lifts still
    /// ends. `[action_limits]` changes the default and the maximum.
    pub ttl_secs: Option<u64>,
}

/// Arguments for `tfps_unban`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TfpsUnbanParams {
    /// The source to release, as an IPv4 address. An IPv6 address is
    /// `invalid_params`: TFPS's block map cannot hold one.
    pub ip: String,
}

/// Arguments for `actions_revert`: exactly one of `id` or `all: true`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ActionsRevertParams {
    /// The id of the action to back out, as `tfps_ban`'s answer gives it.
    pub id: Option<String>,
    /// `true` to back out every ban sipnab placed that is still in force,
    /// newest first.
    pub all: Option<bool>,
}

/// The peer's failure, as the MCP error a caller sees.
///
/// `internal_error`, not `invalid_params`: nothing the caller passed caused a
/// non-zero exit or unreadable output. The message is the peer's own stderr,
/// verbatim, because that is the only diagnosis there is, followed by what to
/// install when the peer lacks the capability asked for
/// ([`crate::security::tfps::peer_capability_hint`]).
fn peer_error(e: TfpsError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(e.to_string(), None)
}

/// Parse an address argument, refusing anything TFPS cannot hold.
///
/// Refused before the peer is asked, so the positional slot of `tfps_ctl
/// ban` can only ever hold an IPv4 address. The rule is
/// [`crate::security::tfps::tfps_address`], shared with the REST routes.
fn parse_ip(s: &str) -> Result<IpAddr, rmcp::ErrorData> {
    crate::security::tfps::tfps_address(s).map_err(|why| rmcp::ErrorData::invalid_params(why, None))
}

/// A permit to act on TFPS from MCP, or the refusal naming how to enable it.
///
/// Asked before the address is even parsed, so a server with nothing enabled
/// answers every call the same way and never reaches `tfps_ctl`.
fn mcp_permit(
    policy: &crate::security::actions::ActionPolicy,
) -> Result<crate::security::actions::ActionPermit, rmcp::ErrorData> {
    policy
        .permit(
            crate::security::actions::ActionTarget::Tfps,
            crate::security::actions::ActionSurface::Mcp,
        )
        .map_err(|refusal| rmcp::ErrorData::invalid_params(refusal.to_string(), None))
}

/// Run one action through the service, off the async runtime: the service
/// writes the journal with `fsync` and waits for `tfps_ctl`.
async fn act<T, F>(actions: &Actions, f: F) -> Result<CallToolResult, rmcp::ErrorData>
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce(&ActionService, u64, std::time::Instant) -> Result<T, ActionError> + Send + 'static,
{
    let Some(service) = actions.service().cloned() else {
        return action_refusal(ActionError::JournalUnusable(
            "actions are enabled but their journal is not open, so none may run".to_string(),
        ));
    };
    let now_unix = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let done =
        tokio::task::spawn_blocking(move || f(&service, now_unix, std::time::Instant::now()))
            .await
            .map_err(|e| {
                rmcp::ErrorData::internal_error(format!("action task failed: {e}"), None)
            })?;
    match done {
        Ok(done) => answer(&done, false),
        Err(e) => action_refusal(e),
    }
}

/// How an action's refusal reaches an agent.
///
/// An argument that breaks a rule is `invalid_params`, as a bad address is.
/// A well-formed call sipnab or TFPS would not carry out is an error result
/// the agent can read: `{"error", "refusal", "retry_after_secs"?}`, with
/// `refusal` one of `rate`, `not_owned`, `in_doubt`, `journal`, `tfps`.
fn action_refusal(e: ActionError) -> Result<CallToolResult, rmcp::ErrorData> {
    let message = e.to_string();
    let (refusal, retry_after) = match e {
        ActionError::NotEnabled(_) | ActionError::Rule(_) => {
            return Err(rmcp::ErrorData::invalid_params(message, None));
        }
        ActionError::Throttled(t) => ("rate", Some(t.retry_after().as_secs().max(1))),
        ActionError::NotOwned => ("not_owned", None),
        ActionError::InDoubt(_) => ("in_doubt", None),
        ActionError::JournalUnusable(_) => ("journal", None),
        ActionError::Tfps(_) => ("tfps", None),
    };
    let mut body = serde_json::json!({ "error": message, "refusal": refusal });
    if let Some(secs) = retry_after {
        body["retry_after_secs"] = secs.into();
    }
    Ok(CallToolResult::error(vec![ContentBlock::text(
        body.to_string(),
    )]))
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
        description = "TFPS's audit log, one row per block it enforced: the \
                       source, the rule that condemned it (reason), what that \
                       rule saw, and when. TFPS records only enforced blocks \
                       today, so disposition is always block. The same export \
                       the label corpus harness scores sipnab's scanner \
                       detector against. limit caps the rows TFPS returns; \
                       0 or absent is one page of --mcp-max-rows, which also \
                       bounds a larger limit, and truncated says whether TFPS \
                       held more. Answers {installed: false, reason} without \
                       TFPS.",
        output_schema = schema_for_output::<TfpsListAnswer<TfpsLabel>>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn tfps_labels(
        &self,
        Parameters(params): Parameters<TfpsLabelsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // No more than a page is ever asked for; `0` is the default, as on
        // every other tool on this surface.
        let limit = crate::security::tfps::labels_request(params.limit, self.row_cap);
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
                       Off unless the operator enabled TFPS actions for MCP \
                       (--allow-action tfps:mcp); over HTTP it also needs an \
                       actions-scope token. Every ban expires: ttl_secs, or \
                       an hour, 7 days at most, never 0. Loopback, \
                       broadcast, multicast and 0.0.0.0 are never banned. \
                       Rate limited: 10 actions a minute for the server, 5 \
                       per caller, one per address a minute. Journaled before \
                       TFPS is asked; the answer carries the action's id. \
                       TFPS refuses its host's own addresses and its \
                       ignoreip: applied false, with refused saying why. A \
                       refusal by sipnab is an error result whose JSON names \
                       it: rate (with retry_after_secs), in_doubt, journal, \
                       or tfps when TFPS could not be asked.",
        output_schema = schema_for_output::<ActionDone>(),
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
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        mcp_permit(self.actions.policy())?;
        let ip = parse_ip(&params.ip)?;
        let ttl = params.ttl_secs;
        let caller = crate::mcp::server::action_caller(&extensions);
        act(&self.actions, move |service, now_unix, now| {
            service.ban(
                crate::security::actions::ActionSurface::Mcp,
                &caller,
                ip,
                ttl,
                now_unix,
                now,
            )
        })
        .await
    }

    /// Relay an operator's decision to release a source.
    ///
    /// # Errors
    ///
    /// As `tfps_ban`.
    #[tool(
        name = "tfps_unban",
        description = "Ask TFPS to release a source sipnab banned: an \
                       operator action relayed through sipnab. Off unless the \
                       operator enabled TFPS actions for MCP (--allow-action \
                       tfps:mcp); over HTTP it also needs an actions-scope \
                       token. sipnab lifts only a ban it placed and still \
                       holds; anything else is an error result with refusal \
                       not_owned, and TFPS is not asked. The same rate \
                       limits as tfps_ban apply, so an address acted on a \
                       moment ago rests first. Journaled before TFPS is \
                       asked; the answer carries the action's id.",
        output_schema = schema_for_output::<ActionDone>(),
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
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        mcp_permit(self.actions.policy())?;
        let ip = parse_ip(&params.ip)?;
        let caller = crate::mcp::server::action_caller(&extensions);
        act(&self.actions, move |service, now_unix, now| {
            service.unban(
                crate::security::actions::ActionSurface::Mcp,
                &caller,
                ip,
                now_unix,
                now,
            )
        })
        .await
    }

    /// Back out what sipnab did to TFPS: one action, or every ban it holds.
    ///
    /// # Errors
    ///
    /// `invalid_params` when actions are off for MCP, or the arguments do
    /// not name exactly one of `id` or `all: true`.
    #[tool(
        name = "actions_revert",
        description = "Back out a ban sipnab placed ({id}) or every ban it \
                       still holds, newest first ({all: true}). Off unless \
                       the operator enabled TFPS actions for MCP \
                       (--allow-action tfps:mcp); over HTTP it also needs an \
                       actions-scope token. Each unban is journaled as a \
                       revert and counts against the same rate limits as \
                       tfps_ban. A ban TFPS already dropped is listed under \
                       lapsed, not unbanned; a ban sipnab cannot prove it \
                       placed is left alone under skipped_unknown. A refusal \
                       is an error result naming it, as for tfps_ban.",
        output_schema = schema_for_output::<crate::security::actions::RevertReport>(),
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn actions_revert(
        &self,
        Parameters(params): Parameters<ActionsRevertParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use crate::security::actions::RevertTarget;
        mcp_permit(self.actions.policy())?;
        let target = match (params.id, params.all) {
            (Some(id), None) if !id.trim().is_empty() => RevertTarget::One(id),
            (None, Some(true)) => RevertTarget::All,
            _ => {
                return Err(rmcp::ErrorData::invalid_params(
                    "name one action: {\"id\": \"a-...\"}, or {\"all\": true} for every ban \
                     sipnab holds",
                    None,
                ));
            }
        };
        let caller = crate::mcp::server::action_caller(&extensions);
        act(&self.actions, move |service, now_unix, now| {
            service.revert(
                crate::security::actions::Reverter::Surface {
                    surface: crate::security::actions::ActionSurface::Mcp,
                    caller: &caller,
                },
                target,
                now_unix,
                now,
            )
        })
        .await
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

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    const STATUS: &str = include_str!("../../../tests/fixtures/tfps-status-golden.json");
    const BANNED: &str = include_str!("../../../tests/fixtures/tfps-banned-golden.jsonl");
    const DROPPED: &str = include_str!("../../../tests/fixtures/tfps-dropped-golden.jsonl");
    const BAN: &str = include_str!("../../../tests/fixtures/tfps-ban-golden.jsonl");
    const UNBAN: &str = include_str!("../../../tests/fixtures/tfps-unban-golden.jsonl");
    const LABELS: &str = include_str!("../../../tests/fixtures/tfps-labels-golden.jsonl");

    /// Line `n` (1-based) of a JSON Lines fixture.
    fn line(text: &str, n: usize) -> Result<&str, TestError> {
        Ok(text.lines().nth(n - 1).ok_or("the fixture has that line")?)
    }

    /// A directory holding a fake `tfps_ctl`, or nothing.
    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        /// A `tfps_ctl` running `body` under `/bin/sh`.
        fn with_body(body: &str) -> Result<Self, TestError> {
            let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
            let path = dir.path().join("tfps_ctl");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n"))
                .map_err(|e| format!("write: {e:?}"))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod: {e:?}"))?;
            Ok(Self { dir })
        }

        /// A `tfps_ctl` that prints `text`.
        fn echoing(text: &str) -> Result<Self, TestError> {
            Self::with_body(&format!("cat <<'SIPNAB_FIXTURE'\n{text}\nSIPNAB_FIXTURE"))
        }

        /// A `tfps_ctl` that prints `text`, records its argv, and exits 0.
        fn recording(text: &str) -> Result<Self, TestError> {
            Self::with_body(&format!(
                "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/argv\"\n\
                 cat <<'SIPNAB_FIXTURE'\n{text}\nSIPNAB_FIXTURE"
            ))
        }

        /// The argv the recording fake was last handed, one per line.
        fn argv(&self) -> Result<Vec<String>, TestError> {
            Ok(std::fs::read_to_string(self.dir.path().join("argv"))
                .map_err(|e| format!("argv recorded: {e:?}"))?
                .lines()
                .map(str::to_string)
                .collect())
        }

        /// A server whose locator names this fake outright, with no action
        /// enabled: the default every deployment starts from.
        fn server(&self) -> SipnabMcp {
            stock().with_tfps(TfpsLocator::new(
                Some(self.dir.path().join("tfps_ctl")),
                None,
            ))
        }

        /// The same server with TFPS actions enabled for MCP, as
        /// `--allow-action tfps:mcp` does, journaled beside the fake.
        fn acting_server(&self) -> Result<SipnabMcp, TestError> {
            let locator = TfpsLocator::new(Some(self.dir.path().join("tfps_ctl")), None);
            Ok(self.server().with_actions(acting(&self.dir, &locator)?))
        }

        /// Whether the fake was run at all.
        fn ran(&self) -> bool {
            self.dir.path().join("argv").exists()
        }
    }

    /// A call over stdio, which carries no credential to name.
    fn stdio() -> rmcp::model::Extensions {
        rmcp::model::Extensions::default()
    }

    /// TFPS actions enabled for MCP, through a service that asks `locator`
    /// and journals into a fresh directory under `dir`. The address cooldown
    /// is a millisecond, so a test can ban and then unban one address.
    fn acting(
        dir: &tempfile::TempDir,
        locator: &TfpsLocator,
    ) -> Result<crate::security::actions::Actions, TestError> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let limits =
            crate::security::actions::ActionLimits::new(10, 5, std::time::Duration::from_millis(1))
                .map_err(|e| format!("valid limits: {e:?}"))?;
        let (service, _) = crate::security::actions::ActionService::start(
            policy("tfps:mcp")?,
            limits,
            &dir.path().join(format!("journal-for-server-{n}")),
            Arc::new(crate::security::actions::TfpsCtl::new(locator.clone())),
            1_756_900_000,
            std::time::Instant::now(),
        )
        .map_err(|e| format!("a journal in a fresh directory: {e:?}"))?;
        Ok(crate::security::actions::Actions::with_service(
            policy("tfps:mcp")?,
            Arc::new(service),
        ))
    }

    /// The JSON body of an error result: sipnab's refusal of an action.
    fn refusal(result: &CallToolResult) -> Result<serde_json::Value, TestError> {
        assert_eq!(result.is_error, Some(true), "{result:?}");
        payload(result)
    }

    /// The policy one `--allow-action` value enables.
    fn policy(flag: &str) -> Result<crate::security::actions::ActionPolicy, TestError> {
        Ok(
            crate::security::actions::ActionPolicy::from_settings(&[flag.to_string()], &[])
                .map_err(|e| format!("a valid --allow-action value: {e:?}"))?,
        )
    }

    /// A server with empty stores.
    fn stock() -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(100, false))),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// A server on a machine with no TFPS: the search path is an empty dir.
    fn absent() -> Result<(SipnabMcp, tempfile::TempDir), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let locator = TfpsLocator::new(None, None).with_search_path(dir.path().as_os_str());
        Ok((stock().with_tfps(locator), dir))
    }

    /// The JSON payload of a successful result.
    fn payload(result: &CallToolResult) -> Result<serde_json::Value, TestError> {
        let text = result.content[0]
            .as_text()
            .map(|t| t.text.clone())
            .ok_or("first block is text")?;
        Ok(serde_json::from_str(&text).map_err(|e| format!("payload is JSON: {e:?}"))?)
    }

    // ── the absent peer: an answer, on every tool ─────────────────────

    #[tokio::test]
    async fn every_tool_answers_installed_false_on_a_bare_machine() -> Result<(), TestError> {
        // Actions enabled, so ban and unban reach the service; with nothing
        // enabled they refuse first, which
        // `by_default_ban_and_unban_refuse_and_tfps_ctl_never_runs` covers.
        let (srv, dir) = absent()?;
        let locator = TfpsLocator::new(None, None).with_search_path(dir.path().as_os_str());
        let srv = srv.with_actions(acting(&dir, &locator)?);
        let expect_absent = |r: CallToolResult| -> Result<(), TestError> {
            assert_eq!(r.is_error, Some(false), "a result, not an error: {r:?}");
            let p = payload(&r)?;
            assert_eq!(
                p,
                serde_json::json!({
                    "installed": false,
                    "reason": crate::security::tfps::NOT_INSTALLED_REASON
                }),
                "installed:false carries the reason and nothing else"
            );
            Ok(())
        };
        expect_absent(
            srv.tfps_status()
                .await
                .map_err(|e| format!("status: {e:?}"))?,
        )?;
        expect_absent(
            srv.tfps_banned()
                .await
                .map_err(|e| format!("banned: {e:?}"))?,
        )?;
        expect_absent(
            srv.tfps_dropped()
                .await
                .map_err(|e| format!("dropped: {e:?}"))?,
        )?;
        expect_absent(
            srv.tfps_labels(Parameters(TfpsLabelsParams { limit: None }))
                .await
                .map_err(|e| format!("labels: {e:?}"))?,
        )?;
        // An action is not a read: it was asked for and could not run, so it
        // is a refusal naming what is missing, not an `installed: false`.
        let ban = refusal(
            &srv.tfps_ban(
                Parameters(TfpsBanParams {
                    ip: "198.51.100.20".into(),
                    ttl_secs: None,
                }),
                stdio(),
            )
            .await
            .map_err(|e| format!("ban: {e:?}"))?,
        )?;
        assert_eq!(ban["refusal"], "tfps", "{ban}");
        assert!(
            ban["error"]
                .as_str()
                .is_some_and(|e| e.contains(crate::security::tfps::NOT_INSTALLED_REASON)),
            "{ban}"
        );
        // sipnab placed no ban, so there is none of its own to lift.
        let unban = refusal(
            &srv.tfps_unban(
                Parameters(TfpsUnbanParams {
                    ip: "198.51.100.20".into(),
                }),
                stdio(),
            )
            .await
            .map_err(|e| format!("unban: {e:?}"))?,
        )?;
        assert_eq!(unban["refusal"], "not_owned", "{unban}");
        Ok(())
    }

    // ── the present peer: each contract shape reaches the caller ──────

    #[tokio::test]
    async fn status_reports_what_the_peer_said_and_which_executable_answered()
    -> Result<(), TestError> {
        let fake = Fake::recording(STATUS)?;
        let p = payload(
            &fake
                .server()
                .tfps_status()
                .await
                .map_err(|e| format!("status: {e:?}"))?,
        )?;
        assert_eq!(p["installed"], true);
        assert_eq!(
            p["tfps_ctl"],
            fake.dir.path().join("tfps_ctl").display().to_string()
        );
        assert_eq!(p["status"]["enforcement"], "active");
        assert_eq!(p["status"]["blocked_now"], 3);
        assert_eq!(p["status"]["version"], "0.2.1");
        assert_eq!(fake.argv()?, ["status", "--json"]);
        Ok(())
    }

    #[tokio::test]
    async fn banned_rows_arrive_paged_with_the_senders_text_fenced() -> Result<(), TestError> {
        let fake = Fake::echoing(BANNED)?;
        let r = fake
            .server()
            .tfps_banned()
            .await
            .map_err(|e| format!("banned: {e:?}"))?;
        let p = payload(&r)?;
        assert_eq!(p["installed"], true);
        assert_eq!(p["total"], 3);
        assert_eq!(p["returned"], 3);
        assert_eq!(p["truncated"], false);
        assert_eq!(
            p["rows"][0]["ip"], "198.51.100.10",
            "addresses stay verbatim"
        );
        assert_eq!(p["rows"][0]["reason"], "user-agent");
        let detail = p["rows"][0]["detail"].as_str().ok_or("detail")?;
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
        Ok(())
    }

    #[tokio::test]
    async fn dropped_rows_fence_the_last_request_line() -> Result<(), TestError> {
        let fake = Fake::echoing(DROPPED)?;
        let p = payload(
            &fake
                .server()
                .tfps_dropped()
                .await
                .map_err(|e| format!("dropped: {e:?}"))?,
        )?;
        assert_eq!(p["rows"][0]["dropped"], 30);
        assert_eq!(
            p["rows"][0]["last_request"],
            crate::mcp::shape::fence_field("OPTIONS sip:100@198.51.100.1 SIP/2.0")
        );
        assert_eq!(p["rows"][1]["last_request"], serde_json::Value::Null);
        Ok(())
    }

    /// `limit` reaches TFPS as `--limit N` when a page holds it; absent,
    /// `0` or more than a page asks for the page and one row more
    /// ([`crate::security::tfps::labels_request`]). Proved on the wire: the
    /// fake records its argv.
    #[tokio::test]
    async fn labels_ask_tfps_for_no_more_than_a_page() -> Result<(), TestError> {
        let fake = Fake::recording(LABELS)?;
        let p = payload(
            &fake
                .server()
                .with_row_cap(1000)
                .tfps_labels(Parameters(TfpsLabelsParams { limit: Some(250) }))
                .await
                .map_err(|e| format!("labels: {e:?}"))?,
        )?;
        assert_eq!(p["total"], 3);
        assert_eq!(
            p["rows"][0]["detail"],
            crate::mcp::shape::fence_field("sipvicious")
        );
        assert_eq!(fake.argv()?, ["log", "--json", "--limit", "250"]);

        for limit in [None, Some(0), Some(5000)] {
            let _ = fake
                .server()
                .with_row_cap(1000)
                .tfps_labels(Parameters(TfpsLabelsParams { limit }))
                .await
                .map_err(|e| format!("labels: {e:?}"))?;
            assert_eq!(
                fake.argv()?,
                ["log", "--json", "--limit", "1001"],
                "{limit:?} asks for one page and one row more"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_list_is_bounded_by_the_row_cap() -> Result<(), TestError> {
        let fake = Fake::echoing(LABELS)?;
        let srv = fake.server().with_row_cap(2);
        let p = payload(
            &srv.tfps_labels(Parameters(TfpsLabelsParams { limit: None }))
                .await
                .map_err(|e| format!("labels: {e:?}"))?,
        )?;
        assert_eq!(p["total"], 3);
        assert_eq!(p["returned"], 2);
        assert_eq!(p["truncated"], true);
        Ok(())
    }

    #[tokio::test]
    async fn ban_relays_the_operators_request_and_reports_what_tfps_did() -> Result<(), TestError> {
        let fake = Fake::recording(line(BAN, 1)?)?;
        let p = payload(
            &fake
                .acting_server()?
                .tfps_ban(
                    Parameters(TfpsBanParams {
                        ip: "198.51.100.20".into(),
                        ttl_secs: Some(86_400),
                    }),
                    stdio(),
                )
                .await
                .map_err(|e| format!("ban: {e:?}"))?,
        )?;
        assert_eq!(p["applied"], true, "{p}");
        assert!(
            p["id"].as_str().is_some_and(|id| id.starts_with("a-")),
            "the answer names the action's journal id: {p}"
        );
        assert_eq!(
            fake.argv()?,
            ["ban", "--json", "198.51.100.20", "--ttl", "86400"]
        );
        Ok(())
    }

    /// TFPS signals a refusal with exit 1 and the same structured line. That
    /// is TFPS's answer, reported as given -- not turned into an error, which
    /// would hide the reason it gave.
    #[tokio::test]
    async fn a_refused_ban_is_reported_not_raised() -> Result<(), TestError> {
        let fake = Fake::with_body(&format!(
            "cat <<'SIPNAB_FIXTURE'\n{}\nSIPNAB_FIXTURE\necho 'error: 1 of 1 refused' >&2\nexit 1",
            line(BAN, 3)?
        ))?;
        let r = fake
            .acting_server()?
            .tfps_ban(
                Parameters(TfpsBanParams {
                    ip: "192.0.2.1".into(),
                    ttl_secs: None,
                }),
                stdio(),
            )
            .await
            .map_err(|e| format!("a refusal is a result: {e:?}"))?;
        let p = payload(&r)?;
        assert_eq!(p["applied"], false);
        assert_eq!(p["refused"], "local");
        Ok(())
    }

    #[tokio::test]
    async fn unban_sends_the_agreed_argv() -> Result<(), TestError> {
        // sipnab lifts only its own bans, so this server bans first.
        let fake = Fake::with_body(&format!(
            "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/argv\"\n\
             case \"$1\" in\n\
             ban) echo '{}';;\n\
             unban) echo '{}';;\n\
             esac",
            line(BAN, 1)?,
            line(UNBAN, 1)?
        ))?;
        let srv = fake.acting_server()?;
        let ban = payload(
            &srv.tfps_ban(
                Parameters(TfpsBanParams {
                    ip: "198.51.100.20".into(),
                    ttl_secs: None,
                }),
                stdio(),
            )
            .await
            .map_err(|e| format!("ban: {e:?}"))?,
        )?;
        assert_eq!(ban["applied"], true, "{ban}");
        // Past the address cooldown, which is a millisecond here.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let p = payload(
            &srv.tfps_unban(
                Parameters(TfpsUnbanParams {
                    ip: "198.51.100.20".into(),
                }),
                stdio(),
            )
            .await
            .map_err(|e| format!("unban: {e:?}"))?,
        )?;
        assert_eq!(p["applied"], true, "{p}");
        assert_eq!(fake.argv()?, ["unban", "--json", "198.51.100.20"]);
        Ok(())
    }

    // ── actions are off unless enabled ────────────────────────────────

    /// sipnab changes no external system by default. Norm, 2026-09-28:
    /// "Default is secure, sipnab doesn't update external systems."
    #[tokio::test]
    async fn by_default_ban_and_unban_refuse_and_tfps_ctl_never_runs() -> Result<(), TestError> {
        let fake = Fake::recording(line(BAN, 1)?)?;
        let ban = fake
            .server()
            .tfps_ban(
                Parameters(TfpsBanParams {
                    ip: "198.51.100.20".into(),
                    ttl_secs: None,
                }),
                stdio(),
            )
            .await
            .err()
            .ok_or("no action is enabled")?;
        let unban = fake
            .server()
            .tfps_unban(
                Parameters(TfpsUnbanParams {
                    ip: "198.51.100.20".into(),
                }),
                stdio(),
            )
            .await
            .err()
            .ok_or("no action is enabled")?;
        for err in [ban, unban] {
            assert!(
                err.message.contains("--allow-action tfps:mcp")
                    && err.message.contains("[actions]"),
                "the refusal names how to enable it: {}",
                err.message
            );
        }
        assert!(!fake.ran(), "a refused action reached tfps_ctl");
        Ok(())
    }

    /// Enabled for REST only, the MCP door stays shut.
    #[tokio::test]
    async fn enabled_for_rest_only_the_mcp_tools_still_refuse() -> Result<(), TestError> {
        let fake = Fake::recording(line(BAN, 1)?)?;
        let err = fake
            .server()
            .with_actions(policy("tfps:rest")?)
            .tfps_ban(
                Parameters(TfpsBanParams {
                    ip: "198.51.100.20".into(),
                    ttl_secs: None,
                }),
                stdio(),
            )
            .await
            .err()
            .ok_or("enabled for REST, not MCP")?;
        assert!(
            err.message.contains("--allow-action tfps:mcp"),
            "{}",
            err.message
        );
        assert!(!fake.ran(), "a refused action reached tfps_ctl");
        Ok(())
    }

    // ── refusals and failures ─────────────────────────────────────────

    #[tokio::test]
    async fn an_address_that_is_not_one_is_refused_before_the_peer_is_asked()
    -> Result<(), TestError> {
        // The fake would record any call; nothing must reach it.
        let fake = Fake::with_body(&format!(
            "touch \"$(dirname \"$0\")/called\"\n\
             cat <<'SIPNAB_FIXTURE'\n{}\nSIPNAB_FIXTURE",
            line(BAN, 1)?
        ))?;
        for bad in ["not-an-ip", "", "-x", "198.51.100.20; rm -rf /"] {
            let err = fake
                .acting_server()?
                .tfps_ban(
                    Parameters(TfpsBanParams {
                        ip: bad.into(),
                        ttl_secs: None,
                    }),
                    stdio(),
                )
                .await
                .err()
                .ok_or("not an address")?;
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{bad:?}");
            let err = fake
                .acting_server()?
                .tfps_unban(Parameters(TfpsUnbanParams { ip: bad.into() }), stdio())
                .await
                .err()
                .ok_or("not an address")?;
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{bad:?}");
        }
        assert!(
            !fake.dir.path().join("called").exists(),
            "the peer was asked with something that is not an address"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_an_error_carrying_stderr_verbatim() -> Result<(), TestError> {
        let fake = Fake::with_body("echo 'tfps.db: database is locked' >&2; exit 3")?;
        let err = fake.server().tfps_status().await.err().ok_or("exit 3")?;
        assert_eq!(err.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(
            err.message.contains("tfps.db: database is locked"),
            "the peer's own words: {}",
            err.message
        );
        assert!(err.message.contains("status 3"), "{}", err.message);
        Ok(())
    }

    #[tokio::test]
    async fn output_off_the_contract_is_an_error() -> Result<(), TestError> {
        let fake = Fake::echoing("<html>not json</html>")?;
        let err = fake
            .server()
            .tfps_banned()
            .await
            .err()
            .ok_or("not the contract")?;
        assert_eq!(err.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(err.message.contains("cannot read"), "{}", err.message);
        Ok(())
    }

    // ── the promises the annotations make ─────────────────────────────

    #[test]
    fn the_read_tools_are_read_only_and_the_two_actions_are_not() -> Result<(), TestError> {
        let router = SipnabMcp::tfps_router();
        for name in ["tfps_status", "tfps_banned", "tfps_dropped", "tfps_labels"] {
            let tool = router
                .get(name)
                .ok_or_else(|| format!("{name} registered"))?;
            let a = tool.annotations.as_ref().ok_or("annotated")?;
            assert_eq!(a.read_only_hint, Some(true), "{name}");
            assert_eq!(a.open_world_hint, Some(false), "{name}");
        }
        for name in ["tfps_ban", "tfps_unban"] {
            let tool = router
                .get(name)
                .ok_or_else(|| format!("{name} registered"))?;
            let a = tool.annotations.as_ref().ok_or("annotated")?;
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
        let ban = router.get("tfps_ban").ok_or("registered")?;
        assert_eq!(
            ban.annotations.as_ref().and_then(|a| a.destructive_hint),
            Some(true),
            "a ban cuts a source off; a host should confirm it"
        );
        let unban = router.get("tfps_unban").ok_or("registered")?;
        assert_eq!(
            unban.annotations.as_ref().and_then(|a| a.destructive_hint),
            Some(false),
            "a release restores; it destroys nothing"
        );
        Ok(())
    }
}
