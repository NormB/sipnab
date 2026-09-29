// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one path every action takes (approved spec "sipnab Operations
//! Journal", 2026-09-28).
//!
//! In this order, and no other:
//!
//! 1. the policy enables the target on the surface asking;
//! 2. the address may be banned at all, and the lifetime is allowed;
//! 3. the rate limits admit it;
//! 4. the intent is written to the journal and synced;
//! 5. only then is TFPS asked;
//! 6. the outcome is journaled and the ledger updated.
//!
//! A refusal at any step is journaled and nothing further happens. A journal
//! that cannot be written refuses the action: an action never runs
//! unrecorded.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::journal::ledger::{Intent, Ledger, Owned, TfpsView};
use crate::journal::{Journal, JournalError, JournalLimits, Record};

use super::{
    ActionGovernor, ActionLimits, ActionPermit, ActionPolicy, ActionRefusal, ActionSurface,
    ActionTarget, ActionThrottle, BanRule, ban_ttl, check_ban_address,
};

/// How many distinct callers and addresses the rate limits track.
const MAX_TRACKED: usize = 4096;

/// What TFPS said to a ban or an unban.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TfpsReply {
    /// It took effect.
    Applied,
    /// TFPS refused, in its own words.
    Refused(String),
}

/// The three things the service asks TFPS. A trait so the service can be
/// driven without a kernel; the real implementation runs `tfps_ctl`.
pub trait TfpsActions: Send + Sync {
    /// Ban `ip` for `ttl_secs`; `now_unix` is the time the ban is asked at.
    ///
    /// # Errors
    ///
    /// TFPS could not be asked, in words for the operator.
    fn ban(&self, ip: Ipv4Addr, ttl_secs: u64, now_unix: u64) -> Result<TfpsReply, String>;

    /// Unban `ip`.
    ///
    /// # Errors
    ///
    /// TFPS could not be asked.
    fn unban(&self, ip: Ipv4Addr) -> Result<TfpsReply, String>;

    /// Every address TFPS blocks now, with its expiry in Unix seconds.
    ///
    /// # Errors
    ///
    /// TFPS could not be asked.
    fn banned(&self) -> Result<Vec<(Ipv4Addr, Option<u64>)>, String>;
}

/// The real TFPS: `tfps_ctl`, found as the rest of sipnab finds it.
pub struct TfpsCtl {
    /// Finds and runs `tfps_ctl`.
    locator: crate::security::tfps::TfpsLocator,
}

impl TfpsCtl {
    /// Ask TFPS through `locator`.
    #[must_use]
    pub fn new(locator: crate::security::tfps::TfpsLocator) -> Self {
        Self { locator }
    }
}

/// An answer to `ban` or `unban`, or why TFPS could not be asked.
fn action_reply(
    reply: Result<
        crate::security::tfps::Reply<crate::security::tfps::TfpsAction>,
        crate::security::tfps::TfpsError,
    >,
) -> Result<TfpsReply, String> {
    use crate::security::tfps::Reply;
    match reply {
        Ok(Reply::Answered { value, .. }) if value.applied => Ok(TfpsReply::Applied),
        // TFPS names every refusal; an unnamed one is still not applied.
        Ok(Reply::Answered { value, .. }) => Ok(TfpsReply::Refused(
            value.refused.unwrap_or_else(|| "unnamed".to_string()),
        )),
        Ok(Reply::NotInstalled { reason }) => Err(reason),
        Err(e) => Err(e.to_string()),
    }
}

impl TfpsActions for TfpsCtl {
    fn ban(&self, ip: Ipv4Addr, ttl_secs: u64, _now_unix: u64) -> Result<TfpsReply, String> {
        action_reply(
            self.locator
                .ban(&ActionPermit(()), IpAddr::V4(ip), Some(ttl_secs)),
        )
    }

    fn unban(&self, ip: Ipv4Addr) -> Result<TfpsReply, String> {
        action_reply(self.locator.unban(&ActionPermit(()), IpAddr::V4(ip)))
    }

    fn banned(&self) -> Result<Vec<(Ipv4Addr, Option<u64>)>, String> {
        use crate::security::tfps::Reply;
        match self.locator.banned() {
            Ok(Reply::Answered { value, .. }) => value
                .into_iter()
                .map(|row| {
                    row.ip
                        .parse::<Ipv4Addr>()
                        .map(|ip| (ip, row.expires))
                        .map_err(|_| {
                            format!("tfps_ctl listed an address it cannot mean: {}", row.ip)
                        })
                })
                .collect(),
            Ok(Reply::NotInstalled { reason }) => Err(reason),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Why an action did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionError {
    /// The operator did not enable this action on this surface.
    NotEnabled(ActionRefusal),
    /// The address or the lifetime is not allowed.
    Rule(BanRule),
    /// The rate limits refused it.
    Throttled(ActionThrottle),
    /// sipnab holds no ban on this address, so it will not lift one.
    NotOwned,
    /// Actions from before a crash are still unresolved; nothing new runs
    /// until TFPS can be asked about them.
    InDoubt(usize),
    /// The journal cannot be used, so no action may run.
    JournalUnusable(String),
    /// TFPS could not be asked.
    Tfps(String),
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnabled(r) => write!(f, "{r}"),
            Self::Rule(r) => write!(f, "{r}"),
            Self::Throttled(t) => write!(f, "{t}"),
            Self::NotOwned => write!(
                f,
                "sipnab holds no ban on this address: it did not place one, or the one it placed \
                 has ended or was dropped by TFPS. sipnab lifts only its own bans; to lift \
                 another, unban it on the TFPS host"
            ),
            Self::InDoubt(n) => write!(
                f,
                "{n} action(s) from before sipnab last stopped are unresolved, because TFPS could \
                 not be asked about them; no new action runs until it can"
            ),
            Self::JournalUnusable(m) => write!(f, "actions are off: {m}"),
            Self::Tfps(m) => write!(f, "TFPS could not be asked: {m}"),
        }
    }
}

impl std::error::Error for ActionError {}

/// An action that ran: the answer `tfps_ban` and `tfps_unban` give on every
/// surface.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct ActionDone {
    /// The id every journal record about this action carries, such as
    /// `a-r-68d9c1f2-4412-3`.
    pub id: String,
    /// Whether TFPS applied it.
    pub applied: bool,
    /// Why TFPS refused, in its own words: `local`, `declared`, `kernel`, or
    /// `not-blocked` for an unban. `null` when applied.
    pub refused: Option<String>,
}

/// What starting the service found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StartReport {
    /// Actions in doubt that TFPS's answer resolved.
    pub reconciled: usize,
    /// Actions still in doubt because TFPS could not be asked.
    pub still_in_doubt: usize,
    /// Why actions are off, when they are.
    pub disabled: Option<String>,
    /// How the run before this one ended, as the journal records it.
    pub previous_run: PreviousRun,
}

/// How the run before this one ended.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PreviousRun {
    /// The journal is new: there was no run before this one.
    #[default]
    None,
    /// It stopped cleanly and said so.
    Stopped,
    /// It left no stop record: a crash, a kill, a power loss, or a stop that
    /// came while an action was in flight. Whatever it left in doubt is
    /// checked against TFPS before any new action runs.
    Ended,
}

impl PreviousRun {
    /// How the journal's `records` say the last run ended.
    #[must_use]
    pub fn of(records: &[Record]) -> Self {
        let Some(last) = records.last() else {
            return Self::None;
        };
        // The last run is the run of the last record written.
        if records
            .iter()
            .any(|r| r.kind == "run_stop" && r.run == last.run)
        {
            Self::Stopped
        } else {
            Self::Ended
        }
    }
}

/// Which actions a revert backs out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevertTarget {
    /// The ban placed by this action id.
    One(String),
    /// Every ban sipnab placed that is still in force, newest first.
    All,
}

/// Who asks for a revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reverter<'a> {
    /// The operator at this machine's command line: no policy and no rate
    /// limit applies, so recovery works with actions switched off.
    Local,
    /// A caller on a surface: a revert is then an action like any other,
    /// behind the same policy and limits.
    Surface {
        /// Where it was asked.
        surface: ActionSurface,
        /// Who asked, as the journal names them.
        caller: &'a str,
    },
}

/// What a revert did.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct RevertReport {
    /// The ids of the actions backed out, in the order they were.
    pub reverted: Vec<String>,
    /// Addresses whose ban TFPS had already dropped, so there was nothing
    /// to lift; sipnab no longer owns them.
    pub lapsed: Vec<String>,
    /// Addresses TFPS shows banned that sipnab cannot prove it placed, left
    /// alone.
    pub skipped_unknown: Vec<String>,
    /// Reverts TFPS refused or could not be asked for.
    pub failed: Vec<RevertFailure>,
    /// Ids not reached because a rate limit stopped the revert part way.
    pub left: Vec<String>,
}

/// One revert that did not happen.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct RevertFailure {
    /// The action it would have backed out.
    pub id: String,
    /// Its address.
    pub address: String,
    /// Why not, in TFPS's words or sipnab's.
    pub why: String,
}

/// What comparing the journal with TFPS found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Actions in doubt that TFPS's answer resolved.
    pub reconciled: usize,
    /// Actions still in doubt.
    pub still_in_doubt: usize,
    /// Owned bans TFPS had dropped before their expiry.
    pub lapsed: usize,
}

/// The one path every action takes.
pub struct ActionService {
    /// Which surfaces may act on which targets.
    policy: ActionPolicy,
    /// The rules and rate limits.
    limits: ActionLimits,
    /// The TFPS it asks.
    tfps: Arc<dyn TfpsActions>,
    /// Everything an action changes, behind one lock so actions are ordered.
    inner: Mutex<Inner>,
    /// Set by [`Self::stop`]: no new action is admitted after it.
    stopping: std::sync::atomic::AtomicBool,
}

/// The service's state, changed only under its lock.
struct Inner {
    /// The journal; `None` when it could not be opened.
    journal: Option<Journal>,
    /// Why actions are off, when they are.
    disabled: Option<String>,
    /// What the journal says sipnab has done.
    ledger: Ledger,
    /// The rate limits.
    governor: ActionGovernor,
    /// This run's identity.
    run: String,
    /// The next action number in this run.
    next: u64,
    /// The journal directory, for pruning.
    dir: PathBuf,
    /// When a segment is full and how long closed ones are kept.
    journal_limits: JournalLimits,
    /// Refusals this minute past the first of each caller and reason.
    folds: BTreeMap<(String, String), u64>,
    /// The minute `folds` counts, as Unix seconds divided by 60.
    fold_minute: u64,
}

impl ActionService {
    /// Open the journal in `dir`, rebuild what it says, resolve anything left
    /// in doubt against TFPS, and rebuild the rate limits.
    ///
    /// A damaged journal does not stop sipnab: the service starts with
    /// actions off and says why in the report, and everything that only reads
    /// keeps working.
    ///
    /// # Errors
    ///
    /// [`ActionError::JournalUnusable`] when another process holds the journal
    /// or the directory cannot be used at all.
    pub fn start(
        policy: ActionPolicy,
        limits: ActionLimits,
        dir: &Path,
        tfps: Arc<dyn TfpsActions>,
        now_unix: u64,
        now: Instant,
    ) -> Result<(Self, StartReport), ActionError> {
        Self::start_with(
            policy,
            limits,
            dir,
            tfps,
            JournalLimits::default(),
            now_unix,
            now,
        )
    }

    /// [`Self::start`], with the journal's segment size and retention given.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    pub fn start_with(
        policy: ActionPolicy,
        limits: ActionLimits,
        dir: &Path,
        tfps: Arc<dyn TfpsActions>,
        journal_limits: JournalLimits,
        now_unix: u64,
        now: Instant,
    ) -> Result<(Self, StartReport), ActionError> {
        let run = format!("r-{now_unix:x}-{}", std::process::id());
        let mut report = StartReport::default();
        let governor = ActionGovernor::new(limits, MAX_TRACKED, now);
        let (journal, recovered) = match Journal::open_with(dir, &run, journal_limits) {
            Ok(opened) => opened,
            Err(e @ JournalError::Broken { .. }) => {
                report.disabled = Some(e.to_string());
                let inner = Inner {
                    journal: None,
                    disabled: Some(e.to_string()),
                    ledger: Ledger::default(),
                    governor,
                    run,
                    next: 1,
                    dir: dir.to_path_buf(),
                    journal_limits,
                    folds: BTreeMap::new(),
                    fold_minute: now_unix / 60,
                };
                return Ok((
                    Self {
                        policy,
                        limits,
                        tfps,
                        inner: Mutex::new(inner),
                        stopping: std::sync::atomic::AtomicBool::new(false),
                    },
                    report,
                ));
            }
            Err(e) => return Err(ActionError::JournalUnusable(e.to_string())),
        };
        report.previous_run = PreviousRun::of(&recovered.records);
        let ledger = Ledger::from_records(&recovered.records, now_unix);
        let mut inner = Inner {
            journal: Some(journal),
            disabled: None,
            ledger,
            governor,
            run,
            next: 1,
            dir: dir.to_path_buf(),
            journal_limits,
            folds: BTreeMap::new(),
            fold_minute: now_unix / 60,
        };

        // Only when there is something to check: a journal with nothing in
        // doubt and nothing owned has nothing to ask TFPS about.
        if !inner.ledger.in_doubt().is_empty() || !inner.ledger.owned_newest_first().is_empty() {
            // TFPS unreachable: everything stays as the journal says.
            if let Ok(list) = tfps.banned() {
                let (reconciled, _) = inner.check_peer(&list, now_unix)?;
                report.reconciled = reconciled;
            }
            report.still_in_doubt = inner.ledger.in_doubt().len();
        }

        for a in inner
            .ledger
            .recent_actions(now_unix, limits.address_cooldown().as_secs().max(60))
        {
            if let Ok(ip) = a.address.parse::<IpAddr>() {
                let back = Duration::from_secs(now_unix.saturating_sub(a.at));
                let at = now.checked_sub(back).unwrap_or(now);
                let _ = inner.governor.admit(&a.caller, ip, at);
            }
        }

        inner.write(
            "run_start",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "reconciled": report.reconciled,
                "still_in_doubt": report.still_in_doubt,
            }),
        )?;
        Ok((
            Self {
                policy,
                limits,
                tfps,
                inner: Mutex::new(inner),
                stopping: std::sync::atomic::AtomicBool::new(false),
            },
            report,
        ))
    }

    /// Ask TFPS to ban `ip`, for `ttl` seconds or the default.
    ///
    /// # Errors
    ///
    /// The [`ActionError`] of the first step that refused it.
    pub fn ban(
        &self,
        surface: ActionSurface,
        caller: &str,
        ip: IpAddr,
        ttl: Option<u64>,
        now_unix: u64,
        now: Instant,
    ) -> Result<ActionDone, ActionError> {
        let mut inner = self.lock();
        self.admitting()?;
        inner.ready()?;
        let refuse = |inner: &mut Inner, reason: &str, err: ActionError| {
            inner.refused(surface, caller, ip, reason, now_unix);
            err
        };
        if let Err(r) = self.policy.permit(ActionTarget::Tfps, surface) {
            return Err(refuse(&mut inner, "policy", ActionError::NotEnabled(r)));
        }
        let doubt = inner.ledger.in_doubt().len();
        if doubt > 0 {
            return Err(refuse(&mut inner, "in_doubt", ActionError::InDoubt(doubt)));
        }
        if let Err(rule) = check_ban_address(ip) {
            return Err(refuse(&mut inner, "address", ActionError::Rule(rule)));
        }
        let secs = match ban_ttl(ttl, &self.limits) {
            Ok(s) => s,
            Err(rule) => return Err(refuse(&mut inner, "ttl", ActionError::Rule(rule))),
        };
        if let Err(t) = inner.governor.admit(caller, ip, now) {
            return Err(refuse(&mut inner, "rate", ActionError::Throttled(t)));
        }
        let IpAddr::V4(v4) = ip else {
            return Err(ActionError::Rule(BanRule::NotIpv4));
        };
        let id = inner.new_id();
        inner.write(
            "action_intent",
            serde_json::json!({
                "id": id, "target": "tfps", "verb": "ban", "address": ip.to_string(),
                "at": now_unix, "ttl_secs": secs, "expires": now_unix + secs,
                "surface": surface.name(), "caller": caller,
            }),
        )?;
        let reply = self.tfps.ban(v4, secs, now_unix);
        inner.finish(&id, reply)
    }

    /// Ask TFPS to lift a ban sipnab placed.
    ///
    /// # Errors
    ///
    /// The [`ActionError`] of the first step that refused it;
    /// [`ActionError::NotOwned`] for a ban sipnab did not place.
    pub fn unban(
        &self,
        surface: ActionSurface,
        caller: &str,
        ip: IpAddr,
        now_unix: u64,
        now: Instant,
    ) -> Result<ActionDone, ActionError> {
        let mut inner = self.lock();
        self.admitting()?;
        inner.ready()?;
        let refuse = |inner: &mut Inner, reason: &str, err: ActionError| {
            inner.refused(surface, caller, ip, reason, now_unix);
            err
        };
        if let Err(r) = self.policy.permit(ActionTarget::Tfps, surface) {
            return Err(refuse(&mut inner, "policy", ActionError::NotEnabled(r)));
        }
        let doubt = inner.ledger.in_doubt().len();
        if doubt > 0 {
            return Err(refuse(&mut inner, "in_doubt", ActionError::InDoubt(doubt)));
        }
        inner.ledger.set_now(now_unix);
        let Some(owned_id) = inner.ledger.owned(&ip.to_string()).map(|o| o.id.clone()) else {
            return Err(refuse(&mut inner, "ownership", ActionError::NotOwned));
        };
        if let Err(t) = inner.governor.admit(caller, ip, now) {
            return Err(refuse(&mut inner, "rate", ActionError::Throttled(t)));
        }
        let IpAddr::V4(v4) = ip else {
            return Err(ActionError::Rule(BanRule::NotIpv4));
        };
        let id = inner.new_id();
        inner.write(
            "action_intent",
            serde_json::json!({
                "id": id, "target": "tfps", "verb": "unban", "address": ip.to_string(),
                "at": now_unix, "surface": surface.name(), "caller": caller,
            }),
        )?;
        let reply = self.tfps.unban(v4);
        let gone = matches!(&reply, Ok(TfpsReply::Refused(why)) if why == "not-blocked");
        let done = inner.finish(&id, reply)?;
        if gone {
            // TFPS no longer held it: the ban sipnab placed has ended.
            inner.write(
                "lapsed_by_peer",
                serde_json::json!({ "id": owned_id, "address": ip.to_string(), "at": now_unix }),
            )?;
        }
        Ok(done)
    }

    /// Compare what the journal says with what TFPS reports: resolve actions
    /// left in doubt, and journal as `lapsed_by_peer` every owned ban TFPS
    /// dropped before its expiry (TFPS forgets manual bans when it restarts).
    /// Only reads TFPS, so it needs no permit and spends no limit.
    ///
    /// # Errors
    ///
    /// [`ActionError::Tfps`] when TFPS cannot be asked, changing nothing;
    /// [`ActionError::JournalUnusable`] when the journal cannot be written.
    pub fn reconcile(&self, now_unix: u64) -> Result<ReconcileReport, ActionError> {
        let mut inner = self.lock();
        self.admitting()?;
        inner.ready()?;
        inner.flush_folds(now_unix);
        let list = self.tfps.banned().map_err(ActionError::Tfps)?;
        let (reconciled, lapsed) = inner.check_peer(&list, now_unix)?;
        Ok(ReconcileReport {
            reconciled,
            still_in_doubt: inner.ledger.in_doubt().len(),
            lapsed: lapsed.len(),
        })
    }

    /// Check the journal against TFPS every `every`, on a thread of its own,
    /// for as long as `service` lives: the thread holds no strong reference,
    /// so it ends at the first tick after the service is dropped. A ban TFPS
    /// dropped early is found without anyone asking, and journaled.
    ///
    /// # Errors
    ///
    /// The thread could not be started.
    pub fn watch(
        service: &Arc<Self>,
        every: Duration,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        let weak = Arc::downgrade(service);
        std::thread::Builder::new()
            .name("actions-watch".to_string())
            .spawn(move || {
                loop {
                    std::thread::sleep(every);
                    let Some(service) = weak.upgrade() else {
                        break;
                    };
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    match service.reconcile(now_unix) {
                        Ok(r) if r.lapsed > 0 => tracing::warn!(
                            "TFPS no longer holds {} ban(s) sipnab placed before they \
                             expired, typically because TFPS restarted; sipnab no longer \
                             holds them and does not ban again on its own",
                            r.lapsed
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::debug!("actions check against TFPS: {e}"),
                    }
                }
            })
    }

    /// Back out one action, or every ban sipnab placed that is still in
    /// force, newest first; each unban is journaled as its own revert.
    ///
    /// TFPS is asked first what it holds, so a ban it already dropped is
    /// reported as lapsed rather than unbanned. Bans resolved as `unknown`
    /// are never lifted and are listed instead.
    ///
    /// # Errors
    ///
    /// For a [`Reverter::Surface`], the refusals an action gets.
    /// [`ActionError::NotOwned`] when `One` names no ban sipnab holds;
    /// [`ActionError::Tfps`] when TFPS cannot be asked.
    pub fn revert(
        &self,
        reverter: Reverter<'_>,
        target: RevertTarget,
        now_unix: u64,
        now: Instant,
    ) -> Result<RevertReport, ActionError> {
        let mut inner = self.lock();
        self.admitting()?;
        inner.ready()?;
        inner.ledger.set_now(now_unix);
        let (surface, caller) = match reverter {
            Reverter::Local => ("cli", "local"),
            Reverter::Surface { surface, caller } => (surface.name(), caller),
        };
        if let Reverter::Surface { surface, caller } = reverter {
            let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            if let Err(r) = self.policy.permit(ActionTarget::Tfps, surface) {
                inner.refused(surface, caller, ip, "policy", now_unix);
                return Err(ActionError::NotEnabled(r));
            }
            let doubt = inner.ledger.in_doubt().len();
            if doubt > 0 {
                inner.refused(surface, caller, ip, "in_doubt", now_unix);
                return Err(ActionError::InDoubt(doubt));
            }
        }
        let wanted: Vec<Owned> = match &target {
            RevertTarget::All => inner
                .ledger
                .owned_newest_first()
                .into_iter()
                .cloned()
                .collect(),
            RevertTarget::One(id) => {
                let found: Vec<Owned> = inner
                    .ledger
                    .owned_newest_first()
                    .into_iter()
                    .filter(|o| &o.id == id)
                    .cloned()
                    .collect();
                if found.is_empty() {
                    if let Reverter::Surface { surface, caller } = reverter {
                        let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                        inner.refused(surface, caller, ip, "ownership", now_unix);
                    }
                    return Err(ActionError::NotOwned);
                }
                found
            }
        };
        let list = self.tfps.banned().map_err(ActionError::Tfps)?;
        let (_, lapsed) = inner.check_peer(&list, now_unix)?;

        let mut report = RevertReport::default();
        if target == RevertTarget::All {
            report.skipped_unknown = inner
                .ledger
                .unknown()
                .iter()
                .map(|i| i.address.clone())
                .collect();
        }
        for (n, owned) in wanted.iter().enumerate() {
            if lapsed.contains(&owned.address) {
                report.lapsed.push(owned.address.clone());
                continue;
            }
            let Ok(IpAddr::V4(v4)) = owned.address.parse::<IpAddr>() else {
                continue;
            };
            if let Reverter::Surface {
                surface: asked_on,
                caller,
            } = reverter
                && let Err(t) = inner.governor.admit(caller, IpAddr::V4(v4), now)
            {
                if report.reverted.is_empty() && report.lapsed.is_empty() {
                    inner.refused(asked_on, caller, IpAddr::V4(v4), "rate", now_unix);
                    return Err(ActionError::Throttled(t));
                }
                report.left = wanted[n..].iter().map(|o| o.id.clone()).collect();
                break;
            }
            let id = inner.new_id();
            inner.write(
                "revert_intent",
                serde_json::json!({
                    "id": id, "reverts": owned.id, "target": "tfps", "verb": "unban",
                    "address": owned.address, "at": now_unix, "surface": surface,
                    "caller": caller,
                }),
            )?;
            let reply = self.tfps.unban(v4);
            let (result, detail) = match &reply {
                Ok(TfpsReply::Applied) => ("applied", None),
                Ok(TfpsReply::Refused(why)) => ("refused", Some(why.clone())),
                Err(e) => ("failed", Some(e.clone())),
            };
            inner.write(
                "revert_outcome",
                serde_json::json!({ "id": id, "result": result, "detail": detail }),
            )?;
            match reply {
                Ok(TfpsReply::Applied) => report.reverted.push(owned.id.clone()),
                Ok(TfpsReply::Refused(why)) if why == "not-blocked" => {
                    inner.write(
                        "lapsed_by_peer",
                        serde_json::json!({ "id": owned.id, "address": owned.address,
                            "at": now_unix }),
                    )?;
                    report.lapsed.push(owned.address.clone());
                }
                Ok(TfpsReply::Refused(why)) => report.failed.push(RevertFailure {
                    id: owned.id.clone(),
                    address: owned.address.clone(),
                    why,
                }),
                Err(e) if matches!(target, RevertTarget::One(_)) => {
                    return Err(ActionError::Tfps(e));
                }
                Err(e) => report.failed.push(RevertFailure {
                    id: owned.id.clone(),
                    address: owned.address.clone(),
                    why: e,
                }),
            }
        }
        Ok(report)
    }

    /// The ban sipnab owns on `ip`, if one is in force.
    #[must_use]
    pub fn owned(&self, ip: IpAddr) -> Option<Owned> {
        self.lock().ledger.owned(&ip.to_string()).cloned()
    }

    /// Actions left in doubt.
    #[must_use]
    pub fn in_doubt(&self) -> Vec<Intent> {
        self.lock().ledger.in_doubt()
    }

    /// Stop admitting actions, and journal `run_stop` if that can be done
    /// without waiting. Returns whether the record was written.
    ///
    /// Stop means stop: an action whose TFPS call is still running holds the
    /// lock, and is not waited for. Its intent stays in doubt, no stop record
    /// is written, and the next start resolves it against TFPS.
    pub fn stop(&self, now_unix: u64) -> bool {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        if inner.ready().is_err() {
            return false;
        }
        let in_doubt = inner.ledger.in_doubt().len();
        inner
            .write(
                "run_stop",
                serde_json::json!({ "at": now_unix, "in_doubt": in_doubt }),
            )
            .is_ok()
    }

    /// Whether a new action may be admitted: not once [`Self::stop`] ran.
    fn admitting(&self) -> Result<(), ActionError> {
        if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ActionError::JournalUnusable(
                "sipnab is stopping; no new action is admitted".to_string(),
            ));
        }
        Ok(())
    }

    /// The state, recovered if a panic poisoned the lock.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Inner {
    /// Whether an action may run at all.
    fn ready(&self) -> Result<(), ActionError> {
        match (&self.disabled, &self.journal) {
            (Some(why), _) => Err(ActionError::JournalUnusable(why.clone())),
            (None, None) => Err(ActionError::JournalUnusable(
                "the journal is not open".to_string(),
            )),
            (None, Some(_)) => Ok(()),
        }
    }

    /// A fresh action id, unique to this run.
    fn new_id(&mut self) -> String {
        let id = format!("a-{}-{}", self.run, self.next);
        self.next += 1;
        id
    }

    /// Append a record and apply it to the ledger.
    fn write(&mut self, kind: &str, body: serde_json::Value) -> Result<(), ActionError> {
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| ActionError::JournalUnusable("the journal is not open".to_string()))?;
        let seq = journal
            .append(kind, body.clone())
            .map_err(|e| ActionError::JournalUnusable(e.to_string()))?;
        self.ledger.apply(&Record {
            seq,
            ts: String::new(),
            run: self.run.clone(),
            kind: kind.to_string(),
            body,
        });
        if journal.segment_full() {
            // The next segment opens with everything in force, so the closed
            // ones can go once they are past retention.
            journal
                .roll_over(self.ledger.checkpoint_state())
                .map_err(|e| ActionError::JournalUnusable(e.to_string()))?;
            // A prune that fails leaves an extra segment, never a gap.
            let _ = Journal::prune(&self.dir, self.journal_limits.retention);
        }
        Ok(())
    }

    /// Resolve what is in doubt and find the owned bans TFPS dropped early,
    /// against TFPS's `list`. Returns how many were resolved and the
    /// addresses journaled as lapsed.
    fn check_peer(
        &mut self,
        list: &[(Ipv4Addr, Option<u64>)],
        now_unix: u64,
    ) -> Result<(usize, Vec<String>), ActionError> {
        let mut reconciled = 0;
        for intent in self.ledger.in_doubt() {
            let view = view_of(list, &intent.address);
            if let Some(resolution) = intent.resolve(view) {
                let body = serde_json::json!({ "id": intent.id, "resolution": resolution });
                self.write("reconciled", body)?;
                reconciled += 1;
            }
        }
        self.ledger.set_now(now_unix);
        let gone: Vec<Owned> = self
            .ledger
            .owned_newest_first()
            .into_iter()
            .filter(|o| view_of(list, &o.address) == TfpsView::Absent)
            .cloned()
            .collect();
        let mut lapsed = Vec::new();
        for o in gone {
            self.write(
                "lapsed_by_peer",
                serde_json::json!({ "id": o.id, "address": o.address, "at": now_unix }),
            )?;
            lapsed.push(o.address);
        }
        Ok((reconciled, lapsed))
    }

    /// Write the minute's folded refusals once the minute has passed.
    fn flush_folds(&mut self, now_unix: u64) {
        let minute = now_unix / 60;
        if minute == self.fold_minute {
            return;
        }
        let counts: Vec<serde_json::Value> = self
            .folds
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|((caller, reason), n)| {
                serde_json::json!({ "caller": caller, "reason": reason, "folded": n })
            })
            .collect();
        let started = self.fold_minute * 60;
        self.folds.clear();
        self.fold_minute = minute;
        if !counts.is_empty() {
            let _ = self.write(
                "refusals_summary",
                serde_json::json!({ "minute_start": started, "counts": counts }),
            );
        }
    }

    /// Journal a refusal. A refusal that cannot be journaled is still a
    /// refusal, so a write failure here is not an error of its own.
    fn refused(
        &mut self,
        surface: ActionSurface,
        caller: &str,
        ip: IpAddr,
        reason: &str,
        now_unix: u64,
    ) {
        self.flush_folds(now_unix);
        // Bounded like the rate limits: past that many distinct callers and
        // reasons this minute, the rest are counted under one key.
        let key = if self.folds.len() < MAX_TRACKED {
            (caller.to_string(), reason.to_string())
        } else {
            ("(others)".to_string(), reason.to_string())
        };
        if let Some(n) = self.folds.get_mut(&key) {
            *n += 1;
            return;
        }
        self.folds.insert(key, 0);
        let _ = self.write(
            "action_refused",
            serde_json::json!({
                "surface": surface.name(), "caller": caller, "address": ip.to_string(),
                "reason": reason, "at": now_unix,
            }),
        );
    }

    /// Journal what TFPS said and turn it into the answer.
    fn finish(
        &mut self,
        id: &str,
        reply: Result<TfpsReply, String>,
    ) -> Result<ActionDone, ActionError> {
        let (result, detail) = match &reply {
            Ok(TfpsReply::Applied) => ("applied", None),
            Ok(TfpsReply::Refused(why)) => ("refused", Some(why.clone())),
            Err(e) => ("failed", Some(e.clone())),
        };
        self.write(
            "action_outcome",
            serde_json::json!({ "id": id, "result": result, "detail": detail }),
        )?;
        match reply {
            Ok(TfpsReply::Applied) => Ok(ActionDone {
                id: id.to_string(),
                applied: true,
                refused: None,
            }),
            Ok(TfpsReply::Refused(why)) => Ok(ActionDone {
                id: id.to_string(),
                applied: false,
                refused: Some(why),
            }),
            Err(e) => Err(ActionError::Tfps(e)),
        }
    }
}

/// What TFPS's list says about `address`.
fn view_of(list: &[(Ipv4Addr, Option<u64>)], address: &str) -> TfpsView {
    match address.parse::<Ipv4Addr>() {
        Ok(ip) => list
            .iter()
            .find(|(a, _)| *a == ip)
            .map_or(TfpsView::Absent, |(_, expires)| TfpsView::Banned {
                expires: *expires,
            }),
        Err(_) => TfpsView::Absent,
    }
}
