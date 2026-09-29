// SPDX-License-Identifier: MIT OR Apache-2.0

//! Actions: the only things sipnab does that change another system.
//!
//! sipnab publishes what it saw to destinations the operator names, and it
//! asks read-only questions. Changing another system -- asking TFPS to ban a
//! source, say -- is an ACTION, and none is enabled unless the operator
//! enables it, per target and per surface: `--allow-action tfps:rest,mcp`, or
//! `[actions] tfps = ["rest", "mcp"]` in the config file.
//!
//! The gate is a type, as the kill path's is ([`super::transmit_guard`]).
//! [`ActionPermit`] has a private field, so the only way to hold one is
//! [`ActionPolicy::permit`], and the functions that act take one. A new caller
//! cannot act without asking the policy; there is no code path to forget.

use std::fmt;

#[cfg(all(unix, any(feature = "api", feature = "mcp")))]
mod service;
#[cfg(all(unix, any(feature = "api", feature = "mcp")))]
pub use service::{
    ActionDone, ActionError, ActionService, PreviousRun, ReconcileReport, RevertFailure,
    RevertReport, RevertTarget, Reverter, StartReport, TfpsActions, TfpsCtl, TfpsReply,
};

/// A system sipnab can act on, when enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionTarget {
    /// TFPS, through its `tfps_ctl` program: ban and unban.
    Tfps,
}

impl ActionTarget {
    /// Every target, in the spelling the flag and the config file use.
    pub const ALL: [ActionTarget; 1] = [ActionTarget::Tfps];

    /// The flag and config spelling.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ActionTarget::Tfps => "tfps",
        }
    }

    /// The target the flag or config spelling `s` names, if any.
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == s)
    }
}

/// Where an action is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionSurface {
    /// The REST API.
    Rest,
    /// The MCP server, where an AI agent is the caller.
    Mcp,
}

impl ActionSurface {
    /// Every surface, in the spelling the flag and the config file use.
    pub const ALL: [ActionSurface; 2] = [ActionSurface::Rest, ActionSurface::Mcp];

    /// The flag and config spelling.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ActionSurface::Rest => "rest",
            ActionSurface::Mcp => "mcp",
        }
    }

    /// The surface the flag or config spelling `s` names, if any.
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == s)
    }
}

/// Proof that the policy enabled one action on one surface.
///
/// The private field is the guarantee: nothing outside this module can build
/// one, so a function that takes one cannot be reached without the check.
#[derive(Debug)]
pub struct ActionPermit(());

/// Why an action was refused, worded for the operator who will read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRefusal {
    /// What was asked for.
    pub target: ActionTarget,
    /// Where.
    pub surface: ActionSurface,
}

impl fmt::Display for ActionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (t, s) = (self.target.name(), self.surface.name());
        write!(
            f,
            "{t} actions are not enabled for {s}: sipnab changes no external \
             system unless the operator enables it. Start sipnab with \
             --allow-action {t}:{s}, or add {t} = [\"{s}\"] under [actions] in \
             the config file."
        )
    }
}

/// How the journal names a caller that presented a credential: `token:<id>`
/// for a token with an id, `token` for one without (a static key).
///
/// The id comes from a signed claim that puts no length on it, so it is kept
/// to its first 64 characters and a cut is marked, as the MCP audit line
/// does. The credential itself never reaches a caller name.
#[must_use]
pub fn token_caller(id: Option<&str>) -> String {
    /// Characters of the id kept.
    const CAP: usize = 64;
    match id {
        None => "token".to_string(),
        Some(id) => {
            let kept: String = id.chars().take(CAP).collect();
            if id.chars().count() > CAP {
                format!("token:{kept}…(truncated)")
            } else {
                format!("token:{kept}")
            }
        }
    }
}

/// What this run may do to other systems, and the service that does it.
///
/// The policy says which target may be asked from which surface; the service,
/// present whenever the policy enables anything, is the one path an action
/// takes: rules, rate limits, the journal, then the target. A policy that
/// enables something with no service behind it acts on nothing.
#[derive(Clone, Default)]
pub struct Actions {
    /// Which actions are enabled, and from where.
    policy: ActionPolicy,
    /// The service every enabled action goes through.
    #[cfg(all(unix, any(feature = "api", feature = "mcp")))]
    service: Option<std::sync::Arc<ActionService>>,
}

impl std::fmt::Debug for Actions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Actions")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl From<ActionPolicy> for Actions {
    /// The policy alone, with no service: nothing it enables can act.
    fn from(policy: ActionPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }
}

impl Actions {
    /// `policy`, acted on through `service`.
    #[cfg(all(unix, any(feature = "api", feature = "mcp")))]
    #[must_use]
    pub fn with_service(policy: ActionPolicy, service: std::sync::Arc<ActionService>) -> Self {
        Self {
            policy,
            service: Some(service),
        }
    }

    /// The policy.
    #[must_use]
    pub fn policy(&self) -> &ActionPolicy {
        &self.policy
    }

    /// The service, when this run has one.
    #[cfg(all(unix, any(feature = "api", feature = "mcp")))]
    #[must_use]
    pub fn service(&self) -> Option<&std::sync::Arc<ActionService>> {
        self.service.as_ref()
    }

    /// Stop admitting actions and journal the stop if that needs no wait;
    /// see [`ActionService::stop`]. Nothing to do without a service.
    pub fn stop(&self, now_unix: u64) {
        #[cfg(all(unix, any(feature = "api", feature = "mcp")))]
        if let Some(service) = &self.service {
            let _ = service.stop(now_unix);
        }
        #[cfg(not(all(unix, any(feature = "api", feature = "mcp"))))]
        let _ = now_unix;
    }

    /// [`ActionPolicy::permit`].
    ///
    /// # Errors
    ///
    /// [`ActionRefusal`] when the operator did not enable this pair.
    pub fn permit(
        &self,
        target: ActionTarget,
        surface: ActionSurface,
    ) -> Result<ActionPermit, ActionRefusal> {
        self.policy.permit(target, surface)
    }

    /// [`ActionPolicy::any_on`].
    #[must_use]
    pub fn any_on(&self, surface: ActionSurface) -> bool {
        self.policy.any_on(surface)
    }

    /// [`ActionPolicy::targets_on`].
    #[must_use]
    pub fn targets_on(&self, surface: ActionSurface) -> Vec<&'static str> {
        self.policy.targets_on(surface)
    }
}

/// Which actions this run may take, and from where. Empty by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionPolicy {
    /// Each enabled pair, once.
    enabled: Vec<(ActionTarget, ActionSurface)>,
}

impl ActionPolicy {
    /// A permit for `target` on `surface`, or the refusal naming how to enable it.
    ///
    /// # Errors
    ///
    /// [`ActionRefusal`] when the operator did not enable this pair.
    pub fn permit(
        &self,
        target: ActionTarget,
        surface: ActionSurface,
    ) -> Result<ActionPermit, ActionRefusal> {
        if self.enabled.contains(&(target, surface)) {
            Ok(ActionPermit(()))
        } else {
            Err(ActionRefusal { target, surface })
        }
    }

    /// Whether nothing at all is enabled: sipnab changes no other system.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.enabled.is_empty()
    }

    /// Whether anything at all is enabled on `surface`.
    #[must_use]
    pub fn any_on(&self, surface: ActionSurface) -> bool {
        self.enabled.iter().any(|(_, s)| *s == surface)
    }

    /// The targets enabled on `surface`, by name, for a handshake or a banner.
    #[must_use]
    pub fn targets_on(&self, surface: ActionSurface) -> Vec<&'static str> {
        ActionTarget::ALL
            .into_iter()
            .filter(|t| self.enabled.contains(&(*t, surface)))
            .map(ActionTarget::name)
            .collect()
    }

    /// Enable `target` on each of `surfaces`.
    pub fn enable(&mut self, target: ActionTarget, surfaces: &[ActionSurface]) {
        for s in surfaces {
            if !self.enabled.contains(&(target, *s)) {
                self.enabled.push((target, *s));
            }
        }
    }

    /// Build the policy from `--allow-action` values and the `[actions]`
    /// table, which add together.
    ///
    /// # Errors
    ///
    /// A message naming the bad value, when a target or surface is unknown.
    /// An unknown name is refused rather than read as "nothing enabled",
    /// because the operator meant something by it.
    pub fn from_settings(flags: &[String], table: &[(&str, &[String])]) -> Result<Self, String> {
        let mut policy = Self::default();
        for value in flags {
            let (target, surfaces) = parse_flag(value)?;
            policy.enable(target, &surfaces);
        }
        for &(target, surfaces) in table {
            let t = ActionTarget::parse(target)
                .ok_or_else(|| format!("[actions] {target}: {}", unknown_target(target)))?;
            let s = surfaces
                .iter()
                .map(|s| {
                    ActionSurface::parse(s)
                        .ok_or_else(|| format!("[actions] {target}: {}", unknown_surface(s)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            policy.enable(t, &s);
        }
        Ok(policy)
    }
}

/// The message for a target name sipnab does not know, listing the ones it does.
fn unknown_target(t: &str) -> String {
    let known: Vec<_> = ActionTarget::ALL.iter().map(|t| t.name()).collect();
    format!("unknown action target {t:?}; known: {}", known.join(", "))
}

/// The message for a surface name sipnab does not know, listing the ones it does.
fn unknown_surface(s: &str) -> String {
    let known: Vec<_> = ActionSurface::ALL.iter().map(|s| s.name()).collect();
    format!("unknown surface {s:?}; known: {}", known.join(", "))
}

/// Parse one `--allow-action TARGET:SURFACE[,SURFACE]` value.
///
/// # Errors
///
/// A message naming the flag and what was wrong.
pub fn parse_flag(value: &str) -> Result<(ActionTarget, Vec<ActionSurface>), String> {
    let (target, surfaces) = value.split_once(':').ok_or_else(|| {
        format!(
            "--allow-action {value:?}: expected TARGET:SURFACE[,SURFACE], \
             e.g. tfps:rest or tfps:rest,mcp"
        )
    })?;
    let t = ActionTarget::parse(target)
        .ok_or_else(|| format!("--allow-action {value:?}: {}", unknown_target(target)))?;
    let s = surfaces
        .split(',')
        .map(|s| {
            ActionSurface::parse(s)
                .ok_or_else(|| format!("--allow-action {value:?}: {}", unknown_surface(s)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((t, s))
}

/// The action rate limits: always on, and separate from the read limits.
///
/// Three limits, each counted per minute and none of which can be set to
/// zero: actions across the whole server, actions from one caller, and one
/// action per address per cooldown, so an address cannot be banned and
/// unbanned in a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionLimits {
    /// Actions per minute across the server.
    per_minute: u64,
    /// Actions per minute from one caller.
    per_caller_per_minute: u64,
    /// How long one address rests between actions.
    address_cooldown: std::time::Duration,
    /// Lifetime of a ban whose caller gave none, in seconds.
    default_ban_secs: u64,
    /// Longest ban sipnab asks for, in seconds.
    max_ban_secs: u64,
}

impl Default for ActionLimits {
    /// 10 a minute for the server, 5 for one caller, 60 s per address; bans
    /// last an hour unless asked otherwise, and 7 days at most.
    fn default() -> Self {
        Self {
            per_minute: 10,
            per_caller_per_minute: 5,
            address_cooldown: std::time::Duration::from_secs(60),
            default_ban_secs: 3_600,
            max_ban_secs: 7 * 86_400,
        }
    }
}

impl ActionLimits {
    /// Limits of the operator's choosing.
    ///
    /// # Errors
    ///
    /// A message when any limit is zero, which would turn it off, or when the
    /// per-caller limit exceeds the server's and so could never apply.
    pub fn new(
        per_minute: u64,
        per_caller_per_minute: u64,
        address_cooldown: std::time::Duration,
    ) -> Result<Self, String> {
        if per_minute == 0 || per_caller_per_minute == 0 || address_cooldown.is_zero() {
            return Err(
                "action rate limits cannot be turned off: every limit must be at least 1"
                    .to_string(),
            );
        }
        if per_caller_per_minute > per_minute {
            return Err(format!(
                "the per caller action limit ({per_caller_per_minute}) is above the server's \
                 ({per_minute}), so it could never apply"
            ));
        }
        Ok(Self {
            per_minute,
            per_caller_per_minute,
            address_cooldown,
            ..Self::default()
        })
    }

    /// These limits with bans lasting `default_secs` unless asked otherwise,
    /// and `max_secs` at most.
    ///
    /// # Errors
    ///
    /// A message when either is zero, or the default is over the maximum.
    pub fn with_ban_lifetimes(self, default_secs: u64, max_secs: u64) -> Result<Self, String> {
        if default_secs == 0 || max_secs == 0 {
            return Err(
                "ban lifetimes cannot be turned off: both must be at least 1 second".to_string(),
            );
        }
        if default_secs > max_secs {
            return Err(format!(
                "the default ban lifetime ({default_secs} s) is over the maximum ({max_secs} s)"
            ));
        }
        Ok(Self {
            default_ban_secs: default_secs,
            max_ban_secs: max_secs,
            ..self
        })
    }

    /// Lifetime of a ban whose caller gave none, in seconds.
    #[must_use]
    pub fn default_ban_secs(&self) -> u64 {
        self.default_ban_secs
    }

    /// Longest ban sipnab asks for, in seconds.
    #[must_use]
    pub fn max_ban_secs(&self) -> u64 {
        self.max_ban_secs
    }

    /// Actions per minute across the server.
    #[must_use]
    pub fn per_minute(&self) -> u64 {
        self.per_minute
    }

    /// Actions per minute from one caller.
    #[must_use]
    pub fn per_caller_per_minute(&self) -> u64 {
        self.per_caller_per_minute
    }

    /// How long an address rests after an action on it.
    #[must_use]
    pub fn address_cooldown(&self) -> std::time::Duration {
        self.address_cooldown
    }
}

/// Why an action was throttled, and when to try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionThrottle {
    /// The server's actions for this minute are spent.
    ServerWide {
        /// Until the minute ends.
        retry_after: std::time::Duration,
    },
    /// This caller's actions for this minute are spent.
    PerCaller {
        /// Until the minute ends.
        retry_after: std::time::Duration,
    },
    /// This address was acted on within its cooldown.
    Address {
        /// Until the cooldown ends.
        retry_after: std::time::Duration,
    },
    /// More distinct callers or addresses this minute than are tracked.
    ///
    /// Refused rather than admitted: an untracked newcomer let through is
    /// exactly the many-source flood the per-caller limit exists to resist.
    TooManyCallers,
}

impl ActionThrottle {
    /// When to try again; for [`Self::TooManyCallers`], a minute.
    #[must_use]
    pub fn retry_after(&self) -> std::time::Duration {
        match self {
            Self::ServerWide { retry_after }
            | Self::PerCaller { retry_after }
            | Self::Address { retry_after } => *retry_after,
            Self::TooManyCallers => std::time::Duration::from_secs(60),
        }
    }
}

impl fmt::Display for ActionThrottle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.retry_after().as_secs().max(1);
        match self {
            Self::ServerWide { .. } => {
                write!(
                    f,
                    "this server's actions for the minute are spent; retry in {secs} s"
                )
            }
            Self::PerCaller { .. } => {
                write!(
                    f,
                    "this caller's actions for the minute are spent; retry in {secs} s"
                )
            }
            Self::Address { .. } => write!(
                f,
                "this address was acted on moments ago; it rests for the cooldown, retry in {secs} s"
            ),
            Self::TooManyCallers => write!(
                f,
                "too many distinct callers or addresses this minute; retry in {secs} s"
            ),
        }
    }
}

/// Counts actions against [`ActionLimits`].
///
/// The clock belongs to the caller, as it does for [`crate::rate_limit`]:
/// every decision takes `now`, so a test steps across a minute without
/// sleeping.
#[cfg(any(feature = "api", feature = "mcp"))]
#[derive(Debug)]
pub struct ActionGovernor {
    /// The limits it enforces.
    limits: ActionLimits,
    /// Per-minute windows: the server's, and one per caller.
    windows: crate::rate_limit::FixedWindowLimiter<String>,
    /// When each address was last acted on.
    cooldowns: std::collections::HashMap<std::net::IpAddr, std::time::Instant>,
    /// How many callers and addresses it remembers at most.
    max_tracked: usize,
}

#[cfg(any(feature = "api", feature = "mcp"))]
impl ActionGovernor {
    /// A governor whose first minute starts at `now`, tracking at most
    /// `max_tracked` callers and as many addresses.
    #[must_use]
    pub fn new(limits: ActionLimits, max_tracked: usize, now: std::time::Instant) -> Self {
        Self {
            limits,
            windows: crate::rate_limit::FixedWindowLimiter::new(
                limits.per_minute,
                limits.per_caller_per_minute,
                max_tracked,
            )
            .with_window(std::time::Duration::from_secs(60))
            .starting_at(now),
            cooldowns: std::collections::HashMap::new(),
            max_tracked,
        }
    }

    /// Admit one action by `caller` on `address` at `now`, or say why not.
    ///
    /// The address cooldown is checked first, so a refused retry spends none
    /// of the caller's allowance; the minute's counters are spent only by an
    /// action that is admitted or over its limit already.
    ///
    /// # Errors
    ///
    /// The [`ActionThrottle`] that stopped it.
    pub fn admit(
        &mut self,
        caller: &str,
        address: std::net::IpAddr,
        now: std::time::Instant,
    ) -> Result<(), ActionThrottle> {
        let cooldown = self.limits.address_cooldown;
        if let Some(at) = self.cooldowns.get(&address) {
            let since = now.saturating_duration_since(*at);
            if since < cooldown {
                return Err(ActionThrottle::Address {
                    retry_after: cooldown - since,
                });
            }
        }
        if self.cooldowns.len() >= self.max_tracked && !self.cooldowns.contains_key(&address) {
            self.cooldowns
                .retain(|_, at| now.saturating_duration_since(*at) < cooldown);
            if self.cooldowns.len() >= self.max_tracked {
                return Err(ActionThrottle::TooManyCallers);
            }
        }
        self.windows
            .check(caller.to_string(), now)
            .map_err(|refusal| {
                let retry_after = self.windows.retry_after(now);
                match refusal {
                    crate::rate_limit::Refusal::PerPeer => {
                        ActionThrottle::PerCaller { retry_after }
                    }
                    crate::rate_limit::Refusal::Global => {
                        ActionThrottle::ServerWide { retry_after }
                    }
                    crate::rate_limit::Refusal::TrackingFull => ActionThrottle::TooManyCallers,
                }
            })?;
        self.cooldowns.insert(address, now);
        Ok(())
    }

    /// Callers tracked in the current minute.
    #[must_use]
    pub fn tracked_callers(&self) -> usize {
        self.windows.tracked_peers()
    }

    /// Addresses tracked for their cooldown.
    #[must_use]
    pub fn tracked_addresses(&self) -> usize {
        self.cooldowns.len()
    }
}

/// Why an address or a lifetime may not be asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanRule {
    /// 0.0.0.0.
    Unspecified,
    /// 255.255.255.255.
    Broadcast,
    /// 127.0.0.0/8.
    Loopback,
    /// 224.0.0.0/4.
    Multicast,
    /// TFPS bans IPv4 addresses only.
    NotIpv4,
    /// A ban with no expiry.
    Forever,
    /// A ban longer than the maximum.
    TooLong {
        /// The maximum, in seconds.
        max_secs: u64,
    },
}

impl fmt::Display for BanRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "the unspecified address 0.0.0.0 is never banned"),
            Self::Broadcast => write!(f, "the broadcast address is never banned"),
            Self::Loopback => write!(f, "a loopback address is never banned"),
            Self::Multicast => write!(f, "a multicast address is never banned"),
            Self::NotIpv4 => write!(f, "TFPS bans IPv4 addresses only"),
            Self::Forever => write!(
                f,
                "every ban sipnab asks for must expire; give ttl_secs, or leave it out for an hour"
            ),
            Self::TooLong { max_secs } => write!(
                f,
                "a ban may last at most {max_secs} s; ask for less, or ask again when it expires"
            ),
        }
    }
}

/// Whether `ip` may be the subject of a ban at all.
///
/// Some addresses are never a source to block: banning them would harm the
/// network rather than an attacker, whoever asked for it.
///
/// # Errors
///
/// The [`BanRule`] the address breaks.
pub fn check_ban_address(ip: std::net::IpAddr) -> Result<(), BanRule> {
    let std::net::IpAddr::V4(v4) = ip else {
        return Err(BanRule::NotIpv4);
    };
    if v4.is_unspecified() {
        Err(BanRule::Unspecified)
    } else if v4.is_broadcast() {
        Err(BanRule::Broadcast)
    } else if v4.is_loopback() {
        Err(BanRule::Loopback)
    } else if v4.is_multicast() {
        Err(BanRule::Multicast)
    } else {
        Ok(())
    }
}

/// The lifetime to ask TFPS for, from what the caller asked for.
///
/// Every ban expires: `None` becomes the default, `0` ("forever") is refused,
/// and anything over the maximum is refused rather than trimmed, because a
/// ban for a time nobody asked for is not the caller's decision.
///
/// # Errors
///
/// [`BanRule::Forever`] or [`BanRule::TooLong`].
pub fn ban_ttl(requested: Option<u64>, limits: &ActionLimits) -> Result<u64, BanRule> {
    match requested {
        None => Ok(limits.default_ban_secs),
        Some(0) => Err(BanRule::Forever),
        Some(s) if s > limits.max_ban_secs => Err(BanRule::TooLong {
            max_secs: limits.max_ban_secs,
        }),
        Some(s) => Ok(s),
    }
}
