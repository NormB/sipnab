// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Which relay engine to ask about a call, chosen from the call's SDP.
//!
//! Several relay engines can sit behind one SIP proxy. The proxy picks one per
//! call and can move a call to another engine mid-call. Each engine writes its
//! own media address into the SDP it rewrites, so the SDP sipnab captured says
//! which engine carries the call's media. The engine's control address is a
//! different address, usually internal, and never appears in SIP.
//!
//! # SDP is untrusted input
//!
//! A captured SDP body is written by whoever sent the message. sipnab never
//! sends a control query to an address taken from SDP unless the operator
//! allowed it, in one of two ways:
//!
//! - **An engine map** ([`EngineMap`]): rows of SDP media address plus port
//!   range, each naming a control address. The map is the allowlist. An SDP
//!   address and port with no row is reported as an unknown engine and is not
//!   asked.
//! - **Trusted SDP addresses** ([`EngineRule::TrustSdp`]): the operator states
//!   that the SDP media address IS the engine's control host and names the
//!   control port, which never appears in SIP. sipnab then sends control
//!   queries to whatever address a captured SDP names. It exists for a network
//!   where the operator controls every SDP writer; the risk is the operator's.
//!
//! # Which SDP address belongs to the engine
//!
//! A call through an anchoring relay carries four kinds of SDP: each party's
//! own body, and the relay's rewrite of it toward the other party. Measured on
//! `tests/fixtures/opensips-proxy-signaling.pcap`, the caller's INVITE names
//! the caller (`198.51.100.21:6000`), the INVITE the proxy forwards names the
//! relay (`198.51.100.10:30020`), the callee's 200 names the callee
//! (`198.51.100.20:6000`), and the 200 the proxy forwards names the relay again
//! (`198.51.100.10:30018`). The relay's address is the one that travels both
//! ways: in a request and in a response. Each party's own address travels one
//! way only.
//!
//! - With a map, a sighting belongs to an engine when a row matches it. The
//!   parties' addresses match no row.
//! - Trusting SDP, an address belongs to an engine only when it was seen in
//!   both a request and a response of the call. One-sided evidence is not
//!   enough: it is what a party's own address looks like.
//!
//! The engine of the newest such sighting is the call's current engine. The
//! newest sighting of a different engine before it is the previous engine, for
//! a call a re-INVITE moved.
//!
//! # What this module does not do
//!
//! It chooses; it never transmits. [`select`] is a pure function of the rule,
//! the default engine and the sightings. [`EngineRouting`] turns a choice into
//! a relay to ask through a constructor the composition root hands it, so this
//! module names no relay implementation.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::relay::reconcile::ReadOnlyRelay;
use crate::sip::sdp_timeline::SdpExchange;

/// One row of the engine map: SDP media address and port range, to the
/// engine's control address.
///
/// `Debug` writes the row as an operator writes it, `EngineRow("203.0.113.5
/// 30000-39999 192.0.2.5:2223")`, so a parsed command line shows the row it
/// was given.
#[derive(Clone, PartialEq, Eq)]
pub struct EngineRow {
    /// The media address the engine writes into SDP.
    pub media: IpAddr,
    /// The media ports the engine allocates from, both ends included.
    pub ports: RangeInclusive<u16>,
    /// Where the engine answers control queries.
    pub control: SocketAddr,
}

/// Why an engine row or map was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineMapError {
    /// The row does not have the `MEDIA LOW-HIGH CONTROL` shape.
    #[error(
        "engine row {row:?} is not `MEDIA-ADDRESS LOW-HIGH CONTROL-ADDRESS:PORT`, \
         for example `203.0.113.5 30000-39999 192.0.2.5:2223`"
    )]
    Shape {
        /// The row as given.
        row: String,
    },
    /// The media address is not an IP address.
    #[error("engine row {row:?}: {value:?} is not an IP address")]
    Media {
        /// The row as given.
        row: String,
        /// The field that did not parse.
        value: String,
    },
    /// The port range does not parse, starts at 0, or runs backwards.
    #[error(
        "engine row {row:?}: {value:?} is not a port range LOW-HIGH with \
         1 <= LOW <= HIGH <= 65535"
    )]
    Ports {
        /// The row as given.
        row: String,
        /// The field that did not parse.
        value: String,
    },
    /// The control address is not an address and port.
    #[error(
        "engine row {row:?}: {value:?} is not a control address and port \
         (an IPv6 address is written [2001:db8::5]:2223)"
    )]
    Control {
        /// The row as given.
        row: String,
        /// The field that did not parse.
        value: String,
    },
    /// Two rows claim the same media address and port.
    #[error(
        "engine rows {first:?} and {second:?} overlap: both claim media \
         {media} port {port}, so a call there has no single engine"
    )]
    Overlap {
        /// The earlier row.
        first: String,
        /// The later row.
        second: String,
        /// The shared media address.
        media: IpAddr,
        /// The lowest port both claim.
        port: u16,
    },
}

impl fmt::Display for EngineRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}-{} {}",
            self.media,
            self.ports.start(),
            self.ports.end(),
            self.control
        )
    }
}

impl fmt::Debug for EngineRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EngineRow").field(&self.to_string()).finish()
    }
}

impl FromStr for EngineRow {
    type Err = EngineMapError;

    /// Parse `MEDIA LOW-HIGH CONTROL`, with an optional `->` before
    /// `CONTROL`, fields separated by white space.
    fn from_str(row: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = row.split_whitespace().collect();
        let (media, ports, control) = match fields.as_slice() {
            [media, ports, control] => (*media, *ports, *control),
            [media, ports, "->", control] => (*media, *ports, *control),
            _ => {
                return Err(EngineMapError::Shape {
                    row: row.to_string(),
                });
            }
        };
        let media = media.parse::<IpAddr>().map_err(|_| EngineMapError::Media {
            row: row.to_string(),
            value: media.to_string(),
        })?;
        let bad_ports = || EngineMapError::Ports {
            row: row.to_string(),
            value: ports.to_string(),
        };
        let (low, high) = ports.split_once('-').ok_or_else(bad_ports)?;
        let low = low.parse::<u16>().map_err(|_| bad_ports())?;
        let high = high.parse::<u16>().map_err(|_| bad_ports())?;
        if low == 0 || low > high {
            return Err(bad_ports());
        }
        let control = control
            .parse::<SocketAddr>()
            .map_err(|_| EngineMapError::Control {
                row: row.to_string(),
                value: control.to_string(),
            })?;
        Ok(Self {
            media,
            ports: low..=high,
            control,
        })
    }
}

/// The operator's engine map: the allowlist of engines sipnab may ask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineMap {
    /// The rows, in the order given.
    rows: Vec<EngineRow>,
}

impl EngineMap {
    /// Build a map, refusing rows that overlap.
    ///
    /// Two rows overlap when they name the same media address and their port
    /// ranges share a port. Such a sighting would have two engines, and
    /// choosing either one silently is the failure the map exists to prevent.
    ///
    /// # Errors
    ///
    /// [`EngineMapError::Overlap`], naming both rows.
    pub fn new(rows: Vec<EngineRow>) -> Result<Self, EngineMapError> {
        for (i, first) in rows.iter().enumerate() {
            for second in &rows[i + 1..] {
                if canonical(first.media) != canonical(second.media) {
                    continue;
                }
                let low = (*first.ports.start()).max(*second.ports.start());
                let high = (*first.ports.end()).min(*second.ports.end());
                if low <= high {
                    return Err(EngineMapError::Overlap {
                        first: first.to_string(),
                        second: second.to_string(),
                        media: first.media,
                        port: low,
                    });
                }
            }
        }
        Ok(Self { rows })
    }

    /// The rows, in the order given.
    #[must_use]
    pub fn rows(&self) -> &[EngineRow] {
        &self.rows
    }

    /// The row that claims `media` and `port`, if one does.
    #[must_use]
    pub fn row_for(&self, media: IpAddr, port: u16) -> Option<&EngineRow> {
        let media = canonical(media);
        self.rows
            .iter()
            .find(|r| canonical(r.media) == media && r.ports.contains(&port))
    }

    /// Every distinct control address, in row order.
    #[must_use]
    pub fn controls(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for row in &self.rows {
            if !out.contains(&row.control) {
                out.push(row.control);
            }
        }
        out
    }
}

/// How a call's engine is chosen from its SDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineRule {
    /// Only an engine a map row names is asked.
    Map(EngineMap),
    /// The SDP media address is the engine's control host, on this port.
    TrustSdp {
        /// The control port, which never appears in SIP.
        control_port: u16,
    },
}

/// The run's engine rule and whether a moved call's previous engine is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSelection {
    /// How a call's engine is chosen.
    pub rule: EngineRule,
    /// Whether a moved call's previous engine is asked too.
    pub previous: bool,
}

/// One SDP media address and port sipnab saw for a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpSighting {
    /// When the message carrying the SDP was captured.
    pub at: DateTime<Utc>,
    /// Whether a request carried it, rather than a response.
    pub from_request: bool,
    /// The effective `c=` address of the first media description, as written.
    pub address: String,
    /// The first media description's port.
    pub port: u16,
}

impl SdpSighting {
    /// The address and port as one string, as an operator reads it.
    #[must_use]
    pub fn endpoint(&self) -> String {
        match self.address.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) => format!("[{v6}]:{}", self.port),
            _ => format!("{}:{}", self.address, self.port),
        }
    }
}

/// The sightings a dialog's SDP timeline holds, oldest first.
///
/// An exchange with no media address or port (a REFER marker, an SDP with no
/// `m=` line) and a port of 0 (a rejected stream) carry no media endpoint and
/// are left out.
#[must_use]
pub fn sightings(timeline: &[SdpExchange]) -> Vec<SdpSighting> {
    timeline
        .iter()
        .filter_map(|e| match (&e.media_addr, e.media_port) {
            (Some(address), Some(port)) if port != 0 => Some(SdpSighting {
                at: e.timestamp,
                from_request: e.from_request,
                address: address.clone(),
                port,
            }),
            _ => None,
        })
        .collect()
}

/// Why an engine was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChosenBy {
    /// No engine rule is configured: the one engine the run names.
    NoRule,
    /// A rule is configured, but sipnab has seen no SDP for the call, so the
    /// run's default engine is asked.
    NoSdpSeen,
    /// No SDP is seen for the call, and this engine's `list` names it.
    Listed,
    /// A map row matched an SDP sighting.
    MapRow {
        /// The SDP media address and port that matched.
        media: String,
        /// The row that matched.
        row: EngineRow,
    },
    /// The SDP media address was seen both ways and is trusted as the
    /// engine's control host.
    SdpAddress {
        /// The SDP media address and port.
        media: String,
    },
}

/// One engine to ask, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engine {
    /// Where the engine answers control queries.
    pub control: SocketAddr,
    /// Why this engine.
    pub chosen_by: ChosenBy,
}

impl Engine {
    /// The reason, as words an operator reads, or `None` for [`ChosenBy::NoRule`],
    /// whose answer reads exactly as it did before engine selection existed.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match &self.chosen_by {
            ChosenBy::NoRule => None,
            ChosenBy::NoSdpSeen => Some(format!(
                "the default engine ({}): sipnab has seen no SDP for this call",
                crate::cli::RELAY_CONTROL_FLAG
            )),
            ChosenBy::Listed => Some(
                "sipnab has seen no SDP for this call; this engine's list names it".to_string(),
            ),
            ChosenBy::MapRow { media, row } => {
                Some(format!("chosen by engine row {row} for SDP media {media}"))
            }
            ChosenBy::SdpAddress { media } => Some(format!(
                "chosen from SDP media {media}, trusted as the engine's address"
            )),
        }
    }

    /// The JSON spelling of [`Self::chosen_by`]: `no_rule`, `default`,
    /// `listed`, `map_row` or `sdp_address`.
    #[must_use]
    pub const fn chosen_by_word(&self) -> &'static str {
        match self.chosen_by {
            ChosenBy::NoRule => "no_rule",
            ChosenBy::NoSdpSeen => "default",
            ChosenBy::Listed => "listed",
            ChosenBy::MapRow { .. } => "map_row",
            ChosenBy::SdpAddress { .. } => "sdp_address",
        }
    }
}

/// Why no engine can be asked about a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unknown {
    /// The call's SDP names media no map row claims.
    NoMapRow {
        /// Every SDP media address and port seen for the call, oldest first.
        seen: Vec<String>,
    },
    /// Trusting SDP, no address was seen both in a request and a response.
    NotSeenBothWays {
        /// Every SDP media address and port seen for the call, oldest first.
        seen: Vec<String>,
    },
}

impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMapRow { seen } => write!(
                f,
                "engine unknown (no map row): no engine row claims the call's SDP \
                 media {}; nothing was asked",
                seen.join(", ")
            ),
            Self::NotSeenBothWays { seen } => write!(
                f,
                "engine unknown (no address seen both ways): none of the call's SDP \
                 media {} was seen in both a request and a response, so none is the \
                 relay's; nothing was asked",
                seen.join(", ")
            ),
        }
    }
}

/// The engines to ask about one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEngines {
    /// The engine the newest SDP names, or why there is none.
    pub current: Result<Engine, Unknown>,
    /// The engine the SDP named before the call moved, when it moved.
    pub previous: Option<Engine>,
}

/// Choose the engines to ask about one call.
///
/// `rule` is the operator's engine rule, `None` when none is configured.
/// `default` is the engine the run names for questions not about one call.
/// `sightings` are the call's SDP media endpoints, in any order.
///
/// - No rule: `default`, as before engine selection existed.
/// - No sighting: `default`, saying the call's SDP was not seen.
/// - A map: the engine of the newest sighting a row claims; none claimed is
///   [`Unknown::NoMapRow`], and `default` is not asked.
/// - Trusting SDP: the newest sighting of an address seen both in a request and
///   a response, at the trusted control port; none is
///   [`Unknown::NotSeenBothWays`].
///
/// `previous` is the engine of the newest engine sighting older than the
/// current one whose control address differs.
#[must_use]
pub fn select(
    rule: Option<&EngineRule>,
    default: SocketAddr,
    sightings: &[SdpSighting],
) -> CallEngines {
    select_listed(rule, default, sightings, &[])
}

/// [`select`], knowing which engines' `list` named the call, in listing
/// order.
///
/// Only a call with no SDP sighting reads `listed`: the first engine whose
/// list names it is asked, rather than the default, because sipnab may ask it
/// (it was listed, so the operator named it) and it holds the call. SDP, when
/// there is some, outranks a list.
#[must_use]
pub fn select_listed(
    rule: Option<&EngineRule>,
    default: SocketAddr,
    sightings: &[SdpSighting],
    listed: &[SocketAddr],
) -> CallEngines {
    let Some(rule) = rule else {
        return CallEngines {
            current: Ok(Engine {
                control: default,
                chosen_by: ChosenBy::NoRule,
            }),
            previous: None,
        };
    };
    if sightings.is_empty() {
        let current = match listed.first() {
            Some(&control) => Engine {
                control,
                chosen_by: ChosenBy::Listed,
            },
            None => Engine {
                control: default,
                chosen_by: ChosenBy::NoSdpSeen,
            },
        };
        return CallEngines {
            current: Ok(current),
            previous: None,
        };
    }
    let mut sorted: Vec<&SdpSighting> = sightings.iter().collect();
    // Stable, so two sightings captured in the same instant keep the order the
    // dialog store recorded them in.
    sorted.sort_by_key(|s| s.at);

    // Each sighting that belongs to an engine, oldest first.
    let engines: Vec<Engine> = match rule {
        EngineRule::Map(map) => sorted
            .iter()
            .filter_map(|s| {
                let ip = s.address.parse::<IpAddr>().ok()?;
                let row = map.row_for(ip, s.port)?;
                Some(Engine {
                    control: row.control,
                    chosen_by: ChosenBy::MapRow {
                        media: s.endpoint(),
                        row: row.clone(),
                    },
                })
            })
            .collect(),
        EngineRule::TrustSdp { control_port } => {
            let ips = |from_request: bool| -> BTreeSet<IpAddr> {
                sorted
                    .iter()
                    .filter(|s| s.from_request == from_request)
                    .filter_map(|s| s.address.parse::<IpAddr>().ok().map(canonical))
                    .collect()
            };
            let both_ways: BTreeSet<IpAddr> =
                ips(true).intersection(&ips(false)).copied().collect();
            sorted
                .iter()
                .filter_map(|s| {
                    let ip = canonical(s.address.parse::<IpAddr>().ok()?);
                    both_ways.contains(&ip).then(|| Engine {
                        control: SocketAddr::new(ip, *control_port),
                        chosen_by: ChosenBy::SdpAddress {
                            media: s.endpoint(),
                        },
                    })
                })
                .collect()
        }
    };

    let Some(current) = engines.last().cloned() else {
        let seen = seen(&sorted);
        return CallEngines {
            current: Err(match rule {
                EngineRule::Map(_) => Unknown::NoMapRow { seen },
                EngineRule::TrustSdp { .. } => Unknown::NotSeenBothWays { seen },
            }),
            previous: None,
        };
    };
    let previous = engines
        .iter()
        .rev()
        .find(|e| e.control != current.control)
        .cloned();
    CallEngines {
        current: Ok(current),
        previous,
    }
}

/// A call's SDP sightings by Call-ID, read where the dialog store is: a
/// surface that asks on a worker thread hands one in.
pub type SdpLookup = Arc<dyn Fn(&str) -> Vec<SdpSighting> + Send + Sync>;

/// Builds the relay client for a control address.
///
/// Handed in by the composition root, which is the only layer that may name a
/// relay implementation; a test hands in a scripted relay.
pub type Connect = Arc<dyn Fn(SocketAddr) -> Arc<dyn ReadOnlyRelay + Send + Sync> + Send + Sync>;

/// The run's engine rule, and how to reach an engine it chooses.
#[derive(Clone)]
pub struct EngineRouting {
    /// The operator's rule.
    rule: EngineRule,
    /// The engine named by the run's single relay control address.
    default: SocketAddr,
    /// Whether to ask the previous engine of a moved call too.
    previous: bool,
    /// How to reach an engine.
    connect: Connect,
}

impl fmt::Debug for EngineRouting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineRouting")
            .field("rule", &self.rule)
            .field("default", &self.default)
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}

impl EngineRouting {
    /// Routing for `rule`, with `default` as the run's default engine.
    #[must_use]
    pub fn new(rule: EngineRule, default: SocketAddr, previous: bool, connect: Connect) -> Self {
        Self {
            rule,
            default,
            previous,
            connect,
        }
    }

    /// The operator's rule.
    #[must_use]
    pub const fn rule(&self) -> &EngineRule {
        &self.rule
    }

    /// The run's default engine.
    #[must_use]
    pub const fn default_engine(&self) -> SocketAddr {
        self.default
    }

    /// Whether the previous engine of a moved call is asked too.
    #[must_use]
    pub const fn asks_previous(&self) -> bool {
        self.previous
    }

    /// The engines for one call, by [`select`].
    #[must_use]
    pub fn select(&self, sightings: &[SdpSighting]) -> CallEngines {
        select(Some(&self.rule), self.default, sightings)
    }

    /// The engines for one call, by [`select_listed`].
    #[must_use]
    pub fn select_listed(&self, sightings: &[SdpSighting], listed: &[SocketAddr]) -> CallEngines {
        select_listed(Some(&self.rule), self.default, sightings, listed)
    }

    /// A relay client for `control`.
    #[must_use]
    pub fn relay(&self, control: SocketAddr) -> Arc<dyn ReadOnlyRelay + Send + Sync> {
        (self.connect)(control)
    }

    /// The engines a question about which calls are held is put to: the
    /// default engine, then every other control address the map names.
    ///
    /// Trusting SDP names no engine in advance, so only the default is listed:
    /// a `list` is never sent to an address learned from SDP.
    #[must_use]
    pub fn listing_engines(&self) -> Vec<SocketAddr> {
        let mut out = vec![self.default];
        if let EngineRule::Map(map) = &self.rule {
            for control in map.controls() {
                if !out.contains(&control) {
                    out.push(control);
                }
            }
        }
        out
    }
}

/// The SDP sightings sipnab holds for `call_id`: none when the dialog store
/// does not hold the call.
#[must_use]
pub fn call_sightings(
    store: &crate::sip::dialog_store::DialogStore,
    call_id: &str,
) -> Vec<SdpSighting> {
    store
        .get(call_id)
        .map(|d| sightings(&d.sdp_timeline))
        .unwrap_or_default()
}

/// The relay to put one call's question to.
pub enum CallTarget {
    /// Ask this relay.
    Ask {
        /// The relay to ask.
        relay: Arc<dyn ReadOnlyRelay + Send + Sync>,
        /// Its control address, when engine selection chose it; `None` for
        /// the run's one relay with no engine rule.
        control: Option<SocketAddr>,
        /// Why this engine, or `None` when no engine rule is configured, so
        /// the answer reads exactly as it did before engine selection.
        reason: Option<String>,
    },
    /// No engine may be asked, and why.
    Unknown(Unknown),
}

impl fmt::Debug for CallTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ask {
                control, reason, ..
            } => f
                .debug_struct("Ask")
                .field("control", control)
                .field("reason", reason)
                .finish_non_exhaustive(),
            Self::Unknown(u) => f.debug_tuple("Unknown").field(u).finish(),
        }
    }
}

/// Which relay answers a question about one call, the one rule every surface
/// uses.
///
/// `default` is the relay the run names. Without `routing` it is the answer,
/// as before engine selection existed. With `routing`, [`select`] chooses from `sightings`; the default
/// engine is `default` itself, and any other engine is reached through the
/// routing's constructor.
#[must_use]
pub fn call_target(
    default: &Arc<dyn ReadOnlyRelay + Send + Sync>,
    routing: Option<&EngineRouting>,
    sightings: &[SdpSighting],
) -> CallTarget {
    let Some(routing) = routing else {
        return CallTarget::Ask {
            relay: Arc::clone(default),
            control: None,
            reason: None,
        };
    };
    match routing.select(sightings).current {
        Ok(engine) => CallTarget::Ask {
            relay: if engine.control == routing.default_engine() {
                Arc::clone(default)
            } else {
                routing.relay(engine.control)
            },
            control: Some(engine.control),
            reason: engine.reason(),
        },
        Err(unknown) => CallTarget::Unknown(unknown),
    }
}

/// The canonical form of an address, so `::ffff:203.0.113.5` and
/// `203.0.113.5` compare equal.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// The distinct sightings' endpoints, oldest first, for an unknown-engine
/// message.
fn seen(sorted: &[&SdpSighting]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in sorted {
        let e = s.endpoint();
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// A dialog store holding one call whose messages carry SDP naming each
/// `(from_request, address, port)` in turn: an INVITE for a request, a 200
/// for a response, a second apart. For the tests of every surface that picks
/// an engine from SDP.
///
/// # Errors
///
/// When a built message does not parse.
#[cfg(test)]
pub(crate) fn store_with_call(
    call_id: &str,
    sdp: &[(bool, &str, u16)],
) -> Result<crate::sip::dialog_store::DialogStore, Box<dyn std::error::Error>> {
    use chrono::TimeZone;
    let mut store = crate::sip::dialog_store::DialogStore::new(16, false);
    let host = IpAddr::from([192, 0, 2, 30]);
    for (i, (from_request, address, port)) in sdp.iter().enumerate() {
        let family = if address.contains(':') { "IP6" } else { "IP4" };
        let body = format!(
            "v=0\r\no=- 0 0 IN {family} {address}\r\ns=-\r\nc=IN {family} {address}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=sendrecv\r\n"
        );
        let cseq = i + 1;
        let start = if *from_request {
            "INVITE sip:callee@example.invalid SIP/2.0".to_string()
        } else {
            "SIP/2.0 200 OK".to_string()
        };
        let raw = crate::test_utils::build_sip_message(
            &start,
            &[
                &format!("Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-{cseq}"),
                "From: <sip:caller@example.invalid>;tag=f1",
                "To: <sip:callee@example.invalid>;tag=t1",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq} INVITE"),
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", body.len()),
            ],
            body.as_bytes(),
        );
        let when = Utc
            .timestamp_opt(1_793_800_000 + i64::try_from(i)?, 0)
            .single()
            .ok_or("a fixed instant")?;
        store.process_message(crate::sip::parser::parse_sip(
            &raw,
            when,
            host,
            host,
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )?);
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    type TestError = Box<dyn std::error::Error>;

    fn at(secs: i64) -> Result<DateTime<Utc>, TestError> {
        Ok(Utc
            .timestamp_opt(1_793_800_000 + secs, 0)
            .single()
            .ok_or("a fixed instant")?)
    }

    fn sight(
        secs: i64,
        from_request: bool,
        address: &str,
        port: u16,
    ) -> Result<SdpSighting, TestError> {
        Ok(SdpSighting {
            at: at(secs)?,
            from_request,
            address: address.to_string(),
            port,
        })
    }

    fn addr(s: &str) -> Result<SocketAddr, TestError> {
        Ok(s.parse()?)
    }

    fn map(rows: &[&str]) -> Result<EngineMap, TestError> {
        let rows = rows
            .iter()
            .map(|r| r.parse::<EngineRow>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EngineMap::new(rows)?)
    }

    /// The SDP of `tests/fixtures/opensips-proxy-signaling.pcap`, as the
    /// dialog store records it: the caller's INVITE, the INVITE the proxy
    /// forwarded, the callee's 200 and the 200 the proxy forwarded.
    /// `fixture_sightings_are_the_ones_the_capture_carries` reads them from
    /// the capture itself.
    fn fixture_call() -> Result<Vec<SdpSighting>, TestError> {
        Ok(vec![
            sight(0, true, "198.51.100.21", 6000)?,
            sight(1, true, "198.51.100.10", 30020)?,
            sight(2, false, "198.51.100.20", 6000)?,
            sight(3, false, "198.51.100.10", 30018)?,
        ])
    }

    /// The issue's NAT example: two engines behind one public address,
    /// told apart by port range.
    const NAT_ROWS: [&str; 2] = [
        "203.0.113.5 30000-39999 -> 192.0.2.5:2223",
        "203.0.113.5 40000-49999 -> 192.0.2.6:2223",
    ];

    const DEFAULT: &str = "192.0.2.1:2223";

    // ── rows ──────────────────────────────────────────────────────────

    #[test]
    fn a_row_parses_with_or_without_the_arrow() -> Result<(), TestError> {
        let plain: EngineRow = "203.0.113.5 30000-39999 192.0.2.5:2223".parse()?;
        let arrow: EngineRow = "203.0.113.5  30000-39999  ->  192.0.2.5:2223".parse()?;
        assert_eq!(plain, arrow, "a row parses with or without the arrow");
        assert_eq!(
            plain.media,
            "203.0.113.5".parse::<IpAddr>()?,
            "a row parses with or without the arrow"
        );
        assert_eq!(
            plain.ports,
            30000..=39999,
            "a row parses with or without the arrow"
        );
        assert_eq!(
            plain.control,
            addr("192.0.2.5:2223")?,
            "a row parses with or without the arrow"
        );
        assert_eq!(
            plain.to_string(),
            "203.0.113.5 30000-39999 192.0.2.5:2223",
            "a row parses with or without the arrow"
        );
        Ok(())
    }

    #[test]
    fn a_row_takes_ipv6_and_a_one_port_range() -> Result<(), TestError> {
        let row: EngineRow = "2001:db8::5 40000-40000 [2001:db8::10]:2223".parse()?;
        assert_eq!(
            row.media,
            "2001:db8::5".parse::<IpAddr>()?,
            "a row takes ipv6 and a one port range"
        );
        assert_eq!(
            row.ports,
            40000..=40000,
            "a row takes ipv6 and a one port range"
        );
        assert_eq!(
            row.control,
            addr("[2001:db8::10]:2223")?,
            "a row takes ipv6 and a one port range"
        );
        Ok(())
    }

    #[test]
    fn a_malformed_row_is_refused_naming_the_field() -> Result<(), TestError> {
        let refused = |row: &str| row.parse::<EngineRow>().err();
        assert!(
            matches!(
                refused("203.0.113.5 30000-39999"),
                Some(EngineMapError::Shape { .. })
            ),
            "a malformed row is refused naming the field"
        );
        assert!(
            matches!(
                refused("203.0.113.5 30000-39999 => 192.0.2.5:2223"),
                Some(EngineMapError::Shape { .. })
            ),
            "a malformed row is refused naming the field"
        );
        assert!(
            matches!(
                refused("engine.example.com 30000-39999 192.0.2.5:2223"),
                Some(EngineMapError::Media { .. })
            ),
            "a malformed row is refused naming the field"
        );
        assert!(
            matches!(
                refused("203.0.113.5 39999-30000 192.0.2.5:2223"),
                Some(EngineMapError::Ports { .. })
            ),
            "a malformed row is refused naming the field"
        );
        assert!(
            matches!(
                refused("203.0.113.5 0-10 192.0.2.5:2223"),
                Some(EngineMapError::Ports { .. })
            ),
            "a malformed row is refused naming the field"
        );
        assert!(
            matches!(
                refused("203.0.113.5 30000 192.0.2.5:2223"),
                Some(EngineMapError::Ports { .. })
            ),
            "a malformed row is refused naming the field"
        );
        assert!(
            matches!(
                refused("203.0.113.5 30000-39999 192.0.2.5"),
                Some(EngineMapError::Control { .. })
            ),
            "a malformed row is refused naming the field"
        );
        Ok(())
    }

    // ── the map ───────────────────────────────────────────────────────

    #[test]
    fn a_port_finds_its_row_at_both_range_edges() -> Result<(), TestError> {
        let m = map(&NAT_ROWS)?;
        let ip: IpAddr = "203.0.113.5".parse()?;
        let control = |port| m.row_for(ip, port).map(|r| r.control.to_string());
        assert_eq!(
            control(30000).as_deref(),
            Some("192.0.2.5:2223"),
            "a port finds its row at both range edges"
        );
        assert_eq!(
            control(39999).as_deref(),
            Some("192.0.2.5:2223"),
            "a port finds its row at both range edges"
        );
        assert_eq!(
            control(40000).as_deref(),
            Some("192.0.2.6:2223"),
            "a port finds its row at both range edges"
        );
        assert_eq!(
            control(49999).as_deref(),
            Some("192.0.2.6:2223"),
            "a port finds its row at both range edges"
        );
        assert_eq!(control(29999), None, "one below the first range");
        assert_eq!(control(50000), None, "one above the last range");
        Ok(())
    }

    #[test]
    fn an_ipv4_mapped_sighting_matches_its_ipv4_row() -> Result<(), TestError> {
        let m = map(&NAT_ROWS)?;
        let mapped: IpAddr = "::ffff:203.0.113.5".parse()?;
        assert_eq!(
            m.row_for(mapped, 30000).map(|r| r.control),
            Some(addr("192.0.2.5:2223")?),
            "an ipv4 mapped sighting matches its ipv4 row"
        );
        Ok(())
    }

    #[test]
    fn another_address_finds_no_row() -> Result<(), TestError> {
        let m = map(&NAT_ROWS)?;
        assert_eq!(
            m.row_for("203.0.113.6".parse()?, 30000),
            None,
            "another address finds no row"
        );
        Ok(())
    }

    #[test]
    fn overlapping_rows_are_refused_naming_the_shared_port() -> Result<(), TestError> {
        let rows = vec![
            "203.0.113.5 30000-40000 192.0.2.5:2223".parse::<EngineRow>()?,
            "203.0.113.5 40000-49999 192.0.2.6:2223".parse::<EngineRow>()?,
        ];
        match EngineMap::new(rows) {
            Err(EngineMapError::Overlap { port, .. }) => assert_eq!(
                port, 40000,
                "overlapping rows are refused naming the shared port"
            ),
            other => return Err(format!("expected an overlap, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn one_range_on_two_addresses_does_not_overlap() -> Result<(), TestError> {
        let m = map(&[
            "203.0.113.5 30000-39999 192.0.2.5:2223",
            "203.0.113.6 30000-39999 192.0.2.6:2223",
        ])?;
        assert_eq!(
            m.rows().len(),
            2,
            "one range on two addresses does not overlap"
        );
        Ok(())
    }

    // ── the timeline ──────────────────────────────────────────────────

    /// One captured UDP datagram: when, from where, to where, and its bytes.
    struct Frame {
        when: DateTime<Utc>,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        payload: Vec<u8>,
    }

    /// The UDP payloads of a classic little-endian Ethernet/IPv4 capture, with
    /// each frame's time and addresses.
    fn udp_frames(bytes: &[u8]) -> Result<Vec<Frame>, TestError> {
        let u32_at = |b: &[u8], i: usize| -> Result<u32, TestError> {
            let s = b.get(i..i + 4).ok_or("short capture")?;
            Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        };
        let mut out = Vec::new();
        let mut at_byte = 24;
        while at_byte < bytes.len() {
            let secs = i64::from(u32_at(bytes, at_byte)?);
            let micros = i64::from(u32_at(bytes, at_byte + 4)?);
            let len = usize::try_from(u32_at(bytes, at_byte + 8)?)?;
            let frame = bytes
                .get(at_byte + 16..at_byte + 16 + len)
                .ok_or("short record")?;
            at_byte += 16 + len;
            let ip = frame.get(14..).ok_or("no IP header")?;
            let ihl = usize::from(ip.first().ok_or("empty IP")? & 0x0f) * 4;
            let quad = |i: usize| -> Result<IpAddr, TestError> {
                let s = ip.get(i..i + 4).ok_or("short IP header")?;
                Ok(IpAddr::from([s[0], s[1], s[2], s[3]]))
            };
            let udp = ip.get(ihl..).ok_or("no UDP header")?;
            let port = |i: usize| -> Result<u16, TestError> {
                let s = udp.get(i..i + 2).ok_or("short UDP header")?;
                Ok(u16::from_be_bytes([s[0], s[1]]))
            };
            let when = Utc
                .timestamp_opt(secs, u32::try_from(micros * 1000)?)
                .single()
                .ok_or("a frame time")?;
            out.push(Frame {
                when,
                src: quad(12)?,
                dst: quad(16)?,
                sport: port(0)?,
                dport: port(2)?,
                payload: udp.get(8..).ok_or("no payload")?.to_vec(),
            });
        }
        Ok(out)
    }

    /// The four SDP sightings [`fixture_call`] states are the ones the proxy
    /// capture carries, read through the dialog store as a live run reads
    /// them: none is folded away as a retransmission, and each knows whether a
    /// request carried it.
    #[test]
    fn fixture_sightings_are_the_ones_the_capture_carries() -> Result<(), TestError> {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/opensips-proxy-signaling.pcap"),
        )?;
        let mut store = crate::sip::dialog_store::DialogStore::new(16, false);
        for f in udp_frames(&bytes)? {
            let msg = crate::sip::parser::parse_sip(
                &f.payload,
                f.when,
                f.src,
                f.dst,
                f.sport,
                f.dport,
                crate::net::TransportProto::Udp,
            )?;
            store.process_message(msg);
        }
        let dialog = store
            .get("1-4062@198.51.100.21")
            .ok_or("the fixture's one call")?;
        let got: Vec<(bool, String, u16)> = sightings(&dialog.sdp_timeline)
            .into_iter()
            .map(|s| (s.from_request, s.address, s.port))
            .collect();
        let want: Vec<(bool, String, u16)> = fixture_call()?
            .into_iter()
            .map(|s| (s.from_request, s.address, s.port))
            .collect();
        assert_eq!(
            got, want,
            "fixture sightings are the ones the capture carries"
        );
        Ok(())
    }

    #[test]
    fn sightings_skip_exchanges_with_no_media_endpoint() -> Result<(), TestError> {
        use crate::sip::sdp_timeline::OfferAnswer;
        let exchange = |addr: Option<&str>,
                        port: Option<u16>,
                        from_request|
         -> Result<SdpExchange, TestError> {
            Ok(SdpExchange {
                timestamp: at(0)?,
                direction: OfferAnswer::Offer,
                from_request,
                codecs: Vec::new(),
                media_addr: addr.map(str::to_string),
                media_port: port,
                mode: "sendrecv".to_string(),
                is_t38: false,
                event: None,
            })
        };
        let got = sightings(&[
            exchange(Some("198.51.100.10"), Some(30020), true)?,
            exchange(None, None, true)?,
            exchange(Some("198.51.100.10"), Some(0), false)?,
            exchange(Some("198.51.100.10"), Some(30018), false)?,
        ]);
        assert_eq!(
            got,
            vec![
                sight(0, true, "198.51.100.10", 30020)?,
                sight(0, false, "198.51.100.10", 30018)?,
            ],
            "sightings skip exchanges with no media endpoint"
        );
        Ok(())
    }

    // ── selection ─────────────────────────────────────────────────────

    #[test]
    fn no_rule_asks_the_default_engine_as_before() -> Result<(), TestError> {
        let got = select(None, addr(DEFAULT)?, &fixture_call()?);
        assert_eq!(
            got.current,
            Ok(Engine {
                control: addr(DEFAULT)?,
                chosen_by: ChosenBy::NoRule
            }),
            "no rule asks the default engine as before"
        );
        assert_eq!(
            got.previous, None,
            "no rule asks the default engine as before"
        );
        Ok(())
    }

    #[test]
    fn no_sdp_seen_asks_the_default_engine_and_says_why() -> Result<(), TestError> {
        let rule = EngineRule::Map(map(&NAT_ROWS)?);
        let got = select(Some(&rule), addr(DEFAULT)?, &[]);
        assert_eq!(
            got.current,
            Ok(Engine {
                control: addr(DEFAULT)?,
                chosen_by: ChosenBy::NoSdpSeen
            }),
            "no sdp seen asks the default engine and says why"
        );
        let trusting = EngineRule::TrustSdp { control_port: 2223 };
        assert_eq!(
            select(Some(&trusting), addr(DEFAULT)?, &[])
                .current
                .map(|e| e.chosen_by),
            Ok(ChosenBy::NoSdpSeen),
            "no sdp seen asks the default engine and says why"
        );
        Ok(())
    }

    /// With no SDP seen, an engine whose list names the call is asked
    /// rather than the default; SDP, when there is some, outranks the lists.
    #[test]
    fn with_no_sdp_the_engine_that_lists_the_call_is_asked() -> Result<(), TestError> {
        let rule = EngineRule::Map(map(&NAT_ROWS)?);
        let b = addr("192.0.2.6:2223")?;
        let got = select_listed(Some(&rule), addr(DEFAULT)?, &[], &[b]);
        assert_eq!(
            got.current,
            Ok(Engine {
                control: b,
                chosen_by: ChosenBy::Listed
            }),
            "with no sdp the engine that lists the call is asked"
        );
        assert_eq!(
            select_listed(Some(&rule), addr(DEFAULT)?, &[], &[])
                .current
                .map(|e| e.chosen_by),
            Ok(ChosenBy::NoSdpSeen),
            "with no sdp the engine that lists the call is asked"
        );
        let moved = select_listed(Some(&rule), addr(DEFAULT)?, &moved_call()?, &[b]);
        assert!(
            matches!(
                moved.current,
                Ok(Engine {
                    chosen_by: ChosenBy::MapRow { .. },
                    ..
                })
            ),
            "SDP outranks a list: {:?}",
            moved.current
        );
        assert_eq!(
            select_listed(None, addr(DEFAULT)?, &[], &[b])
                .current
                .map(|e| e.control),
            Ok(addr(DEFAULT)?),
            "no rule asks the default whatever lists it"
        );
        Ok(())
    }

    #[test]
    fn a_map_row_picks_the_engine_and_not_a_party() -> Result<(), TestError> {
        let rule = EngineRule::Map(map(&["198.51.100.10 30000-39999 192.0.2.50:2223"])?);
        let got = select(Some(&rule), addr(DEFAULT)?, &fixture_call()?);
        let engine = got.current.map_err(|u| u.to_string())?;
        assert_eq!(
            engine.control,
            addr("192.0.2.50:2223")?,
            "a map row picks the engine and not a party"
        );
        match &engine.chosen_by {
            ChosenBy::MapRow { media, .. } => assert_eq!(
                media, "198.51.100.10:30018",
                "a map row picks the engine and not a party"
            ),
            other => return Err(format!("expected a map row, got {other:?}").into()),
        }
        assert_eq!(got.previous, None, "one engine, so nothing moved");
        Ok(())
    }

    #[test]
    fn no_map_row_is_unknown_and_never_the_default() -> Result<(), TestError> {
        let rule = EngineRule::Map(map(&NAT_ROWS)?);
        let got = select(Some(&rule), addr(DEFAULT)?, &fixture_call()?);
        assert_eq!(
            got.current,
            Err(Unknown::NoMapRow {
                seen: vec![
                    "198.51.100.21:6000".to_string(),
                    "198.51.100.10:30020".to_string(),
                    "198.51.100.20:6000".to_string(),
                    "198.51.100.10:30018".to_string(),
                ]
            }),
            "no map row is unknown and never the default"
        );
        let words = got.current.err().map(|u| u.to_string()).unwrap_or_default();
        assert!(words.starts_with("engine unknown (no map row)"), "{words}");
        Ok(())
    }

    /// The issue's moved call: the first exchange on the engine at 30000-39999,
    /// a re-INVITE later moves it to the engine at 40000-49999.
    fn moved_call() -> Result<Vec<SdpSighting>, TestError> {
        Ok(vec![
            sight(0, true, "192.0.2.21", 6000)?,
            sight(1, true, "203.0.113.5", 30010)?,
            sight(2, false, "192.0.2.20", 6000)?,
            sight(3, false, "203.0.113.5", 30012)?,
            sight(60, true, "192.0.2.21", 6000)?,
            sight(61, true, "203.0.113.5", 40010)?,
            sight(62, false, "192.0.2.20", 6000)?,
            sight(63, false, "203.0.113.5", 40012)?,
        ])
    }

    #[test]
    fn a_moved_call_names_its_current_and_previous_engine() -> Result<(), TestError> {
        let rule = EngineRule::Map(map(&NAT_ROWS)?);
        let got = select(Some(&rule), addr(DEFAULT)?, &moved_call()?);
        assert_eq!(
            got.current.map(|e| e.control),
            Ok(addr("192.0.2.6:2223")?),
            "a moved call names its current and previous engine"
        );
        assert_eq!(
            got.previous.map(|e| e.control),
            Some(addr("192.0.2.5:2223")?),
            "a moved call names its current and previous engine"
        );
        Ok(())
    }

    #[test]
    fn selection_orders_sightings_by_time_not_by_arrival() -> Result<(), TestError> {
        let rule = EngineRule::Map(map(&NAT_ROWS)?);
        let mut shuffled = moved_call()?;
        shuffled.reverse();
        let got = select(Some(&rule), addr(DEFAULT)?, &shuffled);
        assert_eq!(
            got.current.map(|e| e.control),
            Ok(addr("192.0.2.6:2223")?),
            "selection orders sightings by time not by arrival"
        );
        assert_eq!(
            got.previous.map(|e| e.control),
            Some(addr("192.0.2.5:2223")?),
            "selection orders sightings by time not by arrival"
        );
        Ok(())
    }

    #[test]
    fn trusting_sdp_picks_the_address_seen_both_ways() -> Result<(), TestError> {
        let rule = EngineRule::TrustSdp { control_port: 2223 };
        let got = select(Some(&rule), addr(DEFAULT)?, &fixture_call()?);
        let engine = got.current.map_err(|u| u.to_string())?;
        assert_eq!(
            engine.control,
            addr("198.51.100.10:2223")?,
            "trusting sdp picks the address seen both ways"
        );
        assert_eq!(
            engine.chosen_by,
            ChosenBy::SdpAddress {
                media: "198.51.100.10:30018".to_string()
            },
            "trusting sdp picks the address seen both ways"
        );
        Ok(())
    }

    #[test]
    fn trusting_sdp_reads_a_delayed_offer_and_ipv6() -> Result<(), TestError> {
        let rule = EngineRule::TrustSdp { control_port: 2223 };
        // Delayed offer: the 200s carry the offers, the ACKs the answers.
        let calls = vec![
            sight(0, false, "2001:db8::20", 6000)?,
            sight(1, false, "2001:db8::10", 30018)?,
            sight(2, true, "2001:db8::21", 6000)?,
            sight(3, true, "2001:db8::10", 30020)?,
        ];
        let got = select(Some(&rule), addr(DEFAULT)?, &calls);
        assert_eq!(
            got.current.map(|e| e.control),
            Ok(addr("[2001:db8::10]:2223")?),
            "trusting sdp reads a delayed offer and ipv6"
        );
        Ok(())
    }

    #[test]
    fn trusting_sdp_asks_nothing_on_one_sided_evidence() -> Result<(), TestError> {
        let rule = EngineRule::TrustSdp { control_port: 2223 };
        // An unanchored call: each party's own address, one way each.
        let calls = vec![
            sight(0, true, "198.51.100.21", 6000)?,
            sight(1, false, "198.51.100.20", 6000)?,
        ];
        let got = select(Some(&rule), addr(DEFAULT)?, &calls);
        assert!(
            matches!(got.current, Err(Unknown::NotSeenBothWays { .. })),
            "{:?}",
            got.current
        );
        Ok(())
    }

    #[test]
    fn trusting_sdp_names_the_previous_engine_of_a_moved_call() -> Result<(), TestError> {
        let rule = EngineRule::TrustSdp { control_port: 2223 };
        let calls = vec![
            sight(0, true, "203.0.113.5", 30010)?,
            sight(1, false, "203.0.113.5", 30012)?,
            sight(60, true, "203.0.113.6", 30010)?,
            sight(61, false, "203.0.113.6", 30012)?,
        ];
        let got = select(Some(&rule), addr(DEFAULT)?, &calls);
        assert_eq!(
            got.current.map(|e| e.control),
            Ok(addr("203.0.113.6:2223")?),
            "trusting sdp names the previous engine of a moved call"
        );
        assert_eq!(
            got.previous.map(|e| e.control),
            Some(addr("203.0.113.5:2223")?),
            "trusting sdp names the previous engine of a moved call"
        );
        Ok(())
    }

    #[test]
    fn a_hostname_in_sdp_matches_nothing_and_is_named() -> Result<(), TestError> {
        let rule = EngineRule::TrustSdp { control_port: 2223 };
        let calls = vec![
            sight(0, true, "media.example.com", 30010)?,
            sight(1, false, "media.example.com", 30012)?,
        ];
        let got = select(Some(&rule), addr(DEFAULT)?, &calls);
        assert_eq!(
            got.current,
            Err(Unknown::NotSeenBothWays {
                seen: vec![
                    "media.example.com:30010".to_string(),
                    "media.example.com:30012".to_string()
                ]
            }),
            "a hostname in sdp matches nothing and is named"
        );
        Ok(())
    }

    // ── routing ───────────────────────────────────────────────────────

    #[test]
    fn listing_asks_the_default_then_each_mapped_engine_once() -> Result<(), TestError> {
        let connect: Connect = Arc::new(|_| unreachable_relay());
        let routing = EngineRouting::new(
            EngineRule::Map(map(&[
                "203.0.113.5 30000-39999 192.0.2.5:2223",
                "203.0.113.5 40000-49999 192.0.2.6:2223",
                "203.0.113.6 30000-39999 192.0.2.5:2223",
            ])?),
            addr("192.0.2.6:2223")?,
            false,
            connect,
        );
        assert_eq!(
            routing.listing_engines(),
            vec![addr("192.0.2.6:2223")?, addr("192.0.2.5:2223")?],
            "listing asks the default then each mapped engine once"
        );
        let trusting = EngineRouting::new(
            EngineRule::TrustSdp { control_port: 2223 },
            addr(DEFAULT)?,
            false,
            Arc::new(|_| unreachable_relay()),
        );
        assert_eq!(
            trusting.listing_engines(),
            vec![addr(DEFAULT)?],
            "listing asks the default then each mapped engine once"
        );
        Ok(())
    }

    #[test]
    fn a_call_target_without_routing_is_the_default_relay() -> Result<(), TestError> {
        let default = unreachable_relay();
        match call_target(&default, None, &fixture_call()?) {
            CallTarget::Ask {
                relay,
                control,
                reason,
            } => {
                assert!(
                    Arc::ptr_eq(&relay, &default),
                    "a call target without routing is the default relay"
                );
                assert_eq!(
                    control, None,
                    "a call target without routing is the default relay"
                );
                assert_eq!(reason, None, "the answer reads as before");
            }
            other => return Err(format!("expected the default, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_call_target_with_routing_is_the_mapped_engine_or_none() -> Result<(), TestError> {
        let default = unreachable_relay();
        let other = unreachable_relay();
        let handed = Arc::clone(&other);
        let routing = EngineRouting::new(
            EngineRule::Map(map(&NAT_ROWS)?),
            addr("192.0.2.5:2223")?,
            false,
            Arc::new(move |_| Arc::clone(&handed)),
        );
        match call_target(&default, Some(&routing), &moved_call()?) {
            CallTarget::Ask {
                relay,
                control,
                reason,
            } => {
                assert!(Arc::ptr_eq(&relay, &other), "the engine the SDP names");
                assert_eq!(
                    control,
                    Some(addr("192.0.2.6:2223")?),
                    "a call target with routing is the mapped engine or none"
                );
                assert!(
                    reason.is_some_and(|r| r.contains("40000-49999")),
                    "a call target with routing is the mapped engine or none"
                );
            }
            other => return Err(format!("expected an engine, got {other:?}").into()),
        }
        // The default engine is the relay the surface already holds.
        let first_leg: Vec<SdpSighting> = moved_call()?.into_iter().take(4).collect();
        match call_target(&default, Some(&routing), &first_leg) {
            CallTarget::Ask { relay, .. } => assert!(
                Arc::ptr_eq(&relay, &default),
                "a call target with routing is the mapped engine or none"
            ),
            other => return Err(format!("expected the default, got {other:?}").into()),
        }
        assert!(
            matches!(
                call_target(&default, Some(&routing), &fixture_call()?),
                CallTarget::Unknown(Unknown::NoMapRow { .. })
            ),
            "a call target with routing is the mapped engine or none"
        );
        Ok(())
    }

    #[test]
    fn call_sightings_read_the_dialog_store() -> Result<(), TestError> {
        let store = store_with_call(
            "s-1@example.invalid",
            &[(true, "203.0.113.5", 30010), (false, "203.0.113.5", 30012)],
        )?;
        let got: Vec<(bool, String, u16)> = call_sightings(&store, "s-1@example.invalid")
            .into_iter()
            .map(|s| (s.from_request, s.address, s.port))
            .collect();
        assert_eq!(
            got,
            [
                (true, "203.0.113.5".to_string(), 30010),
                (false, "203.0.113.5".to_string(), 30012)
            ],
            "call sightings read the dialog store"
        );
        assert!(
            call_sightings(&store, "absent@example.invalid").is_empty(),
            "call sightings read the dialog store"
        );
        Ok(())
    }

    /// A relay that is never asked: these tests only read the routing.
    fn unreachable_relay() -> Arc<dyn ReadOnlyRelay + Send + Sync> {
        struct Never;
        impl ReadOnlyRelay for Never {
            fn list(
                &self,
                _: &crate::security::transmit_guard::TransmitPermit,
                _: u32,
            ) -> anyhow::Result<crate::relay::types::ControlReply> {
                anyhow::bail!("not asked")
            }
            fn query(
                &self,
                _: &crate::security::transmit_guard::TransmitPermit,
                _: &str,
            ) -> anyhow::Result<crate::relay::types::ControlReply> {
                anyhow::bail!("not asked")
            }
            fn statistics(
                &self,
                _: &crate::security::transmit_guard::TransmitPermit,
            ) -> anyhow::Result<crate::relay::types::ControlReply> {
                anyhow::bail!("not asked")
            }
            fn describe(&self) -> String {
                "never".to_string()
            }
        }
        Arc::new(Never)
    }
}
