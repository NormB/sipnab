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
use crate::relay_vocab::{EngineIdentity, EngineSighting, EngineVerb};
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

/// One row of the ng engine map: an engine sipnab may ask, with the
/// `homer-id` its HEP copies carry when it sends them.
///
/// Written `[HOMER-ID] LISTEN-NG`, for example `2001 192.0.2.5:2223`, or
/// `192.0.2.5:2223` for an engine seen only in captured requests. An optional
/// `->` may stand before the address.
#[derive(Clone, PartialEq, Eq)]
pub struct NgEngineRow {
    /// The engine's `homer-id`, the capture id its HEP copies carry.
    pub homer_id: Option<u32>,
    /// The engine's `listen-ng` address, where it answers control queries.
    pub control: SocketAddr,
}

impl fmt::Display for NgEngineRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.homer_id {
            Some(id) => write!(f, "{id} {}", self.control),
            None => write!(f, "{}", self.control),
        }
    }
}

impl NgEngineRow {
    /// The row with `port` as its `listen-ng` port when it gave a bare
    /// address, unchanged when it named a port of its own.
    #[must_use]
    pub fn with_default_port(mut self, port: u16) -> Self {
        if self.control.port() == 0 {
            self.control.set_port(port);
        }
        self
    }

    /// The row as the command-line flag that adds it, quoted for a shell:
    /// `--rtpengine-ng-engine '2001 192.0.2.5:2223'`.
    #[must_use]
    pub fn flag_text(&self) -> String {
        format!("{} '{self}'", crate::cli::RELAY_NG_ENGINE_FLAG)
    }

    /// The row as the config-file line that adds it, for the `[relay]`
    /// section: `ng_engines = ["2001 192.0.2.5:2223"]`.
    #[must_use]
    pub fn config_line(&self) -> String {
        format!("ng_engines = [\"{self}\"]")
    }
}

/// The ng engine row that would list the engine with `homer_id`, from the
/// `listen-ng` address its HEP copy reported.
///
/// `None` when nothing was reported, or when the address is loopback or
/// unspecified: neither names an address another host can reach. The row is
/// a suggestion an operator reads. sipnab never sends to a reported address
/// until a row lists it.
#[must_use]
pub fn suggested_ng_row(homer_id: u32, reported: Option<SocketAddr>) -> Option<NgEngineRow> {
    let reported = reported?;
    let ip = canonical(reported.ip());
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(NgEngineRow {
        homer_id: Some(homer_id),
        control: SocketAddr::new(ip, reported.port()),
    })
}

/// The ng engine row that would list `engine`, an engine the traffic named
/// and no row lists.
///
/// - A HEP copy's `homer-id`: by [`suggested_ng_row`], from the `listen-ng`
///   it reported.
/// - A captured request's destination: that address, loopback included,
///   because the proxy on this host reached it.
#[must_use]
pub fn suggested_row(engine: EngineIdentity, reported: Option<SocketAddr>) -> Option<NgEngineRow> {
    match engine {
        EngineIdentity::HomerId(id) => suggested_ng_row(id, reported),
        EngineIdentity::ListenNg(sent_to) => Some(NgEngineRow {
            homer_id: None,
            control: SocketAddr::new(canonical(sent_to.ip()), sent_to.port()),
        }),
    }
}

/// [`suggested_row`] as the sentence every surface prints after `engine
/// not listed`: `To list it, add --rtpengine-ng-engine '2001 192.0.2.5:2223',
/// or ng_engines = ["2001 192.0.2.5:2223"] in the config file's [relay]
/// section`. `None` when no row is suggested.
#[must_use]
pub fn suggested_row_words(engine: EngineIdentity, reported: Option<SocketAddr>) -> Option<String> {
    suggested_row(engine, reported).map(|row| {
        format!(
            "To list it, add {}, or {} in the config file's [relay] section",
            row.flag_text(),
            row.config_line()
        )
    })
}

impl fmt::Debug for NgEngineRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NgEngineRow")
            .field(&self.to_string())
            .finish()
    }
}

/// Why an ng engine row or map was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NgEngineError {
    /// The row does not have the `[HOMER-ID] LISTEN-NG` shape.
    #[error(
        "ng engine row {row:?} is not `[HOMER-ID] LISTEN-NG-ADDRESS[:PORT]`, for \
         example `2001 192.0.2.5:2223`, `192.0.2.5:2223` or `192.0.2.5`"
    )]
    Shape {
        /// The row as given.
        row: String,
    },
    /// The `homer-id` is not a whole number from 0 to 4294967295.
    #[error("ng engine row {row:?}: {value:?} is not a homer-id (a whole number, 0 to 4294967295)")]
    HomerId {
        /// The row as given.
        row: String,
        /// The field that did not parse.
        value: String,
    },
    /// The control address is not an address and port.
    #[error(
        "ng engine row {row:?}: {value:?} is not a listen-ng address, or an \
         address and a port other than 0 (an IPv6 address with a port is \
         written [2001:db8::5]:2223)"
    )]
    Control {
        /// The row as given.
        row: String,
        /// The field that did not parse.
        value: String,
    },
    /// Two rows name the same `homer-id` or the same `listen-ng` address.
    #[error(
        "ng engine rows {first:?} and {second:?} both name {what}, so a call \
         there has no single engine"
    )]
    Duplicate {
        /// The earlier row.
        first: String,
        /// The later row.
        second: String,
        /// What both name.
        what: String,
    },
}

impl FromStr for NgEngineRow {
    type Err = NgEngineError;

    /// Parse `[HOMER-ID] [->] LISTEN-NG`, fields separated by white space.
    fn from_str(row: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = row.split_whitespace().collect();
        let (homer_id, control) = match fields.as_slice() {
            [control] | ["->", control] => (None, *control),
            [id, control] | [id, "->", control] => (Some(*id), *control),
            _ => {
                return Err(NgEngineError::Shape {
                    row: row.to_string(),
                });
            }
        };
        let homer_id = homer_id
            .map(|id| {
                id.parse::<u32>().map_err(|_| NgEngineError::HomerId {
                    row: row.to_string(),
                    value: id.to_string(),
                })
            })
            .transpose()?;
        // A bare address waits for the port of `--rtpengine-control`, which
        // `with_default_port` fills in; port 0 stands for it until then, so
        // an explicit port 0 is refused.
        let refused = || NgEngineError::Control {
            row: row.to_string(),
            value: control.to_string(),
        };
        let control = match control.parse::<SocketAddr>() {
            Ok(addr) if addr.port() == 0 => return Err(refused()),
            Ok(addr) => addr,
            Err(_) => SocketAddr::new(control.parse::<IpAddr>().map_err(|_| refused())?, 0),
        };
        Ok(Self { homer_id, control })
    }
}

/// The operator's ng engine map: the engines sipnab may ask about a call
/// whose engine it learned from ng control traffic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NgEngineMap {
    /// The rows, in the order given.
    rows: Vec<NgEngineRow>,
}

impl NgEngineMap {
    /// Build a map, refusing two rows with one `homer-id` or one address.
    ///
    /// # Errors
    ///
    /// [`NgEngineError::Duplicate`], naming both rows.
    pub fn new(rows: Vec<NgEngineRow>) -> Result<Self, NgEngineError> {
        for (i, first) in rows.iter().enumerate() {
            for second in &rows[i + 1..] {
                let what = if first.homer_id.is_some() && first.homer_id == second.homer_id {
                    first.homer_id.map(|id| format!("homer-id {id}"))
                } else if same_control(first.control, second.control) {
                    Some(format!("listen-ng {}", first.control))
                } else {
                    None
                };
                if let Some(what) = what {
                    return Err(NgEngineError::Duplicate {
                        first: first.to_string(),
                        second: second.to_string(),
                        what,
                    });
                }
            }
        }
        Ok(Self { rows })
    }

    /// The rows, in the order given.
    #[must_use]
    pub fn rows(&self) -> &[NgEngineRow] {
        &self.rows
    }

    /// Whether the map has no row.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The row naming `homer_id`, if one does.
    #[must_use]
    pub fn row_for_homer_id(&self, homer_id: u32) -> Option<&NgEngineRow> {
        self.rows.iter().find(|r| r.homer_id == Some(homer_id))
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

/// Every engine rule the run has: the SDP rule, and the ng engine map.
///
/// At least one is configured wherever a value of this type exists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineRules {
    /// How a call's engine is chosen from its SDP, when that is configured.
    pub sdp: Option<EngineRule>,
    /// The engines sipnab may ask about a call whose engine it learned from
    /// ng control traffic.
    pub ng: NgEngineMap,
}

impl From<EngineRule> for EngineRules {
    fn from(rule: EngineRule) -> Self {
        Self {
            sdp: Some(rule),
            ng: NgEngineMap::default(),
        }
    }
}

impl EngineRules {
    /// Whether sipnab may ask `control`: the run's default engine, a control
    /// address an SDP map row names, or an address an ng engine row names.
    ///
    /// An address seen only in captured traffic is none of these. Trusting
    /// SDP addresses does not extend to it: that opt-in is about SDP.
    #[must_use]
    pub fn may_ask(&self, default: SocketAddr, control: SocketAddr) -> bool {
        let listed_by_sdp = match &self.sdp {
            Some(EngineRule::Map(map)) => {
                map.controls().into_iter().any(|c| same_control(c, control))
            }
            _ => false,
        };
        same_control(default, control)
            || listed_by_sdp
            || self
                .ng
                .rows
                .iter()
                .any(|r| same_control(r.control, control))
    }
}

/// The run's engine rules and whether a moved call's previous engine is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSelection {
    /// How a call's engine is chosen.
    pub rules: EngineRules,
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

/// Everything sipnab holds that says which engine a call is on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallEvidence {
    /// The call's SDP media endpoints, oldest first.
    pub sdp: Vec<SdpSighting>,
    /// The `offer` and `delete` requests sipnab saw reach an engine.
    pub ng: Vec<EngineSighting>,
}

impl From<Vec<SdpSighting>> for CallEvidence {
    fn from(sdp: Vec<SdpSighting>) -> Self {
        Self {
            sdp,
            ng: Vec::new(),
        }
    }
}

/// What sipnab has not seen for a call that is asked of a fallback engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unseen {
    /// Only an SDP rule is configured, and the call's SDP was not seen.
    Sdp,
    /// Only an ng engine map is configured, and no `offer` was seen.
    Offer,
    /// Both are configured, and neither was seen.
    OfferOrSdp,
}

impl Unseen {
    /// The words for what was not seen.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::Sdp => "sipnab has seen no SDP for this call",
            Self::Offer => "sipnab has seen no ng offer for this call",
            Self::OfferOrSdp => "sipnab has seen neither an ng offer nor SDP for this call",
        }
    }
}

/// Why an engine was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChosenBy {
    /// No engine rule is configured: the one engine the run names.
    NoRule,
    /// A rule is configured, but sipnab has seen nothing it applies to, so
    /// the run's default engine is asked.
    NoSdpSeen(Unseen),
    /// Nothing a rule applies to is seen for the call, and this engine's
    /// `list` names it.
    Listed(Unseen),
    /// The newest `offer` sipnab saw for the call reached this engine.
    NgOffer {
        /// The engine as the traffic named it.
        engine: EngineIdentity,
        /// The ng engine row that names its control address, when one does;
        /// `None` for an address the run already names.
        row: Option<NgEngineRow>,
    },
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
            ChosenBy::NoSdpSeen(unseen) => Some(format!(
                "the default engine ({}): {}",
                crate::cli::RELAY_CONTROL_FLAG,
                unseen.words()
            )),
            ChosenBy::Listed(unseen) => {
                Some(format!("{}; this engine's list names it", unseen.words()))
            }
            ChosenBy::NgOffer { engine, row } => Some(match (engine, row) {
                (EngineIdentity::HomerId(_), Some(row)) => format!(
                    "chosen by the newest ng offer for this call, which reached {engine} \
                     (ng engine row {row})"
                ),
                (_, _) => {
                    format!("chosen by the newest ng offer for this call, which reached {engine}")
                }
            }),
            ChosenBy::MapRow { media, row } => {
                Some(format!("chosen by engine row {row} for SDP media {media}"))
            }
            ChosenBy::SdpAddress { media } => Some(format!(
                "chosen from SDP media {media}, trusted as the engine's address"
            )),
        }
    }

    /// The JSON spelling of [`Self::chosen_by`]: `no_rule`, `default`,
    /// `listed`, `ng_offer`, `map_row` or `sdp_address`.
    #[must_use]
    pub const fn chosen_by_word(&self) -> &'static str {
        match self.chosen_by {
            ChosenBy::NoRule => "no_rule",
            ChosenBy::NoSdpSeen(_) => "default",
            ChosenBy::Listed(_) => "listed",
            ChosenBy::NgOffer { .. } => "ng_offer",
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
    /// The newest `offer` reached an engine the operator has not listed.
    NgEngineNotListed {
        /// The engine as the traffic named it.
        engine: EngineIdentity,
        /// The `listen-ng` address a HEP copy reported, when it reported one.
        reported: Option<SocketAddr>,
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
            Self::NgEngineNotListed {
                engine: EngineIdentity::HomerId(id),
                reported,
            } => {
                write!(
                    f,
                    "engine not listed (homer-id {id}): the newest ng offer for this call \
                     reached homer-id {id}, and no {} row names it",
                    crate::cli::RELAY_NG_ENGINE_FLAG
                )?;
                if let Some(addr) = reported {
                    write!(f, " (the engine reports listen-ng {addr})")?;
                }
                write!(f, "; nothing was asked")?;
                if let Some(words) = suggested_row_words(EngineIdentity::HomerId(*id), *reported) {
                    write!(f, ". {words}")?;
                }
                Ok(())
            }
            Self::NgEngineNotListed {
                engine: EngineIdentity::ListenNg(addr),
                reported,
            } => {
                write!(
                    f,
                    "engine not listed ({addr}): the newest ng offer for this call was sent \
                     to {addr}, an address sipnab saw only in captured traffic; nothing was \
                     asked"
                )?;
                if let Some(words) = suggested_row_words(EngineIdentity::ListenNg(*addr), *reported)
                {
                    write!(f, ". {words}")?;
                }
                Ok(())
            }
        }
    }
}

/// An engine a call moved off without a `delete` reaching it there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leftover {
    /// The engine as the traffic named it.
    pub engine: EngineIdentity,
    /// Its control address, when sipnab may ask it.
    pub control: Option<SocketAddr>,
    /// The `listen-ng` address the engine's newest HEP copy of an `offer`
    /// reported, when it reported one. Shown, never sent to.
    pub reported: Option<SocketAddr>,
}

impl Leftover {
    /// The words every surface prints for it.
    #[must_use]
    pub fn words(&self) -> String {
        format!(
            "{} never received a delete for this call after its offer (a leftover session)",
            self.engine
        )
    }
}

/// The engines to ask about one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEngines {
    /// The engine the newest evidence names, or why there is none.
    pub current: Result<Engine, Unknown>,
    /// The engine the evidence named before the call moved, when it moved.
    pub previous: Option<Engine>,
    /// The engines the call moved off whose session no `delete` released, in
    /// the order the call left them. Only ng control traffic can say this.
    pub leftovers: Vec<Leftover>,
}

impl CallEngines {
    /// What the evidence says beyond the engine asked: each leftover
    /// session, in [`Leftover::words`]. Empty when there is none.
    #[must_use]
    pub fn notes(&self) -> Vec<String> {
        self.leftovers.iter().map(Leftover::words).collect()
    }
}

/// Choose the engines to ask about one call.
///
/// `rules` are the operator's engine rules, `None` when none is configured.
/// `default` is the engine the run names for questions not about one call.
/// `evidence` is what sipnab holds for the call, in any order.
///
/// In order of precedence:
///
/// 1. No rule: `default`, as before engine selection existed.
/// 2. An `offer` was seen reach an engine: the engine of the newest one, when
///    the operator listed it ([`EngineRules::may_ask`] for an address, an ng
///    engine row for a `homer-id`). An engine not listed is
///    [`Unknown::NgEngineNotListed`]: it is the call's engine, so no other is
///    asked in its place.
/// 3. An SDP rule and SDP sightings: by the rule, as `select_sdp` says.
/// 4. Otherwise `default`, saying what was not seen.
///
/// `previous` is the engine the call was on before it moved, when sipnab may
/// ask it. `leftovers` are the engines the call moved off that no `delete`
/// reached after their last `offer`.
#[must_use]
pub fn select(
    rules: Option<&EngineRules>,
    default: SocketAddr,
    evidence: &CallEvidence,
) -> CallEngines {
    select_listed(rules, default, evidence, &[])
}

/// [`select`], knowing which engines' `list` named the call, in listing
/// order.
///
/// Only a call with no evidence a rule applies to reads `listed`: the first
/// engine whose list names it is asked, rather than the default, because
/// sipnab may ask it (it was listed, so the operator named it) and it holds
/// the call. Evidence, when there is some, outranks a list.
#[must_use]
pub fn select_listed(
    rules: Option<&EngineRules>,
    default: SocketAddr,
    evidence: &CallEvidence,
    listed: &[SocketAddr],
) -> CallEngines {
    let Some(rules) = rules else {
        return CallEngines {
            current: Ok(Engine {
                control: default,
                chosen_by: ChosenBy::NoRule,
            }),
            previous: None,
            leftovers: Vec::new(),
        };
    };
    if let Some(chosen) = select_ng(rules, default, &evidence.ng) {
        return chosen;
    }
    let unseen = match (&rules.sdp, rules.ng.is_empty()) {
        (Some(rule), _) if !evidence.sdp.is_empty() => return select_sdp(rule, &evidence.sdp),
        (Some(_), true) => Unseen::Sdp,
        (Some(_), false) => Unseen::OfferOrSdp,
        (None, _) => Unseen::Offer,
    };
    fallback(unseen, default, listed)
}

/// The engines ng control traffic names for a call, or `None` when it saw
/// no `offer` for it.
///
/// The current engine is the one the newest `offer` reached. The previous
/// engine is the one the newest `offer` before it at another engine reached,
/// when sipnab may ask it. A leftover is each other engine that received an
/// `offer` and no `delete` at or after its last one.
fn select_ng(
    rules: &EngineRules,
    default: SocketAddr,
    sightings: &[EngineSighting],
) -> Option<CallEngines> {
    let mut offers: Vec<&EngineSighting> = sightings
        .iter()
        .filter(|s| s.verb == EngineVerb::Offer)
        .collect();
    // Stable, so two offers of one instant keep the order they were seen in.
    offers.sort_by_key(|s| s.at);
    let newest = *offers.last()?;
    let current = resolve(rules, default, newest.engine).ok_or(Unknown::NgEngineNotListed {
        engine: newest.engine,
        reported: newest.reported_listen_ng,
    });
    let previous = offers
        .iter()
        .rev()
        .find(|s| s.engine != newest.engine)
        .and_then(|s| resolve(rules, default, s.engine));
    let mut leftovers: Vec<Leftover> = Vec::new();
    for offer in &offers {
        if offer.engine == newest.engine || leftovers.iter().any(|l| l.engine == offer.engine) {
            continue;
        }
        let last_offer = offers
            .iter()
            .filter(|s| s.engine == offer.engine)
            .map(|s| s.at)
            .max()
            .unwrap_or(offer.at);
        let released = sightings.iter().any(|s| {
            s.engine == offer.engine && s.verb == EngineVerb::Delete && s.at >= last_offer
        });
        if !released {
            leftovers.push(Leftover {
                engine: offer.engine,
                control: resolve(rules, default, offer.engine).map(|e| e.control),
                reported: offers
                    .iter()
                    .rev()
                    .find(|s| s.engine == offer.engine)
                    .and_then(|s| s.reported_listen_ng),
            });
        }
    }
    Some(CallEngines {
        current,
        previous,
        leftovers,
    })
}

/// The engine sipnab may ask for `engine`, chosen by an ng offer, or `None`
/// when the operator has not listed it.
fn resolve(rules: &EngineRules, default: SocketAddr, engine: EngineIdentity) -> Option<Engine> {
    let (control, row) = match engine {
        EngineIdentity::HomerId(id) => {
            let row = rules.ng.row_for_homer_id(id)?;
            (row.control, Some(row.clone()))
        }
        EngineIdentity::ListenNg(addr) => (rules.may_ask(default, addr).then_some(addr)?, None),
    };
    Some(Engine {
        control,
        chosen_by: ChosenBy::NgOffer { engine, row },
    })
}

/// The engine asked when no evidence a rule applies to was seen: the first
/// engine whose list names the call, else the default.
fn fallback(unseen: Unseen, default: SocketAddr, listed: &[SocketAddr]) -> CallEngines {
    let current = match listed.first() {
        Some(&control) => Engine {
            control,
            chosen_by: ChosenBy::Listed(unseen),
        },
        None => Engine {
            control: default,
            chosen_by: ChosenBy::NoSdpSeen(unseen),
        },
    };
    CallEngines {
        current: Ok(current),
        previous: None,
        leftovers: Vec::new(),
    }
}

/// The engines an SDP rule names for a call with at least one SDP sighting.
///
/// - A map: the engine of the newest sighting a row claims; none claimed is
///   [`Unknown::NoMapRow`], and the default is not asked.
/// - Trusting SDP: the newest sighting of an address seen both in a request
///   and a response, at the trusted control port; none is
///   [`Unknown::NotSeenBothWays`].
///
/// `previous` is the engine of the newest engine sighting older than the
/// current one whose control address differs.
fn select_sdp(rule: &EngineRule, sightings: &[SdpSighting]) -> CallEngines {
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
            leftovers: Vec::new(),
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
        leftovers: Vec::new(),
    }
}

/// A call's evidence by Call-ID, read where the dialog store is: a surface
/// that asks on a worker thread hands one in.
pub type SdpLookup = Arc<dyn Fn(&str) -> CallEvidence + Send + Sync>;

/// Builds the relay client for a control address.
///
/// Handed in by the composition root, which is the only layer that may name a
/// relay implementation; a test hands in a scripted relay.
pub type Connect = Arc<dyn Fn(SocketAddr) -> Arc<dyn ReadOnlyRelay + Send + Sync> + Send + Sync>;

/// The run's engine rule, and how to reach an engine it chooses.
#[derive(Clone)]
pub struct EngineRouting {
    /// The operator's rules.
    rules: EngineRules,
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
            .field("rules", &self.rules)
            .field("default", &self.default)
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}

impl EngineRouting {
    /// Routing for `rules`, with `default` as the run's default engine.
    #[must_use]
    pub fn new(
        rules: impl Into<EngineRules>,
        default: SocketAddr,
        previous: bool,
        connect: Connect,
    ) -> Self {
        Self {
            rules: rules.into(),
            default,
            previous,
            connect,
        }
    }

    /// The operator's rules.
    #[must_use]
    pub const fn rules(&self) -> &EngineRules {
        &self.rules
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
    pub fn select(&self, evidence: &CallEvidence) -> CallEngines {
        select(Some(&self.rules), self.default, evidence)
    }

    /// The engines for one call, by [`select_listed`].
    #[must_use]
    pub fn select_listed(&self, evidence: &CallEvidence, listed: &[SocketAddr]) -> CallEngines {
        select_listed(Some(&self.rules), self.default, evidence, listed)
    }

    /// A relay client for `control`.
    #[must_use]
    pub fn relay(&self, control: SocketAddr) -> Arc<dyn ReadOnlyRelay + Send + Sync> {
        (self.connect)(control)
    }

    /// The engines a question about which calls are held is put to: the
    /// default engine, then every other control address the SDP map names,
    /// then every other address an ng engine row names.
    ///
    /// Trusting SDP names no engine in advance, and an address seen only in
    /// ng traffic is not listed: a `list` is never sent to an address learned
    /// from traffic.
    #[must_use]
    pub fn listing_engines(&self) -> Vec<SocketAddr> {
        let mut out = vec![self.default];
        if let Some(EngineRule::Map(map)) = &self.rules.sdp {
            for control in map.controls() {
                if !out.contains(&control) {
                    out.push(control);
                }
            }
        }
        for row in self.rules.ng.rows() {
            if !out.iter().any(|&c| same_control(c, row.control)) {
                out.push(row.control);
            }
        }
        out
    }
}

/// The evidence sipnab holds for `call_id`: its SDP sightings, none when the
/// dialog store holds no dialog for it, and the engine sightings ng control
/// traffic made, which a relay host holds with no dialog at all.
#[must_use]
pub fn call_sightings(
    store: &crate::sip::dialog_store::DialogStore,
    call_id: &str,
) -> CallEvidence {
    CallEvidence {
        sdp: store
            .get(call_id)
            .map(|d| sightings(&d.sdp_timeline))
            .unwrap_or_default(),
        ng: store.engine_sightings(call_id),
    }
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
/// as before engine selection existed. With `routing`, [`select`] chooses from
/// `evidence`; the default engine is `default` itself, and any other engine is
/// reached through the routing's constructor. The reason carries each note
/// [`CallEngines::notes`] makes, such as a leftover session.
#[must_use]
pub fn call_target(
    default: &Arc<dyn ReadOnlyRelay + Send + Sync>,
    routing: Option<&EngineRouting>,
    evidence: &CallEvidence,
) -> CallTarget {
    let Some(routing) = routing else {
        return CallTarget::Ask {
            relay: Arc::clone(default),
            control: None,
            reason: None,
        };
    };
    target(default, routing, routing.select(evidence), Vec::new())
}

/// The [`CallTarget`] for `chosen`, its reason followed by each note the
/// choice makes and then `more`.
fn target(
    default: &Arc<dyn ReadOnlyRelay + Send + Sync>,
    routing: &EngineRouting,
    chosen: CallEngines,
    more: Vec<String>,
) -> CallTarget {
    let notes: Vec<String> = chosen.notes().into_iter().chain(more).collect();
    match chosen.current {
        Ok(engine) => CallTarget::Ask {
            relay: if engine.control == routing.default_engine() {
                Arc::clone(default)
            } else {
                routing.relay(engine.control)
            },
            control: Some(engine.control),
            reason: engine.reason().map(|why| {
                std::iter::once(why)
                    .chain(notes)
                    .collect::<Vec<_>>()
                    .join("; ")
            }),
        },
        Err(unknown) => CallTarget::Unknown(unknown),
    }
}

/// Every engine the run lists, as a relay to ask, `--rtpengine-control`
/// first.
///
/// Without `routing` it is the one relay, `default`, at `default_addr`. With
/// it, each of [`EngineRouting::listing_engines`]: the default engine is
/// `default` itself, and every other engine is reached through the
/// routing's constructor. The questions not about one call that make sense
/// on every engine (startup reconciliation, the relay's own counters, the
/// lists) ask these.
#[must_use]
pub fn listed_relays(
    default: &Arc<dyn ReadOnlyRelay + Send + Sync>,
    default_addr: SocketAddr,
    routing: Option<&EngineRouting>,
) -> Vec<(SocketAddr, Arc<dyn ReadOnlyRelay + Send + Sync>)> {
    let Some(routing) = routing else {
        return vec![(default_addr, Arc::clone(default))];
    };
    routing
        .listing_engines()
        .into_iter()
        .map(|control| {
            if control == routing.default_engine() {
                (default_addr, Arc::clone(default))
            } else {
                (control, routing.relay(control))
            }
        })
        .collect()
}

/// One engine's answer to `list`, asked for a question about a call sipnab
/// has seen nothing for.
struct EngineList {
    /// The engine's control address.
    control: SocketAddr,
    /// The engine as the subject of a sentence: `rtpengine at ADDR`.
    describe: String,
    /// The Call-IDs it listed and whether it held more, or why it did not
    /// answer.
    answer: Result<crate::relay::types::Enumeration, String>,
}

/// Every listed engine's `list`, asked at most once per question.
///
/// A question about a call whose ng offer and SDP sipnab has not seen asks
/// each listed engine which calls it holds, all at once, and asks the engine
/// whose list names the call. One value lives for one question, so a question that
/// chooses an engine for several calls asks each engine once.
pub struct EngineLists<'a> {
    /// The run's permission to transmit.
    permit: &'a crate::security::transmit_guard::TransmitPermit,
    /// How many Call-IDs each `list` asks for.
    limit: u32,
    /// The answers, once asked.
    answers: std::cell::OnceCell<Vec<EngineList>>,
}

impl<'a> EngineLists<'a> {
    /// Lists not yet asked, to be asked with `permit` for up to `limit`
    /// Call-IDs each.
    #[must_use]
    pub const fn new(
        permit: &'a crate::security::transmit_guard::TransmitPermit,
        limit: u32,
    ) -> Self {
        Self {
            permit,
            limit,
            answers: std::cell::OnceCell::new(),
        }
    }
}

/// [`call_target`], and for a call sipnab has seen nothing for, the engine
/// whose `list` names it.
///
/// When no ng offer and no SDP chooses the call's engine and the routing
/// lists more than one engine, every listed engine is asked its `list`
/// through `lists` (once per question) and [`select_listed`] chooses. The
/// reason then says what the lists said: two engines that hold the call, an
/// engine that did not answer, or a capped list that may hold it.
#[must_use]
pub fn call_target_listed(
    default: &Arc<dyn ReadOnlyRelay + Send + Sync>,
    routing: Option<&EngineRouting>,
    evidence: &CallEvidence,
    call_id: &str,
    lists: &EngineLists<'_>,
) -> CallTarget {
    let Some(routing) = routing else {
        return call_target(default, None, evidence);
    };
    let chosen = routing.select(evidence);
    let unseen = matches!(
        chosen.current,
        Ok(Engine {
            chosen_by: ChosenBy::NoSdpSeen(_),
            ..
        })
    );
    let engines = routing.listing_engines();
    if !unseen || engines.len() < 2 {
        return target(default, routing, chosen, Vec::new());
    }
    let (permit, limit) = (lists.permit, lists.limit);
    let answers = lists.answers.get_or_init(|| {
        // Every engine at once: an engine that does not answer costs one
        // control timeout, not one per engine, and the notes below stay in
        // the engines' order.
        crate::relay::fan_out::ask_each(
            listed_relays(default, routing.default_engine(), Some(routing)),
            |(control, relay)| {
                let answer = match relay.list(permit, limit) {
                    Ok(crate::relay::types::ControlReply::Calls(e)) => Ok(e),
                    Ok(other) => {
                        use crate::relay::types::{ReplyKind, Unanswered};
                        match other.unanswered(ReplyKind::CallList) {
                            Some(Unanswered::Refused(reason)) => Err(format!("refused: {reason}")),
                            _ => Err(ReplyKind::CallList.wrong_kind_phrase().to_string()),
                        }
                    }
                    Err(e) => Err(format!("{e:#}")),
                };
                EngineList {
                    control,
                    describe: relay.describe(),
                    answer,
                }
            },
        )
    });
    let holders: Vec<&EngineList> = answers
        .iter()
        .filter(|l| {
            l.answer
                .as_ref()
                .is_ok_and(|e| e.call_ids.iter().any(|c| c == call_id))
        })
        .collect();
    let mut notes: Vec<String> = Vec::new();
    match holders.as_slice() {
        [] => notes.push("no engine's list names it".to_string()),
        [_] => {}
        several => notes.push(format!(
            "held by several engines: {}",
            several
                .iter()
                .map(|l| l.describe.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
    for l in answers {
        match &l.answer {
            Err(why) => notes.push(format!("{} did not answer its list ({why})", l.describe)),
            Ok(e) if e.truncated && !e.call_ids.iter().any(|c| c == call_id) => {
                notes.push(format!(
                    "the list of {} stopped at {} calls, so it may hold this call",
                    l.describe, lists.limit
                ))
            }
            Ok(_) => {}
        }
    }
    let listed: Vec<SocketAddr> = holders.iter().map(|l| l.control).collect();
    target(
        default,
        routing,
        routing.select_listed(evidence, &listed),
        notes,
    )
}

/// The canonical form of an address, so `::ffff:203.0.113.5` and
/// `203.0.113.5` compare equal.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Whether two control addresses name one socket, an IPv4-mapped address
/// and its IPv4 form alike.
fn same_control(a: SocketAddr, b: SocketAddr) -> bool {
    canonical(a.ip()) == canonical(b.ip()) && a.port() == b.port()
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

    /// [`super::select`] with an SDP rule and SDP sightings only, the form
    /// the SDP tests below are written in.
    fn sdp_select(
        rule: Option<&EngineRule>,
        default: SocketAddr,
        sightings: &[SdpSighting],
    ) -> CallEngines {
        sdp_select_listed(rule, default, sightings, &[])
    }

    /// [`super::select_listed`] with an SDP rule and SDP sightings only.
    fn sdp_select_listed(
        rule: Option<&EngineRule>,
        default: SocketAddr,
        sightings: &[SdpSighting],
        listed: &[SocketAddr],
    ) -> CallEngines {
        super::select_listed(
            rule.cloned().map(EngineRules::from).as_ref(),
            default,
            &CallEvidence::from(sightings.to_vec()),
            listed,
        )
    }

    /// [`super::call_target`] with SDP sightings only.
    fn sdp_call_target(
        default: &Arc<dyn ReadOnlyRelay + Send + Sync>,
        routing: Option<&EngineRouting>,
        sightings: &[SdpSighting],
    ) -> CallTarget {
        super::call_target(default, routing, &CallEvidence::from(sightings.to_vec()))
    }

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
        use crate::sip::sdp_timeline::{OfferAnswer, SdpSender};
        let exchange = |addr: Option<&str>,
                        port: Option<u16>,
                        from_request|
         -> Result<SdpExchange, TestError> {
            Ok(SdpExchange {
                timestamp: at(0)?,
                direction: OfferAnswer::Offer,
                from_request,
                sender: SdpSender {
                    tag: None,
                    addr: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                },
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
        let got = sdp_select(None, addr(DEFAULT)?, &fixture_call()?);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &[]);
        assert_eq!(
            got.current,
            Ok(Engine {
                control: addr(DEFAULT)?,
                chosen_by: ChosenBy::NoSdpSeen(Unseen::Sdp)
            }),
            "no sdp seen asks the default engine and says why"
        );
        let trusting = EngineRule::TrustSdp { control_port: 2223 };
        assert_eq!(
            sdp_select(Some(&trusting), addr(DEFAULT)?, &[])
                .current
                .map(|e| e.chosen_by),
            Ok(ChosenBy::NoSdpSeen(Unseen::Sdp)),
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
        let got = sdp_select_listed(Some(&rule), addr(DEFAULT)?, &[], &[b]);
        assert_eq!(
            got.current,
            Ok(Engine {
                control: b,
                chosen_by: ChosenBy::Listed(Unseen::Sdp)
            }),
            "with no sdp the engine that lists the call is asked"
        );
        assert_eq!(
            sdp_select_listed(Some(&rule), addr(DEFAULT)?, &[], &[])
                .current
                .map(|e| e.chosen_by),
            Ok(ChosenBy::NoSdpSeen(Unseen::Sdp)),
            "with no sdp the engine that lists the call is asked"
        );
        let moved = sdp_select_listed(Some(&rule), addr(DEFAULT)?, &moved_call()?, &[b]);
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
            sdp_select_listed(None, addr(DEFAULT)?, &[], &[b])
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &fixture_call()?);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &fixture_call()?);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &moved_call()?);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &shuffled);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &fixture_call()?);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &calls);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &calls);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &calls);
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
        let got = sdp_select(Some(&rule), addr(DEFAULT)?, &calls);
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

    // ── engines from ng control traffic ───────────────────────────────

    /// An `offer` or `delete` for one call that reached `engine`, `secs`
    /// seconds in.
    fn ng(
        secs: i64,
        engine: EngineIdentity,
        verb: EngineVerb,
    ) -> Result<EngineSighting, TestError> {
        Ok(EngineSighting {
            at: at(secs)?,
            engine,
            verb,
            reported_listen_ng: None,
            frame: None,
        })
    }

    fn homer(id: u32) -> EngineIdentity {
        EngineIdentity::HomerId(id)
    }

    fn sent_to(control: &str) -> Result<EngineIdentity, TestError> {
        Ok(EngineIdentity::ListenNg(addr(control)?))
    }

    /// The ng engine rows for homer-ids 2001 and 2002, and the SDP map of
    /// the NAT example beside them.
    fn ng_rules(sdp: bool) -> Result<EngineRules, TestError> {
        Ok(EngineRules {
            sdp: if sdp {
                Some(EngineRule::Map(map(&NAT_ROWS)?))
            } else {
                None
            },
            ng: NgEngineMap::new(vec![
                "2001 192.0.2.5:2223".parse()?,
                "2002 -> 192.0.2.6:2223".parse()?,
                "192.0.2.7:2223".parse()?,
            ])?,
        })
    }

    fn evidence(sdp: Vec<SdpSighting>, ng: Vec<EngineSighting>) -> CallEvidence {
        CallEvidence { sdp, ng }
    }

    #[test]
    fn an_ng_engine_row_parses_with_or_without_a_homer_id() -> Result<(), TestError> {
        let with: NgEngineRow = "2001 192.0.2.5:2223".parse()?;
        let arrow: NgEngineRow = "2001  ->  192.0.2.5:2223".parse()?;
        let bare: NgEngineRow = "[2001:db8::5]:2223".parse()?;
        assert_eq!(with, arrow, "a row parses with or without the arrow");
        assert_eq!(with.homer_id, Some(2001), "the homer-id");
        assert_eq!(
            with.control,
            addr("192.0.2.5:2223")?,
            "the listen-ng address"
        );
        assert_eq!(bare.homer_id, None, "a row with no homer-id");
        assert_eq!(with.to_string(), "2001 192.0.2.5:2223", "written as given");
        assert_eq!(bare.to_string(), "[2001:db8::5]:2223", "written as given");
        Ok(())
    }

    #[test]
    fn a_malformed_or_duplicate_ng_engine_row_is_refused() -> Result<(), TestError> {
        let refused = |row: &str| row.parse::<NgEngineRow>().err();
        assert!(
            matches!(refused(""), Some(NgEngineError::Shape { .. })),
            "an empty row"
        );
        assert!(
            matches!(
                refused("2001 192.0.2.5:2223 extra"),
                Some(NgEngineError::Shape { .. })
            ),
            "a row with a third field"
        );
        assert!(
            matches!(
                refused("engine-a 192.0.2.5:2223"),
                Some(NgEngineError::HomerId { .. })
            ),
            "a homer-id that is not a number"
        );
        assert!(
            matches!(
                refused("2001 192.0.2.5:0"),
                Some(NgEngineError::Control { .. })
            ),
            "an address with port 0"
        );
        let same_id = NgEngineMap::new(vec![
            "2001 192.0.2.5:2223".parse()?,
            "2001 192.0.2.6:2223".parse()?,
        ]);
        assert!(
            matches!(&same_id, Err(NgEngineError::Duplicate { what, .. }) if what == "homer-id 2001"),
            "{same_id:?}"
        );
        let same_addr = NgEngineMap::new(vec![
            "2001 192.0.2.5:2223".parse()?,
            "[::ffff:192.0.2.5]:2223".parse()?,
        ]);
        assert!(
            matches!(&same_addr, Err(NgEngineError::Duplicate { what, .. }) if what == "listen-ng 192.0.2.5:2223"),
            "{same_addr:?}"
        );
        Ok(())
    }

    /// The newest offer's engine is asked, ahead of an SDP map that names
    /// another engine, and the answer says the offer chose it.
    #[test]
    fn the_newest_offer_names_the_engine_ahead_of_the_sdp_map() -> Result<(), TestError> {
        let rules = ng_rules(true)?;
        // The SDP names the engine at 30000-39999 (192.0.2.5); the offer
        // reached homer-id 2002 (192.0.2.6).
        let call = evidence(
            vec![sight(0, true, "203.0.113.5", 30010)?],
            vec![ng(0, homer(2002), EngineVerb::Offer)?],
        );
        let got = super::select(Some(&rules), addr(DEFAULT)?, &call);
        let engine = got.current.map_err(|u| u.to_string())?;
        assert_eq!(
            engine.control,
            addr("192.0.2.6:2223")?,
            "the offer's engine"
        );
        assert_eq!(engine.chosen_by_word(), "ng_offer", "the offer chose it");
        assert_eq!(
            engine.reason().as_deref(),
            Some(
                "chosen by the newest ng offer for this call, which reached homer-id \
                 2002 (ng engine row 2002 192.0.2.6:2223)"
            ),
            "the reason names the offer and the row"
        );
        Ok(())
    }

    /// Newest by capture time, not by arrival; and sightings that are only
    /// deletes choose nothing, so the SDP map answers.
    #[test]
    fn the_newest_offer_is_by_time_and_a_delete_alone_chooses_nothing() -> Result<(), TestError> {
        let rules = ng_rules(true)?;
        let out_of_order = evidence(
            Vec::new(),
            vec![
                ng(5, homer(2002), EngineVerb::Offer)?,
                ng(1, homer(2001), EngineVerb::Offer)?,
            ],
        );
        assert_eq!(
            super::select(Some(&rules), addr(DEFAULT)?, &out_of_order)
                .current
                .map(|e| e.control),
            Ok(addr("192.0.2.6:2223")?),
            "the newest offer by time"
        );
        let deletes = evidence(
            vec![sight(0, true, "203.0.113.5", 30010)?],
            vec![ng(9, homer(2002), EngineVerb::Delete)?],
        );
        let got = super::select(Some(&rules), addr(DEFAULT)?, &deletes).current;
        assert!(
            matches!(
                &got,
                Ok(Engine {
                    chosen_by: ChosenBy::MapRow { .. },
                    ..
                })
            ),
            "a delete alone chooses nothing: {got:?}"
        );
        Ok(())
    }

    /// An offer at a homer-id no row names is the call's engine and is not
    /// asked; neither the SDP map's engine nor the default is asked instead.
    #[test]
    fn an_offer_at_an_unlisted_homer_id_asks_nothing() -> Result<(), TestError> {
        let rules = ng_rules(true)?;
        let mut offer = ng(0, homer(2009), EngineVerb::Offer)?;
        offer.reported_listen_ng = Some(addr("127.0.0.1:2223")?);
        let call = evidence(vec![sight(0, true, "203.0.113.5", 30010)?], vec![offer]);
        let got = super::select(Some(&rules), addr(DEFAULT)?, &call);
        assert_eq!(
            got.current,
            Err(Unknown::NgEngineNotListed {
                engine: homer(2009),
                reported: Some(addr("127.0.0.1:2223")?),
            }),
            "an unlisted homer-id is not asked"
        );
        assert_eq!(
            got.current.err().map(|u| u.to_string()).as_deref(),
            Some(
                format!(
                    "engine not listed (homer-id 2009): the newest ng offer for this call \
                     reached homer-id 2009, and no {} row names it (the engine reports \
                     listen-ng 127.0.0.1:2223); nothing was asked",
                    crate::cli::RELAY_NG_ENGINE_FLAG
                )
                .as_str()
            ),
            "the refusal names the engine and what it reported"
        );
        Ok(())
    }

    /// A row may give a bare address, whose port is filled in from
    /// `--rtpengine-control`. An explicit port 0, or a homer-id with no
    /// address, is refused.
    #[test]
    fn an_ng_engine_row_with_a_bare_address_waits_for_the_control_port() -> Result<(), TestError> {
        for (row, want) in [
            ("192.0.2.6", "192.0.2.6:2223"),
            ("2001 192.0.2.6", "2001 192.0.2.6:2223"),
            ("2001 -> 2001:db8::6", "2001 [2001:db8::6]:2223"),
            ("192.0.2.6:4444", "192.0.2.6:4444"),
        ] {
            let parsed: NgEngineRow = row.parse()?;
            assert_eq!(
                parsed.with_default_port(2223).to_string(),
                want,
                "{row} takes the control port unless it names its own"
            );
        }
        for bad in [
            "192.0.2.6:0",
            "2001",
            "2001 192.0.2.6:0",
            "2001 [2001:db8::6]:0",
        ] {
            assert!(
                bad.parse::<NgEngineRow>().is_err(),
                "{bad} is refused: port 0, or no address"
            );
        }
        Ok(())
    }

    /// The refusal for an offer at `homer-id 2009` whose HEP copy reported
    /// `reported` as its listen-ng.
    fn unlisted_refusal(reported: &str) -> Result<String, TestError> {
        let rules = ng_rules(false)?;
        let mut offer = ng(0, homer(2009), EngineVerb::Offer)?;
        offer.reported_listen_ng = Some(addr(reported)?);
        let got = super::select(Some(&rules), addr(DEFAULT)?, &evidence(vec![], vec![offer]));
        Ok(got
            .current
            .err()
            .ok_or("an unlisted engine is not asked")?
            .to_string())
    }

    /// A HEP copy that reports a listen-ng another host can reach is given
    /// the exact row that would list it, as a flag and as a config line.
    /// Nothing is asked: the suggestion is words only.
    #[test]
    fn an_unlisted_engine_with_a_reachable_listen_ng_is_given_its_row() -> Result<(), TestError> {
        assert_eq!(
            unlisted_refusal("192.0.2.9:2223")?,
            format!(
                "engine not listed (homer-id 2009): the newest ng offer for this call \
                 reached homer-id 2009, and no {flag} row names it (the engine reports \
                 listen-ng 192.0.2.9:2223); nothing was asked. To list it, add {flag} \
                 '2009 192.0.2.9:2223', or ng_engines = [\"2009 192.0.2.9:2223\"] in the \
                 config file's [relay] section",
                flag = crate::cli::RELAY_NG_ENGINE_FLAG
            ),
            "the refusal carries the row"
        );
        let v6 = unlisted_refusal("[2001:db8::9]:2223")?;
        assert!(
            v6.ends_with(&format!(
                "To list it, add {} '2009 [2001:db8::9]:2223', or ng_engines = \
                 [\"2009 [2001:db8::9]:2223\"] in the config file's [relay] section",
                crate::cli::RELAY_NG_ENGINE_FLAG
            )),
            "an IPv6 listen-ng is written in brackets: {v6}"
        );
        let mapped = unlisted_refusal("[::ffff:192.0.2.9]:2223")?;
        assert!(
            mapped.contains("'2009 192.0.2.9:2223'"),
            "an IPv4-mapped listen-ng is written as IPv4: {mapped}"
        );
        Ok(())
    }

    /// A loopback or unspecified listen-ng names no address another host can
    /// reach, so no row is suggested for it.
    #[test]
    fn a_loopback_or_unspecified_listen_ng_is_given_no_row() -> Result<(), TestError> {
        for reported in [
            "127.0.0.1:2223",
            "127.0.0.9:2223",
            "[::1]:2223",
            "[::ffff:127.0.0.1]:2223",
            "0.0.0.0:2223",
            "[::]:2223",
        ] {
            assert_eq!(
                suggested_ng_row(2009, Some(addr(reported)?)),
                None,
                "no row for {reported}"
            );
            let refusal = unlisted_refusal(reported)?;
            assert!(
                refusal.ends_with("; nothing was asked") && !refusal.contains("To list it"),
                "no row for {reported}: {refusal}"
            );
        }
        assert_eq!(suggested_ng_row(2009, None), None, "nothing reported");
        Ok(())
    }

    /// The suggested row is the row the ng engine parser reads back: the
    /// same homer-id and listen-ng, so pasting it lists that engine.
    #[test]
    fn a_suggested_row_parses_back_to_the_engine_it_names() -> Result<(), TestError> {
        for reported in ["192.0.2.9:2223", "[2001:db8::9]:2223"] {
            let row = suggested_ng_row(2009, Some(addr(reported)?)).ok_or("a row")?;
            let flag = row.flag_text();
            let value = flag
                .strip_prefix(&format!("{} '", crate::cli::RELAY_NG_ENGINE_FLAG))
                .and_then(|v| v.strip_suffix('\''))
                .ok_or(format!("the flag is the flag and a quoted row: {flag}"))?;
            let back: NgEngineRow = value.parse()?;
            assert_eq!(back, row, "the flag value parses back");
            assert_eq!(back.homer_id, Some(2009), "the flag value parses back");
            assert_eq!(back.control, addr(reported)?, "the flag value parses back");
            let line = row.config_line();
            let table: toml::Table = toml::from_str(&line)?;
            let rows = table
                .get("ng_engines")
                .and_then(toml::Value::as_array)
                .ok_or(format!("the config line sets ng_engines: {line}"))?;
            let only = rows.first().and_then(toml::Value::as_str).ok_or("a row")?;
            assert_eq!(rows.len(), 1, "one row: {line}");
            assert_eq!(
                only.parse::<NgEngineRow>()?,
                row,
                "the config row parses back"
            );
        }
        Ok(())
    }

    /// A leftover session on an engine no row names carries what its HEP
    /// copy reported, so the sessions view can suggest its row too.
    #[test]
    fn a_leftover_carries_the_listen_ng_its_engine_reported() -> Result<(), TestError> {
        let rules = ng_rules(false)?;
        let mut first = ng(0, homer(2009), EngineVerb::Offer)?;
        first.reported_listen_ng = Some(addr("192.0.2.70:2223")?);
        let mut newer = ng(5, homer(2009), EngineVerb::Offer)?;
        newer.reported_listen_ng = Some(addr("192.0.2.9:2223")?);
        let moved = ng(10, homer(2001), EngineVerb::Offer)?;
        let got = super::select(
            Some(&rules),
            addr(DEFAULT)?,
            &evidence(vec![], vec![first, newer, moved]),
        );
        assert_eq!(
            got.leftovers,
            vec![Leftover {
                engine: homer(2009),
                control: None,
                reported: Some(addr("192.0.2.9:2223")?),
            }],
            "the newest offer's report is carried"
        );
        Ok(())
    }

    /// A captured offer's destination is asked when the operator named it:
    /// an ng engine row with no homer-id, or the default engine itself.
    #[test]
    fn a_captured_offer_is_asked_at_an_address_the_operator_named() -> Result<(), TestError> {
        let rules = ng_rules(false)?;
        let listed = evidence(
            Vec::new(),
            vec![ng(0, sent_to("192.0.2.7:2223")?, EngineVerb::Offer)?],
        );
        let got = super::select(Some(&rules), addr(DEFAULT)?, &listed).current;
        assert_eq!(
            got.as_ref().map(|e| (e.control, e.reason())),
            Ok((
                addr("192.0.2.7:2223")?,
                Some(
                    "chosen by the newest ng offer for this call, which reached \
                     listen-ng 192.0.2.7:2223"
                        .to_string()
                )
            )),
            "a listed address is asked"
        );
        let mapped = evidence(
            Vec::new(),
            vec![ng(
                0,
                EngineIdentity::ListenNg(addr("[::ffff:192.0.2.1]:2223")?),
                EngineVerb::Offer,
            )?],
        );
        assert_eq!(
            super::select(Some(&rules), addr(DEFAULT)?, &mapped)
                .current
                .map(|e| e.control),
            Ok(addr("[::ffff:192.0.2.1]:2223")?),
            "the default engine, written IPv4-mapped, is named by the operator"
        );
        Ok(())
    }

    /// A captured offer to a control address only an SDP map row names is
    /// asked: the operator listed that address. With no SDP map, the same
    /// offer names an engine nobody listed.
    #[test]
    fn a_captured_offer_to_an_sdp_map_rows_address_is_asked() -> Result<(), TestError> {
        let call = evidence(
            Vec::new(),
            vec![ng(0, sent_to("192.0.2.6:2223")?, EngineVerb::Offer)?],
        );
        let sdp_map_only = EngineRules::from(EngineRule::Map(map(&NAT_ROWS)?));
        assert_eq!(
            super::select(Some(&sdp_map_only), addr(DEFAULT)?, &call)
                .current
                .map(|e| (e.control, e.chosen_by_word())),
            Ok((addr("192.0.2.6:2223")?, "ng_offer")),
            "an address an SDP map row names is listed"
        );
        let no_map = EngineRules {
            sdp: Some(EngineRule::TrustSdp { control_port: 2223 }),
            ng: NgEngineMap::default(),
        };
        assert!(
            matches!(
                super::select(Some(&no_map), addr(DEFAULT)?, &call).current,
                Err(Unknown::NgEngineNotListed { .. })
            ),
            "trusting SDP addresses does not list an address seen in ng traffic"
        );
        Ok(())
    }

    /// A captured offer to an address nobody listed is reported and not
    /// asked: the address came from captured traffic. The refusal gives the
    /// row that would list it, a loopback address included, because the
    /// proxy that sent the offer reached it from this host.
    #[test]
    fn a_captured_offer_to_an_unlisted_address_asks_nothing() -> Result<(), TestError> {
        let rules = ng_rules(true)?;
        for (sent, row) in [
            ("192.0.2.99:2223", "192.0.2.99:2223"),
            ("127.0.0.4:2223", "127.0.0.4:2223"),
            ("[::ffff:192.0.2.99]:2223", "192.0.2.99:2223"),
        ] {
            let call = evidence(Vec::new(), vec![ng(0, sent_to(sent)?, EngineVerb::Offer)?]);
            let got = super::select(Some(&rules), addr(DEFAULT)?, &call).current;
            let shown = addr(sent)?;
            assert_eq!(
                got.err().map(|u| u.to_string()).as_deref(),
                Some(
                    format!(
                        "engine not listed ({shown}): the newest ng offer for this call was \
                         sent to {shown}, an address sipnab saw only in captured traffic; \
                         nothing was asked. To list it, add {flag} '{row}', or ng_engines = \
                         [\"{row}\"] in the config file's [relay] section",
                        flag = crate::cli::RELAY_NG_ENGINE_FLAG
                    )
                    .as_str()
                ),
                "an unlisted address is not asked, and its row is given: {sent}"
            );
        }
        Ok(())
    }

    /// A later offer at another engine moves the call: the earlier engine is
    /// the previous one and, with no delete, a leftover session.
    #[test]
    fn a_later_offer_elsewhere_moves_the_call_and_leaves_a_session() -> Result<(), TestError> {
        let rules = ng_rules(false)?;
        let call = evidence(
            Vec::new(),
            vec![
                ng(0, homer(2001), EngineVerb::Offer)?,
                ng(60, homer(2002), EngineVerb::Offer)?,
            ],
        );
        let got = super::select(Some(&rules), addr(DEFAULT)?, &call);
        assert_eq!(
            got.current.as_ref().map(|e| e.control),
            Ok(addr("192.0.2.6:2223")?),
            "now on 2002"
        );
        assert_eq!(
            got.previous
                .as_ref()
                .map(|e| (e.control, e.chosen_by_word())),
            Some((addr("192.0.2.5:2223")?, "ng_offer")),
            "previously on 2001"
        );
        assert_eq!(
            got.leftovers,
            vec![Leftover {
                engine: homer(2001),
                control: Some(addr("192.0.2.5:2223")?),
                reported: None,
            }],
            "2001 never received a delete"
        );
        assert_eq!(
            got.notes(),
            vec![
                "homer-id 2001 never received a delete for this call after its offer \
                 (a leftover session)"
                    .to_string()
            ],
            "the note every surface prints"
        );
        Ok(())
    }

    /// A delete at the old engine after its offer releases it; one before its
    /// offer does not; a re-offer at the same engine is no move.
    #[test]
    fn a_delete_after_the_old_offer_releases_it_and_one_before_does_not() -> Result<(), TestError> {
        let rules = ng_rules(false)?;
        let released = evidence(
            Vec::new(),
            vec![
                ng(0, homer(2001), EngineVerb::Offer)?,
                ng(60, homer(2002), EngineVerb::Offer)?,
                ng(61, homer(2001), EngineVerb::Delete)?,
            ],
        );
        assert!(
            super::select(Some(&rules), addr(DEFAULT)?, &released)
                .leftovers
                .is_empty(),
            "a delete after the old offer releases it"
        );
        let early = evidence(
            Vec::new(),
            vec![
                ng(0, homer(2001), EngineVerb::Delete)?,
                ng(1, homer(2001), EngineVerb::Offer)?,
                ng(60, homer(2002), EngineVerb::Offer)?,
            ],
        );
        assert_eq!(
            super::select(Some(&rules), addr(DEFAULT)?, &early)
                .leftovers
                .len(),
            1,
            "a delete before the old offer does not release it"
        );
        let reoffer = evidence(
            Vec::new(),
            vec![
                ng(0, homer(2002), EngineVerb::Offer)?,
                ng(60, homer(2002), EngineVerb::Offer)?,
            ],
        );
        let got = super::select(Some(&rules), addr(DEFAULT)?, &reoffer);
        assert!(
            got.previous.is_none() && got.leftovers.is_empty(),
            "a re-offer at the same engine is no move: {got:?}"
        );
        Ok(())
    }

    /// A leftover on an engine sipnab may not ask is still flagged, with no
    /// control address, and is not a previous engine to ask.
    #[test]
    fn a_leftover_on_an_unlisted_engine_is_flagged_and_not_asked() -> Result<(), TestError> {
        let rules = ng_rules(false)?;
        let call = evidence(
            Vec::new(),
            vec![
                ng(0, homer(2009), EngineVerb::Offer)?,
                ng(60, homer(2002), EngineVerb::Offer)?,
            ],
        );
        let got = super::select(Some(&rules), addr(DEFAULT)?, &call);
        assert_eq!(
            got.previous, None,
            "an unlisted previous engine is not asked"
        );
        assert_eq!(
            got.leftovers,
            vec![Leftover {
                engine: homer(2009),
                control: None,
                reported: None,
            }],
            "it is still flagged"
        );
        Ok(())
    }

    /// With only an ng engine map, a call with no offer is asked of the
    /// default engine or the one that lists it, saying no offer was seen;
    /// with both rules, saying neither was seen.
    #[test]
    fn with_no_offer_the_fallback_says_what_was_not_seen() -> Result<(), TestError> {
        let only_ng = ng_rules(false)?;
        let b = addr("192.0.2.6:2223")?;
        let with_sdp = evidence(vec![sight(0, true, "203.0.113.5", 30010)?], Vec::new());
        assert_eq!(
            super::select(Some(&only_ng), addr(DEFAULT)?, &with_sdp)
                .current
                .map(|e| e.reason()),
            Ok(Some(format!(
                "the default engine ({}): sipnab has seen no ng offer for this call",
                crate::cli::RELAY_CONTROL_FLAG
            ))),
            "only an ng map: SDP does not count"
        );
        assert_eq!(
            super::select_listed(
                Some(&only_ng),
                addr(DEFAULT)?,
                &CallEvidence::default(),
                &[b]
            )
            .current
            .map(|e| (e.control, e.chosen_by)),
            Ok((b, ChosenBy::Listed(Unseen::Offer))),
            "the engine that lists it"
        );
        let both = ng_rules(true)?;
        assert_eq!(
            super::select(Some(&both), addr(DEFAULT)?, &CallEvidence::default())
                .current
                .map(|e| e.chosen_by),
            Ok(ChosenBy::NoSdpSeen(Unseen::OfferOrSdp)),
            "both rules, neither seen"
        );
        assert_eq!(
            super::select(Some(&both), addr(DEFAULT)?, &with_sdp)
                .current
                .map(|e| e.chosen_by_word()),
            Ok("map_row"),
            "both rules, SDP seen: the SDP map answers"
        );
        Ok(())
    }

    /// The listing engines include each ng engine row's address once, after
    /// the default and the SDP map's.
    #[test]
    fn listing_asks_every_ng_engine_row_once() -> Result<(), TestError> {
        let routing = EngineRouting::new(
            ng_rules(true)?,
            addr("192.0.2.5:2223")?,
            false,
            Arc::new(|_| unreachable_relay()),
        );
        assert_eq!(
            routing.listing_engines(),
            vec![
                addr("192.0.2.5:2223")?,
                addr("192.0.2.6:2223")?,
                addr("192.0.2.7:2223")?
            ],
            "listing asks every ng engine row once"
        );
        Ok(())
    }

    /// A call target's reason carries the leftover note, so every per-call
    /// surface prints it.
    #[test]
    fn a_call_targets_reason_names_a_leftover_session() -> Result<(), TestError> {
        let default = unreachable_relay();
        let routing = EngineRouting::new(
            ng_rules(false)?,
            addr(DEFAULT)?,
            false,
            Arc::new(|_| unreachable_relay()),
        );
        let call = evidence(
            Vec::new(),
            vec![
                ng(0, homer(2001), EngineVerb::Offer)?,
                ng(60, homer(2002), EngineVerb::Offer)?,
            ],
        );
        match super::call_target(&default, Some(&routing), &call) {
            CallTarget::Ask {
                reason, control, ..
            } => {
                assert_eq!(control, Some(addr("192.0.2.6:2223")?), "the offer's engine");
                assert_eq!(
                    reason.as_deref(),
                    Some(
                        "chosen by the newest ng offer for this call, which reached \
                         homer-id 2002 (ng engine row 2002 192.0.2.6:2223); homer-id 2001 \
                         never received a delete for this call after its offer (a leftover \
                         session)"
                    ),
                    "the reason names the leftover"
                );
            }
            other => return Err(format!("expected an engine, got {other:?}").into()),
        }
        Ok(())
    }

    /// The dialog store's engine sightings reach the evidence a surface
    /// reads, for a call with no dialog at all.
    #[test]
    fn call_evidence_reads_engine_sightings_without_a_dialog() -> Result<(), TestError> {
        let mut store = crate::sip::dialog_store::DialogStore::new(16, false);
        store.record_engine_sighting(
            "relay-only@example.invalid",
            ng(0, homer(2001), EngineVerb::Offer)?,
        );
        assert_eq!(
            call_sightings(&store, "relay-only@example.invalid"),
            evidence(Vec::new(), vec![ng(0, homer(2001), EngineVerb::Offer)?]),
            "the evidence carries the engine sighting"
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
        match sdp_call_target(&default, None, &fixture_call()?) {
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
        match sdp_call_target(&default, Some(&routing), &moved_call()?) {
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
        match sdp_call_target(&default, Some(&routing), &first_leg) {
            CallTarget::Ask { relay, .. } => assert!(
                Arc::ptr_eq(&relay, &default),
                "a call target with routing is the mapped engine or none"
            ),
            other => return Err(format!("expected the default, got {other:?}").into()),
        }
        assert!(
            matches!(
                sdp_call_target(&default, Some(&routing), &fixture_call()?),
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
            .sdp
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
            call_sightings(&store, "absent@example.invalid") == CallEvidence::default(),
            "call sightings read the dialog store"
        );
        Ok(())
    }

    // ── an unseen call, asked of the engine whose list names it ───────

    /// A scripted engine that answers `list` with `calls`, or not at all when
    /// `down`, and records every question.
    struct ListingRelay {
        name: String,
        calls: Vec<&'static str>,
        truncated: bool,
        down: bool,
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl ListingRelay {
        fn scripted(
            control: &str,
            calls: &[&'static str],
            truncated: bool,
            down: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                name: format!("engine at {control}"),
                calls: calls.to_vec(),
                truncated,
                down,
                asked: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn new(control: &str, calls: &[&'static str]) -> Arc<Self> {
            Self::scripted(control, calls, false, false)
        }

        fn down(control: &str) -> Arc<Self> {
            Self::scripted(control, &[], false, true)
        }

        fn capped(control: &str, calls: &[&'static str]) -> Arc<Self> {
            Self::scripted(control, calls, true, false)
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().map(|a| a.clone()).unwrap_or_default()
        }
    }

    impl ReadOnlyRelay for ListingRelay {
        fn list(
            &self,
            _: &crate::security::transmit_guard::TransmitPermit,
            limit: u32,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            if let Ok(mut a) = self.asked.lock() {
                a.push(format!("list {limit}"));
            }
            if self.down {
                anyhow::bail!("no reply within 2s");
            }
            Ok(crate::relay::types::ControlReply::Calls(
                crate::relay::types::Enumeration {
                    call_ids: self.calls.iter().map(|c| (*c).to_string()).collect(),
                    truncated: self.truncated,
                },
            ))
        }
        fn query(
            &self,
            _: &crate::security::transmit_guard::TransmitPermit,
            call_id: &str,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            if let Ok(mut a) = self.asked.lock() {
                a.push(format!("query {call_id}"));
            }
            anyhow::bail!("not scripted")
        }
        fn statistics(
            &self,
            _: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            anyhow::bail!("not scripted")
        }
        fn describe(&self) -> String {
            self.name.clone()
        }
    }

    /// The default engine and the three ng engine rows of [`ng_rules`], each a
    /// scripted engine, and the routing that reaches them.
    struct FourEngines {
        default: Arc<ListingRelay>,
        rows: Vec<Arc<ListingRelay>>,
        routing: EngineRouting,
    }

    impl FourEngines {
        fn new(
            default: Arc<ListingRelay>,
            rows: [Arc<ListingRelay>; 3],
            sdp: bool,
        ) -> Result<Self, TestError> {
            let by_control: Vec<(SocketAddr, Arc<ListingRelay>)> = vec![
                (addr("192.0.2.5:2223")?, Arc::clone(&rows[0])),
                (addr("192.0.2.6:2223")?, Arc::clone(&rows[1])),
                (addr("192.0.2.7:2223")?, Arc::clone(&rows[2])),
            ];
            let connect: Connect = Arc::new(move |control| {
                by_control
                    .iter()
                    .find(|(c, _)| *c == control)
                    .map_or_else(unreachable_relay, |(_, r)| {
                        Arc::clone(r) as Arc<dyn ReadOnlyRelay + Send + Sync>
                    })
            });
            Ok(Self {
                default,
                rows: rows.to_vec(),
                routing: EngineRouting::new(ng_rules(sdp)?, addr(DEFAULT)?, false, connect),
            })
        }

        fn target(
            &self,
            evidence: &CallEvidence,
            call_id: &str,
            lists: &EngineLists<'_>,
        ) -> CallTarget {
            let default: Arc<dyn ReadOnlyRelay + Send + Sync> = Arc::clone(&self.default) as _;
            call_target_listed(&default, Some(&self.routing), evidence, call_id, lists)
        }

        /// What each engine was asked, the default first.
        fn asked(&self) -> Vec<Vec<String>> {
            std::iter::once(self.default.asked())
                .chain(self.rows.iter().map(|r| r.asked()))
                .collect()
        }
    }

    fn live_permit() -> Result<crate::security::transmit_guard::TransmitPermit, TestError> {
        Ok(crate::security::transmit_guard::TransmitPermit::for_source(
            &crate::capture::CaptureSource::Live {
                device: "eth0".to_owned(),
            },
        )
        .ok_or("a live source grants a permit")?)
    }

    fn asked_of(target: &CallTarget) -> Result<(Option<SocketAddr>, Option<String>), TestError> {
        match target {
            CallTarget::Ask {
                control, reason, ..
            } => Ok((*control, reason.clone())),
            CallTarget::Unknown(u) => Err(format!("expected an engine, got {u}").into()),
        }
    }

    /// A call with no ng offer and no SDP seen is asked of the engine whose
    /// list names it, not the default. Each listed engine is asked one `list`
    /// and nothing else.
    #[test]
    fn an_unseen_call_is_asked_of_the_engine_whose_list_names_it() -> Result<(), TestError> {
        let engines = FourEngines::new(
            ListingRelay::new(DEFAULT, &["other@example.invalid"]),
            [
                ListingRelay::new("192.0.2.5:2223", &[]),
                ListingRelay::new("192.0.2.6:2223", &["up-1@example.invalid"]),
                ListingRelay::new("192.0.2.7:2223", &[]),
            ],
            false,
        )?;
        let permit = live_permit()?;
        let lists = EngineLists::new(&permit, crate::relay::reconcile::DEFAULT_LIST_LIMIT);
        let target = engines.target(&CallEvidence::default(), "up-1@example.invalid", &lists);
        assert_eq!(
            asked_of(&target)?,
            (
                Some(addr("192.0.2.6:2223")?),
                Some(
                    "sipnab has seen no ng offer for this call; this engine's list names it"
                        .to_string()
                )
            ),
            "the engine whose list names the call is asked"
        );
        let one_list = vec![format!(
            "list {}",
            crate::relay::reconcile::DEFAULT_LIST_LIMIT
        )];
        assert_eq!(
            engines.asked(),
            vec![
                one_list.clone(),
                one_list.clone(),
                one_list.clone(),
                one_list
            ],
            "each listed engine is asked one list"
        );
        Ok(())
    }

    /// When no list names the call it falls back to the default engine, and
    /// the reason says what the lists said: none names it, an engine did not
    /// answer, a capped list may hold it, or two engines hold it.
    #[test]
    fn an_unseen_call_the_lists_do_not_settle_says_why() -> Result<(), TestError> {
        let permit = live_permit()?;
        let limit = crate::relay::reconcile::DEFAULT_LIST_LIMIT;
        let none = FourEngines::new(
            ListingRelay::new(DEFAULT, &[]),
            [
                ListingRelay::new("192.0.2.5:2223", &[]),
                ListingRelay::down("192.0.2.6:2223"),
                ListingRelay::capped("192.0.2.7:2223", &["a@example.invalid"]),
            ],
            false,
        )?;
        let target = none.target(
            &CallEvidence::default(),
            "up-1@example.invalid",
            &EngineLists::new(&permit, limit),
        );
        assert_eq!(
            asked_of(&target)?,
            (
                Some(addr(DEFAULT)?),
                Some(format!(
                    "the default engine ({flag}): sipnab has seen no ng offer \
                     for this call; no engine's list names it; engine at 192.0.2.6:2223 \
                     did not answer its list (no reply within 2s); the list of engine at \
                     192.0.2.7:2223 stopped at {limit} calls, so it may hold this call",
                    flag = crate::cli::RELAY_CONTROL_FLAG
                ))
            ),
            "the default is asked, and the reason says what the lists said"
        );
        let two = FourEngines::new(
            ListingRelay::new(DEFAULT, &[]),
            [
                ListingRelay::new("192.0.2.5:2223", &["up-1@example.invalid"]),
                ListingRelay::new("192.0.2.6:2223", &[]),
                ListingRelay::new("192.0.2.7:2223", &["up-1@example.invalid"]),
            ],
            false,
        )?;
        let target = two.target(
            &CallEvidence::default(),
            "up-1@example.invalid",
            &EngineLists::new(&permit, limit),
        );
        assert_eq!(
            asked_of(&target)?,
            (
                Some(addr("192.0.2.5:2223")?),
                Some(
                    "sipnab has seen no ng offer for this call; this engine's list names it; \
                     held by several engines: engine at 192.0.2.5:2223, engine at \
                     192.0.2.7:2223"
                        .to_string()
                )
            ),
            "the first engine whose list names it is asked, and both are named"
        );
        Ok(())
    }

    /// Lists are asked only when nothing else chooses the engine: a call with
    /// a seen offer or SDP, a run with no engine rule, and a run whose only
    /// listed engine is the default ask no list.
    #[test]
    fn a_call_with_evidence_or_one_engine_asks_no_list() -> Result<(), TestError> {
        let permit = live_permit()?;
        let limit = crate::relay::reconcile::DEFAULT_LIST_LIMIT;
        let engines = FourEngines::new(
            ListingRelay::new(DEFAULT, &[]),
            [
                ListingRelay::new("192.0.2.5:2223", &["up-1@example.invalid"]),
                ListingRelay::new("192.0.2.6:2223", &[]),
                ListingRelay::new("192.0.2.7:2223", &[]),
            ],
            true,
        )?;
        let lists = EngineLists::new(&permit, limit);
        let offered = evidence(Vec::new(), vec![ng(0, homer(2002), EngineVerb::Offer)?]);
        let by_offer = engines.target(&offered, "up-1@example.invalid", &lists);
        assert_eq!(
            asked_of(&by_offer)?.0,
            Some(addr("192.0.2.6:2223")?),
            "the offer"
        );
        let by_sdp = engines.target(
            &CallEvidence::from(vec![sight(0, true, "203.0.113.5", 30010)?]),
            "up-1@example.invalid",
            &lists,
        );
        assert!(
            matches!(by_sdp, CallTarget::Ask { .. }),
            "the SDP map answers: {by_sdp:?}"
        );
        assert_eq!(
            engines.asked(),
            vec![Vec::<String>::new(); 4],
            "evidence asks no list"
        );

        let default = ListingRelay::new(DEFAULT, &["up-1@example.invalid"]);
        let as_dyn: Arc<dyn ReadOnlyRelay + Send + Sync> = Arc::clone(&default) as _;
        let trusting = EngineRouting::new(
            EngineRule::TrustSdp { control_port: 2223 },
            addr(DEFAULT)?,
            false,
            Arc::new(|_| unreachable_relay()),
        );
        let alone = call_target_listed(
            &as_dyn,
            Some(&trusting),
            &CallEvidence::default(),
            "up-1@example.invalid",
            &lists,
        );
        assert_eq!(asked_of(&alone)?.0, Some(addr(DEFAULT)?), "the default");
        let no_rule = call_target_listed(
            &as_dyn,
            None,
            &CallEvidence::default(),
            "up-1@example.invalid",
            &lists,
        );
        assert_eq!(asked_of(&no_rule)?, (None, None), "no rule, as before");
        assert!(default.asked().is_empty(), "one engine asks no list");
        Ok(())
    }

    /// Within one question each engine is asked its list once, however many
    /// calls the question chooses an engine for.
    #[test]
    fn one_question_asks_each_engine_its_list_once() -> Result<(), TestError> {
        let engines = FourEngines::new(
            ListingRelay::new(DEFAULT, &["b@example.invalid"]),
            [
                ListingRelay::new("192.0.2.5:2223", &["a@example.invalid"]),
                ListingRelay::new("192.0.2.6:2223", &[]),
                ListingRelay::new("192.0.2.7:2223", &[]),
            ],
            false,
        )?;
        let permit = live_permit()?;
        let lists = EngineLists::new(&permit, crate::relay::reconcile::DEFAULT_LIST_LIMIT);
        let a = engines.target(&CallEvidence::default(), "a@example.invalid", &lists);
        let b = engines.target(&CallEvidence::default(), "b@example.invalid", &lists);
        assert_eq!(asked_of(&a)?.0, Some(addr("192.0.2.5:2223")?), "a's engine");
        assert_eq!(asked_of(&b)?.0, Some(addr(DEFAULT)?), "b's engine");
        assert!(
            engines.asked().iter().all(|a| a.len() == 1),
            "one list each: {:?}",
            engines.asked()
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

    // ── the lists of an unseen call, asked at once ──────────────────

    /// An engine whose list answers only when every engine is being asked at
    /// the same moment, naming `calls`.
    struct GatedListing {
        gate: Arc<crate::test_engines::Gate>,
        calls: Vec<&'static str>,
        name: String,
    }

    impl ReadOnlyRelay for GatedListing {
        fn list(
            &self,
            _: &crate::security::transmit_guard::TransmitPermit,
            _: u32,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            if !self.gate.arrive(std::time::Duration::from_secs(5)) {
                anyhow::bail!("asked alone");
            }
            Ok(crate::relay::types::ControlReply::Calls(
                crate::relay::types::Enumeration {
                    call_ids: self.calls.iter().map(|c| (*c).to_string()).collect(),
                    truncated: false,
                },
            ))
        }
        fn query(
            &self,
            _: &crate::security::transmit_guard::TransmitPermit,
            _: &str,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            anyhow::bail!("not scripted")
        }
        fn statistics(
            &self,
            _: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            anyhow::bail!("not scripted")
        }
        fn describe(&self) -> String {
            self.name.clone()
        }
    }

    /// The lists of an unseen call are asked of every engine at once: each
    /// answers only with the others, and the engine whose list names the
    /// call is asked, with no engine reported silent.
    #[test]
    fn an_unseen_calls_lists_are_asked_at_once() -> Result<(), TestError> {
        let gate = Arc::new(crate::test_engines::Gate::new(4));
        let gated =
            |control: &str, calls: &[&'static str]| -> Arc<dyn ReadOnlyRelay + Send + Sync> {
                Arc::new(GatedListing {
                    gate: Arc::clone(&gate),
                    calls: calls.to_vec(),
                    name: format!("engine at {control}"),
                })
            };
        let rows: Vec<(SocketAddr, Arc<dyn ReadOnlyRelay + Send + Sync>)> = vec![
            (addr("192.0.2.5:2223")?, gated("192.0.2.5:2223", &[])),
            (
                addr("192.0.2.6:2223")?,
                gated("192.0.2.6:2223", &["up-1@example.invalid"]),
            ),
            (addr("192.0.2.7:2223")?, gated("192.0.2.7:2223", &[])),
        ];
        let connect: Connect = Arc::new(move |control| {
            rows.iter()
                .find(|(c, _)| *c == control)
                .map_or_else(unreachable_relay, |(_, r)| Arc::clone(r))
        });
        let routing = EngineRouting::new(ng_rules(false)?, addr(DEFAULT)?, false, connect);
        let default = gated(DEFAULT, &[]);
        let permit = live_permit()?;
        let lists = EngineLists::new(&permit, crate::relay::reconcile::DEFAULT_LIST_LIMIT);
        let target = call_target_listed(
            &default,
            Some(&routing),
            &CallEvidence::default(),
            "up-1@example.invalid",
            &lists,
        );
        assert_eq!(
            asked_of(&target)?,
            (
                Some(addr("192.0.2.6:2223")?),
                Some(
                    "sipnab has seen no ng offer for this call; this engine's list names it"
                        .to_string()
                )
            ),
            "every list answered together"
        );
        Ok(())
    }

    /// The default engine and the routing for a set of fake engines, the
    /// first being the default.
    fn udp_target(
        fakes: &[&crate::test_engines::FakeEngine],
        call_id: &str,
    ) -> Result<(CallTarget, std::time::Duration), TestError> {
        use crate::test_engines::{TIMEOUT, client, routing};
        let routing = routing(fakes, TIMEOUT)?;
        let default = client(routing.default_engine(), TIMEOUT);
        let permit = live_permit()?;
        let lists = EngineLists::new(&permit, crate::relay::reconcile::DEFAULT_LIST_LIMIT);
        let started = std::time::Instant::now();
        let target = call_target_listed(
            &default,
            Some(&routing),
            &CallEvidence::default(),
            call_id,
            &lists,
        );
        Ok((target, started.elapsed()))
    }

    /// An unseen call with three dead engines costs one timeout, and each
    /// dead engine is named in its configured place.
    #[test]
    fn an_unseen_call_with_dead_engines_costs_one_timeout() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, all_answered, waited_a_timeout};
        // Asked at once, not in turn: three engines that answer only when
        // all three hold a request. No wall time is read for it.
        let asked = FakeEngine::together_beside_a_live_one(4, 0)?;
        udp_target(&asked.iter().collect::<Vec<_>>(), "up-1@example.invalid")?;
        assert!(
            all_answered(&asked),
            "the engines were asked one after another"
        );
        let fakes = [
            FakeEngine::live()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
        ];
        let (target, took) = udp_target(&fakes.iter().collect::<Vec<_>>(), "up-1@example.invalid")?;
        assert!(
            waited_a_timeout(took),
            "the dead engines were waited for: {took:?}"
        );
        let (control, reason) = asked_of(&target)?;
        assert_eq!(control, Some(fakes[0].addr), "the default's list names it");
        let reason = reason.ok_or("a reason")?;
        let silent: Vec<usize> = fakes[1..]
            .iter()
            .filter_map(|f| reason.find(&format!("{} did not answer", f.describe())))
            .collect();
        assert_eq!(silent.len(), 3, "each dead engine is named: {reason}");
        assert!(
            silent.windows(2).all(|w| w[0] < w[1]),
            "in configured order: {reason}"
        );
        Ok(())
    }

    /// Lists that answer last engine first are still reported first engine
    /// first.
    #[test]
    fn the_notes_follow_the_configured_order_not_the_answers() -> Result<(), TestError> {
        use crate::test_engines::{CUT_BODY, FakeEngine};
        let late = |ms| FakeEngine::answering(CUT_BODY, std::time::Duration::from_millis(ms));
        let fakes = [FakeEngine::live()?, late(300)?, late(150)?, late(0)?];
        let (target, _) = udp_target(&fakes.iter().collect::<Vec<_>>(), "up-1@example.invalid")?;
        let reason = asked_of(&target)?.1.ok_or("a reason")?;
        let at: Vec<usize> = fakes[1..]
            .iter()
            .filter_map(|f| reason.find(&format!("{} did not answer", f.describe())))
            .collect();
        assert_eq!(at.len(), 3, "{reason}");
        assert!(
            at.windows(2).all(|w| w[0] < w[1]),
            "configured order: {reason}"
        );
        Ok(())
    }

    /// With every engine dead the default is asked, every engine is named as
    /// silent, and it costs one timeout.
    #[test]
    fn with_every_engine_dead_the_default_is_asked_after_one_timeout() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, waited_a_timeout};
        let fakes = [
            FakeEngine::dead()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
        ];
        let (target, took) = udp_target(&fakes.iter().collect::<Vec<_>>(), "up-1@example.invalid")?;
        assert!(
            waited_a_timeout(took),
            "the dead engines were waited for: {took:?}"
        );
        let (control, reason) = asked_of(&target)?;
        assert_eq!(control, Some(fakes[0].addr), "the default");
        let reason = reason.ok_or("a reason")?;
        assert_eq!(
            reason.matches("did not answer its list").count(),
            3,
            "{reason}"
        );
        Ok(())
    }
}
