// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What a media relay's answer looks like, independent of which relay gave it.
//!
//! These types were defined inside `src/rtpengine/control.rs`, next to the
//! parser that fills them from rtpengine's ng wire format. That put a shape
//! every relay produces behind a name only one relay owns, and it is the
//! boundary RP2 is about: `EndpointAssertion::relay_asserted` and `Reconciler`
//! were never rtpengine-specific, the module they lived in was.
//!
//! Nothing here knows about bencode, ng, or a cookie. A second control decoder
//! parses its own wire format into these same types and the reconciler above it
//! cannot tell which one answered -- which is the point, and is what
//! `relay_seam_test` holds in place.

/// A command that only reads. There is deliberately no way to say anything
/// else.
///
/// See the module note: the point is not that sipnab avoids sending `delete`,
/// it is that this type cannot express it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOnlyCommand {
    /// Every active Call-ID the relay knows, bounded by `limit`.
    ///
    /// rtpengine defaults to 32 and warns that raising it may exceed a UDP
    /// datagram, which is why [`crate::rtpengine::control::ControlRequest`] carries whether the answer
    /// was complete.
    List {
        /// How many Call-IDs to ask for.
        limit: u32,
    },
    /// The relay's own counters: what it has handled, dropped and is holding.
    ///
    /// Relay-WIDE, and deliberately not a `Query` with a special call-id. A
    /// call-scoped query and a box-wide statistic answer different questions,
    /// and overloading one on the other would make "no such call" and "no
    /// statistics" the same refusal.
    ///
    /// Carries no arguments. `query_relay` already refuses an agent-supplied
    /// destination -- an agent that could name the target would turn the MCP
    /// surface into a way to send packets to a host of its choosing -- and a
    /// statistics command with a host field would reopen exactly that.
    Statistics,
    /// One call's tags and streams.
    Query {
        /// The Call-ID to ask about.
        call_id: String,
    },
}
/// What a `list` answered, and whether it answered fully.
///
/// The completeness flag is not decoration. rtpengine returns 32 Call-IDs by
/// default; covering 32 of 400 calls and saying nothing reports the other 368
/// as orphans and looks exactly like a run that worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    /// The Call-IDs the relay returned.
    pub call_ids: Vec<String>,
    /// Whether the relay had more than it returned.
    pub truncated: bool,
}
/// What a relay answered, decoded from its reply.
///
/// rtpengine answers `{"result": "ok", ...}` or `{"result": "error", ...}`.
/// An error is not a transport failure and must not be reported as one: the
/// relay was reached, understood the question, and declined it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlReply {
    /// A `list` answer.
    Calls(Enumeration),
    /// A `query` answer: one call, as the relay holds it.
    Call(CallView),
    /// A `statistics` answer: the relay's own counters, as it reported them.
    ///
    /// Name/value pairs kept as the relay wrote them rather than mapped onto a
    /// schema of sipnab's own. The two relays count different things under
    /// different names, and inventing a common shape would assert an
    /// equivalence neither of them promised.
    Statistics(Vec<(String, String)>),
    /// The relay refused, with its own words.
    Refused {
        /// What the relay said.
        reason: String,
    },
}

/// What a reply of the wrong kind did, with the kind that was asked for. The
/// one place these words are written: [`ReplyKind::wrong_kind_reason`] and
/// [`ReplyKind::wrong_kind_phrase`] are built from it.
macro_rules! wrong_kind_phrase {
    ($asked:literal) => {
        concat!("answered with something other than ", $asked)
    };
}

/// The kind of answer a question to a relay asks for.
///
/// A reply of another kind arrived and cannot be the answer, so every surface
/// calls it `suspect`, for the reason [`ReplyKind::wrong_kind_reason`] gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// A `list` asks for the Call-IDs the relay holds.
    CallList,
    /// A `query` asks for one call as the relay holds it.
    CallView,
    /// A statistics question asks for the relay's counters.
    Statistics,
}

impl ReplyKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 3] = [Self::CallList, Self::CallView, Self::Statistics];

    /// Why a reply of another kind is `suspect`, in the words every surface
    /// uses for it.
    #[must_use]
    pub fn wrong_kind_reason(self) -> &'static str {
        match self {
            Self::CallList => concat!("the relay ", wrong_kind_phrase!("a call list")),
            Self::CallView => concat!("the relay ", wrong_kind_phrase!("a call view")),
            Self::Statistics => concat!("the relay ", wrong_kind_phrase!("statistics")),
        }
    }

    /// The same reason without its subject, for a line that names the relay
    /// itself: `<relay> answered with something other than <the kind>`.
    #[must_use]
    pub fn wrong_kind_phrase(self) -> &'static str {
        match self {
            Self::CallList => wrong_kind_phrase!("a call list"),
            Self::CallView => wrong_kind_phrase!("a call view"),
            Self::Statistics => wrong_kind_phrase!("statistics"),
        }
    }
}

impl ControlReply {
    /// Why this reply cannot answer a question that asked for `asked`.
    ///
    /// `None` when the reply is of that kind, or is a refusal: a relay can
    /// decline any question, and its refusal is its answer. Otherwise the
    /// reason the reply is `suspect`.
    #[must_use]
    pub fn wrong_kind_for(&self, asked: ReplyKind) -> Option<&'static str> {
        let kind = match self {
            Self::Calls(_) => ReplyKind::CallList,
            Self::Call(_) => ReplyKind::CallView,
            Self::Statistics(_) => ReplyKind::Statistics,
            Self::Refused { .. } => return None,
        };
        (kind != asked).then(|| asked.wrong_kind_reason())
    }

    /// Why this reply holds no answer to a question that asked for `asked`.
    ///
    /// `None` when the reply is of the kind asked for. A refusal is
    /// [`Unanswered::Refused`] whatever was asked: the relay's own words, and
    /// the outcome `refused`. A reply of another kind is
    /// [`Unanswered::WrongKind`]: the outcome `suspect`, for the reason
    /// [`wrong_kind_for`](Self::wrong_kind_for) gives.
    ///
    /// Every surface reads a reply through this, so a list, a query and a
    /// statistics question classify a refusal and a wrong kind the same way.
    #[must_use]
    pub fn unanswered(&self, asked: ReplyKind) -> Option<Unanswered<'_>> {
        if let Self::Refused { reason } = self {
            return Some(Unanswered::Refused(reason));
        }
        self.wrong_kind_for(asked).map(Unanswered::WrongKind)
    }
}

impl ReplyKind {
    /// The outcome and the detail every surface reports for `reply`, a reply
    /// of `subject` that holds no answer to a question for this kind:
    /// `refused` with `<subject>: <the relay's words>`, or `suspect` with
    /// [`wrong_kind_reason`](Self::wrong_kind_reason).
    ///
    /// `subject` names the relay, and the call when one call was asked about.
    /// A reply of this kind is the caller's to read, not to pass here; for one
    /// the answer is the `suspect` of a wrong kind, so nothing reads as `ok`.
    #[must_use]
    pub fn unanswered_by(
        self,
        reply: &ControlReply,
        subject: &str,
    ) -> (crate::stats_vocab::StatisticsOutcome, String) {
        use crate::stats_vocab::StatisticsOutcome;
        match reply.unanswered(self) {
            Some(Unanswered::Refused(reason)) => {
                (StatisticsOutcome::Refused, format!("{subject}: {reason}"))
            }
            Some(Unanswered::WrongKind(why)) => (StatisticsOutcome::Suspect, why.to_string()),
            None => (
                StatisticsOutcome::Suspect,
                self.wrong_kind_reason().to_string(),
            ),
        }
    }
}

/// Why a reply holds no answer: see [`ControlReply::unanswered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unanswered<'a> {
    /// The relay declined, in its own words: the outcome `refused`.
    Refused(&'a str),
    /// The reply is of another kind than the one asked for: the outcome
    /// `suspect`, with the reason.
    WrongKind(&'static str),
}

/// A relay reply arrived but cannot be trusted -- ST-S4 `suspect` (the answer's
/// own problem), never `unreachable` (asked, nothing came back).
///
/// The reason is supplied by whatever read the reply, so this type stays
/// vendor-neutral the way the rest of this module is: the control decoder that
/// finds a reply answering a different transaction passes its own words in, and
/// this carries them to the surface unchanged. Two causes today: a reply whose
/// cookie does not match the request, which is discarded and never
/// interpreted, and a reply that arrived and could not be read (no framing, not
/// bencode, or missing what its answer needs). Either marks the fetch so a
/// surface classifies it suspect rather than as no answer at all.
#[derive(Debug, thiserror::Error)]
#[error("a relay reply could not be trusted: {reason}")]
pub struct UntrustedReply {
    /// Why the reply could not be trusted, in the decoder's own words.
    pub reason: String,
}

/// Classify a relay control-fetch failure into an ST-S4 outcome.
///
/// `Suspect` when a reply arrived and could not be trusted ([`UntrustedReply`]):
/// the answer's own problem, never smoothed into "no answer". Otherwise
/// `Unreachable`: asked, and nothing valid came back -- a timeout, a refused
/// connection, a socket error, indistinguishable over UDP and all reported the
/// same weaker true way. Single-sourced so every surface maps a fetch failure to
/// the same classification rather than each re-deciding from the error text.
#[must_use]
pub fn fetch_error_outcome(err: &anyhow::Error) -> crate::stats_vocab::StatisticsOutcome {
    use crate::stats_vocab::StatisticsOutcome;
    if err.downcast_ref::<UntrustedReply>().is_some() {
        StatisticsOutcome::Suspect
    } else {
        StatisticsOutcome::Unreachable
    }
}

/// One relay-side port, and who the relay exchanges media with on it.
///
/// This is the join key an unexplained stream needs. sipnab sees packets
/// arriving at the relay's own address and port; the relay is the only thing
/// that knows which call that port was allocated for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStream {
    /// The relay's own address for this stream, as it appears on the wire.
    pub local_address: String,
    /// The relay's own port. The half sipnab can see without any signaling.
    pub local_port: u16,
    /// Where the relay currently sends, once it has learned it.
    pub endpoint: Option<String>,
    /// What the far side advertised in SDP, which may differ from `endpoint`
    /// behind NAT -- and the difference is often the bug being chased.
    pub advertised_endpoint: Option<String>,
    /// Whether this port carries RTCP rather than RTP, from the relay's flags.
    pub is_rtcp: bool,
    /// Every SSRC the relay has seen on this port, ingress and egress.
    ///
    /// A second join key, and a better one where a capture is taken off-path
    /// from the relay: an SSRC follows the media even when the addresses do
    /// not survive the path.
    pub ssrcs: Vec<u32>,
    /// What the relay counted on this socket, and when, as it reported it.
    pub facts: RelayStreamFacts,
}

/// Packets, bytes and errors one relay socket counted in one direction.
///
/// Each field is its own `Option`: a relay version that reports packets and
/// bytes but no errors keeps the two it reported. `None` is "not reported",
/// never zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamCounters {
    /// Packets, where the relay reported them.
    pub packets: Option<u64>,
    /// Bytes, where the relay reported them.
    pub bytes: Option<u64>,
    /// Errors, where the relay reported them.
    pub errors: Option<u64>,
}

/// What a relay reported about one of its sockets, beyond the join keys.
///
/// Every field is absent when the relay did not report it. Nothing here is
/// sipnab's measurement: these are the relay's own counters, read from its
/// answer and never mixed with what a capture saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayStreamFacts {
    /// The media section this socket belongs to, as the relay numbered it.
    pub media_index: Option<u32>,
    /// What arrived at this socket from the far side.
    pub ingress: StreamCounters,
    /// What the relay sent out of this socket.
    pub egress: StreamCounters,
    /// When the relay last received a packet here, in whole seconds on the
    /// relay's own clock.
    pub last_packet: Option<i64>,
    /// The socket's flags as the relay wrote them, or `None` when the answer
    /// carried no flags list.
    pub flags: Option<Vec<String>>,
}
/// One side of a call, as the relay holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTag {
    /// The SIP tag identifying this side.
    pub tag: String,
    /// The tags this side is in an offer/answer DIALOG with.
    ///
    /// Offer/answer only. A relay also lets one side receive another's media
    /// by SUBSCRIPTION -- which is how relay-side recording and forking are
    /// built -- and a subscriber is not the party the call is with. Folding
    /// the two together reports a recorder as the other end, so a two-party
    /// call comes back with three parties. They are separated here, at the
    /// only place that can still tell them apart.
    pub in_dialogue_with: Vec<String>,
    /// The tags whose media this side receives by SUBSCRIPTION.
    ///
    /// Kept rather than discarded: a subscription sipnab drops is a relay
    /// stream it will never be able to explain, and [`Self::is_media_subscriber`]
    /// is computed from it.
    pub media_subscriptions: Vec<String>,
    /// The codec the relay recorded for this side, where it recorded one.
    pub codec: Option<String>,
    /// Ports the relay holds for this side, RTP and RTCP together.
    pub streams: Vec<RelayStream>,
}
impl RelayTag {
    /// Whether this side CONSUMES the call's media rather than being party to
    /// it.
    ///
    /// A recording fork or a media subscriber arrives from a relay as a tag of
    /// its own, holding its own relay ports -- because a query walks every
    /// side the relay is holding, not only the two that signed the call. Those
    /// ports do belong to the call and are attributed to it; what they are not
    /// is a leg of it.
    ///
    /// The test is that this side takes media from another and answers no
    /// offer of its own. A leg that has not been answered yet has neither, so
    /// it is not swept up: an unanswered offer is a call with one party, not a
    /// call with a subscriber.
    #[must_use]
    pub fn is_media_subscriber(&self) -> bool {
        !self.media_subscriptions.is_empty() && self.in_dialogue_with.is_empty()
    }
}
/// What a relay knows about one call.
///
/// The Call-ID is carried from the REQUEST, not read from the reply: a
/// rtpengine `query` answer does not echo the Call-ID it was asked about
/// (verified against 12.5.1), so pairing the answer with its question is the
/// caller's job and cannot be checked from the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallView {
    /// The Call-ID this view answers for, from the request.
    pub call_id: String,
    /// Each side of the call.
    pub tags: Vec<RelayTag>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One reply of each kind, with the kind it answers (`None` for a
    /// refusal, which answers every question).
    fn one_of_each() -> [(ControlReply, Option<ReplyKind>); 4] {
        [
            (
                ControlReply::Calls(Enumeration {
                    call_ids: vec!["call-1@192.0.2.10".to_string()],
                    truncated: false,
                }),
                Some(ReplyKind::CallList),
            ),
            (
                ControlReply::Call(CallView {
                    call_id: "call-1@192.0.2.10".to_string(),
                    tags: Vec::new(),
                }),
                Some(ReplyKind::CallView),
            ),
            (
                ControlReply::Statistics(vec![("total".to_string(), "3".to_string())]),
                Some(ReplyKind::Statistics),
            ),
            (
                ControlReply::Refused {
                    reason: "busy".to_string(),
                },
                None,
            ),
        ]
    }

    /// A reply answers the question that asked for its kind, a refusal
    /// answers any question, and every other pairing is `suspect` for the
    /// reason of the kind that was asked for.
    #[test]
    fn a_reply_of_another_kind_is_suspect_for_the_kind_asked() {
        for (reply, kind) in one_of_each() {
            for asked in ReplyKind::ALL {
                let expected = match kind {
                    Some(k) if k != asked => Some(asked.wrong_kind_reason()),
                    _ => None,
                };
                assert_eq!(
                    reply.wrong_kind_for(asked),
                    expected,
                    "{reply:?} asked for {asked:?}"
                );
            }
        }
    }

    /// The reasons are the words REST and `--relay-holdings` already used,
    /// and no two kinds share one.
    #[test]
    fn each_kind_has_its_own_reason() {
        assert_eq!(
            ReplyKind::CallList.wrong_kind_reason(),
            "the relay answered with something other than a call list",
            "the call-list reason"
        );
        assert_eq!(
            ReplyKind::CallView.wrong_kind_reason(),
            "the relay answered with something other than a call view",
            "the call-view reason"
        );
        assert_eq!(
            ReplyKind::Statistics.wrong_kind_reason(),
            "the relay answered with something other than statistics",
            "the statistics reason"
        );
    }

    /// What every surface reports for a reply that holds no answer: a
    /// refusal is `refused` with the relay's words after the subject, and any
    /// other reply is `suspect` with the reason of the kind asked for.
    #[test]
    fn the_report_for_an_unanswered_question_is_refused_or_suspect() {
        use crate::stats_vocab::StatisticsOutcome;
        for (reply, kind) in one_of_each() {
            for asked in ReplyKind::ALL {
                let expected = match kind {
                    None => (StatisticsOutcome::Refused, "relay A: busy".to_string()),
                    Some(_) => (
                        StatisticsOutcome::Suspect,
                        asked.wrong_kind_reason().to_string(),
                    ),
                };
                assert_eq!(
                    asked.unanswered_by(&reply, "relay A"),
                    expected,
                    "{reply:?} asked for {asked:?}"
                );
            }
        }
    }

    /// Every question reads a refusal as the relay's own words, a reply of
    /// its own kind as the answer, and any other reply as the wrong kind.
    #[test]
    fn a_refusal_is_refused_whatever_was_asked() {
        for (reply, kind) in one_of_each() {
            for asked in ReplyKind::ALL {
                let expected = match kind {
                    None => Some(Unanswered::Refused("busy")),
                    Some(k) if k == asked => None,
                    Some(_) => Some(Unanswered::WrongKind(asked.wrong_kind_reason())),
                };
                assert_eq!(
                    reply.unanswered(asked),
                    expected,
                    "{reply:?} asked for {asked:?}"
                );
            }
        }
    }

    /// The suspect pairings exist: of the twelve reply/question pairs, the
    /// six where a non-refusal reply meets a question for another kind.
    #[test]
    fn six_pairings_are_suspect() {
        let suspect = one_of_each()
            .iter()
            .flat_map(|(reply, _)| ReplyKind::ALL.map(|asked| reply.wrong_kind_for(asked)))
            .filter(Option::is_some)
            .count();
        assert_eq!(suspect, 6, "three kinds, each wrong for two questions");
    }

    /// The phrase is the reason without its subject, for every kind.
    #[test]
    fn the_phrase_is_the_reason_without_the_relay() {
        for kind in ReplyKind::ALL {
            assert_eq!(
                format!("the relay {}", kind.wrong_kind_phrase()),
                kind.wrong_kind_reason(),
                "{kind:?}"
            );
        }
        assert_eq!(
            ReplyKind::CallList.wrong_kind_phrase(),
            "answered with something other than a call list",
            "the call-list phrase"
        );
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

    /// No surface writes the wrong-kind words itself: outside this file, no
    /// source line under `src/` holds them, in product code or in a test.
    ///
    /// REST, the TUI, `--relay-holdings`, `--relay-sessions`, the batch
    /// statistics poll and the fleet's engine listing each had the sentence
    /// as a literal, and the MCP tool had no such sentence at all.
    #[test]
    fn the_wrong_kind_words_are_written_in_this_file_only() -> Result<(), Box<dyn std::error::Error>>
    {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files)?;
        assert!(
            files.len() > 100,
            "the walk found src/: {} files",
            files.len()
        );
        let words: Vec<String> = ["a call list", "a call view", "statistics"]
            .iter()
            .map(|kind| format!("something other than {kind}"))
            .collect();
        let mut found = Vec::new();
        for path in files {
            if path.ends_with("relay/types.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            for (n, line) in text.lines().enumerate() {
                if words.iter().any(|w| line.contains(w.as_str())) {
                    found.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
        assert!(
            found.is_empty(),
            "these lines write the wrong-kind words; take them from ReplyKind: {found:#?}"
        );
        Ok(())
    }
}
