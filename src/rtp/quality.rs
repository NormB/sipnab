// SPDX-License-Identifier: MIT OR Apache-2.0

//! Advanced RTP quality metrics.
//!
//! Extends sipnab's basic jitter/loss tracking with:
//! - **MOS estimation** via a simplified E-model (ITU-T G.107)
//! - **Burst/gap analysis** based on RFC 3611 concepts
//!
//! These metrics give operators a human-meaningful quality score and
//! distinguish between random packet loss (tolerable) and bursty loss
//! (perceptually severe at the same overall rate).

// Index loops read more clearly than iterators in these numeric E-model and
// burst/gap calculations, where the index itself is part of the arithmetic.
#![allow(clippy::needless_range_loop)]

// ── Public types ─────────────────────────────────────────────────────

/// Burst/gap analysis results following RFC 3611 concepts.
///
/// A "burst" is defined as 3 or more consecutive lost packets. A "gap"
/// is the period of received packets between bursts. Bursty loss patterns
/// are perceptually worse than uniformly distributed loss at the same rate.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct BurstGapAnalysis {
    /// Number of loss bursts detected.
    pub burst_count: u32,
    /// Average burst duration in milliseconds.
    pub burst_duration_ms: f64,
    /// Average gap duration in milliseconds.
    pub gap_duration_ms: f64,
    /// Packet loss rate during bursts (0.0 to 1.0).
    pub burst_loss_rate: f64,
    /// Packet loss rate during gaps (0.0 to 1.0).
    pub gap_loss_rate: f64,
    /// `true` if loss is bursty (worse perceptually than random loss).
    pub is_bursty: bool,
}

// ── MOS estimation ───────────────────────────────────────────────────

/// Estimate Mean Opinion Score using the simplified E-model (ITU-T G.107).
///
/// Produces a score on the standard 1.0-4.5 MOS scale based on jitter,
/// packet loss, and codec type. Assumes a baseline one-way delay of 100ms
/// (typical for well-provisioned VoIP).
///
/// **No surface in this crate calls this**, and a gate
/// (`no_surface_scores_a_mos_on_the_assumed_delay`) keeps it that way. It
/// remains as the NAMED assumption — the reference point
/// [`DEFAULT_ONE_WAY_DELAY_MS`] documents and the tests pin the model against
/// — while everything that reports a number to a human or an agent goes
/// through [`MosDelay`], which resolves the delay from the capture's own RTCP
/// and says where it came from. A caller outside the crate that wants the old
/// behaviour still has it; a caller that wants the truth wants
/// [`estimate_mos_with_delay`].
///
/// # Arguments
///
/// * `jitter_ms` — measured interarrival jitter in milliseconds.
/// * `loss_pct` — estimated packet loss percentage (0.0-100.0).
/// * `codec` — optional codec name (e.g., `"PCMU"`, `"G729"`, `"opus"`).
///
/// # Returns
///
/// MOS value clamped to the range \[1.0, 4.5\].
///
/// # Examples
///
/// ```
/// use sipnab::estimate_mos;
///
/// // A clean G.711 call scores near the codec ceiling...
/// let clean = estimate_mos(5.0, 0.0, Some("PCMU"));
/// assert!(clean > 4.0, "got {clean}");
///
/// // ...while heavy jitter and loss on G.729 drags the score down.
/// let degraded = estimate_mos(80.0, 15.0, Some("G729"));
/// assert!(degraded < 3.0, "got {degraded}");
/// assert!((1.0..=4.5).contains(&degraded));
/// ```
pub fn estimate_mos(jitter_ms: f64, loss_pct: f64, codec: Option<&str>) -> f64 {
    estimate_mos_with_delay(jitter_ms, loss_pct, codec, DEFAULT_ONE_WAY_DELAY_MS)
}

/// One-way path delay assumed when nothing measured it, in milliseconds.
///
/// An ASSUMPTION, not a measurement, and the only unmeasured input to
/// [`estimate_mos`] that is not already described by [`MosGrounding`] or
/// [`MosProvenance`]. Those two say whether G.113 publishes an impairment
/// factor for the codec, and whether sipnab scored the stream or an endpoint
/// asserted it. Neither can say that the delay term was guessed.
///
/// 100 ms is a reasonable domestic figure and wrong by a wide margin on an
/// intercontinental or satellite leg, where one-way delay runs 150-400 ms.
/// G.107's `Id` has a knee at 177.3 ms, above which the penalty grows with a
/// square-root term — so the assumption does not merely shift the score, it
/// keeps the calculation on the wrong side of that knee, and the MOS comes out
/// more than a full point high for exactly the deployments whose audio is
/// worst.
///
/// Pass the real figure to [`estimate_mos_with_delay`] whenever it is known.
/// RTCP carries it: the XR VoIP-metrics block reports `round_trip_delay`
/// directly, and an RR's LSR/DLSR pair yields the same round trip, of which
/// one-way is conventionally half.
pub const DEFAULT_ONE_WAY_DELAY_MS: f64 = 100.0;

/// Equipment impairment factor used for a codec sipnab has no value for.
///
/// A PLACEHOLDER, and the number is chosen to be unremarkable rather than
/// right: it is what makes an unknown codec score the same as an unidentified
/// stream, which is the honest answer when nothing is known. Every caller that
/// shows the resulting MOS must consult [`mos_grounding`] and say so.
pub const PLACEHOLDER_UNKNOWN_CODEC_IE: f64 = 5.0;

/// Largest equipment impairment factor the E-model can carry.
///
/// Not a policy figure. G.107 Appendix I computes `Ie_eff = Ie + (95 - Ie) *
/// Ppl / (Ppl/BurstR + Bpl)`, so at `Ie = 95` the loss term vanishes and above
/// it the term goes NEGATIVE — more packet loss would raise the score. An `Ie`
/// at or past 95 does not make the model pessimistic, it inverts it, so
/// `crate::config::MediaConfig::validate` refuses one by name.
pub const MAX_CODEC_IE: f64 = 95.0;

/// Operator-declared equipment impairment factors, by lower-cased codec name.
///
/// Process-wide and written once at startup, the same shape as
/// `crate::rtp::stream::set_lost_seq_log_cap` and for the same reason:
/// [`estimate_mos_with_delay`] is a free function reached from the CLI, the
/// REST API, the filter DSL, the Prometheus exporter, the TUI and the WASM
/// build, and not one of them is threaded a config. A table handed to some of
/// those is a declaration honoured on some surfaces and ignored on others,
/// which for a MOS means two surfaces disagreeing about the same stream — the
/// exact defect [`crate::rtp::bands::QualityBands`] exists to prevent for
/// colour.
static CODEC_IE: std::sync::LazyLock<parking_lot::RwLock<std::collections::HashMap<String, f64>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

/// Declare the operator-supplied impairment table for this process.
///
/// # Arguments
///
/// * `table` — codec name to `Ie`. Keys are lower-cased here, so a declaration
///   matches whichever way the SDP `rtpmap` spelled the codec. Values outside
///   `0.0..MAX_CODEC_IE` are DROPPED rather than clamped, because a clamped
///   impairment is a number the operator did not write being reported as
///   grounded in their declaration; the operator-facing refusal happens
///   earlier, in `crate::config::MediaConfig::validate` and in the loader, so
///   it can name the codec.
///
/// # Side effects
///
/// Replaces the process-wide table, affecting every MOS computed after this
/// call — including the grounding [`mos_grounding`] reports.
pub fn set_codec_ie_table(table: std::collections::HashMap<String, f64>) {
    let cleaned = table
        .into_iter()
        .filter(|(_, ie)| ie.is_finite() && *ie >= 0.0 && *ie < MAX_CODEC_IE)
        .map(|(name, ie)| (name.to_lowercase(), ie))
        .collect();
    *CODEC_IE.write() = cleaned;
}

/// The operator-declared `Ie` for `codec`, if one was declared.
///
/// Consulted by BOTH [`estimate_mos_with_delay`] and [`mos_grounding`], which
/// is what keeps the score and the confidence beside it from disagreeing — the
/// property `grounding_agrees_with_the_score` pins.
fn declared_codec_ie(codec: Option<&str>) -> Option<f64> {
    let codec = codec?;
    let table = CODEC_IE.read();
    // The empty table is the overwhelmingly common case — nothing declared —
    // and this is on the path of every MOS the TUI, the exporter and the filter
    // DSL compute. Checking it first keeps that case to one uncontended read
    // and no allocation, rather than lower-casing a codec name per stream per
    // refresh to look it up in a map that has nothing in it.
    if table.is_empty() {
        return None;
    }
    table.get(&codec.to_lowercase()).copied()
}

/// [`estimate_mos`], with the one-way path delay supplied rather than assumed.
///
/// `one_way_delay_ms` is the network path delay in one direction, EXCLUDING
/// jitter — jitter is added on top here, because a jittery path is worse than
/// a smooth one of the same length and the receiver's de-jitter buffer pays
/// for both.
///
/// A delay outside a plausible range is clamped rather than propagated: the
/// result of this function is displayed to an operator as a measurement, and
/// laundering a bad input into a confident-looking 7.3 or a NaN is worse than
/// bounding it.
#[must_use]
pub fn estimate_mos_with_delay(
    jitter_ms: f64,
    loss_pct: f64,
    codec: Option<&str>,
    one_way_delay_ms: f64,
) -> f64 {
    // Codec-specific equipment impairment factor (Ie)
    //
    // The operator's own table is consulted FIRST, and deliberately outranks
    // the built-ins. sipnab's three are the narrowband G.107 figures for a
    // generic implementation; an operator scoring one transcoding gateway, or a
    // G.729 running at a different bit rate, knows their network better than a
    // published average does — and there is no reading of "I declared this
    // codec's impairment" that means "use yours instead". A declaration that
    // silently lost to a built-in would be the worst kind of setting: accepted,
    // documented, and inert on exactly the codecs an operator is most likely to
    // measure.
    let ie = match declared_codec_ie(codec) {
        Some(declared) => declared,
        None => match codec {
            Some("PCMU") | Some("PCMA") => 0.0,   // G.711 baseline
            Some("G729") | Some("G.729") => 10.0, // G.729 compression impairment
            Some("opus") | Some("Opus") => 0.0,   // Opus comparable to G.711
            // PLACEHOLDER, not a measurement. See `mos_grounding`.
            //
            // ITU-T G.113 Table I.1 publishes Ie for a specific list of codecs and
            // sipnab knows three of them. Everything else — AMR, AMR-WB, EVS,
            // G.722, G.726, iLBC — lands here and scores identically to a stream
            // whose codec was never identified at all: `estimate_mos(10.0, 0.0,
            // Some("AMR-WB"))` and `estimate_mos(10.0, 0.0, None)` both return
            // 4.216.
            //
            // AMR-WB cannot be rescued here even though G.113 publishes values for
            // it, and the reason is worth knowing. Those values are `Ie,WB`, on the
            // wideband G.107.1 scale that anchors at 129; this function is the
            // narrowband G.107, anchored at 93.2. Dropping a wideband Ie into it is
            // not an approximation but a 35.8-point scale error. AMR-WB is scored
            // in `crate::rtp::emodel_wb` instead, which also needs something this
            // signature does not carry: the *mode*. Its nine modes span `Ie,WB` 1
            // to 41 — about 4.49 down to 3.51 MOS — so "AMR-WB" alone leaves a full
            // MOS point of ambiguity, and only an SDP `mode-set` pinning one mode,
            // or the RTP payload header, resolves it.
            //
            // AMR narrowband and EVS stay here permanently. G.113 has no AMR-NB row
            // at all, and publishes EVS only as a fullband `Ie,fb` for SWB mode on
            // the third scale (G.107.2, anchored at 148).
            //
            // An operator who KNOWS the figure for their network can supply it —
            // `[media.codec_ie]`, consulted above — and `mos_grounding` then reports
            // the result as declared rather than published, so a declaration is
            // never laundered into a G.113 citation. Everything still landing here
            // is a codec nobody has told sipnab about.
            //
            // Callers that present this number to a human or an agent must consult
            // `mos_grounding` and say so, rather than letting a guess wear the
            // shape of a measurement.
            _ => PLACEHOLDER_UNKNOWN_CODEC_IE,
        },
    };

    // Effective equipment impairment with packet loss (Ie-eff)
    // From G.107 Appendix I: Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl / BurstR + Bpl)
    // Simplified with BurstR=1, Bpl=10 for random loss
    let ie_eff = ie + (95.0 - ie) * loss_pct / (loss_pct + 10.0);

    // Delay impairment (Id). The path delay is an INPUT now; jitter is added
    // on top of it. A non-finite or negative caller value is treated as the
    // default rather than trusted, and the total is bounded so an absurd input
    // cannot leave the MOS scale.
    let path = if one_way_delay_ms.is_finite() && one_way_delay_ms >= 0.0 {
        one_way_delay_ms
    } else {
        DEFAULT_ONE_WAY_DELAY_MS
    };
    let jitter = if jitter_ms.is_finite() && jitter_ms >= 0.0 {
        jitter_ms
    } else {
        0.0
    };
    // 3000 ms is far past the point where the E-model says "unusable"; the cap
    // exists so the sqrt term cannot overflow into a nonsense R-factor.
    let delay_ms = (path + jitter).min(3000.0);
    let id = if delay_ms > 177.3 {
        0.024 * delay_ms + 0.11 * (delay_ms - 177.3) * (delay_ms - 177.3).sqrt()
    } else {
        0.024 * delay_ms
    };

    // R-factor: R = R0 - Is - Id - Ie_eff + A
    // R0 = 93.2 (default signal-to-noise), Is = 0 (no simultaneous impairment), A = 0
    let r = 93.2 - id - ie_eff;

    // R-factor to MOS conversion (ITU-T G.107 Annex B)
    r_to_mos(r)
}

/// One-way delay for a stream, from RTCP when the far end reported it.
///
/// RFC 3611 Section 4.7's VoIP-metrics block carries `round_trip_delay`
/// directly. One-way is conventionally half of it — an approximation, because
/// paths are not always symmetric, but a measured round trip halved beats a
/// constant guessed at build time by a wide margin on exactly the long-haul
/// legs where the guess is worst.
///
/// Returns `None` when nothing measured it, so the caller can say so rather
/// than substitute a number and present it as a measurement. A zero RTT is
/// treated as absent: RFC 3611 uses 0 for "not available", and a genuinely
/// zero round trip does not occur on a path with two endpoints.
#[must_use]
pub fn one_way_delay_from_rtt_ms(round_trip_delay_ms: u16) -> Option<f64> {
    (round_trip_delay_ms > 0).then(|| f64::from(round_trip_delay_ms) / 2.0)
}

/// One-way delay from a round trip sipnab DERIVED, rather than one it was told.
///
/// The sibling of [`one_way_delay_from_rtt_ms`] for
/// [`RttSource::SenderReportEcho`](crate::rtp::rtcp::RttSource::SenderReportEcho):
/// the figure
/// [`rtt_from_sender_report_echo`](crate::rtp::rtcp::rtt_from_sender_report_echo)
/// computes from an RR's `LSR`/`DLSR` pair. It takes an `f64` because that
/// derivation produces one — RFC 3550 §6.4.1's units are 1/65536 s, not whole
/// milliseconds — and the two are kept as separate entry points rather than one
/// generic halver so a caller cannot pass an echo figure where the wire field
/// was meant, or the reverse.
///
/// **Halving is the same convention and the same approximation** as for a
/// reported round trip, with one extra caveat stacked on it: the echo figure is
/// anchored on the capture point, so on any tap that does not sit with the SR's
/// sender it is a LOWER BOUND on the endpoint-to-endpoint round trip. Half of a
/// lower bound is a lower bound, so a MOS resting on this is optimistic — which
/// is why the result is labelled [`DelaySource::DerivedFromEcho`] and never
/// folded in with what an endpoint actually reported.
///
/// Zero is absent, for the same reason as in the reported case: a round trip of
/// exactly zero does not occur on a path with two endpoints, so it is the
/// derivation coming up empty rather than a measurement of no delay. Non-finite
/// is absent too — arithmetic, not evidence.
#[must_use]
pub fn one_way_delay_from_derived_rtt_ms(round_trip_ms: f64) -> Option<f64> {
    (round_trip_ms.is_finite() && round_trip_ms > 0.0).then_some(round_trip_ms / 2.0)
}

/// Where the one-way delay behind a MOS came from.
///
/// A sibling of [`MosProvenance`], and it exists for the same reason: the
/// remedy differs by source. A score that looks wrong under
/// [`Declared`](Self::Declared) means checking the number the operator set; under
/// [`ReportedByEndpoint`](Self::ReportedByEndpoint) it means suspecting the far
/// end, or whoever forged its datagram; under
/// [`DerivedFromEcho`](Self::DerivedFromEcho) it means suspecting where the tap
/// sits, or the clock it keeps; under [`Assumed`](Self::Assumed) it
/// means the delay was never known at all and the score is only as good as a
/// domestic guess.
///
/// The variants are written in preference order and read that way in
/// [`resolve_one_way_delay`], which is the only thing that decides between
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DelaySource {
    /// The operator declared it for this deployment. Trusted first, because it
    /// is the only source that cannot be influenced by a packet on the wire.
    Declared,
    /// Halved from an RTCP round trip the far end reported.
    ///
    /// Better than a guess and NOT a measurement sipnab made: RFC 3550 carries
    /// no authentication, so a broken or hostile endpoint can move this. Used
    /// only when the operator declared nothing, and always recorded, so a MOS
    /// resting on a remote claim can be told apart from one resting on the
    /// operator's own figure.
    ReportedByEndpoint,
    /// Halved from a round trip SIPNAB DERIVED from an RR's `LSR`/`DLSR` pair,
    /// per RFC 3550 §6.4.1.
    ///
    /// A different provenance CLASS from
    /// [`ReportedByEndpoint`](Self::ReportedByEndpoint), not a weaker sample of
    /// it, which is why it gets its own variant rather than borrowing that
    /// name. Nobody reported this figure; sipnab computed it, from two
    /// timestamps stamped on two different clocks, anchored on when the CAPTURE
    /// POINT saw the report. It is the true endpoint-to-endpoint round trip
    /// only when the tap sits with the sender of the SR, and a lower bound
    /// otherwise, because the leg beyond the tap is not in it.
    ///
    /// Ranked BELOW an endpoint's own figure for exactly that reason: a
    /// reported round trip describes the call, and this describes a path
    /// segment plus a vantage point. It is ranked well above
    /// [`Assumed`](Self::Assumed) all the same, because plain receiver reports
    /// are mandatory in RFC 3550 while an XR is rare — so this is the source
    /// that reaches ordinary traffic, and a lower bound derived from the
    /// capture beats a constant chosen at build time.
    DerivedFromEcho,
    /// Nothing said. [`DEFAULT_ONE_WAY_DELAY_MS`] stood in.
    Assumed,
}

impl DelaySource {
    /// A short label for a reader, suitable for putting beside the number.
    ///
    /// Lives here rather than in each view for the reason
    /// [`MosProvenance::label`] does: a provenance rendered in two places is a
    /// provenance that can be worded two ways, and the whole value of the
    /// distinction is that a reader meets the same word for the same thing.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::ReportedByEndpoint => "per far end",
            Self::DerivedFromEcho => "from RR echo",
            Self::Assumed => "assumed",
        }
    }

    /// Whether a delay term this good is a stand-in rather than evidence.
    ///
    /// True only for [`Assumed`](Self::Assumed). The point of the question is
    /// that everything else — including a lower bound sipnab derived itself —
    /// is anchored on something that happened on the wire, and a caller
    /// deciding whether to caveat the MOS should caveat exactly one case.
    #[must_use]
    pub fn is_assumed(self) -> bool {
        matches!(self, Self::Assumed)
    }
}

/// Resolve the one-way delay for a stream, and say where it came from.
///
/// Order: what the operator declared, then what the far end reported, then what
/// sipnab derived from an RR's sender-report echo, then the assumption.
///
/// The operator wins because theirs is the only figure that cannot be changed
/// by an unauthenticated packet — and because they are the one who knows the
/// trunk is satellite. A reported round trip beats a derived one because the
/// two are not the same quantity: an endpoint's XR figure is the round trip
/// between the two RTP interfaces, which is what ITU-T G.114 is about, while
/// the echo is anchored on the capture point and is a lower bound on any tap
/// that does not sit with the SR's sender. Weaker evidence about the right
/// quantity still loses to stronger evidence about the right quantity.
///
/// The echo nonetheless beats the assumption on the overwhelming majority of
/// traffic, and that is the point of it: RFC 3550 makes plain receiver reports
/// mandatory while XR VoIP-metrics blocks are rare, so before this rank existed
/// the delay term fell to [`DEFAULT_ONE_WAY_DELAY_MS`] on essentially every
/// call — a domestic guess feeding the score an operator escalates on, on a
/// long-haul leg where G.107's `Id` knee at 177.3 ms makes it wrong by more
/// than a full MOS point.
#[must_use]
pub fn resolve_one_way_delay(
    declared_ms: Option<f64>,
    reported_rtt_ms: Option<u16>,
    derived_rtt_ms: Option<f64>,
) -> (f64, DelaySource) {
    if let Some(d) = declared_ms.filter(|d| d.is_finite() && *d >= 0.0) {
        return (d, DelaySource::Declared);
    }
    if let Some(one_way) = reported_rtt_ms.and_then(one_way_delay_from_rtt_ms) {
        return (one_way, DelaySource::ReportedByEndpoint);
    }
    if let Some(one_way) = derived_rtt_ms.and_then(one_way_delay_from_derived_rtt_ms) {
        return (one_way, DelaySource::DerivedFromEcho);
    }
    (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed)
}

/// What one surface can see about the one-way delay behind a stream's MOS.
///
/// [`resolve_one_way_delay`] is the RANKING; this is what carries its three
/// inputs to a scorer holding a stream but not the store the RTCP landed in.
/// Two of those inputs live in the store's provenance side-table rather than on
/// the stream — a round trip is somebody else's measurement — so a surface
/// iterating `&RtpStream` cannot reach them, and every surface that scored a
/// MOS without a store therefore scored it on [`DEFAULT_ONE_WAY_DELAY_MS`].
/// That is the defect this type exists to close: the filter DSL, the call list,
/// the REST and MCP projections and the browser build all reported a
/// domestic 100 ms path for calls whose own RTCP said 225 ms or more.
///
/// It is a value rather than a trait so the choice is made ONCE per surface and
/// visible at the call site: `MosDelay::of_run` says the operator's figure was
/// consulted, `MosDelay::from_capture` says this surface has no way to consult
/// it, and `MosDelay::unknown` says nothing was available at all. All three
/// still go through the one resolver, so the answer carries a
/// [`DelaySource`] and a reader can be told which of the four remedies is
/// theirs.
#[derive(Clone, Copy)]
pub struct MosDelay<'a> {
    /// What the operator declared for this deployment, when the surface can
    /// see a config file or a command line.
    declared_ms: Option<f64>,
    /// The store whose provenance table holds the reported and derived round
    /// trips. `None` where a surface genuinely holds no store.
    store: Option<&'a crate::rtp::stream_store::StreamStore>,
}

impl<'a> MosDelay<'a> {
    /// Everything this run knows: the operator's declared figure and the store
    /// its RTCP landed in.
    #[must_use]
    pub fn of_run(
        declared_ms: Option<f64>,
        store: &'a crate::rtp::stream_store::StreamStore,
    ) -> Self {
        Self {
            declared_ms,
            store: Some(store),
        }
    }

    /// The capture's own evidence, on a surface that cannot see a declaration.
    ///
    /// `declared_ms` is `None` here as a FACT about the surface, not a default:
    /// the browser build has no config file and no command line, so the
    /// [`Declared`](DelaySource::Declared) rank is structurally unreachable
    /// there. A capture opened in a browser can still carry RTCP, and it is
    /// scored on it — the alternative, stating the assumption, would make the
    /// same capture read one MOS in the browser and another in the CLI, which
    /// is the "one tool, two numbers" defect wearing a different build target.
    #[must_use]
    pub fn from_capture(store: &'a crate::rtp::stream_store::StreamStore) -> Self {
        Self {
            declared_ms: None,
            store: Some(store),
        }
    }

    /// Nothing at all: no declaration and no store to ask.
    ///
    /// Resolves to [`DelaySource::Assumed`], which is the same number
    /// [`estimate_mos`] returns and a different claim — the score says it was
    /// guessed rather than implying it was measured.
    #[must_use]
    pub fn unknown() -> MosDelay<'static> {
        MosDelay {
            declared_ms: None,
            store: None,
        }
    }

    /// The one-way delay for `stream`, and where it came from.
    ///
    /// The echo figure is offered only when it is what the store settled on,
    /// which by construction means no XR block exists for this stream. That is
    /// not a shortcut around the ranking — both figures are handed to
    /// [`resolve_one_way_delay`] and it does the ranking — it is that the store
    /// has no echo to offer once an endpoint has reported its own.
    #[must_use]
    pub fn resolve(&self, stream: &crate::rtp::stream::RtpStream) -> (f64, DelaySource) {
        resolve_one_way_delay(
            self.declared_ms,
            self.store
                .and_then(|s| s.remote_voip_metrics(&stream.key))
                .map(|xr| xr.metrics.round_trip_delay),
            match self.store.and_then(|s| s.round_trip_for(stream)) {
                Some((ms, crate::rtp::rtcp::RttSource::SenderReportEcho)) => Some(ms),
                _ => None,
            },
        )
    }

    /// Just the delay from [`Self::resolve`], for a caller that has already
    /// said where it came from — a trend loop beside a headline, say.
    #[must_use]
    pub fn one_way_ms(&self, stream: &crate::rtp::stream::RtpStream) -> f64 {
        self.resolve(stream).0
    }

    /// The MOS for a whole stream, scored on the delay this evidence resolves.
    ///
    /// The one place a stream becomes a MOS. Six surfaces each derived the loss
    /// percentage and called [`estimate_mos`] themselves, which is how five of
    /// them were still on the assumption after the sixth stopped being.
    #[must_use]
    pub fn score(&self, stream: &crate::rtp::stream::RtpStream) -> f64 {
        estimate_mos_with_delay(
            stream.jitter,
            stream.loss_percent(),
            stream.codec.as_deref(),
            self.one_way_ms(stream),
        )
    }
}

/// Convert an R-factor to MOS using the standard formula.
///
/// MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6 for R in [0, 100],
/// clamped to [1.0, 4.5].
fn r_to_mos(r: f64) -> f64 {
    if r < 0.0 {
        1.0
    } else if r > 100.0 {
        4.5
    } else {
        // The cubic dips below 1.0 for small positive R (e.g. R≈4.4 at
        // 100% loss on G.711), so the documented floor must be enforced
        // inside the branch too, not only at its edges.
        (1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6).clamp(1.0, 4.5)
    }
}

// ── Burst/gap analysis ───────────────────────────────────────────────

/// Analyze a sequence of packet reception results for burst/gap patterns.
///
/// Takes a slice of booleans where `true` = packet received, `false` = packet
/// lost, and the packet interval in milliseconds (typically 20ms for most
/// audio codecs).
///
/// A burst is defined as 3 or more consecutive lost packets. Everything
/// between bursts is a gap.
///
/// # Arguments
///
/// * `received` — ordered sequence of packet reception outcomes.
/// * `ptime_ms` — packet interval in milliseconds (e.g., 20.0 for G.711).
///
/// # Returns
///
/// A `BurstGapAnalysis` with burst counts, average burst/gap durations in
/// milliseconds (interval count times `ptime_ms`), and per-region loss
/// rates as fractions (0.0 to 1.0). An empty `received` slice yields an
/// all-zero result with `is_bursty == false`. Pure function — no side
/// effects.
pub fn analyze_burst_gap(received: &[bool], ptime_ms: f64) -> BurstGapAnalysis {
    if received.is_empty() {
        return BurstGapAnalysis {
            burst_count: 0,
            burst_duration_ms: 0.0,
            gap_duration_ms: 0.0,
            burst_loss_rate: 0.0,
            gap_loss_rate: 0.0,
            is_bursty: false,
        };
    }

    let mut burst_count: u32 = 0;
    let mut burst_packets: u64 = 0; // Total packets in burst regions
    let mut burst_lost: u64 = 0; // Lost packets in burst regions
    let mut gap_packets: u64 = 0; // Total packets in gap regions
    let mut gap_lost: u64 = 0; // Lost packets in gap regions

    // Track consecutive loss runs
    let mut consecutive_lost: u32 = 0;
    let mut in_burst = false;
    let mut current_burst_len: u32 = 0;
    let mut burst_lengths: Vec<u32> = Vec::new();
    let mut gap_lengths: Vec<u32> = Vec::new();
    let mut current_gap_len: u32 = 0;

    for &pkt_received in received {
        if !pkt_received {
            consecutive_lost += 1;
            // Transition to burst when we hit 3 consecutive losses
            if consecutive_lost >= 3 && !in_burst {
                in_burst = true;
                burst_count += 1;
                // The previous consecutive losses are part of this burst;
                // retroactively move them from gap to burst accounting. Those
                // (consecutive_lost - 1) packets were the immediately
                // preceding losses, so by construction they are all still
                // booked to the current gap in every gap counter at once:
                // current_gap_len >= consecutive_lost > retroactive, and both
                // gap_packets and gap_lost include this run's prior losses.
                //
                // Move them as a single unit under one combined guard so a
                // partial subtraction can never desync the three counters
                // (which would corrupt the gap/burst loss rates). The
                // debug_assert pins the invariant in tests.
                let retroactive = consecutive_lost - 1;
                let r64 = retroactive as u64;
                debug_assert!(
                    current_gap_len >= retroactive && gap_lost >= r64 && gap_packets >= r64,
                    "gap counters desynced before burst reclassification: \
                     len={current_gap_len} lost={gap_lost} packets={gap_packets} r={retroactive}"
                );
                if current_gap_len >= retroactive && gap_lost >= r64 && gap_packets >= r64 {
                    current_gap_len -= retroactive;
                    gap_lost -= r64;
                    gap_packets -= r64;
                }
                // Finalize the preceding gap
                if current_gap_len > 0 {
                    gap_lengths.push(current_gap_len);
                    current_gap_len = 0;
                }
                current_burst_len = retroactive;
                burst_lost += retroactive as u64;
                burst_packets += retroactive as u64;
            }
        } else {
            consecutive_lost = 0;
        }

        if in_burst {
            burst_packets += 1;
            current_burst_len += 1;
            if !pkt_received {
                burst_lost += 1;
            }
            // End burst when we see a received packet (the burst was
            // the consecutive loss run; we include the first received
            // packet after the run to close the burst)
            if pkt_received {
                burst_lengths.push(current_burst_len);
                current_burst_len = 0;
                in_burst = false;
                current_gap_len = 0; // gap starts fresh
            }
        } else {
            gap_packets += 1;
            current_gap_len += 1;
            if !pkt_received {
                gap_lost += 1;
            }
        }
    }

    // Finalize any open burst or gap at end of sequence
    if in_burst && current_burst_len > 0 {
        burst_lengths.push(current_burst_len);
    }
    if !in_burst && current_gap_len > 0 {
        gap_lengths.push(current_gap_len);
    }

    let total_burst_len: u32 = burst_lengths.iter().sum();
    let total_gap_len: u32 = gap_lengths.iter().sum();

    let avg_burst_duration = if burst_lengths.is_empty() {
        0.0
    } else {
        (total_burst_len as f64 / burst_lengths.len() as f64) * ptime_ms
    };

    let avg_gap_duration = if gap_lengths.is_empty() {
        0.0
    } else {
        (total_gap_len as f64 / gap_lengths.len() as f64) * ptime_ms
    };

    let burst_loss_rate = if burst_packets > 0 {
        burst_lost as f64 / burst_packets as f64
    } else {
        0.0
    };

    let gap_loss_rate = if gap_packets > 0 {
        gap_lost as f64 / gap_packets as f64
    } else {
        0.0
    };

    BurstGapAnalysis {
        burst_count,
        burst_duration_ms: avg_burst_duration,
        gap_duration_ms: avg_gap_duration,
        burst_loss_rate,
        gap_loss_rate,
        is_bursty: burst_count > 0,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for E-model MOS estimation (codec impairments, clamping,
/// monotonic degradation) and burst/gap loss-pattern analysis.
#[cfg(test)]
mod grounding_tests {
    use super::*;

    /// The cellular codecs sipnab cannot ground must say so.
    ///
    /// This is the whole point: they currently score identically to an
    /// unidentified stream, so without this signal a caller cannot tell a
    /// measurement from a placeholder.
    #[test]
    fn cellular_codecs_are_reported_as_ungrounded() {
        for c in ["AMR", "AMR-WB", "EVS", "G722", "G726", "iLBC"] {
            assert_eq!(
                mos_grounding(Some(c)),
                MosGrounding::Unpublished,
                "{c} has no published ITU-T G.113 Ie in sipnab and must not \
                 claim a grounded MOS"
            );
        }
    }

    /// A declared impairment changes the SCORE, and only for that codec.
    ///
    /// The defect: every codec G.113 does not publish for scores identically to
    /// a stream whose codec was never identified, so a G.722 network reads as
    /// 4.2 whatever its impairment really is. An operator who knows the figure
    /// had no way to supply it.
    ///
    /// `SILK` rather than `G722` on purpose. The table is process-wide, and
    /// `cellular_codecs_are_reported_as_ungrounded` above asserts `G722` is
    /// ungrounded — declaring it here would make these two tests fight when the
    /// harness runs them in parallel. Nothing else in this binary names `SILK`.
    #[test]
    fn a_declared_impairment_moves_the_score_for_that_codec_alone() {
        let placeholder = estimate_mos(10.0, 0.0, None);
        let before = estimate_mos(10.0, 0.0, Some("SILK"));
        assert_eq!(
            before, placeholder,
            "with nothing declared an unknown codec must still score as the \
             placeholder, or this test cannot see the change it is about"
        );

        set_codec_ie_table([("SILK".to_string(), 20.0)].into_iter().collect());
        let after = estimate_mos(10.0, 0.0, Some("SILK"));
        assert!(
            after < placeholder,
            "a declared impairment of 20 is worse than the placeholder 5, so \
             the score must fall: {placeholder} then {after}"
        );
        assert_eq!(
            estimate_mos(10.0, 0.0, None),
            placeholder,
            "an unidentified stream must be untouched by a declaration about a \
             codec it is not"
        );
        assert_eq!(
            mos_grounding(Some("SILK")),
            MosGrounding::OperatorDeclared,
            "a declared codec is grounded in the OPERATOR's figure, which is a \
             third thing from a G.113 one and from a placeholder"
        );
        // Case is not part of the identity: an SDP `rtpmap` may spell the same
        // codec either way, and a declaration that missed on capitalisation
        // would silently do nothing.
        assert_eq!(
            estimate_mos(10.0, 0.0, Some("silk")),
            after,
            "the lookup must be case-insensitive, or a declaration is a spelling test"
        );

        set_codec_ie_table(std::collections::HashMap::new());
        assert_eq!(
            estimate_mos(10.0, 0.0, Some("SILK")),
            placeholder,
            "clearing the table must restore the placeholder"
        );
        assert_eq!(mos_grounding(Some("SILK")), MosGrounding::Unpublished);
    }

    /// A codec sipnab does not know and nobody declared stays a placeholder.
    ///
    /// The honesty this whole feature must not cost: `[media.codec_ie]` makes
    /// SOME unknown codecs knowable, and the ones left over must still refuse
    /// to claim a grounded MOS rather than inherit the new mechanism's
    /// confidence.
    #[test]
    fn an_undeclared_unknown_codec_still_refuses_to_claim_grounding() {
        assert_eq!(
            mos_grounding(Some("EVS")),
            MosGrounding::Unpublished,
            "EVS is published only on the fullband scale, so a narrowband score \
             for it is a placeholder however many other codecs were declared"
        );
        assert_eq!(
            estimate_mos(10.0, 0.0, Some("EVS")),
            estimate_mos(10.0, 0.0, None)
        );
    }

    /// The three sipnab does know are grounded.
    #[test]
    fn known_codecs_are_reported_as_grounded() {
        for c in ["PCMU", "PCMA", "G729", "opus"] {
            assert_eq!(mos_grounding(Some(c)), MosGrounding::Published, "{c}");
        }
    }

    /// An unidentified stream is ungrounded, matching what the score means.
    #[test]
    fn an_unidentified_codec_is_ungrounded() {
        assert_eq!(mos_grounding(None), MosGrounding::Unpublished);
    }

    /// The grounding signal must agree with the scorer.
    ///
    /// If a codec reported Published while falling to the placeholder arm, the
    /// signal would launder the guess instead of exposing it — worse than
    /// having no signal.
    #[test]
    fn grounding_agrees_with_the_score() {
        let placeholder = estimate_mos(10.0, 0.0, None);
        for c in ["PCMU", "PCMA", "G729", "opus"] {
            assert_ne!(
                estimate_mos(10.0, 0.0, Some(c)),
                placeholder,
                "{c} claims Published grounding, so it must not score the same \
                 as an unidentified stream"
            );
        }
        for c in ["AMR", "AMR-WB", "EVS"] {
            assert_eq!(
                estimate_mos(10.0, 0.0, Some(c)),
                placeholder,
                "{c} is Unpublished, so it does score as the placeholder — if \
                 this changes, the grounding table must change with it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MOS estimation tests ─────────────────────────────────────────

    /// MOS stays within [1.0, 4.5] even at extreme loss where the raw
    /// G.107 cubic dips below 1.0.
    #[test]
    fn mos_never_dips_below_documented_floor() {
        // 100% loss on G.711 lands R ≈ 4.4, where the raw G.107 cubic
        // evaluates to ~0.99 — the [1.0, 4.5] contract must hold anyway.
        let mos = estimate_mos(0.0, 100.0, Some("PCMU"));
        assert!(
            (1.0..=4.5).contains(&mos),
            "Expected clamped MOS at total loss, got {mos}"
        );
        // sweep the small-R region for any other dip
        for loss in [80.0, 90.0, 95.0, 99.0, 100.0] {
            for jitter in [0.0, 40.0, 200.0] {
                let m = estimate_mos(jitter, loss, Some("PCMU"));
                assert!(
                    (1.0..=4.5).contains(&m),
                    "loss={loss} jitter={jitter} mos={m}"
                );
            }
        }
    }

    /// Clean G.711 (0% loss, 10 ms jitter) scores above 4.0.
    #[test]
    fn mos_g711_perfect_conditions() {
        // G.711, 0% loss, 10ms jitter — should be excellent
        let mos = estimate_mos(10.0, 0.0, Some("PCMU"));
        assert!(mos > 4.0, "Expected MOS > 4.0 for perfect G.711, got {mos}");
    }

    /// G.711 at 5% loss and 50 ms jitter lands in the noticeably degraded
    /// 2.0-3.5 band.
    #[test]
    fn mos_g711_moderate_degradation() {
        // G.711, 5% loss, 50ms jitter — noticeable degradation
        let mos = estimate_mos(50.0, 5.0, Some("PCMU"));
        assert!(
            (2.0..=3.5).contains(&mos),
            "Expected MOS 2.0-3.5 for degraded G.711, got {mos}"
        );
    }

    /// G.729's inherent equipment impairment (Ie=10) scores below G.711 at
    /// identical network conditions.
    #[test]
    fn mos_g729_lower_than_g711() {
        // G.729 has inherent codec impairment
        let mos_g711 = estimate_mos(10.0, 0.0, Some("PCMU"));
        let mos_g729 = estimate_mos(10.0, 0.0, Some("G729"));
        assert!(
            mos_g729 < mos_g711,
            "Expected G.729 MOS ({mos_g729}) < G.711 MOS ({mos_g711})"
        );
    }

    /// Opus and G.711 share Ie=0, so their MOS matches at equal conditions.
    #[test]
    fn mos_opus_comparable_to_g711() {
        let mos_g711 = estimate_mos(10.0, 0.0, Some("PCMU"));
        let mos_opus = estimate_mos(10.0, 0.0, Some("opus"));
        assert!(
            (mos_g711 - mos_opus).abs() < 0.01,
            "Opus and G.711 should have same MOS at same conditions"
        );
    }

    /// PCMA and PCMU (both G.711) produce identical MOS.
    #[test]
    fn mos_pcma_same_as_pcmu() {
        let mos_pcmu = estimate_mos(20.0, 1.0, Some("PCMU"));
        let mos_pcma = estimate_mos(20.0, 1.0, Some("PCMA"));
        assert!(
            (mos_pcmu - mos_pcma).abs() < 0.01,
            "PCMA and PCMU should have same MOS"
        );
    }

    /// An unknown/absent codec gets the moderate Ie=5 impairment, scoring
    /// below G.711.
    #[test]
    fn mos_unknown_codec_moderate_impairment() {
        let mos_unknown = estimate_mos(10.0, 0.0, None);
        let mos_g711 = estimate_mos(10.0, 0.0, Some("PCMU"));
        assert!(
            mos_unknown < mos_g711,
            "Unknown codec MOS ({mos_unknown}) should be less than G.711 ({mos_g711})"
        );
    }

    /// Extreme conditions (100% loss, 500 ms jitter) never push MOS below
    /// the 1.0 floor.
    #[test]
    fn mos_never_below_one() {
        // Extreme conditions: 100% loss, 500ms jitter
        let mos = estimate_mos(500.0, 100.0, None);
        assert!(mos >= 1.0, "MOS should never go below 1.0, got {mos}");
    }

    /// Perfect conditions never push MOS above the 4.5 ceiling.
    #[test]
    fn mos_never_above_four_five() {
        // Perfect conditions
        let mos = estimate_mos(0.0, 0.0, Some("PCMU"));
        assert!(mos <= 4.5, "MOS should never exceed 4.5, got {mos}");
    }

    /// Raising jitter from 5 ms to 200 ms lowers the score (delay
    /// impairment Id grows).
    #[test]
    fn mos_high_jitter_degrades_quality() {
        let mos_low = estimate_mos(5.0, 0.0, Some("PCMU"));
        let mos_high = estimate_mos(200.0, 0.0, Some("PCMU"));
        assert!(
            mos_high < mos_low,
            "High jitter MOS ({mos_high}) should be less than low jitter ({mos_low})"
        );
    }

    /// Raising loss from 0% to 20% lowers the score (Ie-eff grows).
    #[test]
    fn mos_high_loss_degrades_quality() {
        let mos_low = estimate_mos(10.0, 0.0, Some("PCMU"));
        let mos_high = estimate_mos(10.0, 20.0, Some("PCMU"));
        assert!(
            mos_high < mos_low,
            "High loss MOS ({mos_high}) should be less than low loss ({mos_low})"
        );
    }

    // ── Burst/gap analysis tests ─────────────────────────────────────

    /// Ten consecutive losses in otherwise clean traffic are detected as
    /// at least one burst.
    #[test]
    fn burst_detected_consecutive_loss() {
        // 10 consecutive lost packets in a sequence of 100
        let mut received = vec![true; 100];
        for i in 20..30 {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty, "10 consecutive losses should be bursty");
        assert!(
            analysis.burst_count >= 1,
            "Should detect at least 1 burst, got {}",
            analysis.burst_count
        );
    }

    /// Isolated single losses (every 50th packet) never form a burst.
    #[test]
    fn no_burst_random_isolated_loss() {
        // Random loss: every 50th packet lost (never more than 1 consecutive)
        let mut received = vec![true; 200];
        for i in (0..200).step_by(50) {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(
            !analysis.is_bursty,
            "Isolated single losses should not be bursty"
        );
        assert_eq!(analysis.burst_count, 0);
    }

    /// Two consecutive losses stay below the 3-loss burst threshold.
    #[test]
    fn no_burst_two_consecutive_loss() {
        // 2 consecutive losses is below the burst threshold (3)
        let mut received = vec![true; 50];
        received[10] = false;
        received[11] = false;

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(
            !analysis.is_bursty,
            "2 consecutive losses should not be a burst"
        );
        assert_eq!(analysis.burst_count, 0);
    }

    /// Exactly three consecutive losses is the minimum counted as one
    /// burst.
    #[test]
    fn burst_exactly_three_consecutive() {
        // Exactly 3 consecutive losses — minimum burst
        let mut received = vec![true; 50];
        received[10] = false;
        received[11] = false;
        received[12] = false;

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty, "3 consecutive losses should be a burst");
        assert_eq!(analysis.burst_count, 1);
    }

    /// Two separated loss runs are counted as two distinct bursts.
    #[test]
    fn multiple_bursts_detected() {
        let mut received = vec![true; 100];
        // First burst: packets 10-14 lost
        for i in 10..15 {
            received[i] = false;
        }
        // Second burst: packets 50-55 lost
        for i in 50..56 {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty);
        assert_eq!(
            analysis.burst_count, 2,
            "Should detect 2 bursts, got {}",
            analysis.burst_count
        );
    }

    /// An empty reception sequence yields the all-zero, non-bursty result.
    #[test]
    fn empty_sequence() {
        let analysis = analyze_burst_gap(&[], 20.0);
        assert!(!analysis.is_bursty);
        assert_eq!(analysis.burst_count, 0);
        assert_eq!(analysis.burst_duration_ms, 0.0);
        assert_eq!(analysis.gap_duration_ms, 0.0);
    }

    /// A loss-free sequence reports no bursts and zero loss rates.
    #[test]
    fn all_received_no_loss() {
        let received = vec![true; 100];
        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(!analysis.is_bursty);
        assert_eq!(analysis.burst_count, 0);
        assert_eq!(analysis.burst_loss_rate, 0.0);
        assert_eq!(analysis.gap_loss_rate, 0.0);
    }

    /// With one clear burst in clean traffic, the burst-region loss rate
    /// exceeds the gap-region loss rate.
    #[test]
    fn burst_loss_rate_higher_than_gap() {
        // Create a clear burst in otherwise clean traffic
        let mut received = vec![true; 200];
        for i in 50..60 {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty);
        assert!(
            analysis.burst_loss_rate > analysis.gap_loss_rate,
            "Burst loss rate ({}) should exceed gap loss rate ({})",
            analysis.burst_loss_rate,
            analysis.gap_loss_rate
        );
    }

    /// A 2-packet all-lost sequence is below the burst threshold, so not
    /// bursty.
    #[test]
    fn all_lost_below_threshold_not_bursty() {
        let received = vec![false, false]; // Only 2 lost = below burst threshold of 3
        let result = analyze_burst_gap(&received, 20.0);
        assert_eq!(result.burst_count, 0);
        assert!(!result.is_bursty);
    }

    /// 100 consecutive losses form exactly one burst with ~100% burst loss
    /// rate.
    #[test]
    fn all_lost_single_burst() {
        let received = vec![false; 100]; // 100 consecutive lost
        let result = analyze_burst_gap(&received, 20.0);
        assert_eq!(result.burst_count, 1);
        assert!(result.is_bursty);
        assert!(
            result.burst_loss_rate > 0.99,
            "burst_loss_rate should be ~1.0, got {}",
            result.burst_loss_rate
        );
    }

    /// The retroactive gap→burst reclassification must move the same
    /// packets out of every gap counter as one unit, keeping the partition
    /// consistent. A gap that already holds an isolated loss (so the gap
    /// counters exceed the reclassified count) followed by a 3+ burst
    /// exercises the guard; burst and gap loss rates must stay coherent.
    #[test]
    fn retroactive_reclassification_keeps_accounting_consistent() {
        let mut received = vec![true; 30];
        received[5] = false; // isolated loss — stays in the gap
        for i in 20..24 {
            received[i] = false; // 4 consecutive losses — a burst
        }

        let a = analyze_burst_gap(&received, 20.0);
        assert_eq!(a.burst_count, 1, "the 4-run is one burst");
        assert!(a.is_bursty);
        // Both rates are well-formed fractions, and the burst region carries
        // heavier loss than the gap region (which holds only the lone loss).
        assert!((0.0..=1.0).contains(&a.burst_loss_rate), "{a:?}");
        assert!((0.0..=1.0).contains(&a.gap_loss_rate), "{a:?}");
        assert!(
            a.gap_loss_rate > 0.0,
            "the isolated loss must register in the gap region: {a:?}"
        );
        assert!(
            a.burst_loss_rate > a.gap_loss_rate,
            "burst loss rate ({}) must exceed gap loss rate ({})",
            a.burst_loss_rate,
            a.gap_loss_rate
        );
    }

    /// Burst duration scales with `ptime_ms`: the same loss pattern lasts
    /// longer at 30 ms packets than at 20 ms.
    #[test]
    fn burst_duration_reflects_ptime() {
        let mut received = vec![true; 50];
        for i in 10..16 {
            received[i] = false; // 6 consecutive losses
        }

        let analysis_20ms = analyze_burst_gap(&received, 20.0);
        let analysis_30ms = analyze_burst_gap(&received, 30.0);

        assert!(analysis_20ms.is_bursty);
        assert!(analysis_30ms.is_bursty);
        assert!(
            analysis_30ms.burst_duration_ms > analysis_20ms.burst_duration_ms,
            "30ms ptime burst duration ({}) should exceed 20ms ({})",
            analysis_30ms.burst_duration_ms,
            analysis_20ms.burst_duration_ms
        );
    }
}

/// Whether sipnab has a published impairment value for a codec, or is guessing.
///
/// [`estimate_mos`] always returns a number, because every surface that shows
/// MOS predates this distinction and a sudden `Option` would break the REST
/// schema, the filter DSL's `rtp.mos`, the Prometheus series and the WASM
/// exports at once. So the number stays and the *confidence* is published
/// beside it.
///
/// The distinction is not academic. A caller that renders 4.2 for an AMR-WB
/// stream is showing a placeholder, and an operator reading it during an
/// incident has no way to tell that apart from a real estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MosGrounding {
    /// ITU-T G.113 publishes an equipment impairment factor for this codec, so
    /// the MOS is a genuine estimate.
    Published,
    /// The operator declared an impairment factor for this codec in
    /// `[media.codec_ie]`, so the MOS rests on a real number — theirs, not a
    /// published one.
    ///
    /// Kept distinct from [`Published`](Self::Published) rather than folded
    /// into it, because the two fail differently and the remedies differ. A
    /// `Published` score that looks wrong means suspecting sipnab's vantage
    /// point; a declared one means suspecting the declaration, which is a file
    /// on the operator's own disk. Reporting a declaration as a G.113 citation
    /// would put an operator's estimate on the same footing as a standard, in
    /// the one field that exists to keep those apart.
    OperatorDeclared,
    /// No published impairment value **on this scale**. The MOS is a
    /// placeholder and means "unknown", not "about 4.2".
    ///
    /// Not always the same as "nothing is published". AMR-WB reports
    /// `Unpublished` here because [`estimate_mos`] is the narrowband model and
    /// takes no mode argument, while G.113 does publish wideband values for
    /// all nine of its modes — see [`crate::rtp::emodel_wb`], which scores it
    /// on the scale those values belong to.
    Unpublished,
}

/// Whether [`estimate_mos`] can ground its answer for `codec`.
///
/// Deliberately keyed on the same names the `match` in [`estimate_mos`] uses,
/// so the two cannot disagree — a codec that scores as known here but falls to
/// the placeholder arm there would be the worst of both.
#[must_use]
pub fn mos_grounding(codec: Option<&str>) -> MosGrounding {
    // The declared table is consulted first, in the same order the scorer
    // consults it. Any other order would let a codec score on one Ie and be
    // described by the other.
    if declared_codec_ie(codec).is_some() {
        return MosGrounding::OperatorDeclared;
    }
    match codec {
        Some("PCMU") | Some("PCMA") | Some("G729") | Some("G.729") | Some("opus")
        | Some("Opus") => MosGrounding::Published,
        _ => MosGrounding::Unpublished,
    }
}

/// Where a MOS shown beside a stream came from.
///
/// [`MosGrounding`] answers a narrower question — whether *sipnab's own*
/// E-model score rests on a published impairment factor — and it has no way to
/// describe a MOS sipnab did not compute. RTCP XR VoIP Metrics blocks
/// (RFC 3611 Section 4.7) carry exactly that: the endpoint's own MOS-LQ and
/// MOS-CQ, which are neither an estimate sipnab made nor a placeholder it
/// substituted, but a third thing. Collapsing that third thing into either of
/// the other two is the mistake this enum exists to prevent, because the
/// remedies differ. An [`Estimated`](Self::Estimated) MOS that looks wrong
/// means suspecting sipnab's vantage point; a
/// [`ReportedByEndpoint`](Self::ReportedByEndpoint) MOS that looks wrong means
/// suspecting the endpoint, or whoever forged its datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MosProvenance {
    /// sipnab scored it with [`estimate_mos`] from the media it observed, on a
    /// codec G.113 publishes an equipment impairment factor for.
    Estimated,
    /// sipnab scored it with [`estimate_mos`] on a codec with no published
    /// impairment factor on this scale. A placeholder meaning "unknown", not a
    /// measurement — see [`MosGrounding::Unpublished`].
    Placeholder,
    /// An endpoint asserted it in an RTCP XR VoIP Metrics block. sipnab
    /// measured nothing here and vouches for nothing: the number describes the
    /// reporter's own reception on the reporter's own path segment, and RTCP
    /// carries no authentication.
    ReportedByEndpoint,
}

impl From<MosGrounding> for MosProvenance {
    /// Lift sipnab's own grounding into the wider provenance scale. There is
    /// deliberately no inverse: [`MosProvenance::ReportedByEndpoint`] has no
    /// [`MosGrounding`] to map back to, which is the whole point.
    fn from(grounding: MosGrounding) -> Self {
        match grounding {
            // A declared impairment maps to `Estimated`, not to `Placeholder`.
            // Both are numbers sipnab COMPUTED — that is what this scale
            // separates, and the operator's Ie is as real an input as G.113's.
            // Which of the two grounded it stays visible on `MosGrounding`
            // itself, where the distinction is actionable.
            MosGrounding::Published | MosGrounding::OperatorDeclared => Self::Estimated,
            MosGrounding::Unpublished => Self::Placeholder,
        }
    }
}

impl MosProvenance {
    /// A short label for a reader, suitable for putting beside the number.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Estimated => "estimated by sipnab",
            Self::Placeholder => "placeholder — codec has no published impairment factor",
            Self::ReportedByEndpoint => "reported by the far end (RTCP XR)",
        }
    }

    /// Whether sipnab computed this number from media it observed. False for
    /// anything an endpoint asserted.
    #[must_use]
    pub fn is_measured_here(self) -> bool {
        matches!(self, Self::Estimated | Self::Placeholder)
    }
}

/// Unit tests for the MOS provenance scale.
#[cfg(test)]
mod provenance_tests {
    use super::{MosGrounding, MosProvenance};

    /// sipnab's two groundings lift into the two sipnab-side provenances, and
    /// neither can become the endpoint-reported one.
    #[test]
    fn grounding_lifts_into_the_sipnab_side_of_the_scale() {
        assert_eq!(
            MosProvenance::from(MosGrounding::Published),
            MosProvenance::Estimated
        );
        assert_eq!(
            MosProvenance::from(MosGrounding::Unpublished),
            MosProvenance::Placeholder
        );
        for g in [MosGrounding::Published, MosGrounding::Unpublished] {
            assert_ne!(
                MosProvenance::from(g),
                MosProvenance::ReportedByEndpoint,
                "no sipnab grounding may masquerade as an endpoint's claim"
            );
        }
    }

    /// The endpoint's claim is not something sipnab measured, and the label
    /// says whose number it is. A reader who cannot tell the two apart is the
    /// failure this enum exists to prevent.
    #[test]
    fn an_endpoint_claim_is_not_a_local_measurement() {
        assert!(!MosProvenance::ReportedByEndpoint.is_measured_here());
        assert!(MosProvenance::Estimated.is_measured_here());
        assert!(MosProvenance::Placeholder.is_measured_here());
        assert!(
            MosProvenance::ReportedByEndpoint
                .label()
                .contains("far end"),
            "the label must attribute the number to its source"
        );
    }
}
