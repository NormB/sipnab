// SPDX-License-Identifier: MIT OR Apache-2.0

//! vCon export — one observed dialog as an unsigned observer vCon container
//! ([`draft-ietf-vcon-vcon-core-03`], syntax version `0.4.0`).
//!
//! # What sipnab is in a vCon, and what it is not
//!
//! sipnab is a **contributor**, never a producer. It did not place the call,
//! record it, or obtain anyone's consent to keep it; it watched packets go
//! past. So the container it emits is an *observer* vCon, and four things are
//! deliberately missing from it:
//!
//! * **No signature and no encryption.** A JWS over this container would say
//!   sipnab vouches for its contents. It vouches for what it *saw*, which is
//!   not the same claim, and a signature is read as the stronger one.
//! * **No consent record and no lawful-basis attachment.** Nobody gave sipnab
//!   permission for anything. An empty consent field would be a claim; an
//!   absent one is the truth.
//! * **No [`Party`] name, ever.** The struct has no `name` field at all, so
//!   the rule cannot be broken by a later edit. `From`/`To` display names are
//!   an unverified assertion by whoever sent the request, which is why every
//!   party emits `validation: "none"` instead.
//! * **No `url` by-reference, ever.** §2.4.1 of the draft requires HTTPS, and
//!   sipnab hosts nothing: a URL here would be a promise that a file is
//!   somewhere and stays there, made by a tool that is run rather than
//!   operated. Media travels inline or it does not travel.
//!
//! # Media: a `recording` Dialog Object is not a recording
//!
//! Two vocabularies collide on one word, and getting them backwards is the one
//! mistake this module must not make. `dialog.type: "recording"` is a FORMAT
//! term for a Dialog Object that carries media; a consumer's `recordings`
//! table is a PROVENANCE term for containers from an in-path recorder.
//! **sipnab emits the first and is never the second** — its own audio export
//! stamps every file with "not a recording made by the endpoints", and that
//! sentence is what the media carries into the container.
//!
//! So audio, when a caller supplies it, arrives as an [`ObservedAudio`] and
//! becomes a `recording` Dialog Object: inline base64url, a `content_hash`
//! over the WAV, `parties` naming only channels sipnab could attribute, and a
//! `duration` that is the FILE's rather than the call's. Above
//! [`MAX_INLINE_MEDIA_BYTES`] it is refused **out loud** — see that constant
//! for the measurement behind the number and [`CaptureCompleteness::media`]
//! for where the refusal surfaces.
//!
//! # The problem this module exists to solve
//!
//! **vCon has no field for "this container is an incomplete record."**
//!
//! `dialog.type: "incomplete"` is close enough to be dangerous: it means the
//! CALL did not complete, not that the CAPTURE missed part of it. Emitting it
//! because sipnab never saw the answer would convert a limitation of the tap
//! into an accusation against the traffic — the exact confusion
//! [`crate::rtp::audio_export`]'s `nothing_to_decode` was written to refuse.
//! So [`disposition`](Dialog::disposition) is set only when a final failure
//! response was actually observed on the wire.
//!
//! The extension mechanism does not help either. An extension is *ignorable*
//! (listed in `extensions`) or *fatal* (listed in `critical`, which refuses
//! the whole container to a consumer that does not implement it). There is no
//! "read this caveat before trusting the contents".
//!
//! So the caveat is duplicated into two surfaces a consumer has to walk past,
//! built from ONE [`CaptureCompleteness`] value:
//!
//! 1. the [`Analysis`] object of type `report` — the designed home for what a
//!    tool determined about a conversation;
//! 2. an [`Attachment`] with purpose `sipnab-capture-completeness`, whose
//!    `party` names the sipnab observer.
//!
//! One value embedded twice, not two strings written twice: the failure mode
//! of the second is a container whose two caveats disagree, which reads as
//! authoritative while contradicting itself. `crate::rtp::audio_export`
//! already learned that the hard way, and this module copies its shape.
//!
//! [`draft-ietf-vcon-vcon-core-03`]: https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};

use crate::analysis::{CaptureAnalysis, CaptureFacts, Severity};
use crate::provenance::node_name;
use crate::rtp::audio_export::DialogAudio;
use crate::sip::dialog::SipDialog;

/// The vCon syntax version this module writes, per the core draft.
///
/// A literal rather than a computed value: it names which draft the field
/// layout below was written against, and bumping it without re-reading that
/// draft would advertise conformance to a document nobody checked.
pub const VCON_SYNTAX_VERSION: &str = "0.4.0";

/// The one extension this container declares.
///
/// Listed in `extensions` and NOT in `critical`, which is the whole decision:
/// a consumer that has never heard of SIP signaling can still read the
/// parties, the dialog and the analysis. Marking it critical would refuse the
/// container outright to every generic vCon reader, in exchange for nothing —
/// the SIP-specific parameters are additive.
pub const SIP_SIGNALING_EXTENSION: &str = "sip-signaling";

/// The extension that defines `Party.role`, declared because sipnab uses it.
///
/// `role` is NOT one of the thirteen Party parameters core-03 §4.2 defines —
/// the working group's own schema lists `tel`, `sip`, `stir`, `mailto`,
/// `name`, `did`, `validation`, `gmlpos`, `civicaddress`, `uuid`, `type`,
/// `org` and `dept`, and no `role`. `draft-ietf-vcon-cc-extension` defines it
/// and says the `CC` token "SHOULD be included in the extensions array".
///
/// This matters more here than the SHOULD suggests. `role: "observer"` is the
/// single most load-bearing fact in the container — it is how a consumer knows
/// sipnab was not a party to the call — and declaring nothing left it riding
/// in a field the container never admitted to using. The extension's own
/// values are agent/customer/supervisor/sme/thirdparty, and it permits others:
/// "Other values for the role parameter MAY also be used."
pub const CC_EXTENSION: &str = "CC";

/// `purpose` of the attachment carrying the per-message signaling trace.
pub const MESSAGE_TRACE_PURPOSE: &str = "sip-message-trace";

/// `purpose` of the attachment carrying the completeness caveat.
///
/// Vendor-prefixed because it is sipnab's own, not a registered vCon purpose:
/// a consumer that does not know it skips it, and one that does knows exactly
/// whose claim it is reading.
pub const COMPLETENESS_PURPOSE: &str = "sipnab-capture-completeness";

/// Version of the sipnab JSON body carried inside the [`Analysis`] object.
///
/// This is the same `schema_version` [`crate::output::json`] stamps on every
/// message and dialog it writes, restated here so the vCon `schema` string can
/// name it. `the_analysis_schema_names_the_version_the_json_surface_emits`
/// holds the two together — a `schema` naming a version the bodies do not
/// carry is a consumer parsing against the wrong contract.
pub const DIAGNOSIS_SCHEMA_VERSION: u32 = 1;

/// The `schema` string of the [`Analysis`] object, naming the body's contract.
pub const ANALYSIS_SCHEMA: &str = "sipnab-dialog-diagnosis/1";

/// `vendor` of the [`Analysis`] object.
pub const ANALYSIS_VENDOR: &str = "sipnab";

/// `product` of the [`Analysis`] object.
///
/// Says "observer" in the field a consumer reads to decide how much weight to
/// give the analysis. A product string of bare `"sipnab"` would leave that to
/// be inferred from the vendor name, and the inference a reader makes about an
/// analysis attached to a conversation is that it came from something that was
/// party to it.
///
/// It used to end "signaling only", which stopped being true the day a
/// container could carry a `recording` Dialog Object. The replacement states
/// the fact that does not change with the payload: whatever is in here was
/// watched from a tap, so it is not a recording system's output no matter how
/// much of it there is.
pub const ANALYSIS_PRODUCT: &str = concat!(
    "sipnab ",
    env!("CARGO_PKG_VERSION"),
    " (passive observer; not a recording system)"
);

/// `role` of the party representing sipnab itself.
pub const OBSERVER_ROLE: &str = "observer";

/// The largest inline media body sipnab will put in a container, in bytes of
/// base64url.
///
/// **MEASURED, not chosen.** `docs/design/vcon.md` §4a.1 records a probe of a
/// running vCon store on 2026-08-24. A container carrying roughly 12 MB of
/// inline base64 came back **HTTP 204**, landed in Postgres, and was refused by
/// the file spool with `16777749 > 10485760` — and neither transport reported
/// the partial write, so the producer was told "accepted" while a backend
/// dropped the payload. The same probe watched roughly 1 MB and roughly 5 MB
/// land in EVERY backend.
///
/// The budget is set at the 5 MiB that was observed to LAND rather than at the
/// 10485760-byte boundary that was observed to FAIL, for two reasons. The rest
/// of the container — parties, the whole message trace, the completeness
/// caveat — has to fit behind the ceiling too, and a budget set at the failure
/// boundary leaves it nothing. And a store that silently drops is a store whose
/// exact boundary is not worth standing on.
///
/// Base64url inflates by four thirds, so this is roughly 3.9 MB of WAV: about
/// four minutes of one-channel G.711 at 8 kHz. A longer call is refused, and
/// the refusal is visible in the container — see [`MediaOutcome`]. Silently
/// dropping the audio would be the §3 failure the whole module is built
/// against: absence reading as "this call had no media".
pub const MAX_INLINE_MEDIA_BYTES: usize = 5 * 1024 * 1024;

/// `mediatype` of the media sipnab inlines. RIFF/WAVE, 16-bit linear PCM.
pub const RECORDING_MEDIATYPE: &str = "audio/x-wav";

/// `dialog.type` of the object carrying the media itself — the FILE's clock.
pub const RECORDING_TYPE: &str = "recording";

/// `dialog.type` of the wrapper carrying the CALL's clock.
///
/// §4.3.3 of the core draft is the one place the format can say "the file is
/// shorter than the call": the set carries the call's `start` and `duration`
/// while the [`RECORDING_TYPE`] object beneath it carries the file's. Emitted
/// ONLY when a payload ring actually wrapped — a wrapper on every container
/// would train readers to skip the one that means something.
pub const RECORDING_SET_TYPE: &str = "recording-set";

/// `type` for a Dialog Object that carries no content of its own.
///
/// §4.3 calls it "Metadata for failed or incompleted communications", and a
/// signaling-only export is exactly an incompleted RECORD of the
/// communication. The prose caveat says which of the two it is, in words, on
/// two surfaces a consumer walks past anyway — the enum cannot.
pub const INCOMPLETE_TYPE: &str = "incomplete";

/// Hash algorithm prefix of [`Dialog::content_hash`], per §2.2 of the draft.
pub const CONTENT_HASH_PREFIX: &str = "sha512-";

/// Header names that must never leave this process inside a vCon.
///
/// The SIP-signaling extension makes republishing these a MUST NOT, and the
/// reason survives the spec: a digest `response` is a live credential for the
/// realm it was computed against, and a vCon is a container built to be handed
/// to somebody else.
///
/// `Proxy-Authenticate` is on the list although the extension names only three.
/// It is the proxy-side twin of `WWW-Authenticate`, carries the same realm and
/// nonce, and leaving it off would mean the rule held for one hop and not the
/// other.
///
/// Matched case-insensitively: SIP header names are case-insensitive on the
/// wire (RFC 3261 §7.3.1), so a filter keyed on exact case is a filter an
/// ordinary peer walks through.
pub const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
];

/// One party to the conversation, or the observer that watched it.
///
/// **There is no `name` field, and that is the design.** sipnab knows what the
/// `From` and `To` headers said, which is what the sender chose to write in
/// them; a vCon `name` reads as an identity somebody established. Leaving the
/// field out of the struct makes "never populate `name`" a property of the
/// type instead of a rule a later edit can forget.
#[derive(Debug, Clone, Serialize)]
pub struct Party {
    /// The party's SIP URI, rebuilt from the observed `From`/`To` user and
    /// host. Absent on the observer, which sent no SIP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip: Option<String>,
    /// Always `"none"`.
    ///
    /// Not a placeholder for a value that arrives later. sipnab has no
    /// mechanism that could raise it — STIR/SHAKEN attestation says something
    /// about the *call*, not about whether this party is who the header says —
    /// so anything else here would be an upgrade nothing performed.
    pub validation: &'static str,
    /// `"observer"` on the sipnab party, absent on the observed parties.
    ///
    /// Absent rather than `"caller"`/`"callee"`: the `From` header is not
    /// proof of direction once a call has been forwarded, transferred or
    /// re-invited, and a wrong role is worse than none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'static str>,
    /// Display name from the observed `From`/`To` header, verbatim.
    ///
    /// Deliberately NOT promoted into a `name`: it travels under a
    /// SIP-specific key so a consumer reads it as "what the header said",
    /// which is all it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_display_name: Option<String>,
    /// The `Contact` header this party offered, when one was observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_contact: Option<String>,
    /// The `User-Agent`/`Server` header this party sent, when one was
    /// observed. On the sipnab party this names sipnab: the observer's
    /// software identity is the one thing about it that is not in doubt, and
    /// this is the only slot in the declared vocabulary that holds one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_user_agent: Option<String>,
}

/// The Dialog Object — deliberately almost empty.
///
/// §4.3 of the core draft blesses this explicitly: "there are situations when
/// no information is available for a dialog … and yet it is known that the
/// dialog occurred". A signaling-only export is exactly that situation. The
/// alternative — inventing a `mediatype`, a `body` or a `url` so the object
/// looks complete — would describe media that does not exist.
#[derive(Debug, Clone, Serialize)]
pub struct Dialog {
    /// `"incomplete"` ONLY when a final failure response was observed;
    /// [`RECORDING_TYPE`] or [`RECORDING_SET_TYPE`] on the media objects.
    ///
    /// `"incomplete"` is never set because sipnab failed to capture the
    /// answer. It is a statement about the CALL; "we did not see the rest" is
    /// a statement about the CAPTURE, and the second one travels in
    /// [`CaptureCompleteness`] where it cannot be mistaken for the first.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    /// Why the call did not complete, mapped from the observed final status.
    ///
    /// Present exactly when [`Self::kind`] is `"incomplete"`, and on no other
    /// object: a `recording` has no disposition, because nothing about it says
    /// anything about how the call ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<&'static str>,
    /// The `Call-ID` this dialog was tracked under — the one identifier that
    /// ties the container back to a capture an operator still holds.
    pub sip_call_id: String,
    /// RFC 3339 start of what this object describes.
    ///
    /// On a `recording` this is the first frame the FILE holds, which is later
    /// than the call's start whenever a payload ring wrapped. On a
    /// `recording-set` it is the first media packet sipnab saw at all. The two
    /// differing is the format's own way of saying the file is a fragment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// Length in seconds of what this object describes.
    ///
    /// The FILE's on a `recording` — decoded samples divided by the sample
    /// rate, never
    /// [`TimingSummary::duration_ms`](crate::output::model::TimingSummary),
    /// which is the CALL's and would state that the endpoints talked for
    /// exactly as long as this run happened to retain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
    /// Indices into [`Vcon::parties`] whose media the channels carry, channel
    /// order.
    ///
    /// Emitted only when EVERY channel could be attributed from evidence: the
    /// stream's sending socket matching a media endpoint that party advertised
    /// in its own SDP. Absent otherwise, because a party index is load-bearing
    /// — `analysis.dialog`, `attachment.party` and `originator` all index this
    /// array — and a plausible guess corrupts every cross-reference silently.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parties: Option<Vec<usize>>,
    /// Indices into [`Vcon::dialog`] of the objects this set groups.
    ///
    /// Present only on a [`RECORDING_SET_TYPE`] object, and named `recordings`
    /// on the wire because §4.3.6 makes that a MUST: "The recordings parameter
    /// MUST be present in recording-set Dialog Objects." It serialized as
    /// `dialogs` until 0.5.125, which validated cleanly only because the
    /// working group's schema leaves `additionalProperties` open — an unknown
    /// key is ignored, so a consumer read a set whose members it could not
    /// resolve.
    #[serde(rename = "recordings", skip_serializing_if = "Option::is_none")]
    pub dialogs: Option<Vec<usize>>,
    /// Index of the [`RECORDING_SET_TYPE`] object this recording belongs to.
    ///
    /// §4.3.7: "The recording_set parameter SHOULD be present when a recording
    /// Dialog Object is part of a recording-set Dialog Object." Without it the
    /// link is one-way, and a consumer holding the audio cannot reach the
    /// call's clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_set: Option<usize>,
    /// IANA media type of [`Self::body`] — [`RECORDING_MEDIATYPE`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediatype: Option<&'static str>,
    /// Always `"base64url"` when [`Self::body`] is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
    /// The media itself, base64url, unpadded.
    ///
    /// Inline is the ONLY form. There is no `url` field on this struct, so
    /// §2.5's "never host artefacts" is a property of the type rather than a
    /// rule a later edit can forget — the same device that keeps `name` off
    /// [`Party`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// [`CONTENT_HASH_PREFIX`] followed by the base64url SHA-512 of the
    /// DECODED body.
    ///
    /// Over the WAV bytes, not over their base64url text, so the value means
    /// the same thing whether the media travels inline or an operator exported
    /// it to a file: `sha512sum` on that `.wav` reproduces it. Hashing the
    /// encoded text would produce a digest nothing outside this container
    /// could ever recompute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

impl Dialog {
    /// A Dialog Object with every optional field absent.
    ///
    /// Constructor rather than `Default`, because `sip_call_id` is mandatory
    /// and a defaulted empty one would emit a container tied to no capture.
    /// Every media field is set explicitly by whoever needs it, so adding a
    /// field cannot silently populate itself on the signaling object.
    fn bare(sip_call_id: String) -> Self {
        Self {
            kind: None,
            disposition: None,
            sip_call_id,
            start: None,
            duration: None,
            parties: None,
            dialogs: None,
            recording_set: None,
            mediatype: None,
            encoding: None,
            body: None,
            content_hash: None,
        }
    }
}

/// An inline attachment: sipnab's own JSON, carried in the container.
#[derive(Debug, Clone, Serialize)]
pub struct Attachment {
    /// What this attachment is for.
    pub purpose: &'static str,
    /// Index into [`Vcon::parties`] of whoever contributed it — always the
    /// sipnab observer here.
    ///
    /// §4.4 makes this mandatory "to provide provenance for the attachment",
    /// and the requirement earns its place: an attachment with no party is a
    /// document of unknown origin inside a container about a conversation, and
    /// a reader will attribute it to a participant.
    pub party: usize,
    /// Index into [`Vcon::dialog`] of the dialog this attachment is part of.
    ///
    /// REQUIRED by the working group's schema, and not nullable: it is an
    /// `integer, minimum 0`. That is why the signaling Dialog Object is always
    /// emitted -- an attachment with nowhere to point is a container that does
    /// not validate, and the completeness caveat is an attachment.
    pub dialog: usize,
    /// When the attachment was exchanged, RFC 3339. REQUIRED by the schema.
    ///
    /// The dialog's observed start rather than the export time: the attachment
    /// describes that dialog, and dating it to the moment of export would put
    /// a document about a call at a timestamp the call never reached.
    pub start: String,
    /// Always `application/json`.
    pub mediatype: &'static str,
    /// Always `json` — the body is JSON TEXT, not base64url text.
    pub encoding: &'static str,
    /// The attachment itself, as a JSON string a consumer parses.
    ///
    /// A string rather than an object, and that is the format's rule rather
    /// than a preference. §2.3 pairs `body` with an `encoding` of `base64url`,
    /// `json` or `none`, and the pairing only means anything if the body is a
    /// string the encoding says how to read. sipnab already agreed with itself
    /// on half of it: [`Dialog::body`] has always carried base64url TEXT.
    ///
    /// Measured, not merely reasoned. A container exported from a fixture and
    /// posted to a live conserver-backed store came back with every body
    /// sipnab had sent as an object normalized to a string — identical once
    /// parsed, and a different shape from the one it sent. A consumer reaching
    /// for `body.blind_spots` on an object gets a field; on a string it gets
    /// nothing, silently. The completeness caveat is the one thing §4 says a
    /// reader must not miss, which makes it the worst field to be wrong about.
    pub body: String,
}

/// What sipnab determined about this dialog.
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// Always `"report"`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Index into [`Vcon::dialog`] of what was analyzed.
    pub dialog: usize,
    /// Always [`ANALYSIS_VENDOR`].
    pub vendor: &'static str,
    /// Always [`ANALYSIS_PRODUCT`], which names sipnab as an observer.
    pub product: &'static str,
    /// Always [`ANALYSIS_SCHEMA`], naming the body's contract and version.
    pub schema: &'static str,
    /// Always `application/json`.
    pub mediatype: &'static str,
    /// Always `json`.
    pub encoding: &'static str,
    /// The report, as a JSON string a consumer parses.
    ///
    /// A string for the reason [`Attachment::body`] is one, and measured the
    /// same way.
    pub body: String,
}

/// One blind spot, flattened out of a [`crate::analysis::Finding`].
///
/// Only the fields a vCon consumer can act on: what was missed, how much of
/// it, and in what unit. The evidence rows stay behind in the capture, where
/// the frame pointers they carry still resolve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlindSpot {
    /// Stable machine identifier of the finding kind.
    pub kind: &'static str,
    /// Short human title.
    pub title: &'static str,
    /// How many times it was observed.
    pub occurrences: u64,
    /// What one occurrence is — `"frame"`, `"message"`, `"call"`.
    pub unit: &'static str,
}

/// The completeness carrier: everything a consumer needs to decide how much of
/// this conversation reached the container.
///
/// Built once per export and embedded in BOTH the analysis body and the
/// completeness attachment. One value, two surfaces — see the module docs for
/// why the duplication is deliberate and why building it twice would be worse
/// than not carrying it at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureCompleteness {
    /// The prose caveat: one string, built from this run's own counters and
    /// from nothing else.
    ///
    /// Every clause in it is a measurement. It never says the call was short,
    /// silent or broken, because none of that follows from a capture that
    /// missed something.
    pub note: String,
    /// Which box observed this.
    pub node: String,
    /// Which sipnab wrote it.
    pub sipnab_version: &'static str,
    /// Frames handed to the parser — the denominator every other number here
    /// is read against.
    pub frames_read: u64,
    /// Frames that reached the parser and produced nothing.
    pub undecodable_frames: u64,
    /// Real SIP the `--portrange` gate discarded before any dialog saw it.
    pub sip_discarded_by_port_gate: u64,
    /// Real SIP-over-WebSocket the configured port set discarded.
    pub sip_discarded_by_websocket_gate: u64,
    /// Messages idle compaction discarded from dialogs sipnab had already
    /// captured. The one retention counter that shortens a ladder already in
    /// hand, which is why the message trace in this container can be shorter
    /// than the call was.
    pub messages_evicted: u64,
    /// New dialogs refused because the store was at capacity.
    pub dialogs_refused: u64,
    /// Oldest dialogs discarded at capacity by rotation.
    pub dialogs_rotated: u64,
    /// Blind spots the capture analysis ranked, or `None` when no analysis was
    /// supplied.
    ///
    /// `None` and `Some([])` are different answers and must stay so: the first
    /// is "nobody looked", the second is "somebody looked and found nothing".
    /// Collapsing them would let an export that skipped the analysis read as a
    /// clean one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blind_spots: Option<Vec<BlindSpot>>,
    /// What became of this dialog's audio, as a token a consumer can branch
    /// on.
    ///
    /// The load-bearing field for §3's dangerous case. An empty `dialog[]`
    /// reads as *a conversation with no media*, which is a claim about the
    /// CALL; this says which of four quite different things actually happened,
    /// so no reader has to infer one from an absence.
    pub media: MediaOutcome,
    /// The audio's own provenance note, verbatim from the exported WAV.
    ///
    /// Not a second sentence about the media: the SAME `String` that is
    /// embedded in the file's RIFF comment, lifted out so a consumer that
    /// cannot parse a WAV still reads it. `None` when there is no audio to
    /// describe. When the media was refused for size, this is the note the
    /// refused file WOULD have carried, which is how a reader learns what they
    /// are missing rather than only that they are missing something.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_note: Option<String>,
}

/// What became of one dialog's audio on its way into a container.
///
/// Four answers, kept apart, because collapsing any two of them recreates the
/// failure `nothing_to_decode` exists to refuse: a limit of THIS RUN reported
/// as a finding about the TRAFFIC. "Nobody asked for media", "the run kept
/// none", "it was too big to carry" and "here it is" are four facts with four
/// different next steps, and an absent `dialog` entry is the same shape for
/// the first three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MediaOutcome {
    /// No media was offered to the exporter at all.
    ///
    /// A signaling-only export. It says nothing about whether the call had
    /// audio, and the token exists so that silence does not have to.
    NotConsidered,
    /// Media was offered and nothing decodable came back.
    ///
    /// The reason is in [`CaptureCompleteness::media_note`], in
    /// `nothing_to_decode`'s own words — retention off, a codec sipnab cannot
    /// decode, a `--snaplen` that truncated the payload away. Never "the call
    /// was silent", which is a claim about the traffic that an empty ring
    /// buffer does not support.
    NoneDecodable,
    /// Media was decoded and REFUSED for size.
    ///
    /// See [`MAX_INLINE_MEDIA_BYTES`]. The audio exists and is not in this
    /// container; it was not truncated, because half a call presented as a
    /// whole one is worse than none.
    RefusedOverBudget,
    /// Media was decoded and is inline in a `recording` Dialog Object.
    Carried,
}

impl MediaOutcome {
    /// The token this outcome serializes as.
    ///
    /// Spelled once here so a test, a doc page and the wire cannot disagree
    /// about it. `serde`'s kebab-case rename produces exactly these strings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotConsidered => "not-considered",
            Self::NoneDecodable => "none-decodable",
            Self::RefusedOverBudget => "refused-over-budget",
            Self::Carried => "carried",
        }
    }
}

/// What a caller was able to decode for one dialog's media.
///
/// A three-way answer rather than an `Option`, because the two "no media"
/// cases are not the same fact and the container must not render them the same
/// way. `Option::None` would force "nobody looked" and "this run kept nothing"
/// into one shape, which is the collapse
/// `nothing_to_decode` was written to prevent.
#[derive(Debug, Clone, Copy)]
pub enum ObservedAudio<'a> {
    /// Nobody asked for media. Yields [`MediaOutcome::NotConsidered`].
    NotConsidered,
    /// Media was looked for and none could be decoded. Carries the exporter's
    /// own explanation, which reports what was MEASURED.
    NothingToDecode(&'a str),
    /// Audio sipnab decoded for this dialog.
    Decoded(&'a DialogAudio),
}

/// A signaling-only vCon for one observed dialog.
#[derive(Debug, Clone, Serialize)]
pub struct Vcon {
    /// Syntax version — [`VCON_SYNTAX_VERSION`].
    pub vcon: &'static str,
    /// UUIDv8 identifying this container. See [`dialog_uuid`].
    pub uuid: String,
    /// When this container was WRITTEN, RFC 3339.
    ///
    /// Not when the dialog happened. §4.1.4 defines it as the creation time of
    /// the vCon, and stamping the call's start here would make an export
    /// written years later look contemporaneous with the traffic. The dialog's
    /// own clock is reachable through the message trace, which carries a
    /// timestamp per message.
    pub created_at: String,
    /// Always `["sip-signaling"]`. `critical` is absent by construction —
    /// there is no field for it here, because nothing in this container may
    /// refuse itself to a generic reader.
    pub extensions: Vec<&'static str>,
    /// The observed parties, then the sipnab observer as the final entry.
    pub parties: Vec<Party>,
    /// Exactly one, near-empty, Dialog Object.
    pub dialog: Vec<Dialog>,
    /// The message trace and the completeness caveat.
    pub attachments: Vec<Attachment>,
    /// Exactly one report.
    pub analysis: Vec<Analysis>,
}

impl Vcon {
    /// Index into [`Self::parties`] of the sipnab observer.
    ///
    /// Always the last entry, and derived rather than remembered: the two
    /// attachments and any later consumer need it, and a hard-coded index
    /// silently points at a caller the day a third observed party appears.
    #[must_use]
    pub fn observer_index(&self) -> usize {
        self.parties.len().saturating_sub(1)
    }

    /// Serialize the container as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Propagates any `serde_json` failure rather than substituting an error
    /// object. A container that failed to serialize is not a container, and
    /// handing back JSON that merely says so invites a caller to write it to
    /// a file named `.vcon`.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Everything an export needs that is not in the dialog itself.
///
/// Taken as one value for the reason [`CaptureFacts`] is: it makes visible, in
/// one place, exactly which facts the completeness claim is standing on, and
/// it lets a test state the precise capture it is describing instead of
/// mutating process globals.
#[derive(Debug, Clone, Copy)]
pub struct ExportContext<'a> {
    /// Identifies the CAPTURE this dialog came from.
    ///
    /// Mixed into [`dialog_uuid`], so re-exporting one dialog from one capture
    /// yields one uuid. Pass something derived from the capture's CONTENT — a
    /// file name, a frame digest — not
    /// [`CaptureIdentity::instance`](crate::provenance::CaptureIdentity::instance),
    /// which rotates per process and would give the same dialog a new uuid
    /// every time the file is reopened.
    pub capture_id: &'a str,
    /// What the run observed outside any single dialog.
    pub facts: &'a CaptureFacts,
    /// The ranked capture analysis, when the caller ran one.
    ///
    /// `None` is honest and is reported as such: see
    /// [`CaptureCompleteness::blind_spots`].
    pub analysis: Option<&'a CaptureAnalysis>,
}

/// What [`dialog_capture_id`] returns for a dialog that carries no provenance.
///
/// A literal placeholder rather than an empty string: `capture_id` is mixed
/// into [`dialog_uuid`], and an empty one would give every provenance-less
/// dialog the same seed as every other, which reads as "these came from the
/// same capture" instead of "nobody knows where these came from".
pub const UNKNOWN_CAPTURE: &str = "unknown-capture";

/// Identify the capture a dialog came from, for [`ExportContext::capture_id`].
///
/// Reads the SOURCE half of the dialog's own first frame pointer — the capture
/// file path on a replay, the device name on a live capture, the listener on a
/// HEP feed. That is content-anchored in the sense `capture_id` asks for: it
/// names where these bytes were read, so re-exporting one dialog out of one
/// file keeps one uuid, and the same Call-ID observed in a different file gets
/// a different one.
///
/// The OPENING message decides, matching the rule the parties follow. A dialog
/// whose messages arrived through two `-I` files would otherwise be attributed
/// to whichever of them the last packet happened to sit in.
///
/// Returns [`UNKNOWN_CAPTURE`] when no message carries a pointer at all — a
/// synthesized dialog, or a source that cannot number its frames. Naming the
/// gap beats inventing an identifier that looks like provenance.
#[must_use]
pub fn dialog_capture_id(dialog: &SipDialog) -> &str {
    dialog
        .messages
        .first()
        .and_then(|m| m.frame.as_ref())
        .map_or(UNKNOWN_CAPTURE, |frame| &frame.source)
}

/// Export one dialog as a vCon, stamped with the current time.
///
/// See [`export_dialog_at`] for the pure form and for what the container
/// contains.
#[must_use]
pub fn export_dialog(dialog: &SipDialog, context: &ExportContext<'_>) -> Vcon {
    export_dialog_at(dialog, context, Utc::now())
}

/// [`export_dialog`] with the container's `created_at` supplied by the caller.
///
/// The pure form: every input the output depends on arrives as an argument, so
/// a test can compare two containers byte for byte and know that a difference
/// came from the capture rather than from the clock.
///
/// # Arguments
///
/// * `dialog` — the observed dialog. Its `From`/`To` become the parties and
///   its messages become the trace.
/// * `context` — the capture the dialog came from, and what that capture
///   missed.
/// * `exported_at` — stamped into [`Vcon::created_at`]. This is the moment the
///   container was written, NOT the moment the call started.
#[must_use]
pub fn export_dialog_at(
    dialog: &SipDialog,
    context: &ExportContext<'_>,
    exported_at: DateTime<Utc>,
) -> Vcon {
    export_dialog_with_audio_at(dialog, context, ObservedAudio::NotConsidered, exported_at)
}

/// [`export_dialog`], carrying this dialog's audio inside the container.
///
/// See [`export_dialog_with_audio_at`] for what the media becomes and for what
/// is refused.
#[must_use]
pub fn export_dialog_with_audio(
    dialog: &SipDialog,
    context: &ExportContext<'_>,
    audio: ObservedAudio<'_>,
) -> Vcon {
    export_dialog_with_audio_at(dialog, context, audio, Utc::now())
}

/// The one builder: signaling, the completeness caveat, and — when there is
/// any — the media.
///
/// The pure form: every input the output depends on arrives as an argument, so
/// a test can compare two containers byte for byte and know that a difference
/// came from the capture rather than from the clock.
///
/// # What the media becomes
///
/// [`ObservedAudio::Decoded`] under [`MAX_INLINE_MEDIA_BYTES`] becomes a
/// `recording` Dialog Object: inline base64url, a `content_hash` over the WAV,
/// a `duration` that is the FILE's, and `parties` only where every channel
/// could be attributed. When the payload ring wrapped, a
/// [`RECORDING_SET_TYPE`] wrapper is added carrying the CALL's clock — the
/// format's one way to say the file is shorter than the call it came from.
///
/// Over the budget, **no `recording` object is emitted and the refusal is
/// stated**: [`CaptureCompleteness::media`] carries
/// [`MediaOutcome::RefusedOverBudget`] and the caveat names the two sizes. A
/// container that quietly dropped the audio would read as a conversation with
/// no media, which is a claim about the call rather than about this run.
///
/// # Arguments
///
/// * `dialog` — the observed dialog. Its `From`/`To` become the parties and
///   its messages become the trace.
/// * `context` — the capture the dialog came from, and what that capture
///   missed.
/// * `audio` — what the caller could decode for this dialog, including the two
///   distinct ways of having nothing.
/// * `exported_at` — stamped into [`Vcon::created_at`]. This is the moment the
///   container was written, NOT the moment the call started.
#[must_use]
pub fn export_dialog_with_audio_at(
    dialog: &SipDialog,
    context: &ExportContext<'_>,
    audio: ObservedAudio<'_>,
    exported_at: DateTime<Utc>,
) -> Vcon {
    let mut parties = observed_parties(dialog);
    parties.push(observer_party());
    // Last entry, computed before the borrow ends so both attachments and any
    // future analysis reference one number.
    let observer = parties.len().saturating_sub(1);

    // The signaling object is always index 0, which is what `Analysis::dialog`
    // points at. Media objects are appended after it, never before, so adding
    // audio cannot move the object the analysis describes.
    let started = observed_start(dialog);
    let mut dialog_objects = vec![dialog_object(dialog, started.clone())];
    let media = media_objects(dialog, audio, &mut dialog_objects);

    let completeness = completeness_of(context, &media);

    let attachments = vec![
        message_trace_attachment(dialog, observer, started.clone()),
        completeness_attachment(&completeness, observer, started),
    ];

    Vcon {
        vcon: VCON_SYNTAX_VERSION,
        uuid: dialog_uuid(dialog, context.capture_id),
        created_at: exported_at.to_rfc3339(),
        extensions: vec![SIP_SIGNALING_EXTENSION, CC_EXTENSION],
        parties,
        dialog: dialog_objects,
        attachments,
        analysis: vec![report(dialog, &completeness)],
    }
}

/// What the media decided, kept together so the caveat and the container
/// cannot disagree about it.
#[derive(Debug, Clone)]
struct MediaVerdict {
    /// Which of the four things happened.
    outcome: MediaOutcome,
    /// The audio's own note, or the exporter's explanation for having none.
    note: Option<String>,
    /// The size clause, when the media was refused for being too large.
    refusal: Option<String>,
}

/// Append the media Dialog Objects, and report what happened.
///
/// Appends rather than inserts, and returns the verdict rather than writing it
/// anywhere: the caveat is built ONCE, from this, and embedded in both
/// surfaces. A second sentence about the media written beside this one is the
/// drift `provenance_note` already learned to refuse.
fn media_objects(
    dialog: &SipDialog,
    audio: ObservedAudio<'_>,
    objects: &mut Vec<Dialog>,
) -> MediaVerdict {
    let decoded = match audio {
        ObservedAudio::NotConsidered => {
            return MediaVerdict {
                outcome: MediaOutcome::NotConsidered,
                note: None,
                refusal: None,
            };
        }
        ObservedAudio::NothingToDecode(reason) => {
            return MediaVerdict {
                outcome: MediaOutcome::NoneDecodable,
                note: Some(reason.to_string()),
                refusal: None,
            };
        }
        ObservedAudio::Decoded(decoded) => decoded,
    };

    let body = URL_SAFE_NO_PAD.encode(&decoded.wav);
    if body.len() > MAX_INLINE_MEDIA_BYTES {
        return MediaVerdict {
            outcome: MediaOutcome::RefusedOverBudget,
            note: Some(decoded.note.clone()),
            refusal: Some(format!(
                " — INCOMPLETE: sipnab decoded {:.1} second(s) of audio for this dialog and \
                 REFUSED to carry it: base64url of the {} byte WAV is {} bytes, over the {} byte \
                 budget this emitter enforces because one probed vCon store answers 204 and drops \
                 the payload without telling the producer. The audio was NOT truncated and is not \
                 in this container; export it beside this file with --export-audio.",
                decoded.duration_secs,
                decoded.wav.len(),
                body.len(),
                MAX_INLINE_MEDIA_BYTES,
            )),
        };
    }

    // The media REPLACES the signaling object rather than sitting beside it,
    // and that is forced by the schema rather than chosen for tidiness. Every
    // Dialog Object needs a `type` from a closed enum, so appending a second
    // object would put two of them in `dialog[]` for one exchange, one
    // carrying audio and one carrying nothing. A consumer reading that sees
    // two dialogs and has no field telling it which is real.
    //
    // One exchange, one Dialog Object. The audio is what that object was always
    // describing.
    if decoded.ring_wrapped {
        // §4.3.3's shape: the SET carries the call's clock and points at a
        // member carrying the file's. The set takes index 0 because the
        // attachments and the analysis already point there, and the call's
        // window is the thing they describe. `kind` moves to the set; the
        // disposition stays behind on nothing, because a wrapped ring means
        // media flowed and the call did not fail to set up.
        let member = objects.len();
        objects[0] = recording_set_object(dialog, decoded, member);
        // Index 0 is the set: §4.3.7's back-pointer, so the link is two-way.
        objects.push(recording_object(dialog, decoded, &body, 0));
    } else {
        let signaling = &mut objects[0];
        // Enriched in place, and RETYPED: it carries audio now, so it is a
        // `recording`. Leaving it `incomplete` would park a WAV on an object
        // every `type == "recording"` selector skips — the audio would be
        // present in the container and unreachable by the consumers that want
        // it. `disposition` goes with the retype, being an `incomplete` field.
        // What the call DID is not lost: `final_status_code` rides in the
        // analysis body, which is where an outcome belongs.
        signaling.kind = Some(RECORDING_TYPE);
        signaling.disposition = None;
        signaling.start = Some(decoded.first_retained.to_rfc3339());
        signaling.duration = Some(decoded.duration_secs);
        signaling.parties = channel_parties(dialog, decoded);
        signaling.mediatype = Some(RECORDING_MEDIATYPE);
        signaling.encoding = Some("base64url");
        signaling.content_hash = Some(content_hash(&decoded.wav));
        signaling.body = Some(body);
    }

    MediaVerdict {
        outcome: MediaOutcome::Carried,
        note: Some(decoded.note.clone()),
        refusal: None,
    }
}

/// The `recording` Dialog Object — the FILE's clock, and the file.
fn recording_object(
    dialog: &SipDialog,
    audio: &DialogAudio,
    body: &str,
    recording_set: usize,
) -> Dialog {
    Dialog {
        kind: Some(RECORDING_TYPE),
        start: Some(audio.first_retained.to_rfc3339()),
        duration: Some(audio.duration_secs),
        // §4.3.7's SHOULD: the member names the set it belongs to, so a
        // consumer holding the audio can reach the call's clock.
        recording_set: Some(recording_set),
        parties: channel_parties(dialog, audio),
        mediatype: Some(RECORDING_MEDIATYPE),
        encoding: Some("base64url"),
        content_hash: Some(content_hash(&audio.wav)),
        body: Some(body.to_string()),
        ..Dialog::bare(dialog.call_id.clone())
    }
}

/// The `recording-set` wrapper — the CALL's clock, for the ring-wrapped case
/// only.
///
/// §4.3.3 of the core draft is the only place vCon can say "this file is a
/// fragment of that call": the set's `start` and `duration` describe the media
/// window sipnab observed, while the `recording` it points at describes the
/// part that survived retention. Nothing obliges a consumer to compare them,
/// which is why the caveat is duplicated as well and not instead.
///
/// The window is measured from MEDIA — first packet to last across the
/// dialog's streams — rather than from the SIP ladder. A signaling span would
/// state something about the call's setup and teardown in a field a reader
/// will compare against an audio duration.
fn recording_set_object(dialog: &SipDialog, audio: &DialogAudio, member: usize) -> Dialog {
    let span = audio
        .media_end
        .signed_duration_since(audio.media_start)
        .num_milliseconds()
        .max(0);
    Dialog {
        kind: Some(RECORDING_SET_TYPE),
        start: Some(audio.media_start.to_rfc3339()),
        // Milliseconds to seconds, keeping the fraction: a call rounded to a
        // whole second could equal the file's duration and hide exactly the
        // difference this object exists to show.
        duration: Some(span as f64 / 1000.0),
        dialogs: Some(vec![member]),
        ..Dialog::bare(dialog.call_id.clone())
    }
}

/// `sha512-` followed by the base64url SHA-512 of the media bytes, per §2.2.
///
/// Over the WAV, never over its base64url text. An operator who exported the
/// same call with `--export-audio` can run `sha512sum` on the file and get a
/// value that maps to this one; a digest of the encoded text is a number
/// nothing outside this container could reproduce.
fn content_hash(media: &[u8]) -> String {
    let digest = Sha512::digest(media);
    format!("{CONTENT_HASH_PREFIX}{}", URL_SAFE_NO_PAD.encode(digest))
}

/// Which observed party's media is on each channel, or `None` when any channel
/// cannot be attributed from evidence.
///
/// The evidence is a party's OWN advertised media endpoint matching the
/// sending socket of the stream on that channel. Symmetric RTP (RFC 4961) is
/// what makes that a match rather than a coincidence: an endpoint sends from
/// the port it told the far end to send to.
///
/// All or nothing, deliberately. §4.3.4 has a null placeholder and it means
/// "no party on this channel", not "sipnab could not tell" — using it for the
/// second would state, about a channel full of audio, that nobody was on it.
/// And a partly-attributed list invites a reader to fill in the rest.
///
/// Absent is the common answer once a relay is in the media path, which is
/// correct: the relay's socket is not either party's, and sipnab reconstructed
/// the audio from a tap rather than receiving it from anyone.
fn channel_parties(dialog: &SipDialog, audio: &DialogAudio) -> Option<Vec<usize>> {
    let advertised = advertised_media_endpoints(dialog);
    if advertised.is_empty() {
        return None;
    }
    audio
        .sources
        .iter()
        .map(|key| {
            advertised
                .iter()
                .find(|(socket, _)| *socket == key.src)
                .map(|(_, party)| *party)
        })
        .collect()
}

/// Every media endpoint an observed party advertised for itself, with that
/// party's index.
///
/// The sender is read off the dialog tag rather than off the packet's source
/// address: a proxy rewrites the second and cannot rewrite the first without
/// breaking the dialog. A request's `From` tag names whoever sent it; a
/// response's `To` tag names whoever answered.
fn advertised_media_endpoints(dialog: &SipDialog) -> Vec<(std::net::SocketAddr, usize)> {
    dialog
        .messages
        .iter()
        .filter_map(|msg| Some((sdp_audio_endpoint(msg)?, sender_party(dialog, msg)?)))
        .collect()
}

/// The socket the first audio media description of a message's SDP names, when
/// it carries one that parses into an address.
fn sdp_audio_endpoint(msg: &crate::sip::SipMessage) -> Option<std::net::SocketAddr> {
    let session = crate::sip::sdp::parse_sdp(&msg.body).ok()?;
    let media = session.media.iter().find(|m| m.media_type == "audio")?;
    let addr = crate::sip::sdp::effective_address(media, &session)?;
    Some(std::net::SocketAddr::new(addr.parse().ok()?, media.port))
}

/// Index into the observed parties of whoever sent this message, or `None`
/// when its tags match neither.
///
/// `None` rather than a fallback to index 0: a message whose tags do not match
/// the dialog's is a forked leg, a re-INVITE from a third party, or a parse
/// sipnab got wrong, and attributing it to the caller would put the caller's
/// index on somebody else's audio.
fn sender_party(dialog: &SipDialog, msg: &crate::sip::SipMessage) -> Option<usize> {
    let tag = if msg.is_request {
        msg.from_tag()
    } else {
        msg.to_tag()
    }?;
    if dialog.from_tag.as_deref() == Some(tag) {
        Some(0)
    } else if dialog.to_tag.as_deref() == Some(tag) {
        Some(1)
    } else {
        None
    }
}

/// The two parties the dialog's own headers named, in `From` then `To` order.
///
/// Strictly from the observed headers. Nothing is inferred from the direction
/// of the packets, from a `Contact` rewritten by a proxy, or from a later
/// re-INVITE — an inferred party is a participant the container asserts and
/// the capture never saw.
fn observed_parties(dialog: &SipDialog) -> Vec<Party> {
    let first = dialog.messages.first();
    vec![
        Party {
            sip: sip_uri(dialog.from_user.as_deref(), dialog.from_host.as_deref()),
            validation: "none",
            role: None,
            sip_display_name: dialog.from_display.clone(),
            // From the OPENING message only. A `Contact`/`User-Agent` taken
            // from the latest message in the ladder would attribute a
            // responder's headers to the caller.
            sip_contact: first.and_then(|m| m.contact().map(str::to_string)),
            sip_user_agent: first.and_then(|m| m.user_agent().map(str::to_string)),
        },
        Party {
            sip: sip_uri(dialog.to_user.as_deref(), dialog.to_host.as_deref()),
            validation: "none",
            role: None,
            sip_display_name: dialog.to_display.clone(),
            // The callee's own headers arrive on its responses, so this reads
            // the first message coming back rather than the first message.
            sip_contact: first_response(dialog).and_then(|m| m.contact().map(str::to_string)),
            sip_user_agent: first_response(dialog).and_then(|m| m.user_agent().map(str::to_string)),
        },
    ]
}

/// The first response in the ladder, whose headers belong to the answering
/// side rather than to the caller.
fn first_response(dialog: &SipDialog) -> Option<&crate::sip::SipMessage> {
    dialog.messages.iter().find(|m| !m.is_request)
}

/// The party representing sipnab itself.
///
/// Carries no `sip` URI: sipnab sent no SIP and a synthesized URI would be a
/// participant that never existed. What it does carry is `role: "observer"`
/// and its own software identity, which together are what an attachment's
/// `party` index has to resolve to for the provenance §4.4 asks for to mean
/// anything.
fn observer_party() -> Party {
    Party {
        sip: None,
        validation: "none",
        role: Some(OBSERVER_ROLE),
        sip_display_name: None,
        sip_contact: None,
        sip_user_agent: Some(format!(
            "sipnab/{} (observer; node {})",
            env!("CARGO_PKG_VERSION"),
            node_name()
        )),
    }
}

/// Rebuild a `sip:` URI from an observed user and host.
///
/// Returns `None` unless a host was observed: `sip:alice@` is not a URI, and
/// a URI with a fabricated host is worse than an absent one.
fn sip_uri(user: Option<&str>, host: Option<&str>) -> Option<String> {
    let host = host?;
    Some(match user {
        Some(user) => format!("sip:{user}@{host}"),
        None => format!("sip:{host}"),
    })
}

/// The signaling Dialog Object: always a `type` and a `start`, plus a
/// disposition when — and only when — the wire carried a final failure.
///
/// Both fields are REQUIRED by the working group's own schema
/// (`definitions/Dialog`), and that requirement is the §3 gap made
/// machine-enforceable. §4.3's prose blesses an empty Dialog Object for a
/// dialog known to have occurred with nothing else available, and that is the
/// most honest shape the format offers sipnab — but the schema rejects it, and
/// a validating consumer is the reader who actually bounces the container.
/// Being right about the prose is no comfort when nothing arrives.
///
/// `type` is a closed enum — `recording`, `text`, `transfer`, `incomplete`,
/// `recording-set` — and for a signaling-only observation NONE of them is
/// true. `incomplete` is the trap: §4.3.1 makes it mean the CALL failed to set
/// up, so emitting it because sipnab did not capture an answer would state a
/// fact about the conversation from a limit of the capture. That is the exact
/// collapse this project refuses everywhere else.
///
/// So `recording` is chosen as the least-wrong member: it is the only
/// media-shaped value, the attachments need a dialog to index into, and the
/// completeness carrier says in plain words when no media traveled. A field
/// that is imprecise beside a caveat that is exact beats a caveat that cannot
/// reach the reader at all.
fn dialog_object(dialog: &SipDialog, start: String) -> Dialog {
    Dialog {
        // Typed by what this object CARRIES, not by what the call did. At
        // construction it carries no content, and of the five values §4.3.1
        // allows, `incomplete` is the only one that does not claim content
        // this object does not hold. Media enrichment retypes it to
        // `recording` when audio actually arrives.
        //
        // `recording` was the earlier choice for the no-failure case, and it
        // is an ingest hazard rather than merely an imprecise label: a
        // conserver chain link that selects `type == "recording"` reads
        // `dialog["url"]` with a bracket rather than a `get`, so an object
        // typed `recording` carrying neither `url` nor `body` raises inside
        // the link — and the conserver dead-letters the WHOLE container on
        // that, not just the step that raised.
        kind: Some(INCOMPLETE_TYPE),
        // Only an OBSERVED final failure names a reason. Its absence says
        // nothing failed that sipnab saw, which is not the same as success.
        disposition: dialog.final_status_code().and_then(failure_disposition),
        start: Some(start),
        ..Dialog::bare(dialog.call_id.clone())
    }
}

/// When the dialog was first observed, RFC 3339, for `Dialog::start`.
///
/// The first message sipnab SAW, not the call's true beginning, which a
/// mid-call tap never knows. The distinction is the completeness carrier's to
/// state; this field only has to be a real observed instant rather than an
/// invented one.
fn observed_start(dialog: &SipDialog) -> String {
    dialog.created_at.to_rfc3339()
}

/// Map an observed final status onto a vCon disposition.
///
/// Returns `None` for anything below `400`, including `2xx` and `3xx`: a
/// redirected call did not fail, and a container claiming it did would send an
/// operator after a fault that is not there.
///
/// The four buckets are coarser than SIP's status ladder on purpose. vCon
/// dispositions describe an OUTCOME a person would recognize, and there is no
/// disposition that means "403 Forbidden"; mapping every code to its own
/// invented string would produce a vocabulary no consumer implements.
fn failure_disposition(code: u16) -> Option<&'static str> {
    match code {
        486 | 600 => Some("busy"),
        503 => Some("congestion"),
        408 | 480 => Some("no-answer"),
        400..=699 => Some("failed"),
        _ => None,
    }
}

/// The per-message signaling trace.
///
/// Bodies come from [`crate::output::json::message_to_json_value`], which is
/// the same projection `--json` writes — one serializer, so a vCon and an
/// NDJSON line describing one message cannot disagree about it.
fn message_trace_attachment(dialog: &SipDialog, observer: usize, start: String) -> Attachment {
    let messages: Vec<serde_json::Value> = dialog
        .messages
        .iter()
        .map(|m| {
            let mut value = crate::output::json::message_to_json_value(m);
            strip_credentials(&mut value);
            value
        })
        .collect();

    Attachment {
        purpose: MESSAGE_TRACE_PURPOSE,
        party: observer,
        dialog: 0,
        start,
        mediatype: "application/json",
        encoding: "json",
        // Both spellings, deliberately. `sip-signaling` describes this body
        // with the keys `version` and `call_id`, and sipnab DECLARES that
        // extension — a reader who implements it and finds neither key reads
        // an EMPTY trace and gets no error, which is the worst failure mode
        // available. `schema_version` and `sip_call_id` are what existing
        // sipnab consumers already read, and dropping them would break those
        // for a draft that is still individual and at -00.
        body: json_text(&serde_json::json!({
            "version": DIAGNOSIS_SCHEMA_VERSION,
            "call_id": dialog.call_id,
            "schema_version": DIAGNOSIS_SCHEMA_VERSION,
            "sip_call_id": dialog.call_id,
            "messages": messages,
        })),
    }
}

/// Remove every credential-bearing header from a JSON value, at any depth.
///
/// Applied to each message body on its way into the container rather than
/// trusted to the projection upstream. The projection carries no raw header
/// map today, so this removes nothing from a message sipnab parses now — it is
/// a filter at the PUBLICATION boundary, and the boundary is where the rule
/// has to hold: `message_to_json_value` gaining a `headers` field would be an
/// ordinary, sensible change to a debugging surface, and it would silently
/// start putting digest credentials into a container built to be handed to
/// somebody else.
///
/// Keys are compared case-insensitively. See [`CREDENTIAL_HEADERS`].
fn strip_credentials(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|key, _| {
                !CREDENTIAL_HEADERS
                    .iter()
                    .any(|banned| key.eq_ignore_ascii_case(banned))
            });
            for nested in map.values_mut() {
                strip_credentials(nested);
            }
        }
        serde_json::Value::Array(items) => {
            for nested in items {
                strip_credentials(nested);
            }
        }
        _ => {}
    }
}

/// The completeness attachment — surface two of two.
fn completeness_attachment(
    completeness: &CaptureCompleteness,
    observer: usize,
    start: String,
) -> Attachment {
    Attachment {
        purpose: COMPLETENESS_PURPOSE,
        party: observer,
        dialog: 0,
        start,
        mediatype: "application/json",
        encoding: "json",
        body: json_text(&to_value_or_note(completeness)),
    }
}

/// The report — surface one of two.
///
/// The signaling diagnosis is reused rather than recomputed: it is already the
/// wire shape `--json-dialogs` emits, and a second projection of one analysis
/// is two definitions waiting to disagree.
fn report(dialog: &SipDialog, completeness: &CaptureCompleteness) -> Analysis {
    let signaling = crate::sip::diagnosis::diagnose_signaling(&dialog.messages);
    let mut body = serde_json::json!({
        "schema_version": DIAGNOSIS_SCHEMA_VERSION,
        "sip_call_id": dialog.call_id,
        "capture_completeness": to_value_or_note(completeness),
    });
    if let Some(map) = body.as_object_mut() {
        if let Some(code) = dialog.final_status_code() {
            map.insert("final_status_code".into(), code.into());
        }
        // Omitted entirely when nothing was detected, matching how every other
        // sipnab surface renders a clean dialog.
        if !signaling.is_empty() {
            map.insert("signaling_diagnosis".into(), to_value_or_note(&signaling));
        }
    }
    strip_credentials(&mut body);

    Analysis {
        kind: "report",
        dialog: 0,
        vendor: ANALYSIS_VENDOR,
        product: ANALYSIS_PRODUCT,
        schema: ANALYSIS_SCHEMA,
        mediatype: "application/json",
        encoding: "json",
        body: json_text(&body),
    }
}

/// Serialize a value, or substitute an object that says the serialization
/// failed and names the field it stood in for.
///
/// The alternative shapes are both worse. Returning `null` would put a hole in
/// the container that reads as "this dialog had no diagnosis"; propagating the
/// error out of [`export_dialog_at`] would make every caller handle a failure
/// that cannot happen for these types, which is how a `Result` stops being
/// read. This one is loud and stays inside the field it replaced.
fn to_value_or_note<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_else(|e| {
        serde_json::json!({
            "error": format!("sipnab could not serialize this field: {e}"),
        })
    })
}

/// A JSON value as the TEXT an `encoding: "json"` body carries.
///
/// Never fails in practice — the input is already a `serde_json::Value`, which
/// serializes — but the fallback is a real message rather than an unwrap,
/// because a body that vanished would leave an attachment whose purpose
/// promises something the container does not hold.
fn json_text(value: &serde_json::Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|e| format!("{{\"error\":\"sipnab could not serialize this body: {e}\"}}"))
}

/// Read the completeness of a capture off its facts, its analysis, and what
/// happened to its media.
fn completeness_of(context: &ExportContext<'_>, media: &MediaVerdict) -> CaptureCompleteness {
    let facts = context.facts;
    let blind_spots = context.analysis.map(|analysis| {
        analysis
            .at(Severity::Blind)
            .map(|finding| {
                let meta = finding.kind.meta();
                BlindSpot {
                    kind: meta.id,
                    title: meta.title,
                    occurrences: finding.occurrences,
                    unit: finding.unit,
                }
            })
            .collect()
    });

    CaptureCompleteness {
        note: completeness_note(facts, blind_spots.as_deref(), media),
        media: media.outcome,
        media_note: media.note.clone(),
        node: node_name().to_string(),
        sipnab_version: env!("CARGO_PKG_VERSION"),
        frames_read: facts.frames_read,
        undecodable_frames: facts.undecodable.frames,
        sip_discarded_by_port_gate: facts.portrange.messages,
        sip_discarded_by_websocket_gate: facts.websocket.messages,
        messages_evicted: facts.retention.messages_evicted,
        dialogs_refused: facts.retention.dialogs_refused,
        dialogs_rotated: facts.retention.dialogs_rotated,
        blind_spots,
    }
}

/// The one caveat string, built from the run's own counters.
///
/// Every clause is a measurement, never an inference. The note says what this
/// run READ and what it dropped; it never says the call was short, silent or
/// broken, because none of those follow from a capture that missed something.
///
/// `blind` is `None` when no capture analysis was supplied, and that case gets
/// its own clause rather than the clean one — "nobody checked" and "checked
/// and found nothing" are different facts, and only the second earns a clean
/// bill.
fn completeness_note(
    facts: &CaptureFacts,
    blind: Option<&[BlindSpot]>,
    media: &MediaVerdict,
) -> String {
    let mut partial = String::new();
    if let Some(refusal) = media.refusal.as_deref() {
        partial.push_str(refusal);
    }

    if facts.undecodable.frames > 0 {
        let reasons = facts.undecodable.reason_list();
        let detail = if reasons.is_empty() {
            String::new()
        } else {
            format!(" ({reasons})")
        };
        partial.push_str(&format!(
            " — INCOMPLETE: {} frame(s) reached the parser and produced nothing{detail}, so any \
             count in this container is a floor.",
            facts.undecodable.frames
        ));
    }
    if facts.portrange.messages > 0 {
        partial.push_str(&format!(
            " — INCOMPLETE: a port gate discarded {} SIP message(s) before any dialog saw them.",
            facts.portrange.messages
        ));
    }
    if facts.websocket.messages > 0 {
        partial.push_str(&format!(
            " — INCOMPLETE: the WebSocket port set discarded {} SIP message(s).",
            facts.websocket.messages
        ));
    }
    if facts.retention.messages_evicted > 0 {
        partial.push_str(&format!(
            " — INCOMPLETE: idle compaction discarded {} message(s) sipnab had already captured, \
             so the trace in this container may be shorter than the call was. Raise [limits] \
             keep_messages_per_idle_dialog to hold more.",
            facts.retention.messages_evicted
        ));
    }
    if facts.retention.dialogs_refused > 0 {
        partial.push_str(&format!(
            " — INCOMPLETE: the dialog store refused {} new dialog(s) at capacity.",
            facts.retention.dialogs_refused
        ));
    }
    if facts.retention.dialogs_rotated > 0 {
        partial.push_str(&format!(
            " — INCOMPLETE: {} dialog(s) were discarded at capacity by rotation.",
            facts.retention.dialogs_rotated
        ));
    }

    let blind_clause = match blind {
        None => " No capture-level analysis was supplied for this export, so nothing here rules \
                  out a blind spot."
            .to_string(),
        Some([]) => " A capture-level analysis ran and ranked no blind spots.".to_string(),
        Some(spots) => {
            let list = spots
                .iter()
                .map(|s| format!("{} ({} {})", s.kind, s.occurrences, s.unit))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                " — INCOMPLETE: the capture analysis ranked {} blind spot(s): {list}.",
                spots.len()
            )
        }
    };

    let verdict = if partial.is_empty() {
        " No omissions recorded: every message sipnab held for this dialog is in this container."
            .to_string()
    } else {
        partial
    };

    format!(
        "Produced by sipnab {} on node {}. sipnab OBSERVED this dialog and took no part in it: \
         the parties below are what the From and To headers said, not identities anyone \
         established, and nothing here is signed.{} sipnab read {} frame(s) for this \
         capture.{verdict}{blind_clause}",
        env!("CARGO_PKG_VERSION"),
        node_name(),
        media_clause(media.outcome),
        facts.frames_read,
    )
}

/// The sentence describing what this container carries in place of media.
///
/// Four sentences rather than one, because the four outcomes are four
/// different facts and the reader's next step differs for each. The dangerous
/// one is [`MediaOutcome::NotConsidered`]: a container with no `recording`
/// object reads as a conversation that had no media, which is a claim about
/// the CALL. It has to be said out loud that this run never looked.
///
/// No `url` is ever mentioned as a place the media might be, because §2.5
/// refuses to host anything and a container that names an elsewhere is
/// asserting where a file lives on infrastructure sipnab does not control.
fn media_clause(outcome: MediaOutcome) -> &'static str {
    match outcome {
        MediaOutcome::NotConsidered => {
            " This container carries SIGNALING ONLY — no media, and no reference to media held \
             elsewhere. That is a fact about this EXPORT, not about the call: nothing here says \
             whether the conversation carried audio."
        }
        MediaOutcome::NoneDecodable => {
            " No media is in this container because this run decoded none for the dialog; the \
             capture_completeness media_note says what was measured. That is a statement about \
             what this run kept, not a finding that the call was silent."
        }
        MediaOutcome::RefusedOverBudget => {
            " No media is in this container because sipnab REFUSED to inline it: it decoded \
             audio and the encoded body was over the budget below. The audio exists and was not \
             truncated."
        }
        MediaOutcome::Carried => {
            " Media IS in this container, as a recording Dialog Object holding a WAV inline. It \
             was reconstructed from RTP this run retained at a capture point — it is NOT a \
             recording made by the endpoints, and the media_note traveling with it says how it \
             is bounded."
        }
    }
}

/// A UUIDv8 for one dialog out of one capture, per §4.1.2 of the core draft.
///
/// Laid out like a UUIDv7 — a 48-bit millisecond timestamp, a 12-bit `rand_a`,
/// then a 62-bit `rand_b` — with two deliberate choices:
///
/// * **`rand_b` is host-derived**, taken from the high 62 bits of a digest of
///   the node name, which is what the draft asks for. Two containers written
///   on one box therefore share those bits: that is the point, not a leak of
///   entropy.
/// * **The timestamp is the DIALOG's, not the export's.** With the export
///   clock in there, re-exporting one dialog would mint a new identifier every
///   time, and a consumer deduplicating on `uuid` would accumulate copies of
///   one conversation. [`Vcon::created_at`] still carries the export time,
///   where §4.1.4 puts it.
///
/// `rand_a` is seeded from the `Call-ID` and `capture_id`, so the whole value
/// is a function of the observed dialog and the capture it came from.
///
/// # What this identifier does not promise
///
/// Uniqueness beyond 12 bits for two dialogs that opened in the same
/// millisecond on the same node. That is inherent in the draft's layout — a
/// host-derived `rand_b` spends the entropy a v7 would have used — and it is
/// stated here rather than discovered by a consumer that assumed otherwise.
///
/// # Why SHA-256 and not SHA-1
///
/// The draft names SHA-1. This tree has no SHA-1 implementation and adding a
/// broken hash as a dependency to fill 62 bits of a non-security identifier is
/// a worse trade than using the SHA-256 already here. UUIDv8 is the
/// custom-layout version: RFC 9562 constrains only the version and variant
/// bits, both of which are set below, so the value is a well-formed UUIDv8
/// either way. What changes is which bits land in `rand_b`, and nothing reads
/// them.
#[must_use]
pub fn dialog_uuid(dialog: &SipDialog, capture_id: &str) -> String {
    let mut bytes = [0u8; 16];

    // 48-bit big-endian millisecond timestamp. `max(0)` rather than a wrap:
    // a pre-epoch capture timestamp is nonsense, and wrapping it would spread
    // one absurd input across the whole 48-bit space.
    let millis = u64::try_from(dialog.created_at.timestamp_millis().max(0)).unwrap_or(0);
    let ts = millis & 0x0000_FFFF_FFFF_FFFF;
    bytes[..6].copy_from_slice(&ts.to_be_bytes()[2..]);

    // rand_a: 12 bits keyed by the dialog and the capture it came from. The
    // separator keeps `("ab", "c")` and `("a", "bc")` apart, which a bare
    // concatenation would collide.
    let mut seed = Sha256::new();
    seed.update(dialog.call_id.as_bytes());
    seed.update([0x1e]);
    seed.update(capture_id.as_bytes());
    let seed = seed.finalize();
    let rand_a = u16::from_be_bytes([seed[0], seed[1]]) >> 4;
    // Version 8 in the high nibble of octet 6, per RFC 9562 §4.2.
    bytes[6] = 0x80 | u8::try_from(rand_a >> 8).unwrap_or(0);
    bytes[7] = u8::try_from(rand_a & 0xff).unwrap_or(0);

    // rand_b: the HIGH 62 bits of the host digest, shifted down so none of
    // them are overwritten by the variant bits that follow. Masking the top
    // two bits off instead would silently discard the two most significant
    // bits the draft asks for.
    let host = Sha256::digest(node_name().as_bytes());
    let mut top = [0u8; 8];
    top.copy_from_slice(&host[..8]);
    let rand_b = u64::from_be_bytes(top) >> 2;
    // Variant `10` in the two high bits of octet 8, per RFC 9562 §4.1.
    bytes[8..].copy_from_slice(&(0x8000_0000_0000_0000_u64 | rand_b).to_be_bytes());

    format_uuid(&bytes)
}

/// Render 16 bytes in the canonical `8-4-4-4-12` hyphenated hex form.
fn format_uuid(bytes: &[u8; 16]) -> String {
    let hex = |slice: &[u8]| -> String {
        use std::fmt::Write as _;
        slice.iter().fold(String::new(), |mut out, b| {
            // Writing into a String cannot fail; the result is discarded
            // because there is no error to propagate.
            let _ = write!(out, "{b:02x}");
            out
        })
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for the container shape, the two completeness surfaces, the
/// credential filter, and the UUIDv8 derivation.
#[cfg(test)]
mod tests {
    /// A `json`-encoded body, parsed.
    ///
    /// §2.3.2 makes `body` a STRING, so a read goes through here rather than
    /// indexing a `Value` that is not an object. The conserver's own model says
    /// the same in a comment: a caller handing it a dict gets it JSON-encoded
    /// before anything else sees the attachment.
    fn body_of(node: &serde_json::Value) -> serde_json::Value {
        let text = node["body"]
            .as_str()
            .unwrap_or_else(|| panic!("a json body must be a string: {node}"));
        serde_json::from_str(text).unwrap_or_else(|e| panic!("body must parse: {e}: {text}"))
    }

    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use std::net::{IpAddr, Ipv4Addr};

    /// The loopback address every synthetic message is stamped with.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// A fixed capture clock, so a container is comparable across runs.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 8, 24, 12, 0, 0).unwrap()
    }

    /// The moment an export is stamped with, distinct from [`ts`] so a test
    /// can tell the two clocks apart.
    fn exported_at() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 8, 25, 9, 30, 0).unwrap()
    }

    /// Parse one message out of a first line and header list.
    fn message(first_line: &str, headers: &[&str]) -> crate::sip::SipMessage {
        parse_sip(
            &build_sip(first_line, headers, b""),
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("fixture parses")
    }

    /// An INVITE opening a dialog, with display names, Contact and User-Agent.
    fn invite() -> crate::sip::SipMessage {
        message(
            "INVITE sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 INVITE",
                "Contact: <sip:alice@10.0.0.1:5060>",
                "User-Agent: AliceUA/1.0",
                "Content-Length: 0",
            ],
        )
    }

    /// A response to the [`invite`] transaction.
    fn response(code: u16, reason: &str) -> crate::sip::SipMessage {
        message(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>;tag=t2",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 INVITE",
                "Contact: <sip:bob@10.0.0.2:5060>",
                "Server: BobUA/2.0",
                "Content-Length: 0",
            ],
        )
    }

    /// A dialog carrying the opening INVITE and every supplied response.
    fn dialog_with(responses: &[crate::sip::SipMessage]) -> SipDialog {
        let invite = invite();
        // `SipDialog::new` already stores the opening message, so pushing it
        // again would give the trace two INVITEs and quietly shift every
        // later index -- which is exactly how the first draft of
        // `the_trace_carries_every_message_through_the_shared_projection`
        // read a duplicate INVITE where it expected the 180.
        let mut dialog = SipDialog::new(&invite).expect("INVITE opens a dialog");
        for r in responses {
            crate::sip::dialog::update_state(&mut dialog, r);
            dialog.messages.push(r.clone());
        }
        dialog
    }

    /// A capture that read frames and lost nothing.
    fn clean_facts() -> CaptureFacts {
        CaptureFacts {
            frames_read: 120,
            ..CaptureFacts::default()
        }
    }

    /// Export against a supplied set of facts and no capture analysis.
    fn export_with(dialog: &SipDialog, facts: &CaptureFacts) -> Vcon {
        export_dialog_at(
            dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts,
                analysis: None,
            },
            exported_at(),
        )
    }

    /// The container's own fields: version, extensions, and the two things
    /// §4.1.7 and the signing decision say must NOT be there.
    #[test]
    fn the_container_declares_its_version_and_signs_nothing() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");

        assert_eq!(v["vcon"], VCON_SYNTAX_VERSION);
        // Both, and CC is not optional decoration: `Party.role` is a CC
        // parameter, not a core-03 §4.2 one, and the container that uses a
        // field must name the extension that defines it.
        assert_eq!(v["extensions"], serde_json::json!(["sip-signaling", "CC"]));
        assert!(
            v["parties"]
                .as_array()
                .expect("parties is an array")
                .iter()
                .any(|p| p.get("role").is_some()),
            "the CC declaration above is only honest while some party \
             actually carries a `role`: {v}"
        );
        assert!(
            v.get("critical").is_none(),
            "a critical extension refuses the whole container to a generic \
             reader, which nothing here justifies: {v}"
        );

        // `subject` is "the subject or topic of the conversation". Borrowing it
        // for a caveat would put sipnab's words where a reader expects the
        // participants', and it would read as authoritative.
        assert!(
            v.get("subject").is_none(),
            "subject must stay empty; the caveat has its own two surfaces: {v}"
        );

        for banned in [
            "signatures",
            "payload",
            "protected",
            "jwe",
            "jws",
            "consent",
        ] {
            assert!(
                v.get(banned).is_none(),
                "an observer vCon must carry no {banned}: {v}"
            );
        }
    }

    /// `created_at` is the EXPORT clock, not the dialog's.
    ///
    /// The two are different values in this fixture on purpose: a container
    /// that stamped the call's start here would look contemporaneous with
    /// traffic it may describe years later.
    #[test]
    fn created_at_is_the_export_time_and_not_the_dialog_time() {
        let dialog = dialog_with(&[]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");

        assert_eq!(v["created_at"], exported_at().to_rfc3339());
        assert_ne!(
            v["created_at"],
            serde_json::json!(dialog.created_at.to_rfc3339()),
            "created_at took the dialog's clock, so a re-export would claim \
             the conversation happened when the file was written"
        );
    }

    /// Parties come from the observed headers, carry no `name`, and always say
    /// `validation: "none"`.
    #[test]
    fn parties_are_the_observed_headers_and_never_a_verified_name() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");
        let parties = v["parties"].as_array().expect("parties is an array");

        assert_eq!(parties.len(), 3, "two observed parties plus the observer");

        for party in parties {
            assert_eq!(
                party["validation"], "none",
                "sipnab cannot validate a party and must not imply it did: {party}"
            );
            assert!(
                party.get("name").is_none(),
                "a From display name is an unverified claim by the sender; \
                 promoting it to `name` asserts an identity: {party}"
            );
        }

        assert_eq!(parties[0]["sip"], "sip:alice@example.com");
        assert_eq!(parties[0]["sip_display_name"], "Alice");
        assert_eq!(parties[0]["sip_contact"], "<sip:alice@10.0.0.1:5060>");
        assert_eq!(parties[0]["sip_user_agent"], "AliceUA/1.0");

        assert_eq!(parties[1]["sip"], "sip:bob@example.net");
        assert_eq!(parties[1]["sip_display_name"], "Bob");
        // The callee's headers arrive on its own response, not on the INVITE.
        assert_eq!(parties[1]["sip_contact"], "<sip:bob@10.0.0.2:5060>");
        assert_eq!(parties[1]["sip_user_agent"], "BobUA/2.0");
    }

    /// The final party is sipnab, and it is unmistakably an observer.
    #[test]
    fn the_last_party_is_the_sipnab_observer() {
        let dialog = dialog_with(&[]);
        let vcon = export_with(&dialog, &clean_facts());
        let observer = vcon.observer_index();
        assert_eq!(observer, vcon.parties.len() - 1);

        let v = serde_json::to_value(&vcon).expect("serializes");
        let party = &v["parties"][observer];
        assert_eq!(party["role"], OBSERVER_ROLE);
        assert!(
            party.get("sip").is_none(),
            "sipnab sent no SIP; a URI here would be a participant that never \
             existed: {party}"
        );
        let ua = party["sip_user_agent"].as_str().expect("names itself");
        assert!(
            ua.contains(env!("CARGO_PKG_VERSION")) && ua.contains(node_name()),
            "the observer must name the build and the box that produced this \
             container, or an attachment's provenance resolves to nothing: {ua}"
        );
    }

    /// A dialog sipnab saw succeed carries an EMPTY Dialog Object.
    ///
    /// The anti-vacuity half matters more than the shape: `incomplete` must
    /// not appear merely because a signaling-only export has no media.
    #[test]
    fn a_signaling_only_dialog_object_describes_no_media_and_claims_no_recording() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");
        let object = &v["dialog"][0];

        assert_eq!(object["sip_call_id"], "vcon-fixture@example.com");
        assert_ne!(
            object["type"], RECORDING_TYPE,
            "this object carries no audio, and `recording` is the one value \
             that promises a consumer content it can reach: {object}"
        );
        assert_eq!(
            object["type"], INCOMPLETE_TYPE,
            "of the five values §4.3.1 allows, only `incomplete` claims no \
             content: {object}"
        );
        assert!(
            object.get("disposition").is_none(),
            "the call was answered, so no failure reason exists to name: \
             {object}"
        );
        for invented in ["mediatype", "url", "body", "filename"] {
            assert!(
                object.get(invented).is_none(),
                "a signaling-only export has no media and must not describe \
                 any: {object} carries {invented}"
            );
        }
    }

    /// A dialog with no final response at all is STILL not `incomplete`.
    ///
    /// This is the case the whole rule exists for. sipnab not seeing the
    /// answer is a fact about the capture; reporting it as `incomplete` would
    /// make it a fact about the call.
    #[test]
    fn an_unanswered_dialog_is_not_reported_as_a_failed_call() {
        let dialog = dialog_with(&[response(100, "Trying")]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");
        // `type` is `incomplete` on every signaling-only object, so it carries
        // no claim about the CALL either way. `disposition` is where a claim
        // about the outcome would live, and this is the case that must not
        // make one.
        assert!(
            v["dialog"][0].get("disposition").is_none(),
            "no final response was observed, so nothing is known about the \
             outcome; naming a disposition would invent one: {}",
            v["dialog"][0]
        );
    }

    /// An observed final failure DOES set a disposition, and the mapping is
    /// the one the outcome deserves.
    #[test]
    fn an_observed_final_failure_maps_to_a_disposition() {
        for (code, expected) in [
            (486u16, "busy"),
            (600, "busy"),
            (503, "congestion"),
            (408, "no-answer"),
            (480, "no-answer"),
            (403, "failed"),
            (500, "failed"),
        ] {
            let dialog = dialog_with(&[response(code, "Fixture")]);
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");
            assert_eq!(
                v["dialog"][0]["type"], "incomplete",
                "{code} did not mark the dialog"
            );
            assert_eq!(
                v["dialog"][0]["disposition"], expected,
                "{code} mapped to the wrong disposition"
            );
        }

        // A redirect is not a failure. Left in the same test as the mapping so
        // widening the range to `300..=699` fails here rather than shipping.
        let redirected = dialog_with(&[response(302, "Moved Temporarily")]);
        let v = serde_json::to_value(export_with(&redirected, &clean_facts())).expect("serializes");
        assert!(
            v["dialog"][0].get("disposition").is_none(),
            "a 3xx redirect did not fail: {}",
            v["dialog"][0]
        );
    }

    /// Every attachment names the observer as its party.
    #[test]
    fn every_attachment_carries_the_observer_as_its_party() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let vcon = export_with(&dialog, &clean_facts());
        let observer = vcon.observer_index();
        let v = serde_json::to_value(&vcon).expect("serializes");

        let attachments = v["attachments"].as_array().expect("attachments");
        assert_eq!(attachments.len(), 2, "the trace and the caveat");
        for attachment in attachments {
            assert_eq!(
                attachment["party"], observer,
                "§4.4 makes `party` mandatory so an attachment has provenance; \
                 without it a reader attributes it to a participant: {attachment}"
            );
            assert_eq!(attachment["mediatype"], "application/json");
        }
        assert_eq!(attachments[0]["purpose"], MESSAGE_TRACE_PURPOSE);
        assert_eq!(attachments[1]["purpose"], COMPLETENESS_PURPOSE);
    }

    /// The trace carries one entry per message, through the same projection
    /// `--json` writes.
    #[test]
    fn the_trace_carries_every_message_through_the_shared_projection() {
        let dialog = dialog_with(&[response(180, "Ringing"), response(200, "OK")]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");
        let trace = body_of(&v["attachments"][0]);
        let messages = trace["messages"].as_array().expect("messages");

        assert_eq!(messages.len(), dialog.messages.len());
        assert_eq!(messages[0]["method"], "INVITE");
        assert_eq!(messages[1]["status_code"], 180);
        assert_eq!(messages[2]["status_code"], 200);
        for message in messages {
            assert_eq!(
                message["schema_version"], DIAGNOSIS_SCHEMA_VERSION,
                "the trace must be the projection --json already writes"
            );
        }
    }

    /// No credential reaches the container, end to end.
    ///
    /// The projection this trace is built from carries no raw header map
    /// today, so this passes on the strength of that projection rather than of
    /// the filter. It is written as a REGRESSION gate: the day
    /// `message_to_json_value` gains a `headers` field, this is what refuses
    /// the digest response before it is handed to somebody else.
    /// `the_credential_filter_removes_banned_headers_at_every_depth` is the
    /// half that discriminates today.
    #[test]
    fn no_credential_survives_an_export() {
        let challenged = message(
            "REGISTER sip:example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 2 REGISTER",
                "Authorization: Digest username=\"alice\", realm=\"example.com\", \
                 nonce=\"NONCEVALUE1\", response=\"SECRETRESPONSE1\"",
                "Proxy-Authorization: Digest nonce=\"NONCEVALUE2\", \
                 response=\"SECRETRESPONSE2\"",
                "Content-Length: 0",
            ],
        );
        let challenge = message(
            "SIP/2.0 401 Unauthorized",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>;tag=t2",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 2 REGISTER",
                "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"NONCEVALUE3\"",
                "Content-Length: 0",
            ],
        );
        let mut dialog = SipDialog::new(&challenged).expect("REGISTER opens a dialog");
        dialog.messages.push(challenge);

        let json = export_with(&dialog, &clean_facts())
            .to_json()
            .expect("serializes");

        for secret in [
            "SECRETRESPONSE1",
            "SECRETRESPONSE2",
            "NONCEVALUE1",
            "NONCEVALUE2",
            "NONCEVALUE3",
        ] {
            assert!(
                !json.contains(secret),
                "a digest credential reached a container built to be handed to \
                 somebody else: {secret} is in the export"
            );
        }
        for header in CREDENTIAL_HEADERS {
            assert!(
                !json.to_ascii_lowercase().contains(header),
                "{header} must never appear in an exported vCon"
            );
        }
    }

    /// The filter itself: banned keys go, at every depth and in any case, and
    /// everything else stays.
    ///
    /// Mutation-proven — deleting the `retain` in [`strip_credentials`] fails
    /// this test. It is written against a hand-built value rather than an
    /// exported one because the projection upstream carries no header map, so
    /// an end-to-end test cannot reach the filter.
    #[test]
    fn the_credential_filter_removes_banned_headers_at_every_depth() {
        let mut value = serde_json::json!({
            "Authorization": "Digest response=\"SECRET\"",
            "call_id": "keep-me",
            "messages": [
                {
                    "WWW-Authenticate": "Digest nonce=\"SECRET\"",
                    "method": "REGISTER",
                    "nested": { "PROXY-AUTHORIZATION": "Digest response=\"SECRET\"" }
                }
            ]
        });
        strip_credentials(&mut value);

        let text = serde_json::to_string(&value).expect("serializes");
        assert!(
            !text.contains("SECRET"),
            "a credential survived the filter: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("auth"),
            "a banned header name survived the filter: {text}"
        );

        // Anti-vacuity: a filter that emptied the object would also pass the
        // assertions above.
        assert_eq!(value["call_id"], "keep-me");
        assert_eq!(value["messages"][0]["method"], "REGISTER");
        assert!(
            value["messages"][0]["nested"].is_object(),
            "the filter removed a whole subtree instead of one key: {value}"
        );
    }

    /// The report names sipnab as an observer and carries the existing schema.
    #[test]
    fn the_report_names_the_tool_as_an_observer() {
        let dialog = dialog_with(&[response(486, "Busy Here")]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");
        let analysis = &v["analysis"][0];

        assert_eq!(analysis["type"], "report");
        assert_eq!(analysis["vendor"], ANALYSIS_VENDOR);
        assert_eq!(analysis["schema"], ANALYSIS_SCHEMA);
        assert_eq!(analysis["dialog"], 0);
        let product = analysis["product"].as_str().expect("a product string");
        assert!(
            product.contains("observer"),
            "an analysis attached to a conversation reads as coming from a \
             participant unless the product says otherwise: {product}"
        );
        assert_eq!(body_of(analysis)["final_status_code"], 486);
        assert!(
            body_of(analysis)["signaling_diagnosis"].is_object(),
            "a 486 is a final failure the signaling diagnosis already \
             detects; the report must reuse it: {analysis}"
        );
    }

    /// The `schema` string names the version the JSON surface actually stamps.
    ///
    /// Two literals in two modules describing one contract. Held together
    /// here, because a `schema` naming version 1 over bodies carrying version
    /// 2 sends a consumer to the wrong parser with no way to notice.
    #[test]
    fn the_analysis_schema_names_the_version_the_json_surface_emits() {
        let emitted = crate::output::json::message_to_json_value(&invite());
        assert_eq!(
            emitted["schema_version"], DIAGNOSIS_SCHEMA_VERSION,
            "the vCon schema string and the JSON surface disagree about the \
             body version"
        );
        assert!(
            ANALYSIS_SCHEMA.ends_with(&format!("/{DIAGNOSIS_SCHEMA_VERSION}")),
            "{ANALYSIS_SCHEMA} does not name version {DIAGNOSIS_SCHEMA_VERSION}"
        );
    }

    /// **The test that justifies the feature.** Two runs whose completeness
    /// carriers must differ: one where compaction evicted messages, one where
    /// nothing was lost.
    ///
    /// If those two strings collapse into one, the carrier is decoration — a
    /// consumer reading it learns nothing about whether this container is the
    /// whole conversation, which is the only reason it exists.
    ///
    /// Mutation-proven: deleting the `messages_evicted` clause in
    /// [`completeness_note`] collapses the two and fails here.
    #[test]
    fn the_completeness_carrier_discriminates_a_lossy_run_from_a_clean_one() {
        let dialog = dialog_with(&[response(200, "OK")]);

        let clean = clean_facts();
        let mut lossy = clean_facts();
        lossy.retention.messages_evicted = 7;

        let clean_vcon = serde_json::to_value(export_with(&dialog, &clean)).expect("serializes");
        let lossy_vcon = serde_json::to_value(export_with(&dialog, &lossy)).expect("serializes");

        let note = |v: &serde_json::Value| -> String {
            body_of(&v["attachments"][1])["note"]
                .as_str()
                .expect("the caveat is a string")
                .to_string()
        };
        let clean_note = note(&clean_vcon);
        let lossy_note = note(&lossy_vcon);

        assert_ne!(
            clean_note, lossy_note,
            "a run that lost 7 captured messages produced the same caveat as \
             a run that lost none, so the caveat says nothing"
        );
        assert!(
            lossy_note.contains("INCOMPLETE") && lossy_note.contains('7'),
            "the lossy caveat must name both the loss and its size: {lossy_note}"
        );
        assert!(
            !clean_note.contains("INCOMPLETE"),
            "a run that lost nothing must not warn about a loss: {clean_note}"
        );

        // The STRUCTURED half has to discriminate too — a consumer that reads
        // fields rather than prose must reach the same verdict.
        assert_eq!(
            body_of(&lossy_vcon["attachments"][1])["messages_evicted"],
            7
        );
        assert_eq!(
            body_of(&clean_vcon["attachments"][1])["messages_evicted"],
            0
        );
    }

    /// Both surfaces carry the SAME caveat, byte for byte.
    ///
    /// One value embedded twice, never two strings built twice. A container
    /// whose report and whose attachment disagreed about what was missed would
    /// be worse than one carrying no caveat at all: it would look
    /// authoritative while contradicting itself.
    #[test]
    fn the_two_completeness_surfaces_carry_one_value() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let mut facts = clean_facts();
        facts.retention.messages_evicted = 3;
        facts.undecodable.frames = 11;

        let v = serde_json::to_value(export_with(&dialog, &facts)).expect("serializes");
        let from_attachment = body_of(&v["attachments"][1]);
        let report = body_of(&v["analysis"][0]);
        let from_report = &report["capture_completeness"];

        assert_eq!(
            &from_attachment, from_report,
            "the report and the attachment describe one capture and must say \
             one thing about it"
        );
        assert!(
            from_attachment["note"]
                .as_str()
                .is_some_and(|n| n.contains("11") && n.contains('3')),
            "the shared caveat lost one of the two losses it was built from: {from_attachment}"
        );
    }

    /// "Nobody looked" and "looked and found nothing" are different answers.
    ///
    /// Collapsing them lets an export that skipped the capture analysis read
    /// as a clean one, which is the same defect `--analyze` refuses when it
    /// derives `complete` from the finding list rather than tracking a flag.
    #[test]
    fn an_absent_analysis_is_not_a_clean_bill() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let facts = clean_facts();

        let unchecked = export_with(&dialog, &facts);
        let checked = export_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &facts,
                analysis: Some(&CaptureAnalysis::default()),
            },
            exported_at(),
        );

        let note = |v: &Vcon| -> String {
            body_of(&serde_json::to_value(v).expect("serializes")["attachments"][1])["note"]
                .as_str()
                .expect("a caveat")
                .to_string()
        };
        assert_ne!(
            note(&unchecked),
            note(&checked),
            "an export with no capture analysis said the same thing as one \
             whose analysis found nothing"
        );

        let unchecked_body =
            body_of(&serde_json::to_value(&unchecked).expect("serializes")["attachments"][1]);
        assert!(
            unchecked_body.get("blind_spots").is_none(),
            "no analysis was supplied, so an empty list would claim one ran: \
             {unchecked_body}"
        );
        let checked_body =
            body_of(&serde_json::to_value(&checked).expect("serializes")["attachments"][1]);
        assert_eq!(
            checked_body["blind_spots"],
            serde_json::json!([]),
            "an analysis that ranked nothing must say so with an empty list, \
             not by omitting the field: {checked_body}"
        );
    }

    /// A ranked blind spot reaches both the prose and the structured list.
    #[test]
    fn a_ranked_blind_spot_reaches_the_carrier() {
        use crate::analysis::{Finding, FindingKind};

        let dialog = dialog_with(&[response(200, "OK")]);
        let facts = clean_facts();
        let analysis = CaptureAnalysis {
            frames_read: 120,
            findings: vec![Finding {
                kind: FindingKind::UndecodableFrames,
                severity: Severity::Blind,
                occurrences: 49,
                unit: FindingKind::UndecodableFrames.meta().unit,
                evidence: Vec::new(),
                evidence_omitted: 0,
            }],
            ..CaptureAnalysis::default()
        };

        let v = serde_json::to_value(export_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &facts,
                analysis: Some(&analysis),
            },
            exported_at(),
        ))
        .expect("serializes");

        let body = body_of(&v["attachments"][1]);
        assert_eq!(body["blind_spots"][0]["occurrences"], 49);
        assert_eq!(
            body["blind_spots"][0]["kind"],
            FindingKind::UndecodableFrames.meta().id
        );
        let note = body["note"].as_str().expect("a caveat");
        assert!(
            note.contains("INCOMPLETE") && note.contains("49"),
            "a ranked blind spot must reach the prose surface too: {note}"
        );
    }

    /// The uuid is a well-formed UUIDv8 and is stable for one dialog out of
    /// one capture.
    #[test]
    fn the_uuid_is_a_stable_uuid_v8() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let id = dialog_uuid(&dialog, "fixture.pcap");

        assert_eq!(id.len(), 36, "canonical 8-4-4-4-12 form: {id}");
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "{id} is not 8-4-4-4-12"
        );
        assert!(
            id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
            "{id} carries a non-hex character"
        );
        assert_eq!(
            groups[2].as_bytes()[0],
            b'8',
            "RFC 9562 puts the version in the first nibble of the third group; \
             {id} does not say 8"
        );
        assert!(
            matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'),
            "RFC 9562 variant `10` means the fourth group starts 8, 9, a or b; \
             {id} does not"
        );

        assert_eq!(
            id,
            dialog_uuid(&dialog, "fixture.pcap"),
            "re-exporting one dialog from one capture must not mint a second \
             identifier, or a consumer deduplicating on uuid accumulates \
             copies of one conversation"
        );
    }

    /// The uuid separates dialogs, separates captures, and follows the
    /// dialog's clock rather than the export's.
    #[test]
    fn the_uuid_separates_dialogs_captures_and_clocks() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let base = dialog_uuid(&dialog, "fixture.pcap");

        let mut other_capture = dialog_with(&[response(200, "OK")]);
        assert_ne!(
            base,
            dialog_uuid(&other_capture, "other.pcap"),
            "one dialog re-observed in a different capture must not reuse the \
             identifier of the first"
        );

        other_capture.call_id = "a-different-call@example.com".to_string();
        assert_ne!(
            base,
            dialog_uuid(&other_capture, "fixture.pcap"),
            "two dialogs in one capture must not share an identifier"
        );

        // The timestamp half: same Call-ID, same capture, different dialog
        // clock. Without it the 48-bit prefix would be dead weight.
        let mut later = dialog_with(&[response(200, "OK")]);
        later.created_at = ts() + chrono::TimeDelta::seconds(90);
        assert_ne!(
            base,
            dialog_uuid(&later, "fixture.pcap"),
            "the embedded timestamp is not tracking the dialog clock"
        );

        // Two exports of one dialog at different EXPORT times still agree, so
        // idempotency does not depend on when the file was written.
        let first = export_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &clean_facts(),
                analysis: None,
            },
            exported_at(),
        );
        let second = export_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &clean_facts(),
                analysis: None,
            },
            exported_at() + chrono::TimeDelta::days(400),
        );
        assert_eq!(first.uuid, second.uuid);
        assert_ne!(
            first.created_at, second.created_at,
            "the export clock must still move, or this proves nothing"
        );
    }

    /// A dialog whose headers named no host gets no URI rather than a
    /// fabricated one.
    #[test]
    fn a_party_with_no_observed_host_carries_no_uri() {
        assert_eq!(sip_uri(Some("alice"), None), None);
        assert_eq!(
            sip_uri(Some("alice"), Some("example.com")).as_deref(),
            Some("sip:alice@example.com")
        );
        assert_eq!(
            sip_uri(None, Some("example.com")).as_deref(),
            Some("sip:example.com"),
            "a host with no user is still a routable URI and is kept"
        );
    }

    /// The whole container round-trips through `serde_json` as an object.
    #[test]
    fn the_container_serializes_to_parseable_json() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let json = export_with(&dialog, &clean_facts())
            .to_json()
            .expect("serializes");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed.is_object());
        assert_eq!(parsed["analysis"].as_array().map(Vec::len), Some(1));
    }
}
