// SPDX-License-Identifier: MIT OR Apache-2.0

//! vCon export — one observed dialog as an unsigned observer vCon container
//! ([`draft-ietf-vcon-vcon-core-04`], syntax version `0.4.0`).
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
//!   absent one is the truth. A lawful-basis attachment appears only when an
//!   enrichment service with `lawful_basis = true` supplies one, and the
//!   `sipnab-enrichment` attachment names that service as its source
//!   (`crate::app::vcon_enrich`).
//! * **No [`Party`] name that sipnab vouches for.** [`Party::name`] carries the
//!   `From`/`To` display name when the wire had one, and that name is an
//!   unverified assertion by whoever sent the request, which is why every
//!   party emits `validation: "none"` beside it.
//! * **No `url` by-reference that sipnab vouches for.**
//!   [Section 2.4.1 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.4.1)
//!   requires HTTPS, and sipnab hosts nothing. The one `url` a container
//!   carries is a recording a rule with `audio = "url"` wrote beside it, named
//!   under the `audio_url_base` the operator's storage serves, with the WAV
//!   file's `content_hash`; sipnab does not check that the URL serves it.
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
//! [`draft-ietf-vcon-vcon-core-04`]: https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/

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
/// `role` is NOT one of the thirteen Party parameters [core-04 section 4.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.2)
/// defines — the working group's own schema lists `tel`, `sip`, `stir`,
/// `mailto`, `name`, `did`, `validation`, `gmlpos`, `civicaddress`, `uuid`,
/// `type`, `org` and `dept`, and no `role`. `draft-ietf-vcon-cc-extension`
/// defines it and says the `CC` token "SHOULD be included in the extensions
/// array".
///
/// This matters more here than the SHOULD suggests. `role: "observer"` is the
/// single most load-bearing fact in the container — it is how a consumer knows
/// sipnab was not a party to the call — and declaring nothing left it riding
/// in a field the container never admitted to using. The extension's own
/// values are agent/customer/supervisor/sme/thirdparty, and it permits others:
/// "Other values for the role parameter MAY also be used."
pub const CC_EXTENSION: &str = "CC";

/// Every extension sipnab's containers declare, which are the extensions
/// sipnab supports when it reads a container.
///
/// One list for both sides: the writer declares these in `extensions`, and a
/// reader refuses a container whose `critical` names anything else
/// ([`crate::capture::vcon_input::unsupported_critical`]).
pub const DECLARED_EXTENSIONS: [&str; 2] = [SIP_SIGNALING_EXTENSION, CC_EXTENSION];

/// `purpose` of the attachment carrying the per-message signaling trace.
pub const MESSAGE_TRACE_PURPOSE: &str = "sip-message-trace";

/// `purpose` of the attachment carrying the completeness caveat.
///
/// Vendor-prefixed because it is sipnab's own, not a registered vCon purpose:
/// a consumer that does not know it skips it, and one that does knows exactly
/// whose claim it is reading.
pub const COMPLETENESS_PURPOSE: &str = "sipnab-capture-completeness";

/// `purpose` of the attachment naming the containers of this call's other
/// legs.
///
/// A call through a B2BUA or a PBX is two dialogs and so two containers.
/// core-04 has no member that groups containers, so the link is an attachment,
/// vendor-prefixed for the reason [`COMPLETENESS_PURPOSE`] is.
pub const RELATED_LEGS_PURPOSE: &str = "sipnab-related-legs";

/// Another leg of the same call, as the related-legs attachment names it.
///
/// The leg is named by its container's uuid and not by its Call-ID: the uuid
/// is what a reader looks a container up by, and it stays the same under
/// redaction, where the Call-ID does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelatedLeg {
    /// The other leg's container uuid, as [`dialog_uuid`] derives it.
    pub uuid: String,
    /// Which correlation strategy tied the two legs, in the vocabulary
    /// `find_correlated` and `get_call_tree` report.
    pub strategy: &'static str,
    /// Whether the tie compared an identifier both legs carry. `false` is a
    /// timing guess, which a busy server can get wrong.
    pub identifier_match: bool,
    /// Confidence of the tie, 0 to 100.
    pub score: u8,
}

/// The legs `store` ties to `dialog`, strongest first, each named by the uuid
/// its own container carries.
///
/// One entry per other leg: `find_correlated_scored` reports each candidate
/// once, under the first strategy that matched it, and never the dialog
/// itself. Equal scores fall back to Call-ID order, so a container is the same
/// bytes from one export to the next.
#[must_use]
pub fn related_legs(
    store: &crate::sip::dialog_store::DialogStore,
    dialog: &SipDialog,
) -> Vec<RelatedLeg> {
    let mut found = store.find_correlated_scored(&dialog.call_id);
    found.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.dialog.call_id.cmp(&b.dialog.call_id))
    });
    found
        .into_iter()
        .map(|r| {
            let (strategy, identifier_match) = r.reason.strategy();
            RelatedLeg {
                uuid: dialog_uuid(r.dialog, dialog_capture_id(r.dialog)),
                strategy,
                identifier_match,
                score: r.score,
            }
        })
        .collect()
}

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
/// **MEASURED, not chosen.** [Section 4a.1 of `docs/design/vcon.md`](https://github.com/NormB/sipnab/blob/main/docs/design/vcon.md#4a1-a-204-does-not-mean-the-container-was-stored) records
/// a probe of a running vCon store on 2026-08-24. A container carrying roughly
/// 12 MB of inline base64 came back **HTTP 204**, landed in Postgres, and was
/// refused by the file spool with `16777749 > 10485760` — and neither transport
/// reported the partial write, so the producer was told "accepted" while a
/// backend dropped the payload. The same probe watched roughly 1 MB and roughly
/// 5 MB land in EVERY backend.
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
/// dropping the audio would be the failure the whole module is built against,
/// the one [section 3 of `docs/design/vcon.md`](https://github.com/NormB/sipnab/blob/main/docs/design/vcon.md#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record) describes: absence reading
/// as "this call had no media".
pub const MAX_INLINE_MEDIA_BYTES: usize = 5 * 1024 * 1024;

/// `dialog.type` of an observed transfer, one of the five values
/// [core-04 section 4.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1) defines.
pub const TRANSFER_TYPE: &str = "transfer";

/// `redacted.type` sipnab writes when a deny header suppressed a dialog.
///
/// The `redacted` object of [core-04 section 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8) normally REFERENCES a
/// less-redacted instance by `uuid` or `url`. Here there is nothing to
/// reference: sipnab never wrote an unredacted container, so the object carries
/// `type` alone. That is the format's way of saying content was withheld and no
/// fuller version of it exists anywhere to ask for.
pub const CONTENT_WITHHELD: &str = "content-withheld";

/// `redacted.type` sipnab writes when a container went through keyed
/// pseudonymization.
///
/// Beside [`CONTENT_WITHHELD`] and in the same `redacted` slot of
/// [core-04 section 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8) deliberately. The two are the same family of
/// statement — "sipnab removed something on purpose" — and giving
/// pseudonymization its own invented mechanism would leave a consumer two
/// places to look for one fact. It carries `type` alone, for the reason
/// [`CONTENT_WITHHELD`] does: there is no less-redacted instance to reference,
/// because sipnab never wrote one.
pub const CONTENT_PSEUDONYMIZED: &str = "pseudonymized";

/// `mediatype` of the media sipnab inlines. RIFF/WAVE, 16-bit linear PCM.
pub const RECORDING_MEDIATYPE: &str = "audio/x-wav";

/// `mediatype` of a recording in Ogg Opus, a rule's `audio_format = "opus"`
/// ([`crate::app::batch::RuleAudioFormat`]).
///
/// One of the media types [core-04 section 4.3.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.8)
/// says a Dialog Object SHOULD use. No `codecs` parameter: core-04 section
/// 2.2 defines "Mediatype" as `type "/" subtype` alone.
pub const OGG_OPUS_MEDIATYPE: &str = "audio/ogg";

/// `dialog.type` of the object carrying the media itself — the FILE's clock.
pub const RECORDING_TYPE: &str = "recording";

/// `dialog.type` of the wrapper carrying the CALL's clock.
///
/// [Section 4.3.3 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3) is the one place the format can say
/// "the file is shorter than the call": the set carries the call's `start` and
/// `duration` while the [`RECORDING_TYPE`] object beneath it carries the
/// file's. Emitted ONLY when a payload ring actually wrapped — a wrapper on
/// every container would train readers to skip the one that means something.
pub const RECORDING_SET_TYPE: &str = "recording-set";

/// `type` for a Dialog Object that carries no content of its own.
///
/// [Section 4.3 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) calls it "Metadata for failed or
/// incompleted communications", and a signaling-only export is exactly an
/// incompleted RECORD of the communication. The prose caveat says which of the
/// two it is, in words, on two surfaces a consumer walks past anyway — the enum
/// cannot.
pub const INCOMPLETE_TYPE: &str = "incomplete";

/// `type` of a Dialog Object holding text one party sent,
/// [core-04 section 4.3.1.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.3).
pub const TEXT_TYPE: &str = "text";

/// Hash algorithm prefix of [`Dialog::content_hash`], per
/// [section 2.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.2).
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
/// wire ([RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1)), so a filter keyed on exact case is a filter an
/// ordinary peer walks through.
pub const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
];

/// One party to the conversation, or the observer that watched it.
///
/// sipnab knows what the `From` and `To` headers said, which is what the
/// sender chose to write in them. [`Self::name`] carries that display name,
/// and [`Self::validation`] is always `"none"`, so the container never
/// presents the name as an identity somebody established.
#[derive(Debug, Clone, Serialize)]
pub struct Party {
    /// The party's SIP URI, rebuilt from the observed `From`/`To` user and
    /// host. Absent on the observer, which sent no SIP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip: Option<String>,
    /// RFC 3966 `tel:` URI, when the SIP user part is a global number.
    ///
    /// A [core-04 section 4.2.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.2.1) Party parameter, and one of the three the
    /// conserver indexes on. It is absent far more often than it is present:
    /// only an RFC 3966 global number qualifies, so a SIP extension yields
    /// nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tel: Option<String>,
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
    /// `name` ([core-04 section 4.2.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.2.5)) — the display name the wire carried.
    ///
    /// It travels under the declared key so a consumer reads it at all: a
    /// container whose only name is under `sip_display_name` is one where
    /// every generic reader shows an unnamed party. What keeps that honest is
    /// [`Self::validation`], which is unconditionally `"none"` — this is a
    /// name a header asserted, not a person sipnab identified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `stir` ([core-04 section 4.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.2.3)) — an observed RFC 8224 PASSporT,
    /// copied verbatim.
    ///
    /// The JWS ALONE. An `Identity` header carries the token followed by
    /// `info`, `alg` and `ppt` parameters, and a consumer handed the whole
    /// header value as a token cannot parse it.
    ///
    /// Transcribed, never asserted: sipnab fetches no certificate and checks
    /// no signature, so this is evidence a consumer may verify rather than a
    /// verdict sipnab reached. [`Self::validation`] stays `"none"` beside it,
    /// and that pairing is what makes carrying the token legitimate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stir: Option<String>,
    /// Display name from the observed `From`/`To` header, verbatim.
    ///
    /// Kept beside [`Self::name`] rather than replaced by it: the
    /// SIP-specific key says "this is what the header said", which the
    /// generic key cannot, and a reader joining containers across sources
    /// needs to know which of them a name came off the wire in.
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

/// `amended` ([core-04 section 4.1.9](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9)) — the instance this
/// one replaces.
///
/// A sealed container cannot be changed: "A signed or encrypted vCon cannot
/// be modified without invalidating it. In these cases, to allow for adding of
/// additional information a new vCon instance version MUST be created." A
/// sealing rule with `sealed_updates = "new-uuid"` therefore writes each later
/// version of a call as a new instance carrying this object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Amended {
    /// The uuid of the prior instance.
    ///
    /// [Section 4.1.9 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9):
    /// "The prior vCon instance version SHOULD be referenced via the uuid of
    /// the prior vCon instance version". The `url` and `content_hash` the
    /// draft also allows are never set: sipnab knows no URL that serves the
    /// prior instance.
    pub uuid: String,
}

/// One Party_History Object of [core-04 section 4.3.13.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.13.1).
///
/// Shaped as one event, with who, when and what, so it maps one-to-one onto
/// an entry of a later `events[]` array.
#[derive(Debug, Clone, Serialize)]
pub struct PartyEvent {
    /// Index into [`Vcon::parties`] of the party the event is about.
    pub party: usize,
    /// When the capture shows it, RFC 3339.
    pub time: String,
    /// One of `join`, `drop`, `hold`, `unhold`, `keydown`, `keyup`. sipnab
    /// writes no `mute` or `unmute`: SIP carries no signal for either.
    pub event: &'static str,
    /// The DTMF digit, on `keydown` and `keyup` only, where section 4.3.13.1
    /// requires it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button: Option<String>,
}

impl PartyEvent {
    /// An event with no `button`.
    fn at(party: usize, time: DateTime<Utc>, event: &'static str) -> Self {
        Self {
            party,
            time: time.to_rfc3339(),
            event,
            button: None,
        }
    }
}

/// `redacted` ([core-04 section 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8)) — content was withheld from this
/// container.
///
/// Only [`Self::kind`] is ever set. The schema also defines `uuid`, `url` and
/// `content_hash`, all of which point at a less-redacted instance, and sipnab
/// has none to point at: the deny header fires before any container is built,
/// so an unredacted original never existed. Emitting a `url` here would offer
/// the withheld content for retrieval, which is the opposite of withholding
/// it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Redacted {
    /// The redaction performed. Always [`CONTENT_WITHHELD`].
    #[serde(rename = "type")]
    pub kind: &'static str,
}

/// `session_id` ([core-04 section 4.3.12](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.12)) — the two halves of an RFC 7989
/// Session-ID.
///
/// Both halves are optional in the schema and both are optional here for the
/// same reason: a first INVITE carries only the local half, and the remote
/// half appears once the far side answers. Emitting an invented `remote` would
/// claim a correlation that has not happened yet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionIdPair {
    /// The UUID this side contributed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    /// The UUID the far side contributed, echoed back as `remote=`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

/// The Dialog Object — deliberately almost empty.
///
/// [Section 4.3 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) provides for this: "There
/// are situations when little or no information is available for a dialog …
/// and yet it is known that the dialog occurred", and the object for it is a
/// placeholder "which contains only the type parameter". A signaling-only
/// export is exactly that situation. The alternative — inventing a
/// `mediatype`, a `body` or a `url` so the object looks complete — would
/// describe media that does not exist.
#[derive(Debug, Clone, Serialize)]
pub struct Dialog {
    /// Always present: [core-04 section 4.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1) makes `type`
    /// mandatory on every Dialog Object.
    ///
    /// `"incomplete"` ONLY when a final failure response was observed;
    /// [`RECORDING_TYPE`] otherwise, as the placeholder of core-04 section 4.3
    /// or on the media objects; [`RECORDING_SET_TYPE`] or [`TRANSFER_TYPE`]
    /// on the objects of those kinds.
    ///
    /// `"incomplete"` is never set because sipnab failed to capture the
    /// answer. It is a statement about the CALL; "we did not see the rest" is
    /// a statement about the CAPTURE, and the second one travels in
    /// [`CaptureCompleteness`] where it cannot be mistaken for the first.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// `session_id` ([core-04 section 4.3.12](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.12)) — the RFC 7989 pair, when the
    /// header was observed.
    ///
    /// The draft's own leg-correlation mechanism, and the one identifier that
    /// survives a B2BUA where `Call-ID` does not: each side contributes a
    /// half, and the far side's half comes back as `remote`. sipnab
    /// approximates leg correlation with `sip_from_tag`/`sip_to_tag`, which no
    /// consumer knows how to join on; this is the field that already means
    /// this.
    ///
    /// NOT the SIPREC session id in [`crate::sip::siprec`], which is a
    /// different identifier with the same name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionIdPair>,
    /// `transferor` ([core-04 section 4.3.14](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.14)) — party index of whoever sent
    /// the REFER.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transferor: Option<usize>,
    /// `transferee` ([core-04 section 4.3.14](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.14)) — party index of the party
    /// being moved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transferee: Option<usize>,
    /// `transfer_target` ([core-04 section 4.3.14](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.14)) — party index the
    /// `Refer-To` named.
    ///
    /// Absent when the `Refer-To` URI could not be parsed into a party: the
    /// member is an INDEX, so it can only be emitted once the party it points
    /// at exists in the array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_target: Option<usize>,
    /// `original` ([core-04 section 4.3.14](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.14)) — dialog index the transfer
    /// happened in. Always 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<usize>,
    /// `consultation` ([core-04 section 4.3.14](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.14)) — dialog index of the
    /// consultative call.
    ///
    /// Present ONLY for an attended transfer, which a `Replaces` parameter in
    /// the `Refer-To` URI is what identifies. Its absence is the format's way
    /// of saying the transfer was blind, so emitting it unconditionally would
    /// claim a consultation for transfers that had none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consultation: Option<usize>,
    /// Why the call did not complete, mapped from the observed final status.
    ///
    /// Present exactly when [`Self::kind`] is `"incomplete"`, and on no other
    /// object: a `recording` has no disposition, because nothing about it says
    /// anything about how the call ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<&'static str>,
    /// The `Call-ID` this dialog was tracked under — the one identifier that
    /// ties the container back to a capture an operator still holds.
    ///
    /// Skipped when EMPTY, which is not a defaulted value but the one case
    /// that has no Call-ID to give: the placeholder of
    /// [core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) for a consultative call this leg
    /// never saw, which "contains only the type parameter". Every other
    /// object sets it, and the placeholder constructor is the only one that
    /// leaves it blank.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sip_call_id: String,
    /// The dialog's `From` tag, when the capture observed one.
    ///
    /// With the `To` tag below this is what distinguishes one leg of a forked
    /// INVITE from another. A Call-ID alone does not: every fork shares it, so
    /// a consumer correlating legs across nodes cannot tell them apart. Both
    /// are parameters the `sip-signaling` extension defines, and sipnab has
    /// held them all along: message attribution already reads them to decide
    /// which party sent each message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_from_tag: Option<String>,
    /// The dialog's `To` tag, when the capture observed one.
    ///
    /// The tag of the response that established the dialog, a 2xx and then a
    /// 101-199 to the opening request, ahead of a tag from a response that
    /// establishes none, such as a `401` challenge (see
    /// [`SipDialog::to_tag`](crate::sip::dialog::SipDialog::to_tag)). Absent
    /// when no message carried a `To` tag, which is itself the signal that no
    /// dialog was established.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_to_tag: Option<String>,
    /// `sip_cseq` ([draft-howe-vcon-sip-signaling-00 section 5.4](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-5.4)):
    /// "the sequence number from the CSeq header field of the INVITE or other
    /// dialog-creating request".
    ///
    /// Absent when the capture did not hold that request. A later request's
    /// number belongs to another transaction, and writing it here would point
    /// a reader correlating against a trace at the wrong one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_cseq: Option<u32>,
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
    /// `originator` ([core-04 section 4.3.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.5)):
    /// the index of the calling party, written only when [`Self::parties`]
    /// does not list it first.
    ///
    /// core-04 section 4.3.4 says the first listed party is implied to be the
    /// originator, and section 4.3.5 says this parameter "is only provided if
    /// the first party of the dialog Object parties list is NOT the
    /// originator". When the capture did not see the dialog-creating request,
    /// the caller is not known, and this names an empty Party Object, the
    /// form section 4.3.5 gives an unknown originator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub originator: Option<usize>,
    /// `party_history` ([core-04 section 4.3.13](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.13)):
    /// what the capture shows each party doing, in time order.
    ///
    /// On the signaling object only, and only events the capture shows (see
    /// `party_history_of`). Absent when it shows none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party_history: Option<Vec<PartyEvent>>,
    /// `campaign` ([draft-ietf-vcon-cc-extension-02 section 3.2.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-cc-extension-02#section-3.2.1)),
    /// from the header a rule's `campaign_header` names. See
    /// [`add_cc_fields`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    /// `skill` ([draft-ietf-vcon-cc-extension-02 section 3.2.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-cc-extension-02#section-3.2.4)),
    /// from the header a rule's `skill_header` names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill: Option<String>,
    /// `interaction_id` ([draft-ietf-vcon-cc-extension-02 section 3.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-cc-extension-02#section-3.2.3)),
    /// from the header a rule's `interaction_id_header` names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_id: Option<String>,
    /// Indices into [`Vcon::dialog`] of the objects this set groups.
    ///
    /// Present only on a [`RECORDING_SET_TYPE`] object, and named `recordings`
    /// on the wire because [core-04 section 4.3.6](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.6) makes that a MUST: "The
    /// recordings parameter MUST be present in recording-set Dialog Objects."
    /// It serialized as `dialogs` until 0.5.125, which validated cleanly only
    /// because the working group's schema leaves `additionalProperties` open —
    /// an unknown key is ignored, so a consumer read a set whose members it
    /// could not resolve.
    #[serde(rename = "recordings", skip_serializing_if = "Option::is_none")]
    pub dialogs: Option<Vec<usize>>,
    /// Index of the [`RECORDING_SET_TYPE`] object this recording belongs to.
    ///
    /// [Section 4.3.7 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.7): "The recording_set parameter
    /// SHOULD be present when a recording Dialog Object is part of a
    /// recording-set Dialog Object." Without it the link is one-way, and a
    /// consumer holding the audio cannot reach the call's clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_set: Option<usize>,
    /// IANA media type of [`Self::body`] — [`RECORDING_MEDIATYPE`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediatype: Option<std::borrow::Cow<'static, str>>,
    /// Always `"base64url"` when [`Self::body`] is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
    /// The media itself, base64url, unpadded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Where the media is served, when it is not inline.
    ///
    /// Set only for an export rule with `audio = "url"`, which names the base
    /// URL; sipnab writes the audio file beside the container and hosts nothing
    /// ([section 2.5 of `docs/design/vcon.md`](https://github.com/NormB/sipnab/blob/main/docs/design/vcon.md#25-never-host-artefacts)).
    /// Always beside [`Self::content_hash`], as
    /// [core-04 section 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.4)
    /// requires, so any copy of the file can be checked against it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// [`CONTENT_HASH_PREFIX`] followed by the base64url SHA-512 of the
    /// DECODED body.
    ///
    /// Over the file's bytes (the WAV, or the Ogg Opus stream of a rule with
    /// `audio_format = "opus"`), not over their base64url text, so the value
    /// means the same thing whether the media travels inline or an operator
    /// exported it to a file: `sha512sum` on that file reproduces it. Hashing
    /// the encoded text would produce a digest nothing outside this container
    /// could ever recompute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

impl Dialog {
    /// The placeholder of [core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) for a
    /// consultative call: `{"type": "recording"}`, and nothing else.
    ///
    /// "In such situations, it is possible to have a placeholder Dialog Object
    /// which contains only the type parameter … As the consultative call is a
    /// call, a placeholder Dialog Object for it MUST be of type "recording" if
    /// the call was set up". sipnab writes one for the consultative call of an
    /// attended transfer, which this leg never saw: the `Replaces` in the
    /// `Refer-To` names an existing dialog to replace, so that call was set
    /// up. core-03 used `{}` here, which core-04 no longer allows.
    fn consultation_placeholder() -> Self {
        Self::bare(RECORDING_TYPE, String::new())
    }

    /// A Dialog Object with every optional field absent.
    ///
    /// Constructor rather than `Default`, because `sip_call_id` is mandatory
    /// and a defaulted empty one would emit a container tied to no capture.
    /// Every media field is set explicitly by whoever needs it, so adding a
    /// field cannot silently populate itself on the signaling object.
    fn bare(kind: &'static str, sip_call_id: String) -> Self {
        Self {
            kind,
            session_id: None,
            transferor: None,
            transferee: None,
            transfer_target: None,
            original: None,
            consultation: None,
            disposition: None,
            sip_call_id,
            sip_from_tag: None,
            sip_to_tag: None,
            sip_cseq: None,
            start: None,
            duration: None,
            parties: None,
            originator: None,
            party_history: None,
            campaign: None,
            skill: None,
            interaction_id: None,
            dialogs: None,
            recording_set: None,
            mediatype: None,
            encoding: None,
            body: None,
            url: None,
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
    /// [Section 4.4.3 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.4.3) makes this mandatory "to provide
    /// provenance for the attachment", and the requirement earns its place: an
    /// attachment with no party is a document of unknown origin inside a
    /// container about a conversation, and a reader will attribute it to a
    /// participant.
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
    /// Always `json`: the body is a JSON value, not base64url text.
    pub encoding: &'static str,
    /// The attachment itself, as the JSON value (an object on every
    /// attachment sipnab writes).
    ///
    /// [Section 2.3.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3.2)
    /// defines the encoding this body declares: "\"json\": The value of the
    /// body parameter is a JSON value (object, array, number, string, or one
    /// of the literals true, false, or null) as defined in \[JSON\]." The CDDL
    /// in [Appendix C](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-C)
    /// says the same: "body is any JSON value when encoding is \"json\";
    /// otherwise body is a string". A string holding the object's text is
    /// therefore a JSON string value, not the object.
    pub body: serde_json::Value,
}

/// What sipnab determined about this dialog.
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// `"report"` on sipnab's own; what the service said on an enrichment's
    /// (`transcript`, `summary`, ...).
    #[serde(rename = "type")]
    pub kind: std::borrow::Cow<'static, str>,
    /// Index into [`Vcon::dialog`] of what was analyzed.
    pub dialog: usize,
    /// [`ANALYSIS_VENDOR`] on sipnab's own; the service's on an enrichment's.
    pub vendor: std::borrow::Cow<'static, str>,
    /// [`ANALYSIS_PRODUCT`] on sipnab's own, which names sipnab as an
    /// observer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<std::borrow::Cow<'static, str>>,
    /// [`ANALYSIS_SCHEMA`] on sipnab's own, naming the body's contract and
    /// version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<std::borrow::Cow<'static, str>>,
    /// `application/json` on sipnab's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediatype: Option<std::borrow::Cow<'static, str>>,
    /// `json` on sipnab's own; `json`, `none` or `base64url`.
    pub encoding: std::borrow::Cow<'static, str>,
    /// The report itself.
    ///
    /// With `encoding: "json"` this is the JSON value, as for
    /// [`Attachment::body`]. With `none` or `base64url` it is a string, the
    /// only shape
    /// [section 2.3.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3.2)
    /// defines for those encodings.
    pub body: serde_json::Value,
    /// How an enrichment service generated this entry: the provenance record
    /// of [draft-howe-vcon-provenance-00 section 4](https://datatracker.ietf.org/doc/html/draft-howe-vcon-provenance-00#section-4),
    /// written by `crate::app::vcon_enrich`. `None` on sipnab's own report,
    /// which no model generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<serde_json::Value>,
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
    /// Whether an operator stopped this run writing content partway through.
    ///
    /// Serialized always, including as `false`. Unlike `blind_spots`, absence
    /// here has no second meaning to protect: `false` IS the answer, and a
    /// consumer branching on the key should not have to treat "missing" and
    /// "nothing happened" as the same thing.
    pub gate_closed_during_run: bool,
    /// Dialogs a deny flag removed from this export.
    pub dialogs_suppressed_by_deny: u64,
    /// Header lines dropped for exceeding the parser's length cap (VAL13).
    ///
    /// The bytes cannot be recovered -- the cap is what stops one runaway line
    /// being unfolded into memory -- so the count is what tells a reader their
    /// view of a message is partial. Reported here rather than left to
    /// `parse_error`, which a bad `Content-Length` also sets: a consumer could
    /// not tell a withheld header from any other parse complaint.
    pub headers_dropped_oversize: u64,
    /// Whether the call had ended when this container was written: sipnab had
    /// seen the BYE, CANCEL or final failure that closes it.
    ///
    /// `false` on a call still running at the end of a capture, and on one a
    /// live export wrote after the idle period with no BYE seen. Such a
    /// container ends where it was written, not where the call ended.
    /// Serialized always, like `gate_closed_during_run`.
    pub call_ended: bool,
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
    /// The load-bearing field for the dangerous case in
    /// [section 3.2 of `docs/design/vcon.md`](https://github.com/NormB/sipnab/blob/main/docs/design/vcon.md#32-every-partial-clause-sipnab-already-builds-is-homeless). An empty `dialog[]` reads as
    /// *a conversation with no media*, which is a claim about the CALL; this
    /// says which of four quite different things actually happened, so no
    /// reader has to infer one from an absence.
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

/// One thing this run did not carry into the container, as a row.
///
/// [`CaptureCompleteness::note`] states every omission in prose, and prose is
/// what a PERSON reads. An agent handed the same container through a tool
/// reads neither: it gets a caveat it would have to parse out of a string, or
/// -- worse -- a container with no audio and an absence that looks clean. This
/// is the same set of facts in a shape a caller can branch on.
///
/// DERIVED from the carrier's own counters rather than written beside them, so
/// there is one account of what was lost and not two.
/// `an_omission_row_exists_for_every_incomplete_clause` is the gate on that:
/// one row per `-- INCOMPLETE:` clause in the note, both directions.
///
/// Shaped like [`BlindSpot`] on purpose. A consumer that learned to read one
/// list of "what was missed" should not have to learn a second vocabulary for
/// the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct Omission {
    /// Stable machine identifier — the carrier field this row was read from.
    pub kind: &'static str,
    /// How many times it happened.
    ///
    /// `1` for a fact that either happened or did not, so a caller never has
    /// to branch on whether a row carries a count.
    pub count: u64,
    /// What one occurrence is — `"frame"`, `"message"`, `"dialog"`,
    /// `"header"`, `"run"`, `"recording"`, `"blind-spot"`.
    pub unit: &'static str,
}

impl CaptureCompleteness {
    /// Every omission this container records, one row per `-- INCOMPLETE:`
    /// clause in [`Self::note`].
    ///
    /// The order matches the note's clause order, so a reader holding both
    /// reads one sequence rather than two orderings of one set.
    ///
    /// An analysis that ran and ranked nothing produces no row, and so does an
    /// analysis that never ran — neither is something this container lost, and
    /// the note keeps those two apart in its own words.
    #[must_use]
    pub fn omissions(&self) -> Vec<Omission> {
        let mut out = Vec::new();
        let mut push = |kind, count, unit| out.push(Omission { kind, count, unit });

        // The refusal is first because the note puts it first: it is the one
        // omission a reader is most likely to be looking for, since the
        // container it describes has an empty-looking `dialog[]`.
        if self.media == MediaOutcome::RefusedOverBudget {
            push("media_refused_over_budget", 1, "recording");
        }
        for (kind, count, unit) in [
            ("undecodable_frames", self.undecodable_frames, "frame"),
            (
                "sip_discarded_by_port_gate",
                self.sip_discarded_by_port_gate,
                "message",
            ),
            (
                "sip_discarded_by_websocket_gate",
                self.sip_discarded_by_websocket_gate,
                "message",
            ),
            ("messages_evicted", self.messages_evicted, "message"),
            ("dialogs_refused", self.dialogs_refused, "dialog"),
            ("dialogs_rotated", self.dialogs_rotated, "dialog"),
        ] {
            if count > 0 {
                push(kind, count, unit);
            }
        }
        // A decision rather than a capture fault, and reported for the reason
        // the note reports it: containers are absent and nothing else in the
        // capture records why.
        if self.gate_closed_during_run {
            push("gate_closed_during_run", 1, "run");
        }
        if self.dialogs_suppressed_by_deny > 0 {
            push(
                "dialogs_suppressed_by_deny",
                self.dialogs_suppressed_by_deny,
                "dialog",
            );
        }
        if self.headers_dropped_oversize > 0 {
            push(
                "headers_dropped_oversize",
                self.headers_dropped_oversize,
                "header",
            );
        }
        if let Some(spots) = self.blind_spots.as_deref()
            && !spots.is_empty()
        {
            push("analysis_blind_spots", spots.len() as u64, "blind-spot");
        }
        out
    }

    /// Whether this container omits nothing at all.
    ///
    /// The same answer the note's clean verdict gives, as a boolean. A caller
    /// that has to search prose for "No omissions recorded" is one string
    /// edit away from reading every container as complete.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.omissions().is_empty()
    }
}

/// What became of one dialog's audio on its way into a container.
///
/// Five answers, kept apart, because collapsing any two of them recreates the
/// failure `nothing_to_decode` exists to refuse: a limit of THIS RUN reported
/// as a finding about the TRAFFIC. "Nobody asked for media", "the run kept
/// none", "it was too big to carry", "the export is redacted" and "here it is"
/// are five facts with five different next steps, and an absent media object
/// is the same shape for the first four.
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
    /// Media was decoded and written to a WAV beside the container; the
    /// `recording` Dialog Object names its URL and hash and holds no body.
    Referenced,
    /// The export is redacted, so no audio was considered for it: redaction
    /// deletes audio rather than pseudonymizing it. Says nothing about whether
    /// the call carried audio.
    WithheldByRedaction,
}

impl MediaOutcome {
    /// Every outcome, in declaration order, so a list of them in help text or
    /// docs can be checked against the enum rather than against a copy.
    pub const ALL: [Self; 6] = [
        Self::NotConsidered,
        Self::NoneDecodable,
        Self::RefusedOverBudget,
        Self::Carried,
        Self::Referenced,
        Self::WithheldByRedaction,
    ];

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
            Self::Referenced => "referenced",
            Self::WithheldByRedaction => "withheld-by-redaction",
        }
    }
}

/// A recording's bytes in the format a rule chose, and their media type.
#[derive(Debug, Clone, Copy)]
pub struct EncodedRecording<'a> {
    /// The file: a WAV, or an Ogg Opus stream.
    pub bytes: &'a [u8],
    /// Its `mediatype` ([core-04 section 4.3.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.8)).
    pub mediatype: &'static str,
    /// The format's name, as the over-budget refusal names it: `WAV` or
    /// `Ogg Opus`.
    pub format: &'static str,
}

impl<'a> EncodedRecording<'a> {
    /// `audio`'s own WAV.
    #[must_use]
    pub fn wav(audio: &'a DialogAudio) -> Self {
        Self {
            bytes: &audio.wav,
            mediatype: RECORDING_MEDIATYPE,
            format: "WAV",
        }
    }
}

/// A recording written to a file beside the container and named by URL.
#[derive(Debug, Clone, Copy)]
pub struct ReferencedRecording<'a> {
    /// The URL the operator's storage serves the file at.
    pub url: &'a str,
    /// The `mediatype` of the recording the file holds.
    pub mediatype: &'static str,
    /// The file's bytes as written. The `content_hash` is over these.
    pub file: &'a [u8],
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
    /// Audio sipnab decoded, carried inline in the format a rule chose
    /// (`audio_format`) rather than as the WAV.
    Encoded(&'a DialogAudio, EncodedRecording<'a>),
    /// Audio sipnab decoded and wrote to a file beside the container, served
    /// at the URL by the operator's storage. Yields
    /// [`MediaOutcome::Referenced`]: the recording names the URL and the
    /// file's hash and holds no body.
    Referenced(&'a DialogAudio, ReferencedRecording<'a>),
    /// The export is redacted, and redaction deletes audio rather than
    /// pseudonymizing it. Yields [`MediaOutcome::WithheldByRedaction`]: the
    /// Dialog Object stays the signaling one, typed by what it carries, which
    /// is nothing — never a `recording` with its content cut out.
    WithheldByRedaction,
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
    /// Not when the dialog happened. [Section 4.1.5 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.5)
    /// defines it as the creation time of the vCon, and stamping the call's
    /// start here would make an export written years later look contemporaneous
    /// with the traffic. The dialog's own clock is reachable through the
    /// message trace, which carries a timestamp per message.
    pub created_at: String,
    /// When the container was last rewritten, RFC 3339. Set by a `live =
    /// true` rule, which writes a call's container as it starts and rewrites
    /// it in place as the call changes ([core-04 section 4.1.6](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.6));
    /// absent on a container written once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// `subject` ([core-04 section 4.1.7](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.7)) — descriptive, and descriptive
    /// only.
    ///
    /// It names the DIALOG so a store whose search matches subject or UUID can
    /// find this container by an identifier an operator has. It never carries
    /// a verdict about the call: an observer is in no position to say what a
    /// conversation was about, and the completeness caveat has its own two
    /// surfaces for what this run did and did not read.
    pub subject: String,
    /// `redacted` ([core-04 section 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8)) — present ONLY on a container
    /// whose content a deny header suppressed. See [`Redacted`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<Redacted>,
    /// `amended` ([core-04 section 4.1.9](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9)) — present
    /// ONLY on a later instance a sealing rule wrote for a call it had already
    /// sealed, naming the instance before it. See [`Amended`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amended: Option<Amended>,
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

/// Serialize a container that has been through the redaction boundary.
///
/// The only serializer the CLI export paths use, and that is the point.
/// [`crate::output::redact::Redacted`] has no accessor and no `Deref`, so a
/// caller holding one can do exactly two things with it: serialize it here, or
/// drop it. Writing a container therefore cannot skip the boundary by
/// accident — it has to skip it by naming
/// [`crate::output::redact::Redacted::pass_through`], which is a line somebody
/// has to defend in review.
///
/// # Errors
///
/// Propagates any `serde_json` failure, for the reason [`Vcon::to_json`] does.
pub fn sealed_json(
    container: &crate::output::redact::Redacted<Vcon>,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(container)
}

/// A container's SHA-256, as lowercase hex.
///
/// Over the BYTES an export writes, which is what makes the value join to
/// anything outside this process: the line `--vcon-digest` prints into a
/// `SHA256SUMS`, the ledger entry a conserver records for a container it
/// accepted. A digest taken over some other rendering of the same container
/// would look right and match nothing, so every surface that publishes one
/// takes it from here.
///
/// # Arguments
///
/// * `bytes` — the container's serialized form, exactly as it is written or
///   sent. [`sealed_json`] produces it.
#[must_use]
pub fn container_digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Seal a container, redacting it when a policy is in force.
///
/// One place where "redaction is off" turns into a value, so no export path
/// has to spell the `Option` out and none of them can spell it differently.
#[must_use]
pub fn seal(
    container: Vcon,
    redactor: Option<&crate::output::redact::Redactor<'_>>,
) -> crate::output::redact::Redacted<Vcon> {
    match redactor {
        Some(r) => crate::output::redact::Redacted::seal_with(container, r),
        None => crate::output::redact::Redacted::pass_through(container),
    }
}

// ── The redaction boundary ───────────────────────────────────────────────
//
// Every impl below DESTRUCTURES. A field added to one of these structs then
// fails to compile until somebody has decided whether it identifies anybody,
// which turns "I forgot to redact the new field" from a CVE in the next
// release into a build error in the pull request that introduced it. That is
// the whole reason the impls are written the long way instead of walking the
// serialized JSON.

impl crate::output::redact::Redact for Vcon {
    fn redact(&mut self, r: &crate::output::redact::Redactor<'_>) {
        let Self {
            // A syntax version.
            vcon: _,
            // A UUIDv8 already derived through SHA-256 from the Call-ID and
            // the capture identity (see `dialog_uuid`), so it is a one-way
            // function of values that are themselves redacted below. Rewriting
            // it would break the container's own identity for no gain.
            uuid: _,
            // When the container was written. Not a fact about anybody.
            created_at: _,
            // When it was last rewritten. Not a fact about anybody either.
            updated_at: _,
            subject,
            redacted,
            // A uuid derived from this container's own uuid scheme (see
            // `revision_uuid`), so it identifies nobody.
            amended: _,
            // A fixed list of extension names.
            extensions: _,
            parties,
            dialog,
            attachments,
            analysis,
        } = self;

        // The subject is built from the Call-ID, and the same token has to
        // come out here as comes out of the Dialog Object below — otherwise a
        // consumer searching by subject cannot find the container it names.
        // Taken BEFORE the dialog objects are redacted, so the value fed to
        // the map is the original.
        let call_id = dialog.first().map(|d| d.sip_call_id.clone());
        match call_id.filter(|id| !id.is_empty() && subject.contains(id.as_str())) {
            Some(id) => {
                // Redact the prose AROUND the Call-ID and join with the token,
                // so the token itself never goes through `text()`.
                //
                // It used to: the Call-ID was substituted and then the whole
                // string was swept, which found the redacted host inside the
                // token -- it looks like an ordinary address -- and tokenized
                // it a SECOND time. The map then recorded both hops, and
                // reversing the outer one yielded another token that read as a
                // real IPv4 address. `redaction_map_reverses_test` holds the
                // invariant that no value in the map is itself a key.
                let token = r.opaque(&id);
                let redacted_parts: Vec<String> = subject
                    .split(id.as_str())
                    .map(|part| r.text(part))
                    .collect();
                *subject = redacted_parts.join(&token);
            }
            None => *subject = r.text(subject),
        }

        // §4.1 says redaction happened, in the format's own vocabulary. A
        // withheld container keeps its own marker: nothing survived it to
        // pseudonymize, and overwriting it would understate what was done.
        if redacted.is_none() {
            *redacted = Some(Redacted {
                kind: CONTENT_PSEUDONYMIZED,
            });
        }

        for party in parties.iter_mut() {
            party.redact(r);
        }
        for object in dialog.iter_mut() {
            object.redact(r);
        }
        // The wire attachments are refused rather than rewritten: see
        // `add_sip_message_attachments`.
        attachments.retain(|a| !is_wire_attachment(a));
        for attachment in attachments.iter_mut() {
            // Dropped before the rest is redacted, so the sweep records no
            // token for a body the container will not hold: a redaction map
            // entry whose original survives elsewhere (the `sdp` field keeps
            // the `o=` session id) would claim a replacement that never
            // happened.
            if attachment.purpose == MESSAGE_TRACE_PURPOSE {
                drop_trace_bodies(&mut attachment.body);
            }
            attachment.redact(r);
            // The numbers come out of the PASSporT, which redaction deletes
            // from the party for the reason given there; they go with it.
            if attachment.purpose == STIR_REPORT_PURPOSE
                && let Some(map) = attachment.body.as_object_mut()
            {
                map.remove("orig_tn");
                map.remove("dest_tn");
            }
        }
        for report in analysis.iter_mut() {
            report.redact(r);
        }

        // What was done, stated inside the container rather than only on the
        // operator's terminal. Without it an agent handed `+1555x123456` reads
        // it as the caller's number and says so to somebody who will act on
        // it. The completeness caveat is where this container already explains
        // itself, so the account of the redaction goes beside the account of
        // the capture instead of inventing a second place to look.
        let report = r.policy().report();
        for attachment in attachments.iter_mut() {
            if attachment.purpose != COMPLETENESS_PURPOSE {
                continue;
            }
            if let (Some(map), Ok(value)) = (
                attachment.body.as_object_mut(),
                serde_json::to_value(&report),
            ) {
                map.insert("redaction".to_string(), value);
            }
        }
    }
}

impl crate::output::redact::Redact for Party {
    fn redact(&mut self, r: &crate::output::redact::Redactor<'_>) {
        let Self {
            sip,
            tel,
            // Unconditionally "none", and a pseudonym does not change that:
            // sipnab never verified who this party was, before or after.
            validation: _,
            // "observer" or absent.
            role: _,
            name,
            stir,
            sip_display_name,
            sip_contact,
            sip_user_agent,
        } = self;

        *sip = sip.as_deref().map(|v| r.uri(v));
        *tel = tel.as_deref().map(|v| r.uri(v));
        *name = name.as_deref().map(|v| r.identity(v));
        *sip_display_name = sip_display_name.as_deref().map(|v| r.identity(v));
        *sip_contact = sip_contact.as_deref().map(|v| r.name_addr(v));
        // A product string names equipment, not a person, and it is load
        // bearing for interop triage — "which firmware sends this" is most of
        // a carrier ticket. Swept as free text rather than kept verbatim,
        // because vendors put serial numbers and MAC addresses in it.
        *sip_user_agent = sip_user_agent.as_deref().map(|v| r.text(v));

        // DELETED, not tokenized. An RFC 8224 PASSporT is a signed JWS whose
        // payload carries `orig` and `dest` in the clear — base64url is an
        // encoding, not encryption — so publishing the token publishes both
        // numbers. It cannot be rewritten either: any edit to the payload
        // invalidates the signature, and a PASSporT that does not verify is
        // worse than an absent one, because a consumer that checks it reports
        // a forgery where there was none.
        *stir = None;
    }
}

impl crate::output::redact::Redact for Dialog {
    fn redact(&mut self, r: &crate::output::redact::Redactor<'_>) {
        let Self {
            kind,
            session_id,
            // Party indices into an array whose entries are themselves
            // redacted. An index identifies nobody on its own.
            transferor: _,
            transferee: _,
            transfer_target: _,
            original: _,
            consultation: _,
            // A coarse outcome from a fixed vocabulary.
            disposition: _,
            sip_call_id,
            // Dialog-scoped nonces. A tag correlates messages inside this one
            // container and says nothing about a subscriber, and rewriting it
            // would put the Dialog Object out of step with the `;tag=` in the
            // message trace, which keeps its own.
            sip_from_tag: _,
            sip_to_tag: _,
            // A sequence number. It identifies a transaction, not a person.
            sip_cseq: _,
            start: _,
            duration: _,
            parties: _,
            originator: _,
            party_history,
            campaign,
            skill,
            interaction_id,
            dialogs: _,
            recording_set: _,
            mediatype,
            encoding,
            body,
            // A URL to the audio leads to the conversation as surely as the
            // audio does, so it goes with the body below.
            url,
            content_hash,
        } = self;

        if !sip_call_id.is_empty() {
            *sip_call_id = r.opaque(sip_call_id);
        }
        // The contact-center labels: draft-ietf-vcon-cc-extension-02 section 6
        // calls `campaign` a candidate for review. `interaction_id` is a
        // join key, so it becomes a token that still joins; the two labels
        // are swept as free text.
        *campaign = campaign.as_deref().map(|v| r.text(v));
        *skill = skill.as_deref().map(|v| r.text(v));
        *interaction_id = interaction_id.as_deref().map(|v| r.opaque(v));
        // A key event's `button` is the digit pressed, which can be a PIN or
        // a card number, and no keyed transform of one digit hides it. The
        // events go; the joins, drops and holds stay.
        if let Some(events) = party_history.as_mut() {
            events.retain(|e| !matches!(e.event, "keydown" | "keyup"));
            if events.is_empty() {
                *party_history = None;
            }
        }
        if let Some(pair) = session_id.as_mut() {
            pair.local = pair.local.as_deref().map(|v| r.opaque(v));
            pair.remote = pair.remote.as_deref().map(|v| r.opaque(v));
        }

        // The audio is REFUSED under redaction, not pseudonymized. A recording
        // is the conversation itself: there is no keyed transform of speech
        // that keeps a diagnosis answerable and carries no content, and a
        // container that pseudonymized every identifier and then inlined four
        // minutes of the call would be the most complete privacy failure this
        // module could ship.
        //
        // This is the backstop, not the path. sipnab's own redacted exports
        // never reach it with audio: they pass
        // `ObservedAudio::WithheldByRedaction`, so the Dialog Object is the
        // signaling one, typed by the rule in `dialog_object`. Cutting the
        // content out of a `recording` here leaves the core-04 section 4.3
        // placeholder, whose content core-04 section 4.3.10 lets a redacted
        // vCon omit; `duration` stays, so the exporter still must not hand
        // one over.
        // A text dialog is the conversation too, so its content goes the same
        // way, and its clock and parties stay.
        if *kind == RECORDING_TYPE || *kind == TEXT_TYPE {
            *body = None;
            *url = None;
            *content_hash = None;
            *mediatype = None;
            *encoding = None;
        }
    }
}

impl crate::output::redact::Redact for Attachment {
    fn redact(&mut self, r: &crate::output::redact::Redactor<'_>) {
        let Self {
            // A fixed purpose name.
            purpose: _,
            // Indices into arrays that are redacted in their own right.
            party: _,
            dialog: _,
            // The dialog's observed start.
            start: _,
            mediatype: _,
            encoding: _,
            body,
        } = self;
        redact_body(body, r);
    }
}

impl crate::output::redact::Redact for Analysis {
    fn redact(&mut self, r: &crate::output::redact::Redactor<'_>) {
        let Self {
            kind: _,
            dialog: _,
            vendor: _,
            product: _,
            schema: _,
            mediatype: _,
            encoding: _,
            body,
            provenance,
        } = self;
        redact_body(body, r);
        // Its hashes bind the unredacted content, and its prompt may quote
        // it. Enrichment never runs with `--redact` (startup refuses the
        // pair), so a record never reaches here from sipnab's own run; one
        // that did is dropped rather than carried beside redacted content.
        *provenance = None;
    }
}

/// Remove `body` and `body_encoding` from every trace message, under
/// redaction.
///
/// A message body can be the conversation itself (the text of a SIP MESSAGE)
/// or a secret (a DTMF digit in an INFO), and no keyed transform of either
/// keeps it useful and harmless. An SDP body is not lost: the trace keeps it
/// in `sdp`, which redaction rewrites like any other field.
fn drop_trace_bodies(body: &mut serde_json::Value) {
    let Some(messages) = body["messages"].as_array_mut() else {
        return;
    };
    for message in messages {
        if let Some(map) = message.as_object_mut() {
            map.remove("body");
            map.remove("body_encoding");
        }
    }
}

/// Redact an [`Attachment::body`] or an [`Analysis::body`] in place.
///
/// An object or an array is walked field by field. A string is either JSON
/// text (an enrichment service may still send its `json` body that way, and
/// a `none` body may hold JSON) or free text: JSON text is parsed, walked and
/// written back as text, so its shape is kept; anything else, base64url
/// included, is swept as free text instead of being passed through, because
/// it is still capture-derived.
fn redact_body(body: &mut serde_json::Value, r: &crate::output::redact::Redactor<'_>) {
    let serde_json::Value::String(text) = body else {
        crate::output::redact::redact_json(body, r);
        return;
    };
    *text = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(mut value) if value.is_object() || value.is_array() => {
            crate::output::redact::redact_json(&mut value, r);
            serde_json::to_string(&value).unwrap_or_else(|_| r.text(text))
        }
        _ => r.text(text),
    };
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
    /// Largest inline media body this run will carry, overriding
    /// [`MAX_INLINE_MEDIA_BYTES`].
    ///
    /// `None` takes the measured default, which is the right answer for the
    /// store that default was measured against. The number is a property of a
    /// CONSUMER rather than of the format, and the consumer it was measured
    /// against publishes no per-container cap — so an operator writing to a
    /// spool they control is entitled to a different one. `Some(0)` refuses
    /// every inline body, which is how an operator says "never inline media"
    /// without turning the exporter off.
    pub max_inline_media_bytes: Option<usize>,
    /// The quality of this dialog's RTP streams, as `GET /v1/streams`
    /// reports it, for the analysis report's `media_quality`. Empty when the
    /// caller has no streams for the dialog, which the report then omits.
    pub media: &'a [crate::output::model::StreamSummary],
    /// This call's other legs, from [`related_legs`]. Empty writes no
    /// related-legs attachment.
    pub related_legs: &'a [RelatedLeg],
}

/// Whether `--content-deny-header` withholds this dialog's container.
///
/// The one rule every door applies: the batch export, `GET
/// /v1/dialogs/{id}/vcon` and MCP `export_vcon`. Presence of the named header
/// on any message of the dialog denies; the value plays no part, and the
/// name is matched case-insensitively by
/// [`crate::sip::message::SipMessage::header`]. With no header named, nothing
/// is denied.
#[must_use]
pub fn denied_by_header(dialog: &crate::sip::dialog::SipDialog, header: Option<&str>) -> bool {
    header.is_some_and(|h| dialog.messages.iter().any(|m| m.header(h).is_some()))
}

/// The quality of `call_id`'s RTP streams for [`ExportContext::media`], on the
/// delay basis `GET /v1/streams` uses, so the container and the API report
/// the same figures.
#[must_use]
pub fn media_quality_for(
    store: &crate::rtp::stream_store::StreamStore,
    call_id: &str,
) -> Vec<crate::output::model::StreamSummary> {
    let delay = crate::rtp::quality::MosDelay::from_capture(store);
    store
        .streams_for(call_id)
        .map(|s| crate::output::model::StreamSummary::of(s, delay))
        .collect()
}

impl ExportContext<'_> {
    /// The inline-media budget this export enforces, in bytes of base64url.
    #[must_use]
    pub fn media_budget(&self) -> usize {
        self.max_inline_media_bytes
            .unwrap_or(MAX_INLINE_MEDIA_BYTES)
    }
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

/// What an observed REFER says about a transfer.
///
/// Everything here comes off the wire. The `Refer-To` URI is what one party
/// ASKED for, not somewhere the call is known to have gone, and the transfer
/// object says only that the request was observed.
struct ObservedTransfer {
    /// The `Refer-To` target as a bare SIP URI, when one could be read.
    target: Option<String>,
    /// Whether the `Refer-To` carried a `Replaces` parameter, which is what
    /// distinguishes an attended transfer from a blind one.
    attended: bool,
}

/// The first REFER in the ladder, read for what it says about a transfer.
///
/// The FIRST: a dialog can carry several REFERs, and later ones are further
/// transfers rather than restatements of this one. Emitting an object per
/// REFER would be defensible; emitting one built from a mixture of them would
/// not.
fn observed_transfer(dialog: &SipDialog) -> Option<ObservedTransfer> {
    let refer = dialog.messages.iter().find(|m| {
        m.is_request && m.method.as_ref() == Some(&crate::sip::method::SipMethod::Refer)
    })?;
    // A REFER with no `Refer-To` is malformed. It still happened, so the
    // transfer is reported with no target rather than dropped -- an absent
    // target says the header was missing, which is a fact about the traffic.
    let raw = refer.header("Refer-To").unwrap_or_default();
    Some(ObservedTransfer {
        target: refer_to_uri(raw),
        // RFC 3891: the `Replaces` rides in the URI's header portion, after a
        // `?`. Matched case-insensitively because a URI header name is
        // case-insensitive and a peer that capitalizes it differently is
        // making a blind transfer look attended -- or, worse, the reverse.
        attended: raw
            .split_once('?')
            .is_some_and(|(_, q)| q.to_ascii_lowercase().contains("replaces=")),
    })
}

/// The bare SIP URI inside a `Refer-To` header value.
///
/// Strips the angle brackets, any display name before them, and the URI
/// header portion after `?`. What remains is what can be compared against a
/// party's `sip` value; keeping the parameters would make every target a
/// string no other field in the container matches.
fn refer_to_uri(raw: &str) -> Option<String> {
    let inside = match (raw.find('<'), raw.find('>')) {
        (Some(a), Some(b)) if b > a + 1 => &raw[a + 1..b],
        // A bare URI with no brackets is legal when it carries no parameters.
        _ => raw.trim(),
    };
    let uri = inside.split('?').next().unwrap_or("").trim();
    (uri.starts_with("sip:") || uri.starts_with("sips:")).then(|| uri.to_string())
}

/// The party a `Refer-To` names, appended so `transfer_target` has an index.
///
/// `validation: "none"`, like every other party: a `Refer-To` URI is what one
/// participant asked for, and sipnab watched the asking rather than the
/// arriving.
fn transfer_target_party(uri: &str) -> Party {
    Party {
        sip: Some(uri.to_string()),
        tel: None,
        validation: "none",
        role: None,
        name: None,
        stir: None,
        sip_display_name: None,
        sip_contact: None,
        sip_user_agent: None,
    }
}

/// A container for a dialog a deny header suppressed: identity, no content.
///
/// The alternative sipnab shipped first was to emit NOTHING for a denied
/// dialog, and to report the count in the completeness attachment on its
/// siblings. That leaves a consumer reading the format rather than this
/// implementation with no way to know a call was withheld at all, and it puts
/// the only record of the withholding inside containers describing OTHER
/// calls.
///
/// This says it where the format says it. What travels is the dialog's
/// identity — which call, when, between whom — and a `redacted` object
/// ([core-04 section 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8)) declaring that its content was withheld and no
/// fuller instance exists. What does not travel is everything the deny header
/// asked sipnab not to keep: no message trace, no media, no bodies.
///
/// # Arguments
///
/// * `deny_header` — the header whose presence fired the rule, named in the
///   caveat so an operator reading the container months later can tell a
///   deliberate suppression from a capture that missed the traffic.
#[must_use]
pub fn export_withheld_dialog(
    dialog: &SipDialog,
    context: &ExportContext<'_>,
    deny_header: &str,
) -> Vcon {
    export_withheld_dialog_at(dialog, context, deny_header, Utc::now())
}

/// [`export_withheld_dialog`], with the clock supplied.
#[must_use]
pub fn export_withheld_dialog_at(
    dialog: &SipDialog,
    context: &ExportContext<'_>,
    deny_header: &str,
    exported_at: DateTime<Utc>,
) -> Vcon {
    let mut parties = observed_parties(dialog);
    parties.push(observer_party());

    let started = observed_start(dialog);
    // The same contentless object every other no-media export builds, and for
    // the same reason: no value of `type` is true of an object carrying
    // nothing. A withheld dialog is not a FAILED one.
    let object = dialog_object(dialog, started);

    let note = format!(
        "Produced by sipnab {} on node {}. The content of this dialog was WITHHELD: it carried \
         the header `{deny_header}`, which this capture was configured to treat as a refusal to \
         record. What is here is the dialog's identity. What is absent was not missed -- no \
         message trace, no media and no bodies were retained, and no unredacted container of \
         this dialog exists anywhere to request.",
        env!("CARGO_PKG_VERSION"),
        node_name(),
    );

    Vcon {
        vcon: VCON_SYNTAX_VERSION,
        uuid: dialog_uuid(dialog, context.capture_id),
        created_at: exported_at.to_rfc3339(),
        updated_at: None,
        subject: subject_of(dialog),
        redacted: Some(Redacted {
            kind: CONTENT_WITHHELD,
        }),
        amended: None,
        extensions: DECLARED_EXTENSIONS.to_vec(),
        parties,
        dialog: vec![object],
        // No trace attachment: the trace IS the withheld content. The caveat
        // travels alone so the container still explains itself.
        attachments: vec![withheld_caveat(&note, exported_at)],
        analysis: Vec::new(),
    }
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
    export_dialog_and_completeness(dialog, context, audio, exported_at).container
}

/// A container and the completeness carrier it was built from.
///
/// The carrier is inside the container already, twice — in the analysis body
/// and in the `sipnab-capture-completeness` attachment — but
/// [section 2.3 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3) makes both of those JSON TEXT, so a
/// caller wanting the structured facts would have to parse a string out of a
/// container it had just built. Worse, it would then hold a second decoding of
/// a value this module already has.
#[derive(Debug, Clone)]
pub struct ExportedDialog {
    /// The container.
    pub container: Vcon,
    /// What the capture missed, as the value both of the container's copies
    /// were serialized from.
    pub completeness: CaptureCompleteness,
}

/// [`export_dialog_with_audio_at`], handing back the completeness beside the
/// container.
///
/// For a surface that must state a container's omissions in its OWN response
/// rather than only inside the document: an agent that gets a container with
/// no audio and nothing saying why has been told the same nothing a silent
/// drop would have told it.
///
/// # Arguments
///
/// The same four [`export_dialog_with_audio_at`] takes, and it is the function
/// that does the work.
#[must_use]
pub fn export_dialog_and_completeness(
    dialog: &SipDialog,
    context: &ExportContext<'_>,
    audio: ObservedAudio<'_>,
    exported_at: DateTime<Utc>,
) -> ExportedDialog {
    let mut parties = observed_parties(dialog);

    // A transfer target joins the party array BEFORE the observer, so the
    // observer stays the final entry. Every attachment's `party` resolves to
    // that index, and appending a participant after it would silently
    // re-point all of them at somebody who took part in the call.
    let transfer = observed_transfer(dialog);
    let target_party = transfer
        .as_ref()
        .and_then(|t| t.target.as_deref())
        .map(|uri| {
            parties.push(transfer_target_party(uri));
            parties.len() - 1
        });

    // The calling party's index. Party 0 when the capture saw the
    // dialog-creating request, whose `From` names the caller; otherwise an
    // empty Party Object, which core-04 section 4.3.5 offers for an
    // originator that is not known. It goes before the observer, for the
    // reason the transfer target does.
    let caller = if opened_by_the_caller(dialog) {
        0
    } else {
        parties.push(unknown_originator_party());
        parties.len() - 1
    };

    parties.push(observer_party());
    // Last entry, computed before the borrow ends so both attachments and any
    // future analysis reference one number.
    let observer = parties.len().saturating_sub(1);

    // The signaling object is always index 0, which is what `Analysis::dialog`
    // points at. Media objects are appended after it, never before, so adding
    // audio cannot move the object the analysis describes.
    let started = observed_start(dialog);
    let mut dialog_objects = vec![dialog_object(dialog, started.clone())];
    let media = media_objects(dialog, audio, &mut dialog_objects, context.media_budget());
    name_the_originator(&mut dialog_objects, caller);
    // On index 0 after the media is placed, because a ring-wrapped recording
    // replaces that object with its recording-set.
    dialog_objects[0].party_history = party_history_of(dialog);

    // The transfer object goes last, after any media, for the same reason
    // media goes after signaling: appending never moves an existing index.
    if let Some(observed) = transfer {
        // An attended transfer's consultative call is known to have happened
        // and nothing about it was captured on this leg. core-04 section 4.3
        // names this case: a placeholder typed `recording`, because the call
        // was set up. It is pushed first so the transfer object can name its
        // index.
        let consultation = observed.attended.then(|| {
            dialog_objects.push(Dialog::consultation_placeholder());
            dialog_objects.len() - 1
        });
        dialog_objects.push(Dialog {
            // core-04 Table 1 marks `start` optional on a transfer; core-03's
            // schema required it. It is kept because it is known: the instant
            // is the dialog's own, since a transfer is something that happened
            // DURING this conversation, and a separate start would assert a
            // second one nobody observed. The parameters core-04 forbids on a
            // transfer (`parties`, `session_id` and the rest) start absent in
            // `bare` and nothing here sets them.
            start: Some(started.clone()),
            // The party that sent the REFER is the caller on this leg, and the
            // party being moved is the other one. Both come from the dialog's
            // own From/To rather than from the REFER's, which a mid-dialog
            // request may present in either direction.
            transferor: Some(0),
            transferee: Some(1),
            transfer_target: target_party,
            original: Some(0),
            consultation,
            ..Dialog::bare(TRANSFER_TYPE, dialog.call_id.clone())
        });
    }

    // Text dialogs go last, after the transfer object, for the reason that
    // object goes after the media: appending never moves an existing index.
    dialog_objects.extend(text_dialogs_of(dialog));

    let completeness = completeness_of(context, &media, dialog.state().is_final());

    let mut attachments = vec![
        message_trace_attachment(dialog, observer, started.clone()),
        completeness_attachment(&completeness, observer, started.clone()),
    ];
    attachments.extend(stir_verification_report(dialog));
    if !context.related_legs.is_empty() {
        attachments.push(Attachment {
            purpose: RELATED_LEGS_PURPOSE,
            party: observer,
            dialog: 0,
            start: started,
            mediatype: "application/json",
            encoding: "json",
            body: serde_json::json!({ "legs": context.related_legs }),
        });
    }

    let container = Vcon {
        vcon: VCON_SYNTAX_VERSION,
        uuid: dialog_uuid(dialog, context.capture_id),
        created_at: exported_at.to_rfc3339(),
        updated_at: None,
        subject: subject_of(dialog),
        redacted: None,
        amended: None,
        extensions: DECLARED_EXTENSIONS.to_vec(),
        parties,
        dialog: dialog_objects,
        attachments,
        analysis: vec![report(dialog, &completeness, context.media)],
    };

    ExportedDialog {
        container,
        completeness,
    }
}

/// `purpose` of the attachment a `grouping = "call"` container carries: which
/// Dialog Objects are the call's legs, and what tied each pair.
pub const CALL_LEGS_PURPOSE: &str = "sipnab-call-legs";

/// A tie between two legs of one call, by their positions in the legs handed
/// to [`merge_call_legs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegTie {
    /// The leg the correlation walk reached the other one from.
    pub from: usize,
    /// The leg it reached.
    pub to: usize,
    /// The correlation strategy, in the vocabulary `get_call_tree` reports.
    pub strategy: &'static str,
    /// Whether the tie compared an identifier both legs carry. `false` is a
    /// timing guess.
    pub identifier_match: bool,
    /// Confidence of the tie, 0 to 100.
    pub score: u8,
}

/// One container for a call, from one container per leg.
///
/// Each leg's container is built exactly as a `grouping = "leg"` rule builds
/// it, and this only moves them into one: every leg's observed parties in leg
/// order and then one observer, last, as in every sipnab container; every
/// leg's Dialog Objects in leg order; every attachment and analysis, with its
/// party and dialog indices moved to match. Nothing is merged across legs. A
/// PBX that is the callee on one leg and the caller on the next appears as a
/// party of each, because nothing in the signaling proves the two are one.
///
/// The [`CALL_LEGS_PURPOSE`] attachment names each leg's signaling object and
/// every tie with its strength, so a reader can see when the legs were joined
/// on a timing guess. `truncated` records that the walk stopped at its leg
/// cap and the call may have more legs than the container holds.
///
/// The first leg supplies the subject and `created_at`. A leg whose content
/// was withheld stays withheld here, and its marker becomes the container's.
///
/// `None` for no legs: there is no call to write.
#[must_use]
pub fn merge_call_legs(
    legs: Vec<Vcon>,
    ties: &[LegTie],
    uuid: String,
    truncated: bool,
) -> Option<Vcon> {
    let all = legs;
    let (created_at, subject) = {
        let first = all.first()?;
        (first.created_at.clone(), first.subject.clone())
    };

    // Observed parties of every leg, then one observer. The observer's final
    // index is known once every leg's parties are counted.
    let observed: usize = all
        .iter()
        .map(|leg| leg.parties.len().saturating_sub(1))
        .sum();
    let observer = observed;
    let mut parties = Vec::with_capacity(observed + 1);
    let mut dialog = Vec::new();
    let mut attachments = Vec::new();
    let mut analysis = Vec::new();
    let mut extensions: Vec<&'static str> = Vec::new();
    let mut signaling = Vec::with_capacity(all.len());
    let mut redacted = None;
    let mut kept_observer = None;

    for leg in all {
        let Vcon {
            vcon: _,
            uuid: _,
            created_at: _,
            updated_at: _,
            subject: _,
            redacted: leg_redacted,
            amended: _,
            extensions: leg_extensions,
            parties: leg_parties,
            dialog: leg_dialog,
            attachments: leg_attachments,
            analysis: leg_analysis,
        } = leg;
        let leg_observer = leg_parties.len().saturating_sub(1);
        let party_base = parties.len();
        let dialog_base = dialog.len();
        let party = |i: usize| {
            if i == leg_observer {
                observer
            } else {
                party_base + i
            }
        };
        let object = |i: usize| dialog_base + i;

        for (i, p) in leg_parties.into_iter().enumerate() {
            if i == leg_observer {
                kept_observer.get_or_insert(p);
            } else {
                parties.push(p);
            }
        }
        signaling.push(dialog_base);
        for d in leg_dialog {
            dialog.push(d.moved(&party, &object));
        }
        for mut a in leg_attachments {
            a.party = party(a.party);
            a.dialog = object(a.dialog);
            if a.purpose == MESSAGE_TRACE_PURPOSE {
                move_trace_parties(&mut a.body, &party);
            }
            attachments.push(a);
        }
        for mut a in leg_analysis {
            a.dialog = object(a.dialog);
            analysis.push(a);
        }
        for e in leg_extensions {
            if !extensions.contains(&e) {
                extensions.push(e);
            }
        }
        if redacted.is_none() {
            redacted = leg_redacted;
        }
    }
    parties.push(kept_observer.unwrap_or_else(observer_party));

    let start = dialog
        .first()
        .and_then(|d| d.start.clone())
        .unwrap_or_else(|| created_at.clone());
    let body = serde_json::json!({
        "legs": signaling.iter().map(|i| serde_json::json!({ "dialog": i })).collect::<Vec<_>>(),
        "ties": ties.iter().filter_map(|t| {
            Some(serde_json::json!({
                "dialogs": [signaling.get(t.from)?, signaling.get(t.to)?],
                "strategy": t.strategy,
                "identifier_match": t.identifier_match,
                "score": t.score,
            }))
        }).collect::<Vec<_>>(),
        "truncated": truncated,
    });
    attachments.push(Attachment {
        purpose: CALL_LEGS_PURPOSE,
        party: observer,
        dialog: 0,
        start,
        mediatype: "application/json",
        encoding: "json",
        body,
    });

    Some(Vcon {
        vcon: VCON_SYNTAX_VERSION,
        uuid,
        created_at,
        updated_at: None,
        subject,
        redacted,
        amended: None,
        extensions,
        parties,
        dialog,
        attachments,
        analysis,
    })
}

/// Pass every trace message's `party` through `party`, for
/// [`merge_call_legs`]: the index lives inside the body, where the
/// attachment's own remap does not reach.
fn move_trace_parties(body: &mut serde_json::Value, party: &impl Fn(usize) -> usize) {
    let Some(messages) = body["messages"].as_array_mut() else {
        return;
    };
    for message in messages {
        if let Some(index) = message["party"]
            .as_u64()
            .and_then(|i| usize::try_from(i).ok())
        {
            message["party"] = party(index).into();
        }
    }
}

impl Dialog {
    /// This object with every party index passed through `party` and every
    /// Dialog Object index through `object`, for [`merge_call_legs`].
    ///
    /// Destructured, so a new index field is a compile error here rather than
    /// an index left pointing into another leg.
    fn moved(self, party: &impl Fn(usize) -> usize, object: &impl Fn(usize) -> usize) -> Self {
        let Self {
            kind,
            session_id,
            transferor,
            transferee,
            transfer_target,
            original,
            consultation,
            disposition,
            sip_call_id,
            sip_from_tag,
            sip_to_tag,
            sip_cseq,
            start,
            duration,
            parties,
            originator,
            party_history,
            campaign,
            skill,
            interaction_id,
            dialogs,
            recording_set,
            mediatype,
            encoding,
            body,
            url,
            content_hash,
        } = self;
        Self {
            kind,
            session_id,
            transferor: transferor.map(party),
            transferee: transferee.map(party),
            transfer_target: transfer_target.map(party),
            original: original.map(object),
            consultation: consultation.map(object),
            disposition,
            sip_call_id,
            sip_from_tag,
            sip_to_tag,
            sip_cseq,
            start,
            duration,
            parties: parties.map(|p| p.into_iter().map(party).collect()),
            originator: originator.map(party),
            campaign,
            skill,
            interaction_id,
            party_history: party_history.map(|events| {
                events
                    .into_iter()
                    .map(|e| PartyEvent {
                        party: party(e.party),
                        ..e
                    })
                    .collect()
            }),
            dialogs: dialogs.map(|d| d.into_iter().map(object).collect()),
            recording_set: recording_set.map(object),
            mediatype,
            encoding,
            body,
            url,
            content_hash,
        }
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
    budget: usize,
) -> MediaVerdict {
    let (decoded, encoded) = match audio {
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
        ObservedAudio::WithheldByRedaction => {
            return MediaVerdict {
                outcome: MediaOutcome::WithheldByRedaction,
                note: None,
                refusal: None,
            };
        }
        ObservedAudio::Decoded(decoded) => (decoded, EncodedRecording::wav(decoded)),
        ObservedAudio::Encoded(decoded, encoded) => (decoded, encoded),
        ObservedAudio::Referenced(decoded, file) => {
            place_recording(
                dialog,
                decoded,
                objects,
                MediaBody::Url {
                    url: file.url,
                    mediatype: file.mediatype,
                    content_hash: content_hash(file.file),
                },
            );
            return MediaVerdict {
                outcome: MediaOutcome::Referenced,
                note: Some(decoded.note.clone()),
                refusal: None,
            };
        }
    };

    // The budget is on what the container carries: the encoded bytes, as
    // base64url, whatever format the rule chose.
    let body = URL_SAFE_NO_PAD.encode(encoded.bytes);
    if body.len() > budget {
        return MediaVerdict {
            outcome: MediaOutcome::RefusedOverBudget,
            note: Some(decoded.note.clone()),
            refusal: Some(format!(
                " — INCOMPLETE: sipnab decoded {:.1} second(s) of audio for this dialog and \
                 REFUSED to carry it: base64url of the {} byte {} is {} bytes, over the {} byte \
                 budget this emitter enforces because one probed vCon store answers 204 and drops \
                 the payload without telling the producer. The audio was NOT truncated and is not \
                 in this container; export it beside this file with the export_audio MCP tool.",
                decoded.duration_secs,
                encoded.bytes.len(),
                encoded.format,
                body.len(),
                budget,
            )),
        };
    }

    place_recording(
        dialog,
        decoded,
        objects,
        MediaBody::Inline {
            body: &body,
            mediatype: encoded.mediatype,
            content_hash: content_hash(encoded.bytes),
        },
    );

    MediaVerdict {
        outcome: MediaOutcome::Carried,
        note: Some(decoded.note.clone()),
        refusal: None,
    }
}

/// Where a recording's bytes are, inline as base64url or at a URL, with the
/// `mediatype` and `content_hash` the object names.
#[derive(Debug, Clone)]
enum MediaBody<'a> {
    /// The file, base64url-encoded, in `body`. The hash is over the file.
    Inline {
        /// The base64url text.
        body: &'a str,
        /// The file's media type.
        mediatype: &'static str,
        /// [`content_hash`] of the file.
        content_hash: String,
    },
    /// The file is served at this URL; the object carries its hash only,
    /// over the file's bytes as written.
    Url {
        /// Where the operator's storage serves the file.
        url: &'a str,
        /// The media type of the recording the file holds.
        mediatype: &'static str,
        /// [`content_hash`] of the file as written.
        content_hash: String,
    },
}

impl MediaBody<'_> {
    /// Fill `object`'s media fields: `mediatype` and `content_hash`, then
    /// `body` and `encoding` inline, or `url`.
    fn fill(self, object: &mut Dialog) {
        match self {
            Self::Inline {
                body,
                mediatype,
                content_hash,
            } => {
                object.mediatype = Some(mediatype.into());
                object.content_hash = Some(content_hash);
                object.encoding = Some("base64url");
                object.body = Some(body.to_string());
            }
            Self::Url {
                url,
                mediatype,
                content_hash,
            } => {
                object.mediatype = Some(mediatype.into());
                object.content_hash = Some(content_hash);
                object.url = Some(url.to_string());
            }
        }
    }
}

/// Put the decoded audio into `objects` as a recording, inline or by URL.
fn place_recording(
    dialog: &SipDialog,
    decoded: &DialogAudio,
    objects: &mut Vec<Dialog>,
    media: MediaBody<'_>,
) {
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
        objects.push(recording_object(dialog, decoded, media, 0));
    } else {
        let signaling = &mut objects[0];
        // Enriched in place, and RETYPED: it carries audio now, so it is a
        // `recording`. Leaving it `incomplete` would park a WAV on an object
        // every `type == "recording"` selector skips — the audio would be
        // present in the container and unreachable by the consumers that want
        // it. `disposition` goes with the retype, being an `incomplete` field.
        // What the call DID is not lost: `final_status_code` rides in the
        // analysis body, which is where an outcome belongs.
        signaling.kind = RECORDING_TYPE;
        signaling.disposition = None;
        signaling.start = Some(decoded.first_retained.to_rfc3339());
        signaling.duration = Some(decoded.duration_secs);
        signaling.parties = channel_parties(dialog, decoded);
        media.fill(signaling);
    }
}

/// The `recording` Dialog Object — the FILE's clock, and the file.
fn recording_object(
    dialog: &SipDialog,
    audio: &DialogAudio,
    media: MediaBody<'_>,
    recording_set: usize,
) -> Dialog {
    let mut object = Dialog {
        start: Some(audio.first_retained.to_rfc3339()),
        duration: Some(audio.duration_secs),
        // §4.3.7's SHOULD: the member names the set it belongs to, so a
        // consumer holding the audio can reach the call's clock.
        recording_set: Some(recording_set),
        parties: channel_parties(dialog, audio),
        ..Dialog::bare(RECORDING_TYPE, dialog.call_id.clone())
    };
    media.fill(&mut object);
    object
}

/// The `recording-set` wrapper — the CALL's clock, for the ring-wrapped case
/// only.
///
/// [Section 4.3.3 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3) is the only place vCon can say "this
/// file is a fragment of that call": the set's `start` and `duration` describe
/// the media window sipnab observed, while the `recording` it points at
/// describes the part that survived retention. Nothing obliges a consumer to
/// compare them, which is why the caveat is duplicated as well and not instead.
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
        start: Some(audio.media_start.to_rfc3339()),
        // Milliseconds to seconds, keeping the fraction: a call rounded to a
        // whole second could equal the file's duration and hide exactly the
        // difference this object exists to show.
        duration: Some(span as f64 / 1000.0),
        dialogs: Some(vec![member]),
        ..Dialog::bare(RECORDING_SET_TYPE, dialog.call_id.clone())
    }
}

/// `sha512-` followed by the base64url SHA-512 of the media bytes, per
/// [section 2.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.2).
///
/// Over the WAV, never over its base64url text. An operator who exported the
/// same call with the `export_audio` MCP tool can run `sha512sum` on the file and get a
/// value that maps to this one; a digest of the encoded text is a number
/// nothing outside this container could reproduce.
pub fn content_hash(media: &[u8]) -> String {
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
/// All or nothing, deliberately. [Section 4.3.4 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4) has a
/// null placeholder and it means "no party on this channel", not "sipnab could
/// not tell" — using it for the second would state, about a channel full of
/// audio, that nobody was on it. And a partly-attributed list invites a reader
/// to fill in the rest.
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
        .map(|key| advertised_party(&advertised, key.src))
        .collect()
}

/// The party that advertised `socket` for itself, the first in message order
/// when several did; `None` when none did.
fn advertised_party(
    advertised: &[(std::net::SocketAddr, usize)],
    socket: std::net::SocketAddr,
) -> Option<usize> {
    advertised
        .iter()
        .find(|(advertised, _)| *advertised == socket)
        .map(|(_, party)| *party)
}

/// The party that sent an RTP telephone event from `src` to `dst`, in a
/// dialog of `parties` observed parties, or `None` when the evidence does not
/// name one.
///
/// - The party that advertised `src` for itself sent it, the evidence the
///   audio channels are attributed by (see [`channel_parties`]).
/// - Otherwise the destination decides, the same SDP endpoint that links the
///   stream to its dialog: the party that advertised `dst` received the event,
///   so in a two-party dialog the other party sent it.
/// - `None` when the destination was advertised by no party or by both, or
///   the dialog has other than two parties: no single receiver, so no sender
///   to infer.
fn key_press_party(
    advertised: &[(std::net::SocketAddr, usize)],
    parties: usize,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
) -> Option<usize> {
    if let Some(sender) = advertised_party(advertised, src) {
        return Some(sender);
    }
    if parties != 2 {
        return None;
    }
    let receiver = advertised_party(advertised, dst)?;
    let single = advertised
        .iter()
        .all(|(socket, party)| *socket != dst || *party == receiver);
    (single && receiver < 2).then(|| 1 - receiver)
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
            tel: tel_uri(dialog.from_user.as_deref()),
            validation: "none",
            role: None,
            name: dialog.from_display.clone(),
            // The `Identity` header authenticates the CALLER. Attaching it to
            // the callee would invent an attestation for a party the
            // authentication service said nothing about.
            stir: first
                .and_then(|m| m.header("Identity"))
                .and_then(passport_of),
            sip_display_name: dialog.from_display.clone(),
            // From the OPENING message only. A `Contact`/`User-Agent` taken
            // from the latest message in the ladder would attribute a
            // responder's headers to the caller.
            sip_contact: first.and_then(|m| m.contact().map(str::to_string)),
            sip_user_agent: first.and_then(|m| m.user_agent().map(str::to_string)),
        },
        Party {
            sip: sip_uri(dialog.to_user.as_deref(), dialog.to_host.as_deref()),
            tel: tel_uri(dialog.to_user.as_deref()),
            validation: "none",
            role: None,
            name: dialog.to_display.clone(),
            stir: None,
            sip_display_name: dialog.to_display.clone(),
            // Only from messages the callee itself sent. A proxy's `100`, or
            // any response without the dialog's remote tag, describes some
            // other element, so its `Server` is not the callee's software.
            sip_contact: callee_messages(dialog).find_map(|m| m.contact().map(str::to_string)),
            sip_user_agent: callee_messages(dialog)
                .find_map(|m| m.user_agent().map(str::to_string)),
        },
    ]
}

/// The messages in the ladder that the callee itself sent, in order.
///
/// See [`sent_by_callee`] for the rule.
fn callee_messages(dialog: &SipDialog) -> impl Iterator<Item = &crate::sip::SipMessage> {
    let remote_tag = dialog.to_tag.as_deref();
    dialog
        .messages
        .iter()
        .filter(move |m| sent_by_callee(m, remote_tag))
}

/// Whether `m` was sent by the callee whose `To` tag is `remote_tag`.
///
/// A response counts when its status is 101 or higher and its `To` tag is the
/// dialog's remote tag. A `100 Trying` is excluded because a proxy generates
/// it hop by hop and never forwards one
/// ([RFC 3261 section 16.7](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.7)),
/// so its `Server` header names the proxy. A response with another tag, or
/// none, came from another element or another fork. A request counts when its
/// `From` tag is the remote tag, such as the callee's `BYE`. With no remote
/// tag observed, nothing is attributed to the callee.
fn sent_by_callee(m: &crate::sip::SipMessage, remote_tag: Option<&str>) -> bool {
    let Some(remote) = remote_tag else {
        return false;
    };
    if m.is_request {
        m.from_tag() == Some(remote)
    } else {
        m.status_code.is_some_and(|c| c > 100) && m.to_tag() == Some(remote)
    }
}

/// The party representing sipnab itself.
///
/// Carries no `sip` URI: sipnab sent no SIP and a synthesized URI would be a
/// participant that never existed. What it does carry is `role: "observer"`
/// and its own software identity, which together are what an attachment's
/// `party` index has to resolve to for the provenance
/// [core-04 section 4.4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.4.3) asks for to mean anything.
fn observer_party() -> Party {
    Party {
        sip: None,
        // The observer is not reachable at a number. Supplying one would put
        // sipnab in the conserver's party index as a participant.
        tel: None,
        validation: "none",
        role: Some(OBSERVER_ROLE),
        // The observer is not a named participant, and it authenticated
        // nothing.
        name: None,
        stir: None,
        sip_display_name: None,
        sip_contact: None,
        sip_user_agent: Some(format!(
            "sipnab/{} (observer; node {})",
            env!("CARGO_PKG_VERSION"),
            node_name()
        )),
    }
}

/// A `tel:` URI, but only when the SIP user part is unambiguously one.
///
/// The conserver indexes parties by `tel`, `mailto` and `name` and by nothing
/// else, so a container with none of the three is fetchable by UUID and
/// invisible to its party search. `tel` is the only one of the three sipnab
/// can supply from evidence: `name` is a deliberate refusal, and no capture
/// carries an email address.
///
/// The rule is narrow on purpose. RFC 3966 global numbers start with `+` and
/// are unambiguous; a bare digit run is a LOCAL number that needs a
/// `phone-context` to mean anything, and most SIP user parts that look like
/// digits are extensions — `1001` is not a telephone number, and indexing it
/// as one would put a wrong answer in a search index rather than no answer.
/// So: `+` followed by digits, or nothing.
fn tel_uri(user: Option<&str>) -> Option<String> {
    let user = user?;
    let digits = user.strip_prefix('+')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("tel:+{digits}"))
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

/// The signaling Dialog Object: what one observed dialog was, with no content.
///
/// `type` is a closed enum — `recording`, `text`, `transfer`, `incomplete`,
/// `recording-set` — and [core-04 section 4.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1) requires
/// it on every Dialog Object. [core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) gives a
/// dialog known to have occurred, with little or nothing captured from it, a
/// placeholder: `recording` if the call was set up, `incomplete` if it was
/// not. Its content is absent, which core-04 section 4.3.8 and Table 1 note
/// (1) allow without a `mediatype`.
///
/// `incomplete` is the trap: [core-04 section 4.3.1.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.5)
/// makes it mean the CALL failed to set up, so emitting it because sipnab did
/// not capture an answer would state a fact about the conversation from a
/// limit of the capture. That is the exact collapse this project refuses
/// everywhere else. So `incomplete` is kept for an OBSERVED final failure, and
/// every other outcome — answered, no final response seen, redirected — is the
/// `recording` placeholder. The completeness carrier says in plain words when
/// no media traveled.
fn dialog_object(dialog: &SipDialog, start: String) -> Dialog {
    // The failure reason, decided once. `None` covers three different cases
    // -- the call succeeded, no final response was seen, or the final response
    // was a redirect -- and all three share the same property: sipnab observed
    // no failure, so no failure may be reported.
    let caller_canceled = dialog
        .messages
        .iter()
        .any(|m| m.is_request && m.method == Some(crate::sip::SipMethod::Cancel));
    let failure = dialog
        .final_status_code()
        .and_then(|code| failure_disposition(code, caller_canceled));

    Dialog {
        // At construction this object carries no content: it is the core-04
        // section 4.3 placeholder for a dialog known to have occurred. Media
        // enrichment fills it in place when audio actually arrives.
        //
        // `incomplete` was once the choice for every outcome and is wrong for
        // a call that connected: core-04 section 4.3.1.5 binds that value to
        // a call that "failed to be setup", so a signaling-only export of a
        // ninety-second conversation shipped a container asserting the call
        // never happened. It is reserved for the case that genuinely is one.
        //
        // core-03 let this object name no type at all ("a Dialog Object with
        // no parameters in it"), and sipnab used that from 0.5.128. core-04
        // removed the sentence and makes the placeholder `recording`. A
        // conserver link that selects `type == "recording"` and reads
        // `dialog["url"]` with a bracket raises on it; that link raised on the
        // type-free object too, at `dialog["type"]`. docs/vcon.md records the
        // measurement.
        sip_from_tag: dialog.from_tag.clone(),
        sip_to_tag: dialog.to_tag.clone(),
        sip_cseq: creating_cseq(dialog),
        session_id: session_id_of(dialog),
        // ONE decision drives both fields, because core-04 sections 4.3.1.5
        // and 4.3.11 couple them: an `incomplete` object MUST carry a
        // disposition, and a disposition is only nameable when a failure was
        // actually observed. Only an OBSERVED final failure names a reason;
        // its absence says nothing failed that sipnab saw, which is not the
        // same as success.
        disposition: failure,
        start: Some(start),
        // core-04 Table 1: `parties` SHOULD be present on a `recording` and
        // is optional on an `incomplete`, where it names the parties the
        // setup was attempted between. These are the indices of the `From`
        // and `To` parties `observed_parties` built, in that order.
        parties: Some(vec![0, 1]),
        duration: conversation_secs(dialog),
        ..Dialog::bare(
            failure.map_or(RECORDING_TYPE, |_| INCOMPLETE_TYPE),
            dialog.call_id.clone(),
        )
    }
}

/// Whether the dialog's first observed message is the dialog-creating request.
///
/// A request with no `To` tag is outside any dialog
/// ([RFC 3261 section 8.1.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.2)),
/// so its `From` is the party that originated this one. A tagged request or a
/// response first means the capture joined after setup, and its `From` names
/// whoever sent that one transaction, which may be either party.
fn opened_by_the_caller(dialog: &SipDialog) -> bool {
    dialog
        .messages
        .first()
        .is_some_and(|m| m.is_request && m.to_tag().is_none())
}

/// One RFC 4733 telephone event, as the RTP decoder saw its end packet.
#[derive(Debug, Clone)]
pub struct RtpKeyPress {
    /// The socket the event's packets came from.
    pub src: std::net::SocketAddr,
    /// The socket the event's packets were sent to.
    pub dst: std::net::SocketAddr,
    /// The digit the event names.
    pub digit: char,
    /// When sipnab captured the packet that ended the event (E bit set).
    pub ended_at: DateTime<Utc>,
    /// The event's duration from that packet, in milliseconds
    /// ([RFC 4733 section 2.5.1.3](https://www.rfc-editor.org/rfc/rfc4733.html#section-2.5.1.3)).
    pub duration_ms: u32,
}

/// Add `keydown` and `keyup` events ([core-04 section 4.3.13.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.13.1))
/// to a one-leg container's signaling object, with the digit as `button`.
///
/// - An in-dialog INFO with `Content-Type: application/dtmf-relay` is a
///   `keydown` at the INFO, for its sender, and a `keyup` `Duration`
///   milliseconds later when the body states one. The digit is the
///   `Signal` value.
/// - An RFC 4733 event in `rtp` is a `keyup` at its end packet and a
///   `keydown` its duration before, for the party whose own SDP advertised
///   the event's source socket. When no party advertised the source, the
///   party that advertised the destination socket received the event and the
///   other party of the two sent it (see `key_press_party`).
///
/// An INFO whose tags match neither party, or an event whose source no party
/// advertised and whose destination no single party advertised, adds
/// nothing. The events join the existing history in time order.
///
/// A rule asks for these with `dtmf_events`, because a digit can be a PIN.
/// Redaction removes them (see the `Dialog` redaction).
pub fn add_key_events(container: &mut Vcon, dialog: &SipDialog, rtp: &[RtpKeyPress]) {
    let mut added: Vec<(DateTime<Utc>, PartyEvent)> = Vec::new();
    let mut press = |party: usize, down: DateTime<Utc>, up: Option<DateTime<Utc>>, digit: &str| {
        let key = |at: DateTime<Utc>, event: &'static str| PartyEvent {
            button: Some(digit.to_string()),
            ..PartyEvent::at(party, at, event)
        };
        added.push((down, key(down, "keydown")));
        if let Some(up) = up {
            added.push((up, key(up, "keyup")));
        }
    };

    for m in &dialog.messages {
        let is_relay = m.is_request
            && m.method.as_ref() == Some(&crate::sip::SipMethod::Info)
            && m.content_type().is_some_and(|ct| {
                ct.to_ascii_lowercase()
                    .starts_with("application/dtmf-relay")
            });
        if !is_relay {
            continue;
        }
        let (Some(party), Some((digit, duration))) = (sender_party(dialog, m), dtmf_relay(&m.body))
        else {
            continue;
        };
        let up = duration.map(|ms| m.timestamp + chrono::TimeDelta::milliseconds(i64::from(ms)));
        press(party, m.timestamp, up, &digit);
    }

    let advertised = advertised_media_endpoints(dialog);
    let parties = observed_parties(dialog).len();
    for event in rtp {
        let Some(party) = key_press_party(&advertised, parties, event.src, event.dst) else {
            continue;
        };
        let down = event.ended_at - chrono::TimeDelta::milliseconds(i64::from(event.duration_ms));
        press(party, down, Some(event.ended_at), &event.digit.to_string());
    }

    if added.is_empty() {
        return;
    }
    let Some(signaling) = container.dialog.first_mut() else {
        return;
    };
    let mut timed: Vec<(DateTime<Utc>, PartyEvent)> = signaling
        .party_history
        .take()
        .unwrap_or_default()
        .into_iter()
        .map(|e| {
            let at = DateTime::parse_from_rfc3339(&e.time)
                .map_or(DateTime::<Utc>::MIN_UTC, |t| t.with_timezone(&Utc));
            (at, e)
        })
        .collect();
    timed.extend(added);
    timed.sort_by_key(|(at, _)| *at);
    signaling.party_history = Some(timed.into_iter().map(|(_, e)| e).collect());
}

/// The digit and the duration in milliseconds of an `application/dtmf-relay`
/// body: `Signal=5` and `Duration=160` lines. `None` without a `Signal`.
fn dtmf_relay(body: &[u8]) -> Option<(String, Option<u32>)> {
    let text = std::str::from_utf8(body).ok()?;
    let value = |name: &str| {
        text.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };
    let digit = value("Signal").filter(|d| !d.is_empty())?;
    let duration = value("Duration").and_then(|d| d.parse().ok());
    Some((digit, duration))
}

/// One `text` Dialog Object ([core-04 section 4.3.1.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.3))
/// per SIP MESSAGE ([RFC 3428](https://www.rfc-editor.org/rfc/rfc3428.html))
/// that carried content.
///
/// - One per sender tag and CSeq number: a retransmission is the same text,
///   and each direction numbers its own requests.
/// - `start` is when sipnab captured the first transmission; core-04 section
///   4.3.2 makes that the start of a text when the typing time is not known.
/// - `parties` is the sender, then the other party, when the message's tag
///   names the sender (see [`sender_party`]), so `originator` is never
///   needed (core-04 section 4.3.5: for text, the originator is the sender).
///   Absent when the tag names neither party.
/// - `mediatype` is the message's `Content-Type`, as written. The body is
///   inline: the text with `encoding: "none"` when it is UTF-8, otherwise
///   base64url.
/// - A MESSAGE with no body, or whose `Content-Type` is
///   `application/im-iscomposing+xml` (an RFC 3994 typing indication rather
///   than text a party sent), is not a text dialog.
///
/// MSRP is not parsed by sipnab, so a session that carries its text over
/// MSRP has no text dialog.
fn text_dialogs_of(dialog: &SipDialog) -> Vec<Dialog> {
    let mut seen: Vec<(Option<&str>, u32)> = Vec::new();
    let mut texts = Vec::new();
    for m in &dialog.messages {
        let is_text = m.is_request
            && m.method.as_ref() == Some(&crate::sip::SipMethod::Message)
            && !m.body.is_empty()
            && !m.content_type().is_some_and(|ct| {
                ct.to_ascii_lowercase()
                    .starts_with("application/im-iscomposing+xml")
            });
        if !is_text {
            continue;
        }
        if let Some((cseq, _)) = m.cseq() {
            let key = (m.from_tag(), cseq);
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
        }
        let (encoding, body) = match std::str::from_utf8(&m.body) {
            Ok(text) => ("none", text.to_string()),
            Err(_) => ("base64url", URL_SAFE_NO_PAD.encode(&m.body)),
        };
        texts.push(Dialog {
            start: Some(m.timestamp.to_rfc3339()),
            parties: sender_party(dialog, m).map(|sender| vec![sender, 1 - sender]),
            mediatype: Some(
                m.content_type()
                    .unwrap_or("text/plain")
                    .trim()
                    .to_string()
                    .into(),
            ),
            encoding: Some(encoding),
            body: Some(body),
            ..Dialog::bare(TEXT_TYPE, dialog.call_id.clone())
        });
    }
    texts
}

/// The join, drop, hold and unhold events the capture shows, in time order,
/// for [`Dialog::party_history`].
///
/// - `join`: both parties, at the 200 to the initial INVITE, when the capture
///   holds that INVITE and its 200 (the rule [`conversation_secs`] uses).
/// - `drop`: the sender of the first BYE, at the BYE, and the other party at
///   the 2xx answering it, when captured.
/// - `hold` and `unhold`: an in-dialog INVITE or UPDATE whose first audio
///   media description is `sendonly` or `inactive` puts the OTHER party on
///   hold, at the request's capture time. A later `sendrecv` from the same
///   sender takes it off hold. `recvonly` changes nothing.
///
/// A message whose tags match neither party yields no event: the `party`
/// would be a guess. `None` when there is no event.
fn party_history_of(dialog: &SipDialog) -> Option<Vec<PartyEvent>> {
    let mut events: Vec<(DateTime<Utc>, PartyEvent)> = Vec::new();
    if dialog.timing.invite_sent.is_some()
        && let Some(answered) = dialog.timing.answered_at
    {
        for party in [0, 1] {
            events.push((answered, PartyEvent::at(party, answered, "join")));
        }
    }

    let is = |m: &crate::sip::SipMessage, method: crate::sip::SipMethod| {
        m.is_request && m.method.as_ref() == Some(&method)
    };
    if let Some(bye) = dialog
        .messages
        .iter()
        .find(|m| is(m, crate::sip::SipMethod::Bye))
        && let Some(sender) = sender_party(dialog, bye)
    {
        events.push((bye.timestamp, PartyEvent::at(sender, bye.timestamp, "drop")));
        let bye_cseq = bye.cseq().map(|(n, _)| n);
        if let Some(answer) = dialog.messages.iter().find(|m| {
            !m.is_request
                && m.status_code.is_some_and(|c| (200..300).contains(&c))
                && m.cseq()
                    .is_some_and(|(n, method)| Some(n) == bye_cseq && method == "BYE")
        }) {
            events.push((
                answer.timestamp,
                PartyEvent::at(1 - sender, answer.timestamp, "drop"),
            ));
        }
    }

    let mut held = [false, false];
    for m in &dialog.messages {
        let reoffer = (is(m, crate::sip::SipMethod::Invite) && m.to_tag().is_some())
            || is(m, crate::sip::SipMethod::Update);
        if !reoffer {
            continue;
        }
        let (Some(sender), Some(direction)) = (sender_party(dialog, m), audio_direction(m)) else {
            continue;
        };
        let other = 1 - sender;
        use crate::sip::sdp::SdpDirection;
        match direction {
            SdpDirection::SendOnly | SdpDirection::Inactive if !held[other] => {
                held[other] = true;
                events.push((m.timestamp, PartyEvent::at(other, m.timestamp, "hold")));
            }
            SdpDirection::SendRecv if held[other] => {
                held[other] = false;
                events.push((m.timestamp, PartyEvent::at(other, m.timestamp, "unhold")));
            }
            _ => {}
        }
    }

    events.sort_by_key(|(at, _)| *at);
    (!events.is_empty()).then(|| events.into_iter().map(|(_, e)| e).collect())
}

/// The direction of the first audio media description in a message's SDP.
fn audio_direction(m: &crate::sip::SipMessage) -> Option<crate::sip::sdp::SdpDirection> {
    let session = crate::sip::sdp::parse_sdp(&m.body).ok()?;
    session
        .media
        .iter()
        .find(|media| media.media_type == "audio")
        .map(|media| media.direction)
}

/// The CSeq number of the dialog-creating request, when the capture holds it
/// as the dialog's first message (see [`opened_by_the_caller`]).
fn creating_cseq(dialog: &SipDialog) -> Option<u32> {
    if !opened_by_the_caller(dialog) {
        return None;
    }
    dialog.messages.first()?.cseq().map(|(number, _)| number)
}

/// The empty Party Object [core-04 section 4.3.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.5)
/// uses for an originator that is not known: "If the originator is not known,
/// an empty Party Object ... may be used as ... the party referenced by the
/// originator parameter". It carries only `validation: "none"`, which every
/// sipnab party carries.
fn unknown_originator_party() -> Party {
    Party {
        sip: None,
        tel: None,
        validation: "none",
        role: None,
        name: None,
        stir: None,
        sip_display_name: None,
        sip_contact: None,
        sip_user_agent: None,
    }
}

/// Set `originator` on every object whose `parties` does not list the caller
/// first, per [core-04 section 4.3.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.5).
///
/// An object with no `parties`, such as a transfer, where core-04 Table 1
/// forbids `originator`, is left alone.
fn name_the_originator(objects: &mut [Dialog], caller: usize) {
    for object in objects {
        if let Some(parties) = &object.parties {
            object.originator = (parties.first() != Some(&caller)).then_some(caller);
        }
    }
}

/// The conversation's length in seconds, from the answer to the initial
/// INVITE to the BYE, for the signaling object's `duration`
/// ([core-04 section 4.3.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3)).
///
/// `None` unless the capture holds the initial INVITE, its 200 and a BYE: an
/// uncaptured INVITE leaves the 200 unattributable to the initial
/// transaction, and an absent BYE means the end is not known.
fn conversation_secs(dialog: &SipDialog) -> Option<f64> {
    dialog.timing.invite_sent?;
    let ms = dialog.timing.conversation_ms()?;
    Some(ms as f64 / 1000.0)
}

/// The JWS alone from an RFC 8224 `Identity` header value.
///
/// The header is `<token>;info=<...>;alg=...;ppt=shaken`. The `stir` parameter
/// of [core-04 section 4.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.2.3) carries the PASSporT "in the JWS Compact
/// Serialization form", which is the token and nothing else — a consumer handed
/// the whole header value cannot parse it as a token, and the parameters
/// describe where to FETCH the certificate rather than forming part of the
/// credential.
///
/// Shape-checked, not verified: three dot-separated non-empty segments is what
/// JWS Compact Serialization is. Anything else is not a PASSporT and is
/// dropped rather than passed on as one. That is the only judgement made here;
/// no certificate is fetched and no signature is checked.
fn passport_of(identity: &str) -> Option<String> {
    let token = identity.split(';').next()?.trim();
    let mut parts = token.split('.');
    let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || a.is_empty() || b.is_empty() || c.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// The RFC 7989 pair, from the first message that carried the header.
///
/// Malformed halves yield `None` rather than a transcribed string:
/// `SessionIdHalf::uuid` answers `None` for `nil` and for anything that is not
/// a UUID, and a correlation field holding a value nothing can join on is
/// worse than an absent one.
fn session_id_of(dialog: &SipDialog) -> Option<SessionIdPair> {
    let raw = dialog
        .messages
        .iter()
        .find_map(|m| m.header("Session-ID"))?;
    let parsed = crate::sip::session_id::SessionId::parse(raw)?;
    let pair = SessionIdPair {
        local: parsed.local.uuid().map(str::to_string),
        remote: parsed
            .remote
            .as_ref()
            .and_then(|h| h.uuid())
            .map(str::to_string),
    };
    // Both halves unusable means the header carried nothing joinable.
    (pair.local.is_some() || pair.remote.is_some()).then_some(pair)
}

/// `subject` ([core-04 section 4.1.7](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.7)) — what this container is about,
/// descriptively.
///
/// A store whose search matches subject or UUID substring can otherwise find a
/// sipnab container only by a UUIDv8 nobody has memorized. This names the
/// dialog and stops there: an observer is in no position to characterize what
/// a conversation was ABOUT, and a subject that tried would be the one field
/// in the container asserting something nothing measured.
fn subject_of(dialog: &SipDialog) -> String {
    format!("SIP call {}", dialog.call_id)
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
///
/// `487 Request Terminated` after a CANCEL sipnab observed (`caller_canceled`)
/// is the caller giving up while the call rang:
/// [section 4.3.11 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11)
/// defines "\"no-answer\" - a call or connection was attempted, but no one
/// answered or accepted the connection". It is not "hung-up", which the same
/// section defines as "a call or connection was made, but the party hung-up
/// before any conversation occurred": the call was never made. A 487 without
/// an observed CANCEL stays "failed", because "If the reason that the call or
/// conversation failed is not known ... the disposition value \"failed\"
/// SHOULD be used". sipnab never emits "hung-up": an answered call is not an
/// `incomplete` Dialog Object, and the section says disposition "SHOULD NOT
/// be present for other dialog types".
fn failure_disposition(code: u16, caller_canceled: bool) -> Option<&'static str> {
    match code {
        487 if caller_canceled => Some("no-answer"),
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
            // The headers ride BESIDE the shared `--json` projection rather
            // than inside it: the projection is what a vCon and an NDJSON line
            // must agree about, and this adds to the container without moving
            // that line. The `sip-signaling` extension names `headers` in its
            // message structure, and a SIP trace without them is a summary of
            // a trace.
            //
            // This is also what makes `strip_credentials` do work. Until the
            // headers arrived it filtered a projection that carried no
            // `Authorization` to remove, so `no_credential_survives_an_export`
            // passed because the field did not exist — a regression gate for
            // something that could not regress. Emitting them and stripping
            // them is one change, deliberately: the field and the filter that
            // makes it safe to publish must never land apart.
            if let Some(map) = value.as_object_mut() {
                map.insert("headers".to_string(), header_map(m));
                // `extension_headers` is the SAME headers in a shape this
                // boundary cannot police: a list of `"Name: value"` strings
                // hides every credential behind an array index, where a
                // filter keyed on object keys can never reach it. That is the
                // exact failure `header_map` documents and exists to avoid,
                // and it is why the map replaces the list here rather than
                // sitting beside it. Nothing is lost — every entry of the
                // list is a key of the map, which
                // `the_header_map_carries_every_header_the_list_would_have`
                // pins.
                map.remove("extension_headers");
                draft_message_fields(map, dialog, m);
            }
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
        //
        // `version` is the string "1.0", the trace format version
        // draft-howe-vcon-sip-signaling-00 section 6.2.1 defines. It was the
        // number 1 until the per-message fields below joined the body; a
        // reader of sipnab's own shape reads `schema_version`, which is
        // unchanged.
        body: serde_json::json!({
            "version": TRACE_FORMAT_VERSION,
            "call_id": dialog.call_id,
            "schema_version": DIAGNOSIS_SCHEMA_VERSION,
            "sip_call_id": dialog.call_id,
            "messages": messages,
        }),
    }
}

/// The trace format version [draft-howe-vcon-sip-signaling-00 section 6.2.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-6.2.1)
/// defines: "This document defines version \"1.0\"".
pub const TRACE_FORMAT_VERSION: &str = "1.0";

/// Add the per-message fields of the draft's trace format to one projected
/// message, beside sipnab's own.
///
/// [draft-howe-vcon-sip-signaling-00 section 6.2.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-6.2.1)
/// names `timestamp`, `direction`, `party`, `method`, `status_code`,
/// `status_text`, `headers` and `body`. The projection already carries
/// `timestamp`, `method` (requests only), `status_code` (responses only) and
/// `reason`; this adds the rest.
///
/// - `direction` is `"received"` on every message. The draft defines it "from
///   the perspective of the vCon producer", and sipnab sent nothing: every
///   message is a copy it received from the tap.
/// - `party` is the sender's index when the message's tag names a party (see
///   [`sender_party`]), and absent otherwise, which the draft allows "when
///   the sender cannot be determined".
/// - `status_text` is the reason phrase, on a response only.
/// - `body` is the message body when it has one: the text when it is UTF-8,
///   otherwise base64url with `body_encoding: "base64url"`, as the draft says
///   for binary bodies.
fn draft_message_fields(
    map: &mut serde_json::Map<String, serde_json::Value>,
    dialog: &SipDialog,
    m: &crate::sip::SipMessage,
) {
    map.insert("direction".into(), "received".into());
    if let Some(party) = sender_party(dialog, m) {
        map.insert("party".into(), party.into());
    }
    if !m.is_request
        && let Some(reason) = &m.reason
    {
        map.insert("status_text".into(), reason.clone().into());
    }
    if !m.body.is_empty() {
        match std::str::from_utf8(&m.body) {
            Ok(text) => {
                map.insert("body".into(), text.into());
            }
            Err(_) => {
                map.insert("body".into(), URL_SAFE_NO_PAD.encode(&m.body).into());
                map.insert("body_encoding".into(), "base64url".into());
            }
        }
    }
}

/// `purpose` of the initial INVITE in wire format,
/// [draft-howe-vcon-sip-signaling-00 section 6.1.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-6.1.1).
pub const SIP_INVITE_PURPOSE: &str = "sip-invite";

/// `purpose` of a SIP response in wire format,
/// [draft-howe-vcon-sip-signaling-00 section 6.1.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-6.1.1).
pub const SIP_RESPONSE_PURPOSE: &str = "sip-response";

/// `purpose` of an SDP body,
/// [draft-howe-vcon-sip-signaling-00 section 6.3](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-6.3).
pub const SIP_SDP_PURPOSE: &str = "sip-sdp";

/// The media type of a SIP message in wire format, which section 6.1.2 makes a
/// MUST.
const MESSAGE_SIP_MEDIATYPE: &str = "message/sip";

/// The media type of an SDP attachment, which section 6.3 makes a MUST.
const SDP_MEDIATYPE: &str = "application/sdp";

/// Whether an attachment carries wire bytes or an SDP body, which redaction
/// removes (see [`add_sip_message_attachments`]).
fn is_wire_attachment(attachment: &Attachment) -> bool {
    [SIP_INVITE_PURPOSE, SIP_RESPONSE_PURPOSE, SIP_SDP_PURPOSE].contains(&attachment.purpose)
}

/// Add the minimal producer's attachments of
/// [draft-howe-vcon-sip-signaling-00 section 8.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-8.1)
/// to a one-leg container: the initial INVITE and its final response as
/// `message/sip` (sections 6.1.1 and 6.1.2), and each one's SDP body as
/// `application/sdp` (section 6.3).
///
/// Which messages:
///
/// - The final response is the first transmission of the last final (200 to
///   699) response to an INVITE that carried no `To` tag. After a `407`
///   challenge that is the answer to the re-sent INVITE.
/// - The INVITE is the first transmission of the request with that
///   response's CSeq number. With no final response it is the last initial
///   INVITE.
///
/// Each attachment names the party whose tag the message carries, and the
/// observer when the tag matches neither party (a proxy's own response).
/// `start` is when sipnab captured the message, and `dialog` is 0, the
/// signaling object.
///
/// The bytes are the message as captured, with every credential-bearing
/// header line ([`CREDENTIAL_HEADERS`]) removed, as the trace removes them.
/// UTF-8 bytes use the `none` encoding; anything else is base64url, as
/// section 6.1.2 requires.
///
/// `budget` is the rule's inline budget in bytes, for these attachments
/// together. An attachment that does not fit is left out and named, with its
/// size, in the completeness attachment's `sip_messages_refused`.
///
/// Redaction removes all three kinds (see `is_wire_attachment`): the bytes
/// hold every identifier the trace holds, in a form redaction cannot rewrite
/// without changing the message they are a copy of.
pub fn add_sip_message_attachments(container: &mut Vcon, dialog: &SipDialog, budget: usize) {
    let observer = container.observer_index();
    let (invite, response) = minimal_exchange(dialog);
    let mut wanted: Vec<Attachment> = Vec::new();
    for (purpose, message) in [
        (SIP_INVITE_PURPOSE, invite),
        (SIP_RESPONSE_PURPOSE, response),
    ] {
        let Some(m) = message else { continue };
        let party = sender_party(dialog, m).unwrap_or(observer);
        let start = m.timestamp.to_rfc3339();
        let (encoding, body) = inline_text(&without_credentials(&m.raw));
        wanted.push(Attachment {
            purpose,
            party,
            dialog: 0,
            start: start.clone(),
            mediatype: MESSAGE_SIP_MEDIATYPE,
            encoding,
            body,
        });
        if m.content_type()
            .is_some_and(|ct| ct.to_ascii_lowercase().starts_with(SDP_MEDIATYPE))
            && !m.body.is_empty()
        {
            let (encoding, body) = inline_text(&m.body);
            wanted.push(Attachment {
                purpose: SIP_SDP_PURPOSE,
                party,
                dialog: 0,
                start,
                mediatype: SDP_MEDIATYPE,
                encoding,
                body,
            });
        }
    }

    let mut left = budget;
    let mut refused: Vec<serde_json::Value> = Vec::new();
    for attachment in wanted {
        let bytes = attachment.body.as_str().map_or(0, str::len);
        if bytes <= left {
            left -= bytes;
            container.attachments.push(attachment);
        } else {
            refused.push(serde_json::json!({
                "purpose": attachment.purpose,
                "bytes": bytes,
            }));
        }
    }
    if refused.is_empty() {
        return;
    }
    if let Some(map) = container
        .attachments
        .iter_mut()
        .find(|a| a.purpose == COMPLETENESS_PURPOSE)
        .and_then(|a| a.body.as_object_mut())
    {
        map.insert("sip_messages_refused".into(), refused.into());
    }
}

/// The initial INVITE and its final response, as [`add_sip_message_attachments`]
/// chooses them.
fn minimal_exchange(
    dialog: &SipDialog,
) -> (
    Option<&crate::sip::SipMessage>,
    Option<&crate::sip::SipMessage>,
) {
    let is_initial_invite = |m: &crate::sip::SipMessage| {
        m.is_request
            && m.method.as_ref() == Some(&crate::sip::SipMethod::Invite)
            && m.to_tag().is_none()
    };
    let initial_cseqs: Vec<u32> = dialog
        .messages
        .iter()
        .filter(|m| is_initial_invite(m))
        .filter_map(|m| m.cseq().map(|(n, _)| n))
        .collect();
    let final_cseq = dialog
        .messages
        .iter()
        .rev()
        .filter(|m| !m.is_request && m.status_code.is_some_and(|c| (200..700).contains(&c)))
        .filter_map(|m| m.cseq().filter(|(_, method)| *method == "INVITE"))
        .map(|(n, _)| n)
        .find(|n| initial_cseqs.contains(n));
    let Some(cseq) = final_cseq else {
        return (
            dialog.messages.iter().rev().find(|m| is_initial_invite(m)),
            None,
        );
    };
    let in_transaction = |m: &&crate::sip::SipMessage| {
        m.cseq()
            .is_some_and(|(n, method)| n == cseq && method == "INVITE")
    };
    let invite = dialog
        .messages
        .iter()
        .filter(in_transaction)
        .find(|m| is_initial_invite(m));
    // The LAST final status of the transaction, then its first transmission:
    // a retransmitted 200 is the same response.
    let last_final = dialog
        .messages
        .iter()
        .rev()
        .filter(in_transaction)
        .find(|m| !m.is_request && m.status_code.is_some_and(|c| c >= 200))
        .and_then(|m| m.status_code);
    let response = dialog
        .messages
        .iter()
        .filter(in_transaction)
        .find(|m| !m.is_request && m.status_code == last_final);
    (invite, response)
}

/// `raw` without the header lines whose name is a credential header, and
/// without the folded continuation lines of those headers.
///
/// Only the header section is filtered; the body is kept byte for byte, so
/// `Content-Length` still describes it.
fn without_credentials(raw: &[u8]) -> Vec<u8> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |i| i + 2);
    let (head, rest) = raw.split_at(split);
    let mut out = Vec::with_capacity(raw.len());
    let mut dropping = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        let folded = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if !folded {
            dropping = std::str::from_utf8(line).is_ok_and(header_line_is_a_credential);
        }
        if !dropping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(rest);
    out
}

/// An inline attachment body: the text with the `none` encoding when it is
/// UTF-8, otherwise base64url.
fn inline_text(bytes: &[u8]) -> (&'static str, serde_json::Value) {
    match std::str::from_utf8(bytes) {
        Ok(text) => ("none", text.into()),
        Err(_) => ("base64url", URL_SAFE_NO_PAD.encode(bytes).into()),
    }
}

/// `purpose` of the report that transcribes the network's STIR verdict,
/// [draft-howe-vcon-sip-signaling-00 section 7.3](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-7.3).
pub const STIR_REPORT_PURPOSE: &str = "stir-verification-report";

/// What the report says about who verified.
const STIR_REPORT_REASON: &str = "Transcribed from the verstat parameter (ATIS-1000074) the \
     network wrote on this header. sipnab verified nothing: it checked no signature and \
     fetched no certificate, and the verifier is not named on the wire.";

/// The `stir-verification-report` attachment, when the dialog-creating INVITE
/// carries a `verstat` parameter.
///
/// sipnab transcribes; it does not verify. The terminating network writes
/// `verstat` (ATIS-1000074) on `P-Asserted-Identity` or `From` after its own
/// verification, and this report carries that verdict in the draft's shape:
///
/// - `result` maps `TN-Validation-Passed` to `verified` and
///   `TN-Validation-Failed` to `failed`. `No-TN-Validation` is `no-signature`
///   when the INVITE carried no `Identity` header, and is left out when it
///   did, because the draft has no value for "not verified".
/// - `attestation`, `orig_tn` and `dest_tn` are the PASSporT's own claims,
///   when the INVITE carried one.
/// - `timestamp` is when sipnab captured the INVITE, which is after the
///   verification.
/// - `verifier` is absent: the header does not name who verified.
/// - `verstat` and `verstat_header` keep the value and where it was read.
///
/// `party` is 0, the caller whose PASSporT this is (section 7.2 asks the same
/// of a certificate attachment), and `dialog` is 0.
///
/// `P-Asserted-Identity` is read before `From`, and the first initial INVITE
/// carrying a `verstat` decides. No `verstat` is no report.
fn stir_verification_report(dialog: &SipDialog) -> Option<Attachment> {
    let (message, header, verstat) = dialog
        .messages
        .iter()
        .filter(|m| {
            m.is_request
                && m.method.as_ref() == Some(&crate::sip::SipMethod::Invite)
                && m.to_tag().is_none()
        })
        .find_map(|m| {
            ["P-Asserted-Identity", "From"]
                .into_iter()
                .find_map(|header| {
                    m.headers_by_name(header)
                        .into_iter()
                        .find_map(verstat_of)
                        .map(|v| (m, header, v))
                })
        })?;
    let result = match verstat.as_str() {
        v if v.eq_ignore_ascii_case("TN-Validation-Passed") => Some("verified"),
        v if v.eq_ignore_ascii_case("TN-Validation-Failed") => Some("failed"),
        v if v.eq_ignore_ascii_case("No-TN-Validation") && message.header("Identity").is_none() => {
            Some("no-signature")
        }
        _ => None,
    };
    let mut body = serde_json::Map::new();
    body.insert("timestamp".into(), message.timestamp.to_rfc3339().into());
    if let Some(result) = result {
        body.insert("result".into(), result.into());
    }
    add_passport_fields(&mut body, message);
    body.insert("reason".into(), STIR_REPORT_REASON.into());
    body.insert("verstat".into(), verstat.into());
    body.insert("verstat_header".into(), header.into());
    Some(Attachment {
        purpose: STIR_REPORT_PURPOSE,
        party: 0,
        dialog: 0,
        start: message.timestamp.to_rfc3339(),
        mediatype: "application/json",
        encoding: "json",
        body: serde_json::Value::Object(body),
    })
}

/// Add the attestation and telephone numbers of the PASSporT in `message`'s
/// `Identity` header to a STIR report body, when it parses.
///
/// The PASSporT parser is part of the `tls` feature, so a build without it
/// writes the report with no `attestation`, `orig_tn` or `dest_tn`.
#[cfg(feature = "tls")]
fn add_passport_fields(
    body: &mut serde_json::Map<String, serde_json::Value>,
    message: &crate::sip::message::SipMessage,
) {
    let Some(info) = message.stir_shaken().and_then(Result::ok) else {
        return;
    };
    let attestation = match info.attestation {
        crate::sip::stir_shaken::Attestation::A => Some("A"),
        crate::sip::stir_shaken::Attestation::B => Some("B"),
        crate::sip::stir_shaken::Attestation::C => Some("C"),
        _ => None,
    };
    if let Some(level) = attestation {
        body.insert("attestation".into(), level.into());
    }
    if let Some(orig) = &info.orig_tn {
        body.insert("orig_tn".into(), orig.clone().into());
    }
    if !info.dest_tn.is_empty() {
        body.insert("dest_tn".into(), info.dest_tn.clone().into());
    }
}

/// Without the `tls` feature there is no PASSporT parser, so nothing is added.
#[cfg(not(feature = "tls"))]
fn add_passport_fields(
    _body: &mut serde_json::Map<String, serde_json::Value>,
    _message: &crate::sip::message::SipMessage,
) {
}

/// The value of a `verstat` parameter anywhere in a header value: the text
/// after `verstat=` up to `;`, `>`, `@`, `,` or white space.
///
/// Anywhere, because ATIS-1000074 places it as a URI parameter, which sits
/// inside the angle brackets of a `sip:` URI's user part or after a `tel:`
/// number.
fn verstat_of(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let at = lower.find("verstat=")? + "verstat=".len();
    let rest = &value[at..];
    let end = rest
        .find(|c: char| matches!(c, ';' | '>' | '@' | ',') || c.is_whitespace())
        .unwrap_or(rest.len());
    let verstat = rest[..end].trim();
    (!verstat.is_empty()).then(|| verstat.to_string())
}

/// `purpose` of the attachment vcon-lib reads tags from
/// (`Vcon.tags`, `Vcon.get_tag`): a list of `"name:value"` strings.
pub const TAGS_PURPOSE: &str = "tags";

/// The most `finding:` tags one container carries.
pub const MAX_FINDING_TAGS: usize = 5;

/// Add the `tags` attachment to a container a `[[vcon.rule]]` writes.
///
/// The body is a JSON list of `"name:value"` strings, the shape vcon-lib's
/// `Vcon.add_tag` writes and `Vcon.get_tag` reads. vcon-lib takes the text
/// between the first and the second colon as the value, and no value here
/// holds a colon: rule and filter names are letters, digits, `-` and `_`.
///
/// - `rule:<name>`: the rule that wrote the container.
/// - `filter:<name>`: each `[filters]` name the rule's `when` references,
///   in the order it first appears, that the call matched on its own.
/// - `finding:<name>`: each detection of the signaling diagnosis the
///   container's analysis reports, by its field name, in the diagnosis's own
///   order and once across a call's legs, at most [`MAX_FINDING_TAGS`]. See
///   `finding_tags`.
///
/// `party` is the observer, which wrote it; `dialog` is 0.
pub fn add_tags(container: &mut Vcon, legs: &[&SipDialog], rule: &str, filters: &[&str]) {
    let mut body: Vec<String> = vec![format!("rule:{rule}")];
    body.extend(filters.iter().map(|f| format!("filter:{f}")));
    body.extend(finding_tags(legs, MAX_FINDING_TAGS));
    let start = container
        .dialog
        .first()
        .and_then(|d| d.start.clone())
        .unwrap_or_else(|| container.created_at.clone());
    let party = container.observer_index();
    container.attachments.push(Attachment {
        purpose: TAGS_PURPOSE,
        party,
        dialog: 0,
        start,
        mediatype: "application/json",
        encoding: "json",
        body: body.into(),
    });
}

/// `finding:<name>` for each detection the signaling diagnosis of `legs`
/// reports, at most `max`.
///
/// The order is the order [`crate::sip::diagnosis::SignalingDiagnosis`]
/// declares its detections, which puts the final failure first. The
/// diagnosis's `hints` are prose, not detections, and are not tags.
fn finding_tags(legs: &[&SipDialog], max: usize) -> Vec<String> {
    let mut names: Vec<&'static str> = Vec::new();
    for leg in legs {
        let crate::sip::diagnosis::SignalingDiagnosis {
            final_failure,
            auth_loop,
            retransmissions,
            ack_missing,
            abandoned,
            post_dial_delay,
            registration_failure,
            icmp_unreachable,
            source_disagreement,
            hints: _,
        } = crate::sip::diagnosis::diagnose_signaling(&leg.messages);
        for (name, present) in [
            ("final_failure", final_failure.is_some()),
            ("auth_loop", auth_loop.is_some()),
            ("retransmissions", retransmissions.is_some()),
            ("ack_missing", ack_missing.is_some()),
            ("abandoned", abandoned.is_some()),
            ("post_dial_delay", post_dial_delay.is_some()),
            ("registration_failure", registration_failure.is_some()),
            ("icmp_unreachable", icmp_unreachable.is_some()),
            ("source_disagreement", source_disagreement.is_some()),
        ] {
            if present && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
        .into_iter()
        .take(max)
        .map(|name| format!("finding:{name}"))
        .collect()
}

/// Which SIP header fills each contact-center Dialog parameter of
/// [draft-ietf-vcon-cc-extension-02 section 3.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-cc-extension-02#section-3.2).
///
/// A `[[vcon.rule]]` names the headers (`campaign_header`, `skill_header`,
/// `interaction_id_header`); `None` writes nothing for that parameter.
#[derive(Debug, Clone, Copy, Default)]
pub struct CcHeaders<'a> {
    /// The header whose value is `campaign` (section 3.2.1).
    pub campaign: Option<&'a str>,
    /// The header whose value is `skill` (section 3.2.4).
    pub skill: Option<&'a str>,
    /// The header whose value is `interaction_id` (section 3.2.3).
    pub interaction_id: Option<&'a str>,
}

/// Fill `campaign`, `skill` and `interaction_id` on a one-leg container's
/// signaling object from the headers `headers` names.
///
/// Each value is the first value of that header on the first message in the
/// ladder that carries it, trimmed, matched without regard to case
/// ([RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1)).
/// A header the call never carried leaves its parameter absent. The `CC`
/// extension these parameters belong to is already in `extensions`.
///
/// The parameter is `interaction_id`, as section 3.2.3 spells it. vcon-lib's
/// Dialog allow-list spells it `interaction`; a vcon-lib reader that filters
/// on that list drops `interaction_id`.
pub fn add_cc_fields(container: &mut Vcon, dialog: &SipDialog, headers: CcHeaders<'_>) {
    let first = |name: Option<&str>| -> Option<String> {
        let name = name?;
        dialog
            .messages
            .iter()
            .find_map(|m| m.header(name))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let (campaign, skill, interaction_id) = (
        first(headers.campaign),
        first(headers.skill),
        first(headers.interaction_id),
    );
    if let Some(signaling) = container.dialog.first_mut() {
        signaling.campaign = campaign;
        signaling.skill = skill;
        signaling.interaction_id = interaction_id;
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
/// Every header on one message, as a JSON object a consumer can index.
///
/// An OBJECT keyed by header name rather than a list of name/value pairs,
/// because that is the shape [`strip_credentials`] can filter: it removes
/// entries whose KEY is a credential, and a `[{"name": ..., "value": ...}]`
/// list would hide every credential behind the key `"value"` where no filter
/// keyed on names can reach it.
///
/// Values are arrays because SIP headers repeat — `Via` and `Record-Route`
/// carry the path, and collapsing them to one value would lose the route the
/// message actually took. A single-valued header is a one-element array rather
/// than a bare string, so a consumer indexes one shape and never type-switches.
fn header_map(msg: &crate::sip::SipMessage) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for header in &msg.headers {
        let entry = map
            .entry(header.name.to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(list) = entry.as_array_mut() {
            list.push(serde_json::Value::String(header.value.clone()));
        }
    }
    serde_json::Value::Object(map)
}

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
            // A string entry shaped like a header LINE is filtered on the
            // name before the colon. Keying only on object keys was the whole
            // hole: `--json` gained `extension_headers`, a list of
            // `"Authorization: Digest ..."` strings, and every credential in
            // it walked straight through a filter that was looking for a key
            // named `Authorization`. This boundary must hold for the shape a
            // field arrives in, not for the shape it had when the filter was
            // written.
            items.retain(|item| match item.as_str() {
                Some(line) => !header_line_is_a_credential(line),
                None => true,
            });
            for nested in items {
                strip_credentials(nested);
            }
        }
        _ => {}
    }
}

/// Whether a `"Name: value"` line names a credential-bearing header.
///
/// The name is everything before the first colon, trimmed and compared
/// case-insensitively — [RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1) makes header names case-insensitive.
/// A string with no colon is not a header line and is left alone.
fn header_line_is_a_credential(line: &str) -> bool {
    let Some((name, _)) = line.split_once(':') else {
        return false;
    };
    let name = name.trim();
    CREDENTIAL_HEADERS
        .iter()
        .any(|banned| name.eq_ignore_ascii_case(banned))
}

/// The lone attachment on a withheld container: the caveat, nothing else.
///
/// It reuses [`COMPLETENESS_PURPOSE`] deliberately. A consumer that already
/// reads sipnab's caveat finds this one in the same place, and inventing a
/// second purpose would mean a reader looking for "why is this container
/// thin?" has two places to look and no reason to prefer either.
fn withheld_caveat(note: &str, exported_at: DateTime<Utc>) -> Attachment {
    Attachment {
        purpose: COMPLETENESS_PURPOSE,
        // The observer is the last party, and on a withheld container that is
        // index 2 -- two observed parties plus sipnab, the same as any other.
        party: 2,
        dialog: 0,
        start: exported_at.to_rfc3339(),
        mediatype: "application/json",
        encoding: "json",
        body: serde_json::json!({
            "note": note,
            "content_withheld": true,
            "sipnab_version": env!("CARGO_PKG_VERSION"),
            "node": node_name(),
        }),
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
        body: to_value_or_note(completeness),
    }
}

/// The report — surface one of two.
///
/// The signaling diagnosis is reused rather than recomputed: it is already the
/// wire shape `--json-dialogs` emits, and a second projection of one analysis
/// is two definitions waiting to disagree.
fn report(
    dialog: &SipDialog,
    completeness: &CaptureCompleteness,
    media: &[crate::output::model::StreamSummary],
) -> Analysis {
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
        // The quality of the dialog's RTP, as `GET /v1/streams` reports it:
        // the same projection, so the container and the API cannot disagree.
        // Addresses are left out: `--redact` rewrites the addresses it knows,
        // and the figures are what a reader of the call needs from here.
        // Omitted when the caller had no streams for the dialog.
        if !media.is_empty() {
            let rows: Vec<serde_json::Value> = media
                .iter()
                .map(|m| {
                    let mut row = serde_json::json!({
                        "ssrc": m.ssrc,
                        "codec": m.codec,
                        "packets": m.packets,
                        "jitter_ms": m.jitter_ms,
                        "loss_pct": m.loss_pct,
                        "mos": m.mos,
                        "r_factor": m.r_factor,
                        "mos_grounded": m.mos_grounded,
                        "mos_grounding": m.mos_grounding,
                    });
                    if let Some(obj) = row.as_object_mut() {
                        if let Some(note) = &m.mos_note {
                            obj.insert("mos_note".into(), note.clone().into());
                        }
                        if let Some(wb) = m.mos_wideband {
                            obj.insert("mos_wideband".into(), wb.into());
                        }
                        if let Some(ctx) = &m.mos_wideband_context {
                            obj.insert("mos_wideband_context".into(), ctx.clone().into());
                        }
                        if let Some(why) = &m.mos_wideband_unavailable {
                            obj.insert("mos_wideband_unavailable".into(), why.clone().into());
                        }
                    }
                    row
                })
                .collect();
            map.insert("media_quality".into(), rows.into());
        }
    }
    strip_credentials(&mut body);

    Analysis {
        kind: "report".into(),
        dialog: 0,
        vendor: ANALYSIS_VENDOR.into(),
        product: Some(ANALYSIS_PRODUCT.into()),
        schema: Some(ANALYSIS_SCHEMA.into()),
        mediatype: Some("application/json".into()),
        encoding: "json".into(),
        body,
        provenance: None,
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

/// Read the completeness of a capture off its facts, its analysis, and what
/// happened to its media.
fn completeness_of(
    context: &ExportContext<'_>,
    media: &MediaVerdict,
    call_ended: bool,
) -> CaptureCompleteness {
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
        note: completeness_note(facts, blind_spots.as_deref(), media, call_ended),
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
        gate_closed_during_run: facts.gate_closed_during_run,
        dialogs_suppressed_by_deny: facts.dialogs_suppressed_by_deny,
        headers_dropped_oversize: facts.headers_dropped_oversize,
        call_ended,
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
    call_ended: bool,
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

    // The two clauses below report DECISIONS, not capture faults, and they say
    // so. Every clause above describes something this run failed to see; a
    // reader who cannot tell the two apart goes hunting for a fault that does
    // not exist. They are separate `if`s rather than a chain because a run can
    // have both, and that run is the one whose container explains itself least.
    if facts.gate_closed_during_run {
        partial.push_str(
            " — INCOMPLETE: an operator closed the persistence gate during this run, so \
             containers are absent for a reason this capture does not otherwise record. That \
             is a decision, not a gap in what sipnab saw.",
        );
    }
    if facts.dialogs_suppressed_by_deny > 0 {
        partial.push_str(&format!(
            " — INCOMPLETE: {} dialog(s) carried a deny flag in their signaling and produced no \
             content. That is a decision recorded here, not a gap in what sipnab saw.",
            facts.dialogs_suppressed_by_deny
        ));
    }

    if facts.headers_dropped_oversize > 0 {
        // Named as HEADERS specifically. "Something was dropped" sends a reader
        // looking through frames that are all present; the loss is inside
        // messages the container otherwise carries in full.
        partial.push_str(&format!(
            " — INCOMPLETE: {} header line(s) exceeded the parser's length cap and were \
             dropped, so at least one message here is missing a header it carried on the \
             wire. The bytes are not recoverable from this container; the cap is what keeps \
             a single runaway line from being unfolded into memory.",
            facts.headers_dropped_oversize
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

    // A statement about the CALL, not about the capture, so it is neither an
    // INCOMPLETE clause nor an omission row: every message sipnab held can be
    // here and the call still have gone on after the container was written.
    let running_clause = if call_ended {
        ""
    } else {
        " The call had not ended when this container was written: sipnab had seen no BYE, \
         CANCEL or final failure for it, so the trace and any media end where this container \
         was written, not where the call ended."
    };

    format!(
        "Produced by sipnab {} on node {}. sipnab OBSERVED this dialog and took no part in it: \
         the parties below are what the From and To headers said, not identities anyone \
         established, and nothing here is signed.{} sipnab read {} frame(s) for this \
         capture.{running_clause}{verdict}{blind_clause}",
        env!("CARGO_PKG_VERSION"),
        node_name(),
        media_clause(media.outcome),
        facts.frames_read,
    )
}

/// The sentence describing what this container carries in place of media.
///
/// Five sentences rather than one, because the five outcomes are five
/// different facts and the reader's next step differs for each. The dangerous
/// one is [`MediaOutcome::NotConsidered`]: a container with no `recording`
/// object reads as a conversation that had no media, which is a claim about
/// the CALL. It has to be said out loud that this run never looked.
///
/// No `url` is ever mentioned as a place the media might be, because
/// [section 2.5 of `docs/design/vcon.md`](https://github.com/NormB/sipnab/blob/main/docs/design/vcon.md#25-never-host-artefacts) refuses to host anything and a
/// container that names an elsewhere is asserting where a file lives on
/// infrastructure sipnab does not control.
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
        MediaOutcome::WithheldByRedaction => {
            " No media is in this container because the export is redacted, and redaction \
             deletes audio rather than pseudonymizing it. That is a fact about this EXPORT, not \
             about the call: nothing here says whether the conversation carried audio."
        }
        MediaOutcome::Carried => {
            " Media IS in this container, as a recording Dialog Object holding a WAV inline. It \
             was reconstructed from RTP this run retained at a capture point — it is NOT a \
             recording made by the endpoints, and the media_note traveling with it says how it \
             is bounded."
        }
        MediaOutcome::Referenced => {
            " Media is REFERENCED by this container: a recording Dialog Object names the URL of \
             a WAV sipnab wrote beside this file, with that WAV's hash, and holds no body. \
             sipnab hosts nothing and has not checked that the URL serves the file; the hash \
             verifies any copy of it. It was reconstructed from RTP this run retained at a \
             capture point — it is NOT a recording made by the endpoints, and the media_note \
             traveling with it says how it is bounded."
        }
    }
}

/// A UUIDv8 for one dialog out of one capture, per
/// [section 4.1.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.2).
///
/// Laid out like a UUIDv7 — a 48-bit millisecond timestamp, a 12-bit `rand_a`,
/// then a 62-bit `rand_b` — with two deliberate choices:
///
/// * **`rand_b` is keyed on the node, the dialog and the capture**: the high 62
///   bits of SHA-256 over the node name, the Call-ID (or a call's leg
///   Call-IDs) and the capture identity. The draft asks for a digest of the
///   host name alone; mixing in the dialog and the capture keeps two dialogs
///   that opened in the same millisecond on one node apart, and the value is
///   still a function of stable inputs. Keying it on the node alone, as
///   releases before 0.5.125 did, left `rand_a`'s 12 bits as the only
///   difference between such dialogs.
/// * **The timestamp is the DIALOG's, not the export's.** With the export
///   clock in there, re-exporting one dialog would mint a new identifier every
///   time, and a consumer deduplicating on `uuid` would accumulate copies of
///   one conversation. [`Vcon::created_at`] still carries the export time,
///   where [core-04 section 4.1.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.5) puts it.
///
/// `rand_a` is seeded from the `Call-ID` and `capture_id`, so the whole value
/// is a function of the observed dialog and the capture it came from.
///
/// # What this identifier does not promise
///
/// Randomness. Two dialogs that opened in the same millisecond on the same
/// node differ in the 74 digest bits, which separates them unless two of
/// those digests collide; nothing random is mixed in, so the same dialog from
/// the same capture on the same node always yields the same value.
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
    uuid_for(dialog.created_at, &dialog.call_id, capture_id)
}

/// The uuid of the one container a `grouping = "call"` rule writes for a call
/// made of `legs`.
///
/// [`dialog_uuid`]'s derivation, keyed on every leg's Call-ID rather than on
/// one, so it is the same for the same call from the same capture and differs
/// from every leg's own container uuid. The legs are sorted, so the key does
/// not depend on the order a walk found them in.
#[must_use]
pub fn call_uuid(legs: &[&SipDialog], capture_id: &str) -> String {
    let started = legs.iter().map(|d| d.created_at).min().unwrap_or_default();
    let mut ids: Vec<&str> = legs.iter().map(|d| d.call_id.as_str()).collect();
    ids.sort_unstable();
    // `call` and the unit separator cannot open a Call-ID's own key the same
    // way: a Call-ID is a `word`, and 0x1f is not a word character.
    let key = format!("call\u{1f}{}", ids.join("\u{1f}"));
    uuid_for(started, &key, capture_id)
}

/// [`dialog_uuid`]'s layout, for an identity `key` that opened at `started`.
fn uuid_for(started: DateTime<Utc>, key: &str, capture_id: &str) -> String {
    let mut bytes = [0u8; 16];
    let capture_id: &str = &capture_identity_key(capture_id);

    // 48-bit big-endian millisecond timestamp. `max(0)` rather than a wrap:
    // a pre-epoch capture timestamp is nonsense, and wrapping it would spread
    // one absurd input across the whole 48-bit space.
    let millis = u64::try_from(started.timestamp_millis().max(0)).unwrap_or(0);
    let ts = millis & 0x0000_FFFF_FFFF_FFFF;
    bytes[..6].copy_from_slice(&ts.to_be_bytes()[2..]);

    // rand_a: 12 bits keyed by the dialog and the capture it came from. The
    // separator keeps `("ab", "c")` and `("a", "bc")` apart, which a bare
    // concatenation would collide.
    let mut seed = Sha256::new();
    seed.update(key.as_bytes());
    seed.update([0x1e]);
    seed.update(capture_id.as_bytes());
    let seed = seed.finalize();
    let rand_a = u16::from_be_bytes([seed[0], seed[1]]) >> 4;
    // Version 8 in the high nibble of octet 6, per RFC 9562 §4.2.
    bytes[6] = 0x80 | u8::try_from(rand_a >> 8).unwrap_or(0);
    bytes[7] = u8::try_from(rand_a & 0xff).unwrap_or(0);

    // rand_b: 62 more bits keyed on the NODE AND THE DIALOG, shifted down so
    // none of them are overwritten by the variant bits that follow. Masking
    // the top two bits off instead would silently discard the two most
    // significant bits the draft asks for.
    //
    // Keying this on the node ALONE — which it did until 0.5.125 — spent 62 of
    // the identifier's 74 bits on a value identical for every dialog on the
    // box. That left `rand_a`'s 12 bits as the only thing telling two dialogs
    // apart within one millisecond on one node, so roughly one pair in 4096
    // collided. §4.1.2 makes the uuid globally unique and a store KEYS on it:
    // a collision raises nothing, it overwrites the record already there and
    // one capture is gone. `two_dialogs_in_one_millisecond_on_one_node_get_different_uuids`
    // holds a real colliding pair found by brute force.
    //
    // Determinism is untouched, and that is the property this must not buy the
    // fix with: the digest is over stable inputs, so re-exporting one dialog
    // from one capture still yields one identifier. The same separator as
    // above keeps `("ab", "c")` apart from `("a", "bc")`.
    let mut host = Sha256::new();
    host.update(node_name().as_bytes());
    host.update([0x1e]);
    host.update(key.as_bytes());
    host.update([0x1e]);
    host.update(capture_id.as_bytes());
    let host = host.finalize();
    let mut top = [0u8; 8];
    top.copy_from_slice(&host[..8]);
    let rand_b = u64::from_be_bytes(top) >> 2;
    // Variant `10` in the two high bits of octet 8, per RFC 9562 §4.1.
    bytes[8..].copy_from_slice(&(0x8000_0000_0000_0000_u64 | rand_b).to_be_bytes());

    format_uuid(&bytes)
}

/// The uuid of the `revision`-th later instance of the container whose first
/// instance has uuid `base`; revision 0 is `base` itself.
///
/// A rule that seals its containers with `sealed_updates = "new-uuid"` writes
/// each later version of a call as a new instance, because
/// [section 4.1.9 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9)
/// says "A signed or encrypted vCon cannot be modified without invalidating
/// it. In these cases, to allow for adding of additional information a new
/// vCon instance version MUST be created", and
/// [section 4.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.2)
/// says "The UUID value MUST be globally unique".
///
/// The layout is [`dialog_uuid`]'s, with these inputs:
///
/// * the 48-bit timestamp is `base`'s, so every instance of one call carries
///   the call's start;
/// * `rand_a` (12 bits) and `rand_b` (62 bits) are the leading bits of
///   SHA-256 over `amended`, `base` and the revision number as four
///   big-endian bytes, separated by 0x1e.
///
/// The value is therefore a function of the first instance's uuid and the
/// revision number alone: the same call from the same capture, rewritten the
/// same number of times, yields the same chain of uuids on every run, and the
/// first instance's determinism properties carry over. Two revisions of one
/// call differ in at least the 74 hashed bits.
#[must_use]
pub fn revision_uuid(base: &str, revision: u32) -> String {
    if revision == 0 {
        return base.to_owned();
    }
    let hex: Vec<u8> = base
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|c| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        })
        .collect();
    let mut bytes = [0u8; 16];
    // The first 12 hex digits are the 48-bit timestamp. A base that is not a
    // uuid keeps a zero timestamp; the hashed bits still separate revisions.
    if hex.len() == 32 {
        for (i, byte) in bytes.iter_mut().take(6).enumerate() {
            *byte = (hex[2 * i] << 4) | hex[2 * i + 1];
        }
    }
    let mut seed = Sha256::new();
    seed.update(b"amended");
    seed.update([0x1e]);
    seed.update(base.as_bytes());
    seed.update([0x1e]);
    seed.update(revision.to_be_bytes());
    let seed = seed.finalize();
    let rand_a = u16::from_be_bytes([seed[0], seed[1]]) >> 4;
    // Version 8 in the high nibble of octet 6, per RFC 9562 §4.2.
    bytes[6] = 0x80 | u8::try_from(rand_a >> 8).unwrap_or(0);
    bytes[7] = u8::try_from(rand_a & 0xff).unwrap_or(0);
    let mut top = [0u8; 8];
    top.copy_from_slice(&seed[2..10]);
    let rand_b = u64::from_be_bytes(top) >> 2;
    // Variant `10` in the two high bits of octet 8, per RFC 9562 §4.1.
    bytes[8..].copy_from_slice(&(0x8000_0000_0000_0000_u64 | rand_b).to_be_bytes());
    format_uuid(&bytes)
}

/// The capture identity a uuid is seeded from, with one file spelled one way.
///
/// `capture_id` is the SOURCE half of a frame pointer -- the path exactly as
/// the operator typed it. `-I tests/x.pcap` and `-I /abs/tests/x.pcap` name the
/// same bytes and seeded different uuids, so a consumer deduplicating on `uuid`
/// saw two conversations where the content proves there is one (VAL14).
///
/// Only the SEED is normalized, never the recorded pointer. The pointer keeps
/// the operator's own spelling because that is what they recognize and what
/// `show_evidence` resolves, and because an absolute path carries the account
/// name, which has no business in a container that leaves the building. A uuid
/// is a digest, so the normalized form is never published.
///
/// # What is treated as a path
///
/// A separator, or a capture-file extension. Both are needed and neither alone
/// is enough: `x.pcap` in the working directory has no separator, and a VLAN
/// interface is spelled `eth0.100`, which has a dot and is not a file. A live
/// device or a HEP listener joined to the working directory would make one
/// interface two identities depending on where sipnab was started, which is
/// the bug this fixes, pointed the other way.
///
/// `std::path::absolute` is lexical: it consults the working directory but not
/// the filesystem, so this neither stats a file nor resolves a symlink, and a
/// capture that has since been moved or deleted still exports the same uuid.
fn capture_identity_key(capture_id: &str) -> std::borrow::Cow<'_, str> {
    const CAPTURE_EXTENSIONS: &[&str] = &["pcap", "pcapng", "cap"];

    if capture_id.starts_with("hep:") || capture_id.starts_with("uprobe:") {
        return std::borrow::Cow::Borrowed(capture_id);
    }
    let path = std::path::Path::new(capture_id);
    let looks_like_a_file = capture_id.contains(std::path::MAIN_SEPARATOR)
        || path.extension().is_some_and(|e| {
            CAPTURE_EXTENSIONS
                .iter()
                .any(|k| e.eq_ignore_ascii_case(std::ffi::OsStr::new(k)))
        });
    if !looks_like_a_file {
        return std::borrow::Cow::Borrowed(capture_id);
    }
    std::path::absolute(path).map_or(std::borrow::Cow::Borrowed(capture_id), |p| {
        std::borrow::Cow::Owned(p.to_string_lossy().into_owned())
    })
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

    type TestError = Box<dyn std::error::Error>;

    /// A `json`-encoded body, parsed.
    ///
    /// [Section 2.3.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3.2)
    /// makes an `encoding: "json"` body the JSON value itself, and every body
    /// sipnab writes is an object, so a string here is refused.
    fn body_of(node: &serde_json::Value) -> Result<serde_json::Value, TestError> {
        let body = &node["body"];
        if !body.is_object() {
            return Err(format!("a json body must be the object itself: {node}").into());
        }
        Ok(body.clone())
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
    fn ts() -> Result<DateTime<Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 8, 24, 12, 0, 0)
                .single()
                .ok_or("invalid fixture timestamp")?,
        )
    }

    /// The moment an export is stamped with, distinct from [`ts`] so a test
    /// can tell the two clocks apart.
    fn exported_at() -> Result<DateTime<Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 8, 25, 9, 30, 0)
                .single()
                .ok_or("invalid fixture timestamp")?,
        )
    }

    /// Parse one message out of a first line and header list.
    fn message(first_line: &str, headers: &[&str]) -> Result<crate::sip::SipMessage, TestError> {
        Ok(parse_sip(
            &build_sip(first_line, headers, b""),
            ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// An INVITE opening a dialog, with display names, Contact and User-Agent.
    fn invite() -> Result<crate::sip::SipMessage, TestError> {
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
    fn response(code: u16, reason: &str) -> Result<crate::sip::SipMessage, TestError> {
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
    fn dialog_with(responses: &[crate::sip::SipMessage]) -> Result<SipDialog, TestError> {
        let invite = invite()?;
        // `SipDialog::new` already stores the opening message, so pushing it
        // again would give the trace two INVITEs and quietly shift every
        // later index -- which is exactly how the first draft of
        // `the_trace_carries_every_message_through_the_shared_projection`
        // read a duplicate INVITE where it expected the 180.
        let mut dialog = SipDialog::new(&invite).ok_or("INVITE opens a dialog")?;
        for r in responses {
            crate::sip::dialog::update_state(&mut dialog, r);
            dialog.messages.push(r.clone());
        }
        Ok(dialog)
    }

    /// A capture that read frames and lost nothing.
    fn clean_facts() -> CaptureFacts {
        CaptureFacts {
            frames_read: 120,
            ..CaptureFacts::default()
        }
    }

    /// A leg container with a recording that maps its two channels to the
    /// leg's parties, and a transfer object naming parties and objects.
    fn leg_with_indices() -> Result<Vcon, TestError> {
        let mut v = export_with(&dialog_with(&[response(200, "OK")?])?, &clean_facts())?;
        let signaling = v.dialog.len();
        v.dialog.push(Dialog {
            parties: Some(vec![0, 1]),
            ..Dialog::bare("recording", "fixture".into())
        });
        v.dialog.push(Dialog {
            transferor: Some(0),
            transferee: Some(1),
            transfer_target: Some(1),
            original: Some(0),
            consultation: Some(signaling),
            dialogs: Some(vec![0, signaling]),
            recording_set: Some(signaling),
            ..Dialog::bare(TRANSFER_TYPE, "fixture".into())
        });
        Ok(v)
    }

    /// The second leg's party and object indices move past the first leg's,
    /// and the observer is one party, last, that every attachment names.
    #[test]
    fn merging_moves_every_index_of_the_second_leg() -> Result<(), TestError> {
        let first = leg_with_indices()?;
        let (parties, objects) = (first.parties.len() - 1, first.dialog.len());
        let merged = merge_call_legs(
            vec![first, leg_with_indices()?],
            &[LegTie {
                from: 0,
                to: 1,
                strategy: "x_call_id",
                identifier_match: true,
                score: 100,
            }],
            "uuid".into(),
            false,
        )
        .ok_or("two legs merge")?;
        assert_eq!(merged.parties.len(), 2 * parties + 1);
        let observer = merged.parties.len() - 1;
        assert_eq!(merged.parties[observer].role, Some("observer"));
        let second_recording = &merged.dialog[objects + objects - 2];
        assert_eq!(second_recording.parties, Some(vec![parties, parties + 1]));
        let transfer = &merged.dialog[2 * objects - 1];
        assert_eq!(transfer.transferor, Some(parties));
        assert_eq!(transfer.transferee, Some(parties + 1));
        assert_eq!(transfer.transfer_target, Some(parties + 1));
        assert_eq!(transfer.original, Some(objects));
        assert_eq!(transfer.consultation, Some(objects + objects - 2));
        assert_eq!(transfer.dialogs, Some(vec![objects, objects + objects - 2]));
        assert_eq!(transfer.recording_set, Some(objects + objects - 2));
        assert!(merged.attachments.iter().all(|a| a.party == observer));
        // The tie and the leg list name Dialog Objects, not leg positions.
        let legs = merged
            .attachments
            .iter()
            .find(|a| a.purpose == CALL_LEGS_PURPOSE)
            .ok_or("a call-legs attachment")?;
        let body = &legs.body;
        assert_eq!(body["ties"][0]["dialogs"], serde_json::json!([0, objects]));
        assert_eq!(
            body["legs"],
            serde_json::json!([{ "dialog": 0 }, { "dialog": objects }])
        );
        Ok(())
    }

    /// No legs is no call.
    #[test]
    fn merging_no_legs_is_no_container() {
        assert!(merge_call_legs(Vec::new(), &[], "uuid".into(), false).is_none());
    }

    /// Export against a supplied set of facts and no capture analysis.
    fn export_with(dialog: &SipDialog, facts: &CaptureFacts) -> Result<Vcon, TestError> {
        Ok(export_dialog_at(
            dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts,
                max_inline_media_bytes: None,
                analysis: None,
                media: &[],
                related_legs: &[],
            },
            exported_at()?,
        ))
    }

    /// The analysis body parsed out of an exported container.
    fn report_body(v: &Vcon) -> Result<serde_json::Value, TestError> {
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(v)?)?;
        let body = &json["analysis"][0]["body"];
        if !body.is_object() {
            return Err(format!("the analysis body is the object itself: {body}").into());
        }
        Ok(body.clone())
    }

    /// One PCMU stream's summary, as `GET /v1/streams` reports it.
    fn pcmu_summary() -> Result<crate::output::model::StreamSummary, TestError> {
        let key = crate::rtp::stream::StreamKey {
            ssrc: 0x1234_5678,
            src: "10.0.0.1:20000".parse()?,
            dst: "10.0.0.2:30000".parse()?,
            session: 0,
        };
        let hdr = crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 0,
            ssrc: 0x1234_5678,
            payload_offset: 12,
        };
        let mut stream = crate::rtp::stream::RtpStream::new(key, &hdr, exported_at()?);
        stream.codec = Some("PCMU".to_string());
        Ok(crate::output::model::StreamSummary::of(
            &stream,
            crate::rtp::quality::MosDelay::unknown(),
        ))
    }

    /// The report carries each stream's MOS, the figure `GET /v1/streams`
    /// reports, with what it rests on.
    #[test]
    fn the_report_carries_each_streams_mos() -> Result<(), TestError> {
        let summary = pcmu_summary()?;
        let facts = clean_facts();
        let v = export_dialog_at(
            &dialog_with(&[response(200, "OK")?])?,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &facts,
                max_inline_media_bytes: None,
                analysis: None,
                media: std::slice::from_ref(&summary),
                related_legs: &[],
            },
            exported_at()?,
        );
        let body = report_body(&v)?;
        let row = &body["media_quality"][0];
        assert_eq!(row["ssrc"], summary.ssrc, "{body}");
        assert_eq!(row["codec"], "PCMU", "{body}");
        assert_eq!(row["mos"].as_f64(), Some(summary.mos), "{body}");
        assert_eq!(row["r_factor"].as_f64(), Some(summary.r_factor), "{body}");
        assert_eq!(row["mos_grounded"], true, "{body}");
        assert_eq!(row["mos_grounding"], "published", "{body}");
        Ok(())
    }

    /// No streams, no key: a dialog without media is not a dialog whose
    /// media scored nothing.
    #[test]
    fn a_report_without_media_has_no_media_quality() -> Result<(), TestError> {
        let v = export_with(&dialog_with(&[response(200, "OK")?])?, &clean_facts())?;
        assert!(report_body(&v)?.get("media_quality").is_none());
        Ok(())
    }

    // ── What the container says it does not contain ─────────────

    /// A run whose gate closed mid-capture says so.
    ///
    /// The container that survives is evidence about a capture that stopped
    /// recording partway. Without the clause it reads as a complete run that
    /// simply had fewer calls, and a reader comparing it against a switch's
    /// CDRs would conclude sipnab missed them.
    #[test]
    fn a_run_whose_gate_closed_says_so_in_the_completeness_caveat() -> Result<(), TestError> {
        let mut facts = clean_facts();
        facts.gate_closed_during_run = true;
        let v = export_with(&dialog_with(&[response(200, "OK")?])?, &facts)?;
        let json = serde_json::to_string(&v)?;
        assert!(
            json.contains("closed the persistence gate"),
            "a run that stopped writing mid-capture does not reproduce from              the capture alone, and the container has to say so: {json}"
        );
        Ok(())
    }

    /// A deny flag is recorded rather than leaving a silent absence.
    #[test]
    fn a_deny_flag_is_recorded_rather_than_leaving_a_silent_absence() -> Result<(), TestError> {
        let mut facts = clean_facts();
        facts.dialogs_suppressed_by_deny = 3;
        let v = export_with(&dialog_with(&[response(200, "OK")?])?, &facts)?;
        let json = serde_json::to_string(&v)?;
        assert!(
            json.contains("3 dialog(s) carried a deny flag"),
            "absence reading as 'nothing happened' is the failure this module              exists to refuse: {json}"
        );
        Ok(())
    }

    /// A dropped header is disclosed, not covered by the clean verdict.
    ///
    /// VAL13. A header at or past the parser's length cap is discarded -- the
    /// cap is what stops one runaway line being unfolded into memory -- and the
    /// container reported "No omissions recorded" over it. That is the one
    /// thing a completeness field must never do: the field whose whole job is
    /// to say data was dropped said none was.
    ///
    /// The bytes are unrecoverable by design, so disclosure is the entire
    /// remedy. A reader who knows a header was withheld can go back to the
    /// capture; one told nothing was omitted cannot know to.
    #[test]
    fn a_dropped_oversize_header_is_disclosed_in_the_note() -> Result<(), TestError> {
        let mut facts = clean_facts();
        facts.headers_dropped_oversize = 3;
        let v = export_with(&dialog_with(&[response(200, "OK")?])?, &facts)?;
        let json = serde_json::to_string(&v)?;

        assert!(
            !json.contains("No omissions recorded"),
            "a capture that lost a header has not recorded no omissions: {json}"
        );
        assert!(
            json.contains("header"),
            "the note must say WHAT was dropped, not merely that something was: \
             {json}"
        );
        assert!(
            json.contains('3'),
            "and how many, so a reader can weigh it: {json}"
        );
        Ok(())
    }

    /// A run with neither still earns the clean verdict.
    ///
    /// The clause has to be absent, not merely quiet. A note that always
    /// mentioned the gate would make every container read as suspect, and a
    /// caveat that fires on every run is one nobody reads.
    #[test]
    fn a_run_with_no_suppression_says_nothing_about_it() -> Result<(), TestError> {
        let v = export_with(&dialog_with(&[response(200, "OK")?])?, &clean_facts())?;
        let json = serde_json::to_string(&v)?;
        assert!(
            !json.contains("persistence gate"),
            "an untouched gate must not be mentioned: {json}"
        );
        assert!(
            !json.contains("deny flag"),
            "a run with no deny flag must not mention one: {json}"
        );
        assert!(
            json.contains("No omissions recorded"),
            "and the run still earns the clean verdict: {json}"
        );
        Ok(())
    }

    /// A container written before the call ended says so, in prose and as a
    /// field.
    ///
    /// A live export writes a call that has been quiet for the idle period
    /// even though no BYE was seen, and an export at the end of a capture
    /// writes whatever was still running. Either container ends where it was
    /// written, not where the call ended, and a reader cannot tell that from
    /// the message trace alone.
    #[test]
    fn a_container_written_before_the_call_ended_says_so() -> Result<(), TestError> {
        let running = dialog_with(&[response(200, "OK")?])?;
        assert!(
            !running.state().is_final(),
            "premise: an answered call with no BYE is still running"
        );
        let exported = export_reporting(&running, &clean_facts())?;
        assert!(
            exported.completeness.note.contains("had not ended"),
            "the note must say the call had not ended: {}",
            exported.completeness.note
        );
        assert!(!exported.completeness.call_ended);

        let ended = dialog_with(&[response(486, "Busy Here")?])?;
        assert!(ended.state().is_final(), "premise: a 486 ends the call");
        let exported = export_reporting(&ended, &clean_facts())?;
        assert!(
            !exported.completeness.note.contains("had not ended"),
            "an ended call must not be described as running: {}",
            exported.completeness.note
        );
        assert!(exported.completeness.call_ended);
        Ok(())
    }

    // ── The omissions, as rows a caller can branch on ───────────

    /// Export against supplied facts and report the completeness beside the
    /// container.
    ///
    /// The prose caveat lives inside the container twice, as JSON TEXT both
    /// times, so a test reading it back would be asserting against a string it
    /// had to parse out of a string. This hands back the value the container
    /// was built from.
    fn export_reporting(
        dialog: &SipDialog,
        facts: &CaptureFacts,
    ) -> Result<ExportedDialog, TestError> {
        Ok(export_dialog_and_completeness(
            dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts,
                max_inline_media_bytes: None,
                analysis: None,
                media: &[],
                related_legs: &[],
            },
            ObservedAudio::NotConsidered,
            exported_at()?,
        ))
    }

    /// Facts with exactly one loss counter set, named.
    fn facts_losing(kind: &str, count: u64) -> Result<CaptureFacts, TestError> {
        let mut facts = clean_facts();
        match kind {
            "undecodable_frames" => facts.undecodable.frames = count,
            "sip_discarded_by_port_gate" => facts.portrange.messages = count,
            "sip_discarded_by_websocket_gate" => facts.websocket.messages = count,
            "messages_evicted" => facts.retention.messages_evicted = count,
            "dialogs_refused" => facts.retention.dialogs_refused = count,
            "dialogs_rotated" => facts.retention.dialogs_rotated = count,
            "gate_closed_during_run" => facts.gate_closed_during_run = count > 0,
            "dialogs_suppressed_by_deny" => facts.dialogs_suppressed_by_deny = count,
            "headers_dropped_oversize" => facts.headers_dropped_oversize = count,
            other => {
                return Err(format!(
                    "no fixture for `{other}`; the list below and this must move together"
                )
                .into());
            }
        }
        Ok(facts)
    }

    /// Every loss counter the note has a clause for.
    const LOSS_COUNTERS: &[&str] = &[
        "undecodable_frames",
        "sip_discarded_by_port_gate",
        "sip_discarded_by_websocket_gate",
        "messages_evicted",
        "dialogs_refused",
        "dialogs_rotated",
        "gate_closed_during_run",
        "dialogs_suppressed_by_deny",
        "headers_dropped_oversize",
    ];

    /// How many `— INCOMPLETE:` clauses a note carries.
    fn incomplete_clauses(note: &str) -> usize {
        note.matches("— INCOMPLETE:").count()
    }

    /// RV7: the prose and the rows describe the same set, always.
    ///
    /// The note is the surface a person reads and the rows are the surface an
    /// agent reads, and they are built from one set of counters. This is the
    /// pairing gate: a clause added to `completeness_note` with no matching row
    /// in [`CaptureCompleteness::omissions`] — or the reverse — fails here,
    /// naming the counter. Checking one half would certify half a fix.
    #[test]
    fn an_omission_row_exists_for_every_incomplete_clause() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        for kind in LOSS_COUNTERS {
            let exported = export_reporting(&dialog, &facts_losing(kind, 7)?)?;
            let note = &exported.completeness.note;
            let rows = exported.completeness.omissions();
            assert_eq!(
                incomplete_clauses(note),
                1,
                "premise: `{kind}` must produce exactly one clause, or the \
                 comparison below is against the wrong number: {note}"
            );
            assert_eq!(
                rows.len(),
                1,
                "`{kind}` states a clause in prose and no row an agent can \
                 read: {rows:?}\n{note}"
            );
            assert_eq!(
                rows[0].kind, *kind,
                "the row must name the counter it came from: {rows:?}"
            );
        }

        // And all of them at once: a run with every loss is the one whose
        // container explains itself least, and the one an `else if` between
        // two clauses would silently shorten.
        let mut all = clean_facts();
        all.undecodable.frames = 1;
        all.portrange.messages = 2;
        all.websocket.messages = 3;
        all.retention.messages_evicted = 4;
        all.retention.dialogs_refused = 5;
        all.retention.dialogs_rotated = 6;
        all.gate_closed_during_run = true;
        all.dialogs_suppressed_by_deny = 7;
        all.headers_dropped_oversize = 8;
        let exported = export_reporting(&dialog, &all)?;
        let rows = exported.completeness.omissions();
        assert_eq!(
            rows.len(),
            LOSS_COUNTERS.len(),
            "one row per loss, and every counter above is a loss: {rows:?}"
        );
        assert_eq!(
            incomplete_clauses(&exported.completeness.note),
            rows.len(),
            "the prose and the rows must describe one set: {}",
            exported.completeness.note
        );
        Ok(())
    }

    /// A row carries the count and the unit, not merely the name.
    ///
    /// "Something was dropped" is the failure VAL13 was: a reader who cannot
    /// weigh the loss cannot decide whether to go back to the capture.
    #[test]
    fn an_omission_row_carries_the_count_and_the_unit() -> Result<(), TestError> {
        let exported = export_reporting(
            &dialog_with(&[response(200, "OK")?])?,
            &facts_losing("headers_dropped_oversize", 3)?,
        )?;
        let rows = exported.completeness.omissions();
        assert_eq!(
            rows,
            vec![Omission {
                kind: "headers_dropped_oversize",
                count: 3,
                unit: "header",
            }],
            "the row must say what was lost, how much, and in what unit"
        );
        Ok(())
    }

    /// A capture that lost nothing records no omissions.
    ///
    /// The anti-vacuity half. A list that is never empty is a list nobody
    /// reads, and `complete()` reporting `false` on a clean run would make
    /// every container read as suspect.
    #[test]
    fn a_clean_capture_records_no_omissions() -> Result<(), TestError> {
        let exported = export_reporting(&dialog_with(&[response(200, "OK")?])?, &clean_facts())?;
        assert!(
            exported.completeness.omissions().is_empty(),
            "a clean capture omitted nothing: {:?}",
            exported.completeness.omissions()
        );
        assert!(
            exported.completeness.complete(),
            "and says so: {}",
            exported.completeness.note
        );
        assert!(
            exported.completeness.note.contains("No omissions recorded"),
            "which is the same answer the prose gives: {}",
            exported.completeness.note
        );
        Ok(())
    }

    /// A ranked blind spot is an omission row; an analysis that found nothing
    /// is not.
    ///
    /// `None` and `Some([])` are different answers on the carrier and stay
    /// different here: neither is an omission, and only a RANKED spot is.
    #[test]
    fn a_ranked_blind_spot_is_an_omission_and_a_clean_analysis_is_not() -> Result<(), TestError> {
        use crate::analysis::{Finding, FindingKind};

        let dialog = dialog_with(&[response(200, "OK")?])?;
        let facts = clean_facts();
        let ranked = CaptureAnalysis {
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

        for (analysis, expected) in [
            (None, 0usize),
            (Some(&CaptureAnalysis::default()), 0),
            (Some(&ranked), 1),
        ] {
            let exported = export_dialog_and_completeness(
                &dialog,
                &ExportContext {
                    capture_id: "fixture.pcap",
                    facts: &facts,
                    max_inline_media_bytes: None,
                    analysis,
                    media: &[],
                    related_legs: &[],
                },
                ObservedAudio::NotConsidered,
                exported_at()?,
            );
            let rows = exported.completeness.omissions();
            assert_eq!(
                rows.len(),
                expected,
                "an analysis that ranked {expected} spot(s) must produce \
                 {expected} row(s): {rows:?}"
            );
            assert_eq!(
                incomplete_clauses(&exported.completeness.note),
                expected,
                "and the prose must agree: {}",
                exported.completeness.note
            );
        }
        Ok(())
    }

    /// RV5: a container's digest is the digest of the bytes an export writes.
    ///
    /// The whole point of the value is that it joins to something outside this
    /// process — a `SHA256SUMS` line, a store's ledger entry. A digest over
    /// some other rendering of the same container would look right and match
    /// nothing.
    #[test]
    fn a_container_digest_is_the_digest_of_the_bytes_an_export_writes() -> Result<(), TestError> {
        use sha2::Digest as _;

        let dialog = dialog_with(&[response(200, "OK")?])?;
        let container = export_with(&dialog, &clean_facts())?;
        let sealed = seal(container, None);
        let json = sealed_json(&sealed)?;

        let expected: String = sha2::Sha256::digest(json.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            container_digest(json.as_bytes()),
            expected,
            "the digest must be SHA-256 over the container's own bytes, in the \
             lowercase hex `sha256sum` writes"
        );
        Ok(())
    }

    /// Two different containers do not share a digest.
    ///
    /// The anti-vacuity half: a function returning a constant would satisfy
    /// the test above and identify nothing.
    #[test]
    fn two_different_containers_do_not_share_a_digest() -> Result<(), TestError> {
        let ok = export_with(&dialog_with(&[response(200, "OK")?])?, &clean_facts())?;
        let busy = export_with(
            &dialog_with(&[response(486, "Busy Here")?])?,
            &clean_facts(),
        )?;
        let one = sealed_json(&seal(ok, None))?;
        let two = sealed_json(&seal(busy, None))?;
        assert_ne!(
            container_digest(one.as_bytes()),
            container_digest(two.as_bytes()),
            "two containers describing different calls hashed to one value, so \
             the digest identifies nothing"
        );
        Ok(())
    }

    /// Zero suppressed dialogs is not "some".
    ///
    /// The counter is a `u64`, and the clause is gated on `> 0`. A `!= 0`
    /// written as `is_some`-style truthiness, or a clause built
    /// unconditionally, would put "0 dialog(s) carried a deny flag" into every
    /// container -- which reads as a measurement of something.
    #[test]
    fn zero_suppressed_dialogs_produces_no_clause() -> Result<(), TestError> {
        let mut facts = clean_facts();
        facts.dialogs_suppressed_by_deny = 0;
        let json = serde_json::to_string(&export_with(
            &dialog_with(&[response(200, "OK")?])?,
            &facts,
        )?)?;
        assert!(!json.contains("deny flag"), "zero is not some: {json}");
        Ok(())
    }

    /// Both causes are reported when both happened.
    ///
    /// They are independent, and an `else if` between them would hide whichever
    /// came second. The run that has both is the one whose container is least
    /// self-explanatory.
    #[test]
    fn both_suppression_causes_appear_together() -> Result<(), TestError> {
        let mut facts = clean_facts();
        facts.gate_closed_during_run = true;
        facts.dialogs_suppressed_by_deny = 2;
        let json = serde_json::to_string(&export_with(
            &dialog_with(&[response(200, "OK")?])?,
            &facts,
        )?)?;
        assert!(
            json.contains("closed the persistence gate"),
            "the gate clause is missing: {json}"
        );
        assert!(
            json.contains("2 dialog(s) carried a deny flag"),
            "the deny clause is missing: {json}"
        );
        Ok(())
    }

    /// A later instance's uuid is a function of the first instance's uuid
    /// and the revision number alone: revision 0 is the first instance, each
    /// later revision differs from every other, the value is a well-formed
    /// UUIDv8, and it keeps the first instance's 48-bit timestamp.
    ///
    /// [Section 4.1.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.2):
    /// "The UUID value MUST be globally unique."
    #[test]
    fn a_revision_uuid_is_new_deterministic_and_well_formed() {
        let base = "018bcfe5-6800-8a6b-a667-78f1c5213800";
        assert_eq!(
            revision_uuid(base, 0),
            base,
            "revision 0 is the first instance"
        );
        let chain: Vec<String> = (0..4).map(|n| revision_uuid(base, n)).collect();
        for (i, a) in chain.iter().enumerate() {
            for b in &chain[i + 1..] {
                assert_ne!(a, b, "two revisions share a uuid");
            }
            assert_eq!(&a[..13], &base[..13], "the timestamp is kept");
            assert_eq!(&a[14..15], "8", "version 8");
            assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"), "variant 10");
            assert_eq!(a.len(), 36);
        }
        assert_eq!(
            chain,
            (0..4).map(|n| revision_uuid(base, n)).collect::<Vec<_>>()
        );
        assert_ne!(
            revision_uuid(base, 1),
            revision_uuid("018bcfe5-6800-8a6b-a667-78f1c5213801", 1),
            "the derivation is keyed on the first instance's uuid"
        );
    }

    /// Every `encoding: "json"` body is the JSON value itself, never a string
    /// holding JSON text.
    ///
    /// [Section 2.3.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3.2):
    /// "\"json\": The value of the body parameter is a JSON value (object,
    /// array, number, string, or one of the literals true, false, or null)".
    /// sipnab's bodies are objects, so a string in that position is the
    /// object's text, which a consumer would have to parse a second time.
    #[test]
    fn a_json_encoded_body_is_the_json_value_not_its_text() -> Result<(), TestError> {
        let v = export_with(&dialog_with(&[response(200, "OK")?])?, &clean_facts())?;
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&v)?)?;
        let mut seen = 0;
        for key in ["attachments", "analysis"] {
            for object in json[key].as_array().ok_or("an array")? {
                if object["encoding"] == "json" {
                    seen += 1;
                    assert!(
                        object["body"].is_object(),
                        "a {key} body with encoding json must be the object, not its text: {}",
                        object["body"]
                    );
                }
            }
        }
        assert!(seen >= 2, "the export carries json bodies to check: {json}");
        Ok(())
    }

    /// The counts reach the container as fields, not only as prose.
    ///
    /// A consumer branching on this should not have to parse an English
    /// sentence. The note explains; the fields are what a program reads.
    #[test]
    fn suppression_is_carried_as_fields_a_program_can_read() -> Result<(), TestError> {
        let mut facts = clean_facts();
        facts.gate_closed_during_run = true;
        facts.dialogs_suppressed_by_deny = 5;
        let v = export_with(&dialog_with(&[response(200, "OK")?])?, &facts)?;
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&v)?)?;
        let body = &json["analysis"][0]["body"];
        let completeness = &body["capture_completeness"];
        assert_eq!(
            completeness["gate_closed_during_run"], true,
            "the gate fact must be a field: {body}"
        );
        assert_eq!(
            completeness["dialogs_suppressed_by_deny"], 5,
            "the deny count must be a field: {body}"
        );
        Ok(())
    }

    /// A suppressed dialog is a decision, not a gap in what sipnab saw.
    ///
    /// The wording matters as much as the presence. Every other INCOMPLETE
    /// clause in this note reports something the capture MISSED; these two
    /// report something an operator CHOSE. A reader who cannot tell them apart
    /// will go looking for a capture fault that does not exist.
    #[test]
    fn a_deliberate_suppression_does_not_read_as_a_capture_fault() -> Result<(), TestError> {
        let mut facts = clean_facts();
        facts.dialogs_suppressed_by_deny = 1;
        let json = serde_json::to_string(&export_with(
            &dialog_with(&[response(200, "OK")?])?,
            &facts,
        )?)?;
        assert!(
            json.contains("not a gap in what sipnab saw"),
            "the clause must say the absence was chosen: {json}"
        );
        Ok(())
    }

    /// The container's own fields: version, extensions, and the two things
    /// [core-04 section 4.1.7](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.7) and the signing decision say must NOT be
    /// there.
    #[test]
    fn the_container_declares_its_version_and_signs_nothing() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;

        assert_eq!(v["vcon"], VCON_SYNTAX_VERSION);
        // Both, and CC is not optional decoration: `Party.role` is a CC
        // parameter, not a core-04 section 4.2 one, and the container that uses a
        // field must name the extension that defines it.
        assert_eq!(v["extensions"], serde_json::json!(["sip-signaling", "CC"]));
        assert!(
            v["parties"]
                .as_array()
                .ok_or("parties is an array")?
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

        // `subject` is "the subject or topic of the conversation", and it now
        // names the dialog so a store whose search matches subject or UUID can
        // find this container by something an operator knows. What it must
        // NEVER become is a place for sipnab's words about the call: the
        // caveat has its own two surfaces, and a caveat here would read as
        // authoritative and sit where a reader expects the participants'.
        let subject = v["subject"].as_str().ok_or("a subject is present")?;
        assert!(
            subject.contains("vcon-fixture@example.com"),
            "the subject must identify the dialog: {subject:?}"
        );
        for verdict in [
            "SIGNALING ONLY",
            "incomplete",
            "PARTIAL",
            "no media",
            "failed",
            "sipnab read",
        ] {
            assert!(
                !subject.contains(verdict),
                "the subject carries a caveat or a verdict ({verdict:?}), \
                 which belongs on the two surfaces built for it: {subject:?}"
            );
        }

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
        Ok(())
    }

    /// `created_at` is the EXPORT clock, not the dialog's.
    ///
    /// The two are different values in this fixture on purpose: a container
    /// that stamped the call's start here would look contemporaneous with
    /// traffic it may describe years later.
    #[test]
    fn created_at_is_the_export_time_and_not_the_dialog_time() -> Result<(), TestError> {
        let dialog = dialog_with(&[])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;

        assert_eq!(v["created_at"], exported_at()?.to_rfc3339());
        assert_ne!(
            v["created_at"],
            serde_json::json!(dialog.created_at.to_rfc3339()),
            "created_at took the dialog's clock, so a re-export would claim \
             the conversation happened when the file was written"
        );
        Ok(())
    }

    /// Parties come from the observed headers and always say
    /// `validation: "none"`.
    ///
    /// `name` IS emitted, and this test is where that stays honest. The
    /// earlier rule here was that a `From` display name is an unverified claim
    /// by the sender, so promoting it asserts an identity — true of the name
    /// alone, and answered by the field beside it rather than by silence.
    /// `validation: "none"` on every party says sipnab established nothing, so
    /// a name under the declared key reads as what the header said. Withholding
    /// it instead only meant every generic consumer showed an unnamed party.
    #[test]
    fn parties_are_the_observed_headers_and_never_a_verified_name() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let parties = v["parties"].as_array().ok_or("parties is an array")?;

        assert_eq!(parties.len(), 3, "two observed parties plus the observer");

        for party in parties {
            assert_eq!(
                party["validation"], "none",
                "sipnab cannot validate a party and must not imply it did: {party}"
            );
            assert!(
                party.get("validation").is_some(),
                "a party carrying a name without `validation` beside it \
                 asserts an identity: {party}"
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
        Ok(())
    }

    /// A response to the [`invite`] transaction with an explicit `To` tag and
    /// extra headers, so a proxy's hop-by-hop `100` and the callee's own
    /// responses can be told apart.
    fn tagged_response(
        code: u16,
        reason: &str,
        to_tag: Option<&str>,
        extra: &[&str],
    ) -> Result<crate::sip::SipMessage, TestError> {
        let to = match to_tag {
            Some(t) => format!("To: \"Bob\" <sip:bob@example.net>;tag={t}"),
            None => "To: \"Bob\" <sip:bob@example.net>".to_string(),
        };
        let mut headers = vec![
            "From: \"Alice\" <sip:alice@example.com>;tag=t1",
            to.as_str(),
            "Call-ID: vcon-fixture@example.com",
            "CSeq: 1 INVITE",
        ];
        headers.extend_from_slice(extra);
        headers.push("Content-Length: 0");
        message(&format!("SIP/2.0 {code} {reason}"), &headers)
    }

    /// The callee party of a dialog, as exported.
    fn callee_of(dialog: &SipDialog) -> Result<serde_json::Value, TestError> {
        let v = serde_json::to_value(export_with(dialog, &clean_facts())?)?;
        Ok(v["parties"][1].clone())
    }

    const PROXY_SERVER: &str = "Server: OpenSIPS (4.0.1 (aarch64/linux))";

    /// A proxy's `100 Trying` says nothing about the callee.
    ///
    /// [RFC 3261 section 16.7](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.7)
    /// keeps a `100` hop-by-hop: the proxy generates it and never forwards
    /// one. A replay call exported the proxy's `Server` banner as the callee's
    /// `sip_user_agent` because the exporter read the first response in the
    /// ladder, which was the proxy's `100`.
    #[test]
    fn a_proxy_100_trying_does_not_name_the_callee_software() -> Result<(), TestError> {
        let dialog = dialog_with(&[
            tagged_response(100, "Giving it a try", None, &[PROXY_SERVER])?,
            tagged_response(
                180,
                "Ringing",
                Some("t2"),
                &["Contact: <sip:bob@192.0.2.20:5070>", "Server: BobUA/2.0"],
            )?,
            tagged_response(
                200,
                "OK",
                Some("t2"),
                &["Contact: <sip:bob@192.0.2.20:5070>"],
            )?,
        ])?;
        let callee = callee_of(&dialog)?;
        assert_eq!(
            callee["sip_user_agent"], "BobUA/2.0",
            "the callee's software is on its own 180, not the proxy's 100: {callee}"
        );
        assert_eq!(
            callee["sip_contact"], "<sip:bob@192.0.2.20:5070>",
            "the callee's Contact is on its own responses: {callee}"
        );
        Ok(())
    }

    /// A callee that names no software anywhere gets no `sip_user_agent`,
    /// never the proxy's.
    #[test]
    fn a_callee_with_no_banner_borrows_none_from_the_proxy() -> Result<(), TestError> {
        let dialog = dialog_with(&[
            tagged_response(100, "Giving it a try", None, &[PROXY_SERVER])?,
            tagged_response(180, "Ringing", Some("t2"), &[])?,
            tagged_response(200, "OK", Some("t2"), &[])?,
        ])?;
        let callee = callee_of(&dialog)?;
        assert!(
            callee.get("sip_user_agent").is_none(),
            "no message the callee sent carried a banner: {callee}"
        );
        Ok(())
    }

    /// A proxy's `100` to an in-dialog request echoes the callee's tag.
    ///
    /// A re-INVITE already carries the remote `To` tag, so the `100` a proxy
    /// generates for it carries that tag too while still describing the proxy.
    /// The tag alone cannot clear a `100`.
    #[test]
    fn a_proxy_100_carrying_the_remote_tag_still_does_not_name_the_callee() -> Result<(), TestError>
    {
        let dialog = dialog_with(&[
            tagged_response(200, "OK", Some("t2"), &[])?,
            tagged_response(100, "Giving it a try", Some("t2"), &[PROXY_SERVER])?,
        ])?;
        let callee = callee_of(&dialog)?;
        assert!(
            callee.get("sip_user_agent").is_none(),
            "a 100 is hop-by-hop whatever tag it echoes: {callee}"
        );
        Ok(())
    }

    /// A response carrying a tag other than the dialog's remote tag came from
    /// some other element (another fork, or a proxy), not the callee the
    /// dialog was established with.
    #[test]
    fn a_response_without_the_remote_tag_does_not_name_the_callee() -> Result<(), TestError> {
        let dialog = dialog_with(&[
            tagged_response(
                183,
                "Session Progress",
                Some("fork-a"),
                &["Server: OtherFork/1.0"],
            )?,
            tagged_response(200, "OK", Some("t2"), &["Server: BobUA/2.0"])?,
        ])?;
        let callee = callee_of(&dialog)?;
        assert_eq!(
            callee["sip_user_agent"], "BobUA/2.0",
            "only the tag that confirmed the dialog is the callee's: {callee}"
        );
        Ok(())
    }

    /// The callee's own requests (its BYE) carry its `User-Agent` too.
    #[test]
    fn the_callees_own_request_names_its_software() -> Result<(), TestError> {
        let bye = message(
            "BYE sip:alice@example.com SIP/2.0",
            &[
                "From: \"Bob\" <sip:bob@example.net>;tag=t2",
                "To: \"Alice\" <sip:alice@example.com>;tag=t1",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 BYE",
                "User-Agent: BobPhone/3.0",
                "Content-Length: 0",
            ],
        )?;
        let dialog = dialog_with(&[
            tagged_response(100, "Giving it a try", None, &[PROXY_SERVER])?,
            tagged_response(200, "OK", Some("t2"), &[])?,
            bye,
        ])?;
        let callee = callee_of(&dialog)?;
        assert_eq!(
            callee["sip_user_agent"], "BobPhone/3.0",
            "a request the callee sent names the callee's software: {callee}"
        );
        Ok(())
    }

    /// The final party is sipnab, and it is unmistakably an observer.
    #[test]
    fn the_last_party_is_the_sipnab_observer() -> Result<(), TestError> {
        let dialog = dialog_with(&[])?;
        let vcon = export_with(&dialog, &clean_facts())?;
        let observer = vcon.observer_index();
        assert_eq!(observer, vcon.parties.len() - 1);

        let v = serde_json::to_value(&vcon)?;
        let party = &v["parties"][observer];
        assert_eq!(party["role"], OBSERVER_ROLE);
        assert!(
            party.get("sip").is_none(),
            "sipnab sent no SIP; a URI here would be a participant that never \
             existed: {party}"
        );
        let ua = party["sip_user_agent"].as_str().ok_or("names itself")?;
        assert!(
            ua.contains(env!("CARGO_PKG_VERSION")) && ua.contains(node_name()),
            "the observer must name the build and the box that produced this \
             container, or an attachment's provenance resolves to nothing: {ua}"
        );
        Ok(())
    }

    /// A dialog sipnab saw succeed carries a core-04 placeholder: typed
    /// `recording`, with no Dialog Content.
    ///
    /// [core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) replaced core-03's Dialog Object
    /// "with no parameters" by a placeholder that "contains only the type
    /// parameter", and a placeholder for a call that was set up "MUST be of
    /// type "recording"". The anti-vacuity half matters as much as the type:
    /// no media-shaped field may appear merely because the object is typed,
    /// and `incomplete` must not appear merely because a signaling-only export
    /// has no media.
    #[test]
    fn a_signaling_only_dialog_object_is_a_placeholder_that_describes_no_media()
    -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let object = &v["dialog"][0];

        assert_eq!(object["sip_call_id"], "vcon-fixture@example.com");
        assert_eq!(
            object["type"], RECORDING_TYPE,
            "core-04 section 4.3.1 requires a type on every Dialog Object, and \
             a placeholder for a call that was set up is `recording`: {object}"
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
        Ok(())
    }

    /// A Dialog Object that carries nothing and failed at nothing is a
    /// `recording` placeholder and names no disposition.
    ///
    /// [core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3): a placeholder "contains only the
    /// type parameter" and is `recording` for a call that was set up.
    /// `incomplete` is the wrong reach because
    /// [core-04 section 4.3.1.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.5) binds it to a call that
    /// "failed to be setup", which is a claim about the CALL that a successful
    /// capture must not make.
    #[test]
    fn a_dialog_that_failed_at_nothing_is_a_recording_placeholder_with_no_reason()
    -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let object = &v["dialog"][0];

        assert_eq!(
            object["type"], RECORDING_TYPE,
            "the call connected; core-04 section 4.3 types its placeholder \
             `recording`: {object}"
        );
        assert!(
            object.get("disposition").is_none(),
            "nothing failed, so there is no reason to name: {object}"
        );
        assert_eq!(
            object["sip_call_id"], "vcon-fixture@example.com",
            "the object must still identify the dialog it stands for: {object}"
        );
        Ok(())
    }

    /// The vendored schema's Dialog constraints, read from the file the gate
    /// validates against.
    fn vendored_dialog_schema() -> Result<serde_json::Value, TestError> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/schemas/vcon.schema.json"
        );
        let text = std::fs::read_to_string(path)?;
        let schema: serde_json::Value = serde_json::from_str(&text)?;
        Ok(schema["definitions"]["Dialog"].clone())
    }

    /// The vendored schema requires `type`, and only `type`, on a Dialog
    /// Object.
    ///
    /// The core-04 schema of [Appendix B](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-B). core-03's copy
    /// carried a local deviation, `type` out of `required`, for the Dialog
    /// Object "with no parameters" core-03's prose allowed; core-04 replaced
    /// that object by a typed placeholder and made `start` a SHOULD
    /// ([core-04 section 4.3.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.2)). A copy that still reads
    /// `["start"]` or `["type", "start"]` is the core-03 file.
    #[test]
    fn the_vendored_schema_requires_type_and_only_type() -> Result<(), TestError> {
        let dialog = vendored_dialog_schema()?;

        assert_eq!(
            dialog["required"],
            serde_json::json!(["type"]),
            "core-04 requires `type` alone; anything else is not the core-04 \
             schema"
        );

        // Everything else about the object must still be the published
        // constraint, or the deviation has quietly grown past its warrant.
        let kinds = dialog["properties"]["type"]["enum"]
            .as_array()
            .ok_or("type is still a closed enum")?;
        assert_eq!(
            kinds.len(),
            5,
            "core-04 section 4.3.1 defines five dialog types; a sixth means \
             the draft moved and the typing rule needs revisiting: {kinds:?}"
        );
        let dispositions = dialog["properties"]["disposition"]["enum"]
            .as_array()
            .ok_or("disposition is still a closed enum")?;
        assert_eq!(
            dispositions.len(),
            6,
            "§4.3.11 defines six dispositions, and the mapping below is \
             checked against exactly this list: {dispositions:?}"
        );
        Ok(())
    }

    /// Every disposition the export can emit is one the schema admits.
    ///
    /// The mapping and the schema are two independent statements of the same
    /// closed set, and `an_observed_final_failure_maps_to_a_disposition` pins
    /// only the codes someone thought to list. This sweeps the whole status
    /// space, so a disposition invented outside [core-04 section 4.3.11](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11)
    /// cannot reach a container by way of a code nobody wrote a case for.
    #[test]
    fn every_disposition_the_export_can_emit_is_one_the_schema_admits() -> Result<(), TestError> {
        let schema = vendored_dialog_schema()?;
        let admitted: Vec<&str> = schema["properties"]["disposition"]["enum"]
            .as_array()
            .ok_or("closed enum")?
            .iter()
            .map(|v| v.as_str().ok_or("string"))
            .collect::<Result<_, _>>()?;

        let mut emitted = std::collections::BTreeSet::new();
        for code in 100u16..=699 {
            let dialog = dialog_with(&[response(code, "Sweep")?])?;
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
            let Some(d) = v["dialog"][0].get("disposition") else {
                continue;
            };
            let d = d.as_str().ok_or("disposition is a string")?.to_string();
            assert!(
                admitted.contains(&d.as_str()),
                "status {code} emitted disposition {d:?}, which §4.3.11 does \
                 not define; the schema admits only {admitted:?}"
            );
            emitted.insert(d);
        }

        assert!(
            !emitted.is_empty(),
            "the sweep produced no disposition at all, so it proved nothing \
             -- the mapping or the fixture stopped reaching this branch"
        );
        Ok(())
    }

    /// An object that names `incomplete` can always name WHY.
    ///
    /// [Section 4.3.11 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11) makes the disposition a MUST on an
    /// incomplete object. The two fields are now decided together for exactly
    /// this reason, and the assertion runs in both directions: the type without
    /// the reason is a spec violation, and the reason without the type is an
    /// orphan field a consumer keyed on `type` will never read.
    #[test]
    fn an_object_that_names_incomplete_can_always_name_why() -> Result<(), TestError> {
        for code in [200u16, 100, 180, 302, 486, 503, 408, 404, 500, 600] {
            let dialog = dialog_with(&[response(code, "Fixture")?])?;
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
            let object = &v["dialog"][0];
            let typed_incomplete =
                object.get("type").and_then(|t| t.as_str()) == Some(INCOMPLETE_TYPE);
            let has_reason = object.get("disposition").is_some();

            assert_eq!(
                typed_incomplete, has_reason,
                "status {code}: §4.3.1 binds `incomplete` and `disposition` \
                 together, so one without the other is always a defect: \
                 {object}"
            );
        }
        Ok(())
    }

    /// The three ways sipnab observes no failure all reach the same shape.
    ///
    /// A call that succeeded, a call whose final response was never seen, and
    /// a call that was redirected are different facts about the CONVERSATION
    /// and the identical fact about the capture: no failure was observed. A
    /// container that distinguished them would be reporting something sipnab
    /// does not know.
    #[test]
    fn no_observed_failure_reaches_one_shape_whatever_the_reason() -> Result<(), TestError> {
        let success = dialog_with(&[response(200, "OK")?])?;
        let unanswered = dialog_with(&[response(100, "Trying")?])?;
        let redirected = dialog_with(&[response(302, "Moved Temporarily")?])?;

        for (label, dialog) in [
            ("answered", &success),
            ("no final response", &unanswered),
            ("redirected", &redirected),
        ] {
            let v = serde_json::to_value(export_with(dialog, &clean_facts())?)?;
            let object = &v["dialog"][0];
            assert!(
                object["type"] == RECORDING_TYPE && object.get("disposition").is_none(),
                "{label}: sipnab observed no failure, so the object is the \
                 `recording` placeholder and names no reason it does not \
                 have: {object}"
            );
        }
        Ok(())
    }

    /// A placeholder object still carries what a consumer indexes on.
    ///
    /// A placeholder carries no content, and costs nothing only while the
    /// object remains addressable. An Analysis Object points at a dialog by
    /// INDEX and the identity fields are how a reader confirms it landed on
    /// the right one, so an object stripped to nothing would make the
    /// reference unverifiable.
    #[test]
    fn a_placeholder_object_still_carries_the_identity_a_consumer_indexes_on()
    -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let object = &v["dialog"][0];

        assert_eq!(object["type"], RECORDING_TYPE, "premise: {object}");
        for required in ["sip_call_id", "start"] {
            assert!(
                object.get(required).is_some(),
                "a placeholder object is still the anchor an Analysis Object \
                 indexes into; without {required} the reference cannot be \
                 checked against anything: {object}"
            );
        }
        assert!(
            object.as_object().ok_or("an object")?.len() >= 3,
            "the object collapsed to its type alone, which is the bare \
             placeholder of core-04 section 4.3 rather than an export that \
             kept its identity: {object}"
        );
        Ok(())
    }

    /// A FAILED call's container validates against the working group's schema.
    ///
    /// The existing gate validates a call that succeeded, which is the branch
    /// that emits no `type` and no `disposition` -- so it exercises none of
    /// the constraints the schema places on either. The failure branch is the
    /// one that fills both fields from closed enums, and until now nothing
    /// checked its output against the schema at all.
    #[test]
    fn a_failed_call_container_validates_against_the_working_group_schema() -> Result<(), TestError>
    {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/schemas/vcon.schema.json"
        );
        let text = std::fs::read_to_string(path)?;
        let schema: serde_json::Value = serde_json::from_str(&text)?;
        let validator = jsonschema::validator_for(&schema)?;

        for code in [486u16, 503, 408, 480, 404, 500, 600] {
            let dialog = dialog_with(&[response(code, "Fixture")?])?;
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
            assert!(
                v["dialog"][0].get("disposition").is_some(),
                "premise: {code} must reach the failure branch, or this \
                 validates the shape it was written to exclude: {}",
                v["dialog"][0]
            );
            if let Err(e) = validator.validate(&v) {
                return Err(
                    format!("the container for a {code} does not validate: {e}\n{v:#}").into(),
                );
            }
        }
        Ok(())
    }

    /// An INVITE carrying the headers PV5-PV7 read.
    fn invite_with_provenance() -> Result<crate::sip::SipMessage, TestError> {
        message(
            "INVITE sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 INVITE",
                "Contact: <sip:alice@10.0.0.1:5060>",
                "User-Agent: AliceUA/1.0",
                "Identity: eyJhbGciOiJFUzI1NiJ9.eyJhdHRlc3QiOiJBIn0.SIGNATURE;\
                 info=<https://example.com/cert.pem>;alg=ES256;ppt=shaken",
                "Session-ID: ab30317f1a784dc48ff824d0d3715d86;\
                 remote=47755a9de7794ba387653f2099600ef2",
                "Content-Length: 0",
            ],
        )
    }

    /// A dialog opened by [`invite_with_provenance`].
    fn provenance_dialog() -> Result<SipDialog, TestError> {
        let invite = invite_with_provenance()?;
        let mut dialog = SipDialog::new(&invite).ok_or("INVITE opens a dialog")?;
        crate::sip::dialog::update_state(&mut dialog, &response(200, "OK")?);
        dialog.messages.push(response(200, "OK")?);
        Ok(dialog)
    }

    /// PV4: the container names its own subject.
    ///
    /// A store whose search matches subject or UUID substring can otherwise
    /// find a sipnab container only by a UUID nobody memorized. The subject
    /// is purely descriptive -- it names the dialog, it does not characterize
    /// the conversation, which an observer is in no position to do.
    #[test]
    fn a_container_carries_a_subject_that_names_the_dialog() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let subject = v["subject"].as_str().ok_or("a subject is present")?;
        assert!(
            subject.contains("vcon-fixture@example.com"),
            "the subject must carry the Call-ID or the container stays \
             unfindable by anything an operator knows: {subject:?}"
        );
        Ok(())
    }

    /// PV5: the display name travels under the declared key too.
    ///
    /// `sip_display_name` is a sipnab extension no consumer reads.
    /// `validation: "none"` on every party is what makes `name` honest: it
    /// says this is a name the wire carried, not a person sipnab identified.
    #[test]
    fn a_party_carries_the_display_name_under_the_declared_key() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let parties = v["parties"].as_array().ok_or("parties")?;

        assert_eq!(parties[0]["name"], "Alice", "caller name: {}", parties[0]);
        assert_eq!(parties[1]["name"], "Bob", "callee name: {}", parties[1]);
        for (i, p) in parties.iter().enumerate() {
            assert_eq!(
                p["validation"], "none",
                "party {i} names a person without saying it verified nothing: {p}"
            );
        }
        assert!(
            parties[2].get("name").is_none(),
            "the observer is not a named participant: {}",
            parties[2]
        );
        Ok(())
    }

    /// Every surface describing `--export-vcon` states the party-name rule the
    /// exporter actually applies.
    ///
    /// The exporter writes a party `name` exactly when the `From` or `To`
    /// carried a display name, quoted or bare, and never derives one from the
    /// URI's user part. The `--export-vcon` help kept saying no party carries
    /// a `name` after the exporter started writing one, and a replay call
    /// exported `"name": "alice"` under that help. This test measures the
    /// rule from the exporter first, then holds the help and every document
    /// row describing the export to it: a denial while the exporter emits a
    /// name, or a missing statement of the display-name rule, fails here.
    #[test]
    fn help_and_docs_state_the_party_name_rule_the_exporter_applies() -> Result<(), TestError> {
        use clap::CommandFactory;

        let names_for =
            |from: &str, to: &str| -> Result<(serde_json::Value, serde_json::Value), TestError> {
                let invite = message(
                    "INVITE sip:bob@example.net SIP/2.0",
                    &[
                        from,
                        to,
                        "Call-ID: vcon-name-rule@example.invalid",
                        "CSeq: 1 INVITE",
                        "Content-Length: 0",
                    ],
                )?;
                let dialog = SipDialog::new(&invite).ok_or("INVITE opens a dialog")?;
                let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
                Ok((
                    v["parties"][0]["name"].clone(),
                    v["parties"][1]["name"].clone(),
                ))
            };
        let quoted = names_for(
            "From: \"alice\" <sip:alice@example.invalid>;tag=t1",
            "To: \"bob\" <sip:bob@example.invalid>",
        )?;
        let bare = names_for(
            "From: alice <sip:alice@example.invalid>;tag=t1",
            "To: bob <sip:bob@example.invalid>",
        )?;
        let none = names_for(
            "From: <sip:alice@example.invalid>;tag=t1",
            "To: <sip:bob@example.invalid>",
        )?;
        assert_eq!(
            quoted,
            (
                serde_json::Value::from("alice"),
                serde_json::Value::from("bob")
            ),
            "quoted"
        );
        assert_eq!(
            bare,
            (
                serde_json::Value::from("alice"),
                serde_json::Value::from("bob")
            ),
            "bare token"
        );
        assert_eq!(
            none,
            (serde_json::Value::Null, serde_json::Value::Null),
            "a header with no display name must not lend its user part as a name"
        );
        let exporter_emits_display_name = quoted.0.is_string();

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let read = |rel: &str| std::fs::read_to_string(root.join(rel));
        let row = |text: &str, prefix: &str| -> Result<String, TestError> {
            Ok(text
                .lines()
                .find(|l| l.starts_with(prefix))
                .ok_or_else(|| format!("no row starting {prefix:?}"))?
                .to_string())
        };
        let mcp_doc = read("docs/mcp-tools-vcon.md")?;
        let mcp_section = mcp_doc
            .split("### `export_vcon`")
            .nth(1)
            .and_then(|s| s.split("\n### ").next())
            .ok_or("docs/mcp-tools-vcon.md has no export_vcon section")?
            .to_string();
        let help = crate::cli::Cli::command()
            .get_arguments()
            .find(|a| a.get_id() == "export_vcon")
            .and_then(|a| a.get_long_help())
            .ok_or("--export-vcon has long help")?
            .to_string();
        let surfaces = [
            ("--export-vcon --help", help),
            (
                "docs/cli-reference.md --export-vcon row",
                row(&read("docs/cli-reference.md")?, "| `--export-vcon` |")?,
            ),
            (
                "docs/internals/build-ci-release.md vcon feature row",
                row(&read("docs/internals/build-ci-release.md")?, "| `vcon` |")?,
            ),
            ("docs/mcp-tools-vcon.md export_vcon section", mcp_section),
            ("docs/vcon.md", read("docs/vcon.md")?),
        ];
        let denials = [
            "no party names",
            "no party name,",
            "no party name and",
            "no party name.",
            "no party carries a `name`",
            "no party carries a name",
        ];
        for (label, text) in &surfaces {
            let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
            let lower = flat.to_lowercase();
            if exporter_emits_display_name {
                for denial in denials {
                    assert!(
                        !lower.contains(denial),
                        "{label} says {denial:?}, but the exporter writes the \
                         display name as a party name: {flat}"
                    );
                }
                assert!(
                    lower.contains("display name"),
                    "{label} does not say a party name is the wire's display \
                     name: {flat}"
                );
            }
        }
        Ok(())
    }

    /// PV6: an observed PASSporT is transcribed, never asserted.
    ///
    /// A passive tap sees the `Identity` header verbatim and can copy it. It
    /// cannot verify it -- no certificate is fetched, no signature checked --
    /// so `validation` stays `"none"` beside it. The pairing is the point: the
    /// PASSporT is evidence a consumer may verify, not a verdict sipnab reached.
    #[test]
    fn an_observed_passport_is_copied_verbatim_and_still_unverified() -> Result<(), TestError> {
        let dialog = provenance_dialog()?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let caller = &v["parties"][0];

        let stir = caller["stir"].as_str().ok_or("the PASSporT is carried")?;
        assert!(
            stir.starts_with("eyJhbGciOiJFUzI1NiJ9."),
            "the JWS must be copied verbatim, not reformatted: {stir:?}"
        );
        assert!(
            !stir.contains("info=") && !stir.contains("ppt="),
            "`stir` is the JWS alone -- the header parameters are not part of \
             it and a consumer parsing this as a token would choke: {stir:?}"
        );
        assert_eq!(
            caller["validation"], "none",
            "sipnab fetched no certificate and checked no signature, so \
             carrying a PASSporT must not raise the claim: {caller}"
        );
        assert!(
            v["parties"][1].get("stir").is_none(),
            "the Identity header authenticates the CALLER; attaching it to \
             the callee would invent an attestation: {}",
            v["parties"][1]
        );
        Ok(())
    }

    /// PV7: RFC 7989 `Session-ID` becomes the declared `session_id`.
    ///
    /// The draft's own leg-correlation mechanism, and the one identifier that
    /// survives a B2BUA where Call-ID does not. sipnab approximates leg
    /// correlation with custom `sip_from_tag`/`sip_to_tag`; this is the field
    /// a consumer already knows how to join on.
    #[test]
    fn an_observed_session_id_is_carried_as_the_declared_pair() -> Result<(), TestError> {
        let dialog = provenance_dialog()?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let sid = &v["dialog"][0]["session_id"];

        assert_eq!(
            sid["local"], "ab30317f1a784dc48ff824d0d3715d86",
            "the local half is the UUID this side contributed: {sid}"
        );
        assert_eq!(
            sid["remote"], "47755a9de7794ba387653f2099600ef2",
            "the remote half is the one that survives the B2BUA: {sid}"
        );
        Ok(())
    }

    /// A dialog whose messages carry neither header emits neither field.
    ///
    /// The anti-vacuity half of PV6 and PV7 together: absent means "not
    /// observed", and a synthesized empty `session_id` or `stir` would report
    /// a header that never arrived.
    #[test]
    fn absent_provenance_headers_produce_no_fields_at_all() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;

        assert!(
            v["dialog"][0].get("session_id").is_none(),
            "no Session-ID was observed: {}",
            v["dialog"][0]
        );
        for (i, p) in v["parties"].as_array().ok_or("parties")?.iter().enumerate() {
            assert!(
                p.get("stir").is_none(),
                "party {i} carries a PASSporT that never arrived: {p}"
            );
        }
        Ok(())
    }

    /// A dialog whose opening INVITE carries one extra header.
    fn dialog_carrying_header(name: &str, value: &str) -> Result<SipDialog, TestError> {
        let invite = message(
            "INVITE sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 INVITE",
                &format!("{name}: {value}"),
                "Content-Length: 0",
            ],
        )?;
        Ok(SipDialog::new(&invite).ok_or("INVITE opens a dialog")?)
    }
    /// No party in ANY export shape carries a name without its disclaimer.
    ///
    /// "No `name`" was asserted in three separate files, and changing the
    /// contract found them one at a time by breaking the build. The invariant
    /// that replaced it is a PAIRING, so it is checked here across every shape
    /// the exporter can produce rather than restated per surface.
    #[test]
    fn no_export_shape_names_a_party_without_saying_it_verified_nothing() -> Result<(), TestError> {
        let shapes: [(&str, SipDialog); 4] = [
            ("answered", dialog_with(&[response(200, "OK")?])?),
            ("failed", dialog_with(&[response(486, "Busy Here")?])?),
            ("unanswered", dialog_with(&[response(100, "Trying")?])?),
            ("with provenance headers", provenance_dialog()?),
        ];
        for (label, dialog) in shapes {
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
            let parties = v["parties"].as_array().ok_or("parties")?;
            assert!(!parties.is_empty(), "{label}: no parties at all");
            for (i, p) in parties.iter().enumerate() {
                assert_eq!(
                    p["validation"], "none",
                    "{label}: party {i} omits the disclaimer that makes every \
                     other field on it readable as observation: {p}"
                );
            }
        }
        Ok(())
    }

    /// A PASSporT never travels without the disclaimer either.
    ///
    /// `stir` is the strongest-looking field a passive observer can fill: it
    /// is a signed token, and a reader may take its presence for verification.
    /// sipnab fetched no certificate and checked no signature, so the token and
    /// `validation: "none"` are one statement split across two keys.
    #[test]
    fn a_passport_never_travels_without_the_disclaimer_beside_it() -> Result<(), TestError> {
        let dialog = provenance_dialog()?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let carrier = v["parties"]
            .as_array()
            .ok_or("parties")?
            .iter()
            .find(|p| p.get("stir").is_some())
            .ok_or("premise: some party must carry the PASSporT")?;
        assert_eq!(
            carrier["validation"], "none",
            "a signed token beside a validation claim of anything but `none` \
             reports an attestation sipnab did not perform: {carrier}"
        );
        Ok(())
    }

    /// The extractor takes the JWS and refuses everything that is not one.
    ///
    /// The parameters after the token say where to FETCH a certificate; they
    /// are not part of the credential, and a consumer handed the whole header
    /// value cannot parse it as a token. Shape is the only judgement made --
    /// three dot-separated non-empty segments -- because verifying is
    /// precisely what sipnab must not claim to have done.
    #[test]
    fn the_passport_extractor_keeps_the_token_and_drops_the_rest() -> Result<(), TestError> {
        let token = "eyJhbGciOiJFUzI1NiJ9.eyJhdHRlc3QiOiJBIn0.SIGNATURE";
        assert_eq!(
            passport_of(&format!(
                "{token};info=<https://x/c.pem>;alg=ES256;ppt=shaken"
            )),
            Some(token.to_string()),
            "the parameters must not ride along inside the token"
        );
        assert_eq!(passport_of(token), Some(token.to_string()), "a bare token");
        assert_eq!(
            passport_of(&format!("  {token}  ;info=<x>")),
            Some(token.to_string()),
            "surrounding whitespace is header framing, not token content"
        );

        for not_a_jws in [
            "",
            "not.a",
            "a.b.c.d",
            ".b.c",
            "a..c",
            "a.b.",
            "opaque-string",
            ";info=<https://x/c.pem>",
        ] {
            assert_eq!(
                passport_of(not_a_jws),
                None,
                "{not_a_jws:?} is not JWS Compact Serialization and must not \
                 be published as a PASSporT"
            );
        }
        Ok(())
    }

    /// A Session-ID nothing can join on is dropped, not transcribed.
    ///
    /// `nil` is the RFC 7989 placeholder for "no UUID here", and a malformed
    /// half is not a UUID at all. Either one in `session_id` gives a consumer
    /// a correlation key that matches nothing -- worse than an absent field,
    /// because absence is readable and a dead key is not.
    #[test]
    fn a_session_id_half_that_cannot_correlate_is_left_out() -> Result<(), TestError> {
        let local = "ab30317f1a784dc48ff824d0d3715d86";

        // A first INVITE carries only the local half.
        let one_sided = dialog_carrying_header("Session-ID", local)?;
        let pair = session_id_of(&one_sided).ok_or("the local half is usable")?;
        assert_eq!(pair.local.as_deref(), Some(local));
        assert!(
            pair.remote.is_none(),
            "the far side has not answered, so no remote half exists: {pair:?}"
        );

        // `nil` is the placeholder, not an identifier.
        let nil_remote = dialog_carrying_header(
            "Session-ID",
            &format!("{local};remote=00000000000000000000000000000000"),
        )?;
        let pair = session_id_of(&nil_remote).ok_or("the local half is still usable")?;
        assert!(
            pair.remote.is_none(),
            "the nil UUID is 'no value here' and must not become a \
             correlation key: {pair:?}"
        );

        // Nothing usable at all yields no field rather than an empty object.
        let junk = dialog_carrying_header("Session-ID", "not-a-uuid;remote=also-not")?;
        assert!(
            session_id_of(&junk).is_none(),
            "neither half can correlate, so the field would be dead weight"
        );
        Ok(())
    }

    /// Each SIP response class is handled on its own signaling semantics.
    ///
    /// The sweep beside this proves every disposition sipnab CAN emit is one
    /// [core-04 section 4.3.11](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11) admits. It does not prove the classes are
    /// told apart, and a mapping that answered "failed" for the whole
    /// `100..=699` range would satisfy it. Only a final failure to set the call
    /// up is `incomplete`, and this states what each class is instead.
    ///
    /// 4xx carries one exception worth naming: 401 and 407 are challenges, not
    /// outcomes. A challenged INVITE that is then authenticated succeeds, and
    /// `final_status_code` prefers a non-challenge final precisely so the
    /// challenge does not become the reported result.
    #[test]
    fn every_response_class_is_read_on_its_own_terms() -> Result<(), TestError> {
        // (code, expect_incomplete, why)
        let cases: [(u16, bool, &str); 14] = [
            (
                100,
                false,
                "provisional: the transaction is still in progress",
            ),
            (180, false, "provisional: ringing is not an outcome"),
            (183, false, "provisional: early media is not an outcome"),
            (200, false, "success: the call was set up"),
            (202, false, "success: accepted is not a failure"),
            (
                300,
                false,
                "redirection: the call was not failed, it was moved",
            ),
            (302, false, "redirection: moved temporarily"),
            (305, false, "redirection: use proxy"),
            (
                400,
                true,
                "client error: a final failure to set the call up",
            ),
            (486, true, "client error: busy here"),
            (503, true, "server error: service unavailable"),
            (600, true, "global failure: busy everywhere"),
            (
                699,
                true,
                "6xx: unassigned, but the class is a global failure",
            ),
            (
                999,
                false,
                "outside every defined class: not a failure sipnab can name",
            ),
        ];

        for (code, expect_incomplete, why) in cases {
            let dialog = dialog_with(&[response(code, "Fixture")?])?;
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
            let object = &v["dialog"][0];
            let typed = object.get("type").and_then(|t| t.as_str());

            if expect_incomplete {
                assert_eq!(
                    typed,
                    Some(INCOMPLETE_TYPE),
                    "{code} -- {why} -- must be reported as a setup failure: {object}"
                );
                assert!(
                    object.get("disposition").is_some(),
                    "{code} -- {why} -- §4.3.1 makes the reason mandatory here: {object}"
                );
            } else {
                assert_eq!(
                    typed,
                    Some(RECORDING_TYPE),
                    "{code} -- {why} -- must NOT be reported as a setup failure; it is \
                     the core-04 section 4.3 `recording` placeholder: {object}"
                );
                assert!(
                    object.get("disposition").is_none(),
                    "{code} -- {why} -- naming a reason invents a failure: {object}"
                );
            }
        }
        Ok(())
    }

    /// An authentication challenge is not the call's outcome.
    ///
    /// A 401 or 407 alone is a challenge sipnab watched go unanswered, which
    /// IS a setup that never completed. The same challenge followed by a
    /// success is an ordinary authenticated call, and reporting the challenge
    /// as the result would mark every authenticated call a failure.
    #[test]
    fn an_authentication_challenge_is_not_the_outcome_once_the_call_succeeds()
    -> Result<(), TestError> {
        let challenged_only = dialog_with(&[response(407, "Proxy Authentication Required")?])?;
        let v = serde_json::to_value(export_with(&challenged_only, &clean_facts())?)?;
        assert_eq!(
            v["dialog"][0]["type"], INCOMPLETE_TYPE,
            "a challenge that was never answered is a setup that never \
             completed: {}",
            v["dialog"][0]
        );

        let then_answered = dialog_with(&[
            response(407, "Proxy Authentication Required")?,
            response(200, "OK")?,
        ])?;
        let v = serde_json::to_value(export_with(&then_answered, &clean_facts())?)?;
        assert!(
            v["dialog"][0]["type"] == RECORDING_TYPE && v["dialog"][0].get("disposition").is_none(),
            "the challenge was answered and the call was set up; reporting the \
             407 as the outcome would fail every authenticated call: {}",
            v["dialog"][0]
        );
        Ok(())
    }

    /// A withheld export against a stated deny header.
    fn export_withheld(
        dialog: &SipDialog,
        facts: &CaptureFacts,
        header: &str,
    ) -> Result<Vcon, TestError> {
        Ok(export_withheld_dialog_at(
            dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts,
                analysis: None,
                max_inline_media_bytes: None,
                media: &[],
                related_legs: &[],
            },
            header,
            exported_at()?,
        ))
    }
    /// PV2: a withheld dialog says so in the registered vocabulary.
    ///
    /// `dialogs_suppressed_by_deny` is a sipnab field inside a sipnab
    /// attachment, and a consumer that reads the format rather than this
    /// implementation will never see it. `redacted`
    /// ([core-04 section 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8)) is where the format says content was
    /// withheld, and an object carrying `type` with no `uuid` and no `url` says
    /// the thing that is true here: content was withheld and no unredacted
    /// instance exists anywhere to point at.
    #[test]
    fn a_withheld_dialog_is_declared_redacted_with_nothing_to_point_at() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_withheld(&dialog, &clean_facts(), "X-No-Record")?)?;

        let redacted = &v["redacted"];
        assert_eq!(
            redacted["type"], CONTENT_WITHHELD,
            "§4.1 requires `type` on a redacted object, and it names the \
             redaction performed: {redacted}"
        );
        assert!(
            redacted.get("uuid").is_none(),
            "a uuid here points at an unredacted instance. sipnab never wrote \
             one, so any value would name a container that does not exist: \
             {redacted}"
        );
        assert!(
            redacted.get("url").is_none() && redacted.get("content_hash").is_none(),
            "a url would offer the withheld content for retrieval, which is \
             the opposite of withholding it: {redacted}"
        );
        Ok(())
    }

    /// The tombstone carries no content of any kind.
    ///
    /// The whole point is that the container says a call happened and offers
    /// nothing from it. A tombstone that leaked the trace would be worse than
    /// emitting nothing, because it would look like a deliberate disclosure.
    #[test]
    fn a_withheld_dialog_carries_identity_and_no_content_whatsoever() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_withheld(&dialog, &clean_facts(), "X-No-Record")?)?;

        assert_eq!(
            v["dialog"][0]["sip_call_id"], "vcon-fixture@example.com",
            "the container must still identify which dialog was withheld, or \
             an operator cannot answer a question about it later"
        );
        for content in ["body", "url", "mediatype", "encoding", "content_hash"] {
            assert!(
                v["dialog"][0].get(content).is_none(),
                "a withheld dialog carries no {content}: {}",
                v["dialog"][0]
            );
        }
        assert_eq!(
            v["dialog"][0]["type"], RECORDING_TYPE,
            "a withheld call that connected is the `recording` placeholder, \
             the same rule as any other contentless object; core-04 section \
             4.3.10 lets the content be absent from a redacted vCon: {}",
            v["dialog"][0]
        );

        // The message trace is the content that matters most here: it is the
        // SIP the deny header asked sipnab not to keep.
        let purposes: Vec<&str> = v["attachments"]
            .as_array()
            .ok_or("attachments")?
            .iter()
            .filter_map(|a| a["purpose"].as_str())
            .collect();
        assert!(
            !purposes.contains(&"sip-message-trace"),
            "the trace is the withheld content; shipping it defeats the deny \
             header entirely: {purposes:?}"
        );
        Ok(())
    }

    /// An ordinary container declares no redaction at all.
    ///
    /// The anti-vacuity half. A `redacted` object on every container would say
    /// content was withheld from calls nothing was withheld from, which is a
    /// claim about those calls.
    #[test]
    fn a_container_nothing_was_withheld_from_declares_no_redaction() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        assert!(
            v.get("redacted").is_none(),
            "nothing was withheld from this dialog: {v}"
        );
        Ok(())
    }

    /// A dialog whose caller REFERs the callee elsewhere.
    fn dialog_with_refer(refer_to: &str) -> Result<SipDialog, TestError> {
        let invite = invite()?;
        let mut dialog = SipDialog::new(&invite).ok_or("INVITE opens a dialog")?;
        dialog.messages.push(response(200, "OK")?);
        dialog.messages.push(message(
            "REFER sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>;tag=t2",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 2 REFER",
                &format!("Refer-To: {refer_to}"),
                "Content-Length: 0",
            ],
        )?);
        Ok(dialog)
    }

    /// A transfer object carries the `start` its own schema requires.
    ///
    /// VAL12. Every Dialog Object in the vendored schema lists `start` as
    /// required, and a transfer object sets `type`, so it is a typed object
    /// with a mandatory field missing -- invalid against both the vendored and
    /// the published schema. The value was never unavailable: `observed_start`
    /// is computed for the signaling object a few lines above and is the same
    /// instant, because the transfer is part of THIS dialog rather than a
    /// separate conversation.
    ///
    /// The empty consultation object is the deliberate deviation here and is
    /// not this: issue #20 settled that an attended transfer's unseen leg is
    /// an EMPTY object, and the draft's own schema rejecting `{}` is the
    /// working group's contradiction rather than sipnab's.
    #[test]
    fn a_transfer_object_carries_the_start_its_schema_requires() -> Result<(), TestError> {
        let dialog = dialog_with_refer("<sip:carol@example.org>")?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let objects = v["dialog"].as_array().ok_or("dialog array")?;
        let transfer = objects
            .iter()
            .find(|o| o["type"] == "transfer")
            .ok_or("a transfer object")?;

        let start = transfer.get("start").and_then(serde_json::Value::as_str);
        assert!(
            start.is_some(),
            "the transfer object names a type and omits `start`, which every \
             Dialog Object in the schema requires: {transfer}"
        );

        // The same instant as the signaling object it belongs to. A transfer
        // is a thing that happened during this dialog, so a different start
        // would assert a second conversation that nobody observed.
        let signaling = objects.first().ok_or("a signaling object")?;
        assert_eq!(
            start,
            signaling.get("start").and_then(serde_json::Value::as_str),
            "the transfer belongs to this dialog and must share its start: \
             {transfer}"
        );
        Ok(())
    }

    /// PV8: an observed REFER becomes a `transfer` Dialog Object.
    ///
    /// A transfer object carries no content by design, which makes it
    /// structurally an observer's object rather than a recorder's — and a
    /// transfer is where a passive tap adds most over a recorder that only
    /// ever sees one leg.
    #[test]
    fn an_observed_refer_becomes_a_transfer_object() -> Result<(), TestError> {
        let dialog = dialog_with_refer("<sip:carol@example.org>")?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let objects = v["dialog"].as_array().ok_or("dialog array")?;

        assert!(
            objects.len() >= 2,
            "the transfer is a SECOND object; replacing the signaling object \
             would move what `Analysis::dialog` points at: {objects:#?}"
        );
        let transfer = objects
            .iter()
            .find(|o| o["type"] == "transfer")
            .ok_or("a transfer object")?;

        for content in ["body", "url", "mediatype", "encoding"] {
            assert!(
                transfer.get(content).is_none(),
                "§4.3.1 forbids Dialog Content on a transfer object: {transfer}"
            );
        }
        assert!(
            transfer.get("disposition").is_none(),
            "`disposition` belongs to `incomplete`, and nothing failed: {transfer}"
        );
        Ok(())
    }

    /// The transfer names who moved whom, by party index.
    #[test]
    fn a_transfer_names_the_transferor_the_transferee_and_the_target() -> Result<(), TestError> {
        let dialog = dialog_with_refer("<sip:carol@example.org>")?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let parties = v["parties"].as_array().ok_or("parties")?;
        let transfer = v["dialog"]
            .as_array()
            .ok_or("dialog")?
            .iter()
            .find(|o| o["type"] == "transfer")
            .ok_or("a transfer object")?;

        let transferor = transfer["transferor"].as_u64().ok_or("transferor index")? as usize;
        let transferee = transfer["transferee"].as_u64().ok_or("transferee index")? as usize;
        assert_eq!(
            parties[transferor]["sip"], "sip:alice@example.com",
            "the transferor is whoever SENT the REFER: {transfer}"
        );
        assert_eq!(
            parties[transferee]["sip"], "sip:bob@example.net",
            "the transferee is the party being moved: {transfer}"
        );

        let target = transfer["transfer_target"].as_u64().ok_or("target index")? as usize;
        assert_eq!(
            parties[target]["sip"], "sip:carol@example.org",
            "the target comes from `Refer-To`, and it is a party index — so \
             the party must exist in the array to point at: {transfer}"
        );
        assert_eq!(
            parties[target]["validation"], "none",
            "a Refer-To URI is what one party asked for, not an identity: {}",
            parties[target]
        );

        assert_eq!(
            transfer["original"], 0,
            "`original` points at the dialog this transfer happened in, which \
             is always index 0: {transfer}"
        );
        Ok(())
    }

    /// The observer stays LAST even after a transfer target is added.
    ///
    /// Every attachment's `party` index resolves to the observer, and it is
    /// computed as the final entry. Appending a target party after it would
    /// silently re-point every attachment at a participant.
    #[test]
    fn a_transfer_target_does_not_displace_the_observer() -> Result<(), TestError> {
        let dialog = dialog_with_refer("<sip:carol@example.org>")?;
        let vcon = export_with(&dialog, &clean_facts())?;
        let observer = vcon.observer_index();
        assert_eq!(observer, vcon.parties.len() - 1, "the observer is last");

        let v = serde_json::to_value(&vcon)?;
        assert_eq!(v["parties"][observer]["role"], "observer");
        for attachment in v["attachments"].as_array().ok_or("attachments")? {
            assert_eq!(
                attachment["party"], observer,
                "an attachment must still resolve to the observer: {attachment}"
            );
        }
        Ok(())
    }

    /// An ATTENDED transfer names a consultation dialog that is a
    /// `recording` placeholder.
    ///
    /// `Refer-To` carrying `?Replaces=` says the transferor already had a
    /// consultation call with the target. A passive tap on this leg never saw
    /// it. [core-04 section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) answers this case by name:
    /// "As the consultative call is a call, a placeholder Dialog Object for it
    /// MUST be of type "recording" if the call was set up". `Replaces` names
    /// an existing dialog to replace, so the call was set up, and the
    /// placeholder carries the type and nothing else.
    #[test]
    fn an_attended_transfer_points_consultation_at_a_recording_placeholder() -> Result<(), TestError>
    {
        let dialog = dialog_with_refer(
            "<sip:carol@example.org?Replaces=abc%40example.org%3Bto-tag%3D1%3Bfrom-tag%3D2>",
        )?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let objects = v["dialog"].as_array().ok_or("dialog array")?;
        let transfer = objects
            .iter()
            .find(|o| o["type"] == "transfer")
            .ok_or("a transfer object")?;

        let consultation = transfer["consultation"]
            .as_u64()
            .ok_or("an attended transfer names its consultation")?
            as usize;
        let placeholder = &objects[consultation];
        assert_eq!(
            placeholder,
            &serde_json::json!({"type": RECORDING_TYPE}),
            "the consultation call happened and sipnab saw nothing of it. \
             core-04 section 4.3 gives this case a placeholder holding only \
             its type: {placeholder}"
        );
        Ok(())
    }

    /// RV6: an ordinary container passes the vendored schema, and the
    /// validator is reading the real exporter's output.
    ///
    /// The gates above validate with `jsonschema`, which ships only in the
    /// test tree. This is the SHIPPED validator, run against the SHIPPED
    /// exporter — the pair a producer actually has.
    #[test]
    fn an_exported_container_passes_the_vendored_schema_validator() -> Result<(), TestError> {
        use crate::output::vcon_schema::{SchemaVerdict, validate};

        for responses in [
            vec![response(200, "OK")?],
            vec![response(486, "Busy Here")?],
            vec![response(180, "Ringing")?, response(200, "OK")?],
        ] {
            let v = serde_json::to_value(export_with(&dialog_with(&responses)?, &clean_facts())?)?;
            let report = validate(&v);
            assert_eq!(
                report.verdict,
                SchemaVerdict::Valid,
                "a container sipnab writes must satisfy the schema sipnab                  vendors: {report:#?}\n{v:#}"
            );
        }
        Ok(())
    }

    /// An attended transfer's container is valid under core-04.
    ///
    /// core-03's schema rejected the empty consultation object, and the
    /// validator reported it as a documented deviation. core-04's placeholder
    /// carries its type, so the container sipnab writes for an attended
    /// transfer is valid with nothing to excuse.
    #[test]
    fn an_attended_transfer_container_is_valid_under_core_04() -> Result<(), TestError> {
        use crate::output::vcon_schema::{SchemaVerdict, validate};

        let dialog = dialog_with_refer(
            "<sip:carol@example.org?Replaces=abc%40example.org%3Bto-tag%3D1%3Bfrom-tag%3D2>",
        )?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let report = validate(&v);

        assert_eq!(
            report.verdict,
            SchemaVerdict::Valid,
            "nothing in an attended transfer's container departs from the \
             core-04 schema: {report:#?}\n{v:#}"
        );
        assert!(report.errors.is_empty(), "{report:#?}");
        Ok(())
    }

    /// Every branch of the exporter writes a container the PUBLISHER's core-04
    /// schema accepts, judged by `jsonschema` rather than by sipnab's own
    /// validator.
    ///
    /// Two validators and two schema files would let a defect in one hide
    /// behind the other. This reads `tests/schemas/publisher/`, the file as the
    /// working group committed it, and runs the reference engine over every
    /// shape the exporter has: an answered call, an observed failure, a call
    /// with no final response, a redirect, a blind and an attended transfer,
    /// and a withheld dialog.
    #[test]
    fn every_export_branch_validates_against_the_publishers_core_04_schema() -> Result<(), TestError>
    {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/schemas/publisher/vcon_json_schema.json"
        );
        let schema: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        let validator = jsonschema::validator_for(&schema)?;

        let attended = dialog_with_refer(
            "<sip:carol@example.org?Replaces=abc%40example.org%3Bto-tag%3D1%3Bfrom-tag%3D2>",
        )?;
        let cases = [
            (
                "answered",
                serde_json::to_value(export_with(
                    &dialog_with(&[response(200, "OK")?])?,
                    &clean_facts(),
                )?)?,
            ),
            (
                "busy",
                serde_json::to_value(export_with(
                    &dialog_with(&[response(486, "Busy Here")?])?,
                    &clean_facts(),
                )?)?,
            ),
            (
                "no final response",
                serde_json::to_value(export_with(
                    &dialog_with(&[response(180, "Ringing")?])?,
                    &clean_facts(),
                )?)?,
            ),
            (
                "redirected",
                serde_json::to_value(export_with(
                    &dialog_with(&[response(302, "Moved Temporarily")?])?,
                    &clean_facts(),
                )?)?,
            ),
            (
                "blind transfer",
                serde_json::to_value(export_with(
                    &dialog_with_refer("<sip:carol@example.org>")?,
                    &clean_facts(),
                )?)?,
            ),
            (
                "attended transfer",
                serde_json::to_value(export_with(&attended, &clean_facts())?)?,
            ),
            (
                "withheld",
                serde_json::to_value(export_withheld(
                    &dialog_with(&[response(200, "OK")?])?,
                    &clean_facts(),
                    "X-No-Record",
                )?)?,
            ),
        ];
        for (label, v) in &cases {
            if let Err(e) = validator.validate(v) {
                return Err(format!(
                    "the {label} container fails the publisher's core-04 schema: {e}\n{v:#}"
                )
                .into());
            }
        }
        Ok(())
    }

    /// A `transfer` object carries none of the parameters core-04 prohibits on
    /// it, even when the dialog it belongs to observed them.
    ///
    /// [core-04 section 4.3.1.6](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.6), Table 1, marks these MUST
    /// NOT on `transfer`. The dialog here carries a `Session-ID`, so the
    /// signaling object has a `session_id` the transfer object must not copy.
    #[test]
    fn a_transfer_object_carries_nothing_core_04_prohibits_on_it() -> Result<(), TestError> {
        let mut dialog = dialog_with_refer("<sip:carol@example.org>")?;
        dialog.messages.push(message(
            "BYE sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>;tag=t2",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 3 BYE",
                "Session-ID: ab30317f1a784dc48ff824d0d3715d86;remote=47755a9de7794ba387653f2099600ef2",
                "Content-Length: 0",
            ],
        )?);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let objects = v["dialog"].as_array().ok_or("dialog array")?;
        assert!(
            objects[0].get("session_id").is_some(),
            "premise: the signaling object carries the observed session_id, or \
             this test cannot tell a copied one from an absent one: {}",
            objects[0]
        );
        let transfer = objects
            .iter()
            .find(|o| o["type"] == TRANSFER_TYPE)
            .ok_or("a transfer object")?;
        for prohibited in [
            "parties",
            "originator",
            "session_id",
            "party_history",
            "message_id",
            "recordings",
            "recording_set",
            "mediatype",
            "filename",
            "body",
            "encoding",
            "url",
            "content_hash",
        ] {
            assert!(
                transfer.get(prohibited).is_none(),
                "core-04 Table 1 marks `{prohibited}` MUST NOT on transfer: {transfer}"
            );
        }
        Ok(())
    }

    /// A BLIND transfer names no consultation at all.
    ///
    /// The anti-vacuity half: `consultation` present on every transfer would
    /// claim a consultative call for transfers that were blind, and the
    /// presence of the member is what distinguishes the two.
    #[test]
    fn a_blind_transfer_claims_no_consultation() -> Result<(), TestError> {
        let dialog = dialog_with_refer("<sip:carol@example.org>")?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let transfer = v["dialog"]
            .as_array()
            .ok_or("dialog")?
            .iter()
            .find(|o| o["type"] == "transfer")
            .ok_or("a transfer object")?;

        assert!(
            transfer.get("consultation").is_none(),
            "no `Replaces` was observed, so no consultative call is known to \
             have happened: {transfer}"
        );
        Ok(())
    }

    /// A dialog with no REFER gets no transfer object.
    #[test]
    fn a_dialog_without_a_refer_has_no_transfer_object() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let objects = v["dialog"].as_array().ok_or("dialog array")?;
        assert_eq!(objects.len(), 1, "one signaling object only: {objects:#?}");
        assert!(
            objects.iter().all(|o| o["type"] != "transfer"),
            "nothing was transferred: {objects:#?}"
        );
        Ok(())
    }

    /// A dialog with no final response at all is STILL not `incomplete`.
    ///
    /// This is the case the whole rule exists for. sipnab not seeing the
    /// answer is a fact about the capture; reporting it as `incomplete` would
    /// make it a fact about the call.
    #[test]
    fn an_unanswered_dialog_is_not_reported_as_a_failed_call() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(100, "Trying")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
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
        Ok(())
    }

    /// An observed final failure DOES set a disposition, and the mapping is
    /// the one the outcome deserves.
    #[test]
    fn an_observed_final_failure_maps_to_a_disposition() -> Result<(), TestError> {
        for (code, expected) in [
            (486u16, "busy"),
            (600, "busy"),
            (503, "congestion"),
            (408, "no-answer"),
            (480, "no-answer"),
            (403, "failed"),
            (500, "failed"),
        ] {
            let dialog = dialog_with(&[response(code, "Fixture")?])?;
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
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
        let redirected = dialog_with(&[response(302, "Moved Temporarily")?])?;
        let v = serde_json::to_value(export_with(&redirected, &clean_facts())?)?;
        assert!(
            v["dialog"][0].get("disposition").is_none(),
            "a 3xx redirect did not fail: {}",
            v["dialog"][0]
        );
        Ok(())
    }

    /// A CANCEL for the [`invite`] transaction: the caller giving up.
    fn cancel() -> Result<crate::sip::SipMessage, TestError> {
        message(
            "CANCEL sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 CANCEL",
                "Content-Length: 0",
            ],
        )
    }

    /// A call the caller canceled while it rang, ended by `487 Request
    /// Terminated`, is `no-answer`.
    ///
    /// [Section 4.3.11 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11):
    /// "\"no-answer\" - a call or connection was attempted, but no one answered
    /// or accepted the connection". Not `hung-up`, which is "a call or
    /// connection was made, but the party hung-up before any conversation
    /// occurred": an unanswered call was never made.
    #[test]
    fn a_canceled_unanswered_call_is_no_answer_per_section_4_3_11() -> Result<(), TestError> {
        let dialog = dialog_with(&[
            response(180, "Ringing")?,
            cancel()?,
            response(487, "Request Terminated")?,
        ])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        assert_eq!(v["dialog"][0]["type"], "incomplete");
        assert_eq!(
            v["dialog"][0]["disposition"], "no-answer",
            "{}",
            v["dialog"][0]
        );
        Ok(())
    }

    /// A 487 with no CANCEL in the capture keeps `failed`: sipnab did not
    /// see why the request ended, and section 4.3.11 says "If the reason that
    /// the call or conversation failed is not known ... the disposition value
    /// \"failed\" SHOULD be used". A CANCEL that lost the race to `486`
    /// leaves the call `busy`, the outcome the far end reported.
    #[test]
    fn only_an_observed_cancel_makes_a_487_no_answer() -> Result<(), TestError> {
        for (messages, expected) in [
            (vec![response(487, "Request Terminated")?], "failed"),
            (vec![cancel()?, response(486, "Busy Here")?], "busy"),
        ] {
            let dialog = dialog_with(&messages)?;
            let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
            assert_eq!(
                v["dialog"][0]["disposition"], expected,
                "{}",
                v["dialog"][0]
            );
        }
        Ok(())
    }

    /// A call answered after a CANCEL crossed the `200` is not an incomplete
    /// dialog at all, so it carries no disposition: section 4.3.11 says
    /// disposition "SHOULD NOT be present for other dialog types".
    #[test]
    fn an_answered_call_carries_no_disposition_even_after_a_cancel() -> Result<(), TestError> {
        let dialog = dialog_with(&[cancel()?, response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        assert!(
            v["dialog"][0].get("disposition").is_none(),
            "{}",
            v["dialog"][0]
        );
        assert_ne!(v["dialog"][0]["type"], "incomplete");
        Ok(())
    }

    /// Every attachment names the observer as its party.
    #[test]
    fn every_attachment_carries_the_observer_as_its_party() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let vcon = export_with(&dialog, &clean_facts())?;
        let observer = vcon.observer_index();
        let v = serde_json::to_value(&vcon)?;

        let attachments = v["attachments"].as_array().ok_or("attachments")?;
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
        Ok(())
    }

    /// The trace carries one entry per message, through the same projection
    /// `--json` writes.
    #[test]
    fn the_trace_carries_every_message_through_the_shared_projection() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(180, "Ringing")?, response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let trace = body_of(&v["attachments"][0])?;
        let messages = trace["messages"].as_array().ok_or("messages")?;

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
        Ok(())
    }

    /// The trace carries the headers, which is what gives the filter work.
    ///
    /// This is the other half of `no_credential_survives_an_export` and exists
    /// because that test can pass for two very different reasons: the filter
    /// removed the credential, or the container never carried a header at all.
    /// It passed for the second reason until 0.5.125. Drop `headers` again and
    /// this fails, so the pair cannot silently go back to proving nothing.
    #[test]
    fn the_trace_carries_the_headers_the_filter_exists_to_clean() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let trace = body_of(&v["attachments"][0])?;
        let first = &trace["messages"][0];

        let headers = first["headers"]
            .as_object()
            .ok_or_else(|| format!("every message must carry its headers: {first}"))?;
        assert!(
            !headers.is_empty(),
            "an empty header map gives the credential filter nothing to \
             remove, which is how a regression gate stops guarding: {first}"
        );
        for expected in ["From", "To", "Call-ID"] {
            assert!(
                headers.contains_key(expected),
                "`{expected}` is on the wire and must reach the trace: {headers:?}"
            );
        }
        // Repeats survive as repeats: a collapsed `Via` loses the path.
        assert!(
            headers.values().all(|v| v.is_array()),
            "every header value must be an array so a consumer indexes one \
             shape and repeated headers keep every value: {headers:?}"
        );
        Ok(())
    }

    /// The container publishes no `extension_headers` list.
    ///
    /// **First of four tests owed** for the two gates 0.5.159 turned red.
    /// `--json` gained `extension_headers` — every header outside the closed
    /// field list, as `"Name: value"` strings — and the vCon trace inherited
    /// it from the shared projection, carrying `Authorization` values in a
    /// shape `strip_credentials` could not filter and `Via` hostnames the
    /// redactor did not reach. Two gates written years apart caught it.
    ///
    /// The list does not belong here at all: the container already publishes
    /// a `headers` OBJECT, which is strictly more useful and is the shape
    /// this boundary can police.
    #[test]
    fn the_container_carries_no_extension_header_list() -> Result<(), TestError> {
        let msg = message(
            "REGISTER sip:example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP pbx.internal.example:5060;branch=z9hG4bK1",
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>",
                "Call-ID: vcon-extension-headers@example.com",
                "CSeq: 2 REGISTER",
                "Content-Length: 0",
            ],
        )?;
        // The projection this trace is built from really does carry it, or
        // this test proves nothing about the removal.
        assert!(
            crate::output::json::message_to_json_value(&msg)
                .get("extension_headers")
                .is_some(),
            "the shared projection must carry the field this removes"
        );

        let dialog = SipDialog::new(&msg).ok_or("REGISTER opens a dialog")?;
        let json = export_with(&dialog, &clean_facts())?.to_json()?;
        assert!(
            !json.contains("extension_headers"),
            "the wire-line list reached a published container:\n{json}"
        );
        Ok(())
    }

    /// Nothing is lost by removing it: the map carries every header the list
    /// would have.
    ///
    /// **Second of four.** Removing a field is only safe if the container
    /// still says everything it said. This drives both shapes from one
    /// message and compares them as sets, so a header the map happens to miss
    /// fails here rather than going quietly missing from every export.
    #[test]
    fn the_header_map_carries_every_header_the_list_would_have() -> Result<(), TestError> {
        let msg = message(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP pbx.internal.example:5060;branch=z9hG4bK1",
                "Via: SIP/2.0/UDP edge.example:5060;branch=z9hG4bK2",
                "Max-Forwards: 70",
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: vcon-parity@example.com",
                "CSeq: 1 INVITE",
                "Diversion: <sip:1003@example.com>;reason=user-busy",
                "Content-Length: 0",
            ],
        )?;
        let listed: Vec<String> =
            crate::output::json::message_to_json_value(&msg)["extension_headers"]
                .as_array()
                .ok_or("the projection carries the list")?
                .iter()
                .filter_map(|v| v.as_str())
                .filter_map(|line| line.split_once(':').map(|(n, _)| n.to_ascii_lowercase()))
                .collect();
        assert!(
            !listed.is_empty(),
            "the fixture must carry extension headers"
        );

        let mapped = header_map(&msg);
        let mapped = mapped.as_object().ok_or("the map is an object")?;
        for name in &listed {
            assert!(
                mapped.keys().any(|k| k.to_ascii_lowercase() == *name),
                "`{name}` is in the list and not in the map, so removing the \
                 list would drop it from every export: {:?}",
                mapped.keys().collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    /// A credential written as a wire LINE is filtered too.
    ///
    /// **Third of four**, and the defense that would have made the removal
    /// unnecessary. `strip_credentials` keyed only on object keys, so a list
    /// of `"Authorization: Digest ..."` strings walked straight through a
    /// filter looking for a key named `Authorization`. The boundary must hold
    /// for the shape a field arrives in, not for the shape it had when the
    /// filter was written — the next field to arrive will not ask first.
    #[test]
    fn a_credential_written_as_a_wire_line_is_filtered() -> Result<(), TestError> {
        // Markers are DERIVED rather than written as literals, and the
        // rendered container is never printed. Both are for CodeQL's
        // `rust/cleartext-logging`, which reads a literal beside `response=`
        // as a secret and an assert message carrying the filtered value as a
        // disclosure of one. It cannot be scoped to inline test code, and the
        // failure message loses nothing: the marker names which line survived,
        // which is the whole answer.
        let marker = |n: usize| format!("marker-{n}");
        let mut value = serde_json::json!({
            "lines": [
                "Via: SIP/2.0/UDP edge.example:5060",
                format!("Authorization: Digest response=\"{}\"", marker(1)),
                format!("proxy-authorization: Digest response=\"{}\"", marker(2)),
                format!("  WWW-Authenticate  : Digest nonce=\"{}\"", marker(3)),
                "Contact: <sip:a@b>",
                "not a header line at all",
            ],
        });
        strip_credentials(&mut value);
        let lines: Vec<String> = value["lines"]
            .as_array()
            .ok_or("the array survives")?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();

        for n in 1..=3 {
            assert!(
                !lines.iter().any(|l| l.contains(&marker(n))),
                "the line carrying {} survived the wire-line filter",
                marker(n)
            );
        }
        // The header NAME goes with the value. A filter that stripped the
        // parameter and left `Authorization: Digest` behind would still tell a
        // reader which endpoint authenticates and how.
        for name in CREDENTIAL_HEADERS {
            assert!(
                !lines
                    .iter()
                    .any(|l| l.to_ascii_lowercase().starts_with(name)),
                "a {name} line survived with its name intact"
            );
        }
        // And it removes only what it should.
        for kept in [
            "Via: SIP/2.0/UDP edge.example:5060",
            "not a header line at all",
        ] {
            assert!(
                lines.iter().any(|l| l == kept),
                "{kept:?} is not a credential and must survive"
            );
        }
        assert_eq!(lines.len(), 3, "three lines in, three of six kept");
        Ok(())
    }

    /// A credential is removed at any depth, in either shape.
    ///
    /// **Fifth of ten tests owed for the five defects 0.5.159 uncovered.**
    /// `strip_credentials` recurses, and nothing said so. The container it
    /// actually runs against nests three deep — an attachment body holds a
    /// `messages` array whose entries hold a `headers` object — so a filter
    /// that policed only the top level would have passed every test written
    /// against a flat fixture while removing nothing from a real export.
    #[test]
    fn a_credential_is_removed_at_any_depth_in_either_shape() -> Result<(), TestError> {
        let marker = |n: usize| format!("marker-{n}");
        let mut value = serde_json::json!({
            "attachments": [{
                "body": {
                    "messages": [{
                        // The object shape, three levels down.
                        "headers": {
                            "Authorization": [format!("Digest response=\"{}\"", marker(1))],
                            "Via": ["SIP/2.0/UDP edge.example:5060"],
                        },
                        // The wire-line shape, beside it at the same depth.
                        "extension_headers": [
                            format!("Proxy-Authorization: Digest response=\"{}\"", marker(2)),
                            "Contact: <sip:a@b>",
                        ],
                        // And one more level, inside an array of arrays.
                        "nested": [[
                            format!("WWW-Authenticate: Digest nonce=\"{}\"", marker(3)),
                        ]],
                    }],
                },
            }],
        });
        strip_credentials(&mut value);
        let rendered = value.to_string();

        for n in 1..=3 {
            assert!(
                !rendered.contains(&marker(n)),
                "the value carrying {} survived at depth",
                marker(n)
            );
        }
        // The recursion removed only what it should: a header that is not on
        // the list survives at every one of those depths.
        assert!(
            rendered.contains("edge.example"),
            "Via was removed: {rendered}"
        );
        assert!(
            rendered.contains("sip:a@b"),
            "Contact was removed: {rendered}"
        );
        // And the containers themselves survive: a filter that deleted the
        // whole `headers` object rather than the offending key would also
        // pass a "no secret present" check while destroying the trace.
        assert!(
            value["attachments"][0]["body"]["messages"][0]["headers"]["Via"].is_array(),
            "the headers object was destroyed rather than filtered: {rendered}"
        );
        Ok(())
    }

    /// No exported container carries a credential, by either route.
    ///
    /// **Sixth of ten**, and the end-to-end one. The five tests around it
    /// drive `strip_credentials` directly; this drives a real dialog through
    /// the real exporter and searches the serialized container, because the
    /// defect was never in the filter — it was in which shapes reached it.
    /// A message carrying credentials in BOTH shapes at once is the case no
    /// earlier fixture produced.
    #[test]
    fn no_exported_container_carries_a_credential_by_either_route() -> Result<(), TestError> {
        let marker = |n: usize| format!("marker-{n}");
        let msg = message(
            "REGISTER sip:example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP edge.example:5060;branch=z9hG4bK1",
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>",
                "Call-ID: vcon-both-shapes@example.com",
                "CSeq: 2 REGISTER",
                &format!("Authorization: Digest response=\"{}\"", marker(1)),
                &format!("Proxy-Authorization: Digest nonce=\"{}\"", marker(2)),
                "Content-Length: 0",
            ],
        )?;
        // The projection really does carry both shapes, or this proves nothing
        // about the exporter.
        let projected = crate::output::json::message_to_json_value(&msg).to_string();
        assert!(
            projected.contains(&marker(1)) && projected.contains(&marker(2)),
            "the shared projection must carry the credentials this removes"
        );

        let dialog = SipDialog::new(&msg).ok_or("REGISTER opens a dialog")?;
        let json = export_with(&dialog, &clean_facts())?.to_json()?;

        for n in 1..=2 {
            assert!(
                !json.contains(&marker(n)),
                "the value carrying {} reached a published container",
                marker(n)
            );
        }
        for header in CREDENTIAL_HEADERS {
            assert!(
                !json.to_ascii_lowercase().contains(header),
                "`{header}` appears in an exported vCon by name"
            );
        }
        // The message is still in the container: a filter that dropped the
        // whole trace would pass every assertion above.
        assert!(
            json.contains("vcon-both-shapes@example.com"),
            "the dialog itself was dropped rather than filtered"
        );
        Ok(())
    }

    /// The wire-line rule reads a header name the way RFC 3261 does.
    ///
    /// **First of two tests owed** for the CodeQL alert that turned CI red on
    /// the cut. [RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1) makes header names case-insensitive and
    /// allows linear whitespace before the colon, so a filter matching one
    /// spelling is a filter a sender can walk past by choosing another.
    #[test]
    fn the_wire_line_rule_reads_a_header_name_the_way_rfc_3261_does() -> Result<(), TestError> {
        for line in [
            "Authorization: Digest x",
            "authorization: Digest x",
            "AUTHORIZATION: Digest x",
            "  Proxy-Authorization  : Digest x",
            "WWW-Authenticate:",
            "proxy-authenticate : Digest x",
        ] {
            assert!(
                header_line_is_a_credential(line),
                "{line:?} names a credential-bearing header"
            );
        }
        for line in [
            "Via: SIP/2.0/UDP edge.example:5060",
            "Contact: <sip:a@b>",
            "not a header line at all",
            "",
            // A name that merely CONTAINS one is a different header.
            "X-Authorization-Note: nothing",
            "Pre-Authorization: nothing",
        ] {
            assert!(
                !header_line_is_a_credential(line),
                "{line:?} is not one of the four and must survive"
            );
        }
        Ok(())
    }

    /// **Second of two.** The rule and the list it reads cannot drift apart.
    ///
    /// `header_line_is_a_credential` and the object-key filter beside it both
    /// read `CREDENTIAL_HEADERS`. A second list would be the same defect this
    /// release paid for twice — one boundary policing one shape while another
    /// shape walked through.
    #[test]
    fn every_credential_header_is_recognized_in_both_shapes() -> Result<(), TestError> {
        assert_eq!(
            CREDENTIAL_HEADERS.len(),
            4,
            "the list is the four RFC 3261 authentication headers"
        );
        for name in CREDENTIAL_HEADERS {
            // The wire-line shape.
            assert!(
                header_line_is_a_credential(&format!("{name}: Digest x")),
                "{name} is on the list and the wire-line rule does not know it"
            );
            // The object-key shape, through the real filter.
            let mut value = serde_json::json!({ *name: "Digest x", "via": "keep" });
            strip_credentials(&mut value);
            assert!(
                value.get(*name).is_none(),
                "{name} is on the list and survived as an object key"
            );
            assert!(
                value.get("via").is_some(),
                "the filter removed a header that is not on the list"
            );
        }
        Ok(())
    }

    /// `Via` does not publish the operator's proxy chain.
    ///
    /// **Fourth of four**, and it found a defect older than the change that
    /// prompted it. `Path`, `Route`, `Record-Route` and `Service-Route` were
    /// all on the redactor's host-bearing list and `Via` — the one header
    /// every SIP message carries — was not, because it is not a name-addr and
    /// so did not fit beside them. It fell through to the free-text sweep,
    /// which finds addresses and numbers and walks straight past a hostname.
    ///
    /// The existing leak test could not have caught it: its fixture carries
    /// eleven identifying headers and no `Via`.
    ///
    /// **What this deliberately does not assert.** A bare hostname in a header
    /// nothing models — `X-Vendor-Route: pbx.internal.example` — is not
    /// findable by any pattern, and demanding it would be a gate whose fix
    /// cannot exist. The rule here is the one a rewriter can keep: a header
    /// whose grammar says where the host is has its host rewritten.
    #[test]
    fn a_via_header_does_not_publish_the_proxy_chain() -> Result<(), TestError> {
        let msg = message(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP pbx.internal.example:5060;branch=z9hG4bK1;received=10.11.12.13",
                "Via: SIP/2.0/TCP edge.internal.example;branch=z9hG4bK2",
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: vcon-redact-via@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        )?;
        let dialog = SipDialog::new(&msg).ok_or("INVITE opens a dialog")?;
        let container = export_with(&dialog, &clean_facts())?;
        let policy = crate::output::redact::RedactionPolicy::new(
            crate::output::redact::RedactionKey::from_secret(crate::test_material::key_bytes(
                "vcon-unmodeled-header-test",
            )),
        );
        let redactor = policy.redactor();
        let json = sealed_json(&seal(container, Some(&redactor)))?;
        for leaked in [
            "pbx.internal.example",
            "edge.internal.example",
            "10.11.12.13",
        ] {
            assert!(
                !json.contains(leaked),
                "`{leaked}` survived redaction of a Via header:\n{json}"
            );
        }
        // The branch is KEPT: it is the transaction handle a reader follows,
        // and tokenizing it would cost the correlation and hide nothing.
        assert!(
            json.contains("z9hG4bK1"),
            "the branch parameter must survive; it identifies the \
             transaction and carries no identity:\n{json}"
        );
        Ok(())
    }

    /// No credential reaches the container, end to end.
    ///
    /// This was written as a REGRESSION gate for a day that has now arrived.
    /// Its old doc said "the projection this trace is built from carries no
    /// raw header map today, so this passes on the strength of that projection
    /// rather than of the filter … the day `message_to_json_value` gains a
    /// `headers` field, this is what refuses the digest response before it is
    /// handed to somebody else." 0.5.125 is that day: the trace carries every
    /// header, so the `Authorization` and `Proxy-Authorization` planted below
    /// are really in the container until the filter takes them out. Empty
    /// `CREDENTIAL_HEADERS` and this fails, which is what it always claimed.
    #[test]
    fn no_credential_survives_an_export() -> Result<(), TestError> {
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
        )?;
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
        )?;
        let mut dialog = SipDialog::new(&challenged).ok_or("REGISTER opens a dialog")?;
        dialog.messages.push(challenge);

        let json = export_with(&dialog, &clean_facts())?.to_json()?;

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
        Ok(())
    }

    /// The filter itself: banned keys go, at every depth and in any case, and
    /// everything else stays.
    ///
    /// Mutation-proven — deleting the `retain` in [`strip_credentials`] fails
    /// this test. It is written against a hand-built value rather than an
    /// exported one because the projection upstream carries no header map, so
    /// an end-to-end test cannot reach the filter.
    #[test]
    fn the_credential_filter_removes_banned_headers_at_every_depth() -> Result<(), TestError> {
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

        let text = serde_json::to_string(&value)?;
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
        Ok(())
    }

    /// The report names sipnab as an observer and carries the existing schema.
    #[test]
    fn the_report_names_the_tool_as_an_observer() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(486, "Busy Here")?])?;
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())?)?;
        let analysis = &v["analysis"][0];

        assert_eq!(analysis["type"], "report");
        assert_eq!(analysis["vendor"], ANALYSIS_VENDOR);
        assert_eq!(analysis["schema"], ANALYSIS_SCHEMA);
        assert_eq!(analysis["dialog"], 0);
        let product = analysis["product"].as_str().ok_or("a product string")?;
        assert!(
            product.contains("observer"),
            "an analysis attached to a conversation reads as coming from a \
             participant unless the product says otherwise: {product}"
        );
        assert_eq!(body_of(analysis)?["final_status_code"], 486);
        assert!(
            body_of(analysis)?["signaling_diagnosis"].is_object(),
            "a 486 is a final failure the signaling diagnosis already \
             detects; the report must reuse it: {analysis}"
        );
        Ok(())
    }

    /// The `schema` string names the version the JSON surface actually stamps.
    ///
    /// Two literals in two modules describing one contract. Held together
    /// here, because a `schema` naming version 1 over bodies carrying version
    /// 2 sends a consumer to the wrong parser with no way to notice.
    #[test]
    fn the_analysis_schema_names_the_version_the_json_surface_emits() -> Result<(), TestError> {
        let emitted = crate::output::json::message_to_json_value(&invite()?);
        assert_eq!(
            emitted["schema_version"], DIAGNOSIS_SCHEMA_VERSION,
            "the vCon schema string and the JSON surface disagree about the \
             body version"
        );
        assert!(
            ANALYSIS_SCHEMA.ends_with(&format!("/{DIAGNOSIS_SCHEMA_VERSION}")),
            "{ANALYSIS_SCHEMA} does not name version {DIAGNOSIS_SCHEMA_VERSION}"
        );
        Ok(())
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
    fn the_completeness_carrier_discriminates_a_lossy_run_from_a_clean_one() -> Result<(), TestError>
    {
        let dialog = dialog_with(&[response(200, "OK")?])?;

        let clean = clean_facts();
        let mut lossy = clean_facts();
        lossy.retention.messages_evicted = 7;

        let clean_vcon = serde_json::to_value(export_with(&dialog, &clean)?)?;
        let lossy_vcon = serde_json::to_value(export_with(&dialog, &lossy)?)?;

        let note = |v: &serde_json::Value| -> Result<String, TestError> {
            Ok(body_of(&v["attachments"][1])?["note"]
                .as_str()
                .ok_or("the caveat is a string")?
                .to_string())
        };
        let clean_note = note(&clean_vcon)?;
        let lossy_note = note(&lossy_vcon)?;

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
            body_of(&lossy_vcon["attachments"][1])?["messages_evicted"],
            7
        );
        assert_eq!(
            body_of(&clean_vcon["attachments"][1])?["messages_evicted"],
            0
        );
        Ok(())
    }

    /// Both surfaces carry the SAME caveat, byte for byte.
    ///
    /// One value embedded twice, never two strings built twice. A container
    /// whose report and whose attachment disagreed about what was missed would
    /// be worse than one carrying no caveat at all: it would look
    /// authoritative while contradicting itself.
    #[test]
    fn the_two_completeness_surfaces_carry_one_value() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let mut facts = clean_facts();
        facts.retention.messages_evicted = 3;
        facts.undecodable.frames = 11;

        let v = serde_json::to_value(export_with(&dialog, &facts)?)?;
        let from_attachment = body_of(&v["attachments"][1])?;
        let report = body_of(&v["analysis"][0])?;
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
        Ok(())
    }

    /// "Nobody looked" and "looked and found nothing" are different answers.
    ///
    /// Collapsing them lets an export that skipped the capture analysis read
    /// as a clean one, which is the same defect `--analyze` refuses when it
    /// derives `complete` from the finding list rather than tracking a flag.
    #[test]
    fn an_absent_analysis_is_not_a_clean_bill() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let facts = clean_facts();

        let unchecked = export_with(&dialog, &facts)?;
        let checked = export_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &facts,
                max_inline_media_bytes: None,
                analysis: Some(&CaptureAnalysis::default()),
                media: &[],
                related_legs: &[],
            },
            exported_at()?,
        );

        let note = |v: &Vcon| -> Result<String, TestError> {
            Ok(
                body_of(&serde_json::to_value(v)?["attachments"][1])?["note"]
                    .as_str()
                    .ok_or("a caveat")?
                    .to_string(),
            )
        };
        assert_ne!(
            note(&unchecked)?,
            note(&checked)?,
            "an export with no capture analysis said the same thing as one \
             whose analysis found nothing"
        );

        let unchecked_body = body_of(&serde_json::to_value(&unchecked)?["attachments"][1])?;
        assert!(
            unchecked_body.get("blind_spots").is_none(),
            "no analysis was supplied, so an empty list would claim one ran: \
             {unchecked_body}"
        );
        let checked_body = body_of(&serde_json::to_value(&checked)?["attachments"][1])?;
        assert_eq!(
            checked_body["blind_spots"],
            serde_json::json!([]),
            "an analysis that ranked nothing must say so with an empty list, \
             not by omitting the field: {checked_body}"
        );
        Ok(())
    }

    /// A ranked blind spot reaches both the prose and the structured list.
    #[test]
    fn a_ranked_blind_spot_reaches_the_carrier() -> Result<(), TestError> {
        use crate::analysis::{Finding, FindingKind};

        let dialog = dialog_with(&[response(200, "OK")?])?;
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
                max_inline_media_bytes: None,
                analysis: Some(&analysis),
                media: &[],
                related_legs: &[],
            },
            exported_at()?,
        ))?;

        let body = body_of(&v["attachments"][1])?;
        assert_eq!(body["blind_spots"][0]["occurrences"], 49);
        assert_eq!(
            body["blind_spots"][0]["kind"],
            FindingKind::UndecodableFrames.meta().id
        );
        let note = body["note"].as_str().ok_or("a caveat")?;
        assert!(
            note.contains("INCOMPLETE") && note.contains("49"),
            "a ranked blind spot must reach the prose surface too: {note}"
        );
        Ok(())
    }

    /// One capture addressed two ways is one capture.
    ///
    /// VAL14. `capture_id` is the SOURCE half of a frame pointer, which is the
    /// path exactly as it was typed. `-I tests/x.pcap` and
    /// `-I /abs/tests/x.pcap` are the same bytes, and minted different uuids --
    /// so a consumer deduplicating on `uuid`, which [core-04 section 4.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.2)
    /// says it may, saw two conversations where the content proves there is
    /// one.
    ///
    /// Normalizing only the SEED and not the recorded pointer is deliberate.
    /// The pointer keeps the spelling the operator used, because that is what
    /// they will recognize and what `show_evidence` resolves; and an absolute
    /// path carries the account name, which has no business being published in
    /// a container that leaves the building. The uuid is a digest, so the
    /// normalized form never appears anywhere.
    #[test]
    fn one_capture_addressed_two_ways_mints_one_uuid() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let rel = "tests/pcap-samples/sip-rtp-g711.pcap";
        let abs = std::path::absolute(rel)?.to_string_lossy().into_owned();
        assert_ne!(rel, abs, "the fixture must actually test two spellings");

        assert_eq!(
            dialog_uuid(&dialog, rel),
            dialog_uuid(&dialog, &abs),
            "one capture addressed relatively and absolutely is one capture"
        );

        // The property this must not buy the fix with: two DIFFERENT captures
        // still differ. Collapsing everything to one key would make the uuid
        // stable and useless.
        assert_ne!(
            dialog_uuid(&dialog, rel),
            dialog_uuid(&dialog, "tests/pcap-samples/sip-proxy.pcap"),
            "different captures must keep different uuids"
        );

        // A live device and a HEP listener are not paths. Joining them to the
        // working directory would make one interface two identities depending
        // on where sipnab was started.
        for not_a_path in ["eth0", "any", "hep:0.0.0.0:9060", "uprobe:opensips/1234"] {
            assert_eq!(
                dialog_uuid(&dialog, not_a_path),
                dialog_uuid(&dialog, not_a_path),
                "{not_a_path} must be stable"
            );
        }
        Ok(())
    }

    /// The uuid is a well-formed UUIDv8 and is stable for one dialog out of
    /// one capture.
    #[test]
    fn the_uuid_is_a_stable_uuid_v8() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
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
        Ok(())
    }

    /// The uuid separates dialogs, separates captures, and follows the
    /// dialog's clock rather than the export's.
    #[test]
    fn the_uuid_separates_dialogs_captures_and_clocks() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let base = dialog_uuid(&dialog, "fixture.pcap");

        let mut other_capture = dialog_with(&[response(200, "OK")?])?;
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
        let mut later = dialog_with(&[response(200, "OK")?])?;
        later.created_at = ts()? + chrono::TimeDelta::seconds(90);
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
                max_inline_media_bytes: None,
                analysis: None,
                media: &[],
                related_legs: &[],
            },
            exported_at()?,
        );
        let second = export_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &clean_facts(),
                max_inline_media_bytes: None,
                analysis: None,
                media: &[],
                related_legs: &[],
            },
            exported_at()? + chrono::TimeDelta::days(400),
        );
        assert_eq!(first.uuid, second.uuid);
        assert_ne!(
            first.created_at, second.created_at,
            "the export clock must still move, or this proves nothing"
        );
        Ok(())
    }

    /// A dialog whose headers named no host gets no URI rather than a
    /// fabricated one.
    #[test]
    fn a_party_with_no_observed_host_carries_no_uri() -> Result<(), TestError> {
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
        Ok(())
    }

    /// The whole container round-trips through `serde_json` as an object.
    #[test]
    fn the_container_serializes_to_parseable_json() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(200, "OK")?])?;
        let json = export_with(&dialog, &clean_facts())?.to_json()?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert!(parsed.is_object());
        assert_eq!(parsed["analysis"].as_array().map(Vec::len), Some(1));
        Ok(())
    }

    // ── The redaction boundary ──────────────────────────────────────────

    /// Every identifying value the PA5 inventory names, in one dialog.
    ///
    /// Written as ONE fixture rather than one per field on purpose: the leak
    /// test below asserts over the whole serialized container, so a field that
    /// nothing redacts fails the test wherever it happens to be emitted. A
    /// per-field test would only ever cover the fields somebody remembered.
    fn identifying_dialog() -> Result<SipDialog, TestError> {
        let headers: &[&str] = &[
            "From: \"Alice Kowalski\" <sip:+15551234567@pbx.internal.example>;tag=t1",
            "To: \"Bob Vance\" <sip:+15559876543@carrier.internal.example>",
            "Call-ID: 8f2a1c@pbx.internal.example",
            "CSeq: 1 INVITE",
            "Contact: <sip:+15551234567@10.11.12.13:5060>",
            "P-Asserted-Identity: <sip:+15551234567@pbx.internal.example>",
            "Diversion: <sip:+15550001111@pbx.internal.example>;reason=no-answer",
            "Remote-Party-ID: <sip:+15551234567@pbx.internal.example>;party=calling",
            "P-Charging-Vector: icid-value=\"sbc01.carrier.internal.example-abc\";\
             icid-generated-at=sbc01.carrier.internal.example;orig-ioi=carrier.internal.example;\
             term-ioi=peer.internal.example;transit-ioi=transit1.internal.example.1",
            "Authorization: Digest username=\"alice\", realm=\"pbx.internal.example\", \
             nonce=\"deadbeefcafe\", response=\"0123456789abcdef0123456789abcdef\"",
            "User-Agent: AliceUA/1.0",
            "Content-Type: application/sdp",
        ];
        let body = b"v=0\r\n\
                     o=alice 2890844526 2890844527 IN IP4 10.11.12.13\r\n\
                     s=Alice Kowalski calling\r\n\
                     c=IN IP4 10.11.12.13\r\n\
                     t=0 0\r\n\
                     m=audio 49170 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n";
        let invite = parse_sip(
            &build_sip(
                "INVITE sip:+15559876543@carrier.internal.example SIP/2.0",
                headers,
                body,
            ),
            ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?;
        Ok(SipDialog::new(&invite).ok_or("INVITE opens a dialog")?)
    }

    /// Every value the container must not contain once redaction is on.
    const MUST_NOT_LEAK: &[&str] = &[
        // Subscriber E.164s, and the bare national numbers inside them.
        "+15551234567",
        "5551234567",
        "+15559876543",
        "9876543",
        "+15550001111",
        // Display names.
        "Alice Kowalski",
        "Bob Vance",
        // Internal host names, whole and in fragments that identify them.
        "pbx.internal.example",
        "carrier.internal.example",
        "sbc01",
        "peer.internal.example",
        "transit1",
        // Internal addresses.
        "10.11.12.13",
        // The digest credential: the offline attack against HA1.
        "deadbeefcafe",
        "0123456789abcdef",
        // The Call-ID's local half.
        "8f2a1c",
    ];

    /// A redacted container, and the policy that produced it.
    fn redacted_container() -> Result<String, TestError> {
        let dialog = identifying_dialog()?;
        let facts = clean_facts();
        let container = export_with(&dialog, &facts)?;
        let policy = crate::output::redact::RedactionPolicy::new(
            crate::output::redact::RedactionKey::from_secret(crate::test_material::key_bytes(
                "vcon-leak-test",
            )),
        );
        let redactor = policy.redactor();
        Ok(sealed_json(&seal(container, Some(&redactor)))?)
    }

    /// **The leak test.** Not one value on the inventory survives redaction.
    ///
    /// Asserted over the WHOLE serialized container rather than field by
    /// field, and that is the point. A field-by-field test proves only that the
    /// fields somebody thought of are covered; this one fails the day a new
    /// field carries an identity out through a path nobody considered — which
    /// is the failure mode a privacy feature actually has.
    #[test]
    fn nothing_on_the_inventory_survives_redaction() -> Result<(), TestError> {
        let json = redacted_container()?;
        for value in MUST_NOT_LEAK {
            assert!(
                !json.contains(value),
                "'{value}' survived redaction in:\n{json}"
            );
        }
        Ok(())
    }

    /// The same values ARE present without redaction.
    ///
    /// Without this the leak test above is unfalsifiable: a fixture whose
    /// values never reached the container in the first place would pass it
    /// while proving nothing at all. This is the guard that makes the guard
    /// mean something.
    #[test]
    fn the_leak_test_is_testing_something() -> Result<(), TestError> {
        let dialog = identifying_dialog()?;
        let facts = clean_facts();
        let json = export_with(&dialog, &facts)?.to_json()?;
        // The two digest values are the exception, and they are absent for a
        // reason that predates redaction: `strip_credentials` already removes
        // the whole `Authorization` row from the trace. Everything else on the
        // inventory has to be here, or the test above is measuring an empty
        // fixture.
        for value in MUST_NOT_LEAK {
            if *value == "deadbeefcafe" || *value == "0123456789abcdef" {
                continue;
            }
            assert!(
                json.contains(value),
                "the fixture never emitted '{value}', so redacting it proves nothing"
            );
        }
        Ok(())
    }

    /// Correlation survives: one identity, one token, everywhere it appears.
    ///
    /// The whole reason this is pseudonymization and not masking. `From`,
    /// `Contact`, `P-Asserted-Identity` and `Remote-Party-ID` all carry the
    /// same caller in this fixture, and an agent asked "is this the same
    /// subscriber" has to still be able to answer yes.
    #[test]
    fn one_identity_reaches_the_container_as_one_token() -> Result<(), TestError> {
        let json = redacted_container()?;
        let value: serde_json::Value = serde_json::from_str(&json)?;
        let token = value["parties"][0]["tel"]
            .as_str()
            .or_else(|| value["parties"][0]["sip"].as_str())
            .ok_or_else(|| format!("the caller party must carry a URI: {json}"))?
            .to_string();
        let user = token
            .rsplit_once('@')
            .map_or(token.as_str(), |(left, _)| left)
            .rsplit_once(':')
            .map_or(token.as_str(), |(_, right)| right);
        let hits = json.matches(user).count();
        assert!(
            hits >= 3,
            "the caller's token appears {hits} time(s); correlation across From, Contact and \
             P-Asserted-Identity is the reason this is not masking:\n{json}"
        );
        Ok(())
    }

    /// The container says, in the format's own vocabulary, that it was
    /// redacted.
    ///
    /// Without it an agent quotes `+1x...` to an operator as the caller's
    /// number. The `redacted` object ([core-04 section 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8)) is where a
    /// vCon consumer already looks for "content was removed", so
    /// pseudonymization goes there rather than inventing a second place.
    #[test]
    fn a_redacted_container_declares_itself() -> Result<(), TestError> {
        let json = redacted_container()?;
        let value: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(value["redacted"]["type"], CONTENT_PSEUDONYMIZED, "{json}");

        let caveat = value["attachments"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["purpose"] == COMPLETENESS_PURPOSE))
            .ok_or_else(|| format!("the completeness caveat must be present: {json}"))?;
        let body = body_of(caveat)?;
        assert_eq!(body["redaction"]["enabled"], true, "{body}");
        assert_eq!(body["redaction"]["key_mode"], "supplied", "{body}");
        assert!(
            body["redaction"]["classes"]
                .as_array()
                .is_some_and(|c| c.iter().any(|v| v == "credential")),
            "{body}"
        );
        Ok(())
    }

    /// A withheld container keeps its own marker.
    ///
    /// `content-withheld` is the stronger statement of the two: nothing
    /// survived to pseudonymize. Overwriting it would understate what the deny
    /// rule did.
    #[test]
    fn a_withheld_container_keeps_its_stronger_marker() -> Result<(), TestError> {
        let dialog = identifying_dialog()?;
        let facts = clean_facts();
        let container = export_withheld_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "fixture.pcap",
                facts: &facts,
                analysis: None,
                max_inline_media_bytes: None,
                media: &[],
                related_legs: &[],
            },
            "X-No-Record",
            exported_at()?,
        );
        let policy = crate::output::redact::RedactionPolicy::new(
            crate::output::redact::RedactionKey::from_secret(crate::test_material::key_bytes(
                "vcon-leak-test",
            )),
        );
        let json = sealed_json(&seal(container, Some(&policy.redactor())))?;
        let value: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(value["redacted"]["type"], CONTENT_WITHHELD, "{json}");
        for leak in MUST_NOT_LEAK {
            assert!(!json.contains(leak), "'{leak}' survived: {json}");
        }
        Ok(())
    }

    /// An unsealed export is byte-identical to a sealed pass-through.
    ///
    /// The bypass exists — `--redact` is opt-in — and this pins that turning
    /// redaction OFF changes nothing else about a container. A boundary that
    /// quietly reshaped the output for every run would be paid for by every
    /// consumer, redacting or not.
    #[test]
    fn pass_through_changes_nothing() -> Result<(), TestError> {
        let dialog = identifying_dialog()?;
        let facts = clean_facts();
        let direct = export_with(&dialog, &facts)?.to_json()?;
        let sealed = sealed_json(&seal(export_with(&dialog, &facts)?, None))?;
        assert_eq!(direct, sealed);
        Ok(())
    }

    /// A PASSporT is deleted, not carried through redaction.
    ///
    /// An RFC 8224 token is a signed JWS whose payload holds `orig` and `dest`
    /// in the clear — base64url is an encoding, not encryption — so publishing
    /// it publishes both numbers. It cannot be rewritten either: any edit to
    /// the payload invalidates the signature, and a PASSporT that does not
    /// verify is worse than an absent one, because a consumer that checks it
    /// reports a forgery where there was none.
    #[test]
    fn a_passport_does_not_survive_redaction() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        // The payload decodes to {"dest":{"tn":["15559876543"]},...}.
        let token = "eyJhbGciOiJFUzI1NiJ9.\
                     eyJkZXN0Ijp7InRuIjpbIjE1NTU5ODc2NTQzIl19fQ.sig";
        let mut party = Party {
            sip: Some("sip:+15551234567@pbx.internal.example".to_string()),
            tel: None,
            validation: "none",
            role: None,
            name: None,
            stir: Some(token.to_string()),
            sip_display_name: None,
            sip_contact: None,
            sip_user_agent: None,
        };
        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("stir"),
        ));
        party.redact(&policy.redactor());
        assert!(
            party.stir.is_none(),
            "a PASSporT carries the numbers it attests, in the clear"
        );
        Ok(())
    }

    /// The capturing host's own name does not survive redaction.
    ///
    /// It reaches the container twice: as a field, and inside the completeness
    /// caveat's prose — "Produced by sipnab X on node Y". The field was
    /// redacted from the first day and the prose was not, which is exactly the
    /// free-text leak a structured-field-only design ships with: every
    /// identifier dutifully tokenized, and the operator's capture host named in
    /// a sentence beside them.
    #[test]
    fn the_capture_host_does_not_survive_in_prose() -> Result<(), TestError> {
        let node = crate::provenance::node_name();
        if node.is_empty() {
            return Ok(());
        }
        let json = redacted_container()?;
        assert!(
            !json.contains(node),
            "the capture host '{node}' survived redaction in:\n{json}"
        );
        Ok(())
    }

    /// Inline audio is refused rather than pseudonymized.
    ///
    /// There is no keyed transform of speech that keeps a diagnosis answerable
    /// and carries no content. A container that tokenized every identifier and
    /// then inlined the conversation would be the most complete privacy
    /// failure this module could ship.
    #[test]
    fn redaction_refuses_inline_audio() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let mut object = Dialog::bare(RECORDING_TYPE, "call-1".to_string());
        object.mediatype = Some(RECORDING_MEDIATYPE.into());
        object.encoding = Some("base64url");
        object.body = Some("UklGRiQAAABXQVZF".to_string());
        object.content_hash = Some(format!("{CONTENT_HASH_PREFIX}abc"));
        object.duration = Some(4.5);

        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("audio"),
        ));
        object.redact(&policy.redactor());

        assert!(object.body.is_none(), "the audio must not survive");
        assert!(object.content_hash.is_none(), "nor a hash over it");
        assert!(object.mediatype.is_none());
        assert!(object.encoding.is_none());
        assert_eq!(
            object.duration,
            Some(4.5),
            "the clock stays: the export still has to say a recording existed"
        );
        Ok(())
    }

    // ── The signaling Dialog Object's parties, originator and duration ──

    /// A request in the fixture's dialog, sent by `sender` ("alice" or "bob").
    ///
    /// The tags follow the sender: Alice's requests carry `From` tag `t1`,
    /// Bob's carry `t2`, which is what [`sender_party`] reads.
    fn in_dialog_request(
        method: &str,
        cseq: u32,
        sender: &str,
        extra: &[&str],
        body: &[u8],
    ) -> Result<crate::sip::SipMessage, TestError> {
        let (from, to) = if sender == "alice" {
            (
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>;tag=t2",
            )
        } else {
            (
                "From: \"Bob\" <sip:bob@example.net>;tag=t2",
                "To: \"Alice\" <sip:alice@example.com>;tag=t1",
            )
        };
        let cseq_line = format!("CSeq: {cseq} {method}");
        let length = format!("Content-Length: {}", body.len());
        let mut headers = vec![from, to, "Call-ID: vcon-fixture@example.com", &cseq_line];
        headers.extend_from_slice(extra);
        headers.push(&length);
        Ok(parse_sip(
            &build_sip(
                &format!("{method} sip:peer@example.org SIP/2.0"),
                &headers,
                body,
            ),
            ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// A dialog built the way the store builds one: state and timing updated
    /// per message, each message stamped `secs` after [`ts`].
    fn timed_dialog(steps: Vec<(crate::sip::SipMessage, i64)>) -> Result<SipDialog, TestError> {
        let mut steps = steps.into_iter();
        let (mut first, at) = steps.next().ok_or("a dialog needs one message")?;
        first.timestamp = ts()? + chrono::TimeDelta::seconds(at);
        let mut dialog = SipDialog::new(&first).ok_or("the first message opens a dialog")?;
        let method = dialog.method.clone();
        crate::sip::timing::update_timing(&mut dialog.timing, &first, &method);
        for (mut m, at) in steps {
            m.timestamp = ts()? + chrono::TimeDelta::seconds(at);
            crate::sip::dialog::update_state(&mut dialog, &m);
            crate::sip::timing::update_timing(&mut dialog.timing, &m, &method);
            dialog.messages.push(m);
        }
        Ok(dialog)
    }

    /// An answered call Alice ended: INVITE at 0 s, 200 at 3 s, BYE at 63 s.
    fn answered_and_ended() -> Result<SipDialog, TestError> {
        timed_dialog(vec![
            (invite()?, 0),
            (response(180, "Ringing")?, 1),
            (response(200, "OK")?, 3),
            (in_dialog_request("ACK", 1, "alice", &[], b"")?, 3),
            (in_dialog_request("BYE", 2, "alice", &[], b"")?, 63),
        ])
    }

    /// The container as JSON, after checking it against the vendored schema.
    fn valid_json(v: &Vcon) -> Result<serde_json::Value, TestError> {
        use crate::output::vcon_schema::{SchemaVerdict, validate};
        let json = serde_json::to_value(v)?;
        let report = validate(&json);
        if report.verdict != SchemaVerdict::Valid {
            return Err(
                format!("the container fails the vendored schema: {report:#?}\n{json:#}").into(),
            );
        }
        Ok(json)
    }

    /// GAP-4: the signaling object names the `From` and `To` parties, in that
    /// order, and no `originator`, because the opening INVITE's `From` is the
    /// caller ([core-04 section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4)).
    #[test]
    fn the_signaling_object_names_from_then_to_as_its_parties() -> Result<(), TestError> {
        let v = export_with(&answered_and_ended()?, &clean_facts())?;
        let json = valid_json(&v)?;
        assert_eq!(json["dialog"][0]["parties"], serde_json::json!([0, 1]));
        assert!(json["dialog"][0].get("originator").is_none());
        Ok(())
    }

    /// GAP-4: an unanswered call still names who was called; core-04 Table 1
    /// lets an `incomplete` object carry the parties it tried to connect.
    #[test]
    fn a_failed_call_names_the_parties_it_tried_to_connect() -> Result<(), TestError> {
        let v = export_with(
            &dialog_with(&[response(486, "Busy Here")?])?,
            &clean_facts(),
        )?;
        let json = valid_json(&v)?;
        assert_eq!(json["dialog"][0]["type"], INCOMPLETE_TYPE);
        assert_eq!(json["dialog"][0]["parties"], serde_json::json!([0, 1]));
        Ok(())
    }

    /// GAP-4: `duration` is the conversation, answer to BYE, in seconds
    /// ([core-04 section 4.3.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3)).
    #[test]
    fn the_signaling_object_carries_answer_to_bye_as_its_duration() -> Result<(), TestError> {
        let v = export_with(&answered_and_ended()?, &clean_facts())?;
        let json = valid_json(&v)?;
        assert_eq!(json["dialog"][0]["duration"], serde_json::json!(60.0));
        Ok(())
    }

    /// GAP-4: no BYE, or no answer, is no duration: the capture does not hold
    /// both ends, and an invented one would be read as measured.
    #[test]
    fn a_call_without_both_ends_carries_no_duration() -> Result<(), TestError> {
        let unended = timed_dialog(vec![(invite()?, 0), (response(200, "OK")?, 3)])?;
        let unanswered = timed_dialog(vec![(invite()?, 0), (response(486, "Busy Here")?, 3)])?;
        for dialog in [unended, unanswered] {
            let json = valid_json(&export_with(&dialog, &clean_facts())?)?;
            assert!(json["dialog"][0].get("duration").is_none());
        }
        Ok(())
    }

    /// GAP-4: a 200 seen without its INVITE cannot be tied to the initial
    /// transaction, so the conversation's start is not known and no
    /// `duration` is written, even with a BYE.
    #[test]
    fn an_answer_without_its_invite_carries_no_duration() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (response(200, "OK")?, 3),
            (in_dialog_request("BYE", 2, "alice", &[], b"")?, 63),
        ])?;
        let json = valid_json(&export_with(&dialog, &clean_facts())?)?;
        assert!(json["dialog"][0].get("duration").is_none());
        Ok(())
    }

    /// GAP-4: a capture that joined mid-call does not know who called. The
    /// first party is then not known to be the originator, so `originator`
    /// names an empty Party Object, the form core-04 section 4.3.5 gives an
    /// unknown originator, and the observer stays last.
    #[test]
    fn a_dialog_first_seen_mid_call_names_an_unknown_originator() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![(in_dialog_request("BYE", 7, "bob", &[], b"")?, 0)])?;
        let v = export_with(&dialog, &clean_facts())?;
        let json = valid_json(&v)?;
        assert_eq!(json["dialog"][0]["parties"], serde_json::json!([0, 1]));
        let originator = json["dialog"][0]["originator"]
            .as_u64()
            .ok_or("an originator index")?;
        assert_eq!(originator, 2);
        let unknown = &json["parties"][2];
        assert!(unknown.get("sip").is_none() && unknown.get("role").is_none());
        assert_eq!(v.observer_index(), 3);
        assert_eq!(json["parties"][3]["role"], OBSERVER_ROLE);
        Ok(())
    }

    // ── sip_cseq ──

    /// GAP-16: `sip_cseq` is the CSeq number of the dialog-creating request,
    /// [draft-howe-vcon-sip-signaling-00 section 5.4](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-5.4):
    /// "the sequence number from the CSeq header field of the INVITE or other
    /// dialog-creating request".
    #[test]
    fn the_signaling_object_carries_the_dialog_creating_cseq() -> Result<(), TestError> {
        let invite = message(
            "INVITE sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 314159 INVITE",
                "Content-Length: 0",
            ],
        )?;
        let dialog = timed_dialog(vec![
            (invite, 0),
            (in_dialog_request("BYE", 314_160, "alice", &[], b"")?, 9),
        ])?;
        let json = valid_json(&export_with(&dialog, &clean_facts())?)?;
        assert_eq!(json["dialog"][0]["sip_cseq"], serde_json::json!(314_159));
        Ok(())
    }

    /// GAP-16: a capture that never saw the dialog-creating request has no
    /// number to give, and a later request's CSeq is a different transaction.
    #[test]
    fn a_dialog_first_seen_mid_call_carries_no_sip_cseq() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![(in_dialog_request("BYE", 7, "bob", &[], b"")?, 0)])?;
        let json = valid_json(&export_with(&dialog, &clean_facts())?)?;
        assert!(json["dialog"][0].get("sip_cseq").is_none());
        Ok(())
    }

    // ── The sip-message-trace body in the draft's shape ──

    /// The trace attachment's body, as JSON.
    fn trace_body(v: &Vcon) -> Result<serde_json::Value, TestError> {
        let json = valid_json(v)?;
        let trace = json["attachments"]
            .as_array()
            .and_then(|a| a.iter().find(|a| a["purpose"] == MESSAGE_TRACE_PURPOSE))
            .ok_or("a trace attachment")?;
        body_of(trace)
    }

    /// GAP-14: the trace body carries the fields of
    /// [draft-howe-vcon-sip-signaling-00 section 6.2.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-6.2.1):
    /// `version` "1.0", and per message `direction`, `party`, `method` for a
    /// request, `status_code` and `status_text` for a response. The
    /// `schema_version: 1` fields stay for existing readers.
    #[test]
    fn the_trace_body_carries_the_draft_message_fields() -> Result<(), TestError> {
        let body = trace_body(&export_with(&answered_and_ended()?, &clean_facts())?)?;
        assert_eq!(body["version"], "1.0");
        assert_eq!(body["call_id"], "vcon-fixture@example.com");
        assert_eq!(body["schema_version"], 1);
        let messages = body["messages"].as_array().ok_or("messages")?;
        let invite = &messages[0];
        assert_eq!(invite["direction"], "received");
        assert_eq!(invite["party"], 0);
        assert_eq!(invite["method"], "INVITE");
        assert!(invite.get("status_code").is_none() && invite.get("status_text").is_none());
        let answer = &messages[2];
        assert_eq!(answer["party"], 1);
        assert_eq!(answer["status_code"], 200);
        assert_eq!(answer["status_text"], "OK");
        assert!(answer.get("method").is_none());
        assert_eq!(messages[4]["method"], "BYE");
        assert_eq!(messages[4]["party"], 0);
        Ok(())
    }

    /// GAP-14: a message whose tags match neither party has no `party`; the
    /// draft makes it optional "when the sender cannot be determined".
    #[test]
    fn a_trace_message_from_an_unknown_sender_names_no_party() -> Result<(), TestError> {
        let trying = message(
            "SIP/2.0 100 Trying",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        )?;
        let body = trace_body(&export_with(&dialog_with(&[trying])?, &clean_facts())?)?;
        assert!(body["messages"][1].get("party").is_none());
        assert_eq!(body["messages"][1]["direction"], "received");
        Ok(())
    }

    /// GAP-14: a text body travels as the string; a body that is not UTF-8
    /// travels as base64url with `body_encoding`, as the draft's `body` field
    /// says.
    #[test]
    fn the_trace_carries_each_body_as_text_or_base64url() -> Result<(), TestError> {
        let relay = in_dialog_request(
            "INFO",
            2,
            "alice",
            &["Content-Type: application/dtmf-relay"],
            b"Signal=5\r\nDuration=160\r\n",
        )?;
        let binary = in_dialog_request(
            "INFO",
            3,
            "alice",
            &["Content-Type: application/octet-stream"],
            &[0xff, 0xfe, 0x00, 0x41],
        )?;
        let dialog = timed_dialog(vec![
            (invite()?, 0),
            (response(200, "OK")?, 1),
            (relay, 2),
            (binary, 3),
        ])?;
        let body = trace_body(&export_with(&dialog, &clean_facts())?)?;
        let messages = body["messages"].as_array().ok_or("messages")?;
        assert_eq!(messages[2]["body"], "Signal=5\r\nDuration=160\r\n");
        assert!(messages[2].get("body_encoding").is_none());
        assert_eq!(
            messages[3]["body"],
            URL_SAFE_NO_PAD.encode([0xff, 0xfe, 0x00, 0x41])
        );
        assert_eq!(messages[3]["body_encoding"], "base64url");
        assert!(messages[0].get("body").is_none(), "an empty body is absent");
        Ok(())
    }

    /// GAP-14: under redaction no message body survives in the trace. A
    /// body can be the conversation itself (a SIP MESSAGE), and the SDP it
    /// would duplicate is already in the redacted `sdp` field.
    #[test]
    fn redaction_removes_every_trace_message_body() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let relay = in_dialog_request(
            "INFO",
            2,
            "alice",
            &["Content-Type: application/dtmf-relay"],
            b"Signal=5\r\nDuration=160\r\n",
        )?;
        let dialog = timed_dialog(vec![(invite()?, 0), (response(200, "OK")?, 1), (relay, 2)])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("trace"),
        ));
        v.redact(&policy.redactor());
        let body = trace_body(&v)?;
        for m in body["messages"].as_array().ok_or("messages")? {
            assert!(m.get("body").is_none() && m.get("body_encoding").is_none());
        }
        Ok(())
    }

    /// GAP-14: merging legs moves each trace message's `party` with the
    /// party array, as it moves every other party index.
    #[test]
    fn merging_moves_every_trace_message_party() -> Result<(), TestError> {
        let first = export_with(&answered_and_ended()?, &clean_facts())?;
        let observed = first.parties.len() - 1;
        let second = export_with(&answered_and_ended()?, &clean_facts())?;
        let merged = merge_call_legs(vec![first, second], &[], "uuid".into(), false)
            .ok_or("two legs merge")?;
        let traces: Vec<&Attachment> = merged
            .attachments
            .iter()
            .filter(|a| a.purpose == MESSAGE_TRACE_PURPOSE)
            .collect();
        assert_eq!(traces.len(), 2);
        assert_eq!(traces[0].body["messages"][0]["party"], 0);
        assert_eq!(traces[1].body["messages"][0]["party"], observed);
        assert_eq!(traces[1].body["messages"][2]["party"], observed + 1);
        Ok(())
    }

    // ── sip-invite, sip-response and sip-sdp attachments ──

    /// An SDP offer or answer with one audio line on `port`.
    fn sdp_body(port: u16) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )
    }

    /// A message parsed from a first line, headers and a body.
    fn message_with_body(
        first_line: &str,
        headers: &[&str],
        body: &[u8],
    ) -> Result<crate::sip::SipMessage, TestError> {
        let length = format!("Content-Length: {}", body.len());
        let mut all: Vec<&str> = headers.to_vec();
        all.push(&length);
        Ok(parse_sip(
            &build_sip(first_line, &all, body),
            ts()?,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// An initial INVITE from Alice with CSeq `cseq`, extra headers and an
    /// SDP offer.
    fn offer(cseq: u32, extra: &[&str]) -> Result<crate::sip::SipMessage, TestError> {
        let cseq_line = format!("CSeq: {cseq} INVITE");
        let mut headers = vec![
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
            "From: \"Alice\" <sip:alice@example.com>;tag=t1",
            "To: \"Bob\" <sip:bob@example.net>",
            "Call-ID: vcon-fixture@example.com",
            &cseq_line,
            "Content-Type: application/sdp",
        ];
        headers.extend_from_slice(extra);
        message_with_body(
            "INVITE sip:bob@example.net SIP/2.0",
            &headers,
            sdp_body(4000).as_bytes(),
        )
    }

    /// A response from Bob to the INVITE with CSeq `cseq`, with an SDP answer
    /// when `with_sdp`.
    fn answer_to(
        cseq: u32,
        status: &str,
        to_tag: &str,
        with_sdp: bool,
    ) -> Result<crate::sip::SipMessage, TestError> {
        let cseq_line = format!("CSeq: {cseq} INVITE");
        let to = format!("To: \"Bob\" <sip:bob@example.net>;tag={to_tag}");
        let mut headers = vec![
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
            "From: \"Alice\" <sip:alice@example.com>;tag=t1",
            &to,
            "Call-ID: vcon-fixture@example.com",
            &cseq_line,
        ];
        let body = if with_sdp {
            headers.push("Content-Type: application/sdp");
            sdp_body(5000)
        } else {
            String::new()
        };
        message_with_body(&format!("SIP/2.0 {status}"), &headers, body.as_bytes())
    }

    /// The attachments of `v` with `purpose`.
    fn with_purpose<'a>(v: &'a Vcon, purpose: &str) -> Vec<&'a Attachment> {
        v.attachments
            .iter()
            .filter(|a| a.purpose == purpose)
            .collect()
    }

    /// GAP-13: the minimal producer of
    /// [draft-howe-vcon-sip-signaling-00 section 8.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-8.1):
    /// the initial INVITE and the final response as `message/sip`
    /// attachments in full wire format (section 6.1.2), and each SDP body as
    /// an `application/sdp` attachment (section 6.3), each naming its sender.
    #[test]
    fn the_initial_invite_and_final_response_travel_as_wire_messages() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (offer(1, &[])?, 0),
            (answer_to(1, "180 Ringing", "t2", false)?, 1),
            (answer_to(1, "200 OK", "t2", true)?, 2),
        ])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_sip_message_attachments(&mut v, &dialog, MAX_INLINE_MEDIA_BYTES);
        valid_json(&v)?;

        let invite = with_purpose(&v, SIP_INVITE_PURPOSE);
        assert_eq!(invite.len(), 1);
        assert_eq!(invite[0].mediatype, "message/sip");
        assert_eq!(invite[0].encoding, "none");
        assert_eq!(invite[0].party, 0);
        assert_eq!(invite[0].dialog, 0);
        assert_eq!(invite[0].start, dialog.messages[0].timestamp.to_rfc3339());
        assert_eq!(
            invite[0].body.as_str(),
            std::str::from_utf8(&dialog.messages[0].raw).ok()
        );

        let response = with_purpose(&v, SIP_RESPONSE_PURPOSE);
        assert_eq!(response.len(), 1, "the final response only");
        assert_eq!(response[0].party, 1);
        assert!(
            response[0]
                .body
                .as_str()
                .is_some_and(|b| b.starts_with("SIP/2.0 200 OK\r\n")),
        );

        let sdp = with_purpose(&v, SIP_SDP_PURPOSE);
        assert_eq!(sdp.len(), 2, "the offer and the answer");
        assert_eq!(sdp[0].mediatype, "application/sdp");
        assert_eq!(sdp[0].party, 0);
        assert_eq!(sdp[0].body, serde_json::json!(sdp_body(4000)));
        assert_eq!(sdp[1].party, 1);
        assert_eq!(sdp[1].body, serde_json::json!(sdp_body(5000)));
        Ok(())
    }

    /// GAP-13: a challenged call attaches the INVITE the final response
    /// answered, and its credential header is removed from the wire bytes,
    /// as it is removed from the trace.
    #[test]
    fn a_challenged_call_attaches_the_answered_invite_without_its_credentials()
    -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (offer(1, &[])?, 0),
            (
                answer_to(1, "407 Proxy Authentication Required", "p1", false)?,
                1,
            ),
            (
                offer(
                    2,
                    &["Proxy-Authorization: Digest username=\"alice\", response=\"secret\""],
                )?,
                2,
            ),
            (answer_to(2, "200 OK", "t2", true)?, 3),
        ])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_sip_message_attachments(&mut v, &dialog, MAX_INLINE_MEDIA_BYTES);
        let invite = with_purpose(&v, SIP_INVITE_PURPOSE);
        let text = invite[0].body.as_str().ok_or("a text body")?;
        assert!(text.contains("CSeq: 2 INVITE"));
        assert!(!text.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!text.contains("secret"));
        assert!(text.ends_with(&sdp_body(4000)), "the body is kept");
        let response = with_purpose(&v, SIP_RESPONSE_PURPOSE);
        assert!(
            response[0]
                .body
                .as_str()
                .is_some_and(|b| b.starts_with("SIP/2.0 200 OK")),
        );
        Ok(())
    }

    /// GAP-13: a message that is not UTF-8 is base64url, as section 6.1.2
    /// requires for anything but the `none` encoding of UTF-8 text.
    #[test]
    fn a_wire_message_that_is_not_utf8_is_base64url() -> Result<(), TestError> {
        let binary = message_with_body(
            "INVITE sip:bob@example.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/octet-stream",
            ],
            &[0xff, 0xfe],
        )?;
        let dialog = timed_dialog(vec![(binary, 0)])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_sip_message_attachments(&mut v, &dialog, MAX_INLINE_MEDIA_BYTES);
        let invite = with_purpose(&v, SIP_INVITE_PURPOSE);
        assert_eq!(invite[0].encoding, "base64url");
        assert_eq!(
            invite[0].body,
            serde_json::json!(URL_SAFE_NO_PAD.encode(&dialog.messages[0].raw))
        );
        Ok(())
    }

    /// GAP-13: the rule's inline budget covers these attachments. One that
    /// does not fit is left out, and the completeness attachment names it.
    #[test]
    fn a_wire_message_over_the_budget_is_refused_and_named() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (offer(1, &[])?, 0),
            (answer_to(1, "200 OK", "t2", true)?, 2),
        ])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_sip_message_attachments(&mut v, &dialog, 0);
        for purpose in [SIP_INVITE_PURPOSE, SIP_RESPONSE_PURPOSE, SIP_SDP_PURPOSE] {
            assert!(with_purpose(&v, purpose).is_empty(), "{purpose}");
        }
        let completeness = with_purpose(&v, COMPLETENESS_PURPOSE);
        let refused = completeness[0].body["sip_messages_refused"]
            .as_array()
            .ok_or("a refused list")?;
        assert_eq!(refused.len(), 4);
        assert_eq!(refused[0]["purpose"], SIP_INVITE_PURPOSE);
        assert!(refused[0]["bytes"].as_u64().is_some_and(|n| n > 0));
        Ok(())
    }

    /// GAP-13: under redaction the wire attachments are removed. The bytes
    /// hold every identifier the trace holds, in a form redaction cannot
    /// rewrite without changing the message.
    #[test]
    fn redaction_removes_the_wire_attachments() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let dialog = timed_dialog(vec![
            (offer(1, &[])?, 0),
            (answer_to(1, "200 OK", "t2", true)?, 2),
        ])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_sip_message_attachments(&mut v, &dialog, MAX_INLINE_MEDIA_BYTES);
        assert_eq!(with_purpose(&v, SIP_SDP_PURPOSE).len(), 2, "precondition");
        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("wire"),
        ));
        v.redact(&policy.redactor());
        for purpose in [SIP_INVITE_PURPOSE, SIP_RESPONSE_PURPOSE, SIP_SDP_PURPOSE] {
            assert!(with_purpose(&v, purpose).is_empty(), "{purpose}");
        }
        Ok(())
    }

    /// GAP-13: sipnab's own `-I` reader takes the messages from the trace and
    /// does not read the wire attachments a second time.
    #[test]
    fn reading_the_container_back_counts_each_message_once() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (offer(1, &[])?, 0),
            (answer_to(1, "200 OK", "t2", true)?, 2),
        ])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_sip_message_attachments(&mut v, &dialog, MAX_INLINE_MEDIA_BYTES);
        let rebuilt = crate::capture::vcon_input::rebuild(&serde_json::to_value(&v)?, "test")
            .map_err(|e| format!("{e}"))?;
        assert_eq!(rebuilt.messages.len(), dialog.messages.len());
        Ok(())
    }

    // ── stir-verification-report ──

    /// An `Identity` header carrying a PASSporT with attestation `attest`.
    fn identity_header(attest: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","ppt":"shaken","typ":"passport"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"attest":"{attest}","dest":{{"tn":["12125559876"]}},"iat":1,"orig":{{"tn":"12125551234"}},"origid":"x"}}"#
            )
            .as_bytes(),
        );
        format!(
            "Identity: {header}.{payload}.c2ln;info=<https://cert.example/c.pem>;alg=ES256;ppt=shaken"
        )
    }

    /// An initial INVITE from Alice carrying `extra` headers.
    fn invite_carrying(extra: &[&str]) -> Result<crate::sip::SipMessage, TestError> {
        let mut headers = vec![
            "From: \"Alice\" <sip:+12125551234@example.com>;tag=t1",
            "To: \"Bob\" <sip:+12125559876@example.net>",
            "Call-ID: vcon-fixture@example.com",
            "CSeq: 1 INVITE",
        ];
        headers.extend_from_slice(extra);
        message_with_body("INVITE sip:bob@example.net SIP/2.0", &headers, b"")
    }

    /// The `stir-verification-report` attachments of an export of `invite`.
    fn stir_reports(invite: crate::sip::SipMessage) -> Result<Vec<Attachment>, TestError> {
        let dialog = timed_dialog(vec![(invite, 0)])?;
        let v = export_with(&dialog, &clean_facts())?;
        valid_json(&v)?;
        Ok(with_purpose(&v, STIR_REPORT_PURPOSE)
            .into_iter()
            .cloned()
            .collect())
    }

    /// GAP-15: a `verstat` the network wrote on `P-Asserted-Identity`
    /// becomes the report of
    /// [draft-howe-vcon-sip-signaling-00 section 7.3](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-7.3),
    /// with the PASSporT's claims beside it and a reason saying sipnab
    /// verified nothing.
    // The attestation and numbers come from the PASSporT parser, a `tls` item.
    #[cfg(feature = "tls")]
    #[test]
    fn a_verstat_becomes_a_stir_verification_report() -> Result<(), TestError> {
        let identity = identity_header("A");
        let reports = stir_reports(invite_carrying(&[
            "P-Asserted-Identity: <sip:+12125551234@example.com;verstat=TN-Validation-Passed>",
            &identity,
        ])?)?;
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.party, 0);
        assert_eq!(report.dialog, 0);
        assert_eq!(report.mediatype, "application/json");
        assert_eq!(report.encoding, "json");
        let body = &report.body;
        assert_eq!(body["result"], "verified");
        assert_eq!(body["verstat"], "TN-Validation-Passed");
        assert_eq!(body["verstat_header"], "P-Asserted-Identity");
        assert_eq!(body["attestation"], "A");
        assert_eq!(body["orig_tn"], "12125551234");
        assert_eq!(body["dest_tn"], serde_json::json!(["12125559876"]));
        assert_eq!(body["timestamp"], ts()?.to_rfc3339());
        assert!(
            body.get("verifier").is_none(),
            "sipnab cannot name the verifier"
        );
        assert!(
            body["reason"]
                .as_str()
                .is_some_and(|r| r.contains("sipnab verified nothing")),
        );
        Ok(())
    }

    /// GAP-15: each ATIS-1000074 value maps onto the draft's `result`;
    /// `No-TN-Validation` is `no-signature` only when no PASSporT was seen.
    #[test]
    fn each_verstat_value_maps_onto_the_draft_result() -> Result<(), TestError> {
        let identity = identity_header("B");
        let cases: [(&str, bool, Option<&str>); 4] = [
            ("TN-Validation-Failed", true, Some("failed")),
            ("TN-Validation-Passed", false, Some("verified")),
            ("No-TN-Validation", false, Some("no-signature")),
            ("No-TN-Validation", true, None),
        ];
        for (verstat, with_identity, result) in cases {
            let pai = format!("P-Asserted-Identity: <tel:+12125551234;verstat={verstat}>");
            let mut extra = vec![pai.as_str()];
            if with_identity {
                extra.push(&identity);
            }
            let reports = stir_reports(invite_carrying(&extra)?)?;
            assert_eq!(reports.len(), 1, "{verstat}");
            assert_eq!(
                reports[0].body.get("result").and_then(|r| r.as_str()),
                result,
                "{verstat} with_identity={with_identity}"
            );
        }
        Ok(())
    }

    /// GAP-15: with no `P-Asserted-Identity`, a `verstat` on `From` is read.
    #[test]
    fn a_verstat_on_from_is_read_when_no_pai_carries_one() -> Result<(), TestError> {
        let message = message_with_body(
            "INVITE sip:bob@example.net SIP/2.0",
            &[
                "From: <sip:+12125551234;verstat=TN-Validation-Passed@example.com;user=phone>;tag=t1",
                "To: <sip:+12125559876@example.net>",
                "Call-ID: vcon-fixture@example.com",
                "CSeq: 1 INVITE",
            ],
            b"",
        )?;
        let reports = stir_reports(message)?;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].body["verstat_header"], "From");
        assert_eq!(reports[0].body["verstat"], "TN-Validation-Passed");
        Ok(())
    }

    /// GAP-15: no `verstat` is no verdict to transcribe, PASSporT or not.
    #[test]
    fn no_verstat_writes_no_report() -> Result<(), TestError> {
        let identity = identity_header("A");
        assert!(stir_reports(invite_carrying(&[&identity])?)?.is_empty());
        assert!(stir_reports(invite()?)?.is_empty());
        Ok(())
    }

    /// GAP-15: redaction deletes the telephone numbers the report copies out
    /// of the PASSporT, as it deletes the PASSporT itself.
    #[test]
    fn redaction_deletes_the_report_numbers() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let identity = identity_header("A");
        let dialog = timed_dialog(vec![(
            invite_carrying(&[
                "P-Asserted-Identity: <tel:+12125551234;verstat=TN-Validation-Passed>",
                &identity,
            ])?,
            0,
        )])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("stir"),
        ));
        v.redact(&policy.redactor());
        let report = with_purpose(&v, STIR_REPORT_PURPOSE);
        assert_eq!(report.len(), 1);
        assert!(report[0].body.get("orig_tn").is_none());
        assert!(report[0].body.get("dest_tn").is_none());
        assert_eq!(report[0].body["result"], "verified");
        Ok(())
    }

    // ── party_history ──

    /// An in-dialog re-INVITE or UPDATE from `sender` whose SDP says
    /// `direction`.
    fn reoffer(
        method: &str,
        cseq: u32,
        sender: &str,
        direction: &str,
    ) -> Result<crate::sip::SipMessage, TestError> {
        let body = format!("{}a={direction}\r\n", sdp_body(4000));
        in_dialog_request(
            method,
            cseq,
            sender,
            &["Content-Type: application/sdp"],
            body.as_bytes(),
        )
    }

    /// A response from the far end to an in-dialog request from `sender`.
    fn in_dialog_response(
        status: &str,
        cseq: u32,
        method: &str,
        sender: &str,
    ) -> Result<crate::sip::SipMessage, TestError> {
        let (from, to) = if sender == "alice" {
            (
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>;tag=t2",
            )
        } else {
            (
                "From: \"Bob\" <sip:bob@example.net>;tag=t2",
                "To: \"Alice\" <sip:alice@example.com>;tag=t1",
            )
        };
        let cseq_line = format!("CSeq: {cseq} {method}");
        message_with_body(
            &format!("SIP/2.0 {status}"),
            &[from, to, "Call-ID: vcon-fixture@example.com", &cseq_line],
            b"",
        )
    }

    /// `party_history` of the signaling object, as `(party, seconds after
    /// [`ts`], event)`.
    fn history(v: &Vcon) -> Result<Vec<(usize, i64, String)>, TestError> {
        let json = valid_json(v)?;
        let Some(list) = json["dialog"][0]["party_history"].as_array() else {
            return Ok(Vec::new());
        };
        let t0 = ts()?;
        list.iter()
            .map(|e| {
                let at = DateTime::parse_from_rfc3339(e["time"].as_str().ok_or("time")?)?
                    .with_timezone(&Utc);
                Ok((
                    usize::try_from(e["party"].as_u64().ok_or("party")?)?,
                    (at - t0).num_seconds(),
                    e["event"].as_str().ok_or("event")?.to_string(),
                ))
            })
            .collect()
    }

    /// GAP-17: both parties join at the answer, and each drops when the
    /// capture shows it leaving: the BYE's sender at the BYE, the other at
    /// the BYE's 200 ([core-04 section 4.3.13](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.13)).
    #[test]
    fn the_answer_and_the_bye_are_joins_and_drops() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (invite()?, 0),
            (response(200, "OK")?, 3),
            (in_dialog_request("ACK", 1, "alice", &[], b"")?, 3),
            (in_dialog_request("BYE", 2, "bob", &[], b"")?, 63),
            (in_dialog_response("200 OK", 2, "BYE", "bob")?, 64),
        ])?;
        let v = export_with(&dialog, &clean_facts())?;
        assert_eq!(
            history(&v)?,
            vec![
                (0, 3, "join".to_string()),
                (1, 3, "join".to_string()),
                (1, 63, "drop".to_string()),
                (0, 64, "drop".to_string()),
            ]
        );
        Ok(())
    }

    /// GAP-17: a re-INVITE or UPDATE whose SDP says `sendonly` or `inactive`
    /// puts the OTHER party on hold; a later `sendrecv` from the same sender
    /// takes it off hold. `recvonly` changes nothing.
    #[test]
    fn sdp_direction_in_a_reoffer_is_hold_and_unhold() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (invite()?, 0),
            (response(200, "OK")?, 3),
            (reoffer("INVITE", 2, "alice", "sendonly")?, 10),
            (reoffer("INVITE", 3, "alice", "sendrecv")?, 20),
            (reoffer("UPDATE", 1, "bob", "inactive")?, 30),
            (reoffer("UPDATE", 2, "bob", "recvonly")?, 35),
            (reoffer("UPDATE", 3, "bob", "sendrecv")?, 40),
        ])?;
        let v = export_with(&dialog, &clean_facts())?;
        assert_eq!(
            history(&v)?,
            vec![
                (0, 3, "join".to_string()),
                (1, 3, "join".to_string()),
                (1, 10, "hold".to_string()),
                (1, 20, "unhold".to_string()),
                (0, 30, "hold".to_string()),
                (0, 40, "unhold".to_string()),
            ]
        );
        Ok(())
    }

    /// GAP-17: only events the capture shows. An unanswered call has none; a
    /// capture that joined mid-call shows no join; a `sendrecv` re-INVITE
    /// with no hold before it is no unhold.
    #[test]
    fn no_event_is_written_that_the_capture_does_not_show() -> Result<(), TestError> {
        let unanswered = export_with(
            &dialog_with(&[response(486, "Busy Here")?])?,
            &clean_facts(),
        )?;
        assert!(
            valid_json(&unanswered)?["dialog"][0]
                .get("party_history")
                .is_none()
        );

        let mid_call = timed_dialog(vec![
            (reoffer("INVITE", 5, "alice", "sendrecv")?, 0),
            (in_dialog_request("BYE", 6, "alice", &[], b"")?, 9),
        ])?;
        assert_eq!(
            history(&export_with(&mid_call, &clean_facts())?)?,
            vec![(0, 9, "drop".to_string())]
        );
        Ok(())
    }

    /// GAP-17: merging legs moves `party_history` with the party array.
    #[test]
    fn merging_moves_the_party_history() -> Result<(), TestError> {
        let first = export_with(&answered_and_ended()?, &clean_facts())?;
        let observed = first.parties.len() - 1;
        let objects = first.dialog.len();
        let merged = merge_call_legs(
            vec![first, export_with(&answered_and_ended()?, &clean_facts())?],
            &[],
            "uuid".into(),
            false,
        )
        .ok_or("two legs merge")?;
        let history = merged.dialog[objects]
            .party_history
            .as_ref()
            .ok_or("the second leg's history")?;
        assert_eq!(history[0].party, observed);
        assert_eq!(history[1].party, observed + 1);
        Ok(())
    }

    // ── keydown and keyup ──

    /// One `party_history` entry as `(party, milliseconds after [`ts`],
    /// event, button)`.
    type KeyEvent = (usize, i64, String, Option<String>);

    /// The signaling object's events, as [`KeyEvent`]s.
    fn key_history(v: &Vcon) -> Result<Vec<KeyEvent>, TestError> {
        let json = valid_json(v)?;
        let t0 = ts()?;
        json["dialog"][0]["party_history"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|e| {
                let at = DateTime::parse_from_rfc3339(e["time"].as_str().ok_or("time")?)?
                    .with_timezone(&Utc);
                Ok((
                    usize::try_from(e["party"].as_u64().ok_or("party")?)?,
                    (at - t0).num_milliseconds(),
                    e["event"].as_str().ok_or("event")?.to_string(),
                    e["button"].as_str().map(str::to_string),
                ))
            })
            .collect()
    }

    /// An answered call with an SDP offer from Alice (10.0.0.1:4000) and an
    /// answer from Bob (10.0.0.1:5000), and `more` after it.
    fn answered_with_media(
        more: Vec<(crate::sip::SipMessage, i64)>,
    ) -> Result<SipDialog, TestError> {
        let mut steps = vec![
            (offer(1, &[])?, 0),
            (answer_to(1, "200 OK", "t2", true)?, 1),
        ];
        steps.extend(more);
        timed_dialog(steps)
    }

    /// GAP-17: an INFO `application/dtmf-relay` is a `keydown` at the INFO
    /// and a `keyup` its stated `Duration` later, with the digit as
    /// `button` ([core-04 section 4.3.13.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.13.1)).
    #[test]
    fn an_info_dtmf_relay_is_a_keydown_and_a_keyup() -> Result<(), TestError> {
        let info = in_dialog_request(
            "INFO",
            2,
            "alice",
            &["Content-Type: application/dtmf-relay"],
            b"Signal= 5\r\nDuration= 160\r\n",
        )?;
        let dialog = answered_with_media(vec![(info, 10)])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_key_events(&mut v, &dialog, &[]);
        assert_eq!(
            key_history(&v)?,
            vec![
                (0, 1000, "join".into(), None),
                (1, 1000, "join".into(), None),
                (0, 10_000, "keydown".into(), Some("5".into())),
                (0, 10_160, "keyup".into(), Some("5".into())),
            ]
        );
        Ok(())
    }

    /// GAP-17: an RFC 4733 telephone event is a `keydown` at its end packet
    /// less its duration, and a `keyup` at the end packet, for the party
    /// whose own SDP advertised the sending socket.
    #[test]
    fn an_rtp_telephone_event_is_a_keydown_and_a_keyup() -> Result<(), TestError> {
        let dialog = answered_with_media(Vec::new())?;
        let mut v = export_with(&dialog, &clean_facts())?;
        let pressed = |port: u16, digit: char| RtpKeyPress {
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 9000),
            digit,
            ended_at: ts().unwrap_or_default() + chrono::TimeDelta::seconds(20),
            duration_ms: 200,
        };
        add_key_events(&mut v, &dialog, &[pressed(5000, '#'), pressed(6000, '1')]);
        assert_eq!(
            key_history(&v)?,
            vec![
                (0, 1000, "join".into(), None),
                (1, 1000, "join".into(), None),
                (1, 19_800, "keydown".into(), Some("#".into())),
                (1, 20_000, "keyup".into(), Some("#".into())),
            ],
            "a socket no party advertised yields no event"
        );
        Ok(())
    }

    /// A socket in the [`key_press_party`] tests.
    fn sock(last: u8, port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), port)
    }

    /// A telephone event from a socket no party advertised is the other
    /// party's when exactly one party of the two advertised its destination:
    /// that party received it. A source a party advertised still wins.
    #[test]
    fn a_key_press_from_an_unadvertised_socket_is_the_other_party_of_its_destination() {
        let advertised = [(sock(1, 4000), 0), (sock(2, 5000), 1)];
        assert_eq!(
            key_press_party(&advertised, 2, sock(9, 7000), sock(2, 5000)),
            Some(0),
            "sent to the callee's socket: the caller pressed it"
        );
        assert_eq!(
            key_press_party(&advertised, 2, sock(9, 7000), sock(1, 4000)),
            Some(1),
            "sent to the caller's socket: the callee pressed it"
        );
        assert_eq!(
            key_press_party(&advertised, 2, sock(2, 5000), sock(2, 5000)),
            Some(1),
            "an advertised source names the sender"
        );
    }

    /// Without a single receiver among exactly two parties there is no
    /// sender to infer, and the event names no party.
    #[test]
    fn a_key_press_with_an_ambiguous_destination_names_no_party() {
        let advertised = [(sock(1, 4000), 0), (sock(2, 5000), 1)];
        assert_eq!(
            key_press_party(&advertised, 2, sock(9, 7000), sock(8, 8000)),
            None,
            "a destination no party advertised"
        );
        let both = [(sock(1, 4000), 0), (sock(1, 4000), 1)];
        assert_eq!(
            key_press_party(&both, 2, sock(9, 7000), sock(1, 4000)),
            None,
            "a destination both parties advertised"
        );
        assert_eq!(
            key_press_party(&advertised, 3, sock(9, 7000), sock(2, 5000)),
            None,
            "more than two parties: the receiver does not name the sender"
        );
    }

    /// `add_key_events` writes an event from an unadvertised socket to Bob's
    /// advertised socket (10.0.0.1:5000) for Alice.
    #[test]
    fn an_rtp_telephone_event_to_an_advertised_socket_is_the_senders() -> Result<(), TestError> {
        let dialog = answered_with_media(Vec::new())?;
        let mut v = export_with(&dialog, &clean_facts())?;
        let pressed = RtpKeyPress {
            src: sock(9, 7000),
            dst: sock(1, 5000),
            digit: '7',
            ended_at: ts()? + chrono::TimeDelta::seconds(20),
            duration_ms: 120,
        };
        add_key_events(&mut v, &dialog, &[pressed]);
        assert_eq!(
            key_history(&v)?,
            vec![
                (0, 1000, "join".into(), None),
                (1, 1000, "join".into(), None),
                (0, 19_880, "keydown".into(), Some("7".into())),
                (0, 20_000, "keyup".into(), Some("7".into())),
            ]
        );
        Ok(())
    }

    /// GAP-17: redaction removes `keydown` and `keyup`: the digit can be a
    /// PIN. The other events stay.
    #[test]
    fn redaction_removes_the_key_events() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let info = in_dialog_request(
            "INFO",
            2,
            "alice",
            &["Content-Type: application/dtmf-relay"],
            b"Signal=5\r\nDuration=160\r\n",
        )?;
        let dialog = answered_with_media(vec![(info, 10)])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_key_events(&mut v, &dialog, &[]);
        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("keys"),
        ));
        v.redact(&policy.redactor());
        let events: Vec<String> = key_history(&v)?.into_iter().map(|e| e.2).collect();
        assert_eq!(events, vec!["join".to_string(), "join".to_string()]);
        Ok(())
    }

    /// GAP-17: the history is in time order whatever order the events are
    /// found in: a hold and a key press before the BYE come before its drop.
    #[test]
    fn the_party_history_is_in_time_order() -> Result<(), TestError> {
        let info = in_dialog_request(
            "INFO",
            3,
            "bob",
            &["Content-Type: application/dtmf-relay"],
            b"Signal=7\r\nDuration=100\r\n",
        )?;
        let dialog = answered_with_media(vec![
            (reoffer("INVITE", 2, "alice", "sendonly")?, 10),
            (info, 20),
            (in_dialog_request("BYE", 4, "alice", &[], b"")?, 63),
        ])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        assert_eq!(
            history(&v)?,
            vec![
                (0, 1, "join".to_string()),
                (1, 1, "join".to_string()),
                (1, 10, "hold".to_string()),
                (0, 63, "drop".to_string()),
            ]
        );
        add_key_events(&mut v, &dialog, &[]);
        let events: Vec<String> = key_history(&v)?.into_iter().map(|e| e.2).collect();
        assert_eq!(
            events,
            ["join", "join", "hold", "keydown", "keyup", "drop"].map(String::from)
        );
        Ok(())
    }

    // ── text dialogs from SIP MESSAGE ──

    /// A SIP MESSAGE from `sender` with `cseq`, `content_type` and `body`.
    fn sip_message(
        sender: &str,
        cseq: u32,
        content_type: &str,
        body: &[u8],
    ) -> Result<crate::sip::SipMessage, TestError> {
        let (from, to) = if sender == "alice" {
            (
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.net>",
            )
        } else {
            (
                "From: \"Bob\" <sip:bob@example.net>;tag=t2",
                "To: \"Alice\" <sip:alice@example.com>",
            )
        };
        let cseq_line = format!("CSeq: {cseq} MESSAGE");
        let ct = format!("Content-Type: {content_type}");
        message_with_body(
            "MESSAGE sip:peer@example.org SIP/2.0",
            &[
                from,
                to,
                "Call-ID: vcon-fixture@example.com",
                &cseq_line,
                &ct,
            ],
            body,
        )
    }

    /// The `text` Dialog Objects of a container, as JSON.
    fn text_dialogs(v: &Vcon) -> Result<Vec<serde_json::Value>, TestError> {
        let json = valid_json(v)?;
        Ok(json["dialog"]
            .as_array()
            .map(|l| l.iter().filter(|d| d["type"] == "text").cloned().collect())
            .unwrap_or_default())
    }

    /// GAP-18: each SIP MESSAGE (RFC 3428) body is a `text` Dialog Object
    /// ([core-04 section 4.3.1.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.3))
    /// with its sender first in `parties`, its capture time as `start`, and
    /// the body inline.
    #[test]
    fn each_sip_message_body_is_a_text_dialog() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (
                sip_message("alice", 1, "text/plain;charset=UTF-8", b"hello")?,
                0,
            ),
            (
                sip_message("alice", 1, "text/plain;charset=UTF-8", b"hello")?,
                1,
            ),
            (in_dialog_response("200 OK", 1, "MESSAGE", "alice")?, 1),
            (sip_message("bob", 1, "text/plain", b"hi back")?, 5),
        ])?;
        let texts = text_dialogs(&export_with(&dialog, &clean_facts())?)?;
        assert_eq!(texts.len(), 2, "a retransmission is one text");
        assert_eq!(texts[0]["parties"], serde_json::json!([0, 1]));
        assert_eq!(texts[0]["start"], ts()?.to_rfc3339());
        assert_eq!(texts[0]["mediatype"], "text/plain;charset=UTF-8");
        assert_eq!(texts[0]["encoding"], "none");
        assert_eq!(texts[0]["body"], "hello");
        assert_eq!(texts[0]["sip_call_id"], "vcon-fixture@example.com");
        assert!(texts[0].get("originator").is_none());
        assert_eq!(texts[1]["parties"], serde_json::json!([1, 0]));
        assert_eq!(texts[1]["body"], "hi back");
        assert!(
            texts[1].get("originator").is_none(),
            "the sender is listed first"
        );
        Ok(())
    }

    /// GAP-18: a composing indication (RFC 3994) is not text a party sent,
    /// and an empty MESSAGE carries none; a body that is not UTF-8 is
    /// base64url.
    #[test]
    fn only_a_message_with_content_is_a_text_dialog() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (
                sip_message(
                    "alice",
                    1,
                    "application/im-iscomposing+xml",
                    b"<isComposing/>",
                )?,
                0,
            ),
            (sip_message("alice", 2, "text/plain", b"")?, 1),
            (
                sip_message("alice", 3, "application/vnd.3gpp.sms", &[0x01, 0xff])?,
                2,
            ),
        ])?;
        let texts = text_dialogs(&export_with(&dialog, &clean_facts())?)?;
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0]["mediatype"], "application/vnd.3gpp.sms");
        assert_eq!(texts[0]["encoding"], "base64url");
        assert_eq!(texts[0]["body"], URL_SAFE_NO_PAD.encode([0x01, 0xff]));
        Ok(())
    }

    /// GAP-18: under redaction a text dialog keeps its clock and parties and
    /// loses its content, as a recording does: the text is the conversation.
    #[test]
    fn redaction_removes_the_text() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let dialog = timed_dialog(vec![(
            sip_message("alice", 1, "text/plain", b"my pin is 1234")?,
            0,
        )])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("text"),
        ));
        v.redact(&policy.redactor());
        let texts = text_dialogs(&v)?;
        assert_eq!(texts.len(), 1);
        for field in ["body", "encoding", "mediatype"] {
            assert!(texts[0].get(field).is_none());
        }
        assert_eq!(texts[0]["parties"], serde_json::json!([0, 1]));
        Ok(())
    }

    // ── the tags attachment ──

    /// The `tags` attachments of `v`.
    fn tags_of(v: &Vcon) -> Result<Vec<serde_json::Value>, TestError> {
        let json = valid_json(v)?;
        Ok(json["attachments"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter(|a| a["purpose"] == TAGS_PURPOSE)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// GAP-24: one `tags` attachment whose body is the list of `name:value`
    /// strings vcon-lib reads (`Vcon.get_tag` splits on the colon): the
    /// rule, each named filter the call matched, then the findings.
    #[test]
    fn the_tags_name_the_rule_the_filters_and_the_findings() -> Result<(), TestError> {
        let dialog = dialog_with(&[response(486, "Busy Here")?])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_tags(&mut v, &[&dialog], "support", &["carrier-a", "busy"]);
        let tags = tags_of(&v)?;
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0]["party"], v.observer_index());
        assert_eq!(tags[0]["dialog"], 0);
        assert_eq!(tags[0]["mediatype"], "application/json");
        assert_eq!(tags[0]["encoding"], "json");
        assert_eq!(
            tags[0]["body"],
            serde_json::json!([
                "rule:support",
                "filter:carrier-a",
                "filter:busy",
                "finding:final_failure"
            ])
        );
        Ok(())
    }

    /// GAP-24: the findings are the signaling diagnosis's detections in its
    /// own order, each once across a call's legs, and at most the cap.
    #[test]
    fn the_finding_tags_are_bounded_and_named_once() -> Result<(), TestError> {
        let failed = dialog_with(&[response(486, "Busy Here")?])?;
        let also_failed = dialog_with(&[response(486, "Busy Here")?])?;
        assert_eq!(
            finding_tags(&[&failed, &also_failed], MAX_FINDING_TAGS),
            vec!["finding:final_failure".to_string()]
        );
        assert!(finding_tags(&[&failed], 0).is_empty());
        let clean = answered_and_ended()?;
        assert!(finding_tags(&[&clean], MAX_FINDING_TAGS).is_empty());
        Ok(())
    }

    // ── CC extension Dialog parameters ──

    /// GAP-25: a rule's header mapping fills `campaign`, `skill` and
    /// `interaction_id` on the signaling object
    /// ([draft-ietf-vcon-cc-extension-02 section 3.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-cc-extension-02#section-3.2))
    /// from the first message carrying each header, matched without regard
    /// to case; a header with no value leaves its field absent.
    #[test]
    fn the_cc_headers_fill_campaign_skill_and_interaction_id() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![
            (
                invite_carrying(&[
                    "X-Campaign: spring-renewals",
                    "x-queue: billing",
                    "X-Interaction-ID:",
                ])?,
                0,
            ),
            (response(200, "OK")?, 1),
        ])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_cc_fields(
            &mut v,
            &dialog,
            CcHeaders {
                campaign: Some("X-Campaign"),
                skill: Some("X-Queue"),
                interaction_id: Some("X-Interaction-ID"),
            },
        );
        let json = valid_json(&v)?;
        assert_eq!(json["dialog"][0]["campaign"], "spring-renewals");
        assert_eq!(json["dialog"][0]["skill"], "billing");
        assert!(json["dialog"][0].get("interaction_id").is_none());
        assert!(
            json["dialog"][0].get("interaction").is_none(),
            "the spec's name only"
        );
        Ok(())
    }

    /// GAP-25: no mapping writes nothing.
    #[test]
    fn no_cc_mapping_writes_no_cc_field() -> Result<(), TestError> {
        let dialog = timed_dialog(vec![(invite_carrying(&["X-Campaign: c"])?, 0)])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_cc_fields(&mut v, &dialog, CcHeaders::default());
        let json = valid_json(&v)?;
        for field in ["campaign", "skill", "interaction_id"] {
            assert!(json["dialog"][0].get(field).is_none(), "{field}");
        }
        Ok(())
    }

    /// GAP-25: under redaction `interaction_id` becomes a token, so two
    /// containers of one interaction still join, and `campaign` and `skill`
    /// are swept as text.
    #[test]
    fn redaction_tokenizes_the_interaction_id() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let dialog = timed_dialog(vec![(
            invite_carrying(&["X-Interaction-ID: 4155550100-77"])?,
            0,
        )])?;
        let mut v = export_with(&dialog, &clean_facts())?;
        add_cc_fields(
            &mut v,
            &dialog,
            CcHeaders {
                interaction_id: Some("X-Interaction-ID"),
                ..CcHeaders::default()
            },
        );
        let policy = RedactionPolicy::new(RedactionKey::from_secret(
            crate::test_material::key_bytes("cc"),
        ));
        v.redact(&policy.redactor());
        let id = v.dialog[0]
            .interaction_id
            .as_deref()
            .ok_or("an interaction_id")?;
        assert_ne!(id, "4155550100-77");
        assert_eq!(id, policy.redactor().opaque("4155550100-77"));
        Ok(())
    }
}
