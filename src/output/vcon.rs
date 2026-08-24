// SPDX-License-Identifier: MIT OR Apache-2.0

//! vCon export — one observed dialog as an unsigned, signaling-only vCon
//! container ([`draft-ietf-vcon-vcon-core-03`], syntax version `0.4.0`).
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
//! * **No media and no `url` by-reference.** sipnab hosts nothing, so a URL in
//!   this container would point at something that does not exist. Phase 1
//!   carries signaling only.
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

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::analysis::{CaptureAnalysis, CaptureFacts, Severity};
use crate::provenance::node_name;
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
pub const ANALYSIS_PRODUCT: &str = concat!(
    "sipnab ",
    env!("CARGO_PKG_VERSION"),
    " (passive observer; signaling only)"
);

/// `role` of the party representing sipnab itself.
pub const OBSERVER_ROLE: &str = "observer";

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
    /// `"incomplete"` ONLY when a final failure response was observed.
    ///
    /// Never set because sipnab failed to capture the answer. `incomplete` is
    /// a statement about the CALL; "we did not see the rest" is a statement
    /// about the CAPTURE, and the second one travels in
    /// [`CaptureCompleteness`] where it cannot be mistaken for the first.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    /// Why the call did not complete, mapped from the observed final status.
    /// Present exactly when [`Self::kind`] is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<&'static str>,
    /// The `Call-ID` this dialog was tracked under — the one identifier that
    /// ties the container back to a capture an operator still holds.
    pub sip_call_id: String,
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
    /// Always `application/json`.
    pub mediatype: &'static str,
    /// Always `json` — the body is inline JSON, not base64url text.
    pub encoding: &'static str,
    /// The attachment itself.
    pub body: serde_json::Value,
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
    /// The report.
    pub body: serde_json::Value,
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
    let mut parties = observed_parties(dialog);
    parties.push(observer_party());
    // Last entry, computed before the borrow ends so both attachments and any
    // future analysis reference one number.
    let observer = parties.len().saturating_sub(1);

    let completeness = completeness_of(context);
    let dialog_object = dialog_object(dialog);

    let attachments = vec![
        message_trace_attachment(dialog, observer),
        completeness_attachment(&completeness, observer),
    ];

    Vcon {
        vcon: VCON_SYNTAX_VERSION,
        uuid: dialog_uuid(dialog, context.capture_id),
        created_at: exported_at.to_rfc3339(),
        extensions: vec![SIP_SIGNALING_EXTENSION],
        parties,
        dialog: vec![dialog_object],
        attachments,
        analysis: vec![report(dialog, &completeness)],
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

/// The near-empty Dialog Object, plus a disposition when — and only when — the
/// wire carried a final failure.
fn dialog_object(dialog: &SipDialog) -> Dialog {
    let disposition = dialog.final_status_code().and_then(failure_disposition);
    Dialog {
        kind: disposition.map(|_| "incomplete"),
        disposition,
        sip_call_id: dialog.call_id.clone(),
    }
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
fn message_trace_attachment(dialog: &SipDialog, observer: usize) -> Attachment {
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
        mediatype: "application/json",
        encoding: "json",
        body: serde_json::json!({
            "schema_version": DIAGNOSIS_SCHEMA_VERSION,
            "sip_call_id": dialog.call_id,
            "messages": messages,
        }),
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
fn completeness_attachment(completeness: &CaptureCompleteness, observer: usize) -> Attachment {
    Attachment {
        purpose: COMPLETENESS_PURPOSE,
        party: observer,
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
        body,
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

/// Read the completeness of a capture off its facts and its analysis.
fn completeness_of(context: &ExportContext<'_>) -> CaptureCompleteness {
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
        note: completeness_note(facts, blind_spots.as_deref()),
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
fn completeness_note(facts: &CaptureFacts, blind: Option<&[BlindSpot]>) -> String {
    let mut partial = String::new();

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
         established, and nothing here is signed. This container carries SIGNALING ONLY — no \
         media, and no reference to media held elsewhere. sipnab read {} frame(s) for this \
         capture.{verdict}{blind_clause}",
        env!("CARGO_PKG_VERSION"),
        node_name(),
        facts.frames_read,
    )
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
        assert_eq!(v["extensions"], serde_json::json!(["sip-signaling"]));
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
    fn a_signaling_only_dialog_object_is_empty_and_never_incomplete() {
        let dialog = dialog_with(&[response(200, "OK")]);
        let v = serde_json::to_value(export_with(&dialog, &clean_facts())).expect("serializes");
        let object = &v["dialog"][0];

        assert_eq!(object["sip_call_id"], "vcon-fixture@example.com");
        assert!(
            object.get("type").is_none() && object.get("disposition").is_none(),
            "an answered call must not be reported incomplete: {object}"
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
        assert!(
            v["dialog"][0].get("type").is_none(),
            "no final response was observed, so nothing is known about the \
             outcome; `incomplete` would invent one: {}",
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
        let messages = v["attachments"][0]["body"]["messages"]
            .as_array()
            .expect("messages");

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
        assert_eq!(analysis["body"]["final_status_code"], 486);
        assert!(
            analysis["body"]["signaling_diagnosis"].is_object(),
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
            v["attachments"][1]["body"]["note"]
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
        assert_eq!(lossy_vcon["attachments"][1]["body"]["messages_evicted"], 7);
        assert_eq!(clean_vcon["attachments"][1]["body"]["messages_evicted"], 0);
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
        let from_attachment = &v["attachments"][1]["body"];
        let from_report = &v["analysis"][0]["body"]["capture_completeness"];

        assert_eq!(
            from_attachment, from_report,
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
            serde_json::to_value(v).expect("serializes")["attachments"][1]["body"]["note"]
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
            serde_json::to_value(&unchecked).expect("serializes")["attachments"][1]["body"].clone();
        assert!(
            unchecked_body.get("blind_spots").is_none(),
            "no analysis was supplied, so an empty list would claim one ran: \
             {unchecked_body}"
        );
        let checked_body =
            serde_json::to_value(&checked).expect("serializes")["attachments"][1]["body"].clone();
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

        let body = &v["attachments"][1]["body"];
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
