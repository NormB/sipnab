// SPDX-License-Identifier: MIT OR Apache-2.0

//! Media inside an OBSERVER vCon: what travels, what is refused, and what the
//! container says when nothing does.
//!
//! `docs/design/vcon.md` §4b decides all three, and the decision is easy to get
//! backwards because two vocabularies collide on one word. `dialog.type:
//! "recording"` is a FORMAT term for a Dialog Object carrying media; a
//! consumer's `recordings` table is a PROVENANCE term for containers from an
//! in-path recorder. sipnab emits the first and is never the second — its own
//! audio export stamps every file with "not a recording made by the endpoints".
//!
//! Three properties are gated here, and each has a failure case beside its
//! success case, because every one of them passes vacuously in one direction:
//!
//! 1. **The media is the media.** A `content_hash` that verifies against the
//!    body, over the WAV rather than over its base64url text, so the digest
//!    means the same thing as `sha512sum` on the file an operator exported.
//! 2. **The refusal is visible.** Above the budget nothing is inlined AND the
//!    container says so. A container that quietly dropped the audio is the §3
//!    failure the whole feature is built against: absence reading as "this call
//!    had no media", which is a claim about the CALL.
//! 3. **The two clocks stay apart.** A `recording` carries the FILE's duration.
//!    Only when a payload ring wrapped does a `recording-set` appear carrying
//!    the CALL's — §4.3.3 is the format's one way to say the file is a fragment
//!    — and asserting the two DIFFER is the half that discriminates.
#![cfg(feature = "vcon")]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use chrono::{DateTime, TimeDelta, Utc};
use sipnab::analysis::CaptureFacts;
use sipnab::net::TransportProto;
use sipnab::output::vcon::{
    ExportContext, ExportedDialog, MAX_INLINE_MEDIA_BYTES, MediaOutcome, ObservedAudio, Omission,
    RECORDING_MEDIATYPE, RECORDING_SET_TYPE, RECORDING_TYPE, Vcon, export_dialog_and_completeness,
    export_dialog_with_audio,
};
use sipnab::rtp::audio_export::{DialogAudio, decode_dialog_audio};
use sipnab::rtp::parser::RtpHeader;
use sipnab::rtp::stream::{RtpStream, StreamKey};
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::parser::parse_sip;

// ── Fixtures ─────────────────────────────────────────────────────────

/// The capture clock every fixture is stamped from.
fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_780_000_000, 0).expect("a valid capture clock")
}

/// A socket, spelled compactly.
fn sock(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

/// An SDP body offering G.711 from one address and port.
fn sdp(addr: &str, port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {addr}\r\ns=-\r\nc=IN IP4 {addr}\r\n\
         t=0 0\r\nm=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
    )
}

/// Parse one SIP message with a body, computing its `Content-Length` so the
/// parser sees the SDP the fixture meant to send.
fn message(first_line: &str, headers: &[String], body: &str) -> Vec<u8> {
    let mut raw = format!("{first_line}\r\n");
    for h in headers {
        raw.push_str(h);
        raw.push_str("\r\n");
    }
    if body.is_empty() {
        raw.push_str("Content-Length: 0\r\n\r\n");
    } else {
        raw.push_str("Content-Type: application/sdp\r\n");
        raw.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        raw.push_str(body);
    }
    raw.into_bytes()
}

/// A two-party dialog whose caller and callee each advertise a media endpoint.
///
/// Returned as the STORE because `SipDialog` is deliberately not `Clone`: it
/// owns every retained message, so a borrow is the only way out that does not
/// copy a ladder.
fn dialog_store(call_id: &str, caller_media: SocketAddr, callee_media: SocketAddr) -> DialogStore {
    let mut store = DialogStore::new(64, true);
    let caller = sock(10, 0, 0, 1, 5060);
    let callee = sock(10, 0, 0, 2, 5060);

    let invite = message(
        "INVITE sip:bob@example.net SIP/2.0",
        &[
            "From: \"Alice\" <sip:alice@example.com>;tag=alice-tag".to_string(),
            "To: \"Bob\" <sip:bob@example.net>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Contact: <sip:alice@10.0.0.1:5060>".to_string(),
        ],
        &sdp(&caller_media.ip().to_string(), caller_media.port()),
    );
    store.process_message(
        parse_sip(
            &invite,
            t0(),
            caller.ip(),
            callee.ip(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("the INVITE fixture parses"),
    );

    let ok = message(
        "SIP/2.0 200 OK",
        &[
            "From: \"Alice\" <sip:alice@example.com>;tag=alice-tag".to_string(),
            "To: \"Bob\" <sip:bob@example.net>;tag=bob-tag".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Contact: <sip:bob@10.0.0.2:5060>".to_string(),
        ],
        &sdp(&callee_media.ip().to_string(), callee_media.port()),
    );
    store.process_message(
        parse_sip(
            &ok,
            t0() + TimeDelta::milliseconds(1200),
            callee.ip(),
            caller.ip(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("the 200 OK fixture parses"),
    );
    store
}

/// A stream with retained payload, a wall-clock window, and a drop count.
fn stream(
    src: SocketAddr,
    dst: SocketAddr,
    ssrc: u32,
    frames: usize,
    fill: u8,
    dropped: u64,
    span: TimeDelta,
) -> RtpStream {
    let key = StreamKey { ssrc, src, dst };
    let hdr = RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 0,
        sequence: 1,
        timestamp: 0,
        ssrc,
        payload_offset: 12,
    };
    let mut s = RtpStream::new(key, &hdr, t0());
    s.codec = Some("PCMU".to_string());
    s.clock_rate = 8000;
    s.payload_buffer = (0..frames)
        .map(|i| (u32::try_from(i).unwrap_or(0) * 160, vec![fill; 160]))
        .collect::<VecDeque<_>>();
    s.payload_frames_dropped = dropped;
    s.packet_count = frames as u64 + dropped;
    s.first_seen = t0();
    s.last_seen = t0() + span;
    s
}

/// Export one dialog with the audio decoded from its streams.
fn export(store: &DialogStore, call_id: &str, streams: &[&RtpStream]) -> (Vcon, DialogAudio) {
    export_within(store, call_id, streams, None)
}

/// The same export, under a stated inline-media budget.
fn export_within(
    store: &DialogStore,
    call_id: &str,
    streams: &[&RtpStream],
    budget: Option<usize>,
) -> (Vcon, DialogAudio) {
    let audio = decode_dialog_audio(streams).expect("the fixture streams decode");
    let dialog = store
        .get(call_id)
        .expect("the fixture dialog is in the store");
    let facts = CaptureFacts::default();
    let vcon = export_dialog_with_audio(
        dialog,
        &ExportContext {
            capture_id: "vcon-media-fixture.pcap",
            facts: &facts,
            max_inline_media_bytes: budget,
            analysis: None,
        },
        ObservedAudio::Decoded(&audio),
    );
    (vcon, audio)
}

/// The same export again, reporting the completeness carrier beside the
/// container.
///
/// The carrier is inside the container as JSON TEXT, so reading a field off it
/// means parsing a string out of a document. The rows RV7 is about are read
/// from the value itself.
fn export_reporting_within(
    store: &DialogStore,
    call_id: &str,
    streams: &[&RtpStream],
    budget: Option<usize>,
) -> (ExportedDialog, DialogAudio) {
    let audio = decode_dialog_audio(streams).expect("the fixture streams decode");
    let dialog = store
        .get(call_id)
        .expect("the fixture dialog is in the store");
    let facts = CaptureFacts::default();
    let exported = export_dialog_and_completeness(
        dialog,
        &ExportContext {
            capture_id: "vcon-media-fixture.pcap",
            facts: &facts,
            max_inline_media_bytes: budget,
            analysis: None,
        },
        ObservedAudio::Decoded(&audio),
        Utc::now(),
    );
    (exported, audio)
}

/// The container as JSON, which is what actually crosses the wire.
fn json_of(vcon: &Vcon) -> serde_json::Value {
    serde_json::from_str(&vcon.to_json().expect("a container serializes"))
        .expect("the container is valid JSON")
}

/// Is any audio actually inlined in this container?
///
/// The question the absence tests are asking, and it stopped being answerable
/// by looking for a Dialog Object of type `recording`. The schema requires
/// every Dialog Object to carry a `type` from a closed enum, none of which
/// means "signaling only" -- so the signaling object spends `recording` on
/// itself and a type check can no longer distinguish "audio traveled" from
/// "a call was observed". What distinguishes them is the BODY: media inlined,
/// or no media at all.
fn carries_audio(json: &serde_json::Value) -> bool {
    json["dialog"]
        .as_array()
        .expect("dialog is an array")
        .iter()
        .any(|d| d.get("body").is_some() && d.get("content_hash").is_some())
}

/// The one Dialog Object of the given `type`, or `None`.
fn dialog_of<'a>(json: &'a serde_json::Value, kind: &str) -> Option<&'a serde_json::Value> {
    json["dialog"]
        .as_array()
        .expect("dialog is an array")
        .iter()
        .find(|d| d["type"] == kind)
}

/// The completeness caveat, which is embedded identically in the analysis body
/// and in the attachment.
fn completeness(json: &serde_json::Value) -> serde_json::Value {
    // Owned, not borrowed: §2.3.2 makes `body` a STRING, so reading it means
    // parsing it, and the parsed value is a temporary this function creates.
    body_of(&json["analysis"][0])["capture_completeness"].clone()
}

// ── The media travels, and the hash proves it is the media ───────────

/// Decoded audio becomes a `recording` whose hash verifies and whose duration
/// is the FILE's.
///
/// Three assertions that fail independently. The hash is over the DECODED body
/// rather than over its base64url text, so an operator holding the `.wav`
/// exported beside this container can reproduce it with `sha512sum` — a digest
/// of the encoded text is a number nothing outside the container could ever
/// recompute.
///
/// The duration is the third, and it is the one this repository has already got
/// wrong once in the audio exporter: a ten-minute call whose ring kept thirty
/// seconds exports as "30.0s", byte-identical to a genuinely thirty-second
/// call. `TimingSummary::duration_ms` is the CALL's and must never land here.
#[test]
fn decoded_audio_becomes_a_recording_whose_hash_verifies_against_its_body() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha512};

    let store = dialog_store(
        "hash@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    let a = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        50,
        0xFF,
        0,
        TimeDelta::seconds(1),
    );
    let (vcon, audio) = export(&store, "hash@example.com", &[&a]);
    let json = json_of(&vcon);

    let recording =
        dialog_of(&json, RECORDING_TYPE).expect("audio must produce a recording object");
    assert_eq!(
        recording["mediatype"], RECORDING_MEDIATYPE,
        "a consumer decides how to open the body from this: {recording}"
    );
    assert_eq!(
        recording["encoding"], "base64url",
        "the body is base64url and must say so: {recording}"
    );
    assert!(
        recording.get("url").is_none(),
        "sipnab hosts nothing, so a url here points at something that does not \
         exist: {recording}"
    );

    // The hash verifies against the body, which is the whole point of carrying
    // one. Decode, digest, compare -- not "the field is a string".
    let body = recording["body"].as_str().expect("body is a string");
    let decoded = URL_SAFE_NO_PAD
        .decode(body)
        .expect("the body must decode as unpadded base64url");
    assert_eq!(
        decoded, audio.wav,
        "the inlined body is not the WAV that was decoded"
    );
    let expected = format!(
        "sha512-{}",
        URL_SAFE_NO_PAD.encode(Sha512::digest(&decoded))
    );
    assert_eq!(
        recording["content_hash"], expected,
        "content_hash must be sha512- plus the base64url SHA-512 of the DECODED \
         body, so sha512sum on the exported .wav reproduces it"
    );

    // The FILE's duration. 50 frames of 160 mu-law samples at 8 kHz is one
    // second of audio, and the call fixture is longer than that.
    let duration = recording["duration"]
        .as_f64()
        .expect("duration is a number");
    assert!(
        (duration - 1.0).abs() < 0.001,
        "duration must be the file's {} decoded seconds, got {duration}",
        audio.duration_secs
    );

    // The container names what it is carrying, so an empty `dialog[]` never has
    // to be interpreted.
    assert_eq!(
        completeness(&json)["media"],
        MediaOutcome::Carried.as_str(),
        "the caveat must say media is carried: {}",
        completeness(&json)
    );
    assert!(
        completeness(&json)["media_note"]
            .as_str()
            .unwrap_or_default()
            .contains("not a recording made by the endpoints"),
        "the note that travels with the audio must carry the disclaimer the WAV \
         carries: {}",
        completeness(&json)
    );
}

/// Two different dialogs produce two different `content_hash` values.
///
/// The half that discriminates. An emitter that hashed a constant, the Call-ID,
/// or an empty slice would satisfy every assertion above — the value would
/// still be a well-formed `sha512-` string that "verifies" against a body
/// nobody re-derived. Two captures whose audio differs must not collide, or a
/// consumer deduplicating on the hash discards one of them.
#[test]
fn two_dialogs_with_different_audio_get_different_content_hashes() {
    let first = dialog_store(
        "one@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    let second = dialog_store(
        "two@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    let a = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        50,
        0xFF,
        0,
        TimeDelta::seconds(1),
    );
    // Different payload bytes: same length, different audio.
    let b = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        2,
        50,
        0x2A,
        0,
        TimeDelta::seconds(1),
    );

    let (one, _) = export(&first, "one@example.com", &[&a]);
    let (two, _) = export(&second, "two@example.com", &[&b]);
    let hash_of = |v: &Vcon| {
        dialog_of(&json_of(v), RECORDING_TYPE).expect("a recording object")["content_hash"]
            .as_str()
            .expect("content_hash is a string")
            .to_string()
    };

    let (h1, h2) = (hash_of(&one), hash_of(&two));
    assert_ne!(
        h1, h2,
        "two calls carrying different audio hashed to one value, so the hash \
         identifies nothing: {h1}"
    );
    assert!(
        h1.starts_with("sha512-"),
        "the algorithm must be named in the value, per §2.2: {h1}"
    );
}

// ── The refusal, and that it is visible ──────────────────────────────

/// Audio over the budget is refused, and the container SAYS SO.
///
/// `docs/design/vcon.md` §4a.1 measured a store that answers **204**, writes to
/// Postgres, and drops the payload above 10485760 bytes with nothing reported
/// to the producer. So the refusal has to happen here, and it has to be
/// audible: a container that silently omitted the audio would read as a
/// conversation with no media, which is a claim about the CALL rather than
/// about this run's budget.
#[test]
fn audio_over_the_budget_is_refused_and_the_container_says_so() {
    let store = dialog_store(
        "huge@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    // 13000 frames of 160 mu-law samples is ~4.16 MB of WAV, which base64url
    // inflates past the 5 MiB budget by four thirds.
    let big = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        13_000,
        0xFF,
        0,
        TimeDelta::seconds(260),
    );
    let (vcon, audio) = export(&store, "huge@example.com", &[&big]);
    let json = json_of(&vcon);

    // Not vacuous: the fixture really is over the budget.
    assert!(
        audio.wav.len() * 4 / 3 > MAX_INLINE_MEDIA_BYTES,
        "the fixture is {} WAV bytes, which does not exceed the budget once \
         encoded -- the assertions below would pass for the wrong reason",
        audio.wav.len()
    );

    assert!(
        !carries_audio(&json),
        "audio over the budget must not be inlined: {json}"
    );
    assert_eq!(
        completeness(&json)["media"],
        MediaOutcome::RefusedOverBudget.as_str(),
        "the refusal must be a token a consumer can branch on: {}",
        completeness(&json)
    );

    let c = completeness(&json);
    let note = c["note"].as_str().expect("the caveat is a string");
    assert!(
        note.contains("REFUSED"),
        "the prose caveat must name the refusal, not only the token: {note}"
    );
    assert!(
        note.contains(&MAX_INLINE_MEDIA_BYTES.to_string()),
        "the caveat must name the budget the audio failed, or an operator \
         cannot tell whether re-running would help: {note}"
    );
    assert!(
        !note.contains("No omissions recorded"),
        "a container that refused the audio must not also claim completeness: \
         {note}"
    );
    // The container must never suggest the media is somewhere else. §2.5: a
    // dead link inside a record is indistinguishable from removed evidence.
    assert!(
        json.to_string().find("\"url\"").is_none(),
        "no url may appear anywhere in the container"
    );
}

/// A run that decoded nothing produces no `recording` and says why.
///
/// The dangerous case §3 names. An empty `dialog[]` reads as a conversation
/// with no media; the truth is a statement about what this run KEPT. The
/// explanation is `nothing_to_decode`'s own, which reports the measurement and
/// never claims the call was silent.
#[test]
fn a_dialog_with_no_exportable_audio_carries_no_recording_and_explains_itself() {
    let store = dialog_store(
        "silent@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    // Packets measured, payload never retained: the state every batch-mode run
    // is in.
    let mut kept_nothing = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        0,
        0,
        0,
        TimeDelta::seconds(60),
    );
    kept_nothing.packet_count = 3000;

    let reason = decode_dialog_audio(&[&kept_nothing])
        .expect_err("nothing was retained, so the decode must fail")
        .to_string();
    let dialog = store
        .get("silent@example.com")
        .expect("dialog is in the store");
    let facts = CaptureFacts::default();
    let vcon = export_dialog_with_audio(
        dialog,
        &ExportContext {
            capture_id: "vcon-media-fixture.pcap",
            facts: &facts,
            max_inline_media_bytes: None,
            analysis: None,
        },
        ObservedAudio::NothingToDecode(&reason),
    );
    let json = json_of(&vcon);

    assert!(
        !carries_audio(&json),
        "nothing was decoded, so nothing may be inlined: {json}"
    );
    assert_eq!(
        completeness(&json)["media"],
        MediaOutcome::NoneDecodable.as_str(),
        "the container must distinguish 'kept none' from 'nobody looked': {}",
        completeness(&json)
    );
    let c = completeness(&json);
    let media_note = c["media_note"]
        .as_str()
        .expect("the reason travels with the container");
    assert!(
        media_note.contains("3000") && media_note.contains("PCMU"),
        "the container must report what sipnab MEASURED: {media_note}"
    );
    assert!(
        media_note.contains("not a finding that the call was silent"),
        "the container must carry the disclaimer, or absence reads as a silent \
         call: {media_note}"
    );

    // And a signaling-only export is a THIRD answer, not the same one.
    let signaling = sipnab::output::vcon::export_dialog(
        dialog,
        &ExportContext {
            capture_id: "vcon-media-fixture.pcap",
            facts: &facts,
            max_inline_media_bytes: None,
            analysis: None,
        },
    );
    assert_eq!(
        completeness(&json_of(&signaling))["media"],
        MediaOutcome::NotConsidered.as_str(),
        "'nobody asked for media' and 'this run kept none' must not collapse \
         into one answer"
    );
}

// ── The two clocks ───────────────────────────────────────────────────

/// A wrapped ring produces a `recording-set` whose duration is NOT the file's.
///
/// §4.3.3 is the only place vCon can say "this file is a fragment of that
/// call": the set carries the call's clock while the recording beneath it
/// carries the file's. Asserting they DIFFER is the discriminating half —
/// equal values prove nothing, and an emitter that copied the file's duration
/// into both would pass a mere presence check while saying the ring never
/// wrapped.
#[test]
fn a_wrapped_ring_wraps_the_recording_in_a_set_carrying_the_calls_clock() {
    let store = dialog_store(
        "wrapped@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    // Five minutes of media observed, two frames retained: the file holds the
    // END of the stream and 4200 earlier frames are gone.
    let wrapped = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        2,
        0xFF,
        4200,
        TimeDelta::seconds(300),
    );
    let (vcon, audio) = export(&store, "wrapped@example.com", &[&wrapped]);
    let json = json_of(&vcon);

    let set =
        dialog_of(&json, RECORDING_SET_TYPE).expect("a wrapped ring must produce a recording-set");
    let recording = dialog_of(&json, RECORDING_TYPE).expect("a recording object");

    let set_duration = set["duration"].as_f64().expect("set duration is a number");
    let file_duration = recording["duration"]
        .as_f64()
        .expect("recording duration is a number");
    assert!(
        (set_duration - 300.0).abs() < 0.5,
        "the set must carry the CALL's five-minute media window, got \
         {set_duration}"
    );
    assert!(
        (file_duration - audio.duration_secs).abs() < 0.001,
        "the recording must carry the FILE's duration, got {file_duration}"
    );
    assert!(
        set_duration > file_duration * 100.0,
        "the two clocks must DIFFER, or the container says the file is the whole \
         call: set={set_duration} file={file_duration}"
    );

    // The set points at the recording, and the index must resolve.
    let member = set["recordings"][0]
        .as_u64()
        .expect("the set names its member by index");
    let objects = json["dialog"].as_array().expect("dialog is an array");
    assert_eq!(
        objects
            .get(usize::try_from(member).expect("index fits"))
            .map(|d| &d["type"]),
        Some(&serde_json::json!(RECORDING_TYPE)),
        "the set's member index points at something that is not the recording: \
         {json}"
    );

    // The starts differ too: the file begins after the ring dropped its way
    // through five minutes of call.
    assert_ne!(
        set["start"], recording["start"],
        "a file that begins where the call began is not a wrapped ring"
    );
}

/// A ring that never wrapped produces NO `recording-set`.
///
/// The failure case for the test above, and the reason the wrapper is
/// conditional. An unnecessary wrapper on every container trains a reader to
/// skip the one that carries information, which costs exactly the case §4b
/// added it for.
#[test]
fn an_intact_ring_adds_no_recording_set() {
    let store = dialog_store(
        "intact@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    let intact = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        50,
        0xFF,
        0,
        TimeDelta::seconds(1),
    );
    let (vcon, _) = export(&store, "intact@example.com", &[&intact]);
    let json = json_of(&vcon);

    assert!(
        carries_audio(&json),
        "the audio must still be carried: {json}"
    );
    assert!(
        dialog_of(&json, RECORDING_SET_TYPE).is_none(),
        "nothing was dropped, so there is no call/file discrepancy to wrap: \
         {json}"
    );
    assert_eq!(
        json["dialog"].as_array().map(Vec::len),
        Some(1),
        "one exchange is ONE Dialog Object. The audio enriches the object the \
         container already had rather than adding a second `recording` beside \
         it, because two objects of that type for one call give a consumer no \
         field saying which is real: {json}"
    );
}

// ── Party attribution ────────────────────────────────────────────────

/// Channels attribute to parties only from a party's OWN advertised endpoint.
///
/// A party index is load-bearing: `analysis.dialog`, `attachment.party` and
/// `originator` all index `parties[]`, so a wrong one corrupts every
/// cross-reference in the container silently, in a way that reads as data
/// rather than as an error.
#[test]
fn a_channel_names_the_party_whose_advertised_socket_it_came_from() {
    let store = dialog_store(
        "attributed@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    let from_alice = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        50,
        0xFF,
        0,
        TimeDelta::seconds(1),
    );
    let from_bob = stream(
        sock(10, 0, 0, 2, 30000),
        sock(10, 0, 0, 1, 20000),
        2,
        50,
        0xD5,
        0,
        TimeDelta::seconds(1),
    );
    let (vcon, _) = export(&store, "attributed@example.com", &[&from_alice, &from_bob]);
    let json = json_of(&vcon);
    let recording = dialog_of(&json, RECORDING_TYPE).expect("a recording object");

    assert_eq!(
        recording["parties"],
        serde_json::json!([0, 1]),
        "channel 0 carries the caller's media and channel 1 the callee's, from \
         the endpoints each of them advertised: {recording}"
    );
    // Not vacuous: those indices must resolve to the observed parties, not to
    // the sipnab observer.
    let parties = json["parties"].as_array().expect("parties is an array");
    assert_eq!(
        parties[0]["sip"], "sip:alice@example.com",
        "index 0 must be the caller: {json}"
    );
    assert_eq!(
        parties[1]["sip"], "sip:bob@example.net",
        "index 1 must be the callee: {json}"
    );
}

/// Media arriving from a socket no party advertised gets NO `parties`.
///
/// The failure case, and the common one in the field: a relay in the media path
/// sends from its own allocation, which is neither party's. §4.3.4's null
/// placeholder means "no party on this channel", not "sipnab could not tell",
/// so it must not be borrowed for the second — and a plausible guess is exactly
/// what corrupts a cross-reference in a way nobody can see.
#[test]
fn media_from_an_unadvertised_socket_names_no_party_at_all() {
    let store = dialog_store(
        "relayed@example.com",
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
    );
    // A media relay's own allocation: nobody advertised it in SDP.
    let relayed = stream(
        sock(192, 0, 2, 9, 40000),
        sock(10, 0, 0, 1, 20000),
        7,
        50,
        0xFF,
        0,
        TimeDelta::seconds(1),
    );
    let (vcon, _) = export(&store, "relayed@example.com", &[&relayed]);
    let json = json_of(&vcon);
    let recording = dialog_of(&json, RECORDING_TYPE).expect("the audio is still carried");

    assert!(
        recording.get("parties").is_none(),
        "sipnab cannot attribute a relay's socket to either party and must say \
         nothing rather than guess: {recording}"
    );
    // The audio still travels: an unattributable channel is not a reason to
    // drop it.
    assert!(
        recording["body"].as_str().is_some_and(|b| !b.is_empty()),
        "the media must still be carried: {recording}"
    );
}

/// A `json`-encoded body, parsed.
///
/// §2.3.2 makes `body` a STRING, so every read of one goes through here rather
/// than indexing a `Value` that is not an object. The conserver's own model
/// says the same in a comment: a caller handing it a dict gets it JSON-encoded
/// before anything else touches the attachment.
fn body_of(node: &serde_json::Value) -> serde_json::Value {
    let text = node["body"]
        .as_str()
        .unwrap_or_else(|| panic!("a json body must be a string: {node}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("body must parse: {e}: {text}"))
}

// ── Conformance: the schema gate, on the containers that carry media ────────
//
// The signaling-only container was the only one ever validated against the
// working group's schema, which is how `dialogs` survived: §4.3.6 names the
// field `recordings`, and the schema leaves `additionalProperties` open, so a
// wrong name is not a validation error anywhere. These four run the validator
// over the MEDIA paths and assert, by hand, the two rules the open schema
// cannot enforce.

mod support;

/// One media container, built the way the tests above build theirs.
///
/// `wrapped` chooses the ring case: an intact ring retains everything sipnab
/// saw, a wrapped one retains only the tail of a five-minute window, which is
/// what produces the `recording-set`.
fn media_container(wrapped: bool) -> serde_json::Value {
    let call_id = if wrapped {
        "wrapped@example.com"
    } else {
        "intact@example.com"
    };
    let store = dialog_store(call_id, sock(10, 0, 0, 1, 20000), sock(10, 0, 0, 2, 30000));
    let (dropped, span) = if wrapped {
        (4200, TimeDelta::seconds(300))
    } else {
        (0, TimeDelta::seconds(0))
    };
    let s = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        2,
        0xFF,
        dropped,
        span,
    );
    let (vcon, _audio) = export(&store, call_id, &[&s]);
    json_of(&vcon)
}

/// Every media container validates against the working group's own schema.
#[test]
fn a_media_container_validates_against_the_working_group_schema() {
    let validator = support::schema::load_validator("vcon.schema.json");
    for (label, wrapped) in [("intact ring", false), ("wrapped ring", true)] {
        let json = media_container(wrapped);
        if let Err(e) = validator.validate(&json) {
            panic!("the {label} container does not validate: {e}\n{json:#}");
        }
    }
}

/// §4.3.6: "The recordings parameter MUST be present in recording-set Dialog
/// Objects."
///
/// The schema cannot check this — `recordings` is defined but not conditionally
/// required, and unknown keys are permitted — so the MUST is asserted here.
/// A set that named its members anything else validated cleanly and left a
/// consumer unable to resolve them.
#[test]
fn a_recording_set_names_its_members_with_the_field_the_spec_requires() {
    let json = media_container(true);
    let set = &json["dialog"][0];
    assert_eq!(set["type"], RECORDING_SET_TYPE, "index 0 must be the set");
    assert!(
        set.get("recordings").is_some(),
        "§4.3.6 makes `recordings` a MUST on a recording-set: {set}"
    );
    assert!(
        set.get("dialogs").is_none(),
        "`dialogs` is not a vCon field; a consumer ignores it and the set's \
         members become unresolvable: {set}"
    );
}

/// Audio never rides on an object typed `incomplete`.
///
/// Every consumer that selects media by `type == "recording"` — which is what
/// the conserver's own transcription link does — would skip a Dialog Object
/// carrying a WAV. The audio would be in the container and unreachable.
#[test]
fn audio_never_rides_on_an_object_typed_incomplete() {
    for wrapped in [false, true] {
        let json = media_container(wrapped);
        for object in json["dialog"].as_array().expect("dialog is an array") {
            if object.get("body").is_some() {
                assert_eq!(
                    object["type"], RECORDING_TYPE,
                    "this object carries audio and is typed {}, which every \
                     `type == \"recording\"` selector skips: {object}",
                    object["type"]
                );
                assert!(
                    object.get("disposition").is_none(),
                    "`disposition` is an `incomplete` field and this object \
                     carries audio: {object}"
                );
            }
        }
    }
}

/// The same "absent, never null" contract, across the MEDIA shapes.
///
/// Kept beside the signaling-only case rather than folded into it, for the
/// reason the schema gate above exists: the media objects carry a different set
/// of optional fields, and the signaling-only container never populates them.
#[test]
fn no_media_container_emits_an_explicit_null() {
    for (label, wrapped) in [("intact ring", false), ("wrapped ring", true)] {
        let json = media_container(wrapped);
        let nulls = support::schema::null_paths(&json);
        assert!(
            nulls.is_empty(),
            "{label}: these fields serialized as an explicit `null` rather \
             than being omitted: {nulls:?}"
        );
        let objects = json["dialog"].as_array().expect("dialog is an array");
        assert!(
            objects.iter().any(|o| o.get("body").is_some()),
            "{label}: no object carried audio, so this walk never reached the \
             media fields it exists to check: {json}"
        );
    }
}

/// A media object still names `recording` now that `type` became optional.
///
/// `type` was dropped from the signaling-only object because no value of it
/// was true there. That reasoning stops exactly where content begins: an
/// object carrying a WAV must say so, because every consumer that wants audio
/// selects on `type == "recording"` and an untyped object is one they skip
/// with the audio still inside it. The two changes share a code path, so the
/// correctness of the first is only safe while this holds.
#[test]
fn a_media_object_still_names_recording_after_type_became_optional() {
    for (label, wrapped, expected) in [
        ("intact ring", false, RECORDING_TYPE),
        ("wrapped ring", true, RECORDING_SET_TYPE),
    ] {
        let json = media_container(wrapped);
        let object = &json["dialog"][0];
        assert!(
            carries_audio(&json),
            "premise: the {label} container must actually carry audio, or \
             this asserts a type on an object with nothing to reach: {object}"
        );
        assert_eq!(
            object["type"], expected,
            "the {label} object holds content and must name it; an untyped \
             object is skipped by every `type == \"recording\"` selector and \
             the audio becomes unreachable: {object}"
        );
        assert!(
            object.get("disposition").is_none(),
            "content and a setup failure are mutually exclusive claims: \
             {object}"
        );
    }
}

/// PV9: the inline-media ceiling is an operator's number with a measured
/// default.
///
/// The 5 MiB default is measured against one store that answers HTTP 204 and
/// then drops the payload in its file spool, telling the producer nothing. It
/// stays the default for exactly that reason. But the number is a property of
/// a CONSUMER rather than of the format, and that consumer publishes no
/// per-container cap -- an operator writing to a spool they control should not
/// inherit a limit measured somewhere else.
#[test]
fn the_inline_media_budget_is_an_operator_setting() {
    let call_id = "intact@example.com";
    let store = dialog_store(call_id, sock(10, 0, 0, 1, 20000), sock(10, 0, 0, 2, 30000));
    let s = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        2,
        0xFF,
        0,
        TimeDelta::seconds(0),
    );

    // Unset: the measured default carries this fixture.
    let (default_vcon, _) = export_within(&store, call_id, &[&s], None);
    assert!(
        carries_audio(&json_of(&default_vcon)),
        "premise: the fixture must fit under the default, or the refusal \
         below proves nothing about the budget"
    );

    // A budget below what this WAV encodes to refuses it.
    let (tight_vcon, audio) = export_within(&store, call_id, &[&s], Some(8));
    let tight = json_of(&tight_vcon);
    assert!(
        !carries_audio(&tight),
        "a lowered budget must actually refuse: {}",
        tight["dialog"]
    );

    // And the refusal names the budget that was ENFORCED. Quoting the
    // compiled-in default while enforcing something else would send an
    // operator looking for a limit nothing applied.
    let note = completeness(&tight)["note"]
        .as_str()
        .expect("a completeness note")
        .to_string();
    assert!(
        note.contains("8 byte budget"),
        "the refusal must quote the enforced budget: {note}"
    );
    assert!(
        note.contains(&audio.wav.len().to_string()),
        "the refusal must name the size that was refused, so an operator can \
         choose a number: {note}"
    );

    // Zero is a legitimate setting: "never inline media", said once, with the
    // refusal still visible rather than passing as a call that had no audio.
    let (zero_vcon, _) = export_within(&store, call_id, &[&s], Some(0));
    let zero = json_of(&zero_vcon);
    assert!(
        !carries_audio(&zero),
        "a zero budget must inline nothing: {}",
        zero["dialog"]
    );
    assert!(
        completeness(&zero)["media"] != "none-decodable",
        "a refused body must not report as undecodable audio -- that is a \
         claim about the CALL: {}",
        completeness(&zero)
    );
}

/// A raised budget carries audio the default would have refused.
///
/// RV7: a refused recording is an omission ROW, not only a sentence.
///
/// The container an agent gets back has an empty-looking `dialog[]` and a
/// caveat buried in an attachment body that is a JSON string. Every surface
/// above this one has to be able to say "the audio exists and is not here"
/// without parsing prose, and the row is what makes that possible.
///
/// Paired with the clause count in the same assertion, for the reason
/// `an_omission_row_exists_for_every_incomplete_clause` gives: checking one
/// half of a fact written twice certifies half a fix.
#[test]
fn a_refused_recording_is_an_omission_row_beside_the_clause() {
    let call_id = "intact@example.com";
    let store = dialog_store(call_id, sock(10, 0, 0, 1, 20000), sock(10, 0, 0, 2, 30000));
    let s = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        2,
        0xFF,
        0,
        TimeDelta::seconds(0),
    );

    // Carried first, so the row below is the refusal talking and not a row
    // this export emits for every container.
    let (carried, _) = export_reporting_within(&store, call_id, &[&s], None);
    assert_eq!(
        carried.completeness.media,
        MediaOutcome::Carried,
        "premise: the fixture must fit under the default, or the contrast          below is between two refusals"
    );
    assert!(
        carried.completeness.omissions().is_empty(),
        "a container that carries its audio omitted nothing: {:?}",
        carried.completeness.omissions()
    );
    assert!(
        carried.completeness.complete(),
        "and says so: {}",
        carried.completeness.note
    );

    let (refused, _) = export_reporting_within(&store, call_id, &[&s], Some(0));
    assert_eq!(
        refused.completeness.media,
        MediaOutcome::RefusedOverBudget,
        "premise: a zero budget refuses every body"
    );
    assert_eq!(
        refused.completeness.omissions(),
        vec![Omission {
            kind: "media_refused_over_budget",
            count: 1,
            unit: "recording",
        }],
        "the refusal must reach the rows: {}",
        refused.completeness.note
    );
    assert_eq!(
        refused.completeness.note.matches("— INCOMPLETE:").count(),
        1,
        "and the prose and the rows must describe one set: {}",
        refused.completeness.note
    );
    assert!(
        !refused.completeness.complete(),
        "a container missing its audio is not complete: {}",
        refused.completeness.note
    );
}

/// The other direction of the same setting, and the one that makes it worth
/// having: without this, "configurable" could mean a knob that only ever
/// tightens.
#[test]
fn a_raised_budget_carries_what_the_default_would_refuse() {
    let call_id = "intact@example.com";
    let store = dialog_store(call_id, sock(10, 0, 0, 1, 20000), sock(10, 0, 0, 2, 30000));
    let s = stream(
        sock(10, 0, 0, 1, 20000),
        sock(10, 0, 0, 2, 30000),
        1,
        2,
        0xFF,
        0,
        TimeDelta::seconds(0),
    );

    // A budget of one byte under what this body needs refuses it; one byte
    // over carries it. Deriving both from the measured body rather than from
    // a guessed constant is what keeps this from silently going vacuous when
    // the fixture changes size.
    let (_, audio) = export_within(&store, call_id, &[&s], None);
    let encoded = audio.wav.len().div_ceil(3) * 4;

    let (refused, _) = export_within(&store, call_id, &[&s], Some(encoded / 2));
    assert!(
        !carries_audio(&json_of(&refused)),
        "premise: half the encoded size must be under budget"
    );

    let (carried, _) = export_within(&store, call_id, &[&s], Some(encoded * 2));
    assert!(
        carries_audio(&json_of(&carried)),
        "twice the encoded size must carry it: {}",
        json_of(&carried)["dialog"]
    );
}
