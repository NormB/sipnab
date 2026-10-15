// SPDX-License-Identifier: MIT OR Apache-2.0

//! A SIPREC recording session in a vCon: the recorded call's participants as
//! parties, and each recorded stream tied to the participant that sends it.
//!
//! On a tap beside a Session Recording Server (SRS), sipnab sees the
//! recording session (RS) a Session Recording Client (SRC) opens, not the
//! call being recorded. The RS's SIP `From` and `To` name the SRC and the
//! SRS ([RFC 7866 section 6.1.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-6.1.1):
//! "The SRC and the SRS are identified in the From and To headers,
//! respectively"). The people on the recorded call are named only in the
//! RFC 7865 metadata the SRC sends beside its SDP. This module reads that
//! metadata with the one parser in [`crate::sip::siprec`] and turns it into
//! Party Objects, roles and a stream map.
//!
//! What comes from where:
//!
//! * each `<participant>` becomes one party. `sip` or `tel` comes from the
//!   `aor` of its `<nameID>`, and `name` from the `<name>` inside it
//!   ([RFC 7865 section 6.5.1](https://www.rfc-editor.org/rfc/rfc7865.html#section-6.5.1)).
//!   `validation` is `"none"`, as on every party sipnab writes: the SRC
//!   asserted these, and nobody established them.
//! * the party that sent the metadata gets `role: "recording-client"` and the
//!   other end of the RS gets `role: "recording-server"`. The roles are not
//!   among the values `draft-ietf-vcon-cc-extension` lists, which permits
//!   others, and sipnab already uses that field for `"observer"`.
//! * a stream's owner is the participant whose `<participantstreamassoc>`
//!   lists the stream under `<send>` ([RFC 7865 section 6.8.1](https://www.rfc-editor.org/rfc/rfc7865.html#section-6.8.1)).
//!   The stream's `<label>` names the SDP `a=label` of the m-line that carries
//!   it ([RFC 7865 section 6.7.1](https://www.rfc-editor.org/rfc/rfc7865.html#section-6.7.1)),
//!   and that m-line's address and port are where the SRC sends it from.

use crate::output::vcon::{Attachment, Party};
use crate::rtp::audio_export::DialogAudio;
use crate::sip::dialog::SipDialog;
use crate::sip::siprec::{LabeledStream, SirecMetadata};

/// `role` of the party that sent the recording metadata: the SRC.
pub const RECORDING_CLIENT_ROLE: &str = "recording-client";

/// `role` of the other end of the recording session: the SRS.
pub const RECORDING_SERVER_ROLE: &str = "recording-server";

/// `purpose` of the attachment that maps each recorded stream to the party
/// that sends it.
///
/// Vendor-prefixed for the reason the completeness attachment is: core-04 has
/// no member for it, so a consumer that does not know it skips it.
pub const SIPREC_STREAMS_PURPOSE: &str = "sipnab-siprec-streams";

/// What a dialog is, as far as SIPREC goes.
#[derive(Debug, Clone)]
pub(crate) enum RecordingSession {
    /// Not a recording session.
    NotRecording,
    /// A recording session whose participants sipnab could not read. The
    /// string says why, for the completeness note.
    Unread(&'static str),
    /// A recording session with readable metadata.
    Read(Recorded),
}

/// The metadata of a recording session, and the SDP labels beside it.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    /// Index of the observed party that sent the metadata, 0 or 1, when its
    /// dialog tag says which.
    client: Option<usize>,
    /// The metadata, as [`crate::sip::siprec::parse_siprec_body`] read it.
    metadata: SirecMetadata,
    /// The labeled m-lines of the SDP in the same message.
    labeled: Vec<LabeledStream>,
}

/// One recorded stream, with the party index of whoever sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlacedStream {
    /// The metadata's `<label>`, which the SDP's `a=label` names.
    label: Option<String>,
    /// The metadata's `stream_id`.
    stream_id: Option<String>,
    /// Index into the container's parties of the participant that sends it.
    party: Option<usize>,
}

/// A recording session after its participants joined the party array.
#[derive(Debug, Clone)]
pub(crate) struct Placed {
    /// Every recorded stream, in metadata order.
    streams: Vec<PlacedStream>,
    /// The labeled m-lines of the SDP that carried the metadata.
    labeled: Vec<LabeledStream>,
}

/// Why a recording session with no metadata has no participants.
const NO_METADATA: &str =
    "no rs-metadata part that sipnab could read reached the capture in this dialog";

/// Why a recording session whose metadata parsed has no participants.
const NO_PARTICIPANT: &str =
    "its rs-metadata named no participant, which is what a malformed or truncated XML body gives";

/// Classify `dialog` and read its recording metadata.
///
/// The message used is the newest one whose metadata names a participant,
/// found with [`crate::sip::siprec::metadata_of`], the rule the dialog store
/// keeps its own copy by. The newest with participants rather than the newest
/// at all: RFC 7865 lets a later snapshot be a partial update, and one that
/// restates no participant does not remove the ones a complete snapshot
/// named. Its SDP is read from the same message, because a label's scope is
/// the message it appeared in.
pub(crate) fn recording_session(dialog: &SipDialog) -> RecordingSession {
    let mut carried_metadata = false;
    for msg in dialog.messages.iter().rev() {
        let Some(metadata) = crate::sip::siprec::metadata_of(msg) else {
            continue;
        };
        carried_metadata = true;
        if metadata.participants.is_empty() {
            continue;
        }
        let labeled = msg
            .content_type()
            .map(|ct| crate::sip::siprec::labeled_streams(ct, &msg.body))
            .unwrap_or_default();
        return RecordingSession::Read(Recorded {
            client: crate::output::vcon::sender_party(dialog, msg),
            metadata,
            labeled,
        });
    }
    if carried_metadata {
        RecordingSession::Unread(NO_PARTICIPANT)
    } else if announces_recording(dialog) {
        RecordingSession::Unread(NO_METADATA)
    } else {
        RecordingSession::NotRecording
    }
}

/// Whether the dialog's first message says it opens a recording session.
///
/// [RFC 7866 section 6.1.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-6.1.1):
/// "An SRC MUST include the "siprec" option tag in the Require header when
/// initiating an RS", and "The SRC MUST include the "+sip.src" feature tag in
/// the Contact URI". Either one is enough here, because this only decides
/// whether the completeness note explains missing participants.
fn announces_recording(dialog: &SipDialog) -> bool {
    let Some(first) = dialog.messages.first() else {
        return false;
    };
    let require = first.header("Require").is_some_and(|v| {
        v.split(',')
            .any(|tag| tag.trim().eq_ignore_ascii_case("siprec"))
    });
    let contact = first
        .contact()
        .is_some_and(|c| c.to_ascii_lowercase().contains("+sip.src"));
    require || contact
}

/// The Party Object for one metadata participant.
fn participant_party(p: &crate::sip::siprec::SirecParticipant) -> Party {
    let aor = p.aor.as_deref().map(str::trim);
    let lower = aor.map(str::to_ascii_lowercase).unwrap_or_default();
    let is_sip = lower.starts_with("sip:") || lower.starts_with("sips:");
    let sip = aor.filter(|_| is_sip).map(str::to_string);
    let tel = if lower.starts_with("tel:") {
        aor.map(str::to_string)
    } else {
        // The user part of a SIP AOR, by the rule every other party's `tel`
        // follows: a global number or nothing.
        let user = sip
            .as_deref()
            .and_then(|u| u.split_once(':'))
            .and_then(|(_, rest)| rest.split_once('@'))
            .map(|(user, _)| user.split(';').next().unwrap_or(user));
        crate::output::vcon::tel_uri(user)
    };
    Party {
        sip,
        tel,
        validation: "none",
        role: None,
        name: p.name.clone(),
        stir: None,
        // No From or To header carried this name, and this key says one did.
        sip_display_name: None,
        sip_contact: None,
        sip_user_agent: None,
    }
}

impl RecordingSession {
    /// Add the recorded participants to `parties` and mark the SRC and SRS.
    ///
    /// `parties` holds the two observed parties, From then To. The
    /// participants are appended in metadata order, so the first one's index
    /// is the length `parties` had on entry.
    pub(crate) fn place(&self, parties: &mut Vec<Party>) -> Option<Placed> {
        let Self::Read(recorded) = self else {
            return None;
        };
        if let Some(client) = recorded.client.filter(|c| *c <= 1) {
            if let Some(p) = parties.get_mut(client) {
                p.role = Some(RECORDING_CLIENT_ROLE);
            }
            if let Some(p) = parties.get_mut(1 - client) {
                p.role = Some(RECORDING_SERVER_ROLE);
            }
        }
        let base = parties.len();
        let participants = &recorded.metadata.participants;
        parties.extend(participants.iter().map(participant_party));
        let streams = recorded
            .metadata
            .streams
            .iter()
            .map(|stream| PlacedStream {
                label: stream.label.clone(),
                stream_id: stream.stream_id.clone(),
                party: stream.participant_id.as_deref().and_then(|owner| {
                    participants
                        .iter()
                        .position(|p| p.participant_id.as_deref() == Some(owner))
                        .map(|i| base + i)
                }),
            })
            .collect();
        Some(Placed {
            streams,
            labeled: recorded.labeled.clone(),
        })
    }

    /// The sentence the completeness note carries about this, or `""`.
    pub(crate) fn clause(&self) -> String {
        match self {
            Self::NotRecording => String::new(),
            Self::Unread(why) => format!(
                " This dialog is a SIPREC recording session (RFC 7866), but {why}, so its \
                 parties are the recording client and server, not the participants of the \
                 recorded call."
            ),
            Self::Read(_) => " This dialog is a SIPREC recording session (RFC 7866): the From \
                              and To parties are the recording client and server, and the \
                              parties after them, before the observer, are the participants of \
                              the recorded call as the client's RFC 7865 metadata named them, \
                              which is what that metadata said, not an identity anyone \
                              established."
                .to_string(),
        }
    }
}

impl Placed {
    /// The party on each audio channel, from the stream's label, or `None`
    /// unless every channel resolves.
    ///
    /// A channel's sending socket names the m-line it came from, that m-line's
    /// `a=label` names a metadata stream, and that stream's sender is the
    /// party. All or nothing, for the reason the ordinary rule is: a partly
    /// filled list invites a reader to fill in the rest.
    pub(crate) fn channel_parties(&self, audio: &DialogAudio) -> Option<Vec<usize>> {
        if audio.sources.is_empty() {
            return None;
        }
        audio
            .sources
            .iter()
            .map(|key| {
                let label = &self
                    .labeled
                    .iter()
                    .find(|m| m.socket == Some(key.src))?
                    .label;
                self.streams
                    .iter()
                    .find(|s| s.label.as_deref() == Some(label.as_str()))?
                    .party
            })
            .collect()
    }

    /// The stream-map attachment, contributed by the observer.
    pub(crate) fn attachment(&self, observer: usize, start: String) -> Attachment {
        let rows: Vec<serde_json::Value> = self
            .streams
            .iter()
            .map(|s| {
                let mut row = serde_json::Map::new();
                if let Some(label) = &s.label {
                    row.insert("label".into(), label.clone().into());
                }
                if let Some(id) = &s.stream_id {
                    row.insert("stream_id".into(), id.clone().into());
                }
                if let Some(party) = s.party {
                    row.insert("party".into(), party.into());
                }
                serde_json::Value::Object(row)
            })
            .collect();
        Attachment {
            purpose: SIPREC_STREAMS_PURPOSE,
            party: observer,
            dialog: 0,
            start,
            mediatype: "application/json",
            encoding: "json",
            body: serde_json::json!({ "streams": rows }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::CaptureFacts;
    use crate::net::TransportProto;
    use crate::output::vcon::{
        COMPLETENESS_PURPOSE, ExportContext, OBSERVER_ROLE, ObservedAudio, Vcon, export_dialog_at,
        export_dialog_with_audio_at,
    };
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use chrono::{DateTime, Utc};

    type TestError = Box<dyn std::error::Error>;

    /// The SRC's address.
    const SRC: &str = "172.28.0.31";
    /// The SRS's address.
    const SRS: &str = "172.28.0.30";

    /// A fixed capture clock.
    fn ts() -> Result<DateTime<Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 9, 5, 17, 59, 35)
                .single()
                .ok_or("invalid fixture timestamp")?,
        )
    }

    /// The metadata of `tests/pcap-samples/siprec-opensips-invite.pcap`: two
    /// participants, Alice sending streams 0 (audio) and 1 (video), Bob
    /// sending stream 2 (audio). The shape OpenSIPS 4.0.1's `siprec` module
    /// writes, which is [RFC 7865 section 8.1](https://www.rfc-editor.org/rfc/rfc7865.html#section-8.1)'s shape with fewer elements.
    const METADATA: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<recording xmlns='urn:ietf:params:xml:ns:recording:1'>\r\n\
<datamode>complete</datamode>\r\n\
<session session_id=\"4f1c0a2e\"></session>\r\n\
<participant participant_id=\"9b2d1f00\">\r\n\
<nameID aor=\"sip:alice@example.invalid\"><name>Alice</name></nameID>\r\n\
</participant>\r\n\
<participant participant_id=\"c7e40a13\">\r\n\
<nameID aor=\"sip:+15550100@example.invalid\"/>\r\n\
</participant>\r\n\
<stream stream_id=\"1a2b3c4d\" session_id=\"4f1c0a2e\"><label>0</label></stream>\r\n\
<stream stream_id=\"2b3c4d5e\" session_id=\"4f1c0a2e\"><label>1</label></stream>\r\n\
<stream stream_id=\"3c4d5e6f\" session_id=\"4f1c0a2e\"><label>2</label></stream>\r\n\
<participantstreamassoc participant_id=\"9b2d1f00\">\r\n\
<send>1a2b3c4d</send><send>2b3c4d5e</send><recv>3c4d5e6f</recv>\r\n\
</participantstreamassoc>\r\n\
<participantstreamassoc participant_id=\"c7e40a13\">\r\n\
<send>3c4d5e6f</send><recv>1a2b3c4d</recv><recv>2b3c4d5e</recv>\r\n\
</participantstreamassoc>\r\n\
</recording>";

    /// The SRC's SDP offer: one m-line per recorded stream, each labeled.
    fn offer() -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {SRC}\r\ns=SIPREC\r\nc=IN IP4 {SRC}\r\nt=0 0\r\n\
             m=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:0\r\na=sendonly\r\n\
             m=video 20002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=label:1\r\na=sendonly\r\n\
             m=audio 20004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:2\r\na=sendonly\r\n"
        )
    }

    /// A multipart body: the offer, then `metadata`.
    fn multipart(metadata: &str) -> String {
        format!(
            "--B\r\nContent-Type: application/sdp\r\n\r\n{}\r\n\
             --B\r\nContent-Type: application/rs-metadata+xml\r\n\
             Content-Disposition: recording-session\r\n\r\n{metadata}\r\n--B--\r\n",
            offer()
        )
    }

    /// Parse one message sent from `from` to `to`.
    fn message(
        first_line: &str,
        headers: &[&str],
        body: &str,
        from: &str,
        to: &str,
    ) -> Result<crate::sip::SipMessage, TestError> {
        let length = format!("Content-Length: {}", body.len());
        let mut all = headers.to_vec();
        all.push(&length);
        Ok(parse_sip(
            &build_sip(first_line, &all, body.as_bytes()),
            ts()?,
            from.parse()?,
            to.parse()?,
            5060,
            5060,
            TransportProto::Udp,
        )?)
    }

    /// The SRC's INVITE, carrying `body` as `content_type`.
    fn invite(content_type: &str, body: &str) -> Result<crate::sip::SipMessage, TestError> {
        let ct = format!("Content-Type: {content_type}");
        message(
            &format!("INVITE sip:srs@{SRS} SIP/2.0"),
            &[
                "From: <sip:src@172.28.0.31>;tag=9b2d1f00",
                "To: <sip:srs@172.28.0.30>",
                "Call-ID: siprec-fixture@172.28.0.31",
                "CSeq: 1 INVITE",
                "Contact: <sip:src@172.28.0.31:5060>;+sip.src",
                "Require: siprec",
                &ct,
            ],
            body,
            SRC,
            SRS,
        )
    }

    /// The SRS's 200 OK, answering with receive-only m-lines.
    fn answer() -> Result<crate::sip::SipMessage, TestError> {
        let sdp = format!(
            "v=0\r\no=- 2 2 IN IP4 {SRS}\r\ns=-\r\nc=IN IP4 {SRS}\r\nt=0 0\r\n\
             m=audio 30000 RTP/AVP 0\r\na=recvonly\r\n\
             m=video 30002 RTP/AVP 96\r\na=recvonly\r\n\
             m=audio 30004 RTP/AVP 0\r\na=recvonly\r\n"
        );
        message(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:src@172.28.0.31>;tag=9b2d1f00",
                "To: <sip:srs@172.28.0.30>;tag=srs1",
                "Call-ID: siprec-fixture@172.28.0.31",
                "CSeq: 1 INVITE",
                "Contact: <sip:srs@172.28.0.30:5060>;+sip.srs",
                "Content-Type: application/sdp",
            ],
            &sdp,
            SRS,
            SRC,
        )
    }

    /// A recording-session dialog whose INVITE carries `metadata`.
    fn recording(metadata: &str) -> Result<SipDialog, TestError> {
        dialog_of(invite("multipart/mixed;boundary=B", &multipart(metadata))?)
    }

    /// A dialog opened by `opening` and answered by the SRS.
    fn dialog_of(opening: crate::sip::SipMessage) -> Result<SipDialog, TestError> {
        let mut dialog = SipDialog::new(&opening).ok_or("the INVITE opens a dialog")?;
        let ok = answer()?;
        crate::sip::dialog::update_state(&mut dialog, &ok);
        dialog.messages.push(ok);
        Ok(dialog)
    }

    /// Export with no audio and a clean capture.
    fn export(dialog: &SipDialog) -> Result<serde_json::Value, TestError> {
        export_audio(dialog, ObservedAudio::NotConsidered)
    }

    /// Export with `audio` and a clean capture.
    fn export_audio(
        dialog: &SipDialog,
        audio: ObservedAudio<'_>,
    ) -> Result<serde_json::Value, TestError> {
        Ok(serde_json::to_value(container(dialog, audio)?)?)
    }

    /// The container itself.
    fn container(dialog: &SipDialog, audio: ObservedAudio<'_>) -> Result<Vcon, TestError> {
        let facts = CaptureFacts {
            frames_read: 2,
            ..CaptureFacts::default()
        };
        Ok(export_dialog_with_audio_at(
            dialog,
            &ExportContext {
                capture_id: "siprec.pcap",
                facts: &facts,
                max_inline_media_bytes: None,
                analysis: None,
                media: &[],
                related_legs: &[],
            },
            audio,
            ts()?,
        ))
    }

    /// The attachment with `purpose`, when there is one.
    fn attachment<'a>(v: &'a serde_json::Value, purpose: &str) -> Option<&'a serde_json::Value> {
        v["attachments"]
            .as_array()?
            .iter()
            .find(|a| a["purpose"] == purpose)
    }

    /// The completeness note.
    fn note(v: &serde_json::Value) -> Result<String, TestError> {
        Ok(attachment(v, COMPLETENESS_PURPOSE)
            .and_then(|a| a["body"]["note"].as_str())
            .ok_or("a completeness note")?
            .to_string())
    }

    /// Two participants in the metadata become two parties, with their AORs
    /// and names, between the SRC and SRS and the observer.
    #[test]
    fn two_recorded_participants_become_two_parties() -> Result<(), TestError> {
        let v = export(&recording(METADATA)?)?;
        let parties = v["parties"].as_array().ok_or("parties")?;
        assert_eq!(
            parties.len(),
            5,
            "SRC, SRS, two participants, observer: {parties:#?}"
        );
        assert_eq!(parties[2]["sip"], "sip:alice@example.invalid");
        assert_eq!(parties[2]["name"], "Alice");
        assert_eq!(parties[3]["sip"], "sip:+15550100@example.invalid");
        assert_eq!(
            parties[3]["tel"], "tel:+15550100",
            "a global number in the AOR's user part is a tel URI, by the rule \
             every other party follows"
        );
        assert!(
            parties[3].get("name").is_none(),
            "Bob's metadata gave no name: {}",
            parties[3]
        );
        for p in &parties[2..4] {
            assert_eq!(p["validation"], "none");
            assert!(
                p.get("role").is_none(),
                "a recorded participant's role is not known: {p}"
            );
            assert!(
                p.get("sip_display_name").is_none(),
                "no From or To header carried this name: {p}"
            );
        }
        assert_eq!(parties[4]["role"], OBSERVER_ROLE, "the observer stays last");
        Ok(())
    }

    /// The SRC and the SRS stay parties 0 and 1, with roles that say which
    /// is which.
    #[test]
    fn the_client_and_server_keep_their_places_with_roles() -> Result<(), TestError> {
        let v = export(&recording(METADATA)?)?;
        assert_eq!(v["parties"][0]["sip"], "sip:src@172.28.0.31");
        assert_eq!(v["parties"][0]["role"], RECORDING_CLIENT_ROLE);
        assert_eq!(v["parties"][1]["sip"], "sip:srs@172.28.0.30");
        assert_eq!(v["parties"][1]["role"], RECORDING_SERVER_ROLE);
        Ok(())
    }

    /// Each recorded stream names the party that sends it, by
    /// `participantstreamassoc`.
    #[test]
    fn each_recorded_stream_names_the_participant_that_sends_it() -> Result<(), TestError> {
        let v = export(&recording(METADATA)?)?;
        let streams = attachment(&v, SIPREC_STREAMS_PURPOSE).ok_or("a stream map")?;
        assert_eq!(streams["party"], 4, "contributed by the observer");
        assert_eq!(
            streams["body"]["streams"],
            serde_json::json!([
                {"label": "0", "stream_id": "1a2b3c4d", "party": 2},
                {"label": "1", "stream_id": "2b3c4d5e", "party": 2},
                {"label": "2", "stream_id": "3c4d5e6f", "party": 3},
            ])
        );
        Ok(())
    }

    /// Decoded audio whose channels were sent from `sources`, in order.
    fn audio(sources: &[u16]) -> Result<DialogAudio, TestError> {
        Ok(DialogAudio {
            wav: vec![0; 64],
            sample_rate: 8000,
            channels: sources.len() as u16,
            duration_secs: 1.0,
            partial: String::new(),
            note: "fixture".into(),
            ring_wrapped: false,
            sources: sources
                .iter()
                .map(|port| -> Result<_, TestError> {
                    Ok(crate::rtp::stream::StreamKey::new(
                        7,
                        format!("{SRC}:{port}").parse()?,
                        format!("{SRS}:{}", port + 10000).parse()?,
                    ))
                })
                .collect::<Result<_, _>>()?,
            first_retained: ts()?,
            media_start: ts()?,
            media_end: ts()?,
            summary_head: "fixture".into(),
        })
    }

    /// Each audio channel is attributed to the participant whose stream it
    /// carries, through the label on the m-line it was sent from.
    #[test]
    fn each_audio_channel_names_the_participant_whose_stream_it_carries() -> Result<(), TestError> {
        let dialog = recording(METADATA)?;
        let both = audio(&[20000, 20004])?;
        let v = export_audio(&dialog, ObservedAudio::Decoded(&both))?;
        assert_eq!(v["dialog"][0]["type"], "recording");
        assert_eq!(
            v["dialog"][0]["parties"],
            serde_json::json!([2, 3]),
            "channel 0 is Alice's stream (label 0), channel 1 Bob's (label 2)"
        );
        let swapped = audio(&[20004, 20000])?;
        let v = export_audio(&dialog, ObservedAudio::Decoded(&swapped))?;
        assert_eq!(
            v["dialog"][0]["parties"],
            serde_json::json!([3, 2]),
            "the order follows the channels, not the metadata"
        );
        Ok(())
    }

    /// A channel from a socket no labeled m-line names leaves the channel
    /// list absent rather than partly filled.
    #[test]
    fn a_channel_with_no_label_leaves_channel_parties_absent() -> Result<(), TestError> {
        let one_unknown = audio(&[20000, 29999])?;
        let v = export_audio(&recording(METADATA)?, ObservedAudio::Decoded(&one_unknown))?;
        assert!(
            v["dialog"][0].get("parties").is_none(),
            "all or nothing: {}",
            v["dialog"][0]
        );
        Ok(())
    }

    /// The parties an ordinary export of the same dialog writes: today's
    /// behavior for a recording session sipnab cannot read.
    fn unchanged(v: &serde_json::Value) -> Result<(), TestError> {
        let parties = v["parties"].as_array().ok_or("parties")?;
        assert_eq!(parties.len(), 3, "SRC, SRS and the observer: {parties:#?}");
        assert!(parties[0].get("role").is_none() && parties[1].get("role").is_none());
        assert!(attachment(v, SIPREC_STREAMS_PURPOSE).is_none());
        Ok(())
    }

    /// Metadata that names no participant leaves today's parties, and the
    /// completeness note says why.
    #[test]
    fn malformed_metadata_leaves_the_parties_unchanged_and_says_why() -> Result<(), TestError> {
        let v = export(&recording("<recording><participant participant_id=")?)?;
        unchanged(&v)?;
        let note = note(&v)?;
        assert!(
            note.contains("SIPREC recording session") && note.contains("named no participant"),
            "{note}"
        );
        Ok(())
    }

    /// A SIPREC INVITE with no metadata part at all leaves today's parties,
    /// and the completeness note says why.
    #[test]
    fn a_recording_session_with_no_metadata_leaves_the_parties_unchanged() -> Result<(), TestError>
    {
        let v = export(&dialog_of(invite("application/sdp", &offer())?)?)?;
        unchanged(&v)?;
        let note = note(&v)?;
        assert!(
            note.contains("SIPREC recording session") && note.contains("no rs-metadata"),
            "{note}"
        );
        Ok(())
    }

    /// An ordinary call says nothing about SIPREC.
    #[test]
    fn an_ordinary_call_says_nothing_about_siprec() -> Result<(), TestError> {
        let plain = message(
            "INVITE sip:bob@example.net SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=a",
                "To: <sip:bob@example.net>",
                "Call-ID: plain@example.com",
                "CSeq: 1 INVITE",
            ],
            "",
            SRC,
            SRS,
        )?;
        let dialog = SipDialog::new(&plain).ok_or("dialog")?;
        let v = serde_json::to_value(export_dialog_at(
            &dialog,
            &ExportContext {
                capture_id: "plain.pcap",
                facts: &CaptureFacts::default(),
                max_inline_media_bytes: None,
                analysis: None,
                media: &[],
                related_legs: &[],
            },
            ts()?,
        ))?;
        unchanged(&v)?;
        assert!(!note(&v)?.contains("SIPREC"));
        Ok(())
    }

    /// Merging two legs into one call container moves each stream's `party`
    /// with the party array, as it moves every other party index.
    #[test]
    fn merging_legs_moves_each_stream_party() -> Result<(), TestError> {
        let first = container(&recording(METADATA)?, ObservedAudio::NotConsidered)?;
        let shift = first.parties.len() - 1;
        let second = container(&recording(METADATA)?, ObservedAudio::NotConsidered)?;
        let merged = crate::output::vcon::merge_call_legs(
            vec![first, second],
            &[crate::output::vcon::LegTie {
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
        let maps: Vec<_> = merged
            .attachments
            .iter()
            .filter(|a| a.purpose == SIPREC_STREAMS_PURPOSE)
            .map(|a| a.body["streams"].clone())
            .collect();
        assert_eq!(maps.len(), 2, "one stream map per leg");
        let owners = |m: &serde_json::Value| -> Vec<u64> {
            m.as_array()
                .map(|rows| rows.iter().filter_map(|r| r["party"].as_u64()).collect())
                .unwrap_or_default()
        };
        assert_eq!(owners(&maps[0]), [2, 2, 3]);
        let s = shift as u64;
        assert_eq!(owners(&maps[1]), [2 + s, 2 + s, 3 + s]);
        assert_eq!(merged.parties[2 + shift].sip, merged.parties[2].sip);
        Ok(())
    }

    /// `--redact` rewrites the recorded participants' AORs and names the way
    /// it rewrites every other party's.
    #[test]
    fn redaction_rewrites_participant_aors_and_names() -> Result<(), TestError> {
        use crate::output::redact::{Redact as _, RedactionKey, RedactionPolicy};
        let mut v = container(&recording(METADATA)?, ObservedAudio::NotConsidered)?;
        let policy = RedactionPolicy::new(RedactionKey::from_secret(b"siprec"));
        let r = policy.redactor();
        v.redact(&r);
        let alice = &v.parties[2];
        assert_eq!(
            alice.sip.as_deref(),
            Some(r.uri("sip:alice@example.invalid").as_str())
        );
        assert_eq!(alice.name.as_deref(), Some(r.identity("Alice").as_str()));
        let json = serde_json::to_string(&v)?;
        for secret in ["alice@", "Alice", "15550100"] {
            assert!(
                !json.contains(secret),
                "{secret} survived redaction: {json}"
            );
        }
        Ok(())
    }
}
