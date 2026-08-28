// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rules that need a dialog's messages read against each other.
//!
//! # Why these cannot be message rules
//!
//! "A request outside a dialog MUST NOT contain a `To` tag" is the clearest
//! example. One message cannot say whether it sits inside a dialog, so a
//! message-scoped version of that rule fires on every re-`INVITE` in every
//! capture that starts mid-call — which is most captures. The rule only becomes
//! decidable once the surrounding messages are in hand, and even then only in
//! the two shapes `to_tag_in_initial_request` documents.
//!
//! The SDP rules have the same shape: an answer is only wrong relative to the
//! offer it answers.

use crate::sip::dialog::SipDialog;
use crate::sip::message::SipMessage;
use crate::sip::method::SipMethod;
use crate::sip::sdp::{SdpDirection, SdpMedia, SdpSession, effective_address};

use super::FindingSink;
use super::finding::{
    ACK_BRANCH_MISMATCH, ACK_CSEQ_MISMATCH, ANSWER_DIRECTION_ILLEGAL, ANSWER_EXTRA_FORMAT,
    ANSWER_NO_COMMON_FORMAT, DYNAMIC_PT_REBOUND, HOLD_CONNECTION_ZERO, OPUS_RTPMAP_RATE,
    PRACK_MISSING, RECORD_ROUTE_NOT_COPIED, REJECTED_STREAM_ATTRIBUTES, TELEPHONE_EVENT_ONE_WAY,
    TO_TAG_IN_INITIAL_REQUEST,
};

/// The unspecified IPv4 address RFC 2543 used to signal hold.
pub(crate) const HOLD_ADDRESS_V4: &str = "0.0.0.0";

/// The unspecified IPv6 address, the same idea in the newer family.
pub(crate) const HOLD_ADDRESS_V6: &str = "::";

/// One SDP body found in the dialog, with where it came from.
pub(crate) struct SdpEntry {
    /// Index into the dialog's message list.
    pub(crate) index: usize,
    /// The parsed session description.
    pub(crate) sdp: SdpSession,
}

/// An offer paired with the answer that resolved it.
pub(crate) struct OfferAnswer {
    /// The offer.
    pub(crate) offer: SdpEntry,
    /// The answer to that offer.
    pub(crate) answer: SdpEntry,
}

/// Pair every SDP body in the dialog into offers and answers.
///
/// Follows the same role assignment as [`crate::sip::sdp_timeline`], so the
/// linter and the timeline never disagree about which body was the offer: an
/// `ACK` never offers, a response with no offer before it carries the delayed
/// offer, and every other request offers.
///
/// An offer with no answer is dropped rather than paired with the next offer —
/// a call that was re-offered before the first answer arrived has no answer to
/// judge.
pub(crate) fn offer_answer_pairs(dialog: &SipDialog) -> Vec<OfferAnswer> {
    let mut pairs = Vec::new();
    let mut pending: Option<SdpEntry> = None;

    for (index, msg) in dialog.messages.iter().enumerate() {
        let Some(sdp) = msg.sdp() else {
            continue;
        };
        let entry = SdpEntry { index, sdp };
        let is_answer = if msg.is_request {
            msg.method.as_ref() == Some(&SipMethod::Ack)
        } else {
            pending.is_some()
        };

        match (is_answer, pending.take()) {
            (true, Some(offer)) => pairs.push(OfferAnswer {
                offer,
                answer: entry,
            }),
            // An answer with nothing outstanding answers an offer the capture
            // never saw. Nothing to compare it against.
            (true, None) => {}
            (false, _) => pending = Some(entry),
        }
    }

    pairs
}

/// The media descriptions of an offer and an answer, lined up by position.
///
/// RFC 3264 §6 makes the answer's `m=` lines correspond to the offer's one for
/// one and in order, so position is the pairing, not media type.
fn paired_media(pair: &OfferAnswer) -> impl Iterator<Item = (usize, &SdpMedia, &SdpMedia)> {
    pair.offer
        .sdp
        .media
        .iter()
        .zip(pair.answer.sdp.media.iter())
        .enumerate()
        .map(|(i, (o, a))| (i, o, a))
}

/// Run every dialog-scoped rule.
pub(crate) fn lint(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    to_tag_in_initial_request(dialog, sink);
    ack_cseq(dialog, sink);
    ack_branch(dialog, sink);
    record_route_copied(dialog, sink);

    let pairs = offer_answer_pairs(dialog);
    for pair in &pairs {
        answer_formats(pair, sink);
        answer_direction(pair, sink);
        telephone_event_unanswered(pair, sink);
        rejected_stream_attributes(pair, sink);
    }
    hold_with_unspecified_address(dialog, sink);
    prack_for_reliable_provisionals(dialog, sink);
    dynamic_payload_types(dialog, sink);
    opus_rtpmap(dialog, sink);
}

/// RFC 3261 §17.1.1.3 — an `ACK` to a non-2xx stays on the `INVITE`'s branch.
///
/// # Why the 2xx case is excluded rather than merely uninteresting
///
/// §17.1.1.3 opens "A UAC core that generates an ACK for 2xx MUST instead
/// follow the rules described in Section 13". An ACK to a 2xx is a NEW
/// transaction and §8.1.1.7 makes it carry a NEW branch, so a rule that read
/// every ACK would report the correct behavior as a violation on every
/// successful call in every capture — the single largest false-positive source
/// available in SIP.
///
/// So the rule reports only where the capture proved the response was non-2xx:
/// a final response to this `INVITE`, matched by CSeq number, with a status
/// below 200 or at 300 and above. An ACK whose INVITE the capture never carried
/// settles nothing and is skipped.
fn ack_branch(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&ACK_BRANCH_MISMATCH) {
        return;
    }

    for (index, ack) in dialog.messages.iter().enumerate() {
        if !ack.is_request || ack.method.as_ref() != Some(&SipMethod::Ack) {
            continue;
        }
        let (Some((seq, _)), Some(ack_branch)) = (ack.cseq(), ack.top_via_branch()) else {
            continue;
        };

        // The final answer to this INVITE, if the capture holds one. A 2xx
        // takes the ACK off this rule entirely.
        let non_2xx = dialog.messages.iter().any(|m| {
            !m.is_request
                && m.cseq()
                    .is_some_and(|(s, method)| s == seq && method.eq_ignore_ascii_case("INVITE"))
                && m.status_code.is_some_and(|c| (300..700).contains(&c))
        });
        if !non_2xx {
            continue;
        }

        let Some(invite_branch) = dialog
            .messages
            .iter()
            .find(|m| {
                m.is_request
                    && m.method.as_ref() == Some(&SipMethod::Invite)
                    && m.cseq().is_some_and(|(s, _)| s == seq)
            })
            .and_then(|m| m.top_via_branch())
        else {
            continue;
        };

        if ack_branch == invite_branch {
            continue;
        }
        sink.push(
            &ACK_BRANCH_MISMATCH,
            index,
            format!("ACK branch={ack_branch}, INVITE branch={invite_branch}"),
            format!("ACK branch={invite_branch}"),
            "§17.1.1.3 makes the ACK to a non-2xx carry a single Via equal to the top Via \
             of the INVITE, so it reuses that branch and completes the same transaction \
             hop by hop. On a new branch it is a new transaction to every element in the \
             path: the INVITE server transaction never absorbs it, retransmits its final \
             response until Timer H, and the stray ACK arrives at a proxy that has no \
             matching transaction for it.",
        );
    }
}

/// RFC 3261 §12.1.1 — a dialog-establishing response reproduces the request's
/// `Record-Route`, in order.
///
/// # What this compares, and what it deliberately does not
///
/// The request half is the dialog-forming request the capture holds; the
/// response half is the 2xx that establishes the dialog. Both are read as
/// ordered lists of bracketed URIs, and the comparison is on the URIs alone.
///
/// A capture is a window: an element that inserts a `Record-Route` on the way
/// out sees a request WITHOUT it, and the response comes back WITH it. That
/// asymmetry is ordinary at any point that is not the UAS, so a rule reporting
/// "the response has more than the request" would fire on every proxy-side
/// capture in existence. Only the other direction is reported — a value the
/// request carried and the response dropped, or one whose position moved —
/// because that is what §12.1.1's copy-and-maintain-order sentence forbids and
/// what breaks the caller's route set.
fn record_route_copied(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&RECORD_ROUTE_NOT_COPIED) {
        return;
    }
    let Some(request) = dialog.messages.first().filter(|m| m.is_request) else {
        return;
    };
    let asked = record_route_uris(request);
    if asked.is_empty() {
        return;
    }
    let Some((seq, _)) = request.cseq() else {
        return;
    };

    for (index, response) in dialog.messages.iter().enumerate().skip(1) {
        if response.is_request
            || !response
                .status_code
                .is_some_and(|c| (200..300).contains(&c))
            || !response.cseq().is_some_and(|(s, _)| s == seq)
        {
            continue;
        }
        let echoed = record_route_uris(response);
        // A prefix comparison, not equality: extra values ABOVE the ones the
        // request carried are the ordinary shape of a capture taken before the
        // last recording proxy, and only a dropped or reordered value is the
        // defect §12.1.1 names.
        if echoed.len() >= asked.len() && echoed[echoed.len() - asked.len()..] == asked[..] {
            continue;
        }
        sink.push(
            &RECORD_ROUTE_NOT_COPIED,
            index,
            format!("request recorded {asked:?}, the 2xx returned {echoed:?}"),
            format!("the 2xx ending with {asked:?}, in that order"),
            "§12.1.1 makes the UAS copy every Record-Route value from the request into the \
             response and keep their order. §12.1.2 then has the caller build its route set \
             from the response, in reverse — so a value dropped here is a proxy removed from \
             the path it recorded itself into, and a value reordered sends the BYE through \
             the hops backwards. Both fail after the call is up, which is why they are read \
             as a network fault rather than a signaling one.",
        );
    }
}

/// Every bracketed `Record-Route` URI in a message, in header order.
fn record_route_uris(msg: &SipMessage) -> Vec<String> {
    msg.headers_by_name("Record-Route")
        .iter()
        .flat_map(|row| super::message::bracketed_uris(row))
        .map(str::to_string)
        .collect()
}

/// RFC 3262 §4 — a reliable provisional has to draw a `PRACK`.
///
/// # Why this is guarded three ways
///
/// A capture is a window, not a transcript. The naive rule — "a 100rel
/// provisional with no PRACK behind it" — fires on every dialog whose capture
/// stopped between the two, which on a busy trunk is a large share of them, and
/// a rule that fires on ordinary traffic gets switched off in week one.
///
/// So it reports only where the capture has already proved it saw the rest of
/// the exchange: the dialog carries a final response to the `INVITE`, which the
/// UAS only sends after the reliable provisional is settled. If the final
/// answer arrived and no `PRACK` appears anywhere in the dialog, the PRACK is
/// genuinely absent rather than merely off the end of the file.
fn prack_for_reliable_provisionals(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&PRACK_MISSING) {
        return;
    }

    // The provisional that asked for reliability, and where it sat.
    let Some((index, _)) = dialog
        .messages
        .iter()
        .enumerate()
        .find(|(_, m)| super::message::requires_100rel(m))
    else {
        return;
    };

    // Guard one: the capture has to show the exchange finishing.
    let saw_final = dialog.messages.iter().any(|m| {
        !m.is_request
            && m.status_code.is_some_and(|c| c >= 200)
            && m.cseq()
                .is_some_and(|(_, method)| method.eq_ignore_ascii_case("INVITE"))
    });
    if !saw_final {
        return;
    }

    // Guard two: a PRACK anywhere in the dialog settles it.
    let saw_prack = dialog
        .messages
        .iter()
        .any(|m| m.is_request && m.method == Some(SipMethod::Prack));
    if saw_prack {
        return;
    }

    sink.push(
        &PRACK_MISSING,
        index,
        "provisional required 100rel, the INVITE reached a final response, and no PRACK \
         appears in the dialog",
        "PRACK acknowledging the RSeq of the reliable provisional",
        "§4 makes the UAC create a PRACK for a provisional sent reliably. Without one the \
         UAS retransmits the provisional until it gives up, which the caller hears as \
         ringing that never becomes a call.",
    );
}

/// RFC 3261 §8.1.1.2 — a request outside a dialog carries no `To` tag.
///
/// Two shapes settle it, and nothing else does:
///
/// - A `REGISTER` carrying a `To` tag. REGISTER never sits inside a dialog
///   (§10), so the tag is wrong wherever the capture started.
/// - A dialog whose first message is a request with a `To` tag, whose own
///   *transaction* answered with a **different** `To` tag. §8.2.6.2 makes a UAS
///   echo the request's tag when the request had one, so a UAS that supplied its
///   own is telling us the request's tag identified no dialog it knew about.
///
/// A re-`INVITE` in a capture that began mid-call satisfies neither, which is
/// the whole point.
///
/// # Why the answer has to be the same transaction
///
/// An earlier form of this rule compared against *every* response in the dialog
/// and fired on 2,182 dialogs of the validation corpus, 2,160 of them
/// `SUBSCRIBE`. The cause was not subscriptions: a `SUBSCRIBE` dialog carries
/// `NOTIFY` requests in the reverse direction, and a response to a `NOTIFY`
/// correctly carries the *subscriber's* tag, which is not the tag the
/// `SUBSCRIBE` addressed. Every one of those 2,160 was the rule reading a
/// perfectly conformant dialog backwards. Matching on the top `Via` branch —
/// the RFC 3261 §8.1.1.7 transaction identifier — restricts the comparison to
/// the answer that actually answered this request.
fn to_tag_in_initial_request(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&TO_TAG_IN_INITIAL_REQUEST) {
        return;
    }
    let Some(first) = dialog.messages.first() else {
        return;
    };
    if !first.is_request {
        return;
    }
    let Some(tag) = first.to_tag() else {
        return;
    };
    let method = first.method.as_ref();

    let register = method == Some(&SipMethod::Register);
    let branch = first.top_via_branch();
    let cseq = first.cseq();
    let rejected_tag = dialog
        .messages
        .iter()
        .skip(1)
        .filter(|m| !m.is_request && m.status_code.is_some_and(|c| c > 100))
        // Same transaction, by the §8.1.1.7 branch where there is one and by
        // CSeq identity where the peer predates it.
        .filter(|m| match (branch, m.top_via_branch()) {
            (Some(want), Some(got)) => want == got,
            _ => m.cseq() == cseq && cseq.is_some(),
        })
        .filter_map(|m| m.to_tag())
        .any(|answer_tag| answer_tag != tag);

    if !register && !rejected_tag {
        return;
    }

    let evidence = if register {
        "REGISTER never sits inside a dialog (§10), so no To tag can be a dialog identifier."
    } else {
        "The response carries a different To tag, so §8.2.6.2 says the responder treated \
         this as a new dialog and supplied its own."
    };
    sink.push(
        &TO_TAG_IN_INITIAL_REQUEST,
        0,
        format!(
            "{} carries a To tag on the dialog's first message",
            method.map_or("request", SipMethod::as_str)
        ),
        "To header field with no tag parameter",
        format!(
            "§8.1.1.2 makes the To tag the peer's half of a dialog identifier, so a request \
             that starts one MUST NOT carry it. {evidence} Forking proxies and dialog-stateful \
             SBCs key on the pair, and a pre-set tag makes them route the answer somewhere \
             the caller is not."
        ),
    );
}

/// RFC 3261 §17.1.1.3 — an `ACK` reuses its `INVITE`'s sequence number.
///
/// Only fires when the capture holds at least one `INVITE`, so a dialog whose
/// `INVITE` was never captured raises nothing rather than raising everything.
fn ack_cseq(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&ACK_CSEQ_MISMATCH) {
        return;
    }
    let invite_seqs: Vec<u32> = dialog
        .messages
        .iter()
        .filter(|m| m.is_request && m.method.as_ref() == Some(&SipMethod::Invite))
        .filter_map(|m| m.cseq().map(|(seq, _)| seq))
        .collect();
    if invite_seqs.is_empty() {
        return;
    }

    for (index, msg) in dialog.messages.iter().enumerate() {
        if !msg.is_request || msg.method.as_ref() != Some(&SipMethod::Ack) {
            continue;
        }
        let Some((seq, _)) = msg.cseq() else {
            continue;
        };
        if invite_seqs.contains(&seq) {
            continue;
        }
        sink.push(
            &ACK_CSEQ_MISMATCH,
            index,
            format!("ACK CSeq {seq}, INVITE CSeq {invite_seqs:?}"),
            format!("ACK CSeq {}", invite_seqs[0]),
            "§17.1.1.3 makes the ACK reuse the INVITE's sequence number with the method \
             changed to ACK. A UAS matching on that number never sees this ACK, so it \
             retransmits its 2xx until Timer H and then tears the call down mid-conversation.",
        );
    }
}

/// RFC 3264 §6.1 — what the answer may and may not list.
///
/// Two findings, deliberately separate. An answer sharing no format with the
/// offer breaks a MUST. An answer listing an *extra* format breaks nothing —
/// §6.1 permits it in as many words — but the answerer cannot send with it, so
/// every reader who takes it for a negotiated codec is misled.
///
/// A stream the answerer declined carries port zero (§6), and a declined stream
/// lists whatever the offer did. Neither finding applies there.
fn answer_formats(pair: &OfferAnswer, sink: &mut FindingSink<'_>) {
    for (m_index, offer, answer) in paired_media(pair) {
        if answer.port == 0 || offer.formats.is_empty() {
            continue;
        }

        let common: Vec<&String> = answer
            .formats
            .iter()
            .filter(|f| offer.formats.contains(f))
            .collect();

        if common.is_empty() {
            sink.push(
                &ANSWER_NO_COMMON_FORMAT,
                pair.answer.index,
                format!(
                    "m={} line {m_index} answers {:?} with {:?}",
                    answer.media_type, offer.formats, answer.formats
                ),
                format!("at least one of {:?}", offer.formats),
                "§6.1 makes the answer list at least one format from the offer. With no \
                 format in common neither end can send anything the other decodes, and the \
                 correct answer was to decline the stream with port 0.",
            );
            continue;
        }

        let extra: Vec<&String> = answer
            .formats
            .iter()
            .filter(|f| !offer.formats.contains(f))
            .collect();
        if !extra.is_empty() {
            sink.push(
                &ANSWER_EXTRA_FORMAT,
                pair.answer.index,
                format!(
                    "m={} line {m_index} answers with {extra:?}, absent from the offer",
                    answer.media_type
                ),
                format!("formats drawn from {:?}", offer.formats),
                "§6.1 permits this and says why it rarely helps: the answerer cannot send \
                 with a format the offer never listed. Equipment that reads the answer as \
                 the negotiated set picks one of these and sends media the far end drops.",
            );
        }
    }
}

/// RFC 3264 §6.1 — the direction an answer is allowed to take.
///
/// A `sendonly` offer admits `recvonly` or `inactive`; a `recvonly` offer admits
/// `sendonly` or `inactive`; an `inactive` offer admits `inactive` alone. A
/// `sendrecv` offer admits all four, so it is not checked.
fn answer_direction(pair: &OfferAnswer, sink: &mut FindingSink<'_>) {
    for (m_index, offer, answer) in paired_media(pair) {
        if answer.port == 0 {
            continue;
        }
        let permitted: &[SdpDirection] = match offer.direction {
            SdpDirection::SendOnly => &[SdpDirection::RecvOnly, SdpDirection::Inactive],
            SdpDirection::RecvOnly => &[SdpDirection::SendOnly, SdpDirection::Inactive],
            SdpDirection::Inactive => &[SdpDirection::Inactive],
            SdpDirection::SendRecv => continue,
        };
        if permitted.contains(&answer.direction) {
            continue;
        }
        sink.push(
            &ANSWER_DIRECTION_ILLEGAL,
            pair.answer.index,
            format!(
                "m={} line {m_index} answers {} with {}",
                answer.media_type,
                direction_name(offer.direction),
                direction_name(answer.direction)
            ),
            format!(
                "one of {}",
                permitted
                    .iter()
                    .map(|d| direction_name(*d))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
            "§6.1 fixes the answer's direction from the offer's. Answering a one-way offer \
             the same way leaves both ends expecting the other to send, which is a call that \
             connects and stays silent.",
        );
    }
}

/// The SDP attribute name for a direction.
fn direction_name(direction: SdpDirection) -> &'static str {
    match direction {
        SdpDirection::SendRecv => "sendrecv",
        SdpDirection::SendOnly => "sendonly",
        SdpDirection::RecvOnly => "recvonly",
        SdpDirection::Inactive => "inactive",
    }
}

/// RFC 3264 §8.4 — hold signaled by blanking the connection address.
///
/// §8.4 keeps one legitimate use: an *initial* offer from an agent that does not
/// yet know its own address. The first SDP in the dialog is therefore exempt,
/// and a later one is not. A port of zero is a declined stream rather than a
/// held one, so it is exempt too.
///
/// sipnab has always found hold through `a=sendonly` and `a=inactive`
/// ([`crate::sip::sdp_timeline`]). This is the third mechanism, and until now
/// a call held this way looked to the tool like a call that simply stopped.
fn hold_with_unspecified_address(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&HOLD_CONNECTION_ZERO) {
        return;
    }
    let mut seen_first = false;
    for (index, msg) in dialog.messages.iter().enumerate() {
        let Some(sdp) = msg.sdp() else {
            continue;
        };
        if !seen_first {
            seen_first = true;
            continue;
        }
        for (m_index, media) in sdp.media.iter().enumerate() {
            if media.port == 0 {
                continue;
            }
            let Some(addr) = effective_address(media, &sdp) else {
                continue;
            };
            if addr != HOLD_ADDRESS_V4 && addr != HOLD_ADDRESS_V6 {
                continue;
            }
            sink.push(
                &HOLD_CONNECTION_ZERO,
                index,
                format!(
                    "m={} line {m_index} re-offered with c={addr}",
                    media.media_type
                ),
                "a=sendonly, or a=inactive for a stream that was recvonly",
                "§8.4 replaced this RFC 2543 mechanism with the direction attributes, \
                 because a blanked connection address leaves no path for RTCP, has no IPv6 \
                 form, and breaks connection-oriented media. Equipment that reads only the \
                 direction attributes sees no hold at all and keeps sending.",
            );
        }
    }
}

/// The `a=rtpmap` encoding name RFC 4733 registers for named telephone events.
const TELEPHONE_EVENT: &str = "telephone-event";

/// Whether a media description declares `telephone-event` in its `a=rtpmap`.
fn declares_telephone_event(media: &SdpMedia) -> bool {
    media
        .rtpmap
        .iter()
        .any(|m| m.encoding.eq_ignore_ascii_case(TELEPHONE_EVENT))
}

/// RFC 3264 §7 — an offered format the answer omits is not negotiated.
///
/// Restricted to `telephone-event` on an accepted audio stream, because that is
/// the one omission whose consequence is invisible until somebody presses a
/// key. Every other missing format shows up as a codec that does not work; DTMF
/// shows up as an IVR that ignores the caller.
///
/// # Why this is not a MUST, and why it is not RFC 4733
///
/// RFC 4733 states no offer/answer rule at all — §2.5.1.1 says negotiation
/// happens "by out-of-band means, using SDP, for example" and stops there. The
/// binding text is RFC 3264 §7, and it is a MAY: the offerer *may* cease
/// listening for a format the answer omitted. So nothing here breaks, and the
/// interop failure is real anyway, because plenty of equipment sends
/// `telephone-event` on the payload type it offered regardless of the answer.
///
/// The stream has to be accepted (port non-zero) and share an audio format:
/// a declined stream negotiated nothing, and a stream with no common format is
/// already [`ANSWER_NO_COMMON_FORMAT`]'s finding and would be reported twice.
fn telephone_event_unanswered(pair: &OfferAnswer, sink: &mut FindingSink<'_>) {
    if !sink.wants(&TELEPHONE_EVENT_ONE_WAY) {
        return;
    }
    for (m_index, offer, answer) in paired_media(pair) {
        if answer.port == 0
            || !offer.media_type.eq_ignore_ascii_case("audio")
            || !declares_telephone_event(offer)
            || declares_telephone_event(answer)
            || !answer.formats.iter().any(|f| offer.formats.contains(f))
        {
            continue;
        }
        sink.push(
            &TELEPHONE_EVENT_ONE_WAY,
            pair.answer.index,
            format!(
                "m={} line {m_index} offered telephone-event, the answer omits it",
                offer.media_type
            ),
            "a=rtpmap:<pt> telephone-event/8000 in the answer, or in-band DTMF on both sides",
            "§7 lets the offerer stop listening for a format the answer left out, so RFC 4733 \
             DTMF is not negotiated on this stream. What makes it a one-way fault rather than \
             no DTMF at all is that equipment routinely sends the event anyway on the payload \
             type it offered: the far end receives a payload type it never agreed to and \
             either drops it or decodes it as audio, while DTMF in the other direction works. \
             That asymmetry is the whole of every \"the IVR cannot hear our digits\" ticket.",
        );
    }
}

/// The attribute names a declined stream is still carrying.
///
/// Read off the parsed description rather than the raw body, so this reports
/// only attributes sipnab actually understood. An attribute the parser drops
/// cannot be named here, and claiming a count the parser cannot back would be
/// worse than reporting the ones it can.
fn retained_attributes(media: &SdpMedia) -> Vec<&'static str> {
    let mut out = Vec::new();
    if !media.rtpmap.is_empty() {
        out.push("a=rtpmap");
    }
    if !media.fmtp.is_empty() {
        out.push("a=fmtp");
    }
    if !media.crypto.is_empty() {
        out.push("a=crypto");
    }
    if !media.ice_candidates.is_empty() {
        out.push("a=candidate");
    }
    if media.ptime.is_some() {
        out.push("a=ptime");
    }
    if media.rtcp_mux {
        out.push("a=rtcp-mux");
    }
    if media.rtcp_port.is_some() {
        out.push("a=rtcp");
    }
    out
}

/// RFC 3264 §8.2 — a stream declined with port zero may drop its attributes.
///
/// Reported at notice and as interop because §8.2 is a MAY in both directions:
/// "the answer MAY omit all attributes present previously, and MAY list just a
/// single media format". Keeping them is legal. What makes it worth a line is
/// the `a=crypto` case — SRTP key material published for a stream neither side
/// will ever use — and equipment that reads the attributes of a port-zero
/// stream and allocates for it anyway.
///
/// The offer half is not reported. An offer at port zero is §8.2's own
/// mechanism for removing an existing stream, so its attributes are what the
/// stream had; only the answer is the place §8.2 addresses.
fn rejected_stream_attributes(pair: &OfferAnswer, sink: &mut FindingSink<'_>) {
    if !sink.wants(&REJECTED_STREAM_ATTRIBUTES) {
        return;
    }
    for (m_index, offer, answer) in paired_media(pair) {
        // A stream the OFFER already removed was not declined by this answer.
        if answer.port != 0 || offer.port == 0 {
            continue;
        }
        let retained = retained_attributes(answer);
        if retained.is_empty() {
            continue;
        }
        sink.push(
            &REJECTED_STREAM_ATTRIBUTES,
            pair.answer.index,
            format!(
                "m={} line {m_index} declined with port 0 still carries {}",
                answer.media_type,
                retained.join(", ")
            ),
            format!("m={} 0 {} <one format>", answer.media_type, answer.proto),
            "§8.2 lets a stream at port zero omit every attribute it previously carried, and \
             a declined stream has no use for any of them. An a=crypto line here is SRTP key \
             material published for a stream that will never carry a packet, and equipment \
             that reads attributes before it reads the port allocates a relay leg and a \
             transcoder for a stream nobody answered.",
        );
    }
}

/// The dynamic RTP payload types, RFC 3551 §6: 96 through 127.
const DYNAMIC_PT_RANGE: std::ops::RangeInclusive<u8> = 96..=127;

/// RFC 3264 §8.3.2 — a dynamic payload type keeps its codec for the session.
///
/// # Why the binding is tracked per media stream and not per session
///
/// §8.3.2 scopes it in its own words: "the mapping from a particular dynamic
/// payload type number to a particular codec **within that media stream** MUST
/// NOT change for the duration of a session". A call whose audio `m=` line uses
/// 96 for `opus` and whose video `m=` line uses 96 for `H264` breaks nothing,
/// and a session-wide table would report every such call. The key here is
/// therefore the `m=` line's position, which is also how RFC 3264 §6 pairs
/// offers with answers.
fn dynamic_payload_types(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&DYNAMIC_PT_REBOUND) {
        return;
    }
    // (stream position, payload type) -> the encoding that claimed it first,
    // and the message index that did the claiming.
    let mut bound: Vec<((usize, u8), (String, usize))> = Vec::new();

    for (index, msg) in dialog.messages.iter().enumerate() {
        let Some(sdp) = msg.sdp() else {
            continue;
        };
        for (m_index, media) in sdp.media.iter().enumerate() {
            for map in &media.rtpmap {
                if !DYNAMIC_PT_RANGE.contains(&map.payload_type) {
                    continue;
                }
                let key = (m_index, map.payload_type);
                match bound.iter().find(|(k, _)| *k == key) {
                    None => bound.push((key, (map.encoding.clone(), index))),
                    Some((_, (first, first_index))) => {
                        if first.eq_ignore_ascii_case(&map.encoding) {
                            continue;
                        }
                        sink.push(
                            &DYNAMIC_PT_REBOUND,
                            index,
                            format!(
                                "m= line {m_index} bound payload type {} to {first} in message \
                                 {first_index} and to {} here",
                                map.payload_type, map.encoding
                            ),
                            format!(
                                "payload type {} still meaning {first}, or a different number \
                                 for {}",
                                map.payload_type, map.encoding
                            ),
                            "§8.3.2 fixes a dynamic payload type to one codec for the whole \
                             session, and says why: SDP and the media stream are only loosely \
                             synchronized, so packets encoded under the old mapping are still \
                             in flight when the new one arrives. The receiver decodes them \
                             with the wrong codec, which is heard as a burst of noise at the \
                             moment of the re-INVITE. §8.3.2 permits a second number for the \
                             same codec, which is the correct way to do this.",
                        );
                    }
                }
            }
        }
    }
}

/// The clock rate RFC 7587 §7 requires in an opus `a=rtpmap`.
const OPUS_CLOCK_RATE: u32 = 48000;

/// The channel count RFC 7587 §7 requires in an opus `a=rtpmap`.
const OPUS_CHANNELS: u32 = 2;

/// The `a=rtpmap` encoding name RFC 7587 registers.
const OPUS_ENCODING: &str = "opus";

/// RFC 7587 §7 — an opus `a=rtpmap` reads `opus/48000/2`, always.
///
/// # Why the clock rate is a signaling rule here and not an observation
///
/// RFC 7587 §4.1 states the wire fact — "The RTP timestamp is incremented with
/// a 48000 Hz clock rate for all modes of Opus and all sampling rates" — and it
/// is deliberately not the citation. §4.1 is not RFC 2119 language, and §7's
/// SDP bullet is: "The RTP clock rate in "a=rtpmap" MUST be 48000, and the
/// number of channels MUST be 2."
///
/// The observation half of this defect — opus negotiated while the wire carries
/// 160-octet packets at an 8 kHz cadence — is **not** implemented, and the
/// reason is that it cannot be decided from what a stream records. 160 octets
/// per 20 ms is 64 kbit/s, which is exactly G.711 and is also a legal Opus CBR
/// configuration; separating them needs the RTP timestamp cadence, and the
/// stream store keeps a last timestamp and no first one, so no clock rate can
/// be derived from it. A rule that reported legal Opus CBR as a defect would be
/// switched off in week one, and this one is decidable from the SDP alone.
///
/// A channel count RFC 4566 §6 makes default to one is a violation as much as
/// an explicit `/1` is: `opus/48000` and `opus/48000/1` are the same
/// declaration, and §7's MUST admits neither.
fn opus_rtpmap(dialog: &SipDialog, sink: &mut FindingSink<'_>) {
    if !sink.wants(&OPUS_RTPMAP_RATE) {
        return;
    }
    for (index, msg) in dialog.messages.iter().enumerate() {
        let Some(sdp) = msg.sdp() else {
            continue;
        };
        for (m_index, media) in sdp.media.iter().enumerate() {
            for map in &media.rtpmap {
                if !map.encoding.eq_ignore_ascii_case(OPUS_ENCODING) {
                    continue;
                }
                let channels = map.channels.unwrap_or(1);
                if map.clock_rate == OPUS_CLOCK_RATE && channels == OPUS_CHANNELS {
                    continue;
                }
                sink.push(
                    &OPUS_RTPMAP_RATE,
                    index,
                    format!(
                        "m= line {m_index} declares opus/{}/{channels} on payload type {}",
                        map.clock_rate, map.payload_type
                    ),
                    format!("opus/{OPUS_CLOCK_RATE}/{OPUS_CHANNELS}"),
                    "§7 makes the rtpmap clock rate 48000 and the channel count 2 whatever \
                     the encoder is actually doing, because §4.1 increments the RTP timestamp \
                     at 48 kHz for every Opus mode and every sampling rate. A peer that \
                     believes the declared 8000 computes packet durations six times short: \
                     the jitter buffer sizes itself for a stream that does not exist, and \
                     every RTCP interarrival figure derived from it is wrong by the same \
                     factor. Signal the narrower band with maxplaybackrate in a=fmtp, which \
                     is what RFC 7587's own 16 kHz example does while still writing \
                     opus/48000/2.",
                );
            }
        }
    }
}

/// Tests for the dialog-scoped rules.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::dialog_store::DialogStore;
    use crate::sip::lint::{LintConfig, Linter};
    use crate::sip::message::SipMessage;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixed capture timestamp, advanced one second per message.
    fn ts(offset: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_718_452_800 + offset, 0).unwrap_or_default()
    }

    /// Parse one message of a dialog.
    fn msg(raw: &str, offset: i64) -> SipMessage {
        parse_sip(
            raw.as_bytes(),
            ts(offset),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("test fixture must parse")
    }

    /// Build a store holding one dialog from raw messages, in order.
    ///
    /// `SipDialog` is not `Clone`, so the store outlives the borrow rather than
    /// the dialog being lifted out of it.
    fn store_of(raws: &[&str]) -> DialogStore {
        let mut store = DialogStore::new(16, false);
        for (i, raw) in raws.iter().enumerate() {
            store.process_message(msg(raw, i as i64));
        }
        store
    }

    /// The single dialog a fixture store holds.
    fn only(store: &DialogStore) -> &SipDialog {
        store
            .iter()
            .next()
            .expect("fixture must produce one dialog")
    }

    /// Rule identifiers raised for a dialog.
    fn ids(raws: &[&str]) -> Vec<&'static str> {
        let store = store_of(raws);
        Linter::new(LintConfig::new())
            .lint_dialog(only(&store))
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    /// An INVITE carrying `sdp`, or none when `sdp` is empty.
    fn invite(cseq: u32, to_tag: &str, sdp: &str) -> String {
        let body = if sdp.is_empty() {
            String::new()
        } else {
            "Content-Type: application/sdp\r\n".to_string()
        };
        format!(
            "INVITE sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK{cseq}\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:bob@example.net>{to_tag}\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: {cseq} INVITE\r\n\
             {body}Content-Length: {}\r\n\
             \r\n{sdp}",
            sdp.len()
        )
    }

    /// A 200 OK carrying `sdp`.
    fn ok(cseq: u32, method: &str, sdp: &str) -> String {
        let body = if sdp.is_empty() {
            String::new()
        } else {
            "Content-Type: application/sdp\r\n".to_string()
        };
        format!(
            "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK{cseq}\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:bob@192.0.2.2>\r\n\
             {body}Content-Length: {}\r\n\
             \r\n{sdp}",
            sdp.len()
        )
    }

    /// An ACK with an explicit CSeq number.
    fn ack(cseq: u32) -> String {
        format!(
            "ACK sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK{cseq}a\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: {cseq} ACK\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// An SDP body offering `formats` at `addr:port` with a direction line.
    fn sdp_body(addr: &str, port: u16, formats: &str, direction: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP {formats}\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a={direction}\r\n"
        )
    }

    /// A conformant INVITE/200/ACK exchange raises nothing.
    /// A reliable provisional, in a dialog whose INVITE reached a final answer.
    fn reliable_183(cseq: u32) -> String {
        format!(
            "SIP/2.0 183 Session Progress\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK{cseq}\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: {cseq} INVITE\r\n\
             Require: 100rel\r\n\
             RSeq: 1\r\n\
             Contact: <sip:bob@192.0.2.2>\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// A PRACK acknowledging that provisional.
    fn prack(cseq: u32) -> String {
        format!(
            "PRACK sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKprack{cseq}\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: {cseq} PRACK\r\n\
             RAck: 1 {cseq} INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// A reliable provisional the dialog never acknowledged is reported.
    #[test]
    fn a_reliable_provisional_without_a_prack_is_reported() {
        let got = ids(&[
            &invite(1, "", ""),
            &reliable_183(1),
            &ok(1, "INVITE", ""),
            &ack(1),
        ]);
        assert!(got.contains(&PRACK_MISSING.id), "{got:?}");
    }

    /// A PRACK anywhere in the dialog settles it.
    #[test]
    fn a_dialog_carrying_a_prack_is_silent() {
        let got = ids(&[
            &invite(1, "", ""),
            &reliable_183(1),
            &prack(1),
            &ok(1, "INVITE", ""),
            &ack(1),
        ]);
        assert!(!got.contains(&PRACK_MISSING.id), "{got:?}");
    }

    /// A capture that stops before the final answer reports nothing.
    ///
    /// The guard that keeps this rule off ordinary traffic. A capture is a
    /// window, and a dialog cut off between the provisional and the PRACK has
    /// not shown that the PRACK is missing — only that the file ended. Without
    /// this the rule fires on a large share of any busy trunk.
    #[test]
    fn a_truncated_dialog_is_not_accused_of_a_missing_prack() {
        let got = ids(&[&invite(1, "", ""), &reliable_183(1)]);
        assert!(
            !got.contains(&PRACK_MISSING.id),
            "no final response means the capture never showed the rest: {got:?}"
        );
    }

    /// A provisional that never asked for reliability needs no PRACK.
    #[test]
    fn an_ordinary_provisional_needs_no_prack() {
        let ringing = reliable_183(1)
            .replace("Require: 100rel\r\n", "")
            .replace("RSeq: 1\r\n", "")
            .replace("183 Session Progress", "180 Ringing");
        let got = ids(&[&invite(1, "", ""), &ringing, &ok(1, "INVITE", ""), &ack(1)]);
        assert!(!got.contains(&PRACK_MISSING.id), "{got:?}");
    }

    #[test]
    fn a_conformant_call_raises_nothing() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendrecv")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendrecv")),
            ack(1),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert_eq!(ids(&refs), Vec::<&str>::new());
    }

    /// An ACK whose CSeq does not match its INVITE is reported.
    #[test]
    fn ack_with_the_wrong_cseq_is_reported() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendrecv")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendrecv")),
            ack(2),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert!(ids(&refs).contains(&ACK_CSEQ_MISMATCH.id));
    }

    /// A dialog with no captured INVITE raises no ACK finding.
    ///
    /// A capture that starts mid-call is the common case, and a rule that
    /// treats a missing INVITE as a mismatch reports the capture, not the call.
    #[test]
    fn ack_without_a_captured_invite_is_silent() {
        let raws = [ok(7, "INVITE", ""), ack(7)];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert!(!ids(&refs).contains(&ACK_CSEQ_MISMATCH.id));
    }

    /// An answer sharing no format with the offer is a MUST violation.
    #[test]
    fn answer_with_no_common_format_is_reported() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendrecv")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "8", "sendrecv")),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        let store = store_of(&refs);
        let findings = Linter::new(LintConfig::new()).lint_dialog(only(&store));
        let f = findings
            .iter()
            .find(|f| f.rule_id == ANSWER_NO_COMMON_FORMAT.id)
            .expect("disjoint formats must be reported");
        assert_eq!(f.citation(), "RFC 3264 §6.1");
        assert_eq!(f.message_index, 1);
    }

    /// An answer adding a format the offer lacked is legal, and reports as
    /// interop rather than as a broken MUST.
    ///
    /// §6.1 permits the extra listing outright. A tool that called this illegal
    /// would be citing a rule that says the opposite.
    #[test]
    fn answer_with_an_extra_format_is_interop_not_must() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendrecv")),
            ok(
                1,
                "INVITE",
                &sdp_body("192.0.2.2", 41000, "0 8", "sendrecv"),
            ),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        let store = store_of(&refs);
        let findings = Linter::new(LintConfig::new()).lint_dialog(only(&store));
        let f = findings
            .iter()
            .find(|f| f.rule_id == ANSWER_EXTRA_FORMAT.id)
            .expect("extra format must be reported");
        assert_eq!(f.basis, crate::sip::lint::Basis::Interop);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == ANSWER_NO_COMMON_FORMAT.id)
        );
    }

    /// A stream declined with port zero raises no format finding.
    #[test]
    fn a_declined_stream_raises_no_format_finding() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendrecv")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 0, "8", "sendrecv")),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        let raised = ids(&refs);
        assert!(!raised.contains(&ANSWER_NO_COMMON_FORMAT.id), "{raised:?}");
        assert!(!raised.contains(&ANSWER_EXTRA_FORMAT.id), "{raised:?}");
    }

    /// Answering a `sendonly` offer with `sendonly` is reported.
    #[test]
    fn illegal_answer_direction_is_reported() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendonly")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendonly")),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert!(ids(&refs).contains(&ANSWER_DIRECTION_ILLEGAL.id));
    }

    /// Answering a `sendonly` offer with `recvonly` is correct and silent.
    #[test]
    fn legal_answer_direction_is_silent() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendonly")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "recvonly")),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert!(!ids(&refs).contains(&ANSWER_DIRECTION_ILLEGAL.id));
    }

    /// A re-offer blanking the connection address is reported as a hold.
    #[test]
    fn hold_by_blanked_address_is_reported() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendrecv")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendrecv")),
            ack(1),
            invite(
                2,
                ";tag=a6c85cf",
                &sdp_body("0.0.0.0", 40000, "0", "sendrecv"),
            ),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        let store = store_of(&refs);
        let findings = Linter::new(LintConfig::new()).lint_dialog(only(&store));
        let f = findings
            .iter()
            .find(|f| f.rule_id == HOLD_CONNECTION_ZERO.id)
            .expect("blanked re-offer must be reported");
        assert_eq!(f.citation(), "RFC 3264 §8.4");
        assert_eq!(f.message_index, 3);
    }

    /// An *initial* offer with a blanked address is silent.
    ///
    /// §8.4 keeps that use: an agent that does not yet know its own address.
    /// Reporting it would fire on every third-party call control flow.
    #[test]
    fn blanked_address_in_the_first_offer_is_silent() {
        let raws = [
            invite(1, "", &sdp_body("0.0.0.0", 40000, "0", "sendrecv")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendrecv")),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert!(!ids(&refs).contains(&HOLD_CONNECTION_ZERO.id));
    }

    /// A REGISTER carrying a To tag is reported wherever the capture started.
    #[test]
    fn register_with_a_to_tag_is_reported() {
        let register = "REGISTER sip:example.com SIP/2.0\r\n\
                        Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
                        Max-Forwards: 70\r\n\
                        To: <sip:alice@example.com>;tag=deadbeef\r\n\
                        From: <sip:alice@example.com>;tag=1928301774\r\n\
                        Call-ID: lint-fixture-reg\r\n\
                        CSeq: 1 REGISTER\r\n\
                        Content-Length: 0\r\n\
                        \r\n";
        assert!(ids(&[register]).contains(&TO_TAG_IN_INITIAL_REQUEST.id));
    }

    /// A re-INVITE in a capture that began mid-call is silent.
    ///
    /// The message alone looks identical to the violation. Only the answer
    /// echoing the same tag settles it, and here it does.
    #[test]
    fn mid_dialog_reinvite_is_silent() {
        let raws = [
            invite(
                9,
                ";tag=a6c85cf",
                &sdp_body("192.0.2.1", 40000, "0", "sendrecv"),
            ),
            ok(9, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendrecv")),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert!(!ids(&refs).contains(&TO_TAG_IN_INITIAL_REQUEST.id));
    }

    /// A `SUBSCRIBE` dialog carrying reverse-direction `NOTIFY` traffic is
    /// silent.
    ///
    /// Found against the validation corpus, where the first form of this rule
    /// fired on 2,182 dialogs and 2,160 of them were this exact shape. The
    /// `NOTIFY` travels the other way, so the response to it correctly carries
    /// the subscriber's tag rather than the notifier's — a difference that is
    /// conformance, not a violation, and that a rule comparing against every
    /// response in the dialog reads as a violation every single time.
    #[test]
    fn a_subscribe_dialog_with_notifies_is_silent() {
        let subscribe = "SUBSCRIBE sip:bob@example.net SIP/2.0\r\n\
                         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKsub1\r\n\
                         Max-Forwards: 70\r\n\
                         To: <sip:bob@example.net>;tag=notifier\r\n\
                         From: <sip:alice@example.com>;tag=subscriber\r\n\
                         Call-ID: lint-fixture-sub\r\n\
                         CSeq: 2 SUBSCRIBE\r\n\
                         Event: presence\r\n\
                         Content-Length: 0\r\n\
                         \r\n";
        // The refresh is answered with the tag it addressed. Conformant.
        let sub_ok = "SIP/2.0 200 OK\r\n\
                      Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKsub1\r\n\
                      To: <sip:bob@example.net>;tag=notifier\r\n\
                      From: <sip:alice@example.com>;tag=subscriber\r\n\
                      Call-ID: lint-fixture-sub\r\n\
                      CSeq: 2 SUBSCRIBE\r\n\
                      Content-Length: 0\r\n\
                      \r\n";
        // The NOTIFY runs the other way, so its To is the subscriber.
        let notify = "NOTIFY sip:alice@example.com SIP/2.0\r\n\
                      Via: SIP/2.0/UDP 192.0.2.2:5060;branch=z9hG4bKnot1\r\n\
                      Max-Forwards: 70\r\n\
                      To: <sip:alice@example.com>;tag=subscriber\r\n\
                      From: <sip:bob@example.net>;tag=notifier\r\n\
                      Call-ID: lint-fixture-sub\r\n\
                      CSeq: 1 NOTIFY\r\n\
                      Event: presence\r\n\
                      Content-Length: 0\r\n\
                      \r\n";
        // And its answer carries the subscriber's tag, which differs from the
        // SUBSCRIBE's To tag for entirely correct reasons.
        let notify_ok = "SIP/2.0 200 OK\r\n\
                         Via: SIP/2.0/UDP 192.0.2.2:5060;branch=z9hG4bKnot1\r\n\
                         To: <sip:alice@example.com>;tag=subscriber\r\n\
                         From: <sip:bob@example.net>;tag=notifier\r\n\
                         Call-ID: lint-fixture-sub\r\n\
                         CSeq: 1 NOTIFY\r\n\
                         Content-Length: 0\r\n\
                         \r\n";
        let raised = ids(&[subscribe, sub_ok, notify, notify_ok]);
        assert!(
            !raised.contains(&TO_TAG_IN_INITIAL_REQUEST.id),
            "a conformant SUBSCRIBE/NOTIFY dialog must stay silent: {raised:?}"
        );
    }

    /// A request whose own transaction answers with a different tag is still
    /// reported.
    ///
    /// The narrowing above must not silence the rule altogether: the answer to
    /// *this* request, on *this* branch, choosing its own tag is the evidence
    /// the rule exists for.
    #[test]
    fn a_tag_the_same_transaction_replaced_is_reported() {
        let raws = [
            invite(1, ";tag=inventedbythecaller", ""),
            ok(1, "INVITE", ""),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        assert!(ids(&refs).contains(&TO_TAG_IN_INITIAL_REQUEST.id));
    }

    /// Offer and answer pair by position, and an unanswered offer pairs with
    /// nothing.
    #[test]
    fn offers_pair_with_their_answers() {
        let raws = [
            invite(1, "", &sdp_body("192.0.2.1", 40000, "0", "sendrecv")),
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendrecv")),
            ack(1),
            invite(
                2,
                ";tag=a6c85cf",
                &sdp_body("192.0.2.1", 40002, "0", "sendonly"),
            ),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        let store = store_of(&refs);
        let pairs = offer_answer_pairs(only(&store));
        assert_eq!(pairs.len(), 1, "the unanswered re-offer must not pair");
        assert_eq!(pairs[0].offer.index, 0);
        assert_eq!(pairs[0].answer.index, 1);
    }

    /// An answer with no offer before it pairs with nothing, and does not
    /// become an offer for whatever follows.
    ///
    /// The shape a capture that started mid-call produces: the `ACK` carries
    /// the answer to an offer the capture never saw. Treating it as an offer
    /// would pair it with the next re-offer and compare two offers against each
    /// other, which reports the difference between them as a conformance
    /// defect. Mutation testing found this arm untested.
    #[test]
    fn an_answer_with_no_offer_before_it_pairs_with_nothing() {
        let answer_sdp = sdp_body("192.0.2.1", 40000, "0", "sendrecv");
        let orphan_ack = format!(
            "ACK sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1a\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: 1 ACK\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n{answer_sdp}",
            answer_sdp.len()
        );
        let raws = [
            orphan_ack,
            ok(2, "INVITE", &sdp_body("192.0.2.2", 41000, "8", "sendrecv")),
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        let store = store_of(&refs);
        let pairs = offer_answer_pairs(only(&store));
        assert!(
            pairs.is_empty(),
            "an orphan answer must not become an offer for the next body"
        );
    }

    /// A delayed offer carried in the 2xx pairs with the ACK that answers it.
    #[test]
    fn delayed_offers_pair_with_the_ack() {
        let invite_no_sdp = invite(1, "", "");
        let answer_sdp = sdp_body("192.0.2.1", 40000, "0", "sendrecv");
        let ack_with_sdp = format!(
            "ACK sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1a\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: 1 ACK\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n{answer_sdp}",
            answer_sdp.len()
        );
        let raws = [
            invite_no_sdp,
            ok(1, "INVITE", &sdp_body("192.0.2.2", 41000, "0", "sendrecv")),
            ack_with_sdp,
        ];
        let refs: Vec<&str> = raws.iter().map(String::as_str).collect();
        let store = store_of(&refs);
        let pairs = offer_answer_pairs(only(&store));
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].offer.index, 1, "the 2xx carried the delayed offer");
        assert_eq!(pairs[0].answer.index, 2);
    }

    // ── RFC 3261 §17.1.1.3 — the non-2xx ACK stays on the branch ────────

    /// A final non-2xx response with an explicit status.
    fn final_failure(cseq: u32, code: u16) -> String {
        format!(
            "SIP/2.0 {code} Busy Here\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK{cseq}\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: {cseq} INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// An ACK carrying a chosen branch.
    fn ack_on_branch(cseq: u32, branch: &str) -> String {
        format!(
            "ACK sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: lint-fixture-1\r\n\
             CSeq: {cseq} ACK\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// An ACK to a 486 on a fresh branch is reported.
    #[test]
    fn an_ack_to_a_non_2xx_on_a_new_branch_is_reported() {
        let got = ids(&[
            &invite(1, "", ""),
            &final_failure(1, 486),
            &ack_on_branch(1, "z9hG4bKfresh"),
        ]);
        assert!(got.contains(&ACK_BRANCH_MISMATCH.id), "{got:?}");
    }

    /// An ACK to a 486 reusing the INVITE's branch is silent.
    #[test]
    fn an_ack_to_a_non_2xx_on_the_invite_branch_is_silent() {
        let got = ids(&[
            &invite(1, "", ""),
            &final_failure(1, 486),
            &ack_on_branch(1, "z9hG4bK1"),
        ]);
        assert!(!got.contains(&ACK_BRANCH_MISMATCH.id), "{got:?}");
    }

    /// An ACK to a 2xx on a NEW branch is correct and must stay silent.
    ///
    /// This is the mutation that matters. §17.1.1.3 opens by sending the 2xx
    /// case to §13, where the ACK is its own transaction and §8.1.1.7 requires
    /// a new branch — so dropping the non-2xx guard would report the correct
    /// behavior on every answered call in every capture.
    #[test]
    fn an_ack_to_a_2xx_on_a_new_branch_is_silent() {
        let got = ids(&[
            &invite(1, "", ""),
            &ok(1, "INVITE", ""),
            &ack_on_branch(1, "z9hG4bKbrandnew"),
        ]);
        assert!(!got.contains(&ACK_BRANCH_MISMATCH.id), "{got:?}");
    }

    // ── RFC 3261 §12.1.1 — the response reproduces Record-Route ─────────

    /// Splice header lines into a message just above its `Content-Length`.
    fn with_headers(raw: &str, lines: &[&str]) -> String {
        let mut extra = String::new();
        for line in lines {
            extra.push_str(line);
            extra.push_str("\r\n");
        }
        raw.replacen("Content-Length:", &format!("{extra}Content-Length:"), 1)
    }

    /// A 2xx that drops a recorded route is reported.
    #[test]
    fn a_2xx_dropping_a_record_route_is_reported() {
        let request = with_headers(
            &invite(1, "", ""),
            &[
                "Record-Route: <sip:p2.example.net;lr>",
                "Record-Route: <sip:p1.example.net;lr>",
            ],
        );
        let response = with_headers(
            &ok(1, "INVITE", ""),
            &["Record-Route: <sip:p1.example.net;lr>"],
        );
        let got = ids(&[&request, &response, &ack(1)]);
        assert!(got.contains(&RECORD_ROUTE_NOT_COPIED.id), "{got:?}");
    }

    /// A 2xx that reverses the order is reported.
    ///
    /// §12.1.1 makes the UAS "maintain the order of those values", and §12.1.2
    /// has the caller read the response's list in reverse — so a reversal
    /// silently sends every in-dialog request through the path backwards.
    #[test]
    fn a_2xx_reordering_the_record_route_is_reported() {
        let routes = [
            "Record-Route: <sip:p2.example.net;lr>",
            "Record-Route: <sip:p1.example.net;lr>",
        ];
        let request = with_headers(&invite(1, "", ""), &routes);
        let response = with_headers(&ok(1, "INVITE", ""), &[routes[1], routes[0]]);
        let got = ids(&[&request, &response, &ack(1)]);
        assert!(got.contains(&RECORD_ROUTE_NOT_COPIED.id), "{got:?}");
    }

    /// A 2xx reproducing the list exactly is silent.
    #[test]
    fn a_2xx_copying_the_record_route_is_silent() {
        let routes = [
            "Record-Route: <sip:p2.example.net;lr>",
            "Record-Route: <sip:p1.example.net;lr>",
        ];
        let request = with_headers(&invite(1, "", ""), &routes);
        let response = with_headers(&ok(1, "INVITE", ""), &routes);
        let got = ids(&[&request, &response, &ack(1)]);
        assert!(!got.contains(&RECORD_ROUTE_NOT_COPIED.id), "{got:?}");
    }

    /// A 2xx carrying MORE routes than the request is silent.
    ///
    /// A capture taken before the last recording proxy sees the request
    /// without that proxy's own value and the response with it. That asymmetry
    /// is ordinary at every point that is not the UAS, so a rule comparing for
    /// equality would fire on most proxy-side captures in existence.
    #[test]
    fn a_2xx_carrying_an_extra_record_route_above_the_request_is_silent() {
        let request = with_headers(
            &invite(1, "", ""),
            &["Record-Route: <sip:p1.example.net;lr>"],
        );
        let response = with_headers(
            &ok(1, "INVITE", ""),
            &[
                "Record-Route: <sip:p2.example.net;lr>",
                "Record-Route: <sip:p1.example.net;lr>",
            ],
        );
        let got = ids(&[&request, &response, &ack(1)]);
        assert!(!got.contains(&RECORD_ROUTE_NOT_COPIED.id), "{got:?}");
    }

    /// A dialog whose request recorded nothing is silent whatever the response
    /// says.
    #[test]
    fn a_dialog_with_no_recorded_route_is_silent() {
        let got = ids(&[&invite(1, "", ""), &ok(1, "INVITE", ""), &ack(1)]);
        assert!(!got.contains(&RECORD_ROUTE_NOT_COPIED.id), "{got:?}");
    }

    // ── RFC 3264 — the SDP rules ────────────────────────────────────────

    /// An SDP body with an explicit `m=` line and attribute block.
    fn sdp_with(port: u16, formats: &str, attrs: &[&str]) -> String {
        let mut out = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 192.0.2.1\r\n\
             s=-\r\n\
             c=IN IP4 192.0.2.1\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP {formats}\r\n"
        );
        for a in attrs {
            out.push_str("a=");
            out.push_str(a);
            out.push_str("\r\n");
        }
        out
    }

    /// An offer declaring telephone-event that the answer omits is reported.
    #[test]
    fn telephone_event_dropped_by_the_answer_is_reported() {
        let offer = sdp_with(
            10000,
            "0 101",
            &["rtpmap:0 PCMU/8000", "rtpmap:101 telephone-event/8000"],
        );
        let answer = sdp_with(20000, "0", &["rtpmap:0 PCMU/8000"]);
        let got = ids(&[&invite(1, "", &offer), &ok(1, "INVITE", &answer), &ack(1)]);
        assert!(got.contains(&TELEPHONE_EVENT_ONE_WAY.id), "{got:?}");
    }

    /// An answer that keeps telephone-event is silent.
    #[test]
    fn telephone_event_answered_is_silent() {
        let body = sdp_with(
            10000,
            "0 101",
            &["rtpmap:0 PCMU/8000", "rtpmap:101 telephone-event/8000"],
        );
        let got = ids(&[&invite(1, "", &body), &ok(1, "INVITE", &body), &ack(1)]);
        assert!(!got.contains(&TELEPHONE_EVENT_ONE_WAY.id), "{got:?}");
    }

    /// A stream the answer declined negotiated nothing, so it is silent.
    #[test]
    fn telephone_event_on_a_declined_stream_is_silent() {
        let offer = sdp_with(
            10000,
            "0 101",
            &["rtpmap:0 PCMU/8000", "rtpmap:101 telephone-event/8000"],
        );
        let answer = sdp_with(0, "0", &[]);
        let got = ids(&[&invite(1, "", &offer), &ok(1, "INVITE", &answer), &ack(1)]);
        assert!(!got.contains(&TELEPHONE_EVENT_ONE_WAY.id), "{got:?}");
    }

    /// A declined stream that still carries its attributes is reported, and
    /// the finding names `a=crypto` where one is present.
    #[test]
    fn a_declined_stream_keeping_its_attributes_is_reported() {
        let offer = sdp_with(10000, "0", &["rtpmap:0 PCMU/8000"]);
        let answer = sdp_with(
            0,
            "0",
            &[
                "rtpmap:0 PCMU/8000",
                "crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj",
            ],
        );
        let store = store_of(&[&invite(1, "", &offer), &ok(1, "INVITE", &answer), &ack(1)]);
        let findings = Linter::new(LintConfig::new()).lint_dialog(only(&store));
        let found = findings
            .iter()
            .find(|f| f.rule_id == REJECTED_STREAM_ATTRIBUTES.id)
            .unwrap_or_else(|| panic!("{findings:?}"));
        assert!(found.observed.contains("a=crypto"), "{}", found.observed);
    }

    /// A declined stream stripped of its attributes is silent.
    #[test]
    fn a_bare_declined_stream_is_silent() {
        let offer = sdp_with(10000, "0", &["rtpmap:0 PCMU/8000"]);
        let answer = sdp_with(0, "0", &[]);
        let got = ids(&[&invite(1, "", &offer), &ok(1, "INVITE", &answer), &ack(1)]);
        assert!(!got.contains(&REJECTED_STREAM_ATTRIBUTES.id), "{got:?}");
    }

    /// A stream the OFFER already removed is not this rule's finding.
    ///
    /// §8.2 removes an existing stream by re-offering it at port zero, and the
    /// answer then MUST mark it zero too. Reporting that pair would fire on
    /// every conformant stream teardown.
    #[test]
    fn a_stream_the_offer_removed_is_silent() {
        let removed = sdp_with(0, "0", &["rtpmap:0 PCMU/8000"]);
        let got = ids(&[
            &invite(1, "", &removed),
            &ok(1, "INVITE", &removed),
            &ack(1),
        ]);
        assert!(!got.contains(&REJECTED_STREAM_ATTRIBUTES.id), "{got:?}");
    }

    /// A dynamic payload type rebound to another codec mid-dialog is reported.
    #[test]
    fn a_rebound_dynamic_payload_type_is_reported() {
        let first = sdp_with(10000, "96", &["rtpmap:96 opus/48000/2"]);
        let second = sdp_with(10000, "96", &["rtpmap:96 G729/8000"]);
        let got = ids(&[
            &invite(1, "", &first),
            &ok(1, "INVITE", &first),
            &ack(1),
            &invite(2, ";tag=a6c85cf", &second),
            &ok(2, "INVITE", &second),
        ]);
        assert!(got.contains(&DYNAMIC_PT_REBOUND.id), "{got:?}");
    }

    /// A dynamic payload type that keeps its codec is silent.
    #[test]
    fn a_stable_dynamic_payload_type_is_silent() {
        let body = sdp_with(10000, "96", &["rtpmap:96 opus/48000/2"]);
        let got = ids(&[
            &invite(1, "", &body),
            &ok(1, "INVITE", &body),
            &ack(1),
            &invite(2, ";tag=a6c85cf", &body),
            &ok(2, "INVITE", &body),
        ]);
        assert!(!got.contains(&DYNAMIC_PT_REBOUND.id), "{got:?}");
    }

    /// Payload type 96 meaning different things in two different `m=` lines is
    /// silent.
    ///
    /// §8.3.2 scopes the binding "within that media stream". A session-wide
    /// table would report every call whose audio and video streams both start
    /// their dynamic numbering at 96, which is most of them.
    #[test]
    fn one_number_in_two_streams_is_not_a_rebinding() {
        let body = "v=0\r\n\
             o=- 1 1 IN IP4 192.0.2.1\r\n\
             s=-\r\n\
             c=IN IP4 192.0.2.1\r\n\
             t=0 0\r\n\
             m=audio 10000 RTP/AVP 96\r\n\
             a=rtpmap:96 opus/48000/2\r\n\
             m=video 10002 RTP/AVP 96\r\n\
             a=rtpmap:96 H264/90000\r\n";
        let got = ids(&[&invite(1, "", body), &ok(1, "INVITE", body), &ack(1)]);
        assert!(!got.contains(&DYNAMIC_PT_REBOUND.id), "{got:?}");
    }

    /// A static payload type is outside the rule's range.
    ///
    /// 0 through 95 are assigned by RFC 3551, not negotiated, so §8.3.2's
    /// sentence about "a particular dynamic payload type number" does not
    /// reach them.
    #[test]
    fn a_static_payload_type_is_outside_the_dynamic_range() {
        let first = sdp_with(10000, "8", &["rtpmap:8 PCMA/8000"]);
        let second = sdp_with(10000, "8", &["rtpmap:8 L8/8000"]);
        let got = ids(&[
            &invite(1, "", &first),
            &ok(1, "INVITE", &first),
            &ack(1),
            &invite(2, ";tag=a6c85cf", &second),
        ]);
        assert!(!got.contains(&DYNAMIC_PT_REBOUND.id), "{got:?}");
    }

    /// `opus/8000` is reported, and the expectation quotes the required form.
    #[test]
    fn an_opus_rtpmap_at_the_wrong_clock_rate_is_reported() {
        let body = sdp_with(10000, "96", &["rtpmap:96 opus/8000/2"]);
        let store = store_of(&[&invite(1, "", &body)]);
        let findings = Linter::new(LintConfig::new()).lint_dialog(only(&store));
        let found = findings
            .iter()
            .find(|f| f.rule_id == OPUS_RTPMAP_RATE.id)
            .unwrap_or_else(|| panic!("{findings:?}"));
        assert_eq!(found.expected, "opus/48000/2");
    }

    /// `opus/48000` with no channel count is the same declaration as
    /// `opus/48000/1`, and §7 admits neither.
    #[test]
    fn an_opus_rtpmap_without_a_channel_count_is_reported() {
        for encoding in ["opus/48000", "opus/48000/1"] {
            let body = sdp_with(10000, "96", &[&format!("rtpmap:96 {encoding}")]);
            let got = ids(&[&invite(1, "", &body)]);
            assert!(got.contains(&OPUS_RTPMAP_RATE.id), "{encoding}: {got:?}");
        }
    }

    /// `opus/48000/2` is silent, whatever `a=fmtp` narrows it to.
    #[test]
    fn a_conformant_opus_rtpmap_is_silent() {
        let body = sdp_with(
            10000,
            "96",
            &["rtpmap:96 opus/48000/2", "fmtp:96 maxplaybackrate=16000"],
        );
        let got = ids(&[&invite(1, "", &body)]);
        assert!(!got.contains(&OPUS_RTPMAP_RATE.id), "{got:?}");
    }
}
