// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDP (Session Description Protocol) parser for SIP message bodies.
//!
//! Parses RFC 4566 SDP session descriptions extracted from SIP message
//! bodies. Handles session-level and media-level attributes including
//! rtpmap, fmtp, crypto (SDES), ICE candidates, and directionality.

use crate::error::ParseError;

/// A parsed SDP session description (RFC 4566).
#[derive(Debug, Clone)]
pub struct SdpSession {
    /// Origin line (`o=`).
    pub origin: Option<String>,
    /// Session name (`s=`).
    pub session_name: Option<String>,
    /// Session-level connection data (`c=`).
    pub connection: Option<SdpConnection>,
    /// Media descriptions (`m=` lines with their attributes).
    pub media: Vec<SdpMedia>,
}

/// Connection data from a `c=` line.
#[derive(Debug, Clone)]
pub struct SdpConnection {
    /// IP address extracted from the connection line.
    pub addr: String,
}

/// A single media description (`m=` line) with its attributes.
#[derive(Debug, Clone)]
pub struct SdpMedia {
    /// Media type: `"audio"`, `"video"`, `"image"` (T.38), etc.
    pub media_type: String,
    /// Transport port number.
    pub port: u16,
    /// Transport protocol: `"RTP/AVP"`, `"RTP/SAVP"`, `"udptl"`, etc.
    pub proto: String,
    /// Payload type numbers or format strings.
    pub formats: Vec<String>,
    /// Media-level connection data (`c=`), overrides session-level if present.
    pub connection: Option<SdpConnection>,
    /// Stream direction attribute.
    pub direction: SdpDirection,
    /// `a=rtpmap` entries mapping payload types to encodings.
    pub rtpmap: Vec<RtpMap>,
    /// `a=fmtp` entries (raw format parameter strings).
    pub fmtp: Vec<String>,
    /// Packetization time from `a=ptime`.
    pub ptime: Option<u32>,
    /// SDES-SRTP crypto attributes from `a=crypto` lines.
    pub crypto: Vec<SdpCrypto>,
    /// ICE candidate lines from `a=candidate` attributes.
    pub ice_candidates: Vec<String>,
    /// Whether this media description carries `a=rtcp-mux` (RFC 5761 §5.1.1).
    ///
    /// In an offer it requests RTP and RTCP on one port; in an answer it agrees.
    /// The pair matters: RFC 5761 §5.1.1 makes an offerer whose answer stayed
    /// silent send RTCP on the separate port after all, so an offer and an
    /// answer are two different facts and a `bool` per description holds both.
    pub rtcp_mux: bool,
    /// Explicit RTCP port from `a=rtcp:<port>` (RFC 3605 §2.1), when present.
    ///
    /// Without it RTCP goes to the RTP port plus one (RFC 3264 §6.1), which is
    /// what makes "RTCP arrived somewhere else" a decidable observation.
    pub rtcp_port: Option<u16>,
}

/// Stream directionality attribute.
///
/// `Copy` because it is a fieldless enum passed by value throughout the
/// offer/answer rules, where `&SdpDirection` would buy nothing and clutter
/// every comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpDirection {
    /// Both send and receive (default).
    SendRecv,
    /// Send only.
    SendOnly,
    /// Receive only.
    RecvOnly,
    /// Neither send nor receive.
    Inactive,
}

/// An RTP payload type mapping from `a=rtpmap`.
#[derive(Debug, Clone)]
pub struct RtpMap {
    /// RTP payload type number (0-127).
    pub payload_type: u8,
    /// Encoding name (e.g., `"PCMU"`, `"opus"`, `"telephone-event"`).
    pub encoding: String,
    /// Clock rate in Hz (e.g., 8000, 48000).
    pub clock_rate: u32,
    /// Number of channels, if specified.
    pub channels: Option<u32>,
}

/// SDES-SRTP crypto attribute from `a=crypto`.
#[derive(Debug, Clone)]
pub struct SdpCrypto {
    /// Crypto attribute tag number.
    pub tag: u32,
    /// Crypto suite name (e.g., `"AES_CM_128_HMAC_SHA1_80"`).
    pub suite: String,
    /// Key parameters (e.g., `"inline:base64key|salt"`).
    pub key_params: String,
}

/// The RFC 8866 origin tuple that identifies a media session.
///
/// # Why a tuple and not `sess-id`
///
/// RFC 8866 §5.2 (which obsoletes RFC 4566) is explicit that
/// "the tuple of `<username>`, `<sess-id>`, `<nettype>`, `<addrtype>`, and
/// `<unicast-address>` forms a globally unique identifier for the session".
///
/// `sess-id` ALONE is not unique, and the RFC recommends deriving it from a
/// timestamp — so two unrelated calls placed by the same user agent inside the
/// same second can carry the same `sess-id`. Correlating on that field by
/// itself would manufacture links between unrelated calls, which is worse than
/// finding none.
///
/// # Why `sess-version` is deliberately excluded
///
/// It is not part of the uniqueness tuple, and excluding it is what makes this
/// useful. `sess-version` increments on every modification to the session
/// description, so a re-INVITE — hold, resume, codec change, re-anchoring —
/// bumps it. Including it would break correlation the moment a call was put on
/// hold, which is precisely when someone is looking.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SdpOriginKey {
    /// `<username>`; often `-` when the tool does not supply one.
    pub username: String,
    /// `<sess-id>`. Not unique alone — see the type documentation.
    pub sess_id: String,
    /// `<nettype>`, e.g. `IN`.
    pub nettype: String,
    /// `<addrtype>`, e.g. `IP4`.
    pub addrtype: String,
    /// `<unicast-address>` of the session originator.
    pub unicast_address: String,
}

impl SdpOriginKey {
    /// Parse an `o=` VALUE (everything after `o=`) into the uniqueness tuple.
    ///
    /// Returns `None` unless all six fields are present: a short origin line is
    /// malformed, and guessing which field is missing would be inventing one.
    /// `sess-version` is parsed past and discarded by design.
    #[must_use]
    pub fn parse(origin_value: &str) -> Option<Self> {
        let f: Vec<&str> = origin_value.split_whitespace().collect();
        // username sess-id sess-version nettype addrtype unicast-address
        if f.len() != 6 {
            return None;
        }
        Some(Self {
            username: f[0].to_string(),
            sess_id: f[1].to_string(),
            // f[2] is sess-version, excluded on purpose.
            nettype: f[3].to_string(),
            addrtype: f[4].to_string(),
            unicast_address: f[5].to_string(),
        })
    }
}

/// Parse an SDP body from raw bytes into an [`SdpSession`].
///
/// Lines may be separated by `\r\n` or bare `\n`. The version line (`v=0`)
/// must be present; other fields are optional.
///
/// # Errors
///
/// [`ParseError::Empty`] for an empty body, [`ParseError::InvalidUtf8`]
/// for non-UTF-8 bytes, [`ParseError::SdpMissingVersion`] /
/// [`ParseError::BadSdpVersion`] for a missing or non-zero `v=` line.
///
/// # Examples
///
/// ```
/// let sdp = sipnab::sip::sdp::parse_sdp(
///     b"v=0\r\n\
///       c=IN IP4 10.0.0.2\r\n\
///       m=audio 49170 RTP/AVP 0\r\n\
///       a=rtpmap:0 PCMU/8000\r\n",
/// )?;
/// assert_eq!(sdp.media.len(), 1);
/// assert_eq!(sdp.media[0].media_type, "audio");
/// assert_eq!(sdp.media[0].port, 49170);
/// assert_eq!(sdp.media[0].rtpmap[0].encoding, "PCMU");
/// # Ok::<(), sipnab::ParseError>(())
/// ```
pub fn parse_sdp(body: &[u8]) -> Result<SdpSession, ParseError> {
    if body.is_empty() {
        return Err(ParseError::Empty { what: "SDP body" });
    }

    let text =
        std::str::from_utf8(body).map_err(|_| ParseError::InvalidUtf8 { what: "SDP body" })?;

    // Validate version line. `str::lines()` is a lazy iterator that borrows
    // `text` without allocating, so we can walk it here for validation and
    // again below for the main parse loop.
    let first_nonempty = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or(ParseError::SdpMissingVersion)?;

    let version_value = first_nonempty
        .strip_prefix("v=")
        .ok_or(ParseError::SdpMissingVersion)?;
    if version_value.trim() != "0" {
        return Err(ParseError::BadSdpVersion {
            version: version_value.trim().to_string(),
        });
    }

    let mut session = SdpSession {
        origin: None,
        session_name: None,
        connection: None,
        media: Vec::new(),
    };

    // Track whether we are inside a media section
    let mut in_media = false;

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }

        // SDP lines have the form "X=value" where X is a single character
        if line.len() < 2 || line.as_bytes()[1] != b'=' {
            continue;
        }

        let tag = line.as_bytes()[0];
        let value = &line[2..];

        match tag {
            b'v' => {
                // Already validated above
            }
            b'o' if !in_media => {
                session.origin = Some(value.to_string());
            }
            b's' if !in_media => {
                session.session_name = Some(value.to_string());
            }
            b'c' => {
                let conn = parse_connection(value);
                if in_media {
                    if let Some(media) = session.media.last_mut() {
                        media.connection = conn;
                    }
                } else {
                    session.connection = conn;
                }
            }
            b'm' => {
                in_media = true;
                if let Some(media) = parse_media_line(value) {
                    session.media.push(media);
                }
            }
            b'a' if in_media => {
                if let Some(media) = session.media.last_mut() {
                    parse_attribute(value, media);
                }
            }
            _ => {
                // Ignore unknown or session-level lines we don't need
            }
        }
    }

    Ok(session)
}

/// Return the effective connection address for a media section.
///
/// Uses the media-level `c=` address if present, otherwise falls back
/// to the session-level `c=` address.
pub fn effective_address(media: &SdpMedia, session: &SdpSession) -> Option<String> {
    media
        .connection
        .as_ref()
        .or(session.connection.as_ref())
        .map(|c| c.addr.clone())
}

/// Encoding name for a payload type statically assigned by RFC 3551, or
/// `None` for the dynamic and unassigned range.
///
/// An `a=rtpmap` is only *required* for the dynamic types (96-127). RFC 3551
/// §6 binds the numbers below permanently, so `m=audio 8000 RTP/AVP 0 8` is a
/// complete offer of G.711 µ-law and A-law with nothing further to state —
/// which is exactly what most SBCs and hardware phones send for plain G.711.
///
/// Reading codecs from `a=rtpmap` alone therefore reports *no codecs* for a
/// large share of real traffic, and an empty codec list is not a neutral
/// answer: it reaches an operator as "the far end offered nothing".
///
/// Table 4 (audio) and Table 5 (video) are transcribed in full, including the
/// entries marked reserved. 1 and 2 were assigned to 1016 and G721/G726-32 in
/// RFC 1890 and reserved when RFC 3551 obsoleted it; captures predating that
/// still carry them, so they are named as reserved rather than silently
/// dropped — a payload type that decodes to nothing is a finding, not a blank.
///
/// Types 19-24, 27, 29, 30 and 35-95 are unassigned and yield `None`.
#[must_use]
pub fn static_payload_name(payload_type: u8) -> Option<&'static str> {
    Some(match payload_type {
        // Table 4 — audio.
        0 => "PCMU",
        3 => "GSM",
        4 => "G723",
        5 => "DVI4", // 8 kHz
        6 => "DVI4", // 16 kHz
        7 => "LPC",
        8 => "PCMA",
        9 => "G722",
        10 => "L16", // stereo
        11 => "L16", // mono
        12 => "QCELP",
        13 => "CN",
        14 => "MPA",
        15 => "G728",
        16 => "DVI4", // 11.025 kHz
        17 => "DVI4", // 22.05 kHz
        18 => "G729",
        // Table 5 — video, and one audio/video multiplex.
        25 => "CelB",
        26 => "JPEG",
        28 => "nv",
        31 => "H261",
        32 => "MPV",
        33 => "MP2T",
        34 => "H263",
        // Reserved by RFC 3551 §6, previously assigned by RFC 1890.
        1 | 2 => "reserved",
        _ => return None,
    })
}

/// Parse a `c=` line value (e.g., `"IN IP4 10.0.0.1"`) into an [`SdpConnection`].
/// Returns `None` when fewer than three whitespace-separated fields are present.
fn parse_connection(value: &str) -> Option<SdpConnection> {
    // Format: IN IP4 addr  or  IN IP6 addr
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() >= 3 {
        Some(SdpConnection {
            addr: parts[2].to_string(),
        })
    } else {
        None
    }
}

/// Parse an `m=` line value (e.g., `"audio 20000 RTP/AVP 0 8 18 101"`) into an [`SdpMedia`].
/// Returns `None` when fewer than three fields are present or the port is
/// not a valid `u16`. Attribute fields start empty and direction defaults
/// to `sendrecv`.
fn parse_media_line(value: &str) -> Option<SdpMedia> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let media_type = parts[0].to_string();
    let port: u16 = parts[1].parse().ok()?;
    let proto = parts[2].to_string();
    let formats: Vec<String> = parts[3..].iter().map(|s| (*s).to_string()).collect();

    Some(SdpMedia {
        media_type,
        port,
        proto,
        formats,
        connection: None,
        direction: SdpDirection::SendRecv,
        rtpmap: Vec::new(),
        fmtp: Vec::new(),
        ptime: None,
        crypto: Vec::new(),
        ice_candidates: Vec::new(),
        rtcp_mux: false,
        rtcp_port: None,
    })
}

/// Parse a single `a=` attribute value and apply it to the current media section.
///
/// # Arguments
///
/// * `value` — the attribute text after `a=` (e.g. `"rtpmap:0 PCMU/8000"`).
/// * `media` — the media description the attribute belongs to.
///
/// # Side effects
///
/// Mutates `media` in place: sets `direction` for bare direction attributes,
/// and appends to `rtpmap`, `fmtp`, `crypto`, or `ice_candidates` (or sets
/// `ptime`) for the corresponding `name:value` attributes. Unrecognized
/// attributes are ignored.
fn parse_attribute(value: &str, media: &mut SdpMedia) {
    // Direction attributes (no colon)
    match value {
        "sendrecv" => {
            media.direction = SdpDirection::SendRecv;
            return;
        }
        "sendonly" => {
            media.direction = SdpDirection::SendOnly;
            return;
        }
        "recvonly" => {
            media.direction = SdpDirection::RecvOnly;
            return;
        }
        "inactive" => {
            media.direction = SdpDirection::Inactive;
            return;
        }
        // RFC 5761 §5.1.1: a flag attribute, no value. In an offer it asks for
        // RTP and RTCP on one port, in an answer it agrees.
        "rtcp-mux" => {
            media.rtcp_mux = true;
            return;
        }
        _ => {}
    }

    // Attributes with values (name:value)
    if let Some(rest) = value.strip_prefix("rtpmap:") {
        if let Some(map) = parse_rtpmap(rest) {
            media.rtpmap.push(map);
        }
    } else if let Some(rest) = value.strip_prefix("fmtp:") {
        media.fmtp.push(rest.to_string());
    } else if let Some(rest) = value.strip_prefix("ptime:") {
        media.ptime = rest.trim().parse().ok();
    } else if let Some(rest) = value.strip_prefix("crypto:") {
        if let Some(crypto) = parse_crypto(rest) {
            media.crypto.push(crypto);
        }
    } else if let Some(rest) = value.strip_prefix("candidate:") {
        media.ice_candidates.push(rest.to_string());
    } else if let Some(rest) = value.strip_prefix("rtcp:") {
        // RFC 3605 §2.1: `a=rtcp:<port> [nettype space addrtype space
        // connection-address]`. Only the port is read here — the optional
        // address redirects RTCP elsewhere entirely, which is a separate
        // question from which port it lands on.
        media.rtcp_port = rest.split_whitespace().next().and_then(|p| p.parse().ok());
    }
}

/// Parse an `a=rtpmap` value (e.g., `"0 PCMU/8000"` or `"111 opus/48000/2"`).
/// Returns `None` when the payload type, encoding, or clock rate is missing
/// or non-numeric, or when the payload type is outside the 7-bit RFC 3551
/// range (0–127).
fn parse_rtpmap(value: &str) -> Option<RtpMap> {
    let mut parts = value.splitn(2, ' ');
    let pt_str = parts.next()?.trim();
    let encoding_part = parts.next()?.trim();

    let payload_type: u8 = pt_str.parse().ok()?;
    // RFC 3551: RTP payload types are 7-bit (0–127). Reject anything larger,
    // matching the parser's convention of skipping malformed entries.
    if payload_type > 127 {
        return None;
    }

    let mut slash_parts = encoding_part.splitn(3, '/');
    let encoding = slash_parts.next()?.to_string();
    let clock_rate: u32 = slash_parts.next()?.parse().ok()?;
    let channels: Option<u32> = slash_parts.next().and_then(|c| c.parse().ok());

    Some(RtpMap {
        payload_type,
        encoding,
        clock_rate,
        channels,
    })
}

/// Parse an `a=crypto` value (e.g., `"1 AES_CM_128_HMAC_SHA1_80 inline:key"`).
/// Returns `None` when the tag is non-numeric or fewer than three
/// space-separated fields are present.
fn parse_crypto(value: &str) -> Option<SdpCrypto> {
    let mut parts = value.splitn(3, ' ');
    let tag: u32 = parts.next()?.trim().parse().ok()?;
    let suite = parts.next()?.trim().to_string();
    let key_params = parts.next()?.trim().to_string();

    Some(SdpCrypto {
        tag,
        suite,
        key_params,
    })
}

/// Tests for SDP session/media/attribute parsing and error handling.
#[cfg(test)]
mod tests {
    use super::SdpOriginKey;

    const ORIGIN_A: &str = "alice 2890844526 2890842807 IN IP4 198.51.100.7";

    #[test]
    fn the_origin_key_is_the_rfc8866_uniqueness_tuple() {
        let k = SdpOriginKey::parse(ORIGIN_A).expect("parses");
        assert_eq!(k.username, "alice");
        assert_eq!(k.sess_id, "2890844526");
        assert_eq!(k.nettype, "IN");
        assert_eq!(k.addrtype, "IP4");
        assert_eq!(k.unicast_address, "198.51.100.7");
    }

    /// `sess-version` is NOT part of the tuple, and that is what makes the key
    /// useful: a re-INVITE (hold, resume, codec change) bumps it, and a key
    /// that included it would stop matching exactly when someone is looking.
    #[test]
    fn a_bumped_sess_version_is_still_the_same_session() {
        let before = SdpOriginKey::parse(ORIGIN_A).expect("parses");
        let after =
            SdpOriginKey::parse("alice 2890844526 2890842999 IN IP4 198.51.100.7").expect("parses");
        assert_eq!(before, after, "a re-INVITE must not break correlation");
    }

    /// THE fabrication guard. RFC 8866 recommends deriving `sess-id` from a
    /// timestamp, so two unrelated calls from one user agent in the same second
    /// can share it. Matching on `sess-id` alone would invent a link.
    #[test]
    fn a_shared_sess_id_alone_is_not_the_same_session() {
        let one = SdpOriginKey::parse(ORIGIN_A).expect("parses");
        let other =
            SdpOriginKey::parse("bob 2890844526 2890842807 IN IP4 203.0.113.9").expect("parses");
        assert_eq!(one.sess_id, other.sess_id, "same sess-id, by construction");
        assert_ne!(one, other, "but a different session — the tuple decides");
    }

    /// Anything that is not exactly six fields is refused, in BOTH directions.
    ///
    /// The over-long case is not hypothetical: scanning 10,207 origin lines
    /// across the local corpus found 10,197 with exactly six fields and 10 with
    /// seven. `<username>` is a `non-ws-string` in RFC 8866, so a seventh field
    /// means the line is malformed and which field is the address is a guess.
    /// Refusing keeps a guess out of a key whose entire value is exactness.
    #[test]
    fn only_a_six_field_origin_line_is_accepted() {
        // Five: guessing which one is missing would invent it.
        assert!(SdpOriginKey::parse("alice 2890844526 IN IP4 198.51.100.7").is_none());
        // Seven: measured in the wild, 10 of 10,207.
        assert!(
            SdpOriginKey::parse("alice 2890844526 2890842807 IN IP4 198.51.100.7 extra").is_none()
        );
        assert!(SdpOriginKey::parse("").is_none());
        // And the conforming case still passes, or the test above proves nothing.
        assert!(SdpOriginKey::parse(ORIGIN_A).is_some());
    }
    use super::*;

    /// `a=rtcp-mux` and `a=rtcp:` are read, and their absence stays absent.
    ///
    /// Both were parsed as unknown attributes and dropped. RFC 5761 §5.1.1
    /// makes the offer/answer pair decide which port RTCP lands on, so a tool
    /// that cannot see the attribute cannot tell a conformant capture from one
    /// where RTCP went somewhere nobody agreed to.
    #[test]
    fn rtcp_attributes_are_parsed() {
        let muxed = parse_sdp(
            b"v=0\r\n\
              c=IN IP4 192.0.2.1\r\n\
              m=audio 49170 RTP/AVP 97\r\n\
              a=rtpmap:97 iLBC/8000\r\n\
              a=rtcp-mux\r\n",
        )
        .expect("muxed SDP must parse");
        assert!(muxed.media[0].rtcp_mux);
        assert_eq!(muxed.media[0].rtcp_port, None);

        let explicit = parse_sdp(
            b"v=0\r\n\
              c=IN IP4 192.0.2.1\r\n\
              m=audio 49170 RTP/AVP 0\r\n\
              a=rtcp:53020 IN IP4 192.0.2.9\r\n",
        )
        .expect("explicit RTCP port must parse");
        assert!(!explicit.media[0].rtcp_mux);
        assert_eq!(explicit.media[0].rtcp_port, Some(53020));

        let plain = parse_sdp(
            b"v=0\r\n\
              c=IN IP4 192.0.2.1\r\n\
              m=audio 49170 RTP/AVP 0\r\n",
        )
        .expect("plain SDP must parse");
        assert!(!plain.media[0].rtcp_mux);
        assert_eq!(plain.media[0].rtcp_port, None);
    }

    /// Minimal SDP with one audio media line.
    #[test]
    fn parse_minimal_sdp() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=sipnab\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0\r\n";

        let session = parse_sdp(sdp).expect("should parse minimal SDP");
        assert_eq!(session.origin.as_deref(), Some("- 0 0 IN IP4 10.0.0.1"));
        assert_eq!(session.session_name.as_deref(), Some("sipnab"));
        assert_eq!(
            session.connection.as_ref().map(|c| c.addr.as_str()),
            Some("10.0.0.1")
        );
        assert_eq!(session.media.len(), 1);

        let audio = &session.media[0];
        assert_eq!(audio.media_type, "audio");
        assert_eq!(audio.port, 20000);
        assert_eq!(audio.proto, "RTP/AVP");
        assert_eq!(audio.formats, vec!["0"]);
        assert_eq!(audio.direction, SdpDirection::SendRecv);
    }

    /// Multiple media lines (audio + video).
    #[test]
    fn parse_multiple_media() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0 8\r\n\
            m=video 30000 RTP/AVP 96\r\n";

        let session = parse_sdp(sdp).expect("should parse multi-media SDP");
        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].media_type, "audio");
        assert_eq!(session.media[0].port, 20000);
        assert_eq!(session.media[1].media_type, "video");
        assert_eq!(session.media[1].port, 30000);
    }

    /// rtpmap entries are correctly parsed.
    #[test]
    fn parse_rtpmap_entries() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0 8 111\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=rtpmap:8 PCMA/8000\r\n\
            a=rtpmap:111 opus/48000/2\r\n";

        let session = parse_sdp(sdp).expect("should parse rtpmap SDP");
        let audio = &session.media[0];
        assert_eq!(audio.rtpmap.len(), 3);

        assert_eq!(audio.rtpmap[0].payload_type, 0);
        assert_eq!(audio.rtpmap[0].encoding, "PCMU");
        assert_eq!(audio.rtpmap[0].clock_rate, 8000);
        assert!(audio.rtpmap[0].channels.is_none());

        assert_eq!(audio.rtpmap[2].payload_type, 111);
        assert_eq!(audio.rtpmap[2].encoding, "opus");
        assert_eq!(audio.rtpmap[2].clock_rate, 48000);
        assert_eq!(audio.rtpmap[2].channels, Some(2));
    }

    /// An rtpmap with a payload type above the 7-bit RFC 3551 range
    /// (0–127) is rejected and not recorded.
    #[test]
    fn parse_rtpmap_rejects_payload_type_above_127() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0 128\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=rtpmap:128 opus/48000/2\r\n";

        let session = parse_sdp(sdp).expect("should parse SDP");
        let audio = &session.media[0];
        // The pt=128 rtpmap is out of the 7-bit range and must be skipped;
        // only the valid pt=0 entry survives.
        assert_eq!(audio.rtpmap.len(), 1);
        assert_eq!(audio.rtpmap[0].payload_type, 0);
    }

    /// The maximum valid 7-bit payload type (127) is still accepted.
    #[test]
    fn parse_rtpmap_accepts_payload_type_127() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 127\r\n\
            a=rtpmap:127 opus/48000/2\r\n";

        let session = parse_sdp(sdp).expect("should parse SDP");
        assert_eq!(session.media[0].rtpmap.len(), 1);
        assert_eq!(session.media[0].rtpmap[0].payload_type, 127);
    }

    /// `a=crypto` lines are extracted correctly.
    #[test]
    fn parse_crypto_line() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/SAVP 0\r\n\
            a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj\r\n";

        let session = parse_sdp(sdp).expect("should parse crypto SDP");
        let audio = &session.media[0];
        assert_eq!(audio.crypto.len(), 1);
        assert_eq!(audio.crypto[0].tag, 1);
        assert_eq!(audio.crypto[0].suite, "AES_CM_128_HMAC_SHA1_80");
        assert!(audio.crypto[0].key_params.starts_with("inline:"));
    }

    /// `a=sendonly` sets direction correctly.
    #[test]
    fn parse_sendonly_direction() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0\r\n\
            a=sendonly\r\n";

        let session = parse_sdp(sdp).expect("should parse sendonly SDP");
        assert_eq!(session.media[0].direction, SdpDirection::SendOnly);
    }

    /// Media-level `c=` overrides session-level `c=`.
    #[test]
    fn media_connection_overrides_session() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0\r\n\
            c=IN IP4 192.168.1.100\r\n";

        let session = parse_sdp(sdp).expect("should parse media-level c=");
        assert_eq!(
            session.connection.as_ref().map(|c| c.addr.as_str()),
            Some("10.0.0.1")
        );
        assert_eq!(
            effective_address(&session.media[0], &session).as_deref(),
            Some("192.168.1.100")
        );
    }

    /// ICE candidates are collected.
    #[test]
    fn parse_ice_candidates() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0\r\n\
            a=candidate:1 1 UDP 2130706431 10.0.0.1 20000 typ host\r\n\
            a=candidate:2 1 UDP 1694498815 203.0.113.1 20000 typ srflx\r\n";

        let session = parse_sdp(sdp).expect("should parse ICE SDP");
        assert_eq!(session.media[0].ice_candidates.len(), 2);
        assert!(session.media[0].ice_candidates[0].contains("typ host"));
        assert!(session.media[0].ice_candidates[1].contains("typ srflx"));
    }

    /// T.38 `m=image` line is parsed correctly.
    #[test]
    fn parse_t38_image() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=image 49170 udptl t38\r\n";

        let session = parse_sdp(sdp).expect("should parse T.38 SDP");
        assert_eq!(session.media.len(), 1);
        assert_eq!(session.media[0].media_type, "image");
        assert_eq!(session.media[0].proto, "udptl");
        assert_eq!(session.media[0].formats, vec!["t38"]);
    }

    /// Missing `v=` line produces an error.
    #[test]
    fn malformed_missing_version() {
        let sdp = b"o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n";

        let result = parse_sdp(sdp);
        assert!(result.is_err(), "SDP without v= should error");
    }

    /// Empty body produces an error.
    #[test]
    fn empty_body_error() {
        let result = parse_sdp(b"");
        assert!(result.is_err(), "Empty SDP should error");
    }

    /// SDP with bare `\n` line endings parses correctly.
    #[test]
    fn parse_bare_lf_endings() {
        let sdp = b"v=0\n\
            o=- 0 0 IN IP4 10.0.0.1\n\
            s=-\n\
            c=IN IP4 10.0.0.1\n\
            t=0 0\n\
            m=audio 20000 RTP/AVP 0\n";

        let session = parse_sdp(sdp).expect("should parse LF-only SDP");
        assert_eq!(session.media.len(), 1);
        assert_eq!(session.media[0].media_type, "audio");
    }

    /// `a=ptime` is parsed.
    #[test]
    fn parse_ptime() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0\r\n\
            a=ptime:20\r\n";

        let session = parse_sdp(sdp).expect("should parse ptime SDP");
        assert_eq!(session.media[0].ptime, Some(20));
    }

    /// `a=fmtp` lines are collected.
    #[test]
    fn parse_fmtp() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 101\r\n\
            a=fmtp:101 0-16\r\n";

        let session = parse_sdp(sdp).expect("should parse fmtp SDP");
        assert_eq!(session.media[0].fmtp, vec!["101 0-16"]);
    }

    /// Session without media-level `c=` falls back to session `c=`.
    #[test]
    fn effective_address_session_fallback() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0\r\n";

        let session = parse_sdp(sdp).expect("should parse");
        assert_eq!(
            effective_address(&session.media[0], &session).as_deref(),
            Some("10.0.0.1")
        );
    }

    /// IPv6 connection line.
    #[test]
    fn parse_ipv6_connection() {
        let sdp = b"v=0\r\n\
            o=- 0 0 IN IP6 ::1\r\n\
            s=-\r\n\
            c=IN IP6 2001:db8::1\r\n\
            t=0 0\r\n\
            m=audio 20000 RTP/AVP 0\r\n";

        let session = parse_sdp(sdp).expect("should parse IPv6 SDP");
        assert_eq!(
            session.connection.as_ref().map(|c| c.addr.as_str()),
            Some("2001:db8::1")
        );
    }
}
