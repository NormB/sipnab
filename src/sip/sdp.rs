//! SDP (Session Description Protocol) parser for SIP message bodies.
//!
//! Parses RFC 4566 SDP session descriptions extracted from SIP message
//! bodies. Handles session-level and media-level attributes including
//! rtpmap, fmtp, crypto (SDES), ICE candidates, and directionality.

use anyhow::{Context, Result};

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
}

/// Stream directionality attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Parse an SDP body from raw bytes into an [`SdpSession`].
///
/// Lines may be separated by `\r\n` or bare `\n`. The version line (`v=0`)
/// must be present; other fields are optional.
///
/// # Errors
///
/// Returns an error if the body is empty, not valid UTF-8, or missing the
/// required `v=0` version line.
pub fn parse_sdp(body: &[u8]) -> Result<SdpSession> {
    if body.is_empty() {
        anyhow::bail!("Empty SDP body");
    }

    let text = std::str::from_utf8(body).context("SDP body contains invalid UTF-8")?;

    let lines: Vec<&str> = text.lines().collect();

    // Validate version line
    let first_nonempty = lines
        .iter()
        .find(|l| !l.trim().is_empty())
        .context("SDP body contains no non-empty lines")?;

    let version_value = first_nonempty
        .strip_prefix("v=")
        .context("SDP must start with v= line")?;
    if version_value.trim() != "0" {
        anyhow::bail!("Unsupported SDP version: '{}'", version_value.trim());
    }

    let mut session = SdpSession {
        origin: None,
        session_name: None,
        connection: None,
        media: Vec::new(),
    };

    // Track whether we are inside a media section
    let mut in_media = false;

    for line in &lines {
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

/// Parse a `c=` line value (e.g., `"IN IP4 10.0.0.1"`) into an [`SdpConnection`].
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
    })
}

/// Parse a single `a=` attribute value and apply it to the current media section.
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
    }
}

/// Parse an `a=rtpmap` value (e.g., `"0 PCMU/8000"` or `"111 opus/48000/2"`).
fn parse_rtpmap(value: &str) -> Option<RtpMap> {
    let mut parts = value.splitn(2, ' ');
    let pt_str = parts.next()?.trim();
    let encoding_part = parts.next()?.trim();

    let payload_type: u8 = pt_str.parse().ok()?;

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(session.connection.as_ref().map(|c| c.addr.as_str()), Some("10.0.0.1"));
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
