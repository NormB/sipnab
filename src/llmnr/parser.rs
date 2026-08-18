// SPDX-License-Identifier: MIT OR Apache-2.0

//! LLMNR message parser (RFC 4795).
//!
//! The wire format is DNS (RFC 1035 §4): a 12-byte header, then question,
//! answer, authority and additional sections of length-prefixed labels. Only
//! the two sections that carry the inventory signal are decoded — the question
//! (what name was looked up) and the answer (who claims it, at which address).
//! Authority and additional are skipped by length.
//!
//! Names are decoded as UTF-8 (RFC 4795 §3.1 specifies UTF-8, unlike DNS's
//! preferred-name syntax), lossily: a hostname is evidence about a host, and a
//! non-conformant byte in it is not a reason to lose the record.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, ensure};

use super::HEADER_LEN;

/// One question: the name a host asked about.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LlmnrQuestion {
    /// The queried name, dot-joined.
    pub name: String,
    /// QTYPE — 1 (A) and 28 (AAAA) dominate on LLMNR.
    pub qtype: u16,
}

/// One answer record: a name its owner is claiming, and where.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LlmnrAnswer {
    /// The name being claimed.
    pub name: String,
    /// Record type.
    pub rtype: u16,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// The address, when the record is an A or AAAA. `None` for record types
    /// whose RDATA this parser does not decode.
    pub address: Option<IpAddr>,
}

/// A parsed LLMNR message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LlmnrMessage {
    /// Transaction ID, echoed by the responder.
    pub id: u16,
    /// `true` for a response, `false` for a query.
    pub is_response: bool,
    /// The C bit: the responder found a name conflict (RFC 4795 §2.1.1).
    pub conflict: bool,
    /// The TC bit: the message was truncated.
    pub truncated: bool,
    /// The T bit: the sender's name is tentative, i.e. not yet defended.
    pub tentative: bool,
    /// RCODE. Non-zero on a response means the responder refused.
    pub rcode: u8,
    /// Questions asked.
    pub questions: Vec<LlmnrQuestion>,
    /// Answer records returned.
    pub answers: Vec<LlmnrAnswer>,
}

/// Longest name this parser will assemble, per RFC 1035 §2.3.4.
const MAX_NAME_LEN: usize = 255;

/// Longest single label, per RFC 1035 §2.3.4.
const MAX_LABEL_LEN: usize = 63;

/// Compression pointers a single name may follow before the message is
/// treated as hostile. RFC 4795 §2.4 forbids compression in LLMNR entirely,
/// so any budget at all is generous; a small non-zero one keeps a
/// non-conformant responder readable without letting a crafted message loop
/// this parser forever.
const MAX_POINTER_JUMPS: usize = 8;

/// Records decoded per section. A message declaring more is truncated to this
/// and the rest ignored — the counts are attacker-controlled `u16`s, and the
/// inventory value of the fiftieth answer record is nil.
const MAX_RECORDS: usize = 32;

/// Parse an LLMNR message.
///
/// # Errors
///
/// Returns an error when the payload is shorter than the fixed header. A
/// malformed section is truncated rather than fatal: a name that fails to
/// decode ends parsing of that section and the records already recovered are
/// kept, because a partial answer about which host asked for what is still an
/// answer.
pub fn parse_llmnr(data: &[u8]) -> Result<LlmnrMessage> {
    ensure!(
        data.len() >= HEADER_LEN,
        "LLMNR message too short: {} bytes (minimum {})",
        data.len(),
        HEADER_LEN
    );

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut msg = LlmnrMessage {
        id,
        is_response: flags & 0x8000 != 0,
        conflict: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        tentative: flags & 0x0100 != 0,
        rcode: (flags & 0x000f) as u8,
        questions: Vec::new(),
        answers: Vec::new(),
    };

    let mut pos = HEADER_LEN;

    for _ in 0..qdcount.min(MAX_RECORDS) {
        let Some((name, next)) = read_name(data, pos) else {
            return Ok(msg);
        };
        // QTYPE(2) + QCLASS(2).
        let Some(qtype) = data.get(next..next + 2) else {
            return Ok(msg);
        };
        msg.questions.push(LlmnrQuestion {
            name,
            qtype: u16::from_be_bytes([qtype[0], qtype[1]]),
        });
        pos = next + 4;
    }

    for _ in 0..ancount.min(MAX_RECORDS) {
        let Some((name, next)) = read_name(data, pos) else {
            return Ok(msg);
        };
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
        let Some(fixed) = data.get(next..next + 10) else {
            return Ok(msg);
        };
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlength = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata_start = next + 10;
        let Some(rdata) = data.get(rdata_start..rdata_start + rdlength) else {
            return Ok(msg);
        };
        msg.answers.push(LlmnrAnswer {
            name,
            rtype,
            ttl,
            address: decode_address(rtype, rdata),
        });
        pos = rdata_start + rdlength;
    }

    Ok(msg)
}

/// Decode A / AAAA RDATA into an address. Any other record type, or a length
/// that disagrees with the type, yields `None` rather than a guess.
fn decode_address(rtype: u16, rdata: &[u8]) -> Option<IpAddr> {
    match (rtype, rdata.len()) {
        (1, 4) => {
            let o: [u8; 4] = rdata.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        }
        (28, 16) => {
            let o: [u8; 16] = rdata.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Read a length-prefixed name starting at `start`.
///
/// Returns the dot-joined name and the offset immediately after the name *in
/// the record stream* — which, when a compression pointer was followed, is the
/// position after the pointer rather than after the target.
///
/// Returns `None` on anything malformed: an over-long label or name, a pointer
/// past the end of the buffer, or more pointer jumps than the budget allows.
/// Every read is bounds-checked; this function is handed unvalidated network
/// bytes and must not panic on any of them.
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    // Set on the first pointer followed; the caller resumes from there.
    let mut resume: Option<usize> = None;
    let mut jumps = 0usize;
    let mut total = 0usize;

    loop {
        let len = *buf.get(pos)? as usize;

        if len == 0 {
            pos += 1;
            break;
        }

        // Top two bits set marks a compression pointer (RFC 1035 §4.1.4).
        if len & 0xc0 == 0xc0 {
            let low = *buf.get(pos + 1)? as usize;
            let target = ((len & 0x3f) << 8) | low;
            resume.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS || target >= buf.len() {
                return None;
            }
            pos = target;
            continue;
        }

        if len > MAX_LABEL_LEN {
            return None;
        }
        let bytes = buf.get(pos + 1..pos + 1 + len)?;
        total += len + 1;
        if total > MAX_NAME_LEN {
            return None;
        }
        // Lossy on purpose: see the module note. A hostname with one bad byte
        // still names a host.
        labels.push(String::from_utf8_lossy(bytes).into_owned());
        pos += 1 + len;
    }

    Some((labels.join("."), resume.unwrap_or(pos)))
}

/// Human name for a record type, for display. Unknown types render as their
/// number so the output never silently drops information.
#[must_use]
pub fn rtype_name(rtype: u16) -> String {
    match rtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real query for "GHS08", byte-exact from the capture that motivated
    /// this module.
    const QUERY_A: &[u8] = &[
        0x80, 0x06, // transaction ID
        0x00, 0x00, // query, opcode 0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN / NS / AR
        0x05, b'G', b'H', b'S', b'0', b'8', 0x00, // "GHS08"
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];

    /// The same host asking for AAAA, also byte-exact from the capture.
    const QUERY_AAAA: &[u8] = &[
        0x7d, 0x7a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, b'G', b'H',
        b'S', b'0', b'8', 0x00, 0x00, 0x1c, 0x00, 0x01,
    ];

    #[test]
    fn decodes_the_queried_hostname() {
        let msg = parse_llmnr(QUERY_A).expect("valid query");
        assert!(!msg.is_response);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "GHS08");
        assert_eq!(msg.questions[0].qtype, 1);
    }

    #[test]
    fn decodes_an_aaaa_question() {
        let msg = parse_llmnr(QUERY_AAAA).expect("valid query");
        assert_eq!(msg.questions[0].name, "GHS08");
        assert_eq!(rtype_name(msg.questions[0].qtype), "AAAA");
    }

    /// A response is the half that identifies a host: the answer names the
    /// host and gives its address.
    #[test]
    fn decodes_a_response_answer_to_a_name_and_address() {
        let mut data = vec![
            0x80, 0x06, // same transaction ID
            0x80, 0x00, // response
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0x05, b'G', b'H', b'S', b'0', b'8', 0x00]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        data.extend_from_slice(&[0x05, b'G', b'H', b'S', b'0', b'8', 0x00]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE A, CLASS IN
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // TTL 30
        data.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        data.extend_from_slice(&[192, 0, 2, 79]); // 192.0.2.79

        let msg = parse_llmnr(&data).expect("valid response");
        assert!(msg.is_response);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "GHS08");
        assert_eq!(msg.answers[0].ttl, 30);
        assert_eq!(
            msg.answers[0].address,
            Some("192.0.2.79".parse().expect("valid addr"))
        );
    }

    #[test]
    fn decodes_a_multi_label_name() {
        let mut data = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[
            0x03, b'w', b'k', b's', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
        ]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let msg = parse_llmnr(&data).expect("valid query");
        assert_eq!(msg.questions[0].name, "wks.local");
    }

    /// Compression is forbidden in LLMNR but a non-conformant responder may
    /// still use it, and the parser must follow it rather than lose the record.
    #[test]
    fn follows_a_compression_pointer() {
        let mut data = vec![
            0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0x05, b'G', b'H', b'S', b'0', b'8', 0x00]); // name at offset 12
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        data.extend_from_slice(&[0xc0, 0x0c]); // pointer back to offset 12
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04]);
        data.extend_from_slice(&[192, 0, 2, 79]);

        let msg = parse_llmnr(&data).expect("valid response");
        assert_eq!(msg.answers.len(), 1, "the pointer must resolve");
        assert_eq!(msg.answers[0].name, "GHS08");
    }

    /// A pointer that points at itself must terminate, not hang. Network input
    /// is hostile by default.
    #[test]
    fn a_self_referential_pointer_terminates() {
        let mut data = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0xc0, 0x0c]); // offset 12 points to offset 12
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let msg = parse_llmnr(&data).expect("must not hang or panic");
        assert!(
            msg.questions.is_empty(),
            "a looping name yields no question"
        );
    }

    #[test]
    fn rejects_a_payload_shorter_than_the_header() {
        assert!(parse_llmnr(&QUERY_A[..11]).is_err());
    }

    /// A count that overstates what the buffer holds must not panic, and must
    /// keep whatever was genuinely decoded.
    #[test]
    fn a_lying_question_count_keeps_what_was_real() {
        let mut data = QUERY_A.to_vec();
        data[5] = 0x09; // claim nine questions; the buffer holds one
        let msg = parse_llmnr(&data).expect("must not panic");
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "GHS08");
    }

    /// An answer whose RDLENGTH runs past the buffer must be dropped, not read.
    #[test]
    fn an_answer_overrunning_the_buffer_is_dropped() {
        let mut data = vec![
            0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0x05, b'G', b'H', b'S', b'0', b'8', 0x00]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e]);
        data.extend_from_slice(&[0xff, 0xff]); // RDLENGTH 65535
        data.extend_from_slice(&[192, 0, 2, 79]);
        let msg = parse_llmnr(&data).expect("must not panic");
        assert!(msg.answers.is_empty());
    }

    /// An over-long label is refused rather than assembled.
    #[test]
    fn an_over_long_label_is_refused() {
        let mut data = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.push(0x7f); // 127 > MAX_LABEL_LEN, and not a pointer
        data.extend_from_slice(&[b'x'; 127]);
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        let msg = parse_llmnr(&data).expect("must not panic");
        assert!(msg.questions.is_empty());
    }
}
