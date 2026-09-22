// SPDX-License-Identifier: MIT OR Apache-2.0

//! The synthetic captures are exactly what their generator builds, and carry
//! nothing from a real network.
//!
//! `tests/support/synthetic_captures.rs` owns six committed captures: the two
//! oldest fixtures, the rtpengine relay pair and two fuzz seeds. The
//! generator is the provenance: a reader can see in a diff every address,
//! every header and every timing a capture holds. That stays true only while
//! the committed bytes are the generator's output, so the first test here
//! rebuilds each one and compares. A hand edit, a capture dropped in under the
//! same name, or a builder change nobody regenerated all fail it.
//!
//! The rest assert, on the committed bytes rather than on the generator's
//! intent, the properties the captures exist to have: documentation
//! identifiers only, a media-only twin that differs from the relay capture by
//! its control plane alone, rtpengine's wire shapes, and a fuzz seed that is
//! truncated the way its name says.

use std::net::Ipv4Addr;
use std::path::PathBuf;

#[path = "support/synthetic_captures.rs"]
mod synthetic_captures;

use synthetic_captures::OWNED;

/// Absolute path of a repository-relative file.
fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Read a committed file, naming it if it cannot be read.
fn committed(rel: &str) -> Vec<u8> {
    std::fs::read(repo(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The regeneration command, quoted by every failure that needs it.
const REGENERATE: &str = "cargo run --features native --bin gen_fixture";

/// One record of a little-endian classic pcap.
struct Rec {
    caplen: usize,
    orig_len: usize,
    data: Vec<u8>,
}

/// The records of a little-endian, microsecond classic pcap, stopping at a
/// record the file does not hold in full.
///
/// Written here rather than borrowed from sipnab's reader: these tests check
/// the fixtures that reader is tested WITH, so they must not depend on it.
fn records(bytes: &[u8]) -> Vec<Rec> {
    assert!(
        bytes.len() >= 24 && bytes[..4] == [0xd4, 0xc3, 0xb2, 0xa1],
        "not a little-endian microsecond pcap"
    );
    let u32_at =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let mut out = Vec::new();
    let mut at = 24;
    while at + 16 <= bytes.len() {
        let caplen = u32_at(at + 8) as usize;
        let orig_len = u32_at(at + 12) as usize;
        let start = at + 16;
        if start + caplen > bytes.len() {
            break;
        }
        out.push(Rec {
            caplen,
            orig_len,
            data: bytes[start..start + caplen].to_vec(),
        });
        at = start + caplen;
    }
    out
}

/// The Ethernet/IPv4/UDP fields of a frame: MACs, addresses, ports, payload.
struct Udp<'a> {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    flags: u16,
    udp_len: usize,
    dport: u16,
    payload: &'a [u8],
}

/// Decode an Ethernet II / IPv4 / UDP frame, or `None` for anything else.
fn udp_of(frame: &[u8]) -> Option<Udp<'_>> {
    if frame.len() < 42 || frame[12..14] != [0x08, 0x00] || frame[23] != 17 {
        return None;
    }
    let ihl = usize::from(frame[14] & 0x0f) * 4;
    let l4 = 14 + ihl;
    let mac = |at: usize| -> [u8; 6] { frame[at..at + 6].try_into().expect("six bytes") };
    let quad = |at: usize| Ipv4Addr::new(frame[at], frame[at + 1], frame[at + 2], frame[at + 3]);
    Some(Udp {
        dst_mac: mac(0),
        src_mac: mac(6),
        src: quad(26),
        dst: quad(30),
        flags: u16::from_be_bytes([frame[20], frame[21]]),
        udp_len: usize::from(u16::from_be_bytes([frame[l4 + 4], frame[l4 + 5]])),
        dport: u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]),
        payload: frame.get(l4 + 8..)?,
    })
}

/// RFC 5737: the three IPv4 blocks reserved for documentation.
fn is_documentation(a: Ipv4Addr) -> bool {
    matches!(
        a.octets(),
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

/// RFC 7042 section 2.1.2's documentation block, or all zero.
fn is_documentation_mac(m: [u8; 6]) -> bool {
    m == [0; 6] || m[..5] == [0x00, 0x00, 0x5e, 0x00, 0x53]
}

/// Every dotted quad written as text in `data`.
fn dotted_quads(data: &[u8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut i = 0;
    let in_quad = |b: u8| b.is_ascii_digit() || b == b'.';
    while i < data.len() {
        if !data[i].is_ascii_digit() || (i > 0 && in_quad(data[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && in_quad(data[i]) {
            i += 1;
        }
        if let Ok(a) = std::str::from_utf8(&data[start..i])
            .unwrap_or_default()
            .parse::<Ipv4Addr>()
        {
            out.push(a);
        }
    }
    out
}

/// The chunks of a HEP v3 datagram, as `(type, value)`, up to what is present.
fn hep_chunks(payload: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    if payload.len() < 6 || &payload[..4] != b"HEP3" {
        return out;
    }
    let mut at = 6;
    while at + 6 <= payload.len() {
        let kind = u16::from_be_bytes([payload[at + 2], payload[at + 3]]);
        let len = usize::from(u16::from_be_bytes([payload[at + 4], payload[at + 5]]));
        if len < 6 {
            break;
        }
        let end = (at + len).min(payload.len());
        out.push((kind, &payload[at + 6..end]));
        at += len;
    }
    out
}

// ── the generator is the provenance ─────────────────────────────────

/// Every owned capture is byte for byte what its builder produces.
#[test]
fn every_owned_capture_is_what_its_generator_builds() {
    for owned in OWNED {
        let on_disk = committed(owned.path);
        let built = (owned.build)();
        if on_disk != built {
            let first = on_disk
                .iter()
                .zip(&built)
                .position(|(a, b)| a != b)
                .unwrap_or(on_disk.len().min(built.len()));
            panic!(
                "{} is not what tests/support/synthetic_captures.rs builds: \
                 {} bytes committed, {} built, first difference at byte {first}. \
                 A capture that differs from its generator has no provenance. \
                 If the builder changed on purpose, regenerate with `{REGENERATE}`; \
                 if the file changed, find out who changed it and why.",
                owned.path,
                on_disk.len(),
                built.len(),
            );
        }
    }
}

/// Building twice gives the same bytes: no clock, no randomness.
#[test]
fn the_generator_is_deterministic() {
    for owned in OWNED {
        assert!(
            (owned.build)() == (owned.build)(),
            "{} came out different on a second build, so its committed bytes \
             cannot be reproduced by anyone else",
            owned.path
        );
    }
}

/// Nothing in an owned capture could have come from a real network.
///
/// Checked on the committed bytes: every Ethernet address in the documentation
/// block (or zero), every IP header address in RFC 5737, every address written
/// as text in a payload too, and the inner addresses of every HEP datagram on
/// loopback, where rtpengine's own ng socket lives.
#[test]
fn owned_captures_carry_only_documentation_identifiers() {
    let mut offenders: Vec<String> = Vec::new();
    for owned in OWNED {
        for (n, rec) in records(&committed(owned.path)).iter().enumerate() {
            let Some(frame) = udp_of(&rec.data) else {
                continue;
            };
            let at = format!("{} record {n}", owned.path);
            for mac in [frame.dst_mac, frame.src_mac] {
                if !is_documentation_mac(mac) {
                    offenders.push(format!("{at}: MAC {mac:02x?}"));
                }
            }
            for addr in [frame.src, frame.dst] {
                if !is_documentation(addr) {
                    offenders.push(format!("{at}: IP header address {addr}"));
                }
            }
            for addr in dotted_quads(frame.payload) {
                if !is_documentation(addr) && !addr.is_loopback() {
                    offenders.push(format!("{at}: address {addr} in the payload"));
                }
            }
            for (kind, value) in hep_chunks(frame.payload) {
                if matches!(kind, 3 | 4) && value != [127, 0, 0, 1] {
                    offenders.push(format!("{at}: HEP address chunk {value:?}"));
                }
            }
        }
    }
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "an owned capture carries an identifier outside the documentation \
         ranges ({} finding(s)); first few:\n  {}",
        offenders.len(),
        offenders[..offenders.len().min(8)].join("\n  ")
    );
}

// ── the relay pair ──────────────────────────────────────────────────

const RELAY_NG: &str = "tests/fixtures/rtpengine-ng-hep.pcap";
const RELAY_MEDIA_ONLY: &str = "tests/fixtures/rtpengine-media-only.pcap";

/// The media-only capture is the relay capture minus its six HEP datagrams,
/// with every other record identical.
///
/// That is what makes `stripping_the_control_plane_returns_every_stream_to_orphan`
/// a controlled experiment: the only thing that differs between the two runs
/// is the control plane, so the control plane is the only thing that can have
/// named the call.
#[test]
fn the_media_only_capture_is_the_relay_capture_without_its_control_plane() {
    let with = records(&committed(RELAY_NG));
    let without = records(&committed(RELAY_MEDIA_ONLY));
    let (control, media): (Vec<&Rec>, Vec<&Rec>) = with
        .iter()
        .partition(|r| udp_of(&r.data).is_some_and(|u| u.dport == 9060));
    assert_eq!(
        control.len(),
        6,
        "the relay capture holds six HEP datagrams"
    );
    assert_eq!(media.len(), 40, "and forty relayed RTP packets");
    assert_eq!(
        without.len(),
        media.len(),
        "the twin holds exactly the media"
    );
    for (n, (a, b)) in media.iter().zip(&without).enumerate() {
        assert!(
            a.data == b.data,
            "media record {n} differs between the two captures, so the pair no \
             longer isolates the control plane"
        );
    }
}

/// The control plane keeps the shapes a live rtpengine 12.5.1 sent.
///
/// These are the properties the decoder was built against, recorded from a
/// live relay when the pair was first captured and kept when it was rebuilt:
/// the Call-ID on every datagram's correlation-id chunk, requests with their
/// keys in rtpengine's (unsorted) order, replies with no `call-id` of their
/// own, the relay's allocated ports only in the replies, and a `delete` reply
/// too large for one packet, of which the capture holds the first fragment.
#[test]
fn the_relay_control_plane_keeps_rtpengine_wire_shapes() {
    let recs = records(&committed(RELAY_NG));
    let control: Vec<Udp<'_>> = recs
        .iter()
        .filter_map(|r| udp_of(&r.data))
        .filter(|u| u.dport == 9060)
        .collect();
    assert_eq!(control.len(), 6);

    let mut bodies = Vec::new();
    for u in &control {
        let chunks = hep_chunks(u.payload);
        let find = |k: u16| chunks.iter().find(|(t, _)| *t == k).map(|(_, v)| *v);
        assert_eq!(
            find(0x0b),
            Some(&[0x3d][..]),
            "capture protocol is rtpengine ng"
        );
        assert_eq!(
            find(0x11),
            Some(&b"km-670bd208@sipnab"[..]),
            "every datagram, reply or request, names the call in its correlation id"
        );
        let payload = find(0x0f).expect("a payload chunk");
        let space = payload
            .iter()
            .position(|b| *b == b' ')
            .expect("an ng message is a cookie, a space, and the body");
        bodies.push(String::from_utf8_lossy(&payload[space + 1..]).into_owned());
    }

    let [
        offer,
        offer_reply,
        answer,
        answer_reply,
        delete,
        delete_reply,
    ] = &bodies[..]
    else {
        panic!("six bodies");
    };
    assert!(
        offer.starts_with("d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp"),
        "the offer's keys arrive in rtpengine's order, not sorted: {offer}"
    );
    assert!(
        answer.starts_with("d7:command6:answer7:call-id"),
        "{answer}"
    );
    assert!(answer.contains("6:to-tag5:ttag1"), "{answer}");
    assert_eq!(delete, "d7:command6:delete7:call-id18:km-670bd208@sipnabe");
    for reply in [offer_reply, answer_reply, delete_reply] {
        assert!(
            !reply.contains("call-id"),
            "a reply carries no call-id; only the HEP chunk names its call: {reply}"
        );
    }
    assert!(offer_reply.starts_with("d3:sdp") && offer_reply.ends_with("6:result2:oke"));
    assert!(offer_reply.contains("c=IN IP4 192.0.2.40") && offer_reply.contains("m=audio 38664"));
    assert!(answer_reply.contains("c=IN IP4 192.0.2.40") && answer_reply.contains("m=audio 38156"));
    assert!(offer.contains("m=audio 40001") && answer.contains("m=audio 40002"));

    // The delete reply: a first fragment, MF set, whose UDP length names a
    // datagram larger than the packet that carried it.
    let last = &control[5];
    assert_eq!(last.flags, 0x2000, "the delete reply is a first fragment");
    assert!(
        last.udp_len > last.payload.len() + 8,
        "the UDP length ({}) describes the whole datagram, not the {} bytes \
         this fragment holds",
        last.udp_len,
        last.payload.len() + 8
    );
    assert!(delete_reply.starts_with("d7:createdi"), "{delete_reply}");
}

// ── the fuzz seed ───────────────────────────────────────────────────

/// `truncated-sip` is truncated in both of the ways a real capture is.
///
/// One record snapped below its wire length, then a record the file ends
/// inside. The reader must yield the two it can and stop, which is the
/// behavior the seed exists to start the fuzzer next to.
#[test]
fn the_truncated_seed_is_truncated_the_way_its_name_says() {
    let bytes = committed("fuzz/corpus/pcap_reader/truncated-sip");
    let whole = records(&bytes);
    assert_eq!(whole.len(), 2, "two records the file holds in full");
    assert_eq!(whole[0].caplen, whole[0].orig_len, "the first is whole");
    assert!(
        whole[1].caplen < whole[1].orig_len,
        "the second is snapped: captured {} of {} bytes",
        whole[1].caplen,
        whole[1].orig_len
    );
    let consumed = 24 + whole.iter().map(|r| 16 + r.caplen).sum::<usize>();
    assert!(
        bytes.len() > consumed + 16,
        "a third record header follows, and the file ends inside its data"
    );

    // And sipnab's own reader agrees, stopping without reading past the end.
    let read: Vec<_> = sipnab::PcapReader::new(&bytes)
        .expect("a valid header")
        .collect();
    assert_eq!(read.len(), 2);
    assert!((read[1].data.len() as u32) < read[1].orig_len);
}
