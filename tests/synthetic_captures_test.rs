// SPDX-License-Identifier: MIT OR Apache-2.0

//! The synthetic captures are exactly what their generator builds, and carry
//! nothing from a real network.
//!
//! `tests/support/synthetic_captures.rs` owns fourteen committed captures: the
//! two oldest fixtures, two rtpengine relay pairs, two fuzz seeds, the two
//! media files SIPp plays in the harness, and four STUN, TURN and ICE
//! fixtures. The generator is the provenance: a reader can see in a diff every address,
//! every header and every timing a capture holds. That stays true only while
//! the committed bytes are the generator's output, so the first test here
//! rebuilds each one and compares. A hand edit, a capture dropped in under the
//! same name, or a builder change nobody regenerated all fail it.
//!
//! The rest assert, on the committed bytes rather than on the generator's
//! intent, the properties the captures exist to have: documentation
//! identifiers only, media-only twins that differ from their relay captures by
//! the control plane alone, rtpengine's and OpenSIPS's wire shapes, media
//! files SIPp can replay, and a fuzz seed that is truncated the way its name
//! says. The codecs that fill the media files are checked here too, against
//! independent implementations, because a generator is only as honest as the
//! encoder inside it.

use std::net::Ipv4Addr;
use std::path::PathBuf;

#[path = "support/codecs.rs"]
mod codecs;
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

/// Addresses outside RFC 5737 that an owned capture carries on purpose, and
/// why. Each must be the point of its capture, and each must still be in it:
/// [`every_deliberate_address_is_still_where_it_is_listed`] fails on an entry
/// nothing uses any more.
const DELIBERATE: &[(&str, Ipv4Addr, &str)] = &[(
    "tests/fixtures/stun_sdp_mismatch.pcap",
    Ipv4Addr::new(192, 168, 10, 50),
    "a phone behind NAT advertising its RFC 1918 address in SDP is the \
     mismatch the capture exists to show",
)];

/// Whether `path` is allowed to carry `addr` although it is not RFC 5737.
fn deliberate(path: &str, addr: Ipv4Addr) -> bool {
    DELIBERATE.iter().any(|(p, a, _)| *p == path && *a == addr)
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
                if !is_documentation(addr) && !deliberate(owned.path, addr) {
                    offenders.push(format!("{at}: IP header address {addr}"));
                }
            }
            for addr in dotted_quads(frame.payload) {
                if !is_documentation(addr) && !addr.is_loopback() && !deliberate(owned.path, addr) {
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

/// Every deliberate exception is used: its address is in its capture, both
/// in an IP header and written in a payload, so the list cannot outlive the
/// reason it was written for.
#[test]
fn every_deliberate_address_is_still_where_it_is_listed() {
    for (path, addr, why) in DELIBERATE {
        assert!(!why.is_empty(), "{path}: an exception with no reason");
        assert!(
            !deliberate("tests/fixtures/sip_call.pcap", *addr),
            "the exception for {addr} is {path}'s alone"
        );
        let recs = records(&committed(path));
        let frames: Vec<Udp<'_>> = recs.iter().filter_map(|r| udp_of(&r.data)).collect();
        assert!(
            frames.iter().any(|f| f.src == *addr || f.dst == *addr),
            "{path} no longer sends from or to {addr}"
        );
        assert!(
            frames
                .iter()
                .any(|f| dotted_quads(f.payload).contains(addr)),
            "{path} no longer writes {addr} in a payload"
        );
    }
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

// ── the codecs ──────────────────────────────────────────────────────

/// Decode a hex literal.
fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Full-scale pseudo-random samples from the C library's classic LCG, so the
/// same input can be rebuilt in any language to regenerate the vectors below.
fn lcg_noise(count: usize) -> Vec<i16> {
    let mut x: u32 = 1;
    (0..count)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7fff_ffff;
            ((x >> 15) & 0xffff) as u16 as i16
        })
        .collect()
}

/// The G.722 encoder is ITU-T G.722, not a lookalike.
///
/// The vectors were produced by two independent encoders from the same
/// input: spandsp 0.0.6's `g722_encode` at 64 kbit/s, called through ctypes,
/// and FFmpeg's `g722` encoder (`ffmpeg -f s16le -ar 16000 -ac 1 -i - -c:a
/// g722 -f g722 -`). The two agreed byte for byte, and this encoder must
/// agree with both. The first input is the fixtures' own wideband signal,
/// two frames of it; the second is full-scale noise, which drives both
/// sub-bands' quantizers and scale factors to their limits.
#[test]
fn the_g722_encoder_matches_two_independent_implementations() {
    let wideband: Vec<i16> = (0..640).map(codecs::wideband_sample).collect();
    assert_eq!(
        codecs::g722_encode(&wideband),
        hex(G722_WIDEBAND_VECTOR),
        "the fixtures' signal"
    );
    assert_eq!(
        codecs::g722_encode(&lcg_noise(480)),
        hex(G722_NOISE_VECTOR),
        "full-scale noise"
    );
}

/// SHA-256 of `bytes`, in lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The two vectors above cannot reach every decision a G.722 encoder makes,
/// so a third runs three seconds of noise through it: one second at full
/// scale, one 24 dB down, one 48 dB down, which walks both bands' scale
/// factors from the top to near the bottom. spandsp 0.0.6 and FFmpeg encode
/// it to the same 24,000 bytes, and this encoder must too; the vector is
/// compared by hash to keep 24 KB of hex out of the file.
#[test]
fn the_g722_encoder_matches_them_across_three_levels_of_noise() {
    let signal: Vec<i16> = lcg_noise(48_000)
        .iter()
        .enumerate()
        .map(|(n, v)| v >> (4 * (n / 16_000)))
        .collect();
    let encoded = codecs::g722_encode(&signal);
    assert_eq!(encoded.len(), 24_000);
    assert_eq!(
        sha256_hex(&encoded),
        "baab5d97989d0b60a628c023a9a0a32646faff41c7929ee364cd3edfe94529e8"
    );
}

/// Both G.711 encoders agree with CPython's `audioop` (`lin2alaw` and
/// `lin2ulaw` in Python 3.12, a separate C implementation of the same Sun
/// algorithms) on every one of the 65,536 16-bit inputs. The tables are
/// compared by hash; each was computed from `audioop` over the inputs in
/// ascending order, from -32768 to 32767.
#[test]
fn the_g711_encoders_match_cpython_on_every_input() {
    let alaw: Vec<u8> = (i16::MIN..=i16::MAX).map(codecs::alaw).collect();
    let ulaw: Vec<u8> = (i16::MIN..=i16::MAX).map(codecs::ulaw).collect();
    assert_eq!(
        sha256_hex(&alaw),
        "38488f6fd710f4686360edc4d38639f96c491595ef93f8eb8d62d5e07ca6ce7b",
        "A-law"
    );
    assert_eq!(
        sha256_hex(&ulaw),
        "81d633c9e6972a18c74a58720b96cb8ca0bdd096d4060b646dd708c3b846019a",
        "mu-law"
    );
}

/// Encoding frame by frame on one encoder is the same as encoding the whole
/// signal at once: the state carries across calls, as a sender's does.
#[test]
fn the_g722_encoder_carries_its_state_across_frames() {
    let signal: Vec<i16> = (0..3200).map(codecs::wideband_sample).collect();
    let mut encoder = codecs::G722Encoder::new();
    let framed: Vec<u8> = signal
        .chunks(320)
        .flat_map(|frame| encoder.encode(frame))
        .collect();
    assert_eq!(framed, codecs::g722_encode(&signal));
}

/// spandsp 0.0.6 and FFmpeg on the first 640 samples of `wideband_sample`.
const G722_WIDEBAND_VECTOR: &str = "\
    b74e29a604a0a020a0b20b8a0d1cab27aab8108c0f1eac28acba118d511fad2a6efc12ce535fae6cefbd13d0537eb06bf2bb5392d67eb16cf1fc14d0563ff12d73fd15d2585fb06ef4bb5492d95fb06ff6fb15d4581ff02e75fb15d5585eb06ef5ba5595d85db06ef5f916d6581cf12f75f85893dc5aaf73f3f91ad65a1ff02ef6f617dad77eb46db5b656d75b5cb46ef6f615d75b5bb273f5b556975859b27375741798d45bf03277f81bd61619723473fb5894d7ddb5f0b4b2d39ad6daf67472fa1595d8d4753276f713de54d3b075f9fb15d850d4b4355ff553964f59de3d5afa0dcf144ebfd5dcd711ce13529ad8d6de508f5b53be547d7e10d33e13fc5cfa5e12dc5557ba7bfedf1bd953dbb43a5cb9dbd5135eb35d7bf45990d7fab87afaafd0945f7fb9f86f7a11da3b13effbf2fb14dc5c59f03076ba55de1d156d71";

/// spandsp 0.0.6 and FFmpeg on `lcg_noise(480)`.
const G722_NOISE_VECTOR: &str = "\
    2084208420842c0c9422a5a0a804860e90238c9109160435a22aa33296b20a271f0a2a22cc886220a8a2e28614a6e661b190bc0aae91be13e3caaaa6880d23aac724a1e08717a52b218625d1620a3bb4103289c4c5e4ad8ba1a99ba2e92ba9989aa40b1c5209c5891aba21a8f62090081e0488bb0cc6c9380a13a19207a391c4ba7aac863b278b6c0c0929e1ed711288a19e8f30222bdd8a8825e7ec5bd0336a05a82f93560fa00f888d2cd3b0050590964c3944636205a8c43125898c67b35948100cbfa8a591a8a6e7a0b306a30416bd65f2a1861fa06299e2b43094b82c9a1a21201d30179f4432bc8f26c4d18945";

/// G.711 A-law expansion with G.711's polarity: bit 7 set, after the 0x55
/// mask, is positive, so 0xD5 is +8 and 0x55 is -8.
///
/// Written out here because `sipnab::rtp::g711::alaw_to_pcm` has the
/// opposite polarity: it decodes 0xD5 as -8, where sox and FFmpeg both decode
/// +8. Its magnitudes are right, and this function is checked against them
/// below, so only the sign is taken on trust, from those two decoders.
fn alaw_expand(code: u8) -> i16 {
    let a = code ^ 0x55;
    let mut t = i32::from(a & 0x0f) << 4;
    match (a & 0x70) >> 4 {
        0 => t += 8,
        1 => t += 0x108,
        seg => t = (t + 0x108) << (seg - 1),
    }
    (if a & 0x80 != 0 { t } else { -t }) as i16
}

/// The G.711 encoders invert a G.711 decoder: every code maps back to
/// itself, decoding what they encode never goes backwards as the input rises,
/// and it never lands further from the input than the widest step.
///
/// mu-law is checked against sipnab's own decoder. A-law is checked against
/// [`alaw_expand`], whose magnitudes are pinned to sipnab's decoder and whose
/// sign is pinned to sox and FFmpeg.
#[test]
fn the_g711_encoders_invert_a_g711_decoder() {
    use sipnab::rtp::g711::{alaw_to_pcm, ulaw_to_pcm};
    assert_eq!((alaw_expand(0xd5), alaw_expand(0x55)), (8, -8));
    assert_eq!((alaw_expand(0x80), alaw_expand(0x00)), (5504, -5504));
    for code in 0..=255u8 {
        assert_eq!(
            alaw_expand(code).unsigned_abs(),
            alaw_to_pcm(code).unsigned_abs(),
            "A-law {code:#04x}: magnitude"
        );
        assert_eq!(codecs::alaw(alaw_expand(code)), code, "A-law {code:#04x}");
        // mu-law has two zeros; 0x7F decodes to 0, which encodes as 0xFF.
        if code != 0x7f {
            assert_eq!(codecs::ulaw(ulaw_to_pcm(code)), code, "mu-law {code:#04x}");
        }
    }
    /// A law's name, and encode-then-decode through it.
    type RoundTrip = (&'static str, fn(i16) -> i16);
    let round_trips: [RoundTrip; 2] = [
        ("A-law", |x| alaw_expand(codecs::alaw(x))),
        ("mu-law", |x| ulaw_to_pcm(codecs::ulaw(x))),
    ];
    for (name, round_trip) in round_trips {
        let mut previous = i16::MIN;
        for x in i16::MIN..=i16::MAX {
            let y = round_trip(x);
            assert!(
                y >= previous,
                "{name}: {x} decodes below the input before it"
            );
            assert!(
                (i32::from(y) - i32::from(x)).abs() <= 1024,
                "{name}: {x} comes back as {y}"
            );
            previous = y;
        }
    }
}

/// The sine table is the sine it says it is, to within rounding. Checked
/// with floating point here, where a last-bit difference between platforms
/// cannot matter, so the generator itself never has to use it.
#[test]
fn the_sine_table_is_a_sine() {
    for (k, v) in codecs::SINE16.iter().enumerate() {
        let exact = 32767.0 * (2.0 * std::f64::consts::PI * k as f64 / 16.0).sin();
        assert!(
            (f64::from(*v) - exact).abs() <= 0.5,
            "entry {k}: {v} vs {exact}"
        );
    }
}

// ── the SIPp media files ────────────────────────────────────────────

/// The RTP fields of one packet.
struct RtpFields {
    marker: bool,
    pt: u8,
    seq: u16,
    ts: u32,
    ssrc: u32,
    payload_len: usize,
}

fn rtp_of(payload: &[u8]) -> Option<RtpFields> {
    (payload.len() >= 12 && payload[0] == 0x80).then(|| RtpFields {
        marker: payload[1] & 0x80 != 0,
        pt: payload[1] & 0x7f,
        seq: u16::from_be_bytes([payload[2], payload[3]]),
        ts: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ssrc: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        payload_len: payload.len() - 12,
    })
}

/// Each record's capture time in microseconds.
fn times_us(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut at = 24;
    while at + 16 <= bytes.len() {
        let word = |o: usize| {
            u64::from(u32::from_le_bytes([
                bytes[at + o],
                bytes[at + o + 1],
                bytes[at + o + 2],
                bytes[at + o + 3],
            ]))
        };
        out.push(word(0) * 1_000_000 + word(4));
        at += 16 + word(8) as usize;
    }
    out
}

/// What SIPp's `play_pcap_audio` needs from a media file, on the committed
/// bytes: one RTP stream of the scenario's codec, 20 ms frames 20 ms apart,
/// sequence numbers and timestamps that advance by one frame each, and the
/// packet count that keeps the scenarios' timing.
#[test]
fn the_sipp_media_files_are_one_steady_stream_each() {
    for (path, pt, packets) in [
        ("harness/sipp/scenarios/g711a.pcap", 8u8, 5535usize),
        ("harness/sipp/scenarios/g722.pcap", 9, 5413),
    ] {
        let bytes = committed(path);
        let recs = records(&bytes);
        assert_eq!(recs.len(), packets, "{path}: packet count");
        let rtp: Vec<RtpFields> = recs
            .iter()
            .map(|r| {
                udp_of(&r.data)
                    .and_then(|u| rtp_of(u.payload))
                    .unwrap_or_else(|| panic!("{path}: a record that is not RTP"))
            })
            .collect();
        for (i, p) in rtp.iter().enumerate() {
            assert_eq!(p.pt, pt, "{path} packet {i}: payload type");
            assert_eq!(p.payload_len, 160, "{path} packet {i}: 20 ms payload");
            assert_eq!(p.ssrc, rtp[0].ssrc, "{path} packet {i}: one stream");
            assert_eq!(p.marker, i == 0, "{path} packet {i}: marker");
            if i > 0 {
                assert_eq!(p.seq, rtp[i - 1].seq.wrapping_add(1), "{path} packet {i}");
                assert_eq!(p.ts, rtp[i - 1].ts.wrapping_add(160), "{path} packet {i}");
            }
        }
        let t = times_us(&bytes);
        assert!(
            t.windows(2).all(|w| w[1] - w[0] == 20_000),
            "{path}: packets are 20 ms apart"
        );
    }
}

// ── the OpenSIPS relay pair ─────────────────────────────────────────

const OS_NG: &str = "tests/fixtures/rtpengine-opensips-ng.pcap";
const OS_MEDIA_ONLY: &str = "tests/fixtures/rtpengine-opensips-media-only.pcap";

/// The media-only twin is the relay capture minus its four HEP datagrams,
/// every other record identical, so the pair isolates the control plane.
#[test]
fn the_opensips_media_only_capture_is_the_relay_capture_without_its_control_plane() {
    let with = records(&committed(OS_NG));
    let without = records(&committed(OS_MEDIA_ONLY));
    let (control, media): (Vec<&Rec>, Vec<&Rec>) = with
        .iter()
        .partition(|r| udp_of(&r.data).is_some_and(|u| u.dport == 9060));
    assert_eq!(control.len(), 4, "offer, answer and their replies");
    assert_eq!(media.len(), 40, "21 packets in, 19 relayed out");
    assert_eq!(without.len(), media.len());
    for (n, (a, b)) in media.iter().zip(&without).enumerate() {
        assert!(a.data == b.data, "media record {n} differs between the two");
    }
}

/// The caller's packets are what SIPp replays from g722.pcap, header and
/// payload, and the relay forwards each as PCMU under the same sequence
/// number, timestamp and SSRC: a transcode, not a new stream.
#[test]
fn the_opensips_relay_transcodes_the_start_of_g722_pcap() {
    let media: Vec<Vec<u8>> = records(&committed("harness/sipp/scenarios/g722.pcap"))
        .iter()
        .take(21)
        .map(|r| udp_of(&r.data).expect("udp").payload.to_vec())
        .collect();
    let recs = records(&committed(OS_NG));
    let frames: Vec<Udp<'_>> = recs.iter().filter_map(|r| udp_of(&r.data)).collect();
    let caller: Vec<&[u8]> = frames
        .iter()
        .filter(|u| u.dport == 30018)
        .map(|u| u.payload)
        .collect();
    let relayed: Vec<RtpFields> = frames
        .iter()
        .filter(|u| u.dport == 6000)
        .map(|u| rtp_of(u.payload).expect("rtp"))
        .collect();
    assert_eq!(caller.len(), 21);
    for (n, (sent, played)) in caller.iter().zip(&media).enumerate() {
        assert!(
            *sent == played.as_slice(),
            "caller packet {n} is not g722.pcap's packet {n}"
        );
    }
    assert_eq!(relayed.len(), 19);
    for (n, out) in relayed.iter().enumerate() {
        let inp = rtp_of(caller[n]).expect("rtp");
        assert_eq!((inp.pt, out.pt), (9, 0), "G.722 in, PCMU out");
        assert_eq!((out.seq, out.ts, out.ssrc), (inp.seq, inp.ts, inp.ssrc));
    }
}

/// The control plane keeps OpenSIPS's shapes: the Call-ID on every datagram's
/// correlation chunk, requests keyed in OpenSIPS's order with `sdp` first and
/// `command` last, replies with no `call-id`, and the relay's ports only in
/// the replies.
#[test]
fn the_opensips_control_plane_keeps_its_wire_shapes() {
    let recs = records(&committed(OS_NG));
    let bodies: Vec<String> = recs
        .iter()
        .filter_map(|r| udp_of(&r.data))
        .filter(|u| u.dport == 9060)
        .map(|u| {
            let chunks = hep_chunks(u.payload);
            let find = |k: u16| chunks.iter().find(|(t, _)| *t == k).map(|(_, v)| *v);
            assert_eq!(find(0x0b), Some(&[0x3d][..]), "capture protocol ng");
            assert_eq!(find(0x11), Some(&b"1-4062@198.51.100.21"[..]));
            let payload = find(0x0f).expect("payload chunk");
            let space = payload.iter().position(|b| *b == b' ').expect("cookie");
            String::from_utf8_lossy(&payload[space + 1..]).into_owned()
        })
        .collect();
    let [offer, offer_reply, answer, answer_reply] = &bodies[..] else {
        panic!("four bodies, not {}", bodies.len());
    };
    for (request, command) in [(offer, "5:offer"), (answer, "6:answer")] {
        assert!(request.starts_with("d3:sdp"), "{request}");
        assert!(
            request.ends_with(&format!("7:command{command}e")),
            "{request}"
        );
        assert!(request.contains("13:received-froml3:IP4"), "{request}");
    }
    assert!(offer.contains("m=audio 6000 RTP/AVP 9 101"), "{offer}");
    assert!(answer.contains("m=audio 6000 RTP/AVP 0\r\n"), "{answer}");
    assert!(answer.contains("6:to-tag"), "{answer}");
    for (reply, port) in [(offer_reply, 30020), (answer_reply, 30018)] {
        assert!(!reply.contains("call-id"), "{reply}");
        assert!(reply.contains("c=IN IP4 198.51.100.10"), "{reply}");
        assert!(reply.contains(&format!("m=audio {port} ")), "{reply}");
        assert!(reply.ends_with("6:result2:oke"), "{reply}");
    }
}
