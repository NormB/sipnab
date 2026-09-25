// SPDX-License-Identifier: MIT OR Apache-2.0

//! The synthetic captures outside `tests/pcap-samples/`, built from code.
//!
//! Every capture this module owns is fabricated from end to end, so anyone can
//! rebuild the exact committed bytes and read in a diff what each one holds.
//! The repository is public, and a capture nobody can reproduce is one nobody
//! can prove carries no traffic from a real network.
//!
//! Identifiers come from ranges reserved for documentation and nothing else:
//! IPv4 addresses from RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
//! 203.0.113.0/24) plus loopback where a protocol names it, MAC addresses from
//! the RFC 7042 documentation block (00:00:5E:00:53:xx) or all-zero, and SIP
//! hosts from RFC 2606 `example.*` labels or those same address literals. One
//! address is outside them on purpose: `stun_sdp_mismatch` is about a phone
//! advertising its RFC 1918 address, so 192.168.10.50 is the point of it, and
//! `DELIBERATE` in the test lists it with that reason.
//!
//! The audio in the media captures comes from `codecs.rs`, which the including
//! crate declares as a sibling module: tones from an integer sine table, and
//! the G.711 and G.722 encoders that put them on the wire.
//!
//! Deterministic: fixed epochs, fixed identifiers, no randomness and no clock
//! reads. `tests/synthetic_captures_test.rs` rebuilds every capture listed in
//! [`OWNED`] and fails if a byte of the committed file differs, so the
//! generator and the fixture cannot drift apart.
//!
//! To rewrite the files after changing a builder:
//!
//! ```text
//! cargo run --features native --bin gen_fixture
//! ```
//!
//! `src/bin/gen_fixture.rs` includes this file with `#[path]` and writes every
//! entry of [`OWNED`]. The test compares and never writes, so the suite cannot
//! rewrite the files it checks.
#![allow(dead_code)]

use super::codecs;

/// One committed capture this module owns: where it lives and what builds it.
pub struct Owned {
    /// Repository-relative path of the committed file.
    pub path: &'static str,
    /// The builder whose output must equal the committed bytes.
    pub build: fn() -> Vec<u8>,
}

/// Every capture this module writes, in the order `gen_fixture` writes them.
pub const OWNED: &[Owned] = &[
    Owned {
        path: "tests/fixtures/sip_call.pcap",
        build: sip_call,
    },
    Owned {
        path: "tests/fixtures/udp_5060.pcap",
        build: udp_5060,
    },
    Owned {
        path: "tests/fixtures/rtpengine-ng-hep.pcap",
        build: rtpengine_ng_hep,
    },
    Owned {
        path: "tests/fixtures/rtpengine-media-only.pcap",
        build: rtpengine_media_only,
    },
    Owned {
        path: "fuzz/corpus/pcap_reader/truncated-sip",
        build: truncated_sip,
    },
    Owned {
        path: "fuzz/corpus/pcap_reader/empty-classic",
        build: empty_classic,
    },
    Owned {
        path: "harness/sipp/scenarios/g711a.pcap",
        build: g711a_media,
    },
    Owned {
        path: "harness/sipp/scenarios/g722.pcap",
        build: g722_media,
    },
    Owned {
        path: "tests/fixtures/rtpengine-opensips-ng.pcap",
        build: rtpengine_opensips_ng,
    },
    Owned {
        path: "tests/fixtures/rtpengine-opensips-media-only.pcap",
        build: rtpengine_opensips_media_only,
    },
    Owned {
        path: "tests/fixtures/opensips-proxy-signaling.pcap",
        build: opensips_proxy_signaling,
    },
    Owned {
        path: "tests/fixtures/ice_checks.pcap",
        build: ice_checks,
    },
    Owned {
        path: "tests/fixtures/turn_relay.pcap",
        build: turn_relay,
    },
    Owned {
        path: "tests/fixtures/stun_nat_probe.pcap",
        build: stun_nat_probe,
    },
    Owned {
        path: "tests/fixtures/stun_sdp_mismatch.pcap",
        build: stun_sdp_mismatch,
    },
    Owned {
        path: "tests/fixtures/sip-answered-never-acked.pcap",
        build: answered_never_acked,
    },
    Owned {
        path: "tests/fixtures/sip-scanner-and-register-flood.pcap",
        build: scanner_and_register_flood,
    },
];

// ── the pcap container ──────────────────────────────────────────────

/// LINKTYPE_ETHERNET.
const ETHERNET: u32 = 1;

/// One record of a classic pcap file.
struct Record {
    sec: u32,
    usec: u32,
    /// Length of the packet on the wire. Equal to `data.len()` unless the
    /// record is deliberately snapped short.
    orig_len: u32,
    data: Vec<u8>,
}

impl Record {
    /// A record holding the whole frame.
    fn whole(sec: u32, usec: u32, data: Vec<u8>) -> Self {
        Self {
            sec,
            usec,
            orig_len: data.len() as u32,
            data,
        }
    }
}

/// A little-endian, microsecond, Ethernet classic pcap file.
///
/// Magic `0xA1B2C3D4` written little-endian, version 2.4, zone and sigfigs
/// zero: the header libpcap and tcpdump write on every little-endian host.
fn pcap(snaplen: u32, records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&snaplen.to_le_bytes());
    out.extend_from_slice(&ETHERNET.to_le_bytes());
    for r in records {
        out.extend_from_slice(&r.sec.to_le_bytes());
        out.extend_from_slice(&r.usec.to_le_bytes());
        out.extend_from_slice(&(r.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&r.orig_len.to_le_bytes());
        out.extend_from_slice(&r.data);
    }
    out
}

// ── Ethernet, IPv4, UDP ─────────────────────────────────────────────

/// The IPv4 header fields a builder chooses.
#[derive(Clone, Copy)]
struct Ip {
    src: [u8; 4],
    dst: [u8; 4],
    /// The whole TOS byte: DSCP in the top six bits.
    tos: u8,
    ident: u16,
    /// Flags and fragment offset: `0x4000` is DF, `0x2000` is MF.
    flags: u16,
    /// Whether to fill in the header checksum or leave it zero.
    checksum: bool,
}

/// DF set, fragment offset zero.
const DF: u16 = 0x4000;
/// More-fragments set, fragment offset zero: the first fragment of several.
const MF: u16 = 0x2000;

/// One's-complement sum of `data` as 16-bit big-endian words, not yet
/// inverted, so a pseudo-header and a datagram can be summed in pieces.
fn ones_sum(data: &[u8], mut sum: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    sum
}

/// Fold a running sum to 16 bits and invert it.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A UDP header plus `payload`.
///
/// With `checksum` false the checksum field is zero, which RFC 768 defines as
/// "not computed" and is legal for IPv4. With it true the checksum covers the
/// RFC 768 pseudo-header, as a kernel's would.
fn udp(ip: &Ip, sport: u16, dport: u16, payload: &[u8], checksum: bool) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut d = Vec::with_capacity(len as usize);
    d.extend_from_slice(&sport.to_be_bytes());
    d.extend_from_slice(&dport.to_be_bytes());
    d.extend_from_slice(&len.to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    if checksum {
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&ip.src);
        pseudo.extend_from_slice(&ip.dst);
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&len.to_be_bytes());
        let mut ck = fold(ones_sum(&d, ones_sum(&pseudo, 0)));
        if ck == 0 {
            ck = 0xffff; // RFC 768: a computed zero is sent as all ones
        }
        d[6..8].copy_from_slice(&ck.to_be_bytes());
    }
    d
}

/// An IPv4 header (no options) in front of `payload`, carrying UDP.
///
/// `payload` is what this packet holds. For a first fragment that is only the
/// front of the datagram, and the total length describes this packet, not the
/// datagram it was cut from.
fn ipv4_udp(ip: &Ip, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut h = Vec::with_capacity(total as usize);
    h.extend_from_slice(&[0x45, ip.tos]);
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&ip.ident.to_be_bytes());
    h.extend_from_slice(&ip.flags.to_be_bytes());
    h.extend_from_slice(&[64, 17, 0, 0]);
    h.extend_from_slice(&ip.src);
    h.extend_from_slice(&ip.dst);
    if ip.checksum {
        let ck = fold(ones_sum(&h, 0));
        h[10..12].copy_from_slice(&ck.to_be_bytes());
    }
    h.extend_from_slice(payload);
    h
}

/// An Ethernet II frame carrying IPv4.
fn ethernet(dst: [u8; 6], src: [u8; 6], ip_packet: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + ip_packet.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(ip_packet);
    f
}

/// A MAC address from the RFC 7042 section 2.1.2 documentation block.
const fn doc_mac(last: u8) -> [u8; 6] {
    [0x00, 0x00, 0x5e, 0x00, 0x53, last]
}

// ── sip_call.pcap and udp_5060.pcap ─────────────────────────────────
//
// The two oldest fixtures. `src/bin/gen_fixture.rs` wrote them through libpcap
// from April 2026 with private RFC 1918 addresses; the frames here are the same
// frames byte for byte except for the addresses, which moved to RFC 5737 space. That
// is why these two keep the old generator's shape: zero MACs, zero IP
// identification, both checksums left at zero, and libpcap's 65535 snaplen.
// Changing any of those would change what the tests that read them see for a
// reason unrelated to where the addresses came from.

/// The legacy frame shape: zero MACs, IP ident 0, DF, no checksums.
fn legacy_udp_frame(src: [u8; 4], dst: [u8; 4], port: u16, payload: &[u8]) -> Vec<u8> {
    let ip = Ip {
        src,
        dst,
        tos: 0,
        ident: 0,
        flags: DF,
        checksum: false,
    };
    ethernet(
        [0; 6],
        [0; 6],
        &ipv4_udp(&ip, &udp(&ip, port, port, payload, false)),
    )
}

/// The epoch every legacy fixture starts at: 2023-11-14T22:13:20Z.
const LEGACY_EPOCH: u32 = 1_700_000_000;

/// The caller in `sip_call.pcap`, and the sender in `udp_5060.pcap`.
const CALLER: [u8; 4] = [192, 0, 2, 1];
/// The callee in `sip_call.pcap`.
const CALLEE: [u8; 4] = [192, 0, 2, 2];

/// Ten minimal `200 OK` datagrams, 192.0.2.1 to 192.0.2.2 through .11, one
/// second apart.
///
/// Each goes to a different address on purpose: tests count packets, filter
/// on the port, and read ten distinct destinations.
pub fn udp_5060() -> Vec<u8> {
    let records: Vec<Record> = (0u8..10)
        .map(|i| {
            let payload = format!("SIP/2.0 200 OK\r\nSeq: {i}\r\n\r\n");
            let dst = [192, 0, 2, i + 2];
            Record::whole(
                LEGACY_EPOCH + u32::from(i),
                0,
                legacy_udp_frame(CALLER, dst, 5060, payload.as_bytes()),
            )
        })
        .collect();
    pcap(65535, &records)
}

/// One complete call: INVITE, 100, 180, 200, ACK, then BYE and its 200.
///
/// Seven messages over sixty seconds, no SDP bodies and no media. The
/// Call-ID, tags and branches are the ones tests quote.
pub fn sip_call() -> Vec<u8> {
    let call_id = "test-call-1@192.0.2.1";
    let head = |first: &str, branch: &str, to_tag: bool, cseq: &str| {
        let to_tag = if to_tag { ";tag=a6c85cf" } else { "" };
        format!(
            "{first}\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n"
        ) + &format!(
            "To: <sip:1002@192.0.2.2>{to_tag}\r\n\
             From: <sip:1001@192.0.2.1>;tag=1928301774\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n"
        )
    };
    // (offset in ms, from caller?, message)
    let messages: [(u32, bool, String); 7] = [
        (
            0,
            true,
            format!(
                "INVITE sip:1002@192.0.2.2 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
                 Max-Forwards: 70\r\n\
                 To: <sip:1002@192.0.2.2>\r\n\
                 From: <sip:1001@192.0.2.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 1 INVITE\r\n\
                 Contact: <sip:1001@192.0.2.1:5060>\r\n\
                 User-Agent: sipnab-test/1.0\r\n\
                 Content-Type: application/sdp\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        (
            100,
            false,
            head("SIP/2.0 100 Trying", "z9hG4bK776asdhds", false, "1 INVITE")
                + "Content-Length: 0\r\n\r\n",
        ),
        (
            500,
            false,
            head("SIP/2.0 180 Ringing", "z9hG4bK776asdhds", true, "1 INVITE")
                + "Content-Length: 0\r\n\r\n",
        ),
        (
            2000,
            false,
            head("SIP/2.0 200 OK", "z9hG4bK776asdhds", true, "1 INVITE")
                + "Contact: <sip:1002@192.0.2.2:5060>\r\n\
                   Content-Length: 0\r\n\r\n",
        ),
        (
            2050,
            true,
            format!(
                "ACK sip:1002@192.0.2.2 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdack\r\n\
                 Max-Forwards: 70\r\n\
                 To: <sip:1002@192.0.2.2>;tag=a6c85cf\r\n\
                 From: <sip:1001@192.0.2.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 1 ACK\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        (
            60_000,
            true,
            format!(
                "BYE sip:1002@192.0.2.2 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdbye\r\n\
                 Max-Forwards: 70\r\n\
                 To: <sip:1002@192.0.2.2>;tag=a6c85cf\r\n\
                 From: <sip:1001@192.0.2.1>;tag=1928301774\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: 2 BYE\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            ),
        ),
        (
            60_100,
            false,
            head("SIP/2.0 200 OK", "z9hG4bK776asdbye", true, "2 BYE") + "Content-Length: 0\r\n\r\n",
        ),
    ];
    let records: Vec<Record> = messages
        .iter()
        .map(|(ms, from_caller, text)| {
            let (src, dst) = if *from_caller {
                (CALLER, CALLEE)
            } else {
                (CALLEE, CALLER)
            };
            Record::whole(
                LEGACY_EPOCH + ms / 1000,
                (ms % 1000) * 1000,
                legacy_udp_frame(src, dst, 5060, text.as_bytes()),
            )
        })
        .collect();
    pcap(65535, &records)
}

// ── fuzz seeds ──────────────────────────────────────────────────────

/// A classic pcap header and no records at all: the smallest valid file.
///
/// Snaplen zero, which a reader must accept rather than divide by or allocate
/// from.
pub fn empty_classic() -> Vec<u8> {
    pcap(0, &[])
}

/// A SIP exchange whose capture is cut short twice over.
///
/// Three records. The first holds a whole INVITE. The second holds a 180
/// Ringing snapped to its first 96 bytes, so its captured length is below its
/// length on the wire, as a small `-s` snaplen produces. The third record's
/// header promises a whole 200 OK and the file ends 40 bytes into it, which
/// is what a capture killed mid-write leaves behind. A reader must yield the
/// first two and stop at the third without reading past the end.
pub fn truncated_sip() -> Vec<u8> {
    const UAC: [u8; 4] = [192, 0, 2, 10];
    const UAS: [u8; 4] = [198, 51, 100, 20];
    let frame = |src: [u8; 4], dst: [u8; 4], ident: u16, text: &str| {
        let ip = Ip {
            src,
            dst,
            tos: 0,
            ident,
            flags: DF,
            checksum: true,
        };
        let (s, d) = if src == UAC {
            (doc_mac(0x10), doc_mac(0x20))
        } else {
            (doc_mac(0x20), doc_mac(0x10))
        };
        ethernet(
            d,
            s,
            &ipv4_udp(&ip, &udp(&ip, 5060, 5060, text.as_bytes(), true)),
        )
    };
    let common = "From: <sip:alice@example.com>;tag=seed-from\r\n\
                  Call-ID: truncated-seed-1@example.com\r\n";
    let invite = format!(
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-seed-1\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:bob@example.net>\r\n\
         {common}\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@192.0.2.10:5060>\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let reply = |status: &str| {
        format!(
            "SIP/2.0 {status}\r\n\
             Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-seed-1\r\n\
             To: <sip:bob@example.net>;tag=seed-to\r\n\
             {common}\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:bob@198.51.100.20:5060>\r\n\
             Content-Length: 0\r\n\r\n"
        )
    };

    let first = frame(UAC, UAS, 1, &invite);
    let ringing = frame(UAS, UAC, 1, &reply("180 Ringing"));
    let ok = frame(UAS, UAC, 2, &reply("200 OK"));

    let snapped = Record {
        sec: LEGACY_EPOCH,
        usec: 120_000,
        orig_len: ringing.len() as u32,
        data: ringing[..96].to_vec(),
    };
    let mut out = pcap(65535, &[Record::whole(LEGACY_EPOCH, 0, first), snapped]);
    // The third record: a header claiming the whole 200 OK, then 40 bytes of
    // it and end of file.
    out.extend_from_slice(&LEGACY_EPOCH.to_le_bytes());
    out.extend_from_slice(&450_000u32.to_le_bytes());
    out.extend_from_slice(&(ok.len() as u32).to_le_bytes());
    out.extend_from_slice(&(ok.len() as u32).to_le_bytes());
    out.extend_from_slice(&ok[..40]);
    out
}

// ── rtpengine-ng-hep.pcap and rtpengine-media-only.pcap ─────────────
//
// What a capture on a standalone rtpengine relay looks like when the relay
// mirrors its `ng` control plane to a Homer collector with
// `--homer-enable-ng`: six HEP datagrams (`offer`, `answer` and `delete`, each
// followed by its reply) and forty relayed RTP packets on the four sockets
// those commands allocated. No SIP anywhere, because a relay carries none.
//
// Until September 2026 this pair was a live capture from a lab relay running
// rtpengine 12.5.1 (commit af901fa2). It is rebuilt here so that no address,
// MAC or nonce from that network is committed, while keeping every property
// the live exchange showed and the tests rely on:
//
// * `ng` key order as rtpengine sends it, which is NOT the sorted order the
//   bencode specification requires: `command`, `call-id`, `from-tag`,
//   (`to-tag`,) `sdp`.
// * Replies carry no `call-id`. An offer reply is `d3:sdp<n>:...6:result2:oke`
//   and the Call-ID reaches it only through the HEP correlation-id chunk.
// * HEP chunks in rtpengine's order, capture protocol 0x3d, capture agent
//   2001, and the ng socket's loopback addresses in the inner address chunks.
// * The relay-port semantics: the offer REPLY carries the relay port the
//   answerer must send to (38664) and the answer reply the one the offerer
//   must send to (38156). Party A sends from 40001 to 38156, party B from
//   40002 to 38664, and the relay forwards each SSRC out of the other leg's
//   socket.
// * The first three packets of each leg are forwarded in userspace, with DF
//   set, and the rest by the kernel module with DF clear. DSCP EF on every
//   packet the relay sends.
// * The `delete` reply carries the call's statistics and exceeds the MTU, so
//   it leaves the relay as two IP fragments. A capture filtered on a UDP port
//   matches only the first fragment, which holds the UDP header, and that is
//   the only one here. Its IP total length describes the fragment while its
//   UDP and HEP lengths describe the whole datagram.
//
// Timing is as measured on the live exchange: the control plane, eleven
// seconds of idle, then the media window, then the delete thirty-one seconds
// later. Addresses map one to one: the relay is 192.0.2.40 and the host
// running both parties and the collector is 192.0.2.60, the same addresses
// docs/rtpengine.md already printed for this capture.

/// The relay.
const RELAY: [u8; 4] = [192, 0, 2, 40];
/// The host running both parties and the Homer collector.
const PARTIES: [u8; 4] = [192, 0, 2, 60];
/// The Call-ID the driving script minted for the relay's call.
const RELAY_CALL_ID: &str = "km-670bd208@sipnab";
/// The Homer port the relay mirrors to.
const HOMER_PORT: u16 = 9060;
/// The relay's HEP source port.
const RELAY_HEP_PORT: u16 = 59652;
/// rtpengine's `ng` port.
const NG_PORT: u16 = 2223;

/// A bencode value, with dictionaries kept in the order they are written.
///
/// rtpengine does not sort its keys, so an encoder that sorted them would
/// build something rtpengine never sends.
enum Ben {
    Int(i64),
    Str(String),
    List(Vec<Ben>),
    Dict(Vec<(String, Ben)>),
}

impl Ben {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Ben::Int(i) => out.extend_from_slice(format!("i{i}e").as_bytes()),
            Ben::Str(s) => {
                out.extend_from_slice(format!("{}:", s.len()).as_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            Ben::List(items) => {
                out.push(b'l');
                for item in items {
                    item.encode(out);
                }
                out.push(b'e');
            }
            Ben::Dict(pairs) => {
                out.push(b'd');
                for (k, v) in pairs {
                    Ben::Str(k.clone()).encode(out);
                    v.encode(out);
                }
                out.push(b'e');
            }
        }
    }
}

/// A bencode string.
fn bs(s: &str) -> Ben {
    Ben::Str(s.to_string())
}

/// A bencode dictionary from `(key, value)` pairs, order kept.
fn bd(pairs: Vec<(&str, Ben)>) -> Ben {
    Ben::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// An `ng` message: cookie, one space, bencoded body.
fn ng(cookie: &str, body: &Ben) -> Vec<u8> {
    let mut out = format!("{cookie} ").into_bytes();
    body.encode(&mut out);
    out
}

/// The SDP a party offers or answers with: one PCMU stream at `port`.
fn party_sdp(port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.60\r\ns=-\r\nc=IN IP4 192.0.2.60\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
    )
}

/// The SDP rtpengine returns: the relay's own socket in `c=` and `m=`, the
/// party's origin line kept, and an explicit `a=rtcp` for the port above.
fn relay_sdp(port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.60\r\ns=-\r\nc=IN IP4 192.0.2.40\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp:{}\r\n",
        port + 1
    )
}

/// A HEP v3 datagram mirroring one `ng` message of the call `call_id`, chunks
/// in rtpengine's order.
fn hep_ng(call_id: &str, sec: u32, usec: u32, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
        out.extend_from_slice(&0u16.to_be_bytes()); // vendor: generic
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&((6 + data.len()) as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    let mut body = Vec::new();
    chunk(&mut body, 0x0001, &[2]); // IP family: IPv4
    chunk(&mut body, 0x0002, &[17]); // IP protocol: UDP
    chunk(&mut body, 0x0007, &sport.to_be_bytes());
    chunk(&mut body, 0x0008, &dport.to_be_bytes());
    chunk(&mut body, 0x0009, &sec.to_be_bytes());
    chunk(&mut body, 0x000a, &usec.to_be_bytes());
    chunk(&mut body, 0x000b, &[0x3d]); // capture protocol: rtpengine ng
    chunk(&mut body, 0x000c, &2001u32.to_be_bytes()); // capture agent id
    chunk(&mut body, 0x0003, &[127, 0, 0, 1]); // the ng client, on loopback
    chunk(&mut body, 0x0004, &[127, 0, 0, 1]);
    chunk(&mut body, 0x0011, call_id.as_bytes()); // correlation id
    chunk(&mut body, 0x000f, payload);
    let mut out = Vec::with_capacity(6 + body.len());
    out.extend_from_slice(b"HEP3");
    out.extend_from_slice(&((6 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// The stream record rtpengine's `delete` reply carries for one socket.
#[allow(clippy::too_many_arguments)]
fn delete_stream(
    local_port: u16,
    endpoint_port: u16,
    rtcp: bool,
    last_packet: i64,
    last_kernel: i64,
    last_user: i64,
    ingress: Option<(i64, i64, i64, i64, i64)>,
    egress: Option<(i64, i64, i64, i64, i64)>,
    stats: (i64, i64),
) -> Ben {
    let endpoint = || {
        bd(vec![
            ("family", bs("IPv4")),
            ("address", bs("192.0.2.60")),
            ("port", Ben::Int(i64::from(endpoint_port))),
        ])
    };
    let ssrcs = |s: Option<(i64, i64, i64, i64, i64)>| match s {
        None => Ben::List(vec![]),
        Some((ssrc, bytes, packets, ts, seq)) => Ben::List(vec![bd(vec![
            ("SSRC", Ben::Int(ssrc)),
            ("bytes", Ben::Int(bytes)),
            ("packets", Ben::Int(packets)),
            ("last RTP timestamp", Ben::Int(ts)),
            ("last RTP seq", Ben::Int(seq)),
        ])]),
    };
    let flags = if rtcp {
        vec![bs("RTCP"), bs("filled")]
    } else {
        vec![bs("RTP"), bs("filled"), bs("confirmed"), bs("kernelized")]
    };
    let counters = || {
        bd(vec![
            ("packets", Ben::Int(stats.0)),
            ("bytes", Ben::Int(stats.1)),
            ("errors", Ben::Int(0)),
        ])
    };
    bd(vec![
        ("local port", Ben::Int(i64::from(local_port))),
        ("local address", bs("192.0.2.40")),
        ("family", bs("IPv4")),
        ("endpoint", endpoint()),
        ("advertised endpoint", endpoint()),
        ("last packet", Ben::Int(last_packet)),
        ("last kernel packet", Ben::Int(last_kernel)),
        ("last user packet", Ben::Int(last_user)),
        ("flags", Ben::List(flags)),
        ("ingress SSRCs", ssrcs(ingress)),
        ("egress SSRCs", ssrcs(egress)),
        ("stats", counters()),
        ("stats_out", counters()),
    ])
}

/// The body of rtpengine's reply to `delete`: the call's final statistics.
///
/// The shape up to the second stream's `stats` key is the one the live relay
/// sent. The rest of that reply was in the second IP fragment, which a
/// port-filtered capture never sees, so the remainder here is the same
/// structure completed for the other leg plus the totals. None of it reaches
/// the committed file except through the length fields.
fn delete_reply_body(created: i64) -> Ben {
    const SSRC_A: i64 = 0x0a0a_0a0a;
    const SSRC_B: i64 = 0x0b0b_0b0b;
    let last = created + 14;
    let subscription = |tag: &str| {
        Ben::List(vec![bd(vec![
            ("tag", bs(tag)),
            ("type", bs("offer/answer")),
        ])])
    };
    // One leg: the tag, who it is subscribed to, and its media with the RTP
    // and RTCP sockets the relay holds for it.
    let leg = |tag: &str, peer: &str, rtp: u16, party: u16, ingress: i64, egress: i64| {
        bd(vec![
            ("tag", bs(tag)),
            ("created", Ben::Int(created)),
            ("subscriptions", subscription(peer)),
            ("subscribers", subscription(peer)),
            (
                "medias",
                Ben::List(vec![bd(vec![
                    ("index", Ben::Int(1)),
                    ("type", bs("audio")),
                    ("protocol", bs("RTP/AVP")),
                    ("codec", bs("PCMU/8000")),
                    (
                        "streams",
                        Ben::List(vec![
                            delete_stream(
                                rtp,
                                party,
                                false,
                                last,
                                last,
                                created + 11,
                                Some((ingress, 516, 3, 320, 149)),
                                Some((egress, 24036, 150, 23840, 149)),
                                (150, 25800),
                            ),
                            delete_stream(
                                rtp + 1,
                                party + 1,
                                true,
                                created,
                                0,
                                created,
                                None,
                                None,
                                (0, 0),
                            ),
                        ]),
                    ),
                ])]),
            ),
        ])
    };
    bd(vec![
        ("created", Ben::Int(created)),
        ("created_us", Ben::Int(337_633)),
        ("last signal", Ben::Int(created)),
        ("last redis update", Ben::Int(0)),
        ("SSRC", Ben::Dict(vec![])),
        (
            "tags",
            bd(vec![
                ("ftag1", leg("ftag1", "ttag1", 38156, 40001, SSRC_A, SSRC_B)),
                ("ttag1", leg("ttag1", "ftag1", 38664, 40002, SSRC_B, SSRC_A)),
            ]),
        ),
        (
            "totals",
            bd(vec![
                (
                    "RTP",
                    bd(vec![
                        ("packets", Ben::Int(300)),
                        ("bytes", Ben::Int(51600)),
                        ("errors", Ben::Int(0)),
                    ]),
                ),
                (
                    "RTCP",
                    bd(vec![
                        ("packets", Ben::Int(0)),
                        ("bytes", Ben::Int(0)),
                        ("errors", Ben::Int(0)),
                    ]),
                ),
            ]),
        ),
        ("result", bs("ok")),
    ])
}

/// The six control-plane datagrams, as `(frame sec, frame usec, frame)`.
fn relay_control_frames() -> Vec<(u32, u32, Vec<u8>)> {
    // One cookie per transaction, as the protocol requires. Fixed labels, not
    // anything a live client minted.
    const OFFER_COOKIE: &str = "5eed0000000000000000000000000001";
    const ANSWER_COOKIE: &str = "5eed0000000000000000000000000002";
    const DELETE_COOKIE: &str = "5eed0000000000000000000000000003";
    const SETUP: u32 = 1_787_406_991;
    const TEARDOWN: u32 = 1_787_407_033;

    let offer = bd(vec![
        ("command", bs("offer")),
        ("call-id", bs(RELAY_CALL_ID)),
        ("from-tag", bs("ftag1")),
        ("sdp", Ben::Str(party_sdp(40001))),
    ]);
    let offer_reply = bd(vec![
        ("sdp", Ben::Str(relay_sdp(38664))),
        ("result", bs("ok")),
    ]);
    let answer = bd(vec![
        ("command", bs("answer")),
        ("call-id", bs(RELAY_CALL_ID)),
        ("from-tag", bs("ftag1")),
        ("to-tag", bs("ttag1")),
        ("sdp", Ben::Str(party_sdp(40002))),
    ]);
    let answer_reply = bd(vec![
        ("sdp", Ben::Str(relay_sdp(38156))),
        ("result", bs("ok")),
    ]);
    let delete = bd(vec![
        ("command", bs("delete")),
        ("call-id", bs(RELAY_CALL_ID)),
    ]);
    let delete_reply = delete_reply_body(i64::from(SETUP));

    // (frame sec, frame usec, HEP usec, client port, from client?, cookie, body)
    let schedule: [(u32, u32, u32, u16, bool, &str, &Ben); 6] = [
        (SETUP, 338_134, 338_017, 43734, true, OFFER_COOKIE, &offer),
        (
            SETUP,
            338_166,
            338_158,
            43734,
            false,
            OFFER_COOKIE,
            &offer_reply,
        ),
        (SETUP, 338_592, 338_579, 56389, true, ANSWER_COOKIE, &answer),
        (
            SETUP,
            338_625,
            338_610,
            56389,
            false,
            ANSWER_COOKIE,
            &answer_reply,
        ),
        (
            TEARDOWN,
            376_072,
            376_051,
            52471,
            true,
            DELETE_COOKIE,
            &delete,
        ),
        (
            TEARDOWN,
            376_158,
            376_118,
            52471,
            false,
            DELETE_COOKIE,
            &delete_reply,
        ),
    ];

    let mut frames = Vec::new();
    for (n, (sec, usec, hep_usec, client, from_client, cookie, body)) in
        schedule.into_iter().enumerate()
    {
        let (sport, dport) = if from_client {
            (client, NG_PORT)
        } else {
            (NG_PORT, client)
        };
        let hep = hep_ng(
            RELAY_CALL_ID,
            sec,
            hep_usec,
            sport,
            dport,
            &ng(cookie, body),
        );
        let mut ip = Ip {
            src: RELAY,
            dst: PARTIES,
            tos: 0,
            ident: 13_179 + n as u16,
            flags: DF,
            checksum: true,
        };
        let datagram = udp(&ip, RELAY_HEP_PORT, HOMER_PORT, &hep, true);
        // An MTU of 1500 leaves 1480 bytes of datagram per fragment. Only the
        // delete reply exceeds it, and only its first fragment is kept.
        let packet = if datagram.len() > 1480 {
            ip.flags = MF;
            ipv4_udp(&ip, &datagram[..1480])
        } else {
            ipv4_udp(&ip, &datagram)
        };
        frames.push((sec, usec, ethernet(doc_mac(0x60), doc_mac(0x40), &packet)));
    }
    frames
}

/// The forty relayed RTP packets, as `(frame sec, frame usec, frame)`.
fn relay_media_frames() -> Vec<(u32, u32, Vec<u8>)> {
    /// Microseconds from the first media packet, which socket, and the
    /// sequence number: the order and spacing the live relay showed. The
    /// first three of each leg arrive in one burst before the 20 ms cadence
    /// settles, and in the last two rounds party B's packet lands after the
    /// relay has already forwarded party A's.
    #[derive(Clone, Copy)]
    enum Leg {
        /// Party A (40001) to the relay's 38156.
        AToRelay,
        /// Party B (40002) to the relay's 38664.
        BToRelay,
        /// The relay's 38664 to party B, carrying party A's SSRC.
        RelayToB,
        /// The relay's 38156 to party A, carrying party B's SSRC.
        RelayToA,
    }
    use Leg::{AToRelay as A, BToRelay as B, RelayToA as RA, RelayToB as RB};
    const SCHEDULE: [(u32, Leg, u16); 40] = [
        (0, A, 0),
        (207, B, 0),
        (208, A, 1),
        (208, B, 1),
        (208, A, 2),
        (208, B, 2),
        (261, RB, 0),
        (346, RB, 1),
        (377, RB, 2),
        (553, RA, 0),
        (639, RA, 1),
        (680, RA, 2),
        (9140, A, 3),
        (9140, B, 3),
        (9159, RB, 3),
        (9167, RA, 3),
        (29218, A, 4),
        (29218, B, 4),
        (29231, RB, 4),
        (29240, RA, 4),
        (49282, A, 5),
        (49282, B, 5),
        (49297, RB, 5),
        (49307, RA, 5),
        (69320, A, 6),
        (69320, B, 6),
        (69355, RB, 6),
        (69369, RA, 6),
        (89385, A, 7),
        (89385, B, 7),
        (89400, RB, 7),
        (89408, RA, 7),
        (109439, A, 8),
        (109453, RB, 8),
        (109681, B, 8),
        (109690, RA, 8),
        (129495, A, 9),
        (129514, RB, 9),
        (129775, B, 9),
        (129794, RA, 9),
    ];
    const START_SEC: u32 = 1_787_407_002;
    const START_USEC: u32 = 573_815;
    const SSRC_A: u32 = 0x0a0a_0a0a;
    const SSRC_B: u32 = 0x0b0b_0b0b;

    let mut party_ident: u16 = 38_295;
    let mut relay_ident: u16 = 21_022;
    let mut frames = Vec::new();
    for (offset, leg, seq) in SCHEDULE {
        let (src, sport, dst, dport, ssrc) = match leg {
            Leg::AToRelay => (PARTIES, 40001, RELAY, 38156, SSRC_A),
            Leg::BToRelay => (PARTIES, 40002, RELAY, 38664, SSRC_B),
            Leg::RelayToB => (RELAY, 38664, PARTIES, 40002, SSRC_A),
            Leg::RelayToA => (RELAY, 38156, PARTIES, 40001, SSRC_B),
        };
        let from_relay = src == RELAY;
        let ident = if from_relay {
            relay_ident += 1;
            relay_ident - 1
        } else {
            party_ident += 1;
            party_ident - 1
        };
        let ip = Ip {
            src,
            dst,
            // The relay marks what it sends EF. Its first three packets per
            // leg go through userspace with DF set; the kernel module then
            // takes over and sends without it.
            tos: if from_relay { 0xb8 } else { 0 },
            ident,
            flags: if from_relay && seq >= 3 { 0 } else { DF },
            checksum: true,
        };
        let mut rtp = Vec::with_capacity(172);
        rtp.extend_from_slice(&[0x80, 0x00]); // v2, no marker, PT 0 (PCMU)
        rtp.extend_from_slice(&seq.to_be_bytes());
        rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
        rtp.extend_from_slice(&ssrc.to_be_bytes());
        rtp.extend_from_slice(&[0xd5; 160]); // 20 ms of one repeated sample
        let (dst_mac, src_mac) = if from_relay {
            (doc_mac(0x60), doc_mac(0x40))
        } else {
            (doc_mac(0x40), doc_mac(0x60))
        };
        let packet = ipv4_udp(&ip, &udp(&ip, sport, dport, &rtp, true));
        let usec = START_USEC + offset;
        frames.push((
            START_SEC + usec / 1_000_000,
            usec % 1_000_000,
            ethernet(dst_mac, src_mac, &packet),
        ));
    }
    frames
}

/// The relay's view with its control plane: six HEP datagrams and the media.
pub fn rtpengine_ng_hep() -> Vec<u8> {
    let mut frames = relay_control_frames();
    frames.extend(relay_media_frames());
    frames.sort_by_key(|(sec, usec, _)| (*sec, *usec));
    let records: Vec<Record> = frames
        .into_iter()
        .map(|(sec, usec, f)| Record::whole(sec, usec, f))
        .collect();
    pcap(262_144, &records)
}

/// The same capture with its six HEP datagrams removed and nothing else
/// changed: the control case, in which every stream is an orphan again.
pub fn rtpengine_media_only() -> Vec<u8> {
    let records: Vec<Record> = relay_media_frames()
        .into_iter()
        .map(|(sec, usec, f)| Record::whole(sec, usec, f))
        .collect();
    pcap(262_144, &records)
}

// ── shared: RTP ─────────────────────────────────────────────────────

/// An RTP packet: the fixed twelve-byte header, no CSRCs, then `payload`.
fn rtp(marker: bool, pt: u8, seq: u16, ts: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + payload.len());
    p.push(0x80); // version 2, no padding, no extension, no CSRCs
    p.push(if marker { 0x80 } else { 0 } | pt);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

// ── g711a.pcap and g722.pcap: SIPp's media files ────────────────────
//
// The files the harness scenarios hand SIPp's `play_pcap_audio`:
// uac_hold.xml plays g711a.pcap and uac_pcap_g722.xml plays g722.pcap. SIPp
// sends each recorded RTP header and payload from the call's own media socket
// at the recorded spacing, so the RTP is all that leaves the file. The
// addresses and MAC addresses around it are never sent anywhere.
//
// Until September 2026 both were copies of third-party captures that stated
// no license. These keep their payload types, their 20 ms framing and their
// packet counts, so a scenario that paused for part of the old file pauses
// for the same part of these: 110.68 s of G.711 A-law and 108.24 s of G.722.
// The audio is the tones in `codecs.rs`: 500 Hz and 1.5 kHz for A-law, 1 kHz
// and 5 kHz for G.722, whose higher sub-band then carries real signal.

/// Where the media files' packets say they came from and went to.
const MEDIA_SRC: [u8; 4] = [192, 0, 2, 10];
const MEDIA_DST: [u8; 4] = [192, 0, 2, 20];
/// The port both ends of the media files use. SIPp replaces it on playback.
const MEDIA_PORT: u16 = 6000;
/// The first media packet's time: 2023-11-14T22:13:20Z, as the other fixtures.
const MEDIA_EPOCH: u32 = LEGACY_EPOCH;

/// Packets in g711a.pcap: 110.68 seconds of 20 ms frames.
pub const G711A_PACKETS: usize = 5535;
/// Packets in g722.pcap: 108.24 seconds of 20 ms frames.
pub const G722_PACKETS: usize = 5413;
/// The SSRC each media file's stream carries.
pub const G711A_SSRC: u32 = 0x0711_a1a1;
pub const G722_SSRC: u32 = 0x0722_0722;
/// RTP payload types from the RFC 3551 static table.
const PT_PCMU: u8 = 0;
const PT_PCMA: u8 = 8;
const PT_G722: u8 = 9;

/// The first `count` G.722 RTP payloads of the wideband signal, 160 bytes
/// (320 samples at 16 kHz) each, from one encoder carried across frames as
/// a real sender's is.
pub fn g722_payloads(count: usize) -> Vec<Vec<u8>> {
    let mut encoder = codecs::G722Encoder::new();
    (0..count)
        .map(|frame| {
            let samples: Vec<i16> = (frame * 320..(frame + 1) * 320)
                .map(codecs::wideband_sample)
                .collect();
            encoder.encode(&samples)
        })
        .collect()
}

/// G.711 A-law payload `frame` of the narrowband signal: 160 samples.
pub fn g711a_payload(frame: usize) -> Vec<u8> {
    (frame * 160..(frame + 1) * 160)
        .map(|n| codecs::alaw(codecs::narrowband_sample(n)))
        .collect()
}

/// A stream's RTP packets: sequence numbers from 1, timestamps from 0 in
/// steps of 160, the marker bit on the first packet only.
///
/// G.722's timestamps advance at 8000 Hz although it samples at 16 kHz, as
/// RFC 3551 section 4.5.2 requires, so 20 ms is 160 for both codecs.
fn media_rtp(pt: u8, ssrc: u32, payloads: impl Iterator<Item = Vec<u8>>) -> Vec<Vec<u8>> {
    payloads
        .enumerate()
        .map(|(i, payload)| rtp(i == 0, pt, (i + 1) as u16, (i as u32) * 160, ssrc, &payload))
        .collect()
}

/// The RTP packets g722.pcap holds, of which the relay fixtures below reuse
/// the first few, as SIPp replayed them.
pub fn g722_rtp(count: usize) -> Vec<Vec<u8>> {
    media_rtp(PT_G722, G722_SSRC, g722_payloads(count).into_iter())
}

/// A SIPp media file: one RTP packet every 20 ms.
fn media_file(packets: &[Vec<u8>]) -> Vec<u8> {
    let records: Vec<Record> = packets
        .iter()
        .enumerate()
        .map(|(i, packet)| {
            let ip = Ip {
                src: MEDIA_SRC,
                dst: MEDIA_DST,
                tos: 0,
                ident: i as u16,
                flags: DF,
                checksum: true,
            };
            let usec = i as u64 * 20_000;
            Record::whole(
                MEDIA_EPOCH + (usec / 1_000_000) as u32,
                (usec % 1_000_000) as u32,
                ethernet(
                    doc_mac(0x20),
                    doc_mac(0x10),
                    &ipv4_udp(&ip, &udp(&ip, MEDIA_PORT, MEDIA_PORT, packet, true)),
                ),
            )
        })
        .collect();
    pcap(65535, &records)
}

/// harness/sipp/scenarios/g711a.pcap.
pub fn g711a_media() -> Vec<u8> {
    let packets = media_rtp(PT_PCMA, G711A_SSRC, (0..G711A_PACKETS).map(g711a_payload));
    media_file(&packets)
}

/// harness/sipp/scenarios/g722.pcap.
pub fn g722_media() -> Vec<u8> {
    media_file(&g722_rtp(G722_PACKETS))
}

// ── rtpengine-opensips-ng.pcap and rtpengine-opensips-media-only.pcap ─
//
// A SIPp call driven through OpenSIPS and rtpengine in the harness, with
// `--homer-enable-ng`, as a SEPARATE relay host sees it: the relay's `ng`
// control plane mirrored over HEP, and the media, and no SIP. The one Call-ID
// in it is the one SIPp minted and OpenSIPS handed the relay
// (`[call_number]-[pid]@[local_ip]`), so a stream that ends up named can only
// have been named through the control plane.
//
// Until September 2026 this pair was a harness capture on the private
// container network whose G.722 payloads were the first 21 frames of the
// third-party g722.pcap. It is rebuilt here keeping what the capture showed:
//
// * four HEP datagrams, `offer` and `answer` with their replies, keyed in
//   OpenSIPS's order (`sdp`, `call-id`, `received-from`, `from-tag`,
//   (`to-tag`,) `command`), which is not sorted either;
// * the caller offering G.722 and the callee answering PCMU only, so the
//   relay transcodes: the caller sends G.722 to the relay's 30018, and the
//   relay sends PCMU to the callee from 30020 under the caller's sequence
//   numbers, timestamps and SSRC;
// * the caller's RTP exactly as SIPp replays it: the first 21 packets of
//   harness/sipp/scenarios/g722.pcap, header and payload;
// * the timing to the microsecond, DF on everything, and DSCP EF on the
//   relay's media.
//
// The relay's PCMU payloads stand in for its transcode: the 1 kHz component of
// the same source signal, the part that survives in narrowband, as mu-law.
// No test reads them beyond their payload type.
//
// Addresses keep the harness's last octets in 198.51.100.0/24: the relay .10,
// the callee .20, the caller .21 and the Homer sink .30.

/// The relay.
const OS_RELAY: [u8; 4] = [198, 51, 100, 10];
/// SIPp's answering side.
const OS_UAS: [u8; 4] = [198, 51, 100, 20];
/// SIPp's calling side.
const OS_UAC: [u8; 4] = [198, 51, 100, 21];
/// The HEP collector the relay mirrors to.
const OS_HOMER: [u8; 4] = [198, 51, 100, 30];
/// The Call-ID SIPp minted and OpenSIPS passed to the relay.
pub const OS_CALL_ID: &str = "1-4062@198.51.100.21";
/// The relay's HEP source port.
const OS_HEP_PORT: u16 = 52954;
/// OpenSIPS's `ng` client port and rtpengine's `ng` listening port.
const OS_NG_CLIENT: u16 = 33539;
const OS_NG_PORT: u16 = 22222;
/// The relay socket the caller sends G.722 to, and the one it sends the
/// callee PCMU from.
const OS_RELAY_FROM_UAC: u16 = 30018;
const OS_RELAY_TO_UAS: u16 = 30020;
/// The second the whole exchange falls in, and the next.
const OS_SEC: u32 = 1_787_422_044;

/// One packet of the relay capture.
#[derive(Clone, Copy)]
enum OsPacket {
    /// Control-plane datagram `n` (offer, reply, answer, reply).
    Hep(usize),
    /// The caller's next G.722 packet to the relay.
    Caller,
    /// The relay's next PCMU packet to the callee.
    Relay,
}

/// Microseconds after `OS_SEC` and which packet, as the harness capture had
/// them.
const OS_SCHEDULE: [(u32, OsPacket); 44] = {
    use OsPacket::{Caller as C, Hep as H, Relay as R};
    [
        (876_001, H(0)),
        (876_036, H(1)),
        (877_993, H(2)),
        (878_015, H(3)),
        (879_383, C),
        (899_215, C),
        (899_296, R),
        (918_901, C),
        (918_957, R),
        (938_857, C),
        (938_891, R),
        (958_873, C),
        (958_906, R),
        (978_836, C),
        (978_863, R),
        (998_820, C),
        (998_847, R),
        (1_019_516, C),
        (1_019_549, R),
        (1_038_949, C),
        (1_038_976, R),
        (1_059_199, C),
        (1_059_231, R),
        (1_079_357, C),
        (1_079_392, R),
        (1_099_084, C),
        (1_099_112, R),
        (1_119_500, C),
        (1_119_542, R),
        (1_138_522, C),
        (1_138_551, R),
        (1_158_914, C),
        (1_158_941, R),
        (1_179_379, C),
        (1_179_405, R),
        (1_199_124, C),
        (1_199_157, R),
        (1_219_037, C),
        (1_219_111, R),
        (1_238_979, C),
        (1_239_013, R),
        (1_259_721, C),
        (1_259_755, R),
        (1_279_136, C),
    ]
};

/// The HEP timestamp of each control-plane datagram, microseconds into
/// `OS_SEC`: when rtpengine saw the message, a little before it sent the copy.
const OS_HEP_USEC: [u32; 4] = [875_981, 876_032, 877_981, 878_012];

/// The SDP SIPp's scenarios send, from `ip`, with `media` after `m=audio`.
fn sipp_sdp(ip: [u8; 4], media: &str, extra: &str) -> String {
    let ip = std::net::Ipv4Addr::from(ip);
    format!(
        "v=0\r\no=user1 53655765 2353687637 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {media}\r\n{extra}"
    )
}

/// The same SDP after rtpengine rewrote it: the relay's address in `c=`, the
/// relay's port in `m=`, the origin line kept, `a=sendrecv` and `a=rtcp`
/// added.
fn relayed_sdp(origin: [u8; 4], port: u16, formats: &str, extra: &str) -> String {
    let origin = std::net::Ipv4Addr::from(origin);
    let relay = std::net::Ipv4Addr::from(OS_RELAY);
    format!(
        "v=0\r\no=user1 53655765 2353687637 IN IP4 {origin}\r\ns=-\r\nc=IN IP4 {relay}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {formats}\r\n{extra}a=sendrecv\r\na=rtcp:{}\r\n",
        port + 1
    )
}

/// SIPp's From tag and To tag for the call.
const OS_FROM_TAG: &str = "4062SIPpTag091";
const OS_TO_TAG: &str = "1SIPpTag0110260";

/// The four SDP bodies of the call, in the order the relay saw them: the
/// caller's offer, the offer as the relay rewrote it for the callee, the
/// callee's answer, and the answer as the relay rewrote it for the caller.
///
/// One definition for both captures of the call: the relay's control plane
/// carries these inside `ng` messages, and the proxy carries them in SIP.
fn opensips_sdps() -> [String; 4] {
    const G722_AND_EVENTS: &str = "a=rtpmap:9 G722/8000\r\n\
                                   a=rtpmap:101 telephone-event/8000\r\n\
                                   a=fmtp:101 0-11,16\r\n";
    [
        sipp_sdp(OS_UAC, "6000 RTP/AVP 9 101", G722_AND_EVENTS),
        relayed_sdp(OS_UAC, OS_RELAY_TO_UAS, "9 101", G722_AND_EVENTS),
        sipp_sdp(OS_UAS, "6000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000\r\n"),
        relayed_sdp(OS_UAS, OS_RELAY_FROM_UAC, "9", "a=rtpmap:9 G722/8000\r\n"),
    ]
}

/// The four control-plane messages, as the `ng` payloads HEP carries.
fn opensips_ng_messages() -> [Vec<u8>; 4] {
    const OFFER_COOKIE: &str = "5eed_1";
    const ANSWER_COOKIE: &str = "5eed_2";
    let [offer_sdp, offer_reply_sdp, answer_sdp, answer_reply_sdp] = opensips_sdps();
    let received_from = |ip: [u8; 4]| {
        Ben::List(vec![
            bs("IP4"),
            bs(&std::net::Ipv4Addr::from(ip).to_string()),
        ])
    };
    let offer = bd(vec![
        ("sdp", Ben::Str(offer_sdp)),
        ("call-id", bs(OS_CALL_ID)),
        ("received-from", received_from(OS_UAC)),
        ("from-tag", bs(OS_FROM_TAG)),
        ("command", bs("offer")),
    ]);
    let offer_reply = bd(vec![
        ("sdp", Ben::Str(offer_reply_sdp)),
        ("result", bs("ok")),
    ]);
    let answer = bd(vec![
        ("sdp", Ben::Str(answer_sdp)),
        ("call-id", bs(OS_CALL_ID)),
        ("received-from", received_from(OS_UAS)),
        ("from-tag", bs(OS_FROM_TAG)),
        ("to-tag", bs(OS_TO_TAG)),
        ("command", bs("answer")),
    ]);
    let answer_reply = bd(vec![
        ("sdp", Ben::Str(answer_reply_sdp)),
        ("result", bs("ok")),
    ]);
    [
        ng(OFFER_COOKIE, &offer),
        ng(OFFER_COOKIE, &offer_reply),
        ng(ANSWER_COOKIE, &answer),
        ng(ANSWER_COOKIE, &answer_reply),
    ]
}

/// The relay's PCMU payload for the frame at `index`: the 1 kHz part of the
/// source signal at 8 kHz, as mu-law.
fn relay_pcmu_payload(index: usize) -> Vec<u8> {
    (index * 160..(index + 1) * 160)
        .map(|n| codecs::ulaw(codecs::tone(n, 2, 12_000) as i16))
        .collect()
}

/// Every frame of the relay capture, with or without its control plane.
fn opensips_relay_capture(with_control_plane: bool) -> Vec<u8> {
    let messages = opensips_ng_messages();
    let caller_rtp = g722_rtp(21);
    let (mut next_caller, mut next_relay) = (0usize, 0usize);
    let (mut hep_ident, mut caller_ident, mut relay_ident) = (0x0100u16, 0x2000u16, 0x4000u16);
    let mut records = Vec::new();
    for (offset, packet) in OS_SCHEDULE {
        let sec = OS_SEC + offset / 1_000_000;
        let usec = offset % 1_000_000;
        let frame = match packet {
            OsPacket::Hep(n) => {
                hep_ident += 1;
                let (sport, dport) = if n % 2 == 0 {
                    (OS_NG_CLIENT, OS_NG_PORT)
                } else {
                    (OS_NG_PORT, OS_NG_CLIENT)
                };
                let hep = hep_ng(
                    OS_CALL_ID,
                    OS_SEC,
                    OS_HEP_USEC[n],
                    sport,
                    dport,
                    &messages[n],
                );
                let ip = Ip {
                    src: OS_RELAY,
                    dst: OS_HOMER,
                    tos: 0,
                    ident: hep_ident,
                    flags: DF,
                    checksum: true,
                };
                let datagram = udp(&ip, OS_HEP_PORT, HOMER_PORT, &hep, true);
                if !with_control_plane {
                    continue;
                }
                ethernet(doc_mac(0x30), doc_mac(0x10), &ipv4_udp(&ip, &datagram))
            }
            OsPacket::Caller => {
                caller_ident += 1;
                let rtp = &caller_rtp[next_caller];
                next_caller += 1;
                let ip = Ip {
                    src: OS_UAC,
                    dst: OS_RELAY,
                    tos: 0,
                    ident: caller_ident,
                    flags: DF,
                    checksum: true,
                };
                let datagram = udp(&ip, MEDIA_PORT, OS_RELAY_FROM_UAC, rtp, true);
                ethernet(doc_mac(0x10), doc_mac(0x21), &ipv4_udp(&ip, &datagram))
            }
            OsPacket::Relay => {
                relay_ident += 1;
                // The relay forwards the caller's packet `next_relay` under
                // its own sequence number, timestamp and SSRC, as PCMU.
                let source = &caller_rtp[next_relay];
                let seq = u16::from_be_bytes([source[2], source[3]]);
                let ts = u32::from_be_bytes([source[4], source[5], source[6], source[7]]);
                let rtp = rtp(
                    false,
                    PT_PCMU,
                    seq,
                    ts,
                    G722_SSRC,
                    &relay_pcmu_payload(next_relay),
                );
                next_relay += 1;
                let ip = Ip {
                    src: OS_RELAY,
                    dst: OS_UAS,
                    tos: 0xb8,
                    ident: relay_ident,
                    flags: DF,
                    checksum: true,
                };
                let datagram = udp(&ip, OS_RELAY_TO_UAS, MEDIA_PORT, &rtp, true);
                ethernet(doc_mac(0x20), doc_mac(0x10), &ipv4_udp(&ip, &datagram))
            }
        };
        records.push(Record::whole(sec, usec, frame));
    }
    pcap(262_144, &records)
}

/// The relay's view with its control plane: four HEP datagrams and the media.
pub fn rtpengine_opensips_ng() -> Vec<u8> {
    opensips_relay_capture(true)
}

/// The same capture with its four HEP datagrams removed and nothing else
/// changed: the control case, in which nothing names the streams.
pub fn rtpengine_opensips_media_only() -> Vec<u8> {
    opensips_relay_capture(false)
}

// ── opensips-proxy-signaling.pcap ───────────────────────────────────
//
// The other half of the call above: the OpenSIPS proxy's own view of it, SIP
// and nothing else. The proxy never touches media, so a capture on it holds
// every message of the call and not one RTP packet, while the relay capture
// holds the media and not one SIP message. Neither can say whether the call
// was healthy on its own; `clients/python/leg_correlate.py` joins the two, and
// `scripts/smoke-clients.sh` runs it against both files on loopback.
//
// Built for that join, not rebuilt from a harness capture: the Call-ID, the
// tags and every SDP body are the ones the relay's control plane carries (one
// definition, `opensips_sdps`), and the timing brackets the relay's: the
// INVITE reaches the proxy just before the relay sees `offer`, the 200 OK
// just before `answer`, and the BYE after the last media packet. The proxy
// forwards the offer and the answer as the relay rewrote them, which is what
// a proxy calling rtpengine does. Record-Route keeps it on the path, so the
// ACK and the BYE cross it as well.

/// The proxy, alone at .5 in the harness's 198.51.100.0/24.
const OS_PROXY: [u8; 4] = [198, 51, 100, 5];

/// One SIP message as the proxy's capture holds it.
struct ProxyMessage {
    /// Microseconds after `OS_SEC`.
    at: u32,
    src: [u8; 4],
    dst: [u8; 4],
    text: String,
}

/// Every message the proxy sent or received for the call, in capture order.
fn opensips_proxy_messages() -> Vec<ProxyMessage> {
    let [offer, offer_relayed, answer, answer_relayed] = opensips_sdps();
    let ip = |a: [u8; 4]| std::net::Ipv4Addr::from(a).to_string();
    let (uac, uas, proxy) = (ip(OS_UAC), ip(OS_UAS), ip(OS_PROXY));
    let via_uac =
        |branch: &str| format!("Via: SIP/2.0/UDP {uac}:5060;branch=z9hG4bK-4062-1-{branch}\r\n");
    let via_proxy =
        |branch: &str| format!("Via: SIP/2.0/UDP {proxy}:5060;branch=z9hG4bK-os-{branch}\r\n");
    let rr = format!("Record-Route: <sip:{proxy};lr>\r\n");
    let from = format!("From: sipp <sip:sipp@{uac}:5060>;tag={OS_FROM_TAG}\r\n");
    let to = |tagged: bool| {
        let tag = if tagged {
            format!(";tag={OS_TO_TAG}")
        } else {
            String::new()
        };
        format!("To: service <sip:service@{proxy}:5060>{tag}\r\n")
    };
    let call = format!("Call-ID: {OS_CALL_ID}\r\n");
    let body = |sdp: &str| {
        if sdp.is_empty() {
            "Content-Length: 0\r\n\r\n".to_string()
        } else {
            format!(
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                sdp.len()
            )
        }
    };
    let uac_contact = format!("Contact: <sip:sipp@{uac}:5060>\r\n");
    let uas_contact = format!("Contact: <sip:{uas}:5060;transport=UDP>\r\n");

    // A request as the caller sends it to the proxy, and as the proxy
    // forwards it to the callee: one Via more, Max-Forwards one less, and
    // the Request-URI retargeted.
    let from_uac = |first: &str, cseq: &str, tagged: bool, extra: &str, sdp: &str| {
        format!(
            "{first} sip:service@{proxy}:5060 SIP/2.0\r\n{}{from}{}{call}CSeq: {cseq}\r\n\
             Max-Forwards: 70\r\n{extra}{}",
            via_uac(cseq.split(' ').next_back().unwrap_or_default()),
            to(tagged),
            body(sdp)
        )
    };
    let to_uas = |first: &str, cseq: &str, tagged: bool, extra: &str, sdp: &str| {
        let method = cseq.split(' ').next_back().unwrap_or_default();
        format!(
            "{first} sip:service@{uas}:5060 SIP/2.0\r\n{}{}{from}{}{call}CSeq: {cseq}\r\n\
             Max-Forwards: 69\r\n{extra}{}",
            via_proxy(method),
            via_uac(method),
            to(tagged),
            body(sdp)
        )
    };
    // A response as the callee sends it to the proxy (both Vias), and as the
    // proxy relays it to the caller (its own Via removed).
    let from_uas = |status: &str, cseq: &str, tagged: bool, extra: &str, sdp: &str| {
        let method = cseq.split(' ').next_back().unwrap_or_default();
        format!(
            "SIP/2.0 {status}\r\n{}{}{from}{}{call}CSeq: {cseq}\r\n{extra}{}",
            via_proxy(method),
            via_uac(method),
            to(tagged),
            body(sdp)
        )
    };
    let to_uac = |status: &str, cseq: &str, tagged: bool, extra: &str, sdp: &str| {
        let method = cseq.split(' ').next_back().unwrap_or_default();
        format!(
            "SIP/2.0 {status}\r\n{}{from}{}{call}CSeq: {cseq}\r\n{extra}{}",
            via_uac(method),
            to(tagged),
            body(sdp)
        )
    };
    let invite_extra = format!("{uac_contact}Subject: Performance Test\r\n");
    let answer_extra = format!("{rr}{uas_contact}");
    let m = |at: u32, src: [u8; 4], dst: [u8; 4], text: String| ProxyMessage { at, src, dst, text };
    vec![
        m(
            875_400,
            OS_UAC,
            OS_PROXY,
            from_uac("INVITE", "1 INVITE", false, &invite_extra, &offer),
        ),
        m(
            875_600,
            OS_PROXY,
            OS_UAC,
            to_uac("100 Giving it a try", "1 INVITE", false, "", ""),
        ),
        m(
            876_100,
            OS_PROXY,
            OS_UAS,
            to_uas(
                "INVITE",
                "1 INVITE",
                false,
                &format!("{rr}{invite_extra}"),
                &offer_relayed,
            ),
        ),
        m(
            877_000,
            OS_UAS,
            OS_PROXY,
            from_uas("180 Ringing", "1 INVITE", true, &answer_extra, ""),
        ),
        m(
            877_100,
            OS_PROXY,
            OS_UAC,
            to_uac("180 Ringing", "1 INVITE", true, &answer_extra, ""),
        ),
        m(
            877_900,
            OS_UAS,
            OS_PROXY,
            from_uas("200 OK", "1 INVITE", true, &answer_extra, &answer),
        ),
        m(
            878_050,
            OS_PROXY,
            OS_UAC,
            to_uac("200 OK", "1 INVITE", true, &answer_extra, &answer_relayed),
        ),
        m(
            879_000,
            OS_UAC,
            OS_PROXY,
            from_uac("ACK", "1 ACK", true, &uac_contact, ""),
        ),
        m(
            879_150,
            OS_PROXY,
            OS_UAS,
            to_uas("ACK", "1 ACK", true, &uac_contact, ""),
        ),
        m(
            1_300_000,
            OS_UAC,
            OS_PROXY,
            from_uac("BYE", "2 BYE", true, &uac_contact, ""),
        ),
        m(
            1_300_150,
            OS_PROXY,
            OS_UAS,
            to_uas("BYE", "2 BYE", true, &uac_contact, ""),
        ),
        m(
            1_301_000,
            OS_UAS,
            OS_PROXY,
            from_uas("200 OK", "2 BYE", true, &uas_contact, ""),
        ),
        m(
            1_301_150,
            OS_PROXY,
            OS_UAC,
            to_uac("200 OK", "2 BYE", true, &uas_contact, ""),
        ),
    ]
}

/// The proxy's capture of the call: thirteen SIP messages and no media.
pub fn opensips_proxy_signaling() -> Vec<u8> {
    let mac = |a: [u8; 4]| doc_mac(a[3]);
    let records: Vec<Record> = opensips_proxy_messages()
        .into_iter()
        .enumerate()
        .map(|(n, msg)| {
            let ip = Ip {
                src: msg.src,
                dst: msg.dst,
                tos: 0,
                ident: 0x0500 + n as u16,
                flags: DF,
                checksum: true,
            };
            let datagram = udp(&ip, 5060, 5060, msg.text.as_bytes(), true);
            let frame = ethernet(mac(msg.dst), mac(msg.src), &ipv4_udp(&ip, &datagram));
            Record::whole(OS_SEC + msg.at / 1_000_000, msg.at % 1_000_000, frame)
        })
        .collect();
    pcap(262_144, &records)
}

// ── STUN, TURN and ICE ──────────────────────────────────────────────
//
// Four hand-built captures that no committed generator wrote until
// September 2026. They are rebuilt here frame for frame: ice_checks.pcap and
// turn_relay.pcap come out byte-identical to the files committed before, and
// stun_nat_probe.pcap and stun_sdp_mismatch.pcap differ from theirs only in
// the MAC addresses, which were outside the RFC 7042 documentation block and
// are now inside it.
//
// Two quirks of the originals are kept, because changing them would change
// what the tests read: every SOFTWARE attribute's length counts its padding,
// where RFC 8489 section 14 excludes it, and the first ICE pair's six frames
// carry one MAC pair whichever way they travel.

/// The STUN magic cookie, RFC 8489 section 5.
const STUN_COOKIE: u32 = 0x2112_a442;

/// STUN attribute types used below.
const ATTR_CHANNEL_NUMBER: u16 = 0x000c;
const ATTR_LIFETIME: u16 = 0x000d;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_DONT_FRAGMENT: u16 = 0x001a;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_PRIORITY: u16 = 0x0024;
const ATTR_USE_CANDIDATE: u16 = 0x0025;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_ICE_CONTROLLED: u16 = 0x8029;
const ATTR_ICE_CONTROLLING: u16 = 0x802a;

/// A STUN message: type, length, magic cookie, transaction ID, attributes.
///
/// Every value here is already a multiple of four bytes long, so no padding
/// is added and each attribute's length is its value's length.
fn stun(kind: u16, txid: [u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let body: usize = attrs.iter().map(|(_, v)| 4 + v.len()).sum();
    let mut m = Vec::with_capacity(20 + body);
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&(body as u16).to_be_bytes());
    m.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    m.extend_from_slice(&txid);
    for (t, v) in attrs {
        assert!(v.len() % 4 == 0, "attribute {t:#06x} is not padded");
        m.extend_from_slice(&t.to_be_bytes());
        m.extend_from_slice(&(v.len() as u16).to_be_bytes());
        m.extend_from_slice(v);
    }
    m
}

/// An XOR-MAPPED-ADDRESS style value for an IPv4 address and port.
fn xor_address(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut v = vec![0, 1]; // reserved, family IPv4
    v.extend_from_slice(&(port ^ (STUN_COOKIE >> 16) as u16).to_be_bytes());
    v.extend_from_slice(&(u32::from_be_bytes(ip) ^ STUN_COOKIE).to_be_bytes());
    v
}

/// A SOFTWARE value padded with zeros to a multiple of four, the padding
/// counted in its length as the originals had it.
fn software(text: &str) -> Vec<u8> {
    let mut v = text.as_bytes().to_vec();
    v.resize(text.len().div_ceil(4) * 4, 0);
    v
}

/// ERROR-CODE for a class and number, with no reason phrase.
fn error_code(code: u16) -> Vec<u8> {
    vec![0, 0, (code / 100) as u8, (code % 100) as u8]
}

/// A UDP frame the way every STUN fixture builds one: IP checksum filled in,
/// UDP checksum left zero.
#[allow(clippy::too_many_arguments)]
fn stun_frame(
    macs: ([u8; 6], [u8; 6]),
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    tos: u8,
    ident: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip = Ip {
        src,
        dst,
        tos,
        ident,
        flags: DF,
        checksum: true,
    };
    let (dst_mac, src_mac) = macs;
    ethernet(
        dst_mac,
        src_mac,
        &ipv4_udp(&ip, &udp(&ip, sport, dport, payload, false)),
    )
}

/// A record `ms` milliseconds after `epoch`.
fn at_ms(epoch: u32, ms: u32, frame: Vec<u8>) -> Record {
    Record::whole(epoch + ms / 1000, (ms % 1000) * 1000, frame)
}

/// Two ICE connectivity-check exchanges.
///
/// The first pair (192.0.2.10:50004 and 203.0.113.9:16000) completes: a
/// check and its success, a nominating check with USE-CANDIDATE and its
/// success, and the controlled side's own check the other way. The second
/// pair (192.0.2.11:50006 and 203.0.113.11:16002) fails both ways with 487
/// Role Conflict.
pub fn ice_checks() -> Vec<u8> {
    const A: [u8; 4] = [192, 0, 2, 10];
    const B: [u8; 4] = [203, 0, 113, 9];
    const C: [u8; 4] = [192, 0, 2, 11];
    const D: [u8; 4] = [203, 0, 113, 11];
    const CONTROLLING_TIEBREAKER: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let first_pair = (doc_mac(0x02), doc_mac(0x01));
    let c_to_d = (doc_mac(0x04), doc_mac(0x03));
    let d_to_c = (doc_mac(0x03), doc_mac(0x04));
    let tie = || CONTROLLING_TIEBREAKER.to_vec();
    let frame = |macs, src, sport, dst, dport, msg: Vec<u8>| {
        stun_frame(macs, src, sport, dst, dport, 0, 0, &msg)
    };
    let records = vec![
        at_ms(
            LEGACY_EPOCH,
            0,
            frame(
                first_pair,
                A,
                50004,
                B,
                16000,
                stun(
                    0x0001,
                    [0x11; 12],
                    &[
                        (ATTR_PRIORITY, vec![0x7e, 0xff, 0xff, 0xff]),
                        (ATTR_ICE_CONTROLLING, tie()),
                        (ATTR_SOFTWARE, software("example-agent 1.0")),
                    ],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            12,
            frame(
                first_pair,
                B,
                16000,
                A,
                50004,
                stun(
                    0x0101,
                    [0x11; 12],
                    &[(ATTR_XOR_MAPPED_ADDRESS, xor_address(A, 50004))],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            100,
            frame(
                first_pair,
                A,
                50004,
                B,
                16000,
                stun(
                    0x0001,
                    [0x12; 12],
                    &[
                        (ATTR_PRIORITY, vec![0x7e, 0xff, 0xff, 0xff]),
                        (ATTR_ICE_CONTROLLING, tie()),
                        (ATTR_USE_CANDIDATE, vec![]),
                    ],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            118,
            frame(
                first_pair,
                B,
                16000,
                A,
                50004,
                stun(
                    0x0101,
                    [0x12; 12],
                    &[(ATTR_XOR_MAPPED_ADDRESS, xor_address(A, 50004))],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            150,
            frame(
                first_pair,
                B,
                16000,
                A,
                50004,
                stun(
                    0x0001,
                    [0x13; 12],
                    &[
                        (ATTR_PRIORITY, vec![0x6e, 0x00, 0x00, 0xff]),
                        (ATTR_ICE_CONTROLLED, tie()),
                    ],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            161,
            frame(
                first_pair,
                A,
                50004,
                B,
                16000,
                stun(
                    0x0101,
                    [0x13; 12],
                    &[(ATTR_XOR_MAPPED_ADDRESS, xor_address(B, 16000))],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            200,
            frame(
                c_to_d,
                C,
                50006,
                D,
                16002,
                stun(
                    0x0001,
                    [0x21; 12],
                    &[
                        (ATTR_PRIORITY, vec![0x7e, 0xff, 0xff, 0xff]),
                        (ATTR_ICE_CONTROLLING, tie()),
                    ],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            212,
            frame(
                d_to_c,
                D,
                16002,
                C,
                50006,
                stun(0x0111, [0x21; 12], &[(ATTR_ERROR_CODE, error_code(487))]),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            230,
            frame(
                d_to_c,
                D,
                16002,
                C,
                50006,
                stun(
                    0x0001,
                    [0x22; 12],
                    &[
                        (ATTR_PRIORITY, vec![0x7e, 0xff, 0xff, 0xfe]),
                        (ATTR_ICE_CONTROLLING, tie()),
                    ],
                ),
            ),
        ),
        at_ms(
            LEGACY_EPOCH,
            244,
            frame(
                c_to_d,
                C,
                50006,
                D,
                16002,
                stun(0x0111, [0x22; 12], &[(ATTR_ERROR_CODE, error_code(487))]),
            ),
        ),
    ];
    pcap(262_144, &records)
}

/// A TURN allocation and the media relayed through it.
///
/// The client 192.0.2.10:50000 allocates on the server 198.51.100.20:3478
/// (relayed address 198.51.100.77:49160, reflexive 203.0.113.5:12262),
/// permits and binds channel 0x4001 to the peer 203.0.113.9:16000, sends one
/// RTP packet in a Send indication, then exchanges RTP both ways as
/// ChannelData: fifty 20 ms rounds, one RTCP receiver report each way, a
/// minute's silence, and twenty-five rounds more.
pub fn turn_relay() -> Vec<u8> {
    const CLIENT: [u8; 4] = [192, 0, 2, 10];
    const SERVER: [u8; 4] = [198, 51, 100, 20];
    const PEER: [u8; 4] = [203, 0, 113, 9];
    const CLIENT_PORT: u16 = 50000;
    const SERVER_PORT: u16 = 3478;
    const CHANNEL: u16 = 0x4001;
    const CLIENT_SSRC: u32 = 0x1122_3344;
    const PEER_SSRC: u32 = 0x5566_7788;

    let mut ident = 0u16;
    let mut records = Vec::new();
    let mut push = |ms: u32, from_client: bool, payload: Vec<u8>| {
        ident += 1;
        let (src, sport, dst, dport) = if from_client {
            (CLIENT, CLIENT_PORT, SERVER, SERVER_PORT)
        } else {
            (SERVER, SERVER_PORT, CLIENT, CLIENT_PORT)
        };
        let frame = stun_frame(
            (doc_mac(0x02), doc_mac(0x01)),
            src,
            sport,
            dst,
            dport,
            0,
            ident,
            &payload,
        );
        records.push(at_ms(LEGACY_EPOCH, ms, frame));
    };
    let channel_data = |data: &[u8]| {
        let mut v = CHANNEL.to_be_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    };
    let media = |seq: u16, ssrc: u32| {
        rtp(
            false,
            PT_PCMU,
            seq,
            u32::from(seq) * 160,
            ssrc,
            &[0xd5; 160],
        )
    };

    push(
        0,
        true,
        stun(
            0x0003,
            [
                0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6,
            ],
            &[
                (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
                (ATTR_DONT_FRAGMENT, vec![]),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![1, 0, 0, 0]),
                (ATTR_LIFETIME, 3600u32.to_be_bytes().to_vec()),
                (ATTR_SOFTWARE, software("turn-client-1.0")),
            ],
        ),
    );
    push(
        12,
        false,
        stun(
            0x0103,
            [
                0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6,
            ],
            &[
                (
                    ATTR_XOR_RELAYED_ADDRESS,
                    xor_address([198, 51, 100, 77], 49160),
                ),
                (
                    ATTR_XOR_MAPPED_ADDRESS,
                    xor_address([203, 0, 113, 5], 12262),
                ),
                (ATTR_LIFETIME, 60u32.to_be_bytes().to_vec()),
                (ATTR_SOFTWARE, software("turn-server-1.0")),
            ],
        ),
    );
    let permission_txid = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];
    push(
        20,
        true,
        stun(
            0x0008,
            permission_txid,
            &[(ATTR_XOR_PEER_ADDRESS, xor_address(PEER, 16000))],
        ),
    );
    push(28, false, stun(0x0108, permission_txid, &[]));
    let bind_txid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    push(
        40,
        true,
        stun(
            0x0009,
            bind_txid,
            &[
                (ATTR_CHANNEL_NUMBER, vec![0x40, 0x01, 0, 0]),
                (ATTR_XOR_PEER_ADDRESS, xor_address(PEER, 16000)),
            ],
        ),
    );
    push(48, false, stun(0x0109, bind_txid, &[]));
    push(
        52,
        true,
        stun(
            0x0016,
            [
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ],
            &[
                (ATTR_XOR_PEER_ADDRESS, xor_address(PEER, 16000)),
                (ATTR_DATA, media(0, CLIENT_SSRC)),
            ],
        ),
    );
    for seq in 1..=50u16 {
        let ms = 60 + u32::from(seq - 1) * 20;
        push(ms, true, channel_data(&media(seq, CLIENT_SSRC)));
        push(ms + 5, false, channel_data(&media(seq, PEER_SSRC)));
    }
    // One RTCP receiver report each way, with one report block on the other
    // side's SSRC. The block's words are the original's as they were: nothing
    // lost, extended highest sequence 0, jitter 50, last SR 5, no delay. The
    // 50 and the 5 read as if they were meant one word earlier; they are kept
    // where they were so the file stays the file the tests were written on.
    let receiver_report = |sender: u32, source: u32| {
        let mut r = vec![0x81, 0xc9, 0x00, 0x07];
        r.extend_from_slice(&sender.to_be_bytes());
        r.extend_from_slice(&source.to_be_bytes());
        r.extend_from_slice(&[0; 4]); // fraction lost, cumulative lost
        r.extend_from_slice(&0u32.to_be_bytes()); // extended highest sequence
        r.extend_from_slice(&50u32.to_be_bytes()); // interarrival jitter
        r.extend_from_slice(&5u32.to_be_bytes()); // last SR
        r.extend_from_slice(&[0; 4]); // delay since last SR
        r
    };
    push(
        1100,
        true,
        channel_data(&receiver_report(CLIENT_SSRC, PEER_SSRC)),
    );
    push(
        1105,
        false,
        channel_data(&receiver_report(PEER_SSRC, CLIENT_SSRC)),
    );
    for seq in 51..=75u16 {
        let ms = 61_000 + u32::from(seq - 51) * 20;
        push(ms, true, channel_data(&media(seq, CLIENT_SSRC)));
        push(ms + 5, false, channel_data(&media(seq, PEER_SSRC)));
    }
    pcap(262_144, &records)
}

/// The Binding request both NAT fixtures open with, from a SIP port.
fn nat_probe_request(first_txid_byte: u8) -> Vec<u8> {
    let mut txid = [0u8; 12];
    txid[0] = first_txid_byte;
    for (i, b) in txid.iter_mut().enumerate().skip(1) {
        *b = i as u8;
    }
    stun(
        0x0001,
        txid,
        &[(ATTR_SOFTWARE, software("traversal-2.1.0 45"))],
    )
}

/// The MAC addresses of every frame in the two NAT fixtures: one pair,
/// whichever way a frame travels, as in the originals.
const NAT_MACS: ([u8; 6], [u8; 6]) = (doc_mac(0x02), doc_mac(0x01));
/// DSCP AF31 with ECN clear, on every frame of the two NAT fixtures.
const NAT_TOS: u8 = 0x68;
/// The STUN server both NAT fixtures ask.
const STUN_SERVER: [u8; 4] = [198, 51, 100, 20];

/// A NAT probe from a SIP phone: one Binding request that goes unanswered
/// and is retransmitted, then a second phone's request that is answered with
/// a reflexive address, 203.0.113.5:12262, that is not the one it asked
/// from.
pub fn stun_nat_probe() -> Vec<u8> {
    const EPOCH: u32 = 1000;
    let frame = |src, sport, dst, dport, payload: &[u8]| {
        stun_frame(NAT_MACS, src, sport, dst, dport, NAT_TOS, 0x1234, payload)
    };
    let first = nat_probe_request(0xaa);
    let second = nat_probe_request(0xbb);
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&second[8..20]);
    let answer = stun(
        0x0101,
        txid,
        &[(
            ATTR_XOR_MAPPED_ADDRESS,
            xor_address([203, 0, 113, 5], 12262),
        )],
    );
    let records = vec![
        Record::whole(
            EPOCH,
            0,
            frame([192, 0, 2, 10], 5060, STUN_SERVER, 3478, &first),
        ),
        Record::whole(
            EPOCH,
            99_500,
            frame([192, 0, 2, 10], 5060, STUN_SERVER, 3478, &first),
        ),
        Record::whole(
            EPOCH + 1,
            0,
            frame([192, 0, 2, 11], 5062, STUN_SERVER, 3478, &second),
        ),
        Record::whole(
            EPOCH + 1,
            7_000,
            frame(STUN_SERVER, 3478, [192, 0, 2, 11], 5062, &answer),
        ),
    ];
    pcap(65535, &records)
}

/// A phone behind NAT whose SDP names its private address.
///
/// The phone at 192.168.10.50 sends two unanswered Binding requests, then
/// calls bob at 198.51.100.30 with `c=IN IP4 192.168.10.50` in its offer.
/// The media that arrives comes from 203.0.113.7, not from the address the
/// answer's SDP names, which is the mismatch the fixture exists to show. The
/// private address is deliberate and the only address in the file outside
/// RFC 5737: an RFC 1918 address in SDP is what a phone behind NAT sends.
pub fn stun_sdp_mismatch() -> Vec<u8> {
    const PHONE: [u8; 4] = [192, 168, 10, 50];
    const PROXY: [u8; 4] = [198, 51, 100, 30];
    const FAR_MEDIA: [u8; 4] = [203, 0, 113, 7];
    let mut ident = 0x1234u16;
    let mut records = Vec::new();
    let mut push = |ms: u32, src, sport, dst, dport, payload: &[u8]| {
        ident += 1;
        records.push(at_ms(
            LEGACY_EPOCH,
            ms,
            stun_frame(NAT_MACS, src, sport, dst, dport, NAT_TOS, ident, payload),
        ));
    };
    let probe = nat_probe_request(0xaa);
    push(0, PHONE, 5060, STUN_SERVER, 3478, &probe);
    push(500, PHONE, 5060, STUN_SERVER, 3478, &probe);

    let via = "Via: SIP/2.0/UDP 192.168.10.50:5060;branch=z9hG4bK";
    let from = "From: <sip:alice@192.168.10.50>;tag=alice1\r\n";
    let call_id = "Call-ID: stun-sdp-mismatch-1@192.168.10.50\r\n";
    let alice_contact = "Contact: <sip:alice@192.168.10.50:5060>\r\n";
    let bob_contact = "Contact: <sip:bob@198.51.100.30:5060>\r\n";
    let sdp = |user: &str, ip: &str, port: u16| {
        format!(
            "v=0\r\no={user} 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
        )
    };
    let offer = sdp("phone", "192.168.10.50", 40000);
    let answer = sdp("proxy", "198.51.100.30", 41000);
    let request = |line: &str, branch: &str, to_tag: &str, cseq: &str, body: &str| {
        let content_type = if body.is_empty() {
            ""
        } else {
            "Content-Type: application/sdp\r\n"
        };
        format!(
            "{line}\r\n{via}-{branch}\r\n{from}To: <sip:bob@198.51.100.30>{to_tag}\r\n\
             {call_id}CSeq: {cseq}\r\n{alice_contact}Max-Forwards: 70\r\n\
             User-Agent: sipnab-fixture/1\r\n{content_type}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let response = |status: &str, branch: &str, cseq: &str, body: &str| {
        let content_type = if body.is_empty() {
            ""
        } else {
            "Content-Type: application/sdp\r\n"
        };
        format!(
            "SIP/2.0 {status}\r\n{via}-{branch}\r\n{from}To: <sip:bob@198.51.100.30>;tag=bob1\r\n\
             {call_id}CSeq: {cseq}\r\n{bob_contact}{content_type}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let invite = request(
        "INVITE sip:bob@198.51.100.30 SIP/2.0",
        "invite-1",
        "",
        "1 INVITE",
        &offer,
    );
    push(1000, PHONE, 5060, PROXY, 5060, invite.as_bytes());
    for (ms, status, body) in [
        (1100, "100 Trying", ""),
        (1200, "180 Ringing", ""),
        (2000, "200 OK", answer.as_str()),
    ] {
        let reply = response(status, "invite-1", "1 INVITE", body);
        push(ms, PROXY, 5060, PHONE, 5060, reply.as_bytes());
    }
    let ack = request(
        "ACK sip:bob@198.51.100.30 SIP/2.0",
        "ack-1",
        ";tag=bob1",
        "1 ACK",
        "",
    );
    push(2050, PHONE, 5060, PROXY, 5060, ack.as_bytes());
    for k in 0..30u16 {
        let ms = 2100 + u32::from(k) * 20;
        let ts = u32::from(k) * 160;
        let out = rtp(false, PT_PCMU, 100 + k, ts, 0x1122_3344, &[0; 160]);
        push(ms, PHONE, 40000, PROXY, 41000, &out);
        let back = rtp(false, PT_PCMU, 500 + k, ts, 0x5566_7788, &[0; 160]);
        push(ms + 5, FAR_MEDIA, 41000, PHONE, 40000, &back);
    }
    let bye = request(
        "BYE sip:bob@198.51.100.30 SIP/2.0",
        "bye-1",
        ";tag=bob1",
        "2 BYE",
        "",
    );
    push(8000, PHONE, 5060, PROXY, 5060, bye.as_bytes());
    let ok = response("200 OK", "bye-1", "2 BYE", "");
    push(8050, PROXY, 5060, PHONE, 5060, ok.as_bytes());
    pcap(65535, &records)
}

// ── operator-task fixtures ──────────────────────────────────────────
//
// The captures the operator-task programs in clients/python run against in
// scripts/smoke-clients.sh: a call answered and never acknowledged (cookbook
// recipe 30), and a registrar watched while a scanner probes it and two
// sources retry refused credentials (recipes 10 and 23).

/// The MAC addresses of every frame in the operator-task fixtures.
const OPERATOR_MACS: ([u8; 6], [u8; 6]) = (doc_mac(0x12), doc_mac(0x11));

/// One SIP datagram between two documentation addresses on port 5060.
fn sip_frame(ident: u16, src: [u8; 4], dst: [u8; 4], text: &str) -> Vec<u8> {
    stun_frame(
        OPERATOR_MACS,
        src,
        5060,
        dst,
        5060,
        0,
        ident,
        text.as_bytes(),
    )
}

/// An INVITE answered `200 OK` whose `ACK` never arrives.
///
/// 192.0.2.70 calls 192.0.2.80. The callee answers one second in, and
/// retransmits the `200 OK` on RFC 3261 Timer G (T1 = 500 ms, doubling to
/// T2 = 4 s) until 64*T1 after the first answer: eleven transmissions over
/// 31.5 s, then silence. No `ACK` and no `BYE` follow, so the capture ends
/// with the call up on one side only. The last answer is 31.5 s after the
/// first, under the 32 s Timer H sipnab defaults to, so the finding needs
/// `--ack-timeout` below that, as recipe 30 shows.
pub fn answered_never_acked() -> Vec<u8> {
    const CALLER: [u8; 4] = [192, 0, 2, 70];
    const CALLEE: [u8; 4] = [192, 0, 2, 80];
    let call_id = "noack-5d4c3b@192.0.2.70";
    let head = |first: &str, to_tag: &str, cseq: &str| {
        format!(
            "{first}\r\n\
             Via: SIP/2.0/UDP 192.0.2.70:5060;branch=z9hG4bK-noack-1\r\n\
             From: \"kate\" <sip:kate@192.0.2.70>;tag=k1\r\n\
             To: <sip:liam@192.0.2.80>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n"
        )
    };
    let invite = head("INVITE sip:liam@192.0.2.80 SIP/2.0", "", "1 INVITE")
        + "Max-Forwards: 70\r\n\
           Contact: <sip:kate@192.0.2.70:5060>\r\n\
           User-Agent: sipnab-fixture/1\r\n\
           Content-Length: 0\r\n\r\n";
    let reply = |status: &str, to_tag: &str| {
        head(&format!("SIP/2.0 {status}"), to_tag, "1 INVITE")
            + "Contact: <sip:liam@192.0.2.80:5060>\r\nContent-Length: 0\r\n\r\n"
    };
    let mut records = vec![
        at_ms(LEGACY_EPOCH, 0, sip_frame(1, CALLER, CALLEE, &invite)),
        at_ms(
            LEGACY_EPOCH,
            10,
            sip_frame(2, CALLEE, CALLER, &reply("100 Trying", "")),
        ),
        at_ms(
            LEGACY_EPOCH,
            300,
            sip_frame(3, CALLEE, CALLER, &reply("180 Ringing", ";tag=l1")),
        ),
    ];
    // Timer G: 500 ms, doubling, capped at T2 = 4 s, until 64*T1 = 32 s.
    let ok = reply("200 OK", ";tag=l1");
    let (mut at, mut interval, mut ident) = (1000u32, 500u32, 4u16);
    while at - 1000 <= 32_000 {
        records.push(at_ms(
            LEGACY_EPOCH,
            at,
            sip_frame(ident, CALLEE, CALLER, &ok),
        ));
        ident += 1;
        at += interval;
        interval = (interval * 2).min(4000);
    }
    pcap(65535, &records)
}

/// A registrar probed by a scanner and hammered by two sources whose
/// credentials it refuses.
///
/// The registrar is 192.0.2.20. The PBX at 192.0.2.10 registers and is
/// accepted. The scanner at 203.0.113.42 sends OPTIONS as `friendly-scanner`
/// to six extensions, each answered `404`. The device at 198.51.100.77
/// (`SynthSwitch/1.0`) sends twelve REGISTERs carrying the same credentials
/// inside one second, each challenged `401`, the pattern recipe 23 describes.
/// Then the PBX does the same after its credentials change: twelve refused
/// retries, from a source that completed a registration earlier in the file,
/// which is the counter-evidence recipe 10c exists to show.
pub fn scanner_and_register_flood() -> Vec<u8> {
    const REGISTRAR: [u8; 4] = [192, 0, 2, 20];
    const PBX: [u8; 4] = [192, 0, 2, 10];
    const SCANNER: [u8; 4] = [203, 0, 113, 42];
    const DEVICE: [u8; 4] = [198, 51, 100, 77];
    let mut ident = 0x2000u16;
    let mut records = Vec::new();
    let mut push = |ms: u32, src: [u8; 4], dst: [u8; 4], text: &str| {
        ident += 1;
        records.push(at_ms(LEGACY_EPOCH, ms, sip_frame(ident, src, dst, text)));
    };
    let auth = |user: &str| {
        format!(
            "Authorization: Digest username=\"{user}\", realm=\"example.com\", \
             nonce=\"5f1e2d3c\", uri=\"sip:example.com\", \
             response=\"0123456789abcdef0123456789abcdef\"\r\n"
        )
    };
    // One REGISTER transaction and its answer: `status` is the final response.
    let register = |host: &str, user: &str, ua: &str, n: u32, status: &str| {
        let via = format!("Via: SIP/2.0/UDP {host}:5060;branch=z9hG4bK-{user}-{n}\r\n");
        let common = format!(
            "From: <sip:{user}@example.com>;tag={user}-t\r\n\
             To: <sip:{user}@example.com>\r\n\
             Call-ID: reg-{user}@{host}\r\n\
             CSeq: {n} REGISTER\r\n"
        );
        let request = format!(
            "REGISTER sip:example.com SIP/2.0\r\n{via}Max-Forwards: 70\r\n{common}\
             Contact: <sip:{user}@{host}:5060>\r\nExpires: 3600\r\n{}\
             User-Agent: {ua}\r\nContent-Length: 0\r\n\r\n",
            auth(user)
        );
        let challenge = if status.starts_with("401") {
            "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"6a7b8c9d\"\r\n"
        } else {
            ""
        };
        let response =
            format!("SIP/2.0 {status}\r\n{via}{common}{challenge}Content-Length: 0\r\n\r\n");
        (request, response)
    };

    let (req, resp) = register("192.0.2.10", "pbx", "SynthPBX/2.0", 1, "200 OK");
    push(0, PBX, REGISTRAR, &req);
    push(20, REGISTRAR, PBX, &resp);

    for (k, ext) in (100u32..106).enumerate() {
        let k = k as u32;
        let via = format!("Via: SIP/2.0/UDP 203.0.113.42:5060;branch=z9hG4bK-scan-{ext}\r\n");
        let common = format!(
            "From: <sip:scan@203.0.113.42>;tag=scan{ext}\r\n\
             To: <sip:{ext}@192.0.2.20>\r\n\
             Call-ID: scan-{ext}@203.0.113.42\r\n\
             CSeq: 1 OPTIONS\r\n"
        );
        let probe = format!(
            "OPTIONS sip:{ext}@192.0.2.20 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{common}\
             User-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n"
        );
        let refusal = format!("SIP/2.0 404 Not Found\r\n{via}{common}Content-Length: 0\r\n\r\n");
        push(1000 + k * 100, SCANNER, REGISTRAR, &probe);
        push(1010 + k * 100, REGISTRAR, SCANNER, &refusal);
    }

    for n in 0..12u32 {
        let (req, resp) = register(
            "198.51.100.77",
            "sw77",
            "SynthSwitch/1.0",
            n + 1,
            "401 Unauthorized",
        );
        push(3000 + n * 80, DEVICE, REGISTRAR, &req);
        push(3010 + n * 80, REGISTRAR, DEVICE, &resp);
    }

    for n in 0..12u32 {
        let (req, resp) = register(
            "192.0.2.10",
            "pbx",
            "SynthPBX/2.0",
            n + 2,
            "401 Unauthorized",
        );
        push(6000 + n * 80, PBX, REGISTRAR, &req);
        push(6010 + n * 80, REGISTRAR, PBX, &resp);
    }
    pcap(65535, &records)
}
