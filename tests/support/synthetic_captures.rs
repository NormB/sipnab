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
//! hosts from RFC 2606 `example.*` labels or those same address literals.
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

/// A HEP v3 datagram mirroring one `ng` message, chunks in rtpengine's order.
fn hep_ng(sec: u32, usec: u32, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
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
    chunk(&mut body, 0x0011, RELAY_CALL_ID.as_bytes()); // correlation id
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
        let hep = hep_ng(sec, hep_usec, sport, dport, &ng(cookie, body));
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
