#!/usr/bin/env python3
"""Generate the synthetic capture fixtures under `tests/pcap-samples/`.

Every fixture this script writes is fabricated from end to end. Nothing in it
is derived from a real capture: the addresses are RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or RFC 1918, the SIP
URI hosts are `example.com` / `example.net` / `*.example.com` labels or IP
literals from those ranges, the MAC addresses come from the RFC 7042 §2.1.2
documentation block (00:00:5E:00:53:xx), and every user part, Call-ID, tag,
branch and User-Agent is an obviously synthetic label. No digit run that could
read as an E.164 number appears anywhere.

Why this exists: the repository is public, and a checked-in capture whose
provenance cannot be proven is not something the project is willing to
publish. Generating the fixtures makes their provenance a reviewable diff
instead of an assertion.

The fixtures are load-bearing -- the test suite asserts exact dialog counts,
states, message counts, Call-IDs, RTP stream counts and packet counts against
them -- so each builder below reproduces the *observable* shape its dependents
require and documents which property each choice exists to preserve. Read the
per-fixture docstrings before changing a message: a header that looks
decorative is usually the reason some test can tell a working extractor from
a broken one.

Deterministic: fixed epochs, fixed identifiers, no randomness, no clock reads.
Running it twice produces byte-identical files, so a regeneration shows up as
an empty diff.

Emits Ethernet/IPv4/UDP and Ethernet/IPv4/TCP frames by hand -- no scapy, no
libpcap -- and writes both classic pcap and pcapng containers.

Usage:
    python3 tests/gen-pcap-samples.py            # write every fixture
    python3 tests/gen-pcap-samples.py --check    # rebuild into a temp dir and
                                                 # diff against the tree
"""

from __future__ import annotations

import argparse
import filecmp
import os
import struct
import sys
import tempfile

# ── containers ──────────────────────────────────────────────────────

#: LINKTYPE_ETHERNET. Every fixture here is Ethernet; the suite's Linux-SLL
#: coverage lives in other samples that this script does not own.
LINKTYPE_ETHERNET = 1


def write_pcap(path: str, packets, linktype: int = LINKTYPE_ETHERNET) -> None:
    """Write `packets` as a classic little-endian pcap file.

    `packets` is an iterable of `(epoch_seconds_float, frame_bytes)`.
    Microsecond resolution, which is what the 0xA1B2C3D4 magic declares.
    """
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for ts, frame in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec == 1_000_000:  # rounding carried into the next second
            sec += 1
            usec = 0
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame))
        out += frame
    _write(path, bytes(out))


def _opt(code: int, value: bytes) -> bytes:
    """One pcapng option: code, length, value, padded to 4 bytes."""
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def _block(btype: int, body: bytes) -> bytes:
    """One pcapng block: type, total length, body, trailing total length."""
    total = len(body) + 12
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def write_pcapng(
    path: str,
    packets,
    linktype: int = LINKTYPE_ETHERNET,
    if_name: str = "synth0",
) -> None:
    """Write `packets` as a little-endian pcapng file: SHB, IDB, then EPBs.

    The section header block carries NO options, which keeps it 28 bytes.
    That is load-bearing: `pcap_reader.rs` hands the reader the first 40 bytes
    of a pcapng sample and requires it to construct successfully, so the SHB
    plus the head of the IDB has to fit inside 40 bytes. Adding an `shb_os`
    string here would push the IDB past the cut and turn that test's "just the
    SHB" comment into a lie.

    The interface block does carry options -- a name and `if_tsresol` -- since
    sipnab surfaces interface provenance and a fixture with none would leave
    that path uncovered. Both values are synthetic labels.
    """
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = bytearray(_block(0x0A0D0D0A, shb_body))

    idb_body = struct.pack("<HHI", linktype, 0, 262144)
    idb_body += _opt(2, if_name.encode())  # if_name
    idb_body += _opt(9, bytes([6]))  # if_tsresol = 10^-6
    idb_body += _opt(0, b"")
    out += _block(1, idb_body)

    for ts, frame in packets:
        micros = int(round(ts * 1_000_000))
        hi, lo = micros >> 32, micros & 0xFFFF_FFFF
        pad = (-len(frame)) % 4
        epb = struct.pack("<IIIII", 0, hi, lo, len(frame), len(frame))
        epb += frame + b"\x00" * pad
        out += _block(6, epb)

    _write(path, bytes(out))


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


# ── framing ─────────────────────────────────────────────────────────

#: RFC 7042 §2.1.2 documentation MAC block. Index by the last octet so each
#: host in a fixture keeps a stable, obviously-synthetic address.
def mac(n: int) -> bytes:
    """A documentation-range MAC address, `00:00:5E:00:53:<n>`."""
    return bytes([0x00, 0x00, 0x5E, 0x00, 0x53, n & 0xFF])


def _ip_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int, ttl: int = 64) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ident & 0xFFFF,
        0x4000,
        ttl,
        proto,
        0,
        _ip_bytes(src),
        _ip_bytes(dst),
    )
    header = header[:10] + struct.pack(">H", _checksum(header)) + header[12:]
    return header + payload


def _eth(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + payload


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int) -> bytes:
    """One Ethernet/IPv4/UDP frame carrying `payload`.

    The UDP checksum is left zero, which RFC 768 permits over IPv4 and which
    every capture reader in the suite accepts; computing it would only add a
    way for a hand-edited fixture to become silently invalid.
    """
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return _eth(
        mac(_host_id(src)),
        mac(_host_id(dst)),
        _ipv4(src, dst, 17, udp, ident),
    )


def tcp_frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    ident: int,
) -> bytes:
    """One Ethernet/IPv4/TCP frame.

    `flags` uses the usual bit values: 0x02 SYN, 0x10 ACK, 0x08 PSH,
    0x01 FIN. The window is fixed and the checksum is left zero, as for UDP.
    """
    offset_flags = (5 << 12) | flags
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, 0, 0)
    return _eth(
        mac(_host_id(src)),
        mac(_host_id(dst)),
        _ipv4(src, dst, 6, tcp + payload, ident),
    )


def _host_id(addr: str) -> int:
    """A stable per-address MAC suffix, so one host keeps one MAC."""
    octets = [int(o) for o in addr.split(".")]
    return (octets[2] * 7 + octets[3]) & 0xFF


# ── SIP ─────────────────────────────────────────────────────────────

CRLF = "\r\n"


def sip_message(start_line: str, headers, body: str = "") -> bytes:
    """Assemble a SIP message with a correct `Content-Length`.

    `headers` is a list of `(name, value)` pairs, kept as a list because
    header ORDER is observable: several tests read the first Via or assert on
    a message's rendered form.
    """
    body_bytes = body.encode()
    lines = [start_line]
    lines += [f"{name}: {value}" for name, value in headers]
    lines.append(f"Content-Length: {len(body_bytes)}")
    return (CRLF.join(lines) + CRLF + CRLF).encode() + body_bytes


def sdp(
    origin_user: str,
    session_id: int,
    version: int,
    addr: str,
    port: int,
    payloads="0 101",
    rtpmaps=("0 PCMU/8000", "101 telephone-event/8000"),
    mode: str = "sendrecv",
    extra=(),
) -> str:
    """An SDP offer/answer body.

    `addr` is both the origin address and the `c=` line, which is what keeps
    `nat_mismatch` false: sipnab flags a stream whose source address no SDP in
    the dialog ever advertised, so the media address here must be the address
    the RTP actually comes from.
    """
    lines = [
        "v=0",
        f"o={origin_user} {session_id} {version} IN IP4 {addr}",
        "s=synthetic session",
        f"c=IN IP4 {addr}",
        "t=0 0",
        f"m=audio {port} RTP/AVP {payloads}",
    ]
    lines += [f"a=rtpmap:{r}" for r in rtpmaps]
    lines += list(extra)
    lines.append(f"a={mode}")
    return CRLF.join(lines) + CRLF


# ── RTP / RTCP ──────────────────────────────────────────────────────


def rtp_packet(payload_type: int, seq: int, timestamp: int, ssrc: int, size: int = 160) -> bytes:
    """One RTP packet with a fixed synthetic payload.

    The payload is a constant byte pattern -- 0xFF is PCMU digital silence --
    so the fixture carries no recoverable audio, only the packet cadence the
    stream statistics are computed from.
    """
    header = struct.pack(
        ">BBHII",
        0x80,
        payload_type & 0x7F,
        seq & 0xFFFF,
        timestamp & 0xFFFF_FFFF,
        ssrc & 0xFFFF_FFFF,
    )
    return header + b"\xff" * size


def rtcp_sender_report(ssrc: int, ntp_sec: int, rtp_ts: int, packets: int, octets: int) -> bytes:
    """One RTCP sender report (PT 200), the shape a receiver expects."""
    body = struct.pack(
        ">IIIIII",
        ssrc & 0xFFFF_FFFF,
        ntp_sec & 0xFFFF_FFFF,
        0,
        rtp_ts & 0xFFFF_FFFF,
        packets & 0xFFFF_FFFF,
        octets & 0xFFFF_FFFF,
    )
    header = struct.pack(">BBH", 0x80, 200, (len(body) + 4) // 4 - 1)
    return header + body


# ── shared synthetic identities ─────────────────────────────────────

#: Every SIP URI host in these fixtures is one of these labels or an IP
#: literal from a documentation/private range. Nothing resolves to a real
#: organisation.
DOMAIN = "example.com"
ATLANTA = "atlanta.example.com"
BILOXI = "biloxi.example.com"

#: User-Agent strings. Deliberately not any shipping product's banner: a
#: fixture that names a real PBX build invites someone to read it as a
#: fingerprint of a real deployment.
UA_PHONE = "SynthPhone/1.0"
UA_SWITCH = "SynthSwitch/1.0"
UA_PROXY = "SynthProxy/1.0"
UA_LOAD = "SynthLoad/1.0"


def branch(label: str) -> str:
    """An RFC 3261 §8.1.1.7 branch: the magic cookie plus a synthetic label."""
    return f"z9hG4bK-synth-{label}"


# ── sip-register.pcap ───────────────────────────────────────────────

#: First-packet epoch. The multi-input suite orders an `-I` set by capture
#: time and documents this file as the FIRST member of the
#: register < proxy < g711 chain (tests/multi_input_test.rs:124-127), so this
#: epoch and `PROXY_EPOCH` below are load-bearing: they must stay strictly
#: ordered, more than 1 ms apart (`SAME_INSTANT_SECS`), and this file's LAST
#: packet must precede the proxy's first or the reader warns about overlap.
REGISTER_EPOCH = 1312180642.150251
PROXY_EPOCH = 1312180650.454022
SDP_EXAMPLE_EPOCH = 1312871576.583165


def build_sip_register(path: str) -> None:
    """A single REGISTER answered 200 OK: one dialog, two messages, no media.

    Load-bearing properties:
    * classic pcap, LINKTYPE_ETHERNET, little-endian microseconds;
    * exactly one dialog, so a directory walk that adds this file adds a
      known number of dialogs (`tests/multi_input_test.rs`);
    * NO RTP at all -- `tests/rtp_integration_test.rs` requires the WAV export
      to fail on it for want of a G.711 stream;
    * a Call-ID that collides with no other fixture's, because the multi-input
      tests add dialog counts from two files and a collision would merge them.
    """
    ua, registrar = "192.0.2.101", "192.0.2.102"
    call_id = "reg-alice-synth@192.0.2.101"
    tag = "tag-alice-reg"
    via = f"SIP/2.0/UDP {ua}:5060;branch={branch('reg-alice')};rport"
    common = [
        ("Via", via),
        ("From", f"Alice <sip:alice@{DOMAIN}>;tag={tag}"),
        ("To", f"Alice <sip:alice@{DOMAIN}>"),
        ("Call-ID", call_id),
        ("CSeq", "1 REGISTER"),
    ]
    request = sip_message(
        f"REGISTER sip:{DOMAIN} SIP/2.0",
        common
        + [
            ("Contact", f"<sip:alice@{ua}:5060>"),
            ("Max-Forwards", "70"),
            ("Expires", "180"),
            ("User-Agent", UA_PHONE),
        ],
    )
    # The registrar grants a shorter expiry than the phone asked for. sipnab
    # reports that as a `shortened_expiry` registration diagnosis; keeping it
    # means the fixture still exercises the diagnosis path it always did.
    response = sip_message(
        "SIP/2.0 200 OK",
        common
        + [
            ("Contact", f"<sip:alice@{ua}:5060>;expires=20"),
            ("Server", UA_SWITCH),
        ],
    )
    packets = [
        (REGISTER_EPOCH, udp_frame(ua, registrar, 5060, 5080, request, 0x1001)),
        (
            REGISTER_EPOCH + 0.034522,
            udp_frame(registrar, ua, 5080, 5060, response, 0x1002),
        ),
    ]
    write_pcap(path, packets)


# ── sip-proxy.pcap ──────────────────────────────────────────────────


def build_sip_proxy(path: str) -> None:
    """One call through a proxy: three host pairs, one Call-ID, 11 messages.

    Load-bearing properties:
    * `msg_count == 11` exactly (`tests/multi_input_test.rs:214`);
    * ONE Call-ID spread over THREE host pairs, so the `--cores` sharder --
      which keys on the sorted address pair -- splits one dialog across
      workers and the merge path is actually exercised;
    * classic pcap with at least three whole records, because the truncation
      helper in the multi-input suite cuts inside the third record's payload;
    * answered-to-BYE under five seconds, which is what makes the example
      WASM plugin fire on this capture (docs/design/wasm-plugin-api.md).
    """
    caller, proxy, callee = "192.0.2.101", "192.0.2.102", "192.0.2.100"
    call_id = "proxied-call-synth@192.0.2.101"
    ftag, ttag = "tag-caller-proxy", "tag-callee-proxy"
    via_caller = f"SIP/2.0/UDP {caller}:5060;branch={branch('proxy-caller')}"
    via_proxy = f"SIP/2.0/UDP {proxy}:5080;branch={branch('proxy-hop')}"
    frm = f"Caller <sip:caller@{ATLANTA}>;tag={ftag}"
    to_plain = f"Callee <sip:callee@{BILOXI}>"
    to_tagged = f"{to_plain};tag={ttag}"
    offer = sdp("caller", 10001, 1, caller, 6010)
    answer = sdp("callee", 10002, 1, callee, 6020)

    def req(method, vias, to, cseq, body="", extra=()):
        headers = [("Via", v) for v in vias]
        headers += [
            ("From", frm),
            ("To", to),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
            ("Max-Forwards", "70"),
        ]
        headers += list(extra)
        if body:
            headers.append(("Content-Type", "application/sdp"))
        return sip_message(f"{method} sip:callee@{BILOXI} SIP/2.0", headers, body)

    def resp(code, reason, vias, to, cseq, method, body="", extra=()):
        headers = [("Via", v) for v in vias]
        headers += [
            ("From", frm),
            ("To", to),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
        ]
        headers += list(extra)
        if body:
            headers.append(("Content-Type", "application/sdp"))
        return sip_message(f"SIP/2.0 {code} {reason}", headers, body)

    contact_caller = ("Contact", f"<sip:caller@{caller}:5060>")
    contact_callee = ("Contact", f"<sip:callee@{callee}:5060>")
    ua_caller = ("User-Agent", UA_PHONE)
    ua_proxy = ("Server", UA_PROXY)

    flow = [
        (0.0, caller, proxy, 5060, 5080,
         req("INVITE", [via_caller], to_plain, 1, offer, [contact_caller, ua_caller])),
        (0.024724, proxy, caller, 5080, 5060,
         resp(100, "Trying", [via_caller], to_plain, 1, "INVITE", "", [ua_proxy])),
        (0.036248, proxy, callee, 5080, 5060,
         req("INVITE", [via_proxy, via_caller], to_plain, 1, offer,
             [contact_caller, ("Record-Route", f"<sip:{proxy}:5080;lr>"), ua_proxy])),
        (0.076903, callee, proxy, 5060, 5080,
         resp(100, "Trying", [via_proxy, via_caller], to_plain, 1, "INVITE", "",
              [("Server", UA_PHONE)])),
        (0.095776, callee, proxy, 5060, 5080,
         resp(180, "Ringing", [via_proxy, via_caller], to_tagged, 1, "INVITE", "",
              [contact_callee, ("Server", UA_PHONE)])),
        (0.121593, proxy, caller, 5080, 5060,
         resp(180, "Ringing", [via_caller], to_tagged, 1, "INVITE", "",
              [contact_callee, ua_proxy])),
        (0.708086, callee, proxy, 5060, 5080,
         resp(200, "OK", [via_proxy, via_caller], to_tagged, 1, "INVITE", answer,
              [contact_callee, ("Server", UA_PHONE)])),
        (0.725139, proxy, caller, 5080, 5060,
         resp(200, "OK", [via_caller], to_tagged, 1, "INVITE", answer,
              [contact_callee, ua_proxy])),
        (0.747151, caller, callee, 5060, 5060,
         req("ACK", [f"SIP/2.0/UDP {caller}:5060;branch={branch('proxy-ack')}"],
             to_tagged, 1, "", [contact_caller, ua_caller])),
        (2.957262, callee, caller, 5060, 5060,
         sip_message(
             f"BYE sip:caller@{caller}:5060 SIP/2.0",
             [
                 ("Via", f"SIP/2.0/UDP {callee}:5060;branch={branch('proxy-bye')}"),
                 ("From", to_tagged),
                 ("To", frm),
                 ("Call-ID", call_id),
                 ("CSeq", "1 BYE"),
                 ("Max-Forwards", "70"),
                 ("User-Agent", UA_PHONE),
             ],
         )),
        (2.970123, caller, callee, 5060, 5060,
         sip_message(
             "SIP/2.0 200 OK",
             [
                 ("Via", f"SIP/2.0/UDP {callee}:5060;branch={branch('proxy-bye')}"),
                 ("From", to_tagged),
                 ("To", frm),
                 ("Call-ID", call_id),
                 ("CSeq", "1 BYE"),
                 ("User-Agent", UA_PHONE),
             ],
         )),
    ]
    packets = [
        (PROXY_EPOCH + off, udp_frame(src, dst, sp, dp, msg, 0x2000 + i))
        for i, (off, src, dst, sp, dp, msg) in enumerate(flow)
    ]
    write_pcap(path, packets)


# ── sip-sdp-example.pcap ────────────────────────────────────────────


def build_sip_sdp_example(path: str) -> None:
    """A plain answered call carrying SDP on both sides, no media recorded.

    Load-bearing: it must open cleanly through the TUI file-open path, and the
    answered-to-BYE span stays under five seconds so the documented plugin
    behavior (docs/design/wasm-plugin-api.md) still holds.
    """
    caller, callee = "192.0.2.101", "192.0.2.100"
    call_id = "sdp-example-synth@192.0.2.101"
    ftag, ttag = "tag-caller-sdp", "tag-callee-sdp"
    via = f"SIP/2.0/UDP {caller}:5060;branch={branch('sdp-example')}"
    frm = f"Caller <sip:caller@{ATLANTA}>;tag={ftag}"
    to_plain = f"Callee <sip:callee@{BILOXI}>"
    to_tagged = f"{to_plain};tag={ttag}"
    offer = sdp(
        "caller", 10003, 1, caller, 6010,
        payloads="8 96",
        rtpmaps=("8 PCMA/8000", "96 telephone-event/8000"),
    )
    answer = sdp(
        "callee", 10004, 1, callee, 6020,
        payloads="8 96",
        rtpmaps=("8 PCMA/8000", "96 telephone-event/8000"),
    )

    def head(to, cseq, method):
        return [
            ("Via", via),
            ("From", frm),
            ("To", to),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
        ]

    invite = sip_message(
        f"INVITE sip:callee@{BILOXI} SIP/2.0",
        head(to_plain, 1, "INVITE")
        + [
            ("Max-Forwards", "70"),
            ("Contact", f"<sip:caller@{caller}:5060>"),
            ("User-Agent", UA_PHONE),
            ("Content-Type", "application/sdp"),
        ],
        offer,
    )
    trying = sip_message("SIP/2.0 100 Trying", head(to_plain, 1, "INVITE"))
    ringing = sip_message(
        "SIP/2.0 180 Ringing",
        head(to_tagged, 1, "INVITE") + [("Contact", f"<sip:callee@{callee}:5060>")],
    )
    ok = sip_message(
        "SIP/2.0 200 OK",
        head(to_tagged, 1, "INVITE")
        + [
            ("Contact", f"<sip:callee@{callee}:5060>"),
            ("Server", UA_PHONE),
            ("Content-Type", "application/sdp"),
        ],
        answer,
    )
    ack = sip_message(
        f"ACK sip:callee@{callee}:5060 SIP/2.0",
        [
            ("Via", f"SIP/2.0/UDP {caller}:5060;branch={branch('sdp-example-ack')}"),
            ("From", frm),
            ("To", to_tagged),
            ("Call-ID", call_id),
            ("CSeq", "1 ACK"),
            ("Max-Forwards", "70"),
        ],
    )
    bye = sip_message(
        f"BYE sip:caller@{caller}:5060 SIP/2.0",
        [
            ("Via", f"SIP/2.0/UDP {callee}:5060;branch={branch('sdp-example-bye')}"),
            ("From", to_tagged),
            ("To", frm),
            ("Call-ID", call_id),
            ("CSeq", "1 BYE"),
            ("Max-Forwards", "70"),
        ],
    )
    bye_ok = sip_message(
        "SIP/2.0 200 OK",
        [
            ("Via", f"SIP/2.0/UDP {callee}:5060;branch={branch('sdp-example-bye')}"),
            ("From", to_tagged),
            ("To", frm),
            ("Call-ID", call_id),
            ("CSeq", "1 BYE"),
        ],
    )
    flow = [
        (0.0, caller, callee, invite),
        (0.031262, callee, caller, trying),
        (0.042025, callee, caller, ringing),
        (1.942786, callee, caller, ok),
        (1.954387, caller, callee, ack),
        (5.039576, callee, caller, bye),
        (5.051128, caller, callee, bye_ok),
    ]
    packets = [
        (SDP_EXAMPLE_EPOCH + off, udp_frame(src, dst, 5060, 5060, msg, 0x3000 + i))
        for i, (off, src, dst, msg) in enumerate(flow)
    ]
    write_pcap(path, packets)


# ── sip-auth-failure.pcapng ─────────────────────────────────────────

AUTH_FAILURE_EPOCH = 1463472095.431471

#: A synthetic Digest challenge. The nonce and response are fixed hex labels,
#: not values any real credential would produce.
CHALLENGE = 'Digest realm="example.com", nonce="7a1b2c3d4e5f6071", algorithm=MD5, qop="auth"'
CREDENTIALS = (
    'Digest username="alice", realm="example.com", nonce="7a1b2c3d4e5f6071", '
    'uri="sip:example.com", response="0f1e2d3c4b5a6978", algorithm=MD5, '
    'cnonce="synthcnonce", nc=00000001, qop=auth'
)


def build_sip_auth_failure(path: str) -> None:
    """Two challenged requests that end 403 Forbidden. No media anywhere.

    Load-bearing properties:
    * the FIRST dialog emitted must be the one carrying the 403, because
      `mcp_diagnostic_tools_test` triages `first_call_id(...)` and asserts the
      verdict is `signaling`;
    * ZERO RTP packets in the whole capture -- with a stream store that saw no
      media, sipnab withholds `no_media`, and the verdict stays `signaling`
      rather than becoming `both`;
    * a >= 400 final response, which is what makes `signaling_diagnosis`
      non-null; `json_schema_test` requires at least one such line to
      validate the diagnosed shape.
    """
    client, server = "203.0.113.1", "203.0.113.101"

    def exchange(method, call_id, tag, label, port):
        via = f"SIP/2.0/UDP {client}:{port};branch={branch(label)};rport"
        via2 = f"SIP/2.0/UDP {client}:{port};branch={branch(label + '-2')};rport"
        frm = f"Alice <sip:alice@{DOMAIN}>;tag={tag}"
        to = f"Alice <sip:alice@{DOMAIN}>"
        to_tagged = f"{to};tag=tag-server-{label}"
        base = [("From", frm), ("Call-ID", call_id)]
        extra = [("Event", "message-summary")] if method == "SUBSCRIBE" else []
        first = sip_message(
            f"{method} sip:{DOMAIN} SIP/2.0",
            [("Via", via)]
            + base
            + [("To", to), ("CSeq", f"1 {method}"), ("Max-Forwards", "70"),
               ("Contact", f"<sip:alice@{client}:{port}>"), ("User-Agent", UA_PHONE)]
            + extra,
        )
        unauthorized = sip_message(
            "SIP/2.0 401 Unauthorized",
            [("Via", via)]
            + base
            + [("To", to_tagged), ("CSeq", f"1 {method}"),
               ("WWW-Authenticate", CHALLENGE), ("Server", UA_SWITCH)],
        )
        retry = sip_message(
            f"{method} sip:{DOMAIN} SIP/2.0",
            [("Via", via2)]
            + base
            + [("To", to), ("CSeq", f"2 {method}"), ("Max-Forwards", "70"),
               ("Contact", f"<sip:alice@{client}:{port}>"),
               ("Authorization", CREDENTIALS), ("User-Agent", UA_PHONE)]
            + extra,
        )
        forbidden = sip_message(
            "SIP/2.0 403 Forbidden",
            [("Via", via2)]
            + base
            + [("To", to_tagged), ("CSeq", f"2 {method}"), ("Server", UA_SWITCH)],
        )
        return [first, unauthorized, retry, forbidden]

    reg = exchange("REGISTER", "auth-fail-register-synth@203.0.113.1", "tag-reg", "reg", 42952)
    sub = exchange("SUBSCRIBE", "auth-fail-subscribe-synth@203.0.113.1", "tag-sub", "sub", 42952)
    offsets = [0.0, 0.00076, 0.00139, 0.001636, 0.504477, 0.50529, 0.506024, 0.506446]
    order = [
        (reg[0], client, server),
        (reg[1], server, client),
        (reg[2], client, server),
        (reg[3], server, client),
        (sub[0], client, server),
        (sub[1], server, client),
        (sub[2], client, server),
        (sub[3], server, client),
    ]
    packets = []
    for i, (off, (msg, src, dst)) in enumerate(zip(offsets, order)):
        sport, dport = (42952, 5060) if src == client else (5060, 42952)
        packets.append(
            (AUTH_FAILURE_EPOCH + off, udp_frame(src, dst, sport, dport, msg, 0x4000 + i))
        )
    write_pcapng(path, packets)


# ── sip-routing-error.pcapng ────────────────────────────────────────

ROUTING_ERROR_EPOCH = 1463594496.212041


def build_sip_routing_error(path: str) -> None:
    """A phone whose requests keep landing on the wrong answer.

    Registrations succeed, then SUBSCRIBE, PUBLISH and INVITE traffic comes
    back 404, 480 and 489 from three different peers. Nothing beyond "it is a
    pcapng that parses and holds packets" is asserted about this file, so the
    shape here exists to keep it a useful routing-failure sample rather than
    to satisfy a specific assertion.
    """
    phone_a, phone_b = "203.0.113.1", "203.0.113.145"
    server, presence = "203.0.113.101", "203.0.113.102"
    offsets = [
        0.0, 0.000234, 0.000764, 0.001166, 1.417258, 1.442999,
        17.205308, 17.205538, 17.20702, 17.20743, 17.320374, 17.320636,
        17.320957, 17.321377, 17.321623, 17.321775, 17.323737, 17.32403,
        17.325359, 17.325656, 54.679995, 54.680221, 54.68033, 54.680528,
        54.68098, 54.681116, 54.681339, 54.682623, 54.684342, 54.697985,
        54.69819, 54.701616, 54.799362, 54.799713, 54.799899, 54.800211,
        54.803255, 54.803656, 61.453921, 61.479944, 129.009024, 129.035476,
        189.063171, 189.08908, 190.284046, 190.285462, 190.286625, 190.286924,
        190.289557, 190.292415, 252.661931, 252.689071, 264.349743, 264.350183,
        264.352362, 264.352669, 264.867642, 264.868312,
    ]

    def msg(method, code, reason, call_id, cseq, label, user, body=""):
        via = f"SIP/2.0/UDP {phone_a}:44285;branch={branch(label)};rport"
        headers = [
            ("Via", via),
            ("From", f"<sip:{user}@{DOMAIN}>;tag=tag-{label}"),
            ("To", f"<sip:{user}@{DOMAIN}>" + ("" if code is None else f";tag=tag-peer-{label}")),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
        ]
        if code is None:
            headers += [("Max-Forwards", "70"), ("User-Agent", UA_PHONE)]
            if method in ("SUBSCRIBE", "PUBLISH"):
                headers.append(("Event", "presence"))
            if body:
                headers.append(("Content-Type", "application/sdp"))
            return sip_message(f"{method} sip:{user}@{DOMAIN} SIP/2.0", headers, body)
        headers.append(("Server", UA_SWITCH))
        return sip_message(f"SIP/2.0 {code} {reason}", headers)

    # (method, code, reason, call-id suffix, cseq, src, dst)
    script = [
        ("REGISTER", None, "", "reg-a", 1, phone_a, server),
        ("REGISTER", 401, "Unauthorized", "reg-a", 1, server, phone_a),
        ("REGISTER", None, "", "reg-a", 2, phone_a, server),
        ("REGISTER", 200, "OK", "reg-a", 2, server, phone_a),
        ("SUBSCRIBE", None, "", "sub-a", 1, phone_a, presence),
        ("SUBSCRIBE", 480, "Temporarily Unavailable", "sub-a", 1, presence, phone_a),
        ("REGISTER", None, "", "reg-b", 1, phone_b, server),
        ("REGISTER", 401, "Unauthorized", "reg-b", 1, server, phone_b),
        ("REGISTER", None, "", "reg-b", 2, phone_b, server),
        ("REGISTER", 200, "OK", "reg-b", 2, server, phone_b),
        ("PUBLISH", None, "", "pub-b1", 1, phone_b, server),
        ("SUBSCRIBE", None, "", "sub-b1", 1, phone_b, server),
        ("SUBSCRIBE", None, "", "sub-b2", 1, phone_b, server),
        ("PUBLISH", 489, "Bad Event", "pub-b1", 1, server, phone_b),
        ("SUBSCRIBE", 401, "Unauthorized", "sub-b1", 1, server, phone_b),
        ("SUBSCRIBE", 401, "Unauthorized", "sub-b2", 1, server, phone_b),
        ("SUBSCRIBE", None, "", "sub-b1", 2, phone_b, server),
        ("SUBSCRIBE", 489, "Bad Event", "sub-b1", 2, server, phone_b),
        ("SUBSCRIBE", None, "", "sub-b2", 2, phone_b, server),
        ("SUBSCRIBE", 404, "Not Found", "sub-b2", 2, server, phone_b),
        ("INVITE", None, "", "inv-b", 1, phone_b, server),
        ("PUBLISH", None, "", "pub-b2", 1, phone_b, server),
        ("SUBSCRIBE", None, "", "sub-b3", 1, phone_b, server),
        ("INVITE", 401, "Unauthorized", "inv-b", 1, server, phone_b),
        ("PUBLISH", 489, "Bad Event", "pub-b2", 1, server, phone_b),
        ("SUBSCRIBE", 401, "Unauthorized", "sub-b3", 1, server, phone_b),
        ("ACK", None, "", "inv-b", 1, phone_b, server),
        ("INVITE", None, "", "inv-b", 2, phone_b, server),
        ("SUBSCRIBE", None, "", "sub-b3", 2, phone_b, server),
        ("INVITE", 404, "Not Found", "inv-b", 2, server, phone_b),
        ("SUBSCRIBE", 489, "Bad Event", "sub-b3", 2, server, phone_b),
        ("ACK", None, "", "inv-b", 2, phone_b, server),
        ("PUBLISH", None, "", "pub-b3", 1, phone_b, server),
        ("SUBSCRIBE", None, "", "sub-b4", 1, phone_b, server),
        ("PUBLISH", 489, "Bad Event", "pub-b3", 1, server, phone_b),
        ("SUBSCRIBE", 401, "Unauthorized", "sub-b4", 1, server, phone_b),
        ("SUBSCRIBE", None, "", "sub-b4", 2, phone_b, server),
        ("SUBSCRIBE", 489, "Bad Event", "sub-b4", 2, server, phone_b),
        ("SUBSCRIBE", None, "", "sub-a2", 1, phone_a, presence),
        ("SUBSCRIBE", 480, "Temporarily Unavailable", "sub-a2", 1, presence, phone_a),
        ("SUBSCRIBE", None, "", "sub-a3", 1, phone_a, presence),
        ("SUBSCRIBE", 480, "Temporarily Unavailable", "sub-a3", 1, presence, phone_a),
        ("SUBSCRIBE", None, "", "sub-a4", 1, phone_a, presence),
        ("SUBSCRIBE", 480, "Temporarily Unavailable", "sub-a4", 1, presence, phone_a),
        ("INVITE", None, "", "inv-a", 1, phone_a, server),
        ("INVITE", 401, "Unauthorized", "inv-a", 1, server, phone_a),
        ("ACK", None, "", "inv-a", 1, phone_a, server),
        ("INVITE", None, "", "inv-a", 2, phone_a, server),
        ("INVITE", 404, "Not Found", "inv-a", 2, server, phone_a),
        ("ACK", None, "", "inv-a", 2, phone_a, server),
        ("SUBSCRIBE", None, "", "sub-a5", 1, phone_a, presence),
        ("SUBSCRIBE", 480, "Temporarily Unavailable", "sub-a5", 1, presence, phone_a),
        ("SUBSCRIBE", None, "", "sub-b5", 1, phone_b, server),
        ("SUBSCRIBE", 401, "Unauthorized", "sub-b5", 1, server, phone_b),
        ("SUBSCRIBE", None, "", "sub-b5", 2, phone_b, server),
        ("SUBSCRIBE", 489, "Bad Event", "sub-b5", 2, server, phone_b),
        ("PUBLISH", None, "", "pub-b4", 1, phone_b, server),
        ("PUBLISH", 489, "Bad Event", "pub-b4", 1, server, phone_b),
    ]
    assert len(script) == len(offsets), f"{len(script)} messages vs {len(offsets)} offsets"

    packets = []
    for i, ((method, code, reason, suffix, cseq, src, dst), off) in enumerate(
        zip(script, offsets)
    ):
        # The suffix names which phone owns the dialog, so the user part and
        # the addresses cannot drift apart as the script is edited.
        user = "alice" if "-a" in suffix else "bob"
        body = ""
        if method == "INVITE" and code is None:
            body = sdp("bob", 3000000 + i, 1, src, 8000)
        payload = msg(method, code, reason, f"routing-{suffix}-synth@203.0.113.1",
                      cseq, f"route-{suffix}-{cseq}", user, body)
        sport = 44285 if src in (phone_a,) else (40216 if src == phone_b else 5060)
        dport = 5060 if dst in (server, presence) else (44285 if dst == phone_a else 40216)
        packets.append(
            (ROUTING_ERROR_EPOCH + off, udp_frame(src, dst, sport, dport, payload, 0x5000 + i))
        )
    write_pcapng(path, packets)


# ── sip-488-codec-reject.pcapng ─────────────────────────────────────

CODEC_REJECT_EPOCH = 1566926798.890031

#: The OPTIONS keepalive at the head of the capture. Its dialog carries no
#: body at all, which is what makes `check_codec_negotiation` answer
#: `no_sdp_in_capture` instead of claiming the far end never answered.
CODEC_REJECT_PING_A = "options-ping-a-synth@192.168.10.13"
#: The third keepalive, deliberately non-conformant: no `Max-Forwards` and a
#: branch with no RFC 3261 magic cookie, so the linter has two message-level
#: findings to report on message index 0 of a two-message dialog.
CODEC_REJECT_PING_C = "options-ping-c-synth@198.51.100.206"
#: The rejected call. A bare token with no host part -- a real and legal
#: Call-ID shape that nothing else in the sample set covers.
CODEC_REJECT_CALL = "codec-reject-synth"


def build_sip_488_codec_reject(path: str) -> None:
    """Three OPTIONS keepalives, then a call rejected 488.

    Load-bearing properties, each asserted somewhere:
    * the FIRST dialog is an OPTIONS exchange with NO body, so an absent SDP
      is distinguishable from an offer nobody answered;
    * the INVITE offers `m=audio 0 RTP/AVP 0` with NO `a=rtpmap`, so naming
      the codec requires the RFC 3551 static payload table -- payload type 0
      is permanently PCMU. An extractor that only reads rtpmap lines reports
      "the caller offered nothing" here, which is a different diagnosis;
    * the call's final response is 488, and it carries a signaling
      diagnosis, which is the shape `call_report.schema.json` needs
      validated;
    * the third keepalive's request has no `Max-Forwards` and a branch with
      no `z9hG4bK` cookie, and its dialog holds exactly two messages.
    """
    pbx, phone, peer = "192.168.10.13", "192.168.10.183", "198.51.100.206"
    remote = "192.168.10.138"
    packets = []

    def add(off, src, dst, sport, dport, payload):
        packets.append(
            (
                CODEC_REJECT_EPOCH + off,
                udp_frame(src, dst, sport, dport, payload, 0x6000 + len(packets)),
            )
        )

    # -- keepalive A and B: ordinary, conformant OPTIONS pings --------
    for label, call_id, cseq, offs, far in (
        ("a", CODEC_REJECT_PING_A, 42822, (0.0, 0.056572), phone),
        ("b", "options-ping-b-synth@192.168.10.13", 6328, (4.4345, 4.458226), remote),
    ):
        via = f"SIP/2.0/UDP {pbx}:5060;rport;branch={branch('ping-' + label)}"
        head = [
            ("Via", via),
            ("From", f"<sip:keepalive@{pbx}>;tag=tag-ping-{label}"),
            ("To", f"<sip:keepalive@{far}>"),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} OPTIONS"),
        ]
        request = sip_message(
            f"OPTIONS sip:keepalive@{far} SIP/2.0",
            head
            + [
                ("Contact", f"<sip:keepalive@{pbx}:5060>"),
                ("Max-Forwards", "70"),
                ("User-Agent", UA_SWITCH),
            ],
        )
        answer_head = list(head)
        answer_head[2] = ("To", f"<sip:keepalive@{far}>;tag=tag-peer-{label}")
        response = sip_message(
            "SIP/2.0 200 OK",
            answer_head
            + [
                ("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, INFO"),
                ("Accept", "application/sdp"),
                ("Supported", "replaces, timer"),
                ("Server", UA_PHONE),
            ],
        )
        add(offs[0], pbx, far, 5060, 5060, request)
        add(offs[1], far, pbx, 5060, 5060, response)

    # -- keepalive C: the non-conformant one --------------------------
    # No Max-Forwards, and a branch with no z9hG4bK cookie. Both are real
    # defects that ship in real keepalive generators, and both are what the
    # message-level linter rules are asserted against.
    head_c = [
        ("Via", f"SIP/2.0/UDP {peer}:5010;branch=0"),
        ("From", f"<sip:ping@{DOMAIN}>;tag=tag-ping-c"),
        ("To", f"<sip:probe@{phone}:5060>"),
        ("Call-ID", CODEC_REJECT_PING_C),
        ("CSeq", "1 OPTIONS"),
    ]
    add(
        7.332828,
        peer,
        phone,
        5010,
        5060,
        sip_message(f"OPTIONS sip:probe@{phone}:5060 SIP/2.0", head_c),
    )
    head_c_answer = list(head_c)
    head_c_answer[0] = (
        "Via",
        f"SIP/2.0/UDP {peer}:5010;rport=5010;received={peer};branch=0",
    )
    head_c_answer[2] = ("To", f"<sip:probe@{phone}>;tag=tag-probe-c")
    add(
        7.334082,
        phone,
        peer,
        5060,
        5010,
        sip_message(
            "SIP/2.0 200 OK",
            head_c_answer
            + [
                ("Accept", "application/sdp, message/sipfrag;version=2.0"),
                ("Allow", "OPTIONS, SUBSCRIBE, NOTIFY, INVITE, ACK, BYE, CANCEL"),
                ("Supported", "replaces, timer"),
                ("Accept-Language", "en"),
                ("Server", UA_SWITCH),
            ],
        ),
    )

    # -- the rejected call --------------------------------------------
    # `m=audio 0 RTP/AVP 0` with no a=rtpmap: RFC 3551 Table 4 makes payload
    # type 0 permanently PCMU, so the codec is nameable without an rtpmap and
    # an empty `offered` list is a bug rather than a property of the capture.
    offer = CRLF.join(
        [
            "v=0",
            f"o=caller 559 2101 IN IP4 {phone}",
            "s=synthetic session",
            "c=IN IP4 0.0.0.0",
            "t=0 0",
            "m=audio 0 RTP/AVP 0",
            "a=inactive",
        ]
    ) + CRLF
    frm = f"<sip:caller@{pbx}>;tag=tag-caller-488"
    to_plain = f"<sip:callee@{pbx}>"
    to_tagged_auth = f"{to_plain};tag=tag-auth-488"
    to_tagged_final = f"{to_plain};tag=tag-reject-488"

    def call_head(via_label, to, cseq, method):
        return [
            ("Via", f"SIP/2.0/UDP {phone}:5060;branch={branch(via_label)};rport"),
            ("From", frm),
            ("To", to),
            ("Call-ID", CODEC_REJECT_CALL),
            ("CSeq", f"{cseq} {method}"),
        ]

    contact = ("Contact", f"<sip:caller@{phone};transport=udp>")
    add(9.944647, phone, pbx, 5060, 5060, sip_message(
        f"INVITE sip:callee@{pbx} SIP/2.0",
        call_head("488-first", to_plain, 20, "INVITE")
        + [("Max-Forwards", "70"), ("Supported", "replaces, outbound"),
           ("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE"), contact,
           ("User-Agent", UA_PHONE), ("Content-Type", "application/sdp")],
        offer,
    ))
    add(9.946189, pbx, phone, 5060, 5060, sip_message(
        "SIP/2.0 401 Unauthorized",
        call_head("488-first", to_tagged_auth, 20, "INVITE")
        + [("WWW-Authenticate", CHALLENGE), ("Server", UA_SWITCH)],
    ))
    add(9.994675, phone, pbx, 5060, 5060, sip_message(
        f"ACK sip:callee@{pbx} SIP/2.0",
        call_head("488-first", to_tagged_auth, 20, "ACK")
        + [("Max-Forwards", "70"), contact],
    ))
    add(9.994933, phone, pbx, 5060, 5060, sip_message(
        f"INVITE sip:callee@{pbx} SIP/2.0",
        call_head("488-second", to_plain, 21, "INVITE")
        + [("Max-Forwards", "70"), ("Supported", "replaces, outbound"),
           ("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE"), contact,
           ("User-Agent", UA_PHONE), ("Authorization", CREDENTIALS),
           ("Content-Type", "application/sdp")],
        offer,
    ))
    add(9.997598, pbx, phone, 5060, 5060, sip_message(
        "SIP/2.0 100 Trying",
        call_head("488-second", to_plain, 21, "INVITE") + [("Server", UA_SWITCH)],
    ))
    add(9.997954, pbx, phone, 5060, 5060, sip_message(
        "SIP/2.0 488 Not Acceptable Here",
        call_head("488-second", to_tagged_final, 21, "INVITE")
        + [("Warning", '399 example.com "no compatible codec"'), ("Server", UA_SWITCH)],
    ))
    add(10.063309, phone, pbx, 5060, 5060, sip_message(
        f"ACK sip:callee@{pbx} SIP/2.0",
        call_head("488-second", to_tagged_final, 21, "ACK")
        + [("Max-Forwards", "70"), contact],
    ))
    write_pcapng(path, packets)


# ── rtp-protocol.pcap ───────────────────────────────────────────────

RTP_PROTOCOL_EPOCH = 1311238105.417810


def build_rtp_protocol(path: str) -> None:
    """An answered call with reliable provisionals and two-way G.711A media.

    The only assertion on this file is that it loads with at least one packet.
    It keeps a PRACK exchange and two RTP streams because that is what makes
    it a distinct sample: a capture where the provisional response is
    acknowledged and media flows both ways.
    """
    caller, callee = "198.51.100.101", "198.51.100.100"
    call_id = "rtp-protocol-synth@198.51.100.101"
    ftag, ttag = "tag-caller-rtp", "tag-callee-rtp"
    via = f"SIP/2.0/UDP {caller}:5060;branch={branch('rtp-protocol')}"
    frm = f"Caller <sip:caller@{ATLANTA}>;tag={ftag}"
    to_plain = f"Callee <sip:callee@{BILOXI}>"
    to_tagged = f"{to_plain};tag={ttag}"
    codecs = ("8 PCMA/8000", "101 telephone-event/8000")
    offer = sdp("caller", 10005, 1, caller, 6040, payloads="8 101", rtpmaps=codecs)
    answer = sdp("callee", 10006, 1, callee, 6020, payloads="8 101", rtpmaps=codecs)

    def head(to, cseq, method):
        return [
            ("Via", via),
            ("From", frm),
            ("To", to),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
        ]

    sip_flow = [
        (0.0, caller, callee, sip_message(
            f"INVITE sip:callee@{BILOXI} SIP/2.0",
            head(to_plain, 1, "INVITE")
            + [("Max-Forwards", "70"), ("Supported", "100rel"),
               ("Contact", f"<sip:caller@{caller}:5060>"), ("User-Agent", UA_PHONE),
               ("Content-Type", "application/sdp")],
            offer,
        )),
        (0.064906, callee, caller, sip_message(
            "SIP/2.0 100 Trying", head(to_plain, 1, "INVITE"))),
        (0.09048, callee, caller, sip_message(
            "SIP/2.0 180 Ringing",
            head(to_tagged, 1, "INVITE")
            + [("Require", "100rel"), ("RSeq", "1"),
               ("Contact", f"<sip:callee@{callee}:5060>")],
        )),
        (0.113948, caller, callee, sip_message(
            f"PRACK sip:callee@{callee}:5060 SIP/2.0",
            [("Via", f"SIP/2.0/UDP {caller}:5060;branch={branch('rtp-prack')}"),
             ("From", frm), ("To", to_tagged), ("Call-ID", call_id),
             ("CSeq", "2 PRACK"), ("RAck", "1 1 INVITE"), ("Max-Forwards", "70")],
        )),
        (0.137309, callee, caller, sip_message(
            "SIP/2.0 200 OK",
            [("Via", f"SIP/2.0/UDP {caller}:5060;branch={branch('rtp-prack')}"),
             ("From", frm), ("To", to_tagged), ("Call-ID", call_id),
             ("CSeq", "2 PRACK")],
        )),
        (2.043514, callee, caller, sip_message(
            "SIP/2.0 200 OK",
            head(to_tagged, 1, "INVITE")
            + [("Contact", f"<sip:callee@{callee}:5060>"), ("Server", UA_PHONE),
               ("Content-Type", "application/sdp")],
            answer,
        )),
        (2.078739, caller, callee, sip_message(
            f"ACK sip:callee@{callee}:5060 SIP/2.0",
            [("Via", f"SIP/2.0/UDP {caller}:5060;branch={branch('rtp-ack')}"),
             ("From", frm), ("To", to_tagged), ("Call-ID", call_id),
             ("CSeq", "1 ACK"), ("Max-Forwards", "70")],
        )),
        (6.916023, callee, caller, sip_message(
            f"BYE sip:caller@{caller}:5060 SIP/2.0",
            [("Via", f"SIP/2.0/UDP {callee}:5060;branch={branch('rtp-bye')}"),
             ("From", to_tagged), ("To", frm), ("Call-ID", call_id),
             ("CSeq", "1 BYE"), ("Max-Forwards", "70")],
        )),
        (6.964766, caller, callee, sip_message(
            "SIP/2.0 200 OK",
            [("Via", f"SIP/2.0/UDP {callee}:5060;branch={branch('rtp-bye')}"),
             ("From", to_tagged), ("To", frm), ("Call-ID", call_id),
             ("CSeq", "1 BYE")],
        )),
    ]
    packets = [
        (RTP_PROTOCOL_EPOCH + off, udp_frame(src, dst, 5060, 5060, msg, 0x7000 + i))
        for i, (off, src, dst, msg) in enumerate(sip_flow)
    ]
    packets += _rtp_stream(
        RTP_PROTOCOL_EPOCH + 2.121889, caller, callee, 6040, 6020,
        payload_type=8, ssrc=0x0A11_0001, count=201, ident=0x7100,
    )
    packets += _rtp_stream(
        RTP_PROTOCOL_EPOCH + 2.088612, callee, caller, 6020, 6040,
        payload_type=8, ssrc=0x0A11_0002, count=47, ident=0x7300,
    )
    packets.append((
        RTP_PROTOCOL_EPOCH + 6.5,
        udp_frame(caller, callee, 6041, 6021,
                  rtcp_sender_report(0x0A11_0001, 37000, 32000, 201, 32160), 0x73F0),
    ))
    packets.append((
        RTP_PROTOCOL_EPOCH + 6.52,
        udp_frame(callee, caller, 6021, 6041,
                  rtcp_sender_report(0x0A11_0002, 37000, 7520, 47, 7520), 0x73F1),
    ))
    packets.sort(key=lambda p: p[0])
    write_pcap(path, packets)


def _rtp_stream(start, src, dst, sport, dport, payload_type, ssrc, count, ident,
                interval=0.02, size=160):
    """`count` RTP packets at a fixed cadence, as `(timestamp, frame)` pairs.

    A deterministic 1 ms sawtooth rides on the interval so the stream carries
    non-zero jitter -- a perfectly periodic stream makes every jitter
    statistic exactly zero, which is a value no real capture produces and
    which hides an arithmetic bug that returns zero.
    """
    out = []
    for i in range(count):
        wobble = ((i % 5) - 2) * 0.001
        ts = start + i * interval + wobble
        packet = rtp_packet(payload_type, 1000 + i, 160 * i, ssrc, size)
        out.append((ts, udp_frame(src, dst, sport, dport, packet, ident + i)))
    return out


# ── sip-over-tcp.pcap ───────────────────────────────────────────────

OVER_TCP_EPOCH = 1311857686.556175


def build_sip_over_tcp(path: str) -> None:
    """The same call shape carried over TCP instead of UDP.

    Load-bearing: the example WASM plugin must find EXACTLY ONE short
    answered call here -- one dialog whose 2xx-to-INVITE is followed by a BYE
    less than five seconds later. The gap below is 2.15 s. A second qualifying
    dialog would break `plugin_example_test`'s `assert_eq!(seen, 1)`.

    Each SIP message is one TCP segment with a correct `Content-Length`, so
    the reader's stream framing is exercised without depending on a
    message split across segments (nothing asserts that case here).
    """
    caller, callee = "198.51.100.100", "198.51.100.101"
    sport, dport = 64802, 5060
    call_id = "over-tcp-synth@198.51.100.100"
    ftag, ttag = "tag-caller-tcp", "tag-callee-tcp"
    via = f"SIP/2.0/TCP {caller}:{sport};branch={branch('over-tcp')}"
    frm = f"Caller <sip:caller@{ATLANTA}>;tag={ftag}"
    to_plain = f"Callee <sip:callee@{BILOXI}>"
    to_tagged = f"{to_plain};tag={ttag}"
    codecs = ("8 PCMA/8000", "101 telephone-event/8000")
    offer = sdp("caller", 10007, 1, caller, 6000, payloads="8 101", rtpmaps=codecs)
    answer = sdp("callee", 10008, 1, callee, 6050, payloads="8 101", rtpmaps=codecs)

    def head(to, cseq, method):
        return [
            ("Via", via),
            ("From", frm),
            ("To", to),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
        ]

    messages = [
        (0.005921, True, sip_message(
            f"INVITE sip:callee@{BILOXI};transport=tcp SIP/2.0",
            head(to_plain, 1, "INVITE")
            + [("Max-Forwards", "70"),
               ("Contact", f"<sip:caller@{caller}:{sport};transport=tcp>"),
               ("User-Agent", UA_PHONE), ("Content-Type", "application/sdp")],
            offer,
        )),
        (0.046414, False, sip_message("SIP/2.0 100 Trying", head(to_plain, 1, "INVITE"))),
        (0.064948, False, sip_message(
            "SIP/2.0 180 Ringing",
            head(to_tagged, 1, "INVITE")
            + [("Contact", f"<sip:callee@{callee}:{dport};transport=tcp>")],
        )),
        (4.349461, False, sip_message(
            "SIP/2.0 200 OK",
            head(to_tagged, 1, "INVITE")
            + [("Contact", f"<sip:callee@{callee}:{dport};transport=tcp>"),
               ("Server", UA_PHONE), ("Content-Type", "application/sdp")],
            answer,
        )),
        (4.376957, True, sip_message(
            f"ACK sip:callee@{callee}:{dport};transport=tcp SIP/2.0",
            [("Via", f"SIP/2.0/TCP {caller}:{sport};branch={branch('over-tcp-ack')}"),
             ("From", frm), ("To", to_tagged), ("Call-ID", call_id),
             ("CSeq", "1 ACK"), ("Max-Forwards", "70")],
        )),
        (6.500977, False, sip_message(
            f"BYE sip:caller@{caller}:{sport};transport=tcp SIP/2.0",
            [("Via", f"SIP/2.0/TCP {callee}:{dport};branch={branch('over-tcp-bye')}"),
             ("From", to_tagged), ("To", frm), ("Call-ID", call_id),
             ("CSeq", "1 BYE"), ("Max-Forwards", "70")],
        )),
        (6.532184, True, sip_message(
            "SIP/2.0 200 OK",
            [("Via", f"SIP/2.0/TCP {callee}:{dport};branch={branch('over-tcp-bye')}"),
             ("From", to_tagged), ("To", frm), ("Call-ID", call_id),
             ("CSeq", "1 BYE")],
        )),
    ]

    packets = []
    ident = 0x8000
    # Three-way handshake first, so the capture reads as a real connection.
    seq_c, seq_s = 1000, 5000
    packets.append((OVER_TCP_EPOCH, tcp_frame(
        caller, callee, sport, dport, seq_c, 0, 0x02, b"", ident)))
    ident += 1
    packets.append((OVER_TCP_EPOCH + 0.000412, tcp_frame(
        callee, caller, dport, sport, seq_s, seq_c + 1, 0x12, b"", ident)))
    ident += 1
    seq_c += 1
    seq_s += 1
    packets.append((OVER_TCP_EPOCH + 0.000701, tcp_frame(
        caller, callee, sport, dport, seq_c, seq_s, 0x10, b"", ident)))
    ident += 1

    for off, from_caller, payload in messages:
        if from_caller:
            packets.append((OVER_TCP_EPOCH + off, tcp_frame(
                caller, callee, sport, dport, seq_c, seq_s, 0x18, payload, ident)))
            ident += 1
            seq_c += len(payload)
            packets.append((OVER_TCP_EPOCH + off + 0.000180, tcp_frame(
                callee, caller, dport, sport, seq_s, seq_c, 0x10, b"", ident)))
        else:
            packets.append((OVER_TCP_EPOCH + off, tcp_frame(
                callee, caller, dport, sport, seq_s, seq_c, 0x18, payload, ident)))
            ident += 1
            seq_s += len(payload)
            packets.append((OVER_TCP_EPOCH + off + 0.000180, tcp_frame(
                caller, callee, sport, dport, seq_c, seq_s, 0x10, b"", ident)))
        ident += 1

    packets += _rtp_stream(
        OVER_TCP_EPOCH + 4.416138, caller, callee, 6000, 6050,
        payload_type=8, ssrc=0x0B22_0001, count=24, ident=0x8100,
    )
    packets += _rtp_stream(
        OVER_TCP_EPOCH + 4.398769, callee, caller, 6050, 6000,
        payload_type=8, ssrc=0x0B22_0002, count=42, ident=0x8200,
    )
    packets.append((OVER_TCP_EPOCH + 6.4, udp_frame(
        caller, callee, 6001, 6051,
        rtcp_sender_report(0x0B22_0001, 37001, 3840, 24, 3840), 0x82F0)))
    packets.append((OVER_TCP_EPOCH + 6.42, udp_frame(
        callee, caller, 6051, 6001,
        rtcp_sender_report(0x0B22_0002, 37001, 6720, 42, 6720), 0x82F1)))
    packets.sort(key=lambda p: p[0])
    write_pcap(path, packets)


# ── b2bua-asterisk.pcapng ───────────────────────────────────────────

B2BUA_EPOCH = 1463595783.881485

#: The B2BUA's second leg. Asserted verbatim as a `lint_dialog` argument and
#: quoted in `docs/mcp.md`, so changing it means changing those too. The
#: `@host:port` form is deliberate: it is a Call-ID shape real switches emit
#: and the only one in the sample set.
B2BUA_CALL_ID = "b2bua-leg-synth@203.0.113.101:5060"
#: The caller's leg. Carries the extension the demo tape filters on.
B2BUA_LEG_A_ID = "b2bua-caller-synth@203.0.113.1"
#: The extension the `04-filter.tape` demo types to narrow the dialog list.
#: `tests/site_journey_test.rs` reads the query out of the tape and requires
#: it to match at least one dialog and fewer than all of them, so this string
#: has to appear in exactly one dialog here.
B2BUA_EXTENSION = "2302"


def build_b2bua_asterisk(path: str) -> None:
    """A B2BUA bridging two call legs, with media that only flows one way.

    This is the most heavily asserted fixture in the set. What must hold:

    * TWELVE dialogs, in a fixed first-seen order, because a demo journey
      selects the SIXTH one (index 5) and expects a multi-leg ladder;
    * the sixth dialog is the caller's leg and the seventh is the B2BUA's,
      created within two seconds of each other and sharing the B2BUA's
      address -- that timing is the only thing that correlates them into one
      three-participant flow;
    * the B2BUA leg holds exactly FIFTEEN messages;
    * SDP negotiates `sendrecv` in both directions on every exchange, while
      355 RTP packets flow in ONE direction only. That gap is the finding
      `OBS-3264-6.1-DIRECTION-UNMET`, and no linter reading message text can
      see it -- both halves of the offer/answer are perfectly legal;
    * exactly ONE RTP stream is attributable to the B2BUA leg;
    * every answer offers formats the offer did not list, which is the
      interop-class finding the ruleset-partition test needs;
    * NO RFC 3261 syntax finding on the B2BUA leg: every request carries
      `Max-Forwards`, every branch carries the magic cookie, every URI with
      parameters is bracketed, and every ACK repeats its INVITE's CSeq. A
      single sloppy header here turns the `rfc3261 -> finding_count == 0`
      assertion red;
    * the answered-to-BYE span stays ABOVE five seconds so the example
      plugin's "short call" detector stays quiet on this capture.
    """
    caller, b2bua = "203.0.113.1", "203.0.113.101"
    presence, callee = "203.0.113.102", "203.0.113.145"
    caller_port, callee_port = 44285, 40216

    offer_codecs = ("0 PCMU/8000", "101 telephone-event/8000")
    answer_codecs = (
        "0 PCMU/8000",
        "3 GSM/8000",
        "110 speex/8000",
        "8 PCMA/8000",
        "97 iLBC/8000",
        "101 telephone-event/8000",
    )

    def offer_sdp(addr, port, session):
        return sdp("b2bua", session, 1, addr, port, payloads="0 101",
                   rtpmaps=offer_codecs)

    def answer_sdp(addr, port, session):
        # The answer lists formats the offer never carried. Legal SDP, and
        # the interop-class finding this fixture exists to raise.
        return sdp("callee", session, 1, addr, port, payloads="0 3 110 8 97 101",
                   rtpmaps=answer_codecs)

    packets = []

    def add(off, src, dst, sport, dport, payload):
        packets.append((
            B2BUA_EPOCH + off,
            udp_frame(src, dst, sport, dport, payload, 0x9000 + len(packets)),
        ))

    def simple(method, call_id, user, tag, cseq, label, event=None):
        """A request from a phone toward the B2BUA or the presence server."""
        headers = [
            ("Via", f"SIP/2.0/UDP {{via}};branch={branch(label)};rport"),
            ("From", f"<sip:{user}@{DOMAIN}>;tag={tag}"),
            ("To", f"<sip:{user}@{DOMAIN}>"),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
            ("Max-Forwards", "70"),
            ("User-Agent", UA_PHONE),
        ]
        if event:
            headers.append(("Event", event))
        return headers

    def render(headers, start_line, via_host, body=""):
        """Finish a header list: substitute the Via host and attach a body."""
        out = []
        for name, value in headers:
            out.append((name, value.replace("{via}", via_host)))
        if body:
            out.append(("Content-Type", "application/sdp"))
        return sip_message(start_line, out, body)

    def answer_of(headers, code, reason, peer_tag):
        """The response to `headers`: same dialog identifiers, To tag added.

        Request-only header fields are dropped rather than echoed, so a
        response never carries a `Max-Forwards` the linter would object to.
        """
        out = []
        for name, value in headers:
            if name == "To":
                value = f"{value};tag={peer_tag}"
            if name in ("Max-Forwards", "User-Agent", "Event"):
                continue
            out.append((name, value))
        out.append(("Server", UA_SWITCH))
        return out, f"SIP/2.0 {code} {reason}"

    def peer_exchange(off_req, off_resp, method, call_id, user, tag, cseq, label,
                      code, reason, phone, phone_port, server, event=None):
        """One request and its response, added to the capture in order."""
        headers = simple(method, call_id, user, tag, cseq, label, event)
        via_host = f"{phone}:{phone_port}"
        add(off_req, phone, server, phone_port, 5060,
            render(headers, f"{method} sip:{user}@{DOMAIN} SIP/2.0", via_host))
        resp_headers, start = answer_of(headers, code, reason, f"tag-peer-{label}")
        add(off_resp, server, phone, 5060, phone_port,
            render(resp_headers, start, via_host))

    # -- dialogs 1 and 2: two registrations ---------------------------
    peer_exchange(0.0, 0.000308, "REGISTER", "b2bua-reg-a-synth@203.0.113.1",
                  "alice", "tag-reg-a1", 1, "reg-a1", 401, "Unauthorized",
                  caller, caller_port, b2bua)
    peer_exchange(0.000846, 0.001208, "REGISTER", "b2bua-reg-a-synth@203.0.113.1",
                  "alice", "tag-reg-a2", 2, "reg-a2", 200, "OK",
                  caller, caller_port, b2bua)
    peer_exchange(7.34635, 7.347448, "REGISTER", "b2bua-reg-b-synth@203.0.113.145",
                  "bob", "tag-reg-b1", 1, "reg-b1", 401, "Unauthorized",
                  callee, callee_port, b2bua)
    peer_exchange(7.350068, 7.350481, "REGISTER", "b2bua-reg-b-synth@203.0.113.145",
                  "bob", "tag-reg-b2", 2, "reg-b2", 200, "OK",
                  callee, callee_port, b2bua)

    # -- dialogs 3-5: presence traffic the switch declines ------------
    pub1 = simple("PUBLISH", "b2bua-pub-1-synth@203.0.113.145", "bob", "tag-pub-1", 1,
                  "pub-1", "presence")
    sub1 = simple("SUBSCRIBE", "b2bua-sub-1-synth@203.0.113.145", "bob", "tag-sub-1", 1,
                  "sub-1", "message-summary")
    sub2 = simple("SUBSCRIBE", "b2bua-sub-2-synth@203.0.113.145", "bob", "tag-sub-2", 1,
                  "sub-2", "dialog")
    via_b = f"{callee}:{callee_port}"
    add(7.456642, callee, b2bua, callee_port, 5060,
        render(pub1, f"PUBLISH sip:bob@{DOMAIN} SIP/2.0", via_b))
    add(7.456788, callee, b2bua, callee_port, 5060,
        render(sub1, f"SUBSCRIBE sip:bob@{DOMAIN} SIP/2.0", via_b))
    add(7.45688, callee, b2bua, callee_port, 5060,
        render(sub2, f"SUBSCRIBE sip:bob@{DOMAIN} SIP/2.0", via_b))
    for off, headers, code, reason, label in (
        (7.457011, pub1, 489, "Bad Event", "pub-1"),
        (7.457179, sub1, 401, "Unauthorized", "sub-1"),
    ):
        resp_headers, start = answer_of(headers, code, reason, f"tag-peer-{label}")
        add(off, b2bua, callee, 5060, callee_port, render(resp_headers, start, via_b))
    sub1b = simple("SUBSCRIBE", "b2bua-sub-1-synth@203.0.113.145", "bob", "tag-sub-1", 2,
                   "sub-1b", "message-summary")
    add(7.458968, callee, b2bua, callee_port, 5060,
        render(sub1b, f"SUBSCRIBE sip:bob@{DOMAIN} SIP/2.0", via_b))
    resp_headers, start = answer_of(sub2, 401, "Unauthorized", "tag-peer-sub-2")
    add(7.459415, b2bua, callee, 5060, callee_port, render(resp_headers, start, via_b))
    resp_headers, start = answer_of(sub1b, 489, "Bad Event", "tag-peer-sub-1b")
    add(7.45957, b2bua, callee, 5060, callee_port, render(resp_headers, start, via_b))
    sub2b = simple("SUBSCRIBE", "b2bua-sub-2-synth@203.0.113.145", "bob", "tag-sub-2", 2,
                   "sub-2b", "dialog")
    add(7.46145, callee, b2bua, callee_port, 5060,
        render(sub2b, f"SUBSCRIBE sip:bob@{DOMAIN} SIP/2.0", via_b))
    resp_headers, start = answer_of(sub2b, 404, "Not Found", "tag-peer-sub-2b")
    add(7.461719, b2bua, callee, 5060, callee_port, render(resp_headers, start, via_b))

    # -- dialog 6: the caller's leg (13 messages) ---------------------
    a_from = f"Alice <sip:alice@{DOMAIN}>;tag=tag-leg-a"
    a_to = f"<sip:{B2BUA_EXTENSION}@{DOMAIN}>"
    a_to_auth = f"{a_to};tag=tag-leg-a-auth"
    a_to_final = f"{a_to};tag=tag-leg-a-ok"
    a_contact = ("Contact", f"<sip:alice@{caller}:{caller_port}>")

    def leg_a(via_label, to, cseq, method):
        return [
            ("Via", f"SIP/2.0/UDP {caller}:{caller_port};branch={branch(via_label)};rport"),
            ("From", a_from),
            ("To", to),
            ("Call-ID", B2BUA_LEG_A_ID),
            ("CSeq", f"{cseq} {method}"),
        ]

    add(12.038851, caller, b2bua, caller_port, 5060, sip_message(
        f"INVITE sip:{B2BUA_EXTENSION}@{DOMAIN} SIP/2.0",
        leg_a("leg-a-1", a_to, 1, "INVITE")
        + [("Max-Forwards", "70"), a_contact, ("User-Agent", UA_PHONE),
           ("Content-Type", "application/sdp")],
        offer_sdp(caller, 8000, 4000001),
    ))
    add(12.039625, b2bua, caller, 5060, caller_port, sip_message(
        "SIP/2.0 401 Unauthorized",
        leg_a("leg-a-1", a_to_auth, 1, "INVITE")
        + [("WWW-Authenticate", CHALLENGE), ("Server", UA_SWITCH)],
    ))
    add(12.040215, caller, b2bua, caller_port, 5060, sip_message(
        f"ACK sip:{B2BUA_EXTENSION}@{DOMAIN} SIP/2.0",
        leg_a("leg-a-1", a_to_auth, 1, "ACK") + [("Max-Forwards", "70")],
    ))
    add(12.040341, caller, b2bua, caller_port, 5060, sip_message(
        f"INVITE sip:{B2BUA_EXTENSION}@{DOMAIN} SIP/2.0",
        leg_a("leg-a-2", a_to, 2, "INVITE")
        + [("Max-Forwards", "70"), a_contact, ("Authorization", CREDENTIALS),
           ("User-Agent", UA_PHONE), ("Content-Type", "application/sdp")],
        offer_sdp(caller, 8000, 4000001),
    ))
    add(12.041488, b2bua, caller, 5060, caller_port, sip_message(
        "SIP/2.0 100 Trying", leg_a("leg-a-2", a_to, 2, "INVITE") + [("Server", UA_SWITCH)],
    ))
    add(12.783586, b2bua, caller, 5060, caller_port, sip_message(
        "SIP/2.0 180 Ringing",
        leg_a("leg-a-2", a_to_final, 2, "INVITE")
        + [("Contact", f"<sip:{B2BUA_EXTENSION}@{b2bua}:5060>"), ("Server", UA_SWITCH)],
    ))
    add(19.105296, b2bua, caller, 5060, caller_port, sip_message(
        "SIP/2.0 200 OK",
        leg_a("leg-a-2", a_to_final, 2, "INVITE")
        + [("Contact", f"<sip:{B2BUA_EXTENSION}@{b2bua}:5060>"), ("Server", UA_SWITCH),
           ("Content-Type", "application/sdp")],
        offer_sdp(b2bua, 13060, 4000002),
    ))
    add(19.112168, caller, b2bua, caller_port, 5060, sip_message(
        f"ACK sip:{B2BUA_EXTENSION}@{b2bua}:5060 SIP/2.0",
        leg_a("leg-a-ack", a_to_final, 2, "ACK") + [("Max-Forwards", "70")],
    ))
    add(19.112464, b2bua, caller, 5060, caller_port, sip_message(
        f"INVITE sip:alice@{caller}:{caller_port} SIP/2.0",
        [("Via", f"SIP/2.0/UDP {b2bua}:5060;branch={branch('leg-a-reinvite')};rport"),
         ("From", a_to_final), ("To", a_from), ("Call-ID", B2BUA_LEG_A_ID),
         ("CSeq", "102 INVITE"), ("Max-Forwards", "70"),
         ("Contact", f"<sip:{B2BUA_EXTENSION}@{b2bua}:5060>"), ("Server", UA_SWITCH),
         ("Content-Type", "application/sdp")],
        offer_sdp(callee, 8000, 4000003),
    ))
    add(19.135069, caller, b2bua, caller_port, 5060, sip_message(
        "SIP/2.0 200 OK",
        [("Via", f"SIP/2.0/UDP {b2bua}:5060;branch={branch('leg-a-reinvite')};rport"),
         ("From", a_to_final), ("To", a_from), ("Call-ID", B2BUA_LEG_A_ID),
         ("CSeq", "102 INVITE"), a_contact, ("User-Agent", UA_PHONE),
         ("Content-Type", "application/sdp")],
        offer_sdp(caller, 8000, 4000004),
    ))
    add(19.135614, b2bua, caller, 5060, caller_port, sip_message(
        f"ACK sip:alice@{caller}:{caller_port} SIP/2.0",
        [("Via", f"SIP/2.0/UDP {b2bua}:5060;branch={branch('leg-a-reack')};rport"),
         ("From", a_to_final), ("To", a_from), ("Call-ID", B2BUA_LEG_A_ID),
         ("CSeq", "102 ACK"), ("Max-Forwards", "70")],
    ))
    add(26.727966, caller, b2bua, caller_port, 5060, sip_message(
        f"BYE sip:{B2BUA_EXTENSION}@{b2bua}:5060 SIP/2.0",
        leg_a("leg-a-bye", a_to_final, 3, "BYE") + [("Max-Forwards", "70")],
    ))
    add(26.728901, b2bua, caller, 5060, caller_port, sip_message(
        "SIP/2.0 200 OK", leg_a("leg-a-bye", a_to_final, 3, "BYE") + [("Server", UA_SWITCH)],
    ))

    # -- dialog 7: the B2BUA's leg (15 messages) ----------------------
    b_from = f"<sip:alice@{DOMAIN}>;tag=tag-leg-b"
    b_to = f"<sip:bob@{DOMAIN}>"
    b_to_tagged = f"{b_to};tag=tag-leg-b-ok"
    b_contact = ("Contact", f"<sip:alice@{b2bua}:5060>")

    def leg_b(via_label, to, cseq, method):
        return [
            ("Via", f"SIP/2.0/UDP {b2bua}:5060;branch={branch(via_label)};rport"),
            ("From", b_from),
            ("To", to),
            ("Call-ID", B2BUA_CALL_ID),
            ("CSeq", f"{cseq} {method}"),
        ]

    def leg_b_invite(via_label, to, cseq, addr, port, session):
        return sip_message(
            f"INVITE sip:bob@{callee}:{callee_port} SIP/2.0",
            leg_b(via_label, to, cseq, "INVITE")
            + [("Max-Forwards", "70"), b_contact, ("Server", UA_SWITCH),
               ("Content-Type", "application/sdp")],
            offer_sdp(addr, port, session),
        )

    def leg_b_ok(via_label, cseq, session):
        return sip_message(
            "SIP/2.0 200 OK",
            leg_b(via_label, b_to_tagged, cseq, "INVITE")
            + [("Contact", f"<sip:bob@{callee}:{callee_port}>"),
               ("User-Agent", UA_PHONE), ("Content-Type", "application/sdp")],
            answer_sdp(callee, 8000, session),
        )

    add(12.042406, b2bua, callee, 5060, callee_port,
        leg_b_invite("leg-b-1", b_to, 102, b2bua, 18010, 5000001))
    add(12.541975, b2bua, callee, 5060, callee_port,
        leg_b_invite("leg-b-1", b_to, 102, b2bua, 18010, 5000001))
    add(12.678198, callee, b2bua, callee_port, 5060, sip_message(
        "SIP/2.0 100 Trying", leg_b("leg-b-1", b_to, 102, "INVITE")))
    add(12.678482, callee, b2bua, callee_port, 5060, sip_message(
        "SIP/2.0 100 Trying", leg_b("leg-b-1", b_to, 102, "INVITE")))
    add(12.783121, callee, b2bua, callee_port, 5060, sip_message(
        "SIP/2.0 180 Ringing",
        leg_b("leg-b-1", b_to_tagged, 102, "INVITE")
        + [("Contact", f"<sip:bob@{callee}:{callee_port}>")],
    ))
    add(19.100771, callee, b2bua, callee_port, 5060, leg_b_ok("leg-b-1", 102, 5000002))
    add(19.102133, b2bua, callee, 5060, callee_port, sip_message(
        f"ACK sip:bob@{callee}:{callee_port} SIP/2.0",
        leg_b("leg-b-ack1", b_to_tagged, 102, "ACK") + [("Max-Forwards", "70")],
    ))
    add(19.105639, b2bua, callee, 5060, callee_port,
        leg_b_invite("leg-b-2", b_to_tagged, 103, caller, 8000, 5000003))
    add(19.292218, callee, b2bua, callee_port, 5060, leg_b_ok("leg-b-2", 103, 5000004))
    add(19.293498, b2bua, callee, 5060, callee_port, sip_message(
        f"ACK sip:bob@{callee}:{callee_port} SIP/2.0",
        leg_b("leg-b-ack2", b_to_tagged, 103, "ACK") + [("Max-Forwards", "70")],
    ))
    add(26.729044, b2bua, callee, 5060, callee_port,
        leg_b_invite("leg-b-3", b_to_tagged, 104, b2bua, 18010, 5000005))
    add(26.9684, callee, b2bua, callee_port, 5060, leg_b_ok("leg-b-3", 104, 5000006))
    add(26.968725, b2bua, callee, 5060, callee_port, sip_message(
        f"ACK sip:bob@{callee}:{callee_port} SIP/2.0",
        leg_b("leg-b-ack3", b_to_tagged, 104, "ACK") + [("Max-Forwards", "70")],
    ))
    add(26.968815, b2bua, callee, 5060, callee_port, sip_message(
        f"BYE sip:bob@{callee}:{callee_port} SIP/2.0",
        leg_b("leg-b-bye", b_to_tagged, 105, "BYE") + [("Max-Forwards", "70")],
    ))
    add(26.974147, callee, b2bua, callee_port, 5060, sip_message(
        "SIP/2.0 200 OK",
        leg_b("leg-b-bye", b_to_tagged, 105, "BYE") + [("User-Agent", UA_PHONE)],
    ))

    # -- dialogs 8-12: more declined presence traffic -----------------
    peer_exchange(13.197562, 13.223478, "SUBSCRIBE", "b2bua-sub-3-synth@203.0.113.1",
                  "alice", "tag-sub-3", 1, "sub-3", 480, "Temporarily Unavailable",
                  caller, caller_port, presence, event="presence")
    for base, idx in ((19.473847, 4), (27.181702, 6)):
        pub = simple("PUBLISH", f"b2bua-pub-{idx}-synth@203.0.113.145", "bob",
                     f"tag-pub-{idx}", 1, f"pub-{idx}", "presence")
        sub = simple("SUBSCRIBE", f"b2bua-sub-{idx + 1}-synth@203.0.113.145", "bob",
                     f"tag-sub-{idx + 1}", 1, f"sub-{idx + 1}", "message-summary")
        add(base, callee, b2bua, callee_port, 5060,
            render(pub, f"PUBLISH sip:bob@{DOMAIN} SIP/2.0", via_b))
        add(base + 0.000545, callee, b2bua, callee_port, 5060,
            render(sub, f"SUBSCRIBE sip:bob@{DOMAIN} SIP/2.0", via_b))
        resp_headers, start = answer_of(pub, 489, "Bad Event", f"tag-peer-pub-{idx}")
        add(base + 0.001944, b2bua, callee, 5060, callee_port,
            render(resp_headers, start, via_b))
        resp_headers, start = answer_of(sub, 401, "Unauthorized", f"tag-peer-sub-{idx + 1}")
        add(base + 0.002218, b2bua, callee, 5060, callee_port,
            render(resp_headers, start, via_b))
        subb = simple("SUBSCRIBE", f"b2bua-sub-{idx + 1}-synth@203.0.113.145", "bob",
                      f"tag-sub-{idx + 1}", 2, f"sub-{idx + 1}b", "message-summary")
        add(base + 0.030886, callee, b2bua, callee_port, 5060,
            render(subb, f"SUBSCRIBE sip:bob@{DOMAIN} SIP/2.0", via_b))
        resp_headers, start = answer_of(subb, 489, "Bad Event", f"tag-peer-sub-{idx + 1}b")
        add(base + 0.031434, b2bua, callee, 5060, callee_port,
            render(resp_headers, start, via_b))

    # -- the media: 355 packets one way, one packet the other ---------
    # The single reverse packet is what a phone emits before it settles on
    # the far end's address; it is attributed to the caller's leg, and the
    # 355-packet flow to the B2BUA's. One stream per leg is what the lint
    # tool's `rtp_streams_observed == 1` reads.
    packets.append((
        B2BUA_EPOCH + 19.256641,
        udp_frame(caller, callee, 8000, 8000,
                  rtp_packet(0, 500, 0, 0x0C33_0002), 0x9F00),
    ))
    packets += _rtp_stream(
        B2BUA_EPOCH + 19.588654, callee, caller, 8000, 8000,
        payload_type=0, ssrc=0x0C33_0001, count=355, ident=0xA000,
    )
    packets.sort(key=lambda p: p[0])
    write_pcapng(path, packets)


# ── sipp-branch-scenario.pcapng ─────────────────────────────────────

#: First packet of the load run. The MCP suite queries the window
#: 21:52:35Z..21:53:00Z and asserts exactly 247 dialogs start inside it, so
#: this epoch and `SIPP_DIALOG_SPACING` below decide that number together.
SIPP_EPOCH = 1479419555.303349
#: Seconds between successive dialog starts. At 0.1 s the 248th dialog starts
#: at +24.7 s, which is past 21:53:00Z -- so exactly 247 fall in the window.
SIPP_DIALOG_SPACING = 0.1
#: Seconds between messages inside one dialog. Small enough that a nine-message
#: dialog finishes well inside its 0.1 s slot, and that post-dial delay stays
#: far below the 32 s the `problems` alias thresholds on.
SIPP_MESSAGE_SPACING = 0.006

#: The twelve message sequences the run produces, with how many dialogs take
#: each. Reproduced exactly, because the suite asserts the resulting
#: (state, msg_count, final_status) histogram in several places at once:
#: 1334 dialogs, 127 of them Failed, 6 of those Failed with more than five
#: messages, and 8989 packets in total.
#:
#: A dialog is Failed when its INVITE ends on the 403 with no 200 to a BYE
#: after it -- so the two sequences that stop at the 403, or at an
#: unanswered BYE, are the Failed ones and every other sequence is
#: Registered. Failed and Registered therefore partition the capture, which
#: is what lets the filter tests assert that two selections sum to the whole.
SIPP_PATTERNS = [
    ("registered", 1021, ["REGISTER", "200", "INVITE", "180", "403", "BYE", "200"]),
    ("failed", 121, ["REGISTER", "200", "INVITE", "180", "403"]),
    ("registered", 96,
     ["REGISTER", "200", "INVITE", "180", "100", "200", "ACK", "BYE", "200"]),
    ("registered", 71, ["REGISTER", "200", "INVITE"]),
    ("failed", 6, ["REGISTER", "200", "INVITE", "180", "403", "BYE"]),
    ("registered", 5, ["REGISTER", "200", "INVITE", "180", "100", "200", "ACK"]),
    ("registered", 4, ["REGISTER", "200", "INVITE", "180", "100", "BYE", "200"]),
    ("registered", 4, ["REGISTER", "200", "INVITE", "BYE", "200"]),
    ("registered", 3,
     ["REGISTER", "200", "INVITE", "180", "100", "ACK", "BYE", "200"]),
    ("registered", 1, ["REGISTER", "200", "INVITE", "180", "100"]),
    ("registered", 1, ["REGISTER", "200", "INVITE", "180", "100", "200"]),
    ("registered", 1, ["REGISTER", "200", "INVITE", "180", "BYE", "200"]),
]

#: Dialogs that start inside the queried window. Sixteen of them must fail.
SIPP_WINDOW_DIALOGS = 247
SIPP_FAILED_IN_WINDOW = 16


def _sipp_assignment():
    """Which message sequence each of the 1334 dialogs runs, in order.

    The failing dialogs are placed by an explicit arithmetic rule rather than
    by shuffling: sixteen inside the queried window and the remaining 111
    after it, which is what makes `search_by_time` plus a state filter return
    16 of 247 rather than a number that drifts whenever this file is touched.
    """
    failed_seqs = [seq for kind, count, seq in SIPP_PATTERNS if kind == "failed"
                   for _ in range(count)]
    registered_seqs = [seq for kind, count, seq in SIPP_PATTERNS if kind == "registered"
                       for _ in range(count)]
    total = len(failed_seqs) + len(registered_seqs)

    failed_slots = [15 * k + 9 for k in range(SIPP_FAILED_IN_WINDOW)]
    assert max(failed_slots) < SIPP_WINDOW_DIALOGS, "a failure escaped the window"
    remaining = len(failed_seqs) - SIPP_FAILED_IN_WINDOW
    failed_slots += [SIPP_WINDOW_DIALOGS + 4 + 9 * k for k in range(remaining)]
    assert max(failed_slots) < total, "a failure slot ran past the last dialog"
    failed_slots = set(failed_slots)

    # Spread the rare sequences through the run instead of leaving them
    # clumped at the end: a capture whose only nine-message dialogs sit in the
    # last hundred rows would let a pagination bug pass on every early page.
    stride = 617  # coprime with 1207, so this is a permutation
    spread = [None] * len(registered_seqs)
    for j, seq in enumerate(registered_seqs):
        spread[(j * stride) % len(registered_seqs)] = seq

    out, next_failed, next_registered = [], 0, 0
    for i in range(total):
        if i in failed_slots:
            out.append(failed_seqs[next_failed])
            next_failed += 1
        else:
            out.append(spread[next_registered])
            next_registered += 1
    return out


def build_sipp_branch_scenario(path: str) -> None:
    """A load generator's run: 1334 register-then-call dialogs, no media.

    Load-bearing properties, all asserted:
    * 1334 dialogs and 8989 packets;
    * every dialog is either Registered or Failed, so the two filters
      partition the capture and an inert filter cannot pass;
    * 127 Failed dialogs, six of them with more than five messages;
    * 247 dialogs start in the window 21:52:35Z..21:53:00Z, sixteen of which
      failed -- the numbers that prove `search_by_time` narrows and that a
      filter passed alongside it narrows further;
    * one Call-ID per dialog but a fresh top-Via branch per transaction, so
      `--dialog-track branch` reports strictly more units than `call-id`.
      That disagreement is the only proof the flag is wired to anything;
    * NO RTP at all, which is why `find_problems` returns exactly the 127
      failures and nothing else.
    """
    client, server = "192.0.2.10", "192.0.2.20"
    client_port, server_port = 5061, 5060
    packets = []
    ident = 0

    for i, sequence in enumerate(_sipp_assignment()):
        call_id = f"call-{i + 1}-synth@{client}"
        ftag = f"synthtag-a-{i + 1}"
        ttag = f"synthtag-b-{i + 1}"
        start = SIPP_EPOCH + i * SIPP_DIALOG_SPACING
        reg_branch = branch(f"{i + 1}-reg")
        inv_branch = branch(f"{i + 1}-inv")
        bye_branch = branch(f"{i + 1}-bye")
        offer = sdp("ua-a", 1000 + i, 1, client, 6000)

        def head(via_branch, method, cseq, to_tag=None, register=False):
            peer = "<sip:ua-a@example.net>" if register else "<sip:ua-b@example.net>"
            to = peer if to_tag is None else f"{peer};tag={to_tag}"
            return [
                ("Via", f"SIP/2.0/UDP {client}:{client_port};branch={via_branch}"),
                ("From", f"<sip:ua-a@example.net>;tag={ftag}"),
                ("To", to),
                ("Call-ID", call_id),
                ("CSeq", f"{cseq} {method}"),
            ]

        cseq_invite = 2
        for k, step in enumerate(sequence):
            ts = start + k * SIPP_MESSAGE_SPACING
            ident += 1
            if step == "REGISTER":
                payload = sip_message(
                    "REGISTER sip:example.net SIP/2.0",
                    head(reg_branch, "REGISTER", 1, register=True)
                    + [("Contact", f"<sip:ua-a@{client}:{client_port}>"),
                       ("Max-Forwards", "70"), ("Expires", "300"),
                       ("User-Agent", UA_LOAD)],
                )
                out = True
            elif step == "INVITE":
                payload = sip_message(
                    "INVITE sip:ua-b@example.net SIP/2.0",
                    head(inv_branch, "INVITE", cseq_invite)
                    + [("Contact", f"<sip:ua-a@{client}:{client_port}>"),
                       ("Max-Forwards", "70"), ("Content-Type", "application/sdp")],
                    offer,
                )
                out = True
            elif step == "BYE":
                payload = sip_message(
                    f"BYE sip:ua-b@{server}:{server_port} SIP/2.0",
                    head(bye_branch, "BYE", cseq_invite + 1, ttag)
                    + [("Max-Forwards", "70")],
                )
                out = True
            elif step == "ACK":
                payload = sip_message(
                    f"ACK sip:ua-b@{server}:{server_port} SIP/2.0",
                    head(inv_branch, "ACK", cseq_invite, ttag)
                    + [("Max-Forwards", "70")],
                )
                out = True
            else:
                # A response. Which request it answers is decided by what came
                # before it in the sequence, which is what keeps the CSeq
                # method correct without a second table to keep in step.
                prior = sequence[:k]
                if "INVITE" not in prior:
                    via_branch, method, cseq = reg_branch, "REGISTER", 1
                elif "BYE" in prior:
                    via_branch, method, cseq = bye_branch, "BYE", cseq_invite + 1
                else:
                    via_branch, method, cseq = inv_branch, "INVITE", cseq_invite
                reason = {
                    "100": "Trying", "180": "Ringing",
                    "200": "OK", "403": "Forbidden",
                }[step]
                tag = None if step == "100" and method == "INVITE" else ttag
                headers = head(via_branch, method, cseq, tag,
                               register=(method == "REGISTER"))
                headers.append(("Contact", f"<sip:ua-b@{server}:{server_port}>"))
                headers.append(("Server", UA_LOAD))
                if method == "REGISTER":
                    headers.append(("Expires", "300"))
                payload = sip_message(f"SIP/2.0 {step} {reason}", headers)
                out = False

            if out:
                frame = udp_frame(client, server, client_port, server_port, payload, ident)
            else:
                frame = udp_frame(server, client, server_port, client_port, payload, ident)
            packets.append((ts, frame))

    write_pcapng(path, packets)


# ── driver ──────────────────────────────────────────────────────────

#: Every fixture this script owns, as `(repo-relative path, builder)`.
FIXTURES = [
    ("tests/pcap-samples/sip-register.pcap", build_sip_register),
    ("tests/pcap-samples/sip-proxy.pcap", build_sip_proxy),
    ("tests/pcap-samples/sip-sdp-example.pcap", build_sip_sdp_example),
    ("tests/pcap-samples/sip-auth-failure.pcapng", build_sip_auth_failure),
    ("tests/pcap-samples/sip-routing-error.pcapng", build_sip_routing_error),
    ("tests/pcap-samples/sip-488-codec-reject.pcapng", build_sip_488_codec_reject),
    ("tests/pcap-samples/rtp-protocol.pcap", build_rtp_protocol),
    ("tests/pcap-samples/sip-over-tcp.pcap", build_sip_over_tcp),
    ("tests/pcap-samples/b2bua-asterisk.pcapng", build_b2bua_asterisk),
    ("tests/pcap-samples/sipp-branch-scenario.pcapng", build_sipp_branch_scenario),
]

#: Fixtures kept in a second place. The fuzz corpus seed is a copy of the
#: sample, so regenerating one without the other leaves two files with the
#: same name and different bytes.
COPIES = [
    ("tests/pcap-samples/sip-register.pcap", "fuzz/corpus/pcap_reader/sip-register.pcap"),
]


def repo_root() -> str:
    """The repository root, derived from this script's own location."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def generate(root: str) -> None:
    """Write every fixture and every copy under `root`."""
    for rel, builder in FIXTURES:
        builder(os.path.join(root, rel))
    for src, dst in COPIES:
        with open(os.path.join(root, src), "rb") as handle:
            data = handle.read()
        _write(os.path.join(root, dst), data)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="rebuild into a temp tree and report any fixture that differs",
    )
    args = parser.parse_args(argv)
    root = repo_root()

    if not args.check:
        generate(root)
        for rel, _ in FIXTURES:
            path = os.path.join(root, rel)
            print(f"{rel}: {os.path.getsize(path)} bytes")
        for _, dst in COPIES:
            print(f"{dst}: {os.path.getsize(os.path.join(root, dst))} bytes")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        generate(tmp)
        stale = []
        for rel in [r for r, _ in FIXTURES] + [d for _, d in COPIES]:
            here, there = os.path.join(root, rel), os.path.join(tmp, rel)
            if not os.path.exists(here) or not filecmp.cmp(here, there, shallow=False):
                stale.append(rel)
        if stale:
            print("out of date with the generator:", file=sys.stderr)
            for rel in stale:
                print(f"  {rel}", file=sys.stderr)
            return 1
        print(f"{len(FIXTURES) + len(COPIES)} fixtures match the generator")
        return 0


if __name__ == "__main__":
    sys.exit(main())
