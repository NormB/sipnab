#!/usr/bin/env python3
"""Generate the link-type capture fixtures under `tests/pcap-samples/`.

Three fixtures, one per link-layer framing that had decoder code but no
capture file to prove it end to end:

* `loopback-dlt-loop.pcap` -- DLT_LOOP (108), OpenBSD loopback encapsulation.
  The implementation existed and was covered only by frames synthesized inside
  a unit test, so nothing exercised the reader, the pipeline and the report
  against a real file. DLT_LOOP's address-family word is ALWAYS big-endian --
  that single difference is the entire reason it exists alongside DLT_NULL
  (0), whose word is in the writing host's order -- so this file writes
  `00 00 00 02` inside a little-endian pcap container, where the two readings
  cannot be confused.
* `linux-sll-pppoe.pcap` -- DLT_LINUX_SLL (113) carrying PPPoE Session.
* `linux-sll2-pppoe.pcap` -- DLT_LINUX_SLL2 (276) carrying PPPoE Session.
  Both are what `tcpdump -i any` writes on a BNG/BRAS, where the access
  encapsulation is PPPoE: a cooked header, then RFC 2516's PPPoE header, then
  the PPP Protocol field, then IP. sipnab decoded PPPoE behind Ethernet and
  skipped a flat header length on the cooked link types, so this exact shape
  -- the one the operator scenario produces -- reached the IP slicer at the
  PPPoE header and was counted as undecodable.

Every byte here is fabricated. Addresses are RFC 5737 documentation ranges or
loopback, SIP URI hosts are `example.com` labels, MAC / link-layer addresses
come from the RFC 7042 §2.1.2 documentation block (00:00:5E:00:53:xx), and no
digit run that could read as an E.164 number appears anywhere. The fixtures
are checked by `tests/pcap_samples_are_synthetic_test.rs` on those properties,
on the bytes rather than on this file's intent.

Deterministic: fixed epochs, fixed identifiers, no randomness, no clock reads.
Running it twice produces byte-identical files, so a regeneration shows up as
an empty diff.

Usage:
    python3 tests/gen-link-type-samples.py            # write every fixture
    python3 tests/gen-link-type-samples.py --check    # rebuild into a temp
                                                      # dir and diff
"""

from __future__ import annotations

import argparse
import filecmp
import os
import struct
import sys
import tempfile

# ── link types ──────────────────────────────────────────────────────

#: libpcap LINKTYPE_LOOP: OpenBSD loopback encapsulation. A 4-byte address
#: family in NETWORK byte order, then the IP header.
LINKTYPE_LOOP = 108

#: libpcap LINKTYPE_LINUX_SLL: packet type (2), ARPHRD_ type (2), address
#: length (2), address (8), protocol type (2, AT OFFSET 14), payload at 16.
LINKTYPE_LINUX_SLL = 113

#: libpcap LINKTYPE_LINUX_SLL2: protocol type (2, AT OFFSET 0), reserved (2),
#: interface index (4), ARPHRD_ type (2), packet type (1), address length (1),
#: address (8), payload at 20. The protocol field moved to the front; the two
#: layouts are not the same header with a different length.
LINKTYPE_LINUX_SLL2 = 276

#: AF_INET. Written big-endian for DLT_LOOP, which is the whole point.
AF_INET = 2

#: ARPHRD_ETHER -- the ARPHRD_ type that makes a cooked frame's protocol field
#: an Ethernet protocol type at all (libpcap's LINKTYPE_LINUX_SLL page makes
#: the field mean something else for ARPHRD_NETLINK, IPGRE, IP6GRE, RADIOTAP
#: and FRAD).
ARPHRD_ETHER = 1

#: EtherType for the PPPoE Session stage (RFC 2516 §6).
ETHERTYPE_PPPOE_SESSION = 0x8864

#: PPP Protocol number for IPv4 (RFC 1661 registry -- NOT the 0x0800
#: EtherType).
PPP_PROTO_IPV4 = 0x0021

#: RFC 7042 §2.1.2 documentation MAC block, used for the cooked frames'
#: link-layer address field.
SLL_ADDRESS = bytes([0x00, 0x00, 0x5E, 0x00, 0x53, 0x01, 0x00, 0x00])


def write_pcap(path: str, packets, linktype: int) -> None:
    """Write `packets` as a classic little-endian pcap file.

    `packets` is an iterable of `(epoch_seconds_float, frame_bytes)`.
    Microsecond resolution, which is what the 0xA1B2C3D4 magic declares. The
    container's little-endianness is load-bearing for the DLT_LOOP fixture:
    the address family inside it is big-endian regardless, which is what makes
    that file a test of the link type's rule rather than of the host's.
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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(bytes(out))


# ── framing ─────────────────────────────────────────────────────────


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


def ipv4_udp(src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int) -> bytes:
    """One IPv4/UDP datagram, no link header.

    The UDP checksum is left zero, which RFC 768 permits over IPv4; the IPv4
    header checksum is computed, because a reader that validates it would
    otherwise reject every frame in these files.
    """
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        ident & 0xFFFF,
        0x4000,
        64,
        17,
        0,
        _ip_bytes(src),
        _ip_bytes(dst),
    )
    header = header[:10] + struct.pack(">H", _checksum(header)) + header[12:]
    return header + udp


def dlt_loop(datagram: bytes) -> bytes:
    """Wrap an IP datagram in an OpenBSD loopback (DLT_LOOP) header.

    The 4-byte address family is written in NETWORK byte order -- `>I`, never
    `<I`. libpcap's LINKTYPE_LOOP exists precisely because DLT_NULL's word is
    in the writing host's order, so a decoder that reads this one host-endian
    on a little-endian machine sees family 0x02000000, which is not AF_INET,
    and drops the frame. `tests/link_type_fixtures_test.rs` rewrites this field
    to little-endian and asserts the whole capture then reports nothing, which
    is what proves the fixture exercises the rule instead of passing under
    either reading.
    """
    return struct.pack(">I", AF_INET) + datagram


def pppoe_session(datagram: bytes) -> bytes:
    """Wrap an IP datagram in a PPPoE Session header (RFC 2516 §4 and §6).

    VER = 1, TYPE = 1 (`0x11`), CODE = 0x00 for the session stage, a fixed
    SESSION_ID, and a LENGTH that honestly counts the PPP Protocol field plus
    the payload -- RFC 2516 §4 excludes the Ethernet and PPPoE headers from it.
    """
    body = struct.pack(">H", PPP_PROTO_IPV4) + datagram
    return struct.pack(">BBHH", 0x11, 0x00, 0x18E5, len(body)) + body


def linux_sll(payload: bytes, proto: int) -> bytes:
    """Wrap `payload` in a Linux SLL (cooked capture v1) header.

    Protocol type at offset 14, payload at 16.
    """
    return (
        struct.pack(">HHH", 0, ARPHRD_ETHER, 6)
        + SLL_ADDRESS
        + struct.pack(">H", proto)
        + payload
    )


def linux_sll2(payload: bytes, proto: int) -> bytes:
    """Wrap `payload` in a Linux SLL2 header.

    Protocol type at offset 0, ARPHRD_ type at 8, payload at 20.
    """
    return (
        struct.pack(">HHIHBB", proto, 0, 2, ARPHRD_ETHER, 0, 6)
        + SLL_ADDRESS
        + payload
    )


# ── SIP ─────────────────────────────────────────────────────────────

CRLF = "\r\n"


def sip_message(start_line: str, headers, body: str = "") -> bytes:
    """Assemble a SIP message with a correct `Content-Length`.

    `headers` is a list of `(name, value)` pairs: header ORDER is observable
    in sipnab's output, so it is a list and not a mapping.
    """
    body_bytes = body.encode()
    lines = [start_line]
    lines += [f"{name}: {value}" for name, value in headers]
    lines.append(f"Content-Length: {len(body_bytes)}")
    return (CRLF.join(lines) + CRLF + CRLF).encode() + body_bytes


def sdp(addr: str, port: int, session: int) -> str:
    """An SDP offer/answer for one PCMU stream.

    `addr` is both the origin address and the `c=` line, so the RTP below
    comes from an address a dialog SDP advertised and `nat_mismatch` stays
    false. The session id and version are three digits on purpose: a run of 9
    to 15 digits anywhere in a fixture reads as an E.164 number, and
    `pcap_samples_are_synthetic_test` fails the file for it.
    """
    return CRLF.join(
        [
            "v=0",
            f"o=synth {session} {session} IN IP4 {addr}",
            "s=synthetic session",
            f"c=IN IP4 {addr}",
            "t=0 0",
            f"m=audio {port} RTP/AVP 0",
            "a=rtpmap:0 PCMU/8000",
            "a=sendrecv",
        ]
    ) + CRLF


def rtp_packet(seq: int, timestamp: int, ssrc: int) -> bytes:
    """One PCMU RTP packet carrying digital silence.

    The payload is a constant 0xFF -- PCMU silence -- so the fixture holds no
    recoverable audio, only the cadence the stream statistics are computed
    from.
    """
    header = struct.pack(">BBHII", 0x80, 0, seq & 0xFFFF, timestamp, ssrc)
    return header + b"\xff" * 160


# ── the call every fixture carries ──────────────────────────────────

#: Both cooked-capture fixtures carry the same call between two documentation
#: addresses; the loopback fixture carries it between loopback addresses,
#: which is what a capture on `lo0` actually holds.
CALLER = "192.0.2.10"
CALLEE = "198.51.100.20"
LOOPBACK = "127.0.0.1"

#: One Call-ID per fixture, so a test that reads the wrong file fails loudly
#: instead of asserting against a coincidence.
CALL_IDS = {
    "loop": "synthetic-dlt-loop-call@example.com",
    "sll": "synthetic-linux-sll-call@example.com",
    "sll2": "synthetic-linux-sll2-call@example.com",
}

#: SIP ports. 5060 is the well-known port; the caller's ephemeral port is
#: fixed so the tests can assert it exactly.
CALLER_PORT = 5062
CALLEE_PORT = 5060

#: RTP ports, advertised in the SDP above and used by the media below.
CALLER_RTP = 40000
CALLEE_RTP = 40002

#: RTP packets per direction. Two streams of this many is what the dialog
#: report must show; anything less means frames were dropped between the link
#: decoder and the stream tracker.
RTP_PER_DIRECTION = 10

#: SSRCs, one per direction.
CALLER_SSRC = 0x1111_2222
CALLEE_SSRC = 0x3333_4444


def call_frames(call_id: str, caller: str, callee: str, epoch: float):
    """The seven SIP messages and twenty RTP packets of one complete call.

    INVITE / 100 / 180 / 200 / ACK / BYE / 200, then ten RTP packets in each
    direction between the SDP-advertised ports. A complete call rather than a
    fragment because the end-to-end tests assert a dialog's FINAL state: a
    capture that ends mid-dialog would let a decoder that dropped the BYE
    still look correct.

    Yields `(epoch_seconds, ip_datagram)` -- the link header is added by the
    per-fixture builder, since that is the only thing the three files differ
    in.
    """
    tag_from = "synth-from-tag"
    tag_to = "synth-to-tag"
    via_caller = f"SIP/2.0/UDP {caller}:{CALLER_PORT};branch=z9hG4bK-synth-1"
    frm = f"<sip:alice@example.com>;tag={tag_from}"
    to_plain = "<sip:bob@example.com>"
    to_tagged = f"{to_plain};tag={tag_to}"

    def request(method: str, cseq: int, to: str, body: str = ""):
        headers = [
            ("Via", via_caller),
            ("From", frm),
            ("To", to),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
            ("Max-Forwards", "70"),
            ("Contact", f"<sip:alice@{caller}:{CALLER_PORT}>"),
            ("User-Agent", "SynthPhone/1.0"),
        ]
        if body:
            headers.append(("Content-Type", "application/sdp"))
        return sip_message(f"{method} sip:bob@example.com SIP/2.0", headers, body)

    def response(code: int, reason: str, cseq: int, method: str, to: str, body: str = ""):
        headers = [
            ("Via", via_caller),
            ("From", frm),
            ("To", to),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} {method}"),
            ("Contact", f"<sip:bob@{callee}:{CALLEE_PORT}>"),
            ("User-Agent", "SynthSwitch/1.0"),
        ]
        if body:
            headers.append(("Content-Type", "application/sdp"))
        return sip_message(f"SIP/2.0 {code} {reason}", headers, body)

    offer = sdp(caller, CALLER_RTP, 101)
    answer = sdp(callee, CALLEE_RTP, 202)

    # (offset seconds, from-caller?, payload)
    signaling = [
        (0.000, True, request("INVITE", 1, to_plain, offer)),
        (0.010, False, response(100, "Trying", 1, "INVITE", to_plain)),
        (0.120, False, response(180, "Ringing", 1, "INVITE", to_tagged)),
        (2.400, False, response(200, "OK", 1, "INVITE", to_tagged, answer)),
        (2.430, True, request("ACK", 1, to_tagged)),
        (5.000, True, request("BYE", 2, to_tagged)),
        (5.020, False, response(200, "OK", 2, "BYE", to_tagged)),
    ]

    ident = 1
    for offset, from_caller, payload in signaling:
        src, dst = (caller, callee) if from_caller else (callee, caller)
        sport, dport = (
            (CALLER_PORT, CALLEE_PORT) if from_caller else (CALLEE_PORT, CALLER_PORT)
        )
        yield epoch + offset, ipv4_udp(src, dst, sport, dport, payload, ident)
        ident += 1

    # Media runs between the answer and the BYE, 20 ms apart, so the two
    # streams interleave the way a real call's do.
    for i in range(RTP_PER_DIRECTION):
        offset = 2.500 + i * 0.020
        ts = 160 * i
        yield epoch + offset, ipv4_udp(
            caller, callee, CALLER_RTP, CALLEE_RTP, rtp_packet(i, ts, CALLER_SSRC), ident
        )
        ident += 1
        yield epoch + offset + 0.005, ipv4_udp(
            callee, caller, CALLEE_RTP, CALLER_RTP, rtp_packet(i, ts, CALLEE_SSRC), ident
        )
        ident += 1


# ── fixtures ────────────────────────────────────────────────────────

#: Fixed epochs, one per fixture, all after the samples the multi-input suite
#: orders so that dropping one of these into a directory alongside them cannot
#: change that suite's chronological ordering.
LOOP_EPOCH = 1400000000.100000
SLL_EPOCH = 1400001000.200000
SLL2_EPOCH = 1400002000.300000


def build_loopback_dlt_loop(path: str) -> None:
    """DLT_LOOP (108): a loopback capture of one complete call.

    The implementation had no capture file at all -- only frames built inside
    a unit test -- so nothing proved the reader, the pipeline and the report
    handle the link type together. Loopback addresses on both ends because
    that is what a capture on `lo0` holds, and because it makes the file
    obviously not a recording of anything on a network.
    """
    frames = [
        (ts, dlt_loop(datagram))
        for ts, datagram in call_frames(CALL_IDS["loop"], LOOPBACK, LOOPBACK, LOOP_EPOCH)
    ]
    write_pcap(path, frames, LINKTYPE_LOOP)


def build_linux_sll_pppoe(path: str) -> None:
    """DLT_LINUX_SLL (113) carrying PPPoE Session: `-i any` on a BNG."""
    frames = [
        (ts, linux_sll(pppoe_session(datagram), ETHERTYPE_PPPOE_SESSION))
        for ts, datagram in call_frames(CALL_IDS["sll"], CALLER, CALLEE, SLL_EPOCH)
    ]
    write_pcap(path, frames, LINKTYPE_LINUX_SLL)


def build_linux_sll2_pppoe(path: str) -> None:
    """DLT_LINUX_SLL2 (276) carrying PPPoE Session: the same, newer header."""
    frames = [
        (ts, linux_sll2(pppoe_session(datagram), ETHERTYPE_PPPOE_SESSION))
        for ts, datagram in call_frames(CALL_IDS["sll2"], CALLER, CALLEE, SLL2_EPOCH)
    ]
    write_pcap(path, frames, LINKTYPE_LINUX_SLL2)


#: Every fixture this script owns, as `(relative path, builder)`.
FIXTURES = [
    ("tests/pcap-samples/loopback-dlt-loop.pcap", build_loopback_dlt_loop),
    ("tests/pcap-samples/linux-sll-pppoe.pcap", build_linux_sll_pppoe),
    ("tests/pcap-samples/linux-sll2-pppoe.pcap", build_linux_sll2_pppoe),
]


def repo_root() -> str:
    """The repository root, from this script's own location."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def generate(root: str) -> None:
    """Write every fixture under `root`."""
    for rel, builder in FIXTURES:
        builder(os.path.join(root, rel))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="rebuild into a temporary directory and report any file that "
        "differs from the one in the tree",
    )
    args = parser.parse_args(argv)
    root = repo_root()

    if not args.check:
        generate(root)
        for rel, _ in FIXTURES:
            print(f"wrote {rel}")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        generate(tmp)
        drifted = [
            rel
            for rel, _ in FIXTURES
            if not filecmp.cmp(os.path.join(root, rel), os.path.join(tmp, rel), shallow=False)
        ]
    for rel in drifted:
        print(f"DRIFTED: {rel}", file=sys.stderr)
    if drifted:
        print("run: python3 tests/gen-link-type-samples.py", file=sys.stderr)
        return 1
    print(f"{len(FIXTURES)} fixtures match this generator")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
