#!/usr/bin/env python3
"""Generate a synthetic SIP pcap that trips real lint rules, for the MCP demo.

Every shipped capture is well-formed — a scan of all 31 samples plus the
checked-in fixtures, one of them carrying 1334 dialogs, produces ZERO lint
findings. That is a good property of the corpus and a problem for a demo: the
homepage claims an agent can be handed findings that cite the RFC section they
come from, and nothing in the tree could show it.

So this builds a capture whose messages are wrong in ways an operator actually
meets, one dialog per defect, each chosen because a real stack emits it:

  * missing `Max-Forwards`      -- SIP-3261-8.1.1.6, common from hand-rolled
                                   test clients and some embedded UAs
  * `Content-Length` that lies  -- SIP-3261-20.14, what a truncating middlebox
                                   leaves behind
  * unbracketed URI with params -- SIP-3261-19.1.1, the parameter that silently
                                   demotes to a header parameter

Three dialogs, FOUR findings: the answered call's `200 OK` also carries no
`Contact`, which trips SIP-3261-12.1.1. That was not designed in and is left
because it is honest -- a UAS that omits Contact answers a call nobody can hang
up cleanly, and a capture that shows two defects on one dialog is closer to
what an operator meets than one defect per dialog ever is.

All addresses come from RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so nothing here resembles a real deployment
and no capture of anyone's traffic is involved.

Deterministic: fixed epoch and fixed timestamps, so the bytes are identical on
every run. That matters because the homepage demo is regenerated and diffed --
a demo that can disagree with the code is worse than no demo.

Usage: python3 demos/gen-lint-pcap.py tests/pcap-samples/sip-lint-findings.pcap
"""

import struct
import sys

PKTS = []  # (ts_float, src_ip, dst_ip, sport, dport, payload_bytes)


def ipv4_checksum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(src_ip, dst_ip, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total, 0, 0x4000, 64, 17, 0,
            bytes(int(o) for o in src_ip.split(".")),
            bytes(int(o) for o in dst_ip.split(".")),
        )
    )
    ck = ipv4_checksum(ip)
    ip[10:12] = struct.pack("!H", ck)
    eth = bytes([0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00])
    return eth + bytes(ip) + udp


def add(ts, src, dst, msg):
    PKTS.append((ts, src, dst, 5060, 5060, msg.replace("\n", "\r\n").encode()))


def missing_max_forwards(t0):
    """SIP-3261-8.1.1: a request with no `Max-Forwards`.

    RFC 3261 §8.1.1 lists it among the headers every request MUST contain. A
    proxy that never decrements it cannot detect a loop, so this is the header
    whose absence turns a routing mistake into a storm.
    """
    cip, dip, cid = "192.0.2.10", "192.0.2.20", "lint-maxfwd@192.0.2.10"
    add(t0, cip, dip,
        f"INVITE sip:bob@{dip} SIP/2.0\n"
        f"Via: SIP/2.0/UDP {cip}:5060;branch=z9hG4bK-maxfwd\n"
        f'From: "alice" <sip:alice@{cip}>;tag=a1\n'
        f"To: <sip:bob@{dip}>\nCall-ID: {cid}\nCSeq: 1 INVITE\n"
        f"Contact: <sip:alice@{cip}:5060>\nContent-Length: 0\n\n")
    add(t0 + 0.05, dip, cip,
        f"SIP/2.0 200 OK\n"
        f"Via: SIP/2.0/UDP {cip}:5060;branch=z9hG4bK-maxfwd\n"
        f'From: "alice" <sip:alice@{cip}>;tag=a1\n'
        f"To: <sip:bob@{dip}>;tag=b1\nCall-ID: {cid}\nCSeq: 1 INVITE\n"
        f"Max-Forwards: 70\nContent-Length: 0\n\n")


def content_length_lies(t0):
    """SIP-3261-20.14: a `Content-Length` larger than the body that follows.

    What a middlebox leaves behind when it truncates. A receiver that trusts
    the header waits for bytes that never arrive, or reads into the next
    message on a stream transport.
    """
    cip, dip, cid = "198.51.100.10", "198.51.100.20", "lint-clen@198.51.100.10"
    body = "v=0\no=- 1 1 IN IP4 198.51.100.10\ns=-\nc=IN IP4 198.51.100.10\nt=0 0\nm=audio 6000 RTP/AVP 0\n"
    add(t0, cip, dip,
        f"INVITE sip:carol@{dip} SIP/2.0\n"
        f"Via: SIP/2.0/UDP {cip}:5060;branch=z9hG4bK-clen\n"
        f"Max-Forwards: 70\n"
        f'From: "dave" <sip:dave@{cip}>;tag=d1\n'
        f"To: <sip:carol@{dip}>\nCall-ID: {cid}\nCSeq: 1 INVITE\n"
        f"Contact: <sip:dave@{cip}:5060>\n"
        f"Content-Type: application/sdp\n"
        # 900 declared against a body of ~110 bytes.
        f"Content-Length: 900\n\n{body}")


def uri_without_brackets(t0):
    """SIP-3261-20: a parameterized URI in a `To` header with no angle brackets.

    RFC 3261 §20 requires the brackets once a URI carries parameters, because
    without them a `;tag=` cannot be told from a URI parameter. Real stacks
    disagree about how to parse it, which is exactly why it is worth flagging.
    """
    cip, dip, cid = "203.0.113.10", "203.0.113.20", "lint-brackets@203.0.113.10"
    add(t0, cip, dip,
        f"INVITE sip:erin@{dip} SIP/2.0\n"
        f"Via: SIP/2.0/UDP {cip}:5060;branch=z9hG4bK-brackets\n"
        f"Max-Forwards: 70\n"
        f'From: "frank" <sip:frank@{cip}>;tag=f1\n'
        f"To: sip:erin@{dip};user=phone\n"
        f"Call-ID: {cid}\nCSeq: 1 INVITE\n"
        f"Contact: <sip:frank@{cip}:5060>\nContent-Length: 0\n\n")


def main(path):
    missing_max_forwards(0.0)
    content_length_lies(1.0)
    uri_without_brackets(2.0)

    PKTS.sort(key=lambda p: p[0])
    out = bytearray(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    base = 1_700_000_000
    for ts, s, d, sp, dp, msg in PKTS:
        pkt = frame(s, d, sp, dp, msg)
        out += struct.pack(
            "!IIII", base + int(ts), int(round((ts % 1) * 1_000_000)), len(pkt), len(pkt)
        )
        out += pkt
    with open(path, "wb") as f:
        f.write(out)
    print(f"wrote {path}: {len(PKTS)} packets, {len(out)} bytes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sip-lint-findings.pcap")
