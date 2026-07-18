#!/usr/bin/env python3
"""Generate a synthetic SIP pcap for the CLI `--problems` demo.

All RFC 5737 documentation IPs (no PII). One healthy call for contrast, then
four calls that fail in different ways -- so `sipnab --problems` surfaces a
meaningful list (486 Busy Here, 603 Decline, 404 Not Found, 503 Service
Unavailable) while the completed call is correctly filtered out.

Emits Ethernet/IPv4/UDP frames by hand (no scapy). Deterministic: fixed epoch
+ timestamps, so the bytes are stable across runs and the demo is repeatable.

Usage: python3 demos/gen-problem-pcap.py tests/pcap-samples/sip-problem-call.pcap
"""
import struct
import sys

PKTS = []  # (ts_float, src_ip, dst_ip, sport, dport, payload_bytes)
SDP = (
    "v=0\no=- 1 1 IN IP4 {ip}\ns=-\nc=IN IP4 {ip}\nt=0 0\n"
    "m=audio 10000 RTP/AVP 0 8 101\na=rtpmap:0 PCMU/8000\n"
    "a=rtpmap:8 PCMA/8000\na=rtpmap:101 telephone-event/8000\n"
)


def ipv4_checksum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def frame(src_ip, dst_ip, sport, dport, payload):
    eth = bytes([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]) + struct.pack("!H", 0x0800)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0) + src + dst
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]
    return eth + ip + udp


def add(ts, src, dst, msg):
    PKTS.append((ts, src, dst, 5060, 5060, msg.replace("\n", "\r\n").encode()))


def hdrs(caller, callee, cip, dip, cid, cseq, tag_to=""):
    to = f"<sip:{callee}@{dip}>" + (f";tag={tag_to}" if tag_to else "")
    return (
        f"Via: SIP/2.0/UDP {cip}:5060;branch=z9hG4bK-{cid[:6]}\n"
        f"Max-Forwards: 70\nFrom: \"{caller}\" <sip:{caller}@{cip}>;tag={caller[0]}1\n"
        f"To: {to}\nCall-ID: {cid}\nCSeq: {cseq}\n"
    )


def healthy_call(t0, caller, callee, cip, dip, cid):
    body = SDP.format(ip=cip)
    add(t0 + 0.000, cip, dip,
        f"INVITE sip:{callee}@{dip} SIP/2.0\n{hdrs(caller, callee, cip, dip, cid, '1 INVITE')}"
        f"Contact: <sip:{caller}@{cip}:5060>\nContent-Type: application/sdp\n"
        f"Content-Length: {len(body)}\n\n{body}")
    add(t0 + 0.003, dip, cip, f"SIP/2.0 100 Trying\n{hdrs(caller, callee, cip, dip, cid, '1 INVITE')}Content-Length: 0\n\n")
    add(t0 + 0.850, dip, cip, f"SIP/2.0 180 Ringing\n{hdrs(caller, callee, cip, dip, cid, '1 INVITE', tag_to=callee[0]+'2')}Content-Length: 0\n\n")
    okbody = SDP.format(ip=dip)
    add(t0 + 2.100, dip, cip,
        f"SIP/2.0 200 OK\n{hdrs(caller, callee, cip, dip, cid, '1 INVITE', tag_to=callee[0]+'2')}"
        f"Contact: <sip:{callee}@{dip}:5060>\nContent-Type: application/sdp\n"
        f"Content-Length: {len(okbody)}\n\n{okbody}")
    add(t0 + 2.140, cip, dip, f"ACK sip:{callee}@{dip} SIP/2.0\n{hdrs(caller, callee, cip, dip, cid, '1 ACK', tag_to=callee[0]+'2')}Content-Length: 0\n\n")
    add(t0 + 20.00, cip, dip, f"BYE sip:{callee}@{dip} SIP/2.0\n{hdrs(caller, callee, cip, dip, cid, '2 BYE', tag_to=callee[0]+'2')}Content-Length: 0\n\n")
    add(t0 + 20.01, dip, cip, f"SIP/2.0 200 OK\n{hdrs(caller, callee, cip, dip, cid, '2 BYE', tag_to=callee[0]+'2')}Content-Length: 0\n\n")


def failed_call(t0, caller, callee, cip, dip, cid, code, reason):
    body = SDP.format(ip=cip)
    add(t0 + 0.000, cip, dip,
        f"INVITE sip:{callee}@{dip} SIP/2.0\n{hdrs(caller, callee, cip, dip, cid, '1 INVITE')}"
        f"Contact: <sip:{caller}@{cip}:5060>\nContent-Type: application/sdp\n"
        f"Content-Length: {len(body)}\n\n{body}")
    add(t0 + 0.004, dip, cip, f"SIP/2.0 100 Trying\n{hdrs(caller, callee, cip, dip, cid, '1 INVITE')}Content-Length: 0\n\n")
    add(t0 + 1.800, dip, cip, f"SIP/2.0 {code} {reason}\n{hdrs(caller, callee, cip, dip, cid, '1 INVITE', tag_to=callee[0]+'9')}Content-Length: 0\n\n")
    add(t0 + 1.810, cip, dip, f"ACK sip:{callee}@{dip} SIP/2.0\n{hdrs(caller, callee, cip, dip, cid, '1 ACK', tag_to=callee[0]+'9')}Content-Length: 0\n\n")


# Chronological mix: healthy call runs long; failures interleave during it.
healthy_call(0.0, "alice", "bob", "192.0.2.10", "192.0.2.20", "completed-9f8e7d@192.0.2.10")
failed_call(3.0, "carol", "dave", "192.0.2.30", "192.0.2.40", "busy-3a2b1c@192.0.2.30", 486, "Busy Here")
failed_call(6.0, "erin", "frank", "198.51.100.30", "198.51.100.40", "decline-7c6d5e@198.51.100.30", 603, "Decline")
failed_call(9.0, "grace", "heidi", "203.0.113.30", "203.0.113.40", "notfound-1b2c3d@203.0.113.30", 404, "Not Found")
failed_call(12.0, "ivan", "judy", "192.0.2.50", "192.0.2.60", "unavail-4e5f60@192.0.2.50", 503, "Service Unavailable")


def main(path):
    PKTS.sort(key=lambda p: p[0])
    out = bytearray(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    base = 1_700_000_000
    for ts, s, d, sp, dp, msg in PKTS:
        pkt = frame(s, d, sp, dp, msg)
        out += struct.pack("!IIII", base + int(ts), int(round((ts % 1) * 1_000_000)), len(pkt), len(pkt))
        out += pkt
    with open(path, "wb") as f:
        f.write(out)
    print(f"wrote {path}: {len(PKTS)} packets, {len(out)} bytes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sip-problem-call.pcap")
