#!/usr/bin/env python3
"""Generate the one-click sample capture behind "Try a sample capture".

This is the first capture most visitors ever open in sipnab, from the browser
analyzer's "Load a sample call" button and the homepage's "Try a sample
capture" link. It should therefore show a phone's whole life, not one call:

    REGISTER  alice -> 401 -> REGISTER (authenticated) -> 200   [stays up]
    REGISTER  bob   -> 401 -> REGISTER (authenticated) -> 200
    OPTIONS   -> 200                     (the PBX probing alice)
    INVITE    -> 100 -> 180 -> 200 -> ACK
    RTP       both directions, PCMU, 20 ms packets
    BYE       -> 200
    REGISTER  bob, Expires: 0 -> 200          (bob unregistering)

Two registrations on purpose, and only one of them comes off. Alice is still
bound when the capture ends; bob registers, takes the call, and removes his
binding. A reader sees the two side by side, which is the only way to notice
that sipnab reports BOTH as `Registered` -- there is no `Unregistered` state
(backlog REG1). One registration alone hides that; two make it a question.

The file this replaces held a single INVITE dialog and nothing else, and its
SIP sat on port 5080 -- outside the default `--portrange 5060-5061` -- so
`sipnab -I sample-call.pcap` with no flags reported zero SIP messages and two
orphan RTP streams. A sample capture that shows nothing under default settings
is worse than no sample at all.

All addresses are RFC 5737 documentation IPs, so there is no PII and nothing
resolves to a real host.

Emits Ethernet/IPv4/UDP frames by hand (no scapy). Deterministic: fixed epoch
and timestamps, so the bytes are stable across runs.

Usage: python3 demos/gen-sample-call.py website/static/demos/sample-call.pcap
"""
import struct
import sys

PHONE = "192.0.2.10"   # alice
BOB = "192.0.2.30"     # bob
PBX = "192.0.2.20"
SIP_PORT = 5060
RTP_PHONE, RTP_PBX = 10000, 10002

PKTS = []  # (ts, src, dst, sport, dport, payload)


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


def sip(ts, src, dst, msg):
    PKTS.append((ts, src, dst, SIP_PORT, SIP_PORT, msg.replace("\n", "\r\n").encode()))


def rtp(ts, src, dst, sport, dport, seq, stamp, ssrc):
    hdr = struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, stamp & 0xFFFFFFFF, ssrc)
    PKTS.append((ts, src, dst, sport, dport, hdr + b"\xff" * 160))


# ── REGISTER, challenged then authenticated ─────────────────────────
def registration(t0, user, ip, cid, nonce, expires, cseq_base=1):
    """One challenged-then-authenticated REGISTER exchange.

    `expires=0` makes it an un-REGISTER: RFC 3261 SS10.2.2 removes a binding by
    re-registering it with a zero interval, and both spellings are sent --
    `Expires: 0` and `;expires=0` on the Contact -- because a registrar reads
    the Contact parameter first and real phones send both.
    """
    hdrs = (
        f"Via: SIP/2.0/UDP {ip}:5060;branch=z9hG4bK-reg-{{n}}\n"
        f"Max-Forwards: 70\n"
        f'From: "{user.title()}" <sip:{user}@example.com>;tag=reg-{user}\n'
        f"To: <sip:{user}@example.com>\n"
        f"Call-ID: {cid}\n"
    )
    auth = (
        f'Authorization: Digest username="{user}", realm="example.com", '
        f'nonce="{nonce}", uri="sip:example.com", '
        f'response="6629fae49393a05397450978507c4ef1", algorithm=MD5\n'
    )
    contact = f"<sip:{user}@{ip}:5060>" + (";expires=0" if expires == 0 else "")
    n1, n2 = cseq_base, cseq_base + 1
    sip(t0 + 0.000, ip, PBX,
        f"REGISTER sip:example.com SIP/2.0\n{hdrs.format(n=n1)}CSeq: {n1} REGISTER\n"
        f"Contact: {contact}\nExpires: {expires}\n"
        f"User-Agent: sipnab-demo/1.0\nContent-Length: 0\n\n")
    sip(t0 + 0.004, PBX, ip,
        f"SIP/2.0 401 Unauthorized\n{hdrs.format(n=n1)}CSeq: {n1} REGISTER\n"
        f'WWW-Authenticate: Digest realm="example.com", '
        f'nonce="{nonce}", algorithm=MD5\n'
        f"Content-Length: 0\n\n")
    sip(t0 + 0.011, ip, PBX,
        f"REGISTER sip:example.com SIP/2.0\n{hdrs.format(n=n2)}CSeq: {n2} REGISTER\n"
        f"Contact: {contact}\nExpires: {expires}\n{auth}"
        f"User-Agent: sipnab-demo/1.0\nContent-Length: 0\n\n")
    sip(t0 + 0.017, PBX, ip,
        f"SIP/2.0 200 OK\n{hdrs.format(n=n2)}CSeq: {n2} REGISTER\n"
        f"Contact: <sip:{user}@{ip}:5060>;expires={expires}\nContent-Length: 0\n\n")


# alice registers and STAYS registered for the whole capture.
registration(0.000, "alice", PHONE, "reg-alice-4f2a19@192.0.2.10", "4f2a19c8b3e07d51", 3600)
# bob registers, takes the call, and unregisters at the end.
registration(0.500, "bob", BOB, "reg-bob-7c3d02@192.0.2.30", "7c3d02a19b4e6f88", 3600)

# ── OPTIONS: the PBX probing the phone it just registered ───────────
CID_OPT = "opt-8b7c02@192.0.2.20"
OPT_HDRS = (
    f"Via: SIP/2.0/UDP {PBX}:5060;branch=z9hG4bK-opt-1\n"
    f"Max-Forwards: 70\n"
    f"From: <sip:pbx@example.com>;tag=opt1\n"
    f"To: <sip:alice@example.com>\n"
    f"Call-ID: {CID_OPT}\nCSeq: 1 OPTIONS\n"
)
sip(2.000, PBX, PHONE, f"OPTIONS sip:alice@{PHONE} SIP/2.0\n{OPT_HDRS}Content-Length: 0\n\n")
sip(2.006, PHONE, PBX,
    f"SIP/2.0 200 OK\n{OPT_HDRS}"
    f"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY\n"
    f"Accept: application/sdp\nContent-Length: 0\n\n")

# ── INVITE with media, answered, then hung up ───────────────────────
CID_INV = "call-2c9d47@192.0.2.10"
SDP_OFFER = (
    f"v=0\no=alice 2890844526 2890844526 IN IP4 {PHONE}\ns=-\n"
    f"c=IN IP4 {PHONE}\nt=0 0\nm=audio {RTP_PHONE} RTP/AVP 0 101\n"
    f"a=rtpmap:0 PCMU/8000\na=rtpmap:101 telephone-event/8000\na=sendrecv\n"
)
SDP_ANSWER = (
    f"v=0\no=bob 2890844600 2890844600 IN IP4 {PBX}\ns=-\n"
    f"c=IN IP4 {PBX}\nt=0 0\nm=audio {RTP_PBX} RTP/AVP 0\n"
    f"a=rtpmap:0 PCMU/8000\na=sendrecv\n"
)


def inv_hdrs(cseq, to_tag=""):
    to = "<sip:bob@example.com>" + (f";tag={to_tag}" if to_tag else "")
    return (
        f"Via: SIP/2.0/UDP {PHONE}:5060;branch=z9hG4bK-inv-1\n"
        f"Max-Forwards: 70\n"
        f'From: "Alice" <sip:alice@example.com>;tag=inv1\n'
        f"To: {to}\nCall-ID: {CID_INV}\nCSeq: {cseq}\n"
    )


sip(5.000, PHONE, PBX,
    f"INVITE sip:bob@example.com SIP/2.0\n{inv_hdrs('1 INVITE')}"
    f"Contact: <sip:alice@{PHONE}:5060>\nUser-Agent: sipnab-demo/1.0\n"
    f"Content-Type: application/sdp\nContent-Length: {len(SDP_OFFER)}\n\n{SDP_OFFER}")
sip(5.006, PBX, PHONE, f"SIP/2.0 100 Trying\n{inv_hdrs('1 INVITE')}Content-Length: 0\n\n")
sip(5.180, PBX, PHONE, f"SIP/2.0 180 Ringing\n{inv_hdrs('1 INVITE', 'inv9')}Content-Length: 0\n\n")
sip(7.420, PBX, PHONE,
    f"SIP/2.0 200 OK\n{inv_hdrs('1 INVITE', 'inv9')}"
    f"Contact: <sip:bob@{PBX}:5060>\nContent-Type: application/sdp\n"
    f"Content-Length: {len(SDP_ANSWER)}\n\n{SDP_ANSWER}")
sip(7.430, PHONE, PBX, f"ACK sip:bob@{PBX} SIP/2.0\n{inv_hdrs('1 ACK', 'inv9')}Content-Length: 0\n\n")

# Six seconds of two-way PCMU at 20 ms: 300 packets each way.
SSRC_A, SSRC_B = 0x1A2B3C4D, 0x5E6F7A8B
for i in range(300):
    t = 7.440 + i * 0.020
    rtp(t, PHONE, PBX, RTP_PHONE, RTP_PBX, i, i * 160, SSRC_A)
    rtp(t + 0.004, PBX, PHONE, RTP_PBX, RTP_PHONE, i, i * 160, SSRC_B)

sip(13.460, PHONE, PBX, f"BYE sip:bob@{PBX} SIP/2.0\n{inv_hdrs('2 BYE', 'inv9')}Content-Length: 0\n\n")
sip(13.468, PBX, PHONE, f"SIP/2.0 200 OK\n{inv_hdrs('2 BYE', 'inv9')}Content-Length: 0\n\n")

# ── bob unregisters: the same registration, zero interval ───────────
#
# RFC 3261 SS10.2.2. A registration is a binding with a lifetime, and the way to
# remove one is to re-register it with a zero expiry rather than to send
# anything called UNREGISTER -- there is no such method.
#
# Same Call-ID as bob's original registration, which is what RFC 3261 SS10.2.4
# tells a UA to reuse for refreshes of the same binding. That is also why this
# is worth showing next to alice: both dialogs report `Registered` when the
# capture ends, and only alice still is.
registration(15.000, "bob", BOB, "reg-bob-7c3d02@192.0.2.30", "7c3d02a19b4e6f88", 0,
             cseq_base=3)


def main(path):
    PKTS.sort(key=lambda p: p[0])
    out = bytearray(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    base = 1_700_000_000
    for ts, s, d, sp, dp, payload in PKTS:
        pkt = frame(s, d, sp, dp, payload)
        out += struct.pack("!IIII", base + int(ts), int(round((ts % 1) * 1_000_000)), len(pkt), len(pkt))
        out += pkt
    with open(path, "wb") as f:
        f.write(out)
    print(f"wrote {path}: {len(PKTS)} packets, {len(out)} bytes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample-call.pcap")
