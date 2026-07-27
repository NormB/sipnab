#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate the synthetic carrier pcap that the published benchmarks measure.

The benchmark pages claim every number is reproducible. That claim was false
for twenty-nine releases: the generator lived in an unpublished internal
harness, so nobody could rebuild the corpus -- not even on the reference host
named in the methodology. This script is that generator, rewritten to the
documented corpus parameters and shipped in the repository.

Corpus shape (defaults reproduce the published 535k-packet corpus):

    5000 calls x (7 SIP + 100 RTP) = 535,000 packets, 93.5% RTP
      35,000 SIP messages   INVITE 100 180 200 ACK BYE 200
     500,000 RTP packets    bidirectional G.711 PCMU, 20 ms, 160-byte payload
         100 unique Call-IDs   (each reused across 50 calls)
         200 RTP streams       (100 bidirectional pairs, reused across calls)

The small Call-ID and RTP-endpoint pools are deliberate: they are what make
grep-class tools report 100 dialogs where sipnab reports 35k messages and 200
streams, and they are why voipmonitor needs `sdp_multiplication=0` to do full
RTP association on this corpus. Keep them if you want comparable numbers.

Packets are emitted in waves of concurrently-active calls and round-robined
within a wave, so host-pair sharding (`--cores N`) sees interleaved traffic
rather than one call at a time. Output is deterministic: same arguments in,
byte-identical pcap out.

Usage:
    python3 bench/carrier.py --calls 5000 --out corpus.pcap
    python3 bench/carrier.py --calls 20000 --out carrier-20k.pcap
"""

import argparse
import struct
import sys

# ---------------------------------------------------------------- constants

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

ETH_P_IP = 0x0800
IPPROTO_UDP = 17

SIP_PORT = 5060
RTP_PORT_BASE = 10000

# G.711 PCMU: 8 kHz, 20 ms packets -> 160 samples, 160 payload bytes.
RTP_PAYLOAD_TYPE = 0
RTP_PAYLOAD_LEN = 160
RTP_TS_STEP = 160

SIP_PER_CALL = 7  # INVITE 100 180 200 ACK BYE 200

# Monotonic pcap clock. Inter-packet timing does not affect offline
# reconstruction throughput, but it does decide what the derived metrics mean:
# with a flat step the corpus reports 0s call durations and nonsense jitter, so
# the media phase spaces each stream's packets a real packet-time apart and
# signalling gets a plausible 1 ms.
BASE_TS_SEC = 1_700_000_000
PTIME_USEC = 20_000  # one G.711 packet-time
SIGNALLING_STEP_USEC = 1_000


# ------------------------------------------------------------ frame builders


def checksum16(data):
    """One's-complement checksum over a 16-bit-aligned buffer."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for (word,) in struct.iter_unpack("!H", data):
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(n):
    """Deterministic locally-administered MAC for host index n."""
    return bytes((0x02, 0x00, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF))


def ipv4(a, b, c, d):
    return bytes((a, b, c, d))


def build_frame_header(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload_len):
    """Ethernet + IPv4 + UDP headers for a fixed-size payload.

    Returned as a prefix to concatenate with the payload. Everything here is
    constant for a given (endpoint pair, payload length), so callers build it
    once per stream instead of once per packet -- that is what keeps 2.14M
    packets generatable in Python in reasonable time.
    """
    udp_len = 8 + payload_len
    ip_total_len = 20 + udp_len

    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5
        0x00,  # DSCP/ECN
        ip_total_len,
        0x0000,  # identification
        0x4000,  # don't fragment
        64,  # TTL
        IPPROTO_UDP,
        0x0000,  # checksum placeholder
        src_ip,
        dst_ip,
    )
    ip = ip[:10] + struct.pack("!H", checksum16(ip)) + ip[12:]

    # UDP checksum 0 = "not computed", which is legal for IPv4 and is what
    # capture-replay corpora normally carry.
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)

    eth = dst_mac + src_mac + struct.pack("!H", ETH_P_IP)
    return eth + ip + udp


# --------------------------------------------------------------- SIP corpus


def sdp_body(host_ip_str, rtp_port):
    return (
        "v=0\r\n"
        f"o=sipnab 8000 8000 IN IP4 {host_ip_str}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {host_ip_str}\r\n"
        "t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=ptime:20\r\n"
        "a=sendrecv\r\n"
    )


def sip_messages(call_id, caller, callee, src_str, dst_str, src_rtp, dst_rtp, branch, tag_a, tag_b):
    """The seven messages of one complete call, as (from_caller, text) pairs."""
    via_a = f"Via: SIP/2.0/UDP {src_str}:5060;branch=z9hG4bK{branch};rport\r\n"
    via_b = f"Via: SIP/2.0/UDP {src_str}:5060;branch=z9hG4bK{branch};rport;received={src_str}\r\n"
    frm = f"From: <sip:{caller}@{src_str}>;tag={tag_a}\r\n"
    to = f"To: <sip:{callee}@{dst_str}>"
    to_tagged = f"{to};tag={tag_b}\r\n"
    cid = f"Call-ID: {call_id}\r\n"
    maxf = "Max-Forwards: 70\r\n"
    contact_a = f"Contact: <sip:{caller}@{src_str}:5060>\r\n"
    contact_b = f"Contact: <sip:{callee}@{dst_str}:5060>\r\n"

    offer = sdp_body(src_str, src_rtp)
    answer = sdp_body(dst_str, dst_rtp)

    invite = (
        f"INVITE sip:{callee}@{dst_str} SIP/2.0\r\n"
        f"{via_a}{maxf}{frm}{to}\r\n{cid}"
        "CSeq: 1 INVITE\r\n"
        f"{contact_a}"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(offer)}\r\n\r\n{offer}"
    )
    trying = (
        f"SIP/2.0 100 Trying\r\n{via_b}{frm}{to}\r\n{cid}"
        "CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
    )
    ringing = (
        f"SIP/2.0 180 Ringing\r\n{via_b}{frm}{to_tagged}{cid}"
        f"CSeq: 1 INVITE\r\n{contact_b}Content-Length: 0\r\n\r\n"
    )
    ok_invite = (
        f"SIP/2.0 200 OK\r\n{via_b}{frm}{to_tagged}{cid}"
        f"CSeq: 1 INVITE\r\n{contact_b}"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(answer)}\r\n\r\n{answer}"
    )
    ack = (
        f"ACK sip:{callee}@{dst_str} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {src_str}:5060;branch=z9hG4bK{branch}ack\r\n"
        f"{maxf}{frm}{to_tagged}{cid}CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
    )
    bye = (
        f"BYE sip:{callee}@{dst_str} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {src_str}:5060;branch=z9hG4bK{branch}bye\r\n"
        f"{maxf}{frm}{to_tagged}{cid}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
    )
    ok_bye = (
        f"SIP/2.0 200 OK\r\n"
        f"Via: SIP/2.0/UDP {src_str}:5060;branch=z9hG4bK{branch}bye;received={src_str}\r\n"
        f"{frm}{to_tagged}{cid}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
    )

    # True  = caller -> callee, False = callee -> caller
    return [
        (True, invite),
        (False, trying),
        (False, ringing),
        (False, ok_invite),
        (True, ack),
        (True, bye),
        (False, ok_bye),
    ]


# ------------------------------------------------------------------ writer


class PcapWriter:
    def __init__(self, path):
        self.fh = open(path, "wb", buffering=1 << 20)
        self.fh.write(
            struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
        )
        self.n = 0
        self._usec = 0
        self.step = SIGNALLING_STEP_USEC

    def write(self, frame):
        # Little-endian pcap: record header is host-order per the magic above.
        sec = BASE_TS_SEC + self._usec // 1_000_000
        usec = self._usec % 1_000_000
        self._usec += self.step
        ln = len(frame)
        self.fh.write(struct.pack("<IIII", sec, usec, ln, ln))
        self.fh.write(frame)
        self.n += 1

    def close(self):
        self.fh.close()


# ------------------------------------------------------------------- corpus


def generate(out_path, calls, rtp_per_call, call_id_pool, stream_pairs, concurrency, quiet):
    if rtp_per_call % 2:
        raise SystemExit("--rtp-per-call must be even (traffic is bidirectional)")

    # Pool size 0 means "one per call". The bounded pools give the fixed-state
    # corpus the tool comparison uses; unbounded pools make dialog and stream
    # state grow with call volume, which is what a memory sweep must measure.
    # Getting this wrong measures buffer memory and calls it state growth.
    if call_id_pool <= 0:
        call_id_pool = calls
    if stream_pairs <= 0:
        stream_pairs = calls

    writer = PcapWriter(out_path)

    # Endpoint pools. Host-pair diversity drives `--cores N` sharding, so the
    # pair index is derived from the stream pair, not from the call index.
    def endpoints(pair):
        a_ip = ipv4(10, 1, (pair >> 8) & 0xFF, pair & 0xFF)
        b_ip = ipv4(10, 2, (pair >> 8) & 0xFF, pair & 0xFF)
        a_str = f"10.1.{(pair >> 8) & 0xFF}.{pair & 0xFF}"
        b_str = f"10.2.{(pair >> 8) & 0xFF}.{pair & 0xFF}"
        return a_ip, b_ip, a_str, b_str

    # Precompute per-pair headers once. Everything downstream is byte-copies.
    pair_cache = {}
    for pair in range(stream_pairs):
        a_ip, b_ip, a_str, b_str = endpoints(pair)
        a_mac, b_mac = mac(pair), mac(pair + (1 << 20))
        a_rtp = RTP_PORT_BASE + 2 * pair
        b_rtp = RTP_PORT_BASE + 2 * pair + 1
        pair_cache[pair] = {
            "a_str": a_str,
            "b_str": b_str,
            "a_rtp": a_rtp,
            "b_rtp": b_rtp,
            # SIP frames vary in length, so only the RTP prefixes can be cached.
            "rtp_ab": build_frame_header(a_mac, b_mac, a_ip, b_ip, a_rtp, b_rtp, 12 + RTP_PAYLOAD_LEN),
            "rtp_ba": build_frame_header(b_mac, a_mac, b_ip, a_ip, b_rtp, a_rtp, 12 + RTP_PAYLOAD_LEN),
            "sip_ab": (a_mac, b_mac, a_ip, b_ip),
            "sip_ba": (b_mac, a_mac, b_ip, a_ip),
        }

    call_ids = [f"call-{i:04d}@sipnab.bench" for i in range(call_id_pool)]
    rtp_body = bytes(RTP_PAYLOAD_LEN)  # silence; payload content is irrelevant to parsing

    rtp_each_way = rtp_per_call // 2
    sip_msgs = 0
    rtp_pkts = 0

    for wave_start in range(0, calls, concurrency):
        wave = range(wave_start, min(wave_start + concurrency, calls))

        # Per-call state for this wave.
        state = []
        for c in wave:
            pair = c % stream_pairs
            p = pair_cache[pair]
            msgs = sip_messages(
                call_ids[c % call_id_pool],
                f"caller{c}",
                f"callee{c}",
                p["a_str"],
                p["b_str"],
                p["a_rtp"],
                p["b_rtp"],
                f"{c:08x}",
                f"tagA{c:x}",
                f"tagB{c:x}",
            )
            state.append((c, pair, p, msgs))

        # Setup: INVITE / 100 / 180 / 200 / ACK, interleaved across the wave.
        writer.step = SIGNALLING_STEP_USEC
        for idx in range(5):
            for _c, _pair, p, msgs in state:
                from_a, text = msgs[idx]
                s_mac, d_mac, s_ip, d_ip = p["sip_ab"] if from_a else p["sip_ba"]
                sport, dport = SIP_PORT, SIP_PORT
                body = text.encode()
                writer.write(
                    build_frame_header(s_mac, d_mac, s_ip, d_ip, sport, dport, len(body)) + body
                )
                sip_msgs += 1

        # Media: round-robin both directions across every active call. One pass
        # of the inner loop is one packet-time for every active stream, so the
        # clock step is a packet-time divided by the packets emitted per pass.
        # That makes each individual stream come out at a true 20 ms cadence.
        writer.step = max(1, PTIME_USEC // (2 * len(state)))
        for seq in range(rtp_each_way):
            ts = (seq * RTP_TS_STEP) & 0xFFFFFFFF
            for c, pair, p, _msgs in state:
                ssrc_a = 0x1000_0000 + 2 * pair
                ssrc_b = 0x1000_0000 + 2 * pair + 1
                hdr_a = struct.pack("!BBHII", 0x80, RTP_PAYLOAD_TYPE, seq & 0xFFFF, ts, ssrc_a)
                hdr_b = struct.pack("!BBHII", 0x80, RTP_PAYLOAD_TYPE, seq & 0xFFFF, ts, ssrc_b)
                writer.write(p["rtp_ab"] + hdr_a + rtp_body)
                writer.write(p["rtp_ba"] + hdr_b + rtp_body)
                rtp_pkts += 2

        # Teardown: BYE / 200.
        writer.step = SIGNALLING_STEP_USEC
        for idx in (5, 6):
            for _c, _pair, p, msgs in state:
                from_a, text = msgs[idx]
                s_mac, d_mac, s_ip, d_ip = p["sip_ab"] if from_a else p["sip_ba"]
                body = text.encode()
                writer.write(
                    build_frame_header(s_mac, d_mac, s_ip, d_ip, SIP_PORT, SIP_PORT, len(body)) + body
                )
                sip_msgs += 1

        if not quiet:
            done = min(wave_start + concurrency, calls)
            print(f"\r  {done}/{calls} calls, {writer.n} packets", end="", file=sys.stderr)

    total = writer.n
    writer.close()

    if not quiet:
        print(file=sys.stderr)
    print(
        f"{out_path}: {total} packets "
        f"({sip_msgs} SIP, {rtp_pkts} RTP = {100.0 * rtp_pkts / total:.1f}%), "
        f"{calls} calls, {min(call_id_pool, calls)} unique Call-IDs, "
        f"{2 * min(stream_pairs, calls)} RTP streams"
    )


def main():
    ap = argparse.ArgumentParser(
        description="Generate the synthetic carrier pcap used by the sipnab benchmarks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--out", default="corpus.pcap", help="output pcap path")
    ap.add_argument("--calls", type=int, default=5000, help="number of complete calls")
    ap.add_argument(
        "--rtp-per-call", type=int, default=100, help="RTP packets per call, both directions"
    )
    ap.add_argument(
        "--call-ids",
        type=int,
        default=100,
        help="size of the Call-ID pool; 0 means a unique Call-ID per call",
    )
    ap.add_argument(
        "--stream-pairs",
        type=int,
        default=100,
        help="bidirectional RTP pairs (streams = 2x this); 0 means a unique pair per call",
    )
    ap.add_argument(
        "--concurrency", type=int, default=100, help="calls active simultaneously in a wave"
    )
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    args = ap.parse_args()

    generate(
        args.out,
        args.calls,
        args.rtp_per_call,
        args.call_ids,
        args.stream_pairs,
        args.concurrency,
        args.quiet,
    )


if __name__ == "__main__":
    main()
