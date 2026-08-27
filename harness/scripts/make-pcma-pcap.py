#!/usr/bin/env python3
"""Generate a PCMA RTP pcap for SIPp's play_pcap_audio.

The harness ships one audio pcap and both ends replay it, SSRC and all. That
makes the caller's and callee's media byte-identical, so a stereo export of the
two directions produces two identical channels and nothing in the result can
show that the far end was heard at all. A second file with a different tone and
a different SSRC is what makes the two legs distinguishable.
"""

import argparse
import math
import struct


def alaw_encode(sample: int) -> int:
    """16-bit linear PCM to A-law, per G.711."""
    sign = 0x80 if sample >= 0 else 0x00
    if sample < 0:
        sample = -sample
    sample = min(sample, 32635)
    if sample >= 256:
        exponent = int(math.log2(sample >> 8)) + 1
        mantissa = (sample >> (exponent + 3)) & 0x0F
        value = (exponent << 4) | mantissa
    else:
        value = sample >> 4
    return (value ^ 0x55 ^ sign) & 0xFF


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    ap.add_argument("--hz", type=float, default=660.0, help="tone frequency")
    ap.add_argument("--seconds", type=float, default=8.0)
    ap.add_argument("--ssrc", type=lambda s: int(s, 0), default=0x5AFE1234)
    ap.add_argument("--payload-type", type=int, default=8, help="8 = PCMA")
    args = ap.parse_args()

    rate, per_packet = 8000, 160          # 20 ms of G.711
    packets = int(args.seconds * rate / per_packet)

    with open(args.out, "wb") as f:
        # LINKTYPE_ETHERNET(1). LINKTYPE_RAW looks tidier -- there is no real
        # Ethernet segment to describe -- but SIPp refuses it with
        # "Unsupported link-type 12" and never plays a packet.
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        seq, ts, usec = 0, 0, 0
        for _ in range(packets):
            payload = bytes(
                alaw_encode(int(16000 * math.sin(2 * math.pi * args.hz * (ts + i) / rate)))
                for i in range(per_packet)
            )
            rtp = struct.pack("!BBHII", 0x80, args.payload_type, seq & 0xFFFF,
                              ts & 0xFFFFFFFF, args.ssrc) + payload
            udp = struct.pack("!HHHH", 6000, 6000, 8 + len(rtp), 0) + rtp
            total = 20 + len(udp)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                             bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp
            eth = struct.pack("!6s6sH", b"\x02\x00\x00\x00\x00\x02",
                              b"\x02\x00\x00\x00\x00\x01", 0x0800) + ip
            f.write(struct.pack("<IIII", usec // 1000000, usec % 1000000,
                                len(eth), len(eth)))
            f.write(eth)
            seq += 1
            ts += per_packet
            usec += 20000
    print(f"wrote {args.out}: {packets} packets, {args.seconds}s "
          f"PCMA @{args.hz:.0f}Hz ssrc=0x{args.ssrc:08x}")


if __name__ == "__main__":
    main()
