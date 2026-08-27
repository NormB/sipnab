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
import pathlib
import struct
import subprocess
import tempfile
import wave


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


def load_wav_8k(path: str) -> list[int]:
    """Read a WAV as 8 kHz mono 16-bit samples.

    Resampling goes through `sox` because writing a resampler here would be a
    second-rate one: the anti-alias filtering is what keeps a 22 kHz voice from
    arriving as an aliased buzz at 8 kHz, and getting that wrong produces audio
    that sounds broken for a reason nobody would look for in a pcap generator.
    """
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        out = tmp.name
    try:
        subprocess.run(
            ["sox", path, "-r", "8000", "-c", "1", "-b", "16", "-e", "signed-integer", out],
            check=True, capture_output=True, timeout=120,
        )
        with wave.open(out, "rb") as w:
            if w.getnchannels() != 1 or w.getframerate() != 8000 or w.getsampwidth() != 2:
                raise SystemExit(f"{path}: sox did not produce 8 kHz mono 16-bit")
            raw = w.readframes(w.getnframes())
    except FileNotFoundError as e:
        raise SystemExit("sox is required for --from-wav") from e
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"sox failed on {path}: {e.stderr[:200]!r}") from e
    finally:
        pathlib.Path(out).unlink(missing_ok=True)
    return list(struct.unpack(f"<{len(raw) // 2}h", raw))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    ap.add_argument(
        "--from-wav",
        help="encode this WAV instead of a tone; resampled to 8 kHz mono",
    )
    ap.add_argument("--hz", type=float, default=660.0, help="tone frequency")
    ap.add_argument("--seconds", type=float, default=8.0)
    ap.add_argument("--ssrc", type=lambda s: int(s, 0), default=0x5AFE1234)
    ap.add_argument("--payload-type", type=int, default=8, help="8 = PCMA")
    args = ap.parse_args()

    rate, per_packet = 8000, 160          # 20 ms of G.711

    # A tone proves two legs differ. It cannot show whether a CALL was
    # captured -- nobody can tell a well-recorded sine from a badly recorded
    # one. Speech is the only fixture where a listener knows immediately
    # whether the far end came through.
    samples: list[int] | None = None
    if args.from_wav:
        samples = load_wav_8k(args.from_wav)
        packets = -(-len(samples) // per_packet)      # ceil
    else:
        packets = int(args.seconds * rate / per_packet)

    with open(args.out, "wb") as f:
        # LINKTYPE_ETHERNET(1). LINKTYPE_RAW looks tidier -- there is no real
        # Ethernet segment to describe -- but SIPp refuses it with
        # "Unsupported link-type 12" and never plays a packet.
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        seq, ts, usec = 0, 0, 0
        for _ in range(packets):
            if samples is None:
                frame = [
                    int(16000 * math.sin(2 * math.pi * args.hz * (ts + i) / rate))
                    for i in range(per_packet)
                ]
            else:
                # The last packet is padded with silence rather than truncated:
                # a short final RTP packet is legal but confuses some decoders,
                # and the difference is 20 ms nobody will hear.
                frame = samples[ts : ts + per_packet]
                frame += [0] * (per_packet - len(frame))
            payload = bytes(alaw_encode(s) for s in frame)
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
    src = args.from_wav or f"{args.hz:.0f}Hz tone"
    print(f"wrote {args.out}: {packets} packets, {packets * 0.02:.1f}s PCMA "
          f"from {src}, ssrc=0x{args.ssrc:08x}")


if __name__ == "__main__":
    main()
