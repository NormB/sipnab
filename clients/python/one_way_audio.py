#!/usr/bin/env python3
"""One-way audio on one call, and whose loss it is (cookbook recipes 4, 11
and 22).

    one_way_audio.py CALL-ID

Asks a running sipnab, over REST:

1. `GET /v1/dialogs/{call_id}/report`: the diagnosis (one-way audio, NAT
   mismatch and the hints that name the addresses and ports), and each RTP
   stream with its packets and loss (recipe 4).
2. `GET /v1/dialogs?filter=call_id == ... AND <signal> == true` for each of
   the five asymmetry signals: different codec, packetization, payload type
   or duration on the two legs, or media starting late (recipe 11). They live
   in the filter language, not in the report's diagnosis block.
3. `GET /v1/stats`: what the capture itself lost. A dropped packet is counted
   as network loss that never happened, so the loss figures are the
   network's only when the capture host dropped nothing (recipe 22).

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token). Standard library
only.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote as urlquote
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sipnab_dsl import quote

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"

ASYMMETRIES = (
    "codec_asymmetry",
    "ptime_asymmetry",
    "payload_asymmetry",
    "duration_asymmetry",
    "late_media",
)


def get(path: str, **params) -> dict:
    query = f"?{urlencode(params, quote_via=urlquote)}" if params else ""
    req = Request(f"{BASE}{path}{query}", headers={"Authorization": f"Bearer {TOKEN}"})
    with urlopen(req, timeout=10) as resp:
        return json.load(resp)


def asymmetry_filter(call_id: str, signal: str) -> str:
    return f"call_id == {quote(call_id)} AND {signal} == true"


def whose_loss(quality: dict) -> list[str]:
    """Whether the loss figures describe the network or the capture."""
    # snippet:start whose-loss
    kernel = quality["kernel_dropped_packets"]
    interface = quality["interface_dropped_packets"]
    lines = []
    if kernel:
        lines.append(
            f"capture: {kernel} packet(s) dropped by the kernel buffer on the capture host, "
            "counted above as network loss (raise -B/--buffer, narrow the BPF filter, "
            "or lower --snaplen)"
        )
    if interface:
        lines.append(
            f"capture: {interface} packet(s) dropped by the interface or its driver, counted "
            "above as network loss (a bigger buffer cannot fix these: check the NIC)"
        )
    if not lines:
        lines.append(
            "capture: no packet dropped by the kernel buffer or the interface, "
            "so the loss above is the network's"
        )
    snapped, undecodable = quality["snapped_frames"], quality["undecodable_frames"]
    if snapped or undecodable:
        lines.append(
            f"capture: {snapped} frame(s) cut short by the snaplen and {undecodable} frame(s) "
            "it could not decode; loss figures may be low as well as high"
        )
    return lines
    # snippet:end whose-loss


def render(report: dict, asymmetries: list[str], stats: dict) -> list[str]:
    diagnosis = report.get("diagnosis") or {}
    yes = {True: "yes", False: "no"}
    lines = [
        f"{report['call_id']}  {report['state']}  {report.get('final_status_code') or '-'}",
        f"one-way audio: {yes[bool(diagnosis.get('one_way_audio'))]}",
        f"NAT mismatch: {yes[bool(diagnosis.get('nat_mismatch'))]}",
    ]
    streams = report.get("streams") or []
    for s in streams:
        lines.append(
            f"  {s['ssrc']}  {s['src']} -> {s['dst']}  {s.get('codec') or '?'}  "
            f"{s['packets']} packets  loss {s['loss_pct']:.1f}%"
        )
    if not streams:
        lines.append("  no RTP stream is associated with this call")
    lines.extend(f"hint: {h}" for h in diagnosis.get("hints", []))
    lines.append(f"asymmetry: {', '.join(asymmetries) if asymmetries else 'none'}")
    lines.extend(whose_loss(stats["capture_quality"]))
    return lines


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: one_way_audio.py CALL-ID", file=sys.stderr)
        return 2
    call_id = sys.argv[1]
    try:
        report = get(f"/v1/dialogs/{urlquote(call_id, safe='')}/report")
        asymmetries = [
            signal
            for signal in ASYMMETRIES
            if get("/v1/dialogs", filter=asymmetry_filter(call_id, signal))["total"] > 0
        ]
        stats = get("/v1/stats")
    except ValueError as e:
        print(f"one_way_audio: {e}", file=sys.stderr)
        return 2
    except HTTPError as e:
        print(f"one_way_audio: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"one_way_audio: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    print("\n".join(render(report, asymmetries, stats)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
