#!/usr/bin/env python3
"""Join one call across the two sipnab capture points, over REST.

The proxy node and the relay node see different halves of a call: the proxy
watches signaling on opensips-1 and never touches media, the relay watches
media on rtpengine and never sees an INVITE. Neither can answer "was this call
healthy" on its own, and that is the point of running two.

Reads only. Nothing here changes capture state.
"""

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_KEY = HERE.parent / "secrets" / "api.key"


def get(base: str, path: str, key: str):
    """One authenticated GET, returning parsed JSON."""
    req = urllib.request.Request(
        f"{base}{path}", headers={"Authorization": f"Bearer {key}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        # The status matters: 401 means the key is wrong, 404 means the route is
        # absent in this build. Collapsing them into "failed" sends the reader
        # looking in the wrong place.
        raise SystemExit(f"{base}{path}: HTTP {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise SystemExit(f"{base}{path}: unreachable ({e.reason})") from e


def preflight(bases: list[str], key: str) -> None:
    """Refuse to report unless every node is answering.

    A sipnab sidecar joins the network namespace of the service it watches, so
    RECREATING that service tears the namespace out from under it and the
    sidecar dies. Nothing about the surviving node looks wrong: it answers,
    reports its own counts, and the join over one node produces an empty
    correlation that reads as "no calls matched" rather than "half the evidence
    is missing".

    That is not a hypothetical. Recreating the proxy container left its sipnab
    dead for three runs while the relay answered normally, and each run was
    reported as a correlation failure.
    """
    dead = []
    for base in bases:
        req = urllib.request.Request(
            f"{base}/v1/stats", headers={"Authorization": f"Bearer {key}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            dead.append(f"{base} ({e})")
    if dead:
        raise SystemExit(
            "  These capture points are not answering, so any correlation "
            "below would be\n  drawn from half the evidence:\n    "
            + "\n    ".join(dead)
            + "\n\n  A sipnab sidecar shares the namespace of the service it "
            "watches. Recreating\n  that service kills the sidecar. "
            "`docker compose up -d --force-recreate <sidecar>`\n  brings it "
            "back."
        )


def node_view(base: str, key: str) -> dict:
    """Everything one node knows, in one shape."""
    stats = get(base, "/v1/stats", key)
    return {
        "base": base,
        "node": stats["capture_identity"]["node"],
        "instance": stats["capture_identity"]["instance"],
        "source": stats["source"],
        "dialogs": get(base, "/v1/dialogs?limit=200", key)["dialogs"],
        "streams": get(base, "/v1/streams?limit=200", key)["streams"],
        "stats": stats,
    }


def correlate(proxy: dict, relay: dict) -> list[dict]:
    """Pair each proxy dialog with the relay streams that carried its media.

    Joined on `associated_dialog`, which the relay fills from the rtpengine ng
    control plane that rtpengine mirrors to a Homer destination. That is the
    only fact linking the two nodes: signaling never transits rtpengine, so
    without the mirror every relay stream carries `associated_dialog: null` and
    no correlation downstream can recover a Call-ID it was never told.

    An earlier draft of this function matched on SDP media ports read from the
    dialog summary. Those fields do not exist -- the summary carries no media
    ports at all -- so every call reported zero streams and the join looked
    merely empty rather than wrong.
    """
    by_call: dict[str, list[dict]] = {}
    unnamed = []
    for s in relay["streams"]:
        call_id = s.get("associated_dialog")
        if call_id:
            by_call.setdefault(call_id, []).append(s)
        else:
            unnamed.append(s)

    joined = []
    for d in proxy["dialogs"]:
        call_id = d.get("call_id")
        streams = by_call.get(call_id, [])
        joined.append(
            {
                "call_id": call_id,
                "state": d.get("state"),
                "code": d.get("final_status_code"),
                "duration_sec": d.get("duration_sec"),
                "relay_streams": len(streams),
                "relay_packets": sum(s.get("packets") or 0 for s in streams),
                "codecs": sorted({s.get("codec") for s in streams if s.get("codec")}),
                "worst_mos": min(
                    (s["mos"] for s in streams if s.get("mos") is not None),
                    default=None,
                ),
                "bidirectional": len(
                    {(s.get("src"), s.get("dst")) for s in streams}
                )
                >= 2,
            }
        )

    # Media the relay could not name is reported, never dropped. It is the
    # signal that the ng mirror is off or lagging, and silently omitting it
    # would make a broken mirror look like a quiet network.
    if unnamed:
        joined.append(
            {
                "call_id": None,
                "state": "UNNAMED MEDIA",
                "code": None,
                "duration_sec": None,
                "relay_streams": len(unnamed),
                "relay_packets": sum(s.get("packets") or 0 for s in unnamed),
                "codecs": sorted({s.get("codec") for s in unnamed if s.get("codec")}),
                "worst_mos": None,
                "bidirectional": False,
            }
        )
    return joined


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--proxy", default="http://127.0.0.1:8080")
    ap.add_argument("--relay", default="http://127.0.0.1:8081")
    ap.add_argument("--key-file", type=pathlib.Path, default=DEFAULT_KEY)
    ap.add_argument("--json", action="store_true", help="emit JSON, not a table")
    args = ap.parse_args()

    if not args.key_file.is_file():
        raise SystemExit(f"no API key at {args.key_file}; run 'make api-key'")
    key = args.key_file.read_text().strip()

    # Before anything is read, not after: a node that died takes its half of
    # every call with it, and the result still looks like a well-formed answer.
    preflight([args.proxy, args.relay], key)

    proxy = node_view(args.proxy, key)
    relay = node_view(args.relay, key)

    # The two nodes must be genuinely different. Identical instance ids mean
    # both clients reached ONE sipnab, and every correlation below would be a
    # node agreeing with itself.
    if proxy["instance"] == relay["instance"]:
        raise SystemExit(
            f"proxy and relay report the same capture instance "
            f"({proxy['instance']}) -- both URLs point at one sipnab, so there "
            f"is nothing to correlate"
        )

    result = {
        "proxy": {k: proxy[k] for k in ("base", "node", "instance", "source")},
        "relay": {k: relay[k] for k in ("base", "node", "instance", "source")},
        "proxy_dialogs": len(proxy["dialogs"]),
        "proxy_streams": len(proxy["streams"]),
        "relay_dialogs": len(relay["dialogs"]),
        "relay_streams": len(relay["streams"]),
        "calls": correlate(proxy, relay),
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"proxy  {proxy['node']:<16} {proxy['base']}")
    print(f"       dialogs={len(proxy['dialogs']):<5} streams={len(proxy['streams'])}")
    print(f"relay  {relay['node']:<16} {relay['base']}")
    print(f"       dialogs={len(relay['dialogs']):<5} streams={len(relay['streams'])}")
    print()
    hdr = f"{'Call-ID':<24} {'State':<11} {'Code':<5} {'Strm':<5} {'Pkts':<7} {'Codec':<7} {'MOS':<5} {'2-way'}"
    print(hdr)
    print("-" * len(hdr))
    shown = [c for c in result["calls"] if c["relay_streams"]] or result["calls"]
    for c in shown[:25]:
        mos = f"{c['worst_mos']:.2f}" if c["worst_mos"] is not None else "-"
        print(
            f"{str(c['call_id'] or '-')[:23]:<24} {str(c['state'])[:10]:<11} "
            f"{str(c['code'] or '-'):<5} {c['relay_streams']:<5} "
            f"{c['relay_packets']:<7} {','.join(c['codecs'])[:6]:<7} {mos:<5} "
            f"{'yes' if c['bidirectional'] else 'no'}"
        )
    correlated = sum(1 for c in result["calls"] if c["call_id"] and c["relay_streams"])
    print()
    print(f"  {correlated} call(s) correlated across both nodes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
