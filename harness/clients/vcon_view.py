#!/usr/bin/env python3
"""List, show and play back vCons stored on the conserver.

A stored vCon is mostly a megabyte of base64 audio, so `curl | jq` shows you
everything except the parts worth reading. This prints the call as a summary
and writes the recording out as a WAV you can play.
"""

import argparse
import base64
import io
import json
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request
import wave

DEFAULT_BASE = "http://127.0.0.1:8000"


class ListingBroken(Exception):
    """The conserver's listing endpoint is unusable.

    `GET /vcon` scans keys matching `vcon*`, which also matches the conserver's
    own bare `vcons` index key, then parses each as `vcon:<uuid>` and raises
    IndexError on the one without a colon. The STORE is fine -- only the index
    route is broken -- so the durable table is queried instead of giving up.
    """


def durable_uuids() -> list[str]:
    """UUIDs from the durable store, read straight from Postgres.

    A better listing than the API's even when the API works: it shows what
    actually persisted, where the cache-backed route also lists entries that
    expired an hour ago and now answer 404.
    """
    sql = "select uuid from vcons_observed order by created_at desc"
    try:
        out = subprocess.run(
            ["docker", "exec", "vcon-backend-postgres-1", "sh", "-c",
             f'psql -U $POSTGRES_USER -d $POSTGRES_DB -tAc "{sql}"'],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def token(explicit: str | None) -> str:
    """The conserver API token, from the flag or the running container."""
    if explicit:
        return explicit
    try:
        env = subprocess.run(
            ["docker", "inspect", "vcon-backend-api-1", "--format",
             "{{range .Config.Env}}{{println .}}{{end}}"],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        raise SystemExit(f"no --token given and the container is unreadable: {e}") from e
    for line in env.splitlines():
        if line.startswith("CONSERVER_API_TOKEN="):
            return line.split("=", 1)[1]
    raise SystemExit("no CONSERVER_API_TOKEN in the container environment")


def get(base: str, path: str, tok: str, missing_ok: bool = False):
    req = urllib.request.Request(
        f"{base}{path}", headers={"x-conserver-api-token": tok}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404 and missing_ok:
            return None
        if e.code >= 500 and path == "/vcon" and not missing_ok:
            # The conserver's listing scans keys matching `vcon*`, which also
            # matches its own bare `vcons` index key, then splits each on ":"
            # and indexes [1]. The index key has no colon, so the endpoint
            # raises IndexError and answers 500. Nothing here can fix that, but
            # reporting it as "the store is down" would send someone to look at
            # valkey, which is fine.
            raise ListingBroken() from e
        raise SystemExit(f"{path}: HTTP {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise SystemExit(f"{path}: unreachable ({e.reason})") from e


def recordings(v: dict) -> list[dict]:
    return [d for d in v.get("dialog", []) if d.get("type") == "recording" and d.get("body")]


def show(v: dict) -> None:
    print(f"  uuid       {v.get('uuid')}")
    print(f"  created    {v.get('created_at')}")
    print(f"  vcon       {v.get('vcon')}")
    print("  parties:")
    for p in v.get("parties", []):
        who = p.get("sip") or p.get("tel") or p.get("sip_user_agent") or "?"
        role = f" [{p['role']}]" if p.get("role") else ""
        name = f" \"{p['sip_display_name']}\"" if p.get("sip_display_name") else ""
        print(f"    - {who}{name}{role}  validation={p.get('validation')}")

    for d in v.get("dialog", []):
        if d.get("type") == "recording":
            continue
        print(f"  dialog     type={d.get('type')} call-id={d.get('sip_call_id')} "
              f"duration={d.get('duration')}")

    for i, r in enumerate(recordings(v)):
        raw = base64.urlsafe_b64decode(r["body"] + "=" * (-len(r["body"]) % 4))
        line = f"  recording{i} {r.get('mediatype')} {len(raw)} bytes"
        try:
            w = wave.open(io.BytesIO(raw))
            line += (f"  {w.getnchannels()}ch {w.getsampwidth()*8}-bit "
                     f"{w.getframerate()}Hz {w.getnframes()/w.getframerate():.1f}s")
        except wave.Error:
            line += "  (not a readable WAV)"
        print(line)

    for a in v.get("analysis", []):
        body = a.get("body")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                body = {}
        note = (body or {}).get("capture_completeness", {}).get("note")
        if note:
            print(f"  analysis   {a.get('type')}: {note[:160]}...")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("uuid", nargs="?", help="omit to list what is stored")
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--token")
    ap.add_argument("--audio", type=pathlib.Path, help="write the recording to this WAV")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    tok = token(args.token)

    if not args.uuid:
        # `/vcon`, not `/vcons`. The plural is in the OpenAPI schema and
        # answers 500 on this deployment, which reads like the store being
        # broken rather than the wrong path being asked for.
        try:
            uuids = get(args.base, "/vcon", tok)
            if isinstance(uuids, dict):
                uuids = uuids.get("vcons", uuids.get("uuids", []))
        except ListingBroken:
            durable = durable_uuids()
            print("  The conserver's listing route is failing (known upstream")
            print("  defect: it parses its own `vcons` index key as a uuid).")
            if not durable:
                raise SystemExit(
                    "  Postgres is unreachable too, so nothing can be listed.\n"
                    "  Fetch directly if you know the uuid:  vcon_view.py <uuid>"
                ) from None
            print(f"  Listing the {len(durable)} DURABLY stored vCon(s) instead:\n")
            for u in durable:
                print(f"    {u}")
            print("\n  view one:  vcon_view.py <uuid>")
            print("  hear one:  vcon_view.py <uuid> --audio call.wav")
            return 0
        # The index and the store are different things. `/vcon` returns an
        # index that is appended to and never pruned, while the objects behind
        # it expire from the cache after about an hour unless they were posted
        # through an ingress chain. Listing the index alone therefore offers
        # uuids that answer 404, which reads as a broken store rather than as
        # an expired entry -- so each one is probed and labeled.
        print(f"  {len(uuids)} uuid(s) in the index; checking which are retrievable\n")
        live, gone = [], []
        for u in uuids:
            (live if get(args.base, f"/vcon/{u}", tok, missing_ok=True) else gone).append(u)
        for u in live:
            print(f"    {u}  retrievable")
        for u in gone[:6]:
            print(f"    {u}  EXPIRED (indexed, no longer stored)")
        if len(gone) > 6:
            print(f"    ... and {len(gone) - 6} more expired")
        print(f"\n  {len(live)} retrievable, {len(gone)} expired")
        if gone:
            print("  Expired entries were cached only. To store durably, post through")
            print("  an ingress chain:  POST /vcon?ingress_lists=sipnab")
        print("\n  view one:  vcon_view.py <uuid>")
        print("  hear one:  vcon_view.py <uuid> --audio call.wav")
        return 0

    v = get(args.base, f"/vcon/{args.uuid}", tok, missing_ok=True)
    if v is None:
        raise SystemExit(
            f"  {args.uuid} is not in the store.\n"
            f"  If it appeared in the listing, it was cached and has expired --\n"
            f"  the cache TTL is about an hour. Only vCons posted through an\n"
            f"  ingress chain (POST /vcon?ingress_lists=sipnab) are stored durably."
        )
    if args.json:
        # The audio is elided: it is a megabyte of base64 that makes the rest
        # unreadable, and --audio is how you get the actual sound.
        slim = dict(v)
        slim["dialog"] = [
            {**d, "body": f"<{len(d['body'])} base64 chars elided>"}
            if d.get("type") == "recording" and d.get("body") else d
            for d in v.get("dialog", [])
        ]
        print(json.dumps(slim, indent=2))
        return 0

    show(v)

    if args.audio:
        recs = recordings(v)
        if not recs:
            raise SystemExit("  this vCon carries no recording")
        raw = base64.urlsafe_b64decode(recs[0]["body"] + "=" * (-len(recs[0]["body"]) % 4))
        args.audio.write_bytes(raw)
        print(f"\n  wrote {args.audio} ({len(raw)} bytes) -- play it with any audio player")
    return 0


if __name__ == "__main__":
    sys.exit(main())
