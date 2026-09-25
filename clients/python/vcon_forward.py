#!/usr/bin/env python3
"""Forward the vCons sipnab writes to a vCon server, then delete them.

    VCON_INGRESS_TOKEN=... vcon_forward.py --spool /var/spool/sipnab-vcon \\
        --url http://vcon.example:8000 --ingress-list sipnab [--once]

sipnab's `--export-vcon-dir` is a queue that nothing drains: sipnab writes
one container per dialog and makes no outbound connection (docs/vcon.md,
"The spool contract"). This posts each container, byte for byte, to the
conserver's scoped route `POST /vcon/external-ingress?ingress_list=<list>`
with the list's key in `x-conserver-api-token`, and on a 2xx deletes it.

- A container is deleted only if the file is still the one that was sent.
  sipnab reuses a dialog's file name and replaces it by rename, so a
  re-export that lands mid-send is kept and goes out on the next pass.
- 401, 403 and 404 mean the key or the list is wrong: the forwarder stops
  and deletes nothing, rather than retrying every file forever.
- Any other 4xx means the server will never take that container. It moves
  to `rejected/` inside the spool, out of the queue, for a person to read.
- A 5xx or an unreachable server keeps the file and ends the pass.

A 2xx means the server queued the container, not that it stored it. Check
the store itself to know that.

The key comes from the environment, not the command line, so it is not
visible in the process list. Standard library only.
"""

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

REJECTED = "rejected"


class ConfigError(Exception):
    """The server refused the key or does not know the ingress list."""


@dataclass
class Config:
    spool: Path
    url: str
    ingress_list: str
    token: str
    timeout: float = 10.0


@dataclass
class Result:
    sent: list = field(default_factory=list)
    kept: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    error: str = ""


def pending(spool: Path) -> list:
    """Whole containers waiting in the spool, oldest name first.

    sipnab stages each write as a dot-prefixed `.partial` sibling and
    renames it into place, so anything starting with a dot is not a
    container yet.
    """
    return sorted(
        p
        for p in Path(spool).iterdir()
        if p.is_file() and p.suffix == ".json" and not p.name.startswith(".")
    )


def _identity(path: Path):
    st = path.stat()
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def post(cfg: Config, body: bytes) -> int:
    """POST one container; return the HTTP status."""
    url = (
        f"{cfg.url.rstrip('/')}/vcon/external-ingress"
        f"?ingress_list={quote(cfg.ingress_list)}"
    )
    req = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-conserver-api-token": cfg.token,
        },
    )
    try:
        with urlopen(req, timeout=cfg.timeout) as resp:
            return resp.status
    except HTTPError as e:
        return e.code


def drain(cfg: Config) -> Result:
    """Send every waiting container once. Raises ConfigError on 401/403/404."""
    result = Result()
    for path in pending(cfg.spool):
        try:
            before = _identity(path)
            body = path.read_bytes()
        except FileNotFoundError:
            continue  # taken by another forwarder, or replaced
        try:
            status = post(cfg, body)
        except (URLError, OSError) as e:
            result.kept.append(path.name)
            result.error = f"{path.name}: {e}"
            break
        if status in (401, 403, 404):
            raise ConfigError(
                f"{cfg.url} answered {status} for ingress list "
                f"{cfg.ingress_list!r}: check the key and the list name"
            )
        if 200 <= status < 300:
            result.sent.append(path.name)
            try:
                if _identity(path) == before:
                    path.unlink()
                else:
                    result.kept.append(path.name)  # re-exported mid-send
            except FileNotFoundError:
                pass
        elif 400 <= status < 500:
            aside = Path(cfg.spool) / REJECTED
            aside.mkdir(exist_ok=True)
            os.replace(path, aside / path.name)
            result.rejected.append(path.name)
        else:
            result.kept.append(path.name)
            result.error = f"{path.name}: server answered {status}"
            break
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--spool", required=True, type=Path, help="sipnab's --export-vcon-dir")
    ap.add_argument("--url", required=True, help="conserver base URL, e.g. http://host:8000")
    ap.add_argument("--ingress-list", default="sipnab", help="ingress list (default sipnab)")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between passes")
    ap.add_argument("--once", action="store_true", help="one pass, then exit")
    args = ap.parse_args(argv)

    token = os.environ.get("VCON_INGRESS_TOKEN")
    if not token:
        print("vcon_forward: set VCON_INGRESS_TOKEN to the ingress list's key", file=sys.stderr)
        return 2
    cfg = Config(spool=args.spool, url=args.url, ingress_list=args.ingress_list, token=token)

    while True:
        try:
            result = drain(cfg)
        except ConfigError as e:
            print(f"vcon_forward: {e}", file=sys.stderr)
            return 1
        for name in result.sent:
            print(f"sent {name}", flush=True)
        for name in result.rejected:
            print(f"rejected {name} (moved to {REJECTED}/)", flush=True)
        if result.error:
            print(f"vcon_forward: {result.error}; will retry", file=sys.stderr, flush=True)
        if args.once:
            return 0 if not result.error else 1
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
