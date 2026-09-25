#!/usr/bin/env python3
"""A stand-in for TFPS's `tfps_ctl`, for the one CI run that bans a source.

TFPS's `ban` writes a pinned BPF map and needs root, so no CI runner can run
the real one. scripts/smoke-clients.sh starts sipnab with `--tfps-ctl`
naming this file instead, and sipnab runs it exactly as it runs `tfps_ctl`.

Nothing here is invented shape. Every document is built from the golden
fixtures tests/tfps_contract_test.rs pins (tests/fixtures/tfps-*-golden*),
which were checked against `tfps_ctl --json` at sippulse/tfps `984577dc`, and
the test beside this file holds each printed line to their keys and order.
The behavior is `tfps_ctl`'s, read from crates/tfps/src/bin/tfps_ctl.rs at
that commit:

- `ban <ip> --json [--ttl N]` places the address in the block list and
  prints one action document; `--ttl` defaults to 3600 and `0` means no
  expiry (`ban_expires`). It refuses the host's own addresses with
  `refused: "local"` and exits 1 (`enforcement_guard`, `ban_action_docs`).
  The fake knows one kind of host address, loopback, which the real guard
  always holds; it does not read interfaces or an `ignoreip` file.
- `banned --json` prints one row per blocked address. A hand ban is not
  written to the audit log (`ban`: "NOT recorded in block_log,
  deliberately"), so its reason, detail and first_seen are null
  (`banned_attribution`).
- `status --json` prints the pinned status document as it is.

Anything else exits 2, so a caller never mistakes a subcommand the fake does
not model for an answer. The block list is a JSON file named by
`$FAKE_TFPS_STATE`, which stands in for the pinned map.
"""

import ipaddress
import json
import os
import pathlib
import sys
import time

FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "tests" / "fixtures"


def template(name: str, row: int) -> dict:
    """Row `row` of a golden fixture, keys in the peer's order."""
    return json.loads((FIXTURES / name).read_text().splitlines()[row])


def fail(message: str) -> int:
    print(f"fake_tfps_ctl: {message}", file=sys.stderr)
    return 2


def main(argv: list[str]) -> int:
    state_path = os.environ.get("FAKE_TFPS_STATE")
    if not state_path:
        return fail("set FAKE_TFPS_STATE to the file standing in for the block map")
    state = pathlib.Path(state_path)
    blocked = json.loads(state.read_text()) if state.exists() else {}
    if not argv:
        return fail("no subcommand")
    command, rest = argv[0], argv[1:]
    ttl, positional, it = 3600, [], iter(rest)
    for arg in it:
        if arg == "--json":
            continue
        if arg == "--ttl":
            ttl = int(next(it))
        elif arg == "--db":
            next(it)
        else:
            positional.append(arg)

    if command == "status":
        print((FIXTURES / "tfps-status-golden.json").read_text().strip())
        return 0
    if command == "banned":
        for ip, expires in blocked.items():
            row = template("tfps-banned-golden.jsonl", 2)
            row.update(ip=ip, expires=expires)
            print(json.dumps(row, separators=(",", ":")))
        return 0
    if command == "ban":
        if not positional:
            return fail("give at least one address")
        refused_any = False
        for raw in positional:
            ip = ipaddress.IPv4Address(raw)
            if ip.is_loopback:
                doc = template("tfps-ban-golden.jsonl", 2)
                doc.update(ip=str(ip))
                refused_any = True
            else:
                expires = None if ttl == 0 else int(time.time()) + ttl
                blocked[str(ip)] = expires
                doc = template("tfps-ban-golden.jsonl", 1)
                doc.update(ip=str(ip), expires=expires)
            print(json.dumps(doc, separators=(",", ":")))
        state.write_text(json.dumps(blocked))
        return 1 if refused_any else 0
    return fail(f"this fake does not model `{command}`")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
