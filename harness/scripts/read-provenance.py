#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Read (or update) a capture's provenance sidecar.

Split out of `promote.sh` rather than inlined as a heredoc: the shell script is
itself written from a heredoc often enough that a nested one has already gone
wrong once, and a file that can be run on its own can be tested on its own.

Default mode prints the eight fields `promote.sh` needs, one per line, in a
fixed order. `--set-home <home>` rewrites the record instead.
"""

import json
import sys

FIELDS = (
    "pins",
    "media_anchor",
    "taken_at",
    "bpf_filter",
    "packets",
    "sha256",
    "seconds",
    "home",
)


def main(argv: list[str]) -> int:
    set_home = None
    args = list(argv)
    if len(args) >= 2 and args[0] == "--set-home":
        set_home, args = args[1], args[2:]
    if len(args) != 1:
        print("usage: read-provenance.py [--set-home <home>] <file.provenance.json>",
              file=sys.stderr)
        return 2
    path = args[0]
    record = json.load(open(path, encoding="utf-8"))

    if set_home is not None:
        record["home"] = set_home
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=1, sort_keys=True)
            handle.write("\n")
        return 0

    missing = [k for k in FIELDS if k not in record or str(record[k]) == ""]
    if missing:
        print("provenance record is missing: " + ", ".join(missing), file=sys.stderr)
        return 1
    for key in FIELDS:
        value = str(record[key])
        # One field per line is the contract with the shell. A newline inside a
        # value would silently become an extra field and shift every one after
        # it, which is the failure this whole file exists to have stopped.
        if "\n" in value:
            print(f"provenance field {key} contains a newline", file=sys.stderr)
            return 1
        print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
