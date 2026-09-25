#!/usr/bin/env python3
"""Count dialogs by one field under a filter, as JSON a model can be handed.

    aggregate_for_model.py capture.pcap --group-by FIELD [--filter EXPR]
                           [--max-bytes N] [--sipnab PATH]

Sends a filter-DSL expression (docs/filter-dsl.md) to `aggregate_dialogs`
over MCP stdio and prints one line of JSON no longer than --max-bytes UTF-8
bytes (default 4096): the model's budget, not sipnab's.

sipnab bounds how many buckets an answer holds (`--mcp-max-rows`) and how
long each capture-derived value is (256 bytes, then a marker), never the
answer as a whole, because the budget belongs to whoever reads it. So the
cut is made here. It drops the smallest buckets whole into `other_count`,
never part of a string, so what the model reads is valid JSON under every
budget, its buckets and `other_count` still add up to `total_matched`, and
`omitted_buckets` says how many were folded. A cut mid-string would leave
a model an unterminated value to complete from its imagination.

Values sipnab took from packets keep its untrusted-data markers: a model
should see them. The budget is in bytes, since each marker character is
three.

Exit status: 0 printed, 1 sipnab refused the filter or field (its message
names the fields it knows) or the budget cannot hold even an empty answer,
3 sipnab could not be asked.
"""

import argparse
import asyncio
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import mcp_calls  # noqa: E402


def encode(doc: dict) -> str:
    """The compact JSON a model is handed: no spaces, characters unescaped."""
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def bound(answer: dict, filter_expr: str | None, max_bytes: int) -> tuple[str, int]:
    """The answer as JSON of at most `max_bytes` bytes, and the buckets folded."""
    # snippet:start model-bound
    buckets = answer["buckets"]
    if sum(b["count"] for b in buckets) + answer["other_count"] != answer["total_matched"]:
        raise ValueError(
            f"sipnab's buckets and other_count do not add up to total_matched "
            f"{answer['total_matched']}; refusing to pass on a wrong total"
        )

    def doc(kept: int) -> str:
        return encode({
            "group_by": answer["group_by"],
            "filter": filter_expr,
            "total_matched": answer["total_matched"],
            "distinct_values": answer["distinct_values"],
            "buckets": [{"value": b["value"], "count": b["count"]} for b in buckets[:kept]],
            "other_count": answer["other_count"] + sum(b["count"] for b in buckets[kept:]),
            "omitted_buckets": len(buckets) - kept,
        })

    def fits(kept: int) -> bool:
        return len(doc(kept).encode("utf-8")) <= max_bytes

    if not fits(0):
        raise ValueError(
            f"the answer is {len(doc(0).encode('utf-8'))} byte(s) with no bucket at all, "
            f"over the {max_bytes}-byte budget"
        )
    # Fewer buckets is never longer, so the most that fit is found by halving.
    lo, hi = 0, len(buckets)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if fits(mid) else (lo, mid - 1)
    return doc(lo), len(buckets) - lo
    # snippet:end model-bound


async def aggregate(call, group_by: str, filter_expr: str | None) -> dict:
    await mcp_calls.wait_drained(call)
    args = {"group_by": group_by}
    if filter_expr:
        args["filter"] = filter_expr
    return await call("aggregate_dialogs", args)


async def run(args) -> dict:
    sipnab = mcp_calls.find_sipnab(args.sipnab)
    async with mcp_calls.stdio(sipnab, args.captures) as call:
        return await aggregate(call, args.group_by, args.filter)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("captures", nargs="+", help="capture files")
    ap.add_argument("--group-by", required=True, help="state, response_code, method, from.user, to.user, ua, src.ip, dst.ip or rtp.codec")
    ap.add_argument("--filter", help="a filter-DSL expression or alias, applied before grouping")
    ap.add_argument("--max-bytes", type=int, default=4096, help="the model's budget, in UTF-8 bytes")
    ap.add_argument("--sipnab", help="the sipnab binary")
    args = ap.parse_args()
    try:
        answer = asyncio.run(run(args))
        text, _ = bound(answer, args.filter, args.max_bytes)
    except (mcp_calls.ToolError, ValueError) as e:
        print(f"aggregate_for_model: {e}", file=sys.stderr)
        return 1
    except (OSError, TimeoutError) as e:
        print(f"aggregate_for_model: sipnab could not be asked: {e}", file=sys.stderr)
        return 3
    except BaseExceptionGroup as g:
        cause = mcp_calls.leaf(g)
        if isinstance(cause, mcp_calls.ToolError):
            print(f"aggregate_for_model: {cause}", file=sys.stderr)
            return 1
        print(f"aggregate_for_model: sipnab could not be asked: {cause}", file=sys.stderr)
        return 3
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
