#!/usr/bin/env python3
"""Triage a capture the way an agent does it: over MCP, to one verdict.

    agent_triage.py capture.pcap [more.pcap ...] [--sipnab PATH]
    agent_triage.py --url http://127.0.0.1:8731 --token-file agent.token

With captures, sipnab is started as an MCP stdio child (no network, no
token). With --url, the program reaches a sipnab already serving MCP over
HTTP, presenting the bearer token in --token-file: a token minted with
`sipnab --mint-token --token-scope read` from the server's signing key is
the shape cookbook recipe 55 deploys. Both ways it asks the same three
things:

    capture_status      until a file source is read to its end
    list_dialogs        every dialog, paged with its cursor
    get_capture_report  the findings

and prints triage.py's verdict on the report, a summary of the dialogs by
state, and one `next: triage_call <Call-ID>` line per call a finding names:
the tool an agent calls next. The two answers must describe one capture: a
report that examined a different number of dialogs than the listing holds,
or a Failed dialog no finding names while the report says clean, is
inconclusive rather than a verdict picked from one of them.

The exit status is triage.py's: 0 clean, 1 problems, 2 inconclusive, 3
sipnab could not be asked. The MCP SDK comes from requirements-mcp.txt;
sipnab comes from --sipnab, else $SIPNAB_BIN, else PATH.
"""

import argparse
import asyncio
import collections
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import mcp_calls  # noqa: E402
import triage  # noqa: E402

EXIT = triage.EXIT


def named_calls(report: dict) -> list[str]:
    """Call-IDs the report's findings name, in the order it names them."""
    seen = []
    for f in report["findings"]:
        for e in f.get("evidence", []):
            call_id = e.get("call_id")
            if call_id and call_id not in seen:
                seen.append(call_id)
    return seen


def agent_verdict(rows: list[dict], total: int, report: dict) -> tuple[str, list[str]]:
    """The verdict, and the lines that justify it and say what to do next."""
    # snippet:start agent-verdict
    result, lines = triage.verdict(report)
    disagree = []
    if len(rows) != total:
        disagree.append(
            f"inconclusive: list_dialogs reported {total} dialog(s) and paging returned {len(rows)}"
        )
    if report["dialogs_examined"] != total:
        disagree.append(
            f"inconclusive: get_capture_report examined {report['dialogs_examined']} dialog(s) "
            f"and list_dialogs holds {total}, so the two answers are not about one capture"
        )
    named = named_calls(report)
    # A finding that omitted evidence counted calls it does not name, so a
    # Failed dialog missing from the names may be one of those.
    omitted = any(f.get("evidence_omitted") for f in report["findings"])
    unexplained = [] if omitted else [
        r["call_id"] for r in rows if r["state"] == "Failed" and r["call_id"] not in named
    ]
    if disagree or (unexplained and result == "clean"):
        result = "inconclusive"
    by_state = collections.Counter(r["state"] for r in rows)
    ordered = sorted(by_state.items(), key=lambda kv: (-kv[1], kv[0]))
    summary = ", ".join(f"{n} {state}" for state, n in ordered)
    lines = disagree + lines
    lines.append(f"summary: {len(rows)} dialog(s) listed: {summary}" if rows else "summary: no dialog listed")
    lines += [f"unexplained: {c} is Failed and no finding names it" for c in unexplained]
    lines += [f"next: triage_call {c}" for c in named]
    return result, lines
    # snippet:end agent-verdict


async def all_dialogs(call, page: int = 200) -> tuple[list[dict], int]:
    """Every dialog's Call-ID and state, and the total list_dialogs reports."""
    rows, cursor, total = [], None, 0
    while True:
        args = {"limit": page, "fields": ["state"]}
        if cursor:
            args["cursor"] = cursor
        answer = await call("list_dialogs", args)
        rows += answer["dialogs"]
        total = answer["total_matched"]
        cursor = answer.get("next_cursor")
        # A cursor with an empty page would page forever.
        if not cursor or not answer["dialogs"]:
            return rows, total


async def triage_over(call) -> tuple[str, list[str]]:
    await mcp_calls.wait_drained(call)
    rows, total = await all_dialogs(call)
    report = await call("get_capture_report", {"format": "json"})
    return agent_verdict(rows, total, report)


async def run(args) -> tuple[str, list[str]]:
    if args.url:
        token = pathlib.Path(args.token_file).read_text().strip()
        transport = mcp_calls.http(args.url, token)
    else:
        transport = mcp_calls.stdio(mcp_calls.find_sipnab(args.sipnab), args.captures)
    async with transport as call:
        return await triage_over(call)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("captures", nargs="*", help="capture files, for a stdio sipnab")
    ap.add_argument("--url", help="a sipnab serving MCP over HTTP, instead of captures")
    ap.add_argument("--token-file", help="the bearer token for --url")
    ap.add_argument("--sipnab", help="the sipnab binary for stdio")
    args = ap.parse_args()
    if bool(args.url) == bool(args.captures):
        ap.error("give captures (stdio) or --url (HTTP), not both and not neither")
    if args.url and not args.token_file:
        ap.error("--url needs --token-file")
    try:
        result, lines = asyncio.run(run(args))
    except (OSError, TimeoutError, mcp_calls.ToolError) as e:
        print(f"agent_triage: sipnab could not be asked: {e}", file=sys.stderr)
        return 3
    except SystemExit as e:
        # mcp_probe.py's HTTP client exits naming the status, 401 for a
        # refused token. Exit 1 would read as "problems found".
        print(f"agent_triage: sipnab could not be asked: {e}", file=sys.stderr)
        return 3
    except BaseExceptionGroup as g:
        print(f"agent_triage: sipnab could not be asked: {mcp_calls.leaf(g)}", file=sys.stderr)
        return 3
    print("\n".join(lines))
    return EXIT[result]


if __name__ == "__main__":
    sys.exit(main())
