#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Follow one call across several sipnab nodes, with no interactive agent.

Standard library only, on purpose: a support laptop may not permit
``pip install``, and this has to work on the laptop you actually have.

Usage
-----

Ask the edge node first and follow what it names::

    ./trace-call.py \\
        --node sbc=http://127.0.0.1:8811 \\
        --node proxy=http://127.0.0.1:8822 \\
        --node pbx=http://127.0.0.1:8823 \\
        --call-id 'abc123@10.0.0.1'

Omit ``--call-id`` and the first node's newest INVITE dialog is used, which
is enough to prove the wiring before you have a complaint to chase.

For a token-protected node (``--mcp-token-file`` on the server), add
``--token-file ~/.config/sipnab/prod01.token``. Loopback binds need no token.

What it prints, and why
-----------------------

Each leg comes back with the ``strategy`` that matched it. The script prints
that strategy and whether it was an identifier match or a guess, because on a
box that may or may not be a B2BUA for any given call, that distinction is the
answer -- not a footnote to it. See ``docs/mcp-walkthrough.md``.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

#: The protocol revision sipnab speaks. Sent on ``initialize``.
MCP_PROTOCOL = "2025-06-18"


class McpError(RuntimeError):
    """A JSON-RPC error returned by the server, or a broken transport."""


class Node:
    """One sipnab MCP server, reached over Streamable HTTP."""

    def __init__(self, name: str, url: str, token: str | None = None) -> None:
        self.name = name
        self.url = url.rstrip("/")
        if not self.url.endswith("/mcp"):
            self.url += "/mcp"
        self.token = token
        self.session: str | None = None
        #: What the node calls ITSELF (`--node-name`), learned on connect.
        #: The CLI label above is only what you typed.
        self.node_name: str | None = None
        self._id = 0

    # -- transport ---------------------------------------------------------

    def _post(self, method: str, params: dict | None = None, notify: bool = False):
        self._id += 1
        body: dict = {"jsonrpc": "2.0", "method": method}
        if not notify:
            body["id"] = self._id
        if params is not None:
            body["params"] = params

        headers = {
            "Content-Type": "application/json",
            # BOTH types, always. sipnab answers 406 to a request that offers
            # only application/json -- before any tool runs, so the failure
            # does not look like a tool problem.
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session:
            # Echoing the session id is not optional: without it the server
            # answers 422 "Unexpected message, expect initialize request".
            headers["Mcp-Session-Id"] = self.session

        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if self.session is None:
                    self.session = resp.headers.get("mcp-session-id")
                if notify:
                    return None
                return self._read_sse(resp.read().decode())
        except urllib.error.HTTPError as exc:
            hint = {
                401: "wrong or missing bearer token",
                403: "Host header not in --mcp-allowed-host",
                404: "path must be exactly /mcp",
                406: "Accept must offer application/json AND text/event-stream",
            }.get(exc.code, exc.reason)
            raise McpError(f"{self.name}: HTTP {exc.code} ({hint})") from exc
        except urllib.error.URLError as exc:
            raise McpError(f"{self.name}: cannot reach {self.url}: {exc.reason}") from exc

    @staticmethod
    def _read_sse(payload: str):
        """Pull the JSON-RPC result out of an SSE body.

        The reply is ``text/event-stream`` even when it is a single message,
        so ``json.loads(body)`` fails: the JSON arrives on ``data:`` lines.
        The first frame carries an EMPTY ``data:`` as a keepalive -- skip it
        rather than trying to parse it.
        """
        for line in payload.splitlines():
            if not line.startswith("data:"):
                continue
            chunk = line[len("data:"):].strip()
            if not chunk:
                continue
            msg = json.loads(chunk)
            if "error" in msg:
                err = msg["error"]
                raise McpError(f"{err.get('message')} ({err.get('code')})")
            return msg.get("result")
        raise McpError("no JSON-RPC result in the SSE body")

    # -- protocol ----------------------------------------------------------

    def connect(self) -> dict:
        info = self._post(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "sipnab-trace", "version": "1"},
            },
        )
        # The protocol requires this before the client starts calling tools.
        # Send it even where a server is lenient -- a client that skips it is
        # relying on behavior no server promises.
        self._post("notifications/initialized", notify=True)
        # Ask the node who it is. `capture_status` is one of the responses that
        # carries `capture_identity`; `get_dialog` is NOT, so attribution has
        # to be established once here rather than read off each answer.
        status = self.call("capture_status")
        self.node_name = (status.get("capture_identity") or {}).get("node")
        return info["serverInfo"]

    def call(self, tool: str, arguments: dict | None = None):
        """Call one tool and return its parsed payload.

        Every sipnab tool wraps its JSON in an MCP text content block, so the
        payload is parsed twice: once out of the SSE frame, once out of the
        block's ``text``.
        """
        result = self._post("tools/call", {"name": tool, "arguments": arguments or {}})
        for item in result.get("content", []):
            if item.get("type") == "text":
                return json.loads(item["text"])
        return result


def newest_invite(node: Node) -> str | None:
    """A Call-ID to start from when the operator has not named one."""
    listing = node.call("list_dialogs", {"limit": 50})
    invites = [d for d in listing.get("dialogs", []) if d.get("method") == "INVITE"]
    if not invites:
        return None
    return max(invites, key=lambda d: d.get("created_at") or "")["call_id"]


def trace(nodes: list[Node], call_id: str) -> int:
    """Ask the edge node first, then look up whatever it named.

    The edge is the only box that saw both sides, so its answer names the next
    Call-ID. Fanning out to every node instead costs a round trip per node and
    still leaves you reconciling the answers by hand.
    """
    edge, rest = nodes[0], nodes[1:]

    # An unknown Call-ID correlates to nothing, and so does a real call the SBC
    # kept in proxy mode. Those are opposite findings; asking whether the edge
    # holds the dialog at all is what separates them. An id this node never saw
    # comes back as a JSON-RPC error rather than an empty result.
    try:
        probe = edge.call("get_dialog", {"call_id": call_id, "max_messages": 1})
        held = bool((probe or {}).get("dialog", {}).get("call_id"))
    except McpError:
        held = False
    if not held:
        print(f"[{edge.name}] does not hold {call_id} at all.")
        print("  Not a correlation result: this node never saw that dialog.")
        return 1

    correlated = edge.call("find_correlated", {"call_id": call_id})
    legs = correlated.get("legs", [])
    print(f"[{edge.name}] {len(legs)} leg(s) correlated to {call_id}")

    for leg in legs:
        # THE field to read when a box may or may not be a B2BUA on any given
        # call. An identifier match is evidence; a timing match is a guess, and
        # printing them the same way is how a guess gets acted on.
        verdict = "identifier" if leg.get("identifier_match") else "GUESS"
        gap = leg.get("observed_gap_ms")
        gap_txt = f", gap {gap}ms" if gap is not None else ""
        print(
            f"  {leg.get('call_id')}"
            f"\n      via {leg.get('strategy')} [{verdict}]"
            f" score {leg.get('score')}{gap_txt}"
        )

    if correlated.get("heuristic_only"):
        clock = correlated.get("timing_clock") or {}
        print("  !! every leg was a timing guess, not an identifier match.")
        print(
            f"     clock on {edge.name}: synchronized={clock.get('synchronized')}"
            f" max_error_us={clock.get('max_error_us')}"
        )
        print("     The window is 2s. Skew larger than that invents legs and hides legs.")

    if not legs:
        print("  (nothing correlated: a call that stayed in proxy mode keeps its")
        print("   Call-ID, so ask the other nodes for the SAME id.)")

    # Whatever the edge named, plus the original id -- a proxy-mode hop carries
    # the original across unchanged and would otherwise never be looked up.
    wanted = [call_id] + [leg["call_id"] for leg in legs if leg.get("call_id")]
    for node in rest:
        for cid in wanted:
            try:
                # `max_messages: 1` because this is an existence check. The
                # default page is 100 messages you are about to throw away.
                answer = node.call("get_dialog", {"call_id": cid, "max_messages": 1})
            except McpError:
                continue
            dialog = (answer or {}).get("dialog") or {}
            if not dialog.get("call_id"):
                continue
            print(
                f"[{node.name}] holds {cid}"
                f"  (node={node.node_name or '?'}, state={dialog.get('state')},"
                f" {answer.get('total_messages')} msgs)"
            )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--node",
        action="append",
        required=True,
        metavar="NAME=URL",
        help="a sipnab MCP server; repeat, edge node FIRST",
    )
    ap.add_argument("--call-id", help="Call-ID to trace (default: newest INVITE)")
    ap.add_argument("--token-file", help="bearer token file, used for every node")
    args = ap.parse_args(argv)

    token = None
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as fh:
            token = fh.read().strip()
        if not token:
            print(f"token file {args.token_file} is empty", file=sys.stderr)
            return 2

    nodes = []
    for spec in args.node:
        if "=" not in spec:
            print(f"--node wants NAME=URL, got {spec!r}", file=sys.stderr)
            return 2
        name, url = spec.split("=", 1)
        nodes.append(Node(name, url, token))

    for node in nodes:
        info = node.connect()
        print(f"[{node.name}] {info['name']} {info['version']} node={node.node_name}")

    call_id = args.call_id or newest_invite(nodes[0])
    if not call_id:
        print(f"[{nodes[0].name}] holds no INVITE dialog to trace", file=sys.stderr)
        return 1
    return trace(nodes, call_id)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except McpError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
