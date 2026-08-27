#!/usr/bin/env python3
"""Ask both sipnab nodes the same question over MCP, and compare the answers.

The REST client reads projections. This one drives the door an agent uses, on
both capture points, so a disagreement between the two surfaces shows up as a
disagreement rather than as a subtly different number nobody diffed.

Reads only: every tool called here is a query.
"""

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
SECRETS = HERE.parent / "secrets"
PROTOCOL = "2025-06-18"


class Mcp:
    """One MCP HTTP session against one node."""

    def __init__(self, base: str, token: str, label: str):
        self.base = base.rstrip("/")
        self.token = token
        self.label = label
        self.session = None
        self._id = 0

    def _call(self, method: str, params: dict | None = None, notify: bool = False):
        self._id += 1
        body = {"jsonrpc": "2.0", "method": method}
        if not notify:
            body["id"] = self._id
        if params is not None:
            body["params"] = params
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            # Both are required: the server may answer either as JSON or as a
            # single SSE event, and refusing one of them is a 406 that reads
            # like an auth problem.
            "Accept": "application/json, text/event-stream",
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(
            f"{self.base}/mcp", data=json.dumps(body).encode(), headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                if self.session is None:
                    self.session = r.headers.get("Mcp-Session-Id")
                raw = r.read().decode()
        except urllib.error.HTTPError as e:
            raise SystemExit(
                f"{self.label}: {method} -> HTTP {e.code} {e.reason}: "
                f"{e.read()[:200].decode(errors='replace')}"
            ) from e
        except urllib.error.URLError as e:
            raise SystemExit(f"{self.label}: {method} unreachable ({e.reason})") from e

        if notify or not raw.strip():
            return None
        # An SSE reply carries the JSON on `data:` lines; a plain reply is the
        # JSON itself. Handling only one of the two works until the day the
        # server picks the other.
        if raw.lstrip().startswith("event:") or raw.lstrip().startswith("data:"):
            # The stream opens with an EMPTY `data:` keepalive before the real
            # payload. Taking the first `data:` line therefore parsed "" and
            # failed with a JSON error that pointed nowhere near the cause.
            payload = None
            for line in raw.splitlines():
                if not line.startswith("data:"):
                    continue
                candidate = line[5:].strip()
                if candidate:
                    payload = candidate
                    break
            if payload is None:
                raise SystemExit(
                    f"{self.label}: {method} -> SSE reply carried no data line: "
                    f"{raw[:200]!r}"
                )
            raw = payload
        msg = json.loads(raw)
        if "error" in msg:
            raise SystemExit(f"{self.label}: {method} -> {msg['error']}")
        return msg.get("result")

    def initialize(self) -> dict:
        result = self._call(
            "initialize",
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "sipnab-harness-probe", "version": "1"},
            },
        )
        self._call("notifications/initialized", notify=True)
        return result

    def tools(self) -> list[str]:
        return [t["name"] for t in self._call("tools/list").get("tools", [])]

    def call(self, name: str, arguments: dict | None = None):
        result = self._call("tools/call", {"name": name, "arguments": arguments or {}})
        for item in result.get("content", []):
            if item.get("type") == "text":
                try:
                    return json.loads(item["text"])
                except json.JSONDecodeError:
                    return item["text"]
        return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--proxy", default="http://127.0.0.1:8731")
    ap.add_argument("--relay", default="http://127.0.0.1:8732")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    nodes = []
    for label, base, token_file in (
        ("proxy", args.proxy, SECRETS / "mcp.token.proxy"),
        ("relay", args.relay, SECRETS / "mcp.token.relay"),
    ):
        if not token_file.is_file():
            raise SystemExit(f"no MCP token at {token_file}; is {label} running?")
        nodes.append(Mcp(base, token_file.read_text().strip(), label))

    out = {}
    for n in nodes:
        info = n.initialize()
        tools = n.tools()
        stats = n.call("capture_status")
        out[n.label] = {
            "server": info.get("serverInfo", {}),
            "tool_count": len(tools),
            "capture_status": stats,
        }
        if not args.json:
            si = info.get("serverInfo", {})
            print(f"{n.label:<7} {n.base}")
            print(f"        server  {si.get('name','?')} {si.get('version','?')}")
            print(f"        tools   {len(tools)}")
            ident = (stats or {}).get("capture_identity", {}) if isinstance(stats, dict) else {}
            print(f"        node    {ident.get('node', '(not reported)')}")
            print(f"        dialogs {stats.get('dialog_count')}  streams {stats.get('stream_count')}")

    # Both doors must be different nodes, or the agent is asking one sipnab
    # twice and calling the agreement corroboration.
    # `instance` rotates per capture and is the identity that actually
    # distinguishes two sipnabs. An earlier draft read a top-level `node` key
    # that does not exist, so this guard printed "two distinct nodes" without
    # having compared anything -- it would have passed with both URLs pointing
    # at one server.
    ids = []
    for k in out:
        st = out[k].get("capture_status")
        if not isinstance(st, dict):
            raise SystemExit(f"{k}: capture_status returned {type(st).__name__}, not an object")
        ident = st.get("capture_identity") or {}
        instance = ident.get("instance")
        if not instance:
            raise SystemExit(
                f"{k}: capture_status carried no capture_identity.instance, so "
                f"this check cannot tell two nodes apart"
            )
        ids.append((k, ident.get("node"), instance))
    if ids[0][2] == ids[1][2]:
        raise SystemExit(
            f"both MCP endpoints report capture instance {ids[0][2]} -- they "
            f"are one sipnab, so nothing here is a second opinion"
        )

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print()
        print("  two distinct nodes answered over MCP")
    return 0


if __name__ == "__main__":
    sys.exit(main())
