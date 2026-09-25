"""One `call(name, arguments)` coroutine over either MCP transport.

The AI-task programs (agent_triage.py, evidence_handoff.py,
aggregate_for_model.py) ask sipnab the same questions whichever way they
reach it, so the transport is chosen once, here:

- stdio: sipnab is started as a child with `--mcp -N`, through the MCP SDK
  that sipnab_mcp.py uses (clients/python/requirements-mcp.txt). No network,
  no token: the pipe is private.
- HTTP: a sipnab already serving `--mcp-transport http`, reached with a
  bearer token through mcp_probe.py's client, the one the capture harness
  uses. A token minted by `--mint-token` from the server's signing key is
  the shape recipe 55 deploys.

Each call returns the tool's answer as parsed JSON, the first text block
sipnab sends (the second is its provenance note). A tool error raises
ToolError with sipnab's own text.
"""

import asyncio
import contextlib
import json
import os
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import mcp_probe  # noqa: E402  (a sibling, found through HERE)


class ToolError(Exception):
    """sipnab refused or failed a tool call; the message is its own."""


def tool_json(texts: list[str], is_error: bool):
    """A tool answer's first text block, parsed; ToolError when it is an error."""
    if is_error:
        raise ToolError(texts[0] if texts else "tool error with no text")
    if not texts:
        raise ToolError("the tool answered with no text block")
    return json.loads(texts[0])


def find_sipnab(flag: str | None) -> str:
    """sipnab from `--sipnab`, else `$SIPNAB_BIN`, else `sipnab` on PATH."""
    return flag or os.environ.get("SIPNAB_BIN") or "sipnab"


def stdio_args(captures: list[str], extra: list[str]) -> list[str]:
    """The arguments a stdio MCP sipnab reading `captures` is started with."""
    args = ["--mcp", "-N", "--quiet", *extra]
    for c in captures:
        args += ["-I", c]
    return args


@contextlib.asynccontextmanager
async def stdio(sipnab: str, captures: list[str], extra: list[str] = ()):
    """A sipnab child speaking MCP on its stdin and stdout, as `call`."""
    # Imported here, so the unit tests, which run without the SDK, can load
    # this module.
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.shared.exceptions import MCPError

    # NO_COLOR: sipnab's log lines, which the SDK passes to stderr, as plain
    # text. The whole environment, not the SDK's short default list.
    params = StdioServerParameters(
        command=sipnab,
        args=stdio_args(captures, list(extra)),
        env={**os.environ, "NO_COLOR": "1"},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            async def call(name: str, arguments: dict):
                try:
                    res = await session.call_tool(name, arguments)
                except MCPError as e:
                    raise ToolError(str(e)) from e
                texts = [c.text for c in res.content if c.type == "text"]
                return tool_json(texts, bool(res.is_error))

            yield call


@contextlib.asynccontextmanager
async def http(url: str, token: str):
    """A sipnab serving MCP over HTTP at `url`, reached with a bearer token."""
    # snippet:start signed-http
    node = mcp_probe.Mcp(url, token, "sipnab")
    # A refused token fails here, as SystemExit naming the HTTP status:
    # sipnab answers 401 before any session exists.
    node.initialize()

    async def call(name: str, arguments: dict):
        return node.call(name, arguments)
    # snippet:end signed-http

    yield call


def leaf(error: BaseException) -> BaseException:
    """The first exception at the bottom of nested exception groups.

    The SDK reports a child that died, or a pipe that closed, as a task
    group's exception group around another one.
    """
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error


async def wait_drained(call, deadline: float = 60.0, sleep=asyncio.sleep, clock=time.monotonic) -> dict:
    """capture_status once a file source is read to its end.

    Evidence, never a fixed sleep: sipnab answers while it reads, and an
    answer given before the end describes part of the capture. A live source
    never ends, so it is returned at once; the report's own `complete` flag
    says how much of it an answer covers.
    """
    start = clock()
    while True:
        status = await call("capture_status", {})
        if status.get("source") != "file" or status.get("source_exhausted"):
            return status
        if clock() - start >= deadline:
            raise TimeoutError(
                f"sipnab had not finished reading its capture in {deadline:g}s "
                "(capture_status never said source_exhausted)"
            )
        await sleep(0.1)
