"""The MCP client: SSE framing, and the guard that compares two nodes.

Both areas shipped broken. The SSE reader took the first `data:` line, which
is an empty keepalive, and crashed on every call. The distinctness guard read
a top-level `node` key that does not exist, so it announced "two distinct
nodes" having compared nothing.
"""

import importlib.util
import io
import json
import pathlib
import sys
import urllib.error

import pytest

CLIENTS = pathlib.Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


mp = _load("mcp_probe")


class FakeResponse(io.BytesIO):
    def __init__(self, payload: bytes, session="s1"):
        super().__init__(payload)
        self.headers = {"Mcp-Session-Id": session}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def client_returning(payload: str, monkeypatch) -> "mp.Mcp":
    c = mp.Mcp("http://127.0.0.1:1", "tok", "probe")
    monkeypatch.setattr(
        mp.urllib.request, "urlopen",
        lambda *a, **k: FakeResponse(payload.encode()),
    )
    return c


def test_sse_keepalive_before_the_payload_is_skipped(monkeypatch):
    """The stream opens with an EMPTY `data:` line. Taking the first one
    parsed "" and failed with a JSON error pointing nowhere near the cause."""
    body = (
        "data: \n"
        "id: 0\n"
        "retry: 3000\n"
        "\n"
        'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'
    )
    c = client_returning(body, monkeypatch)
    assert c._call("initialize") == {"ok": True}


def test_a_plain_json_reply_is_still_read(monkeypatch):
    """The server may answer as JSON rather than SSE. Handling only one of the
    two works until the day it picks the other."""
    c = client_returning('{"jsonrpc":"2.0","id":1,"result":{"ok":1}}', monkeypatch)
    assert c._call("initialize") == {"ok": 1}


def test_an_sse_reply_with_no_data_line_is_an_error_not_a_crash(monkeypatch):
    """A stream carrying only keepalives must produce a message naming the
    problem, not a JSONDecodeError from an empty string."""
    c = client_returning("data: \nid: 0\nretry: 3000\n\n", monkeypatch)
    with pytest.raises(SystemExit) as e:
        c._call("initialize")
    assert "no data line" in str(e.value)


def test_a_jsonrpc_error_is_surfaced_not_returned_as_a_result(monkeypatch):
    """An error object has no `result`. Returning it as one would let a failed
    call read as an empty answer."""
    c = client_returning(
        'data: {"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad"}}\n',
        monkeypatch,
    )
    with pytest.raises(SystemExit) as e:
        c._call("tools/list")
    assert "bad" in str(e.value)


def test_the_session_id_is_captured_from_the_first_reply(monkeypatch):
    """Later requests must carry the session the server assigned."""
    c = client_returning('data: {"jsonrpc":"2.0","id":1,"result":{}}\n', monkeypatch)
    assert c.session is None
    c._call("initialize")
    assert c.session == "s1"


def test_an_http_error_names_the_node_and_the_method(monkeypatch):
    """Two nodes are being driven, so an error that does not say which one
    sends the reader to the wrong log."""
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b"no"))

    c = mp.Mcp("http://127.0.0.1:1", "tok", "relay")
    monkeypatch.setattr(mp.urllib.request, "urlopen", boom)
    with pytest.raises(SystemExit) as e:
        c._call("initialize")
    msg = str(e.value)
    assert "relay" in msg and "initialize" in msg and "401" in msg


def test_tool_output_is_parsed_out_of_the_content_envelope(monkeypatch):
    """MCP wraps a tool result in content[].text carrying JSON. Returning the
    envelope would make every caller unwrap it themselves."""
    inner = json.dumps({"dialog_count": 3})
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "result": {"content": [{"type": "text", "text": inner}]}})
    c = client_returning(f"data: {body}\n", monkeypatch)
    c.session = "s1"
    assert c.call("capture_status") == {"dialog_count": 3}
