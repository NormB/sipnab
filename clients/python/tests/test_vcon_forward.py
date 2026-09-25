"""vcon_forward.py drains sipnab's vCon spool into a vCon server.

sipnab writes one container per dialog into `--export-vcon-dir` and never
sends it anywhere (docs/vcon.md, "The spool contract"). The forwarder posts
each container to a conserver's scoped ingress route and deletes it only
once the server has taken it, and only if the file is still the one it sent:
sipnab reuses a dialog's file name, so a re-export that lands while the old
copy is in flight must survive to be sent on the next pass.

These tests run a real HTTP server on loopback, so the request line, the
header and the body are the ones that cross the wire.
"""

import importlib.util
import os
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

CLIENTS = pathlib.Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vf = _load("vcon_forward")

TOKEN = "scoped-ingress-key"


class Conserver:
    """A stand-in for the conserver's /vcon/external-ingress route.

    `answers` maps a spool file name to the status the server returns for it
    (default 204). `during` maps a name to a callable run while that request
    is being handled, before the answer is sent.
    """

    def __init__(self):
        self.requests = []
        self.answers = {}
        self.during = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 (http.server's naming)
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append(
                    {
                        "path": self.path,
                        "token": self.headers.get("x-conserver-api-token"),
                        "type": self.headers.get("Content-Type"),
                        "body": body,
                    }
                )
                hook = outer.during.get(_name_of(body))
                if hook:
                    hook()
                status = outer.answers.get(_name_of(body), 204)
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _name_of(body: bytes) -> str:
    # Each test container carries its own file name as its uuid, so the
    # server can tell which file a request came from.
    import json

    return json.loads(body)["uuid"]


@pytest.fixture
def server():
    s = Conserver()
    yield s
    s.close()


def _spool(tmp_path, *names):
    spool = tmp_path / "spool"
    spool.mkdir()
    for n in names:
        (spool / n).write_text('{"vcon":"0.0.1","uuid":"%s"}' % n)
    return spool


def _cfg(url, spool, **kw):
    return vf.Config(spool=spool, url=url, ingress_list="sipnab", token=TOKEN, **kw)


def test_pending_lists_only_whole_containers(tmp_path):
    spool = _spool(tmp_path, "b.json", "a.json")
    (spool / ".c.json.partial").write_text("{")
    # Any dot-prefixed name is a write still in progress, whatever its
    # suffix (rsync, for one, stages under a hidden name).
    (spool / ".e.json").write_text("{")
    (spool / "notes.txt").write_text("x")
    (spool / "rejected").mkdir()
    (spool / "rejected" / "d.json").write_text("{}")
    assert [p.name for p in vf.pending(spool)] == ["a.json", "b.json"]


def test_a_taken_container_is_posted_verbatim_then_deleted(tmp_path, server):
    spool = _spool(tmp_path, "a.json")
    sent = (spool / "a.json").read_bytes()
    result = vf.drain(_cfg(server.url, spool))
    assert result.sent == ["a.json"]
    assert not (spool / "a.json").exists()
    [req] = server.requests
    assert req["path"] == "/vcon/external-ingress?ingress_list=sipnab"
    assert req["token"] == TOKEN
    assert req["type"] == "application/json"
    assert req["body"] == sent


def test_a_container_re_exported_in_flight_is_kept_for_the_next_pass(tmp_path, server):
    spool = _spool(tmp_path, "a.json")

    def re_export():
        # sipnab stages a sibling and renames it over the old name.
        staged = spool / ".a.json.partial"
        staged.write_text('{"vcon":"0.0.1","uuid":"a.json","dialog":[1]}')
        os.replace(staged, spool / "a.json")

    server.during["a.json"] = re_export
    result = vf.drain(_cfg(server.url, spool))
    assert result.sent == ["a.json"]
    assert result.kept == ["a.json"]
    assert (spool / "a.json").read_text().endswith('"dialog":[1]}')


def test_a_refused_key_stops_everything_and_deletes_nothing(tmp_path, server):
    spool = _spool(tmp_path, "a.json", "b.json")
    server.answers["a.json"] = 403
    with pytest.raises(vf.ConfigError, match="403"):
        vf.drain(_cfg(server.url, spool))
    assert len(server.requests) == 1
    assert (spool / "a.json").exists() and (spool / "b.json").exists()


def test_an_unknown_ingress_list_is_a_config_error(tmp_path, server):
    spool = _spool(tmp_path, "a.json")
    server.answers["a.json"] = 404
    with pytest.raises(vf.ConfigError, match="404"):
        vf.drain(_cfg(server.url, spool))


def test_a_container_the_server_rejects_moves_aside_and_the_pass_goes_on(tmp_path, server):
    spool = _spool(tmp_path, "a.json", "b.json")
    server.answers["a.json"] = 422
    result = vf.drain(_cfg(server.url, spool))
    assert result.rejected == ["a.json"]
    assert result.sent == ["b.json"]
    assert (spool / "rejected" / "a.json").exists()
    assert not (spool / "a.json").exists()
    assert not (spool / "b.json").exists()


def test_a_server_error_keeps_the_file_and_ends_the_pass(tmp_path, server):
    spool = _spool(tmp_path, "a.json", "b.json")
    server.answers["a.json"] = 503
    result = vf.drain(_cfg(server.url, spool))
    assert result.sent == []
    assert result.kept == ["a.json"]
    assert "503" in result.error
    assert len(server.requests) == 1
    assert (spool / "a.json").exists() and (spool / "b.json").exists()


def test_an_unreachable_server_keeps_everything(tmp_path):
    spool = _spool(tmp_path, "a.json")
    # A port nothing listens on: bind one, note it, close it.
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    result = vf.drain(_cfg(f"http://127.0.0.1:{port}", spool, timeout=2))
    assert result.sent == []
    assert result.kept == ["a.json"]
    assert result.error
    assert (spool / "a.json").exists()


def test_main_refuses_to_start_without_the_token(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VCON_INGRESS_TOKEN", raising=False)
    spool = _spool(tmp_path)
    code = vf.main(["--spool", str(spool), "--url", "http://127.0.0.1:9", "--once"])
    assert code == 2
    assert "VCON_INGRESS_TOKEN" in capsys.readouterr().err


def test_main_once_drains_and_reports(tmp_path, monkeypatch, capsys, server):
    monkeypatch.setenv("VCON_INGRESS_TOKEN", TOKEN)
    spool = _spool(tmp_path, "a.json")
    code = vf.main(
        ["--spool", str(spool), "--url", server.url, "--ingress-list", "sipnab", "--once"]
    )
    assert code == 0
    assert "sent a.json" in capsys.readouterr().out
    assert not (spool / "a.json").exists()
