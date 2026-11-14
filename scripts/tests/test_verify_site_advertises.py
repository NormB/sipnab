# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/verify-site-advertises.sh: the read itself, with a stand-in curl.

tests/site_liveness_test.rs drives the verdicts through `--classify`. These
tests drive the fetch: on 2026-11-14 the CDN answered 403 to the release check
from a hosted runner (CDN-REFUSED-RELEASE-CHECK-FROM-RUNNER) and the log held
one word of it, the status. The cause could not be read from the run: no
`server`, `cf-ray` or `cf-mitigated` header and no byte of the body was kept,
and each check sent two requests where one answers both questions.

No test here reaches a network: `curl` is a script on PATH that writes the
canned headers and body where the real one would, and logs its arguments.
"""

import os
import subprocess

import pytest

from conftest import SCRIPTS

VERIFIER = SCRIPTS / "verify-site-advertises.sh"
URL = "https://sipnab.example.invalid/download/"
PAGE = "<html><body><h1>Download</h1><p>sipnab 0.5.254</p><p>sha256 checksums</p></body></html>\n"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head>\n<body>error code: 1010\x07 " + "x" * 400
HEAD_OK = "HTTP/2 200 \r\nserver: cloudflare\r\ncontent-type: text/html; charset=utf-8\r\ncf-ray: 8e1a2b3c4d5e6f70-IAD\r\n\r\n"
HEAD_403 = ("HTTP/2 403 \r\nServer: cloudflare\r\nContent-Type: text/html; charset=UTF-8\r\n"
            "CF-RAY: 8e1a2b3c4d5e6f71-IAD\r\ncf-mitigated: challenge\r\n\r\n")

CURL = """#!/bin/sh
# A stand-in curl: logs its arguments, writes the canned answer where -D and
# -o point, prints the canned status for -w, exits with the canned status.
printf '%s\\n' "$*" >> "$FAKE/calls"
while [ $# -gt 0 ]; do
  case "$1" in
    -D) cp "$FAKE/head" "$2" 2>/dev/null; shift ;;
    -o) cp "$FAKE/body" "$2" 2>/dev/null; shift ;;
  esac
  shift
done
printf '%s' "$(cat "$FAKE/status")"
exit "$(cat "$FAKE/exit")"
"""


class Edge:
    """What the stand-in curl answers, and what the verifier did with it."""

    def __init__(self, tmp_path):
        self.dir = tmp_path / "fake"
        (self.dir / "bin").mkdir(parents=True)
        curl = self.dir / "bin" / "curl"
        curl.write_text(CURL)
        curl.chmod(0o755)
        self.tmp = tmp_path / "tmp"
        self.tmp.mkdir()
        self.answer(200, HEAD_OK, PAGE)

    def answer(self, status, head, body, curl_exit=0):
        (self.dir / "status").write_text(f"{status:03d}" if isinstance(status, int) else status)
        (self.dir / "exit").write_text(str(curl_exit))
        for name, text in (("head", head), ("body", body)):
            if text is None:
                (self.dir / name).unlink(missing_ok=True)
            else:
                (self.dir / name).write_bytes(text.encode() if isinstance(text, str) else text)

    def check(self, version="0.5.254"):
        env = dict(os.environ, FAKE=str(self.dir), TMPDIR=str(self.tmp),
                   PATH=f"{self.dir / 'bin'}:{os.environ['PATH']}")
        r = subprocess.run(["sh", str(VERIFIER), version, URL], env=env, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout

    def calls(self):
        log = self.dir / "calls"
        return log.read_text().splitlines() if log.exists() else []


@pytest.fixture
def edge(tmp_path):
    return Edge(tmp_path)


def edge_line(out):
    lines = [line for line in out.splitlines() if line.startswith("edge: status=")]
    assert len(lines) == 1, out
    return lines[0]


# --- success ---------------------------------------------------------------


def test_success_a_page_that_names_the_release_is_ok(edge):
    rc, out = edge.check()
    assert rc == 0 and "OK: the page names 0.5.254." in out, out


def test_success_one_check_is_one_request(edge):
    edge.check()
    assert len(edge.calls()) == 1, edge.calls()


def test_success_the_status_and_the_body_come_from_the_same_response(edge):
    edge.check()
    call = edge.calls()[0]
    assert " -o " in call and " -D " in call and "%{http_code}" in call, call


def test_success_the_request_names_its_client_and_the_url(edge):
    edge.check()
    call = edge.calls()[0]
    assert "--user-agent sipnab-release-check/1.0 (+https://github.com/NormB/sipnab)" in call, call
    assert call.endswith(URL), call


def test_success_the_request_is_bounded(edge):
    edge.check()
    assert "--max-time 20" in edge.calls()[0]


def test_success_an_answered_read_logs_what_the_edge_said(edge):
    _, out = edge.check()
    assert edge_line(out) == ("edge: status=200 server=cloudflare cf-ray=8e1a2b3c4d5e6f70-IAD "
                              "cf-mitigated=- content-type=text/html; charset=utf-8"), out


def test_success_the_edge_line_comes_before_the_verdict(edge):
    _, out = edge.check()
    assert out.index("edge: status=") < out.index("OK: the page names"), out


def test_success_a_refused_read_logs_the_headers_that_name_the_refusal(edge):
    edge.answer(403, HEAD_403, CHALLENGE)
    _, out = edge.check()
    assert edge_line(out) == ("edge: status=403 server=cloudflare cf-ray=8e1a2b3c4d5e6f71-IAD "
                              "cf-mitigated=challenge content-type=text/html; charset=UTF-8"), out


def test_success_a_refused_read_logs_the_start_of_the_body(edge):
    edge.answer(403, HEAD_403, CHALLENGE)
    _, out = edge.check()
    body = [line for line in out.splitlines() if line.startswith("edge: first 200 bytes: ")]
    assert len(body) == 1 and "Just a moment..." in body[0] and "error code: 1010" in body[0], out


def test_success_a_rate_limited_read_logs_its_body_too(edge):
    edge.answer(429, HEAD_403.replace("403", "429"), "error code: 1015\n")
    rc, out = edge.check()
    assert rc == 6 and "edge: first 200 bytes: error code: 1015" in out, out


def test_success_an_error_status_logs_its_body(edge):
    edge.answer(503, HEAD_OK.replace("200", "503"), "upstream connect error\n")
    rc, out = edge.check()
    assert rc == 4 and "edge: first 200 bytes: upstream connect error" in out, out


def test_success_the_temporary_files_are_removed(edge):
    edge.check()
    assert list(edge.tmp.iterdir()) == []


# --- failure ---------------------------------------------------------------


def test_failure_a_refused_read_is_blocked(edge):
    edge.answer(403, HEAD_403, CHALLENGE)
    rc, out = edge.check()
    assert rc == 6 and "BLOCKED: the edge refused this client (403)." in out, out


def test_failure_a_refused_read_is_still_one_request(edge):
    edge.answer(403, HEAD_403, CHALLENGE)
    edge.check()
    assert len(edge.calls()) == 1, edge.calls()


def test_failure_a_refusal_whose_body_names_the_release_is_still_blocked(edge):
    edge.answer(403, HEAD_403, PAGE)
    rc, out = edge.check()
    assert rc == 6 and "OK: the page names" not in out, out


def test_failure_a_page_that_names_another_release_is_stale(edge):
    rc, out = edge.check("0.5.255")
    assert rc == 1 and "STALE: the page is healthy and does not name 0.5.255." in out, out


def test_failure_a_host_that_did_not_answer_is_unreachable(edge):
    edge.answer(0, None, None, curl_exit=6)
    rc, out = edge.check()
    assert rc == 2 and "UNREACHABLE: the host did not answer." in out, out


def test_failure_an_unreachable_host_logs_status_000_and_no_headers(edge):
    edge.answer(0, None, None, curl_exit=6)
    _, out = edge.check()
    assert edge_line(out) == "edge: status=000 server=- cf-ray=- cf-mitigated=- content-type=-", out


def test_failure_a_curl_that_prints_no_status_is_unreachable(edge):
    edge.answer("", None, None, curl_exit=7)
    rc, out = edge.check()
    assert rc == 2 and "edge: status=000 " in out, out


def test_failure_a_200_with_no_body_is_empty(edge):
    edge.answer(200, HEAD_OK, "")
    rc, out = edge.check()
    assert rc == 5 and "EMPTY: 200 with no body." in out, out


def test_failure_an_origin_the_cdn_cannot_validate_is_tls(edge):
    edge.answer(526, HEAD_OK.replace("200", "526"), "error code: 526\n")
    rc, out = edge.check()
    assert rc == 3 and "TLS: the CDN could not validate the origin certificate (526)." in out, out


def test_failure_the_temporary_files_are_removed_after_a_refusal(edge):
    edge.answer(403, HEAD_403, CHALLENGE)
    edge.check()
    assert list(edge.tmp.iterdir()) == []


def test_failure_no_version_is_a_usage_error_and_no_request(edge):
    env = dict(os.environ, FAKE=str(edge.dir), PATH=f"{edge.dir / 'bin'}:{os.environ['PATH']}")
    r = subprocess.run(["sh", str(VERIFIER)], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 64 and edge.calls() == [], r.stderr


# --- edge ------------------------------------------------------------------


def test_edge_an_answered_read_logs_no_body_bytes(edge):
    _, out = edge.check()
    assert "first 200 bytes" not in out, out


def test_edge_the_body_excerpt_is_200_bytes_at_most(edge):
    edge.answer(403, HEAD_403, CHALLENGE)
    _, out = edge.check()
    line = next(line for line in out.splitlines() if line.startswith("edge: first 200 bytes: "))
    assert len(line) - len("edge: first 200 bytes: ") <= 200, line
    assert line.endswith("x"), "the excerpt is cut, not dropped"


def test_edge_the_body_excerpt_is_one_printable_line(edge):
    edge.answer(403, HEAD_403, CHALLENGE)
    _, out = edge.check()
    line = next(line for line in out.splitlines() if line.startswith("edge: first 200 bytes: "))
    assert "\x07" not in line and all(32 <= ord(c) < 127 for c in line), repr(line)
    assert "</head> <body>" in line, "a line end in the body is a space in the excerpt"


def test_edge_a_refusal_with_no_body_logs_no_excerpt(edge):
    edge.answer(403, HEAD_403, "")
    rc, out = edge.check()
    assert rc == 6 and "first 200 bytes" not in out, out


def test_edge_header_names_are_read_whatever_their_case(edge):
    edge.answer(403, HEAD_403.upper().replace("HTTP/2 403", "HTTP/2 403"), CHALLENGE)
    _, out = edge.check()
    assert "server=CLOUDFLARE" in out and "cf-mitigated=CHALLENGE" in out, out


def test_edge_a_header_the_answer_lacks_is_a_dash(edge):
    edge.answer(200, "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n", PAGE)
    _, out = edge.check()
    assert edge_line(out) == "edge: status=200 server=- cf-ray=- cf-mitigated=- content-type=text/html", out


def test_edge_of_two_header_blocks_the_last_one_is_logged(edge):
    edge.answer(200, "HTTP/1.1 103 Early Hints\r\nserver: early\r\ncf-mitigated: early\r\n\r\n" + HEAD_OK, PAGE)
    _, out = edge.check()
    assert "server=cloudflare" in out and "server=early" not in out, out
    assert "cf-mitigated=- " in out, "a header of an earlier block is not the answer's"


def test_edge_a_header_value_with_a_colon_is_kept_whole(edge):
    edge.answer(200, "HTTP/2 200 \r\nserver: a:b: c\r\n\r\n", PAGE)
    _, out = edge.check()
    assert "server=a:b: c " in out, out


def test_edge_a_body_with_no_final_line_end_is_read(edge):
    edge.answer(200, HEAD_OK, PAGE.rstrip("\n"))
    rc, out = edge.check()
    assert rc == 0, out


def test_edge_a_page_of_many_lines_is_read_whole(edge):
    edge.answer(200, HEAD_OK, "<html>\n" + "<p>filler</p>\n" * 500 + "<p>download sipnab 0.5.254</p>\n")
    rc, out = edge.check()
    assert rc == 0, out


def test_edge_the_classify_mode_makes_no_request(edge):
    env = dict(os.environ, FAKE=str(edge.dir), PATH=f"{edge.dir / 'bin'}:{os.environ['PATH']}")
    r = subprocess.run(["sh", str(VERIFIER), "--classify", "0.5.254"], env=env, input="200\n" + PAGE,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and edge.calls() == [] and "edge:" not in r.stdout, r.stdout
