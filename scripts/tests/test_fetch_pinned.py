# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/fetch-pinned.sh: one download, verify and retry rule for CI tools.

On 2026-11-08 github.com release downloads answered HTTP 504 from at least
08:57Z to at least 09:48Z. main's Pages deploy and the Docs, Accessibility and
Lighthouse jobs of pull requests #698 and #699 failed in their tool install
steps, each a single `curl --retry 5 --retry-delay 5` of a pinned archive:
about 25 s of retries against an outage of most of an hour.

fetch-pinned.sh is the one rule every CI tool download now goes through
(CI-TOOL-DOWNLOAD-RESILIENCE). It verifies a file already at the destination
(a restored cache entry) before it trusts it, downloads on a miss or a
mismatch, retries a transient failure with exponential backoff inside a time
budget, and exits with a status that says which kind of failure it was:

    0  the destination holds the pinned bytes
    1  every attempt failed transiently; a re-run may pass
    2  the arguments are wrong
    3  the bytes served do not match the pin; do not re-run
    4  a permanent refusal (HTTP 404, a missing file, a bad URL); fix the pin

These tests drive it against a local HTTP server that answers from a script
of responses (504s, stalls, truncated bodies, redirects) and against file://
fixtures. The real github.com is never contacted.
"""

import hashlib
import http.server
import os
import pathlib
import shutil
import socket
import subprocess
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts" / "fetch-pinned.sh"

PAYLOAD = b"pinned archive bytes\n" * 64
SHA = hashlib.sha256(PAYLOAD).hexdigest()
EMPTY_SHA = hashlib.sha256(b"").hexdigest()

# Short delays so a test that retries finishes in well under a second; the
# budget is generous so only the response script decides how many attempts run.
FAST = [
    "--first-delay", "0.01",
    "--max-delay", "0.05",
    "--budget", "20",
    "--attempt-timeout", "5",
    "--connect-timeout", "2",
]


# ---------------------------------------------------------------------------
# The scripted server
# ---------------------------------------------------------------------------


class Server:
    """A local HTTP server answering each request from a list of responses.

    Each response is a dict: `status` (default 200), `body` (default PAYLOAD),
    `stall` (seconds to wait before answering), `truncate` (declare a longer
    Content-Length than the body and close), `close` (close without any
    response) and `location` (a redirect target). After the list runs out the
    last response repeats.
    """

    def __init__(self):
        self.plans = {}
        self.requests = []
        self.lock = threading.Lock()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_GET(self):
                with outer.lock:
                    outer.requests.append(
                        {"path": self.path, "ua": self.headers.get("User-Agent", "")}
                    )
                    plan = outer.plans.get(self.path, [{"status": 404, "body": b"no plan"}])
                    r = plan.pop(0) if len(plan) > 1 else plan[0]
                if r.get("stall"):
                    time.sleep(r["stall"])
                if r.get("close"):
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                body = r.get("body", PAYLOAD)
                status = r.get("status", 200)
                try:
                    self.send_response(status)
                    if "location" in r:
                        self.send_header("Location", r["location"])
                    declared = len(body) + 4096 if r.get("truncate") else len(body)
                    self.send_header("Content-Length", str(declared))
                    self.end_headers()
                    self.wfile.write(body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    def url(self, path):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}{path}"

    def plan(self, path, *responses):
        self.plans[path] = [dict(r) for r in responses]
        return self.url(path)

    def hits(self, path):
        return sum(1 for r in self.requests if r["path"] == path)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.stop()


def run(*args, timeout=60, env=None):
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


# ---------------------------------------------------------------------------
# The virtual clock (FLAKY-FETCH-PINNED-UNDER-LOAD)
# ---------------------------------------------------------------------------
#
# fetch-pinned.sh retries only while the time spent so far plus the next delay
# fits the budget, and the time spent includes starting curl and date. The
# tests that count attempts used budgets of 0.03 s and 0.5 s of wall-clock
# time, so at load average 30 on the self-hosted runner a slow process start
# used up the slack and an attempt was dropped ("assert 3 == 4", and
# "assert 1 >= 2" for a 0.03 s budget). The counts depended on the host's
# load, not on the script.
#
# The script reads time only through `date` (now_ms) and waits only through
# `sleep`. These stubs put both on a clock kept in a file: `sleep D` adds D
# and returns at once, and every `date` read adds STEP ms after it answers,
# which stands for the cost of one attempt. An attempt count asserted on this
# clock is the same at any load.

REAL_DATE = shutil.which("date")
VCLOCK_START_MS = 1_700_000_000_000

DATE_STUB = f"""#!/usr/bin/env bash
case "$*" in
  +%s%3N | +%s) ;;
  *) exec {REAL_DATE} "$@" ;;
esac
read -r t < "$VCLOCK"
if [ "$1" = +%s ]; then echo $((t / 1000)); else echo "$t"; fi
echo $((t + ${{VCLOCK_STEP_MS:-0}})) > "$VCLOCK"
"""

SLEEP_STUB = """#!/usr/bin/env bash
v=$1 int=${1%%.*} frac=""
if [ "$int" != "$v" ]; then frac=${v#*.}; fi
while [ ${#frac} -lt 3 ]; do frac="${frac}0"; done
read -r t < "$VCLOCK"
echo $((t + 10#${int:-0} * 1000 + 10#${frac:0:3})) > "$VCLOCK"
echo "$v" >> "$VCLOCK.sleeps"
"""


class Clock:
    def __init__(self, base):
        self.dir = base / "vclock-bin"
        self.dir.mkdir()
        self.file = base / "vclock"
        self.file.write_text(f"{VCLOCK_START_MS}\n")
        for name, body in (("date", DATE_STUB), ("sleep", SLEEP_STUB)):
            stub = self.dir / name
            stub.write_text(body)
            stub.chmod(0o755)

    def env(self, step_ms=0, extra_path=None):
        e = dict(os.environ)
        path = [str(self.dir)] + ([str(extra_path)] if extra_path else [])
        e["PATH"] = os.pathsep.join(path + [e.get("PATH", "")])
        e["VCLOCK"] = str(self.file)
        e["VCLOCK_STEP_MS"] = str(step_ms)
        return e

    def sleeps(self):
        f = pathlib.Path(f"{self.file}.sleeps")
        return f.read_text().split() if f.exists() else []

    def elapsed_ms(self):
        return int(self.file.read_text()) - VCLOCK_START_MS


@pytest.fixture
def clock(tmp_path):
    return Clock(tmp_path)


def slow_curl(base, seconds):
    """A curl on PATH that waits SECONDS of real time before each attempt:
    what a process start costs at load average 30, made certain."""
    d = base / "slow-curl-bin"
    d.mkdir()
    stub = d / "curl"
    stub.write_text(f"#!/usr/bin/env bash\n{shutil.which('sleep')} {seconds}\nexec {shutil.which('curl')} \"$@\"\n")
    stub.chmod(0o755)
    return d


def fetch(url, dest, sha=SHA, *extra):
    return run("--url", url, "--sha256", sha, "--dest", str(dest), *FAST, *extra)


def leftovers(directory, dest_name):
    """Files in `directory` other than the destination itself."""
    return sorted(p.name for p in pathlib.Path(directory).iterdir() if p.name != dest_name)


def schedule(*args):
    r = run("--print-schedule", *args)
    assert r.returncode == 0, r.stderr
    return r.stdout.split()


# ---------------------------------------------------------------------------
# SUCCESS: the destination ends up holding the pinned bytes
# ---------------------------------------------------------------------------


def test_success_a_fresh_download_with_the_pinned_hash(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "a.tgz"
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD
    assert server.hits("/a.tgz") == 1


def test_success_creates_the_missing_parent_directories(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "one" / "two" / "a.tgz"
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD


def test_success_after_one_504(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 504, "body": b"gateway"}, {"status": 200})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 2


def test_success_after_five_504s_in_a_row(server, tmp_path):
    # The old step gave up after six attempts 5 s apart. Recovery after N
    # failures is the property that rescues an outage.
    url = server.plan("/a.tgz", *[{"status": 504, "body": b"gw"}] * 5, {"status": 200})
    dest = tmp_path / "a.tgz"
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 6
    assert dest.read_bytes() == PAYLOAD


def test_success_after_a_mix_of_500_502_and_503(server, tmp_path):
    url = server.plan(
        "/a.tgz",
        {"status": 500, "body": b"x"},
        {"status": 502, "body": b"x"},
        {"status": 503, "body": b"x"},
        {"status": 200},
    )
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 4


def test_success_after_a_429_rate_limit(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 429, "body": b"slow down"}, {"status": 200})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 2


def test_success_after_a_408_request_timeout(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 408, "body": b"late"}, {"status": 200})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 2


def test_success_after_an_attempt_that_stalls_past_its_timeout(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200, "stall": 3}, {"status": 200})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.01", "--budget", "20", "--attempt-timeout", "1",
    )
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 2


def test_success_after_a_transfer_cut_short_of_its_content_length(server, tmp_path):
    url = server.plan(
        "/a.tgz", {"status": 200, "body": PAYLOAD[:100], "truncate": True}, {"status": 200}
    )
    dest = tmp_path / "a.tgz"
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD
    assert server.hits("/a.tgz") == 2


def test_success_after_a_connection_closed_with_no_reply(server, tmp_path):
    url = server.plan("/a.tgz", {"close": True}, {"status": 200})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 2


def test_success_a_verified_cache_hit_makes_no_request(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "a.tgz"
    dest.write_bytes(PAYLOAD)
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 0
    assert "restored from the cache" in r.stdout


def test_success_a_corrupted_cache_hit_is_replaced_by_a_download(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "a.tgz"
    dest.write_bytes(b"X" + PAYLOAD[1:])
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD
    assert server.hits("/a.tgz") == 1
    assert "does not match" in r.stderr


def test_success_a_truncated_cache_hit_is_replaced_by_a_download(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "a.tgz"
    dest.write_bytes(PAYLOAD[:10])
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD


def test_success_follows_a_redirect_to_the_asset_host(server, tmp_path):
    # github.com/<o>/<r>/releases/download/... answers 302 to the asset host.
    target = server.plan("/asset", {"status": 200})
    url = server.plan("/release", {"status": 302, "body": b"", "location": target})
    dest = tmp_path / "a.tgz"
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD
    assert server.hits("/asset") == 1


def test_success_a_file_url_fixture(tmp_path):
    src = tmp_path / "src" / "a.tgz"
    src.parent.mkdir()
    src.write_bytes(PAYLOAD)
    dest = tmp_path / "out" / "a.tgz"
    r = fetch(src.as_uri(), dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD


def test_success_reports_the_attempt_that_succeeded(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 504, "body": b"x"}, {"status": 504, "body": b"x"}, {"status": 200})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 0, r.stderr
    assert "attempt 3" in r.stdout


def test_success_the_destination_is_replaced_not_appended(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "a.tgz"
    dest.write_bytes(b"stale bytes that are longer than nothing" * 1000)
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD


# ---------------------------------------------------------------------------
# FAILURE: the step fails, says why, and leaves nothing to be trusted later
# ---------------------------------------------------------------------------


def test_failure_504_for_the_whole_budget_exits_1_naming_url_and_status(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 504, "body": b"gw"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.01", "--max-delay", "0.02", "--budget", "0.1",
    )
    assert r.returncode == 1, r.stderr
    assert url in r.stderr
    assert "HTTP 504" in r.stderr
    assert not (tmp_path / "a.tgz").exists()


def test_failure_the_attempts_are_the_ones_the_schedule_allows(server, tmp_path, clock):
    # budget 0.5 with delays 0.05, 0.1, 0.2: their 0.35 s fits, the next 0.4
    # does not, so four attempts and then the error. On the virtual clock an
    # attempt costs nothing, so the count is the schedule's at any load.
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.05", "--max-delay", "10", "--budget", "0.5",
        env=clock.env(),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 4
    assert "4 attempts" in r.stderr
    assert clock.sleeps() == ["0.05", "0.1", "0.2"]


def test_failure_404_is_permanent_after_one_attempt(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 404, "body": b"Not Found"})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 4, r.stderr
    assert server.hits("/a.tgz") == 1
    assert "HTTP 404" in r.stderr
    assert url in r.stderr


def test_failure_403_is_permanent_after_one_attempt(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 403, "body": b"Forbidden"})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 4, r.stderr
    assert server.hits("/a.tgz") == 1
    assert "HTTP 403" in r.stderr


def test_failure_a_wrong_hash_exits_3_and_is_not_retried(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200, "body": b"substituted bytes"})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 3, r.stderr
    assert server.hits("/a.tgz") == 1
    assert not (tmp_path / "a.tgz").exists()


def test_failure_a_wrong_hash_names_the_expected_and_the_served_hash(server, tmp_path):
    body = b"substituted bytes"
    url = server.plan("/a.tgz", {"status": 200, "body": body})
    r = fetch(url, tmp_path / "a.tgz")
    assert SHA in r.stderr
    assert hashlib.sha256(body).hexdigest() in r.stderr
    assert url in r.stderr


def test_failure_a_truncated_archive_served_as_complete_exits_3(server, tmp_path):
    # Content-Length matches the short body, so the transfer itself succeeds;
    # only the hash can tell.
    url = server.plan("/a.tgz", {"status": 200, "body": PAYLOAD[:-7]})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 3, r.stderr
    assert not (tmp_path / "a.tgz").exists()


def test_failure_stalls_for_the_whole_budget_exit_1_naming_the_timeout(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200, "stall": 5})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.01", "--budget", "1", "--attempt-timeout", "1",
    )
    assert r.returncode == 1, r.stderr
    assert "timed out" in r.stderr


def test_failure_a_wrong_hash_leaves_no_partial_file(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200, "body": b"wrong"})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 3, r.stderr
    assert leftovers(tmp_path, "a.tgz") == []


def test_failure_a_corrupted_cache_and_an_outage_removes_the_corrupted_file(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 504, "body": b"gw"})
    dest = tmp_path / "a.tgz"
    dest.write_bytes(b"corrupted")
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(dest),
        "--first-delay", "0.01", "--budget", "0.05",
    )
    assert r.returncode == 1, r.stderr
    assert not dest.exists()


def test_failure_a_missing_file_url_is_permanent(tmp_path):
    missing = tmp_path / "nowhere.tgz"
    r = fetch(missing.as_uri(), tmp_path / "a.tgz")
    assert r.returncode == 4, r.stderr
    assert missing.as_uri() in r.stderr


def test_failure_an_unsupported_scheme_is_permanent(tmp_path):
    r = fetch("gopherz://example.invalid/a.tgz", tmp_path / "a.tgz")
    assert r.returncode == 4, r.stderr


def test_failure_no_url_is_a_usage_error(tmp_path):
    r = run("--sha256", SHA, "--dest", str(tmp_path / "a"))
    assert r.returncode == 2
    assert "--url" in r.stderr


def test_failure_no_sha256_is_a_usage_error(tmp_path):
    r = run("--url", "file:///dev/null", "--dest", str(tmp_path / "a"))
    assert r.returncode == 2
    assert "--sha256" in r.stderr


def test_failure_no_dest_is_a_usage_error():
    r = run("--url", "file:///dev/null", "--sha256", SHA)
    assert r.returncode == 2
    assert "--dest" in r.stderr


def test_failure_a_short_sha256_is_a_usage_error(tmp_path):
    r = run("--url", "file:///dev/null", "--sha256", SHA[:63], "--dest", str(tmp_path / "a"))
    assert r.returncode == 2
    assert "64" in r.stderr


def test_failure_an_uppercase_sha256_is_a_usage_error(tmp_path):
    # Every pin in the workflows is lowercase and a test holds them to it;
    # sha256sum prints lowercase, so an uppercase pin would never match.
    r = run("--url", "file:///dev/null", "--sha256", SHA.upper(), "--dest", str(tmp_path / "a"))
    assert r.returncode == 2


def test_failure_a_non_numeric_budget_is_a_usage_error(tmp_path):
    r = run(
        "--url", "file:///dev/null", "--sha256", SHA, "--dest", str(tmp_path / "a"),
        "--budget", "five",
    )
    assert r.returncode == 2
    assert "--budget" in r.stderr


def test_failure_an_unknown_option_is_a_usage_error(tmp_path):
    r = run("--url", "file:///dev/null", "--sha256", SHA, "--dest", str(tmp_path / "a"), "--retry", "5")
    assert r.returncode == 2
    assert "--retry" in r.stderr


def test_failure_a_directory_as_the_destination_is_a_usage_error(tmp_path):
    r = run("--url", "file:///dev/null", "--sha256", SHA, "--dest", str(tmp_path))
    assert r.returncode == 2


def test_failure_an_option_missing_its_value_is_a_usage_error(tmp_path):
    r = run("--url", "file:///dev/null", "--sha256", SHA, "--dest")
    assert r.returncode == 2


def test_failure_a_zero_first_delay_is_a_usage_error(tmp_path):
    # A zero delay never grows, so the schedule would never end.
    r = run(
        "--url", "file:///dev/null", "--sha256", SHA, "--dest", str(tmp_path / "a"),
        "--first-delay", "0",
    )
    assert r.returncode == 2
    assert "--first-delay" in r.stderr


def test_failure_the_error_is_a_github_annotation(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 404, "body": b"x"})
    r = fetch(url, tmp_path / "a.tgz")
    assert any(line.startswith("::error::") for line in r.stderr.splitlines()), r.stderr


# ---------------------------------------------------------------------------
# EDGE: the schedule, the budget and the boundaries
# ---------------------------------------------------------------------------


def test_edge_the_default_schedule_doubles_from_5_to_a_60_s_cap_within_300_s():
    assert schedule() == ["5", "10", "20", "40", "60", "60", "60"]


def test_edge_the_schedule_stops_at_the_max_delay():
    assert schedule("--first-delay", "1", "--max-delay", "3", "--budget", "12") == [
        "1", "2", "3", "3", "3",
    ]


def test_edge_a_max_delay_below_the_first_delay_caps_every_delay():
    assert schedule("--first-delay", "10", "--max-delay", "2", "--budget", "7") == [
        "2", "2", "2",
    ]


def test_edge_a_budget_shorter_than_the_first_delay_allows_no_retry():
    assert schedule("--first-delay", "5", "--budget", "4") == []
    # The boundary: a delay that exactly fills the budget is still taken.
    assert schedule("--first-delay", "5", "--budget", "5") == ["5"]


def test_edge_the_schedule_never_sums_past_the_budget():
    for first, cap, budget in [("1", "60", "300"), ("0.25", "4", "9.9"), ("3", "3", "8"), ("7", "100", "1000")]:
        delays = [float(d) for d in schedule("--first-delay", first, "--max-delay", cap, "--budget", budget)]
        assert sum(delays) <= float(budget) + 1e-9, (first, cap, budget, delays)
        nxt = min(float(cap), (delays[-1] * 2) if delays else float(first))
        assert sum(delays) + nxt > float(budget), (first, cap, budget, delays)


def test_edge_millisecond_delays_are_printed_exactly():
    assert schedule("--first-delay", "0.05", "--max-delay", "0.2", "--budget", "0.5") == [
        "0.05", "0.1", "0.2",
    ]


def test_edge_a_zero_budget_makes_exactly_one_attempt(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 504, "body": b"x"})
    r = run("--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"), "--budget", "0")
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 1


def test_edge_time_spent_in_stalled_attempts_counts_against_the_budget(server, tmp_path):
    # Real time, on purpose: this is the test that curl's own time is counted.
    # Delays 0.1, 0.2, 0.4 fit a 1.2 s budget, so the schedule alone allows
    # four attempts. Each stalled attempt takes its 0.5 s timeout, and after
    # the second the 1.1 s spent plus the 0.2 s delay passes the budget. Load
    # only adds time, so it can only lower the count: the bound is an upper
    # one, and anything below the schedule's four proves the time counted.
    url = server.plan("/a.tgz", {"status": 200, "stall": 3})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.1", "--max-delay", "10", "--budget", "1.2",
        "--attempt-timeout", "0.5",
    )
    assert r.returncode == 1, r.stderr
    assert 1 <= server.hits("/a.tgz") <= 2


def test_edge_the_cost_of_each_attempt_counts_against_the_budget(server, tmp_path, clock):
    # The virtual-clock form of the test above: each attempt costs 500 ms, so
    # after the second the 1.1 s spent plus the 0.2 s delay passes 1.2 s.
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.1", "--max-delay", "10", "--budget", "1.2",
        env=clock.env(step_ms=500),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 2
    assert clock.sleeps() == ["0.1"]


def test_edge_an_empty_file_with_the_empty_hash_is_valid(server, tmp_path):
    url = server.plan("/empty", {"status": 200, "body": b""})
    dest = tmp_path / "empty"
    r = fetch(url, dest, EMPTY_SHA)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == b""


def test_edge_a_destination_path_with_spaces(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "with space" / "a b.tgz"
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert dest.read_bytes() == PAYLOAD


def test_edge_a_cached_file_of_the_right_size_but_wrong_bytes_is_not_trusted(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "a.tgz"
    dest.write_bytes(bytes(len(PAYLOAD)))
    r = fetch(url, dest)
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 1
    assert dest.read_bytes() == PAYLOAD


def test_edge_the_user_agent_carries_no_email_address(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    fetch(url, tmp_path / "a.tgz")
    assert server.requests, "no request reached the server"
    for req in server.requests:
        assert "@" not in req["ua"], req["ua"]


def test_edge_no_temporary_file_is_left_after_a_success(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 504, "body": b"x"}, {"status": 200})
    r = fetch(url, tmp_path / "a.tgz")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "a.tgz").read_bytes() == PAYLOAD
    assert leftovers(tmp_path, "a.tgz") == []


def test_edge_no_temporary_file_is_left_after_an_exhausted_outage(server, tmp_path, clock):
    # Delays 0.01 and 0.02 exactly fill the 0.03 s budget: three attempts.
    url = server.plan("/a.tgz", {"status": 504, "body": b"x"})
    dest_dir = tmp_path / "dl"
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(dest_dir / "a.tgz"),
        "--first-delay", "0.01", "--budget", "0.03", env=clock.env(),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 3
    assert leftovers(dest_dir, "a.tgz") == []


def test_edge_a_504_body_is_never_left_as_the_destination(server, tmp_path):
    # Without --fail curl would write the gateway's HTML page to the output.
    url = server.plan("/a.tgz", {"status": 504, "body": b"<html>504</html>"})
    dest = tmp_path / "a.tgz"
    r = run("--url", url, "--sha256", SHA, "--dest", str(dest), "--budget", "0")
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 1
    assert not dest.exists()


def test_edge_a_cache_hit_says_it_came_from_the_cache_and_a_miss_says_it_downloaded(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 200})
    dest = tmp_path / "a.tgz"
    miss = fetch(url, dest)
    hit = fetch(url, dest)
    # The phrases, not the bare words: the pytest directory name holds "cache".
    assert "fetch-pinned: downloaded " in miss.stdout, miss.stdout
    assert "restored from the cache" not in miss.stdout, miss.stdout
    assert "restored from the cache" in hit.stdout, hit.stdout
    assert "fetch-pinned: downloaded " not in hit.stdout, hit.stdout


def test_edge_the_retry_message_names_the_status_and_the_next_delay(server, tmp_path):
    url = server.plan("/a.tgz", {"status": 502, "body": b"x"}, {"status": 200})
    r = run("--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"), "--first-delay", "0.02", "--budget", "5")
    assert r.returncode == 0, r.stderr
    assert "HTTP 502" in r.stderr
    assert "0.02" in r.stderr


# ---------------------------------------------------------------------------
# FLAKY-FETCH-PINNED-UNDER-LOAD: attempt counts do not depend on the load
# ---------------------------------------------------------------------------


def test_success_a_slow_process_start_does_not_change_the_attempt_count(server, tmp_path, clock):
    # 150 ms of real time before every curl, ten times the slack the old
    # wall-clock version of the schedule test had per attempt.
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.05", "--max-delay", "10", "--budget", "0.5",
        env=clock.env(extra_path=slow_curl(tmp_path, 0.15)),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 4


def test_success_a_slow_process_start_still_reaches_the_answer_after_retries(server, tmp_path, clock):
    url = server.plan("/a.tgz", {"status": 504, "body": b"x"}, {"status": 504, "body": b"x"}, {"status": 200})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.01", "--max-delay", "0.02", "--budget", "0.03",
        env=clock.env(extra_path=slow_curl(tmp_path, 0.15)),
    )
    assert r.returncode == 0, r.stderr
    assert server.hits("/a.tgz") == 3
    assert (tmp_path / "a.tgz").read_bytes() == PAYLOAD


def test_success_the_virtual_clock_sees_every_delay_the_script_waits(server, tmp_path, clock):
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "1", "--max-delay", "4", "--budget", "15",
        env=clock.env(),
    )
    assert clock.sleeps() == ["1", "2", "4", "4", "4"]
    assert clock.elapsed_ms() == 15_000


def test_failure_the_script_reads_its_time_through_date(server, tmp_path, clock):
    # If the script stopped reading time through `date` (EPOCHREALTIME, say),
    # the virtual clock would be bypassed and the counting tests would depend
    # on the load again. A first attempt that costs 1 s on the virtual clock
    # leaves no room in a 0.5 s budget.
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.05", "--budget", "0.5",
        env=clock.env(step_ms=1000),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 1
    assert "1 attempt " in r.stderr


def test_failure_the_script_waits_through_sleep(server, tmp_path, clock):
    # A 30 s first delay on the virtual clock returns at once; a script that
    # waited any other way would hit the 10 s subprocess timeout.
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"}, {"status": 200})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "30", "--max-delay", "30", "--budget", "40",
        env=clock.env(), timeout=10,
    )
    assert r.returncode == 0, r.stderr
    assert clock.sleeps() == ["30"]


def test_failure_the_error_reports_the_time_spent_on_the_clock(server, tmp_path, clock):
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.05", "--max-delay", "10", "--budget", "0.5",
        env=clock.env(),
    )
    assert r.returncode == 1, r.stderr
    assert "over 0.35 s (budget 0.5 s)" in r.stderr


def test_edge_a_delay_that_exactly_fills_the_rest_of_the_budget_is_taken(server, tmp_path, clock):
    # Attempts cost 100 ms: after the first, 0.1 + 0.4 = 0.5 is the budget
    # exactly and is taken; after the second, 0.6 + 0.8 is not.
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.4", "--max-delay", "10", "--budget", "0.5",
        env=clock.env(step_ms=100),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 2


def test_edge_one_millisecond_over_the_budget_is_not_taken(server, tmp_path, clock):
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "0.4", "--max-delay", "10", "--budget", "0.5",
        env=clock.env(step_ms=101),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 1


def test_edge_whole_second_clocks_still_bound_the_attempts(server, tmp_path, clock):
    # Where date has no %N (macOS) the script falls back to whole seconds.
    # The stub answers +%s for that form; this drives the fallback by making
    # +%s%3N fail.
    stub = clock.dir / "date"
    stub.write_text(stub.read_text().replace("+%s%3N | +%s) ;;", "+%s) ;;\n  +%s%3N) exit 1 ;;"))
    url = server.plan("/a.tgz", {"status": 503, "body": b"x"})
    r = run(
        "--url", url, "--sha256", SHA, "--dest", str(tmp_path / "a.tgz"),
        "--first-delay", "1", "--max-delay", "1", "--budget", "3",
        env=clock.env(),
    )
    assert r.returncode == 1, r.stderr
    assert server.hits("/a.tgz") == 4

