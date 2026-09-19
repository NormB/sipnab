"""Publishing to crates.io from the release workflow.

A crates.io version can never be replaced. `cargo yank` stops new lockfiles
resolving to it and nothing removes it, so the release job decides everything
before it uploads anything, and it stops on any answer from crates.io other
than "published" (200) and "not published" (404). crates.io answers 403 to a
request without a User-Agent (measured 2026-09-18). Reading that as "not
published" would upload blind; reading it as "published" would skip a release
without a word.

The upload itself cannot be driven from a test: it is irreversible, and it
needs the OIDC token only the release job can exchange. These tests drive
everything up to it: the lookups go to a local server that answers the way
crates.io does, and the upload goes to a stand-in `cargo` that records what it
was asked to publish.
"""

import http.server
import pathlib
import subprocess
import sys
import threading
import tomllib

import pytest

from conftest import SCRIPTS, load

REPO = SCRIPTS.parent
publish = load("publish-crates")


def manifest_version(rel: str) -> str:
    with open(REPO / rel, "rb") as f:
        return tomllib.load(f)["package"]["version"]


def write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# -- which crates, in which order -------------------------------------------


def test_the_repository_publishes_its_two_crates_dependency_first():
    """sipnab depends on sipnab-bpf-types by path, so a sipnab upload whose
    dependency version is not on crates.io yet is refused. The two crates
    marked `publish = false` never go up."""
    crates = publish.publishable(REPO)
    assert [(c.name, c.version) for c in crates] == [
        ("sipnab-bpf-types", manifest_version("crates/sipnab-bpf-types/Cargo.toml")),
        ("sipnab", manifest_version("Cargo.toml")),
    ]


def test_the_order_follows_path_dependencies_not_the_members_list(tmp_path):
    """The rule, on a workspace built to break a list-order shortcut: the root
    comes first in `members`, `mid` depends on `leaf` from a target table, and
    `private` opts out."""
    write(tmp_path / "Cargo.toml", """
[workspace]
members = [".", "crates/mid", "crates/private", "crates/leaf"]

[package]
name = "root"
version = "1.2.3"

[dependencies]
mid = { version = "0.2", path = "crates/mid" }
""")
    write(tmp_path / "crates/mid/Cargo.toml", """
[package]
name = "mid"
version = "0.2.0"

[target.'cfg(unix)'.dependencies]
leaf = { version = "0.3", path = "../leaf" }
""")
    write(tmp_path / "crates/private/Cargo.toml", """
[package]
name = "private"
version = "0.0.1"
publish = false
""")
    write(tmp_path / "crates/leaf/Cargo.toml", """
[package]
name = "leaf"
version = "0.3.1"
""")
    assert [(c.name, c.version) for c in publish.publishable(tmp_path)] == [
        ("leaf", "0.3.1"),
        ("mid", "0.2.0"),
        ("root", "1.2.3"),
    ]


# -- what to upload, given what crates.io says --------------------------------

TWO = [publish.Crate("sipnab-bpf-types", "0.1.1"), publish.Crate("sipnab", "9.9.9")]


def answers(table):
    return lambda crate: table[crate.name]


def test_a_version_already_on_crates_io_is_not_uploaded_again():
    """sipnab-bpf-types is bumped only when it changes, so most releases find
    its version already published."""
    todo = publish.plan(TWO, answers({"sipnab-bpf-types": 200, "sipnab": 404}))
    assert [c.name for c in todo] == ["sipnab"]


def test_a_rerun_after_everything_is_published_uploads_nothing():
    """Re-running a release job, or a release published by hand first, is not
    an error."""
    assert publish.plan(TWO, answers({"sipnab-bpf-types": 200, "sipnab": 200})) == []


@pytest.mark.parametrize("status", [403, 429, 500, 503])
def test_any_other_answer_stops_the_plan(status):
    """Checked for every crate before any upload, so a bad answer about the
    second crate stops the first one going up too."""
    with pytest.raises(publish.PublishError, match=str(status)):
        publish.plan(TWO, answers({"sipnab-bpf-types": 404, "sipnab": status}))


# -- the script, end to end, against a stand-in crates.io and cargo -----------


class FakeCratesIo(http.server.BaseHTTPRequestHandler):
    status: dict = {}
    agents: list = []

    def do_GET(self):
        FakeCratesIo.agents.append(self.headers.get("User-Agent", ""))
        prefix = "/api/v1/crates/"
        name, _, version = self.path.removeprefix(prefix).partition("/")
        code = FakeCratesIo.status.get((name, version), 404)
        if not self.headers.get("User-Agent"):
            code = 403
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


@pytest.fixture
def crates_io():
    FakeCratesIo.status = {}
    FakeCratesIo.agents = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeCratesIo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def fake_cargo(tmp_path, fail_on=None):
    """A `cargo` that appends its arguments to a log, and fails when asked to
    publish `fail_on`."""
    log = tmp_path / "cargo.log"
    cargo = tmp_path / "cargo"
    cargo.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{log}"\n'
        + (f'case "$*" in *"-p {fail_on}"*) exit 101;; esac\n' if fail_on else "")
        + "exit 0\n"
    )
    cargo.chmod(0o755)
    return cargo, log


def run(api, cargo, tag):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "publish-crates.py"),
         "--tag", tag, "--api", api, "--cargo", str(cargo)],
        capture_output=True, text=True, timeout=60, cwd=REPO,
    )


def uploads(log: pathlib.Path):
    return log.read_text().splitlines() if log.exists() else []


SIPNAB = manifest_version("Cargo.toml")
BPF_TYPES = manifest_version("crates/sipnab-bpf-types/Cargo.toml")


def test_the_release_uploads_only_what_crates_io_lacks(crates_io, tmp_path):
    FakeCratesIo.status = {("sipnab-bpf-types", BPF_TYPES): 200}
    cargo, log = fake_cargo(tmp_path)
    out = run(crates_io, cargo, f"v{SIPNAB}")
    assert out.returncode == 0, out.stderr
    assert uploads(log) == ["publish --locked -p sipnab"]
    # crates.io refuses a request without one.
    assert FakeCratesIo.agents and all("sipnab" in ua for ua in FakeCratesIo.agents)


def test_a_new_dependency_version_goes_up_before_the_crate_that_needs_it(crates_io, tmp_path):
    cargo, log = fake_cargo(tmp_path)
    out = run(crates_io, cargo, f"v{SIPNAB}")
    assert out.returncode == 0, out.stderr
    assert uploads(log) == [
        "publish --locked -p sipnab-bpf-types",
        "publish --locked -p sipnab",
    ]


def test_a_failed_upload_stops_the_run(crates_io, tmp_path):
    """sipnab cannot be published against a sipnab-bpf-types version that did
    not go up."""
    cargo, log = fake_cargo(tmp_path, fail_on="sipnab-bpf-types")
    out = run(crates_io, cargo, f"v{SIPNAB}")
    assert out.returncode != 0
    assert uploads(log) == ["publish --locked -p sipnab-bpf-types"]


def test_an_unexpected_answer_uploads_nothing(crates_io, tmp_path):
    FakeCratesIo.status = {("sipnab", SIPNAB): 500}
    cargo, log = fake_cargo(tmp_path)
    out = run(crates_io, cargo, f"v{SIPNAB}")
    assert out.returncode != 0
    assert "500" in out.stderr
    assert uploads(log) == []


def test_the_tag_must_name_the_version_being_published(crates_io, tmp_path):
    """A tag and a manifest that disagree are a release cut wrong. Uploading
    either version would publish something the tag does not describe."""
    cargo, log = fake_cargo(tmp_path)
    out = run(crates_io, cargo, "v0.0.0")
    assert out.returncode != 0
    assert "v0.0.0" in out.stderr and SIPNAB in out.stderr
    assert uploads(log) == []
