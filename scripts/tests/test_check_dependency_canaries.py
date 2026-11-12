# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""scripts/check-dependency-canaries.py, against saved crates.io answers."""

import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check-dependency-canaries.py"
spec = importlib.util.spec_from_file_location("canaries", SCRIPT)
canaries = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canaries)


import pytest

# The list the script ships with, read before any test replaces it.
SHIPPED = list(canaries.CANARIES)

# The canary sipnab kept until it moved to rsa 0.10.0. The tests of the
# mechanism run against it, so they do not depend on what is awaited today.
WAITING_FOR_RSA = (
    "rsa",
    (0, 10, 0),
    "rsa {found} is stable: move rsa to it and remove the GHSA-qwgh-2vcv-g2f7 exception",
)


@pytest.fixture(autouse=True)
def one_canary(monkeypatch):
    monkeypatch.setattr(canaries, "CANARIES", [WAITING_FOR_RSA])


def answer(tmp_path, stable, newest=None):
    p = tmp_path / "rsa.json"
    p.write_text(json.dumps({"crate": {"max_stable_version": stable, "max_version": newest or stable}}))
    return ["--from-json", f"rsa={p}"]


def test_the_shipped_list_no_longer_waits_for_rsa():
    # sipnab is on rsa 0.10: a canary for it would fail the scheduled run for
    # a move that is done.
    assert "rsa" not in [name for name, _, _ in SHIPPED]


def test_an_empty_list_passes_without_asking_crates_io_and_says_so(monkeypatch, capsys):
    def no_network(name):
        raise AssertionError(f"asked crates.io about {name}")

    monkeypatch.setattr(canaries, "CANARIES", [])
    monkeypatch.setattr(canaries, "fetch", no_network)
    assert canaries.main([]) == 0
    assert "no dependency release is awaited" in capsys.readouterr().out


def test_each_shipped_canary_names_a_crate_a_version_and_what_to_do():
    for name, awaited, todo in SHIPPED:
        assert name and len(awaited) == 3 and all(isinstance(n, int) for n in awaited), (name, awaited)
        assert "{found}" in todo, name


def test_rsa_0_9_keeps_waiting(tmp_path, capsys):
    assert canaries.main(answer(tmp_path, "0.9.10")) == 0
    assert "still before 0.10.0" in capsys.readouterr().out


def test_a_release_candidate_is_not_the_awaited_release(tmp_path):
    # rsa 0.10 exists today only as 0.10.0-rc.N, which crates.io leaves out
    # of max_stable_version.
    assert canaries.main(answer(tmp_path, "0.9.10", "0.10.0-rc.19")) == 0


def test_a_stable_rsa_0_10_fires_and_says_what_to_do(tmp_path, capsys):
    assert canaries.main(answer(tmp_path, "0.10.0")) == 1
    out = capsys.readouterr().out
    assert "rsa 0.10.0 is stable" in out
    assert "GHSA-qwgh-2vcv-g2f7" in out


def test_a_later_major_fires_too(tmp_path):
    assert canaries.main(answer(tmp_path, "1.2.3")) == 1


def test_an_answer_without_a_version_is_not_a_pass(tmp_path, capsys):
    p = tmp_path / "rsa.json"
    p.write_text(json.dumps({"crate": {}}))
    assert canaries.main(["--from-json", f"rsa={p}"]) == 2
    assert "NOT CHECKED" in capsys.readouterr().err


def test_an_unreadable_answer_is_not_a_pass(tmp_path):
    assert canaries.main(["--from-json", f"rsa={tmp_path / 'missing.json'}"]) == 2
