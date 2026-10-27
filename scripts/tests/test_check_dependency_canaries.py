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


def answer(tmp_path, stable, newest=None):
    p = tmp_path / "rsa.json"
    p.write_text(json.dumps({"crate": {"max_stable_version": stable, "max_version": newest or stable}}))
    return ["--from-json", f"rsa={p}"]


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
