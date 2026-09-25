"""The stand-in for `tfps_ctl` that scripts/smoke-clients.sh hands sipnab.

TFPS's `ban` writes a BPF map and needs root, so no CI runner can run it. The
fake answers in the documents the real binary prints, and this holds it to
that: every line it prints carries exactly the keys, in order, of the golden
fixtures tests/tfps_contract_test.rs pins, which were checked against
`tfps_ctl --json` at sippulse/tfps 984577dc. What it adds over those canned
lines is one behavior of the real binary, read from its source at that
commit: `ban` inserts into the block list `banned` lists, and a hand ban is
not written to the audit log, so `banned` attributes it to nothing.
"""

import json
import os
import pathlib
import subprocess
import sys

TESTS = pathlib.Path(__file__).resolve().parent
FAKE = TESTS / "fake_tfps_ctl.py"
FIXTURES = TESTS.parent.parent.parent / "tests" / "fixtures"


def keys(name: str) -> list[str]:
    first = (FIXTURES / name).read_text().splitlines()[0]
    return list(json.loads(first).keys())


def run(state: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["FAKE_TFPS_STATE"] = str(state)
    return subprocess.run(
        [sys.executable, str(FAKE), *args], capture_output=True, text=True, env=env, check=False
    )


def lines(out: str) -> list[dict]:
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def test_a_ban_then_appears_in_banned_in_the_real_documents_shapes(tmp_path):
    state = tmp_path / "state.json"
    ban = run(state, "ban", "--json", "203.0.113.42", "--ttl", "0")
    assert ban.returncode == 0, ban.stderr
    [doc] = lines(ban.stdout)
    assert list(doc) == keys("tfps-ban-golden.jsonl")
    assert doc == {
        "ip": "203.0.113.42",
        "action": "ban",
        "applied": True,
        "refused": None,
        "expires": None,
        "source": "operator",
    }
    banned = run(state, "banned", "--json")
    assert banned.returncode == 0, banned.stderr
    [row] = lines(banned.stdout)
    assert list(row) == keys("tfps-banned-golden.jsonl")
    assert row == {
        "ip": "203.0.113.42",
        "reason": None,
        "detail": None,
        "first_seen": None,
        "expires": None,
        "enforced": True,
    }


def test_a_ttl_becomes_an_expiry_and_the_default_is_an_hour(tmp_path):
    state = tmp_path / "state.json"
    [with_ttl] = lines(run(state, "ban", "--json", "198.51.100.77", "--ttl", "600").stdout)
    [default] = lines(run(state, "ban", "--json", "198.51.100.78").stdout)
    assert isinstance(with_ttl["expires"], int)
    assert 3000 <= default["expires"] - with_ttl["expires"] <= 3001


def test_the_host_itself_is_refused_with_exit_1_and_the_same_document(tmp_path):
    state = tmp_path / "state.json"
    ban = run(state, "ban", "--json", "127.0.0.1")
    assert ban.returncode == 1
    [doc] = lines(ban.stdout)
    assert list(doc) == keys("tfps-ban-golden.jsonl")
    assert (doc["applied"], doc["refused"]) == (False, "local")
    assert lines(run(state, "banned", "--json").stdout) == []


def test_status_is_the_pinned_document(tmp_path):
    out = run(tmp_path / "state.json", "status", "--json")
    assert out.returncode == 0
    assert json.loads(out.stdout) == json.loads((FIXTURES / "tfps-status-golden.json").read_text())


def test_a_subcommand_the_fake_does_not_model_is_an_error_not_an_answer(tmp_path):
    out = run(tmp_path / "state.json", "dropped", "--json")
    assert out.returncode == 2
    assert "does not model" in out.stderr


def test_without_a_state_file_it_refuses_to_run(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "FAKE_TFPS"))}
    out = subprocess.run(
        [sys.executable, str(FAKE), "banned", "--json"], capture_output=True, text=True, env=env
    )
    assert out.returncode == 2
    assert "FAKE_TFPS_STATE" in out.stderr
