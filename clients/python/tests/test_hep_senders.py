"""The REST client that shows who is feeding a HEP collector.

A collector fed by several agents answers "is everyone sending?" only if it
names each sender, and "is anyone being turned away?" only if it reports what
it refused. Both halves come from one route, `GET /v1/hep/senders`.
"""

import importlib.util
import pathlib
import sys

import pytest

CLIENTS = pathlib.Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


hs = _load("hep_senders")


def sender(capture_id: int, packets: int, silent: bool = False) -> dict:
    return {
        "source": f"hep:{capture_id}@127.0.0.1",
        "capture_id": capture_id,
        "peer": "127.0.0.1",
        "identity": "claimed_by_sender",
        "trust": "unauthenticated",
        "packets": packets,
        "idle_seconds": 0,
        "silent": silent,
    }


def roster(**extra) -> dict:
    report = {
        "listening": True,
        "trust": "unauthenticated",
        "packets_admitted": 30,
        "packets_refused": 0,
        "senders": [sender(101, 23), sender(102, 7)],
        "refused_sources": [],
    }
    report.update(extra)
    return report


def test_each_sender_is_one_line_with_its_claimed_id_and_its_count():
    lines = hs.render(roster())
    assert "hep:101@127.0.0.1  capture id 101  23 packets" in lines
    assert "hep:102@127.0.0.1  capture id 102  7 packets" in lines
    assert lines[-1] == "2 sender(s), 30 packet(s) admitted, 0 refused"


def test_a_silent_sender_says_so():
    lines = hs.render(roster(senders=[sender(101, 23, silent=True)]))
    assert "hep:101@127.0.0.1  capture id 101  23 packets  SILENT" in lines


def test_refused_packets_are_reported_by_source_and_reason():
    lines = hs.render(
        roster(
            packets_refused=4,
            refused_sources=[{"peer": "203.0.113.9", "packets": 4, "by_reason": {"allowlist": 4}}],
        )
    )
    assert "refused 203.0.113.9  4 packets  allowlist=4" in lines


def test_a_sipnab_with_no_hep_listener_is_an_error_not_an_empty_roster():
    with pytest.raises(SystemExit, match="no HEP listener"):
        hs.render({"listening": False, "senders": [], "refused_sources": []})
