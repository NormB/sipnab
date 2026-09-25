"""One customer's calls out of a set of rotated captures, as a capture the
vendor can open, and nothing else.

`-O` narrows only by BPF, which selects addresses rather than SIP users
(recipe 32). So the program finds the customer's calls, turns their
addresses into a BPF expression, exports, and reads the export back: each
call must come out whole, and any other call that shares an address is a
disclosure, so the export is refused and removed rather than handed over.
"""

import importlib.util
import pathlib
import sys

CLIENTS = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CLIENTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ce = _load("customer_export")


def msg(call_id: str, src: str, dst: str, sdp: str | None = None) -> dict:
    out = {"call_id": call_id, "src": src, "dst": dst}
    if sdp is not None:
        out["sdp"] = sdp
    return out


def test_calls_are_counted_and_their_signaling_and_media_addresses_collected():
    calls = ce.collect(
        [
            msg("a@x", "192.0.2.10", "192.0.2.20", "v=0\r\nc=IN IP4 203.0.113.5\r\nm=audio 4000"),
            msg("a@x", "192.0.2.20", "192.0.2.10"),
            msg("b@x", "192.0.2.10", "198.51.100.3"),
        ]
    )
    assert {k: v["messages"] for k, v in calls.items()} == {"a@x": 2, "b@x": 1}
    assert ce.hosts(calls) == ["192.0.2.10", "192.0.2.20", "198.51.100.3", "203.0.113.5"]


def test_the_bpf_names_every_host_in_numeric_order():
    assert ce.bpf(["192.0.2.9", "192.0.2.10"]) == "host 192.0.2.9 or host 192.0.2.10"


def test_an_export_holding_every_call_whole_and_nothing_else_passes():
    wanted = {"a@x": {"messages": 7}}
    assert ce.check_export(wanted, {"a@x": {"messages": 7}}) == []


def test_a_call_that_came_out_short_is_reported():
    wanted = {"a@x": {"messages": 7}}
    assert ce.check_export(wanted, {"a@x": {"messages": 5}}) == [
        "a@x: 5 of its 7 message(s) are in the export",
    ]
    assert ce.check_export(wanted, {}) == ["a@x: not in the export"]


def test_another_call_sharing_an_address_is_a_disclosure():
    wanted = {"a@x": {"messages": 7}}
    got = {"a@x": {"messages": 7}, "z@y": {"messages": 4}}
    assert ce.check_export(wanted, got) == [
        "z@y: another customer's call shares an address with this one, "
        "and BPF cannot separate them",
    ]


def test_the_wireshark_filter_names_each_call():
    assert ce.wireshark_filter(["a@x", "b@x"]) == 'sip.Call-ID == "a@x" || sip.Call-ID == "b@x"'


def test_the_user_filter_matches_either_end_of_the_call():
    assert ce.user_filter("alice") == "from.user == 'alice' OR to.user == 'alice'"
