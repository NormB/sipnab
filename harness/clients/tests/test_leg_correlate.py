"""The REST client that joins one call across two capture points.

Every test here exists because the behavior it pins was wrong at some point.
The join was written against dialog fields that do not exist, so it reported
zero relay streams for every call and looked merely empty rather than broken.
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


lc = _load("leg_correlate")


def node(instance: str, dialogs=None, streams=None) -> dict:
    return {
        "base": f"http://127.0.0.1/{instance}",
        "node": instance,
        "instance": instance,
        "source": "live",
        "dialogs": dialogs or [],
        "streams": streams or [],
        "stats": {},
    }


def stream(call_id, src, dst, packets=100, codec="PCMA", mos=4.2):
    return {
        "associated_dialog": call_id,
        "src": src,
        "dst": dst,
        "packets": packets,
        "codec": codec,
        "mos": mos,
    }


def test_join_is_on_associated_dialog_not_invented_fields():
    """The join uses the one fact both nodes hold.

    An earlier version matched on `media_ports`/`sdp_ports` read off the dialog
    summary. Those keys do not exist -- the summary carries no media ports at
    all -- so every call reported zero streams and the join looked empty
    instead of wrong.
    """
    proxy = node("proxy", dialogs=[{"call_id": "a@h", "state": "Completed",
                                    "final_status_code": 200, "duration_sec": 9}])
    relay = node("relay", streams=[
        stream("a@h", "192.0.2.21:6000", "192.0.2.11:30000", packets=400),
        stream("a@h", "192.0.2.11:30000", "192.0.2.21:6000", packets=400),
    ])
    calls = lc.correlate(proxy, relay)
    call = next(c for c in calls if c["call_id"] == "a@h")
    assert call["relay_streams"] == 2
    assert call["relay_packets"] == 800
    assert call["code"] == 200


def test_media_the_relay_could_not_name_is_reported_not_dropped():
    """Unnamed media is the signal that the control plane is not reaching the
    relay. Silently omitting it makes a broken mirror look like a quiet
    network."""
    proxy = node("proxy", dialogs=[])
    relay = node("relay", streams=[stream(None, "192.0.2.20:6000",
                                          "192.0.2.11:30002", packets=4500)])
    calls = lc.correlate(proxy, relay)
    unnamed = [c for c in calls if c["state"] == "UNNAMED MEDIA"]
    assert len(unnamed) == 1
    assert unnamed[0]["relay_packets"] == 4500
    assert unnamed[0]["call_id"] is None


def test_a_one_way_call_is_not_reported_as_bidirectional():
    """`bidirectional` drives an operator's reading of whether the far end was
    heard, so a single direction must not satisfy it."""
    proxy = node("proxy", dialogs=[{"call_id": "b@h", "state": "Completed"}])
    relay = node("relay", streams=[stream("b@h", "192.0.2.21:6000",
                                          "192.0.2.11:30004")])
    call = lc.correlate(proxy, relay)[0]
    assert call["relay_streams"] == 1
    assert call["bidirectional"] is False


def test_two_directions_are_reported_as_bidirectional():
    proxy = node("proxy", dialogs=[{"call_id": "c@h", "state": "Completed"}])
    relay = node("relay", streams=[
        stream("c@h", "192.0.2.21:6000", "192.0.2.11:30006"),
        stream("c@h", "192.0.2.11:30006", "192.0.2.21:6000"),
    ])
    assert lc.correlate(proxy, relay)[0]["bidirectional"] is True


def test_worst_mos_is_the_minimum_not_the_first():
    """A call is as good as its worst leg. Reporting the first stream's MOS
    would let a clean direction hide a broken one."""
    proxy = node("proxy", dialogs=[{"call_id": "d@h", "state": "Completed"}])
    relay = node("relay", streams=[
        stream("d@h", "a:1", "b:2", mos=4.4),
        stream("d@h", "b:2", "a:1", mos=2.1),
    ])
    assert lc.correlate(proxy, relay)[0]["worst_mos"] == pytest.approx(2.1)


def test_a_call_with_no_media_reports_zero_not_an_error():
    """A signaling-only call is a normal outcome, not a failure to join."""
    proxy = node("proxy", dialogs=[{"call_id": "e@h", "state": "Failed",
                                    "final_status_code": 486}])
    call = lc.correlate(proxy, node("relay"))[0]
    assert call["relay_streams"] == 0
    assert call["worst_mos"] is None
    assert call["codecs"] == []


def test_streams_are_not_attributed_to_the_wrong_call():
    """Two calls in flight must not pool their media."""
    proxy = node("proxy", dialogs=[{"call_id": "f@h"}, {"call_id": "g@h"}])
    relay = node("relay", streams=[
        stream("f@h", "a:1", "b:2", packets=10),
        stream("g@h", "c:3", "d:4", packets=99),
    ])
    by_id = {c["call_id"]: c for c in lc.correlate(proxy, relay)}
    assert by_id["f@h"]["relay_packets"] == 10
    assert by_id["g@h"]["relay_packets"] == 99
