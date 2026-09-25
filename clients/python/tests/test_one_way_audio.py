"""One-way audio for one call: what the diagnosis saw, whether the legs
disagree, and whether the loss belongs to the network or to the capture.

A capture that dropped packets reports them as network loss that never
happened. The last line of the diagnosis says which it is, and why.
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


owa = _load("one_way_audio")

CLEAN = {
    "kernel_dropped_packets": 0,
    "interface_dropped_packets": 0,
    "snapped_frames": 0,
    "undecodable_frames": 0,
}

REPORT = {
    "call_id": "c@x",
    "state": "Completed",
    "final_status_code": 200,
    "diagnosis": {
        "one_way_audio": True,
        "nat_mismatch": True,
        "hints": ["RTP flowed a -> b only."],
    },
    "streams": [
        {
            "ssrc": "0x11223344",
            "src": "192.0.2.1:4000",
            "dst": "192.0.2.2:4002",
            "codec": "PCMU",
            "packets": 30,
            "loss_pct": 0.0,
        }
    ],
}


def test_a_capture_that_lost_nothing_puts_the_loss_on_the_network():
    assert owa.whose_loss(CLEAN) == [
        "capture: no packet dropped by the kernel buffer or the interface, "
        "so the loss above is the network's",
    ]


def test_kernel_drops_are_the_capture_hosts_and_name_their_fix():
    lines = owa.whose_loss(dict(CLEAN, kernel_dropped_packets=18432))
    assert lines[0] == (
        "capture: 18432 packet(s) dropped by the kernel buffer on the capture host, "
        "counted above as network loss (raise -B/--buffer, narrow the BPF filter, "
        "or lower --snaplen)"
    )


def test_interface_drops_say_a_buffer_cannot_fix_them():
    lines = owa.whose_loss(dict(CLEAN, interface_dropped_packets=7))
    assert lines[0] == (
        "capture: 7 packet(s) dropped by the interface or its driver, counted above "
        "as network loss (a bigger buffer cannot fix these: check the NIC)"
    )


def test_truncated_and_undecodable_frames_are_named_beside_the_verdict():
    lines = owa.whose_loss(dict(CLEAN, snapped_frames=3, undecodable_frames=2))
    assert lines[1] == (
        "capture: 3 frame(s) cut short by the snaplen and 2 frame(s) it could not "
        "decode; loss figures may be low as well as high"
    )


def test_the_report_names_the_diagnosis_the_streams_and_the_asymmetries():
    lines = owa.render(REPORT, ["late_media"], {"capture_quality": CLEAN})
    assert lines == [
        "c@x  Completed  200",
        "one-way audio: yes",
        "NAT mismatch: yes",
        "  0x11223344  192.0.2.1:4000 -> 192.0.2.2:4002  PCMU  30 packets  loss 0.0%",
        "hint: RTP flowed a -> b only.",
        "asymmetry: late_media",
        "capture: no packet dropped by the kernel buffer or the interface, "
        "so the loss above is the network's",
    ]


def test_a_call_with_no_media_says_so_rather_than_listing_nothing():
    report = dict(REPORT, streams=[], diagnosis={"one_way_audio": False, "nat_mismatch": False})
    lines = owa.render(report, [], {"capture_quality": CLEAN})
    assert "  no RTP stream is associated with this call" in lines
    assert "asymmetry: none" in lines


def test_the_asymmetry_filter_quotes_the_call_id():
    assert owa.asymmetry_filter("o'x@h", "late_media") == "call_id == 'o\\'x@h' AND late_media == true"
