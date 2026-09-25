"""From sipnab's accusation to a TFPS ban, and back out of TFPS's list.

sipnab recommends and does not apply (src/security/recommend.rs). The program
applies, and only where sipnab's own counter-evidence says a ban cannot
disconnect a working peer: a source that also completed a registration or a
call is withheld, and a run that never asked is withheld too. What TFPS
answers is reported as given, and a ban counts only once TFPS lists it.
"""

import importlib.util
import json
import pathlib
import sys

CLIENTS = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = CLIENTS.parent.parent / "tests" / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sb = _load("scanner_ban")


def block(ip: str, rules: str, counter: str) -> str:
    """One `--recommend-block` block, in the wording recommend.rs prints."""
    evidence = {
        "established": f"# COUNTER-EVIDENCE: {ip} also completed a registration or a call in\n"
        "#   this capture. A rule that blocks a customer is worse than the scan\n",
        "none": f"# COUNTER-EVIDENCE: none. {ip} completed no registration and no call in\n"
        "#   this capture, so nothing here says a block would disconnect a\n",
        "unknown": "# COUNTER-EVIDENCE: UNKNOWN. No scanner detector was armed on this\n",
    }[counter]
    return (
        f"# ---- sipnab block recommendation ---- {ip} ----\n"
        "# sipnab RECOMMENDS. It has applied nothing, has reached no firewall\n"
        "# EVIDENCE: 1 finding(s), first 2023-11-14T22:13:21+00:00, last 2023-11-14T22:13:21+00:00\n"
        f"# EVIDENCE: rule(s) tripped: {rules}\n"
        f"{evidence}"
        f"nft add element inet sipnab blocked {{ {ip} }}\n"
    )


def test_each_block_becomes_one_accusation_with_its_counter_evidence():
    text = block("192.0.2.10", "reg_flood", "established") + block(
        "203.0.113.42", "scanner, reg_flood", "none"
    ) + block("198.51.100.9", "reg_flood", "unknown")
    assert sb.parse_recommendations(text) == [
        {"ip": "192.0.2.10", "rules": "reg_flood", "counter": "established"},
        {"ip": "203.0.113.42", "rules": "scanner, reg_flood", "counter": "none"},
        {"ip": "198.51.100.9", "rules": "reg_flood", "counter": "unknown"},
    ]


def test_nothing_to_recommend_is_no_accusation():
    text = "# sipnab: no source was accused in this capture, so no block rule is\n"
    assert sb.parse_recommendations(text) == []


def test_a_block_whose_counter_evidence_is_unreadable_is_an_error():
    text = "# ---- sipnab block recommendation ---- 192.0.2.10 ----\n# EVIDENCE: rule(s) tripped: scanner\n"
    try:
        sb.parse_recommendations(text)
    except ValueError as e:
        assert "192.0.2.10" in str(e)
    else:
        raise AssertionError("a block with no COUNTER-EVIDENCE line was accepted")


def test_only_a_source_with_no_counter_evidence_is_banned():
    accused = [
        {"ip": "192.0.2.10", "rules": "reg_flood", "counter": "established"},
        {"ip": "203.0.113.42", "rules": "scanner", "counter": "none"},
        {"ip": "198.51.100.9", "rules": "reg_flood", "counter": "unknown"},
    ]
    ban, withheld = sb.plan(accused)
    assert [a["ip"] for a in ban] == ["203.0.113.42"]
    assert withheld == [
        "withheld 192.0.2.10 (reg_flood): it also completed a registration or a call "
        "in this capture",
        "withheld 198.51.100.9 (reg_flood): no scanner detector ran, so nothing asked "
        "whether it is a working peer",
    ]


def golden(name: str) -> list[dict]:
    return [json.loads(l) for l in (FIXTURES / name).read_text().splitlines() if l.strip()]


def test_tfps_answers_are_reported_as_given_including_each_refusal():
    lines = [sb.describe_action(a, "scanner") for a in golden("tfps-ban-golden.jsonl")]
    assert lines == [
        "banned 198.51.100.20 (scanner) until 2025-09-03T17:40:10Z",
        "banned 198.51.100.23 (scanner) with no expiry",
        "refused 192.0.2.1 (scanner): it is an address of the TFPS host (local)",
        "refused 192.0.2.77 (scanner): TFPS's ignoreip says never enforce against it (declared)",
        "refused 198.51.100.7 (scanner): TFPS could not write the block (kernel)",
    ]


def test_a_ban_counts_only_once_tfps_lists_it_as_enforced():
    rows = golden("tfps-banned-golden.jsonl")
    assert sb.unverified(["198.51.100.10", "198.51.100.12"], rows) == []
    assert sb.unverified(["198.51.100.10", "198.51.100.20"], rows) == ["198.51.100.20"]
    unenforced = [dict(rows[0], enforced=False)]
    assert sb.unverified(["198.51.100.10"], unenforced) == ["198.51.100.10"]
