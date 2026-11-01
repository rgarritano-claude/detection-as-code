"""Offline tests for soar/playbooks/phishing_triage, run against the phantom mock.

All containers and reputation responses are synthetic lab-simulation data.
"""

from __future__ import annotations

import copy
import json

import pytest

import phantom.rules as phantom_mock
from conftest import DATA_DIR, PLAYBOOK_DIR, load_playbook

FIXTURE = DATA_DIR / "soar" / "phishing_triage" / "reported_email_container.json"
CONTAINMENT = {"quarantine email", "block sender", "create ticket"}
REPUTATION = {"url reputation", "domain reputation", "file reputation"}


@pytest.fixture
def pb():
    return load_playbook(PLAYBOOK_DIR / "phishing_triage")


@pytest.fixture
def container():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert doc["_meta"]["synthetic"] is True
    return copy.deepcopy(doc["container"])


def score(malicious=0, suspicious=0, status="success"):
    """Build a reputation responder returning fixed detection counts."""
    def responder(_parameter):
        return {"status": status, "summary": {"malicious": malicious, "suspicious": suspicious}}
    return responder


def run(pb, container, **responders):
    """responders: url=..., domain=..., file=... -> reputation responder callables."""
    mapping = {f"{k} reputation": v for k, v in responders.items()}
    state = phantom_mock.reset(container, mapping)
    pb.on_start(container)
    pb.on_finish(container, summary=None)
    return state


def verdict_notes(state):
    return [n for n in state.notes if n["title"].startswith("Phishing triage verdict")]


# --- indicator extraction ---------------------------------------------------------


def test_extracts_and_dedupes_indicators(pb, container):
    state = run(pb, container)
    indicators = json.loads(state.run_data["indicators"])
    assert indicators["urls"] == ["https://lab-payroll-update.example.net/login?user=lab-user"]
    assert indicators["domains"] == ["lab-payroll-update.example.net"]  # from URL + sender, deduped
    assert indicators["sender"] == "it-support@lab-payroll-update.example.net"
    assert indicators["recipient"] == "lab-user@example.com"
    assert indicators["message_id"] == "<lab-sim-0001@lab-payroll-update.example.net>"
    assert indicators["file_hashes"] == [
        "08c1c84b883546086688284655653cae443d90f704a0aa24acd435087305ff1c"
    ]


def test_runs_each_reputation_lookup_with_configured_assets(pb, container):
    state = run(pb, container)
    reps = {a["action"]: a for a in state.acts if a["action"] in REPUTATION}
    assert set(reps) == REPUTATION
    assert reps["url reputation"]["parameters"] == [
        {"url": "https://lab-payroll-update.example.net/login?user=lab-user"}]
    assert reps["file reputation"]["assets"] == [pb.ASSETS["file_reputation"]]


# --- decision paths ---------------------------------------------------------------


def test_malicious_path_contains_and_tickets(pb, container):
    state = run(pb, container, url=score(malicious=5), domain=score(), file=score())
    assert set(state.act_names()) == REPUTATION | CONTAINMENT
    assert state.severity == "high"
    assert state.status == "open"
    assert state.owner is None

    acts = {a["action"]: a for a in state.acts}
    assert acts["quarantine email"]["parameters"] == [
        {"id": "<lab-sim-0001@lab-payroll-update.example.net>", "email": "lab-user@example.com"}]
    assert acts["block sender"]["parameters"] == [{"email": "it-support@lab-payroll-update.example.net"}]
    assert "flagged malicious by 5 engines" in acts["create ticket"]["parameters"][0]["description"]
    assert any(n["title"] == "Containment actions" for n in state.notes)


def test_suspicious_path_assigns_analyst(pb, container):
    state = run(pb, container, url=score(malicious=1), domain=score(), file=score())
    assert not CONTAINMENT & set(state.act_names())
    assert state.owner == {"user": None, "role": pb.ANALYST_ROLE}
    assert state.severity == "medium"
    assert state.status == "open"
    assert "below threshold" in verdict_notes(state)[0]["content"]


def test_clean_path_auto_closes(pb, container):
    state = run(pb, container, url=score(), domain=score(), file=score())
    assert not CONTAINMENT & set(state.act_names())
    assert state.status == "closed"
    assert state.owner is None
    assert any(n["title"].startswith("Auto-closed") for n in state.notes)


# --- edge cases --------------------------------------------------------------------


def test_failed_lookup_fails_safe_to_analyst(pb, container):
    state = run(pb, container, url=score(), domain=score(), file=score(status="failed"))
    assert state.status == "open"
    assert state.owner["role"] == pb.ANALYST_ROLE


def test_text_only_email_is_not_auto_closed(pb, container):
    """No URLs or attachments (BEC-style): a clean sender domain must not auto-close."""
    container["artifacts"] = [a for a in container["artifacts"] if a["label"] == "email"]
    state = run(pb, container, domain=score())
    assert {a["action"] for a in state.acts} == {"domain reputation"}
    assert state.status == "open"
    assert state.owner["role"] == pb.ANALYST_ROLE


def test_empty_container_goes_to_analyst_without_lookups(pb, container):
    container["artifacts"] = []
    state = run(pb, container)
    assert state.acts == []
    assert state.owner["role"] == pb.ANALYST_ROLE


def test_missing_message_id_skips_quarantine_but_still_blocks(pb, container):
    del container["artifacts"][0]["cef"]["emailHeaders"]
    state = run(pb, container, url=score(malicious=3), domain=score(), file=score())
    names = set(state.act_names())
    assert "quarantine email" not in names
    assert {"block sender", "create ticket"} <= names
    summary = next(n for n in state.notes if n["title"] == "Containment actions")
    assert "SKIPPED quarantine email" in summary["content"]


def test_decision_runs_exactly_once(pb, container):
    """The join must fire once even though three lookups each call back."""
    state = run(pb, container, url=score(), domain=score(), file=score())
    assert len(verdict_notes(state)) == 1


# --- classify() unit tests ------------------------------------------------------------


@pytest.mark.parametrize(
    "mal,sus,status,expected",
    [
        (2, 0, "success", "malicious"),   # at threshold
        (1, 0, "success", "suspicious"),  # below threshold
        (0, 3, "success", "suspicious"),  # suspicious-only hits
        (None, None, "success", "suspicious"),  # no score returned
        (0, 0, "failed", "suspicious"),
        (0, 0, "success", "clean"),
    ],
)
def test_classify_thresholds(pb, mal, sus, status, expected):
    indicators = {"urls": ["https://x.example.net"], "domains": [], "file_hashes": []}
    results = [{"type": "url", "value": "https://x.example.net", "status": status,
                "malicious": mal, "suspicious": sus}]
    verdict, reasons = pb.classify(indicators, results)
    assert verdict == expected
    assert reasons


def test_malicious_sender_domain_alone_is_malicious(pb):
    indicators = {"urls": [], "domains": ["bad.example.net"], "file_hashes": []}
    results = [{"type": "domain", "value": "bad.example.net", "status": "success",
                "malicious": 4, "suspicious": 0}]
    assert pb.classify(indicators, results)[0] == "malicious"
