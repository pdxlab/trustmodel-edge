"""TRUS-1725 / TRUS-2002 — verify EDGE_TELEMETRY_OMIT_PAYLOAD toggle.

For PHI/PCI/GDPR tenants the raw ``args`` on a /v1/decide request must
never leave the pod. When ``telemetry_omit_payload`` is on, the enqueued
audit event carries ``action_payload={}``; rule matching still runs
against the real args in-pod so the returned verdict / rule_id / reason
/ redactions are unchanged.

TRUS-2002 extended the same flag to ``subject_id``: it must never leave
the pod in clear text either — only a keyed pseudonym.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from edge.config import Settings
from edge.telemetry import get_store, hash_subject

_SUBJECT_HASH_KEY = "test-subject-hash-key"


# ── override the conftest ``settings`` fixture to flip the flag on ─────
@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        tenant_id="test-tenant",
        pod_id="test-pod",
        bootstrap_token_path=tmp_path / "bootstrap-token",
        state_dir=tmp_path / "state",
        log_level="WARNING",
        telemetry_omit_payload=True,
        telemetry_subject_hash_key=_SUBJECT_HASH_KEY,
    )


def test_decide_enqueues_empty_action_payload_when_flag_on(warm_client) -> None:
    """Flag ON → enqueued audit event's ``action_payload`` is ``{}``."""
    client, auth = warm_client

    args = {"q": "sensitive-patient-query"}
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": args},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    assert response.json()["verdict"] == "allow"

    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 1, "one audit event per /v1/decide call"
    assert events[0].payload["action_payload"] == {}, (
        "PHI mode must strip the payload before enqueue"
    )
    # Non-payload fields still populate so the audit chain stays meaningful.
    assert events[0].payload["decision"] == "allow"
    assert events[0].payload["action_type"] == "search.query"


def test_decide_redact_still_reports_redactions_when_flag_on(warm_client) -> None:
    """Redactions list still populates from the in-pod evaluation.

    The flag drops ``action_payload`` on forward but does NOT change what
    the evaluator saw — verdict/redactions come from real args.
    """
    client, auth = warm_client

    response = client.post(
        "/v1/decide",
        json={
            "tool": "profile.update",
            "args": {"name": "x", "ssn": "111-22-3333"},
        },
        headers=auth,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "redact"
    assert "args.ssn" in body["redactions"]

    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 1
    assert events[0].payload["action_payload"] == {}
    assert "args.ssn" in events[0].payload["evidence"]["redactions"]


def test_decide_hashes_subject_id_when_flag_on(warm_client) -> None:
    """TRUS-2002 — the raw subject must not appear anywhere on the wire;
    only a deterministic pseudonym keyed by telemetry_subject_hash_key."""
    client, auth = warm_client

    subject = "patient-jane-doe@example.com"
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {"q": "x"}, "subject": subject},
        headers=auth,
    )
    assert response.status_code == 200, response.text

    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 1
    forwarded_subject = events[0].payload["subject_id"]
    assert forwarded_subject != subject
    assert forwarded_subject != ""
    assert forwarded_subject == hash_subject(subject, _SUBJECT_HASH_KEY)


def test_decide_same_subject_hashes_the_same_across_calls(warm_client) -> None:
    """Recourse lookups depend on this: the same person's decisions must
    still correlate to the same pseudonym even though the raw identifier
    never leaves the pod."""
    client, auth = warm_client
    subject = "patient-jane-doe@example.com"

    for _ in range(2):
        response = client.post(
            "/v1/decide",
            json={"tool": "search.query", "args": {"q": "x"}, "subject": subject},
            headers=auth,
        )
        assert response.status_code == 200, response.text

    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 2
    assert events[0].payload["subject_id"] == events[1].payload["subject_id"]


def test_decide_no_subject_forwards_empty_string_when_flag_on(warm_client) -> None:
    client, auth = warm_client
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {"q": "x"}},
        headers=auth,
    )
    assert response.status_code == 200, response.text

    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 1
    assert events[0].payload["subject_id"] == ""
