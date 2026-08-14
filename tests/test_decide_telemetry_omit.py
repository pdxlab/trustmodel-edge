"""TRUS-1725 — verify EDGE_TELEMETRY_OMIT_PAYLOAD toggle.

For PHI/PCI/GDPR tenants the raw ``args`` on a /v1/decide request must
never leave the pod. When ``telemetry_omit_payload`` is on, the enqueued
audit event carries ``action_payload={}``; rule matching still runs
against the real args in-pod so the returned verdict / rule_id / reason
/ redactions are unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from edge.config import Settings
from edge.telemetry import get_store


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
