"""TRUS-2002 — a tenant that explicitly opts out keeps the old wire format.

``EDGE_TELEMETRY_OMIT_PAYLOAD=false`` is now a deliberate choice, and for
those tenants behaviour must be exactly as before: raw args and raw subject
forwarded, even if a hash key happens to be configured.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from edge.config import Settings
from edge.telemetry import get_store


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        tenant_id="test-tenant",
        pod_id="test-pod",
        bootstrap_token_path=tmp_path / "bootstrap-token",
        state_dir=tmp_path / "state",
        log_level="WARNING",
        telemetry_omit_payload=False,
        telemetry_subject_hash_key="ignored-when-opted-out",
    )


def test_opt_out_forwards_raw_args_and_subject(warm_client) -> None:
    client, auth = warm_client
    args = {"q": "raw-query"}
    subject = "user-123"
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": args, "subject": subject},
        headers=auth,
    )
    assert response.status_code == 200, response.text

    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 1
    assert events[0].payload["action_payload"] == args
    assert events[0].payload["subject_id"] == subject
