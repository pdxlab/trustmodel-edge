"""``POST /v1/enroll-callback`` behavior tests (TRUS-987 / TRUS-1659).

Formerly the stub-route contract test — enroll-callback was the last 501 stub.
It now runs the idempotent ``bootstrap_if_needed`` handshake, so these assert
the real behavior. (/v1/decide → tests/test_decide.py, /v1/telemetry-flush →
tests/test_telemetry_route.py.)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from edge.enroll import EnrollmentFailed
from edge.identity import EdgeCredentials


def _fake_creds() -> EdgeCredentials:
    return EdgeCredentials(
        edge_id="edge-test",
        tenant_id="test-tenant",
        cert_pem="cert",
        key_pem="key",
        ca_chain_pem="ca",
        cert_valid_to=datetime.now(UTC) + timedelta(days=30),
        agp_endpoint="https://api.trustmodel.ai",
        telemetry_endpoint="https://api.trustmodel.ai",
    )


def test_enroll_callback_success(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "edge.routes.enroll.bootstrap_if_needed", lambda _cfg: _fake_creds()
    )
    response = client.post("/v1/enroll-callback")
    assert response.status_code == 200
    body = response.json()
    assert body["edge_id"] == "edge-test"
    assert body["tenant_id"] == "test-tenant"
    assert "cert_valid_to" in body


def test_enroll_callback_failure_returns_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(_cfg: object) -> EdgeCredentials:
        raise EnrollmentFailed("no bootstrap token")

    monkeypatch.setattr("edge.routes.enroll.bootstrap_if_needed", _boom)
    response = client.post("/v1/enroll-callback")
    assert response.status_code == 503
    assert "enrollment failed" in response.json()["detail"]
