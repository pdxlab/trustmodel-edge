"""Health endpoint tests — used directly by Helm probes + ``helm test``."""

from __future__ import annotations

from fastapi.testclient import TestClient

from edge import __version__


def test_health_live(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_ready_pre_enrollment_returns_503(client: TestClient) -> None:
    """Without an enrolled instance attached, readiness must be 503 (TRUS-987)."""
    # Force enrollment_complete=False to simulate pre-enroll window
    client.app.state.enrollment_complete = False
    response = client.get("/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not-ready"
    assert body["enrollment_complete"] is False


def test_health_ready_after_enrollment_returns_200(ready_client: TestClient) -> None:
    response = ready_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["version"] == __version__
    assert body["enrollment_complete"] is True
    assert body["revoked"] is False
    assert body["edge_id"] == "00000000-0000-0000-0000-000000000001"


def test_health_ready_after_revocation_returns_503(ready_client: TestClient) -> None:
    """Revoked Edge must flip readiness off so K8s pulls it from Service."""
    ready_client.app.state.heartbeat.revoked = True
    response = ready_client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["revoked"] is True
