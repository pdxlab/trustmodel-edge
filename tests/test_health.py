"""Health endpoint tests — used directly by Helm probes + ``helm test``.

Readiness gates on BOTH:
* enrollment complete (TRUS-987)
* policy cache warm (TRUS-988)

Tests cover each gate independently + their combination.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from edge import __version__


def test_health_live(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_ready_cold_returns_503(client: TestClient) -> None:
    """Enrolled but policy cache cold → readiness fails so K8s keeps traffic off
    until the first sync succeeds (TRUS-988 gate)."""
    response = client.get("/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["version"] == __version__
    assert body["policy_cache_warm"] is False


def test_health_ready_pre_enrollment_returns_503(client: TestClient) -> None:
    """Without an enrolled instance attached, readiness must be 503 (TRUS-987 gate)."""
    # Force enrollment_complete=False to simulate pre-enroll window.
    client.app.state.enrollment_complete = False
    response = client.get("/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["enrollment_complete"] is False


def test_health_ready_after_enrollment_and_cache_warm_returns_200(
    ready_client: TestClient,
) -> None:
    """Both gates green (enrollment + cache warm) → 200."""
    response = ready_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["version"] == __version__
    assert body["enrollment_complete"] is True
    assert body["revoked"] is False
    assert body["policy_cache_warm"] is True
    assert body["edge_id"] == "00000000-0000-0000-0000-000000000001"


def test_health_ready_warm_only_returns_200(warm_client) -> None:
    """warm_client uses skip_enrollment=True (so enrollment_complete=True) and
    pre-seeds the cache → /health/ready 200 even without a heartbeat attached.
    Fixture returns ``(client, auth_headers)`` post-TRUS-1270; health doesn't
    need the auth header but we still unpack the tuple."""
    client, _ = warm_client
    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["policy_cache_warm"] is True


def test_health_ready_after_revocation_returns_503(ready_client: TestClient) -> None:
    """Revoked Edge must flip readiness off so K8s pulls it from Service."""
    ready_client.app.state.heartbeat.revoked = True
    response = ready_client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["revoked"] is True
