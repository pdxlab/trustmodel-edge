"""Health endpoint tests — used directly by Helm probes + ``helm test``."""

from __future__ import annotations

from fastapi.testclient import TestClient

from edge import __version__


def test_health_live(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_ready_cold_returns_503(client: TestClient) -> None:
    """A cold Edge (no policy cached yet) fails readiness so K8s
    keeps traffic off the pod until the first sync succeeds."""
    response = client.get("/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["version"] == __version__


def test_health_ready_warm_returns_200(warm_client: TestClient) -> None:
    """Once the cache is warm, readiness flips to 200."""
    response = warm_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["version"] == __version__
