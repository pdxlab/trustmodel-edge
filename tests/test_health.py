"""Health endpoint tests — used directly by Helm probes + ``helm test``."""

from __future__ import annotations

from fastapi.testclient import TestClient

from edge import __version__


def test_health_live(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_ready(client: TestClient) -> None:
    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["version"] == __version__
