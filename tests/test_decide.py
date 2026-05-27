"""End-to-end tests for ``POST /v1/decide`` over the warm cache."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_decide_returns_503_when_cache_cold(client: TestClient) -> None:
    """Default fail mode is closed → 503 when policy hasn't been warmed."""
    response = client.post(
        "/v1/decide", json={"tool": "search.query", "args": {"q": "x"}}
    )
    assert response.status_code == 503


def test_decide_allow_path(warm_client: TestClient) -> None:
    response = warm_client.post(
        "/v1/decide", json={"tool": "search.query", "args": {"q": "x"}}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "allow"
    assert body["policy_id"] == "pol-demo-1"
    assert body["stale"] is False


def test_decide_deny_path(warm_client: TestClient) -> None:
    response = warm_client.post(
        "/v1/decide", json={"tool": "email.send", "args": {"to": "x@y.com"}}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "deny"


def test_decide_redact_path(warm_client: TestClient) -> None:
    response = warm_client.post(
        "/v1/decide",
        json={
            "tool": "profile.update",
            "args": {"name": "x", "ssn": "111-22-3333"},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "redact"
    assert "args.ssn" in body["redactions"]
