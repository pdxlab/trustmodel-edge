"""End-to-end tests for ``POST /v1/decide`` over the warm cache.

TRUS-1270: /decide is now OAuth-authenticated. The ``warm_client`` fixture
returns ``(client, auth_headers)``; tests pass ``**auth_headers`` so the
request carries a valid Bearer token.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_decide_returns_503_when_cache_cold(client: TestClient) -> None:
    """Default fail mode is closed → 503 when policy hasn't been warmed.

    No auth needed: the auth check runs before the cache check, but a
    cold-cache deployment also has no enrollment key on disk, so the
    auth path itself 503s. Either way, 503 is correct.
    """
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {"q": "x"}},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 503


def test_decide_allow_path(warm_client) -> None:
    client, auth = warm_client
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {"q": "x"}},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "allow"
    assert body["policy_id"] == "pol-demo-1"
    assert body["stale"] is False


def test_decide_deny_path(warm_client) -> None:
    client, auth = warm_client
    response = client.post(
        "/v1/decide",
        json={"tool": "email.send", "args": {"to": "x@y.com"}},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "deny"


def test_decide_redact_path(warm_client) -> None:
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
