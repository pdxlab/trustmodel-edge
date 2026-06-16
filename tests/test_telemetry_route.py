"""Tests for ``POST /v1/telemetry-flush`` + decide() → enqueue wiring.

TRUS-1270: ``warm_client`` now returns ``(client, auth_headers)``.
"""

from __future__ import annotations


def test_decide_enqueues_an_audit_event(warm_client) -> None:
    """Every decide call should land a row in the SQLite queue."""
    from edge.telemetry import get_store

    client, auth = warm_client
    store = get_store()
    before = store.count()

    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {"q": "x"}},
        headers=auth,
    )
    assert response.status_code == 200

    after = store.count()
    assert after == before + 1

    queued = store.dequeue_batch(limit=10)
    payload = queued[-1].payload
    assert payload["decision"] == "allow"
    assert payload["action_type"] == "search.query"
    # agent_id now comes from the JWT, not the request body
    assert payload["agent_id"] == "test-agent-slug"
    assert payload["evidence"]["rule_id"] == "allow-rest"


def test_telemetry_flush_route_returns_count(warm_client) -> None:
    """With the sender stubbed in tests, flush_now is also stubbed to
    return 0 — but the route still has to return a well-formed JSON
    body with the count key."""
    client, _ = warm_client
    response = client.post("/v1/telemetry-flush")
    assert response.status_code == 200
    body = response.json()
    assert "sent" in body
    assert isinstance(body["sent"], int)
