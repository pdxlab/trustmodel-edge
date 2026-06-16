"""Tests for ``GET /metrics``."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_metrics_exposes_prometheus_text(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "edge_decisions_total" in body
    assert "edge_decision_latency_ms" in body
    assert "edge_policy_cache_hits_total" in body
    assert "edge_policy_stale_seconds" in body
    assert "edge_policy_cache_age_seconds" in body


def test_metrics_increments_on_decide(warm_client) -> None:
    # Hit decide a few times, then scrape metrics; expect counters > 0.
    client, auth = warm_client
    for _ in range(3):
        client.post(
            "/v1/decide",
            json={"tool": "search.query", "args": {}},
            headers=auth,
        )
    metrics = client.get("/metrics").text
    assert 'edge_decisions_total{verdict="allow"}' in metrics
    # Histogram observations should be present
    assert "edge_decision_latency_ms_count" in metrics
