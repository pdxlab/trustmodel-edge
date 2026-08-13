"""Prometheus metrics for Edge.

A process-wide ``CollectorRegistry`` exposes:

* ``edge_decisions_total{verdict}``  — counter, one increment per decide()
* ``edge_decision_latency_ms``       — histogram, p50/p99 derive from it
* ``edge_policy_cache_hits_total``   — counter, increments on cache lookups
* ``edge_policy_stale_seconds``      — gauge, seconds since last successful sync
* ``edge_policy_cache_age_seconds``  — gauge, age of in-memory snapshot

``GET /metrics`` (in :mod:`edge.routes.metrics`) renders the registry.
"""

from edge.metrics.prometheus import (
    cache_age_seconds,
    cache_hits_total,
    decision_latency_ms,
    decisions_total,
    policy_not_found_total,
    registry,
    stale_seconds,
)

__all__ = [
    "cache_age_seconds",
    "cache_hits_total",
    "decision_latency_ms",
    "decisions_total",
    "policy_not_found_total",
    "registry",
    "stale_seconds",
]
