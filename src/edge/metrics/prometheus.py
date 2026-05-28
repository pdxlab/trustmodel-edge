"""Prometheus metric definitions.

Single ``CollectorRegistry`` so tests can drop + rebuild it between cases
without conflicting with the default registry.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

registry = CollectorRegistry()

decisions_total = Counter(
    "edge_decisions_total",
    "Total decide() calls, labelled by verdict.",
    labelnames=("verdict",),
    registry=registry,
)

decision_latency_ms = Histogram(
    "edge_decision_latency_ms",
    "decide() latency in milliseconds.",
    # Buckets tuned for sub-5ms p99 target.
    buckets=(0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000),
    registry=registry,
)

cache_hits_total = Counter(
    "edge_policy_cache_hits_total",
    "Cache lookups during decide(). Always increments under EDGE_MODE.",
    registry=registry,
)

stale_seconds = Gauge(
    "edge_policy_stale_seconds",
    "Seconds since the last successful policy sync.",
    registry=registry,
)

cache_age_seconds = Gauge(
    "edge_policy_cache_age_seconds",
    "Age of the currently-served in-memory snapshot.",
    registry=registry,
)
