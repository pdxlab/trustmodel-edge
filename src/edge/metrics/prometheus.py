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

# TRUS-1716 — increments when a /v1/decide call names a policy that
# isn't in the Edge cache (either the caller sent an unknown name or a
# just-published policy hasn't synced yet). Rollout monitor for Deploy 3:
# any non-zero sustained rate → investigate.
#
# Deliberately UNLABELED (Priyanka #12 review, 2026-08-13): the caller
# controls ``policy_name`` on the miss path, so exposing it as a Prom
# label would let a buggy/hostile caller spray random values and mint
# a new time series per value — metric-registry memory blowup on the
# hot decide path. The specific ``policy_name`` still goes to the WARN
# log for debug; the metric is aggregate-only.
policy_not_found_total = Counter(
    "edge_decisions_policy_not_found_total",
    "Count of /v1/decide calls that hit the policy_name lookup miss branch.",
    registry=registry,
)
