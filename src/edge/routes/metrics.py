"""``GET /metrics`` — Prometheus exposition.

Updates the cache-age / stale-seconds gauges on each scrape so the
numbers reflect the moment of read, then renders the registry in the
Prometheus text format.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from edge.metrics import cache_age_seconds, registry, stale_seconds
from edge.policy.cache import get_cache

router = APIRouter(tags=["meta"])


@router.get("/metrics")
async def metrics(_request: Request) -> Response:
    cache = get_cache()
    last = cache.last_success_at
    if last is not None:
        age = (datetime.now(UTC) - last).total_seconds()
        cache_age_seconds.set(age)
        stale_seconds.set(age)
    else:
        cache_age_seconds.set(0)
        stale_seconds.set(0)

    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
