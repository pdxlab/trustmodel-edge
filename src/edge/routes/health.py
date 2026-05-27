"""K8s-style health endpoints.

* ``GET /health/live``  — liveness. 200 while the process is responsive.
* ``GET /health/ready`` — readiness. 200 when Edge can serve ``decide()``.

Readiness flips to 200 once the policy cache is warm (either disk-loaded
or first successful sync). Stale policy alone does not flip ready to
503 — `decide()` still serves under the configured fail mode in that
case, so the pod is still useful.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from edge import __version__
from edge.policy.cache import get_cache

router = APIRouter(tags=["meta"])


@router.get("/health/live")
async def health_live() -> dict[str, str]:
    """Liveness — pod is up. Never touches disk or network."""
    return {"status": "ok"}


@router.get("/health/ready")
async def health_ready() -> JSONResponse:
    """Readiness — Edge has a policy cached and can serve decide()."""
    cache = get_cache()
    if not cache.is_warm:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "version": __version__,
                "reason": "policy cache not warm",
            },
        )
    return JSONResponse(
        status_code=200,
        content={
            "status": "ready",
            "version": __version__,
            "last_sync_at": str(cache.last_success_at),
        },
    )
