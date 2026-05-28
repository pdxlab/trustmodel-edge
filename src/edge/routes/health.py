"""K8s-style health endpoints.

* ``GET /health/live``  — liveness. 200 while the process is responsive.
* ``GET /health/ready`` — readiness. 200 only when Edge can serve
  ``decide()``:

  - **Enrollment complete (TRUS-987)** — bootstrap + enroll finished;
    cert credentials present; not in revocation-shutdown.
  - **Policy cache warm (TRUS-988)** — either disk-loaded or warmed via
    the first successful sync.

  Stale policy alone does not flip ready to 503 — `decide()` still
  serves under the configured fail mode in that case, so the pod is
  still useful.

Returns 503 (not 200) when any gate fails so K8s removes the pod from
the Service endpoints set during enrollment / outage windows.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from edge import __version__
from edge.policy.cache import get_cache

router = APIRouter(tags=["meta"])


@router.get("/health/live")
async def health_live() -> dict[str, str]:
    """Liveness — pod is up. Never touches disk or network."""
    return {"status": "ok"}


@router.get("/health/ready")
async def health_ready(request: Request) -> JSONResponse:
    """Readiness gates on both enrollment (TRUS-987) and policy warm (TRUS-988)."""
    state = request.app.state
    enrollment_complete = bool(getattr(state, "enrollment_complete", False))
    heartbeat = getattr(state, "heartbeat", None)
    revoked = bool(heartbeat is not None and heartbeat.revoked)
    cache = get_cache()
    cache_warm = cache.is_warm

    body: dict[str, object] = {
        "version": __version__,
        "enrollment_complete": enrollment_complete,
        "revoked": revoked,
        "policy_cache_warm": cache_warm,
        "last_sync_at": str(cache.last_success_at) if cache_warm else None,
    }
    if heartbeat is not None and heartbeat.credentials is not None:
        body["edge_id"] = heartbeat.credentials.edge_id
        body["tenant_id"] = heartbeat.credentials.tenant_id

    if not enrollment_complete or revoked or not cache_warm:
        reason: list[str] = []
        if not enrollment_complete:
            reason.append("enrollment incomplete")
        if revoked:
            reason.append("revoked")
        if not cache_warm:
            reason.append("policy cache not warm")
        body["status"] = "not_ready"
        body["reason"] = "; ".join(reason)
        return JSONResponse(status_code=503, content=body)

    body["status"] = "ready"
    return JSONResponse(status_code=200, content=body)
