"""K8s-style health endpoints.

* ``GET /health/live``  — liveness. 200 while the process is responsive.
* ``GET /health/ready`` — readiness. 200 only after enrollment completes
  (TRUS-987) AND the heartbeat loop is healthy. Will further tighten in
  TRUS-988 (require first policy sync).
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from edge import __version__

router = APIRouter(tags=["meta"])


@router.get("/health/live")
async def health_live() -> dict[str, str]:
    """Liveness — pod is up. Never touches disk or network."""
    return {"status": "ok"}


@router.get("/health/ready")
async def health_ready(request: Request, response: Response) -> dict[str, object]:
    """Readiness — Edge can serve traffic.

    Gates on:
    * ``app.state.enrollment_complete`` (TRUS-987) — bootstrap + enroll
      finished successfully.
    * Not currently in revocation-shutdown.

    Returns 503 (not 200) when not ready so K8s removes the pod from the
    Service endpoints set during enrollment / outage windows.
    """
    state = request.app.state
    enrollment_complete = bool(getattr(state, "enrollment_complete", False))
    heartbeat = getattr(state, "heartbeat", None)
    revoked = bool(heartbeat is not None and heartbeat.revoked)

    body: dict[str, object] = {
        "status": "ready" if (enrollment_complete and not revoked) else "not-ready",
        "version": __version__,
        "enrollment_complete": enrollment_complete,
        "revoked": revoked,
    }
    if heartbeat is not None and heartbeat.credentials is not None:
        body["edge_id"] = heartbeat.credentials.edge_id
        body["tenant_id"] = heartbeat.credentials.tenant_id

    if not enrollment_complete or revoked:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return body
