"""``POST /v1/enroll-callback`` — manual re-enroll / ensure-enrolled hook.

Primary enrollment runs automatically at pod startup (see :mod:`edge.app`).
This endpoint lets in-cluster ops re-establish credentials on demand — e.g.
after a cert-rotation failure. Idempotent: reuses still-valid credentials,
otherwise runs the bootstrap-token enrollment handshake and persists fresh
certs. Reuses the same :func:`edge.enroll.bootstrap_if_needed` the startup
path uses, so there's one enrollment code path, not two.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from edge.config import Settings
from edge.enroll import EnrollmentFailed, bootstrap_if_needed

router = APIRouter(tags=["enroll"])


@router.post("/enroll-callback")
async def enroll_callback(request: Request) -> dict:
    """Ensure the Edge is enrolled; re-enroll if credentials are missing/expired.

    Runs the (blocking) enrollment handshake in a threadpool so it can't stall
    the event loop. Returns the active edge identity on success; 503 if the
    control-plane handshake fails (bootstrap token missing/expired, CP down).
    """
    cfg: Settings = request.app.state.settings
    try:
        creds = await run_in_threadpool(bootstrap_if_needed, cfg)
    except EnrollmentFailed as exc:
        raise HTTPException(status_code=503, detail=f"enrollment failed: {exc}") from exc

    # Reflect a successful (re-)enroll in readiness, same as the startup path.
    request.app.state.enrollment_complete = True
    return {
        "edge_id": creds.edge_id,
        "tenant_id": creds.tenant_id,
        "cert_valid_to": creds.cert_valid_to.isoformat(),
    }
