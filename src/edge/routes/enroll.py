"""``POST /v1/enroll-callback`` — enrollment lifecycle hook.

Stub for TRUS-986. Real outbound-only enrollment + bootstrap-token flow lands
in TRUS-987. The actual enroll handshake happens at pod startup against the
control plane; this endpoint exists for in-cluster ops to trigger re-enroll
manually (e.g., after a cert rotation failure).
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["enroll"])


@router.post("/enroll-callback", status_code=501)
async def enroll_callback() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content={
            "error": "not_implemented",
            "implementation_ticket": "TRUS-987",
            "description": "Outbound-only enrollment + bootstrap-token flow lands in TRUS-987.",
        },
    )
