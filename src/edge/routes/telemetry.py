"""``POST /v1/telemetry-flush`` — manual telemetry drain trigger.

Stub for TRUS-986. Real on-disk queue + batched outbound sync lands in
TRUS-989. Continuous syncer will run as a background task; this endpoint
gives ops a way to force a flush (e.g., before a planned shutdown).
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["telemetry"])


@router.post("/telemetry-flush", status_code=501)
async def telemetry_flush() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content={
            "error": "not_implemented",
            "implementation_ticket": "TRUS-989",
            "description": "On-disk telemetry queue + outbound sync lands in TRUS-989.",
        },
    )
