"""``POST /v1/decide`` — agent decision endpoint.

Stub for TRUS-986. Real logic lands in TRUS-988 (policy cache + offline-
tolerant decide). Returns 501 with a payload pointing at the implementing
ticket so downstream callers can detect "not-yet-implemented" deterministically.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["decide"])


@router.post("/decide", status_code=501)
async def decide() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content={
            "error": "not_implemented",
            "implementation_ticket": "TRUS-988",
            "description": "Policy cache + offline-tolerant decide() lands in TRUS-988.",
        },
    )
