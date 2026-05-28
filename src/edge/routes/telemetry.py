"""``POST /v1/telemetry-flush`` — manual telemetry drain trigger.

Ops uses this before a planned shutdown to push any queued audit events
out before the pod exits. The background sender drains continuously
under normal operation; this endpoint just forces a synchronous drain
up to a configurable deadline.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from edge.telemetry import flush_now

router = APIRouter(tags=["telemetry"])


@router.post("/telemetry-flush")
async def telemetry_flush(request: Request) -> dict[str, int]:
    """Drain the queue synchronously up to the configured deadline."""
    sender = request.app.state.telemetry_sender
    deadline = request.app.state.settings.telemetry_drain_timeout_seconds
    sent = await flush_now(sender, deadline_seconds=deadline)
    return {"sent": sent}
