"""Heartbeat + rotation background loop (TRUS-987).

Runs as an asyncio task spawned in the FastAPI lifespan:

* Tick every ``settings.heartbeat_interval_s`` (default 60s).
* On revocation (``EdgeRevoked``) — log, set the revocation flag on
  app.state, and let the lifespan teardown raise SystemExit non-zero.
* On rotation_due — call ``/rotate``, persist the fresh bundle, swap
  the in-memory credentials.
* On transient errors (``EdgeControlPlaneError``) — log + retry next tick.
"""

from __future__ import annotations

import asyncio
from typing import Callable

import structlog

from edge.config import Settings
from edge.control_plane import (
    EdgeControlPlaneError,
    EdgeRevoked,
    heartbeat as cp_heartbeat,
    rotate as cp_rotate,
)
from edge.identity import EdgeCredentials, persist_credentials

log = structlog.get_logger()


class HeartbeatState:
    """Shared mutable state between the heartbeat loop, app, and routes."""

    def __init__(self, creds: EdgeCredentials):
        self.credentials = creds
        self.revoked: bool = False
        self.last_tick_ok_at: float | None = None

    def replace_credentials(self, new: EdgeCredentials) -> None:
        self.credentials = new


async def _one_tick(
    settings: Settings,
    state: HeartbeatState,
    monotonic: Callable[[], float] = asyncio.get_event_loop,
) -> None:
    cp = str(settings.control_plane_url).rstrip("/")
    try:
        resp = cp_heartbeat(control_plane_url=cp, creds=state.credentials)
    except EdgeRevoked:
        state.revoked = True
        log.warning("edge.heartbeat.revoked", edge_id=state.credentials.edge_id)
        raise
    except EdgeControlPlaneError as exc:
        log.info("edge.heartbeat.transient_error", error=str(exc))
        return

    state.last_tick_ok_at = asyncio.get_event_loop().time()

    if resp.rotation_due:
        try:
            rotated = cp_rotate(control_plane_url=cp, creds=state.credentials)
        except EdgeRevoked:
            state.revoked = True
            raise
        except EdgeControlPlaneError as exc:
            log.info("edge.rotate.transient_error", error=str(exc))
            return
        new_creds = EdgeCredentials(
            edge_id=state.credentials.edge_id,
            tenant_id=state.credentials.tenant_id,
            cert_pem=rotated.cert_pem,
            key_pem=rotated.key_pem,
            ca_chain_pem=rotated.ca_chain_pem,
            cert_valid_to=rotated.cert_valid_to,
            agp_endpoint=state.credentials.agp_endpoint,
            telemetry_endpoint=state.credentials.telemetry_endpoint,
        )
        persist_credentials(settings.state_dir, new_creds)
        state.replace_credentials(new_creds)
        log.info(
            "edge.rotate.success",
            edge_id=new_creds.edge_id,
            cert_valid_to=new_creds.cert_valid_to.isoformat(),
        )


async def heartbeat_loop(settings: Settings, state: HeartbeatState) -> None:
    """Run forever until cancelled or EdgeRevoked is raised."""
    interval = settings.heartbeat_interval_s
    log.info("edge.heartbeat.loop_start", interval_s=interval)
    while True:
        try:
            await _one_tick(settings, state)
        except EdgeRevoked:
            # Caller (lifespan) reads state.revoked and triggers exit.
            return
        await asyncio.sleep(interval)
