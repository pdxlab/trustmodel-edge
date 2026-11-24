"""Heartbeat + rotation background loop (TRUS-987).

Runs as an asyncio task spawned in the FastAPI lifespan:

* Tick every ``settings.heartbeat_interval_s`` (default 60s).
* On revocation (``EdgeRevoked``) — log, set the revocation flag on
  app.state, and let the lifespan teardown raise SystemExit non-zero.
* On rotation_due — from the server, or locally from the cert's own
  expiry — call ``/rotate``, swap the in-memory credentials, persist the
  fresh bundle. A failed write is logged and retried every tick (TRUS-2374).
* On a 401/403 — first adopt newer credentials another replica wrote to
  the shared state_dir; only then treat it as revocation (TRUS-2374).
* On transient errors (``EdgeControlPlaneError``) — log + retry next tick.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import structlog

from edge.config import Settings
from edge.control_plane import (
    EdgeControlPlaneError,
    EdgeRevoked,
)
from edge.control_plane import (
    heartbeat as cp_heartbeat,
)
from edge.control_plane import (
    rotate as cp_rotate,
)
from edge.identity import (
    EdgeCredentials,
    is_rotation_due,
    load_credentials,
    persist_credentials,
)

log = structlog.get_logger()


class HeartbeatState:
    """Shared mutable state between the heartbeat loop, app, and routes."""

    def __init__(self, creds: EdgeCredentials):
        self.credentials = creds
        self.revoked: bool = False
        self.last_tick_ok_at: float | None = None
        # True while the newest credentials exist only in memory: /rotate
        # succeeded but writing them to state_dir failed (TRUS-2374).
        self.persist_pending: bool = False

    def replace_credentials(self, new: EdgeCredentials) -> None:
        self.credentials = new


def _adopt_newer_from_disk(settings: Settings, state: HeartbeatState) -> bool:
    """Switch to credentials another replica rotated into the shared state_dir.

    Replicas that share a state_dir share one Edge identity, and /rotate
    invalidates the previous key at once. After one replica rotates, the
    others are rejected until they pick up the new key from disk.
    """
    on_disk = load_credentials(settings.state_dir)
    current = state.credentials
    if (
        on_disk is None
        or on_disk.edge_id != current.edge_id
        or on_disk.key_pem == current.key_pem
        or on_disk.cert_valid_to <= current.cert_valid_to
    ):
        return False
    state.replace_credentials(on_disk)
    state.persist_pending = False
    log.info(
        "edge.identity.adopted_from_disk",
        edge_id=on_disk.edge_id,
        cert_valid_to=on_disk.cert_valid_to.isoformat(),
    )
    return True


def _persist(settings: Settings, state: HeartbeatState) -> None:
    try:
        persist_credentials(settings.state_dir, state.credentials)
    except OSError as exc:
        state.persist_pending = True
        log.error(
            "edge.rotate.persist_failed",
            edge_id=state.credentials.edge_id,
            state_dir=str(settings.state_dir),
            error=str(exc),
            detail=(
                "The rotated credentials are in memory only and the previous key "
                "is no longer accepted. Retrying every heartbeat; a restart before "
                "the write succeeds needs a new bootstrap token."
            ),
        )
        return
    if state.persist_pending:
        log.info("edge.rotate.persist_recovered", edge_id=state.credentials.edge_id)
    state.persist_pending = False


async def _one_tick(
    settings: Settings,
    state: HeartbeatState,
    monotonic: Callable[[], float] = asyncio.get_event_loop,
) -> None:
    cp = str(settings.control_plane_url).rstrip("/")
    if state.persist_pending and not _adopt_newer_from_disk(settings, state):
        _persist(settings, state)

    try:
        resp = cp_heartbeat(control_plane_url=cp, creds=state.credentials)
    except EdgeRevoked:
        if _adopt_newer_from_disk(settings, state):
            return
        state.revoked = True
        log.warning("edge.heartbeat.revoked", edge_id=state.credentials.edge_id)
        raise
    except EdgeControlPlaneError as exc:
        log.info("edge.heartbeat.transient_error", error=str(exc))
        return

    state.last_tick_ok_at = asyncio.get_event_loop().time()

    # The local check heals a set left half-renamed (new key, old cert): the
    # server sees a fresh cert, but the old cert on disk would read as
    # expired at the next cold start (TRUS-2374).
    if resp.rotation_due or is_rotation_due(state.credentials):
        try:
            rotated = cp_rotate(control_plane_url=cp, creds=state.credentials)
        except EdgeRevoked:
            if _adopt_newer_from_disk(settings, state):
                return
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
        # /rotate has already invalidated the old key server-side, so the new
        # one goes into use before the disk write, which can fail.
        state.replace_credentials(new_creds)
        log.info(
            "edge.rotate.success",
            edge_id=new_creds.edge_id,
            cert_valid_to=new_creds.cert_valid_to.isoformat(),
        )
        _persist(settings, state)


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
        except Exception:  # noqa: BLE001
            # An unhandled error used to end this task without a trace,
            # silently stopping heartbeats and rotation (TRUS-2374).
            log.exception("edge.heartbeat.tick_failed")
        await asyncio.sleep(interval)
