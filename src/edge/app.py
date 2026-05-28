"""FastAPI app factory.

The factory pattern lets tests instantiate the app with overrides and the
production entrypoint (``edge.__main__``) wire it to uvicorn.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from edge import __version__
from edge.config import Settings, load_settings
from edge.logging import configure_logging
from edge.policy.cache import get_cache, reset_cache
from edge.policy.client import PolicyClient
from edge.policy.sync import run_forever as policy_run_forever
from edge.policy.sync import warm as policy_warm
from edge.routes import decide, enroll, health, metrics, telemetry
from edge.telemetry import flush_now as telemetry_flush_now
from edge.telemetry import get_store as get_telemetry_store
from edge.telemetry import reset_store as reset_telemetry_store
from edge.telemetry.sender import TelemetrySender

log = structlog.get_logger()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    cfg: Settings = app.state.settings
    log.info("edge.startup", version=__version__, tenant=cfg.tenant_id)

    cache = get_cache()
    cache.load_from_disk(cfg.state_dir)
    log.info("edge.policy.disk_load", warm=cache.is_warm)

    policy_client = PolicyClient(
        control_plane_url=str(cfg.control_plane_url),
        state_dir=cfg.state_dir,
        request_timeout_seconds=cfg.policy_request_timeout_seconds,
    )

    # Warm the cache. If disk was empty AND network warm fails we want
    # the readiness probe to stay red — caller can choose to require
    # success. Today, allow disk-fallback to satisfy warm.
    try:
        await policy_warm(policy_client, cache, state_dir=cfg.state_dir)
        app.state.policy_warm_ok = True
    except RuntimeError as exc:
        log.error("edge.policy.warm_failed", detail=str(exc))
        app.state.policy_warm_ok = False

    sync_task = asyncio.create_task(
        policy_run_forever(
            policy_client,
            cache,
            state_dir=cfg.state_dir,
            interval_seconds=cfg.policy_sync_interval_seconds,
        ),
        name="edge.policy.sync",
    )
    app.state.policy_sync_task = sync_task

    # ── Telemetry queue + sender (TRUS-989) ─────────────────────────
    store = get_telemetry_store(
        state_dir=cfg.state_dir, max_size=cfg.telemetry_queue_size
    )
    sender = TelemetrySender(
        store,
        control_plane_url=str(cfg.control_plane_url),
        state_dir=cfg.state_dir,
        batch_size=cfg.telemetry_batch_size,
        flush_interval_seconds=cfg.telemetry_flush_interval_seconds,
    )
    app.state.telemetry_sender = sender
    sender_task = asyncio.create_task(sender.run_forever(), name="edge.telemetry.sender")
    app.state.telemetry_sender_task = sender_task

    try:
        yield
    finally:
        # Drain the telemetry queue best-effort before shutting down.
        try:
            drained = await telemetry_flush_now(
                sender, deadline_seconds=cfg.telemetry_drain_timeout_seconds
            )
            log.info("edge.telemetry.drained", count=drained)
        except Exception:  # noqa: BLE001
            log.exception("edge.telemetry.drain_failed")

        sender_task.cancel()
        sync_task.cancel()
        # Swallow CancelledError (expected) + any straggler exception from
        # the loop bodies — we're shutting down, no point re-raising.
        for task in (sender_task, sync_task):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        # Drop singletons so tests in the same process get a fresh
        # cache + store. Production runs only one lifespan.
        reset_cache()
        reset_telemetry_store()
        log.info("edge.shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI app. Pass ``settings`` in tests to override env."""
    cfg = settings or load_settings()
    configure_logging(cfg.log_level)

    app = FastAPI(
        title="TrustModel Edge",
        version=__version__,
        description="In-VPC AGP data plane. See pdxlab/trustmodel-edge.",
        lifespan=_lifespan,
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.settings = cfg

    app.include_router(health.router)
    app.include_router(metrics.router)
    app.include_router(decide.router, prefix="/v1")
    app.include_router(enroll.router, prefix="/v1")
    app.include_router(telemetry.router, prefix="/v1")

    return app
