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

    try:
        yield
    finally:
        sync_task.cancel()
        # Swallow CancelledError (expected) + any straggler exception from
        # the loop body — we are shutting down, no point re-raising.
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await sync_task
        # Drop the singleton so unit tests in the same process get a
        # fresh cache. Production runs only one lifespan, so this is
        # essentially a no-op there.
        reset_cache()
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
