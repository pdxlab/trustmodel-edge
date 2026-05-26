"""FastAPI app factory.

The factory pattern lets tests instantiate the app with overrides and the
production entrypoint (``edge.__main__``) wire it to uvicorn.

Startup flow (TRUS-987):

1. Read bootstrap token from K8s Secret (or env override).
2. Call ``POST /api/v1/edge/enroll`` against the control plane.
3. Persist cert + key + ca chain to the PVC.
4. Mark ``app.state.enrollment_complete = True`` — flips /health/ready to 200.
5. Spawn the heartbeat background task (every 60s).
6. Begin serving traffic.

Tests bypass enrollment via the ``skip_enrollment`` flag on
:func:`create_app` so they don't need a live control plane.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from edge import __version__
from edge.config import Settings, load_settings
from edge.enroll import EnrollmentFailed, bootstrap_if_needed
from edge.heartbeat import HeartbeatState, heartbeat_loop
from edge.logging import configure_logging
from edge.routes import decide, enroll, health, telemetry

log = structlog.get_logger()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    log.info("edge.startup", version=__version__, tenant=settings.tenant_id)

    heartbeat_task: asyncio.Task | None = None

    if app.state.skip_enrollment:
        log.info("edge.startup.skip_enrollment")
        app.state.enrollment_complete = True
    else:
        try:
            creds = bootstrap_if_needed(settings)
        except EnrollmentFailed as exc:
            log.error("edge.startup.enrollment_failed", error=str(exc))
            # Non-zero exit signals K8s to restart the pod. Readiness never
            # flipped to 200, so the rolling deploy doesn't kill the prior
            # healthy replica.
            raise SystemExit(2) from exc

        app.state.heartbeat = HeartbeatState(creds)
        app.state.enrollment_complete = True
        heartbeat_task = asyncio.create_task(heartbeat_loop(settings, app.state.heartbeat))

    try:
        yield
    finally:
        if heartbeat_task is not None:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except (asyncio.CancelledError, SystemExit):
                pass

            # Only exit non-zero if we owned the loop (production path).
            # Tests can stick state.heartbeat.revoked=True on the fixture
            # without triggering process termination.
            if app.state.heartbeat is not None and app.state.heartbeat.revoked:
                log.warning("edge.shutdown.revoked_exit")
                raise SystemExit(3)

    log.info("edge.shutdown")


def create_app(
    settings: Settings | None = None,
    *,
    skip_enrollment: bool = False,
) -> FastAPI:
    """Build the FastAPI app. Tests pass ``skip_enrollment=True``."""
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
    app.state.skip_enrollment = skip_enrollment
    app.state.enrollment_complete = False
    app.state.heartbeat = None

    app.include_router(health.router)
    app.include_router(decide.router, prefix="/v1")
    app.include_router(enroll.router, prefix="/v1")
    app.include_router(telemetry.router, prefix="/v1")

    return app
