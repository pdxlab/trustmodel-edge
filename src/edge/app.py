"""FastAPI app factory.

The factory pattern lets tests instantiate the app with overrides and the
production entrypoint (``edge.__main__``) wire it to uvicorn.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from edge import __version__
from edge.config import Settings, load_settings
from edge.logging import configure_logging
from edge.routes import decide, enroll, health, telemetry

log = structlog.get_logger()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("edge.startup", version=__version__, tenant=app.state.settings.tenant_id)
    yield
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
    app.include_router(decide.router, prefix="/v1")
    app.include_router(enroll.router, prefix="/v1")
    app.include_router(telemetry.router, prefix="/v1")

    return app
