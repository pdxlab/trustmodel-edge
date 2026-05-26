"""K8s-style health endpoints.

* ``GET /health/live``  — liveness. 200 while the process is responsive.
* ``GET /health/ready`` — readiness. 200 when Edge can serve ``decide()``.

Readiness will tighten in TRUS-987 (require enrollment complete) and TRUS-988
(require policy cache populated). For TRUS-986 the chart needs a probe target
that returns 200, so readiness mirrors liveness today.
"""

from __future__ import annotations

from fastapi import APIRouter

from edge import __version__

router = APIRouter(tags=["meta"])


@router.get("/health/live")
async def health_live() -> dict[str, str]:
    """Liveness — pod is up. Never touches disk or network."""
    return {"status": "ok"}


@router.get("/health/ready")
async def health_ready() -> dict[str, object]:
    """Readiness — Edge can serve traffic.

    TRUS-986 scope: trivially ready. TRUS-987 / TRUS-988 will gate on
    enrollment + first policy sync.
    """
    return {"status": "ready", "version": __version__}
