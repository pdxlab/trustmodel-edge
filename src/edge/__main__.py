"""Production entrypoint — ``python -m edge`` or ``edge`` console script.

Uvicorn binds to the host/port from ``Settings``. Single-worker by design;
K8s scales via HPA across pods rather than per-pod worker count, which keeps
graceful shutdown + telemetry queue ownership simple.
"""

from __future__ import annotations

import uvicorn

from edge.app import create_app
from edge.config import load_settings


def main() -> None:
    settings = load_settings()
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,  # structlog already configured via create_app
        access_log=False,  # noisy; rely on structured request logs (added in TRUS-988)
    )


if __name__ == "__main__":
    main()
