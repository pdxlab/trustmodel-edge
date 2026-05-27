"""Edge runtime configuration — env-driven, validated at startup.

All settings come from environment variables (12-factor). The Helm chart
maps ``values.yaml`` keys to these env vars via ConfigMap + Secret. Naming
mirrors agp-control-plane: ``EDGE_*`` prefix, double-underscore for nesting
where needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime config for the Edge pod.

    Reads from env first, then ``.env`` file when present (dev only).
    """

    model_config = SettingsConfigDict(
        env_prefix="EDGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ─── Identity ────────────────────────────────────────────────────
    tenant_id: str = Field(
        ...,
        description="Tenant slug this Edge instance serves (set by Helm install)",
    )
    pod_id: str = Field(
        default="edge-local",
        description="Stable pod identifier; in K8s set from metadata.name via downward API",
    )

    # ─── Control plane (TrustModel side) ─────────────────────────────
    control_plane_url: HttpUrl = Field(
        default=HttpUrl("https://api.trustmodel.ai"),
        description="aurora-gateway base URL for enrollment / policy sync / telemetry",
    )

    # ─── Bootstrap ───────────────────────────────────────────────────
    bootstrap_token_path: Path = Field(
        default=Path("/etc/trustmodel/bootstrap-token"),
        description="Path to one-time bootstrap token file (mounted from K8s Secret)",
    )

    # ─── Storage ─────────────────────────────────────────────────────
    state_dir: Path = Field(
        default=Path("/var/lib/trustmodel"),
        description="Root of persistent state: mTLS cert, policy cache, telemetry queue",
    )

    # ─── Telemetry ───────────────────────────────────────────────────
    telemetry_queue_size: int = Field(
        default=10_000,
        ge=100,
        le=1_000_000,
        description="Max in-memory telemetry events before back-pressure kicks in",
    )

    # ─── Policy sync (TRUS-988) ──────────────────────────────────────
    policy_sync_interval_seconds: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Seconds between successful policy refreshes",
    )
    policy_stale_threshold_seconds: int = Field(
        default=3600,
        ge=60,
        description="After this many seconds without a successful sync, "
        "switch to the configured fail mode",
    )
    policy_fail_mode: Literal["open", "closed"] = Field(
        default="closed",
        description="What decide() returns once the cache is stale. "
        "'closed' is fail-safe; 'open' is for non-compliance-critical tenants.",
    )
    policy_request_timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        le=60.0,
        description="HTTP timeout for /api/v1/edge/policy/current calls",
    )

    # ─── Observability ───────────────────────────────────────────────
    log_level: str = Field(
        default="INFO",
        description="Python log level: DEBUG / INFO / WARNING / ERROR",
    )

    # ─── HTTP server ─────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0")  # noqa: S104 - container binds all
    port: int = Field(default=8080, ge=1, le=65535)


def load_settings() -> Settings:
    """Load + validate settings. Called once at app startup."""
    return Settings()  # type: ignore[call-arg]
