"""Edge runtime configuration — env-driven, validated at startup.

All settings come from environment variables (12-factor). The Helm chart
maps ``values.yaml`` keys to these env vars via ConfigMap + Secret. Naming
mirrors agp-control-plane: ``EDGE_*`` prefix, double-underscore for nesting
where needed.
"""

from __future__ import annotations

from pathlib import Path

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

    # ─── Observability ───────────────────────────────────────────────
    log_level: str = Field(
        default="INFO",
        description="Python log level: DEBUG / INFO / WARNING / ERROR",
    )

    # ─── HTTP server ─────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0")  # noqa: S104 - container binds all
    port: int = Field(default=8080, ge=1, le=65535)

    # ─── Enrollment (TRUS-987) ───────────────────────────────────────
    # Convenience override for local dev/Docker — when set, takes
    # precedence over reading the bootstrap-token file from disk. In K8s
    # the Helm chart mounts the token via a Secret at
    # bootstrap_token_path, so leave this empty there.
    bootstrap_token: str = Field(
        default="",
        description="Bootstrap token override (dev/test). Empty → read from bootstrap_token_path.",
    )
    cluster_fingerprint: str = Field(
        default="",
        description="Stable cluster identifier. K8s sets via downward API; local dev leaves empty.",
    )

    # Heartbeat tick interval (server-side returns canonical 60s but we
    # honor a local override for tests).
    heartbeat_interval_s: int = Field(default=60, ge=5, le=3600)


def load_settings() -> Settings:
    """Load + validate settings. Called once at app startup."""
    return Settings()  # type: ignore[call-arg]
