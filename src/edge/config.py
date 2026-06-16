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

    # ─── Telemetry (TRUS-989) ────────────────────────────────────────
    telemetry_queue_size: int = Field(
        default=10_000,
        ge=100,
        le=1_000_000,
        description="Max events in the on-disk queue before back-pressure drops new ones",
    )
    telemetry_batch_size: int = Field(
        default=100,
        ge=1,
        le=10_000,
        description="Max events the sender ships per POST to /api/v1/edge/telemetry",
    )
    telemetry_flush_interval_seconds: float = Field(
        default=5.0,
        ge=0.5,
        le=300.0,
        description="Idle sleep between drain cycles when the queue is empty or unreachable",
    )
    telemetry_drain_timeout_seconds: float = Field(
        default=30.0,
        ge=0.0,
        le=300.0,
        description="Shutdown deadline for flushing remaining queued events",
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

    # ── OAuth (TRUS-1270) ───────────────────────────────────────────────
    # TTL for JWTs minted at POST /v1/oauth/token. 1h matches aurora-gateway's
    # default; agents re-request on expiry. Configurable down to 1 min for
    # tests / aggressive rotation, up to 24h for low-churn deployments.
    oauth_token_ttl_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="TTL for agent JWTs minted by Edge at /v1/oauth/token",
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
