"""Shared pytest fixtures.

A single ``client`` fixture builds the FastAPI app with test-only settings
(no real bootstrap token / state dir / control plane required) and returns
a TestClient.

Tests that need enrollment-aware behavior get the ``ready_client`` fixture
which pre-populates app.state.heartbeat with a fake EdgeCredentials so
``/health/ready`` flips to 200.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from edge.app import create_app
from edge.config import Settings
from edge.heartbeat import HeartbeatState
from edge.identity import EdgeCredentials


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        tenant_id="test-tenant",
        pod_id="test-pod",
        bootstrap_token_path=tmp_path / "bootstrap-token",
        state_dir=tmp_path / "state",
        log_level="WARNING",
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings, skip_enrollment=True)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fake_credentials() -> EdgeCredentials:
    return EdgeCredentials(
        edge_id="00000000-0000-0000-0000-000000000001",
        tenant_id="test-tenant",
        cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        key_pem="-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        ca_chain_pem="-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n",
        cert_valid_to=datetime.now(timezone.utc) + timedelta(days=90),
        agp_endpoint="https://api.trustmodel.ai",
        telemetry_endpoint="https://api.trustmodel.ai/api/v1/edge/telemetry",
    )


@pytest.fixture
def ready_client(settings: Settings, fake_credentials: EdgeCredentials) -> Iterator[TestClient]:
    app = create_app(settings, skip_enrollment=True)
    app.state.heartbeat = HeartbeatState(fake_credentials)
    with TestClient(app) as c:
        yield c
