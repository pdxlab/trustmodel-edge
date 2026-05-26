"""Shared pytest fixtures.

A single ``client`` fixture builds the FastAPI app with test-only settings
(no real bootstrap token / state dir required) and returns a TestClient.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from edge.app import create_app
from edge.config import Settings


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
    app = create_app(settings)
    with TestClient(app) as c:
        yield c
