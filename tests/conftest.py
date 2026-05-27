"""Shared pytest fixtures.

Two TestClient fixtures:

* ``client``      — vanilla Edge with the policy-sync warm/refresh stubbed
  to no-ops. Cache stays cold. Use for tests that don't depend on a
  policy being cached (health probes, stub routes, etc.).
* ``warm_client`` — same as above but pre-seeds the cache with a small
  demo policy so ``decide()`` returns deterministic verdicts. Use for
  end-to-end ``/v1/decide`` tests.

The autouse ``_reset_singletons`` fixture drops the policy-cache and
prometheus-metrics state between tests so a previous test's snapshot or
counter value can't leak into the next test.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from edge.app import create_app
from edge.config import Settings
from edge.policy import cache as cache_mod
from edge.policy.bundle import EdgePolicy, Policy, PolicyRule


@pytest.fixture(autouse=True)
def _reset_singletons() -> Iterator[None]:
    cache_mod.reset_cache()
    yield
    cache_mod.reset_cache()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        tenant_id="test-tenant",
        pod_id="test-pod",
        bootstrap_token_path=tmp_path / "bootstrap-token",
        state_dir=tmp_path / "state",
        log_level="WARNING",
    )


def _stub_lifespan_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace warm + run_forever so the lifespan does not call out."""
    import asyncio

    from edge import app as app_mod

    async def _warm_stub(_client, _cache, *, state_dir, require_success=False):
        return None

    async def _run_forever_stub(_client, _cache, *, state_dir, interval_seconds):
        # Block forever; the lifespan cancels us on shutdown.
        await asyncio.Event().wait()

    monkeypatch.setattr(app_mod, "policy_warm", _warm_stub)
    monkeypatch.setattr(app_mod, "policy_run_forever", _run_forever_stub)


@pytest.fixture
def client(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    _stub_lifespan_network(monkeypatch)
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


def _demo_edge_policy() -> EdgePolicy:
    return EdgePolicy(
        id="pol-demo-1",
        tenant_id="test-tenant",
        name="demo",
        version="1.0.0",
        bundle=Policy(
            name="demo",
            version="1.0.0",
            description="test fixture",
            rules=[
                PolicyRule(
                    rule_id="deny-email",
                    when={"tool": "email.send"},
                    then="deny",
                    framework_tags=[],
                    priority=10,
                ),
                PolicyRule(
                    rule_id="redact-ssn",
                    when={"tool": "*", "args.ssn": True},
                    then="redact:args.ssn",
                    framework_tags=[],
                    priority=50,
                ),
                PolicyRule(
                    rule_id="allow-rest",
                    when={"tool": "*"},
                    then="allow",
                    framework_tags=[],
                    priority=999,
                ),
            ],
            framework_tags=[],
        ),
        is_active=True,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def warm_client(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    """TestClient with a pre-seeded policy cache."""
    _stub_lifespan_network(monkeypatch)

    # Seed cache before lifespan kicks in. _reset_singletons already
    # cleared it. The cache singleton survives lifespan start/stop in
    # this test scope, but app.shutdown also calls reset_cache. To
    # keep the cache populated through the lifespan, also stub out
    # reset_cache so app.shutdown doesn't blow it away.
    monkeypatch.setattr("edge.app.reset_cache", lambda: None)

    import asyncio

    cache = cache_mod.get_cache()
    asyncio.new_event_loop().run_until_complete(
        cache.replace(_demo_edge_policy(), state_dir=settings.state_dir)
    )

    app = create_app(settings)
    with TestClient(app) as c:
        yield c
