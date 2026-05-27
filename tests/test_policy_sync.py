"""Tests for the sync loop functions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from edge.policy.cache import PolicyCache
from edge.policy.client import PolicyClient
from edge.policy.sync import sync_once, warm


def _payload() -> dict:
    return {
        "id": "pol-1",
        "tenant_id": "test-tenant",
        "name": "demo",
        "version": "1.0.0",
        "bundle": {
            "name": "demo",
            "version": "1.0.0",
            "description": "",
            "rules": [{"rule_id": "r1", "when": {"tool": "*"}, "then": "allow", "priority": 999}],
            "framework_tags": [],
        },
        "is_active": True,
        "created_at": datetime.now(UTC).isoformat(),
    }


def _client(handler, tmp_path: Path) -> PolicyClient:
    return PolicyClient(
        control_plane_url="http://aurora.test",
        state_dir=tmp_path,
        transport=httpx.MockTransport(handler),
        jwt_minter=lambda **_kw: "stub",
    )


@pytest.mark.asyncio
async def test_sync_once_populates_cache_and_persists(tmp_path: Path) -> None:
    cache = PolicyCache()
    handler = lambda _: httpx.Response(200, json=_payload())
    ok = await sync_once(_client(handler, tmp_path), cache, state_dir=tmp_path)
    assert ok is True
    assert cache.is_warm
    assert (tmp_path / "policy.json").exists()


@pytest.mark.asyncio
async def test_sync_once_returns_false_on_5xx_and_keeps_snapshot(tmp_path: Path) -> None:
    cache = PolicyCache()
    ok_handler = lambda _: httpx.Response(200, json=_payload())
    assert await sync_once(_client(ok_handler, tmp_path), cache, state_dir=tmp_path)
    snap_before = cache.snapshot()

    fail_handler = lambda _: httpx.Response(503, text="down")
    assert (
        await sync_once(_client(fail_handler, tmp_path), cache, state_dir=tmp_path)
        is False
    )
    assert cache.snapshot() is snap_before


@pytest.mark.asyncio
async def test_sync_once_404_logs_and_returns_false(tmp_path: Path) -> None:
    cache = PolicyCache()
    handler = lambda _: httpx.Response(404, json={"error": "no_active_policy"})
    ok = await sync_once(_client(handler, tmp_path), cache, state_dir=tmp_path)
    assert ok is False
    assert cache.is_warm is False


@pytest.mark.asyncio
async def test_warm_raises_when_first_fetch_fails_and_disk_empty(tmp_path: Path) -> None:
    cache = PolicyCache()
    handler = lambda _: httpx.Response(503, text="down")
    with pytest.raises(RuntimeError, match="could not be warmed"):
        await warm(_client(handler, tmp_path), cache, state_dir=tmp_path)


@pytest.mark.asyncio
async def test_warm_tolerates_failure_when_disk_cache_present(tmp_path: Path) -> None:
    # Seed disk via a successful sync first.
    cache = PolicyCache()
    ok_handler = lambda _: httpx.Response(200, json=_payload())
    await sync_once(_client(ok_handler, tmp_path), cache, state_dir=tmp_path)

    # Now warm a fresh cache that has loaded from disk; force a network
    # failure and verify it doesn't raise (disk fallback is acceptable).
    fresh_cache = PolicyCache()
    assert fresh_cache.load_from_disk(tmp_path) is True

    fail_handler = lambda _: httpx.Response(503, text="down")
    # Should not raise — fresh_cache is already warm via disk.
    await warm(_client(fail_handler, tmp_path), fresh_cache, state_dir=tmp_path)
    assert fresh_cache.is_warm
