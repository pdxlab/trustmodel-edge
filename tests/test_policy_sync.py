"""Tests for the sync loop functions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

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
    def _stub_minter(**_kw: object) -> str:
        return "stub"

    return PolicyClient(
        control_plane_url="http://aurora.test",
        state_dir=tmp_path,
        transport=httpx.MockTransport(handler),
        jwt_minter=_stub_minter,
    )


def _ok_handler(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=_payload())


def _down_handler(_: httpx.Request) -> httpx.Response:
    return httpx.Response(503, text="down")


def _404_handler(_: httpx.Request) -> httpx.Response:
    return httpx.Response(404, json={"error": "no_active_policy"})


@pytest.mark.asyncio
async def test_sync_once_populates_cache_and_persists(tmp_path: Path) -> None:
    cache = PolicyCache()
    ok = await sync_once(_client(_ok_handler, tmp_path), cache, state_dir=tmp_path)
    assert ok is True
    assert cache.is_warm
    assert (tmp_path / "policy.json").exists()


@pytest.mark.asyncio
async def test_sync_once_returns_false_on_5xx_and_keeps_snapshot(tmp_path: Path) -> None:
    cache = PolicyCache()
    assert await sync_once(_client(_ok_handler, tmp_path), cache, state_dir=tmp_path)
    snap_before = cache.snapshot()

    assert (
        await sync_once(_client(_down_handler, tmp_path), cache, state_dir=tmp_path)
        is False
    )
    assert cache.snapshot() is snap_before


@pytest.mark.asyncio
async def test_sync_once_404_logs_and_returns_false(tmp_path: Path) -> None:
    cache = PolicyCache()
    ok = await sync_once(_client(_404_handler, tmp_path), cache, state_dir=tmp_path)
    assert ok is False
    assert cache.is_warm is False


@pytest.mark.asyncio
async def test_warm_raises_when_first_fetch_fails_and_disk_empty(tmp_path: Path) -> None:
    cache = PolicyCache()
    with pytest.raises(RuntimeError, match="could not be warmed"):
        await warm(_client(_down_handler, tmp_path), cache, state_dir=tmp_path)


@pytest.mark.asyncio
async def test_warm_tolerates_failure_when_disk_cache_present(tmp_path: Path) -> None:
    # Seed disk via a successful sync first.
    cache = PolicyCache()
    await sync_once(_client(_ok_handler, tmp_path), cache, state_dir=tmp_path)

    # Now warm a fresh cache that has loaded from disk; force a network
    # failure and verify it doesn't raise (disk fallback is acceptable).
    fresh_cache = PolicyCache()
    assert fresh_cache.load_from_disk(tmp_path) is True

    # Should not raise — fresh_cache is already warm via disk.
    await warm(_client(_down_handler, tmp_path), fresh_cache, state_dir=tmp_path)
    assert fresh_cache.is_warm
