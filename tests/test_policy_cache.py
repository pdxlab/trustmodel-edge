"""Tests for the in-memory + on-disk policy cache."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from edge.policy.bundle import EdgePolicy, Policy, PolicyRule
from edge.policy.cache import PolicyCache


def _make_edge_policy(*, version: str = "1.0.0", rules: list | None = None) -> EdgePolicy:
    return EdgePolicy(
        id=f"pol-{version}",
        tenant_id="test-tenant",
        name="demo",
        version=version,
        bundle=Policy(
            name="demo",
            version=version,
            rules=rules
            or [PolicyRule(rule_id="r1", when={"tool": "*"}, then="allow", priority=999)],
        ),
        is_active=True,
        created_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_replace_makes_cache_warm_and_persists(tmp_path: Path) -> None:
    cache = PolicyCache()
    assert cache.is_warm is False
    await cache.replace(_make_edge_policy(), state_dir=tmp_path)
    assert cache.is_warm is True
    assert cache.last_success_at is not None
    snap = cache.snapshot()
    assert snap is not None
    assert snap.edge_policy.id == "pol-1.0.0"
    assert snap.compiled.policy_id == "pol-1.0.0"
    assert (tmp_path / "policy.json").exists()


@pytest.mark.asyncio
async def test_replace_atomically_swaps_snapshot(tmp_path: Path) -> None:
    cache = PolicyCache()
    await cache.replace(_make_edge_policy(version="1.0.0"), state_dir=tmp_path)
    first = cache.snapshot()

    await cache.replace(_make_edge_policy(version="2.0.0"), state_dir=tmp_path)
    second = cache.snapshot()

    assert first is not second
    assert second is not None and second.edge_policy.version == "2.0.0"


def test_load_from_disk_rehydrates(tmp_path: Path) -> None:
    # Persist manually via the same code path
    import asyncio
    seeded_cache = PolicyCache()
    asyncio.run(seeded_cache.replace(_make_edge_policy(), state_dir=tmp_path))

    new_cache = PolicyCache()
    assert new_cache.load_from_disk(tmp_path) is True
    assert new_cache.is_warm
    assert new_cache.snapshot().edge_policy.id == "pol-1.0.0"


def test_load_from_disk_missing_file_returns_false(tmp_path: Path) -> None:
    cache = PolicyCache()
    assert cache.load_from_disk(tmp_path) is False
    assert cache.is_warm is False


def test_load_from_disk_garbage_returns_false(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text("{not valid json", encoding="utf-8")
    cache = PolicyCache()
    assert cache.load_from_disk(tmp_path) is False
    assert cache.is_warm is False
