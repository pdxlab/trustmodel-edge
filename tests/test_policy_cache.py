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


# ---------------------------------------------------------------------- #
# TRUS-1716 — multi-policy dict cache tests.
# ---------------------------------------------------------------------- #


def _make_edge_policy_named(
    name: str, *, is_primary: bool = False, version: str = "1.0.0"
) -> EdgePolicy:
    return EdgePolicy(
        id=f"pol-{name}-{version}",
        tenant_id="test-tenant",
        name=name,
        version=version,
        bundle=Policy(
            name=name,
            version=version,
            rules=[
                PolicyRule(
                    rule_id=f"r-{name}",
                    when={"tool": "*"},
                    then="allow",
                    priority=999,
                )
            ],
        ),
        is_active=True,
        is_primary=is_primary,
        created_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_replace_all_populates_per_name_dict(tmp_path: Path) -> None:
    cache = PolicyCache()
    policies = [
        _make_edge_policy_named("alpha", is_primary=True),
        _make_edge_policy_named("beta"),
        _make_edge_policy_named("gamma"),
    ]
    await cache.replace_all(policies, primary_name="alpha", state_dir=tmp_path)

    assert cache.is_warm
    assert cache.primary_name() == "alpha"
    # Per-name lookup.
    assert cache.compiled_by_name("alpha") is not None
    assert cache.compiled_by_name("beta") is not None
    assert cache.compiled_by_name("gamma") is not None
    # Unknown name → None (not a crash).
    assert cache.compiled_by_name("does-not-exist") is None
    # Sorted names for determinism.
    assert cache.all_names() == ["alpha", "beta", "gamma"]
    # Primary resolves.
    assert cache.primary_compiled() is not None
    assert cache.primary_compiled().name == "alpha"
    # Manifest + per-name files on disk.
    assert (tmp_path / "manifest.json").exists()
    assert (tmp_path / "policies" / "alpha.json").exists()
    assert (tmp_path / "policies" / "beta.json").exists()
    assert (tmp_path / "policies" / "gamma.json").exists()


@pytest.mark.asyncio
async def test_replace_all_missing_primary_in_payload_clears_primary(
    tmp_path: Path,
) -> None:
    """If primary_name doesn't match any policy in the batch, clear the
    primary pointer rather than hold a phantom reference."""
    cache = PolicyCache()
    await cache.replace_all(
        [_make_edge_policy_named("alpha")],
        primary_name="ghost",  # not in the list
        state_dir=tmp_path,
    )
    assert cache.primary_name() is None
    assert cache.primary_compiled() is None


@pytest.mark.asyncio
async def test_replace_all_second_call_evicts_missing_names(tmp_path: Path) -> None:
    """A subsequent ``replace_all`` fully replaces the map — names that
    weren't in the new payload are evicted from the cache AND their
    per-name JSON files are deleted."""
    cache = PolicyCache()
    await cache.replace_all(
        [
            _make_edge_policy_named("alpha", is_primary=True),
            _make_edge_policy_named("beta"),
        ],
        primary_name="alpha",
        state_dir=tmp_path,
    )
    assert (tmp_path / "policies" / "beta.json").exists()

    # Second sync — beta is gone.
    await cache.replace_all(
        [_make_edge_policy_named("alpha", is_primary=True)],
        primary_name="alpha",
        state_dir=tmp_path,
    )
    assert cache.compiled_by_name("beta") is None
    assert cache.all_names() == ["alpha"]
    # Orphan file on disk gets cleaned up.
    assert not (tmp_path / "policies" / "beta.json").exists()


@pytest.mark.asyncio
async def test_replace_all_atomic_swap(tmp_path: Path) -> None:
    """A concurrent reader observes either the OLD map or the NEW map,
    never a half-populated one. We can't cheaply schedule true race
    conditions in asyncio, but we can verify the read APIs read from a
    single dict reference at each snapshot boundary."""
    cache = PolicyCache()
    await cache.replace_all(
        [_make_edge_policy_named("alpha", is_primary=True)],
        primary_name="alpha",
        state_dir=tmp_path,
    )
    assert cache.compiled_by_name("alpha") is not None
    assert cache.compiled_by_name("beta") is None

    await cache.replace_all(
        [
            _make_edge_policy_named("alpha", is_primary=True),
            _make_edge_policy_named("beta"),
        ],
        primary_name="alpha",
        state_dir=tmp_path,
    )
    assert cache.compiled_by_name("alpha") is not None
    assert cache.compiled_by_name("beta") is not None


@pytest.mark.asyncio
async def test_replace_singular_still_works_for_backcompat(tmp_path: Path) -> None:
    """Pre-1716 ``replace()`` API keeps working — treats the passed policy
    as sole tenant policy AND its primary. Writes the legacy
    ``policy.json`` layout for downgrade safety."""
    cache = PolicyCache()
    await cache.replace(_make_edge_policy_named("solo"), state_dir=tmp_path)

    assert cache.is_warm
    assert cache.primary_name() == "solo"
    assert cache.compiled_by_name("solo") is not None
    # Legacy singular API — resolves to the primary snapshot.
    assert cache.compiled() is not None
    assert cache.compiled().name == "solo"
    assert (tmp_path / "policy.json").exists()


def test_load_from_disk_prefers_new_manifest_over_legacy(tmp_path: Path) -> None:
    """After upgrade, both files may briefly coexist on disk. The
    manifest layout wins so we serve the multi-policy world."""
    import asyncio
    import json as _json

    seeded_cache = PolicyCache()
    asyncio.new_event_loop().run_until_complete(
        seeded_cache.replace_all(
            [
                _make_edge_policy_named("alpha", is_primary=True),
                _make_edge_policy_named("beta"),
            ],
            primary_name="alpha",
            state_dir=tmp_path,
        )
    )
    # Also write a legacy file — should be ignored.
    (tmp_path / "policy.json").write_text(
        _json.dumps(
            {
                "id": "legacy",
                "tenant_id": "test-tenant",
                "name": "legacy-solo",
                "version": "0.0.1",
                "bundle": {
                    "name": "legacy-solo",
                    "version": "0.0.1",
                    "rules": [],
                    "framework_tags": [],
                },
                "is_active": True,
                "created_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    new_cache = PolicyCache()
    assert new_cache.load_from_disk(tmp_path) is True
    assert set(new_cache.all_names()) == {"alpha", "beta"}
    assert new_cache.primary_name() == "alpha"


def test_load_from_disk_falls_back_to_legacy_when_no_manifest(tmp_path: Path) -> None:
    """First boot after upgrade: no manifest yet, but the old
    ``policy.json`` still exists. Read it + treat as primary; the next
    successful sync writes the new manifest layout."""
    import asyncio

    seeded_cache = PolicyCache()
    asyncio.new_event_loop().run_until_complete(
        seeded_cache.replace(_make_edge_policy_named("legacy-solo"), state_dir=tmp_path)
    )
    # Confirm only legacy file exists, no manifest.
    assert (tmp_path / "policy.json").exists()
    assert not (tmp_path / "manifest.json").exists()

    new_cache = PolicyCache()
    assert new_cache.load_from_disk(tmp_path) is True
    assert new_cache.is_warm
    assert new_cache.all_names() == ["legacy-solo"]
    assert new_cache.primary_name() == "legacy-solo"
    assert new_cache.primary_compiled() is not None
