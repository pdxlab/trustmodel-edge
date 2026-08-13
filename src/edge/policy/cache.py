"""In-memory policy cache with on-disk JSON persistence.

**TRUS-1716 multi-policy layer:**

The pre-1716 world held a single ``CacheSnapshot`` under ``_snapshot``.
Post-1716 we hold a ``dict[name -> CacheSnapshot]`` under ``_snapshots``
+ a ``_primary_name`` string naming the tenant's default. ``compiled()``
still returns the primary's ``CompiledPolicy`` so pre-1716 call sites
(and the ``EDGE_MULTI_POLICY_ENABLED=false`` code path) keep working
byte-identically. New call sites use ``compiled_by_name(name)`` for
explicit routing.

Atomic swaps use a single write lock — readers either see the previous
dict or the new one, never a half-populated one.

On startup, :meth:`load_from_disk` reads the new manifest first; if
absent, falls back to the legacy ``policy.json`` layout and treats that
single policy as primary (one-time on-disk migration on first boot with
the new image).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from edge.engine import CompiledPolicy, compile_policy
from edge.policy.bundle import EdgePolicy

logger = logging.getLogger(__name__)

# Pre-1716 singular layout — one file at ``<state_dir>/policy.json``
# holding a single EdgePolicy JSON. Read on first-boot after the upgrade
# so an existing pod's on-disk cache still serves before the first
# network sync completes.
_LEGACY_FILENAME = "policy.json"

# Post-1716 multi-policy layout:
#   ``<state_dir>/manifest.json`` — small JSON with primary name + names list.
#   ``<state_dir>/policies/<name>.json`` — one EdgePolicy per file.
_MANIFEST_FILENAME = "manifest.json"
_POLICIES_SUBDIR = "policies"


@dataclass(frozen=True)
class CacheSnapshot:
    edge_policy: EdgePolicy
    compiled: CompiledPolicy
    refreshed_at: datetime


class PolicyCache:
    """Process-wide policy map. Read-mostly, atomic-swap writes."""

    def __init__(self) -> None:
        self._snapshots: dict[str, CacheSnapshot] = {}
        self._primary_name: str | None = None
        self._write_lock = asyncio.Lock()
        self._last_success_at: datetime | None = None

    @property
    def is_warm(self) -> bool:
        return bool(self._snapshots)

    @property
    def last_success_at(self) -> datetime | None:
        return self._last_success_at

    # ------------------------------------------------------------------ #
    # Read API — dict-based (TRUS-1716)
    # ------------------------------------------------------------------ #

    def compiled_by_name(self, name: str) -> CompiledPolicy | None:
        """Return the compiled policy registered under ``name``, or None."""
        snap = self._snapshots.get(name)
        return snap.compiled if snap else None

    def snapshot_by_name(self, name: str) -> CacheSnapshot | None:
        return self._snapshots.get(name)

    def primary_compiled(self) -> CompiledPolicy | None:
        """Return the primary's compiled policy, or None if no primary."""
        if self._primary_name is None:
            return None
        return self.compiled_by_name(self._primary_name)

    def primary_name(self) -> str | None:
        return self._primary_name

    def all_names(self) -> list[str]:
        """Return the currently-cached policy names, sorted for determinism."""
        return sorted(self._snapshots.keys())

    # ------------------------------------------------------------------ #
    # Backward-compat read API — the singular ``compiled()`` /
    # ``snapshot()`` / ``authorized_clients()`` methods are what pre-1716
    # call sites use. They resolve to the primary snapshot so
    # EDGE_MULTI_POLICY_ENABLED=false behaves byte-identically. Removed
    # in Phase 1c once every call site opts into the dict API.
    # ------------------------------------------------------------------ #

    def snapshot(self) -> CacheSnapshot | None:
        if self._primary_name is None:
            return None
        return self._snapshots.get(self._primary_name)

    def compiled(self) -> CompiledPolicy | None:
        return self.primary_compiled()

    def authorized_clients(self) -> list:
        """Return the OAuthClient list for the primary snapshot.

        Pre-1716 shipped one list per snapshot; post-1716 the plural
        endpoint hoists ``authorized_clients`` to the wrapper and Edge
        stores a single de-duplicated list on the primary. Callers that
        need the raw wrapper list should read
        ``_authorized_clients_shared`` (added below) — the getter kept
        for backward compat serves the primary's copy.
        """
        snap = self.snapshot()
        return list(snap.edge_policy.authorized_clients) if snap else []

    # ------------------------------------------------------------------ #
    # Write API
    # ------------------------------------------------------------------ #

    async def replace(self, edge_policy: EdgePolicy, *, state_dir: Path | None = None) -> None:
        """Legacy singular replace — kept for EDGE_MULTI_POLICY_ENABLED=false.

        Treats the passed policy as the sole tenant policy AND its primary.
        Persists to the legacy ``policy.json`` layout so a downgrade to
        pre-1716 image still finds the on-disk cache.
        """
        compiled = _compile(edge_policy)
        new_snapshot = CacheSnapshot(
            edge_policy=edge_policy,
            compiled=compiled,
            refreshed_at=datetime.now(UTC),
        )
        async with self._write_lock:
            self._snapshots = {edge_policy.bundle.name: new_snapshot}
            self._primary_name = edge_policy.bundle.name
            self._last_success_at = new_snapshot.refreshed_at
            if state_dir is not None:
                _persist_legacy_to_disk(state_dir, edge_policy)

    async def replace_all(
        self,
        policies: list[EdgePolicy],
        *,
        primary_name: str | None,
        state_dir: Path | None = None,
    ) -> None:
        """Atomic-swap the entire named-policy map (TRUS-1716).

        ``primary_name`` names the tenant's default; must appear in
        ``policies`` OR be ``None`` (edge case: tenant has no primary
        flagged — decide() with no ``policy_name`` returns 503).
        Partial state never leaks: readers see either the OLD dict or
        the fully-populated new one.
        """
        new_snapshots: dict[str, CacheSnapshot] = {}
        now = datetime.now(UTC)
        for p in policies:
            new_snapshots[p.bundle.name] = CacheSnapshot(
                edge_policy=p,
                compiled=_compile(p),
                refreshed_at=now,
            )
        # Sanity: if a primary was named but no matching bundle came
        # through, log + clear so decide() falls into the "no primary"
        # branch cleanly instead of holding a stale pointer.
        if primary_name is not None and primary_name not in new_snapshots:
            logger.warning(
                "edge.cache.replace_all.primary_missing_from_payload",
                extra={"primary_name": primary_name, "names": list(new_snapshots)},
            )
            primary_name = None

        async with self._write_lock:
            self._snapshots = new_snapshots
            self._primary_name = primary_name
            self._last_success_at = now
            if state_dir is not None:
                _persist_manifest_to_disk(
                    state_dir, policies, primary_name=primary_name
                )

    def load_from_disk(self, state_dir: Path) -> bool:
        """Rehydrate from disk. Returns True on hit.

        Order of preference:
        1. New manifest layout (``<state_dir>/manifest.json`` +
           ``<state_dir>/policies/<name>.json``).
        2. Legacy singular layout (``<state_dir>/policy.json``) — treated
           as primary; the next successful sync rewrites in new layout.
        """
        if self._load_manifest(state_dir):
            return True
        return self._load_legacy(state_dir)

    # ------------------------------------------------------------------ #
    # Private disk helpers
    # ------------------------------------------------------------------ #

    def _load_manifest(self, state_dir: Path) -> bool:
        manifest_path = state_dir / _MANIFEST_FILENAME
        if not manifest_path.exists():
            return False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            names: list[str] = list(manifest.get("names", []))
            primary_name: str | None = manifest.get("primary_name")
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning(
                "edge.cache.manifest_load_failed", extra={"detail": str(exc)}
            )
            return False

        snapshots: dict[str, CacheSnapshot] = {}
        for name in names:
            policy_path = state_dir / _POLICIES_SUBDIR / f"{name}.json"
            if not policy_path.exists():
                logger.warning(
                    "edge.cache.manifest_missing_policy_file",
                    extra={"name": name, "path": str(policy_path)},
                )
                continue
            try:
                raw = json.loads(policy_path.read_text(encoding="utf-8"))
                edge_policy = EdgePolicy.model_validate(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning(
                    "edge.cache.policy_file_load_failed",
                    extra={"name": name, "detail": str(exc)},
                )
                continue
            mtime = datetime.fromtimestamp(policy_path.stat().st_mtime, tz=UTC)
            snapshots[edge_policy.bundle.name] = CacheSnapshot(
                edge_policy=edge_policy,
                compiled=_compile(edge_policy),
                refreshed_at=mtime,
            )

        if not snapshots:
            return False

        if primary_name is not None and primary_name not in snapshots:
            primary_name = None

        # Sync APIs are async, but load_from_disk runs at startup before
        # the event loop enters serving state — no writers can race here.
        self._snapshots = snapshots
        self._primary_name = primary_name
        # Use the newest file mtime as last_success_at so stale detector
        # has a proximate signal.
        self._last_success_at = max(s.refreshed_at for s in snapshots.values())
        return True

    def _load_legacy(self, state_dir: Path) -> bool:
        legacy_path = state_dir / _LEGACY_FILENAME
        if not legacy_path.exists():
            return False
        try:
            raw = json.loads(legacy_path.read_text(encoding="utf-8"))
            edge_policy = EdgePolicy.model_validate(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "edge.cache.disk_load_failed", extra={"detail": str(exc)}
            )
            return False
        mtime = datetime.fromtimestamp(legacy_path.stat().st_mtime, tz=UTC)
        snapshot = CacheSnapshot(
            edge_policy=edge_policy,
            compiled=_compile(edge_policy),
            refreshed_at=mtime,
        )
        self._snapshots = {edge_policy.bundle.name: snapshot}
        # Legacy layout is singular by definition → treat as primary.
        self._primary_name = edge_policy.bundle.name
        self._last_success_at = mtime
        return True


def _compile(edge_policy: EdgePolicy) -> CompiledPolicy:
    return compile_policy(
        policy_id=edge_policy.id,
        name=edge_policy.bundle.name,
        version=edge_policy.bundle.version,
        rules=[r.model_dump() for r in edge_policy.bundle.rules],
        framework_tags=edge_policy.bundle.framework_tags,
    )


def _persist_legacy_to_disk(state_dir: Path, edge_policy: EdgePolicy) -> None:
    """Write the legacy singular ``policy.json`` file (pre-1716 layout)."""
    state_dir.mkdir(parents=True, exist_ok=True)
    target = state_dir / _LEGACY_FILENAME
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(edge_policy.model_dump_json(), encoding="utf-8")
    tmp.replace(target)


def _persist_manifest_to_disk(
    state_dir: Path,
    policies: list[EdgePolicy],
    *,
    primary_name: str | None,
) -> None:
    """Write the new manifest + one policy file per name (TRUS-1716)."""
    state_dir.mkdir(parents=True, exist_ok=True)
    policies_dir = state_dir / _POLICIES_SUBDIR
    policies_dir.mkdir(parents=True, exist_ok=True)

    # Overwrite each per-name file (tmp + rename for atomicity per-file).
    for p in policies:
        target = policies_dir / f"{p.bundle.name}.json"
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(p.model_dump_json(), encoding="utf-8")
        tmp.replace(target)

    # Drop per-name files that are no longer part of the manifest.
    current_names = {p.bundle.name for p in policies}
    for existing in policies_dir.glob("*.json"):
        if existing.stem not in current_names:
            try:
                existing.unlink()
            except OSError as exc:
                logger.warning(
                    "edge.cache.orphan_delete_failed",
                    extra={"path": str(existing), "detail": str(exc)},
                )

    manifest = {
        "primary_name": primary_name,
        "names": sorted(p.bundle.name for p in policies),
    }
    manifest_target = state_dir / _MANIFEST_FILENAME
    manifest_tmp = manifest_target.with_suffix(".json.tmp")
    manifest_tmp.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_tmp.replace(manifest_target)


_cache_singleton: PolicyCache | None = None


def get_cache() -> PolicyCache:
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = PolicyCache()
    return _cache_singleton


def reset_cache() -> None:
    """Tests use this to drop the singleton between cases."""
    global _cache_singleton
    _cache_singleton = None
