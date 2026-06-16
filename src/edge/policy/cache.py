"""In-memory policy cache with on-disk JSON persistence.

A single :class:`CacheSnapshot` is held under ``_snapshot``. Sync builds a
new snapshot, persists it to ``<state_dir>/policy.json``, and swaps the
reference atomically. Readers see either the previous or the new
snapshot, never a half-applied state.

On startup, :meth:`load_from_disk` rehydrates the snapshot so a pod
restart can serve immediately, before the first network sync completes.
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

_POLICY_FILENAME = "policy.json"


@dataclass(frozen=True)
class CacheSnapshot:
    edge_policy: EdgePolicy
    compiled: CompiledPolicy
    refreshed_at: datetime


class PolicyCache:
    """Process-wide policy snapshot. Read-mostly, atomic-swap writes."""

    def __init__(self) -> None:
        self._snapshot: CacheSnapshot | None = None
        self._write_lock = asyncio.Lock()
        self._last_success_at: datetime | None = None

    @property
    def is_warm(self) -> bool:
        return self._snapshot is not None

    @property
    def last_success_at(self) -> datetime | None:
        return self._last_success_at

    def snapshot(self) -> CacheSnapshot | None:
        return self._snapshot

    def compiled(self) -> CompiledPolicy | None:
        snap = self._snapshot
        return snap.compiled if snap else None

    def authorized_clients(self) -> list:
        """Return the OAuthClient list shipped with the current policy snapshot.

        Empty list when no snapshot yet (cold cache). Items are
        ``edge.policy.bundle.AuthorizedClient`` — kept as a forward-ref to
        avoid a circular import at module load.
        """
        snap = self._snapshot
        return list(snap.edge_policy.authorized_clients) if snap else []

    async def replace(self, edge_policy: EdgePolicy, *, state_dir: Path | None = None) -> None:
        """Compile + swap + persist.

        Compilation is pure; if it raises (malformed bundle), the existing
        snapshot is preserved and the exception bubbles to the sync loop
        which logs + retries next cycle.
        """
        compiled = compile_policy(
            policy_id=edge_policy.id,
            name=edge_policy.bundle.name,
            version=edge_policy.bundle.version,
            rules=[r.model_dump() for r in edge_policy.bundle.rules],
            framework_tags=edge_policy.bundle.framework_tags,
        )
        new_snapshot = CacheSnapshot(
            edge_policy=edge_policy,
            compiled=compiled,
            refreshed_at=datetime.now(UTC),
        )
        async with self._write_lock:
            self._snapshot = new_snapshot
            self._last_success_at = new_snapshot.refreshed_at
            if state_dir is not None:
                _persist_to_disk(state_dir, edge_policy)

    def load_from_disk(self, state_dir: Path) -> bool:
        """Rehydrate from ``<state_dir>/policy.json``. Returns True on hit.

        Used at startup so a pod restart can serve decisions immediately,
        before the first sync completes. Safe to call before warm-up —
        ``refreshed_at`` is set to the disk file's mtime so the stale
        detector can decide whether the on-disk copy is still serviceable.
        """
        path = state_dir / _POLICY_FILENAME
        if not path.exists():
            return False
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            edge_policy = EdgePolicy.model_validate(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("edge.cache.disk_load_failed", extra={"detail": str(exc)})
            return False
        compiled = compile_policy(
            policy_id=edge_policy.id,
            name=edge_policy.bundle.name,
            version=edge_policy.bundle.version,
            rules=[r.model_dump() for r in edge_policy.bundle.rules],
            framework_tags=edge_policy.bundle.framework_tags,
        )
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        self._snapshot = CacheSnapshot(
            edge_policy=edge_policy, compiled=compiled, refreshed_at=mtime
        )
        self._last_success_at = mtime
        return True


def _persist_to_disk(state_dir: Path, edge_policy: EdgePolicy) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    target = state_dir / _POLICY_FILENAME
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(edge_policy.model_dump_json(), encoding="utf-8")
    tmp.replace(target)


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
