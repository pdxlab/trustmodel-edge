"""Policy sync loop.

* :func:`warm` — first sync, awaited by lifespan before readiness flips.
  If the disk cache has data, warm is allowed to fail; if disk is empty
  too, raise so readiness stays red.
* :func:`run_forever` — periodic refresh. Cancelled by lifespan on shutdown.

Failures log and return ``False``; the previous snapshot keeps serving.
Stale-policy detection runs separately (see :mod:`edge.policy.stale`).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from edge.policy.cache import PolicyCache
from edge.policy.client import PolicyClient, PolicyFetchError, PolicyNotFound

logger = logging.getLogger(__name__)


async def sync_once(client: PolicyClient, cache: PolicyCache, *, state_dir: Path) -> bool:
    """One fetch+swap cycle. Never raises.

    Returns True on success, False otherwise.
    """
    try:
        edge_policy = await client.fetch()
    except PolicyNotFound as exc:
        logger.info("edge.sync.no_active_policy", extra={"detail": str(exc)})
        return False
    except PolicyFetchError as exc:
        logger.warning("edge.sync.failed", extra={"detail": str(exc)})
        return False

    try:
        await cache.replace(edge_policy, state_dir=state_dir)
    except Exception:  # noqa: BLE001
        logger.exception("edge.sync.cache_replace_failed")
        return False

    logger.info(
        "edge.sync.ok",
        extra={
            "policy_id": edge_policy.id,
            "version": edge_policy.version,
            "rules": len(edge_policy.bundle.rules),
        },
    )
    return True


async def warm(
    client: PolicyClient,
    cache: PolicyCache,
    *,
    state_dir: Path,
    require_success: bool = False,
) -> None:
    """First sync, blocking startup.

    If ``require_success=True`` and the fetch fails, raises so the
    readiness probe never flips. Otherwise, a failed warm is acceptable
    as long as the disk cache has data — the periodic loop will retry.
    """
    ok = await sync_once(client, cache, state_dir=state_dir)
    if ok:
        return
    if require_success or not cache.is_warm:
        raise RuntimeError(
            "edge policy cache could not be warmed; no disk fallback either"
        )
    logger.warning(
        "edge.sync.warm_failed_using_disk_snapshot",
        extra={"refreshed_at": str(cache.last_success_at)},
    )


async def run_forever(
    client: PolicyClient,
    cache: PolicyCache,
    *,
    state_dir: Path,
    interval_seconds: int,
) -> None:
    """Refresh loop. Cancelled by the lifespan on shutdown."""
    while True:
        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            raise
        await sync_once(client, cache, state_dir=state_dir)
