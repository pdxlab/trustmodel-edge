"""Stale-policy detection.

If the cache's ``last_success_at`` is older than ``stale_threshold_seconds``,
the policy is considered stale. ``decide()`` then applies the configured
fail mode:

* ``"open"``   — allow everything (audit log records the bypass)
* ``"closed"`` — deny everything (default, fail-safe)

The threshold check is read-only on the cache; nothing mutates here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from edge.policy.cache import PolicyCache

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StaleStatus:
    is_stale: bool
    seconds_since_refresh: float
    last_success_at: datetime | None


def status(cache: PolicyCache, *, threshold_seconds: int) -> StaleStatus:
    last = cache.last_success_at
    if last is None:
        return StaleStatus(is_stale=True, seconds_since_refresh=float("inf"), last_success_at=None)
    age = (datetime.now(UTC) - last).total_seconds()
    return StaleStatus(
        is_stale=age > threshold_seconds,
        seconds_since_refresh=age,
        last_success_at=last,
    )


def fail_mode_verdict(fail_mode: str) -> tuple[str, str]:
    """Return (verdict, reason) for the stale fail mode."""
    if fail_mode == "open":
        return "allow", "edge.policy_stale.fail_open"
    return "deny", "edge.policy_stale.fail_closed"
