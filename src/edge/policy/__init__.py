"""Policy sync, cache, and evaluation glue for Edge.

* :mod:`edge.policy.bundle`  — wire-format Pydantic models (mirror of
  ``aurora-gateway/rails/protocol.py``).
* :mod:`edge.policy.jwt`     — RS256 cert-JWT mint from the enrollment cert key.
* :mod:`edge.policy.client`  — HTTP client for ``GET /api/v1/edge/policy/current``.
* :mod:`edge.policy.cache`   — in-memory snapshot + on-disk JSON persistence.
* :mod:`edge.policy.sync`    — warm-up + periodic refresh loop.
* :mod:`edge.policy.stale`   — stale-policy detector that switches to fail mode.

Lifespan wires these together in :mod:`edge.app`.
"""

from edge.policy.bundle import EdgePolicy, Policy, PolicyRule
from edge.policy.cache import PolicyCache, get_cache, reset_cache
from edge.policy.client import PolicyClient, PolicyFetchError, PolicyNotFound

__all__ = [
    "EdgePolicy",
    "Policy",
    "PolicyCache",
    "PolicyClient",
    "PolicyFetchError",
    "PolicyNotFound",
    "PolicyRule",
    "get_cache",
    "reset_cache",
]
