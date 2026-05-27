"""HTTP client for ``GET /api/v1/edge/policy/current``.

Calls aurora-gateway, signs the request with a fresh cert-JWT, parses
the response into an :class:`~edge.policy.bundle.EdgePolicy`.

Failures are surfaced through two exception types so the sync loop can
log differently for "policy not yet published" (404) vs everything else.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx

from edge.policy.bundle import EdgePolicy
from edge.policy.jwt import mint_cert_jwt

logger = logging.getLogger(__name__)

_PATH = "/api/v1/edge/policy/current/"


class PolicyFetchError(RuntimeError):
    """Transport / HTTP / parse failure. Caller decides retry policy."""


class PolicyNotFound(RuntimeError):
    """Aurora-gateway returned 404 — no active policy for this tenant."""


class PolicyClient:
    """Thin wrapper around the policy-current endpoint."""

    def __init__(
        self,
        *,
        control_plane_url: str,
        state_dir: Path,
        request_timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        # Test override: mint_cert_jwt reads from disk; tests inject a stub.
        jwt_minter: Any = mint_cert_jwt,
    ) -> None:
        self._url = control_plane_url.rstrip("/") + _PATH
        self._state_dir = state_dir
        self._timeout = request_timeout_seconds
        self._transport = transport
        self._mint = jwt_minter

    async def fetch(self) -> EdgePolicy:
        """Return the current active policy, or raise.

        Raises:
            PolicyNotFound: 404 from gateway (no active policy for tenant).
            PolicyFetchError: transport error, 5xx, or malformed response.
        """
        token = self._mint(state_dir=self._state_dir)
        headers = {"Authorization": f"Bearer {token}"}

        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout
            ) as client:
                response = await client.get(self._url, headers=headers)
        except httpx.HTTPError as exc:
            raise PolicyFetchError(f"transport error: {exc}") from exc

        if response.status_code == 404:
            raise PolicyNotFound(response.text[:200])
        if not response.is_success:
            raise PolicyFetchError(
                f"non-2xx {response.status_code}: {response.text[:200]}"
            )

        try:
            payload = response.json()
            return EdgePolicy.model_validate(payload)
        except (ValueError, TypeError) as exc:
            raise PolicyFetchError(f"invalid response body: {exc}") from exc
