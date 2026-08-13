"""HTTP client for the policy endpoints on aurora-gateway.

Pre-1716: one endpoint, ``GET /api/v1/edge/policy/current`` returning
one active policy.

Post-1716: new plural endpoint ``GET /api/v1/edge/policies/active``
returns all active policies for the tenant + hoisted authorized_clients.
Edge migrates to the plural via :meth:`PolicyClient.fetch_all`; the
singular :meth:`PolicyClient.fetch` remains for the
``EDGE_MULTI_POLICY_ENABLED=false`` rollout path AND as the fallback if
Aurora hasn't been upgraded yet (404 → singular). See TRUS-1716.

Failures surface through two exception types so the sync loop can log
differently for "policy not yet published" (404) vs everything else.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx

from edge.policy.bundle import AuthorizedClient, EdgePolicy
from edge.policy.jwt import mint_cert_jwt

logger = logging.getLogger(__name__)

_SINGULAR_PATH = "/api/v1/edge/policy/current/"
_PLURAL_PATH = "/api/v1/edge/policies/active/"


class PolicyFetchError(RuntimeError):
    """Transport / HTTP / parse failure. Caller decides retry policy."""


class PolicyNotFound(RuntimeError):
    """Aurora-gateway returned 404 — no active policy for this tenant.

    Also raised on the plural endpoint when Aurora is pre-1716 and the
    endpoint doesn't exist yet; :meth:`PolicyClient.fetch_all` catches
    this to fall back to the singular endpoint.
    """


class PolicyClient:
    """Thin wrapper around the policy-current + policies-active endpoints."""

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
        self._base_url = control_plane_url.rstrip("/")
        self._state_dir = state_dir
        self._timeout = request_timeout_seconds
        self._transport = transport
        self._mint = jwt_minter

    # ------------------------------------------------------------------ #
    # Singular (pre-1716) — one active policy, one wrapper on the wire.
    # ------------------------------------------------------------------ #

    async def fetch(self) -> EdgePolicy:
        """Return the current active policy, or raise.

        Raises:
            PolicyNotFound: 404 from gateway (no active policy for tenant).
            PolicyFetchError: transport error, 5xx, or malformed response.
        """
        payload = await self._http_get(_SINGULAR_PATH)
        try:
            return EdgePolicy.model_validate(payload)
        except (ValueError, TypeError) as exc:
            raise PolicyFetchError(f"invalid response body: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Plural (TRUS-1716) — all active policies, hoisted authorized_clients.
    # ------------------------------------------------------------------ #

    async def fetch_all(
        self,
    ) -> tuple[list[EdgePolicy], str | None, list[AuthorizedClient]]:
        """Return ``(policies, primary_name, authorized_clients)``.

        Falls back to the singular endpoint if Aurora 404s the plural
        one (Aurora is still on the pre-1716 shape) — the fetched policy
        is treated as the tenant's primary. Its
        ``authorized_clients`` field carries the per-policy list the
        pre-1716 shape shipped inside the wrapper.

        Raises:
            PolicyNotFound: BOTH endpoints 404 (tenant has no active policy).
            PolicyFetchError: transport error, 5xx, or malformed response.
        """
        try:
            payload = await self._http_get(_PLURAL_PATH)
        except PolicyNotFound:
            # Aurora is pre-1716 → fall back to the singular endpoint.
            one = await self.fetch()
            return (
                [one],
                one.bundle.name,
                list(one.authorized_clients),
            )
        try:
            raw_policies = payload["policies"]
            raw_clients = payload.get("authorized_clients", [])
        except (KeyError, TypeError) as exc:
            raise PolicyFetchError(
                f"invalid plural response body: missing keys ({exc})"
            ) from exc
        try:
            policies = [EdgePolicy.model_validate(p) for p in raw_policies]
            clients = [AuthorizedClient.model_validate(c) for c in raw_clients]
        except (ValueError, TypeError) as exc:
            raise PolicyFetchError(f"invalid plural response body: {exc}") from exc

        primary_name = next(
            (p.bundle.name for p in policies if p.is_primary), None
        )
        return policies, primary_name, clients

    # ------------------------------------------------------------------ #
    # Shared HTTP helper — cert-JWT auth + timeouts.
    # ------------------------------------------------------------------ #

    async def _http_get(self, path: str) -> Any:
        url = self._base_url + path
        token = self._mint(state_dir=self._state_dir)
        headers = {"Authorization": f"Bearer {token}"}
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout
            ) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise PolicyFetchError(f"transport error: {exc}") from exc

        if response.status_code == 404:
            raise PolicyNotFound(response.text[:200])
        if not response.is_success:
            raise PolicyFetchError(
                f"non-2xx {response.status_code}: {response.text[:200]}"
            )

        try:
            return response.json()
        except ValueError as exc:
            raise PolicyFetchError(f"invalid response body: {exc}") from exc
