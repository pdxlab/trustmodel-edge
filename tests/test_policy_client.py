"""Tests for the policy-current HTTP client (wire contract)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from edge.policy.client import PolicyClient, PolicyFetchError, PolicyNotFound


def _stub_jwt_minter(*, state_dir: Path, edge_id: str | None = None, ttl_seconds: int = 60) -> str:
    return "stub-jwt-token"


def _governance_payload() -> dict:
    return {
        "id": "pol-1",
        "tenant_id": "test-tenant",
        "name": "demo",
        "version": "1.0.0",
        "bundle": {
            "name": "demo",
            "version": "1.0.0",
            "description": "",
            "rules": [
                {
                    "rule_id": "r1",
                    "when": {"tool": "*"},
                    "then": "allow",
                    "framework_tags": [],
                    "priority": 999,
                }
            ],
            "framework_tags": [],
        },
        "is_active": True,
        "created_at": datetime.now(UTC).isoformat(),
    }


def _client(handler, tmp_path: Path) -> PolicyClient:
    return PolicyClient(
        control_plane_url="http://aurora.test",
        state_dir=tmp_path,
        transport=httpx.MockTransport(handler),
        jwt_minter=_stub_jwt_minter,
    )


@pytest.mark.asyncio
async def test_fetch_happy_path_sends_signed_jwt_and_parses_response(tmp_path: Path) -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json=_governance_payload())

    edge = await _client(handler, tmp_path).fetch()

    assert captured["url"] == "http://aurora.test/api/v1/edge/policy/current/"
    assert captured["auth"] == "Bearer stub-jwt-token"
    assert edge.id == "pol-1"
    assert edge.bundle.rules[0].rule_id == "r1"


@pytest.mark.asyncio
async def test_fetch_404_raises_policy_not_found(tmp_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "no_active_policy"})

    with pytest.raises(PolicyNotFound):
        await _client(handler, tmp_path).fetch()


@pytest.mark.asyncio
async def test_fetch_5xx_raises_policy_fetch_error(tmp_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    with pytest.raises(PolicyFetchError):
        await _client(handler, tmp_path).fetch()


@pytest.mark.asyncio
async def test_fetch_transport_error_raises_policy_fetch_error(tmp_path: Path) -> None:
    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable")

    with pytest.raises(PolicyFetchError):
        await _client(boom, tmp_path).fetch()


@pytest.mark.asyncio
async def test_fetch_malformed_body_raises_policy_fetch_error(tmp_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    with pytest.raises(PolicyFetchError):
        await _client(handler, tmp_path).fetch()


# ---------------------------------------------------------------------- #
# TRUS-1716 — plural endpoint + singular fallback.
# ---------------------------------------------------------------------- #


def _policy_dict(name: str, *, is_primary: bool = False) -> dict:
    return {
        "id": f"pol-{name}",
        "tenant_id": "test-tenant",
        "name": name,
        "version": "1.0.0",
        "bundle": {
            "name": name,
            "version": "1.0.0",
            "description": "",
            "rules": [
                {
                    "rule_id": f"r-{name}",
                    "when": {"tool": "*"},
                    "then": "allow",
                    "framework_tags": [],
                    "priority": 999,
                }
            ],
            "framework_tags": [],
        },
        "is_active": True,
        "is_primary": is_primary,
        "created_at": datetime.now(UTC).isoformat(),
    }


@pytest.mark.asyncio
async def test_fetch_all_happy_path_hits_plural_endpoint(tmp_path: Path) -> None:
    """Plural endpoint returns list + hoisted authorized_clients."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "policies": [
                    _policy_dict("alpha", is_primary=True),
                    _policy_dict("beta"),
                ],
                "authorized_clients": [
                    {
                        "client_id": "cid-1",
                        "client_name": "one",
                        "client_secret_hash": "pbkdf2$1$x$x",
                        "allowed_scopes": ["govern:enforce"],
                    }
                ],
            },
        )

    policies, primary_name, clients = await _client(handler, tmp_path).fetch_all()

    assert captured["url"] == "http://aurora.test/api/v1/edge/policies/active/"
    assert [p.bundle.name for p in policies] == ["alpha", "beta"]
    assert primary_name == "alpha"
    assert len(clients) == 1
    assert clients[0].client_id == "cid-1"


@pytest.mark.asyncio
async def test_fetch_all_no_primary_returns_none(tmp_path: Path) -> None:
    """No policy in the payload has ``is_primary=True`` → primary_name is None."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "policies": [_policy_dict("alpha"), _policy_dict("beta")],
                "authorized_clients": [],
            },
        )

    policies, primary_name, clients = await _client(handler, tmp_path).fetch_all()

    assert len(policies) == 2
    assert primary_name is None
    assert clients == []


@pytest.mark.asyncio
async def test_fetch_all_falls_back_to_singular_on_404(tmp_path: Path) -> None:
    """Aurora hasn't shipped the plural endpoint yet — 404 on the plural
    path triggers a fallback to the singular endpoint. The returned
    policy is treated as the tenant's primary."""
    urls_hit: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls_hit.append(request.url.path)
        if request.url.path.endswith("/policies/active/"):
            return httpx.Response(404, json={"error": "not_found"})
        return httpx.Response(200, json=_policy_dict("solo", is_primary=False))

    policies, primary_name, clients = await _client(handler, tmp_path).fetch_all()

    # Both endpoints hit (plural first, then singular fallback).
    assert urls_hit[0].endswith("/policies/active/")
    assert urls_hit[1].endswith("/policy/current/")
    # Fallback treats the sole policy as primary regardless of ``is_primary``
    # on the singular payload — pre-1716 Aurora doesn't ship the field.
    assert len(policies) == 1
    assert policies[0].bundle.name == "solo"
    assert primary_name == "solo"
    assert clients == []


@pytest.mark.asyncio
async def test_fetch_all_singular_fallback_still_404_raises(tmp_path: Path) -> None:
    """Both endpoints 404 → tenant genuinely has no active policy;
    propagate the singular's PolicyNotFound to the sync loop."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "not_found"})

    with pytest.raises(PolicyNotFound):
        await _client(handler, tmp_path).fetch_all()


@pytest.mark.asyncio
async def test_fetch_all_malformed_body_raises_policy_fetch_error(tmp_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        # Missing "policies" key.
        return httpx.Response(200, json={"authorized_clients": []})

    with pytest.raises(PolicyFetchError):
        await _client(handler, tmp_path).fetch_all()
