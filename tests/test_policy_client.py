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
    handler = lambda _: httpx.Response(404, json={"error": "no_active_policy"})
    with pytest.raises(PolicyNotFound):
        await _client(handler, tmp_path).fetch()


@pytest.mark.asyncio
async def test_fetch_5xx_raises_policy_fetch_error(tmp_path: Path) -> None:
    handler = lambda _: httpx.Response(503, text="upstream down")
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
    handler = lambda _: httpx.Response(200, json={"unexpected": "shape"})
    with pytest.raises(PolicyFetchError):
        await _client(handler, tmp_path).fetch()
