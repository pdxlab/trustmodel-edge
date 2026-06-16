"""Auth-failure tests for ``POST /v1/decide`` (TRUS-1270 Phase 2).

The happy path is covered in ``test_decide.py``. These tests cover the
negative auth surface: missing Authorization header, malformed header,
invalid signature, expired token, wrong-scope token.
"""

from __future__ import annotations

import time

from edge.oauth import mint_agent_token


def test_missing_authorization_header_returns_401(warm_client) -> None:
    client, _ = warm_client
    r = client.post("/v1/decide", json={"tool": "search.query", "args": {}})
    assert r.status_code == 401
    assert r.headers.get("www-authenticate") == "Bearer"


def test_non_bearer_authorization_returns_401(warm_client) -> None:
    client, _ = warm_client
    r = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {}},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert r.status_code == 401


def test_empty_bearer_returns_401(warm_client) -> None:
    client, _ = warm_client
    r = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {}},
        headers={"Authorization": "Bearer "},
    )
    assert r.status_code == 401


def test_garbage_jwt_returns_401(warm_client) -> None:
    client, _ = warm_client
    r = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {}},
        headers={"Authorization": "Bearer not.a.jwt"},
    )
    assert r.status_code == 401


def test_jwt_signed_by_wrong_key_returns_401(warm_client, tmp_path) -> None:
    """A JWT signed with a different RSA key — Edge can't verify."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    foreign_pem = foreign_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    token, _ = mint_agent_token(
        client_id="x",
        agent_id="x",
        granted_scopes=["govern:enforce"],
        ttl_seconds=3600,
        private_key_pem=foreign_pem,
        issuer="edge:test",
    )
    client, _ = warm_client
    r = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


def test_token_missing_govern_enforce_returns_403(warm_client, settings) -> None:
    """Token that auth'd correctly but lacks the required scope → 403."""
    private_pem = (settings.state_dir / "key.pem").read_text(encoding="utf-8")
    token, _ = mint_agent_token(
        client_id="test-client-id",
        agent_id="test-agent-slug",
        granted_scopes=["evaluate:run"],  # missing govern:enforce
        ttl_seconds=3600,
        private_key_pem=private_pem,
        issuer="edge:test-tenant",
    )
    client, _ = warm_client
    r = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403
    assert "govern:enforce" in r.json()["detail"]


def test_expired_token_returns_401(warm_client, settings) -> None:
    private_pem = (settings.state_dir / "key.pem").read_text(encoding="utf-8")
    token, _ = mint_agent_token(
        client_id="test-client-id",
        agent_id="test-agent-slug",
        granted_scopes=["govern:enforce"],
        ttl_seconds=1,
        private_key_pem=private_pem,
        issuer="edge:test-tenant",
    )
    time.sleep(2)
    client, _ = warm_client
    r = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


def test_token_agent_id_propagates_to_audit(warm_client) -> None:
    """The audit event must use the JWT-derived agent_id, not whatever
    the request body claims. This is the key property the auth gives us."""
    from edge.telemetry.store import get_store

    client, auth = warm_client
    r = client.post(
        "/v1/decide",
        json={
            "tool": "search.query",
            "args": {},
            "agent_id": "client-claimed-agent-id",  # should be ignored
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 1
    audit = events[0].payload
    assert audit["agent_id"] == "test-agent-slug"  # from token, not body
