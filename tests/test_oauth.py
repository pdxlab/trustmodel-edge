"""Tests for ``edge.oauth`` + ``/v1/oauth/token`` (TRUS-1270 Phase 2).

Two layers:

* **Unit tests** (pure-function): PBKDF2 verify, scope narrowing, JWT
  mint/verify round-trip, client lookup.
* **Integration tests**: TestClient against ``/v1/oauth/token`` with a
  pre-seeded policy cache + RSA key on disk.
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from edge.app import create_app
from edge.config import Settings
from edge.oauth import (
    InvalidClient,
    InvalidToken,
    authenticate_client,
    derive_public_key_pem,
    find_authorized_client,
    mint_agent_token,
    narrow_scopes,
    verify_agent_token,
    verify_django_pbkdf2,
)
from edge.policy import cache as cache_mod
from edge.policy.bundle import AuthorizedClient, EdgePolicy, Policy, PolicyRule

# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


def _make_django_pbkdf2_hash(secret: str, *, iterations: int = 600000) -> str:
    """Build a Django-format PBKDF2 hash so tests don't need Django."""
    salt = "test-salt-for-trus-1270"
    derived = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(derived).decode('ascii')}"


def _make_rsa_keypair() -> tuple[str, bytes]:
    """Generate an ephemeral RSA-2048 key. Returns (private PEM, public PEM)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = derive_public_key_pem(private_pem)
    return private_pem, public_pem


def _make_authorized_client(
    *,
    client_id: str = "client-alpha",
    secret: str = "tmoa_alpha_secret",
    scopes: list[str] | None = None,
    agent_id: str | None = "alpha-agent",
    client_name: str = "agp/alpha",
) -> tuple[AuthorizedClient, str]:
    """Return (AuthorizedClient, raw_secret) for use in tests."""
    return (
        AuthorizedClient(
            client_id=client_id,
            client_name=client_name,
            client_secret_hash=_make_django_pbkdf2_hash(secret),
            allowed_scopes=scopes if scopes is not None else ["govern:enforce"],
            agent_id=agent_id,
        ),
        secret,
    )


# ─────────────────────────────────────────────────────────────────────
# Unit — verify_django_pbkdf2
# ─────────────────────────────────────────────────────────────────────


class TestVerifyDjangoPBKDF2:
    def test_correct_secret_verifies(self) -> None:
        hashed = _make_django_pbkdf2_hash("hunter2")
        assert verify_django_pbkdf2("hunter2", hashed) is True

    def test_wrong_secret_does_not_verify(self) -> None:
        hashed = _make_django_pbkdf2_hash("hunter2")
        assert verify_django_pbkdf2("wrong", hashed) is False

    def test_malformed_hash_returns_false(self) -> None:
        assert verify_django_pbkdf2("secret", "not-a-hash") is False
        assert verify_django_pbkdf2("secret", "pbkdf2_sha256$abc$salt$hash") is False
        assert verify_django_pbkdf2("secret", "") is False

    def test_legacy_algorithm_rejected(self) -> None:
        """We only accept pbkdf2_sha256. Don't fall through to weaker algos."""
        assert (
            verify_django_pbkdf2("hunter2", "md5$1000$salt$00000000000000000000000000000000")
            is False
        )

    def test_different_iterations_still_verify(self) -> None:
        """Iteration count is parsed from the hash — works across Django versions."""
        hashed = _make_django_pbkdf2_hash("hunter2", iterations=100000)
        assert verify_django_pbkdf2("hunter2", hashed) is True


# ─────────────────────────────────────────────────────────────────────
# Unit — narrow_scopes + find_authorized_client + authenticate_client
# ─────────────────────────────────────────────────────────────────────


class TestScopeNarrowing:
    def test_intersection(self) -> None:
        assert narrow_scopes(["govern:enforce", "evaluate:run"], ["govern:enforce"]) == [
            "govern:enforce"
        ]

    def test_empty_request_yields_empty(self) -> None:
        assert narrow_scopes([], ["govern:enforce"]) == []

    def test_preserves_request_order(self) -> None:
        allowed = ["a", "b", "c"]
        assert narrow_scopes(["c", "a"], allowed) == ["c", "a"]


class TestAuthenticateClient:
    def test_happy_path(self) -> None:
        ac, secret = _make_authorized_client()
        result = authenticate_client(
            client_id=ac.client_id,
            client_secret=secret,
            authorized=[ac],
        )
        assert result is ac

    def test_unknown_client(self) -> None:
        ac, secret = _make_authorized_client()
        with pytest.raises(InvalidClient, match="unknown"):
            authenticate_client(client_id="nope", client_secret=secret, authorized=[ac])

    def test_wrong_secret(self) -> None:
        ac, _ = _make_authorized_client()
        with pytest.raises(InvalidClient, match="invalid client_secret"):
            authenticate_client(client_id=ac.client_id, client_secret="wrong", authorized=[ac])

    def test_empty_authorized_list(self) -> None:
        with pytest.raises(InvalidClient):
            authenticate_client(client_id="anything", client_secret="anything", authorized=[])


class TestFindAuthorizedClient:
    def test_match(self) -> None:
        a, _ = _make_authorized_client(client_id="a")
        b, _ = _make_authorized_client(client_id="b")
        assert find_authorized_client("b", [a, b]) is b

    def test_no_match(self) -> None:
        a, _ = _make_authorized_client(client_id="a")
        assert find_authorized_client("z", [a]) is None


# ─────────────────────────────────────────────────────────────────────
# Unit — JWT mint + verify round-trip
# ─────────────────────────────────────────────────────────────────────


class TestJWTRoundTrip:
    def test_mint_and_verify_happy_path(self) -> None:
        private_pem, public_pem = _make_rsa_keypair()
        token, ttl = mint_agent_token(
            client_id="client-x",
            agent_id="agent-x",
            granted_scopes=["govern:enforce"],
            ttl_seconds=3600,
            private_key_pem=private_pem,
            issuer="edge:test",
        )
        assert ttl == 3600
        claims = verify_agent_token(token, public_pem)
        assert claims.sub == "client-x"
        assert claims.agent_id == "agent-x"
        assert claims.scopes == ["govern:enforce"]
        assert claims.exp > claims.iat

    def test_expired_token_rejected(self) -> None:
        private_pem, public_pem = _make_rsa_keypair()
        # Mint with negative TTL → already expired.
        token, _ = mint_agent_token(
            client_id="client-x",
            agent_id=None,
            granted_scopes=["govern:enforce"],
            ttl_seconds=1,
            private_key_pem=private_pem,
            issuer="edge:test",
        )
        time.sleep(2)
        with pytest.raises(InvalidToken):
            verify_agent_token(token, public_pem)

    def test_wrong_signing_key_rejected(self) -> None:
        private_pem_a, _ = _make_rsa_keypair()
        _, public_pem_b = _make_rsa_keypair()
        token, _ = mint_agent_token(
            client_id="client-x",
            agent_id=None,
            granted_scopes=["govern:enforce"],
            ttl_seconds=3600,
            private_key_pem=private_pem_a,
            issuer="edge:test",
        )
        with pytest.raises(InvalidToken):
            verify_agent_token(token, public_pem_b)

    def test_missing_required_claims_rejected(self) -> None:
        """A hand-crafted JWT without exp/iat/sub fails verify."""
        private_pem, public_pem = _make_rsa_keypair()
        token = jwt.encode({"scope": "govern:enforce"}, private_pem, algorithm="RS256")
        with pytest.raises(InvalidToken):
            verify_agent_token(token, public_pem)

    def test_agent_id_optional(self) -> None:
        """Tokens for clients with no GovernedAgent leave agent_id null."""
        private_pem, public_pem = _make_rsa_keypair()
        token, _ = mint_agent_token(
            client_id="client-x",
            agent_id=None,
            granted_scopes=["govern:enforce"],
            ttl_seconds=3600,
            private_key_pem=private_pem,
            issuer="edge:test",
        )
        claims = verify_agent_token(token, public_pem)
        assert claims.agent_id is None


# ─────────────────────────────────────────────────────────────────────
# Integration — POST /v1/oauth/token
# ─────────────────────────────────────────────────────────────────────


def _seed_cache_with_clients(state_dir: Path, clients: list[AuthorizedClient]) -> None:
    import asyncio

    cache = cache_mod.get_cache()
    edge_policy = EdgePolicy(
        id="pol-test",
        tenant_id="test-tenant",
        name="test",
        version="1.0.0",
        bundle=Policy(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    rule_id="allow-all",
                    when={"tool": "*"},
                    then="allow",
                    framework_tags=[],
                    priority=999,
                ),
            ],
            framework_tags=[],
        ),
        is_active=True,
        created_at=datetime.now(UTC),
        authorized_clients=clients,
    )
    asyncio.new_event_loop().run_until_complete(cache.replace(edge_policy, state_dir=state_dir))


@pytest.fixture
def oauth_client(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[TestClient, AuthorizedClient, str]]:
    """TestClient with seeded policy cache + RSA key on disk + 1 authorized client."""
    from tests.conftest import _stub_lifespan_network

    _stub_lifespan_network(monkeypatch)
    monkeypatch.setattr("edge.app.reset_cache", lambda: None)

    settings.state_dir.mkdir(parents=True, exist_ok=True)
    private_pem, _ = _make_rsa_keypair()
    (settings.state_dir / "key.pem").write_text(private_pem, encoding="utf-8")

    ac, secret = _make_authorized_client()
    _seed_cache_with_clients(settings.state_dir, [ac])

    app = create_app(settings, skip_enrollment=True)
    with TestClient(app) as c:
        yield c, ac, secret


class TestOAuthTokenEndpoint:
    def test_happy_path_returns_jwt(self, oauth_client) -> None:
        client, ac, secret = oauth_client
        r = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": ac.client_id,
                "client_secret": secret,
                "scope": "govern:enforce",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3600
        assert body["scope"] == "govern:enforce"
        # Token claims round-trip via signature
        assert body["access_token"]

    def test_wrong_secret_returns_401_invalid_client(self, oauth_client) -> None:
        client, ac, _ = oauth_client
        r = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": ac.client_id,
                "client_secret": "WRONG",
                "scope": "govern:enforce",
            },
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_client"

    def test_unknown_client_returns_401_invalid_client(self, oauth_client) -> None:
        client, _, secret = oauth_client
        r = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "no-such-client",
                "client_secret": secret,
                "scope": "govern:enforce",
            },
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_client"

    def test_wrong_grant_type_returns_400(self, oauth_client) -> None:
        client, ac, secret = oauth_client
        r = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "password",
                "client_id": ac.client_id,
                "client_secret": secret,
            },
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "unsupported_grant_type"

    def test_scope_intersection_narrows(self, oauth_client) -> None:
        """Requested scopes ∩ allowed_scopes; un-allowed scopes are silently dropped
        when at least one allowed scope is granted."""
        client, ac, secret = oauth_client
        r = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": ac.client_id,
                "client_secret": secret,
                "scope": "govern:enforce evaluate:run",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["scope"] == "govern:enforce"

    def test_all_requested_scopes_disallowed_returns_400(self, oauth_client) -> None:
        client, ac, secret = oauth_client
        r = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": ac.client_id,
                "client_secret": secret,
                "scope": "evaluate:run",  # not in allowed_scopes (default [govern:enforce])
            },
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_scope"

    def test_cold_cache_returns_503(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Edge without a policy snapshot doesn't know who's authorized → 503."""
        from tests.conftest import _stub_lifespan_network

        _stub_lifespan_network(monkeypatch)
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        private_pem, _ = _make_rsa_keypair()
        (settings.state_dir / "key.pem").write_text(private_pem, encoding="utf-8")

        app = create_app(settings, skip_enrollment=True)
        with TestClient(app) as c:
            r = c.post(
                "/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "any",
                    "client_secret": "any",
                    "scope": "govern:enforce",
                },
            )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "service_unavailable"
