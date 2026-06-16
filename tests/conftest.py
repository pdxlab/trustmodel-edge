"""Shared pytest fixtures.

Three TestClient fixtures + helpers, covering the combined surface of
TRUS-987 (enrollment + heartbeat) and TRUS-988/989 (policy cache + sync +
telemetry sender):

* ``client``       — vanilla Edge with enrollment skipped and policy /
  telemetry network calls stubbed. Cache stays cold. Use for tests that
  don't depend on a policy being cached (stub routes, basic liveness).
* ``ready_client`` — same as ``client`` but pre-populates
  ``app.state.heartbeat`` with a fake :class:`EdgeCredentials` so
  enrollment-aware tests can assert behavior post-enrollment. Cache
  stays cold (these tests cover the enrollment / heartbeat surface only).
* ``warm_client``  — same as ``client`` but pre-seeds the policy cache
  with a small demo bundle so ``decide()`` returns deterministic
  verdicts. Use for end-to-end ``/v1/decide`` tests.

The autouse ``_reset_singletons`` fixture drops the policy cache,
telemetry store, and prometheus metric state between tests so a previous
test's snapshot or counter value can't leak into the next.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from edge.app import create_app
from edge.config import Settings
from edge.heartbeat import HeartbeatState
from edge.identity import EdgeCredentials
from edge.policy import cache as cache_mod
from edge.policy.bundle import AuthorizedClient, EdgePolicy, Policy, PolicyRule
from edge.telemetry import store as telemetry_store_mod


@pytest.fixture(autouse=True)
def _reset_singletons() -> Iterator[None]:
    cache_mod.reset_cache()
    telemetry_store_mod.reset_store()
    yield
    cache_mod.reset_cache()
    telemetry_store_mod.reset_store()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        tenant_id="test-tenant",
        pod_id="test-pod",
        bootstrap_token_path=tmp_path / "bootstrap-token",
        state_dir=tmp_path / "state",
        log_level="WARNING",
    )


def _stub_lifespan_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace warm + run_forever + telemetry sender so lifespan never calls out."""
    import asyncio

    from edge import app as app_mod

    async def _warm_stub(_client, _cache, *, state_dir, require_success=False):
        return None

    async def _run_forever_stub(_client, _cache, *, state_dir, interval_seconds):
        # Block forever; the lifespan cancels us on shutdown.
        await asyncio.Event().wait()

    monkeypatch.setattr(app_mod, "policy_warm", _warm_stub)
    monkeypatch.setattr(app_mod, "policy_run_forever", _run_forever_stub)

    # Sender's run_forever would try to mint a cert-JWT against an
    # empty state_dir. Replace it with an inert coroutine so the
    # lifespan task can be created and cancelled without errors.
    async def _sender_run_forever_stub(self):
        await asyncio.Event().wait()

    async def _flush_now_stub(_sender, *, deadline_seconds):
        return 0

    monkeypatch.setattr(
        "edge.telemetry.sender.TelemetrySender.run_forever",
        _sender_run_forever_stub,
    )
    monkeypatch.setattr(app_mod, "telemetry_flush_now", _flush_now_stub)


@pytest.fixture
def client(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    _stub_lifespan_network(monkeypatch)
    app = create_app(settings, skip_enrollment=True)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fake_credentials() -> EdgeCredentials:
    return EdgeCredentials(
        edge_id="00000000-0000-0000-0000-000000000001",
        tenant_id="test-tenant",
        cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        key_pem="-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        ca_chain_pem="-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n",
        cert_valid_to=datetime.now(UTC) + timedelta(days=90),
        agp_endpoint="https://api.trustmodel.ai",
        telemetry_endpoint="https://api.trustmodel.ai/api/v1/edge/telemetry",
    )


@pytest.fixture
def ready_client(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    fake_credentials: EdgeCredentials,
) -> Iterator[TestClient]:
    """Enrolled + heartbeat attached + cache warmed → /health/ready returns 200."""
    _stub_lifespan_network(monkeypatch)
    # Keep the seeded cache through lifespan shutdown.
    monkeypatch.setattr("edge.app.reset_cache", lambda: None)

    import asyncio

    cache = cache_mod.get_cache()
    asyncio.new_event_loop().run_until_complete(
        cache.replace(_demo_edge_policy(), state_dir=settings.state_dir)
    )

    app = create_app(settings, skip_enrollment=True)
    app.state.heartbeat = HeartbeatState(fake_credentials)
    with TestClient(app) as c:
        yield c


def _demo_edge_policy(*, authorized_clients: list[AuthorizedClient] | None = None) -> EdgePolicy:
    return EdgePolicy(
        id="pol-demo-1",
        tenant_id="test-tenant",
        name="demo",
        version="1.0.0",
        bundle=Policy(
            name="demo",
            version="1.0.0",
            description="test fixture",
            rules=[
                PolicyRule(
                    rule_id="deny-email",
                    when={"tool": "email.send"},
                    then="deny",
                    framework_tags=[],
                    priority=10,
                ),
                PolicyRule(
                    rule_id="redact-ssn",
                    when={"tool": "*", "args.ssn": True},
                    then="redact:args.ssn",
                    framework_tags=[],
                    priority=50,
                ),
                PolicyRule(
                    rule_id="allow-rest",
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
        authorized_clients=authorized_clients or [],
    )


@pytest.fixture
def warm_client(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[TestClient, dict[str, str]]]:
    """TestClient with a pre-seeded policy cache + a valid Bearer header.

    Returns ``(client, auth_headers)``. TRUS-1270 made the /decide
    endpoint OAuth-authenticated; existing tests that hit /decide must
    pass ``**auth_headers`` so requests carry a token Edge can verify.

    The fixture provisions:
      * an RSA private key at ``<state_dir>/key.pem`` (Edge would normally
        get this via enrollment — we generate one ephemerally for the test)
      * one AuthorizedClient bundled in the seeded EdgePolicy
      * a freshly-minted Bearer token for that client
    """
    _stub_lifespan_network(monkeypatch)

    # Keep the seeded cache through lifespan shutdown.
    monkeypatch.setattr("edge.app.reset_cache", lambda: None)

    # RSA key on disk so /oauth/token + /decide can sign/verify locally.
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = _make_test_rsa_keypair()
    (settings.state_dir / "key.pem").write_text(private_pem, encoding="utf-8")

    # Seed cache with one AuthorizedClient so /decide can resolve the
    # token's sub when verifying.
    test_client_id = "test-client-id"
    ac = AuthorizedClient(
        client_id=test_client_id,
        client_name="test/agent",
        client_secret_hash="pbkdf2_sha256$1$x$x",  # unused — we mint the token directly
        allowed_scopes=["govern:enforce"],
        agent_id="test-agent-slug",
    )

    import asyncio

    cache = cache_mod.get_cache()
    asyncio.new_event_loop().run_until_complete(
        cache.replace(_demo_edge_policy(authorized_clients=[ac]), state_dir=settings.state_dir)
    )

    # Mint a bearer token directly with the on-disk key. Same code path
    # as /v1/oauth/token would produce.
    from edge.oauth import mint_agent_token

    token, _ = mint_agent_token(
        client_id=test_client_id,
        agent_id="test-agent-slug",
        granted_scopes=["govern:enforce"],
        ttl_seconds=3600,
        private_key_pem=private_pem,
        issuer="edge:test-tenant",
    )
    auth_headers = {"Authorization": f"Bearer {token}"}

    app = create_app(settings, skip_enrollment=True)
    with TestClient(app) as c:
        yield c, auth_headers


def _make_test_rsa_keypair() -> tuple[str, bytes]:
    """Local helper — generates an ephemeral RSA-2048 keypair (PEM)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem
