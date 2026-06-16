"""Agent-facing OAuth: token mint, JWT verify, Django-PBKDF2 secret check.

TRUS-1270 Phase 2. Edge serves ``POST /v1/oauth/token`` to in-cluster
agents — accepting ``client_credentials``, validating the secret against
the policy-sync'd ``authorized_clients`` list, and returning a short-lived
JWT signed with the Edge's own enrollment cert private key. The same key
is used to verify tokens presented at ``POST /v1/decide``.

This module is intentionally pure / framework-agnostic so it can be
exercised by unit tests without spinning up FastAPI. The FastAPI route
layer (``src/edge/routes/oauth.py``) is the only consumer.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization

from edge.policy.bundle import AuthorizedClient
from edge.policy.jwt import _KEY_FILE, EnrollmentMissing, _read_or_raise

_ALG = "RS256"


class TokenError(Exception):
    """Base class for all OAuth-side failures Edge surfaces to the agent."""


class InvalidClient(TokenError):
    """Unknown client_id or wrong client_secret. Surfaces as 401."""


class InvalidScope(TokenError):
    """Requested scope contains something the client isn't allowed. 400."""


class InvalidToken(TokenError):
    """JWT failed signature / exp / claim validation. Surfaces as 401."""


# ─────────────────────────────────────────────────────────────────────
# Django PBKDF2 verification
#
# Django's hashed-password wire format:
#   ``pbkdf2_sha256$<iterations>$<salt>$<hash_b64>``
# We parse + recompute + constant-time compare. No new dependencies —
# stdlib ``hashlib.pbkdf2_hmac`` is sufficient.
# ─────────────────────────────────────────────────────────────────────


def verify_django_pbkdf2(presented_secret: str, encoded_hash: str) -> bool:
    """Return True iff ``presented_secret`` hashes to ``encoded_hash``.

    Accepts Django's ``pbkdf2_sha256$...`` format. Any other algorithm
    prefix returns False (we don't accept legacy MD5/SHA1 hashes).
    """
    try:
        algorithm, iterations_str, salt, expected_b64 = encoded_hash.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        iterations = int(iterations_str)
    except ValueError:
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        presented_secret.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    derived_b64 = base64.b64encode(derived).decode("ascii").strip()
    return hmac.compare_digest(derived_b64, expected_b64.strip())


# ─────────────────────────────────────────────────────────────────────
# JWT mint / verify
#
# Signed with the Edge's enrollment cert private key (RS256), the same
# key that ``edge.policy.jwt.mint_cert_jwt`` uses for outbound cert-JWTs.
# Tokens are valid ONLY at the issuing Edge — agents never present them
# to aurora-gateway.
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AgentTokenClaims:
    """Parsed JWT claims surfaced to ``/decide`` after verification."""

    sub: str  # client_id
    agent_id: str | None
    scopes: list[str]
    exp: int
    iat: int


def mint_agent_token(
    *,
    client_id: str,
    agent_id: str | None,
    granted_scopes: list[str],
    ttl_seconds: int,
    private_key_pem: str,
    issuer: str,
) -> tuple[str, int]:
    """Sign a JWT for an agent that has just authenticated.

    Returns ``(access_token, expires_in)``. ``expires_in`` is the TTL the
    agent should rely on; the JWT also carries it as ``exp``.
    """
    now = int(time.time())
    exp = now + ttl_seconds
    payload = {
        "iss": issuer,
        "sub": client_id,
        "agent_id": agent_id,
        # OAuth wire format for scope is a space-separated string. We
        # preserve that here so SDKs that introspect the JWT match what
        # aurora-gateway emits.
        "scope": " ".join(granted_scopes),
        "iat": now,
        "exp": exp,
    }
    token = jwt.encode(payload, private_key_pem, algorithm=_ALG)
    return token, ttl_seconds


def verify_agent_token(token: str, public_key_pem: bytes) -> AgentTokenClaims:
    """Verify signature + exp on a JWT minted by this Edge instance.

    Raises :class:`InvalidToken` on any failure. Returns parsed claims
    on success.
    """
    try:
        payload = jwt.decode(
            token,
            public_key_pem,
            algorithms=[_ALG],
            # We don't enforce ``iss`` here — Edge instances aren't
            # cluster-stable enough to assume a single issuer string
            # across pod restarts. Signature is the trust anchor.
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidToken(f"jwt verification failed: {exc}") from exc

    scope_str = payload.get("scope", "")
    scopes = scope_str.split() if scope_str else []

    return AgentTokenClaims(
        sub=payload["sub"],
        agent_id=payload.get("agent_id"),
        scopes=scopes,
        exp=int(payload["exp"]),
        iat=int(payload["iat"]),
    )


# ─────────────────────────────────────────────────────────────────────
# Key loading
#
# Edge's enrollment private key on disk doubles as our token-signing key.
# We derive the public key from it for verification. Cached at first call;
# the key file is immutable for the life of the pod (rotation goes
# through a separate ``/rotate`` flow that restarts the process).
# ─────────────────────────────────────────────────────────────────────


def load_private_key_pem(state_dir: Path) -> str:
    """Read the enrollment private key from disk. Raises ``EnrollmentMissing``."""
    return _read_or_raise(state_dir / _KEY_FILE, "enrollment private key")


def derive_public_key_pem(private_key_pem: str) -> bytes:
    """Extract the public-key PEM from a PEM-encoded RSA private key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ─────────────────────────────────────────────────────────────────────
# Authorization decisions
#
# These functions take inputs (presented secret, allowed list, requested
# scopes) and return either a result or raise the appropriate TokenError.
# Pure logic — no I/O, no FastAPI bindings.
# ─────────────────────────────────────────────────────────────────────


def find_authorized_client(
    client_id: str, authorized: list[AuthorizedClient]
) -> AuthorizedClient | None:
    """Return the AuthorizedClient with matching client_id, or None."""
    for ac in authorized:
        if ac.client_id == client_id:
            return ac
    return None


def authenticate_client(
    *,
    client_id: str,
    client_secret: str,
    authorized: list[AuthorizedClient],
) -> AuthorizedClient:
    """Look up + verify a client's credentials. Raises :class:`InvalidClient`.

    Constant-ish-time: we always perform a PBKDF2 verify even when the
    client_id is unknown (against a sentinel hash) so secret-existence
    can't be inferred from response timing.
    """
    record = find_authorized_client(client_id, authorized)
    if record is None:
        # Spend roughly the same wall-clock as a real verify so attackers
        # can't enumerate client_ids by timing.
        _sentinel_verify(client_secret)
        raise InvalidClient("unknown client_id")

    if not verify_django_pbkdf2(client_secret, record.client_secret_hash):
        raise InvalidClient("invalid client_secret")
    return record


# Pre-computed in module load with the same PBKDF2 params Django uses by
# default. Used only as a timing sink for the unknown-client branch above.
_SENTINEL_HASH = (
    "pbkdf2_sha256$600000$"
    "edge-sentinel-salt-not-used-for-real-secrets$"
    + base64.b64encode(
        hashlib.pbkdf2_hmac(
            "sha256",
            b"sentinel-never-matches",
            b"edge-sentinel-salt-not-used-for-real-secrets",
            600000,
        )
    ).decode("ascii")
)


def _sentinel_verify(secret: str) -> None:
    verify_django_pbkdf2(secret, _SENTINEL_HASH)


def narrow_scopes(requested: list[str], allowed: list[str]) -> list[str]:
    """Compute the granted scope set = requested ∩ allowed.

    Empty ``requested`` → empty grant (RFC 6749 § 3.3: scope is optional;
    when omitted at request time, the AS may default to allowed or to
    nothing. We pick "nothing" — the agent SDK always sends scope today).
    """
    allowed_set = set(allowed)
    return [s for s in requested if s in allowed_set]


__all__ = [
    "AgentTokenClaims",
    "AuthorizedClient",
    "EnrollmentMissing",
    "InvalidClient",
    "InvalidScope",
    "InvalidToken",
    "TokenError",
    "authenticate_client",
    "derive_public_key_pem",
    "find_authorized_client",
    "load_private_key_pem",
    "mint_agent_token",
    "narrow_scopes",
    "verify_agent_token",
    "verify_django_pbkdf2",
]
