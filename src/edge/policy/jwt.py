"""Mint short-lived RS256 cert-JWTs for control-plane calls.

Each authenticated request Edge makes to aurora-gateway carries an
``Authorization: Bearer <jwt>`` signed by the Edge's enrollment cert
private key. aurora-gateway verifies the signature against the stored
public key for the matching ``sub`` (edge UUID).

Keys + cert are written to disk at enrollment (TRUS-987). We just read
them here. If TRUS-987 isn't done, callers will see :class:`EnrollmentMissing`
and the readiness probe stays red.
"""

from __future__ import annotations

import time
from pathlib import Path

import jwt

_DEFAULT_TTL_SECONDS = 60


class EnrollmentMissing(RuntimeError):
    """The enrollment cert key isn't on disk — Edge hasn't enrolled yet."""


def _read_or_raise(path: Path, label: str) -> str:
    if not path.exists():
        raise EnrollmentMissing(
            f"missing {label} at {path}; enrollment (TRUS-987) has not completed"
        )
    return path.read_text(encoding="utf-8").strip()


def mint_cert_jwt(
    *,
    state_dir: Path,
    edge_id: str | None = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> str:
    """Mint an RS256 JWT signed by the Edge's enrollment cert private key.

    Reads:
      * ``<state_dir>/edge.key``       — RSA private key, PEM
      * ``<state_dir>/edge.id``        — UUID of this Edge instance
        (skipped if ``edge_id`` is passed explicitly, e.g. in tests)

    Claims: ``sub`` (edge UUID), ``iat``, ``exp``.
    """
    key_pem = _read_or_raise(state_dir / "edge.key", "enrollment private key")
    if edge_id is None:
        edge_id = _read_or_raise(state_dir / "edge.id", "edge instance id")

    now = int(time.time())
    return jwt.encode(
        {"sub": edge_id, "iat": now, "exp": now + ttl_seconds},
        key_pem,
        algorithm="RS256",
    )
