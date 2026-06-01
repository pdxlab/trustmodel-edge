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

import json
import time
from pathlib import Path

import jwt

_DEFAULT_TTL_SECONDS = 60

# File names written by edge.enroll.persist_credentials (TRUS-987).
# Keep these aligned with that module — if enrollment changes its on-disk
# layout, mirror the change here.
_KEY_FILE = "key.pem"
_META_FILE = "meta.json"


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

    Reads (file names match what ``edge.enroll.persist_credentials`` writes):
      * ``<state_dir>/key.pem``  — RSA private key, PEM
      * ``<state_dir>/meta.json`` — enrollment metadata; ``edge_id`` field
        extracted as the JWT ``sub`` claim. Skipped if ``edge_id`` is
        passed explicitly (tests).

    Claims: ``sub`` (edge UUID), ``iat``, ``exp``.
    """
    key_pem = _read_or_raise(state_dir / _KEY_FILE, "enrollment private key")
    if edge_id is None:
        meta_raw = _read_or_raise(state_dir / _META_FILE, "enrollment metadata")
        try:
            edge_id = json.loads(meta_raw)["edge_id"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise EnrollmentMissing(
                f"could not read edge_id from {state_dir / _META_FILE}: {exc}"
            ) from exc

    now = int(time.time())
    return jwt.encode(
        {"sub": edge_id, "iat": now, "exp": now + ttl_seconds},
        key_pem,
        algorithm="RS256",
    )
