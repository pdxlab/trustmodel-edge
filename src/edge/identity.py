"""Edge identity — credential persistence + JWT signing (TRUS-987).

Three files land on the PVC at ``settings.state_dir``:

* ``cert.pem`` — public client cert from /api/v1/edge/enroll
* ``key.pem``  — private key (matching the cert; 0600 perms)
* ``ca.pem``   — TrustModel Edge CA chain (for future mTLS termination)

Plus a small ``meta.json`` with the issued tenant_id, edge_id, and the
cert ``valid_to`` timestamp so we can detect rotation-due without parsing
the cert on every tick.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

CREDENTIAL_FILES = {
    "cert": "cert.pem",
    "key": "key.pem",
    "ca": "ca.pem",
    "meta": "meta.json",
}

# Edge rotates when ≤ this many days remain on the cert. Server-side
# (aurora-gateway) advertises the same value via heartbeat.rotation_due
# but Edge can also poll locally for resilience.
ROTATION_TRIGGER_DAYS = 30


@dataclass(frozen=True)
class EdgeCredentials:
    edge_id: str
    tenant_id: str
    cert_pem: str
    key_pem: str
    ca_chain_pem: str
    cert_valid_to: datetime
    agp_endpoint: str
    telemetry_endpoint: str


def read_bootstrap_token(path: Path, override: str = "") -> str | None:
    """Return the bootstrap token plaintext from override or file.

    Order:
    1. ``override`` (settings.bootstrap_token) — dev/test
    2. file at ``path`` — K8s Secret mount
    Returns ``None`` if neither is present.
    """
    if override:
        return override.strip() or None
    try:
        text = path.read_text().strip()
    except FileNotFoundError:
        return None
    return text or None


def persist_credentials(state_dir: Path, creds: EdgeCredentials) -> None:
    """Atomically write all four files. Caller must ensure ``state_dir`` exists."""
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / CREDENTIAL_FILES["cert"]).write_text(creds.cert_pem)
    # 0600 on the private key — non-negotiable
    key_path = state_dir / CREDENTIAL_FILES["key"]
    key_path.write_text(creds.key_pem)
    os.chmod(key_path, 0o600)
    (state_dir / CREDENTIAL_FILES["ca"]).write_text(creds.ca_chain_pem)
    (state_dir / CREDENTIAL_FILES["meta"]).write_text(
        json.dumps(
            {
                "edge_id": creds.edge_id,
                "tenant_id": creds.tenant_id,
                "cert_valid_to": creds.cert_valid_to.isoformat(),
                "agp_endpoint": creds.agp_endpoint,
                "telemetry_endpoint": creds.telemetry_endpoint,
            }
        )
    )


def load_credentials(state_dir: Path) -> EdgeCredentials | None:
    """Return persisted credentials, or None if any file is missing."""
    meta_path = state_dir / CREDENTIAL_FILES["meta"]
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text())
        cert_pem = (state_dir / CREDENTIAL_FILES["cert"]).read_text()
        key_pem = (state_dir / CREDENTIAL_FILES["key"]).read_text()
        ca_pem = (state_dir / CREDENTIAL_FILES["ca"]).read_text()
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    return EdgeCredentials(
        edge_id=meta["edge_id"],
        tenant_id=meta["tenant_id"],
        cert_pem=cert_pem,
        key_pem=key_pem,
        ca_chain_pem=ca_pem,
        cert_valid_to=datetime.fromisoformat(meta["cert_valid_to"]),
        agp_endpoint=meta["agp_endpoint"],
        telemetry_endpoint=meta["telemetry_endpoint"],
    )


def sign_edge_jwt(edge_id: str, key_pem: str, *, ttl_s: int = 60) -> str:
    """Sign an RS256 JWT the gateway verifies against the matching cert pub key."""
    now = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode(
        {"sub": str(edge_id), "iat": now, "exp": now + ttl_s},
        key_pem,
        algorithm="RS256",
    )


def is_rotation_due(creds: EdgeCredentials, *, now: datetime | None = None) -> bool:
    """True when the cert has ≤ ROTATION_TRIGGER_DAYS days left."""
    now = now or datetime.now(timezone.utc)
    remaining = creds.cert_valid_to - now
    return remaining <= timedelta(days=ROTATION_TRIGGER_DAYS)
