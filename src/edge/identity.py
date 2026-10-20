"""Edge identity — credential persistence + JWT signing (TRUS-987).

Three files land on the PVC at ``settings.state_dir``:

* ``cert.pem`` — public client cert from /api/v1/edge/enroll
* ``key.pem``  — private key (matching the cert; 0600 perms)
* ``ca.pem``   — TrustModel Edge CA chain (for future mTLS termination)

Plus a small ``meta.json`` with the issued tenant_id, edge_id and endpoints.
It also records the cert ``valid_to``, but only for operators: the expiry
Edge acts on is read from ``cert.pem`` itself (TRUS-2374).
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import serialization

log = structlog.get_logger()

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
    """Write all four files, replacing the previous set only once every write succeeded.

    Each file is staged as a temp file beside its target and renamed into
    place only after all four are written. A failed write therefore leaves
    the previous set intact, never a new cert and key beside a stale
    meta.json (TRUS-2374). The private key is created 0600 instead of being
    chmod-ed afterwards: chmod is not supported on every volume (GCS FUSE on
    Cloud Run, for one), and a failing chmod used to abort the write.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    meta = json.dumps(
        {
            "edge_id": creds.edge_id,
            "tenant_id": creds.tenant_id,
            "cert_valid_to": creds.cert_valid_to.isoformat(),
            "agp_endpoint": creds.agp_endpoint,
            "telemetry_endpoint": creds.telemetry_endpoint,
        }
    )
    # Key first: renames are not atomic as a group (on GCS FUSE each is a
    # copy + delete), and if we stop part-way a new key is the half that
    # still authenticates — /rotate has already invalidated the old one.
    files = [
        # 0600 on the private key — non-negotiable
        ("key", creds.key_pem, 0o600),
        ("cert", creds.cert_pem, 0o644),
        ("ca", creds.ca_chain_pem, 0o644),
        ("meta", meta, 0o644),
    ]
    staged: list[tuple[Path, Path]] = []
    try:
        for name, text, mode in files:
            target = state_dir / CREDENTIAL_FILES[name]
            staged.append((_write_temp(target, text, mode), target))
        for tmp, target in staged:
            os.replace(tmp, target)
    finally:
        for tmp, _ in staged:
            tmp.unlink(missing_ok=True)

    key_path = state_dir / CREDENTIAL_FILES["key"]
    key_mode = os.stat(key_path).st_mode & 0o777
    if key_mode & 0o077:
        # Mount options (e.g. a FUSE file-mode) override the mode we create
        # the file with. Not fatal, but the operator should know.
        log.warning(
            "edge.identity.key_permissions_not_enforced",
            path=str(key_path),
            mode=oct(key_mode),
        )


def _write_temp(target: Path, text: str, mode: int) -> Path:
    """Write ``text`` to a fresh temp file next to ``target`` and fsync it."""
    tmp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def load_credentials(state_dir: Path) -> EdgeCredentials | None:
    """Return persisted credentials, or None if any file is missing or unreadable.

    ``cert_valid_to`` is the notAfter of ``cert.pem``, not meta.json's copy.
    A rotation whose write stopped part-way left meta.json with the old
    expiry, and trusting it made Edge discard a valid cert and re-enrol with
    an already-spent bootstrap token (TRUS-2374).
    """
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

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (TypeError, ValueError) as exc:
        log.error("edge.identity.unreadable", state_dir=str(state_dir), error=str(exc))
        return None
    if _public_der(cert.public_key()) != _public_der(key.public_key()):
        # A write stopped between renames. Keep going: the gateway decides
        # whether this key is current, and refusing to start would take the
        # host service down for a problem auth will surface anyway.
        log.error(
            "edge.identity.cert_key_mismatch",
            state_dir=str(state_dir),
            detail=(
                "cert.pem and key.pem come from different rotations; using key.pem "
                "with cert.pem's expiry"
            ),
        )

    cert_valid_to = cert.not_valid_after_utc
    recorded = meta.get("cert_valid_to", "")
    try:
        # The gateway's value has microseconds; the cert keeps whole seconds.
        meta_stale = abs(datetime.fromisoformat(recorded) - cert_valid_to) > timedelta(seconds=1)
    except (TypeError, ValueError):
        meta_stale = True
    if meta_stale:
        log.warning(
            "edge.identity.meta_stale",
            state_dir=str(state_dir),
            meta_cert_valid_to=recorded,
            cert_valid_to=cert_valid_to.isoformat(),
        )

    return EdgeCredentials(
        edge_id=meta["edge_id"],
        tenant_id=meta["tenant_id"],
        cert_pem=cert_pem,
        key_pem=key_pem,
        ca_chain_pem=ca_pem,
        cert_valid_to=cert_valid_to,
        agp_endpoint=meta["agp_endpoint"],
        telemetry_endpoint=meta["telemetry_endpoint"],
    )


def _public_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def sign_edge_jwt(edge_id: str, key_pem: str, *, ttl_s: int = 60) -> str:
    """Sign an RS256 JWT the gateway verifies against the matching cert pub key."""
    now = int(datetime.now(UTC).timestamp())
    return jwt.encode(
        {"sub": str(edge_id), "iat": now, "exp": now + ttl_s},
        key_pem,
        algorithm="RS256",
    )


def is_rotation_due(creds: EdgeCredentials, *, now: datetime | None = None) -> bool:
    """True when the cert has ≤ ROTATION_TRIGGER_DAYS days left."""
    now = now or datetime.now(UTC)
    remaining = creds.cert_valid_to - now
    return remaining <= timedelta(days=ROTATION_TRIGGER_DAYS)
