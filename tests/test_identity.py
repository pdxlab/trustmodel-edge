"""Tests for edge.identity — credential persistence + JWT signing."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from edge.identity import (
    CREDENTIAL_FILES,
    EdgeCredentials,
    ROTATION_TRIGGER_DAYS,
    is_rotation_due,
    load_credentials,
    persist_credentials,
    read_bootstrap_token,
    sign_edge_jwt,
)


def _real_keypair() -> tuple[str, str]:
    """Generate a real RSA keypair for signing tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return key_pem, pub_pem


def test_read_bootstrap_token_env_override_wins(tmp_path: Path) -> None:
    # File exists but env override is non-empty → env wins
    p = tmp_path / "bootstrap-token"
    p.write_text("from-file")
    assert read_bootstrap_token(p, "from-env") == "from-env"


def test_read_bootstrap_token_from_file(tmp_path: Path) -> None:
    p = tmp_path / "bootstrap-token"
    p.write_text("tm-bs-abcd\n")
    assert read_bootstrap_token(p, "") == "tm-bs-abcd"


def test_read_bootstrap_token_returns_none_when_missing(tmp_path: Path) -> None:
    assert read_bootstrap_token(tmp_path / "nope", "") is None


def test_persist_and_load_roundtrip(tmp_path: Path) -> None:
    creds = EdgeCredentials(
        edge_id="abc",
        tenant_id="acme",
        cert_pem="cert",
        key_pem="key",
        ca_chain_pem="ca",
        cert_valid_to=datetime(2030, 1, 1, tzinfo=timezone.utc),
        agp_endpoint="https://api.trustmodel.ai",
        telemetry_endpoint="https://api.trustmodel.ai/api/v1/edge/telemetry",
    )
    persist_credentials(tmp_path, creds)
    loaded = load_credentials(tmp_path)
    assert loaded == creds


def test_persist_sets_0600_on_private_key(tmp_path: Path) -> None:
    creds = EdgeCredentials(
        edge_id="abc",
        tenant_id="acme",
        cert_pem="cert",
        key_pem="key",
        ca_chain_pem="ca",
        cert_valid_to=datetime(2030, 1, 1, tzinfo=timezone.utc),
        agp_endpoint="https://x",
        telemetry_endpoint="https://x/t",
    )
    persist_credentials(tmp_path, creds)
    mode = os.stat(tmp_path / CREDENTIAL_FILES["key"]).st_mode & 0o777
    assert mode == 0o600


def test_load_credentials_missing_returns_none(tmp_path: Path) -> None:
    assert load_credentials(tmp_path) is None


def test_sign_edge_jwt_verifies_with_matching_pubkey() -> None:
    key_pem, pub_pem = _real_keypair()
    token = sign_edge_jwt("edge-1", key_pem)
    payload = jwt.decode(token, pub_pem, algorithms=["RS256"], options={"require": ["sub", "exp"]})
    assert payload["sub"] == "edge-1"


def test_sign_edge_jwt_rejects_with_wrong_pubkey() -> None:
    key_pem, _ = _real_keypair()
    _, wrong_pub = _real_keypair()
    token = sign_edge_jwt("edge-1", key_pem)
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, wrong_pub, algorithms=["RS256"])


def test_is_rotation_due_flips_at_threshold() -> None:
    fresh = EdgeCredentials(
        edge_id="e",
        tenant_id="t",
        cert_pem="",
        key_pem="",
        ca_chain_pem="",
        cert_valid_to=datetime.now(timezone.utc) + timedelta(days=ROTATION_TRIGGER_DAYS + 5),
        agp_endpoint="",
        telemetry_endpoint="",
    )
    assert is_rotation_due(fresh) is False

    stale = EdgeCredentials(
        edge_id="e",
        tenant_id="t",
        cert_pem="",
        key_pem="",
        ca_chain_pem="",
        cert_valid_to=datetime.now(timezone.utc) + timedelta(days=ROTATION_TRIGGER_DAYS - 1),
        agp_endpoint="",
        telemetry_endpoint="",
    )
    assert is_rotation_due(stale) is True
