"""Tests for edge.identity — credential persistence + JWT signing."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from edge import identity
from edge.identity import (
    CREDENTIAL_FILES,
    ROTATION_TRIGGER_DAYS,
    EdgeCredentials,
    is_rotation_due,
    load_credentials,
    persist_credentials,
    read_bootstrap_token,
    sign_edge_jwt,
)
from tests.certs import make_credentials, rsa_key_pem


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
    creds = make_credentials()
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
        cert_valid_to=datetime(2030, 1, 1, tzinfo=UTC),
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
        cert_valid_to=datetime.now(UTC) + timedelta(days=ROTATION_TRIGGER_DAYS + 5),
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
        cert_valid_to=datetime.now(UTC) + timedelta(days=ROTATION_TRIGGER_DAYS - 1),
        agp_endpoint="",
        telemetry_endpoint="",
    )
    assert is_rotation_due(stale) is True


# ── TRUS-2374: a half-written rotation must not strand valid credentials ──


def _rewrite_meta(state_dir: Path, **fields: str) -> None:
    meta_path = state_dir / CREDENTIAL_FILES["meta"]
    meta = json.loads(meta_path.read_text())
    meta.update(fields)
    meta_path.write_text(json.dumps(meta))


@pytest.mark.parametrize(
    "stale_value",
    [
        # The xspan incident: meta still held the July cert's expiry.
        (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        # Hand-edited or truncated meta must not break loading either.
        "not-a-date",
        "",
    ],
)
def test_load_takes_expiry_from_cert_not_meta(tmp_path: Path, stale_value: str) -> None:
    creds = make_credentials(days_valid=57)
    persist_credentials(tmp_path, creds)
    _rewrite_meta(tmp_path, cert_valid_to=stale_value)

    loaded = load_credentials(tmp_path)

    assert loaded is not None
    assert loaded.cert_valid_to == creds.cert_valid_to


def test_load_logs_when_meta_disagrees_with_cert(tmp_path: Path, record_logs) -> None:
    persist_credentials(tmp_path, make_credentials())
    _rewrite_meta(tmp_path, cert_valid_to=(datetime.now(UTC) - timedelta(days=1)).isoformat())
    events = record_logs(identity)

    load_credentials(tmp_path)

    assert [(level, event) for level, event, _ in events] == [
        ("warning", "edge.identity.meta_stale")
    ]


def test_load_ignores_subsecond_meta_drift(tmp_path: Path, record_logs) -> None:
    # The gateway's cert_valid_to carries microseconds; the cert keeps whole
    # seconds. That difference is not staleness and must not log every boot.
    creds = make_credentials()
    persist_credentials(tmp_path, creds)
    _rewrite_meta(
        tmp_path, cert_valid_to=(creds.cert_valid_to + timedelta(microseconds=123456)).isoformat()
    )

    events = record_logs(identity)

    assert load_credentials(tmp_path) is not None
    assert events == []


def test_load_flags_cert_key_mismatch_but_keeps_the_key(tmp_path: Path, record_logs) -> None:
    creds = make_credentials(key_index=0)
    persist_credentials(tmp_path, creds)
    (tmp_path / CREDENTIAL_FILES["key"]).write_text(rsa_key_pem(1))
    events = record_logs(identity)

    loaded = load_credentials(tmp_path)

    assert loaded is not None
    assert loaded.key_pem == rsa_key_pem(1)
    assert loaded.cert_valid_to == creds.cert_valid_to
    assert [(level, event) for level, event, _ in events] == [
        ("error", "edge.identity.cert_key_mismatch")
    ]


def test_persist_interrupted_between_renames_leaves_the_new_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # /rotate invalidates the old key at once, so the new key is the half
    # worth having if the process dies part-way through the renames.
    previous = make_credentials(days_valid=29, key_index=0)
    persist_credentials(tmp_path, previous)
    rotated = make_credentials(days_valid=90, key_index=1)

    real_replace = os.replace
    calls = 0

    def _die_after_first(src, dst):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError(5, "Input/output error")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _die_after_first)
    with pytest.raises(OSError):
        persist_credentials(tmp_path, rotated)

    loaded = load_credentials(tmp_path)
    assert loaded is not None
    assert loaded.key_pem == rotated.key_pem
    # Expiry from the old cert errs early, never late.
    assert loaded.cert_valid_to == previous.cert_valid_to
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(CREDENTIAL_FILES.values())


def test_load_rejects_unparseable_cert(tmp_path: Path, record_logs) -> None:
    persist_credentials(tmp_path, make_credentials())
    (tmp_path / CREDENTIAL_FILES["cert"]).write_text("-----BEGIN CERTIFICATE-----\ntrunc")
    events = record_logs(identity)

    assert load_credentials(tmp_path) is None
    assert [(level, event) for level, event, _ in events] == [("error", "edge.identity.unreadable")]


def test_persist_does_not_need_chmod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # GCS FUSE on Cloud Run: the suspected step that aborted the xspan rotation.
    def _no_chmod(*_a, **_kw):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", _no_chmod)
    creds = make_credentials()

    persist_credentials(tmp_path, creds)

    assert load_credentials(tmp_path) == creds


def test_failed_persist_leaves_previous_set_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = make_credentials(days_valid=20, key_index=0)
    persist_credentials(tmp_path, previous)

    real_write_temp = identity._write_temp

    def _fail_on_ca(target: Path, text: str, mode: int) -> Path:
        if target.name == CREDENTIAL_FILES["ca"]:
            raise OSError(5, "Input/output error")
        return real_write_temp(target, text, mode)

    monkeypatch.setattr(identity, "_write_temp", _fail_on_ca)

    with pytest.raises(OSError):
        persist_credentials(tmp_path, make_credentials(days_valid=90, key_index=1))

    assert load_credentials(tmp_path) == previous
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(CREDENTIAL_FILES.values())


def test_persist_warns_when_filesystem_ignores_key_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, record_logs
) -> None:
    # FUSE mounts apply one file mode to every file, whatever we ask for.
    real_stat = os.stat

    def _world_readable_key(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        if str(path).endswith(CREDENTIAL_FILES["key"]):
            return os.stat_result((st.st_mode | 0o044, *tuple(st)[1:]))
        return st

    monkeypatch.setattr(os, "stat", _world_readable_key)
    events = record_logs(identity)

    persist_credentials(tmp_path, make_credentials())

    assert [(level, event) for level, event, _ in events] == [
        ("warning", "edge.identity.key_permissions_not_enforced")
    ]
