"""Tests for the enroll + heartbeat client modules (TRUS-987).

Uses httpx's transport mocking so we never hit a real control plane.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from edge.config import Settings
from edge.control_plane import (
    EdgeControlPlaneError,
    EdgeRevoked,
    enroll as cp_enroll,
    heartbeat as cp_heartbeat,
    rotate as cp_rotate,
)
from edge.enroll import EnrollmentFailed, bootstrap_if_needed
from edge.heartbeat import HeartbeatState, _one_tick
from edge.identity import EdgeCredentials


@lru_cache(maxsize=1)
def _shared_key_pem() -> str:
    """One RSA key shared across all tests so suite stays fast (~1s vs 10s)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _enroll_response_body(edge_id: str = "abc-123") -> dict:
    return {
        "edge_id": edge_id,
        "tenant_id": "acme",
        "client_cert": "CERT",
        "client_key": "KEY",
        "ca_chain": "CA",
        "agp_endpoint": "https://api.trustmodel.ai",
        "telemetry_endpoint": "https://api.trustmodel.ai/api/v1/edge/telemetry",
        "cert_valid_from": "2026-05-26T00:00:00+00:00",
        "cert_valid_to": "2026-08-24T00:00:00+00:00",
    }


def _credentials(valid_to_days_from_now: int = 90) -> EdgeCredentials:
    return EdgeCredentials(
        edge_id="abc-123",
        tenant_id="acme",
        cert_pem="CERT",
        key_pem=_shared_key_pem(),
        ca_chain_pem="CA",
        cert_valid_to=datetime.now(timezone.utc) + timedelta(days=valid_to_days_from_now),
        agp_endpoint="https://api.trustmodel.ai",
        telemetry_endpoint="https://api.trustmodel.ai/api/v1/edge/telemetry",
    )


def _mock_post(status_code: int, json_body: dict | None = None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_body or {}
    response.text = str(json_body or "")
    return response


# ── control_plane.enroll ─────────────────────────────────────────────


def test_enroll_happy_path() -> None:
    with patch("edge.control_plane.httpx.post", return_value=_mock_post(201, _enroll_response_body())):
        bundle = cp_enroll(
            control_plane_url="http://cp",
            bootstrap_token="tm-bs-x",
            edge_pod_id="pod-1",
        )
    assert bundle.edge_id == "abc-123"
    assert bundle.tenant_id == "acme"
    assert bundle.cert_pem == "CERT"


def test_enroll_4xx_raises_control_plane_error() -> None:
    with patch("edge.control_plane.httpx.post", return_value=_mock_post(401)):
        with pytest.raises(EdgeControlPlaneError):
            cp_enroll(control_plane_url="http://cp", bootstrap_token="bad", edge_pod_id="p")


def test_enroll_network_error_raises_control_plane_error() -> None:
    with patch("edge.control_plane.httpx.post", side_effect=httpx.ConnectError("down")):
        with pytest.raises(EdgeControlPlaneError):
            cp_enroll(control_plane_url="http://cp", bootstrap_token="x", edge_pod_id="p")


# ── control_plane.heartbeat ──────────────────────────────────────────


def test_heartbeat_returns_typed_response() -> None:
    body = {"revoked": False, "sync_interval_s": 60, "rotation_due": False}
    with patch("edge.control_plane.httpx.post", return_value=_mock_post(200, body)):
        resp = cp_heartbeat(control_plane_url="http://cp", creds=_credentials())
    assert resp.revoked is False
    assert resp.sync_interval_s == 60
    assert resp.rotation_due is False


def test_heartbeat_revoked_true_raises_edge_revoked() -> None:
    body = {"revoked": True, "sync_interval_s": 60, "rotation_due": False}
    with patch("edge.control_plane.httpx.post", return_value=_mock_post(200, body)):
        with pytest.raises(EdgeRevoked):
            cp_heartbeat(control_plane_url="http://cp", creds=_credentials())


def test_heartbeat_403_raises_edge_revoked() -> None:
    """Revoked Edge → cert-JWT auth fails → 403 → Edge interprets as revocation."""
    with patch("edge.control_plane.httpx.post", return_value=_mock_post(403)):
        with pytest.raises(EdgeRevoked):
            cp_heartbeat(control_plane_url="http://cp", creds=_credentials())


# ── control_plane.rotate ─────────────────────────────────────────────


def test_rotate_happy_path() -> None:
    body = {
        "client_cert": "NEW_CERT",
        "client_key": "NEW_KEY",
        "ca_chain": "CA",
        "cert_valid_from": "2026-05-26T00:00:00+00:00",
        "cert_valid_to": "2026-08-24T00:00:00+00:00",
    }
    with patch("edge.control_plane.httpx.post", return_value=_mock_post(200, body)):
        bundle = cp_rotate(control_plane_url="http://cp", creds=_credentials())
    assert bundle.cert_pem == "NEW_CERT"
    assert bundle.key_pem == "NEW_KEY"


# ── enroll.bootstrap_if_needed ───────────────────────────────────────


def test_bootstrap_if_needed_calls_enroll_when_no_credentials(tmp_path: Path) -> None:
    settings = Settings(
        tenant_id="acme",
        pod_id="pod-1",
        bootstrap_token_path=tmp_path / "tok",
        state_dir=tmp_path / "state",
        bootstrap_token="tm-bs-test",
    )
    settings.state_dir.mkdir()

    with patch("edge.enroll.cp_enroll") as cp:
        from edge.control_plane import EnrollBundle

        cp.return_value = EnrollBundle(
            edge_id="e-1",
            tenant_id="acme",
            cert_pem="C",
            key_pem="K",
            ca_chain_pem="CA",
            cert_valid_from=datetime.now(timezone.utc),
            cert_valid_to=datetime.now(timezone.utc) + timedelta(days=90),
            agp_endpoint="https://x",
            telemetry_endpoint="https://x/t",
        )
        creds = bootstrap_if_needed(settings)

    assert creds.edge_id == "e-1"
    cp.assert_called_once()


def test_bootstrap_if_needed_reuses_existing_credentials(tmp_path: Path) -> None:
    from edge.identity import persist_credentials

    settings = Settings(
        tenant_id="acme",
        pod_id="pod-1",
        bootstrap_token_path=tmp_path / "tok",
        state_dir=tmp_path / "state",
    )
    settings.state_dir.mkdir()
    existing = _credentials(valid_to_days_from_now=80)
    persist_credentials(settings.state_dir, existing)

    with patch("edge.enroll.cp_enroll") as cp:
        creds = bootstrap_if_needed(settings)
    assert creds.edge_id == existing.edge_id
    cp.assert_not_called()


def test_bootstrap_if_needed_missing_token_raises(tmp_path: Path) -> None:
    settings = Settings(
        tenant_id="acme",
        pod_id="pod-1",
        bootstrap_token_path=tmp_path / "absent",
        state_dir=tmp_path / "state",
    )
    settings.state_dir.mkdir()
    with pytest.raises(EnrollmentFailed):
        bootstrap_if_needed(settings)


# ── heartbeat._one_tick ──────────────────────────────────────────────


async def test_one_tick_swaps_credentials_when_rotation_due(tmp_path: Path) -> None:
    from edge.identity import persist_credentials

    settings = Settings(
        tenant_id="acme",
        pod_id="p",
        bootstrap_token_path=tmp_path / "t",
        state_dir=tmp_path / "s",
    )
    settings.state_dir.mkdir()
    persist_credentials(settings.state_dir, _credentials())

    state = HeartbeatState(_credentials())

    hb_body = {"revoked": False, "sync_interval_s": 60, "rotation_due": True}
    rotate_body = {
        "client_cert": "NEW",
        "client_key": "NEW_KEY",
        "ca_chain": "CA",
        "cert_valid_from": "2026-05-26T00:00:00+00:00",
        "cert_valid_to": "2026-08-24T00:00:00+00:00",
    }

    with patch(
        "edge.control_plane.httpx.post",
        side_effect=[_mock_post(200, hb_body), _mock_post(200, rotate_body)],
    ):
        await _one_tick(settings, state)

    assert state.credentials.cert_pem == "NEW"
    assert state.credentials.key_pem == "NEW_KEY"
    assert not state.revoked


async def test_one_tick_marks_revoked_and_propagates(tmp_path: Path) -> None:
    settings = Settings(
        tenant_id="acme",
        pod_id="p",
        bootstrap_token_path=tmp_path / "t",
        state_dir=tmp_path / "s",
    )
    state = HeartbeatState(_credentials())
    with patch("edge.control_plane.httpx.post", return_value=_mock_post(403)):
        with pytest.raises(EdgeRevoked):
            await _one_tick(settings, state)
    assert state.revoked is True


async def test_one_tick_swallows_transient_errors(tmp_path: Path) -> None:
    settings = Settings(
        tenant_id="acme",
        pod_id="p",
        bootstrap_token_path=tmp_path / "t",
        state_dir=tmp_path / "s",
    )
    state = HeartbeatState(_credentials())
    with patch("edge.control_plane.httpx.post", side_effect=httpx.ConnectError("down")):
        await _one_tick(settings, state)  # no raise
    assert state.revoked is False
