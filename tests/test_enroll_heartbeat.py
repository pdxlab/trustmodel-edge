"""Tests for the enroll + heartbeat client modules (TRUS-987).

Uses httpx's transport mocking so we never hit a real control plane.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from edge import heartbeat as heartbeat_mod
from edge.config import Settings
from edge.control_plane import (
    EdgeControlPlaneError,
    EdgeRevoked,
)
from edge.control_plane import (
    enroll as cp_enroll,
)
from edge.control_plane import (
    heartbeat as cp_heartbeat,
)
from edge.control_plane import (
    rotate as cp_rotate,
)
from edge.enroll import EnrollmentFailed, bootstrap_if_needed
from edge.heartbeat import HeartbeatState, _one_tick, heartbeat_loop
from edge.identity import (
    CREDENTIAL_FILES,
    EdgeCredentials,
    load_credentials,
    persist_credentials,
)
from tests.certs import make_credentials


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
        cert_valid_to=datetime.now(UTC) + timedelta(days=valid_to_days_from_now),
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
    with (
        patch("edge.control_plane.httpx.post", return_value=_mock_post(401)),
        pytest.raises(EdgeControlPlaneError),
    ):
        cp_enroll(control_plane_url="http://cp", bootstrap_token="bad", edge_pod_id="p")


def test_enroll_network_error_raises_control_plane_error() -> None:
    with (
        patch("edge.control_plane.httpx.post", side_effect=httpx.ConnectError("down")),
        pytest.raises(EdgeControlPlaneError),
    ):
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
    with (
        patch("edge.control_plane.httpx.post", return_value=_mock_post(200, body)),
        pytest.raises(EdgeRevoked),
    ):
        cp_heartbeat(control_plane_url="http://cp", creds=_credentials())


def test_heartbeat_403_raises_edge_revoked() -> None:
    """Revoked Edge → cert-JWT auth fails → 403 → Edge interprets as revocation."""
    with (
        patch("edge.control_plane.httpx.post", return_value=_mock_post(403)),
        pytest.raises(EdgeRevoked),
    ):
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
            cert_valid_from=datetime.now(UTC),
            cert_valid_to=datetime.now(UTC) + timedelta(days=90),
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
    existing = make_credentials(days_valid=80)
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
    with (
        patch("edge.control_plane.httpx.post", return_value=_mock_post(403)),
        pytest.raises(EdgeRevoked),
    ):
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


# ── TRUS-2374: stale meta.json, failed rotation writes, shared state_dir ──


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(
        tenant_id="acme",
        pod_id="p",
        bootstrap_token_path=tmp_path / "absent-token",
        state_dir=tmp_path / "state",
    )
    settings.state_dir.mkdir()
    return settings


def _set_meta_valid_to(state_dir: Path, value: datetime) -> None:
    meta_path = state_dir / CREDENTIAL_FILES["meta"]
    meta = json.loads(meta_path.read_text())
    meta["cert_valid_to"] = value.isoformat()
    meta_path.write_text(json.dumps(meta))


def _rotate_body(creds: EdgeCredentials) -> dict:
    return {
        "client_cert": creds.cert_pem,
        "client_key": creds.key_pem,
        "ca_chain": creds.ca_chain_pem,
        "cert_valid_from": (creds.cert_valid_to - timedelta(days=90)).isoformat(),
        "cert_valid_to": creds.cert_valid_to.isoformat(),
    }


HB_OK = {"revoked": False, "sync_interval_s": 60, "rotation_due": False}
HB_ROTATE = {"revoked": False, "sync_interval_s": 60, "rotation_due": True}


def test_bootstrap_reuses_valid_cert_when_meta_is_stale(tmp_path: Path) -> None:
    """The xspan incident: the cert was rotated but meta.json still held the old expiry.

    The bootstrap token was spent at first enrolment, so falling back to
    enrol is fatal. Reuse must be decided from the cert itself.
    """
    settings = _settings(tmp_path)
    rotated = make_credentials(days_valid=57)
    persist_credentials(settings.state_dir, rotated)
    _set_meta_valid_to(settings.state_dir, datetime.now(UTC) - timedelta(days=2))

    with patch("edge.enroll.cp_enroll") as cp:
        creds = bootstrap_if_needed(settings)

    cp.assert_not_called()
    assert creds.cert_valid_to == rotated.cert_valid_to
    assert creds.key_pem == rotated.key_pem


def test_bootstrap_reenrols_when_cert_itself_expired_despite_fresh_meta(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    persist_credentials(settings.state_dir, make_credentials(days_valid=-1))
    _set_meta_valid_to(settings.state_dir, datetime.now(UTC) + timedelta(days=30))

    with pytest.raises(EnrollmentFailed, match="no bootstrap token"):
        bootstrap_if_needed(settings)


async def test_rotation_survives_persist_failure_and_retries(tmp_path: Path, record_logs) -> None:
    settings = _settings(tmp_path)
    current = make_credentials(days_valid=29, key_index=0)
    persist_credentials(settings.state_dir, current)
    state = HeartbeatState(current)
    rotated = make_credentials(days_valid=90, key_index=1)
    events = record_logs(heartbeat_mod)

    with (
        patch("edge.heartbeat.persist_credentials", side_effect=PermissionError(1, "EPERM")),
        patch(
            "edge.control_plane.httpx.post",
            side_effect=[_mock_post(200, HB_ROTATE), _mock_post(200, _rotate_body(rotated))],
        ),
    ):
        await _one_tick(settings, state)  # must not raise

    # /rotate already invalidated the old key server-side, so the new one
    # must be in use even though it isn't on disk yet.
    assert state.credentials.key_pem == rotated.key_pem
    assert state.persist_pending is True
    assert ("error", "edge.rotate.persist_failed") in [(lvl, ev) for lvl, ev, _ in events]
    assert load_credentials(settings.state_dir) == current

    with patch("edge.control_plane.httpx.post", return_value=_mock_post(200, HB_OK)):
        await _one_tick(settings, state)

    assert state.persist_pending is False
    assert load_credentials(settings.state_dir) == rotated
    assert ("info", "edge.rotate.persist_recovered") in [(lvl, ev) for lvl, ev, _ in events]


async def test_persist_retry_never_overwrites_newer_disk_credentials(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    ours = make_credentials(days_valid=90, key_index=0)
    state = HeartbeatState(ours)
    state.persist_pending = True
    # Another replica rotated after us and managed to write.
    theirs = make_credentials(days_valid=91, key_index=1)
    persist_credentials(settings.state_dir, theirs)

    with patch("edge.control_plane.httpx.post", return_value=_mock_post(200, HB_OK)):
        await _one_tick(settings, state)

    assert load_credentials(settings.state_dir) == theirs
    assert state.credentials == theirs
    assert state.persist_pending is False


async def test_heartbeat_401_adopts_newer_credentials_from_shared_state_dir(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    stale = make_credentials(days_valid=29, key_index=0)
    state = HeartbeatState(stale)
    rotated_by_other_replica = make_credentials(days_valid=90, key_index=1)
    persist_credentials(settings.state_dir, rotated_by_other_replica)

    with patch("edge.control_plane.httpx.post", return_value=_mock_post(401)):
        await _one_tick(settings, state)  # must not raise

    assert state.revoked is False
    assert state.credentials == rotated_by_other_replica


async def test_heartbeat_401_without_newer_disk_credentials_is_revocation(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    creds = make_credentials(days_valid=60)
    persist_credentials(settings.state_dir, creds)
    state = HeartbeatState(creds)

    with (
        patch("edge.control_plane.httpx.post", return_value=_mock_post(403)),
        pytest.raises(EdgeRevoked),
    ):
        await _one_tick(settings, state)

    assert state.revoked is True


async def test_heartbeat_401_ignores_other_edge_identity_on_disk(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    state = HeartbeatState(make_credentials(days_valid=29, key_index=0, edge_id="edge-a"))
    persist_credentials(
        settings.state_dir, make_credentials(days_valid=90, key_index=1, edge_id="edge-b")
    )

    with (
        patch("edge.control_plane.httpx.post", return_value=_mock_post(401)),
        pytest.raises(EdgeRevoked),
    ):
        await _one_tick(settings, state)

    assert state.credentials.edge_id == "edge-a"


async def test_rotate_401_adopts_newer_credentials_instead_of_revoking(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    current = make_credentials(days_valid=29, key_index=0)
    state = HeartbeatState(current)
    rotated_by_other_replica = make_credentials(days_valid=90, key_index=1)
    persist_credentials(settings.state_dir, rotated_by_other_replica)

    with patch(
        "edge.control_plane.httpx.post",
        side_effect=[_mock_post(200, HB_ROTATE), _mock_post(401)],
    ):
        await _one_tick(settings, state)

    assert state.revoked is False
    assert state.credentials == rotated_by_other_replica
    assert load_credentials(settings.state_dir) == rotated_by_other_replica


async def test_heartbeat_loop_logs_and_survives_unexpected_errors(
    tmp_path: Path, record_logs
) -> None:
    settings = _settings(tmp_path)
    state = HeartbeatState(make_credentials())
    events = record_logs(heartbeat_mod)
    tick = AsyncMock(side_effect=[RuntimeError("boom"), None, EdgeRevoked("revoked")])

    with (
        patch("edge.heartbeat._one_tick", tick),
        patch("edge.heartbeat.asyncio.sleep", AsyncMock()),
    ):
        await asyncio.wait_for(heartbeat_loop(settings, state), timeout=5)

    assert tick.await_count == 3
    # log.exception logs at error level with the traceback attached.
    assert ("exception", "edge.heartbeat.tick_failed") in [(lvl, ev) for lvl, ev, _ in events]


async def test_rotates_on_local_expiry_when_server_does_not_ask(tmp_path: Path) -> None:
    # A set left half-renamed (new key, old cert) reads as nearly expired
    # locally while the server holds a fresh cert. Rotating rewrites it whole.
    settings = _settings(tmp_path)
    half_renamed = make_credentials(days_valid=25, key_index=0)
    state = HeartbeatState(half_renamed)
    rotated = make_credentials(days_valid=90, key_index=1)

    with patch(
        "edge.control_plane.httpx.post",
        side_effect=[_mock_post(200, HB_OK), _mock_post(200, _rotate_body(rotated))],
    ) as post:
        await _one_tick(settings, state)

    assert post.call_count == 2
    assert post.call_args_list[1].args[0].endswith("/api/v1/edge/rotate/")
    assert load_credentials(settings.state_dir) == rotated


async def test_no_rotation_when_neither_server_nor_cert_says_due(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    state = HeartbeatState(make_credentials(days_valid=45))

    with patch("edge.control_plane.httpx.post", return_value=_mock_post(200, HB_OK)) as post:
        await _one_tick(settings, state)

    assert post.call_count == 1
