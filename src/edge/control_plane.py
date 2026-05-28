"""httpx client for the aurora-gateway /api/v1/edge/* endpoints (TRUS-987).

Thin wrapper that:

* Knows the 3 endpoints Edge calls (enroll, rotate, heartbeat).
* Builds the correct Auth header per endpoint (none for enroll, cert-JWT
  for rotate + heartbeat).
* Surfaces typed responses + a single :class:`EdgeRevoked` exception the
  heartbeat loop catches to trigger pod exit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import httpx

from edge.identity import EdgeCredentials, sign_edge_jwt

DEFAULT_TIMEOUT_S = 10.0


class EdgeControlPlaneError(Exception):
    """Generic control-plane failure (network, 5xx, malformed body)."""


class EdgeRevoked(Exception):
    """Server-side told us this Edge instance was revoked.

    Raised when:
    * heartbeat returns ``revoked=True``, OR
    * heartbeat returns 401/403 (cert-JWT rejected — usually because the
      EdgeInstance row was revoked, but possibly because the cert was
      rotated out from under us).
    """


@dataclass
class EnrollBundle:
    edge_id: str
    tenant_id: str
    cert_pem: str
    key_pem: str
    ca_chain_pem: str
    cert_valid_from: datetime
    cert_valid_to: datetime
    agp_endpoint: str
    telemetry_endpoint: str


@dataclass
class RotateBundle:
    cert_pem: str
    key_pem: str
    ca_chain_pem: str
    cert_valid_from: datetime
    cert_valid_to: datetime


@dataclass
class HeartbeatResponse:
    revoked: bool
    sync_interval_s: int
    rotation_due: bool


def _post(url: str, *, json: dict, headers: dict | None = None) -> httpx.Response:
    try:
        r = httpx.post(url, json=json, headers=headers or {}, timeout=DEFAULT_TIMEOUT_S)
    except httpx.HTTPError as exc:
        raise EdgeControlPlaneError(f"network error calling {url}: {exc}") from exc
    return r


def enroll(
    *,
    control_plane_url: str,
    bootstrap_token: str,
    edge_pod_id: str,
    cluster_fingerprint: str = "",
) -> EnrollBundle:
    url = f"{control_plane_url.rstrip('/')}/api/v1/edge/enroll/"
    r = _post(
        url,
        json={
            "bootstrap_token": bootstrap_token,
            "edge_pod_id": edge_pod_id,
            "cluster_fingerprint": cluster_fingerprint,
        },
    )
    if r.status_code != 201:
        raise EdgeControlPlaneError(f"enroll failed: HTTP {r.status_code} {r.text[:200]}")
    b = r.json()
    return EnrollBundle(
        edge_id=b["edge_id"],
        tenant_id=b["tenant_id"],
        cert_pem=b["client_cert"],
        key_pem=b["client_key"],
        ca_chain_pem=b["ca_chain"],
        cert_valid_from=datetime.fromisoformat(b["cert_valid_from"].replace("Z", "+00:00")),
        cert_valid_to=datetime.fromisoformat(b["cert_valid_to"].replace("Z", "+00:00")),
        agp_endpoint=b["agp_endpoint"],
        telemetry_endpoint=b["telemetry_endpoint"],
    )


def _auth_header(creds: EdgeCredentials) -> dict:
    return {"Authorization": f"Bearer {sign_edge_jwt(creds.edge_id, creds.key_pem)}"}


def rotate(*, control_plane_url: str, creds: EdgeCredentials) -> RotateBundle:
    url = f"{control_plane_url.rstrip('/')}/api/v1/edge/rotate/"
    r = _post(url, json={}, headers=_auth_header(creds))
    if r.status_code in (401, 403):
        raise EdgeRevoked(f"rotate rejected by control plane: HTTP {r.status_code}")
    if r.status_code != 200:
        raise EdgeControlPlaneError(f"rotate failed: HTTP {r.status_code} {r.text[:200]}")
    b = r.json()
    return RotateBundle(
        cert_pem=b["client_cert"],
        key_pem=b["client_key"],
        ca_chain_pem=b["ca_chain"],
        cert_valid_from=datetime.fromisoformat(b["cert_valid_from"].replace("Z", "+00:00")),
        cert_valid_to=datetime.fromisoformat(b["cert_valid_to"].replace("Z", "+00:00")),
    )


def heartbeat(
    *,
    control_plane_url: str,
    creds: EdgeCredentials,
    in_flight_count: int = 0,
    queue_depth: int = 0,
) -> HeartbeatResponse:
    url = f"{control_plane_url.rstrip('/')}/api/v1/edge/heartbeat/"
    r = _post(
        url,
        json={"in_flight_count": in_flight_count, "queue_depth": queue_depth},
        headers=_auth_header(creds),
    )
    if r.status_code in (401, 403):
        raise EdgeRevoked(f"heartbeat rejected by control plane: HTTP {r.status_code}")
    if r.status_code != 200:
        raise EdgeControlPlaneError(f"heartbeat failed: HTTP {r.status_code} {r.text[:200]}")
    b = r.json()
    if b.get("revoked"):
        raise EdgeRevoked("heartbeat returned revoked=true")
    return HeartbeatResponse(
        revoked=False,
        sync_interval_s=int(b.get("sync_interval_s", 60)),
        rotation_due=bool(b.get("rotation_due", False)),
    )
