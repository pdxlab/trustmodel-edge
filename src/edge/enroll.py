"""Startup enrollment task (TRUS-987).

Runs once before the FastAPI app accepts traffic:

1. If credentials already exist on the PVC and the cert is still valid →
   reuse them (pod restarts don't need to re-enroll).
2. Otherwise read the bootstrap token (env override OR Secret file), call
   ``POST /api/v1/edge/enroll``, persist the bundle to PVC.

Raises ``EnrollmentFailed`` on permanent failure (missing token, server
401, etc.) so the lifespan can let K8s restart the pod.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import structlog

from edge.config import Settings
from edge.control_plane import EdgeControlPlaneError, enroll as cp_enroll
from edge.identity import (
    EdgeCredentials,
    load_credentials,
    persist_credentials,
    read_bootstrap_token,
)

log = structlog.get_logger()


class EnrollmentFailed(Exception):
    pass


def bootstrap_if_needed(settings: Settings) -> EdgeCredentials:
    """Return usable credentials, enrolling if necessary."""
    existing = load_credentials(settings.state_dir)
    if existing and existing.cert_valid_to > datetime.now(timezone.utc):
        log.info(
            "edge.enroll.reuse",
            edge_id=existing.edge_id,
            cert_valid_to=existing.cert_valid_to.isoformat(),
        )
        return existing

    token = read_bootstrap_token(settings.bootstrap_token_path, settings.bootstrap_token)
    if not token:
        raise EnrollmentFailed(
            f"no bootstrap token at {settings.bootstrap_token_path} and "
            "EDGE_BOOTSTRAP_TOKEN env override is empty"
        )

    log.info("edge.enroll.start", pod_id=settings.pod_id)
    try:
        bundle = cp_enroll(
            control_plane_url=str(settings.control_plane_url).rstrip("/"),
            bootstrap_token=token,
            edge_pod_id=settings.pod_id,
            cluster_fingerprint=settings.cluster_fingerprint,
        )
    except EdgeControlPlaneError as exc:
        raise EnrollmentFailed(str(exc)) from exc

    creds = EdgeCredentials(
        edge_id=bundle.edge_id,
        tenant_id=bundle.tenant_id,
        cert_pem=bundle.cert_pem,
        key_pem=bundle.key_pem,
        ca_chain_pem=bundle.ca_chain_pem,
        cert_valid_to=bundle.cert_valid_to,
        agp_endpoint=bundle.agp_endpoint,
        telemetry_endpoint=bundle.telemetry_endpoint,
    )
    persist_credentials(settings.state_dir, creds)
    log.info(
        "edge.enroll.success",
        edge_id=creds.edge_id,
        tenant_id=creds.tenant_id,
        cert_valid_to=creds.cert_valid_to.isoformat(),
    )
    return creds
