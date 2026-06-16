"""``POST /v1/oauth/token`` — local OAuth 2.0 token endpoint.

TRUS-1270 Phase 2. In-cluster agents present ``client_id`` +
``client_secret`` here; Edge validates against the policy-sync'd
``authorized_clients`` list and returns a short-lived JWT signed with
Edge's own enrollment private key.

Tokens are valid only at this Edge instance — they're never presented to
aurora-gateway. The agent re-requests on expiry; ``client_credentials``
has no refresh-token concept per RFC 6749 § 4.4.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request
from pydantic import BaseModel, Field

from edge.config import Settings
from edge.oauth import (
    EnrollmentMissing,
    InvalidClient,
    authenticate_client,
    derive_public_key_pem,
    load_private_key_pem,
    mint_agent_token,
    narrow_scopes,
)
from edge.policy.cache import get_cache

router = APIRouter(tags=["oauth"])
logger = logging.getLogger(__name__)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(ge=1)
    scope: str = ""


class TokenError(BaseModel):
    """RFC 6749 § 5.2 error response shape."""

    error: str
    error_description: str | None = None


def _key_state(app_state) -> tuple[str, bytes]:
    """Load + cache the private + public keys on the FastAPI app state.

    First call reads from disk; subsequent calls return the cached pair.
    The key file is immutable for the life of the pod (rotation is a
    separate flow that restarts the process), so caching is safe.
    """
    private_key_pem = getattr(app_state, "oauth_private_key_pem", None)
    public_key_pem = getattr(app_state, "oauth_public_key_pem", None)
    if private_key_pem and public_key_pem:
        return private_key_pem, public_key_pem

    cfg: Settings = app_state.settings
    private_key_pem = load_private_key_pem(cfg.state_dir)
    public_key_pem = derive_public_key_pem(private_key_pem)
    app_state.oauth_private_key_pem = private_key_pem
    app_state.oauth_public_key_pem = public_key_pem
    return private_key_pem, public_key_pem


@router.post(
    "/oauth/token",
    response_model=TokenResponse,
    responses={
        400: {"model": TokenError, "description": "invalid_request / invalid_scope"},
        401: {"model": TokenError, "description": "invalid_client"},
        503: {"model": TokenError, "description": "policy cache cold; cannot mint"},
    },
)
async def issue_token(
    request: Request,
    grant_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    client_secret: Annotated[str, Form()],
    scope: Annotated[str, Form()] = "",
) -> TokenResponse:
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_grant_type",
                "error_description": ("this endpoint only supports the 'client_credentials' grant"),
            },
        )

    cache = get_cache()
    authorized = cache.authorized_clients()
    if not cache.is_warm:
        # Cold cache → we don't yet know who's authorized. Fail closed.
        raise HTTPException(
            status_code=503,
            detail={
                "error": "service_unavailable",
                "error_description": ("policy cache not warm; Edge has not completed first sync"),
            },
        )

    try:
        record = authenticate_client(
            client_id=client_id,
            client_secret=client_secret,
            authorized=authorized,
        )
    except InvalidClient as exc:
        logger.info(
            "edge.oauth.invalid_client",
            extra={"client_id_prefix": client_id[:8], "reason": str(exc)},
        )
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": str(exc)},
        ) from exc

    requested = scope.split() if scope else []
    granted = narrow_scopes(requested, record.allowed_scopes)
    if requested and not granted:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_scope",
                "error_description": ("none of the requested scopes are allowed for this client"),
            },
        )

    cfg: Settings = request.app.state.settings
    try:
        private_key_pem, _ = _key_state(request.app.state)
    except EnrollmentMissing as exc:
        # Edge hasn't enrolled yet — readiness probe is already red; surface
        # this so the SDK's auto-retry doesn't tight-loop.
        raise HTTPException(
            status_code=503,
            detail={
                "error": "service_unavailable",
                "error_description": str(exc),
            },
        ) from exc

    token, expires_in = mint_agent_token(
        client_id=record.client_id,
        agent_id=record.agent_id,
        granted_scopes=granted,
        ttl_seconds=cfg.oauth_token_ttl_seconds,
        private_key_pem=private_key_pem,
        issuer=f"edge:{cfg.tenant_id}",
    )

    logger.info(
        "edge.oauth.token_issued",
        extra={
            "client_id": record.client_id,
            "agent_id": record.agent_id,
            "scopes": granted,
            "ttl": expires_in,
        },
    )

    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=expires_in,
        scope=" ".join(granted),
    )
