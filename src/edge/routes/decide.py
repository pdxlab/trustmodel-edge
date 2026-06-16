"""``POST /v1/decide`` — runtime allow/deny/redact for agent actions.

Reads the active policy from the in-process cache (populated by
:mod:`edge.policy.sync`) and runs the vendor-copied evaluator.

If the cache is empty or stale, the configured fail mode kicks in:
* ``policy_fail_mode="closed"`` → 503 + deny verdict (default, fail-safe)
* ``policy_fail_mode="open"``   → allow verdict + audit reason flags it

Audit event emission (TRUS-989) hooks in after the verdict is returned.

Auth (TRUS-1270): callers MUST present a Bearer JWT minted by this Edge's
``POST /v1/oauth/token`` endpoint. The token's ``sub`` becomes the
audit-event ``agent_id``; ``govern:enforce`` must be in the token's
scope set.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from edge.config import Settings
from edge.engine import EvaluationInput, EvaluationResult, evaluate
from edge.metrics import cache_hits_total, decision_latency_ms, decisions_total
from edge.oauth import (
    AgentTokenClaims,
    EnrollmentMissing,
    InvalidToken,
    derive_public_key_pem,
    load_private_key_pem,
    verify_agent_token,
)
from edge.policy.cache import get_cache
from edge.policy.stale import fail_mode_verdict
from edge.policy.stale import status as stale_status
from edge.telemetry import build_audit_event, get_store

router = APIRouter(tags=["decide"])

_GOVERN_ENFORCE = "govern:enforce"


def _public_key(app_state) -> bytes:
    """Lazy-load + cache the public key used to verify agent tokens.

    Mirrors the same lazy-load used by routes/oauth.py — both routes
    share one key cache on ``app.state`` so the disk read happens once.
    """
    public_key_pem = getattr(app_state, "oauth_public_key_pem", None)
    if public_key_pem is not None:
        return public_key_pem
    cfg: Settings = app_state.settings
    private_key_pem = load_private_key_pem(cfg.state_dir)
    public_key_pem = derive_public_key_pem(private_key_pem)
    app_state.oauth_private_key_pem = private_key_pem
    app_state.oauth_public_key_pem = public_key_pem
    return public_key_pem


def _require_agent_token(request: Request, authorization: str) -> AgentTokenClaims:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="missing or malformed Authorization header (expected Bearer)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="empty bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        public_key_pem = _public_key(request.app.state)
    except EnrollmentMissing as exc:
        raise HTTPException(status_code=503, detail=f"edge enrollment incomplete: {exc}") from exc
    try:
        claims = verify_agent_token(token, public_key_pem)
    except InvalidToken as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    if _GOVERN_ENFORCE not in claims.scopes:
        raise HTTPException(
            status_code=403,
            detail=(
                f"token is missing required scope '{_GOVERN_ENFORCE}'; "
                f"granted scopes: {' '.join(claims.scopes) or '(none)'}"
            ),
        )
    return claims


class DecideRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    subject: str | None = None
    subject_attrs: dict[str, Any] | None = None
    # Pre-TRUS-1270 callers could pass agent_id in the body. Now sourced
    # from the Bearer token's ``agent_id`` claim instead. Body field
    # retained for backward compatibility — used only when the token
    # itself doesn't carry an agent_id claim.
    agent_id: str | None = None


class DecideResponse(BaseModel):
    verdict: str
    rule_id: str
    reason: str
    redactions: list[str] = Field(default_factory=list)
    matched_framework_tags: list[str] = Field(default_factory=list)
    latency_ms: float
    policy_id: str | None = None
    policy_version: str | None = None
    stale: bool = False


@router.post("/decide", response_model=DecideResponse)
async def decide(
    body: DecideRequest,
    request: Request,
    authorization: str = Header(default="", alias="Authorization"),
) -> DecideResponse:
    claims = _require_agent_token(request, authorization)
    # Prefer the token's agent_id claim; fall back to the legacy body field.
    agent_id = claims.agent_id or body.agent_id

    cfg: Settings = request.app.state.settings
    cache = get_cache()
    compiled = cache.compiled()

    if compiled is None:
        # No policy at all yet — surface this as 503 unless explicitly
        # configured fail-open. Same code path the readiness probe uses
        # so K8s holds traffic off the pod until warm.
        verdict, reason = fail_mode_verdict(cfg.policy_fail_mode)
        if cfg.policy_fail_mode == "closed":
            raise HTTPException(status_code=503, detail="policy cache not warm")
        decisions_total.labels(verdict=verdict).inc()
        return DecideResponse(
            verdict=verdict,
            rule_id=reason,
            reason="no policy cached; fail-open per tenant config",
            latency_ms=0.0,
            stale=True,
        )

    stale = stale_status(cache, threshold_seconds=cfg.policy_stale_threshold_seconds)
    if stale.is_stale:
        verdict, reason = fail_mode_verdict(cfg.policy_fail_mode)
        decisions_total.labels(verdict=verdict).inc()
        return DecideResponse(
            verdict=verdict,
            rule_id=reason,
            reason=(
                f"policy stale ({int(stale.seconds_since_refresh)}s since last sync); "
                f"applying fail_mode={cfg.policy_fail_mode}"
            ),
            latency_ms=0.0,
            policy_id=compiled.policy_id,
            policy_version=compiled.version,
            stale=True,
        )

    cache_hits_total.inc()

    t0 = time.perf_counter()
    result: EvaluationResult = evaluate(
        compiled,
        EvaluationInput(
            tool=body.tool,
            args=body.args,
            subject=body.subject,
            subject_attrs=body.subject_attrs,
        ),
    )
    latency = (time.perf_counter() - t0) * 1000.0

    decisions_total.labels(verdict=result.verdict).inc()
    decision_latency_ms.observe(latency)

    # Enqueue audit event for outbound shipping (TRUS-989). Best-effort:
    # back-pressure / disk-full can drop the row, but the decision has
    # already been returned to the caller. Counter for ops visibility.
    audit = build_audit_event(
        tenant_id=cfg.tenant_id,
        agent_id=agent_id,
        subject=body.subject,
        policy_id=compiled.policy_id,
        verdict=result.verdict,
        rule_id=result.rule_id,
        reason=result.reason,
        tool=body.tool,
        args=body.args,
        redactions=result.redactions,
        framework_tags=result.matched_framework_tags,
        latency_ms=result.latency_ms,
    )
    get_store().enqueue(audit.to_dict())

    return DecideResponse(
        verdict=result.verdict,
        rule_id=result.rule_id,
        reason=result.reason,
        redactions=result.redactions,
        matched_framework_tags=result.matched_framework_tags,
        latency_ms=result.latency_ms,
        policy_id=compiled.policy_id,
        policy_version=compiled.version,
        stale=False,
    )
