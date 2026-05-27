"""``POST /v1/decide`` — runtime allow/deny/redact for agent actions.

Reads the active policy from the in-process cache (populated by
:mod:`edge.policy.sync`) and runs the vendor-copied evaluator.

If the cache is empty or stale, the configured fail mode kicks in:
* ``policy_fail_mode="closed"`` → 503 + deny verdict (default, fail-safe)
* ``policy_fail_mode="open"``   → allow verdict + audit reason flags it

Audit event emission (TRUS-989) hooks in after the verdict is returned.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from edge.config import Settings
from edge.engine import EvaluationInput, EvaluationResult, evaluate
from edge.metrics import cache_hits_total, decision_latency_ms, decisions_total
from edge.policy.cache import get_cache
from edge.policy.stale import fail_mode_verdict
from edge.policy.stale import status as stale_status

router = APIRouter(tags=["decide"])


class DecideRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    subject: str | None = None
    subject_attrs: dict[str, Any] | None = None


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
async def decide(body: DecideRequest, request: Request) -> DecideResponse:
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
