"""Runtime policy evaluator.

Walks compiled rules in priority order. First match wins. Sub-millisecond
on realistic rule counts (<1000 rules). Output exactly mirrors what an
OPA-backed adapter would return — so swapping in OPA later doesn't change
downstream code.

Vendor-copied from agp-control-plane defenseclaw_adapter/engine/evaluator.py.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from edge.engine.compiler import CompiledPolicy, CompiledRule, MatchPattern


@dataclass(frozen=True)
class EvaluationInput:
    tool: str
    args: dict[str, Any]
    subject: str | None = None
    subject_attrs: dict[str, Any] | None = None


@dataclass(frozen=True)
class EvaluationResult:
    verdict: str  # "allow" | "deny" | "redact"
    rule_id: str
    reason: str
    redactions: list[str]
    matched_framework_tags: list[str]
    latency_ms: float


def _matches(pattern: MatchPattern, inp: EvaluationInput) -> bool:
    if pattern.tool is not None and pattern.tool != inp.tool:
        return False
    if not pattern.arg_keys_present.issubset(set(inp.args.keys())):
        return False
    for k, v in pattern.arg_equals.items():
        if inp.args.get(k) != v:
            return False
    if pattern.subject_attr is not None:  # noqa: SIM102 - vendor-copied from agp-control-plane; keep parity
        if not inp.subject_attrs or pattern.subject_attr not in inp.subject_attrs:
            return False
    return True


def _resolve_action(rule: CompiledRule, inp: EvaluationInput) -> EvaluationResult:
    base_action = rule.action.split(":", 1)[0]
    if base_action == "redact":
        present = [
            p for p in rule.redact_paths
            if p.startswith("args.") and p.removeprefix("args.") in inp.args
        ]
        if not present:
            return EvaluationResult(
                verdict="allow",
                rule_id=f"{rule.rule_id}.no-op-redact",
                reason="Redact rule matched but no targeted args present.",
                redactions=[],
                matched_framework_tags=rule.framework_tags,
                latency_ms=0.0,
            )
        return EvaluationResult(
            verdict="redact",
            rule_id=rule.rule_id,
            reason=f"Redacted: {', '.join(p.removeprefix('args.') for p in present)}",
            redactions=present,
            matched_framework_tags=rule.framework_tags,
            latency_ms=0.0,
        )
    return EvaluationResult(
        verdict=base_action,
        rule_id=rule.rule_id,
        reason=f"Rule {rule.rule_id!r} fired with action {base_action!r}.",
        redactions=[],
        matched_framework_tags=rule.framework_tags,
        latency_ms=0.0,
    )


def evaluate(policy: CompiledPolicy, inp: EvaluationInput) -> EvaluationResult:
    """Walk rules in priority order. First match wins.

    If no rule matches, default to deny — fail-safe semantics. Operators must
    explicitly include an "allow *" rule to authorize an action.
    """
    t0 = time.perf_counter()
    for rule in policy.rules:
        if _matches(rule.pattern, inp):
            res = _resolve_action(rule, inp)
            return EvaluationResult(
                verdict=res.verdict,
                rule_id=res.rule_id,
                reason=res.reason,
                redactions=res.redactions,
                matched_framework_tags=res.matched_framework_tags,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )
    return EvaluationResult(
        verdict="deny",
        rule_id="default.fail_safe",
        reason="No rule matched; fail-safe deny.",
        redactions=[],
        matched_framework_tags=[],
        latency_ms=(time.perf_counter() - t0) * 1000.0,
    )
