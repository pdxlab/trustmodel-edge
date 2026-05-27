"""Sanity tests for the vendor-copied evaluator.

This is a thin parity surface — the upstream defenseclaw_adapter has
exhaustive tests. We just confirm the copy still behaves as expected
under common rule shapes (allow, deny, redact, priority, default-deny).
"""

from __future__ import annotations

from edge.engine import EvaluationInput, compile_policy, evaluate


def _policy(rules: list[dict]):
    return compile_policy(
        policy_id="pol-1", name="t", version="1.0.0", rules=rules
    )


def test_allow_rule_matches() -> None:
    pol = _policy([{"rule_id": "r1", "when": {"tool": "search.query"}, "then": "allow"}])
    res = evaluate(pol, EvaluationInput(tool="search.query", args={}))
    assert res.verdict == "allow"
    assert res.rule_id == "r1"


def test_deny_rule_takes_priority_over_allow_at_same_priority() -> None:
    pol = _policy(
        [
            {"rule_id": "allow_all", "when": {"tool": "*"}, "then": "allow", "priority": 10},
            {"rule_id": "deny_email", "when": {"tool": "email.send"}, "then": "deny", "priority": 10},
        ]
    )
    res = evaluate(pol, EvaluationInput(tool="email.send", args={}))
    assert res.verdict == "deny"
    assert res.rule_id == "deny_email"


def test_redact_replaces_arg_path() -> None:
    pol = _policy(
        [
            {
                "rule_id": "redact_ssn",
                "when": {"tool": "*", "args.ssn": True},
                "then": "redact:args.ssn",
                "priority": 10,
            },
            {"rule_id": "allow_all", "when": {"tool": "*"}, "then": "allow", "priority": 999},
        ]
    )
    res = evaluate(pol, EvaluationInput(tool="profile.update", args={"name": "x", "ssn": "111"}))
    assert res.verdict == "redact"
    assert res.redactions == ["args.ssn"]


def test_no_match_returns_default_deny() -> None:
    pol = _policy([{"rule_id": "r1", "when": {"tool": "explicit"}, "then": "allow"}])
    res = evaluate(pol, EvaluationInput(tool="nothing.matches", args={}))
    assert res.verdict == "deny"
    assert res.rule_id == "default.fail_safe"
