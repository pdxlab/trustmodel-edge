"""Compiles a Pydantic Policy bundle into a CompiledPolicy ready for evaluation.

Input — a list of rules of the form:
    { "rule_id": "...",
      "when": { "tool": "email.send", "subject_attr": "race", ... },
      "then": "deny" | "allow" | "redact:args.ssn[,args.dob,...]",
      "framework_tags": ["ECOA", ...],
      "priority": 100  # optional, lower = higher priority
    }

Output — a CompiledPolicy with rules sorted, match patterns pre-parsed,
and redact paths pre-extracted. Compilation is pure; safe to cache by
content hash.

Vendor-copied from agp-control-plane defenseclaw_adapter/engine/compiler.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MatchPattern:
    """Pre-parsed match conditions for a single rule."""

    tool: str | None  # None = wildcard "*"
    arg_keys_present: frozenset[str]  # required keys in action.args
    arg_equals: dict[str, Any]  # exact-match arg values
    subject_attr: str | None  # subject attribute that must be present in metadata


@dataclass(frozen=True)
class CompiledRule:
    """A rule ready for evaluation."""

    rule_id: str
    pattern: MatchPattern
    action: str  # "allow" | "deny" | "redact:..."
    redact_paths: list[str]  # only populated for redact rules
    framework_tags: list[str]
    priority: int


@dataclass(frozen=True)
class CompiledPolicy:
    """A policy bundle compiled for runtime evaluation."""

    policy_id: str
    name: str
    version: str
    rules: list[CompiledRule]
    framework_tags: list[str] = field(default_factory=list)


def compile_policy(
    *,
    policy_id: str,
    name: str,
    version: str,
    rules: list[dict[str, Any]],
    framework_tags: list[str] | None = None,
) -> CompiledPolicy:
    compiled: list[CompiledRule] = []
    for raw in rules:
        rule_id = str(raw["rule_id"])
        when = raw.get("when", {})
        then = str(raw["then"])
        priority = int(raw.get("priority", 100))
        f_tags = list(raw.get("framework_tags", []))

        tool = when.get("tool")
        tool = None if tool in (None, "*") else str(tool)

        arg_keys_present: set[str] = set()
        arg_equals: dict[str, Any] = {}
        for k, v in when.items():
            if k.startswith("args."):
                key = k.removeprefix("args.")
                if v is True:
                    arg_keys_present.add(key)
                else:
                    arg_equals[key] = v
        subject_attr = when.get("subject_attr")
        subject_attr = str(subject_attr) if subject_attr else None

        redact_paths: list[str] = []
        action = then.split(":", 1)[0]
        if action == "redact":
            paths = then.split(":", 1)[1] if ":" in then else ""
            redact_paths = [p.strip() for p in paths.split(",") if p.strip()]

        compiled.append(
            CompiledRule(
                rule_id=rule_id,
                pattern=MatchPattern(
                    tool=tool,
                    arg_keys_present=frozenset(arg_keys_present),
                    arg_equals=arg_equals,
                    subject_attr=subject_attr,
                ),
                action=then,
                redact_paths=redact_paths,
                framework_tags=f_tags,
                priority=priority,
            )
        )

    # Stable sort: deny < redact < allow at the same priority, lower priority first.
    action_order = {"deny": 0, "redact": 1, "allow": 2}
    compiled.sort(
        key=lambda r: (r.priority, action_order.get(r.action.split(":", 1)[0], 3))
    )

    return CompiledPolicy(
        policy_id=policy_id,
        name=name,
        version=version,
        rules=compiled,
        framework_tags=list(framework_tags or []),
    )
