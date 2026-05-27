"""Vendor-copied policy evaluation engine.

These modules are a verbatim port of the DefenseClaw runtime evaluator
from ``agp-control-plane/packages/adapters/defenseclaw/defenseclaw_adapter/engine``.
Pulled in-tree (rather than as a package dep) so the Edge image stays
small (no pandas / sklearn / weasyprint transitive deps from the
``aurora-metrics`` lineage).

Pure stdlib + dataclasses. Sub-millisecond evaluation on realistic
rule counts. If the upstream evaluator changes shape, mirror the change
here — the e2e parity test in TRUS-988 will catch drift.
"""

from edge.engine.compiler import (
    CompiledPolicy,
    CompiledRule,
    MatchPattern,
    compile_policy,
)
from edge.engine.evaluator import EvaluationInput, EvaluationResult, evaluate

__all__ = [
    "CompiledPolicy",
    "CompiledRule",
    "EvaluationInput",
    "EvaluationResult",
    "MatchPattern",
    "compile_policy",
    "evaluate",
]
