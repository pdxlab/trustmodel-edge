"""Audit event payload builder.

Shape mirrors what aurora-gateway's existing audit ingestor accepts
(see ``agp-control-plane/apps/api/agp/audit/forwarder.py::_build_payload``).
That lets the same downstream pipeline (ComplianceEvent stream, Live
Stream, Recourse, regulator reports) absorb Edge events with no
gateway-side schema changes — same plugin posture as the policy fetch.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# Same namespace the agp-control-plane forwarder uses so tenant slugs
# resolve to identical customer_id UUIDs on both sides.
_TENANT_NAMESPACE = uuid.UUID("d3b0a5f9-7c41-4f30-8a7b-9c5e6f4a1b2c")


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    customer_id: str
    agent_id: str
    subject_id: str
    policy_id: str
    decision: str  # verdict
    reason: str
    action_type: str  # tool name
    action_payload: dict[str, Any]
    evidence: dict[str, Any]
    occurred_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_audit_event(
    *,
    tenant_id: str,
    agent_id: str | None,
    subject: str | None,
    policy_id: str,
    verdict: str,
    rule_id: str,
    reason: str,
    tool: str,
    args: dict[str, Any],
    redactions: list[str],
    framework_tags: list[str],
    latency_ms: float,
) -> AuditEvent:
    """Build an audit-event payload from a decision.

    ``customer_id`` is derived from the tenant slug via uuid5 — same
    deterministic mapping the central agp-control-plane forwarder uses.
    """
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        customer_id=str(uuid.uuid5(_TENANT_NAMESPACE, tenant_id)),
        agent_id=agent_id or "",
        subject_id=subject or "",
        policy_id=policy_id,
        decision=verdict,
        reason=reason,
        action_type=tool,
        action_payload=args,
        evidence={
            "framework_tags": framework_tags,
            "redactions": redactions,
            "rule_id": rule_id,
            "latency_ms": latency_ms,
        },
        occurred_at=datetime.now(UTC).isoformat(),
    )
