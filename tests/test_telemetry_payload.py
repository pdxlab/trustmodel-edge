"""Tests for the audit-event payload builder."""

from __future__ import annotations

import uuid

from edge.telemetry.payload import _TENANT_NAMESPACE, build_audit_event


def test_build_audit_event_populates_required_fields() -> None:
    event = build_audit_event(
        tenant_id="tenant-x",
        agent_id="agt-1",
        subject="user-42",
        policy_id="pol-1",
        verdict="deny",
        rule_id="deny-email",
        reason="email blocked",
        tool="email.send",
        args={"to": "x@y.com"},
        redactions=[],
        framework_tags=["NIST_AI_RMF"],
        latency_ms=0.5,
    )
    assert event.decision == "deny"
    assert event.action_type == "email.send"
    assert event.evidence["rule_id"] == "deny-email"
    assert event.evidence["latency_ms"] == 0.5
    # event_id is a fresh UUID4
    uuid.UUID(event.event_id)


def test_tenant_id_maps_to_stable_customer_id_uuid() -> None:
    """Same tenant slug must always map to the same customer_id UUID
    so events from the same tenant land in the same bucket on the
    gateway side — same deterministic mapping the central forwarder uses."""
    e1 = build_audit_event(
        tenant_id="tenant-kpmg-leonardo",
        agent_id=None,
        subject=None,
        policy_id="p",
        verdict="allow",
        rule_id="r",
        reason="",
        tool="t",
        args={},
        redactions=[],
        framework_tags=[],
        latency_ms=0.0,
    )
    e2 = build_audit_event(
        tenant_id="tenant-kpmg-leonardo",
        agent_id=None,
        subject=None,
        policy_id="p",
        verdict="allow",
        rule_id="r",
        reason="",
        tool="t",
        args={},
        redactions=[],
        framework_tags=[],
        latency_ms=0.0,
    )
    assert e1.customer_id == e2.customer_id
    assert e1.customer_id == str(uuid.uuid5(_TENANT_NAMESPACE, "tenant-kpmg-leonardo"))


def test_optional_fields_default_to_empty_string() -> None:
    event = build_audit_event(
        tenant_id="t",
        agent_id=None,
        subject=None,
        policy_id="p",
        verdict="allow",
        rule_id="r",
        reason="",
        tool="t",
        args={},
        redactions=[],
        framework_tags=[],
        latency_ms=0.0,
    )
    assert event.agent_id == ""
    assert event.subject_id == ""
