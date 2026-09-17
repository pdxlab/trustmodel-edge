"""Tests for the audit-event payload builder."""

from __future__ import annotations

import uuid

from edge.telemetry.payload import _TENANT_NAMESPACE, build_audit_event, hash_subject


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


# ── hash_subject (TRUS-2002) ────────────────────────────────────────────


def test_hash_subject_is_deterministic() -> None:
    """Same subject + key must always produce the same pseudonym, or
    downstream per-subject recourse lookups couldn't correlate events."""
    h1 = hash_subject("customer-42@example.com", "k1")
    h2 = hash_subject("customer-42@example.com", "k1")
    assert h1 == h2
    assert h1 != ""


def test_hash_subject_differs_by_key() -> None:
    """A different key must produce a different pseudonym — otherwise the
    key isn't doing anything and this degrades to an unkeyed hash."""
    h1 = hash_subject("customer-42@example.com", "k1")
    h2 = hash_subject("customer-42@example.com", "k2")
    assert h1 != h2


def test_hash_subject_never_leaks_the_raw_value() -> None:
    subject = "very-guessable-email@example.com"
    digest = hash_subject(subject, "some-key")
    assert subject not in digest


def test_hash_subject_is_not_a_bare_unkeyed_hash() -> None:
    """Regression guard for the actual vulnerability this exists to avoid:
    an attacker with a candidate list (e.g. known customer emails) and a
    bare hash could just hash each candidate and match. Asserting the
    output differs from plain SHA-256 of the subject pins the design to
    "keyed", not just "some hash was applied"."""
    import hashlib

    subject = "customer-42@example.com"
    assert hash_subject(subject, "some-key") != hashlib.sha256(
        subject.encode("utf-8")
    ).hexdigest()


def test_hash_subject_empty_subject_or_key_returns_empty_string() -> None:
    assert hash_subject(None, "some-key") == ""
    assert hash_subject("", "some-key") == ""
    assert hash_subject("customer-42", "") == ""
