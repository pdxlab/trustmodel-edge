"""TRUS-2002 — what leaves the pod on a fresh install with no telemetry config.

Uses the conftest ``settings`` fixture unchanged, i.e. the shipped defaults:
payload-omit ON and no subject hash key. Neither the raw args nor the raw
subject may reach the outbound audit event, while the in-pod verdict stays
correct.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from edge.app import create_app
from edge.config import Settings
from edge.telemetry import get_store
from tests.conftest import _stub_lifespan_network

_SECRET_ARG = "sensitive-patient-query"
_SUBJECT = "patient-jane-doe@example.com"


def test_default_install_keeps_args_and_subject_in_pod(warm_client) -> None:
    client, auth = warm_client
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "args": {"q": _SECRET_ARG}, "subject": _SUBJECT},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    assert response.json()["verdict"] == "allow"

    events = get_store().dequeue_batch(limit=10)
    assert len(events) == 1
    payload = events[0].payload
    assert payload["action_payload"] == {}
    # No hash key configured → withheld, never clear text.
    assert payload["subject_id"] == ""
    # Belt and braces: neither value appears anywhere in the serialized event.
    wire = json.dumps(payload)
    assert _SECRET_ARG not in wire
    assert _SUBJECT not in wire
    # The audit record is still meaningful.
    assert payload["decision"] == "allow"
    assert payload["action_type"] == "search.query"


def test_default_install_verdict_still_uses_real_args(warm_client) -> None:
    """Matching runs in-pod on the real args, so a redact rule still fires."""
    client, auth = warm_client
    response = client.post(
        "/v1/decide",
        json={"tool": "profile.update", "args": {"name": "x", "ssn": "111-22-3333"}},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "redact"
    assert "args.ssn" in body["redactions"]

    events = get_store().dequeue_batch(limit=10)
    assert events[0].payload["action_payload"] == {}
    assert "111-22-3333" not in json.dumps(events[0].payload)
    assert "args.ssn" in events[0].payload["evidence"]["redactions"]


class _RecordingLog:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def info(self, event: str, **kw) -> None:
        self.events.append(("info", event, kw))

    def warning(self, event: str, **kw) -> None:
        self.events.append(("warning", event, kw))


def _startup_events(settings: Settings, monkeypatch) -> list[tuple[str, str, dict]]:
    _stub_lifespan_network(monkeypatch)
    recorder = _RecordingLog()
    monkeypatch.setattr("edge.app.log", recorder)
    with TestClient(create_app(settings, skip_enrollment=True)):
        pass
    return recorder.events


def test_startup_warns_when_subject_is_withheld(settings, monkeypatch) -> None:
    events = _startup_events(settings, monkeypatch)
    assert ("info", "edge.telemetry.privacy", {
        "omit_payload": True, "subject_id_mode": "withheld",
    }) in events
    assert any(
        level == "warning" and name == "edge.telemetry.subject_withheld"
        for level, name, _ in events
    )


def test_startup_does_not_warn_when_hash_key_is_set(settings, monkeypatch) -> None:
    keyed = settings.model_copy(update={"telemetry_subject_hash_key": "k"})
    events = _startup_events(keyed, monkeypatch)
    assert ("info", "edge.telemetry.privacy", {
        "omit_payload": True, "subject_id_mode": "hashed",
    }) in events
    assert not any(name == "edge.telemetry.subject_withheld" for _, name, _ in events)
