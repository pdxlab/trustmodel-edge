"""Stub-route contract tests.

Each TRUS-986 stub must return 501 and name its implementing ticket so
downstream callers + ops dashboards can detect "not-yet-implemented"
deterministically. When TRUS-987 / TRUS-988 / TRUS-989 ship, these tests
get replaced with real behavior tests in those tickets.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    ("path", "ticket"),
    [
        # /v1/decide implemented in TRUS-988 — see tests/test_decide.py.
        ("/v1/enroll-callback", "TRUS-987"),
        ("/v1/telemetry-flush", "TRUS-989"),
    ],
)
def test_stub_returns_501_with_ticket(
    client: TestClient, path: str, ticket: str
) -> None:
    response = client.post(path)
    assert response.status_code == 501
    body = response.json()
    assert body["error"] == "not_implemented"
    assert body["implementation_ticket"] == ticket
