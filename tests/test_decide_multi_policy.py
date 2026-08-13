"""TRUS-1716 — /v1/decide routing by ``policy_name`` in multi-policy mode.

Covers:
- Known ``policy_name`` routes to the matching policy; response
  ``policy_id`` + ``policy_version`` reflect the routed policy (regression
  pin against a future refactor that accidentally hardcodes the primary's
  id).
- Unknown ``policy_name`` → 400 ``code=policy_not_found`` + ``available`` list.
- No ``policy_name`` → primary policy evaluated.
- Feature-flag off + ``policy_name`` set → field ignored, primary evaluated
  (backward-compat).
- Prometheus counter ``edge_decisions_policy_not_found_total`` increments
  on the 400 branch (Deploy 3 monitor window).
"""

from __future__ import annotations

import pytest


def test_decide_routes_to_known_policy_name(multi_warm_client) -> None:
    """Sending ``policy_name='deny-email'`` routes through that policy
    and denies the email tool. Response IDs reflect the routed policy,
    NOT the primary."""
    client, auth = multi_warm_client
    response = client.post(
        "/v1/decide",
        json={
            "tool": "email.send",
            "args": {"to": "x@y.com"},
            "policy_name": "deny-email",
        },
        headers=auth,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "deny"
    assert body["policy_id"] == "pol-deny-email"
    assert body["policy_version"] == "1.0.0"


def test_decide_omitted_policy_name_routes_to_primary(multi_warm_client) -> None:
    """Pre-1716 SDK omits ``policy_name`` → route to primary."""
    client, auth = multi_warm_client
    response = client.post(
        "/v1/decide",
        json={"tool": "email.send", "args": {"to": "x@y.com"}},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # primary-policy is allow-all → allow.
    assert body["verdict"] == "allow"
    assert body["policy_id"] == "pol-primary-policy"


def test_decide_unknown_policy_name_returns_400_with_code(multi_warm_client) -> None:
    """Unknown ``policy_name`` → 400 with stable machine-readable
    ``code=policy_not_found`` + ``available`` list. Callers key on
    ``code`` for retry/fallback logic (TRUS-1643 convention)."""
    client, auth = multi_warm_client
    response = client.post(
        "/v1/decide",
        json={"tool": "search.query", "policy_name": "does-not-exist"},
        headers=auth,
    )
    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "policy_not_found"
    # ``available`` sorted for determinism; must reflect what's actually cached.
    assert set(detail["available"]) == {
        "primary-policy",
        "deny-email",
        "block-search",
    }


def test_decide_unknown_policy_name_increments_not_found_counter(
    multi_warm_client,
) -> None:
    """The 400 branch bumps ``edge_decisions_policy_not_found_total`` —
    Deploy 3 monitor window watches this for any non-zero sustained rate.

    Counter is UNLABELED (Priyanka #12 review): the caller-controlled
    ``policy_name`` value only goes into the WARN log, never into a
    Prometheus label — otherwise a caller spraying random names would
    mint one time series per name on the hot decide path.
    """
    client, auth = multi_warm_client
    from edge.metrics import policy_not_found_total

    baseline = policy_not_found_total._value.get()

    # Two misses with DIFFERENT policy_name values — the counter should
    # add 2 regardless of the names since it's unlabeled.
    r1 = client.post(
        "/v1/decide",
        json={"tool": "search.query", "policy_name": "mystery-1"},
        headers=auth,
    )
    r2 = client.post(
        "/v1/decide",
        json={"tool": "search.query", "policy_name": "mystery-2"},
        headers=auth,
    )
    assert r1.status_code == 400
    assert r2.status_code == 400

    after = policy_not_found_total._value.get()
    assert after - baseline == 2.0


def test_policy_not_found_counter_has_no_policy_name_label(
    multi_warm_client,
) -> None:
    """Regression pin for TRUS-1716 (Priyanka #12 review): the counter
    must NOT expose ``policy_name`` as a label. A future refactor that
    accidentally re-adds the label would explode cardinality; this test
    catches that at PR-review time."""
    from edge.metrics import policy_not_found_total

    # ``.labels(...)`` on an unlabeled Counter raises. If someone
    # re-introduces the label, this test fails loudly.
    with pytest.raises(ValueError):
        policy_not_found_total.labels(policy_name="anything")


def test_decide_ignores_policy_name_when_flag_off(warm_client) -> None:
    """The default rollout state (``multi_policy_enabled=False``) keeps
    pre-1716 semantics: /v1/decide ignores any ``policy_name`` field on
    the request. This exists so pre-1716 Edge pods keep serving byte-
    identically even if a caller upgrades their SDK first.

    The ``warm_client`` fixture leaves ``multi_policy_enabled=False``.
    """
    client, auth = warm_client
    # ``warm_client`` seeds a single policy named "demo" as primary.
    # Sending ``policy_name="something-else"`` MUST NOT 400 — the field
    # is silently ignored when the flag is off.
    response = client.post(
        "/v1/decide",
        json={
            "tool": "search.query",
            "args": {"q": "x"},
            "policy_name": "does-not-exist",
        },
        headers=auth,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # Primary (single) policy in warm_client is allow-all.
    assert body["verdict"] == "allow"
    assert body["policy_id"] == "pol-demo-1"
