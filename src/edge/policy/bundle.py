"""Wire-format Pydantic models for the policy bundle.

Mirror of ``aurora-gateway/rails/protocol.py`` (Policy + PolicyRule) and
the ``EdgePolicy`` row from ``aurora-gateway/edge_control/views.py``.

Duplicated rather than imported because aurora-gateway is Django and
trustmodel-edge is FastAPI — sharing a package across both isn't set
up. The contract is the JSON on the wire; round-tripping through these
classes is byte-equivalent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PolicyRule(BaseModel):
    """One rule within an AGT policy."""

    rule_id: str
    when: dict[str, Any]
    then: str
    framework_tags: list[str] = Field(default_factory=list)
    priority: int = 100


class Policy(BaseModel):
    """A compiled AGT policy ready to publish to the runtime."""

    name: str
    version: str
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)
    framework_tags: list[str] = Field(default_factory=list)


class AuthorizedClient(BaseModel):
    """One OAuthClient that may present ``client_credentials`` at this Edge.

    Pushed down by aurora-gateway in the policy-sync payload (TRUS-1270).
    Edge uses ``client_secret_hash`` to verify the secret presented at
    ``POST /oauth/token`` — fully offline, no round-trip on the mint path.
    The hash is Django's PBKDF2 (``pbkdf2_sha256$<iter>$<salt>$<hash>``).
    """

    client_id: str
    client_name: str = ""
    client_secret_hash: str
    allowed_scopes: list[str] = Field(default_factory=list)
    agent_id: str | None = None


class EdgePolicy(BaseModel):
    """Top-level wrapper returned by ``GET /api/v1/edge/policy/current``.

    Mirrors aurora-gateway's ``EdgePolicyReadSerializer``.
    """

    id: str
    tenant_id: str
    name: str
    version: str
    bundle: Policy
    is_active: bool
    created_at: datetime
    authorized_clients: list[AuthorizedClient] = Field(default_factory=list)
