"""Settings validation (TRUS-2002).

``telemetry_omit_payload=true`` without a hash key would silently ship
subject_id in clear text — the exact gap TRUS-2002 found. This must fail
at startup (config load), not surface as a runtime data leak.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from edge.config import Settings


def _base_kwargs(tmp_path: Path) -> dict:
    return {
        "tenant_id": "test-tenant",
        "pod_id": "test-pod",
        "bootstrap_token_path": tmp_path / "bootstrap-token",
        "state_dir": tmp_path / "state",
        "log_level": "WARNING",
    }


def test_omit_payload_without_hash_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="telemetry_subject_hash_key"):
        Settings(**_base_kwargs(tmp_path), telemetry_omit_payload=True)


def test_omit_payload_with_hash_key_is_accepted(tmp_path: Path) -> None:
    settings = Settings(
        **_base_kwargs(tmp_path),
        telemetry_omit_payload=True,
        telemetry_subject_hash_key="a-real-key",
    )
    assert settings.telemetry_omit_payload is True
    assert settings.telemetry_subject_hash_key == "a-real-key"


def test_omit_payload_off_does_not_require_hash_key(tmp_path: Path) -> None:
    """Default posture — must not regress pre-TRUS-2002 deployments that
    never set either of these."""
    settings = Settings(**_base_kwargs(tmp_path))
    assert settings.telemetry_omit_payload is False
    assert settings.telemetry_subject_hash_key == ""
