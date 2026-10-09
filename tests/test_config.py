"""Settings for telemetry privacy (TRUS-2002).

Payload-omit is ON by default, so a fresh install keeps raw args in the pod.
A missing hash key must NOT fail startup — that would break every existing
deployment on upgrade now that payload-omit is the default. Instead the
subject is withheld, which is strictly more private than a pseudonym.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from edge.config import Settings


def _base_kwargs(tmp_path: Path) -> dict:
    return {
        "tenant_id": "test-tenant",
        "pod_id": "test-pod",
        "bootstrap_token_path": tmp_path / "bootstrap-token",
        "state_dir": tmp_path / "state",
        "log_level": "WARNING",
    }


def test_omit_payload_defaults_on(tmp_path: Path) -> None:
    """Fresh install, no telemetry config → raw args stay in the pod."""
    settings = Settings(**_base_kwargs(tmp_path))
    assert settings.telemetry_omit_payload is True
    assert settings.telemetry_subject_hash_key == ""


def test_omit_payload_without_hash_key_starts_and_withholds_subject(
    tmp_path: Path,
) -> None:
    """Upgrade path: an existing deployment that never set a key must still
    start, and must not fall back to sending subject_id in clear text."""
    settings = Settings(**_base_kwargs(tmp_path), telemetry_omit_payload=True)
    assert settings.subject_id_mode == "withheld"


def test_omit_payload_with_hash_key_pseudonymizes_subject(tmp_path: Path) -> None:
    settings = Settings(
        **_base_kwargs(tmp_path),
        telemetry_omit_payload=True,
        telemetry_subject_hash_key="a-real-key",
    )
    assert settings.telemetry_subject_hash_key == "a-real-key"
    assert settings.subject_id_mode == "hashed"


def test_explicit_opt_out_sends_raw(tmp_path: Path) -> None:
    """A tenant that deliberately opts out keeps pre-TRUS-2002 behaviour,
    with or without a key."""
    for key in ("", "a-real-key"):
        settings = Settings(
            **_base_kwargs(tmp_path),
            telemetry_omit_payload=False,
            telemetry_subject_hash_key=key,
        )
        assert settings.subject_id_mode == "raw"


@pytest.mark.parametrize(
    ("env_value", "expected"),
    [("false", False), ("False", False), ("0", False), ("true", True), ("1", True)],
)
def test_omit_payload_env_var_parses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_value: str, expected: bool
) -> None:
    """The Helm chart and Docker users set this as a string env var; an
    explicit "false" must really opt out rather than fall back to the default."""
    monkeypatch.setenv("EDGE_TELEMETRY_OMIT_PAYLOAD", env_value)
    settings = Settings(**_base_kwargs(tmp_path))
    assert settings.telemetry_omit_payload is expected


def test_hash_key_env_var_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDGE_TELEMETRY_SUBJECT_HASH_KEY", "key-from-secret")
    settings = Settings(**_base_kwargs(tmp_path))
    assert settings.subject_id_mode == "hashed"
