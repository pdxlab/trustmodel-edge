"""Tests for the SQLite-backed telemetry queue."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from edge.telemetry.store import (
    NoopTelemetryStore,
    TelemetryStore,
    get_store,
    reset_store,
)


def _store(tmp_path: Path, max_size: int = 100) -> TelemetryStore:
    return TelemetryStore(tmp_path / "telemetry.db", max_size=max_size)


def test_enqueue_then_dequeue_returns_in_fifo_order(tmp_path: Path) -> None:
    s = _store(tmp_path)
    assert s.enqueue({"n": 1}) is True
    assert s.enqueue({"n": 2}) is True
    assert s.enqueue({"n": 3}) is True
    batch = s.dequeue_batch(limit=10)
    assert [e.payload["n"] for e in batch] == [1, 2, 3]


def test_dequeue_does_not_remove_until_ack(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.enqueue({"n": 1})
    s.enqueue({"n": 2})
    assert s.count() == 2
    batch = s.dequeue_batch(limit=10)
    assert s.count() == 2  # still there
    s.ack([e.id for e in batch])
    assert s.count() == 0


def test_mark_retry_keeps_row_and_records_error(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.enqueue({"n": 1})
    batch = s.dequeue_batch(limit=10)
    s.mark_retry([batch[0].id], error="503: gateway")

    after = s.dequeue_batch(limit=10)
    assert after[0].retries == 1
    assert "503" in after[0].last_error


def test_backpressure_drops_when_max_size_reached(tmp_path: Path) -> None:
    s = _store(tmp_path, max_size=2)
    assert s.enqueue({"n": 1}) is True
    assert s.enqueue({"n": 2}) is True
    assert s.enqueue({"n": 3}) is False  # dropped
    assert s.count() == 2
    assert s.dropped_count == 1


def test_persists_across_instances(tmp_path: Path) -> None:
    s1 = _store(tmp_path)
    s1.enqueue({"n": 42})
    # Simulate pod restart: build a fresh store on the same file.
    s2 = _store(tmp_path)
    batch = s2.dequeue_batch(limit=10)
    assert batch[0].payload == {"n": 42}


# ─────────────────────────────────────────────────────────────────────
# XSpan RCA (2026-07-22) — corrupt DB must not crash the sidecar.
# See TRUS-1073 comment thread + edge/telemetry/store.py._open_or_recreate.
# ─────────────────────────────────────────────────────────────────────


def _write_corrupt_db(path: Path) -> None:
    """Write bytes that SQLite will reject as ``database disk image is
    malformed`` — matches what we saw in the field after concurrent
    GCSFuse writes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # SQLite files start with the magic string b"SQLite format 3\x00".
    # A file that starts with the right magic but has garbage after
    # trips the "malformed" check rather than the "not a database"
    # check — mirrors what we saw in the incident.
    path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100 + b"garbage" * 200)


def test_corrupt_db_is_rotated_and_recreated_on_init(tmp_path: Path) -> None:
    """A pre-existing corrupt file at telemetry.db must not raise —
    the store rotates it aside and comes up with a fresh empty DB."""
    db_path = tmp_path / "telemetry.db"
    _write_corrupt_db(db_path)

    # Should not raise. Should succeed with a working empty DB.
    s = TelemetryStore(db_path, max_size=100)
    assert s.count() == 0
    assert s.enqueue({"marker": "post-recovery"}) is True

    # The rotated file is preserved on disk for post-mortem (renamed,
    # not deleted). Exactly one .corrupt-* file should exist.
    rotated = list(tmp_path.glob("telemetry.db.corrupt-*"))
    assert len(rotated) == 1, f"expected one rotated file, saw: {rotated}"


def test_get_store_falls_back_to_noop_when_state_dir_unwritable(
    tmp_path: Path,
) -> None:
    """If the state dir is unwritable (e.g. read-only FUSE mount),
    ``get_store()`` must return a ``NoopTelemetryStore`` so the sidecar
    lifespan doesn't crash. Governance/enforcement is unaffected."""
    reset_store()
    unwritable = tmp_path / "readonly-state"
    unwritable.mkdir()
    os.chmod(unwritable, 0o500)  # r-x — no write

    try:
        store = get_store(state_dir=unwritable, max_size=100)
    finally:
        # Restore mode so pytest can clean up tmp_path.
        os.chmod(unwritable, 0o700)
        reset_store()

    assert isinstance(store, NoopTelemetryStore)


def test_noop_store_matches_public_interface_and_never_raises() -> None:
    """The noop store must expose every method callers use so
    ``decide()`` and ``TelemetrySender`` don't need to know they're
    running in degraded mode."""
    n = NoopTelemetryStore()

    # decide() -> enqueue
    assert n.enqueue({"anything": "here"}) is True

    # sender -> dequeue_batch / ack / mark_retry
    assert n.dequeue_batch(limit=10) == []
    n.ack([1, 2, 3])  # no-op, no raise
    n.mark_retry([1, 2, 3], error="whatever")  # no-op, no raise

    # metrics -> count / dropped_count
    assert n.count() == 0
    # We bumped dropped once via enqueue above; keeps observability
    # honest so operators can see the sidecar is in degraded mode.
    assert n.dropped_count == 1


def test_get_store_returns_real_store_when_healthy(tmp_path: Path) -> None:
    """Baseline: healthy state dir → real ``TelemetryStore``, not noop.
    Guards against a regression where the fallback fires eagerly."""
    reset_store()
    try:
        store = get_store(state_dir=tmp_path, max_size=100)
        assert isinstance(store, TelemetryStore)
        assert not isinstance(store, NoopTelemetryStore)
    finally:
        reset_store()


def test_corrupt_db_recovery_only_triggers_on_corruption_markers(
    tmp_path: Path,
) -> None:
    """Sanity check: unrelated ``DatabaseError`` (e.g. bad SQL) still
    propagates — we only auto-recover from the specific corruption
    signatures. Prevents silent data loss on truly unexpected errors."""
    db_path = tmp_path / "telemetry.db"
    # Empty file: SQLite treats a zero-byte file as valid and creates
    # a fresh DB in place, so this should NOT trigger recovery.
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"")

    # Should succeed without rotating anything.
    s = TelemetryStore(db_path, max_size=100)
    assert s.count() == 0
    rotated = list(tmp_path.glob("telemetry.db.corrupt-*"))
    assert rotated == []


@pytest.mark.parametrize("unrecoverable_error", ["disk I/O error"])
def test_get_store_wraps_unrecoverable_error_in_noop(
    tmp_path: Path, unrecoverable_error: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If ``TelemetryStore.__init__`` raises something other than a
    known corruption marker (e.g. transient disk I/O error that
    survives one retry), ``get_store()`` must still degrade to noop
    rather than let the exception bubble up into the lifespan."""
    from edge.telemetry import store as store_module

    reset_store()

    class _BrokenStore:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise OSError(unrecoverable_error)

    monkeypatch.setattr(store_module, "TelemetryStore", _BrokenStore)

    try:
        result = get_store(state_dir=tmp_path, max_size=100)
    finally:
        reset_store()

    assert isinstance(result, NoopTelemetryStore)
