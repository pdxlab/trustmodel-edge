"""Tests for the SQLite-backed telemetry queue."""

from __future__ import annotations

from pathlib import Path

from edge.telemetry.store import TelemetryStore


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
