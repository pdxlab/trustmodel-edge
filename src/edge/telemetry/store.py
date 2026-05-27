"""SQLite-backed durable queue for outbound audit events.

One file: ``${EDGE_STATE_DIR}/telemetry.db``. Single writer (Edge is a
single-replica deployment per the architecture doc), so SQLite's
file-locking gives us ordering for free without extra coordination.

Schema is one table:

    events(
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      occurred_at  TEXT     NOT NULL,         -- ISO 8601, for ordering + ttl
      payload      TEXT     NOT NULL,         -- JSON, full AuditEvent
      retries      INTEGER  NOT NULL DEFAULT 0,
      last_error   TEXT     NOT NULL DEFAULT ''
    )

The sender ``dequeue_batch`` reads up to N rows, ``ack`` deletes them
after a successful POST. On 5xx, ``mark_retry`` bumps the count + records
the last error so a future operator can see why specific rows are stuck.

Back-pressure: ``enqueue`` returns False (and increments a drop counter)
when ``count()`` already exceeds the configured max. ``decide()`` keeps
serving — losing audit beats losing decisions.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    retries     INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_events_id ON events (id);
"""

_DB_FILENAME = "telemetry.db"


@dataclass(frozen=True)
class QueuedEvent:
    id: int
    occurred_at: str
    payload: dict[str, Any]
    retries: int
    last_error: str


class TelemetryStore:
    """Thread-safe SQLite queue. Single instance per process.

    SQLite connections aren't safe across threads by default. We use a
    lock + per-call connection (cheap since the DB is local + WAL).
    """

    def __init__(self, db_path: Path, *, max_size: int) -> None:
        self._path = db_path
        self._max_size = max_size
        self._lock = threading.Lock()
        self._dropped = 0
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_DDL)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._path, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        finally:
            conn.close()

    def count(self) -> int:
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            return int(row[0]) if row else 0

    @property
    def dropped_count(self) -> int:
        return self._dropped

    def enqueue(self, payload: dict[str, Any]) -> bool:
        """Append an event. Returns False if back-pressure dropped it."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
                if row and row[0] >= self._max_size:
                    self._dropped += 1
                    logger.warning(
                        "edge.telemetry.dropped",
                        extra={"queue_size": row[0], "total_dropped": self._dropped},
                    )
                    return False
                conn.execute(
                    "INSERT INTO events (occurred_at, payload) VALUES (?, ?)",
                    (datetime.now(UTC).isoformat(), json.dumps(payload, default=str)),
                )
        return True

    def dequeue_batch(self, *, limit: int) -> list[QueuedEvent]:
        """Peek up to ``limit`` oldest events. Does NOT remove them.

        Removal happens via :meth:`ack` once the sender confirms the
        POST returned 2xx. If the sender crashes between peek and ack,
        the rows replay on next start.
        """
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT id, occurred_at, payload, retries, last_error "
                "FROM events ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            QueuedEvent(
                id=int(r[0]),
                occurred_at=str(r[1]),
                payload=json.loads(r[2]),
                retries=int(r[3]),
                last_error=str(r[4]),
            )
            for r in rows
        ]

    def ack(self, ids: list[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self._lock, self._conn() as conn:
            conn.execute(f"DELETE FROM events WHERE id IN ({placeholders})", ids)

    def mark_retry(self, ids: list[int], *, error: str) -> None:
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self._lock, self._conn() as conn:
            conn.execute(
                f"UPDATE events SET retries = retries + 1, last_error = ? "
                f"WHERE id IN ({placeholders})",
                (error[:500], *ids),
            )


_store_singleton: TelemetryStore | None = None


def get_store(*, state_dir: Path | None = None, max_size: int | None = None) -> TelemetryStore:
    """Process-wide store. First call must pass ``state_dir`` + ``max_size``.

    Lifespan calls this with the resolved settings; subsequent callers
    (the producer in ``decide()``, the sender worker, tests) get the
    same instance back.
    """
    global _store_singleton
    if _store_singleton is None:
        if state_dir is None or max_size is None:
            raise RuntimeError(
                "TelemetryStore not initialised. Lifespan must call "
                "get_store(state_dir=..., max_size=...) once at startup."
            )
        _store_singleton = TelemetryStore(state_dir / _DB_FILENAME, max_size=max_size)
    return _store_singleton


def reset_store() -> None:
    """Drop the singleton. Tests use this between cases."""
    global _store_singleton
    _store_singleton = None
