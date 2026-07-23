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


# Marker substrings SQLite uses when it can't open a file it once wrote.
# Seen in the wild on GCSFuse + WAL when concurrent writes race the -shm
# index (XSpan 2026-07-22): the primary DB file itself becomes unreadable
# and every subsequent open raises DatabaseError before we can execute
# the DDL. We rotate the file aside on this signature and try once more
# with a fresh DB.
_CORRUPTION_MARKERS = (
    "database disk image is malformed",
    "file is not a database",
    "database is locked",  # can indicate a broken -wal handoff on FUSE
)

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
        self._open_or_recreate()

    def _open_or_recreate(self) -> None:
        """Run the DDL once. If SQLite reports the file as corrupt, rotate
        it aside and retry with a fresh DB.

        The queue is a durable buffer, not a source of truth — losing
        the on-disk backlog to recover from corruption is acceptable and
        much better than crashing the whole sidecar (XSpan RCA
        2026-07-22: corrupt telemetry.db blocked every new Cloud Run
        instance across the fleet).
        """
        try:
            with self._conn() as conn:
                conn.executescript(_DDL)
            return
        except sqlite3.DatabaseError as exc:
            msg = str(exc).lower()
            if not any(m in msg for m in _CORRUPTION_MARKERS):
                raise
            self._rotate_corrupt_files(reason=str(exc))

        # One retry against the freshly-empty path. If this fails we let
        # the exception propagate; get_store() catches it and installs a
        # NoopTelemetryStore instead, keeping the sidecar alive.
        with self._conn() as conn:
            conn.executescript(_DDL)

    def _rotate_corrupt_files(self, *, reason: str) -> None:
        """Move telemetry.db + telemetry.db-wal + telemetry.db-shm aside
        so a subsequent open builds a fresh DB. Kept on disk (renamed
        with a timestamp suffix) for post-mortem, not deleted."""
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        for suffix in ("", "-wal", "-shm"):
            src = self._path.with_name(self._path.name + suffix)
            if not src.exists():
                continue
            dst = src.with_name(f"{src.name}.corrupt-{stamp}")
            try:
                src.rename(dst)
                logger.warning(
                    "edge.telemetry.rotated_corrupt_db",
                    extra={"src": str(src), "dst": str(dst), "reason": reason},
                )
            except OSError as rot_exc:
                # If we can't rename (permissions, FS quirks), try to
                # unlink so the next open doesn't hit the same corruption.
                # Preserve the rename attempt as context in the log.
                try:
                    src.unlink()
                    logger.warning(
                        "edge.telemetry.deleted_corrupt_db",
                        extra={"src": str(src), "rename_error": str(rot_exc)},
                    )
                except OSError:
                    logger.exception(
                        "edge.telemetry.corrupt_db_cleanup_failed",
                        extra={"src": str(src)},
                    )

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
        with self._lock, self._conn() as conn:
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


class NoopTelemetryStore:
    """Drop-in stand-in used when the real store can't be constructed.

    Governance and enforcement (``/decide``) do NOT depend on telemetry
    landing in the queue. When the on-disk store fails (corrupt DB,
    unwritable state dir, FS quirk), the sidecar must keep serving
    requests — we just lose audit events for the affected instance
    until the deployer redeploys onto healthier storage or the
    long-term event pipeline (TRUS-1073) is available.

    Every method here matches the public surface of ``TelemetryStore``
    and returns benign values so callers (``decide()``, ``TelemetrySender``)
    can't tell the difference at runtime.
    """

    def __init__(self) -> None:
        self._dropped = 0

    def count(self) -> int:
        return 0

    @property
    def dropped_count(self) -> int:
        return self._dropped

    def enqueue(self, payload: dict[str, Any]) -> bool:  # noqa: ARG002
        # Silently drop, but count it so operators can see we're in
        # degraded mode via the /metrics endpoint.
        self._dropped += 1
        return True

    def dequeue_batch(self, *, limit: int) -> list[QueuedEvent]:  # noqa: ARG002
        return []

    def ack(self, ids: list[int]) -> None:  # noqa: ARG002
        return None

    def mark_retry(self, ids: list[int], *, error: str) -> None:  # noqa: ARG002
        return None


# Any code that used to import `TelemetryStore` for type hints should
# accept either flavour. New code should prefer `AnyTelemetryStore`.
AnyTelemetryStore = TelemetryStore | NoopTelemetryStore


_store_singleton: AnyTelemetryStore | None = None


def get_store(
    *, state_dir: Path | None = None, max_size: int | None = None
) -> AnyTelemetryStore:
    """Process-wide store. First call must pass ``state_dir`` + ``max_size``.

    Lifespan calls this with the resolved settings; subsequent callers
    (the producer in ``decide()``, the sender worker, tests) get the
    same instance back.

    If the real ``TelemetryStore`` cannot be constructed (corrupt DB
    that can't be recovered, unwritable state dir, disk full), we log
    prominently and install a ``NoopTelemetryStore`` in its place. The
    sidecar continues to serve ``/decide`` — governance/enforcement
    does not depend on telemetry (TRUS-1073, XSpan RCA 2026-07-22).
    """
    global _store_singleton
    if _store_singleton is None:
        if state_dir is None or max_size is None:
            raise RuntimeError(
                "TelemetryStore not initialised. Lifespan must call "
                "get_store(state_dir=..., max_size=...) once at startup."
            )
        try:
            _store_singleton = TelemetryStore(state_dir / _DB_FILENAME, max_size=max_size)
        except Exception:  # noqa: BLE001 - any failure must degrade, not crash
            logger.exception(
                "edge.telemetry.store_init_failed_degrading_to_noop",
                extra={"state_dir": str(state_dir)},
            )
            _store_singleton = NoopTelemetryStore()
    return _store_singleton


def reset_store() -> None:
    """Drop the singleton. Tests use this between cases."""
    global _store_singleton
    _store_singleton = None
