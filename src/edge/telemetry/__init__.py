"""Durable outbound telemetry queue (TRUS-989).

Every ``decide()`` call produces an audit event that has to land in
aurora-gateway's compliance stream. The queue lives in the customer's
cluster on the same PVC as the policy cache:

* :mod:`edge.telemetry.store`   — SQLite-backed queue at
  ``${EDGE_STATE_DIR}/telemetry.db``. Producers (``decide()``) enqueue;
  the sender worker dequeues + acks.
* :mod:`edge.telemetry.payload` — builds the audit payload from a
  decision. Shape mirrors aurora-gateway's existing audit ingestor so
  the same downstream pipeline absorbs Edge events.
* :mod:`edge.telemetry.sender`  — background asyncio worker that
  batches (max events or max age, whichever first) and POSTs over
  cert-JWT to ``/api/v1/edge/telemetry``. Exponential backoff on 5xx,
  rows kept on disk until 2xx.

Pod restart replays in-flight rows (SQLite persists). Pod crash
mid-POST leaves rows queued, next start sends them.
"""

from edge.telemetry.payload import AuditEvent, build_audit_event
from edge.telemetry.sender import TelemetrySender, flush_now
from edge.telemetry.store import TelemetryStore, get_store, reset_store

__all__ = [
    "AuditEvent",
    "TelemetrySender",
    "TelemetryStore",
    "build_audit_event",
    "flush_now",
    "get_store",
    "reset_store",
]
