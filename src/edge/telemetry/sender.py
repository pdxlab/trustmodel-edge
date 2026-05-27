"""Background worker that drains the telemetry queue outbound.

Loop:

1. Peek a batch (up to ``batch_size`` rows).
2. If empty, sleep ``flush_interval_seconds`` and try again.
3. Otherwise POST the batch to ``${EDGE_CONTROL_PLANE_URL}/api/v1/edge/telemetry``
   with a cert-JWT signed by the enrollment key.
4. On 2xx → ``store.ack(ids)``.
5. On 4xx → log error, ack anyway. Retrying a malformed payload is
   pointless; we'd just block newer events behind a poison pill.
6. On 5xx / transport → ``store.mark_retry(ids, error=...)`` and
   sleep with exponential backoff so we don't hammer a flailing
   gateway.

Drain on shutdown: ``flush_now`` is called from the lifespan
``finally`` block, runs synchronously up to a deadline so as many
buffered events as possible make it out before the pod exits.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import httpx
import zstandard as zstd

from edge.policy.jwt import mint_cert_jwt
from edge.telemetry.store import TelemetryStore

logger = logging.getLogger(__name__)

_PATH = "/api/v1/edge/telemetry/"
_MAX_BACKOFF_SECONDS = 60.0

# Single shared compressor — zstd compressors are cheap to construct but
# reusing one lets the dictionary warm up across batches. Level 3 is the
# default; gives ~3x reduction on JSON audit batches at sub-ms cost.
_ZSTD_COMPRESSOR = zstd.ZstdCompressor(level=3)


class TelemetrySender:
    """Coroutine wrapper around the drain loop. One instance per process."""

    def __init__(
        self,
        store: TelemetryStore,
        *,
        control_plane_url: str,
        state_dir: Path,
        batch_size: int,
        flush_interval_seconds: float,
        request_timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        jwt_minter: Any = mint_cert_jwt,
    ) -> None:
        self._store = store
        self._url = control_plane_url.rstrip("/") + _PATH
        self._state_dir = state_dir
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._timeout = request_timeout_seconds
        self._transport = transport
        self._mint = jwt_minter
        self._backoff = self._flush_interval

    async def run_forever(self) -> None:
        """Drain loop. Cancelled by lifespan on shutdown."""
        while True:
            try:
                sent = await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - never let one bad row kill the worker
                logger.exception("edge.telemetry.tick_failed")
                sent = 0

            # If we sent something, reset backoff and loop hot. Otherwise
            # sleep — failed POST goes through backoff path inside _tick.
            if sent > 0:
                self._backoff = self._flush_interval
                continue
            await asyncio.sleep(self._backoff)

    async def _tick(self) -> int:
        batch = self._store.dequeue_batch(limit=self._batch_size)
        if not batch:
            return 0

        ids = [e.id for e in batch]
        body = {"events": [e.payload for e in batch]}

        try:
            token = self._mint(state_dir=self._state_dir)
        except Exception as exc:  # noqa: BLE001
            # Enrollment cert missing — keep the rows queued, wait.
            self._store.mark_retry(ids, error=f"jwt_mint: {exc}")
            self._bump_backoff()
            return 0

        # zstd-compress the JSON body. Wire format: raw zstd frame, with
        # ``Content-Encoding: zstd`` so the gateway knows to decompress.
        # Gateway will fall through to plain JSON if the header is absent,
        # so we can roll this back single-sided if needed.
        raw_json = json.dumps(body, separators=(",", ":"), default=str).encode("utf-8")
        compressed = _ZSTD_COMPRESSOR.compress(raw_json)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Content-Encoding": "zstd",
        }
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout
            ) as client:
                response = await client.post(self._url, content=compressed, headers=headers)
        except httpx.HTTPError as exc:
            self._store.mark_retry(ids, error=f"transport: {exc}")
            self._bump_backoff()
            return 0

        if response.is_success:
            self._store.ack(ids)
            logger.info("edge.telemetry.sent", extra={"count": len(ids)})
            return len(ids)

        # 400 + 422 specifically: gateway thinks the payload is malformed.
        # Re-sending won't fix that. Ack so a poison row doesn't block the
        # queue; log loudly so an operator notices.
        if response.status_code in (400, 422):
            self._store.ack(ids)
            logger.error(
                "edge.telemetry.rejected_bad_payload",
                extra={
                    "status": response.status_code,
                    "count": len(ids),
                    "body": response.text[:300],
                },
            )
            return len(ids)

        # Everything else (404, 401, 5xx, etc.) = transient gateway issue.
        # Retry later with backoff.
        self._store.mark_retry(
            ids,
            error=f"{response.status_code}: {response.text[:200]}",
        )
        self._bump_backoff()
        return 0

    def _bump_backoff(self) -> None:
        self._backoff = min(self._backoff * 2, _MAX_BACKOFF_SECONDS)


async def flush_now(sender: TelemetrySender, *, deadline_seconds: float) -> int:
    """Drain everything queue-side in one synchronous run.

    Called by the lifespan ``finally`` and by the
    ``POST /v1/telemetry-flush`` route. Loops over ``_tick`` until the
    queue is empty or the deadline passes.
    """
    loop = asyncio.get_event_loop()
    end_at = loop.time() + deadline_seconds
    total = 0
    while loop.time() < end_at:
        sent = await sender._tick()  # noqa: SLF001 — same module
        if sent == 0:
            break
        total += sent
    return total
