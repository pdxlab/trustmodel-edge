"""Tests for the outbound telemetry sender worker."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import zstandard as zstd

from edge.telemetry.sender import TelemetrySender, flush_now
from edge.telemetry.store import TelemetryStore


def _store(tmp_path: Path) -> TelemetryStore:
    return TelemetryStore(tmp_path / "telemetry.db", max_size=1000)


def _sender(store, handler, tmp_path: Path) -> TelemetrySender:
    return TelemetrySender(
        store,
        control_plane_url="http://aurora.test",
        state_dir=tmp_path,
        batch_size=10,
        flush_interval_seconds=0.01,
        transport=httpx.MockTransport(handler),
        jwt_minter=lambda **_kw: "stub-jwt",
    )


@pytest.mark.asyncio
async def test_tick_sends_batch_and_acks_on_2xx(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue({"event_id": "a"})
    store.enqueue({"event_id": "b"})

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        captured["content_encoding"] = request.headers.get("Content-Encoding")
        captured["body"] = request.content
        return httpx.Response(200, json={"received": 2})

    sender = _sender(store, handler, tmp_path)
    sent = await sender._tick()

    assert sent == 2
    assert store.count() == 0  # acked
    assert captured["url"] == "http://aurora.test/api/v1/edge/telemetry/"
    assert captured["auth"] == "Bearer stub-jwt"
    # Wire format: zstd-compressed JSON. Decompress + parse to verify
    # the actual events made it through.
    assert captured["content_encoding"] == "zstd"
    decompressed = zstd.ZstdDecompressor().decompress(captured["body"])
    parsed = json.loads(decompressed)
    assert {e["event_id"] for e in parsed["events"]} == {"a", "b"}


@pytest.mark.asyncio
async def test_tick_marks_retry_on_5xx_and_keeps_rows(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue({"event_id": "a"})

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    sender = _sender(store, handler, tmp_path)

    sent = await sender._tick()

    assert sent == 0
    assert store.count() == 1
    after = store.dequeue_batch(limit=10)
    assert after[0].retries == 1
    assert "503" in after[0].last_error


@pytest.mark.asyncio
async def test_tick_acks_on_400_to_avoid_poison_pill(tmp_path: Path) -> None:
    """400 means gateway thinks the payload is malformed — retrying won't fix it.
    Ack so one bad row doesn't block the whole queue."""
    store = _store(tmp_path)
    store.enqueue({"event_id": "bad"})

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="malformed")

    sender = _sender(store, handler, tmp_path)

    sent = await sender._tick()
    assert sent == 1
    assert store.count() == 0


@pytest.mark.asyncio
async def test_tick_marks_retry_on_404_to_handle_deploy_skew(tmp_path: Path) -> None:
    """404 means the endpoint doesn't exist yet (gateway deploy hasn't
    caught up). Retry so we don't lose events to a temporary state."""
    store = _store(tmp_path)
    store.enqueue({"event_id": "a"})

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    sender = _sender(store, handler, tmp_path)

    sent = await sender._tick()
    assert sent == 0
    assert store.count() == 1
    after = store.dequeue_batch(limit=10)
    assert after[0].retries == 1
    assert "404" in after[0].last_error


@pytest.mark.asyncio
async def test_tick_marks_retry_on_transport_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue({"event_id": "a"})

    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable")

    sender = _sender(store, boom, tmp_path)
    sent = await sender._tick()

    assert sent == 0
    assert store.count() == 1
    after = store.dequeue_batch(limit=10)
    assert "transport" in after[0].last_error


def _500_handler(_: httpx.Request) -> httpx.Response:
    return httpx.Response(500)


def _200_handler(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"received": 0})


@pytest.mark.asyncio
async def test_tick_no_op_when_queue_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)
    sender = _sender(store, _500_handler, tmp_path)
    assert await sender._tick() == 0


@pytest.mark.asyncio
async def test_flush_now_drains_until_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for i in range(25):
        store.enqueue({"event_id": str(i)})

    sender = _sender(store, _200_handler, tmp_path)

    sent = await flush_now(sender, deadline_seconds=2.0)
    assert sent == 25
    assert store.count() == 0


@pytest.mark.asyncio
async def test_jwt_mint_failure_marks_retry_not_crash(tmp_path: Path) -> None:
    """If the enrollment key disappears, the sender must not crash —
    it should mark rows for retry and back off."""
    store = _store(tmp_path)
    store.enqueue({"event_id": "a"})

    def jwt_boom(**_kw):
        raise RuntimeError("no key on disk")

    sender = TelemetrySender(
        store,
        control_plane_url="http://aurora.test",
        state_dir=tmp_path,
        batch_size=10,
        flush_interval_seconds=0.01,
        transport=httpx.MockTransport(lambda _: httpx.Response(200)),
        jwt_minter=jwt_boom,
    )
    sent = await sender._tick()
    assert sent == 0
    assert store.count() == 1
    after = store.dequeue_batch(limit=10)
    assert "jwt_mint" in after[0].last_error
