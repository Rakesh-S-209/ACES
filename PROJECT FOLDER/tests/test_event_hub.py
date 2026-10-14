"""
tests/test_event_hub.py
Unit and property-based tests for EventHub.

Covers:
  - Property 20: all active subscribers receive every published event
  - Property 21: events delivered in strict publication order
  - Property 22: remaining subscribers receive events after one disconnects
  - Requirement 8.2: publish() is non-blocking
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from hypothesis import given, settings
from hypothesis import strategies as st

from src.zero_trust.models import AlertEvent, AlertType
# Re-import the module to reset global state before each test module run
import importlib
import src.soc_pipeline.event_hub as _hub_module
from src.soc_pipeline.event_hub import EventHub


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(alert_type: AlertType = AlertType.PORT_TRAP, ip: str = "1.2.3.4") -> AlertEvent:
    return AlertEvent(
        alert_type=alert_type,
        source_ip=ip,
        timestamp_ms=1_700_000_000_000.0,
        port=3389,
    )


def _fresh_hub() -> EventHub:
    """Return a new EventHub instance backed by a fresh module-level queue."""
    # Reset module-level state for test isolation
    importlib.reload(_hub_module)
    from src.soc_pipeline.event_hub import EventHub as FreshEventHub
    return FreshEventHub()


# ---------------------------------------------------------------------------
# Basic publish / subscribe
# ---------------------------------------------------------------------------

class TestPublishSubscribe:
    @pytest.mark.asyncio
    async def test_single_subscriber_receives_event(self) -> None:
        hub = _fresh_hub()
        event = _make_event()
        received: list[AlertEvent] = []

        async def consumer() -> None:
            async for evt in hub.subscribe():
                received.append(evt)
                break  # stop after first event

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)           # yield so consumer registers
        await hub.publish(event)
        await asyncio.wait_for(task, timeout=2.0)

        assert len(received) == 1
        assert received[0].source_ip == event.source_ip

    @pytest.mark.asyncio
    async def test_publish_does_not_block(self) -> None:
        hub = _fresh_hub()
        # No subscribers — should still complete without hanging
        await asyncio.wait_for(
            hub.publish(_make_event()),
            timeout=1.0,
        )

    @pytest.mark.asyncio
    async def test_get_queue_returns_asyncio_queue(self) -> None:
        hub = _fresh_hub()
        q = hub.get_queue()
        assert isinstance(q, asyncio.Queue)


# ---------------------------------------------------------------------------
# Property 20: all active subscribers receive every event
# ---------------------------------------------------------------------------

class TestProperty20:
    @pytest.mark.asyncio
    async def test_all_subscribers_receive_event(self) -> None:
        hub = _fresh_hub()
        n = 4
        received: list[list[AlertEvent]] = [[] for _ in range(n)]

        async def consumer(idx: int) -> None:
            async for evt in hub.subscribe():
                received[idx].append(evt)
                break

        tasks = [asyncio.create_task(consumer(i)) for i in range(n)]
        await asyncio.sleep(0)  # let all consumers register
        await hub.publish(_make_event())
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)

        for i, bucket in enumerate(received):
            assert len(bucket) == 1, f"Subscriber {i} did not receive the event"

    @pytest.mark.asyncio
    async def test_delivery_count_incremented_correctly(self) -> None:
        hub = _fresh_hub()
        n = 3

        async def consumer() -> None:
            async for _ in hub.subscribe():
                break

        tasks = [asyncio.create_task(consumer()) for _ in range(n)]
        await asyncio.sleep(0)
        await hub.publish(_make_event())
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)

        assert hub.delivery_count == n


# ---------------------------------------------------------------------------
# Property 21: events delivered in publication order
# ---------------------------------------------------------------------------

class TestProperty21:
    @pytest.mark.asyncio
    async def test_events_delivered_in_order(self) -> None:
        hub = _fresh_hub()
        n_events = 5
        received: list[str] = []

        async def consumer() -> None:
            count = 0
            async for evt in hub.subscribe():
                received.append(evt.source_ip)
                count += 1
                if count == n_events:
                    break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)

        for i in range(n_events):
            await hub.publish(_make_event(ip=f"10.0.0.{i}"))

        await asyncio.wait_for(task, timeout=3.0)

        assert received == [f"10.0.0.{i}" for i in range(n_events)]

    @pytest.mark.asyncio
    async def test_multiple_subscribers_see_same_order(self) -> None:
        hub = _fresh_hub()
        n_events = 4
        results: list[list[str]] = [[], []]

        async def consumer(idx: int) -> None:
            count = 0
            async for evt in hub.subscribe():
                results[idx].append(evt.source_ip)
                count += 1
                if count == n_events:
                    break

        tasks = [asyncio.create_task(consumer(i)) for i in range(2)]
        await asyncio.sleep(0)

        for i in range(n_events):
            await hub.publish(_make_event(ip=f"192.168.0.{i}"))

        await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)

        assert results[0] == results[1]
        assert results[0] == [f"192.168.0.{i}" for i in range(n_events)]


# ---------------------------------------------------------------------------
# Property 22: remaining subscribers still receive events after one disconnects
# ---------------------------------------------------------------------------

class TestProperty22:
    @pytest.mark.asyncio
    async def test_remaining_subscriber_receives_after_disconnect(self) -> None:
        hub = _fresh_hub()
        survivor_received: list[AlertEvent] = []

        async def doomed_consumer() -> None:
            """Registers then immediately exits the subscribe loop."""
            async for _ in hub.subscribe():
                break  # exit after first event — triggers deregistration

        async def survivor_consumer() -> None:
            count = 0
            async for evt in hub.subscribe():
                survivor_received.append(evt)
                count += 1
                if count == 2:
                    break

        doomed = asyncio.create_task(doomed_consumer())
        survivor = asyncio.create_task(survivor_consumer())
        await asyncio.sleep(0)

        # First event — both consumers receive it; doomed exits
        await hub.publish(_make_event(ip="10.0.1.1"))
        await asyncio.wait_for(doomed, timeout=2.0)
        await asyncio.sleep(0)  # let doomed deregister

        # Second event — only survivor should receive it
        await hub.publish(_make_event(ip="10.0.1.2"))
        await asyncio.wait_for(survivor, timeout=2.0)

        assert len(survivor_received) == 2
        assert survivor_received[0].source_ip == "10.0.1.1"
        assert survivor_received[1].source_ip == "10.0.1.2"

    @pytest.mark.asyncio
    async def test_subscriber_count_decrements_on_disconnect(self) -> None:
        hub = _fresh_hub()

        async def consumer() -> None:
            async for _ in hub.subscribe():
                break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)
        assert hub.subscriber_count == 1

        await hub.publish(_make_event())
        await asyncio.wait_for(task, timeout=2.0)
        await asyncio.sleep(0)

        assert hub.subscriber_count == 0
