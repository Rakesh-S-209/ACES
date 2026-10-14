"""
src/soc_pipeline/event_hub.py
Central asyncio.Queue-backed publish/subscribe event bus.

Design constraints (Requirements 8.x):
- Singleton queue: one module-level asyncio.Queue instance.
- publish() is non-blocking for the calling coroutine.
- subscribe() yields events in strict publication order.
- get_queue() exposes the raw queue for call_soon_threadsafe bridging
  from OS-level background threads (TokenWatcher, etc.).
- Fan-out delivery count is tracked per published event.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, List

from src.zero_trust.models import AlertEvent

# ---------------------------------------------------------------------------
# Module-level singleton queue (Requirement 8.1)
# ---------------------------------------------------------------------------
_QUEUE: asyncio.Queue[AlertEvent] = asyncio.Queue()

# Active subscriber callback lists — each subscriber holds its own sub-queue
# so that fan-out is decoupled per consumer.
_SUBSCRIBERS: List[asyncio.Queue[AlertEvent]] = []

# Running delivery count (incremented by number of subscribers reached)
_delivery_count: int = 0


class EventHub:
    """
    Thread-safe asyncio pub/sub event router.

    All producers (Gateway, TokenWatcher, PortTrap, SOAR) call ``publish()``.
    All consumers (SOCStreamHandler) call ``subscribe()`` to receive events.

    Thread safety
    -------------
    - Async coroutines use ``await publish()`` directly.
    - OS background threads use ``loop.call_soon_threadsafe(hub.get_queue().put_nowait, event)``.
    """

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(self, event: AlertEvent) -> None:
        """
        Enqueue an AlertEvent and fan it out to all active subscribers.

        The method never blocks the calling coroutine regardless of the
        number of active subscribers (Requirement 8.2).

        Parameters
        ----------
        event : AlertEvent
            The alert to broadcast.
        """
        global _delivery_count

        if _SUBSCRIBERS:
            for sub_queue in list(_SUBSCRIBERS):
                await sub_queue.put(event)
            _delivery_count += len(_SUBSCRIBERS)
        else:
            # No subscribers yet — park in the shared queue so nothing is lost
            await _QUEUE.put(event)

    # ------------------------------------------------------------------
    # Subscribe
    # ------------------------------------------------------------------

    async def subscribe(self) -> AsyncIterator[AlertEvent]:
        """
        Async generator that yields AlertEvents in publication order.

        The generator registers a per-subscriber queue on entry and
        deregisters it on exit (normal return or exception).

        Yields
        ------
        AlertEvent
            Events in the exact order they were published (Requirement 8.6).
        """
        sub_queue: asyncio.Queue[AlertEvent] = asyncio.Queue()
        _SUBSCRIBERS.append(sub_queue)
        try:
            while True:
                event = await sub_queue.get()
                yield event
        finally:
            # Deregister cleanly when the consumer disconnects (Requirement 8.4)
            try:
                _SUBSCRIBERS.remove(sub_queue)
            except ValueError:
                pass  # Already removed by concurrent cleanup

    # ------------------------------------------------------------------
    # Thread-safe queue accessor
    # ------------------------------------------------------------------

    def get_queue(self) -> asyncio.Queue[AlertEvent]:
        """
        Return the module-level singleton queue for external thread bridging.

        OS-level threads (e.g., watchdog) should call::

            loop.call_soon_threadsafe(hub.get_queue().put_nowait, alert)

        This ensures thread-safe delivery into the asyncio event loop
        (Requirement 8.5).

        Returns
        -------
        asyncio.Queue[AlertEvent]
        """
        return _QUEUE

    # ------------------------------------------------------------------
    # Diagnostic helpers
    # ------------------------------------------------------------------

    @property
    def delivery_count(self) -> int:
        """Total number of individual subscriber deliveries made."""
        return _delivery_count

    @property
    def subscriber_count(self) -> int:
        """Number of currently active subscriber coroutines."""
        return len(_SUBSCRIBERS)
