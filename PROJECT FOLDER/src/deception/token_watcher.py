"""
src/deception/token_watcher.py
Honeytoken filesystem monitor daemon.

Watches ``data/honey_tokens/db_config.json`` for any filesystem event (create,
modify, access, delete) and bridges a HONEYTOKEN_ACCESS AlertEvent into the
asyncio event loop via ``loop.call_soon_threadsafe``.

Design constraints (Requirements 6.x):
- Runs in a background daemon thread separate from the asyncio event loop.
- Only fires on the target file — directory events are silently ignored.
- Does NOT add any IP to PERIMETER_BLACKLIST (no network IP is available
  for a local filesystem event).
- If the target file does not exist at startup the watcher still monitors the
  parent directory and treats the newly created file as the honeytoken once
  it appears.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from src.soc_pipeline.event_hub import EventHub
from src.zero_trust.models import AlertEvent, AlertType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Target file name (only this basename triggers an alert)
# ---------------------------------------------------------------------------
_TARGET_FILENAME = "db_config.json"

# Decoy credential template written when the file doesn't exist at startup
_DECOY_TEMPLATE: dict = {
    "host": "db-internal.corp.local",
    "port": 5432,
    "database": "operations_db",
    "username": "svc_app_user",
    "password": "S3cur3P@ssw0rd!2024",
    "_note": "Internal service account — do not share",
}


# ---------------------------------------------------------------------------
# Watchdog event handler
# ---------------------------------------------------------------------------

class _HoneytokenEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that filters filesystem events to the honeytoken
    file and bridges matching events into the asyncio event loop.
    """

    def __init__(self, event_hub: EventHub, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._event_hub = event_hub
        self._loop = loop

    # ------------------------------------------------------------------
    # Watchdog callback — called from the watchdog OS thread
    # ------------------------------------------------------------------

    def on_any_event(self, event: FileSystemEvent) -> None:
        """
        Called by watchdog for every filesystem event under the watched path.

        Filtering rules (Requirements 6.5, 6.6):
        1. Skip if the event targets a directory.
        2. Skip if the event's source path does not end with ``db_config.json``.
        3. For all other events: publish a HONEYTOKEN_ACCESS alert via
           ``call_soon_threadsafe`` so the asyncio event loop receives it
           safely from this OS thread.
        """
        # Rule 1: Ignore directory events
        if event.is_directory:
            return

        # Rule 2: Only process events on the honeytoken file
        src_path: str = getattr(event, "src_path", "") or ""
        if not src_path.endswith(_TARGET_FILENAME):
            return

        # Construct the alert (no source IP — filesystem events have none)
        alert = AlertEvent(
            alert_type=AlertType.HONEYTOKEN_ACCESS,
            source_ip="local",
            timestamp_ms=time.time() * 1000,
            affected_path=os.path.abspath(src_path),
        )

        # Thread-safe bridge into the asyncio event loop (Requirement 6.4)
        try:
            self._loop.call_soon_threadsafe(
                self._event_hub.get_queue().put_nowait, alert
            )
        except Exception as exc:  # pragma: no cover
            logger.error(
                "HoneytokenWatcher: failed to enqueue alert: %s", exc, exc_info=True
            )


# ---------------------------------------------------------------------------
# Public watcher class
# ---------------------------------------------------------------------------

class HoneytokenWatcher:
    """
    Honeytoken filesystem monitor daemon.

    Monitors ``data/honey_tokens/`` for any access to ``db_config.json`` and
    publishes a ``HONEYTOKEN_ACCESS`` alert to the EventHub.

    Parameters
    ----------
    watch_path : str | Path
        Parent directory to monitor (should be ``data/honey_tokens/``).
    event_hub : EventHub
        The singleton event bus to publish alerts to.
    loop : asyncio.AbstractEventLoop
        The running asyncio event loop. Used for ``call_soon_threadsafe``.
    """

    def __init__(
        self,
        watch_path: str | Path,
        event_hub: EventHub,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._watch_path = Path(watch_path)
        self._event_hub = event_hub
        self._loop = loop
        self._observer: Optional[Observer] = None
        self._handler = _HoneytokenEventHandler(event_hub=event_hub, loop=loop)

        # Ensure the decoy file exists so intruders can find and read it
        self._ensure_honeytoken_exists()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the watchdog observer as a background daemon thread.

        The observer begins monitoring before the first inbound request is
        accepted (enforced by the startup lifecycle in main.py).
        """
        self._observer = Observer()
        self._observer.schedule(
            self._handler,
            path=str(self._watch_path),
            recursive=False,
        )
        # Mark as daemon so the thread doesn't prevent process exit
        self._observer.daemon = True
        self._observer.start()
        logger.info(
            "HoneytokenWatcher: started monitoring %s for %s",
            self._watch_path,
            _TARGET_FILENAME,
        )

    def stop(self) -> None:
        """
        Stop the watchdog observer and join its thread.

        Called during application shutdown (Requirement 14.6).
        """
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            logger.info("HoneytokenWatcher: stopped.")
            self._observer = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_honeytoken_exists(self) -> None:
        """
        Create the parent directory and honeytoken file if they don't exist.

        The file is pre-populated with a realistic-looking but invalid
        credential template so that intruders are drawn in before detection
        (Requirement 6.8).
        """
        self._watch_path.mkdir(parents=True, exist_ok=True)
        honeytoken_path = self._watch_path / _TARGET_FILENAME
        if not honeytoken_path.exists():
            try:
                with open(honeytoken_path, "w", encoding="utf-8") as fh:
                    json.dump(_DECOY_TEMPLATE, fh, indent=2)
                logger.info(
                    "HoneytokenWatcher: created decoy credential file at %s",
                    honeytoken_path,
                )
            except OSError as exc:  # pragma: no cover
                logger.warning(
                    "HoneytokenWatcher: could not create honeytoken file: %s", exc
                )
