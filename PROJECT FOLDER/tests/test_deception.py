"""
tests/test_deception.py
Unit and property-based tests for the deception daemons.

Covers:
  Property 15: TokenWatcher publishes exactly one alert per valid file event
  Property 16: TokenWatcher ignores directory events
  Property 17: TokenWatcher bridges events thread-safely via call_soon_threadsafe
  Property 18: PortTrap sends zero bytes on every connection
  Property 19: PortTrap publishes exactly one PORT_TRAP alert with correct fields
"""

from __future__ import annotations

import asyncio
import importlib
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import src.soc_pipeline.event_hub as _hub_module
from src.soc_pipeline.event_hub import EventHub
from src.zero_trust.models import AlertEvent, AlertType


# ---------------------------------------------------------------------------
# Helpers — fresh EventHub for test isolation
# ---------------------------------------------------------------------------

def _fresh_hub() -> EventHub:
    importlib.reload(_hub_module)
    from src.soc_pipeline.event_hub import EventHub as FreshHub
    return FreshHub()


def _make_loop() -> asyncio.AbstractEventLoop:
    """Create a fresh event loop (not set as running) for watcher tests."""
    return asyncio.new_event_loop()


# ---------------------------------------------------------------------------
# HoneytokenWatcher tests
# ---------------------------------------------------------------------------

class TestHoneytokenWatcher:
    """Tests for src/deception/token_watcher.py"""

    # ------------------------------------------------------------------
    # Import and construction
    # ------------------------------------------------------------------

    def test_import(self) -> None:
        from src.deception.token_watcher import HoneytokenWatcher  # noqa: F401

    def test_construction_creates_honeytoken_file(self, tmp_path: Path) -> None:
        """Watcher creates db_config.json if it doesn't exist."""
        from src.deception.token_watcher import HoneytokenWatcher

        hub = _fresh_hub()
        loop = _make_loop()
        watch_dir = tmp_path / "honey_tokens"

        watcher = HoneytokenWatcher(
            watch_path=watch_dir, event_hub=hub, loop=loop
        )

        assert (watch_dir / "db_config.json").exists(), (
            "Honeytoken file should be created on construction"
        )
        loop.close()

    def test_honeytoken_file_contains_valid_json(self, tmp_path: Path) -> None:
        import json
        from src.deception.token_watcher import HoneytokenWatcher

        hub = _fresh_hub()
        loop = _make_loop()
        watch_dir = tmp_path / "honey_tokens"
        HoneytokenWatcher(watch_path=watch_dir, event_hub=hub, loop=loop)

        content = (watch_dir / "db_config.json").read_text()
        data = json.loads(content)
        assert isinstance(data, dict)
        loop.close()

    # ------------------------------------------------------------------
    # Property 16: directory events are ignored
    # ------------------------------------------------------------------

    def test_property_16_directory_event_ignored(self, tmp_path: Path) -> None:
        """on_any_event must not publish when event.is_directory is True."""
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()

        published: list[AlertEvent] = []

        # Patch call_soon_threadsafe to capture any calls
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, *a: published.append(a[0]) if a else None)  # type: ignore[method-assign]

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)

        dir_event = MagicMock()
        dir_event.is_directory = True
        dir_event.src_path = str(tmp_path / "honey_tokens")

        handler.on_any_event(dir_event)

        assert len(published) == 0, "Directory event must not produce an alert"
        loop.close()

    @given(
        dirname=st.text(min_size=1, max_size=30, alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_-"
        ))
    )
    @settings(max_examples=50)
    def test_property_16_directory_events_always_ignored(self, dirname: str) -> None:
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()
        calls: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda *a: calls.append(a))  # type: ignore[method-assign]

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)

        dir_event = MagicMock()
        dir_event.is_directory = True
        dir_event.src_path = f"/some/path/{dirname}"

        handler.on_any_event(dir_event)

        assert len(calls) == 0, (
            f"Directory event for '{dirname}' must not produce any alert"
        )
        loop.close()

    # ------------------------------------------------------------------
    # Property 15: file event on honeytoken publishes exactly one alert
    # ------------------------------------------------------------------

    def test_property_15_file_event_produces_one_alert(self, tmp_path: Path) -> None:
        """A valid file event on db_config.json must enqueue exactly one alert."""
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()
        enqueued: list = []

        # Capture what is passed to put_nowait via call_soon_threadsafe
        def capture(fn, *args):
            # fn is put_nowait, args[0] is the alert
            enqueued.append(args[0] if args else fn)

        loop.call_soon_threadsafe = MagicMock(side_effect=capture)  # type: ignore[method-assign]

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)

        file_event = MagicMock()
        file_event.is_directory = False
        file_event.src_path = str(tmp_path / "honey_tokens" / "db_config.json")

        handler.on_any_event(file_event)

        assert len(enqueued) == 1, (
            f"Expected exactly 1 alert, got {len(enqueued)}"
        )
        alert = enqueued[0]
        assert isinstance(alert, AlertEvent)
        assert alert.alert_type is AlertType.HONEYTOKEN_ACCESS
        loop.close()

    def test_alert_affected_path_is_absolute(self, tmp_path: Path) -> None:
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()
        enqueued: list[AlertEvent] = []

        loop.call_soon_threadsafe = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda fn, alert: enqueued.append(alert)
        )

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)

        file_event = MagicMock()
        file_event.is_directory = False
        file_event.src_path = str(tmp_path / "honey_tokens" / "db_config.json")

        handler.on_any_event(file_event)

        assert len(enqueued) == 1
        assert os.path.isabs(enqueued[0].affected_path), (
            "affected_path must be an absolute path"
        )
        loop.close()

    def test_alert_timestamp_is_epoch_ms(self, tmp_path: Path) -> None:
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()
        enqueued: list[AlertEvent] = []
        loop.call_soon_threadsafe = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda fn, alert: enqueued.append(alert)
        )

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)
        before_ms = time.time() * 1000

        file_event = MagicMock()
        file_event.is_directory = False
        file_event.src_path = str(tmp_path / "honey_tokens" / "db_config.json")
        handler.on_any_event(file_event)

        after_ms = time.time() * 1000

        assert len(enqueued) == 1
        ts = enqueued[0].timestamp_ms
        assert before_ms <= ts <= after_ms, (
            f"timestamp_ms {ts} not in [{before_ms}, {after_ms}]"
        )
        loop.close()

    def test_non_target_file_event_ignored(self, tmp_path: Path) -> None:
        """Events on files other than db_config.json must be ignored."""
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda fn, alert: enqueued.append(alert)
        )

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)

        for bad_name in ["other_file.txt", "db_config.json.bak", "readme.md"]:
            file_event = MagicMock()
            file_event.is_directory = False
            file_event.src_path = str(tmp_path / bad_name)
            handler.on_any_event(file_event)

        assert len(enqueued) == 0, (
            "Non-target filenames must not produce alerts"
        )
        loop.close()

    # ------------------------------------------------------------------
    # Property 17: bridge uses call_soon_threadsafe (not direct put)
    # ------------------------------------------------------------------

    def test_property_17_uses_call_soon_threadsafe(self, tmp_path: Path) -> None:
        """Alert must be enqueued via call_soon_threadsafe, not direct queue.put."""
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()

        threadsafe_calls: list = []
        loop.call_soon_threadsafe = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda *a: threadsafe_calls.append(a)
        )

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)

        file_event = MagicMock()
        file_event.is_directory = False
        file_event.src_path = str(tmp_path / "honey_tokens" / "db_config.json")

        handler.on_any_event(file_event)

        assert loop.call_soon_threadsafe.called, (  # type: ignore[union-attr]
            "call_soon_threadsafe must be called for thread-safe bridging"
        )
        assert len(threadsafe_calls) == 1
        loop.close()

    def test_source_ip_is_local(self, tmp_path: Path) -> None:
        from src.deception.token_watcher import _HoneytokenEventHandler

        hub = _fresh_hub()
        loop = asyncio.new_event_loop()
        enqueued: list[AlertEvent] = []
        loop.call_soon_threadsafe = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda fn, alert: enqueued.append(alert)
        )

        handler = _HoneytokenEventHandler(event_hub=hub, loop=loop)
        file_event = MagicMock()
        file_event.is_directory = False
        file_event.src_path = str(tmp_path / "honey_tokens" / "db_config.json")
        handler.on_any_event(file_event)

        assert enqueued[0].source_ip == "local", (
            "Filesystem events carry no network IP — source_ip must be 'local'"
        )
        loop.close()


# ---------------------------------------------------------------------------
# PortTrap tests
# ---------------------------------------------------------------------------

class TestPortTrap:
    """Tests for src/deception/port_trap.py"""

    def test_import(self) -> None:
        from src.deception.port_trap import PortTrap  # noqa: F401

    # ------------------------------------------------------------------
    # Property 18: zero bytes written to client
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_property_18_zero_bytes_written(self) -> None:
        """handle_connection must never call writer.write() or writer.drain()."""
        from src.deception.port_trap import PortTrap

        hub = _fresh_hub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist, port=3389)

        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.get_extra_info = MagicMock(return_value=("203.0.113.1", 54321))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await trap.handle_connection(reader, writer)

        # Assert write() was NEVER called (zero bytes sent)
        writer.write.assert_not_called()  # type: ignore[attr-defined]
        # Assert close was called
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_property_18_writelines_not_called(self) -> None:
        from src.deception.port_trap import PortTrap

        hub = _fresh_hub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist)

        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 12345))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await trap.handle_connection(reader, writer)

        writer.writelines.assert_not_called()  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Property 19: exactly one PORT_TRAP alert published with correct fields
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_property_19_one_alert_published(self) -> None:
        from src.deception.port_trap import PortTrap

        hub = _fresh_hub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist, port=3389)

        published: list[AlertEvent] = []

        async def mock_publish(event: AlertEvent) -> None:
            published.append(event)

        trap._event_hub.publish = mock_publish  # type: ignore[method-assign]

        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.get_extra_info = MagicMock(return_value=("198.51.100.9", 50001))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await trap.handle_connection(reader, writer)

        assert len(published) == 1, f"Expected 1 alert, got {len(published)}"
        alert = published[0]
        assert alert.alert_type is AlertType.PORT_TRAP
        assert alert.source_ip == "198.51.100.9"
        assert alert.port == 3389

    @pytest.mark.asyncio
    async def test_alert_timestamp_set(self) -> None:
        from src.deception.port_trap import PortTrap

        hub = _fresh_hub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist)

        published: list[AlertEvent] = []
        trap._event_hub.publish = AsyncMock(  # type: ignore[method-assign]
            side_effect=lambda e: published.append(e)
        )

        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.get_extra_info = MagicMock(return_value=("1.2.3.4", 9999))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        before = time.time() * 1000
        await trap.handle_connection(reader, writer)
        after = time.time() * 1000

        assert len(published) == 1
        assert before <= published[0].timestamp_ms <= after

    # ------------------------------------------------------------------
    # IP blacklisted after connection
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_source_ip_added_to_blacklist(self) -> None:
        from src.deception.port_trap import PortTrap

        hub = _fresh_hub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist)

        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.get_extra_info = MagicMock(return_value=("203.0.113.42", 55555))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await trap.handle_connection(reader, writer)

        assert "203.0.113.42" in blacklist, (
            "Source IP must be added to PERIMETER_BLACKLIST after connection"
        )

    @pytest.mark.asyncio
    async def test_unknown_peername_handled(self) -> None:
        """When peername is None, source_ip should default to 'unknown'."""
        from src.deception.port_trap import PortTrap

        hub = _fresh_hub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist)

        published: list[AlertEvent] = []
        trap._event_hub.publish = AsyncMock(  # type: ignore[method-assign]
            side_effect=lambda e: published.append(e)
        )

        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.get_extra_info = MagicMock(return_value=None)
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await trap.handle_connection(reader, writer)

        assert len(published) == 1
        assert published[0].source_ip == "unknown"

    # ------------------------------------------------------------------
    # OSError on bind — graceful degradation (Requirement 7.5)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_bind_failure_does_not_raise(self) -> None:
        """start_server() must not propagate OSError — just log and return."""
        from src.deception.port_trap import PortTrap

        hub = _fresh_hub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist, port=3389)

        with patch("asyncio.start_server", side_effect=OSError("address in use")):
            # Must not raise
            await trap.start_server()

        # Server dict should be empty (no ports were successfully bound)
        assert trap._servers == {}

    # ------------------------------------------------------------------
    # Property 18: hypothesis-driven zero-bytes check across IPs
    # ------------------------------------------------------------------

    @given(
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
        src_port=st.integers(min_value=1024, max_value=65535),
    )
    @settings(max_examples=50, deadline=None)
    def test_property_18_zero_bytes_for_any_ip(
        self, ip: str, src_port: int
    ) -> None:
        """For any source IP, PortTrap must never call writer.write()."""
        from src.deception.port_trap import PortTrap

        async def _run() -> None:
            hub = _fresh_hub()
            blacklist: set[str] = set()
            trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist)

            reader = MagicMock(spec=asyncio.StreamReader)
            writer = MagicMock(spec=asyncio.StreamWriter)
            writer.get_extra_info = MagicMock(return_value=(ip, src_port))
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()

            await trap.handle_connection(reader, writer)

            writer.write.assert_not_called()  # type: ignore[attr-defined]

        asyncio.run(_run())
