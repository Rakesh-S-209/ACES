"""
tests/test_port_trap_integration.py
====================================
Integration tests for the PortTrap deception daemon.

Tests verified:
  1. PortTrap binds to 0.0.0.0 (not a single adapter).
  2. A TCP connect to 127.0.0.1:<port> is accepted and triggers a PORT_TRAP
     AlertEvent on the EventHub with the correct source_ip and port fields.
  3. The source IP is added to the in-memory PERIMETER_BLACKLIST.
  4. A second TCP connect from the LAN IP also triggers an alert.
  5. The hit is persisted to the SQLite port_trap_hits table.
  6. Zero bytes are transmitted back to the connecting client.

Run with:
    python -m pytest tests/test_port_trap_integration.py -v
"""

from __future__ import annotations

import asyncio
import socket
import sys
import time
from pathlib import Path
from typing import List

import pytest

# Make sure the project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.deception.port_trap import PortTrap
from src.soc_pipeline.event_hub import EventHub
from src.zero_trust.models import AlertEvent, AlertType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Use an unprivileged port so the test never needs admin rights.
# Any port >= 1024 that is unlikely to be in use.
_TEST_PORT = 19389


def _get_primary_lan_ip() -> str:
    """Return the primary LAN IP using the same UDP-connect method as run.py."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


async def _collect_events(
    hub: EventHub,
    count: int,
    timeout: float = 4.0,
) -> List[AlertEvent]:
    """Subscribe to the EventHub and collect up to *count* events."""
    collected: List[AlertEvent] = []

    async def _subscriber():
        async for event in hub.subscribe():
            collected.append(event)
            if len(collected) >= count:
                break

    try:
        await asyncio.wait_for(_subscriber(), timeout=timeout)
    except asyncio.TimeoutError:
        pass  # return whatever was collected
    return collected


async def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bytes:
    """
    Open a TCP connection, read any data sent back, then close.
    Returns the bytes received (should be empty for PortTrap).
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=timeout,
    )
    # Give PortTrap a moment to close, then try to read
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=0.5)
    except asyncio.TimeoutError:
        data = b""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    except (asyncio.TimeoutError, Exception):
        pass
    return data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPortTrapBinding:
    """Verify that PortTrap binds to 0.0.0.0 (all interfaces)."""

    def test_start_server_binds_all_interfaces(self):
        """
        The asyncio server must bind to 0.0.0.0 so it is reachable on
        both the LAN adapter and the loopback adapter simultaneously.
        """
        # We verify this by reading the source — the host parameter passed
        # to asyncio.start_server inside PortTrap.start_server() must be "0.0.0.0".
        import inspect
        from src.deception.port_trap import PortTrap as PT
        source = inspect.getsource(PT.start_server)
        assert 'host="0.0.0.0"' in source, (
            'PortTrap.start_server() must pass host="0.0.0.0" to asyncio.start_server '
            'to bind all network interfaces.  Found source:\n' + source
        )

    def test_loopback_reachable_after_bind(self):
        """
        After binding to 0.0.0.0, a socket connect to 127.0.0.1:<port>
        must succeed (the port must be reachable on the loopback adapter).
        Confirmed by asyncio integration test below — this test just checks
        socket-level reachability within a short lived server.
        """
        async def _run():
            hub       = EventHub()
            blacklist: set[str] = set()
            trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                            ports=[_TEST_PORT])
            await trap.start_server()
            assert _TEST_PORT in trap.listening_ports, (
                f"Port {_TEST_PORT} did not bind successfully."
            )
            # Verify 127.0.0.1 is reachable on the bound port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            err = s.connect_ex(("127.0.0.1", _TEST_PORT))
            s.close()
            await trap.stop()
            assert err == 0, (
                f"Could not connect to 127.0.0.1:{_TEST_PORT} after binding "
                f"PortTrap to 0.0.0.0 (connect_ex returned {err})"
            )
        asyncio.run(_run())


class TestPortTrapAlertDispatch:
    """Verify that a TCP connect triggers the full alert pipeline."""

    @pytest.mark.asyncio
    async def test_loopback_connect_triggers_alert(self):
        """
        Connecting to 127.0.0.1:<port> must:
          - Publish a PORT_TRAP AlertEvent to the EventHub.
          - Set alert.source_ip to the connecting IP.
          - Set alert.port to the decoy port number.
          - Add the source IP to the in-memory blacklist.
        """
        hub       = EventHub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[_TEST_PORT])
        await trap.start_server()
        assert _TEST_PORT in trap.listening_ports

        # Start collecting events before the connect so we don't miss it
        collect_task = asyncio.create_task(_collect_events(hub, count=1, timeout=5.0))
        await asyncio.sleep(0.05)   # let the subscriber register

        received = await _tcp_connect("127.0.0.1", _TEST_PORT)

        events = await collect_task
        await trap.stop()

        # --- Assertions ---
        assert len(events) >= 1, (
            "Expected at least 1 PORT_TRAP AlertEvent but received none."
        )
        evt = events[0]
        assert evt.alert_type == AlertType.PORT_TRAP, (
            f"Expected alert_type PORT_TRAP, got {evt.alert_type}"
        )
        assert evt.port == _TEST_PORT, (
            f"Expected port={_TEST_PORT}, got port={evt.port}"
        )
        assert evt.source_ip is not None and evt.source_ip != "", (
            "AlertEvent.source_ip must not be empty"
        )
        assert evt.source_ip in blacklist, (
            f"Source IP {evt.source_ip!r} was not added to the perimeter blacklist"
        )

    @pytest.mark.asyncio
    async def test_zero_bytes_transmitted(self):
        """
        PortTrap must transmit exactly zero bytes back to the client
        (zero-byte policy -- prevents service fingerprinting).
        """
        hub       = EventHub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[_TEST_PORT])
        await trap.start_server()

        received = await _tcp_connect("127.0.0.1", _TEST_PORT)
        await trap.stop()

        assert received == b"", (
            f"PortTrap must send zero bytes.  Got {len(received)} byte(s): {received!r}"
        )

    @pytest.mark.asyncio
    async def test_lan_ip_connect_triggers_alert(self):
        """
        Connecting via the primary LAN IP must also trigger a PORT_TRAP alert
        (confirms the server is genuinely bound to 0.0.0.0, not just loopback).
        """
        lan_ip = _get_primary_lan_ip()
        if lan_ip == "127.0.0.1":
            pytest.skip("No LAN interface detected; skipping LAN IP test.")

        hub       = EventHub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[_TEST_PORT])
        await trap.start_server()
        assert _TEST_PORT in trap.listening_ports

        collect_task = asyncio.create_task(_collect_events(hub, count=1, timeout=5.0))
        await asyncio.sleep(0.05)

        try:
            await _tcp_connect(lan_ip, _TEST_PORT)
        except (ConnectionRefusedError, OSError) as exc:
            await trap.stop()
            pytest.fail(
                f"Could not connect to LAN IP {lan_ip}:{_TEST_PORT}: {exc}\n"
                "PortTrap may not be bound to 0.0.0.0."
            )

        events = await collect_task
        await trap.stop()

        assert len(events) >= 1, (
            f"Expected a PORT_TRAP alert from LAN IP {lan_ip} but received none."
        )
        assert events[0].alert_type == AlertType.PORT_TRAP
        assert events[0].port == _TEST_PORT

    @pytest.mark.asyncio
    async def test_alert_timestamp_is_recent(self):
        """
        The AlertEvent timestamp_ms must be within 5 seconds of the connect time.
        """
        hub       = EventHub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[_TEST_PORT])
        await trap.start_server()

        collect_task = asyncio.create_task(_collect_events(hub, count=1, timeout=5.0))
        await asyncio.sleep(0.05)
        t_before = time.time() * 1000
        await _tcp_connect("127.0.0.1", _TEST_PORT)
        t_after = time.time() * 1000

        events = await collect_task
        await trap.stop()

        assert events, "No alert received"
        ts = events[0].timestamp_ms
        assert t_before - 500 <= ts <= t_after + 500, (
            f"Alert timestamp {ts:.0f} ms is not within 500 ms of connect time "
            f"[{t_before:.0f}, {t_after:.0f}]"
        )


class TestPortTrapDbPersistence:
    """Verify that hits are persisted to the SQLite port_trap_hits table."""

    @pytest.mark.asyncio
    async def test_hit_persisted_to_sqlite(self, tmp_path):
        """
        After a TCP connect PortTrap must call log_port_trap_hit() which
        inserts a row into port_trap_hits.  We use a fresh in-memory DB
        for isolation.
        """
        from src.auth import db as auth_db

        db_file = tmp_path / "test_aces.db"
        auth_db.init_db(db_file)

        hub       = EventHub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[_TEST_PORT])
        await trap.start_server()

        collect_task = asyncio.create_task(_collect_events(hub, count=1, timeout=5.0))
        await asyncio.sleep(0.05)
        await _tcp_connect("127.0.0.1", _TEST_PORT)
        await collect_task
        # Small wait for the async DB write
        await asyncio.sleep(0.2)
        await trap.stop()

        # Query the port_trap_hits table
        conn = auth_db.get_conn()
        rows = conn.execute(
            "SELECT ip, port FROM port_trap_hits WHERE port = ?",
            (_TEST_PORT,),
        ).fetchall()
        assert len(rows) >= 1, (
            "Expected at least one row in port_trap_hits after TCP connect."
        )
        assert rows[0][1] == _TEST_PORT, (
            f"Expected port={_TEST_PORT} in port_trap_hits, got {rows[0][1]}"
        )


class TestPortTrapMultiPort:
    """Verify that all three default decoy ports are bound when using defaults."""

    @pytest.mark.asyncio
    async def test_multiple_custom_ports_all_bind(self):
        """
        When ports=[p1, p2] is passed, both ports must appear in
        trap.listening_ports and both must trigger independent alerts.
        """
        PORT_A = _TEST_PORT
        PORT_B = _TEST_PORT + 1

        hub       = EventHub()
        blacklist: set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[PORT_A, PORT_B])
        await trap.start_server()

        assert PORT_A in trap.listening_ports, f"Port {PORT_A} did not bind"
        assert PORT_B in trap.listening_ports, f"Port {PORT_B} did not bind"

        collect_task = asyncio.create_task(_collect_events(hub, count=2, timeout=6.0))
        await asyncio.sleep(0.05)
        await _tcp_connect("127.0.0.1", PORT_A)
        await _tcp_connect("127.0.0.1", PORT_B)

        events = await collect_task
        await trap.stop()

        assert len(events) >= 2, (
            f"Expected 2 PORT_TRAP alerts (one per port), got {len(events)}"
        )
        ports_seen = {e.port for e in events}
        assert PORT_A in ports_seen, f"No alert for port {PORT_A}"
        assert PORT_B in ports_seen, f"No alert for port {PORT_B}"


# ---------------------------------------------------------------------------
# Standalone runner (python tests/test_port_trap_integration.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=str(Path(__file__).parent.parent),
    )
    sys.exit(result.returncode)
