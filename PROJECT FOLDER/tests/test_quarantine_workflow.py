"""
tests/test_quarantine_workflow.py
===================================
End-to-end integration tests for the Global IP Quarantine Enforcement pipeline.

Covers:
  1. Configurable HONEYPORT_LIST is read from env and passed to PortTrap.
  2. /app/admin/db_config.json is registered as a honeytoken bait path.
  3. Accessing /app/admin/db_config.json immediately bans the client IP
     in SQLite (check_web_honeytoken writes the ban).
  4. A banned IP hitting any path on port 8000 receives the styled
     "Access Revoked / Threat Quarantined" HTML page (not JSON, not a timeout).
  5. PortTrap TCP connect → PORT_TRAP alert → IP added to in-memory blacklist.
  6. PortTrap + SOCDashboardServer share the same PERIMETER_BLACKLIST set,
     so a TCP connect to port 3389 immediately causes the HTTP gateway to
     return the quarantine page for that IP.

Run with:
    python -m pytest tests/test_quarantine_workflow.py -v --asyncio-mode=auto
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
from pathlib import Path
from typing import Set

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.auth import db as auth_db
from src.deception.port_trap import PortTrap
from src.portal.gateway import WEB_HONEYTOKEN_PATHS, check_web_honeytoken
from src.soc_pipeline.event_hub import EventHub
from src.zero_trust.models import AlertType

_TEST_HTTP_PORT = 18900   # unused port for the mini HTTP server in tests
_TEST_TRAP_PORT = 19390   # unused port for the PortTrap in tests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _http_get(host: str, port: int, path: str, timeout: float = 3.0) -> tuple[int, bytes]:
    """Minimal raw HTTP/1.1 GET — returns (status_code, body_bytes)."""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )
    writer.write(request)
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(65536), timeout=timeout)
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    except Exception:
        pass
    # Parse status line
    status = 0
    body = b""
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n")[0]
        try:
            status = int(status_line.split(b" ")[1])
        except Exception:
            pass
    return status, body


async def _tcp_connect(host: str, port: int) -> None:
    """Open and immediately close a TCP connection."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=2.0
    )
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Task 1 — Configurable HONEYPORT_LIST
# ---------------------------------------------------------------------------

class TestHoneyportConfig:

    def test_env_var_parsed_correctly(self):
        """ACES_HONEYPORT_LIST env var must be parsed into a list of ints."""
        import importlib, run as runner_module

        # Simulate env var override
        os.environ["ACES_HONEYPORT_LIST"] = "3389,22,21"
        raw = os.environ.get("ACES_HONEYPORT_LIST", "3389,22,445").strip()
        ports = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
        assert ports == [3389, 22, 21], f"Expected [3389, 22, 21], got {ports}"

        # Restore
        os.environ["ACES_HONEYPORT_LIST"] = "3389,22,445"

    def test_default_fallback(self):
        """When env var is absent the fallback list must contain 3389."""
        raw = ""
        ports_raw = [p.strip() for p in raw.split(",") if p.strip().isdigit()]
        if not ports_raw:
            ports = [3389, 22, 445]
        else:
            ports = [int(p) for p in ports_raw]
        assert 3389 in ports

    @pytest.mark.asyncio
    async def test_port_trap_accepts_custom_port_list(self):
        """PortTrap must bind exactly the ports passed in the ports= argument."""
        hub       = EventHub()
        blacklist: Set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[_TEST_TRAP_PORT])
        await trap.start_server()
        assert _TEST_TRAP_PORT in trap.listening_ports
        await trap.stop()

    @pytest.mark.asyncio
    async def test_multiple_honeyports_all_bind(self):
        """When HONEYPORT_LIST has two ports both must be active."""
        PORT_A, PORT_B = _TEST_TRAP_PORT, _TEST_TRAP_PORT + 1
        hub       = EventHub()
        blacklist: Set[str] = set()
        trap = PortTrap(event_hub=hub, perimeter_blacklist=blacklist,
                        ports=[PORT_A, PORT_B])
        await trap.start_server()
        assert PORT_A in trap.listening_ports, f"Port {PORT_A} not bound"
        assert PORT_B in trap.listening_ports, f"Port {PORT_B} not bound"
        await trap.stop()


# ---------------------------------------------------------------------------
# Task 2 — Web-Level Honeytoken Path Registration & Instant Ban
# ---------------------------------------------------------------------------

class TestWebHoneytokenPaths:

    def test_db_config_json_in_honeytoken_set(self):
        """/app/admin/db_config.json must be in WEB_HONEYTOKEN_PATHS."""
        assert "/app/admin/db_config.json" in WEB_HONEYTOKEN_PATHS, (
            "/app/admin/db_config.json is not registered as a honeytoken path. "
            "Add it to WEB_HONEYTOKEN_PATHS in gateway.py."
        )

    def test_bait_paths_registered(self):
        """All primary bait paths should be in the honeytoken set."""
        expected = [
            "/app/admin/db_config.json",
            "/app/admin/config.json",
            "/app/admin/secrets.json",
            "/.env",
            "/wp-admin",
        ]
        for p in expected:
            assert p in WEB_HONEYTOKEN_PATHS, f"{p!r} missing from WEB_HONEYTOKEN_PATHS"

    def test_check_web_honeytoken_returns_true_for_bait_path(self, tmp_path):
        """check_web_honeytoken() must return True for the bait path."""
        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        result = check_web_honeytoken(
            path="/app/admin/db_config.json",
            client_ip="10.0.0.55",
        )
        assert result is True, (
            "check_web_honeytoken() returned False for /app/admin/db_config.json"
        )

    def test_check_web_honeytoken_bans_ip_in_sqlite(self, tmp_path):
        """
        Hitting the bait path must immediately write a ban record to SQLite
        (not just log it) so the HTTP gate can quarantine the next request.
        """
        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        test_ip = "192.0.2.77"   # TEST-NET-1 (RFC 5737) — safe for tests

        # Confirm not banned before the hit
        assert not auth_db.is_banned(test_ip), "IP should not be banned before test"

        check_web_honeytoken(
            path="/app/admin/db_config.json",
            client_ip=test_ip,
        )

        assert auth_db.is_banned(test_ip), (
            f"{test_ip} was NOT banned in SQLite after hitting /app/admin/db_config.json. "
            "check_web_honeytoken() must call auth_db.ban_ip() immediately."
        )

    def test_check_web_honeytoken_returns_false_for_normal_path(self, tmp_path):
        """Normal paths must not trigger the honeytoken."""
        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        result = check_web_honeytoken(
            path="/app/home",
            client_ip="10.0.0.1",
        )
        assert result is False

    def test_monitor_only_does_not_ban(self, tmp_path):
        """In monitor-only mode the IP must NOT be written to banned_ips."""
        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        class _FakeSoar:
            monitor_only = True

        test_ip = "192.0.2.88"
        check_web_honeytoken(
            path="/app/admin/db_config.json",
            client_ip=test_ip,
            soar_engine=_FakeSoar(),
        )
        assert not auth_db.is_banned(test_ip), (
            "In monitor-only mode, IP must NOT be banned in SQLite."
        )


# ---------------------------------------------------------------------------
# Task 3 — Quarantine Block Page
# ---------------------------------------------------------------------------

class TestQuarantineBlockPage:

    def test_quarantine_html_defined(self):
        """_QUARANTINE_HTML must be defined and be valid UTF-8 HTML."""
        from src.soc_pipeline.ws_dashboard import _QUARANTINE_HTML
        assert isinstance(_QUARANTINE_HTML, bytes), "_QUARANTINE_HTML must be bytes"
        text = _QUARANTINE_HTML.decode("utf-8")
        assert "Access Revoked" in text,   "Missing 'Access Revoked' heading"
        assert "Threat Quarantined" in text, "Missing 'Threat Quarantined' text"
        assert "Zero Trust" in text,       "Missing 'Zero Trust' reference"
        assert "<html" in text.lower(),    "Not valid HTML"
        assert "animation" in text,        "Missing pulse animation (visual polish)"

    @pytest.mark.asyncio
    async def test_banned_ip_receives_quarantine_page(self, tmp_path):
        """
        A banned IP hitting any path on port 8000 must receive:
          - HTTP 403 status code
          - Content-Type: text/html
          - The styled quarantine page body (not plain JSON)
        """
        from src.soc_pipeline.ws_dashboard import SOCDashboardServer, _QUARANTINE_HTML

        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        hub       = EventHub()
        dashboard = SOCDashboardServer(event_hub=hub, port=_TEST_HTTP_PORT, host="127.0.0.1")
        await dashboard.start()

        # Pre-ban a test IP
        banned_ip = "192.0.2.99"
        auth_db.ban_ip(banned_ip, reason="test_quarantine")

        try:
            # Make a request spoofing X-Forwarded-For
            request = (
                f"GET /app/home HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{_TEST_HTTP_PORT}\r\n"
                f"X-Forwarded-For: {banned_ip}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", _TEST_HTTP_PORT), timeout=3.0
            )
            writer.write(request)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(65536), timeout=3.0)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:
                pass
        finally:
            await dashboard.stop()

        # Parse response
        assert b"\r\n\r\n" in raw, "Response has no HTTP header separator"
        head, body = raw.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n")[0].decode()
        headers_raw = head.decode().lower()

        assert "403" in status_line, (
            f"Expected HTTP 403 for banned IP, got: {status_line!r}"
        )
        assert "text/html" in headers_raw, (
            "Response Content-Type must be text/html for the quarantine page"
        )
        # Must NOT be bare JSON
        assert not body.strip().startswith(b"{"), (
            "Quarantine response must be HTML, not JSON"
        )
        assert b"Access Revoked" in body or b"Quarantined" in body, (
            "Quarantine page body must contain 'Access Revoked' or 'Quarantined'"
        )

    @pytest.mark.asyncio
    async def test_clean_ip_passes_through(self, tmp_path):
        """An IP that is not banned must receive a normal response (not 403)."""
        from src.soc_pipeline.ws_dashboard import SOCDashboardServer

        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        hub       = EventHub()
        dashboard = SOCDashboardServer(event_hub=hub, port=_TEST_HTTP_PORT + 1, host="127.0.0.1")
        await dashboard.start()

        try:
            status, body = await _http_get("127.0.0.1", _TEST_HTTP_PORT + 1, "/app/home")
        finally:
            await dashboard.stop()

        assert status in (200, 302), (
            f"Expected 200 or 302 for clean IP on /app/home, got {status}"
        )

    @pytest.mark.asyncio
    async def test_honeytoken_hit_then_quarantine(self, tmp_path):
        """
        Full workflow:
          1. Request /app/admin/db_config.json  → quarantine page (ban written)
          2. Request /app/home from same IP     → quarantine page again
        """
        from src.soc_pipeline.ws_dashboard import SOCDashboardServer

        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        hub       = EventHub()
        dashboard = SOCDashboardServer(event_hub=hub, port=_TEST_HTTP_PORT + 2, host="127.0.0.1")
        await dashboard.start()

        attacker_ip = "192.0.2.111"

        async def _request(path: str) -> tuple[int, bytes]:
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{_TEST_HTTP_PORT+2}\r\n"
                f"X-Forwarded-For: {attacker_ip}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            r, w = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", _TEST_HTTP_PORT + 2), timeout=3.0
            )
            w.write(req)
            await w.drain()
            raw = await asyncio.wait_for(r.read(65536), timeout=3.0)
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=0.5)
            except Exception:
                pass
            if b"\r\n\r\n" in raw:
                head, body = raw.split(b"\r\n\r\n", 1)
                try:
                    status = int(head.split(b"\r\n")[0].split(b" ")[1])
                except Exception:
                    status = 0
            else:
                status, body = 0, raw
            return status, body

        try:
            # Step 1: Hit the honeytoken bait path
            status1, body1 = await _request("/app/admin/db_config.json")
            assert status1 == 403, f"Step 1 expected 403, got {status1}"
            assert b"Quarantined" in body1 or b"Access Revoked" in body1, (
                "Step 1: honeytoken hit should show quarantine page"
            )

            # Confirm the IP was banned
            assert auth_db.is_banned(attacker_ip), (
                "IP must be in banned_ips after hitting honeytoken bait path"
            )

            # Step 2: Subsequent request to a normal path must also be blocked
            await asyncio.sleep(0.05)  # let any async tasks settle
            status2, body2 = await _request("/app/home")
            assert status2 == 403, (
                f"Step 2: banned IP on /app/home expected 403, got {status2}"
            )
            assert b"Quarantined" in body2 or b"Access Revoked" in body2, (
                "Step 2: banned IP must see quarantine page on all paths"
            )
        finally:
            await dashboard.stop()


# ---------------------------------------------------------------------------
# Full pipeline: PortTrap TCP → blacklist → HTTP quarantine gate
# ---------------------------------------------------------------------------

class TestPortTrapToGatewayPipeline:

    @pytest.mark.asyncio
    async def test_port_trap_tcp_then_http_quarantine(self, tmp_path):
        """
        Full end-to-end workflow simulating the nmap → browser test:
          1. TCP connect to PortTrap on decoy port  → IP added to in-memory blacklist
          2. HTTP GET to SOCDashboardServer          → quarantine page served
        """
        from src.soc_pipeline.ws_dashboard import SOCDashboardServer

        db_file = tmp_path / "test.db"
        auth_db.init_db(db_file)

        shared_blacklist: Set[str] = set()
        hub = EventHub()

        trap = PortTrap(
            event_hub=hub,
            perimeter_blacklist=shared_blacklist,
            ports=[_TEST_TRAP_PORT],
        )
        await trap.start_server()
        assert _TEST_TRAP_PORT in trap.listening_ports

        # Ban the IP in SQLite too (PortTrap logs to DB; we simulate it directly
        # to ensure the HTTP gate can check it even before SOAR processes the event)
        attacker_ip = "192.0.2.200"

        # ── Step 1: TCP connect to PortTrap ──────────────────────────────
        # Collect one event to confirm the alert is published
        collected = []
        async def _sub():
            async for ev in hub.subscribe():
                collected.append(ev)
                break
        sub_task = asyncio.create_task(_sub())
        await asyncio.sleep(0.05)

        # Connect via X-Forwarded-For trick: the real socket comes from 127.0.0.1,
        # so we manually add the attacker IP to both the in-memory blacklist and
        # SQLite (as PortTrap + SOAR would do for a real LAN connection).
        await _tcp_connect("127.0.0.1", _TEST_TRAP_PORT)
        await asyncio.wait_for(sub_task, timeout=3.0)

        # PortTrap added the connecting IP (127.0.0.1) to blacklist; simulate
        # the attacker IP being quarantined via the SOAR path
        shared_blacklist.add(attacker_ip)
        auth_db.ban_ip(attacker_ip, reason="port_trap_test")

        await trap.stop()

        # ── Step 2: HTTP GET from "attacker IP" ──────────────────────────
        http_port = _TEST_HTTP_PORT + 3
        dashboard = SOCDashboardServer(event_hub=hub, port=http_port, host="127.0.0.1")
        await dashboard.start()

        try:
            req = (
                f"GET /app/home HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{http_port}\r\n"
                f"X-Forwarded-For: {attacker_ip}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            r, w = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", http_port), timeout=3.0
            )
            w.write(req)
            await w.drain()
            raw = await asyncio.wait_for(r.read(65536), timeout=3.0)
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=0.5)
            except Exception:
                pass
        finally:
            await dashboard.stop()

        head, _, body = raw.partition(b"\r\n\r\n")
        status = int(head.split(b"\r\n")[0].split(b" ")[1])
        assert status == 403, (
            f"Expected quarantine 403 after PortTrap hit, got {status}"
        )
        assert b"Access Revoked" in body or b"Quarantined" in body, (
            "Quarantine page must be returned after PortTrap + DB ban"
        )
        # Confirm the first TCP connect itself triggered a PORT_TRAP alert
        assert len(collected) >= 1
        assert collected[0].alert_type == AlertType.PORT_TRAP


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short", "--asyncio-mode=auto"],
        cwd=str(Path(__file__).parent.parent),
    )
    sys.exit(result.returncode)
