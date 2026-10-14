"""
src/deception/port_trap.py
Multi-port TCP honeyport daemon.

Binds to multiple common deception ports simultaneously (default: 22, 445, 3389)
and accepts every inbound TCP connection.  For each connection the daemon:

  1. Extracts the source IP.
  2. Adds the source IP to PERIMETER_BLACKLIST (in-memory).
  3. Publishes a PORT_TRAP AlertEvent to the EventHub.
  4. Persists the hit to the port_trap_hits SQLite table (survives restarts).
  5. Transmits zero bytes.
  6. Closes the connection within 100 ms.

Design constraints (Requirements 7.x):
- Uses ``asyncio.start_server`` within the running asyncio event loop.
- Each connection is handled as an independent ``asyncio.create_task`` so
  a slow or stalled connection never blocks subsequent detections.
- Transmits zero bytes -- no protocol data is ever sent to the attacker,
  preventing fingerprinting of the deception infrastructure.
- On ``OSError`` at bind time (port already in use / restricted privileges),
  logs a startup warning for that port and continues with the remaining ports.

Multi-port operation:
  A single PortTrap instance manages all configured decoy ports.  Each port
  gets its own ``asyncio.AbstractServer`` stored in ``self._servers``.
  ``stop()`` closes all servers cleanly.

  Default deception ports:
    22   -- SSH decoy
    445  -- SMB / Windows File Sharing decoy
    3389 -- RDP decoy (original single-port behaviour)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set

from src.soc_pipeline.event_hub import EventHub
from src.zero_trust.models import AlertEvent, AlertType

logger = logging.getLogger(__name__)

# How long to wait for writer.wait_closed() before giving up (ms → seconds)
_CLOSE_TIMEOUT_S: float = 0.100  # 100 ms (Requirement 7.4)

# Default decoy ports -- covers the most common Nmap/reconnaissance targets.
# Each entry is (port, decoy_service_description).
DEFAULT_DECOY_PORTS: List[tuple[int, str]] = [
    (22,   "SSH (Decoy)"),
    (445,  "SMB (Windows File Sharing Decoy)"),
    (3389, "Remote Desktop / RDP (Decoy)"),
]


class PortTrap:
    """
    Multi-port async TCP honeyport server.

    Binds to every port in ``ports`` (default: 22, 445, 3389) and accepts
    every inbound TCP connection.  For each connection it:

    1. Extracts the source IP.
    2. Adds the source IP to ``perimeter_blacklist``.
    3. Publishes a ``PORT_TRAP`` AlertEvent to the EventHub.
    4. Persists the hit to SQLite via ``auth.db.log_port_trap_hit()``.
    5. Closes the connection, sending zero bytes.

    Parameters
    ----------
    event_hub : EventHub
        Singleton event bus used to publish PORT_TRAP alerts.
    perimeter_blacklist : set[str]
        In-memory set of blocked IP strings (shared with the Gateway).
    port : int | None
        Legacy single-port argument (kept for backward compatibility).
        If supplied and ``ports`` is not, uses ``[port]``.
    ports : list[int] | None
        Explicit list of TCP ports to bind.  Overrides ``port`` when supplied.
        Defaults to ``[22, 445, 3389]``.
    """

    def __init__(
        self,
        event_hub: EventHub,
        perimeter_blacklist: Set[str],
        port: int = 3389,
        ports: Optional[List[int]] = None,
    ) -> None:
        self._event_hub = event_hub
        self._blacklist = perimeter_blacklist

        # Build the effective port list
        if ports is not None:
            self._ports: List[int] = list(ports)
        else:
            # Legacy single-port path: if caller only passed port=3389 keep
            # backward compat but expand to full default set.
            if port == 3389 and ports is None:
                self._ports = [p for p, _ in DEFAULT_DECOY_PORTS]
            else:
                self._ports = [port]

        # Map port → asyncio server (populated by start_server)
        self._servers: Dict[int, asyncio.AbstractServer] = {}

        # Track which ports are actually listening (for status reporting)
        self.listening_ports: List[int] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def start_server(self) -> None:
        """
        Bind TCP servers on all configured decoy ports.

        Ports that cannot be bound (OS error, privilege, already in use) are
        skipped with a warning.  At least one successful bind is logged at
        INFO level; if no ports could be bound a single warning is emitted.
        """
        bound: List[int] = []
        for decoy_port in self._ports:
            try:
                server = await asyncio.start_server(
                    self._make_dispatcher(decoy_port),
                    host="0.0.0.0",
                    port=decoy_port,
                )
                self._servers[decoy_port] = server
                addrs = ", ".join(
                    str(sock.getsockname()) for sock in server.sockets
                )
                logger.info(
                    "PortTrap: listening on %s (port %d)", addrs, decoy_port
                )
                bound.append(decoy_port)
            except OSError as exc:
                # WinError 10013 = "An attempt was made to access a socket in
                # a way forbidden by its access permissions" -- Windows blocks
                # port 445 (SMB) because the OS itself owns that port via the
                # Server service.  WinError 10048 = address already in use.
                # Log a friendly diagnostic and skip; the other ports remain
                # active so the honeyport system keeps working.
                _winerr = getattr(exc, "winerror", None)
                if _winerr in (10013, 10048):
                    _hint = (
                        "Windows firewall / OS service conflict. "
                        "For port 445 disable the 'Server' service "
                        "(services.msc) or run as Administrator."
                    ) if decoy_port == 445 else (
                        "Port may already be in use or requires elevated privileges."
                    )
                    logger.warning(
                        "PortTrap: cannot bind port %d [WinError %d] -- %s  "
                        "Skipping; other ports remain active.",
                        decoy_port, _winerr, _hint,
                    )
                else:
                    logger.warning(
                        "PortTrap: could not bind port %d -- %s. "
                        "Skipping this port; other ports remain active.",
                        decoy_port,
                        exc,
                    )

        self.listening_ports = bound

        if not bound:
            logger.warning(
                "PortTrap: no decoy ports could be bound. "
                "Port trap disabled; all other subsystems remain active."
            )
        else:
            logger.info(
                "PortTrap: %d decoy port(s) active: %s",
                len(bound),
                bound,
            )

    async def stop(self) -> None:
        """Close all server sockets cleanly."""
        for p, server in list(self._servers.items()):
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
            logger.info("PortTrap: port %d server closed.", p)
        self._servers.clear()
        self.listening_ports = []

    # ------------------------------------------------------------------
    # Internal dispatcher factory -- one dispatcher per port
    # ------------------------------------------------------------------

    def _make_dispatcher(self, decoy_port: int):
        """Return an asyncio server callback bound to a specific decoy port."""
        def _dispatch_connection(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            asyncio.create_task(
                self.handle_connection(reader, writer, decoy_port)
            )
        return _dispatch_connection

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,   # noqa: ARG002 -- never read
        writer: asyncio.StreamWriter,
        port: int = 3389,
    ) -> None:
        """
        Handle a single inbound TCP connection on a decoy port.

        Steps:
        1. Extract source IP from peername.
        2. Add source IP to PERIMETER_BLACKLIST.
        3. Publish PORT_TRAP AlertEvent to EventHub.
        4. Persist hit to SQLite (log_port_trap_hit).
        5. Transmit zero bytes.
        6. Close connection within 100 ms.

        Parameters
        ----------
        reader     : asyncio.StreamReader  -- never read (zero-byte policy)
        writer     : asyncio.StreamWriter  -- used only for peername + close
        port       : int                   -- which decoy port was hit
        """
        # Step 1: Extract attacker IP
        peername = writer.get_extra_info("peername")
        source_ip: str = peername[0] if peername else "unknown"

        # Step 2: Blacklist the attacker IP immediately (in-memory, O(1))
        self._blacklist.add(source_ip)

        # Step 2b: Persist ban to SQLite RIGHT NOW so the HTTP gateway's
        # auth_db.is_banned() check fires on the very next HTTP request —
        # no race window, no waiting for the async SOAR pipeline.
        # This is the critical path: PortTrap TCP → SQLite ban → HTTP 403.
        try:
            from src.auth import db as _auth_db
            _auth_db.ban_ip(source_ip, reason=f"PORT_TRAP:{port}")
            _auth_db.revoke_sessions_for_ip(source_ip)
        except Exception as exc:
            logger.debug("PortTrap: immediate DB ban failed for %s: %s", source_ip, exc)

        # Step 3: Publish PORT_TRAP alert to EventHub (SOAR will enrich later)
        alert = AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip=source_ip,
            timestamp_ms=time.time() * 1000,
            port=port,
        )
        await self._event_hub.publish(alert)

        logger.warning(
            "PortTrap: connection from %s on port %d -- "
            "BANNED in SQLite + in-memory blacklist + alert published.",
            source_ip,
            port,
        )

        # Step 4: Persist the hit record (separate from the ban above —
        # port_trap_hits tracks the connection count for the SOC dashboard)
        try:
            from src.auth import db as _auth_db
            _auth_db.log_port_trap_hit(ip=source_ip, port=port)
        except Exception as exc:
            logger.debug("PortTrap: DB hit log failed for %s: %s", source_ip, exc)

        # Step 5: Transmit zero bytes (nothing written to writer)
        # Step 6: Close within 100 ms (Requirement 7.4)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=_CLOSE_TIMEOUT_S)
        except asyncio.TimeoutError:
            logger.debug(
                "PortTrap: wait_closed() timed out for %s (expected for some clients).",
                source_ip,
            )
        except Exception as exc:  # pragma: no cover
            logger.debug("PortTrap: close error for %s: %s", source_ip, exc)
