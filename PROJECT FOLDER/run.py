# -*- coding: utf-8 -*-
# run.py -- Project A.C.E.S. Production Runner
"""
Bootstraps the full A.C.E.S. backend.
Task E (TrafficSimulator) is DISABLED -- the system waits for real traffic.

All pages are served as native HTML from src/portal/static/.
No Node.js, npm, or React build step is required.

  Task A  -- HoneytokenWatcher     (watchdog daemon thread)
  Task B  -- SOAREngine            (threat orchestrator)
  Task C  -- PortTrap              (TCP honeypot :3389)
  Task D  -- SOCDashboardServer    (HTTP + WebSocket :8000, LAN-accessible)

  DB      -- SQLite auth/ban store at data/aces_production.db

Access URLs (shown at startup using the primary LAN IP):
  Corporate Portal  http://<PRIMARY_LAN_IP>:8000/app/home
  SOC Dashboard     http://<PRIMARY_LAN_IP>:8000/app/soc-board

The primary LAN IP is auto-detected via the interface that routes to the
default gateway (UDP-connect to 8.8.8.8).  All adapters — including
bridged LAN and host-only — are listed at startup for reference.

Press Ctrl+C to shut down cleanly.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import sys
import time
import webbrowser
from pathlib import Path
from typing import Dict

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aces.runner")

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
from src.auth.db import init_db
from src.soc_pipeline.event_hub import EventHub
from src.soc_pipeline.soar_engine import SOAREngine
from src.soc_pipeline.ws_dashboard import SOCDashboardServer
from src.deception.token_watcher import HoneytokenWatcher
from src.deception.port_trap import PortTrap
from src.portal.financial_shell import FinancialPortalShell
from src.zero_trust.models import AlertEvent, AlertType, SessionRecord, TelemetryVector
from src.zero_trust.scorer import BehaviorScorer

# ---------------------------------------------------------------------------
# Shared in-memory state
# ---------------------------------------------------------------------------
ACTIVE_SESSIONS: Dict[str, SessionRecord] = {}
PERIMETER_BLACKLIST: set[str] = set()

# Paths / ports
_DATA_DIR        = Path("data")
_WATCH_DIR       = _DATA_DIR / "honey_tokens"
_HONEYTOKEN_FILE = _WATCH_DIR / "db_config.json"
_DB_PATH         = _DATA_DIR / "aces_production.db"
_DASHBOARD_PORT  = 8000
_DASHBOARD_HOST  = "0.0.0.0"   # accept LAN / VPN connections

# Default honeyport list used when ACES_HONEYPORT_LIST env var is not set.
# This constant is documentation-only — the live list is read from the env
# inside _run() so operators can override it without touching source code.
_DEFAULT_HONEYPORT_LIST: list[int] = [3389, 22, 445]


# ---------------------------------------------------------------------------
# Terminal helpers (pure ASCII)
# ---------------------------------------------------------------------------

_BANNER = (
    "\n"
    "+--------------------------------------------------------------------+\n"
    "| [*] Project A.C.E.S.  --  Production Mode (No Traffic Simulation) |\n"
    "+--------------------------------------------------------------------+\n"
    "| Task A  | HoneytokenWatcher  (watchdog)                           |\n"
    "| Task B  | SOAREngine         (threat orchestrator)                |\n"
    "| Task C  | PortTrap           (TCP honeypot :3389)                  |\n"
    "| Task D  | SOCDashboardServer (HTTP + WebSocket :8000)             |\n"
    "| Task E  | TrafficSimulator   [DISABLED -- waiting for real traffic]|\n"
    "+--------------------------------------------------------------------+\n"
)


def _banner() -> None:
    print(_BANNER, flush=True)


def _status(tag: str, detail: str) -> None:
    print(f"  [OK]  {tag:<36} {detail}", flush=True)


def _warn(tag: str, detail: str) -> None:
    print(f"  [--]  {tag:<36} {detail}", flush=True)


def _divider() -> None:
    print("  " + "-" * 64, flush=True)


def _local_ip() -> str:
    """
    Detect the primary LAN IP — the interface that routes to the internet.

    Uses a non-blocking UDP connect to 8.8.8.8 which forces the OS to
    select the interface associated with the default gateway.  This always
    returns the bridged/LAN adapter IP (e.g. 192.168.29.x) rather than a
    host-only or loopback address, even when multiple adapters are present.

    Falls back to 127.0.0.1 if no network is available.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)          # non-blocking -- no packets are actually sent
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _all_lan_ips() -> list[str]:
    """
    Return all non-loopback IPv4 addresses bound to this host, sorted so
    the primary LAN IP (from _local_ip) comes first.

    Used by the startup banner to list every interface the server is
    reachable on, without hardcoding subnet ranges.
    """
    primary = _local_ip()
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        all_ips = sorted(
            set(a[4][0] for a in addrs if not a[4][0].startswith("127.")),
            key=lambda ip: (0 if ip == primary else 1, ip),
        )
        return all_ips if all_ips else [primary]
    except Exception:
        return [primary]


# ---------------------------------------------------------------------------
# Scorer bootstrap
# ---------------------------------------------------------------------------

def _fit_scorer(n: int = 150) -> BehaviorScorer:
    """
    Build a BehaviorScorer in order of preference:
      1. Load offline-trained pkl from data/behavior_model.pkl (production)
      2. Fall back to synthetic IsolationForest fit (tests / first run)
    """
    pkl_path = _DATA_DIR / "behavior_model.pkl"
    if pkl_path.exists():
        try:
            scorer = BehaviorScorer.from_pkl(pkl_path)
            logger.info("BehaviorScorer: loaded offline model from %s", pkl_path)
            return scorer
        except Exception as exc:
            logger.warning(
                "BehaviorScorer: failed to load pkl (%s) -- falling back to synthetic fit.",
                exc,
            )

    # Synthetic fallback
    logger.info("BehaviorScorer: fitting on %d synthetic baseline samples ...", n)
    scorer = BehaviorScorer(n_estimators=100, contamination=0.05)
    baseline = [
        TelemetryVector(
            click_speed_intervals=[float(i % 300 + 50), float(i % 200 + 80)],
            page_path_weights=[0.4, 0.6],
            sequence_transitions=[1, 2],
            session_duration_ms=float(i * 100 + 500),
            request_rate_per_sec=float(i % 5 + 1),
        )
        for i in range(n)
    ]
    scorer.fit(baseline)
    return scorer


# ---------------------------------------------------------------------------
# Synthetic honeytoken trigger  (called by /api/honeytoken with real client IP)
# ---------------------------------------------------------------------------

async def _honeytoken_trigger(event_hub: EventHub, client_ip: str = "local") -> None:
    """
    Publish a HONEYTOKEN_ACCESS alert with the real client IP.
    The IP has already been banned in SQLite by the time this fires.
    """
    alert = AlertEvent(
        alert_type=AlertType.HONEYTOKEN_ACCESS,
        source_ip=client_ip,
        timestamp_ms=time.time() * 1000,
        affected_path=str(_HONEYTOKEN_FILE.resolve()),
    )
    await event_hub.publish(alert)
    logger.warning(
        "HoneytokenTrigger: alert published for IP=%s", client_ip
    )


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

async def _shutdown(
    watcher: HoneytokenWatcher,
    port_trap: PortTrap,
    dashboard: SOCDashboardServer,
    tasks: list["asyncio.Task[None]"],
) -> None:
    print(flush=True)
    _divider()
    logger.info("Shutdown requested -- tearing down subsystems ...")

    for t in tasks:
        t.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("  [OK]  Background tasks cancelled.")

    await dashboard.stop()
    logger.info("  [OK]  SOCDashboardServer closed.")

    await port_trap.stop()
    logger.info("  [OK]  PortTrap closed.")

    watcher.stop()
    logger.info("  [OK]  HoneytokenWatcher stopped.")

    _divider()
    logger.info("A.C.E.S. engine offline.  Zero data leaks.  Goodbye.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def _run() -> None:
    _banner()
    loop = asyncio.get_running_loop()
    lan_ip   = _local_ip()       # primary LAN / default-gateway interface
    all_ips  = _all_lan_ips()    # every non-loopback adapter on this host

    # SQLite auth / ban store
    init_db(_DB_PATH)
    _status("AuthDB (SQLite)", f"initialised at {_DB_PATH}")

    # EventHub
    event_hub = EventHub()
    _status("EventHub", "singleton initialised")

    # BehaviorScorer — tries pkl first, falls back to synthetic
    logger.info("Initialising BehaviorScorer ...")
    scorer = _fit_scorer(150)
    _scorer_mode = "offline-pkl" if scorer.is_pkl_mode else "synthetic-fit"
    _status("BehaviorScorer", f"IsolationForest ready  [{_scorer_mode}]")

    # Task A -- HoneytokenWatcher
    watcher = HoneytokenWatcher(
        watch_path=_WATCH_DIR, event_hub=event_hub, loop=loop
    )
    watcher.start()
    _status("HoneytokenWatcher [A]", f"watching {_HONEYTOKEN_FILE}")

    # Task B -- SOAREngine
    # Read MONITOR_ONLY env var so the mode can be pre-set before startup
    # without code changes.  Set ACES_MONITOR_ONLY=1 (or true) in .env to
    # enable alert-without-ban mode for live Kali VM demonstrations.
    _monitor_only_env = os.environ.get("ACES_MONITOR_ONLY", "").strip().lower()
    _monitor_only = _monitor_only_env in ("1", "true", "yes", "on")
    soar_engine = SOAREngine(
        event_hub=event_hub,
        active_sessions=ACTIVE_SESSIONS,
        perimeter_blacklist=PERIMETER_BLACKLIST,
        monitor_only=_monitor_only,
    )
    soar_task: asyncio.Task[None] = asyncio.create_task(
        soar_engine.start_orchestrator(), name="soar-orchestrator"
    )
    _mode_label = " [MONITOR-ONLY]" if _monitor_only else ""
    _status("SOAREngine [B]", f"orchestrator task running{_mode_label}")

    # Task C -- PortTrap
    # Build the honeyport list from the ACES_HONEYPORT_LIST env var.
    # Falls back to the default set [3389, 22, 445] when the var is absent.
    _raw_ports = os.environ.get("ACES_HONEYPORT_LIST", "3389,22,445").strip()
    try:
        _honeyport_list: list[int] = [
            int(p.strip()) for p in _raw_ports.split(",") if p.strip().isdigit()
        ]
        if not _honeyport_list:
            raise ValueError("empty list")
    except (ValueError, AttributeError):
        logger.warning(
            "run.py: invalid ACES_HONEYPORT_LIST=%r -- using defaults [3389, 22, 445]",
            _raw_ports,
        )
        _honeyport_list = [3389, 22, 445]

    logger.info("PortTrap: configuring honeyports from env: %s", _honeyport_list)
    port_trap = PortTrap(
        event_hub=event_hub,
        perimeter_blacklist=PERIMETER_BLACKLIST,
        ports=_honeyport_list,
    )
    await port_trap.start_server()
    _status("PortTrap [C]", f"TCP honeypot ports {port_trap.listening_ports}")

    # Task D -- SOCDashboardServer
    dashboard = SOCDashboardServer(
        event_hub=event_hub,
        port=_DASHBOARD_PORT,
        host=_DASHBOARD_HOST,
    )
    portal = FinancialPortalShell(
        scorer=scorer,
        soar_engine=soar_engine,
        active_sessions=ACTIVE_SESSIONS,
    )
    dashboard.portal_shell = portal
    # Inject SOAR engine so analyst /api/ban and /api/unban use the live blacklist
    dashboard.soar_engine = soar_engine
    # Inject PortTrap so /api/soc/deception-config can report real port status
    dashboard.port_trap = port_trap
    # Pass client IP through to the honeytoken trigger
    dashboard.honeytoken_trigger = lambda ip="local": _honeytoken_trigger(event_hub, ip)

    await dashboard.start()
    broadcast_task: asyncio.Task[None] = asyncio.create_task(
        dashboard.broadcast_loop(), name="dashboard-broadcast"
    )
    _status("SOCDashboardServer [D]", f"HTTP + WebSocket on 0.0.0.0:{_DASHBOARD_PORT}")

    # Task E DISABLED
    _warn("TrafficSimulator [E]", "DISABLED -- waiting for real traffic")

    # ── Ready ──────────────────────────────────────────────────────────────
    _divider()
    print(f"  [*]  Primary LAN IP (default-gateway interface): {lan_ip}", flush=True)
    print(f"  [*]  Corporate Portal:  http://{lan_ip}:{_DASHBOARD_PORT}/app/home",     flush=True)
    print(f"  [*]  SOC Dashboard:     http://{lan_ip}:{_DASHBOARD_PORT}/app/soc-board", flush=True)

    # List every adapter so the operator knows all reachable addresses
    extra = [ip for ip in all_ips if ip != lan_ip]
    if extra:
        for ip in extra:
            print(f"  [*]  Also reachable on:  http://{ip}:{_DASHBOARD_PORT}/app/home", flush=True)

    _divider()
    print(flush=True)
    logger.info(
        "[*] A.C.E.S. Production Ready.  "
        "Portal: http://%s:%d/app/home  "
        "SOC: http://%s:%d/app/soc-board",
        lan_ip, _DASHBOARD_PORT, lan_ip, _DASHBOARD_PORT,
    )

    # Open local SOC dashboard in browser
    await asyncio.sleep(0.6)
    webbrowser.open(f"http://127.0.0.1:{_DASHBOARD_PORT}/")

    # Keep alive -- no Task E
    bg = [soar_task, broadcast_task]
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Both Ctrl+C (KeyboardInterrupt converted to CancelledError by
        # asyncio.run) and direct task cancellation land here cleanly.
        pass
    except GeneratorExit:
        # Defensive guard: absorb the rare GeneratorExit that some Python
        # versions raise during event-loop teardown inside coroutines.
        pass
    finally:
        await _shutdown(watcher, port_trap, dashboard, bg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\n  Ctrl+C received -- shutdown complete.", flush=True)
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:
        logger.critical("A.C.E.S. runner crashed: %s", exc, exc_info=True)
        sys.exit(1)
