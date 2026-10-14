# src/portal/gateway.py
"""
Abstract base class + IP-ban middleware + Layer 7 Web Honeytoken Paths.

Layer 7 Deception (Req 3B)
--------------------------
Common attack enumeration endpoints are defined in WEB_HONEYTOKEN_PATHS.
Any incoming request to these paths is immediately flagged as an automated
scanner (Gobuster / Dirbuster / Nikto), a WEB_HONEYTOKEN_HIT alert is
published to the EventHub, the hit is persisted to SQLite, and the traffic
is dropped with a 403 response.

Public routes (no auth, accessible from any network device):
  GET /              -> 302 to /app/home
  GET /app/home      -> index.html
  GET /app/login     -> index.html
  GET /app/signup    -> index.html
  GET /app/dashboard -> portal.html

SOC board hard-403 enforcement
--------------------------------
  GET /app/soc-board -> Immediate 403 for every request lacking a valid
                        engineer session cookie. No 302 redirect.

IP-ban middleware
-----------------
All non-public action requests (POST /api/action) are checked against the
SQLite banned_ips table before any AI scoring occurs.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer 7 Web Honeytoken Paths (Req 3B)
# ---------------------------------------------------------------------------
# Any HTTP request hitting one of these paths is treated as automated scanner
# traffic (Gobuster, Dirbuster, Nikto, etc.) and triggers an immediate alert.
WEB_HONEYTOKEN_PATHS: frozenset[str] = frozenset({
    # ── Dedicated web-level bait files (port-8000 honeytoken traps) ──────
    # These paths are deliberately planted as realistic-looking admin/config
    # resources.  Any request — authenticated or not — is an immediate IOC.
    "/app/admin/db_config.json",       # primary bait: looks like a leaked DB config
    "/app/admin/config.json",
    "/app/admin/secrets.json",
    "/app/admin/credentials.json",
    "/app/admin/backup.sql",
    "/api/internal/config",
    "/api/internal/dump",
    "/api/v1/admin/keys",
    # ── Classic CMS / framework enumeration ──────────────────────────────
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/admin/config.php",
    "/admin/",
    "/administrator/",
    "/backup.sql",
    "/backup/",
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/secrets/",
    "/secrets",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/.git/config",
    "/.git/",
    "/phpmyadmin/",
    "/phpmyadmin",
    "/phpMyAdmin/",
    "/db/",
    "/database/",
    "/shell.php",
    "/cmd.php",
    "/eval.php",
    "/upload.php",
    "/xmlrpc.php",
    "/api/debug",
    "/api/test",
    "/console",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/.htpasswd",
    "/robots.txt",           # scanners always probe this
    "/sitemap.xml",
    "/crossdomain.xml",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
})

# Public action types that bypass SOAR scoring and ban checks entirely.
_PUBLIC_ACTION_TYPES = frozenset({
    "public_page",
    "home_visit",
    "signup_visit",
    "about_visit",
})

# HTTP GET paths that require SOC engineer role.
SOC_FORBIDDEN_PATHS = frozenset({
    "/app/soc-board",
    "/soc",
    "/soc.html",
    "/soc-dashboard",
})

# Import auth lazily so unit tests can run without a DB connection.
_AUTH_AVAILABLE = False
try:
    from src.auth import db as _auth_db
    _AUTH_AVAILABLE = True
except ImportError:  # pragma: no cover
    pass


def check_web_honeytoken(
    path: str,
    client_ip: str,
    event_hub=None,
    soar_engine=None,
) -> bool:
    """
    Check if the request path matches a web honeytoken trap.

    Called by SOCDashboardServer._dispatch_inner() before route dispatch.
    If the path is in WEB_HONEYTOKEN_PATHS:
      - Logs a WARNING to stdout.
      - Immediately bans the client IP in SQLite (hard quarantine).
      - Persists a honeytoken_event row to SQLite.
      - Publishes a HONEYTOKEN_ACCESS alert to the EventHub (non-blocking).
      - Returns True so the caller can drop the traffic with the styled
        "Access Revoked" block page.

    Parameters
    ----------
    path       : str  -- normalised URL path (no query string)
    client_ip  : str  -- real client IP
    event_hub  : EventHub | None
    soar_engine: SOAREngine | None  -- used to check monitor_only

    Returns
    -------
    bool
        True if this path is a web honeytoken hit (caller must return 403).
        False otherwise (normal routing continues).
    """
    if path not in WEB_HONEYTOKEN_PATHS:
        return False

    _monitor_only = (
        soar_engine is not None
        and getattr(soar_engine, "monitor_only", False)
    )
    _action = "MONITOR_ONLY_ALERT" if _monitor_only else "BLOCKED"

    logger.warning(
        "WEB_HONEYTOKEN_HIT: probe from %s -> %s  action=%s",
        client_ip, path, _action,
    )

    if _AUTH_AVAILABLE:
        # ── Immediate hard quarantine (unless monitor-only) ──────────────
        # Ban the IP in SQLite RIGHT NOW so that subsequent requests on
        # port 8000 hit the quarantine gate before any route is evaluated.
        if not _monitor_only:
            try:
                _auth_db.ban_ip(
                    client_ip,
                    reason=f"WEB_HONEYTOKEN_HIT:{path}",
                )
                _auth_db.revoke_sessions_for_ip(client_ip)
            except Exception as exc:
                logger.debug("gateway: immediate ban failed for %s: %s", client_ip, exc)

        # ── Persist structured event record ─────────────────────────────
        try:
            _auth_db.log_honeytoken_event(
                ip=client_ip,
                trigger="WEB_HONEYTOKEN_HIT",
                token_path=path,
                action=_action,
            )
        except Exception as exc:
            logger.debug("gateway: honeytoken DB log failed: %s", exc)

    # ── Publish alert to EventHub ────────────────────────────────────────
    if event_hub is not None:
        import asyncio
        from src.zero_trust.models import AlertEvent, AlertType
        alert = AlertEvent(
            alert_type=AlertType.HONEYTOKEN_ACCESS,
            source_ip=client_ip,
            timestamp_ms=time.time() * 1000,
            affected_path=f"WEB_HONEYTOKEN:{path}",
        )
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(event_hub.publish(alert))
        except Exception as exc:
            logger.debug("gateway: event hub publish failed: %s", exc)

    return True


class BasePortalShell(ABC):
    """
    Abstract base class for all portal shell implementations.

    run() applies:
      1. Public-page bypass  -- skips everything for public action types.
      2. IP-ban check        -- blocks banned IPs before AI scoring.
      3. Delegation          -- calls handle_user_action() on the subclass.
    """

    async def run(
        self,
        session_id: str,
        ip: str,
        action_type: str,
        click_payload: dict,
        username: Optional[str] = None,
    ) -> dict:
        # --- Guard 1: Public-page bypass ------------------------------------
        if action_type in _PUBLIC_ACTION_TYPES:
            logger.debug(
                "BasePortalShell: public-page bypass for ip=%s action=%s",
                ip, action_type,
            )
            return {
                "allowed": True,
                "score": 0.0,
                "action": "ALLOW",
                "session_id": session_id,
                "action_type": action_type,
                "public": True,
            }

        # --- Guard 2: IP-ban check ------------------------------------------
        if _AUTH_AVAILABLE and _auth_db.is_banned(ip):
            logger.warning(
                "BasePortalShell: request from BANNED IP %s rejected.", ip
            )
            return {
                "allowed": False,
                "score": 0.0,
                "action": "BLOCK",
                "session_id": session_id,
                "action_type": action_type,
                "banned": True,
                "reason": "ip_banned",
                "http_status": 403,
            }

        # --- Delegate to concrete subclass ----------------------------------
        return await self.handle_user_action(session_id, ip, action_type, click_payload, username)

    @abstractmethod
    async def handle_user_action(
        self,
        session_id: str,
        ip: str,
        action_type: str,
        click_payload: dict,
        username: Optional[str] = None,
    ) -> dict: ...
