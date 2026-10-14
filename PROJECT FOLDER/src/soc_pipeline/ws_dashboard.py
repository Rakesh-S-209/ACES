# src/soc_pipeline/ws_dashboard.py
"""
SOCDashboardServer -- production multi-route async HTTP + WebSocket server.

All pages are served from native static HTML files in src/portal/static/.
There is NO React/Vite/Node.js dependency.

Routes
------
GET  /                         -> 302 redirect to /app/home
GET  /app/home                 -> NorthStar Capital landing page (index.html)
GET  /app/login                -> Login page  (index.html, #login tab)
GET  /app/signup               -> Sign-up page (index.html, #signup tab)
GET  /app/dashboard            -> Financial portal (portal.html) [cookie session]
GET  /app/soc-board            -> SOC triage board (soc.html)   [Admin role only]
GET  /favicon.ico              -> 204 No Content

POST /api/login                -> authenticate, issue Set-Cookie session token
POST /api/logout               -> revoke session, clear cookie
POST /api/action               -> score portal action (ban-checked, session-checked)
POST /api/honeytoken           -> instant ban + 403 + alert

GET  /api/status               -> active sessions, banned IPs, alert count
GET  /api/events               -> merged event log (ban + abuse_reports)
POST /api/ban                  -> analyst manual ban  [Admin]
POST /api/unban                -> analyst remove ban  [Admin]
POST /api/report-abuse         -> on-demand AbuseIPDB report [Admin]
GET  /api/admin/config         -> honeytoken config + port info [Admin]

WS   /                         -> SOC WebSocket alert stream
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import struct
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set

from src.soc_pipeline.event_hub import EventHub
from src.zero_trust.models import AlertEvent, AlertType
from src.portal.gateway import SOC_FORBIDDEN_PATHS, WEB_HONEYTOKEN_PATHS, check_web_honeytoken

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static file paths  (native HTML -- no React build required)
# ---------------------------------------------------------------------------
_STATIC_DIR  = Path(__file__).parent.parent / "portal" / "static"
_HOME_HTML   = _STATIC_DIR / "index.html"    # landing + login + signup
_PORTAL_HTML = _STATIC_DIR / "portal.html"  # financial portal / dashboard
_SOC_HTML    = _STATIC_DIR / "soc.html"      # SOC triage board

# Honeytoken data directory (read for admin config endpoint)
_DATA_DIR          = Path("data")
_HONEY_TOKEN_DIR   = _DATA_DIR / "honey_tokens"
_HONEY_TOKEN_FILE  = _HONEY_TOKEN_DIR / "db_config.json"

# ---------------------------------------------------------------------------
# WebSocket magic
# ---------------------------------------------------------------------------
_WS_MAGIC   = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_COOKIE_NAME = "aces_session"

# ---------------------------------------------------------------------------
# Lazy auth + SOAR import helpers
# ---------------------------------------------------------------------------
_auth: Any = None


def _get_auth() -> Any:
    global _auth
    if _auth is None:
        try:
            from src.auth import db
            _auth = db
        except ImportError:
            _auth = None
    return _auth


def _ws_accept_key(client_key: str) -> str:
    raw = (client_key.strip() + _WS_MAGIC).encode("utf-8")
    return base64.b64encode(hashlib.sha1(raw).digest()).decode("utf-8")


def _real_ip(headers: Dict[str, str], peername_ip: str) -> str:
    xff = headers.get("x-forwarded-for", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return peername_ip


def _load_html(path: Path) -> bytes:
    try:
        return path.read_bytes() if path.exists() else b""
    except OSError:
        return b""


def _parse_cookie(headers: Dict[str, str]) -> Dict[str, str]:
    cookie_hdr = headers.get("cookie", "")
    result: Dict[str, str] = {}
    for part in cookie_hdr.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v.strip()
    return result


def _get_session_from_request(headers: Dict[str, str]) -> Optional[dict]:
    auth = _get_auth()
    if auth is None:
        return None
    cookies = _parse_cookie(headers)
    token = cookies.get(_COOKIE_NAME, "")
    if not token:
        return None
    return auth.get_session(token)


def _is_admin(session: Optional[dict]) -> bool:
    """Return True for sessions that have admin-level infrastructure access."""
    if session is None:
        return False
    return session.get("role") in ("admin", "Admin") or session.get("username") == "admin_user"


def _can_access_soc(session: Optional[dict]) -> bool:
    """
    Return True for sessions authorised to view the SOC triage board.

    SOC access:  role == 'engineer'  (soc_engineer -- primary SOC analyst)
    Admin panel: role == 'admin'     (admin_user   -- goes to portal.html admin panel)
    Portal:      role == 'user'      (employee_test -- financial portal only)
    """
    if session is None:
        return False
    role = session.get("role", "")
    return role in ("engineer", "Engineer")


# ---------------------------------------------------------------------------
# Quarantine block page  (returned to every banned/quarantined IP)
# ---------------------------------------------------------------------------
# Served as text/html so the browser renders a styled full-page notice
# instead of displaying raw JSON or timing out.
_QUARANTINE_HTML = b"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>A.C.E.S. \xe2\x80\x94 Access Revoked</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#060a0f;font-family:'Segoe UI',system-ui,sans-serif}
body{display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{
  background:#0d1117;border:1px solid #f85149;border-radius:12px;
  padding:48px 56px;max-width:560px;width:90%;text-align:center;
  box-shadow:0 0 60px rgba(248,81,73,.18);
}
.icon{font-size:56px;margin-bottom:20px;display:block;
      animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
h1{color:#f85149;font-size:26px;font-weight:800;letter-spacing:.03em;margin-bottom:12px}
.sub{color:#8b949e;font-size:14px;line-height:1.6;margin-bottom:28px}
.badge{
  display:inline-block;background:#2d1213;color:#f85149;
  border:1px solid #f85149;border-radius:6px;
  padding:6px 18px;font-size:12px;font-weight:700;
  letter-spacing:.08em;text-transform:uppercase;margin-bottom:28px;
}
.meta{
  background:#0a0d12;border:1px solid #21262d;border-radius:8px;
  padding:16px 20px;font-family:'Cascadia Code','Fira Code',monospace;
  font-size:11px;color:#3fb950;text-align:left;margin-bottom:28px;
  white-space:pre-wrap;word-break:break-all;
}
.footer{color:#3a4550;font-size:10px;letter-spacing:.06em;text-transform:uppercase}
a.unblock{
  display:inline-block;margin-top:18px;
  color:#4f8ef7;font-size:12px;text-decoration:none;
  border:1px solid #1a3866;border-radius:6px;padding:6px 16px;
  background:#0c1f3a;transition:opacity .15s;
}
a.unblock:hover{opacity:.8}
</style>
</head>
<body>
<div class="card">
  <span class="icon">\xf0\x9f\x9a\xab</span>
  <div class="badge">\xe2\x9a\xa0\xef\xb8\x8f Threat Quarantined</div>
  <h1>Access Revoked</h1>
  <p class="sub">
    Your IP address has been identified as a threat source by the
    <strong style="color:#c9d1d9">A.C.E.S. Zero Trust engine</strong>
    and has been quarantined.<br/><br/>
    All sessions from this host have been revoked and further requests
    are blocked pending SOC analyst review.
  </p>
  <div class="meta"
>STATUS  : QUARANTINED
POLICY  : Zero Trust \xe2\x80\x94 Anomaly / Deception Trigger
ACTION  : Session Revoked \xc2\xb7 IP Blacklisted
CONTACT : SOC Analyst via internal ticketing system</div>
  <p class="footer">A.C.E.S. Security Operations Center &mdash; Automated Containment</p>
  <a class="unblock" href="/app/home">Return to Portal</a>
</div>
</body>
</html>"""

# ---------------------------------------------------------------------------
# 403 body  (RBAC guard: SOC board + analyst-only API endpoints)
# Used only for role-gating, NOT for quarantined IPs.
# ---------------------------------------------------------------------------
_403_HTML = (
    b"<!DOCTYPE html><html><head><title>403 Forbidden</title></head>"
    b"<body style='font-family:monospace;background:#060a0f;color:#f85149;"
    b"display:flex;flex-direction:column;align-items:center;justify-content:"
    b"center;height:100vh;margin:0'>"
    b"<h1 style='font-size:32px'>403 Forbidden</h1>"
    b"<p style='color:#8b949e'>You do not have permission to access this resource.</p>"
    b"<p style='color:#3a2020;font-size:12px'>Access attempt logged by A.C.E.S.</p>"
    b"</body></html>"
)


# ---------------------------------------------------------------------------
# Main server class
# ---------------------------------------------------------------------------

class SOCDashboardServer:
    """
    Dual-protocol HTTP + WebSocket server for the A.C.E.S. ecosystem.
    Serves native static HTML from src/portal/static/ -- no Node.js required.
    """

    def __init__(
        self,
        event_hub: EventHub,
        port: int = 8000,
        host: str = "0.0.0.0",
    ) -> None:
        self._event_hub   = event_hub
        self._port        = port
        self._host        = host
        self._ws_clients: Set[asyncio.StreamWriter] = set()
        self._server: Optional[asyncio.AbstractServer] = None
        self._alert_count = 0

        # Injected by run.py after construction
        self.portal_shell: Optional[Any]             = None
        self.honeytoken_trigger: Optional[Callable]  = None

        # SOAR engine reference -- injected by run.py for analyst actions
        self.soar_engine: Optional[Any]              = None

        # Pre-load static HTML pages at startup
        self._home_html   = _load_html(_HOME_HTML)
        self._portal_html = _load_html(_PORTAL_HTML)
        self._soc_html    = _load_html(_SOC_HTML)

        if not self._home_html:
            logger.warning("ws_dashboard: %s not found -- home routes will fail", _HOME_HTML)
        if not self._portal_html:
            logger.warning("ws_dashboard: %s not found -- dashboard route will fail", _PORTAL_HTML)
        if not self._soc_html:
            logger.warning("ws_dashboard: %s not found -- SOC route will fail", _SOC_HTML)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        try:
            self._server = await asyncio.start_server(
                self._handle_connection, host=self._host, port=self._port
            )
            logger.info("SOCDashboardServer: listening on %s:%d", self._host, self._port)
        except OSError as exc:
            logger.warning(
                "SOCDashboardServer: cannot bind %s:%d -- %s", self._host, self._port, exc
            )

    async def stop(self) -> None:
        # Close all active WebSocket connections cleanly
        for w in list(self._ws_clients):
            try:
                w.close()
                await asyncio.wait_for(w.wait_closed(), timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                pass
        self._ws_clients.clear()
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=3.0)
            except asyncio.TimeoutError:
                logger.warning("SOCDashboardServer: server.wait_closed() timed out.")
            logger.info("SOCDashboardServer: stopped.")

    # ------------------------------------------------------------------
    # Connection dispatcher
    # ------------------------------------------------------------------

    def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        asyncio.create_task(self._dispatch(reader, writer))

    async def _dispatch(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._dispatch_inner(reader, writer)
        except asyncio.CancelledError:
            # Clean shutdown: close the socket gracefully without logging noise
            try:
                writer.close()
            except Exception:
                pass
            raise  # re-raise so the task framework marks it as cancelled
        except (ConnectionResetError, BrokenPipeError, OSError):
            # Client disconnected mid-flight — not an error, just close
            try:
                writer.close()
            except Exception:
                pass
        except Exception as exc:
            logger.error(
                "SOCDashboardServer: unhandled dispatch error: %s",
                exc, exc_info=True,
            )
            try:
                writer.close()
            except Exception:
                pass

    async def _dispatch_inner(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.read(8192), timeout=5.0)
        except asyncio.TimeoutError:
            writer.close()
            return
        if not raw:
            writer.close()
            return

        req_line  = raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
        headers   = self._parse_headers(raw)
        parts     = req_line.split(" ")
        method    = parts[0] if parts else "GET"
        full_path = parts[1] if len(parts) > 1 else "/"
        path      = full_path.split("?")[0]
        query     = full_path.split("?")[1] if "?" in full_path else ""

        peer      = writer.get_extra_info("peername")
        peer_ip   = peer[0] if peer else "unknown"
        client_ip = _real_ip(headers, peer_ip)

        # ── Global IP quarantine gate ──────────────────────────────────────
        # Checked on EVERY request before any routing occurs.
        # Two-layer check for zero-latency enforcement:
        #   Layer 1 — in-memory PERIMETER_BLACKLIST (populated by PortTrap
        #             immediately on TCP connect, O(1) set lookup, no I/O)
        #   Layer 2 — SQLite banned_ips (survives restarts; also written by
        #             PortTrap.handle_connection() synchronously before the
        #             alert even reaches SOAR)
        # Either layer being True → quarantine page, no further routing.
        #
        # Exemptions:
        #   • Loopback 127.x — prevents the server locking itself out
        #   • monitor_only mode — traffic passes through for SOC observation
        _LOOPBACK_PREFIXES = ("127.",)
        _monitor_only_active = False
        _soar = getattr(self, "soar_engine", None)
        try:
            if _soar is not None:
                _monitor_only_active = bool(getattr(_soar, "monitor_only", False))
        except Exception:
            pass

        if not _monitor_only_active and not any(
            client_ip.startswith(p) for p in _LOOPBACK_PREFIXES
        ):
            # Layer 1: in-memory blacklist (instant — no DB I/O)
            _in_memory_blacklist: set = set()
            try:
                if _soar is not None:
                    _in_memory_blacklist = getattr(_soar, "_blacklist", set())
            except Exception:
                pass

            _quarantined = client_ip in _in_memory_blacklist

            # Layer 2: SQLite (catches bans that survived a restart)
            if not _quarantined:
                auth = _get_auth()
                if auth:
                    try:
                        _quarantined = auth.is_banned(client_ip)
                    except Exception:
                        pass

            if _quarantined:
                await self._http_response(
                    writer, 403, _QUARANTINE_HTML, "text/html; charset=utf-8"
                )
                return

        # ── Layer 7 Web Honeytoken gate ────────────────────────────────────
        # Intercept bait paths (Gobuster / Dirbuster / Nikto enumeration)
        # BEFORE routing.  check_web_honeytoken() also writes the ban to SQLite
        # so the NEXT request from the same IP hits the quarantine gate above.
        _soar_ref = getattr(self, "soar_engine", None)
        _hub_ref  = getattr(self, "_event_hub", None)
        if method in ("GET", "POST", "HEAD") and check_web_honeytoken(
            path, client_ip, event_hub=_hub_ref, soar_engine=_soar_ref
        ):
            await self._http_response(
                writer, 403, _QUARANTINE_HTML, "text/html; charset=utf-8"
            )
            return

        # WebSocket upgrade
        if (
            headers.get("upgrade", "").lower() == "websocket"
            and "sec-websocket-key" in headers
        ):
            await self._ws_handshake(reader, writer, headers, client_ip)
            return

        body_bytes = self._extract_body(raw)

        # ── ROUTE TABLE ────────────────────────────────────────────────────
        # PUBLIC / no-auth routes
        if method == "GET" and path == "/":
            await self._redirect(writer, "/app/home")

        elif method == "GET" and path in ("/app/home", "/app/login", "/app/signup",
                                          "/index.html", "/login", "/signup"):
            await self._serve_html(writer, self._home_html)

        elif method == "GET" and path in ("/app/dashboard", "/portal", "/portal.html"):
            await self._serve_html(writer, self._portal_html)

        # Admin panel -- serves portal.html (admin tab auto-shows for admin role)
        elif method == "GET" and path in ("/app/admin",):
            await self._serve_html(writer, self._portal_html)

        # SOC board -- hard RBAC at HTTP layer, no redirects
        elif method == "GET" and path in SOC_FORBIDDEN_PATHS:
            await self._serve_soc_guarded(writer, headers, client_ip)

        elif method == "GET" and path == "/favicon.ico":
            await self._http_response(writer, 204, b"", "text/plain")

        # ── AUTH API ───────────────────────────────────────────────────────
        elif method == "POST" and path == "/api/login":
            await self._handle_login(writer, body_bytes, client_ip)

        elif method == "POST" and path == "/api/logout":
            await self._handle_logout(writer, headers)

        # ── PORTAL ACTION ──────────────────────────────────────────────────
        elif method == "POST" and path == "/api/action":
            await self._handle_action(writer, body_bytes, client_ip, headers)

        elif method == "POST" and path == "/api/honeytoken":
            await self._handle_honeytoken(writer, client_ip, headers)

        # ── STATUS ─────────────────────────────────────────────────────────
        elif method == "GET" and path == "/api/status":
            await self._handle_status(writer)

        # ── REGISTRATION (open sign-up) ────────────────────────────────────
        elif method == "POST" and path == "/api/register":
            await self._handle_register(writer, body_bytes)

        # ── LIVE METRICS (persistent DB counters) ──────────────────────────
        elif method == "GET" and path == "/api/metrics":
            await self._handle_metrics(writer, headers)

        # ── ANALYST API (Admin-only) ────────────────────────────────────────
        elif method == "GET" and path == "/api/events":
            await self._handle_events(writer, headers, query)

        elif method == "POST" and path == "/api/events/mark-read":
            await self._handle_mark_triage_read(writer, body_bytes, headers)

        elif method == "GET" and path == "/api/events/unread-count":
            await self._handle_unread_count(writer, headers)

        elif method == "POST" and path == "/api/ban":
            await self._handle_manual_ban(writer, body_bytes, headers)

        elif method == "POST" and path == "/api/unban":
            await self._handle_manual_unban(writer, body_bytes, headers)

        elif method == "POST" and path == "/api/report-abuse":
            await self._handle_report_abuse(writer, body_bytes, headers)

        elif method == "GET" and path == "/api/admin/config":
            await self._handle_admin_config(writer, headers)

        # ── SOC-ONLY ANALYST ENDPOINTS ──────────────────────────────────────
        elif method == "GET" and path == "/api/soc/top-threats":
            await self._handle_top_threats(writer, headers)

        elif method == "GET" and path == "/api/soc/deception-config":
            await self._handle_deception_config(writer, headers)

        elif method == "GET" and path == "/api/deception/history":
            await self._handle_deception_history(writer, headers)

        elif method == "POST" and path == "/api/soc/monitor-mode":
            await self._handle_monitor_mode_toggle(writer, body_bytes, headers)

        elif method == "GET" and path == "/api/ml/distribution-graph":
            await self._handle_ml_distribution(writer, headers)

        elif method == "POST" and path == "/api/telemetry/score":
            await self._handle_telemetry_score(writer, body_bytes, client_ip, headers)

        elif method == "OPTIONS":
            await self._http_response(writer, 204, b"", "text/plain")

        else:
            # Unknown path -- serve home page (graceful fallback)
            await self._serve_html(writer, self._home_html)

    # ------------------------------------------------------------------
    # Static HTML serving
    # ------------------------------------------------------------------

    async def _serve_html(
        self, writer: asyncio.StreamWriter, html: bytes
    ) -> None:
        if not html:
            html = (
                b"<html><body style='font-family:monospace;background:#07090f;color:#c9d1d9;"
                b"display:flex;align-items:center;justify-content:center;height:100vh'>"
                b"<div><h2 style='color:#f85149'>Static file not found</h2>"
                b"<p style='color:#8b949e;margin-top:8px'>Check src/portal/static/ directory.</p>"
                b"</div></body></html>"
            )
        await self._http_response(writer, 200, html, "text/html; charset=utf-8")

    # ------------------------------------------------------------------
    # SOC board RBAC guard
    # ------------------------------------------------------------------

    async def _serve_soc_guarded(
        self,
        writer: asyncio.StreamWriter,
        headers: Dict[str, str],
        client_ip: str,
    ) -> None:
        """
        Hard RBAC gate for /app/soc-board.

        Allowed  : role == 'engineer' OR role == 'admin'
        Blocked  : unauthenticated, role == 'user', or any other role
        Response : immediate 403 -- never a 302 redirect (prevents loops).
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._http_response(writer, 403, _403_HTML, "text/html; charset=utf-8")
            await self._log_unauthorized_probe(
                client_ip, "/app/soc-board",
                role=session.get("role", "?") if session else None,
                username=session.get("username", "?") if session else "unauthenticated",
                session_id=(session or {}).get("token", "")[:12],
            )
            return
        await self._serve_html(writer, self._soc_html)

    async def _log_unauthorized_probe(
        self,
        client_ip: str,
        path: str,
        role: Optional[str],
        username: str = "unauthenticated",
        session_id: str = "",
    ) -> None:
        _LOCAL = {"127.0.0.1", "::1", "local", "unknown", "localhost"}
        # Only suppress alerts from true loopback addresses.
        # Probes from the Kali VM (e.g. 192.168.29.235) must reach the SOC stream.
        if client_ip in _LOCAL or client_ip.startswith("127."):
            return
        logger.warning("RBAC PROBE: ip=%s path=%s role=%s user=%s",
                       client_ip, path, role, username)
        alert = AlertEvent(
            alert_type=AlertType.HONEYTOKEN_ACCESS,
            source_ip=client_ip,
            timestamp_ms=time.time() * 1000,
            affected_path=f"UNAUTHORIZED_PROBE:{path}",
            session_id=session_id or None,
        )
        await self._event_hub.publish(alert)

    # ------------------------------------------------------------------
    # Auth endpoints
    # ------------------------------------------------------------------

    async def _handle_login(
        self, writer: asyncio.StreamWriter, body: bytes, client_ip: str
    ) -> None:
        auth = _get_auth()
        if not auth:
            await self._json(writer, 503, {"error": "auth unavailable"})
            return
        try:
            data     = json.loads(body or b"{}")
            username = data.get("username", "")
            password = data.get("password", "")
            role     = auth.verify_credentials(username, password)
            if role is None:
                await self._json(writer, 401, {"error": "invalid_credentials"})
                return
            token  = auth.create_session(username, role, client_ip)
            cookie = f"{_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax"
            await self._http_response(
                writer, 200,
                json.dumps({"token": token, "role": role, "username": username}).encode(),
                "application/json",
                extra_headers={"Set-Cookie": cookie},
            )
        except Exception as exc:
            logger.warning("login error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_logout(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        auth    = _get_auth()
        cookies = _parse_cookie(headers)
        token   = cookies.get(_COOKIE_NAME, "")
        if auth and token:
            auth.revoke_session(token)
        cookie = (
            f"{_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; "
            "Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        )
        await self._redirect(writer, "/app/home", extra_headers={"Set-Cookie": cookie})

    # ------------------------------------------------------------------
    # Portal action
    # ------------------------------------------------------------------

    async def _handle_action(
        self,
        writer: asyncio.StreamWriter,
        body: bytes,
        client_ip: str,
        headers: Dict[str, str],
    ) -> None:
        session = _get_session_from_request(headers)
        if session is None:
            await self._json(writer, 401, {"error": "not_authenticated"})
            return
        if self.portal_shell is None:
            await self._json(writer, 503, {"error": "portal not ready"})
            return
        try:
            data   = json.loads(body or b"{}")
            result = await self.portal_shell.run(
                session_id    = session["token"][:12],
                ip            = client_ip,
                action_type   = data.get("action_type", "view_balance"),
                click_payload = data.get("click_payload", {}),
                username      = session.get("username"),
            )
            http_status = result.pop("http_status", 200)
            if result.get("banned") or not result.get("allowed", True):
                http_status = 403
            await self._http_response(
                writer, http_status,
                json.dumps(result).encode("utf-8"), "application/json",
            )
        except Exception as exc:
            logger.warning("action error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # Honeytoken
    # ------------------------------------------------------------------

    async def _handle_honeytoken(
        self, writer: asyncio.StreamWriter, client_ip: str, headers: Dict[str, str]
    ) -> None:
        auth = _get_auth()
        session = _get_session_from_request(headers)
        username = (session or {}).get("username")
        session_id = ((session or {}).get("token") or "")[:12] or None

        if auth:
            auth.ban_ip(client_ip, reason="honeytoken_access")
            auth.revoke_sessions_for_ip(client_ip)
            logger.warning("SOCDashboardServer: HONEYTOKEN by %s -- BANNED.", client_ip)
            # Persist structured honeytoken trip record so the history table is populated
            try:
                auth.log_honeytoken_event(
                    ip=client_ip,
                    trigger="HONEYTOKEN_ACCESS",
                    token_path="data/honey_tokens/db_config.json",
                    action="BANNED",
                    session_id=session_id,
                    username=username,
                )
            except Exception as exc:
                logger.debug("honeytoken: failed to log trip event: %s", exc)

        if self.honeytoken_trigger is not None:
            try:
                await self.honeytoken_trigger(client_ip)
            except Exception as exc:
                logger.warning("honeytoken trigger: %s", exc)
        cookie = (
            f"{_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; "
            "Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        )
        await self._http_response(
            writer, 403,
            json.dumps({"triggered": True, "banned": True, "reason": "honeytoken_access"}).encode(),
            "application/json",
            extra_headers={"Set-Cookie": cookie},
        )

    # ------------------------------------------------------------------
    # Status (public)
    # ------------------------------------------------------------------

    async def _handle_status(self, writer: asyncio.StreamWriter) -> None:
        auth = _get_auth()
        # Detect AbuseIPDB live mode by checking if the key is configured
        abuseipdb_mode = "offline_mock"
        try:
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
            _placeholders = {"YOUR_ACTUAL_API_KEY_HERE", "your_api_key_here", "YOUR_API_KEY", ""}
            if api_key and api_key not in _placeholders:
                abuseipdb_mode = "live"
        except Exception:
            pass
        payload = {
            "alert_count":    self._alert_count,
            "ws_clients":     self.client_count,
            "banned_ips":     auth.get_all_banned_ips()    if auth else [],
            "sessions":       auth.get_active_sessions()   if auth else [],
            "abuseipdb_mode": abuseipdb_mode,
        }
        await self._json(writer, 200, payload)

    # ------------------------------------------------------------------
    # Registration (open sign-up -- creates user accounts in DB)
    # ------------------------------------------------------------------

    async def _handle_register(
        self, writer: asyncio.StreamWriter, body: bytes
    ) -> None:
        """
        POST /api/register -- create a new user account.

        Accepts JSON: { username, password, email? }
        Role defaults to 'user' for all self-registered accounts.
        Returns 201 on success, 409 if username taken, 400 on bad input.
        """
        auth = _get_auth()
        if not auth:
            await self._json(writer, 503, {"error": "auth unavailable"})
            return
        try:
            data     = json.loads(body or b"{}")
            username = data.get("username", "").strip()
            password = data.get("password", "")
            if not username or not password:
                await self._json(writer, 400, {"error": "username and password required"})
                return
            if len(password) < 8:
                await self._json(writer, 400, {"error": "password must be at least 8 characters"})
                return
            # Validate username characters
            if not re.match(r'^[a-zA-Z0-9_.-]{3,32}$', username):
                await self._json(writer, 400, {
                    "error": "username must be 3-32 characters, letters/digits/underscore/dash only"
                })
                return
            ok = auth.register_user(username, password, role="user")
            if not ok:
                await self._json(writer, 409, {"error": "username already exists"})
                return
            await self._json(writer, 201, {
                "success": True,
                "username": username,
                "role": "user",
                "message": "Account created. You can now sign in.",
            })
            logger.info("Registration: new user '%s' created.", username)
        except Exception as exc:
            logger.warning("register error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # Live metrics (persistent DB-backed counters)
    # ------------------------------------------------------------------

    async def _handle_metrics(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        """
        GET /api/metrics -- SOC-accessible live counters pulled from DB.

        Returns counts that survive page reloads and server restarts:
          active_sessions  -- non-revoked sessions in DB
          banned_ips       -- current banned_ips table size
          evicted_sessions -- revoked sessions in DB (revoked=1)
          total_alerts     -- _alert_count in-process + DB abuse_reports count
          port_trap_hits   -- ban events with reason containing 'port_trap'
          honeytoken_trips -- ban events with reason containing 'honeytoken'
          abuse_reports    -- count of abuse_reports table rows
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        auth = _get_auth()
        try:
            m = auth.get_metrics() if auth else {}
            m["ws_alert_count"] = self._alert_count
            await self._json(writer, 200, m)
        except Exception as exc:
            logger.warning("metrics error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # Analyst endpoints (SOC role required)
    # ------------------------------------------------------------------

    async def _handle_events(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str], query: str
    ) -> None:
        """GET /api/events -- merged event log. engineer or admin role required."""
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._http_response(writer, 403, _403_HTML, "text/html; charset=utf-8")
            return
        auth = _get_auth()
        try:
            rows = auth.get_event_log(limit=200) if auth else []
            await self._json(writer, 200, rows)
        except Exception as exc:
            logger.warning("events error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_mark_triage_read(
        self,
        writer: asyncio.StreamWriter,
        body: bytes,
        headers: Dict[str, str],
    ) -> None:
        """
        POST /api/events/mark-read -- mark one or more triage events as viewed.

        Body: { "event_key": "<key>" }  OR  { "event_keys": ["<key>", ...] }

        The badge counter decrements by the number of newly-read items returned.
        SOC engineer role required.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        auth = _get_auth()
        if not auth:
            await self._json(writer, 503, {"error": "auth unavailable"})
            return
        analyst = (session or {}).get("username", "soc_engineer")
        try:
            data = json.loads(body or b"{}")
            keys: list[str] = []
            if "event_key" in data:
                keys = [data["event_key"]]
            elif "event_keys" in data:
                keys = list(data["event_keys"])
            newly_read = sum(
                1 for k in keys if auth.mark_triage_read(k, analyst=analyst)
            )
            unread = auth.get_unread_triage_count()
            await self._json(writer, 200, {
                "success": True,
                "newly_read": newly_read,
                "unread_count": unread,
            })
        except Exception as exc:
            logger.warning("mark_triage_read error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_unread_count(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        """
        GET /api/events/unread-count -- returns the number of unread triage items.

        Used by the frontend to initialise the badge on page load and to
        poll for changes without re-fetching the full event list.
        SOC engineer role required.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        auth = _get_auth()
        try:
            count = auth.get_unread_triage_count() if auth else 0
            await self._json(writer, 200, {"unread_count": count})
        except Exception as exc:
            logger.warning("unread_count error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_manual_ban(
        self,
        writer: asyncio.StreamWriter,
        body: bytes,
        headers: Dict[str, str],
    ) -> None:
        """POST /api/ban -- analyst manual containment. engineer or admin role required."""
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        try:
            data   = json.loads(body or b"{}")
            ip     = data.get("ip", "").strip()
            reason = data.get("reason", "analyst_manual_ban")
            if not ip:
                await self._json(writer, 400, {"error": "ip required"})
                return
            if self.soar_engine is not None:
                result = await self.soar_engine.manual_ban(ip, reason=reason)
            else:
                # Fallback: write directly to auth DB
                auth = _get_auth()
                if auth:
                    auth.ban_ip(ip, reason=reason)
                    auth.revoke_sessions_for_ip(ip)
                result = {"success": True, "ip": ip, "reason": reason}
            await self._json(writer, 200, result)
        except Exception as exc:
            logger.warning("manual_ban error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_manual_unban(
        self,
        writer: asyncio.StreamWriter,
        body: bytes,
        headers: Dict[str, str],
    ) -> None:
        """POST /api/unban -- analyst removes IP from blacklist. engineer or admin role required."""
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        try:
            data = json.loads(body or b"{}")
            ip   = data.get("ip", "").strip()
            if not ip:
                await self._json(writer, 400, {"error": "ip required"})
                return
            if self.soar_engine is not None:
                result = await self.soar_engine.manual_unban(ip)
            else:
                auth       = _get_auth()
                was_banned = auth.unban_ip(ip) if auth else False
                result = {"success": True, "ip": ip, "was_banned": was_banned}
            await self._json(writer, 200, result)
        except Exception as exc:
            logger.warning("manual_unban error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_report_abuse(
        self,
        writer: asyncio.StreamWriter,
        body: bytes,
        headers: Dict[str, str],
    ) -> None:
        """
        POST /api/report-abuse -- on-demand AbuseIPDB report.
        engineer or admin role required. Reporting is NEVER automatic.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        try:
            data = json.loads(body or b"{}")
            ip   = data.get("ip", "").strip()
            if not ip:
                await self._json(writer, 400, {"error": "ip required"})
                return
            from src.soc_pipeline.abuseipdb_client import (
                CATEGORY_WEB_ATTACK,
                CATEGORY_BRUTE_FORCE,
                report_malicious_ip,
            )
            result = await report_malicious_ip(
                ip_address=ip,
                categories=[CATEGORY_WEB_ATTACK, CATEGORY_BRUTE_FORCE],
                comment="Analyst on-demand report via A.C.E.S. SOC triage board.",
            )
            # Persist to abuse_reports table
            auth = _get_auth()
            if auth:
                try:
                    auth.log_abuse_report(
                        ip=ip,
                        categories=[CATEGORY_WEB_ATTACK, CATEGORY_BRUTE_FORCE],
                        mode=result.get("mode", "unknown"),
                        success=result.get("success", False),
                        anomaly_score=None,
                        trigger="analyst_manual_report",
                        error=result.get("error"),
                        reported_at_ms=result.get("reported_at_ms"),
                    )
                except Exception as exc:
                    logger.warning("report-abuse: failed to log: %s", exc)
            await self._json(writer, 200, result)
        except Exception as exc:
            logger.warning("report_abuse error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_admin_config(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        """
        GET /api/admin/config -- Admin-only infrastructure info.

        Deception topology (honeytoken content, honeypot ports) has been
        REMOVED from this endpoint and relocated to /api/soc/deception-config
        which is accessible only to the SOC engineer role.  This prevents
        an attacker who compromises admin_user from learning the deception layout.
        """
        session = _get_session_from_request(headers)
        if not _is_admin(session):
            await self._json(writer, 403, {"error": "admin_required"})
            return
        config: dict = {
            "aces_env":    os.environ.get("ACES_ENV", "development"),
            "note": (
                "Deception topology (honeytokens, honeypot ports) has been "
                "moved to the SOC engineer interface for operational security. "
                "Only SOC analysts can view the active deception infrastructure."
            ),
        }
        await self._json(writer, 200, config)

    async def _handle_top_threats(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        """
        GET /api/soc/top-threats -- Top 5 most anomalous IPs. SOC-only.

        Returns IPs with anomaly_score >= 0.50, grouped by IP, sorted by
        highest score descending.  Used by the SOC Top 5 Malicious Users panel.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        auth = _get_auth()
        try:
            rows = auth.get_top_anomalies(limit=5, score_threshold=0.50) if auth else []
            await self._json(writer, 200, rows)
        except Exception as exc:
            logger.warning("top_threats error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    async def _handle_deception_config(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        """
        GET /api/soc/deception-config -- Honeytoken config + honeypot ports.
        SOC engineer role only.  NEVER accessible to admin_user.

        Deception topology is operational-security sensitive: if admin_user
        is compromised the attacker must not learn which ports/files are traps.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        config: dict = {}
        # Load honeytoken file
        try:
            if _HONEY_TOKEN_FILE.exists():
                raw = _HONEY_TOKEN_FILE.read_text(encoding="utf-8")
                config["honeytoken_file"] = str(_HONEY_TOKEN_FILE.resolve())
                try:
                    config["honeytoken_content"] = json.loads(raw)
                except json.JSONDecodeError:
                    config["honeytoken_content"] = raw
            else:
                config["honeytoken_file"] = str(_HONEY_TOKEN_FILE.resolve())
                config["honeytoken_content"] = None
                config["honeytoken_note"] = "File not found -- no honeytoken placed yet."
        except Exception as exc:
            config["honeytoken_error"] = str(exc)

        # Reflect actual listening port status from PortTrap if available
        listening: set[int] = set()
        try:
            # Injected by run.py: dashboard.port_trap reference
            pt = getattr(self, "port_trap", None)
            if pt is not None:
                listening = set(getattr(pt, "listening_ports", []))
        except Exception:
            pass

        def _status(p: int) -> str:
            return "LISTENING" if p in listening else "STANDBY"

        config["honeypot_ports"] = [
            {"port": 3389, "protocol": "TCP", "decoy": "Remote Desktop (RDP)", "status": _status(3389)},
            {"port": 22,   "protocol": "TCP", "decoy": "SSH (Decoy)",          "status": _status(22)},
            {"port": 445,  "protocol": "TCP", "decoy": "SMB (Decoy)",          "status": _status(445)},
        ]
        config["aces_env"] = os.environ.get("ACES_ENV", "development")

        # Include monitor_only mode status
        soar = getattr(self, "soar_engine", None)
        config["monitor_only"] = getattr(soar, "monitor_only", False) if soar else False

        await self._json(writer, 200, config)

    # ------------------------------------------------------------------
    # Deception trip history  (GET /api/deception/history)
    # ------------------------------------------------------------------

    async def _handle_deception_history(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        """
        GET /api/deception/history -- Structured honeytoken trip log.

        Returns rows from the honeytoken_events table merged with
        honeytoken-reason banned_ips entries (backward compat).
        SOC engineer role only.

        Response schema per row:
          ip, trigger, token_path, action, username, recorded_at
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        auth = _get_auth()
        try:
            rows = auth.get_honeytoken_history(limit=200) if auth else []
            await self._json(writer, 200, rows)
        except Exception as exc:
            logger.warning("deception_history error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # Monitor-Only mode toggle  (POST /api/soc/monitor-mode)
    # ------------------------------------------------------------------

    async def _handle_monitor_mode_toggle(
        self,
        writer: asyncio.StreamWriter,
        body: bytes,
        headers: Dict[str, str],
    ) -> None:
        """
        POST /api/soc/monitor-mode -- Toggle SOAR monitor-only mode.

        When monitor_only=True the SOAR engine logs and broadcasts all threat
        events to the SOC dashboard WITHOUT writing ban records or adding IPs
        to the in-memory blacklist.  Banned IPs can continue sending HTTP
        traffic so analysts can observe their full attack behaviour in real time.

        Body: { "enabled": true | false }
        Returns: { "monitor_only": bool, "message": str }

        SOC engineer role required.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return
        soar = getattr(self, "soar_engine", None)
        if soar is None:
            await self._json(writer, 503, {"error": "soar_engine_not_ready"})
            return
        try:
            data    = json.loads(body or b"{}")
            enabled = bool(data.get("enabled", True))
            soar.monitor_only = enabled
            mode_str = "MONITOR-ONLY (alert without banning)" if enabled else "ENFORCE (full containment)"
            logger.info(
                "SOCDashboard: monitor_only set to %s by analyst %s",
                enabled,
                (session or {}).get("username", "unknown"),
            )
            await self._json(writer, 200, {
                "monitor_only": enabled,
                "message": f"SOAR engine switched to {mode_str} mode.",
            })
        except Exception as exc:
            logger.warning("monitor_mode_toggle error: %s", exc)
            await self._json(writer, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # ML Distribution Graph  (GET /api/ml/distribution-graph)
    # ------------------------------------------------------------------

    async def _handle_ml_distribution(
        self, writer: asyncio.StreamWriter, headers: Dict[str, str]
    ) -> None:
        """
        GET /api/ml/distribution-graph

        Fits a fresh BehaviorScorer on a seeded normal-traffic baseline,
        then scores two synthetic test populations:
          - normal_scores : 200 samples drawn from the same normal distribution
          - attack_scores : 200 samples with aggressive anomaly characteristics
            (high request_rate, rapid click intervals, unusual path sequences)
            modelling dirb / nmap style scan traffic.

        Returns JSON:
        {
          "normal_scores":  [float, ...],   // ~200 values near 0.0
          "attack_scores":  [float, ...],   // ~200 values near 0.85–1.0
          "threshold":      float,          // SOAR auto-ban threshold
          "soc_threshold":  float,          // SOC-alert (mid-range) threshold
          "baseline_size":  int,
          "model_params":   { n_estimators, contamination }
        }

        SOC engineer role required.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return

        try:
            import os as _os
            import numpy as np
            from pathlib import Path as _Path
            from src.zero_trust.scorer import BASELINE_THRESHOLD, ESCALATION_THRESHOLD

            SOC_ALERT_THRESHOLD = BASELINE_THRESHOLD  # 0.50
            SAMPLE_N = 300   # samples per class
            RNG_SEED = 42

            # ── Load the production pkl bundle ────────────────────────────
            # The bundle contains:
            #   model   — fitted IsolationForest (200 estimators, contamination=0.02)
            #   scaler  — RobustScaler fitted on BenignTraffic.pcap.csv
            #   feature_columns — ordered list of 29 column names
            _pkl_path = _Path("data") / "behavior_model.pkl"
            if not _pkl_path.exists():
                await self._json(writer, 503, {
                    "error": "behavior_model.pkl not found. "
                             "Run train_behavior_model.py first."
                })
                return

            import joblib
            bundle  = joblib.load(_pkl_path)
            model   = bundle["model"]
            scaler  = bundle["scaler"]
            feat_cols = bundle["feature_columns"]   # 29 column names
            n_feat  = len(feat_cols)

            rng = np.random.default_rng(RNG_SEED)

            # ------------------------------------------------------------------
            # NORMAL SCORES — sampled directly from BenignTraffic.pcap.csv
            # ------------------------------------------------------------------
            # This is the only correct source: real benign flows from the
            # same CSV the model was trained on.  We random-sample SAMPLE_N
            # rows, apply the production RobustScaler, and call
            # decision_function() — identical path to training validation.
            _downloads = _Path(_os.environ.get("USERPROFILE", _Path.home())) / "Downloads"
            _csv_path  = _downloads / "BenignTraffic.pcap.csv"
            _using_real_csv = False

            if _csv_path.exists():
                try:
                    import pandas as pd
                    df_raw = pd.read_csv(_csv_path, low_memory=False)
                    df_raw.columns = df_raw.columns.str.strip()
                    # Keep only the 29 feature columns the model was trained on
                    df_feat = df_raw[feat_cols].copy()
                    df_feat.replace([np.inf, -np.inf], np.nan, inplace=True)
                    df_feat.dropna(inplace=True)
                    # Random sample without replacement
                    n_avail = len(df_feat)
                    idx = rng.choice(n_avail, size=min(SAMPLE_N, n_avail), replace=False)
                    X_normal_raw = df_feat.iloc[idx].values.astype(np.float64)
                    X_normal = scaler.transform(X_normal_raw)
                    raw_normal = model.decision_function(X_normal)
                    _using_real_csv = True
                except Exception as _csv_err:
                    logger.warning(
                        "ml_distribution: CSV load failed (%s) — "
                        "falling back to scaler-space benign simulation.", _csv_err
                    )

            if not _using_real_csv:
                # Fallback: reconstruct plausible benign rows in the SCALED
                # feature space directly.  We use the scaler's center_ (median)
                # and scale_ (IQR) to build samples that sit inside the benign
                # cluster without needing the CSV on disk.
                # Each sample = median + small Gaussian noise (σ = 0.3 × IQR)
                center = scaler.center_           # shape (29,)
                iqr    = scaler.scale_            # shape (29,)
                # In scaled space, benign samples cluster near 0; noise ±0.5
                X_normal_scaled = rng.normal(
                    loc=0.0, scale=0.4,
                    size=(SAMPLE_N, n_feat)
                ).astype(np.float64)
                raw_normal = model.decision_function(X_normal_scaled)

            # Normalise: score = 0.5 - clip(raw, -0.5, 0.5)
            normal_scores: list[float] = [
                round(float(0.5 - np.clip(r, -0.5, 0.5)), 6)
                for r in raw_normal
            ]

            # ------------------------------------------------------------------
            # ATTACK SCORES — synthetic scanner flows in 29-feature space
            # ------------------------------------------------------------------
            # We build attack rows directly in the ORIGINAL (unscaled) feature
            # space using distributions derived from known Nmap/Gobuster/Dirbuster
            # traffic characteristics, then apply the production RobustScaler.
            #
            # Feature index reference (matches FEATURE_COLUMNS order):
            #  0  Rate            — packets/sec
            #  1  IAT             — inter-arrival time (s)
            #  2  Variance        — IAT variance
            #  3  Header_Length
            #  4  AVG             — avg packet size
            #  5  Std             — std packet size
            #  6  Tot size        — total bytes
            #  7  Min             — min packet size
            #  8  Max             — max packet size
            #  9  Number          — packet count
            # 10  Time_To_Live
            # 11  Protocol Type
            # 12  fin_flag_number
            # 13  syn_flag_number  ← key scanner indicator
            # 14  rst_flag_number
            # 15  psh_flag_number
            # 16  ack_flag_number
            # 17  ece_flag_number
            # 18  cwr_flag_number
            # 19  syn_count        ← key scanner indicator
            # 20  fin_count
            # 21  rst_count
            # 22  ack_count
            # 23  TCP
            # 24  UDP
            # 25  HTTP
            # 26  HTTPS
            # 27  DNS
            # 28  ICMP
            #
            # Three scanner profiles are mixed 1:1:1 so scores spread across
            # a range rather than collapsing to one point.

            def _attack_row(i: int) -> list[float]:
                profile = i % 3

                if profile == 0:
                    # ── SYN flood / Nmap port scan ────────────────────────
                    rate     = float(rng.uniform(200, 600))
                    iat      = float(rng.uniform(0.001, 0.005))
                    variance = float(rng.uniform(0.0, 0.00002))
                    hdr_len  = float(rng.uniform(20, 40))
                    avg_pkt  = float(rng.uniform(54, 78))
                    std_pkt  = float(rng.uniform(0, 8))
                    tot_size = avg_pkt * float(rng.integers(50, 200))
                    min_pkt  = 54.0
                    max_pkt  = float(rng.uniform(74, 90))
                    number   = float(rng.integers(50, 200))
                    ttl      = float(rng.choice(np.array([64, 128])))
                    proto    = 6.0   # TCP
                    fin, syn, rst, psh, ack, ece, cwr = 0,1,0,0,0,0,0
                    syn_c    = number
                    fin_c = rst_c = ack_c = 0.0
                    tcp, udp, http, https, dns, icmp = 1,0,0,0,0,0

                elif profile == 1:
                    # ── Directory brute-force / Gobuster ─────────────────
                    rate     = float(rng.uniform(30, 120))
                    iat      = float(rng.uniform(0.008, 0.033))
                    variance = float(rng.uniform(0.0, 0.0001))
                    hdr_len  = float(rng.uniform(40, 60))
                    avg_pkt  = float(rng.uniform(180, 280))
                    std_pkt  = float(rng.uniform(10, 40))
                    tot_size = avg_pkt * float(rng.integers(20, 100))
                    min_pkt  = float(rng.uniform(60, 100))
                    max_pkt  = float(rng.uniform(400, 700))
                    number   = float(rng.integers(20, 100))
                    ttl      = float(rng.choice(np.array([64, 128])))
                    proto    = 6.0
                    fin, syn, rst, psh, ack, ece, cwr = 0,0,0,1,1,0,0
                    syn_c    = 0.0
                    fin_c    = 0.0
                    rst_c    = 0.0
                    ack_c    = number
                    tcp, udp, http, https, dns, icmp = 1,0,1,0,0,0

                else:
                    # ── ICMP sweep / ping scan ────────────────────────────
                    rate     = float(rng.uniform(50, 300))
                    iat      = float(rng.uniform(0.003, 0.02))
                    variance = float(rng.uniform(0.0, 0.00005))
                    hdr_len  = float(rng.uniform(8, 20))
                    avg_pkt  = float(rng.uniform(74, 98))
                    std_pkt  = float(rng.uniform(0, 5))
                    tot_size = avg_pkt * float(rng.integers(30, 150))
                    min_pkt  = 74.0
                    max_pkt  = float(rng.uniform(84, 102))
                    number   = float(rng.integers(30, 150))
                    ttl      = float(rng.choice(np.array([64, 128, 255])))
                    proto    = 1.0   # ICMP
                    fin, syn, rst, psh, ack, ece, cwr = 0,0,0,0,0,0,0
                    syn_c = fin_c = rst_c = ack_c = 0.0
                    tcp, udp, http, https, dns, icmp = 0,0,0,0,0,1

                return [
                    rate, iat, variance,
                    hdr_len, avg_pkt, std_pkt, tot_size, min_pkt, max_pkt,
                    number, ttl, proto,
                    float(fin), float(syn), float(rst), float(psh),
                    float(ack), float(ece), float(cwr),
                    syn_c, fin_c, rst_c, ack_c,
                    float(tcp), float(udp), float(http),
                    float(https), float(dns), float(icmp),
                ]

            X_attack_raw = np.array(
                [_attack_row(i) for i in range(SAMPLE_N)], dtype=np.float64
            )
            # Clip extreme values before scaling to avoid RobustScaler overflow
            X_attack_raw = np.nan_to_num(X_attack_raw, nan=0.0, posinf=1e6, neginf=0.0)
            X_attack = scaler.transform(X_attack_raw)
            raw_attack = model.decision_function(X_attack)
            attack_scores: list[float] = [
                round(float(0.5 - np.clip(r, -0.5, 0.5)), 6)
                for r in raw_attack
            ]

            # ── Statistics ────────────────────────────────────────────────
            def _stats(scores: list[float]) -> dict:
                if not scores:
                    return {}
                s = sorted(scores)
                n = len(s)
                mean = sum(s) / n
                variance_s = sum((x - mean) ** 2 for x in s) / n
                std = variance_s ** 0.5
                return {
                    "mean":             round(mean,              4),
                    "std":              round(std,               4),
                    "min":              round(s[0],              4),
                    "max":              round(s[-1],             4),
                    "p50":              round(s[n // 2],         4),
                    "p90":              round(s[int(n * 0.9)],   4),
                    "p99":              round(s[min(int(n * 0.99), n-1)], 4),
                    "above_threshold":  sum(1 for x in scores if x >= ESCALATION_THRESHOLD),
                }

            payload = {
                "normal_scores":  normal_scores,
                "attack_scores":  attack_scores,
                "threshold":      ESCALATION_THRESHOLD,
                "soc_threshold":  SOC_ALERT_THRESHOLD,
                "baseline_size":  SAMPLE_N,
                "test_size":      SAMPLE_N,
                "model_params":   {
                    "n_estimators":  bundle.get("n_estimators", 200),
                    "contamination": bundle.get("contamination", 0.02),
                },
                "model_source":   "csv+pkl" if _using_real_csv else "pkl_scaled_fallback",
                "normal_stats":   _stats(normal_scores),
                "attack_stats":   _stats(attack_scores),
            }
            await self._json(writer, 200, payload)

        except Exception as exc:
            logger.warning("ml_distribution error: %s", exc, exc_info=True)
            await self._json(writer, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # Telemetry Score Endpoint  (POST /api/telemetry/score)
    # ------------------------------------------------------------------

    async def _handle_telemetry_score(
        self,
        writer: asyncio.StreamWriter,
        body: bytes,
        client_ip: str,
        headers: dict,
    ) -> None:
        """
        POST /api/telemetry/score

        Scores a traffic telemetry sample using the production pkl
        IsolationForest (29-feature RobustScaler pipeline) and returns
        the structured payload for the SOC Baseline Timeline chart.

        Accepts JSON body:
          {
            "request_rate_per_sec"   : float   -- packets/sec (key discriminator)
            "click_speed_intervals"  : [float] -- ms between clicks (drives IAT)
            "session_duration_ms"    : float   -- session age in ms
            "page_path_weights"      : [float] -- optional, drives TTL proxy
            "sequence_transitions"   : [int]   -- optional, drives proto proxy
          }

        The endpoint builds a 29-element flow-feature vector directly
        (same feature space as BenignTraffic.pcap.csv) rather than going
        through the 11-feature TelemetryVector bridge, so scores respond
        accurately to slider changes.

        Returns:
          {
            "anomaly_score"      : float  -- score in [0, 1]
            "baseline_threshold" : float  -- 0.50
            "is_anomaly"         : bool
            "timestamp"          : str    -- ISO 8601 UTC
          }

        SOC engineer role required.
        """
        session = _get_session_from_request(headers)
        if not _can_access_soc(session):
            await self._json(writer, 403, {"error": "soc_access_required"})
            return

        try:
            import datetime
            import math
            import numpy as np
            from pathlib import Path as _Path
            from src.zero_trust.scorer import BASELINE_THRESHOLD

            data = json.loads(body or b"{}")

            # ── Parse slider inputs ───────────────────────────────────────
            rate      = float(data.get("request_rate_per_sec", 2.0))
            clicks    = data.get("click_speed_intervals", [200.0, 200.0])
            if not clicks:
                clicks = [200.0]
            sess_ms   = float(data.get("session_duration_ms", 5000.0))
            pw        = data.get("page_path_weights", [0.5, 0.5])
            seqs      = data.get("sequence_transitions", [1, 2])

            mean_click = sum(clicks) / len(clicks)
            max_click  = max(clicks)
            min_click  = min(clicks)
            var_click  = sum((x - mean_click)**2 for x in clicks) / max(len(clicks), 1)
            std_click  = math.sqrt(var_click) if var_click > 0 else 0.0
            n_clicks   = float(len(clicks))

            # ── Build 29-feature flow vector (same schema as FEATURE_COLUMNS) ──
            # Feature names:
            #  Rate, IAT, Variance,
            #  Header_Length, AVG, Std, Tot_size, Min, Max,
            #  Number, Time_To_Live, Protocol_Type,
            #  fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, ece_flag, cwr_flag,
            #  syn_count, fin_count, rst_count, ack_count,
            #  TCP, UDP, HTTP, HTTPS, DNS, ICMP

            # Rate: direct (pps)
            f_rate = max(0.0, min(rate, 10000.0))

            # IAT: inter-arrival time in seconds
            # Benign: mean click ~200 ms → IAT ~0.007 s (benign median)
            # Attack: mean click ~5 ms  → IAT ~0.0001 s
            f_iat = max(1e-7, mean_click / 1000.0)

            # Variance of IAT
            f_variance = var_click / 1_000_000.0   # ms² → s²

            # Packet size proxies — derived from rate
            # High rate = small probing packets (SYN ~60 bytes)
            # Low rate  = normal payload (~500 bytes)
            is_scanning = f_rate > 50.0 or mean_click < 20.0
            f_avg    = 60.0 if is_scanning else max(100.0, min(1400.0,
                           500.0 - (f_rate / 10.0)))
            f_std    = std_click * 1.5
            f_min    = 54.0 if is_scanning else max(60.0, f_avg * 0.5)
            f_max    = 90.0 if is_scanning else min(9000.0, f_avg * 3.0)
            f_tot    = f_avg * max(n_clicks, 1.0)
            f_hdr    = 24.0 if is_scanning else 40.0

            # Number of packets in the flow
            f_number = n_clicks

            # TTL: benign clusters at 64/128; extreme page weights → unusual TTL
            pw0 = float(pw[0]) if pw else 0.5
            f_ttl = max(1.0, pw0 * 250.0)

            # Protocol type
            seq0 = int(seqs[0]) if seqs else 6
            f_proto = float(seq0 % 17)

            # TCP flags
            f_syn = 1.0 if is_scanning else 0.0
            f_ack = 0.0 if is_scanning else 1.0
            f_psh = 0.0
            f_fin = f_rst = f_ece = f_cwr = 0.0
            f_syn_c = n_clicks if is_scanning else 0.0
            f_ack_c = n_clicks if not is_scanning else 0.0
            f_fin_c = f_rst_c = 0.0

            # Protocol presence
            f_tcp   = 1.0
            f_udp   = 1.0 if f_proto == 17.0 else 0.0
            f_http  = 0.0 if is_scanning else 1.0
            f_https = 0.0 if is_scanning else 1.0
            f_dns   = 0.0
            f_icmp  = 0.0

            flow_vec = [
                f_rate, f_iat, f_variance,
                f_hdr, f_avg, f_std, f_tot, f_min, f_max,
                f_number, f_ttl, f_proto,
                f_fin, f_syn, f_rst, f_psh, f_ack, f_ece, f_cwr,
                f_syn_c, f_fin_c, f_rst_c, f_ack_c,
                f_tcp, f_udp, f_http, f_https, f_dns, f_icmp,
            ]

            # ── Load pkl and score ────────────────────────────────────────
            _pkl_path = _Path("data") / "behavior_model.pkl"
            if not _pkl_path.exists():
                # Fallback: use TelemetryVector path if no pkl
                from src.zero_trust.models import TelemetryVector
                from src.zero_trust.validation import validate_telemetry_vector
                if self.portal_shell is None:
                    await self._json(writer, 503, {"error": "scorer_not_ready"})
                    return
                click_vals = clicks if clicks else [200.0]
                vector = TelemetryVector(
                    click_speed_intervals=click_vals,
                    page_path_weights=pw if pw else [0.5, 0.5],
                    sequence_transitions=[int(s) for s in seqs] if seqs else [1, 2],
                    session_duration_ms=max(0.0, sess_ms),
                    request_rate_per_sec=max(0.0, min(rate, 10000.0)),
                )
                validate_telemetry_vector(vector)
                scorer = self.portal_shell._scorer
                payload = scorer.score_detailed(vector)
                await self._json(writer, 200, payload)
                return

            import joblib
            bundle = joblib.load(_pkl_path)
            model  = bundle["model"]
            scaler = bundle["scaler"]

            X_raw = np.array([flow_vec], dtype=np.float64)
            X_raw = np.nan_to_num(X_raw, nan=0.0, posinf=1e6, neginf=0.0)
            X = scaler.transform(X_raw)
            raw = float(model.decision_function(X)[0])
            score = float(max(0.0, min(1.0, 0.5 - max(-0.5, min(0.5, raw)))))

            payload = {
                "anomaly_score":      round(score, 6),
                "baseline_threshold": BASELINE_THRESHOLD,
                "is_anomaly":         score >= BASELINE_THRESHOLD,
                "timestamp":          datetime.datetime.utcnow().isoformat() + "Z",
            }
            await self._json(writer, 200, payload)

        except Exception as exc:
            logger.warning("telemetry_score error: %s", exc, exc_info=True)
            await self._json(writer, 500, {"error": str(exc)})

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_headers(raw: bytes) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for line in raw.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                out[k.strip().lower().decode("utf-8", errors="replace")] = \
                    v.strip().decode("utf-8", errors="replace")
        return out

    @staticmethod
    def _extract_body(raw: bytes) -> bytes:
        if b"\r\n\r\n" in raw:
            return raw.split(b"\r\n\r\n", 1)[1]
        return b""

    async def _http_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes,
        content_type: str = "text/plain",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        phrases = {
            200: "OK", 204: "No Content", 302: "Found",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 503: "Service Unavailable",
        }
        phrase = phrases.get(status, "OK")
        lines = [
            f"HTTP/1.1 {status} {phrase}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Access-Control-Allow-Origin: *",
            "Access-Control-Allow-Headers: Content-Type, Authorization",
            "Access-Control-Allow-Methods: GET, POST, OPTIONS",
            "Connection: close",
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("")
        header = "\r\n".join(lines).encode("utf-8")
        try:
            writer.write(header + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def _json(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        payload: Any,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=True, default=str).encode("utf-8")
        await self._http_response(writer, status, body, "application/json")

    async def _redirect(
        self,
        writer: asyncio.StreamWriter,
        location: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        hdrs = {"Location": location}
        if extra_headers:
            hdrs.update(extra_headers)
        await self._http_response(writer, 302, b"", "text/plain", extra_headers=hdrs)

    # ------------------------------------------------------------------
    # WebSocket
    # ------------------------------------------------------------------

    async def _ws_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        headers: Dict[str, str],
        client_ip: str,
    ) -> None:
        key    = headers.get("sec-websocket-key", "")
        accept = _ws_accept_key(key)
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("utf-8")
        try:
            writer.write(resp)
            await writer.drain()
        except Exception:
            writer.close()
            return

        self._ws_clients.add(writer)
        logger.info("SOCDashboardServer: WS client %s (%d total)",
                    client_ip, len(self._ws_clients))
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(256), timeout=30.0)
                    if not chunk:
                        # Client closed the connection cleanly (EOF)
                        break
                except asyncio.TimeoutError:
                    # No data for 30 s -- send a WebSocket ping to keep alive
                    await self._ws_ping(writer)
                except asyncio.CancelledError:
                    # Server shutdown -- exit the read loop cleanly
                    raise
        except asyncio.CancelledError:
            # Propagate so the task framework marks this task as cancelled.
            # The finally block below still runs and cleans up the socket.
            raise
        except (ConnectionResetError, BrokenPipeError, OSError,
                asyncio.IncompleteReadError):
            pass
        finally:
            self._ws_clients.discard(writer)
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    async def _ws_ping(writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(bytes([0x89, 0x00]))
            await writer.drain()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Broadcast loop
    # ------------------------------------------------------------------

    async def broadcast_loop(self) -> None:
        logger.info("SOCDashboardServer: broadcast loop started.")
        try:
            async for event in self._event_hub.subscribe():
                self._alert_count += 1
                if self._ws_clients:
                    try:
                        frame = self._make_ws_frame(self._serialise(event))
                        await self._broadcast(frame)
                    except Exception as exc:
                        # A single bad event must not kill the broadcast loop.
                        logger.warning(
                            "SOCDashboardServer: failed to broadcast event: %s", exc
                        )
        except asyncio.CancelledError:
            logger.info("SOCDashboardServer: broadcast loop cancelled cleanly.")
            raise  # always re-raise so the task is properly cancelled
        except Exception as exc:
            logger.error("SOCDashboardServer: broadcast loop error: %s", exc, exc_info=True)

    @staticmethod
    def _serialise(event: AlertEvent) -> bytes:
        payload = event.to_json()
        payload["server_ts_ms"] = time.time() * 1000
        # Include current unread triage count so clients can update badge
        # without an extra HTTP round-trip on every alert.
        try:
            from src.auth import db as _auth_db
            payload["unread_count"] = _auth_db.get_unread_triage_count()
        except Exception:
            pass
        return json.dumps(payload, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _make_ws_frame(data: bytes) -> bytes:
        n = len(data)
        if n <= 125:
            hdr = bytes([0x81, n])
        elif n <= 65535:
            hdr = bytes([0x81, 126]) + struct.pack(">H", n)
        else:
            hdr = bytes([0x81, 127]) + struct.pack(">Q", n)
        return hdr + data

    async def _broadcast(self, frame: bytes) -> None:
        dead = []
        for w in list(self._ws_clients):
            try:
                w.write(frame)
                await w.drain()
            except Exception:
                dead.append(w)
        for w in dead:
            self._ws_clients.discard(w)

    @property
    def client_count(self) -> int:
        return len(self._ws_clients)
