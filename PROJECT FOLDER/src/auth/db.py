# src/auth/db.py
"""
Persistent SQLite authentication and IP-ban store.

Tables
------
users      -- hashed credentials for three built-in accounts
sessions   -- JWT-like token -> session binding
banned_ips -- hard-banned IP addresses (honeytoken / SOAR enforcement)

All writes complete in a single synchronous SQLite call so ban enforcement
stays well under 1 ms (Python dict + sqlite3 are both in-process).

Thread safety: sqlite3 is used in WAL mode with check_same_thread=False;
calls are wrapped in a threading.Lock to prevent concurrent writes from
separate asyncio tasks.
"""

from __future__ import annotations

import hashlib
import logging
import re as _re
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Resolved at import time; can be overridden before init_db() for tests
_DEFAULT_DB_PATH = Path("data") / "aces_production.db"

# Session TTL: 8 hours of inactivity before a session is considered expired.
# get_session() checks created_at + SESSION_TTL_SECONDS against the current
# time and returns None (expired) without touching the revoked flag.
SESSION_TTL_SECONDS: float = 8 * 3600  # 8 hours

# Module-level connection (singleton per process)
_conn: Optional[sqlite3.Connection] = None
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash(password: str) -> str:
    """SHA-256 hex digest of password.  Production would use bcrypt/argon2."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def init_db(db_path: Path = _DEFAULT_DB_PATH) -> None:
    """
    Open (or create) the SQLite database and seed default users.
    Safe to call multiple times - uses IF NOT EXISTS.
    """
    global _conn
    db_path.parent.mkdir(parents=True, exist_ok=True)

    _conn = sqlite3.connect(
        str(db_path),
        check_same_thread=False,
        isolation_level=None,  # autocommit
    )
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")

    _conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username    TEXT PRIMARY KEY,
            pwd_hash    TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'Guest'
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            username    TEXT NOT NULL,
            role        TEXT NOT NULL,
            ip          TEXT NOT NULL,
            created_at  REAL NOT NULL,
            expires_at  REAL NOT NULL DEFAULT 0,
            revoked     INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS banned_ips (
            ip          TEXT PRIMARY KEY,
            reason      TEXT NOT NULL,
            banned_at   REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS abuse_reports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip              TEXT    NOT NULL,
            categories      TEXT    NOT NULL,
            mode            TEXT    NOT NULL,
            success         INTEGER NOT NULL,
            anomaly_score   REAL,
            trigger         TEXT,
            error           TEXT,
            reported_at_ms  REAL    NOT NULL
        );
    """)

    # Seed built-in users (idempotent)
    _seed_users()
    # Migrate schema: add expires_at column if it was created before this version
    _migrate_schema()
    logger.info("AuthDB: initialised at %s", db_path)


def _migrate_schema() -> None:
    """Non-destructive schema migrations for existing databases."""
    assert _conn is not None
    # Add expires_at to sessions if it doesn't exist yet
    cols = [row[1] for row in _conn.execute("PRAGMA table_info(sessions)").fetchall()]
    if "expires_at" not in cols:
        _conn.execute("ALTER TABLE sessions ADD COLUMN expires_at REAL NOT NULL DEFAULT 0")
        logger.info("AuthDB: migrated sessions table -- added expires_at column")

    # Create triage_reads table so the SOC badge tracks unread/new items.
    # A row in this table means the event (identified by event_key) has been
    # viewed by at least one SOC analyst.  The badge counter = total events
    # minus the count of rows in this table (events not yet in triage_reads).
    _conn.executescript("""
        CREATE TABLE IF NOT EXISTS triage_reads (
            event_key   TEXT PRIMARY KEY,   -- '<table>:<row_id_or_ip>:<ts>'
            analyst     TEXT,               -- username who marked it read
            read_at     REAL NOT NULL       -- unix epoch timestamp
        );
    """)


def _seed_users() -> None:
    """
    Seed the three canonical test accounts on first startup.
    Uses INSERT OR IGNORE so existing rows are never overwritten.

    Roles
    -----
    engineer  -- soc_engineer   -- SOC board access (real-time threat stream)
    admin     -- admin_user     -- Admin panel (infrastructure / deception config)
    user      -- employee_test  -- Standard employee portal only
    """
    assert _conn is not None
    accounts = [
        ("soc_engineer",  "EngineerPass3!",     "engineer"),
        ("admin_user",    "AdminPass3!",         "admin"),
        ("employee_test", "EmployeeSecure123!",  "user"),
    ]
    for username, password, role in accounts:
        _conn.execute(
            "INSERT OR IGNORE INTO users (username, pwd_hash, role) VALUES (?,?,?)",
            (username, _hash(password), role),
        )


def get_conn() -> sqlite3.Connection:
    assert _conn is not None, "Call init_db() before using AuthDB"
    return _conn


# ---------------------------------------------------------------------------
# User authentication
# ---------------------------------------------------------------------------

def verify_credentials(username: str, password: str) -> Optional[str]:
    """
    Verify username/password.

    Returns
    -------
    str | None
        The user's role on success, None on failure.
    """
    with _lock:
        row = get_conn().execute(
            "SELECT pwd_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    stored_hash, role = row
    if secrets.compare_digest(stored_hash, _hash(password)):
        return role
    return None


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def create_session(username: str, role: str, ip: str) -> str:
    """
    Create a new session token and persist it.

    Returns
    -------
    str
        Opaque 32-byte hex token.
    """
    token      = secrets.token_hex(32)
    now        = time.time()
    expires_at = now + SESSION_TTL_SECONDS
    with _lock:
        get_conn().execute(
            "INSERT INTO sessions (token, username, role, ip, created_at, expires_at) "
            "VALUES (?,?,?,?,?,?)",
            (token, username, role, ip, now, expires_at),
        )
    logger.info("AuthDB: session created for %s (role=%s) from %s expires_at=%s",
                username, role, ip, expires_at)
    return token


def get_session(token: str) -> Optional[dict]:
    """
    Retrieve a non-revoked, non-expired session by token.

    Returns
    -------
    dict | None
        Keys: token, username, role, ip, created_at, expires_at
    """
    with _lock:
        row = get_conn().execute(
            "SELECT token, username, role, ip, created_at, expires_at FROM sessions "
            "WHERE token = ? AND revoked = 0",
            (token,),
        ).fetchone()
    if row is None:
        return None
    token_, username, role, ip, created_at, expires_at = row
    # Enforce TTL: expires_at == 0 means legacy row (no TTL set); allow it.
    # Any positive expires_at that is in the past means the session is expired.
    if expires_at and expires_at > 0 and time.time() > expires_at:
        logger.info("AuthDB: session for %s expired -- auto-revoking.", username)
        with _lock:
            get_conn().execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (token_,))
        return None
    return {
        "token": token_, "username": username, "role": role,
        "ip": ip, "created_at": created_at, "expires_at": expires_at,
    }


def revoke_session(token: str) -> None:
    """Mark a session as revoked."""
    with _lock:
        get_conn().execute(
            "UPDATE sessions SET revoked = 1 WHERE token = ?", (token,)
        )


def revoke_sessions_for_ip(ip: str) -> int:
    """
    Revoke ALL active sessions from *ip*.

    Returns
    -------
    int
        Number of sessions revoked.
    """
    with _lock:
        cur = get_conn().execute(
            "UPDATE sessions SET revoked = 1 WHERE ip = ? AND revoked = 0",
            (ip,),
        )
    count = cur.rowcount
    if count:
        logger.warning("AuthDB: revoked %d session(s) for IP %s", count, ip)
    return count


# ---------------------------------------------------------------------------
# IP ban enforcement
# ---------------------------------------------------------------------------

def ban_ip(ip: str, reason: str = "SOAR enforcement") -> None:
    """
    Hard-ban an IP address.  Idempotent - repeated calls are safe.
    Completes in < 1 ms (single SQLite REPLACE).
    """
    with _lock:
        get_conn().execute(
            "INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at) VALUES (?,?,?)",
            (ip, reason, time.time()),
        )
    logger.warning("AuthDB: IP %s banned (%s)", ip, reason)


def is_banned(ip: str) -> bool:
    """Return True if the IP is currently banned."""
    with _lock:
        row = get_conn().execute(
            "SELECT 1 FROM banned_ips WHERE ip = ?", (ip,)
        ).fetchone()
    return row is not None


def get_all_banned_ips() -> list[dict]:
    """Return all banned IPs as a list of dicts."""
    with _lock:
        rows = get_conn().execute(
            "SELECT ip, reason, banned_at FROM banned_ips ORDER BY banned_at DESC"
        ).fetchall()
    return [{"ip": r[0], "reason": r[1], "banned_at": r[2]} for r in rows]


def unban_ip(ip: str) -> bool:
    """
    Remove an IP address from the banned_ips table.

    This is the backend of the analyst [Remove Ban] action.
    Returns True if the IP was found and removed, False if it was not banned.
    """
    with _lock:
        cur = get_conn().execute(
            "DELETE FROM banned_ips WHERE ip = ?", (ip,)
        )
    removed = cur.rowcount > 0
    if removed:
        logger.info("AuthDB: IP %s unbanned by analyst.", ip)
    return removed


def get_active_sessions() -> list[dict]:
    """Return all non-revoked, non-expired sessions."""
    now = time.time()
    with _lock:
        rows = get_conn().execute(
            "SELECT token, username, role, ip, created_at FROM sessions "
            "WHERE revoked = 0 AND (expires_at = 0 OR expires_at > ?) "
            "ORDER BY created_at DESC",
            (now,),
        ).fetchall()
    return [{"token": r[0], "username": r[1], "role": r[2],
             "ip": r[3], "created_at": r[4]} for r in rows]


def get_event_log(limit: int = 200) -> list[dict]:
    """
    Return a unified event log for the SOC triage queue.

    Merges banned_ips, honeytoken_events, and abuse_reports into a
    scannable list ordered by most-recent first.  Each row contains
    enough context to populate the triage detail panel without a second
    DB call.
    """
    with _lock:
        conn = get_conn()

        # Banned IPs with session info joined where available
        ban_rows = conn.execute(
            """
            SELECT
                b.ip,
                b.reason         AS trigger,
                b.banned_at      AS event_ts,
                s.username,
                s.role,
                NULL             AS anomaly_score,
                'ban'            AS event_type
            FROM banned_ips b
            LEFT JOIN sessions s ON s.ip = b.ip AND s.revoked = 0
            ORDER BY b.banned_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        # Honeytoken trips (includes monitor-only events that never write to banned_ips)
        try:
            honey_rows = conn.execute(
                """
                SELECT
                    h.ip,
                    h.trigger        AS trigger,
                    h.recorded_at    AS event_ts,
                    h.username,
                    NULL             AS role,
                    NULL             AS anomaly_score,
                    'honeytoken'     AS event_type,
                    h.action
                FROM honeytoken_events h
                ORDER BY h.recorded_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        except Exception:
            honey_rows = []

        # Abuse report history -- join sessions to get username/role
        abuse_rows = conn.execute(
            """
            SELECT
                ar.ip,
                ar.trigger       AS trigger,
                ar.reported_at_ms / 1000.0 AS event_ts,
                s.username,
                s.role,
                ar.anomaly_score,
                'abuse_report'   AS event_type
            FROM abuse_reports ar
            LEFT JOIN sessions s ON s.ip = ar.ip AND s.revoked = 0
            ORDER BY ar.reported_at_ms DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    events = []
    # Collect all viewed keys for O(1) lookup
    with _lock:
        read_keys = {
            row[0] for row in get_conn().execute(
                "SELECT event_key FROM triage_reads"
            ).fetchall()
        }

    def _ekey(table: str, identifier: str, ts: float) -> str:
        """Stable event key: '<table>:<identifier>:<ts_int>'."""
        return f"{table}:{identifier}:{int(ts or 0)}"

    for r in ban_rows:
        key = _ekey("ban", r[0], r[2])
        events.append({
            "ip": r[0], "trigger": r[1], "event_ts": r[2],
            "username": r[3], "role": r[4],
            "anomaly_score": r[5], "event_type": r[6],
            "banned": True,
            "event_key": key,
            "viewed": key in read_keys,
        })
    for r in honey_rows:
        action = r[7] if len(r) > 7 else ""
        key = _ekey("honeytoken", r[0], r[2])
        events.append({
            "ip": r[0], "trigger": r[1], "event_ts": r[2],
            "username": r[3] or "unknown", "role": r[4] or "unknown",
            "anomaly_score": r[5], "event_type": r[6],
            "banned": action == "BANNED",
            "event_key": key,
            "viewed": key in read_keys,
        })
    for r in abuse_rows:
        key = _ekey("abuse", r[0], r[2])
        events.append({
            "ip": r[0], "trigger": r[1], "event_ts": r[2],
            "username": r[3], "role": r[4],
            "anomaly_score": r[5], "event_type": r[6],
            "banned": False,
            "event_key": key,
            "viewed": key in read_keys,
        })
    # Sort merged list newest-first
    events.sort(key=lambda e: e["event_ts"] or 0, reverse=True)
    return events[:limit]


# ---------------------------------------------------------------------------
# Triage read/unread tracking
# ---------------------------------------------------------------------------

def mark_triage_read(event_key: str, analyst: str = "soc_engineer") -> bool:
    """
    Mark a triage event as viewed/read by an analyst.

    Parameters
    ----------
    event_key : str  -- stable key returned in get_event_log() rows
    analyst   : str  -- username of the SOC analyst

    Returns
    -------
    bool  True if the record was newly inserted (was unread), False if already read.
    """
    if _conn is None:
        return False
    # Ensure table exists (belt-and-suspenders; also created in _migrate_schema)
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS triage_reads (
                event_key TEXT PRIMARY KEY,
                analyst   TEXT,
                read_at   REAL NOT NULL
            )
        """)
    try:
        with _lock:
            cur = get_conn().execute(
                "INSERT OR IGNORE INTO triage_reads (event_key, analyst, read_at) VALUES (?,?,?)",
                (event_key, analyst, time.time()),
            )
        return cur.rowcount > 0
    except Exception as exc:
        logger.warning("DB: mark_triage_read failed: %s", exc)
        return False


def get_unread_triage_count(limit: int = 200) -> int:
    """
    Return the number of triage events in the current get_event_log() window
    that have NOT been marked as read by an analyst.

    Uses the same event_key derivation as get_event_log() so only events
    visible in the triage queue contribute to the badge count.
    """
    if _conn is None:
        return 0
    try:
        # Re-use get_event_log to get the same slice analysts actually see
        events = get_event_log(limit=limit)
        read_keys: set[str] = set()
        with _lock:
            rows = get_conn().execute(
                "SELECT event_key FROM triage_reads"
            ).fetchall()
            read_keys = {r[0] for r in rows}
        unread = sum(1 for e in events if e.get("event_key") not in read_keys)
        return max(0, unread)
    except Exception as exc:
        logger.warning("DB: get_unread_triage_count failed: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# AbuseIPDB report log
# ---------------------------------------------------------------------------

def log_abuse_report(
    ip: str,
    categories: list,
    mode: str,
    success: bool,
    anomaly_score: float | None = None,
    trigger: str | None = None,
    error: str | None = None,
    reported_at_ms: float | None = None,
) -> None:
    """
    Persist an AbuseIPDB reporting attempt to the abuse_reports table.

    Called from SOAREngine immediately after report_malicious_ip() resolves
    so every outbound (or mock) report is traceable in the SOC dashboard.

    Parameters
    ----------
    ip              : str   -- IP address that was reported
    categories      : list  -- AbuseIPDB category codes used
    mode            : str   -- 'live' or 'offline_mock'
    success         : bool  -- whether the report was accepted
    anomaly_score   : float -- Zero Trust score that triggered the report
    trigger         : str   -- event type (AI_ANOMALY / HONEYTOKEN / PORT_TRAP)
    error           : str   -- error string on failure, None on success
    reported_at_ms  : float -- Unix epoch ms timestamp
    """
    if _conn is None:
        return
    ts = reported_at_ms if reported_at_ms is not None else (__import__("time").time() * 1000)
    try:
        with _lock:
            get_conn().execute(
                "INSERT INTO abuse_reports "
                "(ip, categories, mode, success, anomaly_score, trigger, error, reported_at_ms) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    ip,
                    ",".join(str(c) for c in categories),
                    mode,
                    1 if success else 0,
                    anomaly_score,
                    trigger,
                    error,
                    ts,
                ),
            )
    except Exception as exc:  # pragma: no cover
        logger.warning("AuthDB: failed to log abuse report: %s", exc)


def get_abuse_reports(limit: int = 50) -> list[dict]:
    """Return the most recent AbuseIPDB report log entries."""
    with _lock:
        rows = get_conn().execute(
            "SELECT ip, categories, mode, success, anomaly_score, trigger, "
            "error, reported_at_ms FROM abuse_reports "
            "ORDER BY reported_at_ms DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "ip": r[0], "categories": r[1], "mode": r[2],
            "success": bool(r[3]), "anomaly_score": r[4],
            "trigger": r[5], "error": r[6], "reported_at_ms": r[7],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# User registration (self-service sign-up)
# ---------------------------------------------------------------------------

def register_user(username: str, password: str, role: str = "user") -> bool:
    """
    Create a new user account.

    Parameters
    ----------
    username : str  -- must be 3-32 chars, letters/digits/underscore/dash/dot
    password : str  -- plain-text; stored as SHA-256 hash
    role     : str  -- defaults to 'user' for self-registered accounts

    Returns
    -------
    bool
        True  if the account was created successfully.
        False if the username is already taken (UNIQUE constraint).
    """
    if not username or not password:
        return False
    if not _re.match(r'^[a-zA-Z0-9_.\-]{3,32}$', username):
        return False
    pwd_hash = _hash(password)
    try:
        with _lock:
            get_conn().execute(
                "INSERT INTO users (username, pwd_hash, role) VALUES (?,?,?)",
                (username, pwd_hash, role),
            )
        logger.info("AuthDB: new user '%s' registered (role=%s).", username, role)
        return True
    except sqlite3.IntegrityError:
        # UNIQUE constraint on username -- account already exists
        return False


# ---------------------------------------------------------------------------
# Live metrics (DB-backed counters for the SOC dashboard)
# ---------------------------------------------------------------------------

def get_metrics() -> dict:
    """
    Return persistent counters calculated from the live database state.

    These values survive page reloads and process restarts, unlike the
    in-memory counters that reset to zero when the browser reconnects.

    Returns
    -------
    dict with keys:
        active_sessions   -- non-revoked, non-expired session count
        banned_ips        -- current banned_ips table count
        evicted_sessions  -- sessions marked revoked = 1
        honeytoken_trips  -- bans with reason containing 'honeytoken'
        port_trap_hits    -- bans with reason containing 'port_trap'
        abuse_reports     -- total rows in abuse_reports table
    """
    if _conn is None:
        return {}
    now = time.time()
    with _lock:
        active = get_conn().execute(
            "SELECT COUNT(*) FROM sessions "
            "WHERE revoked = 0 AND (expires_at = 0 OR expires_at > ?)",
            (now,),
        ).fetchone()[0]

        evicted = get_conn().execute(
            "SELECT COUNT(*) FROM sessions WHERE revoked = 1"
        ).fetchone()[0]

        banned = get_conn().execute(
            "SELECT COUNT(*) FROM banned_ips"
        ).fetchone()[0]

        honeytoken = get_conn().execute(
            "SELECT COUNT(*) FROM banned_ips WHERE reason LIKE '%honeytoken%'"
        ).fetchone()[0]

        port_trap = get_conn().execute(
            "SELECT COUNT(*) FROM banned_ips WHERE reason LIKE '%port_trap%'"
        ).fetchone()[0]

        abuse = get_conn().execute(
            "SELECT COUNT(*) FROM abuse_reports"
        ).fetchone()[0]

        # Count from dedicated honeytoken_events table (includes monitor-only events)
        try:
            honey_events = get_conn().execute(
                "SELECT COUNT(*) FROM honeytoken_events"
            ).fetchone()[0]
        except Exception:
            honey_events = 0

        # Count port trap hits from dedicated port_trap_hits table
        try:
            port_trap_db = get_conn().execute(
                "SELECT COUNT(*) FROM port_trap_hits"
            ).fetchone()[0]
        except Exception:
            port_trap_db = 0

    return {
        "active_sessions":  active,
        "evicted_sessions": evicted,
        "banned_ips":       banned,
        "honeytoken_trips": max(honeytoken, honey_events),
        "port_trap_hits":   max(port_trap, port_trap_db),
        "abuse_reports":    abuse,
    }


# ---------------------------------------------------------------------------
# Telemetry event log (mid-range anomaly scores forwarded to SOC)
# ---------------------------------------------------------------------------

def log_telemetry_event(
    ip: str,
    anomaly_score: float,
    action_type: str,
    session_id: str,
    username: str | None = None,
) -> None:
    """
    Persist a mid-range telemetry anomaly event (score >= 0.50, < 0.85).

    These events appear in the SOC triage queue for analyst review but do
    NOT trigger automatic containment -- that only happens at score >= 0.85.

    The telemetry_events table is separate from abuse_reports so analysts
    can distinguish autonomous AI alerts from manual AbuseIPDB submissions.
    """
    if _conn is None:
        return
    # Ensure table exists (created lazily so old DBs don't need migration)
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ip            TEXT    NOT NULL,
                username      TEXT,
                anomaly_score REAL    NOT NULL,
                action_type   TEXT    NOT NULL,
                session_id    TEXT    NOT NULL,
                recorded_at   REAL    NOT NULL
            )
        """)
    ts = time.time()
    try:
        with _lock:
            get_conn().execute(
                "INSERT INTO telemetry_events "
                "(ip, username, anomaly_score, action_type, session_id, recorded_at) "
                "VALUES (?,?,?,?,?,?)",
                (ip, username, anomaly_score, action_type, session_id, ts),
            )
        logger.debug("DB: telemetry event logged ip=%s score=%.4f", ip, anomaly_score)
    except Exception as exc:
        logger.warning("DB: failed to log telemetry event: %s", exc)


# ---------------------------------------------------------------------------
# Honeytoken event log (structured trip records for the SOC dashboard)
# ---------------------------------------------------------------------------

def log_honeytoken_event(
    ip: str,
    trigger: str,
    token_path: str,
    action: str,
    session_id: str | None = None,
    username: str | None = None,
) -> None:
    """
    Persist a structured honeytoken trip event to the honeytoken_events table.

    Called by SOAREngine (monitor-only mode) and by ws_dashboard honeytoken
    handler so every trip — whether or not the IP was actually banned — is
    recorded and visible in the SOC Honeytoken Trip History table.

    Parameters
    ----------
    ip         : str  -- attacker IP address
    trigger    : str  -- alert type string (e.g. 'HONEYTOKEN_ACCESS')
    token_path : str  -- file path or route that was accessed
    action     : str  -- action taken ('BANNED', 'MONITOR_ONLY_ALERT', etc.)
    session_id : str  -- session token (prefix), if available
    username   : str  -- username from session, if available
    """
    if _conn is None:
        return
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS honeytoken_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL,
                trigger     TEXT    NOT NULL,
                token_path  TEXT    NOT NULL,
                action      TEXT    NOT NULL,
                session_id  TEXT,
                username    TEXT,
                recorded_at REAL    NOT NULL
            )
        """)
    ts = time.time()
    try:
        with _lock:
            get_conn().execute(
                "INSERT INTO honeytoken_events "
                "(ip, trigger, token_path, action, session_id, username, recorded_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (ip, trigger, token_path, action, session_id, username, ts),
            )
        logger.info(
            "DB: honeytoken event logged ip=%s trigger=%s action=%s",
            ip, trigger, action,
        )
    except Exception as exc:
        logger.warning("DB: failed to log honeytoken event: %s", exc)


def get_honeytoken_history(limit: int = 100) -> list[dict]:
    """
    Return the most recent honeytoken trip events.

    Merges records from both honeytoken_events (structured) and banned_ips
    (honeytoken-reason bans) so the dashboard table is always complete.

    Returns
    -------
    list[dict]
        Keys: ip, trigger, token_path, action, username, recorded_at
    """
    if _conn is None:
        return []
    # Ensure table exists before querying
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS honeytoken_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL,
                trigger     TEXT    NOT NULL,
                token_path  TEXT    NOT NULL,
                action      TEXT    NOT NULL,
                session_id  TEXT,
                username    TEXT,
                recorded_at REAL    NOT NULL
            )
        """)
        rows = get_conn().execute(
            """
            SELECT ip, trigger, token_path, action, username, recorded_at
            FROM honeytoken_events
            ORDER BY recorded_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        # Also pull honeytoken bans that may have been written before this
        # table existed (backward compat with older banned_ips entries)
        ban_rows = get_conn().execute(
            """
            SELECT b.ip, b.reason, b.banned_at, s.username
            FROM banned_ips b
            LEFT JOIN sessions s ON s.ip = b.ip AND s.revoked = 0
            WHERE b.reason LIKE '%honeytoken%'
            ORDER BY b.banned_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    events: list[dict] = []

    # Build set of IPs already in honeytoken_events to avoid duplicates
    seen_ips = {r[0] for r in rows}

    for r in rows:
        events.append({
            "ip":          r[0],
            "trigger":     r[1],
            "token_path":  r[2],
            "action":      r[3],
            "username":    r[4] or "unknown",
            "recorded_at": r[5],
        })

    for r in ban_rows:
        if r[0] not in seen_ips:
            events.append({
                "ip":          r[0],
                "trigger":     r[1],
                "token_path":  "honeytoken_access",
                "action":      "BANNED",
                "username":    r[3] or "unknown",
                "recorded_at": r[2],
            })

    events.sort(key=lambda e: e["recorded_at"] or 0, reverse=True)
    return events[:limit]


# ---------------------------------------------------------------------------
# Port trap hit log (persistent counter for the SOC dashboard)
# ---------------------------------------------------------------------------

def log_port_trap_hit(ip: str, port: int) -> None:
    """
    Persist a TCP honeypot connection event to the port_trap_hits table.

    Called by PortTrap.handle_connection() so the counter survives process
    restarts and page reloads (unlike the in-memory PERIMETER_BLACKLIST set).

    Parameters
    ----------
    ip   : str -- attacker source IP
    port : int -- honeypot port that was connected to
    """
    if _conn is None:
        return
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS port_trap_hits (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                recorded_at REAL    NOT NULL
            )
        """)
    ts = time.time()
    try:
        with _lock:
            get_conn().execute(
                "INSERT INTO port_trap_hits (ip, port, recorded_at) VALUES (?,?,?)",
                (ip, port, ts),
            )
        logger.info("DB: port trap hit logged ip=%s port=%d", ip, port)
    except Exception as exc:
        logger.warning("DB: failed to log port trap hit: %s", exc)


def get_top_anomalies(limit: int = 5, score_threshold: float = 0.50) -> list[dict]:
    """
    Return the Top N most volatile IPs/sessions by anomaly score.

    Merges telemetry_events with sessions to resolve username/role.
    Filters to records where anomaly_score >= score_threshold.
    Groups by IP, returns the highest score and latest timestamp per IP.
    Sorted descending by max anomaly score (most dangerous first).

    Used by the SOC Top 5 Malicious Users panel.

    Returns
    -------
    list[dict]
        Keys: ip, username, role, max_score, event_count, last_seen
    """
    if _conn is None:
        return []
    # Ensure table exists before querying
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ip            TEXT    NOT NULL,
                username      TEXT,
                anomaly_score REAL    NOT NULL,
                action_type   TEXT    NOT NULL,
                session_id    TEXT    NOT NULL,
                recorded_at   REAL    NOT NULL
            )
        """)
        rows = get_conn().execute(
            """
            SELECT
                te.ip,
                s.username,
                s.role,
                MAX(te.anomaly_score)  AS max_score,
                COUNT(te.id)           AS event_count,
                MAX(te.recorded_at)    AS last_seen
            FROM telemetry_events te
            LEFT JOIN sessions s ON s.ip = te.ip AND s.revoked = 0
            WHERE te.anomaly_score >= ?
            GROUP BY te.ip
            ORDER BY max_score DESC
            LIMIT ?
            """,
            (score_threshold, limit),
        ).fetchall()
    return [
        {
            "ip":          r[0],
            "username":    r[1] or "unknown",
            "role":        r[2] or "unknown",
            "max_score":   round(r[3], 4),
            "event_count": r[4],
            "last_seen":   r[5],
        }
        for r in rows
    ]
