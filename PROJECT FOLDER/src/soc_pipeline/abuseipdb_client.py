# src/soc_pipeline/abuseipdb_client.py
"""
AbuseIPDB v2 reporting client for Project A.C.E.S.

Key management
--------------
The API key is read exclusively from the ABUSEIPDB_API_KEY environment
variable (loaded from .env via python-dotenv at startup).  It is NEVER
hardcoded into this file.

If the variable is absent or empty the client operates in OFFLINE_MOCK
mode: report_malicious_ip() returns a mock success dict and logs a
warning, so the rest of the pipeline continues without a real network call.

Usage
-----
    from src.soc_pipeline.abuseipdb_client import report_malicious_ip

    result = await report_malicious_ip(
        ip_address="203.0.113.5",
        categories=[14, 18],
        comment="ACES Zero Trust: anomaly_score=0.93",
    )

Thread safety
-------------
The function is an async coroutine that creates a fresh aiohttp session
per call.  It is safe to call concurrently from multiple asyncio tasks.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load .env at import time (safe no-op if python-dotenv not installed)
# ---------------------------------------------------------------------------
# We look for .env in the project root (two levels up from this file).
# override=False means real environment variables always take precedence.
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"
try:
    from dotenv import load_dotenv  # type: ignore[import]
    load_dotenv(dotenv_path=_ENV_FILE, override=False)
    logger.debug("AbuseIPDB: loaded .env from %s", _ENV_FILE)
except ImportError:
    # python-dotenv not installed -- rely on variables already in os.environ
    logger.debug(
        "AbuseIPDB: python-dotenv not available; reading ABUSEIPDB_API_KEY "
        "directly from process environment."
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
_TIMEOUT_S: float = 8.0

# AbuseIPDB category codes used by A.C.E.S.:
#   14 = Web App Attack
#   18 = Brute-Force / Unauthorised Authentication
CATEGORY_WEB_ATTACK:  int = 14
CATEGORY_BRUTE_FORCE: int = 18

_DEFAULT_COMMENT_PREFIX = (
    "Project ACES Zero Trust Isolation Forest triggered: Anomaly Score > 0.80."
)

# Placeholder strings that mean "no real key configured"
_PLACEHOLDER_VALUES = {
    "YOUR_ACTUAL_API_KEY_HERE",
    "your_api_key_here",
    "YOUR_API_KEY",
    "",
}

# ---------------------------------------------------------------------------
# Runtime environment flag
# ---------------------------------------------------------------------------

def _get_aces_env() -> str:
    """Return ACES_ENV value (defaults to 'development')."""
    return os.environ.get("ACES_ENV", "development").strip().lower()


def _get_api_key() -> Optional[str]:
    """
    Read the AbuseIPDB API key from the environment (populated by .env load).
    Returns None if the key is absent, empty, or still the placeholder string.
    """
    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if key in _PLACEHOLDER_VALUES:
        return None
    return key


async def report_malicious_ip(
    ip_address: str,
    categories: Optional[List[int]] = None,
    comment: str = "",
    timeout_s: float = _TIMEOUT_S,
) -> Dict[str, Any]:
    """
    Report a malicious IP address to AbuseIPDB v2.

    If ABUSEIPDB_API_KEY is not set or is the placeholder string, the
    function returns a mock success dict immediately (OFFLINE_MOCK mode)
    without making any network request.

    Parameters
    ----------
    ip_address : str
        IPv4 or IPv6 address to report.
    categories : list[int] | None
        AbuseIPDB category codes.  Defaults to [14, 18].
    comment : str
        Human-readable description of the incident.  The A.C.E.S. trace
        prefix is prepended automatically.
    timeout_s : float
        HTTP request timeout in seconds (default 8.0).

    Returns
    -------
    dict
        {
            "success":    bool,
            "mode":       "live" | "offline_mock",
            "ip_address": str,
            "categories": list[int],
            "abuseipdb_response": dict | None,   # live only
            "error":      str | None,            # on failure
            "reported_at_ms": float,
        }
    """
    if categories is None:
        categories = [CATEGORY_WEB_ATTACK, CATEGORY_BRUTE_FORCE]

    full_comment = _DEFAULT_COMMENT_PREFIX
    if comment:
        full_comment = f"{_DEFAULT_COMMENT_PREFIX} Detail: {comment}"

    reported_at = time.time() * 1000
    api_key     = _get_api_key()
    aces_env    = _get_aces_env()

    # -- OFFLINE_MOCK mode ---------------------------------------------------
    if api_key is None:
        logger.warning(
            "AbuseIPDB [OFFLINE_MOCK | env=%s]: ABUSEIPDB_API_KEY not set. "
            "IP %s NOT reported. Add ABUSEIPDB_API_KEY to .env to enable.",
            aces_env,
            ip_address,
        )
        return {
            "success": True,
            "mode": "offline_mock",
            "env": aces_env,
            "ip_address": ip_address,
            "categories": categories,
            "abuseipdb_response": None,
            "error": None,
            "reported_at_ms": reported_at,
        }

    # -- LIVE mode -----------------------------------------------------------
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    payload = {
        "ipAddress":  ip_address,
        "categories": ",".join(str(c) for c in categories),
        "comment":    full_comment,
    }

    try:
        import aiohttp  # optional dependency; graceful fallback if absent
    except ImportError:
        logger.error(
            "AbuseIPDB: aiohttp not installed. "
            "Run: pip install aiohttp  to enable live reporting."
        )
        return {
            "success": False,
            "mode": "live",
            "env": aces_env,
            "ip_address": ip_address,
            "categories": categories,
            "abuseipdb_response": None,
            "error": "aiohttp_not_installed",
            "reported_at_ms": reported_at,
        }

    try:
        timeout = aiohttp.ClientTimeout(total=timeout_s)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                _REPORT_URL,
                headers=headers,
                data=payload,
            ) as resp:
                body = await resp.json(content_type=None)
                if resp.status == 200:
                    logger.info(
                        "AbuseIPDB [LIVE | env=%s]: reported %s categories=%s "
                        "abuseConfidenceScore=%s",
                        aces_env,
                        ip_address,
                        categories,
                        body.get("data", {}).get("abuseConfidenceScore", "?"),
                    )
                    return {
                        "success": True,
                        "mode": "live",
                        "env": aces_env,
                        "ip_address": ip_address,
                        "categories": categories,
                        "abuseipdb_response": body,
                        "error": None,
                        "reported_at_ms": reported_at,
                    }
                else:
                    logger.warning(
                        "AbuseIPDB: non-200 for %s: %d %s",
                        ip_address, resp.status, body,
                    )
                    return {
                        "success": False,
                        "mode": "live",
                        "env": aces_env,
                        "ip_address": ip_address,
                        "categories": categories,
                        "abuseipdb_response": body,
                        "error": f"http_{resp.status}",
                        "reported_at_ms": reported_at,
                    }

    except asyncio.TimeoutError:
        logger.warning("AbuseIPDB: timeout reporting %s", ip_address)
        return {
            "success": False,
            "mode": "live",
            "env": aces_env,
            "ip_address": ip_address,
            "categories": categories,
            "abuseipdb_response": None,
            "error": "timeout",
            "reported_at_ms": reported_at,
        }
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("AbuseIPDB: unexpected error for %s: %s", ip_address, exc)
        return {
            "success": False,
            "mode": "live",
            "env": aces_env,
            "ip_address": ip_address,
            "categories": categories,
            "abuseipdb_response": None,
            "error": str(exc),
            "reported_at_ms": reported_at,
        }
