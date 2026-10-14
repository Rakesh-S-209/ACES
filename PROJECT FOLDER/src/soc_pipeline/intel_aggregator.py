"""
src/soc_pipeline/intel_aggregator.py
Threat Intelligence Aggregator — IP reputation lookup with offline fallback.

Responsibilities (Requirements 5.2 – 5.5, 5.10):
- Query AbuseIPDB (mocked here as a high-fidelity async simulation).
- Wrap every call in a 100 ms asyncio.wait_for timeout guard.
- On timeout or any exception: fall through to the offline static fallback
  dictionary and return a valid IPReputationReport without raising.
- Never raise for any string input — always return a populated report.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict

from src.zero_trust.models import IPReputationReport

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Offline fallback database
# Known-malicious IP prefixes → default reputation entry.
# In production this would be loaded from data/malicious_ips_db.json.
# ---------------------------------------------------------------------------
_OFFLINE_DB: Dict[str, dict] = {
    # Documented test/documentation ranges used as obvious "external" IPs
    "198.51.100.": {"abuse_confidence_score": 90, "country_code": "CN", "total_reports": 200},
    "203.0.113.":  {"abuse_confidence_score": 85, "country_code": "RU", "total_reports": 150},
    "192.0.2.":    {"abuse_confidence_score": 70, "country_code": "KP", "total_reports": 80},
}

# Canonical "safe / internal" IPs that always return a clean report
_SAFE_IPS: frozenset[str] = frozenset({"127.0.0.1", "::1", "local", "unknown"})

# How long (seconds) to wait before triggering the offline fallback
_FETCH_TIMEOUT_S: float = 0.100   # 100 ms (Requirement 5.2 timeout guard)

# Simulated AbuseIPDB network latency for the mock client (ms → s)
_MOCK_LATENCY_S: float = 0.050    # 50 ms — well within 100 ms timeout


class ThreatIntelAggregator:
    """
    Async IP reputation aggregator.

    Uses a mock AbuseIPDB client (``asyncio.sleep`` simulation) wrapped in a
    100 ms timeout.  On failure the offline static dictionary is consulted.
    The function **never raises** regardless of the input string.

    Parameters
    ----------
    timeout_s : float
        Maximum seconds to wait for the remote lookup before falling back to
        offline data (default 0.100 — 100 ms).
    """

    def __init__(self, timeout_s: float = _FETCH_TIMEOUT_S) -> None:
        self._timeout_s = timeout_s

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_reputation(self, ip_address: str) -> IPReputationReport:
        """
        Look up the reputation of *ip_address*.

        Strategy:
        1. Attempt the (mocked) AbuseIPDB call inside a ``wait_for`` guard.
        2. On ``asyncio.TimeoutError`` or any other exception, fall through to
           ``_offline_lookup``.
        3. Always return a valid ``IPReputationReport`` — never raise.

        Parameters
        ----------
        ip_address : str
            Any string (may be IPv4, IPv6, hostname, or garbage).

        Returns
        -------
        IPReputationReport
            Populated report with ``source`` set to either ``"abuseipdb"`` or
            ``"offline_fallback"`` / ``"offline_fallback_error"``.
        """
        try:
            report = await asyncio.wait_for(
                self._mock_abuseipdb_call(ip_address),
                timeout=self._timeout_s,
            )
            return report
        except asyncio.TimeoutError:
            logger.warning(
                "ThreatIntelAggregator: AbuseIPDB timeout for %r — "
                "falling back to offline DB.",
                ip_address,
            )
            return self._offline_lookup(ip_address)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
                "ThreatIntelAggregator: unexpected error for %r (%s) — "
                "falling back to offline DB.",
                ip_address,
                exc,
            )
            return self._offline_lookup(ip_address)

    # ------------------------------------------------------------------
    # Mock AbuseIPDB client
    # ------------------------------------------------------------------

    @staticmethod
    async def _mock_abuseipdb_call(ip_address: str) -> IPReputationReport:
        """
        High-fidelity async simulation of an AbuseIPDB REST call.

        Simulates 50 ms network latency.  Returns a clean report for
        internal/loopback addresses, and a high-confidence malicious report
        for everything else.
        """
        # Simulate async network I/O
        await asyncio.sleep(_MOCK_LATENCY_S)

        if ip_address in _SAFE_IPS:
            return IPReputationReport(
                ip_address=ip_address,
                abuse_confidence_score=0,
                country_code="US",
                total_reports=0,
                is_whitelisted=True,
                source="abuseipdb",
            )

        # External / unknown IP — return a realistic threat report
        return IPReputationReport(
            ip_address=ip_address,
            abuse_confidence_score=85,
            country_code="CN",
            total_reports=412,
            is_whitelisted=False,
            source="abuseipdb",
        )

    # ------------------------------------------------------------------
    # Offline fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _offline_lookup(ip_address: str) -> IPReputationReport:
        """
        Consult the static offline threat-intelligence dictionary.

        Matches the IP against known-malicious prefix ranges.  Always returns
        a valid report — on any internal error returns a zero-confidence
        ``"offline_fallback_error"`` report (Requirement 5.5).
        """
        try:
            for prefix, entry in _OFFLINE_DB.items():
                if ip_address.startswith(prefix):
                    return IPReputationReport(
                        ip_address=ip_address,
                        abuse_confidence_score=entry["abuse_confidence_score"],
                        country_code=entry["country_code"],
                        total_reports=entry["total_reports"],
                        is_whitelisted=False,
                        source="offline_fallback",
                    )

            # IP not in any known range — return a zero-confidence fallback
            return IPReputationReport(
                ip_address=ip_address,
                abuse_confidence_score=0,
                country_code="XX",
                total_reports=0,
                is_whitelisted=False,
                source="offline_fallback",
            )
        except Exception as exc:  # pragma: no cover  pylint: disable=broad-except
            logger.error(
                "ThreatIntelAggregator: offline lookup failed for %r: %s",
                ip_address,
                exc,
            )
            return IPReputationReport(
                ip_address=ip_address,
                abuse_confidence_score=0,
                country_code="XX",
                total_reports=0,
                is_whitelisted=False,
                source="offline_fallback_error",
            )
