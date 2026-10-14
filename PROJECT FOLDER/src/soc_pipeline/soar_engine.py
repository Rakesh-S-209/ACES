"""
src/soc_pipeline/soar_engine.py
SOAR Automation Engine -- Automated Threat Response Orchestrator.

Responsibilities (Requirements 5.x):
- Pulls every AlertEvent from the EventHub subscriber loop.
- For each event:
  1. Adds source IP to PERIMETER_BLACKLIST (O(1), in-memory).
  2. Concurrently fetches IP reputation via ThreatIntelAggregator.
  3. Revokes the matching SessionRecord in ACTIVE_SESSIONS.
  4. Publishes an enriched AI_ANOMALY AlertEvent back to the EventHub.
  5. Appends a SOARResult to the internal audit log.
- Memory-eviction phase (steps 1 + 3) must complete in < 5 ms.
- Never raises -- on any internal error it logs and continues.

Monitor-Only Mode
-----------------
When monitor_only=True (or set after construction via soar_engine.monitor_only = True),
the engine logs and broadcasts all threat events to the SOC dashboard WITHOUT writing
ban records to SQLite or adding IPs to the in-memory blacklist. This lets the Kali VM
continue browsing after triggering honeytokens or anomaly scores so analysts can observe
their full attack behaviour in real time without losing the HTTP session.

Use monitor_only for live demonstrations. Disable it to enforce hard containment.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Dict, List, Optional, Set

from src.soc_pipeline.event_hub import EventHub
from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
from src.zero_trust.models import (
    AlertEvent,
    AlertType,
    IPReputationReport,
    SOARResult,
    SessionRecord,
    SessionStatus,
)

# ---------------------------------------------------------------------------
# Containment skip list
# ---------------------------------------------------------------------------
# NOTE: "local" and "unknown" are intentionally NOT included here.
# Those synthetic values can appear when IP resolution fails; they should
# still go through the scoring pipeline rather than being silently skipped.
# Only true loopback addresses are whitelisted to prevent the server from
# banning its own network interface.
_LOOPBACK_SKIP = frozenset({
    "127.0.0.1",
    "::1",
    "localhost",
})

# ---------------------------------------------------------------------------
# Role evaluation order for anomaly verification
# ---------------------------------------------------------------------------
# Administrative accounts are inspected FIRST so elevated-privilege sessions
# receive the strictest scrutiny before standard user sessions are evaluated.
# The SOC rule hierarchy is: admin → engineer → user → guest.
_ROLE_PRIORITY: dict[str, int] = {
    "admin":    0,   # highest priority -- inspect first
    "Admin":    0,
    "engineer": 1,
    "Engineer": 1,
    "user":     2,
    "User":     2,
    "guest":    3,
    "Guest":    3,
}

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AbuseIPDB background reporting helper
# ---------------------------------------------------------------------------

async def _fire_abuseipdb_report(
    ip: str,
    anomaly_score: float,
    trigger: str,
    categories: Optional[List[int]] = None,
) -> None:
    """
    Fire-and-forget AbuseIPDB report.

    Called as an asyncio.create_task so it never blocks the SOAR pipeline.
    Logs the result to SQLite (abuse_reports table) regardless of success.
    """
    from src.soc_pipeline.abuseipdb_client import (
        CATEGORY_BRUTE_FORCE,
        CATEGORY_WEB_ATTACK,
        report_malicious_ip,
    )
    if categories is None:
        # Choose category based on trigger type
        if trigger == "PORT_TRAP":
            cats = [CATEGORY_BRUTE_FORCE]
        elif trigger == "HONEYTOKEN_ACCESS":
            cats = [CATEGORY_WEB_ATTACK]
        else:
            cats = [CATEGORY_WEB_ATTACK, CATEGORY_BRUTE_FORCE]
    else:
        cats = categories

    comment = (
        f"Trigger={trigger} anomaly_score={anomaly_score:.4f} "
        f"Zero Trust Isolation Forest threshold exceeded."
    )

    result = await report_malicious_ip(
        ip_address=ip,
        categories=cats,
        comment=comment,
    )

    # Persist the report log to SQLite
    try:
        from src.auth import db as _auth_db
        _auth_db.log_abuse_report(
            ip=ip,
            categories=cats,
            mode=result.get("mode", "unknown"),
            success=result.get("success", False),
            anomaly_score=anomaly_score,
            trigger=trigger,
            error=result.get("error"),
            reported_at_ms=result.get("reported_at_ms"),
        )
    except Exception as exc:
        logger.warning("SOAREngine: failed to log abuse report to DB: %s", exc)


class SOAREngine:
    """
    Security Orchestration, Automation and Response engine.

    Listens to the EventHub subscriber stream and executes the full
    threat-containment pipeline for every received AlertEvent.

    Parameters
    ----------
    event_hub : EventHub
        The singleton event bus (read via ``subscribe()``).
    active_sessions : dict[str, SessionRecord]
        Shared in-memory session registry (ACTIVE_SESSIONS).
    perimeter_blacklist : set[str]
        Shared in-memory IP blacklist (PERIMETER_BLACKLIST).
    intel : ThreatIntelAggregator | None
        Optional pre-configured aggregator; a default instance is created if
        not provided.
    """

    def __init__(
        self,
        event_hub: EventHub,
        active_sessions: Dict[str, SessionRecord],
        perimeter_blacklist: Set[str],
        intel: Optional[ThreatIntelAggregator] = None,
        monitor_only: bool = False,
    ) -> None:
        self._event_hub = event_hub
        self._sessions = active_sessions
        self._blacklist = perimeter_blacklist
        self._intel = intel or ThreatIntelAggregator()
        self._audit_log: List[SOARResult] = []
        self._running: bool = False
        # Monitor-Only Mode: log + alert without banning or blocking traffic.
        # Set monitor_only=True for live demonstrations so the Kali VM can
        # continue interacting with the portal after triggering deception sensors.
        self.monitor_only: bool = monitor_only

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def audit_log(self) -> List[SOARResult]:
        """Read-only view of historical SOARResult records."""
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Orchestrator loop
    # ------------------------------------------------------------------

    async def start_orchestrator(self) -> None:
        """
        Main event-processing loop.

        Subscribes to the EventHub and runs the containment pipeline for
        every received AlertEvent until ``stop()`` is called or the task
        is cancelled during clean shutdown.
        """
        self._running = True
        logger.info("SOAREngine: orchestrator started.")
        try:
            async for event in self._event_hub.subscribe():
                if not self._running:
                    break
                try:
                    await self._process_event(event)
                except asyncio.CancelledError:
                    raise  # propagate shutdown signal immediately
                except Exception as exc:  # pylint: disable=broad-except
                    logger.error(
                        "SOAREngine: unhandled error processing event %r: %s",
                        event,
                        exc,
                        exc_info=True,
                    )
        except asyncio.CancelledError:
            logger.info("SOAREngine: orchestrator cancelled cleanly.")
            raise  # always re-raise so asyncio.gather can mark it done
        finally:
            logger.info("SOAREngine: orchestrator stopped.")

    def stop(self) -> None:
        """Signal the orchestrator loop to exit after the current event."""
        self._running = False

    # ------------------------------------------------------------------
    # Per-event containment pipeline
    # ------------------------------------------------------------------

    async def _process_event(self, event: AlertEvent) -> None:
        """
        Execute the full SOAR containment pipeline for one AlertEvent.

        Steps
        -----
        0. **Loopback guard** -- skip containment entirely for local/loopback
           IPs to prevent the infinite feedback cycle where the server bans
           its own interface and the ban triggers more alerts.
        1. **Blacklist** the source IP (in-memory set.add -- O(1)).
        2. **Revoke session** matching source IP (memory-only, < 5 ms budget).
        3. **AbuseIPDB report** in background (non-blocking task).
        4. **Fetch reputation** concurrently (non-blocking task).
        5. **Build and append** SOARResult to the audit log.
        """
        source_ip = event.source_ip

        # --- Step 0: Loopback guard -----------------------------------------
        # Skip containment only for genuine loopback addresses to prevent the
        # server from banning its own interface.  Synthetic sentinel strings
        # ("local", "unknown") are NOT skipped -- they pass through the normal
        # pipeline so they appear in the triage queue for analyst review.
        if source_ip in _LOOPBACK_SKIP or source_ip.startswith("127."):
            logger.info(
                "SOAREngine: loopback bypass -- skipping containment for "
                "whitelisted host %s (feedback-loop protection).",
                source_ip,
            )
            return

        # --- Step 0b: Role-priority inspection --------------------------------
        # Resolve the role attached to this event's session so that
        # administrative accounts are flagged and inspected FIRST in the
        # SOC rule hierarchy before standard user accounts.
        _event_role = "unknown"
        try:
            from src.auth import db as _auth_db
            _sessions_for_ip = _auth_db.get_active_sessions()
            _matched = [s for s in _sessions_for_ip if s.get("ip") == source_ip]
            if _matched:
                # Sort by role priority; admin accounts come first
                _matched.sort(key=lambda s: _ROLE_PRIORITY.get(s.get("role", ""), 99))
                _event_role = _matched[0].get("role", "unknown")
                if _ROLE_PRIORITY.get(_event_role, 99) == 0:
                    logger.warning(
                        "SOAREngine: ADMIN ACCOUNT anomaly detected from %s "
                        "(role=%s) -- escalating to priority inspection.",
                        source_ip, _event_role,
                    )
        except Exception:
            pass

        # --- Monitor-Only Mode guard ----------------------------------------
        # In monitor_only mode: log the event to DB so the SOC dashboard sees
        # it, but do NOT write to banned_ips or the in-memory blacklist.
        # The attacker's HTTP session remains alive for observation.
        #
        # NOTE: We intentionally do NOT re-publish the event here.  The event
        # already arrived via the EventHub subscriber loop, which means the
        # SOCDashboardServer broadcast_loop has already received it and will
        # push it to every WebSocket client.  Re-publishing would create an
        # infinite feedback cycle: SOAR receives event → re-publishes →
        # SOAR receives it again → re-publishes → ...
        if self.monitor_only:
            logger.warning(
                "SOAREngine [MONITOR-ONLY]: threat detected from %s "
                "(type=%s, role=%s) -- logging without containment.",
                source_ip, event.alert_type, _event_role,
            )
            try:
                from src.auth import db as _auth_db
                _auth_db.log_honeytoken_event(
                    ip=source_ip,
                    trigger=str(event.alert_type),
                    token_path=getattr(event, "affected_path", None) or "unknown",
                    action="MONITOR_ONLY_ALERT",
                    session_id=getattr(event, "session_id", None),
                )
            except Exception as exc:
                logger.debug("SOAREngine monitor_only: DB log failed: %s", exc)
            result = SOARResult(success=True, delta_ms=0.0)
            self._audit_log.append(result)
            return

        # --- Phase A: In-memory containment (must be < 5 ms) ----------------
        t_start = time.perf_counter()

        # Step 1: Blacklist IP (in-memory)
        self._blacklist.add(source_ip)

        # Step 1b: Persist ban to SQLite so it survives restarts and is visible
        # in the SOC dashboard immediately (ban counter, triage queue, etc.)
        try:
            from src.auth import db as _auth_db
            _trigger_label = str(event.alert_type).replace("AlertType.", "")
            _auth_db.ban_ip(source_ip, reason=f"SOAR_ENFORCE:{_trigger_label}")
            _auth_db.revoke_sessions_for_ip(source_ip)
        except Exception as exc:
            logger.debug("SOAREngine: DB ban/revoke failed for %s: %s", source_ip, exc)

        # Step 2: Revoke sessions in-memory (ACTIVE_SESSIONS dict)
        revoked_session_ids = self._revoke_sessions_for_ip(source_ip)

        t_eviction_ms = (time.perf_counter() - t_start) * 1000.0

        logger.info(
            "SOAREngine: contained %s -- blacklisted, %d session(s) revoked "
            "(eviction took %.3f ms).",
            source_ip,
            len(revoked_session_ids),
            t_eviction_ms,
        )

        # Persist to honeytoken_events if this is a honeytoken or anomaly alert
        try:
            from src.auth import db as _auth_db
            _trigger = str(event.alert_type)
            _path = getattr(event, "affected_path", None) or "unknown"
            _action = "BANNED"
            _auth_db.log_honeytoken_event(
                ip=source_ip,
                trigger=_trigger,
                token_path=_path,
                action=_action,
                session_id=getattr(event, "session_id", None),
            )
        except Exception as exc:
            logger.debug("SOAREngine: honeytoken DB log failed: %s", exc)

        # --- Phase B: Async reputation enrichment (non-blocking) ------------
        # NOTE: AbuseIPDB reporting is now MANUAL-ONLY.
        # Analysts trigger reports explicitly via the SOC triage board
        # [Report to AbuseIPDB] button.  No automatic background reporting.
        intel_task: asyncio.Task[IPReputationReport] = asyncio.create_task(
            self._intel.fetch_reputation(source_ip)
        )

        try:
            reputation = await intel_task
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
                "SOAREngine: reputation fetch failed for %s: %s -- "
                "using zero-confidence fallback.",
                source_ip,
                exc,
            )
            reputation = IPReputationReport(
                ip_address=source_ip,
                abuse_confidence_score=0,
                country_code="XX",
                total_reports=0,
                is_whitelisted=False,
                source="offline_fallback_error",
            )

        # --- Phase D: Build and log SOARResult --------------------------------
        total_duration_ms = (time.perf_counter() - t_start) * 1000.0

        result = SOARResult(
            success=True,
            delta_ms=t_eviction_ms,
        )
        self._audit_log.append(result)

        logger.debug(
            "SOAREngine: pipeline complete for %s -- "
            "abuse_score=%d, source=%s, total_ms=%.2f",
            source_ip,
            reputation.abuse_confidence_score,
            reputation.source,
            total_duration_ms,
        )

    # ------------------------------------------------------------------
    # Session revocation helper
    # ------------------------------------------------------------------

    def _revoke_sessions_for_ip(self, ip_address: str) -> List[str]:
        """
        Set every SessionRecord matching *ip_address* to REVOKED.

        Records ``revoked_at_ms`` as the current UTC epoch millisecond
        timestamp (Requirement 5.7).

        Returns
        -------
        list[str]
            Session IDs that were transitioned to REVOKED.
        """
        now_ms = time.time() * 1000
        revoked: List[str] = []

        for session_id, record in self._sessions.items():
            if record.ip_address == ip_address and record.status is SessionStatus.ACTIVE:
                record.status = SessionStatus.REVOKED
                record.revoked_at_ms = now_ms
                revoked.append(session_id)
                logger.debug(
                    "SOAREngine: session %s revoked (IP=%s).",
                    session_id,
                    ip_address,
                )

        return revoked

    # ------------------------------------------------------------------
    # Direct trigger (used by Gateway for high-anomaly scores)
    # ------------------------------------------------------------------

    async def trigger_response(
        self,
        ip: str,
        session_id: str,
        anomaly_score: float,
    ) -> SOARResult:
        """
        Directly trigger the SOAR pipeline for a Gateway-flagged IP.

        This method is called by the ZeroTrustGateway when the BehaviorScorer
        returns a score > 0.75 (Requirement 5.1).  It does not go through the
        EventHub subscriber loop -- it executes the pipeline inline.

        Parameters
        ----------
        ip : str
            Attacker IP address.
        session_id : str
            Session identifier of the flagged request.
        anomaly_score : float
            Normalised anomaly score in [0.0, 1.0].

        Returns
        -------
        SOARResult
            Structured result with ``success`` flag and ``delta_ms``.
        """
        t_start = time.perf_counter()

        # Loopback guard -- uses shared _LOOPBACK_SKIP constant
        if ip in _LOOPBACK_SKIP or ip.startswith("127."):
            logger.info(
                "SOAREngine.trigger_response: loopback bypass -- skipping "
                "containment for whitelisted host %s (feedback-loop protection).",
                ip,
            )
            return SOARResult(success=True, delta_ms=0.0)

        # Role-priority check: resolve the role for this session and log
        # admin accounts at elevated severity before standard user containment.
        _sess_role = "unknown"
        if session_id in self._sessions:
            _sess_role = self._sessions[session_id].role
        _role_priority = _ROLE_PRIORITY.get(_sess_role, 99)
        if _role_priority == 0:
            logger.warning(
                "SOAREngine.trigger_response: ADMIN ACCOUNT anomaly detected "
                "ip=%s session=%s score=%.4f -- admin-priority enforcement.",
                ip, session_id, anomaly_score,
            )

        # Monitor-Only Mode: publish alert but skip banning
        if self.monitor_only:
            logger.warning(
                "SOAREngine.trigger_response [MONITOR-ONLY]: anomaly score=%.4f "
                "for ip=%s -- alerting without containment.", anomaly_score, ip,
            )
            now_ms = time.time() * 1000
            alert = AlertEvent(
                alert_type=AlertType.AI_ANOMALY,
                source_ip=ip,
                timestamp_ms=now_ms,
                session_id=session_id,
                anomaly_score=anomaly_score,
                abuse_score=0,
                revocation_delta_ms=None,
            )
            await self._event_hub.publish(alert)
            result = SOARResult(success=True, delta_ms=0.0)
            self._audit_log.append(result)
            return result

        # Step 1 -- Blacklist
        self._blacklist.add(ip)

        # Step 2 -- Revoke session
        now_ms = time.time() * 1000
        revoked = False
        if session_id in self._sessions:
            record = self._sessions[session_id]
            record.status = SessionStatus.REVOKED
            record.revoked_at_ms = now_ms
            revoked = True

        t_eviction_ms = (time.perf_counter() - t_start) * 1000.0

        # Step 3 -- Reputation (concurrent, non-blocking)
        intel_task: asyncio.Task[IPReputationReport] = asyncio.create_task(
            self._intel.fetch_reputation(ip)
        )

        try:
            reputation = await intel_task
        except Exception:  # pylint: disable=broad-except
            reputation = IPReputationReport(
                ip_address=ip,
                abuse_confidence_score=0,
                country_code="XX",
                total_reports=0,
                is_whitelisted=False,
                source="offline_fallback_error",
            )

        # Compute revocation delta from the session record
        delta_ms: Optional[float] = None
        if revoked and session_id in self._sessions:
            delta_ms = self._sessions[session_id].revocation_delta_ms

        # Step 4 -- Publish enriched AI_ANOMALY alert
        alert = AlertEvent(
            alert_type=AlertType.AI_ANOMALY,
            source_ip=ip,
            timestamp_ms=now_ms,
            session_id=session_id,
            anomaly_score=anomaly_score,
            abuse_score=reputation.abuse_confidence_score,
            revocation_delta_ms=delta_ms,
        )
        await self._event_hub.publish(alert)

        result = SOARResult(success=True, delta_ms=t_eviction_ms)
        self._audit_log.append(result)

        logger.info(
            "SOAREngine.trigger_response: IP=%s session=%s revoked=%s "
            "eviction_ms=%.3f abuse=%d",
            ip,
            session_id,
            revoked,
            t_eviction_ms,
            reputation.abuse_confidence_score,
        )
        return result

    # ------------------------------------------------------------------
    # Manual analyst actions (Human-in-the-loop triage)
    # ------------------------------------------------------------------

    async def manual_ban(self, ip: str, reason: str = "analyst_manual_ban") -> dict:
        """
        Analyst-triggered ban from the SOC triage board [Alert] button.

        Adds the IP to both the in-memory blacklist and the SQLite
        banned_ips table.  Publishes an AI_ANOMALY alert to the EventHub
        so the SOC stream shows the action immediately.

        Returns a dict with 'success' and 'ip'.
        """
        # Loopback guard -- uses shared _LOOPBACK_SKIP constant
        if ip in _LOOPBACK_SKIP or ip.startswith("127."):
            logger.info("SOAREngine.manual_ban: loopback bypass -- refusing to ban loopback %s", ip)
            return {"success": False, "ip": ip, "reason": "loopback_protected"}

        self._blacklist.add(ip)
        try:
            from src.auth import db as _auth_db
            _auth_db.ban_ip(ip, reason=reason)
        except Exception as exc:
            logger.warning("SOAREngine.manual_ban: DB write failed: %s", exc)

        now_ms = time.time() * 1000
        self._revoke_sessions_for_ip(ip)
        alert = AlertEvent(
            alert_type=AlertType.AI_ANOMALY,
            source_ip=ip,
            timestamp_ms=now_ms,
            session_id="analyst",
            anomaly_score=1.0,
            abuse_score=0,
            revocation_delta_ms=0.0,
        )
        await self._event_hub.publish(alert)
        logger.info("SOAREngine.manual_ban: analyst banned %s (%s)", ip, reason)
        return {"success": True, "ip": ip, "reason": reason}

    async def manual_unban(self, ip: str) -> dict:
        """
        Analyst-triggered unban from the SOC triage board [Remove Ban] button.

        Removes the IP from the in-memory blacklist and from SQLite so
        subsequent requests from this IP are allowed again.

        Returns a dict with 'success', 'ip', and 'was_banned'.
        """
        was_in_memory = ip in self._blacklist
        self._blacklist.discard(ip)

        was_in_db = False
        try:
            from src.auth import db as _auth_db
            was_in_db = _auth_db.unban_ip(ip)
        except Exception as exc:
            logger.warning("SOAREngine.manual_unban: DB write failed: %s", exc)

        was_banned = was_in_memory or was_in_db
        logger.info("SOAREngine.manual_unban: analyst unbanned %s (was_banned=%s)", ip, was_banned)
        return {"success": True, "ip": ip, "was_banned": was_banned}
