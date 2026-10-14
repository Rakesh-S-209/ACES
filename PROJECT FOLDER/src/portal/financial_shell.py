# src/portal/financial_shell.py
"""
FinancialPortalShell -- concrete high-value corporate portal surface.

Simulates three high-value user paths:
  - view_balance   : low-risk read operation
  - wire_transfer  : medium-risk transactional operation
  - admin_login    : elevated-risk administrative path

For every action the shell:
  1. Builds a TelemetryVector from the click_payload.
  2. Scores it with BehaviorScorer.
  3. If score >= 0.85 escalates to SOAREngine.trigger_response().
  4. Returns a structured response dict.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

from src.portal.gateway import BasePortalShell
from src.soc_pipeline.soar_engine import SOAREngine
from src.zero_trust.models import (
    PolicyAction,
    SessionRecord,
    SessionStatus,
    TelemetryVector,
)
from src.zero_trust.scorer import BehaviorScorer
from src.zero_trust.validation import validate_telemetry_vector

logger = logging.getLogger(__name__)

# Anomaly threshold for immediate SOAR escalation (hard containment)
_ESCALATION_THRESHOLD: float = 0.85

# Anomaly threshold for SOC alert push (telemetry forwarded to SOC, no ban)
# Scores between _SOC_ALERT_THRESHOLD and _ESCALATION_THRESHOLD are logged
# and pushed to the SOC stream for analyst review without auto-containment.
_SOC_ALERT_THRESHOLD: float = 0.50

# Action-specific baseline telemetry profiles
_ACTION_PROFILES: Dict[str, Dict[str, Any]] = {
    "view_balance": {
        "page_path_weights": [0.6, 0.4],
        "sequence_transitions": [1, 2],
        "base_request_rate": 1.5,
    },
    "wire_transfer": {
        "page_path_weights": [0.3, 0.5, 0.2],
        "sequence_transitions": [1, 3, 5],
        "base_request_rate": 3.0,
    },
    "admin_login": {
        "page_path_weights": [0.1, 0.9],
        "sequence_transitions": [10, 20],
        "base_request_rate": 5.0,
    },
}

# Default profile for unknown action types
_DEFAULT_PROFILE: Dict[str, Any] = {
    "page_path_weights": [0.5],
    "sequence_transitions": [1],
    "base_request_rate": 2.0,
}


class FinancialPortalShell(BasePortalShell):
    """
    Production-ready corporate financial portal shell.

    Parameters
    ----------
    scorer : BehaviorScorer
        A pre-fitted IsolationForest scorer shared with the Gateway.
    soar_engine : SOAREngine
        The live SOAR orchestrator for immediate threat containment.
    active_sessions : dict
        Shared in-memory session registry.
    """

    def __init__(
        self,
        scorer: BehaviorScorer,
        soar_engine: SOAREngine,
        active_sessions: Dict[str, SessionRecord],
    ) -> None:
        self._scorer = scorer
        self._soar = soar_engine
        self._sessions = active_sessions

    # ------------------------------------------------------------------
    # BasePortalShell implementation
    # ------------------------------------------------------------------

    async def handle_user_action(
        self,
        session_id: str,
        ip: str,
        action_type: str,
        click_payload: dict,
        username: Optional[str] = None,
    ) -> dict:
        """
        Process a single user interaction on the financial portal.

        Returns
        -------
        dict
            Keys: allowed, score, action, session_id, action_type, ms
        """
        t_start = time.perf_counter()

        # Step 1: Build TelemetryVector from payload
        vector = self._build_telemetry(action_type, click_payload)

        # Step 2: Validate (raises ValueError on bad data -- caught below)
        try:
            validate_telemetry_vector(vector)
        except ValueError as exc:
            logger.warning(
                "FinancialPortalShell: invalid telemetry from %s: %s", ip, exc
            )
            return {
                "allowed": False,
                "score": 0.0,
                "action": PolicyAction.BLOCK.value,
                "session_id": session_id,
                "action_type": action_type,
                "ms": round((time.perf_counter() - t_start) * 1000, 3),
                "reason": f"invalid_telemetry: {exc}",
            }

        # Step 3: Score via BehaviorScorer
        score = self._scorer.predict(vector)

        # Step 4: Upsert SessionRecord
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionRecord(
                session_id=session_id,
                ip_address=ip,
                role=username or "Guest",
                anomaly_score=score,
            )
        else:
            self._sessions[session_id].anomaly_score = score

        # Step 5: Determine role priority for verification order.
        # Admin accounts are evaluated FIRST in the SOC rule hierarchy;
        # anomaly thresholds are the same but admin anomalies are flagged
        # at elevated severity and trigger immediate SOAR inspection.
        _session_role = self._sessions[session_id].role
        _is_admin_session = _session_role.lower() in ("admin",)
        if _is_admin_session and score >= _SOC_ALERT_THRESHOLD:
            logger.warning(
                "FinancialPortalShell: ADMIN_ACCOUNT_ANOMALY session=%s ip=%s "
                "action=%s score=%.4f -- admin-priority verification.",
                session_id, ip, action_type, score,
            )

        # Step 6: Escalate if above threshold
        allowed = True
        action = PolicyAction.ALLOW

        if score >= _ESCALATION_THRESHOLD:
            # Hard containment -- ban, revoke, trigger full SOAR pipeline.
            # Admin sessions reaching this threshold are treated as the
            # highest-priority enforcement target.
            action = PolicyAction.REVOKE
            allowed = False
            _severity_tag = "ADMIN_ESCALATION" if _is_admin_session else "ESCALATION"
            logger.warning(
                "FinancialPortalShell: %s session=%s ip=%s "
                "action=%s score=%.4f role=%s",
                _severity_tag, session_id, ip, action_type, score, _session_role,
            )
            # Hard-ban the IP in SQLite before SOAR fires
            try:
                from src.auth import db as _auth_db
                _auth_db.ban_ip(ip, reason=f"ai_anomaly score={score:.4f} role={_session_role}")
                _auth_db.revoke_sessions_for_ip(ip)
            except Exception:
                pass
            # Trigger SOAR pipeline -- non-blocking escalation
            asyncio.create_task(
                self._soar.trigger_response(
                    ip=ip,
                    session_id=session_id,
                    anomaly_score=score,
                )
            )

        elif score >= _SOC_ALERT_THRESHOLD:
            # Mid-range anomaly: push to SOC event hub for analyst review.
            # Admin sessions in this band are immediately forwarded with
            # elevated trigger label so the SOC triage queue highlights them.
            _trigger_label = (
                f"ADMIN_CLICK_ANOMALY:{action_type}"
                if _is_admin_session
                else f"soc_alert:{action_type}"
            )
            logger.info(
                "FinancialPortalShell: SOC_ALERT session=%s ip=%s "
                "action=%s score=%.4f role=%s trigger=%s",
                session_id, ip, action_type, score, _session_role, _trigger_label,
            )
            # Log the telemetry event to DB so it appears in the triage queue
            try:
                from src.auth import db as _auth_db
                _auth_db.log_telemetry_event(
                    ip=ip,
                    username=username,          # real username from session cookie
                    anomaly_score=score,
                    action_type=action_type,
                    session_id=session_id,
                )
            except Exception as exc:
                logger.debug("FinancialPortalShell: telemetry log failed: %s", exc)
            # Publish a non-containment alert to the SOC WebSocket stream
            try:
                from src.zero_trust.models import AlertEvent, AlertType
                from src.soc_pipeline.event_hub import EventHub  # noqa: F401
                alert = AlertEvent(
                    alert_type=AlertType.AI_ANOMALY,
                    source_ip=ip,
                    timestamp_ms=time.time() * 1000,
                    session_id=session_id,
                    anomaly_score=score,
                    abuse_score=0,
                    revocation_delta_ms=None,
                    affected_path=_trigger_label if _is_admin_session else None,
                )
                asyncio.create_task(self._soar._event_hub.publish(alert))
            except Exception as exc:
                logger.debug("FinancialPortalShell: SOC push failed: %s", exc)

        elapsed_ms = round((time.perf_counter() - t_start) * 1000, 3)
        logger.debug(
            "FinancialPortalShell: session=%s ip=%s action=%s "
            "score=%.4f allowed=%s ms=%.2f",
            session_id, ip, action_type, score, allowed, elapsed_ms,
        )

        return {
            "allowed": allowed,
            "score": round(score, 6),
            "action": action.value,
            "session_id": session_id,
            "action_type": action_type,
            "ms": elapsed_ms,
        }

    # ------------------------------------------------------------------
    # Telemetry construction
    # ------------------------------------------------------------------

    def _build_telemetry(
        self, action_type: str, payload: dict
    ) -> TelemetryVector:
        """
        Construct a TelemetryVector from raw click_payload.

        Falls back to action-specific defaults for any missing fields.
        """
        profile = _ACTION_PROFILES.get(action_type, _DEFAULT_PROFILE)

        click_intervals: list[float] = payload.get("click_intervals", [100.0, 200.0])
        if not click_intervals:
            click_intervals = [100.0]

        session_duration: float = float(
            payload.get("session_duration_ms", 3000.0)
        )
        request_rate: float = float(
            payload.get("request_rate_per_sec", profile["base_request_rate"])
        )

        return TelemetryVector(
            click_speed_intervals=click_intervals,
            page_path_weights=list(profile["page_path_weights"]),
            sequence_transitions=list(profile["sequence_transitions"]),
            session_duration_ms=max(0.0, session_duration),
            request_rate_per_sec=max(0.0, min(request_rate, 10000.0)),
        )
