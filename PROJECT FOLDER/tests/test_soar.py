"""
tests/test_soar.py
Unit and property-based tests for the SOAR pipeline components.

Covers:
  Property 11: SOAR always blacklists the attacker IP
  Property 12: SOAR always revokes the triggering session
  Property 13: AI_ANOMALY alert always published after trigger_response
  Property 14: lookup_ip_reputation never raises for any string input

  ThreatIntelAggregator:
  - Returns valid IPReputationReport for any string (Property 14)
  - Offline fallback seamlessly handles timeout (Properties 11/12 failover)
  - Safe IPs get zero-confidence clean reports
  - External IPs get high-confidence threat reports

  SOAREngine:
  - trigger_response blacklists IP and revokes session (Properties 11/12)
  - Containment (eviction) phase completes in < 5 ms (Property 13 timing)
  - Publishes AI_ANOMALY alert with correct fields
  - Handles missing session gracefully
  - Audit log grows with each trigger
"""

from __future__ import annotations

import asyncio
import importlib
import time
from typing import Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import src.soc_pipeline.event_hub as _hub_module
from src.soc_pipeline.event_hub import EventHub
from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
from src.soc_pipeline.soar_engine import SOAREngine
from src.zero_trust.models import (
    AlertEvent,
    AlertType,
    IPReputationReport,
    SessionRecord,
    SessionStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_hub() -> EventHub:
    importlib.reload(_hub_module)
    from src.soc_pipeline.event_hub import EventHub as FreshHub
    return FreshHub()


def _make_session(
    session_id: str = "sess-001",
    ip: str = "203.0.113.5",
    role: str = "Guest",
    score: float = 0.9,
) -> SessionRecord:
    return SessionRecord(
        session_id=session_id,
        ip_address=ip,
        role=role,
        anomaly_score=score,
    )


def _make_sessions(*records: SessionRecord) -> Dict[str, SessionRecord]:
    return {r.session_id: r for r in records}


# ---------------------------------------------------------------------------
# ThreatIntelAggregator tests
# ---------------------------------------------------------------------------

class TestThreatIntelAggregator:
    """Tests for fetch_reputation() — Property 14."""

    @pytest.mark.asyncio
    async def test_returns_ipreputationreport(self) -> None:
        agg = ThreatIntelAggregator()
        result = await agg.fetch_reputation("203.0.113.1")
        assert isinstance(result, IPReputationReport)

    @pytest.mark.asyncio
    async def test_safe_ip_returns_zero_confidence(self) -> None:
        agg = ThreatIntelAggregator()
        for safe_ip in ("127.0.0.1", "local"):
            result = await agg.fetch_reputation(safe_ip)
            assert result.abuse_confidence_score == 0
            assert result.source == "abuseipdb"

    @pytest.mark.asyncio
    async def test_external_ip_returns_high_confidence(self) -> None:
        agg = ThreatIntelAggregator()
        result = await agg.fetch_reputation("203.0.113.99")
        assert result.abuse_confidence_score > 0
        assert result.source == "abuseipdb"

    @pytest.mark.asyncio
    async def test_source_field_always_non_empty(self) -> None:
        agg = ThreatIntelAggregator()
        result = await agg.fetch_reputation("1.2.3.4")
        assert result.source and len(result.source) > 0

    @pytest.mark.asyncio
    async def test_abuse_score_in_valid_range(self) -> None:
        agg = ThreatIntelAggregator()
        for ip in ("127.0.0.1", "203.0.113.5", "10.0.0.1", "garbage_input"):
            result = await agg.fetch_reputation(ip)
            assert 0 <= result.abuse_confidence_score <= 100

    # ------------------------------------------------------------------
    # Offline fallback on timeout (Properties 11/12 failover path)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_timeout_triggers_offline_fallback(self) -> None:
        """With a near-zero timeout, every call must fall back to offline data."""
        agg = ThreatIntelAggregator(timeout_s=0.000_001)  # 1 µs — always times out
        result = await agg.fetch_reputation("1.2.3.4")
        assert isinstance(result, IPReputationReport)
        assert "offline" in result.source

    @pytest.mark.asyncio
    async def test_offline_fallback_never_raises(self) -> None:
        agg = ThreatIntelAggregator(timeout_s=0.000_001)
        # Should not raise for any of these inputs
        for ip in ("", "not-an-ip", "999.999.999.999", "::1", "local"):
            result = await agg.fetch_reputation(ip)
            assert isinstance(result, IPReputationReport)

    @pytest.mark.asyncio
    async def test_offline_known_prefix_returns_nonzero_score(self) -> None:
        """IPs in the offline DB known-bad prefix table get non-zero scores."""
        agg = ThreatIntelAggregator(timeout_s=0.000_001)
        result = await agg.fetch_reputation("198.51.100.42")
        assert result.source == "offline_fallback"
        assert result.abuse_confidence_score > 0

    @pytest.mark.asyncio
    async def test_offline_unknown_ip_returns_zero_score(self) -> None:
        """IPs not in any offline prefix table return 0-confidence fallback."""
        agg = ThreatIntelAggregator(timeout_s=0.000_001)
        result = await agg.fetch_reputation("10.0.0.99")
        assert result.source == "offline_fallback"
        assert result.abuse_confidence_score == 0

    # ------------------------------------------------------------------
    # Property 14: never raises for any string input (hypothesis)
    # ------------------------------------------------------------------

    @given(ip_string=st.text(min_size=0, max_size=50))
    @settings(max_examples=100, deadline=None)
    def test_property_14_never_raises(self, ip_string: str) -> None:
        """fetch_reputation never raises for any string input."""
        agg = ThreatIntelAggregator(timeout_s=0.000_001)  # force offline path

        async def _run() -> IPReputationReport:
            return await agg.fetch_reputation(ip_string)

        result = asyncio.run(_run())
        assert isinstance(result, IPReputationReport)
        assert result.source
        assert 0 <= result.abuse_confidence_score <= 100


# ---------------------------------------------------------------------------
# SOAREngine.trigger_response tests
# ---------------------------------------------------------------------------

class TestSOAREngineTriggerResponse:
    """Unit tests for direct trigger_response() calls."""

    @pytest.mark.asyncio
    async def test_property_11_ip_blacklisted(self) -> None:
        """After trigger_response, source IP must be in PERIMETER_BLACKLIST."""
        hub = _fresh_hub()
        sessions = _make_sessions(_make_session(ip="203.0.113.5"))
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub,
            active_sessions=sessions,
            perimeter_blacklist=blacklist,
        )

        await engine.trigger_response(
            ip="203.0.113.5", session_id="sess-001", anomaly_score=0.92
        )

        assert "203.0.113.5" in blacklist, (
            "IP must be in PERIMETER_BLACKLIST after trigger_response"
        )

    @pytest.mark.asyncio
    async def test_property_12_session_revoked(self) -> None:
        """After trigger_response, matching session must have status=REVOKED."""
        hub = _fresh_hub()
        sessions = _make_sessions(_make_session(session_id="sess-002", ip="203.0.113.6"))
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub,
            active_sessions=sessions,
            perimeter_blacklist=blacklist,
        )

        await engine.trigger_response(
            ip="203.0.113.6", session_id="sess-002", anomaly_score=0.88
        )

        assert sessions["sess-002"].status is SessionStatus.REVOKED
        assert sessions["sess-002"].revoked_at_ms is not None

    @pytest.mark.asyncio
    async def test_revoked_at_ms_is_recent(self) -> None:
        hub = _fresh_hub()
        sessions = _make_sessions(_make_session(ip="10.0.0.1"))
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )

        before_ms = time.time() * 1000
        await engine.trigger_response(
            ip="10.0.0.1", session_id="sess-001", anomaly_score=0.85
        )
        after_ms = time.time() * 1000

        rec = sessions["sess-001"]
        assert rec.revoked_at_ms is not None
        assert before_ms <= rec.revoked_at_ms <= after_ms

    @pytest.mark.asyncio
    async def test_property_13_ai_anomaly_alert_published(self) -> None:
        """trigger_response must publish exactly one AI_ANOMALY alert."""
        hub = _fresh_hub()
        sessions = _make_sessions(_make_session())
        blacklist: set[str] = set()

        published: list[AlertEvent] = []

        original_publish = hub.publish

        async def capture_publish(event: AlertEvent) -> None:
            published.append(event)
            await original_publish(event)

        hub.publish = capture_publish  # type: ignore[method-assign]

        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )

        await engine.trigger_response(
            ip="203.0.113.5", session_id="sess-001", anomaly_score=0.95
        )

        ai_alerts = [e for e in published if e.alert_type is AlertType.AI_ANOMALY]
        assert len(ai_alerts) == 1, (
            f"Expected 1 AI_ANOMALY alert, got {len(ai_alerts)}"
        )
        assert ai_alerts[0].source_ip == "203.0.113.5"
        assert ai_alerts[0].anomaly_score == pytest.approx(0.95)
        assert ai_alerts[0].session_id == "sess-001"

    @pytest.mark.asyncio
    async def test_ai_alert_has_abuse_score(self) -> None:
        hub = _fresh_hub()
        sessions = _make_sessions(_make_session())
        blacklist: set[str] = set()

        published: list[AlertEvent] = []
        orig = hub.publish

        async def capture(e: AlertEvent) -> None:
            published.append(e)
            await orig(e)

        hub.publish = capture  # type: ignore[method-assign]

        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )
        await engine.trigger_response("203.0.113.5", "sess-001", 0.9)

        assert published[0].abuse_score is not None
        assert 0 <= published[0].abuse_score <= 100

    @pytest.mark.asyncio
    async def test_missing_session_handled_gracefully(self) -> None:
        """trigger_response must not raise if session_id is not in registry."""
        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}  # empty
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )

        # Must not raise
        result = await engine.trigger_response(
            ip="1.2.3.4", session_id="nonexistent", anomaly_score=0.8
        )
        assert result.success is True
        assert "1.2.3.4" in blacklist

    @pytest.mark.asyncio
    async def test_audit_log_grows_on_each_trigger(self) -> None:
        hub = _fresh_hub()
        sessions = _make_sessions(
            _make_session("s1", "10.0.0.1"),
            _make_session("s2", "10.0.0.2"),
        )
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )

        assert len(engine.audit_log) == 0
        await engine.trigger_response("10.0.0.1", "s1", 0.8)
        assert len(engine.audit_log) == 1
        await engine.trigger_response("10.0.0.2", "s2", 0.85)
        assert len(engine.audit_log) == 2

    @pytest.mark.asyncio
    async def test_soar_result_success_is_true(self) -> None:
        hub = _fresh_hub()
        sessions = _make_sessions(_make_session())
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )

        result = await engine.trigger_response("203.0.113.5", "sess-001", 0.9)
        assert result.success is True
        assert result.delta_ms is not None
        assert result.delta_ms >= 0.0

    # ------------------------------------------------------------------
    # Property 13: eviction phase < 5 ms
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_eviction_phase_under_5ms(self) -> None:
        """Memory eviction (blacklist + revoke) must complete in < 5 ms."""
        hub = _fresh_hub()
        sessions = _make_sessions(_make_session())
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )

        result = await engine.trigger_response("203.0.113.5", "sess-001", 0.9)

        assert result.delta_ms is not None
        assert result.delta_ms < 5.0, (
            f"Memory eviction took {result.delta_ms:.3f} ms — must be < 5 ms"
        )

    # ------------------------------------------------------------------
    # Multiple sessions for same IP all revoked
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_all_sessions_for_ip_revoked(self) -> None:
        hub = _fresh_hub()
        sessions = _make_sessions(
            _make_session("s1", "10.1.1.1"),
            _make_session("s2", "10.1.1.1"),   # same IP, different session
            _make_session("s3", "10.2.2.2"),   # different IP — should not be touched
        )
        blacklist: set[str] = set()
        engine = SOAREngine(
            event_hub=hub, active_sessions=sessions, perimeter_blacklist=blacklist
        )

        engine._revoke_sessions_for_ip("10.1.1.1")

        assert sessions["s1"].status is SessionStatus.REVOKED
        assert sessions["s2"].status is SessionStatus.REVOKED
        assert sessions["s3"].status is SessionStatus.ACTIVE  # untouched


# ---------------------------------------------------------------------------
# Property-based tests (hypothesis)
# ---------------------------------------------------------------------------

class TestSOARProperties:
    """Hypothesis-driven property proofs."""

    @given(
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
        score=st.floats(min_value=0.76, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=50, deadline=None)
    def test_property_11_ip_always_blacklisted(
        self, ip: str, score: float
    ) -> None:
        """For any IP and any score > 0.75, IP is in blacklist after trigger."""
        async def _run() -> None:
            hub = _fresh_hub()
            sessions = _make_sessions(_make_session(ip=ip))
            blacklist: set[str] = set()
            engine = SOAREngine(
                event_hub=hub,
                active_sessions=sessions,
                perimeter_blacklist=blacklist,
            )
            await engine.trigger_response(ip=ip, session_id="sess-001", anomaly_score=score)
            assert ip in blacklist

        asyncio.run(_run())

    @given(
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
        score=st.floats(min_value=0.76, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=50, deadline=None)
    def test_property_12_session_always_revoked(
        self, ip: str, score: float
    ) -> None:
        """For any IP/score, matching session has status=REVOKED after trigger."""
        async def _run() -> None:
            hub = _fresh_hub()
            rec = _make_session(session_id="s1", ip=ip, score=score)
            sessions = _make_sessions(rec)
            blacklist: set[str] = set()
            engine = SOAREngine(
                event_hub=hub,
                active_sessions=sessions,
                perimeter_blacklist=blacklist,
            )
            await engine.trigger_response(ip=ip, session_id="s1", anomaly_score=score)
            assert sessions["s1"].status is SessionStatus.REVOKED

        asyncio.run(_run())

    @given(
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
    )
    @settings(max_examples=50, deadline=None)
    def test_property_13_eviction_under_5ms_for_any_ip(self, ip: str) -> None:
        """Memory eviction phase must always complete in < 5 ms."""
        async def _run() -> SOARResult:
            hub = _fresh_hub()
            sessions = _make_sessions(_make_session(ip=ip))
            blacklist: set[str] = set()
            engine = SOAREngine(
                event_hub=hub,
                active_sessions=sessions,
                perimeter_blacklist=blacklist,
            )
            return await engine.trigger_response(
                ip=ip, session_id="sess-001", anomaly_score=0.9
            )

        result = asyncio.run(_run())
        assert result.delta_ms is not None
        assert result.delta_ms < 5.0, (
            f"Eviction for {ip!r} took {result.delta_ms:.3f} ms — must be < 5 ms"
        )

    @given(ip_string=st.text(min_size=0, max_size=40))
    @settings(max_examples=80, deadline=None)
    def test_property_14_reputation_never_raises(self, ip_string: str) -> None:
        """fetch_reputation never raises for any arbitrary string."""
        agg = ThreatIntelAggregator(timeout_s=0.000_001)

        async def _run() -> IPReputationReport:
            return await agg.fetch_reputation(ip_string)

        result = asyncio.run(_run())
        assert isinstance(result, IPReputationReport)
        assert result.source
        assert 0 <= result.abuse_confidence_score <= 100
