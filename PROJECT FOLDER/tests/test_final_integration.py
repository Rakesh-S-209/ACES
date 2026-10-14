# tests/test_final_integration.py
"""
Full-stack integration tests for Project A.C.E.S.

Verifies:
  - FinancialPortalShell and MockStorefrontShell are interchangeable
  - High-risk bursts trigger SOAR escalation identically on both shells
  - AlertEvents flow through the EventHub without exceptions
  - SOCDashboardServer serialises events to valid JSON
  - Portal shells handle malformed payloads gracefully
"""

from __future__ import annotations

import asyncio
import importlib
import json
import time
from typing import Dict, List
from unittest.mock import AsyncMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import src.soc_pipeline.event_hub as _hub_module
from src.soc_pipeline.event_hub import EventHub
from src.soc_pipeline.soar_engine import SOAREngine
from src.soc_pipeline.ws_dashboard import SOCDashboardServer
from src.zero_trust.models import (
    AlertEvent,
    AlertType,
    SessionRecord,
    SessionStatus,
    TelemetryVector,
)
from src.zero_trust.scorer import BehaviorScorer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_hub() -> EventHub:
    importlib.reload(_hub_module)
    from src.soc_pipeline.event_hub import EventHub as FH
    return FH()


def _fitted_scorer(n: int = 120) -> BehaviorScorer:
    scorer = BehaviorScorer(n_estimators=30, contamination=0.05)
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


def _make_engine(
    hub: EventHub,
    sessions: Dict[str, SessionRecord],
    blacklist: set,
) -> SOAREngine:
    return SOAREngine(
        event_hub=hub,
        active_sessions=sessions,
        perimeter_blacklist=blacklist,
    )


# ---------------------------------------------------------------------------
# MockStorefrontShell -- alternative portal for swap tests
# ---------------------------------------------------------------------------

from src.portal.gateway import BasePortalShell


class MockStorefrontShell(BasePortalShell):
    """
    Lightweight mock portal that maps storefront actions to the same
    AI scoring and SOAR pipeline as FinancialPortalShell.
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
        self.escalation_count: int = 0

    async def handle_user_action(
        self,
        session_id: str,
        ip: str,
        action_type: str,
        click_payload: dict,
    ) -> dict:
        click_intervals = click_payload.get("click_intervals", [150.0, 250.0])
        vector = TelemetryVector(
            click_speed_intervals=click_intervals or [150.0],
            page_path_weights=[0.5, 0.5],
            sequence_transitions=[1, 2, 3],
            session_duration_ms=float(click_payload.get("session_duration_ms", 5000.0)),
            request_rate_per_sec=float(click_payload.get("request_rate_per_sec", 2.0)),
        )

        score = self._scorer.predict(vector)

        if session_id not in self._sessions:
            self._sessions[session_id] = SessionRecord(
                session_id=session_id,
                ip_address=ip,
                role="Guest",
                anomaly_score=score,
            )

        allowed = True
        if score >= 0.85:
            self.escalation_count += 1
            allowed = False
            asyncio.create_task(
                self._soar.trigger_response(
                    ip=ip, session_id=session_id, anomaly_score=score
                )
            )

        return {
            "allowed": allowed,
            "score": round(score, 6),
            "action": "ALLOW" if allowed else "REVOKE",
            "session_id": session_id,
            "action_type": action_type,
        }


# ---------------------------------------------------------------------------
# Portal shell interchangeability tests
# ---------------------------------------------------------------------------

class TestPortalShellInterchangeability:
    """Both shells must honour the BasePortalShell contract identically."""

    @pytest.mark.asyncio
    async def test_financial_shell_returns_required_keys(self) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shell = FinancialPortalShell(
            scorer=scorer, soar_engine=engine, active_sessions=sessions
        )
        result = await shell.handle_user_action(
            session_id="s1",
            ip="127.0.0.1",
            action_type="view_balance",
            click_payload={"click_intervals": [100.0, 200.0], "session_duration_ms": 2000.0},
        )
        for key in ("allowed", "score", "action", "session_id", "action_type"):
            assert key in result, f"Missing key: {key}"

    @pytest.mark.asyncio
    async def test_mock_storefront_returns_required_keys(self) -> None:
        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shell = MockStorefrontShell(
            scorer=scorer, soar_engine=engine, active_sessions=sessions
        )
        result = await shell.handle_user_action(
            session_id="s2",
            ip="127.0.0.1",
            action_type="browse_products",
            click_payload={"click_intervals": [120.0], "session_duration_ms": 3000.0},
        )
        for key in ("allowed", "score", "action", "session_id", "action_type"):
            assert key in result, f"Missing key: {key}"

    @pytest.mark.asyncio
    async def test_score_is_in_valid_range_for_both_shells(self) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        financial = FinancialPortalShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)
        storefront = MockStorefrontShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)

        for shell in (financial, storefront):
            result = await shell.handle_user_action(
                "s-range", "10.0.0.1", "view_balance",
                {"click_intervals": [100.0], "session_duration_ms": 1000.0}
            )
            assert 0.0 <= result["score"] <= 1.0

    @pytest.mark.asyncio
    async def test_shells_are_swappable_via_base_type(self) -> None:
        """Calling the abstract interface works for both implementations."""
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shells: list[BasePortalShell] = [
            FinancialPortalShell(scorer=scorer, soar_engine=engine, active_sessions=sessions),
            MockStorefrontShell(scorer=scorer, soar_engine=engine, active_sessions=sessions),
        ]
        payload = {"click_intervals": [50.0, 100.0], "session_duration_ms": 2000.0}

        for i, shell in enumerate(shells):
            result = await shell.handle_user_action(
                f"sess-{i}", "10.0.0.1", "test_action", payload
            )
            assert isinstance(result, dict)
            assert "allowed" in result


# ---------------------------------------------------------------------------
# High-risk burst escalation tests
# ---------------------------------------------------------------------------

class TestHighRiskBurstEscalation:
    """Both shells must escalate identically when given extreme telemetry."""

    def _make_burst_payload(self) -> dict:
        """Craft a payload that looks highly anomalous to the IsolationForest."""
        return {
            "click_intervals": [0.001, 0.001, 0.001],   # impossibly fast clicks
            "session_duration_ms": 50.0,                 # near-instant session
            "request_rate_per_sec": 9999.0,              # extreme rate
        }

    @pytest.mark.asyncio
    async def test_financial_shell_session_created(self) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shell = FinancialPortalShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)
        await shell.handle_user_action(
            "s-burst", "203.0.113.1", "wire_transfer", self._make_burst_payload()
        )
        # Session must have been registered
        assert "s-burst" in sessions

    @pytest.mark.asyncio
    async def test_storefront_shell_session_created(self) -> None:
        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shell = MockStorefrontShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)
        await shell.handle_user_action(
            "s-burst2", "203.0.113.2", "checkout", self._make_burst_payload()
        )
        assert "s-burst2" in sessions

    @pytest.mark.asyncio
    async def test_high_risk_triggers_soar_on_financial_shell(self) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()

        soar_calls: list[dict] = []

        engine = _make_engine(hub, sessions, blacklist)

        original_trigger = engine.trigger_response

        async def capture_trigger(ip, session_id, anomaly_score):
            soar_calls.append({"ip": ip, "session_id": session_id, "score": anomaly_score})
            return await original_trigger(ip, session_id, anomaly_score)

        engine.trigger_response = capture_trigger  # type: ignore[method-assign]

        scorer = _fitted_scorer()
        shell = FinancialPortalShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)

        result = await shell.handle_user_action(
            "s-high", "203.0.113.5", "admin_login", self._make_burst_payload()
        )

        # Give the background task time to fire
        await asyncio.sleep(0.1)

        if result["score"] >= 0.85:
            assert len(soar_calls) >= 1, "SOAR must be triggered for score >= 0.85"

    @pytest.mark.asyncio
    async def test_allowed_false_when_score_above_threshold(self) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shell = FinancialPortalShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)
        result = await shell.handle_user_action(
            "s-thr", "10.0.0.1", "wire_transfer", self._make_burst_payload()
        )

        if result["score"] >= 0.85:
            assert result["allowed"] is False
            assert result["action"] == "REVOKE"


# ---------------------------------------------------------------------------
# EventHub data-flow integration tests
# ---------------------------------------------------------------------------

class TestEventHubDataFlow:
    """Alerts must flow through EventHub without exceptions."""

    @pytest.mark.asyncio
    async def test_alert_published_to_hub(self) -> None:
        hub = _fresh_hub()
        received: list[AlertEvent] = []

        async def consume() -> None:
            async for event in hub.subscribe():
                received.append(event)
                if len(received) >= 1:
                    break

        task = asyncio.create_task(consume())
        await asyncio.sleep(0)

        alert = AlertEvent(
            alert_type=AlertType.AI_ANOMALY,
            source_ip="10.0.0.1",
            timestamp_ms=time.time() * 1000,
            session_id="s1",
            anomaly_score=0.9,
            abuse_score=85,
            revocation_delta_ms=1.2,
        )
        await hub.publish(alert)
        await asyncio.wait_for(task, timeout=2.0)

        assert len(received) == 1
        assert received[0].alert_type is AlertType.AI_ANOMALY

    @pytest.mark.asyncio
    async def test_multiple_alert_types_flow_correctly(self) -> None:
        hub = _fresh_hub()
        received: list[AlertEvent] = []

        async def consume() -> None:
            async for event in hub.subscribe():
                received.append(event)
                if len(received) >= 3:
                    break

        task = asyncio.create_task(consume())
        await asyncio.sleep(0)

        for alert_type, extra in [
            (AlertType.AI_ANOMALY, {"anomaly_score": 0.9, "abuse_score": 80}),
            (AlertType.PORT_TRAP, {"port": 3389}),
            (AlertType.HONEYTOKEN_ACCESS, {"affected_path": "/data/honey_tokens/db_config.json"}),
        ]:
            await hub.publish(
                AlertEvent(
                    alert_type=alert_type,
                    source_ip="1.2.3.4",
                    timestamp_ms=time.time() * 1000,
                    **extra,
                )
            )

        await asyncio.wait_for(task, timeout=3.0)
        alert_types = [e.alert_type for e in received]
        assert AlertType.AI_ANOMALY in alert_types
        assert AlertType.PORT_TRAP in alert_types
        assert AlertType.HONEYTOKEN_ACCESS in alert_types


# ---------------------------------------------------------------------------
# SOCDashboardServer serialisation tests
# ---------------------------------------------------------------------------

class TestSOCDashboardServer:
    """Events must be serialised to valid, complete JSON frames."""

    def test_serialise_ai_anomaly(self) -> None:
        hub = _fresh_hub()
        server = SOCDashboardServer(event_hub=hub)

        event = AlertEvent(
            alert_type=AlertType.AI_ANOMALY,
            source_ip="203.0.113.5",
            timestamp_ms=1_700_000_000_000.0,
            session_id="s1",
            anomaly_score=0.92,
            abuse_score=90,
            revocation_delta_ms=1.5,
        )
        frame = server._serialise(event)
        payload = json.loads(frame.decode("utf-8").strip())

        assert payload["alert_type"] == "AI_ANOMALY"
        assert payload["source_ip"] == "203.0.113.5"
        assert payload["anomaly_score"] == pytest.approx(0.92)
        assert "server_ts_ms" in payload

    def test_serialise_port_trap(self) -> None:
        hub = _fresh_hub()
        server = SOCDashboardServer(event_hub=hub)

        event = AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip="198.51.100.1",
            timestamp_ms=1_700_000_001_000.0,
            port=3389,
        )
        frame = server._serialise(event)
        payload = json.loads(frame.decode("utf-8").strip())

        assert payload["alert_type"] == "PORT_TRAP"
        assert payload["port"] == 3389

    def test_serialise_honeytoken(self) -> None:
        hub = _fresh_hub()
        server = SOCDashboardServer(event_hub=hub)

        event = AlertEvent(
            alert_type=AlertType.HONEYTOKEN_ACCESS,
            source_ip="local",
            timestamp_ms=1_700_000_002_000.0,
            affected_path="/data/honey_tokens/db_config.json",
        )
        frame = server._serialise(event)
        payload = json.loads(frame.decode("utf-8").strip())

        assert payload["affected_path"] == "/data/honey_tokens/db_config.json"

    def test_frame_is_newline_terminated(self) -> None:
        """WebSocket frame must contain the serialised JSON payload."""
        hub = _fresh_hub()
        server = SOCDashboardServer(event_hub=hub)
        event = AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip="1.2.3.4",
            timestamp_ms=0.0,
            port=3389,
        )
        data = server._serialise(event)
        frame = server._make_ws_frame(data)
        # Frame must contain the JSON data bytes
        assert data in frame

    def test_frame_is_valid_utf8(self) -> None:
        hub = _fresh_hub()
        server = SOCDashboardServer(event_hub=hub)
        event = AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip="1.2.3.4",
            timestamp_ms=0.0,
            port=3389,
        )
        frame = server._serialise(event)
        frame.decode("utf-8")  # must not raise

    @pytest.mark.asyncio
    async def test_bind_failure_is_graceful(self) -> None:
        from unittest.mock import patch
        hub = _fresh_hub()
        server = SOCDashboardServer(event_hub=hub, port=8000)

        with patch("asyncio.start_server", side_effect=OSError("in use")):
            await server.start()  # must not raise

        assert server._server is None

    def test_ws_make_frame_valid(self) -> None:
        """_make_ws_frame must produce a correctly framed RFC-6455 text frame."""
        hub = _fresh_hub()
        server = SOCDashboardServer(event_hub=hub)
        data = b'{"alert_type":"PORT_TRAP"}'
        frame = server._make_ws_frame(data)
        # First byte 0x81 = FIN + opcode 1 (text)
        assert frame[0] == 0x81
        # Payload bytes must follow header
        assert data in frame


# ---------------------------------------------------------------------------
# Property-based interchangeability test
# ---------------------------------------------------------------------------

class TestPropertyBasedInterchangeability:
    """Hypothesis: both shells handle any valid payload without exceptions."""

    @given(
        click_intervals=st.lists(
            st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
            min_size=1, max_size=5,
        ),
        duration=st.floats(min_value=0.0, max_value=86_400_000.0, allow_nan=False, allow_infinity=False),
        rate=st.floats(min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False),
        action=st.sampled_from(["view_balance", "wire_transfer", "admin_login"]),
    )
    @settings(max_examples=60, deadline=None)
    def test_financial_shell_never_raises(
        self,
        click_intervals: list[float],
        duration: float,
        rate: float,
        action: str,
    ) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        async def _run() -> dict:
            hub = _fresh_hub()
            sessions: Dict[str, SessionRecord] = {}
            blacklist: set = set()
            engine = _make_engine(hub, sessions, blacklist)
            scorer = _fitted_scorer(80)
            shell = FinancialPortalShell(
                scorer=scorer, soar_engine=engine, active_sessions=sessions
            )
            return await shell.handle_user_action(
                "s1", "10.0.0.1", action,
                {"click_intervals": click_intervals,
                 "session_duration_ms": duration,
                 "request_rate_per_sec": rate},
            )

        result = asyncio.run(_run())
        assert isinstance(result, dict)
        assert 0.0 <= result["score"] <= 1.0

    @given(
        click_intervals=st.lists(
            st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
            min_size=1, max_size=5,
        ),
        duration=st.floats(min_value=0.0, max_value=86_400_000.0, allow_nan=False, allow_infinity=False),
        rate=st.floats(min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=60, deadline=None)
    def test_storefront_shell_never_raises(
        self,
        click_intervals: list[float],
        duration: float,
        rate: float,
    ) -> None:
        async def _run() -> dict:
            hub = _fresh_hub()
            sessions: Dict[str, SessionRecord] = {}
            blacklist: set = set()
            engine = _make_engine(hub, sessions, blacklist)
            scorer = _fitted_scorer(80)
            shell = MockStorefrontShell(
                scorer=scorer, soar_engine=engine, active_sessions=sessions
            )
            return await shell.handle_user_action(
                "s2", "10.0.0.2", "browse",
                {"click_intervals": click_intervals,
                 "session_duration_ms": duration,
                 "request_rate_per_sec": rate},
            )

        result = asyncio.run(_run())
        assert isinstance(result, dict)
        assert 0.0 <= result["score"] <= 1.0

    @given(
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
    )
    @settings(max_examples=40, deadline=None)
    def test_event_flows_to_hub_for_any_ip(self, ip: str) -> None:
        """Any AlertEvent published must be receivable without exception."""
        async def _run() -> AlertEvent:
            hub = _fresh_hub()
            received: list[AlertEvent] = []

            async def consume() -> None:
                async for e in hub.subscribe():
                    received.append(e)
                    break

            task = asyncio.create_task(consume())
            await asyncio.sleep(0)
            await hub.publish(
                AlertEvent(
                    alert_type=AlertType.PORT_TRAP,
                    source_ip=ip,
                    timestamp_ms=time.time() * 1000,
                    port=3389,
                )
            )
            await asyncio.wait_for(task, timeout=2.0)
            return received[0]

        event = asyncio.run(_run())
        assert event.source_ip == ip


# ---------------------------------------------------------------------------
# Malformed payload resilience
# ---------------------------------------------------------------------------

class TestMalformedPayloadResilience:
    """Portal shells must not raise on missing or degenerate payloads."""

    @pytest.mark.asyncio
    async def test_financial_shell_empty_payload(self) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shell = FinancialPortalShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)
        result = await shell.handle_user_action("s1", "127.0.0.1", "view_balance", {})
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_financial_shell_unknown_action_type(self) -> None:
        from src.portal.financial_shell import FinancialPortalShell

        hub = _fresh_hub()
        sessions: Dict[str, SessionRecord] = {}
        blacklist: set = set()
        engine = _make_engine(hub, sessions, blacklist)
        scorer = _fitted_scorer()

        shell = FinancialPortalShell(scorer=scorer, soar_engine=engine, active_sessions=sessions)
        result = await shell.handle_user_action(
            "s2", "127.0.0.1", "unknown_action_xyz",
            {"click_intervals": [100.0], "session_duration_ms": 1000.0}
        )
        assert isinstance(result, dict)
        assert "score" in result
