"""
tests/test_models.py
Unit and property-based tests for core data models.

Covers:
  - TelemetryVector.to_feature_array() finiteness guarantee (Property 8)
  - SessionRecord.revocation_delta_ms correctness (Property 10)
  - AlertEvent.to_json() serialisation round-trip (Property 24)
  - AlertEvent required fields always present (Property 25)
  - AI_ANOMALY AlertEvent contains all enrichment fields (Property 26)
"""

from __future__ import annotations

import math
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.zero_trust.models import (
    AlertEvent,
    AlertType,
    GatewayDecision,
    IPReputationReport,
    PolicyAction,
    SOARResult,
    SessionRecord,
    SessionStatus,
    TelemetryVector,
)


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

finite_floats = st.floats(
    allow_nan=False,
    allow_infinity=False,
    min_value=-1e9,
    max_value=1e9,
)

positive_finite_floats = st.floats(
    allow_nan=False,
    allow_infinity=False,
    min_value=0.0,
    max_value=1e6,
)

unit_floats = st.floats(
    allow_nan=False,
    allow_infinity=False,
    min_value=0.0,
    max_value=1.0,
)

valid_telemetry_strategy = st.builds(
    TelemetryVector,
    click_speed_intervals=st.lists(
        st.floats(min_value=0.0, max_value=9999.0, allow_nan=False, allow_infinity=False),
        min_size=1,
        max_size=10,
    ),
    page_path_weights=st.lists(
        unit_floats,
        min_size=1,
        max_size=10,
    ),
    sequence_transitions=st.lists(
        st.integers(min_value=1, max_value=999_999),
        min_size=1,
        max_size=10,
    ),
    session_duration_ms=st.floats(
        min_value=0.0, max_value=86_400_000.0, allow_nan=False, allow_infinity=False
    ),
    request_rate_per_sec=st.floats(
        min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False
    ),
)


# ---------------------------------------------------------------------------
# TelemetryVector
# ---------------------------------------------------------------------------

class TestTelemetryVector:
    """Unit tests for TelemetryVector data model."""

    def _make_valid(self) -> TelemetryVector:
        return TelemetryVector(
            click_speed_intervals=[100.0, 200.0, 150.0],
            page_path_weights=[0.3, 0.7],
            sequence_transitions=[1, 2, 3],
            session_duration_ms=5000.0,
            request_rate_per_sec=2.5,
        )

    def test_to_feature_array_returns_list(self) -> None:
        result = self._make_valid().to_feature_array()
        assert isinstance(result, list)

    def test_to_feature_array_non_empty(self) -> None:
        result = self._make_valid().to_feature_array()
        assert len(result) > 0

    def test_to_feature_array_all_floats(self) -> None:
        result = self._make_valid().to_feature_array()
        for val in result:
            assert isinstance(val, float)

    def test_to_feature_array_all_finite(self) -> None:
        result = self._make_valid().to_feature_array()
        for val in result:
            assert math.isfinite(val)

    def test_to_feature_array_raises_on_nan(self) -> None:
        vec = TelemetryVector(
            click_speed_intervals=[float("nan")],
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=0.0,
            request_rate_per_sec=0.0,
        )
        with pytest.raises(ValueError, match="non-finite"):
            vec.to_feature_array()

    def test_to_feature_array_raises_on_inf(self) -> None:
        vec = TelemetryVector(
            click_speed_intervals=[float("inf")],
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=0.0,
            request_rate_per_sec=0.0,
        )
        with pytest.raises(ValueError, match="non-finite"):
            vec.to_feature_array()

    def test_to_feature_array_length(self) -> None:
        # Fixed 11-element layout: 3 click stats + 3 path stats + 3 seq stats + 2 scalars
        vec = self._make_valid()
        result = vec.to_feature_array()
        assert len(result) == TelemetryVector._FEATURE_DIM

    # Property 8: to_feature_array produces finite numeric arrays
    @given(valid_telemetry_strategy)
    @settings(max_examples=200)
    def test_property_8_to_feature_array_always_finite(
        self, vec: TelemetryVector
    ) -> None:
        result = vec.to_feature_array()
        assert len(result) > 0
        for val in result:
            assert math.isfinite(val), f"Non-finite value in output: {val}"


# ---------------------------------------------------------------------------
# SessionRecord
# ---------------------------------------------------------------------------

class TestSessionRecord:
    """Unit tests for SessionRecord and revocation_delta_ms."""

    def _make_active(self) -> SessionRecord:
        return SessionRecord(
            session_id="sess-001",
            ip_address="192.168.1.1",
            role="Guest",
            anomaly_score=0.3,
        )

    def test_default_status_is_active(self) -> None:
        rec = self._make_active()
        assert rec.status is SessionStatus.ACTIVE

    def test_revocation_delta_none_when_active(self) -> None:
        rec = self._make_active()
        assert rec.revocation_delta_ms is None

    def test_revocation_delta_none_when_expired(self) -> None:
        rec = self._make_active()
        rec.status = SessionStatus.EXPIRED
        assert rec.revocation_delta_ms is None

    def test_revocation_delta_computed_correctly(self) -> None:
        created = time.time() * 1000
        revoked = created + 1500.0
        rec = SessionRecord(
            session_id="sess-002",
            ip_address="10.0.0.1",
            role="Admin",
            anomaly_score=0.9,
            status=SessionStatus.REVOKED,
            created_at_ms=created,
            revoked_at_ms=revoked,
        )
        assert rec.revocation_delta_ms == pytest.approx(1500.0)

    def test_revocation_delta_non_negative(self) -> None:
        now = time.time() * 1000
        rec = SessionRecord(
            session_id="sess-003",
            ip_address="10.0.0.2",
            role="Engineer",
            anomaly_score=0.8,
            status=SessionStatus.REVOKED,
            created_at_ms=now,
            revoked_at_ms=now + 250.0,
        )
        delta = rec.revocation_delta_ms
        assert delta is not None
        assert delta >= 0.0

    def test_required_fields_non_none(self) -> None:
        rec = self._make_active()
        assert rec.session_id is not None
        assert rec.ip_address is not None
        assert rec.role is not None
        assert rec.anomaly_score is not None
        assert rec.status is not None
        assert rec.created_at_ms is not None

    # Property 9: SessionRecord required fields always present
    @given(
        session_id=st.text(min_size=1, max_size=64),
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
        role=st.sampled_from(["Admin", "Engineer", "Guest"]),
        score=unit_floats,
    )
    @settings(max_examples=150)
    def test_property_9_required_fields_present(
        self, session_id: str, ip: str, role: str, score: float
    ) -> None:
        rec = SessionRecord(
            session_id=session_id,
            ip_address=ip,
            role=role,
            anomaly_score=score,
        )
        assert rec.session_id is not None
        assert rec.ip_address is not None
        assert rec.role is not None
        assert rec.anomaly_score is not None
        assert rec.status is SessionStatus.ACTIVE
        assert rec.created_at_ms is not None

    # Property 10: Revocation delta correctly computed
    @given(
        created=st.floats(min_value=0.0, max_value=1e10, allow_nan=False, allow_infinity=False),
        elapsed=st.floats(min_value=0.0, max_value=1e6, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=150)
    def test_property_10_revocation_delta_correct(
        self, created: float, elapsed: float
    ) -> None:
        revoked = created + elapsed
        rec = SessionRecord(
            session_id="s",
            ip_address="1.2.3.4",
            role="Guest",
            anomaly_score=0.5,
            status=SessionStatus.REVOKED,
            created_at_ms=created,
            revoked_at_ms=revoked,
        )
        delta = rec.revocation_delta_ms
        assert delta is not None
        # Use relative tolerance to handle large float magnitudes
        assert delta == pytest.approx(elapsed, rel=1e-6, abs=1e-3)
        assert delta >= 0.0


# ---------------------------------------------------------------------------
# AlertEvent
# ---------------------------------------------------------------------------

class TestAlertEvent:
    """Unit tests for AlertEvent and to_json()."""

    def _make_ai_anomaly(self) -> AlertEvent:
        return AlertEvent(
            alert_type=AlertType.AI_ANOMALY,
            source_ip="203.0.113.5",
            timestamp_ms=1_700_000_000_000.0,
            session_id="sess-ai-001",
            anomaly_score=0.88,
            abuse_score=95,
            revocation_delta_ms=350.0,
        )

    def _make_honeytoken(self) -> AlertEvent:
        return AlertEvent(
            alert_type=AlertType.HONEYTOKEN_ACCESS,
            source_ip="local",
            timestamp_ms=1_700_000_001_000.0,
            affected_path="/abs/data/honey_tokens/db_config.json",
        )

    def _make_port_trap(self) -> AlertEvent:
        return AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip="198.51.100.42",
            timestamp_ms=1_700_000_002_000.0,
            port=3389,
        )

    # Property 25: required fields always present in serialised output
    def test_required_fields_in_json(self) -> None:
        for event in [
            self._make_ai_anomaly(),
            self._make_honeytoken(),
            self._make_port_trap(),
        ]:
            payload = event.to_json()
            assert "alert_type" in payload
            assert "source_ip" in payload
            assert "timestamp_ms" in payload

    def test_alert_type_serialised_as_string(self) -> None:
        payload = self._make_ai_anomaly().to_json()
        assert payload["alert_type"] == "AI_ANOMALY"

    def test_none_fields_excluded(self) -> None:
        event = AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip="1.2.3.4",
            timestamp_ms=0.0,
            port=3389,
        )
        payload = event.to_json()
        assert "session_id" not in payload
        assert "anomaly_score" not in payload
        assert "affected_path" not in payload
        assert "abuse_score" not in payload
        assert "revocation_delta_ms" not in payload

    # Property 26: AI_ANOMALY must carry enrichment fields
    def test_ai_anomaly_enrichment_fields_non_none(self) -> None:
        event = self._make_ai_anomaly()
        assert event.session_id is not None
        assert event.anomaly_score is not None
        assert event.abuse_score is not None
        assert event.revocation_delta_ms is not None

    # Property 24: serialisation round-trip
    def test_round_trip_ai_anomaly(self) -> None:
        original = self._make_ai_anomaly()
        payload = original.to_json()
        restored = AlertEvent(
            alert_type=AlertType(payload["alert_type"]),
            source_ip=payload["source_ip"],
            timestamp_ms=payload["timestamp_ms"],
            session_id=payload.get("session_id"),
            anomaly_score=payload.get("anomaly_score"),
            abuse_score=payload.get("abuse_score"),
            revocation_delta_ms=payload.get("revocation_delta_ms"),
        )
        assert restored.alert_type == original.alert_type
        assert restored.source_ip == original.source_ip
        assert restored.timestamp_ms == original.timestamp_ms
        assert restored.session_id == original.session_id
        assert restored.anomaly_score == pytest.approx(original.anomaly_score)  # type: ignore[arg-type]
        assert restored.abuse_score == original.abuse_score
        assert restored.revocation_delta_ms == pytest.approx(original.revocation_delta_ms)  # type: ignore[arg-type]

    def test_round_trip_honeytoken(self) -> None:
        original = self._make_honeytoken()
        payload = original.to_json()
        restored = AlertEvent(
            alert_type=AlertType(payload["alert_type"]),
            source_ip=payload["source_ip"],
            timestamp_ms=payload["timestamp_ms"],
            affected_path=payload.get("affected_path"),
        )
        assert restored.alert_type == original.alert_type
        assert restored.affected_path == original.affected_path

    def test_round_trip_port_trap(self) -> None:
        original = self._make_port_trap()
        payload = original.to_json()
        restored = AlertEvent(
            alert_type=AlertType(payload["alert_type"]),
            source_ip=payload["source_ip"],
            timestamp_ms=payload["timestamp_ms"],
            port=payload.get("port"),
        )
        assert restored.alert_type == original.alert_type
        assert restored.port == original.port


# ---------------------------------------------------------------------------
# Supporting dataclasses — smoke tests
# ---------------------------------------------------------------------------

class TestSupportingModels:
    """Verify the remaining dataclasses are importable and constructible."""

    def test_ip_reputation_report(self) -> None:
        r = IPReputationReport(
            ip_address="1.2.3.4",
            abuse_confidence_score=75,
            country_code="US",
            total_reports=12,
            is_whitelisted=False,
            source="abuseipdb",
        )
        assert r.source == "abuseipdb"
        assert 0 <= r.abuse_confidence_score <= 100

    def test_gateway_decision(self) -> None:
        d = GatewayDecision(
            action=PolicyAction.BLOCK,
            session_id=None,
            anomaly_score=0.0,
            reason="blacklisted_ip",
        )
        assert d.action is PolicyAction.BLOCK
        assert d.anomaly_score == 0.0

    def test_soar_result(self) -> None:
        r = SOARResult(success=True, delta_ms=500.0)
        assert r.success is True
        assert r.delta_ms == 500.0
