"""
tests/test_validation.py
Unit and property-based tests for TelemetryVector field validation.

Covers Property 7: validation rejects any vector with out-of-range fields
before ML scoring is attempted.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.zero_trust.models import TelemetryVector
from src.zero_trust.validation import validate_telemetry_vector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_vector() -> TelemetryVector:
    return TelemetryVector(
        click_speed_intervals=[100.0, 200.0],
        page_path_weights=[0.5, 0.8],
        sequence_transitions=[1, 2, 3],
        session_duration_ms=3000.0,
        request_rate_per_sec=5.0,
    )


# ---------------------------------------------------------------------------
# click_speed_intervals
# ---------------------------------------------------------------------------

class TestClickSpeedIntervals:
    def test_empty_list_raises(self) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = []
        with pytest.raises(ValueError, match="click_speed_intervals"):
            validate_telemetry_vector(vec)

    def test_exceeds_max_length_raises(self) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = [1.0] * 1001
        with pytest.raises(ValueError, match="click_speed_intervals"):
            validate_telemetry_vector(vec)

    def test_negative_value_raises(self) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = [100.0, -1.0]
        with pytest.raises(ValueError, match="click_speed_intervals"):
            validate_telemetry_vector(vec)

    def test_nan_raises(self) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = [float("nan")]
        with pytest.raises(ValueError):
            validate_telemetry_vector(vec)

    def test_inf_raises(self) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = [float("inf")]
        with pytest.raises(ValueError):
            validate_telemetry_vector(vec)

    def test_max_length_boundary_passes(self) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = [0.0] * 1000
        validate_telemetry_vector(vec)  # should not raise

    def test_zero_value_passes(self) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = [0.0]
        validate_telemetry_vector(vec)  # 0 is valid (>= 0)


# ---------------------------------------------------------------------------
# page_path_weights
# ---------------------------------------------------------------------------

class TestPagePathWeights:
    def test_empty_raises(self) -> None:
        vec = _valid_vector()
        vec.page_path_weights = []
        with pytest.raises(ValueError, match="page_path_weights"):
            validate_telemetry_vector(vec)

    def test_above_one_raises(self) -> None:
        vec = _valid_vector()
        vec.page_path_weights = [1.1]
        with pytest.raises(ValueError, match="page_path_weights"):
            validate_telemetry_vector(vec)

    def test_below_zero_raises(self) -> None:
        vec = _valid_vector()
        vec.page_path_weights = [-0.1]
        with pytest.raises(ValueError, match="page_path_weights"):
            validate_telemetry_vector(vec)

    def test_boundary_values_pass(self) -> None:
        vec = _valid_vector()
        vec.page_path_weights = [0.0, 1.0]
        validate_telemetry_vector(vec)


# ---------------------------------------------------------------------------
# sequence_transitions
# ---------------------------------------------------------------------------

class TestSequenceTransitions:
    def test_zero_id_raises(self) -> None:
        vec = _valid_vector()
        vec.sequence_transitions = [0]
        with pytest.raises(ValueError, match="sequence_transitions"):
            validate_telemetry_vector(vec)

    def test_id_above_max_raises(self) -> None:
        vec = _valid_vector()
        vec.sequence_transitions = [1_000_000]
        with pytest.raises(ValueError, match="sequence_transitions"):
            validate_telemetry_vector(vec)

    def test_float_in_list_raises(self) -> None:
        vec = _valid_vector()
        vec.sequence_transitions = [1.5]  # type: ignore[list-item]
        with pytest.raises(ValueError, match="sequence_transitions"):
            validate_telemetry_vector(vec)

    def test_boundary_min_passes(self) -> None:
        vec = _valid_vector()
        vec.sequence_transitions = [1]
        validate_telemetry_vector(vec)

    def test_boundary_max_passes(self) -> None:
        vec = _valid_vector()
        vec.sequence_transitions = [999_999]
        validate_telemetry_vector(vec)

    def test_empty_list_passes(self) -> None:
        # Empty sequence is allowed (no invalid values to reject)
        vec = _valid_vector()
        vec.sequence_transitions = []
        validate_telemetry_vector(vec)


# ---------------------------------------------------------------------------
# session_duration_ms
# ---------------------------------------------------------------------------

class TestSessionDurationMs:
    def test_negative_raises(self) -> None:
        vec = _valid_vector()
        vec.session_duration_ms = -1.0
        with pytest.raises(ValueError, match="session_duration_ms"):
            validate_telemetry_vector(vec)

    def test_exceeds_24h_raises(self) -> None:
        vec = _valid_vector()
        vec.session_duration_ms = 86_400_001.0
        with pytest.raises(ValueError, match="session_duration_ms"):
            validate_telemetry_vector(vec)

    def test_exactly_24h_passes(self) -> None:
        vec = _valid_vector()
        vec.session_duration_ms = 86_400_000.0
        validate_telemetry_vector(vec)

    def test_zero_passes(self) -> None:
        vec = _valid_vector()
        vec.session_duration_ms = 0.0
        validate_telemetry_vector(vec)

    def test_nan_raises(self) -> None:
        vec = _valid_vector()
        vec.session_duration_ms = float("nan")
        with pytest.raises(ValueError):
            validate_telemetry_vector(vec)


# ---------------------------------------------------------------------------
# request_rate_per_sec
# ---------------------------------------------------------------------------

class TestRequestRatePerSec:
    def test_negative_raises(self) -> None:
        vec = _valid_vector()
        vec.request_rate_per_sec = -0.1
        with pytest.raises(ValueError, match="request_rate_per_sec"):
            validate_telemetry_vector(vec)

    def test_exceeds_max_raises(self) -> None:
        vec = _valid_vector()
        vec.request_rate_per_sec = 10_001.0
        with pytest.raises(ValueError, match="request_rate_per_sec"):
            validate_telemetry_vector(vec)

    def test_exactly_max_passes(self) -> None:
        vec = _valid_vector()
        vec.request_rate_per_sec = 10_000.0
        validate_telemetry_vector(vec)

    def test_zero_passes(self) -> None:
        vec = _valid_vector()
        vec.request_rate_per_sec = 0.0
        validate_telemetry_vector(vec)


# ---------------------------------------------------------------------------
# Property 7: validation always rejects invalid payloads
# ---------------------------------------------------------------------------

class TestProperty7:
    @given(
        bad_interval=st.floats(
            max_value=-0.001, allow_nan=False, allow_infinity=False
        )
    )
    @settings(max_examples=100)
    def test_negative_click_interval_always_rejected(
        self, bad_interval: float
    ) -> None:
        vec = _valid_vector()
        vec.click_speed_intervals = [abs(bad_interval) * -1 - 0.001]
        with pytest.raises(ValueError):
            validate_telemetry_vector(vec)

    @given(
        bad_weight=st.one_of(
            st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False),
            st.floats(min_value=1.001, allow_nan=False, allow_infinity=False),
        )
    )
    @settings(max_examples=100)
    def test_out_of_range_page_weight_always_rejected(
        self, bad_weight: float
    ) -> None:
        vec = _valid_vector()
        vec.page_path_weights = [bad_weight]
        with pytest.raises(ValueError):
            validate_telemetry_vector(vec)

    @given(
        bad_duration=st.floats(
            max_value=-0.001, allow_nan=False, allow_infinity=False
        )
    )
    @settings(max_examples=100)
    def test_negative_session_duration_always_rejected(
        self, bad_duration: float
    ) -> None:
        vec = _valid_vector()
        vec.session_duration_ms = bad_duration
        with pytest.raises(ValueError):
            validate_telemetry_vector(vec)

    @given(
        bad_rate=st.floats(
            max_value=-0.001, allow_nan=False, allow_infinity=False
        )
    )
    @settings(max_examples=100)
    def test_negative_request_rate_always_rejected(
        self, bad_rate: float
    ) -> None:
        vec = _valid_vector()
        vec.request_rate_per_sec = bad_rate
        with pytest.raises(ValueError):
            validate_telemetry_vector(vec)
