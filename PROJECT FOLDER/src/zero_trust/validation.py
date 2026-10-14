"""
src/zero_trust/validation.py
Field-level validation for TelemetryVector payloads.

All validators raise ValueError with an explicit, field-named description on
the first failing constraint so the Gateway can return HTTP 422 with a precise
error body.  No ML inference is ever called on an invalid payload.
"""

from __future__ import annotations

import math
from typing import Any

from src.zero_trust.models import TelemetryVector

# ---------------------------------------------------------------------------
# Constraint constants (mirrors Requirements 3.x)
# ---------------------------------------------------------------------------

_MAX_CLICK_INTERVALS = 1000
_MIN_PAGE_WEIGHT = 0.0
_MAX_PAGE_WEIGHT = 1.0
_MIN_SEQUENCE_ID = 1
_MAX_SEQUENCE_ID = 999_999
_MAX_SESSION_DURATION_MS = 86_400_000.0   # 24 hours
_MAX_REQUEST_RATE = 10_000.0


# ---------------------------------------------------------------------------
# Individual field validators
# ---------------------------------------------------------------------------

def _validate_click_speed_intervals(value: Any) -> None:
    """
    click_speed_intervals: non-empty list[float], max 1000 elements,
    all values >= 0.0, all finite.

    Raises
    ------
    ValueError
    """
    if not isinstance(value, list) or len(value) == 0:
        raise ValueError(
            "click_speed_intervals must be a non-empty list of floats."
        )
    if len(value) > _MAX_CLICK_INTERVALS:
        raise ValueError(
            f"click_speed_intervals exceeds maximum length of {_MAX_CLICK_INTERVALS} "
            f"(got {len(value)})."
        )
    for i, v in enumerate(value):
        if not isinstance(v, (int, float)):
            raise ValueError(
                f"click_speed_intervals[{i}] must be a float, got {type(v).__name__!r}."
            )
        fv = float(v)
        if not math.isfinite(fv):
            raise ValueError(
                f"click_speed_intervals[{i}] is non-finite: {v!r}."
            )
        if fv < 0.0:
            raise ValueError(
                f"click_speed_intervals[{i}] must be >= 0.0, got {v!r}."
            )


def _validate_page_path_weights(value: Any) -> None:
    """
    page_path_weights: non-empty collection of floats in [0.0, 1.0].

    Raises
    ------
    ValueError
    """
    if not hasattr(value, "__iter__") or not hasattr(value, "__len__"):
        raise ValueError("page_path_weights must be a non-empty collection.")
    if len(value) == 0:  # type: ignore[arg-type]
        raise ValueError("page_path_weights must be non-empty.")
    for i, v in enumerate(value):
        if not isinstance(v, (int, float)):
            raise ValueError(
                f"page_path_weights[{i}] must be a float, got {type(v).__name__!r}."
            )
        fv = float(v)
        if not math.isfinite(fv):
            raise ValueError(
                f"page_path_weights[{i}] is non-finite: {v!r}."
            )
        if not (_MIN_PAGE_WEIGHT <= fv <= _MAX_PAGE_WEIGHT):
            raise ValueError(
                f"page_path_weights[{i}] must be in [0.0, 1.0], got {v!r}."
            )


def _validate_sequence_transitions(value: Any) -> None:
    """
    sequence_transitions: list[int], each element in [1, 999999].

    Raises
    ------
    ValueError
    """
    if not isinstance(value, list):
        raise ValueError("sequence_transitions must be a list of integers.")
    for i, v in enumerate(value):
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError(
                f"sequence_transitions[{i}] must be an integer, "
                f"got {type(v).__name__!r}."
            )
        if not (_MIN_SEQUENCE_ID <= v <= _MAX_SEQUENCE_ID):
            raise ValueError(
                f"sequence_transitions[{i}] must be in "
                f"[{_MIN_SEQUENCE_ID}, {_MAX_SEQUENCE_ID}], got {v!r}."
            )


def _validate_session_duration_ms(value: Any) -> None:
    """
    session_duration_ms: non-negative float, max 86400000.

    Raises
    ------
    ValueError
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(
            f"session_duration_ms must be a float, got {type(value).__name__!r}."
        )
    fv = float(value)
    if not math.isfinite(fv):
        raise ValueError(f"session_duration_ms is non-finite: {value!r}.")
    if fv < 0.0:
        raise ValueError(
            f"session_duration_ms must be >= 0.0, got {value!r}."
        )
    if fv > _MAX_SESSION_DURATION_MS:
        raise ValueError(
            f"session_duration_ms exceeds maximum of {_MAX_SESSION_DURATION_MS} ms "
            f"(24 hours), got {value!r}."
        )


def _validate_request_rate_per_sec(value: Any) -> None:
    """
    request_rate_per_sec: non-negative float, max 10000.0.

    Raises
    ------
    ValueError
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(
            f"request_rate_per_sec must be a float, got {type(value).__name__!r}."
        )
    fv = float(value)
    if not math.isfinite(fv):
        raise ValueError(f"request_rate_per_sec is non-finite: {value!r}.")
    if fv < 0.0:
        raise ValueError(
            f"request_rate_per_sec must be >= 0.0, got {value!r}."
        )
    if fv > _MAX_REQUEST_RATE:
        raise ValueError(
            f"request_rate_per_sec exceeds maximum of {_MAX_REQUEST_RATE}, "
            f"got {value!r}."
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate_telemetry_vector(vector: TelemetryVector) -> None:
    """
    Run all field-level validation checks on a TelemetryVector instance.

    Validates fields in declaration order and raises on the first failure.
    After all field checks pass, calls ``to_feature_array()`` to catch any
    NaN/Infinity values produced during flattening.

    Parameters
    ----------
    vector : TelemetryVector
        The telemetry payload to validate.

    Raises
    ------
    ValueError
        With a descriptive message naming the failing field and constraint.
    """
    _validate_click_speed_intervals(vector.click_speed_intervals)
    _validate_page_path_weights(vector.page_path_weights)
    _validate_sequence_transitions(vector.sequence_transitions)
    _validate_session_duration_ms(vector.session_duration_ms)
    _validate_request_rate_per_sec(vector.request_rate_per_sec)

    # Final guard: ensure to_feature_array() produces an all-finite array.
    # This catches edge cases like inf produced by float arithmetic.
    vector.to_feature_array()
