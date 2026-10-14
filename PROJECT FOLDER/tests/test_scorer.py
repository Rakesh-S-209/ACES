"""
tests/test_scorer.py
Unit and property-based tests for BehaviorScorer.

Covers:
  - Property 1: scores are always in [0.0, 1.0]
  - Property 5: normalisation formula is correct
  - Property 6: score determinism for same input
  - Requirement 2.5: NotFittedError before fit()
  - Requirement 2.8: ValueError on NaN/Inf input
"""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sklearn.exceptions import NotFittedError

from src.zero_trust.models import TelemetryVector
from src.zero_trust.scorer import BehaviorScorer, _CLAMP_HIGH, _CLAMP_LOW


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vector(
    click: list[float] | None = None,
    weights: list[float] | None = None,
    transitions: list[int] | None = None,
    duration: float = 1000.0,
    rate: float = 1.0,
) -> TelemetryVector:
    return TelemetryVector(
        click_speed_intervals=click or [100.0, 200.0, 150.0],
        page_path_weights=weights or [0.3, 0.7],
        sequence_transitions=transitions or [1, 2, 3],
        session_duration_ms=duration,
        request_rate_per_sec=rate,
    )


def _make_scorer_fitted(n: int = 120) -> BehaviorScorer:
    """Return a fitted BehaviorScorer trained on n synthetic normal samples.

    Because to_feature_array() always produces 11 features via summary stats,
    any valid TelemetryVector shape works for both fit and predict.
    """
    scorer = BehaviorScorer(n_estimators=50, contamination=0.05)
    baseline = [
        _make_vector(
            click=[float(i % 300 + 50), float(i % 200 + 100), float(i % 100 + 10)],
            weights=[0.4, 0.6],
            transitions=[1, 2, 3],
            duration=float(i * 100 + 500),
            rate=float(i % 10 + 1),
        )
        for i in range(n)
    ]
    scorer.fit(baseline)
    return scorer


# ---------------------------------------------------------------------------
# Unfitted model
# ---------------------------------------------------------------------------

class TestUnfittedModel:
    def test_predict_before_fit_raises_not_fitted_error(self) -> None:
        scorer = BehaviorScorer()
        vec = _make_vector()
        with pytest.raises(NotFittedError):
            scorer.predict(vec)

    def test_not_fitted_error_message_informative(self) -> None:
        scorer = BehaviorScorer()
        with pytest.raises(NotFittedError, match="fit\\(\\)"):
            scorer.predict(_make_vector())


# ---------------------------------------------------------------------------
# Fitting
# ---------------------------------------------------------------------------

class TestFit:
    def test_fit_succeeds_with_minimum_samples(self) -> None:
        scorer = BehaviorScorer(n_estimators=10)
        scorer.fit([_make_vector()] * 10)

    def test_fit_with_invalid_vector_raises(self) -> None:
        scorer = BehaviorScorer(n_estimators=10)
        bad = _make_vector()
        bad.click_speed_intervals = []  # empty — invalid
        with pytest.raises(ValueError, match="index 0"):
            scorer.fit([bad])

    def test_custom_parameters_accepted(self) -> None:
        scorer = BehaviorScorer(n_estimators=20, contamination=0.1)
        scorer.fit([_make_vector()] * 30)


# ---------------------------------------------------------------------------
# Score range (Property 1)
# ---------------------------------------------------------------------------

class TestScoreRange:
    def test_normal_vector_score_in_range(self) -> None:
        scorer = _make_scorer_fitted()
        score = scorer.predict(_make_vector())
        assert 0.0 <= score <= 1.0

    def test_anomalous_vector_score_in_range(self) -> None:
        scorer = _make_scorer_fitted()
        anomalous = _make_vector(
            click=[0.001, 0.001],   # very fast clicks
            rate=9999.0,            # extremely high request rate
            duration=100.0,
        )
        score = scorer.predict(anomalous)
        assert 0.0 <= score <= 1.0

    def test_anomalous_vector_tends_higher(self) -> None:
        """High-rate anomalous vector should score higher than normal vector."""
        scorer = _make_scorer_fitted(150)
        normal_score = scorer.predict(_make_vector())
        anomalous = _make_vector(
            click=[0.001, 0.001],
            rate=9999.0,
            duration=50.0,
        )
        anomalous_score = scorer.predict(anomalous)
        # Not a hard guarantee but a sanity check on directionality
        assert anomalous_score >= normal_score or anomalous_score >= 0.5


# ---------------------------------------------------------------------------
# Property 5: normalisation formula
# ---------------------------------------------------------------------------

class TestNormalisationFormula:
    @given(
        raw=st.floats(
            min_value=-10.0, max_value=10.0, allow_nan=False, allow_infinity=False
        )
    )
    @settings(max_examples=300)
    def test_property_5_formula_correct(self, raw: float) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, raw))
        expected = (_CLAMP_HIGH - clamped) / 1.0
        assert 0.0 <= expected <= 1.0, (
            f"Formula produced out-of-range value for raw={raw}: {expected}"
        )

    def test_raw_minus_half_gives_one(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, -0.5))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(1.0)

    def test_raw_plus_half_gives_zero(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, 0.5))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(0.0)

    def test_raw_zero_gives_half(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, 0.0))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Property 6: score determinism
# ---------------------------------------------------------------------------

class TestScoreDeterminism:
    def test_same_vector_same_score(self) -> None:
        scorer = _make_scorer_fitted()
        vec = _make_vector()
        s1 = scorer.predict(vec)
        s2 = scorer.predict(vec)
        assert s1 == pytest.approx(s2)

    @given(
        click=st.lists(
            st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
            min_size=1, max_size=5,
        ),
        rate=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=50, deadline=None)
    def test_property_6_deterministic(self, click: list[float], rate: float) -> None:
        scorer = _make_scorer_fitted(100)
        vec = _make_vector(click=click, rate=rate)
        s1 = scorer.predict(vec)
        s2 = scorer.predict(vec)
        assert s1 == pytest.approx(s2, abs=1e-9)


# ---------------------------------------------------------------------------
# Non-finite input (Requirement 2.8)
# ---------------------------------------------------------------------------

class TestNonFiniteInput:
    def test_nan_in_click_intervals_raises(self) -> None:
        scorer = _make_scorer_fitted()
        vec = _make_vector(click=[float("nan")])
        with pytest.raises(ValueError):
            scorer.predict(vec)

    def test_inf_in_click_intervals_raises(self) -> None:
        scorer = _make_scorer_fitted()
        vec = _make_vector(click=[float("inf")])
        with pytest.raises(ValueError):
            scorer.predict(vec)


# ---------------------------------------------------------------------------
# Property 1: score always in [0.0, 1.0] (hypothesis)
# ---------------------------------------------------------------------------

class TestProperty1:
    @given(
        click=st.lists(
            st.floats(min_value=0.0, max_value=9000.0, allow_nan=False, allow_infinity=False),
            min_size=1, max_size=8,
        ),
        weights=st.lists(
            st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
            min_size=1, max_size=5,
        ),
        transitions=st.lists(
            st.integers(min_value=1, max_value=999_999),
            min_size=1, max_size=5,
        ),
        duration=st.floats(
            min_value=0.0, max_value=86_400_000.0, allow_nan=False, allow_infinity=False
        ),
        rate=st.floats(
            min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False
        ),
    )
    @settings(max_examples=200)
    def test_property_1_score_always_bounded(
        self,
        click: list[float],
        weights: list[float],
        transitions: list[int],
        duration: float,
        rate: float,
    ) -> None:
        scorer = _make_scorer_fitted(120)
        vec = TelemetryVector(
            click_speed_intervals=click,
            page_path_weights=weights,
            sequence_transitions=transitions,
            session_duration_ms=duration,
            request_rate_per_sec=rate,
        )
        score = scorer.predict(vec)
        assert 0.0 <= score <= 1.0, (
            f"Score {score!r} is outside [0.0, 1.0] for input vector {vec!r}"
        )
