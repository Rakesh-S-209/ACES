"""
src/zero_trust/scorer.py
Isolation Forest anomaly scorer for behavioral telemetry.

Two operating modes
-------------------
1. **Offline-trained mode** (production):
   Load a pre-trained model bundle from ``data/behavior_model.pkl`` via
   ``BehaviorScorer.from_pkl()``.  The bundle was fitted on 362 K rows of
   real benign network flow data (BenignTraffic.pcap.csv) using
   ``train_behavior_model.py``.  A RobustScaler is included and applied
   transparently during ``predict()``.

2. **Synthetic-fit mode** (tests / first-run fallback):
   Call ``scorer.fit(baseline_vectors)`` with a list of ``TelemetryVector``
   objects to train on synthetic data -- identical to original behaviour.

Normalisation formula (Requirements 2.3)
-----------------------------------------
    clamped = clip(raw_decision_function_output, -0.5, 0.5)
    score   = (0.5 - clamped) / 1.0

    raw = -0.5  ->  score = 1.0  (maximum anomaly)
    raw = +0.5  ->  score = 0.0  (normal behaviour)

Telemetry Payload (score_detailed)
------------------------------------
    score_detailed() returns a structured dict suitable for the
    /api/telemetry/score endpoint and the Baseline Timeline dashboard:
        anomaly_score      : float   raw normalised score in [0, 1]
        baseline_threshold : float   fixed decision boundary (0.50)
        is_anomaly         : bool    True when score >= baseline_threshold
        timestamp          : str     ISO 8601 UTC timestamp
"""

from __future__ import annotations

import datetime
import logging
import math
from pathlib import Path
from typing import Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from src.zero_trust.models import TelemetryVector
from src.zero_trust.validation import validate_telemetry_vector

logger = logging.getLogger(__name__)

# Normalisation clamp range (Requirements 2.3)
_CLAMP_LOW  = -0.5
_CLAMP_HIGH =  0.5

# ---------------------------------------------------------------------------
# Public threshold constants — shared with financial_shell.py and soc.html
# ---------------------------------------------------------------------------
# BASELINE_THRESHOLD is the primary decision boundary exposed in the
# telemetry payload.  Any score >= this value is classified as anomalous.
BASELINE_THRESHOLD: float = 0.50   # SOC alert / normal-traffic boundary
ESCALATION_THRESHOLD: float = 0.85  # SOAR auto-containment boundary

# Default pkl path (relative to project root)
_DEFAULT_PKL = Path("data") / "behavior_model.pkl"

# Feature order the pkl model was trained on (must match train_behavior_model.py)
_PKL_FEATURE_COLUMNS: list[str] = [
    "Rate", "IAT", "Variance",
    "Header_Length", "AVG", "Std", "Tot size", "Min", "Max",
    "Number", "Time_To_Live", "Protocol Type",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number",
    "cwr_flag_number", "syn_count", "fin_count", "rst_count", "ack_count",
    "TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP",
]


# ---------------------------------------------------------------------------
# Feature bridge: TelemetryVector -> 29-element flow feature array
# ---------------------------------------------------------------------------

def _telemetry_to_flow_features(tv: TelemetryVector) -> list[float]:
    """
    Map a portal-level TelemetryVector to the 29 flow-level feature values
    expected by the pkl-trained IsolationForest + RobustScaler.

    Key attack indicators and how they map
    ---------------------------------------
    High request_rate_per_sec (>50 rps)  -> Rate far above benign median (~161 rps median in dataset)
    Short click intervals (<20 ms)       -> IAT near zero (benign IAT median ~0.007 s)
    Extreme page_path_weights (0 or 1)   -> unusual TTL (benign clusters around 93 / 131)
    High sequence IDs (>100)             -> proto outside normal range
    Scanning pattern                     -> syn_flag=1, http/https=0 (not in benign set)
    """
    clicks   = tv.click_speed_intervals or [200.0]
    n_clicks = len(clicks)
    mean_c   = sum(clicks) / n_clicks
    max_c    = max(clicks)
    min_c    = min(clicks)
    var_c    = sum((x - mean_c) ** 2 for x in clicks) / max(n_clicks, 1)
    std_c    = math.sqrt(var_c) if var_c > 0 else 0.0

    # ── Rate (packets/sec) ── direct mapping
    rate = float(max(0.0, min(tv.request_rate_per_sec, 10000.0)))

    # ── IAT (inter-arrival time, seconds) ──
    # Benign median ~0.007 s.  Short click intervals -> near-zero IAT -> anomalous.
    iat = float(max(1e-7, mean_c / 1000.0))

    # ── Variance of IAT ── benign flows have moderate variance
    variance = float(var_c / 1000.0)

    # ── Packet size proxies ──
    # Benign median AVG ~173 bytes.  Scanners send tiny SYN packets (~60 bytes).
    # High rate -> many small packets; low rate -> fewer normal-sized packets.
    avg_size = float(max(60.0, min(1514.0, 1500.0 / max(1.0, rate / 5.0))))
    std_size = float(max(0.0, std_c * 1.5))
    min_size = float(max(60.0, min_c / 3.0))
    max_size = float(min(9000.0, avg_size * 4.0))
    tot_size = float(avg_size * n_clicks)
    number   = float(n_clicks)

    # ── TTL ── benign clusters at 64/128 mapped from path weights
    pw0 = float(tv.page_path_weights[0]) if tv.page_path_weights else 0.5
    # Extreme weights (0 or 1) push TTL outside the benign cluster -> anomalous
    ttl = float(max(1.0, pw0 * 250.0))

    # ── Protocol type ── benign mostly TCP(6); high seq IDs -> exotic proto
    seq0  = int(tv.sequence_transitions[0]) if tv.sequence_transitions else 6
    proto = float(seq0 % 17)

    # ── TCP flag behaviour ──
    # Scanning: high rate OR very short intervals -> SYN-dominated
    is_scanning = rate > 50.0 or mean_c < 20.0
    syn_flag  = 1.0 if is_scanning else 0.0
    ack_flag  = 0.0 if is_scanning else 1.0
    fin_flag  = 0.0
    rst_flag  = 0.0
    psh_flag  = 0.0
    ece_flag  = 0.0
    cwr_flag  = 0.0
    syn_count = float(n_clicks) if is_scanning else 0.0
    ack_count = float(n_clicks) if not is_scanning else 0.0
    fin_count = 0.0
    rst_count = 0.0

    # ── Protocol presence ──
    tcp_frac   = 1.0
    udp_frac   = 1.0 if proto == 17 else 0.0
    # Scanners typically have no HTTP/HTTPS (they're not making web requests)
    http_frac  = 0.0 if is_scanning else 1.0
    https_frac = 0.0 if is_scanning else 1.0
    dns_frac   = 0.0
    icmp_frac  = 0.0

    return [
        rate, iat, variance,
        avg_size, avg_size, std_size, tot_size, min_size, max_size,
        number, ttl, proto,
        fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, ece_flag, cwr_flag,
        syn_count, fin_count, rst_count, ack_count,
        tcp_frac, udp_frac, http_frac, https_frac, dns_frac, icmp_frac,
    ]


# ---------------------------------------------------------------------------
# BehaviorScorer
# ---------------------------------------------------------------------------

class BehaviorScorer:
    """
    Unsupervised anomaly scorer backed by scikit-learn IsolationForest.

    Production usage (offline-trained pkl):
        scorer = BehaviorScorer.from_pkl()
        score  = scorer.predict(telemetry_vector)  # float in [0, 1]

    Test / fallback usage (synthetic fit):
        scorer = BehaviorScorer(n_estimators=100, contamination=0.05)
        scorer.fit(baseline_vectors)
        score  = scorer.predict(telemetry_vector)
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.05,
    ) -> None:
        self._n_estimators   = n_estimators
        self._contamination  = contamination
        self._model:   Optional[IsolationForest] = None
        self._scaler:  Optional[Any]             = None
        self._fitted:  bool  = False
        self._pkl_mode: bool = False

    # ------------------------------------------------------------------
    # Factory: load from pkl
    # ------------------------------------------------------------------

    @classmethod
    def from_pkl(
        cls,
        pkl_path: "Path | str" = _DEFAULT_PKL,
    ) -> "BehaviorScorer":
        """
        Load a pre-trained model bundle produced by train_behavior_model.py.

        The bundle must contain keys: model, scaler, feature_columns.

        Raises FileNotFoundError if the pkl does not exist.
        """
        import joblib
        pkl_path = Path(pkl_path)
        if not pkl_path.exists():
            raise FileNotFoundError(
                f"behavior_model.pkl not found at {pkl_path.resolve()}.\n"
                "Run train_behavior_model.py first."
            )
        bundle = joblib.load(pkl_path)
        for key in ("model", "scaler", "feature_columns"):
            if key not in bundle:
                raise ValueError(
                    f"behavior_model.pkl is missing key '{key}'. "
                    "Re-run train_behavior_model.py."
                )
        instance             = cls.__new__(cls)
        instance._n_estimators  = bundle.get("n_estimators", 200)
        instance._contamination = bundle.get("contamination", 0.02)
        instance._model         = bundle["model"]
        instance._scaler        = bundle["scaler"]
        instance._fitted        = True
        instance._pkl_mode      = True
        logger.info(
            "BehaviorScorer: loaded offline pkl from %s "
            "(%d estimators, contamination=%.3f, %d features)",
            pkl_path.resolve(),
            instance._n_estimators,
            instance._contamination,
            len(bundle["feature_columns"]),
        )
        return instance

    # ------------------------------------------------------------------
    # Synthetic fit (tests / first-run fallback)
    # ------------------------------------------------------------------

    def fit(self, baseline_vectors: list[TelemetryVector]) -> None:
        """Train on a list of TelemetryVector baseline samples."""
        feature_matrix = []
        for i, vec in enumerate(baseline_vectors):
            try:
                validate_telemetry_vector(vec)
                feature_matrix.append(vec.to_feature_array())
            except ValueError as exc:
                raise ValueError(
                    f"Baseline vector at index {i} failed validation: {exc}"
                ) from exc
        X = np.array(feature_matrix, dtype=float)
        model = IsolationForest(
            n_estimators  = self._n_estimators,
            contamination = self._contamination,
            random_state  = 42,
        )
        model.fit(X)
        self._model    = model
        self._scaler   = None
        self._fitted   = True
        self._pkl_mode = False

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, telemetry: TelemetryVector) -> float:
        """
        Score a TelemetryVector.

        Returns a float in [0.0, 1.0]:
            0.0  = perfectly normal (deep inside benign cluster)
            0.50 = SOC alert threshold (mid-range anomaly)
            0.85 = SOAR auto-containment threshold
            1.0  = maximum anomaly
        """
        if not self._fitted or self._model is None:
            raise NotFittedError(
                "BehaviorScorer not fitted. "
                "Call BehaviorScorer.from_pkl() or scorer.fit() first."
            )
        validate_telemetry_vector(telemetry)

        if self._pkl_mode:
            flow = _telemetry_to_flow_features(telemetry)
            # Sanitise
            flow = [0.0 if not math.isfinite(v) else v for v in flow]
            X_raw = np.array([flow], dtype=np.float64)
            X = self._scaler.transform(X_raw) if self._scaler else X_raw
        else:
            fa = telemetry.to_feature_array()
            for v in fa:
                if not math.isfinite(v):
                    raise ValueError(f"Non-finite feature value: {v!r}")
            X = np.array([fa], dtype=float)

        raw: float = float(self._model.decision_function(X)[0])
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, raw))
        score   = (_CLAMP_HIGH - clamped) / 1.0
        return float(max(0.0, min(1.0, score)))

    # ------------------------------------------------------------------
    # Detailed scoring payload (for /api/telemetry/score endpoint)
    # ------------------------------------------------------------------

    def score_detailed(self, telemetry: TelemetryVector) -> dict:
        """
        Score a TelemetryVector and return a structured telemetry payload
        suitable for the Baseline Timeline dashboard chart.

        Returns
        -------
        dict
            {
                "anomaly_score"      : float  -- normalised score in [0, 1]
                "baseline_threshold" : float  -- fixed boundary (0.50)
                "is_anomaly"         : bool   -- True when score >= threshold
                "timestamp"          : str    -- ISO 8601 UTC timestamp
            }
        """
        score = self.predict(telemetry)
        return {
            "anomaly_score":      round(score, 6),
            "baseline_threshold": BASELINE_THRESHOLD,
            "is_anomaly":         score >= BASELINE_THRESHOLD,
            "timestamp":          datetime.datetime.utcnow().isoformat() + "Z",
        }

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_pkl_mode(self) -> bool:
        """True when loaded from a pre-trained pkl bundle."""
        return self._pkl_mode

    @property
    def is_fitted(self) -> bool:
        """True after from_pkl() or fit() succeeds."""
        return self._fitted
