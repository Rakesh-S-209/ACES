"""
src/zero_trust/models.py
Core data models and enumerations for Project A.C.E.S.

All state objects are pure Python dataclasses with no I/O side effects.
No secrets are stored in any model field.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SessionStatus(str, Enum):
    """Lifecycle states of a tracked user session."""
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class AlertType(str, Enum):
    """Categories of security alert events produced by deception subsystems."""
    AI_ANOMALY = "AI_ANOMALY"
    HONEYTOKEN_ACCESS = "HONEYTOKEN_ACCESS"
    PORT_TRAP = "PORT_TRAP"


class PolicyAction(str, Enum):
    """Zero Trust Gateway enforcement outcomes."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVOKE = "REVOKE"


# ---------------------------------------------------------------------------
# TelemetryVector
# ---------------------------------------------------------------------------

@dataclass
class TelemetryVector:
    """
    Structured behavioral telemetry payload captured from a client session.

    Fields
    ------
    click_speed_intervals : list[float]
        Milliseconds between successive click events. All values must be >= 0.
    page_path_weights : list[float]
        Normalised path-popularity scores. All values must be in [0.0, 1.0].
    sequence_transitions : list[int]
        Encoded page-to-page transition IDs. Each must be in [1, 999999].
    session_duration_ms : float
        Total session age in milliseconds. Must be in [0.0, 86400000].
    request_rate_per_sec : float
        Requests per second. Must be in [0.0, 10000.0].
    """

    click_speed_intervals: list[float]
    page_path_weights: list[float]
    sequence_transitions: list[int]
    session_duration_ms: float
    request_rate_per_sec: float

    # Fixed feature dimension: 3 (click) + 3 (path) + 3 (seq) + 2 (scalar) = 11
    _FEATURE_DIM: int = 11

    def to_feature_array(self) -> list[float]:
        """
        Produce a **fixed-length** numeric feature vector for ML inference.

        Variable-length list fields are reduced to three summary statistics
        (mean, max, length) so that the feature dimension is always constant
        regardless of payload size.  This ensures IsolationForest receives
        the same number of features at fit-time and predict-time.

        Feature layout (11 elements):
            [0]  click_speed_intervals — mean
            [1]  click_speed_intervals — max
            [2]  click_speed_intervals — count (float)
            [3]  page_path_weights     — mean
            [4]  page_path_weights     — max
            [5]  page_path_weights     — count (float)
            [6]  sequence_transitions  — mean
            [7]  sequence_transitions  — max
            [8]  sequence_transitions  — count (float)
            [9]  session_duration_ms
            [10] request_rate_per_sec

        Returns
        -------
        list[float]
            A non-empty, all-finite flat list of 11 floats.

        Raises
        ------
        ValueError
            If any element in the resulting array is NaN or infinite.
        """
        def _summarise(values: list) -> tuple[float, float, float]:
            if not values:
                return 0.0, 0.0, 0.0
            floats = [float(v) for v in values]
            return (
                sum(floats) / len(floats),   # mean
                max(floats),                  # max
                float(len(floats)),           # count
            )

        c_mean, c_max, c_cnt = _summarise(self.click_speed_intervals)
        p_mean, p_max, p_cnt = _summarise(self.page_path_weights)
        s_mean, s_max, s_cnt = _summarise(self.sequence_transitions)

        combined: list[float] = [
            c_mean, c_max, c_cnt,
            p_mean, p_max, p_cnt,
            s_mean, s_max, s_cnt,
            float(self.session_duration_ms),
            float(self.request_rate_per_sec),
        ]

        for i, val in enumerate(combined):
            if not math.isfinite(val):
                raise ValueError(
                    f"to_feature_array() produced a non-finite value at index {i}: {val!r}. "
                    "All elements must be finite floats."
                )

        return combined


# ---------------------------------------------------------------------------
# SessionRecord
# ---------------------------------------------------------------------------

@dataclass
class SessionRecord:
    """
    In-memory record for a single tracked user session.

    Fields
    ------
    session_id : str
        Non-empty unique identifier for this session.
    ip_address : str
        Source IPv4 or IPv6 address string.
    role : str
        One of "Admin", "Engineer", or "Guest".
    anomaly_score : float
        Normalised anomaly score in [0.0, 1.0] from BehaviorScorer.
    status : SessionStatus
        Current lifecycle state; defaults to ACTIVE on creation.
    created_at_ms : float
        Unix epoch millisecond timestamp at session creation.
    revoked_at_ms : float | None
        Unix epoch millisecond timestamp at revocation, or None.
    """

    session_id: str
    ip_address: str
    role: str
    anomaly_score: float
    status: SessionStatus = SessionStatus.ACTIVE
    created_at_ms: float = field(default_factory=lambda: time.time() * 1000)
    revoked_at_ms: Optional[float] = None

    @property
    def revocation_delta_ms(self) -> Optional[float]:
        """
        Elapsed milliseconds from session creation to revocation.

        Returns
        -------
        float
            revoked_at_ms - created_at_ms  (always >= 0) when REVOKED.
        None
            For any status other than REVOKED.
        """
        if self.status is SessionStatus.REVOKED and self.revoked_at_ms is not None:
            return self.revoked_at_ms - self.created_at_ms
        return None


# ---------------------------------------------------------------------------
# AlertEvent
# ---------------------------------------------------------------------------

@dataclass
class AlertEvent:
    """
    Structured security alert event published to the EventHub.

    Required fields are present for every alert type.
    Optional fields are populated based on alert type.
    """

    # Required fields
    alert_type: AlertType
    source_ip: str
    timestamp_ms: float

    # Optional enrichment fields (type-specific)
    session_id: Optional[str] = None
    anomaly_score: Optional[float] = None        # AI_ANOMALY
    affected_path: Optional[str] = None          # HONEYTOKEN_ACCESS
    port: Optional[int] = None                   # PORT_TRAP
    abuse_score: Optional[int] = None            # AI_ANOMALY (AbuseIPDB)
    revocation_delta_ms: Optional[float] = None  # AI_ANOMALY

    def to_json(self) -> dict:
        """
        Serialise all non-None fields to a JSON-safe dictionary.

        The ``alert_type`` field is serialised as its string enum value.

        Returns
        -------
        dict
            JSON-serialisable dictionary containing all non-None fields.

        Raises
        ------
        TypeError
            If any field value cannot be serialised (propagated to caller).
        """
        raw: dict = {
            "alert_type": self.alert_type.value,
            "source_ip": self.source_ip,
            "timestamp_ms": self.timestamp_ms,
        }
        optional_fields = {
            "session_id": self.session_id,
            "anomaly_score": self.anomaly_score,
            "affected_path": self.affected_path,
            "port": self.port,
            "abuse_score": self.abuse_score,
            "revocation_delta_ms": self.revocation_delta_ms,
        }
        for key, value in optional_fields.items():
            if value is not None:
                raw[key] = value
        return raw


# ---------------------------------------------------------------------------
# IPReputationReport
# ---------------------------------------------------------------------------

@dataclass
class IPReputationReport:
    """
    AbuseIPDB enrichment data for a queried IP address.

    Fields
    ------
    ip_address : str
        The queried IP address string.
    abuse_confidence_score : int
        Integer in [0, 100] representing abuse likelihood from AbuseIPDB.
    country_code : str
        Two-letter ISO 3166-1 alpha-2 country code, or "XX" for unknown.
    total_reports : int
        Total number of abuse reports for this IP.
    is_whitelisted : bool
        Whether the IP is on AbuseIPDB's whitelist.
    source : str
        Data provenance: "abuseipdb", "offline_fallback", or
        "offline_fallback_error".
    """

    ip_address: str
    abuse_confidence_score: int
    country_code: str
    total_reports: int
    is_whitelisted: bool
    source: str


# ---------------------------------------------------------------------------
# GatewayDecision
# ---------------------------------------------------------------------------

@dataclass
class GatewayDecision:
    """
    Zero Trust Gateway policy decision returned after request evaluation.

    Fields
    ------
    action : PolicyAction
        Enforcement outcome: ALLOW, BLOCK, or REVOKE.
    session_id : str | None
        Session identifier, or None for BLOCK decisions.
    anomaly_score : float
        Normalised anomaly score in [0.0, 1.0]; always present.
    reason : str
        Human-readable reason string explaining the decision.
    """

    action: PolicyAction
    session_id: Optional[str]
    anomaly_score: float
    reason: str


# ---------------------------------------------------------------------------
# SOARResult
# ---------------------------------------------------------------------------

@dataclass
class SOARResult:
    """
    Result object returned by the SOAR engine after pipeline completion.

    Fields
    ------
    success : bool
        True if all pipeline steps completed without error.
    delta_ms : float | None
        Milliseconds from session creation to revocation, or None on failure.
    """

    success: bool
    delta_ms: Optional[float]
