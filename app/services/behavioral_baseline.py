from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
import logging
import math
import statistics
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASELINE_SCHEMA_VERSION: int = 1
DRIFT_WINDOW_SECONDS: int = 3600
MAX_BASELINE_SAMPLES: int = 1000
MIN_SAMPLES_FOR_BASELINE: int = 5

DriftSeverity = Literal["none", "low", "medium", "high", "critical"]
DriftCategory = Literal[
    "action_frequency",
    "action_type_distribution",
    "target_scope",
    "risk_score_elevation",
    "session_anomaly",
    "tool_call_pattern",
    "unknown",
]
BaselineStatus = Literal["learning", "active", "stale", "suspended"]


# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

_BASELINE_UPDATE_BATCH: int = 10
_EMA_ALPHA: float = 0.10
_MIN_STDEV_RISK: float = 2.0
_MIN_STDEV_RATE: float = 2.0
_MIN_STDEV_BREADTH: float = 0.15
_JSD_SIGNAL_THRESHOLD: float = 0.15
_TARGET_SCOPE_SIGNAL_THRESHOLD: float = 0.30
_Z_SCORE_CAP: float = 5.0

# Session anomaly: flag if current session's action count exceeds baseline
# mean session size by this many standard deviations.
_SESSION_ANOMALY_Z_THRESHOLD: float = 2.0
_MIN_STDEV_SESSION: float = 1.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _utcnow_iso() -> str:
    return _utcnow().isoformat().replace("+00:00", "Z")


def _require_str(value: str, field_name: str) -> str:
    stripped = value.strip() if isinstance(value, str) else ""
    if not stripped:
        raise ValueError(f"{field_name} must be a non-empty string")
    return stripped


def _safe_mean(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def _safe_stdev(values: list[float]) -> float:
    return statistics.stdev(values) if len(values) >= 2 else 0.0


def _z_score(observed: float, mean: float, stdev: float) -> float:
    if stdev == 0.0:
        return 0.0
    return abs(observed - mean) / stdev


def _jensen_shannon_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    all_keys = set(p.keys()) | set(q.keys())
    if not all_keys:
        return 0.0

    p_vec = [p.get(k, 0.0) for k in all_keys]
    q_vec = [q.get(k, 0.0) for k in all_keys]

    p_sum = sum(p_vec)
    q_sum = sum(q_vec)
    if p_sum == 0.0 and q_sum == 0.0:
        return 0.0

    p_norm = [v / p_sum for v in p_vec] if p_sum > 0.0 else [0.0] * len(p_vec)
    q_norm = [v / q_sum for v in q_vec] if q_sum > 0.0 else [0.0] * len(q_vec)
    m_vec = [(pi + qi) / 2 for pi, qi in zip(p_norm, q_norm, strict=False)]

    def _kl(a: list[float], b: list[float]) -> float:
        total = 0.0
        for ai, bi in zip(a, b, strict=False):
            if ai > 0.0 and bi > 0.0:
                total += ai * math.log2(ai / bi)
        return total

    jsd = (_kl(p_norm, m_vec) + _kl(q_norm, m_vec)) / 2.0
    return min(max(jsd, 0.0), 1.0)


def _normalize_distribution(counts: dict[str, int]) -> dict[str, float]:
    total = sum(counts.values())
    if total == 0:
        return {}
    return {k: v / total for k, v in counts.items()}


def _severity_from_score(score: float) -> DriftSeverity:
    if score >= 0.90:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.45:
        return "medium"
    if score >= 0.20:
        return "low"
    return "none"


def _emit_telemetry(event_name: str, payload: dict[str, Any]) -> None:
    try:
        from app.services.telemetry import append_telemetry_event  # noqa: PLC0415

        append_telemetry_event(event_name, payload)
    except Exception:  # noqa: BLE001
        pass


def _get_logger() -> logging.Logger:
    try:
        from app.core.logging import get_logger  # noqa: PLC0415

        return get_logger("ironclaw.behavioral_baseline")
    except Exception:  # noqa: BLE001
        return logging.getLogger("ironclaw.behavioral_baseline")


_logger: logging.Logger = _get_logger()


# ---------------------------------------------------------------------------
# Supabase persistence helpers
# ---------------------------------------------------------------------------


def _supabase_persist_observation(obs: AgentObservation) -> None:
    try:
        from app.services.supabase_adapter import get_supabase_adapter  # noqa: PLC0415

        adapter = get_supabase_adapter()
        if adapter is None or not adapter.available:
            return
        result = adapter.persist_observation(obs.to_dict())
        if not result.success:
            _logger.warning(
                "supabase_observation_persist_failed",
                extra={
                    "event": "supabase_observation_persist_failed",
                    "observation_id": obs.observation_id,
                    "agent_id": obs.agent_id,
                    "error": result.error,
                },
            )
    except Exception:  # noqa: BLE001
        pass


def _supabase_persist_baseline(baseline: AgentBaseline) -> None:
    try:
        from app.services.supabase_adapter import get_supabase_adapter  # noqa: PLC0415

        adapter = get_supabase_adapter()
        if adapter is None or not adapter.available:
            return
        result = adapter.persist_baseline(baseline.to_dict())
        if not result.success:
            _logger.warning(
                "supabase_baseline_persist_failed",
                extra={
                    "event": "supabase_baseline_persist_failed",
                    "baseline_id": baseline.baseline_id,
                    "agent_id": baseline.agent_id,
                    "error": result.error,
                },
            )
    except Exception:  # noqa: BLE001
        pass


def _supabase_persist_drift_report(report: DriftReport) -> None:
    try:
        from app.services.supabase_adapter import get_supabase_adapter  # noqa: PLC0415

        adapter = get_supabase_adapter()
        if adapter is None or not adapter.available:
            return
        result = adapter.persist_drift_report(report.to_dict())
        if not result.success:
            _logger.warning(
                "supabase_drift_report_persist_failed",
                extra={
                    "event": "supabase_drift_report_persist_failed",
                    "report_id": report.report_id,
                    "agent_id": report.agent_id,
                    "error": result.error,
                },
            )
    except Exception:  # noqa: BLE001
        pass


def _supabase_delete_agent(agent_id: str, client_id: str | None) -> None:
    try:
        from app.services.supabase_adapter import get_supabase_adapter  # noqa: PLC0415

        adapter = get_supabase_adapter()
        if adapter is None or not adapter.available:
            return
        adapter.delete_agent_data(agent_id, client_id=client_id)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AgentObservation:
    observation_id: str
    agent_id: str
    session_id: str | None
    client_id: str | None
    timestamp: datetime
    action_type: str
    target: str
    risk_score: int
    matched_patterns: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        return payload


@dataclass(slots=True)
class AgentBaseline:
    baseline_id: str
    agent_id: str
    client_id: str | None
    status: BaselineStatus
    schema_version: int
    sample_count: int
    created_at: datetime
    updated_at: datetime
    mean_action_rate: float
    stdev_action_rate: float
    action_type_distribution: dict[str, float]
    mean_risk_score: float
    stdev_risk_score: float
    mean_target_breadth: float
    stdev_target_breadth: float
    mean_tool_call_rate: float
    stdev_tool_call_rate: float
    frozen_action_type_distribution: dict[str, float] = field(default_factory=dict)
    baseline_obs_count: int = 0
    # Session size statistics for session_anomaly detection
    mean_session_size: float = 0.0
    stdev_session_size: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        payload["updated_at"] = self.updated_at.isoformat().replace("+00:00", "Z")
        return payload

    def _replace_status(self, status: BaselineStatus) -> AgentBaseline:
        """Return a shallow copy with only status and updated_at changed."""
        return AgentBaseline(
            baseline_id=self.baseline_id,
            agent_id=self.agent_id,
            client_id=self.client_id,
            status=status,
            schema_version=self.schema_version,
            sample_count=self.sample_count,
            created_at=self.created_at,
            updated_at=_utcnow(),
            mean_action_rate=self.mean_action_rate,
            stdev_action_rate=self.stdev_action_rate,
            action_type_distribution=dict(self.action_type_distribution),
            mean_risk_score=self.mean_risk_score,
            stdev_risk_score=self.stdev_risk_score,
            mean_target_breadth=self.mean_target_breadth,
            stdev_target_breadth=self.stdev_target_breadth,
            mean_tool_call_rate=self.mean_tool_call_rate,
            stdev_tool_call_rate=self.stdev_tool_call_rate,
            frozen_action_type_distribution=dict(self.frozen_action_type_distribution),
            baseline_obs_count=self.baseline_obs_count,
            mean_session_size=self.mean_session_size,
            stdev_session_size=self.stdev_session_size,
            metadata=dict(self.metadata),
        )


@dataclass(slots=True)
class DriftSignal:
    category: DriftCategory
    observed_value: float
    baseline_value: float
    deviation_score: float
    severity: DriftSeverity
    detail: str


@dataclass(slots=True)
class DriftReport:
    report_id: str
    agent_id: str
    client_id: str | None
    session_id: str | None
    timestamp: datetime
    window_seconds: int
    observation_count: int
    baseline_sample_count: int
    baseline_status: BaselineStatus
    overall_drift_score: float
    overall_severity: DriftSeverity
    signals: list[DriftSignal]
    recommendations: list[str]
    should_alert: bool
    should_suspend: bool

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        payload["signals"] = [asdict(s) for s in self.signals]
        return payload


# ---------------------------------------------------------------------------
# Window helpers
# ---------------------------------------------------------------------------


def _window_observations(
    observations: list[AgentObservation],
    window_seconds: int,
    reference_time: datetime | None = None,
) -> list[AgentObservation]:
    cutoff = (reference_time or _utcnow()) - timedelta(seconds=window_seconds)
    return [o for o in observations if o.timestamp >= cutoff]


def _compute_action_rate(
    observations: list[AgentObservation],
    window_seconds: int,
) -> float:
    if not observations or window_seconds <= 0:
        return 0.0
    hours = window_seconds / 3600.0
    return len(observations) / hours


def _compute_action_type_distribution(
    observations: list[AgentObservation],
) -> dict[str, float]:
    counts: dict[str, int] = defaultdict(int)
    for obs in observations:
        counts[obs.action_type] += 1
    return _normalize_distribution(dict(counts))


def _compute_mean_risk(observations: list[AgentObservation]) -> float:
    if not observations:
        return 0.0
    return _safe_mean([float(o.risk_score) for o in observations])


def _compute_target_breadth(observations: list[AgentObservation]) -> float:
    if not observations:
        return 0.0
    unique_targets = len({o.target for o in observations if o.target})
    return unique_targets / len(observations)


def _compute_tool_call_rate(observations: list[AgentObservation]) -> float:
    if not observations:
        return 0.0
    tool_calls = sum(1 for o in observations if o.action_type == "tool_call")
    return tool_calls / len(observations)


def _compute_session_sizes(observations: list[AgentObservation]) -> list[float]:
    """Return per-session observation counts as floats."""
    sessions: dict[str, int] = defaultdict(int)
    for obs in observations:
        key = obs.session_id or "__nosession__"
        sessions[key] += 1
    return [float(v) for v in sessions.values()]


# ---------------------------------------------------------------------------
# Baseline builder
# ---------------------------------------------------------------------------


def _build_baseline_from_observations(
    agent_id: str,
    client_id: str | None,
    observations: list[AgentObservation],
    existing_baseline: AgentBaseline | None,
    drift_window_seconds: int = DRIFT_WINDOW_SECONDS,
) -> AgentBaseline:
    now = _utcnow()
    n = len(observations)

    window_obs = _window_observations(observations, drift_window_seconds)
    action_rate = _compute_action_rate(window_obs, drift_window_seconds)

    action_dist = _compute_action_type_distribution(observations)
    risk_scores = [float(o.risk_score) for o in observations]
    mean_risk = _safe_mean(risk_scores)
    stdev_risk = max(_safe_stdev(risk_scores), _MIN_STDEV_RISK)

    sessions: dict[str, list[AgentObservation]] = defaultdict(list)
    for obs in observations:
        key = obs.session_id or "__nosession__"
        sessions[key].append(obs)
    breadth_per_session = [_compute_target_breadth(s) for s in sessions.values()]
    mean_breadth = _safe_mean(breadth_per_session)
    stdev_breadth = max(_safe_stdev(breadth_per_session), _MIN_STDEV_BREADTH)

    session_sizes = _compute_session_sizes(observations)
    mean_sess_size = _safe_mean(session_sizes)
    stdev_sess_size = max(_safe_stdev(session_sizes), _MIN_STDEV_SESSION)

    tool_rate = _compute_tool_call_rate(observations)
    alpha = _EMA_ALPHA

    if existing_baseline is not None and existing_baseline.status == "active":
        e = existing_baseline
        new_mean_rate = alpha * action_rate + (1 - alpha) * e.mean_action_rate
        new_stdev_rate = max(
            alpha * abs(action_rate - e.mean_action_rate) + (1 - alpha) * e.stdev_action_rate,
            _MIN_STDEV_RATE,
        )
        new_mean_risk = alpha * mean_risk + (1 - alpha) * e.mean_risk_score
        new_stdev_risk = max(
            alpha * abs(mean_risk - e.mean_risk_score) + (1 - alpha) * e.stdev_risk_score,
            _MIN_STDEV_RISK,
        )
        new_mean_breadth = alpha * mean_breadth + (1 - alpha) * e.mean_target_breadth
        new_stdev_breadth = max(
            alpha * abs(mean_breadth - e.mean_target_breadth) + (1 - alpha) * e.stdev_target_breadth,
            _MIN_STDEV_BREADTH,
        )
        new_tool_rate = alpha * tool_rate + (1 - alpha) * e.mean_tool_call_rate
        new_stdev_tool_rate = max(
            alpha * abs(tool_rate - e.mean_tool_call_rate) + (1 - alpha) * e.stdev_tool_call_rate,
            0.0,
        )
        new_mean_sess = alpha * mean_sess_size + (1 - alpha) * e.mean_session_size
        new_stdev_sess = max(
            alpha * abs(mean_sess_size - e.mean_session_size) + (1 - alpha) * e.stdev_session_size,
            _MIN_STDEV_SESSION,
        )
        blended_dist: dict[str, float] = {}
        all_keys = set(action_dist.keys()) | set(e.action_type_distribution.keys())
        for k in all_keys:
            blended_dist[k] = alpha * action_dist.get(k, 0.0) + (1 - alpha) * e.action_type_distribution.get(k, 0.0)
        new_sample_count = e.sample_count + 1
        baseline_id = e.baseline_id
        created_at = e.created_at
        frozen_dist = dict(e.frozen_action_type_distribution) if e.frozen_action_type_distribution else dict(e.action_type_distribution)
    else:
        new_mean_rate = action_rate
        new_stdev_rate = max(_safe_stdev([action_rate]), _MIN_STDEV_RATE)
        new_mean_risk = mean_risk
        new_stdev_risk = stdev_risk
        new_mean_breadth = mean_breadth
        new_stdev_breadth = stdev_breadth
        new_tool_rate = tool_rate
        new_stdev_tool_rate = _safe_stdev([tool_rate])
        new_mean_sess = mean_sess_size
        new_stdev_sess = stdev_sess_size
        blended_dist = action_dist
        new_sample_count = n
        baseline_id = existing_baseline.baseline_id if existing_baseline is not None else f"baseline-{uuid4().hex[:12]}"
        created_at = existing_baseline.created_at if existing_baseline is not None else now
        frozen_dist = dict(action_dist)

    status: BaselineStatus = "learning" if new_sample_count < MIN_SAMPLES_FOR_BASELINE else "active"

    return AgentBaseline(
        baseline_id=baseline_id,
        agent_id=agent_id,
        client_id=client_id,
        status=status,
        schema_version=BASELINE_SCHEMA_VERSION,
        sample_count=new_sample_count,
        created_at=created_at,
        updated_at=now,
        mean_action_rate=new_mean_rate,
        stdev_action_rate=new_stdev_rate,
        action_type_distribution=blended_dist,
        mean_risk_score=new_mean_risk,
        stdev_risk_score=new_stdev_risk,
        mean_target_breadth=new_mean_breadth,
        stdev_target_breadth=new_stdev_breadth,
        mean_tool_call_rate=new_tool_rate,
        stdev_tool_call_rate=new_stdev_tool_rate,
        frozen_action_type_distribution=frozen_dist,
        baseline_obs_count=n,
        mean_session_size=new_mean_sess,
        stdev_session_size=new_stdev_sess,
    )


# ---------------------------------------------------------------------------
# Drift detector
# ---------------------------------------------------------------------------


def _build_drift_signals(
    baseline: AgentBaseline,
    window_observations: list[AgentObservation],
    window_seconds: int,
    session_id: str | None = None,
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []
    obs = window_observations

    if not obs:
        return signals

    # 1. Action frequency
    observed_rate = _compute_action_rate(obs, window_seconds)
    rate_stdev = max(baseline.stdev_action_rate, _MIN_STDEV_RATE)
    rate_z = _z_score(observed_rate, baseline.mean_action_rate, rate_stdev)
    rate_score = min(rate_z / _Z_SCORE_CAP, 1.0)
    if rate_score >= 0.20:
        signals.append(
            DriftSignal(
                category="action_frequency",
                observed_value=observed_rate,
                baseline_value=baseline.mean_action_rate,
                deviation_score=rate_score,
                severity=_severity_from_score(rate_score),
                detail=(f"Observed action rate {observed_rate:.2f}/hr vs baseline {baseline.mean_action_rate:.2f}/hr (z={rate_z:.2f})."),
            )
        )

    # 2. Action type distribution — compare window against frozen pre-anomaly snapshot
    observed_dist = _compute_action_type_distribution(obs)
    reference_dist = baseline.frozen_action_type_distribution if baseline.frozen_action_type_distribution else baseline.action_type_distribution
    jsd = _jensen_shannon_divergence(observed_dist, reference_dist)
    if jsd >= _JSD_SIGNAL_THRESHOLD:
        signals.append(
            DriftSignal(
                category="action_type_distribution",
                observed_value=jsd,
                baseline_value=0.0,
                deviation_score=jsd,
                severity=_severity_from_score(jsd),
                detail=(f"Action type distribution diverged from baseline (JSD={jsd:.3f}). Observed: {observed_dist}."),
            )
        )

    # 3. Risk score elevation
    observed_mean_risk = _compute_mean_risk(obs)
    risk_stdev = max(baseline.stdev_risk_score, _MIN_STDEV_RISK)
    risk_z = _z_score(observed_mean_risk, baseline.mean_risk_score, risk_stdev)
    risk_score_val = min(risk_z / _Z_SCORE_CAP, 1.0)
    if risk_score_val >= 0.20:
        signals.append(
            DriftSignal(
                category="risk_score_elevation",
                observed_value=observed_mean_risk,
                baseline_value=baseline.mean_risk_score,
                deviation_score=risk_score_val,
                severity=_severity_from_score(risk_score_val),
                detail=(f"Mean risk score {observed_mean_risk:.1f} vs baseline {baseline.mean_risk_score:.1f} (z={risk_z:.2f})."),
            )
        )

    # 4. Target scope breadth
    observed_breadth = _compute_target_breadth(obs)
    breadth_stdev = max(baseline.stdev_target_breadth, _MIN_STDEV_BREADTH)
    breadth_z = _z_score(observed_breadth, baseline.mean_target_breadth, breadth_stdev)
    breadth_score = min(breadth_z / _Z_SCORE_CAP, 1.0)
    if breadth_score >= _TARGET_SCOPE_SIGNAL_THRESHOLD:
        signals.append(
            DriftSignal(
                category="target_scope",
                observed_value=observed_breadth,
                baseline_value=baseline.mean_target_breadth,
                deviation_score=breadth_score,
                severity=_severity_from_score(breadth_score),
                detail=(f"Target scope breadth {observed_breadth:.3f} vs baseline {baseline.mean_target_breadth:.3f} (z={breadth_z:.2f})."),
            )
        )

    # 5. Tool call pattern
    observed_tool_rate = _compute_tool_call_rate(obs)
    tool_delta = abs(observed_tool_rate - baseline.mean_tool_call_rate)
    tool_score = min(tool_delta / 0.5, 1.0) if baseline.mean_tool_call_rate < 1.0 else 0.0
    if tool_score >= 0.20:
        signals.append(
            DriftSignal(
                category="tool_call_pattern",
                observed_value=observed_tool_rate,
                baseline_value=baseline.mean_tool_call_rate,
                deviation_score=tool_score,
                severity=_severity_from_score(tool_score),
                detail=(f"Tool call rate {observed_tool_rate:.3f} vs baseline {baseline.mean_tool_call_rate:.3f} (Δ={tool_delta:.3f})."),
            )
        )

    # 6. Session anomaly — only when a session_id is active in the window
    if session_id is not None and baseline.mean_session_size > 0.0:
        session_obs_count = float(sum(1 for o in obs if o.session_id == session_id))
        sess_stdev = max(baseline.stdev_session_size, _MIN_STDEV_SESSION)
        sess_z = _z_score(session_obs_count, baseline.mean_session_size, sess_stdev)
        if sess_z >= _SESSION_ANOMALY_Z_THRESHOLD:
            sess_score = min(sess_z / _Z_SCORE_CAP, 1.0)
            signals.append(
                DriftSignal(
                    category="session_anomaly",
                    observed_value=session_obs_count,
                    baseline_value=baseline.mean_session_size,
                    deviation_score=sess_score,
                    severity=_severity_from_score(sess_score),
                    detail=(f"Session '{session_id}' contains {session_obs_count:.0f} actions vs baseline mean {baseline.mean_session_size:.1f} (z={sess_z:.2f})."),
                )
            )

    return signals


def _compute_overall_drift_score(signals: list[DriftSignal]) -> float:
    if not signals:
        return 0.0
    max_score = max(s.deviation_score for s in signals)
    additive_bonus = sum(s.deviation_score for s in signals) * 0.05
    return min(max_score + additive_bonus, 1.0)


def _build_recommendations(
    signals: list[DriftSignal],
    overall_severity: DriftSeverity,
    baseline_status: BaselineStatus,
) -> list[str]:
    recs: list[str] = []

    if baseline_status == "learning":
        recs.append(f"Agent baseline is still in learning phase; collect at least {MIN_SAMPLES_FOR_BASELINE} samples before treating drift as actionable.")

    if overall_severity in ("high", "critical"):
        recs.append("Suspend or quarantine agent session pending operator review.")
        recs.append("Emit a high-priority security alert and log to audit trail.")

    if overall_severity == "medium":
        recs.append("Flag session for async review; apply tighter action guard thresholds.")

    for sig in signals:
        if sig.category == "action_frequency" and sig.severity in ("high", "critical"):
            recs.append("Abnormal action rate detected — possible runaway loop or automated exfiltration attempt.")
        if sig.category == "risk_score_elevation" and sig.severity in ("high", "critical"):
            recs.append("Risk score elevation suggests adversarial prompt injection or policy override attempt.")
        if sig.category == "action_type_distribution" and sig.severity in ("high", "critical"):
            recs.append("Action type distribution shift — agent may have changed objective or been hijacked.")
        if sig.category == "target_scope" and sig.severity in ("medium", "high", "critical"):
            recs.append("Broadened target scope detected — evaluate for lateral movement or data discovery attempts.")
        if sig.category == "tool_call_pattern" and sig.severity in ("high", "critical"):
            recs.append("Unusual tool call frequency — review for tool chain abuse or capability escalation.")
        if sig.category == "session_anomaly" and sig.severity in ("medium", "high", "critical"):
            recs.append("Session action volume is abnormally high — possible session hijack or runaway agent loop.")

    if not recs:
        recs.append("No action required; behavioral profile is within normal baseline bounds.")

    return recs


# ---------------------------------------------------------------------------
# Core store
# ---------------------------------------------------------------------------


class BehavioralBaselineStore:
    """In-memory store for agent behavioral baselines and drift detection."""

    def __init__(
        self,
        *,
        drift_window_seconds: int = DRIFT_WINDOW_SECONDS,
        max_observations_per_agent: int = MAX_BASELINE_SAMPLES,
        min_samples_for_baseline: int = MIN_SAMPLES_FOR_BASELINE,
    ) -> None:
        self._lock = Lock()
        self._drift_window_seconds = drift_window_seconds
        self._max_observations_per_agent = max_observations_per_agent
        self._min_samples_for_baseline = min_samples_for_baseline
        self._observations: dict[str, list[AgentObservation]] = defaultdict(list)
        self._baselines: dict[str, AgentBaseline] = {}
        self._obs_since_last_update: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Observation ingestion
    # ------------------------------------------------------------------

    def record_observation(
        self,
        agent_id: str,
        action_type: str,
        target: str,
        risk_score: int,
        *,
        session_id: str | None = None,
        client_id: str | None = None,
        matched_patterns: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentObservation:
        validated_agent_id = _require_str(agent_id, "agent_id")
        validated_action = _require_str(action_type, "action_type")
        validated_target = target.strip() if isinstance(target, str) else ""
        validated_risk = max(0, min(int(risk_score), 100))

        obs = AgentObservation(
            observation_id=f"obs-{uuid4().hex[:12]}",
            agent_id=validated_agent_id,
            session_id=session_id,
            client_id=client_id,
            timestamp=_utcnow(),
            action_type=validated_action,
            target=validated_target,
            risk_score=validated_risk,
            matched_patterns=list(matched_patterns or []),
            metadata=dict(metadata or {}),
        )

        with self._lock:
            bucket = self._observations[validated_agent_id]
            bucket.append(obs)
            if len(bucket) > self._max_observations_per_agent:
                self._observations[validated_agent_id] = bucket[-self._max_observations_per_agent :]
            self._obs_since_last_update[validated_agent_id] += 1
            self._recompute_baseline_locked(validated_agent_id, client_id)
            updated_baseline = self._baselines.get(validated_agent_id)

        _supabase_persist_observation(obs)
        if updated_baseline is not None:
            _supabase_persist_baseline(updated_baseline)

        return obs

    def record_observations_bulk(
        self,
        agent_id: str,
        observations: list[dict[str, Any]],
        client_id: str | None = None,
    ) -> list[AgentObservation]:
        """Ingest multiple observations under a single lock acquisition."""
        validated_agent_id = _require_str(agent_id, "agent_id")
        now = _utcnow()
        recorded: list[AgentObservation] = []

        for item in observations:
            validated_action = _require_str(str(item.get("action_type", "")), "action_type")
            raw_target = item.get("target", "")
            validated_target = raw_target.strip() if isinstance(raw_target, str) else ""
            validated_risk = max(0, min(int(item.get("risk_score", 0)), 100))
            obs = AgentObservation(
                observation_id=f"obs-{uuid4().hex[:12]}",
                agent_id=validated_agent_id,
                session_id=item.get("session_id"),
                client_id=client_id,
                timestamp=now,
                action_type=validated_action,
                target=validated_target,
                risk_score=validated_risk,
                matched_patterns=list(item.get("matched_patterns") or []),
                metadata=dict(item.get("metadata") or {}),
            )
            recorded.append(obs)

        with self._lock:
            bucket = self._observations[validated_agent_id]
            bucket.extend(recorded)
            if len(bucket) > self._max_observations_per_agent:
                self._observations[validated_agent_id] = bucket[-self._max_observations_per_agent :]
            self._obs_since_last_update[validated_agent_id] += len(recorded)
            self._recompute_baseline_locked(validated_agent_id, client_id)
            updated_baseline = self._baselines.get(validated_agent_id)

        for obs in recorded:
            _supabase_persist_observation(obs)
        if updated_baseline is not None:
            _supabase_persist_baseline(updated_baseline)

        return recorded

    # ------------------------------------------------------------------
    # Baseline access
    # ------------------------------------------------------------------

    def get_baseline(self, agent_id: str) -> AgentBaseline | None:
        normalized = _require_str(agent_id, "agent_id")
        with self._lock:
            return self._baselines.get(normalized)

    def list_baselines(
        self,
        *,
        client_id: str | None = None,
        status: BaselineStatus | None = None,
    ) -> list[AgentBaseline]:
        with self._lock:
            items = list(self._baselines.values())
        if client_id is not None:
            items = [b for b in items if b.client_id == client_id]
        if status is not None:
            items = [b for b in items if b.status == status]
        return items

    def invalidate_baseline(self, agent_id: str) -> bool:
        normalized = _require_str(agent_id, "agent_id")
        with self._lock:
            baseline = self._baselines.get(normalized)
            if baseline is None:
                return False
            updated = baseline._replace_status("stale")
            self._baselines[normalized] = updated

        _supabase_persist_baseline(updated)
        return True

    def suspend_baseline(self, agent_id: str) -> bool:
        normalized = _require_str(agent_id, "agent_id")
        with self._lock:
            baseline = self._baselines.get(normalized)
            if baseline is None:
                return False
            updated = baseline._replace_status("suspended")
            self._baselines[normalized] = updated

        _supabase_persist_baseline(updated)
        return True

    # ------------------------------------------------------------------
    # Drift detection
    # ------------------------------------------------------------------

    def compute_drift(
        self,
        agent_id: str,
        *,
        session_id: str | None = None,
        client_id: str | None = None,
        window_seconds: int | None = None,
    ) -> DriftReport:
        normalized = _require_str(agent_id, "agent_id")
        effective_window = window_seconds if window_seconds and window_seconds > 0 else self._drift_window_seconds

        with self._lock:
            all_obs = list(self._observations.get(normalized, []))
            baseline = self._baselines.get(normalized)

        window_obs = _window_observations(all_obs, effective_window)

        if baseline is None:
            report = DriftReport(
                report_id=f"drift-{uuid4().hex[:12]}",
                agent_id=normalized,
                client_id=client_id,
                session_id=session_id,
                timestamp=_utcnow(),
                window_seconds=effective_window,
                observation_count=len(window_obs),
                baseline_sample_count=0,
                baseline_status="learning",
                overall_drift_score=0.0,
                overall_severity="none",
                signals=[],
                recommendations=[f"No baseline established yet for agent '{normalized}'. Record at least {self._min_samples_for_baseline} observations to enable drift detection."],
                should_alert=False,
                should_suspend=False,
            )
            _supabase_persist_drift_report(report)
            return report

        if baseline.status == "suspended":
            report = DriftReport(
                report_id=f"drift-{uuid4().hex[:12]}",
                agent_id=normalized,
                client_id=client_id,
                session_id=session_id,
                timestamp=_utcnow(),
                window_seconds=effective_window,
                observation_count=len(window_obs),
                baseline_sample_count=baseline.sample_count,
                baseline_status="suspended",
                overall_drift_score=1.0,
                overall_severity="critical",
                signals=[],
                recommendations=[f"Agent '{normalized}' is currently suspended. Manual operator review is required before resuming this agent."],
                should_alert=True,
                should_suspend=True,
            )
            _supabase_persist_drift_report(report)
            return report

        signals = _build_drift_signals(baseline, window_obs, effective_window, session_id=session_id)
        overall_score = _compute_overall_drift_score(signals)

        effective_score = overall_score * 0.5 if baseline.status == "learning" else overall_score
        overall_severity = _severity_from_score(effective_score)

        recommendations = _build_recommendations(signals, overall_severity, baseline.status)

        should_alert = overall_severity in ("high", "critical")
        should_suspend = overall_severity == "critical"

        report = DriftReport(
            report_id=f"drift-{uuid4().hex[:12]}",
            agent_id=normalized,
            client_id=client_id,
            session_id=session_id,
            timestamp=_utcnow(),
            window_seconds=effective_window,
            observation_count=len(window_obs),
            baseline_sample_count=baseline.sample_count,
            baseline_status=baseline.status,
            overall_drift_score=overall_score,
            overall_severity=overall_severity,
            signals=signals,
            recommendations=recommendations,
            should_alert=should_alert,
            should_suspend=should_suspend,
        )

        if should_suspend:
            self.suspend_baseline(normalized)

        if should_alert:
            _emit_telemetry(
                "behavioral_drift_detected",
                {
                    "agent_id": normalized,
                    "client_id": client_id,
                    "session_id": session_id,
                    "report_id": report.report_id,
                    "overall_severity": overall_severity,
                    "overall_drift_score": overall_score,
                    "signal_count": len(signals),
                    "should_suspend": should_suspend,
                },
            )

        _supabase_persist_drift_report(report)
        return report

    def get_observations(
        self,
        agent_id: str,
        *,
        limit: int = 100,
        session_id: str | None = None,
    ) -> list[AgentObservation]:
        normalized = _require_str(agent_id, "agent_id")
        with self._lock:
            obs = list(self._observations.get(normalized, []))

        if session_id is not None:
            obs = [o for o in obs if o.session_id == session_id]

        return obs[-min(limit, MAX_BASELINE_SAMPLES) :]

    def purge_agent(self, agent_id: str) -> bool:
        normalized = _require_str(agent_id, "agent_id")
        client_id: str | None = None
        with self._lock:
            baseline = self._baselines.get(normalized)
            if baseline is not None:
                client_id = baseline.client_id
            found = normalized in self._observations or normalized in self._baselines
            self._observations.pop(normalized, None)
            self._baselines.pop(normalized, None)
            self._obs_since_last_update.pop(normalized, None)

        if found:
            _supabase_delete_agent(normalized, client_id)

        return found

    def reset(self) -> None:
        with self._lock:
            self._observations.clear()
            self._baselines.clear()
            self._obs_since_last_update.clear()

    # ------------------------------------------------------------------
    # Internal (lock must be held by caller)
    # ------------------------------------------------------------------

    def _recompute_baseline_locked(
        self,
        agent_id: str,
        client_id: str | None,
    ) -> None:
        observations = self._observations.get(agent_id, [])
        existing = self._baselines.get(agent_id)

        if existing is not None and existing.status == "suspended":
            return

        if len(observations) < 1:
            return

        # Always recompute while learning so status can promote to active.
        # Once active, throttle by batch size.
        if existing is not None and existing.status == "active":
            if self._obs_since_last_update[agent_id] < _BASELINE_UPDATE_BATCH:
                return
            self._obs_since_last_update[agent_id] = 0

        updated = _build_baseline_from_observations(
            agent_id=agent_id,
            client_id=client_id,
            observations=observations,
            existing_baseline=existing,
            drift_window_seconds=self._drift_window_seconds,
        )
        self._baselines[agent_id] = updated


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_BEHAVIORAL_BASELINE_STORE = BehavioralBaselineStore()


def get_behavioral_baseline_store() -> BehavioralBaselineStore:
    return _BEHAVIORAL_BASELINE_STORE


def reset_behavioral_baseline_store() -> None:
    _BEHAVIORAL_BASELINE_STORE.reset()
