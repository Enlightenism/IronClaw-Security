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


def _compute_overall_drift_score(signals: list[DriftSignal]) -> float:
    if not signals:
        return 0.0
    scores = [s.deviation_score for s in signals]
    base = max(scores)
    remainder = 1.0 - base
    additional = sum(s * remainder for s in sorted(scores)[:-1]) / max(len(scores), 1)
    return min(base + additional, 1.0)


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
    mean_session_size: float = 0.0
    stdev_session_size: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        payload["updated_at"] = self.updated_at.isoformat().replace("+00:00", "Z")
        return payload

    def _replace_status(self, status: BaselineStatus) -> AgentBaseline:
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
    min_samples_for_baseline: int = MIN_SAMPLES_FOR_BASELINE,
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
        frozen_dist = dict(e.frozen_action_type_distribution) if e.frozen_action_type_distribution else dict(action_dist)
        return AgentBaseline(
            baseline_id=e.baseline_id,
            agent_id=agent_id,
            client_id=client_id,
            status="active",
            schema_version=BASELINE_SCHEMA_VERSION,
            sample_count=n,
            created_at=e.created_at,
            updated_at=now,
            mean_action_rate=new_mean_rate,
            stdev_action_rate=new_stdev_rate,
            action_type_distribution=action_dist,
            mean_risk_score=new_mean_risk,
            stdev_risk_score=new_stdev_risk,
            mean_target_breadth=new_mean_breadth,
            stdev_target_breadth=new_stdev_breadth,
            mean_tool_call_rate=new_tool_rate,
            stdev_tool_call_rate=new_stdev_tool_rate,
            frozen_action_type_distribution=frozen_dist,
            baseline_obs_count=e.baseline_obs_count + n,
            mean_session_size=new_mean_sess,
            stdev_session_size=new_stdev_sess,
        )

    status: BaselineStatus = "active" if n >= min_samples_for_baseline else "learning"
    stdev_rate = max(_safe_stdev([action_rate]), _MIN_STDEV_RATE)
    stdev_tool = max(_safe_stdev([tool_rate]), 0.0)

    return AgentBaseline(
        baseline_id=str(uuid4()),
        agent_id=agent_id,
        client_id=client_id,
        status=status,
        schema_version=BASELINE_SCHEMA_VERSION,
        sample_count=n,
        created_at=now,
        updated_at=now,
        mean_action_rate=action_rate,
        stdev_action_rate=stdev_rate,
        action_type_distribution=action_dist,
        mean_risk_score=mean_risk,
        stdev_risk_score=stdev_risk,
        mean_target_breadth=mean_breadth,
        stdev_target_breadth=stdev_breadth,
        mean_tool_call_rate=tool_rate,
        stdev_tool_call_rate=stdev_tool,
        frozen_action_type_distribution=dict(action_dist),
        baseline_obs_count=n,
        mean_session_size=mean_sess_size,
        stdev_session_size=stdev_sess_size,
    )


# ---------------------------------------------------------------------------
# Drift analysis
# ---------------------------------------------------------------------------


def _analyze_drift(
    agent_id: str,
    client_id: str | None,
    session_id: str | None,
    baseline: AgentBaseline,
    observations: list[AgentObservation],
    window_seconds: int = DRIFT_WINDOW_SECONDS,
) -> DriftReport:
    now = _utcnow()

    # Suspended baseline → immediate critical report, no signal computation needed
    if baseline.status == "suspended":
        return DriftReport(
            report_id=f"drift-{uuid4()}",
            agent_id=agent_id,
            client_id=client_id,
            session_id=session_id,
            timestamp=now,
            window_seconds=window_seconds,
            observation_count=len(_window_observations(observations, window_seconds)),
            baseline_sample_count=baseline.sample_count,
            baseline_status=baseline.status,
            overall_drift_score=1.0,
            overall_severity="critical",
            signals=[],
            recommendations=[
                "Agent is suspended — review all recent actions before resuming.",
                "Consider purging agent data if compromise is confirmed.",
            ],
            should_alert=True,
            should_suspend=True,
        )

    window_obs = _window_observations(observations, window_seconds)
    n = len(window_obs)
    signals: list[DriftSignal] = []

    if baseline.stdev_action_rate > 0:
        observed_rate = _compute_action_rate(window_obs, window_seconds)
        z = min(_z_score(observed_rate, baseline.mean_action_rate, baseline.stdev_action_rate), _Z_SCORE_CAP)
        norm = z / _Z_SCORE_CAP
        sev = _severity_from_score(norm)
        if sev != "none":
            signals.append(
                DriftSignal(
                    category="action_frequency",
                    observed_value=observed_rate,
                    baseline_value=baseline.mean_action_rate,
                    deviation_score=norm,
                    severity=sev,
                    detail=f"Action rate {observed_rate:.2f}/hr vs baseline {baseline.mean_action_rate:.2f}/hr (z={z:.2f})",
                )
            )

    if n > 0 and baseline.frozen_action_type_distribution:
        obs_dist = _compute_action_type_distribution(window_obs)
        jsd = _jensen_shannon_divergence(obs_dist, baseline.frozen_action_type_distribution)
        if jsd >= _JSD_SIGNAL_THRESHOLD:
            norm = min(jsd / 1.0, 1.0)
            sev = _severity_from_score(norm)
            signals.append(
                DriftSignal(
                    category="action_type_distribution",
                    observed_value=jsd,
                    baseline_value=0.0,
                    deviation_score=norm,
                    severity=sev,
                    detail=f"Action type distribution divergence (JSD={jsd:.3f})",
                )
            )

    if n > 0 and baseline.stdev_target_breadth > 0:
        obs_breadth = _compute_target_breadth(window_obs)
        z = min(_z_score(obs_breadth, baseline.mean_target_breadth, baseline.stdev_target_breadth), _Z_SCORE_CAP)
        norm = z / _Z_SCORE_CAP
        if norm >= _TARGET_SCOPE_SIGNAL_THRESHOLD:
            sev = _severity_from_score(norm)
            signals.append(
                DriftSignal(
                    category="target_scope",
                    observed_value=obs_breadth,
                    baseline_value=baseline.mean_target_breadth,
                    deviation_score=norm,
                    severity=sev,
                    detail=f"Target breadth {obs_breadth:.3f} vs baseline {baseline.mean_target_breadth:.3f} (z={z:.2f})",
                )
            )

    if n > 0 and baseline.stdev_risk_score > 0:
        obs_risk = _compute_mean_risk(window_obs)
        z = min(_z_score(obs_risk, baseline.mean_risk_score, baseline.stdev_risk_score), _Z_SCORE_CAP)
        norm = z / _Z_SCORE_CAP
        sev = _severity_from_score(norm)
        if sev != "none":
            signals.append(
                DriftSignal(
                    category="risk_score_elevation",
                    observed_value=obs_risk,
                    baseline_value=baseline.mean_risk_score,
                    deviation_score=norm,
                    severity=sev,
                    detail=f"Mean risk {obs_risk:.1f} vs baseline {baseline.mean_risk_score:.1f} (z={z:.2f})",
                )
            )

    if n > 0 and baseline.stdev_tool_call_rate > 0:
        obs_tool = _compute_tool_call_rate(window_obs)
        z = min(_z_score(obs_tool, baseline.mean_tool_call_rate, baseline.stdev_tool_call_rate), _Z_SCORE_CAP)
        norm = z / _Z_SCORE_CAP
        sev = _severity_from_score(norm)
        if sev != "none":
            signals.append(
                DriftSignal(
                    category="tool_call_pattern",
                    observed_value=obs_tool,
                    baseline_value=baseline.mean_tool_call_rate,
                    deviation_score=norm,
                    severity=sev,
                    detail=f"Tool call rate {obs_tool:.3f} vs baseline {baseline.mean_tool_call_rate:.3f} (z={z:.2f})",
                )
            )

    if session_id and n > 0 and baseline.stdev_session_size > 0:
        session_obs = [o for o in window_obs if o.session_id == session_id]
        sess_size = float(len(session_obs))
        z = min(
            _z_score(sess_size, baseline.mean_session_size, baseline.stdev_session_size),
            _Z_SCORE_CAP,
        )
        if z >= _SESSION_ANOMALY_Z_THRESHOLD:
            norm = min(z / _Z_SCORE_CAP, 1.0)
            sev = _severity_from_score(norm)
            signals.append(
                DriftSignal(
                    category="session_anomaly",
                    observed_value=sess_size,
                    baseline_value=baseline.mean_session_size,
                    deviation_score=norm,
                    severity=sev,
                    detail=f"Session size {sess_size:.0f} vs baseline mean {baseline.mean_session_size:.1f} (z={z:.2f})",
                )
            )

    overall_score = _compute_overall_drift_score(signals)
    overall_sev = _severity_from_score(overall_score)

    recommendations: list[str] = []
    if baseline.status == "learning":
        recommendations.append("Baseline is still learning — more observations needed before drift detection is reliable.")
    if overall_sev in ("high", "critical"):
        recommendations.append("Consider suspending agent pending review.")
    if any(s.category == "risk_score_elevation" for s in signals):
        recommendations.append("Review recent high-risk actions for policy violations.")
    if any(s.category == "action_type_distribution" for s in signals):
        recommendations.append("Inspect action type shift for unauthorized capability expansion.")

    should_alert = overall_sev in ("medium", "high", "critical")
    should_suspend = overall_sev == "critical"

    return DriftReport(
        report_id=f"drift-{uuid4()}",
        agent_id=agent_id,
        client_id=client_id,
        session_id=session_id,
        timestamp=now,
        window_seconds=window_seconds,
        observation_count=n,
        baseline_sample_count=baseline.sample_count,
        baseline_status=baseline.status,
        overall_drift_score=overall_score,
        overall_severity=overall_sev,
        signals=signals,
        recommendations=recommendations,
        should_alert=should_alert,
        should_suspend=should_suspend,
    )


# ---------------------------------------------------------------------------
# BehavioralBaselineStore
# ---------------------------------------------------------------------------


class BehavioralBaselineStore:
    def __init__(
        self,
        drift_window_seconds: int = DRIFT_WINDOW_SECONDS,
        max_observations_per_agent: int = MAX_BASELINE_SAMPLES,
        min_samples_for_baseline: int = MIN_SAMPLES_FOR_BASELINE,
    ) -> None:
        self._drift_window_seconds = drift_window_seconds
        self._max_observations_per_agent = max_observations_per_agent
        self._min_samples_for_baseline = min_samples_for_baseline
        self._lock: Lock = Lock()
        self._observations: dict[str, list[AgentObservation]] = defaultdict(list)
        self._baselines: dict[str, AgentBaseline] = {}
        self._baseline_client_ids: dict[str, str | None] = {}
        self._obs_since_last_build: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # reset
    # ------------------------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self._observations.clear()
            self._baselines.clear()
            self._baseline_client_ids.clear()
            self._obs_since_last_build.clear()

    # ------------------------------------------------------------------
    # record_observation
    # ------------------------------------------------------------------

    def record_observation(
        self,
        agent_id: str,
        action_type: str,
        target: str,
        risk_score: int,
        matched_patterns: list[str] | None = None,
        session_id: str | None = None,
        client_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentObservation:
        agent_id = _require_str(agent_id, "agent_id")
        action_type = _require_str(action_type, "action_type")

        obs = AgentObservation(
            observation_id=f"obs-{uuid4()}",
            agent_id=agent_id,
            session_id=session_id,
            client_id=client_id,
            timestamp=_utcnow(),
            action_type=action_type,
            target=target or "",
            risk_score=max(0, min(100, int(risk_score))),
            matched_patterns=list(matched_patterns or []),
            metadata=dict(metadata or {}),
        )

        with self._lock:
            bucket = self._observations[agent_id]
            bucket.append(obs)
            if len(bucket) > self._max_observations_per_agent:
                self._observations[agent_id] = bucket[-self._max_observations_per_agent :]
            self._baseline_client_ids[agent_id] = client_id
            self._obs_since_last_build[agent_id] += 1
            should_rebuild = self._obs_since_last_build[agent_id] >= _BASELINE_UPDATE_BATCH
            if should_rebuild:
                self._obs_since_last_build[agent_id] = 0
                self._rebuild_baseline(agent_id, client_id)
            elif len(self._observations[agent_id]) >= self._min_samples_for_baseline and agent_id not in self._baselines:
                self._rebuild_baseline(agent_id, client_id)

        try:
            _supabase_persist_observation(obs)
        except Exception:  # noqa: BLE001
            pass

        _emit_telemetry(
            "behavioral_observation_recorded",
            {
                "agent_id": agent_id,
                "action_type": action_type,
                "risk_score": obs.risk_score,
                "session_id": session_id,
            },
        )
        return obs

    # ------------------------------------------------------------------
    # record_observations_bulk
    # ------------------------------------------------------------------

    def record_observations_bulk(
        self,
        agent_id: str,
        items: list[dict[str, Any]],
        session_id: str | None = None,
        client_id: str | None = None,
    ) -> list[AgentObservation]:
        results: list[AgentObservation] = []
        for item in items:
            obs = self.record_observation(
                agent_id=agent_id,
                action_type=item.get("action_type", "unknown"),
                target=item.get("target", ""),
                risk_score=int(item.get("risk_score", 0)),
                matched_patterns=item.get("matched_patterns"),
                session_id=item.get("session_id", session_id),
                client_id=item.get("client_id", client_id),
                metadata=item.get("metadata"),
            )
            results.append(obs)
        return results

    # ------------------------------------------------------------------
    # get_observations
    # ------------------------------------------------------------------

    def get_observations(
        self,
        agent_id: str,
        limit: int | None = None,
        window_seconds: int | None = None,
        session_id: str | None = None,
    ) -> list[AgentObservation]:
        agent_id = _require_str(agent_id, "agent_id")
        with self._lock:
            obs = list(self._observations.get(agent_id, []))
        if window_seconds is not None:
            obs = _window_observations(obs, window_seconds)
        if session_id is not None:
            obs = [o for o in obs if o.session_id == session_id]
        if limit is not None:
            obs = obs[-limit:]
        return obs

    # ------------------------------------------------------------------
    # get_baseline
    # ------------------------------------------------------------------

    def get_baseline(self, agent_id: str) -> AgentBaseline | None:
        agent_id = _require_str(agent_id, "agent_id")
        with self._lock:
            baseline = self._baselines.get(agent_id)
            if baseline is not None:
                return baseline
            observations = list(self._observations.get(agent_id, []))
        if not observations:
            return None
        client_id = self._baseline_client_ids.get(agent_id)
        return _build_baseline_from_observations(
            agent_id=agent_id,
            client_id=client_id,
            observations=observations,
            existing_baseline=None,
            drift_window_seconds=self._drift_window_seconds,
            min_samples_for_baseline=self._min_samples_for_baseline,
        )

    # ------------------------------------------------------------------
    # list_baselines
    # ------------------------------------------------------------------

    def list_baselines(
        self,
        client_id: str | None = None,
        status: str | None = None,
    ) -> list[AgentBaseline]:
        with self._lock:
            agent_ids = list(self._observations.keys())

        results: list[AgentBaseline] = []
        for aid in agent_ids:
            baseline = self.get_baseline(aid)
            if baseline is None:
                continue
            if client_id is not None and baseline.client_id != client_id:
                continue
            if status is not None and baseline.status != status:
                continue
            results.append(baseline)
        return results

    # ------------------------------------------------------------------
    # invalidate_baseline
    # ------------------------------------------------------------------

    def invalidate_baseline(self, agent_id: str) -> bool:
        agent_id = _require_str(agent_id, "agent_id")
        with self._lock:
            baseline = self._baselines.get(agent_id)
            if baseline is None:
                return False
            stale = baseline._replace_status("stale")
            self._baselines[agent_id] = stale

        try:
            _supabase_persist_baseline(stale)
        except Exception:  # noqa: BLE001
            pass
        return True

    # ------------------------------------------------------------------
    # suspend_baseline
    # ------------------------------------------------------------------

    def suspend_baseline(self, agent_id: str) -> bool:
        agent_id = _require_str(agent_id, "agent_id")
        with self._lock:
            baseline = self._baselines.get(agent_id)
            if baseline is None:
                return False
            suspended = baseline._replace_status("suspended")
            self._baselines[agent_id] = suspended

        try:
            _supabase_persist_baseline(suspended)
        except Exception:  # noqa: BLE001
            pass
        return True

    # ------------------------------------------------------------------
    # purge_agent
    # ------------------------------------------------------------------

    def purge_agent(self, agent_id: str, client_id: str | None = None) -> bool:
        agent_id = _require_str(agent_id, "agent_id")
        with self._lock:
            existed = agent_id in self._observations or agent_id in self._baselines
            self._observations.pop(agent_id, None)
            self._baselines.pop(agent_id, None)
            self._baseline_client_ids.pop(agent_id, None)
            self._obs_since_last_build.pop(agent_id, None)
        if existed:
            _supabase_delete_agent(agent_id, client_id=client_id)
        return existed

    # ------------------------------------------------------------------
    # compute_drift
    # ------------------------------------------------------------------

    def compute_drift(
        self,
        agent_id: str,
        session_id: str | None = None,
        client_id: str | None = None,
        window_seconds: int | None = None,
    ) -> DriftReport:
        agent_id = _require_str(agent_id, "agent_id")
        window = window_seconds if window_seconds is not None else self._drift_window_seconds

        with self._lock:
            baseline = self._baselines.get(agent_id)
            observations = list(self._observations.get(agent_id, []))

        if baseline is None:
            n = len(observations)
            status: BaselineStatus = "learning" if n < self._min_samples_for_baseline else "active"
            now = _utcnow()
            baseline = AgentBaseline(
                baseline_id=str(uuid4()),
                agent_id=agent_id,
                client_id=client_id,
                status=status,
                schema_version=BASELINE_SCHEMA_VERSION,
                sample_count=n,
                created_at=now,
                updated_at=now,
                mean_action_rate=0.0,
                stdev_action_rate=_MIN_STDEV_RATE,
                action_type_distribution={},
                mean_risk_score=0.0,
                stdev_risk_score=_MIN_STDEV_RISK,
                mean_target_breadth=0.0,
                stdev_target_breadth=_MIN_STDEV_BREADTH,
                mean_tool_call_rate=0.0,
                stdev_tool_call_rate=0.0,
                frozen_action_type_distribution={},
                mean_session_size=0.0,
                stdev_session_size=_MIN_STDEV_SESSION,
            )

        report = _analyze_drift(
            agent_id=agent_id,
            client_id=client_id,
            session_id=session_id,
            baseline=baseline,
            observations=observations,
            window_seconds=window,
        )

        try:
            _supabase_persist_drift_report(report)
        except Exception:  # noqa: BLE001
            pass

        if report.should_suspend and baseline.status != "suspended":
            with self._lock:
                suspended = baseline._replace_status("suspended")
                self._baselines[agent_id] = suspended
            try:
                _supabase_persist_baseline(suspended)
            except Exception:  # noqa: BLE001
                pass

        _emit_telemetry(
            "behavioral_drift_detected",
            {
                "agent_id": agent_id,
                "overall_severity": report.overall_severity,
                "overall_drift_score": report.overall_drift_score,
                "should_alert": report.should_alert,
                "should_suspend": report.should_suspend,
                "session_id": session_id,
            },
        )
        return report

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rebuild_baseline(self, agent_id: str, client_id: str | None) -> None:
        observations = self._observations.get(agent_id, [])
        existing = self._baselines.get(agent_id)
        if existing and existing.status == "suspended":
            return
        new_baseline = _build_baseline_from_observations(
            agent_id=agent_id,
            client_id=client_id,
            observations=observations,
            existing_baseline=existing,
            drift_window_seconds=self._drift_window_seconds,
            min_samples_for_baseline=self._min_samples_for_baseline,
        )
        self._baselines[agent_id] = new_baseline
        try:
            _supabase_persist_baseline(new_baseline)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Backward-compat alias
# ---------------------------------------------------------------------------

BehavioralBaselineService = BehavioralBaselineStore

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_store: BehavioralBaselineStore | None = None
_store_lock: Lock = Lock()


def get_behavioral_baseline_store() -> BehavioralBaselineStore:
    global _store  # noqa: PLW0603
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = BehavioralBaselineStore()
    return _store


def reset_behavioral_baseline_store() -> None:
    global _store  # noqa: PLW0603
    with _store_lock:
        if _store is not None:
            _store.reset()
        _store = None


# Backward-compat aliases
def get_behavioral_baseline_service() -> BehavioralBaselineStore:
    return get_behavioral_baseline_store()
