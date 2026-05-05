from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.groq_security_brain import GroqMode
from app.ui.groq.brain_status import build_groq_brain_status_view
from app.ui.groq.control_panel import CONTROL_FLAGS
from app.ui.groq.incidents import IncidentSeverity, _INCIDENTS, seed_demo_incidents
from app.ui.groq.request_stream import _REQUEST_EVENTS, seed_demo_requests

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-posture-summary"],
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class DomainPostureScore:
    name: str
    score: int
    max_score: int = 100
    weight: float = 1.0
    rationale: str = ""
    indicators: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "max_score": self.max_score,
            "weight": self.weight,
            "rationale": self.rationale,
            "indicators": dict(self.indicators),
        }


@dataclass(slots=True)
class GlobalPostureSummary:
    overall_score: int
    domains: list[DomainPostureScore]
    generated_at: str
    mode: GroqMode
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "domains": [domain.to_dict() for domain in self.domains],
            "generated_at": self.generated_at,
            "mode": self.mode,
            "metadata": dict(self.metadata),
        }


class DomainPostureScoreView(BaseModel):
    name: str
    score: int
    max_score: int = 100
    weight: float = 1.0
    rationale: str
    indicators: dict[str, Any] = Field(default_factory=dict)


class GlobalPostureSummaryResponse(BaseModel):
    overall_score: int
    domains: list[DomainPostureScoreView]
    generated_at: str
    mode: GroqMode
    metadata: dict[str, Any] = Field(default_factory=dict)


def _clamp_score(value: float, min_v: int = 0, max_v: int = 100) -> int:
    return max(min_v, min(int(round(value)), max_v))


def _seed_runtime_state(mode: GroqMode) -> None:
    seed_demo_incidents()
    seed_demo_requests(mode=mode)


def _score_runtime_actions(mode: GroqMode) -> DomainPostureScore:
    brain_view = build_groq_brain_status_view(mode=mode)
    status = brain_view.status

    total = max(status.total_evaluations, 1)
    blocked = status.blocked_count
    quarantined = status.quarantined_count
    warned = status.warned_count
    allowed = status.allowed_count

    high_risk_ratio = (blocked + quarantined) / total
    warn_ratio = warned / total

    base = 100.0
    base -= high_risk_ratio * 60.0
    base -= warn_ratio * 25.0

    if mode in ("assist", "enforce"):
        base += 5.0
    elif mode == "disabled":
        base -= 10.0

    score = _clamp_score(base)

    rationale = (
        f"Based on {total} recent decisions: {blocked} blocked, "
        f"{quarantined} quarantined, {warned} warned, {allowed} allowed."
    )

    return DomainPostureScore(
        name="runtime_actions",
        score=score,
        weight=0.35,
        rationale=rationale,
        indicators={
            "total_decisions": total,
            "blocked": blocked,
            "quarantined": quarantined,
            "warned": warned,
            "allowed": allowed,
            "high_risk_ratio": round(high_risk_ratio, 3),
            "warn_ratio": round(warn_ratio, 3),
            "health": status.health,
            "last_verdict": status.last_verdict,
            "last_risk_score": status.last_risk_score,
            "recent_signals": list(status.recent_signals),
        },
    )


def _score_control_hygiene(mode: GroqMode) -> DomainPostureScore:
    flags = CONTROL_FLAGS

    base = 100.0

    if flags.mode == "disabled":
        base -= 40.0
    elif flags.mode == "observe":
        base -= 20.0
    elif flags.mode == "assist":
        base -= 5.0

    if flags.allow_shell_commands:
        base -= 20.0
    if flags.allow_network:
        base -= 5.0
    if flags.allow_file_write:
        base -= 5.0
    if flags.allow_prompt_injection_testing:
        base -= 15.0
    if flags.log_only_mode:
        base -= 20.0
    if flags.maintenance_mode:
        base -= 10.0

    score = _clamp_score(base)

    rationale = (
        f"Current mode is '{flags.mode}' with runtime toggles affecting "
        "enforcement strength and attack surface."
    )

    return DomainPostureScore(
        name="control_hygiene",
        score=score,
        weight=0.30,
        rationale=rationale,
        indicators={
            "mode": flags.mode,
            "requested_mode": mode,
            "allow_shell_commands": flags.allow_shell_commands,
            "allow_network": flags.allow_network,
            "allow_file_write": flags.allow_file_write,
            "allow_prompt_injection_testing": flags.allow_prompt_injection_testing,
            "log_only_mode": flags.log_only_mode,
            "maintenance_mode": flags.maintenance_mode,
            "updated_at": flags.updated_at,
            "updated_by": flags.updated_by,
        },
    )


def _score_incident_pressure(mode: GroqMode) -> DomainPostureScore:
    del mode

    open_incidents = [incident for incident in _INCIDENTS if incident.status == "open"]
    total_open = len(open_incidents)

    counts_by_severity: dict[IncidentSeverity, int] = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    for incident in open_incidents:
        counts_by_severity[incident.severity] += 1

    high_count = counts_by_severity["high"]
    critical_count = counts_by_severity["critical"]
    medium_count = counts_by_severity["medium"]

    base = 100.0
    base -= total_open * 6.0
    base -= medium_count * 4.0
    base -= high_count * 10.0
    base -= critical_count * 18.0

    newest_open_incident_at = (
        max((incident.created_at for incident in open_incidents), default=None)
        if open_incidents
        else None
    )

    score = _clamp_score(base)

    rationale = (
        f"{total_open} open incidents with {high_count} high and "
        f"{critical_count} critical requiring attention."
    )

    return DomainPostureScore(
        name="incident_pressure",
        score=score,
        weight=0.20,
        rationale=rationale,
        indicators={
            "open_incidents": total_open,
            "by_severity": counts_by_severity,
            "high_open": high_count,
            "critical_open": critical_count,
            "medium_open": medium_count,
            "newest_open_incident_at": newest_open_incident_at,
        },
    )


def _score_request_stream_exposure(mode: GroqMode) -> DomainPostureScore:
    del mode

    recent_events = list(_REQUEST_EVENTS[-100:])
    total = len(recent_events)

    high_risk = sum(1 for event in recent_events if event.risk_score >= 70)
    blocked_or_quarantined = sum(
        1 for event in recent_events if event.verdict in ("block", "quarantine")
    )
    prompt_injection_signals = sum(
        1
        for event in recent_events
        if any(signal == "prompt_injection" for signal in event.signals)
    )
    credential_leak_signals = sum(
        1
        for event in recent_events
        if any(signal == "credential_leak" for signal in event.signals)
    )
    data_exfiltration_signals = sum(
        1
        for event in recent_events
        if any(signal == "data_exfiltration" for signal in event.signals)
    )

    if total == 0:
        base = 100.0
        high_risk_ratio = 0.0
        blocked_ratio = 0.0
    else:
        high_risk_ratio = high_risk / total
        blocked_ratio = blocked_or_quarantined / total
        base = 100.0
        base -= high_risk_ratio * 45.0
        base -= blocked_ratio * 20.0
        base -= prompt_injection_signals * 2.0
        base -= credential_leak_signals * 3.0
        base -= data_exfiltration_signals * 4.0

    score = _clamp_score(base)
    last_event_at = recent_events[-1].occurred_at if recent_events else None

    rationale = (
        f"Recent stream has {total} requests, {high_risk} high-risk evaluations, "
        f"and {blocked_or_quarantined} blocked or quarantined outcomes."
    )

    return DomainPostureScore(
        name="request_stream_exposure",
        score=score,
        weight=0.15,
        rationale=rationale,
        indicators={
            "recent_requests": total,
            "high_risk_requests": high_risk,
            "blocked_or_quarantined": blocked_or_quarantined,
            "high_risk_ratio": round(high_risk_ratio, 3),
            "blocked_ratio": round(blocked_ratio, 3),
            "prompt_injection_signals": prompt_injection_signals,
            "credential_leak_signals": credential_leak_signals,
            "data_exfiltration_signals": data_exfiltration_signals,
            "last_event_at": last_event_at,
        },
    )


def build_global_posture_summary(mode: GroqMode | None = None) -> GlobalPostureSummary:
    effective_mode: GroqMode = mode or CONTROL_FLAGS.mode
    _seed_runtime_state(effective_mode)

    domains = [
        _score_runtime_actions(effective_mode),
        _score_control_hygiene(effective_mode),
        _score_incident_pressure(effective_mode),
        _score_request_stream_exposure(effective_mode),
    ]

    total_weight = sum(domain.weight for domain in domains) or 1.0
    weighted_score = (
        sum(domain.score * domain.weight for domain in domains) / total_weight
    )
    overall_score = _clamp_score(weighted_score)

    metadata = {
        "source": "ui-groq-posture-summary",
        "version": "v1",
        "domain_count": len(domains),
        "weights": {domain.name: domain.weight for domain in domains},
        "control_mode": CONTROL_FLAGS.mode,
    }

    return GlobalPostureSummary(
        overall_score=overall_score,
        domains=domains,
        generated_at=_utc_now(),
        mode=effective_mode,
        metadata=metadata,
    )


@router.get("/posture-summary", response_model=GlobalPostureSummaryResponse)
def get_posture_summary() -> GlobalPostureSummaryResponse:
    summary = build_global_posture_summary()
    data = summary.to_dict()

    return GlobalPostureSummaryResponse(
        overall_score=data["overall_score"],
        domains=[DomainPostureScoreView(**domain) for domain in data["domains"]],
        generated_at=data["generated_at"],
        mode=data["mode"],
        metadata=data["metadata"],
    )