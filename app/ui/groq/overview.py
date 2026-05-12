from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.groq_security_brain import GroqMode
from app.ui.groq.brain_status import build_groq_brain_status_view
from app.ui.groq.control_panel import CONTROL_FLAGS
from app.ui.groq.incidents import _INCIDENTS, IncidentSeverity
from app.ui.groq.remediation_actions import _REMEDIATION_ACTIONS
from app.ui.groq.request_stream import _REQUEST_EVENTS

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-overview"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class OverviewPostureWidget:
    overall_score: int
    mode: GroqMode
    description: str
    indicators: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "mode": self.mode,
            "description": self.description,
            "indicators": dict(self.indicators),
        }


@dataclass(slots=True)
class OverviewTrafficWidget:
    total_requests: int
    high_risk_requests: int
    blocked_or_quarantined: int
    last_request_at: str | None
    indicators: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "high_risk_requests": self.high_risk_requests,
            "blocked_or_quarantined": self.blocked_or_quarantined,
            "last_request_at": self.last_request_at,
            "indicators": dict(self.indicators),
        }


@dataclass(slots=True)
class OverviewIncidentsWidget:
    open_incidents: int
    high_or_critical_incidents: int
    newest_incident_at: str | None
    indicators: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "open_incidents": self.open_incidents,
            "high_or_critical_incidents": self.high_or_critical_incidents,
            "newest_incident_at": self.newest_incident_at,
            "indicators": dict(self.indicators),
        }


@dataclass(slots=True)
class OverviewControlsWidget:
    mode: GroqMode
    flags: dict[str, Any] = field(default_factory=dict)
    risk_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "flags": dict(self.flags),
            "risk_notes": list(self.risk_notes),
        }


@dataclass(slots=True)
class OverviewRemediationWidget:
    suggested_actions: int
    queued_actions: int
    indicators: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "suggested_actions": self.suggested_actions,
            "queued_actions": self.queued_actions,
            "indicators": dict(self.indicators),
        }


@dataclass(slots=True)
class GroqSecurityOverview:
    generated_at: str
    posture: OverviewPostureWidget
    traffic: OverviewTrafficWidget
    incidents: OverviewIncidentsWidget
    controls: OverviewControlsWidget
    remediation: OverviewRemediationWidget
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "posture": self.posture.to_dict(),
            "traffic": self.traffic.to_dict(),
            "incidents": self.incidents.to_dict(),
            "controls": self.controls.to_dict(),
            "remediation": self.remediation.to_dict(),
            "metadata": dict(self.metadata),
        }


# ---------- Pydantic views ---------------------------------------------------


class OverviewPostureView(BaseModel):
    overall_score: int
    mode: GroqMode
    description: str
    indicators: dict[str, Any] = Field(default_factory=dict)


class OverviewTrafficView(BaseModel):
    total_requests: int
    high_risk_requests: int
    blocked_or_quarantined: int
    last_request_at: str | None
    indicators: dict[str, Any] = Field(default_factory=dict)


class OverviewIncidentsView(BaseModel):
    open_incidents: int
    high_or_critical_incidents: int
    newest_incident_at: str | None
    indicators: dict[str, Any] = Field(default_factory=dict)


class OverviewControlsView(BaseModel):
    mode: GroqMode
    flags: dict[str, Any] = Field(default_factory=dict)
    risk_notes: list[str] = Field(default_factory=list)


class OverviewRemediationView(BaseModel):
    suggested_actions: int
    queued_actions: int
    indicators: dict[str, Any] = Field(default_factory=dict)


class GroqSecurityOverviewResponse(BaseModel):
    generated_at: str
    posture: OverviewPostureView
    traffic: OverviewTrafficView
    incidents: OverviewIncidentsView
    controls: OverviewControlsView
    remediation: OverviewRemediationView
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------- internal scoring helpers ----------------------------------------


def _compute_posture_widget(mode: GroqMode) -> OverviewPostureWidget:
    """
    Lightweight overall posture score using current decision stats and mode.
    This is tuned for always-on prompt protection rather than a fixed window.[web:1277][web:1309]
    """
    brain_view = build_groq_brain_status_view(mode=mode)
    s = brain_view.status

    total = max(s.total_evaluations, 1)
    high_risk = s.blocked_count + s.quarantined_count
    warns = s.warned_count

    high_risk_ratio = high_risk / total
    warn_ratio = warns / total

    base = 100.0
    base -= high_risk_ratio * 55.0
    base -= warn_ratio * 25.0

    if mode == "disabled":
        base -= 35.0
    elif mode == "observe":
        base -= 20.0
    elif mode == "assist":
        base -= 10.0

    score = max(0, min(100, int(round(base))))

    description = (
        f"Protecting live AI prompts in {mode} mode with {total} recent decisions; "
        f"{high_risk} high-risk actions and {warns} warnings observed."
    )

    indicators = {
        "total_decisions": total,
        "blocked": s.blocked_count,
        "quarantined": s.quarantined_count,
        "warned": warns,
        "allowed": s.allowed_count,
        "high_risk_ratio": round(high_risk_ratio, 3),
        "warn_ratio": round(warn_ratio, 3),
    }

    return OverviewPostureWidget(
        overall_score=score,
        mode=mode,
        description=description,
        indicators=indicators,
    )


def _compute_traffic_widget() -> OverviewTrafficWidget:
    """
    Summarize current request stream, focusing on risk for prompt traffic.[web:1277]
    """
    events = _REQUEST_EVENTS
    total = len(events)

    high_risk = 0
    blocked_or_quarantined = 0
    last_request_at: str | None = None

    for e in events:
        if e.risk_score >= 70:
            high_risk += 1
        if e.verdict in ("block", "quarantine"):
            blocked_or_quarantined += 1
        last_request_at = e.occurred_at

    indicators = {
        "buffer_size": total,
        "high_risk_ratio": round((high_risk / total), 3) if total else 0.0,
    }

    return OverviewTrafficWidget(
        total_requests=total,
        high_risk_requests=high_risk,
        blocked_or_quarantined=blocked_or_quarantined,
        last_request_at=last_request_at,
        indicators=indicators,
    )


def _compute_incidents_widget() -> OverviewIncidentsWidget:
    """
    Current AI-created incident load; important for continuous prompt defense.[web:1253][web:1257]
    """
    incidents = _INCIDENTS
    open_incidents = [i for i in incidents if i.status == "open"]
    high_or_critical = [
        i for i in open_incidents if i.severity in ("high", "critical")
    ]

    newest_at = open_incidents[-1].created_at if open_incidents else None

    counts_by_sev: dict[IncidentSeverity, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for i in open_incidents:
        counts_by_sev[i.severity] = counts_by_sev.get(i.severity, 0) + 1

    indicators = {
        "by_severity": counts_by_sev,
    }

    return OverviewIncidentsWidget(
        open_incidents=len(open_incidents),
        high_or_critical_incidents=len(high_or_critical),
        newest_incident_at=newest_at,
        indicators=indicators,
    )


def _compute_controls_widget() -> OverviewControlsWidget:
    """
    Control hygiene snapshot (mode + toggles) with inline risk notes.[web:1275][web:1312]
    """
    f = CONTROL_FLAGS
    flags = {
        "allow_shell_commands": f.allow_shell_commands,
        "allow_network": f.allow_network,
        "allow_file_write": f.allow_file_write,
        "allow_prompt_injection_testing": f.allow_prompt_injection_testing,
        "log_only_mode": f.log_only_mode,
        "maintenance_mode": f.maintenance_mode,
        "updated_at": f.updated_at,
        "updated_by": f.updated_by,
    }

    risk_notes: list[str] = []

    if f.mode == "disabled":
        risk_notes.append("Groq security brain is disabled; prompts are not being actively enforced.")
    elif f.mode == "observe":
        risk_notes.append("Observe mode: prompts are evaluated but not enforced.")
    elif f.mode == "assist":
        risk_notes.append("Assist mode: AI advises, but may not fully block risky actions.")

    if f.allow_shell_commands:
        risk_notes.append("Shell commands are allowed; ensure sandboxing and least privilege.")
    if f.allow_prompt_injection_testing:
        risk_notes.append("Prompt injection testing is enabled; avoid using in production tenants.")
    if f.log_only_mode:
        risk_notes.append("Log-only mode reduces enforcement; consider tightening for sensitive workloads.")

    return OverviewControlsWidget(
        mode=f.mode,
        flags=flags,
        risk_notes=risk_notes,
    )


def _compute_remediation_widget() -> OverviewRemediationWidget:
    """
    Quick view of AI remediation pipeline health (suggested vs queued actions).[
    """
    actions = list(_REMEDIATION_ACTIONS.values())
    suggested = [a for a in actions if a.status == "suggested"]
    queued = [a for a in actions if a.status == "queued"]

    indicators = {
        "total_actions": len(actions),
    }

    return OverviewRemediationWidget(
        suggested_actions=len(suggested),
        queued_actions=len(queued),
        indicators=indicators,
    )


def build_groq_security_overview() -> GroqSecurityOverview:
    """
    Build the full AI security cockpit snapshot.

    This is intentionally a current-state view tailored to continuous
    prompt protection rather than a fixed time window.[web:1277][web:1309]
    """
    mode: GroqMode = CONTROL_FLAGS.mode

    posture = _compute_posture_widget(mode)
    traffic = _compute_traffic_widget()
    incidents = _compute_incidents_widget()
    controls = _compute_controls_widget()
    remediation = _compute_remediation_widget()

    return GroqSecurityOverview(
        generated_at=_utc_now(),
        posture=posture,
        traffic=traffic,
        incidents=incidents,
        controls=controls,
        remediation=remediation,
        metadata={
            "focus": "current_state_prompt_protection",
        },
    )


# ---------- HTTP endpoint ----------------------------------------------------


@router.get("/overview", response_model=GroqSecurityOverviewResponse)
def get_groq_security_overview() -> GroqSecurityOverviewResponse:
    """
    AI security cockpit overview for prompt protection.

    Designed as the main dashboard payload: summarizes current posture,
    live request risk, AI-created incidents, control state, and remediation
    pipeline so operators can see how well user prompts are being protected
    right now.[web:1277][web:1305][web:1309]
    """
    overview = build_groq_security_overview()
    data = overview.to_dict()

    return GroqSecurityOverviewResponse(
        generated_at=data["generated_at"],
        posture=OverviewPostureView(**data["posture"]),
        traffic=OverviewTrafficView(**data["traffic"]),
        incidents=OverviewIncidentsView(**data["incidents"]),
        controls=OverviewControlsView(**data["controls"]),
        remediation=OverviewRemediationView(**data["remediation"]),
        metadata=data["metadata"],
    )