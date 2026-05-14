from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        candidate = candidate.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return default
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return default


@dataclass(frozen=True, slots=True)
class TriageDecision:
    decision: str
    confidence: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class TriageAssignment:
    owner_id: str
    display_name: str
    queue: str
    team: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner_id": self.owner_id,
            "display_name": self.display_name,
            "queue": self.queue,
            "team": self.team,
        }


@dataclass(frozen=True, slots=True)
class TriageArtifact:
    artifact_id: str
    artifact_type: str
    label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class IncidentTriage:
    incident_id: str
    title: str
    severity: str
    status: str
    source: str
    summary: str
    opened_at: datetime
    updated_at: datetime
    assignment: TriageAssignment
    decision: TriageDecision
    evidence: tuple[TriageArtifact, ...] = ()
    requires_human_review: bool = False
    containment_recommended: bool = False
    blocked_actions: int = 0
    quarantined_actions: int = 0
    generated_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "summary": self.summary,
            "opened_at": _isoformat(self.opened_at),
            "updated_at": _isoformat(self.updated_at),
            "assignment": self.assignment.to_dict(),
            "decision": self.decision.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "requires_human_review": self.requires_human_review,
            "containment_recommended": self.containment_recommended,
            "blocked_actions": self.blocked_actions,
            "quarantined_actions": self.quarantined_actions,
            "generated_at": _isoformat(self.generated_at),
        }


def _normalize_assignment(value: Any) -> TriageAssignment:
    if not isinstance(value, dict):
        return TriageAssignment(owner_id="", display_name="Unassigned", queue="incident-triage", team="")
    return TriageAssignment(
        owner_id=_coerce_str(value.get("owner_id")),
        display_name=_coerce_str(value.get("display_name"), "Unassigned") or "Unassigned",
        queue=_coerce_str(value.get("queue"), "incident-triage") or "incident-triage",
        team=_coerce_str(value.get("team")),
    )


def _normalize_decision(value: Any) -> TriageDecision:
    if not isinstance(value, dict):
        return TriageDecision(
            decision="investigate",
            confidence="medium",
            rationale="Insufficient structured decision data provided.",
        )
    return TriageDecision(
        decision=_coerce_str(value.get("decision"), "investigate") or "investigate",
        confidence=_coerce_str(value.get("confidence"), "medium") or "medium",
        rationale=_coerce_str(value.get("rationale"), "No triage rationale provided.") or "No triage rationale provided.",
    )


def _normalize_artifact(value: Any) -> TriageArtifact | None:
    if not isinstance(value, dict):
        return None

    artifact_id = _coerce_str(value.get("artifact_id"))
    artifact_type = _coerce_str(value.get("artifact_type"))
    label = _coerce_str(value.get("label"))
    if not any([artifact_id, artifact_type, label]):
        return None

    return TriageArtifact(
        artifact_id=artifact_id or "artifact",
        artifact_type=artifact_type or "evidence",
        label=label or artifact_type or artifact_id or "Evidence artifact",
    )


def default_incident_triage() -> IncidentTriage:
    now = _utc_now()
    return IncidentTriage(
        incident_id="",
        title="",
        severity="medium",
        status="triage",
        source="runtime",
        summary="",
        opened_at=now,
        updated_at=now,
        assignment=_normalize_assignment(None),
        decision=_normalize_decision(None),
    )


def build_incident_triage(
    data: dict[str, Any] | None = None,
    *,
    baseline: IncidentTriage | None = None,
) -> IncidentTriage:
    source = data or {}
    current = baseline or default_incident_triage()

    raw_evidence = source.get("evidence")
    if isinstance(raw_evidence, list):
        evidence = tuple(item for entry in raw_evidence if (item := _normalize_artifact(entry)) is not None)
    else:
        evidence = current.evidence

    opened_at = _coerce_datetime(source.get("opened_at"), current.opened_at) or current.opened_at
    updated_at = _coerce_datetime(source.get("updated_at"), current.updated_at) or current.updated_at

    return IncidentTriage(
        incident_id=_coerce_str(source.get("incident_id"), current.incident_id),
        title=_coerce_str(source.get("title"), current.title),
        severity=_coerce_str(source.get("severity"), current.severity) or current.severity,
        status=_coerce_str(source.get("status"), current.status) or current.status,
        source=_coerce_str(source.get("source"), current.source) or current.source,
        summary=_coerce_str(source.get("summary"), current.summary),
        opened_at=opened_at,
        updated_at=updated_at,
        assignment=_normalize_assignment(source.get("assignment")) if "assignment" in source else current.assignment,
        decision=_normalize_decision(source.get("decision")) if "decision" in source else current.decision,
        evidence=evidence,
        requires_human_review=_coerce_bool(source.get("requires_human_review"), current.requires_human_review),
        containment_recommended=_coerce_bool(source.get("containment_recommended"), current.containment_recommended),
        blocked_actions=max(0, _coerce_int(source.get("blocked_actions"), current.blocked_actions)),
        quarantined_actions=max(0, _coerce_int(source.get("quarantined_actions"), current.quarantined_actions)),
        generated_at=_coerce_datetime(source.get("generated_at"), _utc_now()) or _utc_now(),
    )


def incident_triage_summary(triage: IncidentTriage) -> dict[str, Any]:
    return {
        "incident_id": triage.incident_id,
        "title": triage.title,
        "severity": triage.severity,
        "status": triage.status,
        "source": triage.source,
        "summary": triage.summary,
        "timeline": {
            "opened_at": _isoformat(triage.opened_at),
            "updated_at": _isoformat(triage.updated_at),
            "generated_at": _isoformat(triage.generated_at),
        },
        "assignment": triage.assignment.to_dict(),
        "decision": triage.decision.to_dict(),
        "signals": {
            "requires_human_review": triage.requires_human_review,
            "containment_recommended": triage.containment_recommended,
            "blocked_actions": triage.blocked_actions,
            "quarantined_actions": triage.quarantined_actions,
            "evidence_count": len(triage.evidence),
        },
        "evidence": [item.to_dict() for item in triage.evidence],
    }
