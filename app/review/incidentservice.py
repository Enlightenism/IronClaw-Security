from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.review.reviewqueueservice import ReviewPriority, ReviewQueueItem, ReviewQueueService


class IncidentRecord(BaseModel):
    incident_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    severity: str = Field(default="medium")
    session_id: str | None = None
    artifact_id: str | None = None
    reasons: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class IncidentReviewEscalationResult(BaseModel):
    incident_id: str
    review_id: str
    queued: bool
    priority: str
    status: str


class IncidentService:
    def __init__(self, review_queue: ReviewQueueService | None = None) -> None:
        self._review_queue = review_queue or ReviewQueueService()
        self._incidents: dict[str, IncidentRecord] = {}

    def get(self, incident_id: str) -> IncidentRecord | None:
        return self._incidents.get(incident_id)

    def list_incidents(self) -> list[IncidentRecord]:
        return list(self._incidents.values())

    def register_incident(self, incident: IncidentRecord) -> IncidentRecord:
        self._incidents[incident.incident_id] = incident
        return incident

    def register_and_escalate(self, incident: IncidentRecord) -> IncidentReviewEscalationResult:
        self.register_incident(incident)
        review_item = self.escalate_to_review_queue(incident.incident_id)
        return IncidentReviewEscalationResult(
            incident_id=incident.incident_id,
            review_id=review_item.review_id,
            queued=True,
            priority=review_item.priority.value,
            status=review_item.status.value,
        )

    def escalate_to_review_queue(self, incident_id: str) -> ReviewQueueItem:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise KeyError(f"incident not found: {incident_id}")

        review_item = self._review_queue.escalate_incident(
            incident_id=incident.incident_id,
            priority=self._severity_to_priority(incident.severity).value,
            title=incident.title,
            summary=incident.summary,
            reasons=self._build_reasons(incident),
            evidence=self._build_evidence(incident),
        )
        return review_item

    def _severity_to_priority(self, severity: str) -> ReviewPriority:
        normalized = (severity or "medium").strip().lower()
        if normalized in {"critical", "sev0", "sev-0", "p0"}:
            return ReviewPriority.CRITICAL
        if normalized in {"high", "sev1", "sev-1", "p1"}:
            return ReviewPriority.HIGH
        if normalized in {"low", "sev3", "sev-3", "p3"}:
            return ReviewPriority.LOW
        return ReviewPriority.MEDIUM

    def _build_reasons(self, incident: IncidentRecord) -> list[str]:
        reasons = list(incident.reasons)
        reasons.append(f"severity:{incident.severity.lower()}")
        if incident.session_id:
            reasons.append(f"session:{incident.session_id}")
        if incident.artifact_id:
            reasons.append(f"artifact:{incident.artifact_id}")
        return self._dedupe_strings(reasons)

    def _build_evidence(self, incident: IncidentRecord) -> list[dict[str, Any]]:
        evidence = list(incident.evidence)
        if incident.session_id:
            evidence.append({"type": "session", "session_id": incident.session_id})
        if incident.artifact_id:
            evidence.append({"type": "artifact", "artifact_id": incident.artifact_id})
        evidence.append(
            {
                "type": "incident",
                "incident_id": incident.incident_id,
                "severity": incident.severity,
                "title": incident.title,
            },
        )
        return self._dedupe_dicts(evidence)

    def _dedupe_strings(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def _dedupe_dicts(self, values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[Any, ...]] = set()
        result: list[dict[str, Any]] = []
        for value in values:
            frozen = self._freeze(value)
            if frozen in seen:
                continue
            seen.add(frozen)
            result.append(value)
        return result

    def _freeze(self, value: Any) -> Any:
        if isinstance(value, dict):
            return tuple(sorted((k, self._freeze(v)) for k, v in value.items()))
        if isinstance(value, list):
            return tuple(self._freeze(v) for v in value)
        if isinstance(value, set):
            return tuple(sorted(self._freeze(v) for v in value))
        return value
