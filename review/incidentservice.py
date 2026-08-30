from __future__ import annotations

from datetime import UTC, datetime
from threading import Lock
from typing import Any

from pydantic import BaseModel, Field

from app.review.reviewqueueservice import ReviewPriority, ReviewQueueService


class IncidentStatus(str):
    OPEN = "open"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class IncidentSeverity(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentRecord(BaseModel):
    incident_id: str = Field(..., description="Stable incident identifier")
    title: str = Field(..., description="Human-readable incident title")
    summary: str = Field(..., description="Short incident summary")
    severity: str = Field(..., description="Severity level")
    status: str = Field(default=IncidentStatus.OPEN, description="Incident lifecycle state")
    source: str = Field(..., description="Origin of the incident")
    source_id: str = Field(..., description="Source entity identifier")
    reasons: list[str] = Field(default_factory=list, description="Why the incident was opened")
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Compact evidence payloads for triage",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional orchestration metadata",
    )
    review_id: str | None = Field(
        default=None,
        description="Linked review queue item when human review is required",
    )
    assigned_to: str | None = Field(
        default=None,
        description="Assigned analyst or responder",
    )
    created_at: str = Field(..., description="UTC ISO-8601 creation timestamp")
    updated_at: str = Field(..., description="UTC ISO-8601 update timestamp")
    resolved_at: str | None = Field(
        default=None,
        description="UTC ISO-8601 resolution timestamp",
    )


class IncidentService:
    """In-memory incident manager with optional review queue escalation.

    Goals:
    - Deterministic lifecycle handling for orchestration/tests.
    - Deduplicate incidents by (source, source_id).
    - Seamlessly create/update linked review queue items.
    - Easy future replacement with a persistent store.
    """

    def __init__(
        self,
        review_queue_service: ReviewQueueService | None = None,
    ) -> None:
        self._lock = Lock()
        self._incidents: dict[str, IncidentRecord] = {}
        self._index_by_source: dict[tuple[str, str], str] = {}
        self._counter = 1
        self._review_queue_service = review_queue_service

    def list_incidents(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
    ) -> list[IncidentRecord]:
        incidents = list(self._incidents.values())

        if status is not None:
            incidents = [incident for incident in incidents if incident.status == status]

        if severity is not None:
            incidents = [incident for incident in incidents if incident.severity == severity]

        if assigned_to is not None:
            incidents = [incident for incident in incidents if incident.assigned_to == assigned_to]

        return sorted(incidents, key=self._sort_key)

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        return self._incidents.get(incident_id)

    def open_incident(
        self,
        *,
        title: str,
        summary: str,
        severity: str,
        source: str,
        source_id: str,
        reasons: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
        escalate_for_review: bool = True,
    ) -> IncidentRecord:
        with self._lock:
            key = (source, source_id)
            existing_id = self._index_by_source.get(key)
            if existing_id:
                return self._update_existing(
                    incident_id=existing_id,
                    title=title,
                    summary=summary,
                    severity=severity,
                    reasons=reasons or [],
                    evidence=evidence or [],
                    metadata=metadata or {},
                    escalate_for_review=escalate_for_review,
                )

            now = self._utcnow()
            incident_id = self._next_incident_id()
            incident = IncidentRecord(
                incident_id=incident_id,
                title=title,
                summary=summary,
                severity=self._coerce_severity(severity),
                status=IncidentStatus.OPEN,
                source=source,
                source_id=source_id,
                reasons=self._dedupe_strings(reasons or []),
                evidence=self._dedupe_evidence(evidence or []),
                metadata=dict(metadata or {}),
                created_at=now,
                updated_at=now,
            )

            if escalate_for_review and self._review_queue_service is not None:
                review_item = self._review_queue_service.escalate_incident(
                    incident_id=incident_id,
                    priority=self._severity_to_priority(incident.severity),
                    title=title,
                    summary=summary,
                    reasons=incident.reasons,
                    evidence=incident.evidence,
                )
                incident = incident.model_copy(update={"review_id": review_item.review_id})

            self._incidents[incident_id] = incident
            self._index_by_source[key] = incident_id
            return incident

    def assign_incident(self, incident_id: str, owner: str) -> IncidentRecord:
        with self._lock:
            incident = self._require(incident_id)
            updated = incident.model_copy(
                update={
                    "assigned_to": owner,
                    "status": IncidentStatus.TRIAGED,
                    "updated_at": self._utcnow(),
                },
            )
            self._incidents[incident_id] = updated
            return updated

    def resolve_incident(self, incident_id: str) -> IncidentRecord:
        with self._lock:
            incident = self._require(incident_id)
            updated = incident.model_copy(
                update={
                    "status": IncidentStatus.RESOLVED,
                    "updated_at": self._utcnow(),
                    "resolved_at": self._utcnow(),
                },
            )
            self._incidents[incident_id] = updated

            if updated.review_id and self._review_queue_service is not None:
                review_item = self._review_queue_service.get(updated.review_id)
                if review_item and review_item.status not in {"completed", "dismissed"}:
                    self._review_queue_service.complete(updated.review_id)

            return updated

    def dismiss_incident(self, incident_id: str, reason: str | None = None) -> IncidentRecord:
        with self._lock:
            incident = self._require(incident_id)
            reasons = list(incident.reasons)
            if reason:
                reasons = self._dedupe_strings([*reasons, reason])

            updated = incident.model_copy(
                update={
                    "status": IncidentStatus.DISMISSED,
                    "reasons": reasons,
                    "updated_at": self._utcnow(),
                    "resolved_at": self._utcnow(),
                },
            )
            self._incidents[incident_id] = updated

            if updated.review_id and self._review_queue_service is not None:
                review_item = self._review_queue_service.get(updated.review_id)
                if review_item and review_item.status not in {"completed", "dismissed"}:
                    self._review_queue_service.dismiss(updated.review_id, reason=reason)

            return updated

    def reopen_incident(self, incident_id: str) -> IncidentRecord:
        with self._lock:
            incident = self._require(incident_id)
            updated = incident.model_copy(
                update={
                    "status": IncidentStatus.OPEN,
                    "updated_at": self._utcnow(),
                    "resolved_at": None,
                },
            )
            self._incidents[incident_id] = updated

            if updated.review_id and self._review_queue_service is not None:
                review_item = self._review_queue_service.get(updated.review_id)
                if review_item and review_item.status in {"completed", "dismissed"}:
                    self._review_queue_service.reopen(updated.review_id)

            return updated

    def counts(self) -> dict[str, int]:
        counts = {
            IncidentStatus.OPEN: 0,
            IncidentStatus.TRIAGED: 0,
            IncidentStatus.RESOLVED: 0,
            IncidentStatus.DISMISSED: 0,
        }
        for incident in self._incidents.values():
            counts[incident.status] = counts.get(incident.status, 0) + 1
        return counts

    def _update_existing(
        self,
        *,
        incident_id: str,
        title: str,
        summary: str,
        severity: str,
        reasons: list[str],
        evidence: list[dict[str, Any]],
        metadata: dict[str, Any],
        escalate_for_review: bool,
    ) -> IncidentRecord:
        incident = self._require(incident_id)
        updated = incident.model_copy(
            update={
                "title": title or incident.title,
                "summary": summary or incident.summary,
                "severity": self._max_severity(incident.severity, self._coerce_severity(severity)),
                "status": IncidentStatus.OPEN if incident.status in {IncidentStatus.DISMISSED, IncidentStatus.RESOLVED} else incident.status,
                "reasons": self._dedupe_strings([*incident.reasons, *reasons]),
                "evidence": self._dedupe_evidence([*incident.evidence, *evidence]),
                "metadata": {**incident.metadata, **metadata},
                "updated_at": self._utcnow(),
                "resolved_at": None if incident.status in {IncidentStatus.DISMISSED, IncidentStatus.RESOLVED} else incident.resolved_at,
            },
        )

        if escalate_for_review and self._review_queue_service is not None:
            review_item = self._review_queue_service.escalate_incident(
                incident_id=incident_id,
                priority=self._severity_to_priority(updated.severity),
                title=updated.title,
                summary=updated.summary,
                reasons=updated.reasons,
                evidence=updated.evidence,
            )
            updated = updated.model_copy(update={"review_id": review_item.review_id})

        self._incidents[incident_id] = updated
        return updated

    def _require(self, incident_id: str) -> IncidentRecord:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise KeyError(f"incident not found: {incident_id}")
        return incident

    def _next_incident_id(self) -> str:
        incident_id = f"inc_{self._counter:05d}"
        self._counter += 1
        return incident_id

    def _coerce_severity(self, severity: str) -> str:
        normalized = (severity or IncidentSeverity.MEDIUM).strip().lower()
        if normalized in {
            IncidentSeverity.LOW,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.HIGH,
            IncidentSeverity.CRITICAL,
        }:
            return normalized
        return IncidentSeverity.MEDIUM

    def _max_severity(self, left: str, right: str) -> str:
        rank = {
            IncidentSeverity.LOW: 0,
            IncidentSeverity.MEDIUM: 1,
            IncidentSeverity.HIGH: 2,
            IncidentSeverity.CRITICAL: 3,
        }
        return left if rank[left] >= rank[right] else right

    def _severity_to_priority(self, severity: str) -> str:
        mapping = {
            IncidentSeverity.LOW: ReviewPriority.LOW.value,
            IncidentSeverity.MEDIUM: ReviewPriority.MEDIUM.value,
            IncidentSeverity.HIGH: ReviewPriority.HIGH.value,
            IncidentSeverity.CRITICAL: ReviewPriority.CRITICAL.value,
        }
        return mapping.get(severity, ReviewPriority.MEDIUM.value)

    def _dedupe_strings(self, values: list[str]) -> list[str]:
        seen = set()
        result: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def _dedupe_evidence(self, values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
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

    def _sort_key(self, incident: IncidentRecord) -> tuple[int, int, str]:
        status_rank = {
            IncidentStatus.OPEN: 0,
            IncidentStatus.TRIAGED: 1,
            IncidentStatus.RESOLVED: 2,
            IncidentStatus.DISMISSED: 3,
        }
        severity_rank = {
            IncidentSeverity.CRITICAL: 0,
            IncidentSeverity.HIGH: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.LOW: 3,
        }
        return (
            status_rank.get(incident.status, 99),
            severity_rank.get(incident.severity, 99),
            incident.created_at,
        )

    def _utcnow(self) -> str:
        return datetime.now(UTC).isoformat()
