from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.review.incidentservice import IncidentRecord, IncidentService
from app.review.reviewqueueservice import ReviewQueueService

router = APIRouter(prefix="/incidents", tags=["incidents"])

_review_queue_service = ReviewQueueService()
_incident_service = IncidentService(review_queue=_review_queue_service)


class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, description="Human-readable incident title")
    summary: str = Field(..., min_length=1, description="Short incident summary")
    severity: str = Field(default="medium", description="Incident severity")
    source: str = Field(..., min_length=1, description="Origin system or detector")
    source_id: str = Field(..., min_length=1, description="Stable source entity identifier")
    reasons: list[str] = Field(default_factory=list, description="Why the incident opened")
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Compact evidence payloads for triage",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional incident metadata",
    )
    escalate_for_review: bool = Field(
        default=True,
        description="Whether to create or update a linked review queue item",
    )


class IncidentAssignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=1, description="Responder or analyst owner")


class IncidentDismissRequest(BaseModel):
    reason: str | None = Field(default=None, description="Dismissal reason")


class IncidentListResponse(BaseModel):
    items: list[IncidentRecord]
    counts: dict[str, int]


def get_incident_service() -> IncidentService:
    return _incident_service


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    assigned_to: str | None = None,
) -> IncidentListResponse:
    service = get_incident_service()
    items = service.list_incidents(
        status=status,
        severity=severity,
        assigned_to=assigned_to,
    )
    return IncidentListResponse(items=items, counts=service.counts())


@router.get("/{incident_id}", response_model=IncidentRecord)
def get_incident(incident_id: str) -> IncidentRecord:
    incident = get_incident_service().get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"incident not found: {incident_id}")
    return incident


@router.post("", response_model=IncidentRecord, status_code=201)
def create_incident(payload: IncidentCreateRequest) -> IncidentRecord:
    return get_incident_service().open_incident(
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        source=payload.source,
        source_id=payload.source_id,
        reasons=payload.reasons,
        evidence=payload.evidence,
        metadata=payload.metadata,
        escalate_for_review=payload.escalate_for_review,
    )


@router.post("/{incident_id}/assign", response_model=IncidentRecord)
def assign_incident(incident_id: str, payload: IncidentAssignRequest) -> IncidentRecord:
    service = get_incident_service()
    try:
        return service.assign_incident(incident_id, payload.assigned_to)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{incident_id}/resolve", response_model=IncidentRecord)
def resolve_incident(incident_id: str) -> IncidentRecord:
    service = get_incident_service()
    try:
        return service.resolve_incident(incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{incident_id}/dismiss", response_model=IncidentRecord)
def dismiss_incident(
    incident_id: str,
    payload: IncidentDismissRequest,
) -> IncidentRecord:
    service = get_incident_service()
    try:
        return service.dismiss_incident(incident_id, reason=payload.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{incident_id}/reopen", response_model=IncidentRecord)
def reopen_incident(incident_id: str) -> IncidentRecord:
    service = get_incident_service()
    try:
        return service.reopen_incident(incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
