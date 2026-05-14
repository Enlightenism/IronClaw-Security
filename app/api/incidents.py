from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import get_current_organization_id
from app.services.attackcorrelation import AttackCorrelationService

router = APIRouter(prefix="/incidents", tags=["incidents"])


class CorrelateSignalEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_fingerprints: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)


class CorrelateSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal_id: str = Field(min_length=1, max_length=200)
    signal_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    severity: str = Field(min_length=1, max_length=40)
    summary: str = Field(min_length=1, max_length=2000)
    score: int | None = Field(default=None, ge=0, le=100)
    evidence: CorrelateSignalEvidence = Field(default_factory=CorrelateSignalEvidence)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signals: list[CorrelateSignal] = Field(min_length=1)
    session_id: str | None = Field(default=None, min_length=1, max_length=120)
    actor_id: str | None = Field(default=None, min_length=1, max_length=120)
    request_id: str | None = Field(default=None, min_length=1, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentIndicators(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_fingerprints: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    clusters: list[str] = Field(default_factory=list)
    ttp_ids: list[str] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    status: str
    severity: str
    signal_count: int = Field(ge=0)
    indicators: IncidentIndicators
    linked_reviews: list[str] = Field(default_factory=list)
    linked_quarantine_records: list[str] = Field(default_factory=list)
    escalation_actions: list[dict[str, Any]] = Field(default_factory=list)
    malware_summary: dict[str, Any] | None = None
    detonation_summary: dict[str, Any] | None = None
    hostile_context: dict[str, Any] | None = None


class CorrelateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(ge=0, le=100)
    risk_band: str
    confidence: float = Field(ge=0.0, le=1.0)
    incident: IncidentSummary
    signals: list[dict[str, Any]]
    linked_reviews: list[str] = Field(default_factory=list)
    linked_quarantine_records: list[str] = Field(default_factory=list)
    recommended_playbooks: list[str] = Field(default_factory=list)
    escalation_actions: list[dict[str, Any]] = Field(default_factory=list)


def get_attack_correlation_service() -> AttackCorrelationService:
    return AttackCorrelationService()


@router.post(
    "/correlate",
    response_model=CorrelateResponse,
    status_code=status.HTTP_200_OK,
)
def correlate_incidents(
    payload: CorrelateRequest,
    organization_id: str = Depends(get_current_organization_id),
    service: AttackCorrelationService = Depends(get_attack_correlation_service),
    session_id: str | None = Query(default=None, min_length=1, max_length=120),
    actor_id: str | None = Query(default=None, min_length=1, max_length=120),
) -> CorrelateResponse:
    if not payload.signals:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one signal is required for correlation",
        )

    result = service.correlate(
        [signal.model_dump() for signal in payload.signals],
        session_id=payload.session_id or session_id,
        actor_id=payload.actor_id or actor_id,
        organization_id=organization_id,
        request_id=payload.request_id,
        metadata=payload.metadata,
    )

    return CorrelateResponse.model_validate(result)
