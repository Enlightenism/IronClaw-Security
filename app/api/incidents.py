from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import get_current_organization_id
from app.services.attackcorrelation import AttackCorrelationService

router = APIRouter(prefix="/incidents", tags=["incidents"])


class CorrelateSignalEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_fingerprints: List[str] = Field(default_factory=list)
    tools: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)


class CorrelateSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal_id: str = Field(min_length=1, max_length=200)
    signal_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    severity: str = Field(min_length=1, max_length=40)
    summary: str = Field(min_length=1, max_length=2000)
    score: Optional[int] = Field(default=None, ge=0, le=100)
    evidence: CorrelateSignalEvidence = Field(default_factory=CorrelateSignalEvidence)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CorrelateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signals: List[CorrelateSignal] = Field(min_length=1)
    session_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    actor_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    request_id: Optional[str] = Field(default=None, min_length=1, max_length=200)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentIndicators(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_fingerprints: List[str] = Field(default_factory=list)
    tools: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    campaigns: List[str] = Field(default_factory=list)
    clusters: List[str] = Field(default_factory=list)
    ttp_ids: List[str] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    status: str
    severity: str
    signal_count: int = Field(ge=0)
    indicators: IncidentIndicators
    linked_reviews: List[str] = Field(default_factory=list)
    linked_quarantine_records: List[str] = Field(default_factory=list)
    escalation_actions: List[Dict[str, Any]] = Field(default_factory=list)
    malware_summary: Optional[Dict[str, Any]] = None
    detonation_summary: Optional[Dict[str, Any]] = None
    hostile_context: Optional[Dict[str, Any]] = None


class CorrelateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(ge=0, le=100)
    risk_band: str
    confidence: float = Field(ge=0.0, le=1.0)
    incident: IncidentSummary
    signals: List[Dict[str, Any]]
    linked_reviews: List[str] = Field(default_factory=list)
    linked_quarantine_records: List[str] = Field(default_factory=list)
    recommended_playbooks: List[str] = Field(default_factory=list)
    escalation_actions: List[Dict[str, Any]] = Field(default_factory=list)


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
    session_id: Optional[str] = Query(default=None, min_length=1, max_length=120),
    actor_id: Optional[str] = Query(default=None, min_length=1, max_length=120),
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