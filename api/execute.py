from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from services.securityorchestrator import (
    SecurityOrchestratorService,
    build_security_orchestration_request,
)

router = APIRouter(prefix="/execute", tags=["execute"])

_service = SecurityOrchestratorService()


class ExecuteRequest(BaseModel):
    request_id: str | None = Field(default=None)
    action: str = Field(default="execute", min_length=1)
    target: str = Field(default="runtime", min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(default=0, ge=0, le=100)
    source: str | None = None
    actor_id: str | None = None
    session_id: str | None = None
    organization_id: str | None = None
    requires_network: bool = False
    requires_filesystem: bool = False
    requires_secrets: bool = False
    requires_human_review: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecuteResponse(BaseModel):
    record_id: str
    request_id: str
    status: str
    outcome: str
    allowed: bool
    orchestration: dict[str, Any]
    created_at: str
    updated_at: str | None = None


@router.post("", response_model=ExecuteResponse, status_code=status.HTTP_200_OK)
def execute(request: ExecuteRequest) -> ExecuteResponse:
    orchestration_request = build_security_orchestration_request(
        request_id=request.request_id,
        action=request.action,
        target=request.target,
        payload=request.payload,
        risk_score=request.risk_score,
        source=request.source,
        actor_id=request.actor_id,
        session_id=request.session_id,
        organization_id=request.organization_id,
        requires_network=request.requires_network,
        requires_filesystem=request.requires_filesystem,
        requires_secrets=request.requires_secrets,
        requires_human_review=request.requires_human_review,
        metadata=request.metadata,
    )
    record = _service.execute(orchestration_request)
    return ExecuteResponse.model_validate(record.to_dict())


@router.get("/{record_id}", response_model=ExecuteResponse, status_code=status.HTTP_200_OK)
def get_execution(record_id: str) -> ExecuteResponse:
    record = _service.get_record(record_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution record '{record_id}' was not found.",
        )
    return ExecuteResponse.model_validate(record.to_dict())


@router.get("", response_model=list[ExecuteResponse], status_code=status.HTTP_200_OK)
def list_executions() -> list[ExecuteResponse]:
    return [ExecuteResponse.model_validate(item) for item in _service.list_records_dict()]


__all__ = [
    "ExecuteRequest",
    "ExecuteResponse",
    "router",
]