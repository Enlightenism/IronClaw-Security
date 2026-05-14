from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.services.incidentstore import (
    IncidentRecord as StoredIncidentRecord,
)
from app.services.incidentstore import (
    build_incident_store,
)

router = APIRouter(
    prefix="/incidents",
    tags=["incidents"],
    dependencies=[Depends(require_api_key)],
)


IncidentSeverity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "triaged", "contained", "resolved"]
IncidentSource = Literal["scan", "guard", "sandbox", "review", "system", "ironclaw"]


class IncidentRecordView(BaseModel):
    incidentid: str = Field(..., description="Stable incident identifier.")
    title: str = Field(..., description="Short incident title.")
    summary: str = Field(..., description="Human-readable incident summary.")
    severity: IncidentSeverity = Field(..., description="Incident severity.")
    status: IncidentStatus = Field(..., description="Current incident status.")
    source: IncidentSource = Field(..., description="Origin of the incident.")
    createdat: str = Field(..., description="UTC ISO-8601 timestamp.")
    updatedat: str = Field(..., description="UTC ISO-8601 timestamp.")
    requestid: str | None = Field(default=None, description="Related request identifier.")
    traceid: str | None = Field(default=None, description="Related trace identifier.")
    assetref: str | None = Field(default=None, description="Related asset or object reference.")
    verdict: str | None = Field(default=None, description="Related security verdict if available.")
    owner: str | None = Field(default=None, description="Assigned owner.")
    tags: list[str] = Field(default_factory=list, description="Search and routing tags.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional incident metadata.")


class IncidentListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int = Field(..., description="Total incidents returned.")
    items: list[IncidentRecordView] = Field(default_factory=list, description="Incident records.")


class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    summary: str = Field(..., min_length=3, max_length=2000)
    severity: IncidentSeverity
    source: IncidentSource
    status: IncidentStatus = "open"
    requestid: str | None = Field(default=None, max_length=200)
    traceid: str | None = Field(default=None, max_length=200)
    assetref: str | None = Field(default=None, max_length=500)
    verdict: str | None = Field(default=None, max_length=100)
    owner: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentStatusUpdateRequest(BaseModel):
    status: IncidentStatus
    owner: str | None = Field(default=None, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    incident: IncidentRecordView


def utcnowiso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_severity(value: Any) -> IncidentSeverity:
    normalized = str(value or "medium").strip().lower()
    if normalized in {"low", "medium", "high", "critical"}:
        return normalized  # type: ignore[return-value]
    return "medium"


def _normalize_status(value: Any) -> IncidentStatus:
    normalized = str(value or "open").strip().lower()
    if normalized in {"open", "triaged", "contained", "resolved"}:
        return normalized  # type: ignore[return-value]
    return "open"


def _normalize_source(value: Any) -> IncidentSource:
    normalized = str(value or "system").strip().lower()
    if normalized in {"scan", "guard", "sandbox", "review", "system", "ironclaw"}:
        return normalized  # type: ignore[return-value]
    return "system"


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    elif isinstance(value, tuple) or isinstance(value, set):
        items = list(value)
    else:
        items = [value]
    return [str(item) for item in items if str(item).strip()]


def toview(item: StoredIncidentRecord | dict[str, Any]) -> IncidentRecordView:
    payload = item.to_dict() if hasattr(item, "to_dict") and callable(item.to_dict) else dict(item)

    raw_metadata = payload.get("metadata")
    metadata = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}

    return IncidentRecordView(
        incidentid=str(payload.get("incidentid") or payload.get("incident_id") or payload.get("id") or ""),
        title=str(payload.get("title") or "Security incident"),
        summary=str(payload.get("summary") or payload.get("description") or payload.get("title") or ""),
        severity=_normalize_severity(payload.get("severity")),
        status=_normalize_status(payload.get("status")),
        source=_normalize_source(payload.get("source")),
        createdat=str(payload.get("createdat") or payload.get("created_at") or utcnowiso()),
        updatedat=str(payload.get("updatedat") or payload.get("updated_at") or utcnowiso()),
        requestid=(str(payload["requestid"]) if payload.get("requestid") is not None else str(payload["request_id"]) if payload.get("request_id") is not None else None),
        traceid=(str(payload["traceid"]) if payload.get("traceid") is not None else str(payload["trace_id"]) if payload.get("trace_id") is not None else None),
        assetref=(str(payload["assetref"]) if payload.get("assetref") is not None else str(payload["asset_ref"]) if payload.get("asset_ref") is not None else None),
        verdict=str(payload["verdict"]) if payload.get("verdict") is not None else None,
        owner=(str(payload["owner"]) if payload.get("owner") is not None else str(payload["assigned_to"]) if payload.get("assigned_to") is not None else str(payload["owner_id"]) if payload.get("owner_id") is not None else None),
        tags=_string_list(payload.get("tags")),
        metadata=metadata,
    )


@router.get("/", response_model=IncidentListResponse)
def listincidents(
    severity: IncidentSeverity | None = Query(default=None),
    status: IncidentStatus | None = Query(default=None),
    source: IncidentSource | None = Query(default=None),
) -> IncidentListResponse:
    store = build_incident_store(mode="memory")
    items = store.listincidents(
        severity=severity,
        status=status,
        source=source,
    )
    return IncidentListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=utcnowiso(),
        total=len(items),
        items=[toview(item) for item in items],
    )


@router.get("/{incidentid}", response_model=IncidentResponse)
def getincident(incidentid: str) -> IncidentResponse:
    store = build_incident_store(mode="memory")
    item = store.getincident(incidentid)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown incident: {incidentid}",
        )

    return IncidentResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=utcnowiso(),
        incident=toview(item),
    )


@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def createincident(payload: IncidentCreateRequest) -> IncidentResponse:
    store = build_incident_store(mode="memory")
    item = store.createincident(
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        source=payload.source,
        status=payload.status,
        requestid=payload.requestid,
        traceid=payload.traceid,
        assetref=payload.assetref,
        verdict=payload.verdict,
        owner=payload.owner,
        tags=payload.tags,
        metadata=payload.metadata,
    )
    return IncidentResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=utcnowiso(),
        incident=toview(item),
    )


@router.put("/{incidentid}/status", response_model=IncidentResponse)
def updateincidentstatus(
    incidentid: str,
    payload: IncidentStatusUpdateRequest,
) -> IncidentResponse:
    store = build_incident_store(mode="memory")
    item = store.updateincidentstatus(
        incidentid,
        status=payload.status,
        owner=payload.owner,
        metadata=payload.metadata,
    )
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown incident: {incidentid}",
        )

    return IncidentResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=utcnowiso(),
        incident=toview(item),
    )
