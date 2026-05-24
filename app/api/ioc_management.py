from __future__ import annotations

import logging
from typing import Any
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.schemas.threat_detection import (
    IOCResponse,
    IOCTypeEnum,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)
from app.services.ioc_store import get_ioc_store
from app.services.threat_feed_ingestion import (
    IOCFilterRequest,
    IOCRecord,
    _utcnow_iso,
)

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/threat/iocs", tags=["ioc-management"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class IOCCreateRequest(BaseModel):
    value: str = Field(..., description="Raw IOC value (IP, domain, hash, CVE, MITRE technique, URL, etc.)")
    ioc_type: IOCTypeEnum = Field(default=IOCTypeEnum.UNKNOWN)
    source: ThreatFeedSourceEnum = Field(default=ThreatFeedSourceEnum.INTERNAL)
    severity: ThreatSeverityLevel = Field(default=ThreatSeverityLevel.MEDIUM)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    description: str = Field(default="")
    org_id: str | None = Field(default=None)
    mitre_technique_id: str | None = Field(default=None)
    mitre_tactic: str | None = Field(default=None)
    cve_id: str | None = Field(default=None)
    expiry: str | None = Field(default=None, description="ISO 8601 expiry timestamp (UTC)")
    extra: dict[str, Any] = Field(default_factory=dict)


class IOCUpdateRequest(BaseModel):
    severity: ThreatSeverityLevel | None = Field(default=None)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    tags: list[str] | None = Field(default=None)
    description: str | None = Field(default=None)
    mitre_technique_id: str | None = Field(default=None)
    mitre_tactic: str | None = Field(default=None)
    cve_id: str | None = Field(default=None)
    expiry: str | None = Field(default=None)
    active: bool | None = Field(default=None)
    extra: dict[str, Any] | None = Field(default=None)


class IOCBulkCreateRequest(BaseModel):
    records: list[IOCCreateRequest] = Field(..., min_length=1, max_length=500)
    overwrite: bool = Field(default=False, description="Overwrite existing records instead of merging")


class IOCBulkCreateResponse(BaseModel):
    inserted: int
    updated: int
    skipped: int


class IOCDeactivateResponse(BaseModel):
    ioc_id: str
    deactivated: bool


class IOCDeleteResponse(BaseModel):
    ioc_id: str
    deleted: bool


class IOCDeleteByIngestResponse(BaseModel):
    feed_ingest_id: str
    deleted: int


class IOCPruneResponse(BaseModel):
    pruned: int


class IOCCountResponse(BaseModel):
    count: int
    source: str | None
    active: bool | None
    org_id: str | None


class IOCHealthResponse(BaseModel):
    status: str
    ioc_count: int | None = None
    detail: str | None = None


class IOCLookupBulkRequest(BaseModel):
    values: list[str] = Field(..., min_length=1, max_length=200)
    org_id: str | None = Field(default=None)
    active_only: bool = Field(default=True)


class IngestLogListResponse(BaseModel):
    ingest_id: str
    source: str
    status: str
    iocs_parsed: int
    iocs_inserted: int
    iocs_updated: int
    iocs_skipped: int
    errors: list[str]
    started_at: str
    completed_at: str | None
    org_id: str | None
    metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ioc_record_to_response(r: IOCRecord) -> IOCResponse:
    return IOCResponse(
        ioc_id=r.ioc_id,
        ioc_type=r.ioc_type,
        value=r.value,
        source=r.source,
        severity=r.severity,
        confidence=r.confidence,
        tags=r.tags,
        description=r.description,
        org_id=r.org_id,
        mitre_technique_id=r.mitre_technique_id,
        mitre_tactic=r.mitre_tactic,
        cve_id=r.cve_id,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
        expiry=r.expiry,
        active=r.active,
        feed_ingest_id=r.feed_ingest_id,
        extra=r.extra,
    )


def _create_request_to_record(req: IOCCreateRequest, feed_ingest_id: str = "") -> IOCRecord:
    now = _utcnow_iso()
    return IOCRecord(
        ioc_id=f"ioc-{uuid.uuid4().hex}",
        ioc_type=req.ioc_type,
        value=req.value,
        source=req.source,
        severity=req.severity,
        confidence=req.confidence,
        tags=req.tags,
        description=req.description,
        org_id=req.org_id,
        mitre_technique_id=req.mitre_technique_id,
        mitre_tactic=req.mitre_tactic,
        cve_id=req.cve_id,
        first_seen=now,
        last_seen=now,
        expiry=req.expiry,
        active=True,
        feed_ingest_id=feed_ingest_id,
        extra=req.extra,
    )


def _row_to_ingest_log_response(row: dict[str, Any]) -> IngestLogListResponse:
    return IngestLogListResponse(
        ingest_id=row.get("ingest_id", ""),
        source=row.get("source", ""),
        status=row.get("status", ""),
        iocs_parsed=int(row.get("iocs_parsed", 0)),
        iocs_inserted=int(row.get("iocs_inserted", 0)),
        iocs_updated=int(row.get("iocs_updated", 0)),
        iocs_skipped=int(row.get("iocs_skipped", 0)),
        errors=list(row.get("errors") or []),
        started_at=row.get("started_at", ""),
        completed_at=row.get("completed_at"),
        org_id=row.get("org_id"),
        metadata=dict(row.get("metadata") or {}),
    )


# ---------------------------------------------------------------------------
# IOC CRUD routes
# ---------------------------------------------------------------------------


@router.post("", response_model=IOCResponse, status_code=201)
def create_ioc(req: IOCCreateRequest) -> IOCResponse:
    record = _create_request_to_record(req)
    store = get_ioc_store()
    ok = store.upsert_ioc(record)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to persist IOC record")
    persisted = store.get_ioc(record.ioc_id)
    if persisted is None:
        raise HTTPException(status_code=500, detail="IOC persisted but could not be retrieved")
    return _ioc_record_to_response(persisted)


@router.get("/{ioc_id}", response_model=IOCResponse)
def get_ioc(ioc_id: str) -> IOCResponse:
    store = get_ioc_store()
    record = store.get_ioc(ioc_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")
    return _ioc_record_to_response(record)


@router.patch("/{ioc_id}", response_model=IOCResponse)
def update_ioc(ioc_id: str, req: IOCUpdateRequest) -> IOCResponse:
    store = get_ioc_store()
    existing = store.get_ioc(ioc_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")

    updated = IOCRecord(
        ioc_id=existing.ioc_id,
        ioc_type=existing.ioc_type,
        value=existing.value,
        source=existing.source,
        severity=req.severity if req.severity is not None else existing.severity,
        confidence=req.confidence if req.confidence is not None else existing.confidence,
        tags=req.tags if req.tags is not None else existing.tags,
        description=req.description if req.description is not None else existing.description,
        org_id=existing.org_id,
        mitre_technique_id=req.mitre_technique_id if req.mitre_technique_id is not None else existing.mitre_technique_id,
        mitre_tactic=req.mitre_tactic if req.mitre_tactic is not None else existing.mitre_tactic,
        cve_id=req.cve_id if req.cve_id is not None else existing.cve_id,
        first_seen=existing.first_seen,
        last_seen=_utcnow_iso(),
        expiry=req.expiry if req.expiry is not None else existing.expiry,
        active=req.active if req.active is not None else existing.active,
        feed_ingest_id=existing.feed_ingest_id,
        extra=req.extra if req.extra is not None else existing.extra,
    )

    ok = store.upsert_ioc(updated)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update IOC record")

    refreshed = store.get_ioc(ioc_id)
    if refreshed is None:
        raise HTTPException(status_code=500, detail="IOC updated but could not be retrieved")
    return _ioc_record_to_response(refreshed)


@router.delete("/{ioc_id}", response_model=IOCDeleteResponse)
def delete_ioc(ioc_id: str) -> IOCDeleteResponse:
    store = get_ioc_store()
    existing = store.get_ioc(ioc_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")
    deleted = store.delete_ioc(ioc_id)
    return IOCDeleteResponse(ioc_id=ioc_id, deleted=deleted)


@router.post("/{ioc_id}/deactivate", response_model=IOCDeactivateResponse)
def deactivate_ioc(ioc_id: str) -> IOCDeactivateResponse:
    store = get_ioc_store()
    existing = store.get_ioc(ioc_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")
    ok = store.deactivate_ioc(ioc_id)
    return IOCDeactivateResponse(ioc_id=ioc_id, deactivated=ok)


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------


@router.post("/bulk", response_model=IOCBulkCreateResponse, status_code=201)
def bulk_create_iocs(req: IOCBulkCreateRequest) -> IOCBulkCreateResponse:
    batch_ingest_id = f"manual-bulk-{uuid.uuid4().hex}"
    records = [_create_request_to_record(r, feed_ingest_id=batch_ingest_id) for r in req.records]
    store = get_ioc_store()
    inserted, updated, skipped = store.bulk_upsert(records, overwrite=req.overwrite)
    return IOCBulkCreateResponse(inserted=inserted, updated=updated, skipped=skipped)


@router.delete("/ingest/{feed_ingest_id}", response_model=IOCDeleteByIngestResponse)
def delete_iocs_by_ingest(feed_ingest_id: str) -> IOCDeleteByIngestResponse:
    store = get_ioc_store()
    deleted = store.delete_by_ingest_id(feed_ingest_id)
    return IOCDeleteByIngestResponse(feed_ingest_id=feed_ingest_id, deleted=deleted)


# ---------------------------------------------------------------------------
# Filter / list
# ---------------------------------------------------------------------------


@router.get("/filter", response_model=list[IOCResponse], operation_id="filter_iocs")
def filter_iocs(
    source: str | None = Query(default=None),
    ioc_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    org_id: str | None = Query(default=None),
    active: bool | None = Query(default=None),
    tag: str | None = Query(default=None),
    mitre_technique_id: str | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    value_contains: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[IOCResponse]:
    store = get_ioc_store()
    req = IOCFilterRequest(
        source=source,
        ioc_type=ioc_type,
        severity=severity,
        org_id=org_id,
        active=active,
        tag=tag,
        mitre_technique_id=mitre_technique_id,
        cve_id=cve_id,
        value_contains=value_contains,
        limit=limit,
        offset=offset,
    )
    records = store.filter_iocs(req)
    return [_ioc_record_to_response(r) for r in records]


# ---------------------------------------------------------------------------
# Lookup routes
# ---------------------------------------------------------------------------


@router.get("/lookup/value", response_model=list[IOCResponse])
def lookup_by_value(
    value: str = Query(..., description="Exact IOC value to look up"),
    org_id: str | None = Query(default=None),
    active_only: bool = Query(default=True),
) -> list[IOCResponse]:
    store = get_ioc_store()
    records = store.lookup_by_value(value, org_id=org_id, active_only=active_only)
    return [_ioc_record_to_response(r) for r in records]


@router.post("/lookup/bulk", response_model=list[IOCResponse])
def lookup_by_values_bulk(req: IOCLookupBulkRequest) -> list[IOCResponse]:
    store = get_ioc_store()
    records = store.lookup_by_values(req.values, org_id=req.org_id, active_only=req.active_only)
    return [_ioc_record_to_response(r) for r in records]


@router.get("/lookup/cve/{cve_id}", response_model=list[IOCResponse])
def lookup_by_cve(
    cve_id: str,
    org_id: str | None = Query(default=None),
    active_only: bool = Query(default=True),
) -> list[IOCResponse]:
    store = get_ioc_store()
    records = store.lookup_by_cve(cve_id, org_id=org_id, active_only=active_only)
    return [_ioc_record_to_response(r) for r in records]


@router.get("/lookup/mitre/{technique_id}", response_model=list[IOCResponse])
def lookup_by_mitre_technique(
    technique_id: str,
    org_id: str | None = Query(default=None),
    active_only: bool = Query(default=True),
) -> list[IOCResponse]:
    store = get_ioc_store()
    records = store.lookup_by_mitre_technique(technique_id, org_id=org_id, active_only=active_only)
    return [_ioc_record_to_response(r) for r in records]


# ---------------------------------------------------------------------------
# Admin / maintenance routes
# ---------------------------------------------------------------------------


@router.post("/admin/prune", response_model=IOCPruneResponse)
def prune_expired_iocs() -> IOCPruneResponse:
    store = get_ioc_store()
    pruned = store.prune_expired()
    logger.info("ioc_management.prune_expired pruned=%d", pruned)
    return IOCPruneResponse(pruned=pruned)


@router.get("/admin/count", response_model=IOCCountResponse)
def count_iocs(
    source: str | None = Query(default=None),
    active: bool | None = Query(default=None),
    org_id: str | None = Query(default=None),
) -> IOCCountResponse:
    store = get_ioc_store()
    count = store.count_iocs(source=source, active=active, org_id=org_id)
    return IOCCountResponse(count=count, source=source, active=active, org_id=org_id)


@router.get("/admin/health", response_model=IOCHealthResponse)
def ioc_store_health() -> IOCHealthResponse:
    store = get_ioc_store()
    result = store.health_check()
    return IOCHealthResponse(
        status=result.get("status", "unknown"),
        ioc_count=result.get("ioc_count"),
        detail=result.get("detail"),
    )


# ---------------------------------------------------------------------------
# Ingest log routes
# ---------------------------------------------------------------------------


@router.get("/ingest/{ingest_id}", response_model=IngestLogListResponse)
def get_ingest_result(ingest_id: str) -> IngestLogListResponse:
    store = get_ioc_store()
    row = store.get_ingest_result(ingest_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Ingest log not found: {ingest_id}")
    return _row_to_ingest_log_response(row)


@router.get("/ingest", response_model=list[IngestLogListResponse])
def list_ingest_history(
    source: str | None = Query(default=None),
    org_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[IngestLogListResponse]:
    store = get_ioc_store()
    rows = store.list_ingest_history(source=source, org_id=org_id, limit=limit, offset=offset)
    return [_row_to_ingest_log_response(r) for r in rows]


@router.delete("/ingest/log/{ingest_id}", response_model=dict)
def delete_ingest_log(ingest_id: str) -> dict:
    store = get_ioc_store()
    ok = store.delete_ingest_log(ingest_id)
    if not ok:
        raise HTTPException(status_code=500, detail=f"Failed to delete ingest log: {ingest_id}")
    return {"ingest_id": ingest_id, "deleted": True}
