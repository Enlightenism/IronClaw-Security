from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Any
import uuid

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.auth import AuthContext, get_auth_context
from app.schemas.threat_detection import (
    CorrelationSignal,
    DetectionRequest,
    DetectionResult,
    DetectionSummary,
    DetectionVerdict,
    FeedRefreshRequest,
    FeedRefreshResult,
    HuntQuery,
    HuntResult,
    HuntStatusEnum,
    IngestStatusEnum,
    IOCImportRequest,
    IOCImportResult,
    IOCResponse,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)
from app.services.threat_detection_engine import get_detection_engine

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/threat", tags=["threat-detection"])


_TABLE_DETECTIONS = "threat_detections"


# ---------------------------------------------------------------------------
# TAXII config payload — used by POST /threat/feeds/refresh for STIX_TAXII
# ---------------------------------------------------------------------------


class TAXIIConfig(BaseModel):
    taxii_url: str
    collection_id: str
    username: str | None = None
    password: str | None = None
    api_root: str | None = None
    verify_ssl: bool = True
    extra: dict[str, Any] = {}


class FeedRefreshRequestWithTAXII(FeedRefreshRequest):
    taxii_config: TAXIIConfig | None = None


# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _get_supabase_client():
    try:
        from app.clients.supabase import get_supabase_client

        return get_supabase_client()
    except ImportError:
        pass
    try:
        from app.core.supabase import get_supabase_client

        return get_supabase_client()
    except ImportError:
        pass
    return None


def _persist_detection_result(result: DetectionResult) -> None:
    client = _get_supabase_client()
    if client is None:
        logger.warning("threat_detection.persist: supabase client unavailable — skipping persistence")
        return
    try:
        row: dict[str, Any] = {
            "event_id": result.event_id,
            "org_id": result.org_id,
            "agent_id": result.agent_id,
            "session_id": result.session_id,
            "verdict": result.verdict.value,
            "score": result.score,
            "severity": result.severity.value,
            "ioc_match_count": len(result.ioc_matches),
            "correlation_signal_count": len(result.correlation_signals),
            "risk_families": result.risk_families,
            "extracted_indicators": result.extracted_indicators,
            "mitre_techniques": result.mitre_techniques,
            "rationale": result.rationale,
            "context": result.context,
            "metadata": result.metadata,
            "scanned_text": result.scanned_text,
            "assessed_at": result.assessed_at,
            "detection_engine_version": result.detection_engine_version,
        }
        client.table(_TABLE_DETECTIONS).insert(row).execute()
    except Exception as exc:
        logger.error("threat_detection.persist.error event_id=%s: %s", result.event_id, exc)


def _build_correlation_signals_from_context(
    auth: AuthContext,
    request: DetectionRequest,
) -> list[CorrelationSignal]:
    signals: list[CorrelationSignal] = []
    if auth.session_id and request.session_id and auth.session_id == request.session_id:
        signals.append(
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="session_context_match",
                matched_event_ids=[request.event_id] if request.event_id else [],
                contributing_ioc_ids=[],
                mitre_technique_ids=[],
                confidence=0.30,
                score_contribution=0.05,
                description="Request session matches authenticated session context.",
            )
        )
    return signals


# ---------------------------------------------------------------------------
# POST /threat/detect
# ---------------------------------------------------------------------------


@router.post(
    "/detect",
    response_model=DetectionResult,
    status_code=status.HTTP_200_OK,
    summary="Run threat detection pipeline",
    description=("Submits a detection request through the full IronClaw threat detection pipeline. " "Extracts observables, resolves IOC matches, applies correlation signals, and returns " "a structured verdict with score, severity, MITRE techniques, and rationale."),
)
def detect_threat(
    request: DetectionRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> DetectionResult:
    effective_org_id = request.org_id or auth.org_id
    effective_session_id = request.session_id or auth.session_id

    scoped_request = DetectionRequest(
        event_id=request.event_id or str(uuid.uuid4()),
        org_id=effective_org_id,
        agent_id=request.agent_id,
        session_id=effective_session_id,
        text=request.text,
        url=request.url,
        domain=request.domain,
        hashes=request.hashes,
        ioc_values=request.ioc_values,
        context=request.context,
        metadata=request.metadata,
        minimum_confidence=request.minimum_confidence,
    )

    correlation_signals = _build_correlation_signals_from_context(auth, scoped_request)

    engine = get_detection_engine()
    result = engine.run(scoped_request, correlation_signals=correlation_signals)

    _persist_detection_result(result)

    logger.info(
        "threat_detection.detect event_id=%s verdict=%s score=%.3f severity=%s ioc_matches=%d",
        result.event_id,
        result.verdict.value,
        result.score,
        result.severity.value,
        len(result.ioc_matches),
    )

    return result


# ---------------------------------------------------------------------------
# POST /threat/detect/batch
# ---------------------------------------------------------------------------


@router.post(
    "/detect/batch",
    response_model=list[DetectionResult],
    status_code=status.HTTP_200_OK,
    summary="Run batch threat detection",
    description=("Submits multiple detection requests in a single call. Each request is processed " "independently through the full pipeline. Returns results in submission order."),
)
def detect_threat_batch(
    requests: list[DetectionRequest],
    auth: AuthContext = Depends(get_auth_context),
) -> list[DetectionResult]:
    if not requests:
        return []

    engine = get_detection_engine()
    results: list[DetectionResult] = []

    for req in requests:
        effective_org_id = req.org_id or auth.org_id
        effective_session_id = req.session_id or auth.session_id

        scoped_request = DetectionRequest(
            event_id=req.event_id or str(uuid.uuid4()),
            org_id=effective_org_id,
            agent_id=req.agent_id,
            session_id=effective_session_id,
            text=req.text,
            url=req.url,
            domain=req.domain,
            hashes=req.hashes,
            ioc_values=req.ioc_values,
            context=req.context,
            metadata=req.metadata,
            minimum_confidence=req.minimum_confidence,
        )

        correlation_signals = _build_correlation_signals_from_context(auth, scoped_request)
        result = engine.run(scoped_request, correlation_signals=correlation_signals)
        _persist_detection_result(result)
        results.append(result)

    logger.info(
        "threat_detection.detect_batch count=%d verdicts=%s",
        len(results),
        [r.verdict.value for r in results],
    )

    return results


# ---------------------------------------------------------------------------
# GET /threat/detections
# ---------------------------------------------------------------------------


@router.get(
    "/detections",
    response_model=list[DetectionSummary],
    status_code=status.HTTP_200_OK,
    summary="List stored detection events",
    description="Returns paginated detection summaries. Scoped by org_id if present on the auth context.",
)
def list_detections(
    org_id: str | None = Query(default=None, description="Filter by organization ID."),
    verdict: DetectionVerdict | None = Query(default=None, description="Filter by verdict."),
    severity: ThreatSeverityLevel | None = Query(default=None, description="Filter by severity."),
    agent_id: str | None = Query(default=None, description="Filter by agent ID."),
    session_id: str | None = Query(default=None, description="Filter by session ID."),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
) -> list[DetectionSummary]:
    effective_org_id = org_id or auth.org_id
    client = _get_supabase_client()

    if client is None:
        logger.warning("threat_detection.list_detections: supabase client unavailable")
        return []

    try:
        q = client.table(_TABLE_DETECTIONS).select("event_id,org_id,agent_id,verdict,score,severity,ioc_match_count,correlation_signal_count,assessed_at,session_id")
        if effective_org_id is not None:
            q = q.eq("org_id", effective_org_id)
        if verdict is not None:
            q = q.eq("verdict", verdict.value)
        if severity is not None:
            q = q.eq("severity", severity.value)
        if agent_id is not None:
            q = q.eq("agent_id", agent_id)
        if session_id is not None:
            q = q.eq("session_id", session_id)

        q = q.order("assessed_at", desc=True).range(offset, offset + limit - 1)
        resp = q.execute()
        rows = resp.data if resp and resp.data else []

        return [
            DetectionSummary(
                event_id=row["event_id"],
                org_id=row.get("org_id"),
                agent_id=row.get("agent_id"),
                verdict=DetectionVerdict(row["verdict"]),
                score=float(row["score"]),
                severity=ThreatSeverityLevel(row["severity"]),
                ioc_match_count=int(row.get("ioc_match_count", 0)),
                correlation_signal_count=int(row.get("correlation_signal_count", 0)),
                assessed_at=row["assessed_at"],
            )
            for row in rows
        ]
    except Exception as exc:
        logger.error("threat_detection.list_detections.error: %s", exc)
        return []


# ---------------------------------------------------------------------------
# GET /threat/detections/{event_id}
# ---------------------------------------------------------------------------


@router.get(
    "/detections/{event_id}",
    status_code=status.HTTP_200_OK,
    summary="Get a stored detection event by ID",
)
def get_detection(
    event_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, Any]:
    client = _get_supabase_client()
    if client is None:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "storage_unavailable", "message": "Supabase client unavailable."},
        )

    try:
        resp = client.table(_TABLE_DETECTIONS).select("*").eq("event_id", event_id).maybe_single().execute()
        if not resp or not resp.data:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "not_found", "message": f"Detection event {event_id!r} not found."},
            )

        row = resp.data
        if auth.org_id and row.get("org_id") and row["org_id"] != auth.org_id:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "forbidden", "message": "Access denied."},
            )

        return row
    except Exception as exc:
        logger.error("threat_detection.get_detection.error event_id=%s: %s", event_id, exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "message": "Failed to retrieve detection event."},
        )


# ---------------------------------------------------------------------------
# POST /threat/hunt
# ---------------------------------------------------------------------------


@router.post(
    "/hunt",
    response_model=HuntResult,
    status_code=status.HTTP_200_OK,
    summary="Run a retrospective threat hunt",
    description=("Sweeps stored detection history for matching IOC values, MITRE techniques, CVEs, " "or risk families within an optional time window."),
)
def run_threat_hunt(
    query: HuntQuery,
    auth: AuthContext = Depends(get_auth_context),
) -> HuntResult:
    from app.services.threat_hunt_service import get_threat_hunt_service

    hunt_id = query.hunt_id or str(uuid.uuid4())
    effective_org_id = query.org_id or auth.org_id
    started_at = _utcnow_iso()

    try:
        service = get_threat_hunt_service()
        result = service.run_hunt(
            HuntQuery(
                hunt_id=hunt_id,
                org_id=effective_org_id,
                ioc_value=query.ioc_value,
                ioc_type=query.ioc_type,
                mitre_technique_id=query.mitre_technique_id,
                cve_id=query.cve_id,
                risk_family=query.risk_family,
                start_time=query.start_time,
                end_time=query.end_time,
                minimum_score=query.minimum_score,
                limit=query.limit,
                offset=query.offset,
            )
        )
        return result
    except ImportError:
        logger.warning("threat_detection.hunt: threat_hunt_service unavailable — returning empty result")
        return HuntResult(
            hunt_id=hunt_id,
            org_id=effective_org_id,
            status=HuntStatusEnum.FAILED,
            total_matches=0,
            matches=[],
            query_summary={"reason": "threat_hunt_service not available"},
            executed_at=started_at,
            errors=["threat_hunt_service module not found"],
        )
    except Exception as exc:
        logger.error("threat_detection.hunt.error hunt_id=%s: %s", hunt_id, exc)
        return HuntResult(
            hunt_id=hunt_id,
            org_id=effective_org_id,
            status=HuntStatusEnum.FAILED,
            total_matches=0,
            matches=[],
            query_summary={},
            executed_at=started_at,
            errors=[str(exc)],
        )


# ---------------------------------------------------------------------------
# POST /threat/iocs
# ---------------------------------------------------------------------------


@router.post(
    "/iocs",
    response_model=IOCImportResult,
    status_code=status.HTTP_200_OK,
    summary="Bulk import IOCs into the threat store",
)
def import_iocs(
    payload: IOCImportRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> IOCImportResult:
    from app.services.ioc_store import get_ioc_store
    from app.services.threat_feed_ingestion import IOCRecord, _detect_ioc_type, _normalize_value
    from app.services.threat_feed_ingestion import _utcnow_iso as _now

    ingest_id = str(uuid.uuid4())
    effective_org_id = payload.org_id or auth.org_id
    now = _now()
    errors: list[str] = []

    records: list[IOCRecord] = []
    for entry in payload.entries:
        try:
            ioc_type = entry.ioc_type or _detect_ioc_type(entry.value)
            normalized_value = _normalize_value(entry.value, ioc_type)
            ioc_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{normalized_value}:{ioc_type}:{effective_org_id or ''}"))
            records.append(
                IOCRecord(
                    ioc_id=ioc_id,
                    ioc_type=ioc_type,
                    value=normalized_value,
                    source="custom_ioc",
                    severity=entry.severity,
                    confidence=entry.confidence,
                    tags=list(entry.tags),
                    description=entry.description,
                    org_id=effective_org_id,
                    mitre_technique_id=entry.mitre_technique_id,
                    mitre_tactic=entry.mitre_tactic,
                    cve_id=entry.cve_id,
                    first_seen=now,
                    last_seen=now,
                    expiry=entry.expiry,
                    active=True,
                    feed_ingest_id=ingest_id,
                    extra=dict(entry.extra),
                )
            )
        except Exception as exc:
            errors.append(f"entry {entry.value!r}: {exc}")

    store = get_ioc_store()
    inserted = updated = skipped = 0

    if records:
        try:
            inserted, updated, skipped = store.bulk_upsert(records, overwrite=payload.overwrite_existing)
        except Exception as exc:
            errors.append(f"bulk_upsert failed: {exc}")

    status_val = IngestStatusEnum.SUCCESS
    if errors and (inserted + updated) == 0:
        status_val = IngestStatusEnum.FAILED
    elif errors:
        status_val = IngestStatusEnum.PARTIAL

    logger.info(
        "threat_detection.import_iocs ingest_id=%s inserted=%d updated=%d skipped=%d errors=%d",
        ingest_id,
        inserted,
        updated,
        skipped,
        len(errors),
    )

    return IOCImportResult(
        ingest_id=ingest_id,
        org_id=effective_org_id,
        iocs_submitted=len(payload.entries),
        iocs_inserted=inserted,
        iocs_updated=updated,
        iocs_skipped=skipped,
        errors=errors,
        status=status_val,
        completed_at=_utcnow_iso(),
    )


# ---------------------------------------------------------------------------
# GET /threat/iocs
# ---------------------------------------------------------------------------


@router.get(
    "/iocs",
    response_model=list[IOCResponse],
    status_code=status.HTTP_200_OK,
    summary="List IOCs from the threat store",
)
def list_iocs(
    source: ThreatFeedSourceEnum | None = Query(default=None),
    ioc_type: str | None = Query(default=None),
    severity: ThreatSeverityLevel | None = Query(default=None),
    org_id: str | None = Query(default=None),
    active: bool | None = Query(default=None),
    tag: str | None = Query(default=None),
    mitre_technique_id: str | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    value_contains: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
) -> list[IOCResponse]:
    from app.services.ioc_store import get_ioc_store
    from app.services.threat_feed_ingestion import IOCFilterRequest

    effective_org_id = org_id or auth.org_id
    store = get_ioc_store()

    try:
        records = store.filter_iocs(
            IOCFilterRequest(
                source=source,
                ioc_type=ioc_type,
                severity=severity,
                org_id=effective_org_id,
                active=active,
                tag=tag,
                mitre_technique_id=mitre_technique_id,
                cve_id=cve_id,
                value_contains=value_contains,
                limit=limit,
                offset=offset,
            )
        )
    except Exception as exc:
        logger.error("threat_detection.list_iocs.error: %s", exc)
        return []

    return [
        IOCResponse(
            ioc_id=r.ioc_id,
            ioc_type=str(r.ioc_type),
            value=r.value,
            source=str(r.source),
            severity=str(r.severity),
            confidence=float(r.confidence),
            tags=list(r.tags),
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
            extra=dict(r.extra),
        )
        for r in records
    ]


# ---------------------------------------------------------------------------
# DELETE /threat/iocs/{ioc_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/iocs/{ioc_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a single IOC from the threat store",
)
def delete_ioc(
    ioc_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, Any]:
    from app.services.ioc_store import get_ioc_store

    store = get_ioc_store()
    deleted = store.delete_ioc(ioc_id)

    if not deleted:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "not_found", "message": f"IOC {ioc_id!r} not found or already deleted."},
        )

    logger.info("threat_detection.delete_ioc ioc_id=%s principal=%s", ioc_id, auth.principal_id)
    return {"deleted": True, "ioc_id": ioc_id}


# ---------------------------------------------------------------------------
# POST /threat/feeds/refresh
# ---------------------------------------------------------------------------


@router.post(
    "/feeds/refresh",
    response_model=FeedRefreshResult,
    status_code=status.HTTP_200_OK,
    summary="Trigger a threat feed refresh",
    description="Manually trigger ingestion for one or more threat intelligence feed sources.",
)
def refresh_feeds(
    payload: FeedRefreshRequestWithTAXII,
    auth: AuthContext = Depends(get_auth_context),
) -> FeedRefreshResult:
    from app.services.threat_feed_ingestion import ThreatFeedSourceEnum as _SourceEnum
    from app.services.threat_feed_ingestion import run_feed_ingestion

    request_id = str(uuid.uuid4())
    effective_org_id = payload.org_id or auth.org_id
    started_at = _utcnow_iso()
    per_source_results: list[dict[str, Any]] = []
    total_inserted = total_updated = total_errors = 0

    taxii_cfg_dict: dict[str, Any] | None = payload.taxii_config.model_dump() if payload.taxii_config is not None else None

    for source in payload.sources:
        try:
            is_taxii = hasattr(_SourceEnum, "STIX_TAXII") and source == _SourceEnum.STIX_TAXII
            if is_taxii:
                result = run_feed_ingestion(
                    source=source,
                    org_id=effective_org_id,
                    force=payload.force,
                    custom_url=payload.custom_url,
                    taxii_config=taxii_cfg_dict,
                )
            else:
                result = run_feed_ingestion(
                    source=source,
                    org_id=effective_org_id,
                    force=payload.force,
                    custom_url=payload.custom_url,
                )
            per_source_results.append(result if isinstance(result, dict) else result.dict() if hasattr(result, "dict") else vars(result))
            total_inserted += getattr(result, "iocs_inserted", 0)
            total_updated += getattr(result, "iocs_updated", 0)
            total_errors += len(getattr(result, "errors", []))
        except Exception as exc:
            logger.error("threat_detection.refresh_feeds.error source=%s: %s", source, exc)
            per_source_results.append({"source": source, "status": "failed", "error": str(exc)})
            total_errors += 1

    logger.info(
        "threat_detection.refresh_feeds request_id=%s sources=%s inserted=%d updated=%d errors=%d",
        request_id,
        [s.value for s in payload.sources],
        total_inserted,
        total_updated,
        total_errors,
    )

    return FeedRefreshResult(
        request_id=request_id,
        org_id=effective_org_id,
        results=per_source_results,
        total_iocs_inserted=total_inserted,
        total_iocs_updated=total_updated,
        total_errors=total_errors,
        started_at=started_at,
        completed_at=_utcnow_iso(),
    )


# ---------------------------------------------------------------------------
# GET /threat/health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Threat detection subsystem health check",
    tags=["threat-detection", "system"],
)
def threat_health(
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, Any]:
    from app.services.ioc_store import get_ioc_store

    store = get_ioc_store()
    store_health = store.health_check()

    engine = get_detection_engine()
    engine_ok = engine is not None

    return {
        "status": "ok" if engine_ok and store_health.get("status") == "ok" else "degraded",
        "engine": "ok" if engine_ok else "unavailable",
        "ioc_store": store_health,
        "checked_at": _utcnow_iso(),
    }


__all__ = ["router"]
