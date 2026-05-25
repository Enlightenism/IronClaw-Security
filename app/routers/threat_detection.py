from __future__ import annotations

from datetime import UTC, datetime
import logging
import time
from typing import Any
import uuid

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse

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
    IngestStatusEnum,
    TAXIIIngestRequest,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)
from app.services.stix_adapter import TAXIIConfig, get_stix_adapter
from app.services.threat_detection_engine import get_detection_engine

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/threat", tags=["threat-detection"])


_TABLE_DETECTIONS = "threat_detections"


# ---------------------------------------------------------------------------
# Supabase client accessor — single canonical path
# ---------------------------------------------------------------------------


def _get_supabase_client():
    try:
        from app.clients.supabase import get_supabase_client as _get

        return _get()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# UTC helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _utcnow_ms() -> int:
    return int(time.monotonic() * 1000)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


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
            "mitre_techniques": result.mitre_techniques,
            "context": result.context,
            "assessed_at": result.assessed_at,
            "detection_engine_version": result.detection_engine_version,
            "metadata": result.metadata,
        }
        client.table(_TABLE_DETECTIONS).upsert(row, on_conflict="event_id").execute()
    except Exception as exc:
        logger.error("threat_detection.persist error event_id=%s: %s", result.event_id, exc)


# ---------------------------------------------------------------------------
# Internal: construct TAXIIConfig from TAXIIIngestRequest
# ---------------------------------------------------------------------------


def _taxii_config_from_ingest_request(req: TAXIIIngestRequest) -> TAXIIConfig:
    return TAXIIConfig(
        discovery_url=req.discovery_url,
        collection_id=req.collection_id,
        username=req.username,
        password=req.password,
        api_root=req.api_root,
        verify_ssl=req.verify_ssl,
        timeout=req.timeout,
        page_size=req.page_size,
        extra_headers=dict(req.extra_headers),
    )


# ---------------------------------------------------------------------------
# Internal: dispatch non-TAXII sources to ThreatFeedIngestionService
# ---------------------------------------------------------------------------


def _run_standard_feed(
    source: ThreatFeedSourceEnum,
    *,
    org_id: str | None,
    force: bool,
    custom_url: str | None,
) -> dict[str, Any]:
    try:
        from app.services.threat_feed_ingestion import run_feed_ingestion

        result = run_feed_ingestion(
            source=source,
            org_id=org_id,
            force=force,
            custom_url=custom_url,
        )
        if isinstance(result, dict):
            return result
        if hasattr(result, "to_dict"):
            return result.to_dict()
        if hasattr(result, "model_dump"):
            return result.model_dump()
        return vars(result)
    except Exception as exc:
        logger.error("threat_detection._run_standard_feed source=%s error=%s", source, exc)
        return {
            "source": str(source),
            "status": IngestStatusEnum.FAILED,
            "error": str(exc),
            "iocs_inserted": 0,
            "iocs_updated": 0,
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Internal: dispatch to scheduler force_feed_run (audit-persisted forced run)
# ---------------------------------------------------------------------------


def _run_scheduler_forced_feed(
    source: ThreatFeedSourceEnum,
    *,
    org_id: str | None,
) -> dict[str, Any]:
    try:
        from app.services.threat_feed_scheduler import force_feed_run

        record = force_feed_run(source, org_id=org_id)
        return record.to_dict()
    except Exception as exc:
        logger.error("threat_detection._run_scheduler_forced_feed source=%s error=%s", source, exc)
        return {
            "source": str(source),
            "status": IngestStatusEnum.FAILED,
            "error": str(exc),
            "iocs_inserted": 0,
            "iocs_updated": 0,
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# POST /threat/detect
# ---------------------------------------------------------------------------


@router.post(
    "/detect",
    response_model=DetectionResult,
    status_code=status.HTTP_200_OK,
    summary="Run threat detection on an event payload",
)
async def detect_threat(
    payload: DetectionRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> DetectionResult:
    engine = get_detection_engine()
    effective_org_id = payload.org_id or auth.org_id
    effective_request = payload.model_copy(update={"org_id": effective_org_id}) if effective_org_id != payload.org_id else payload
    result = engine.run(effective_request)
    _persist_detection_result(result)
    return result


# ---------------------------------------------------------------------------
# POST /threat/feeds/refresh
# ---------------------------------------------------------------------------


@router.post(
    "/feeds/refresh",
    response_model=FeedRefreshResult,
    status_code=status.HTTP_200_OK,
    summary="Trigger a threat feed refresh",
    description=(
        "Manually trigger ingestion for one or more threat intelligence feed sources. "
        "When STIX_TAXII is included in sources and taxii_ingest is supplied, "
        "constructs a TAXIIConfig and dispatches directly to STIXAdapter.ingest_from_taxii(). "
        "All other sources are dispatched to the standard feed ingestion service. "
        "When use_scheduler=true and the source is registered in the scheduler, "
        "delegates to force_feed_run() for a fully audit-persisted, scheduler-tracked forced run."
    ),
)
async def refresh_feeds(
    payload: FeedRefreshRequest,
    use_scheduler: bool = Query(
        default=False,
        description=("When true, delegate to the scheduler's force_feed_run() for sources registered " "in the scheduler (MITRE_ATTACK, CISA_KEV). Produces a full SchedulerRunRecord " "persisted to feed_ingest_log. Has no effect on STIX_TAXII sources."),
    ),
    auth: AuthContext = Depends(get_auth_context),
) -> FeedRefreshResult:
    request_id = str(uuid.uuid4())
    effective_org_id = payload.org_id or auth.org_id
    started_at = _utcnow_iso()
    per_source_results: list[dict[str, Any]] = []
    total_inserted = total_updated = total_errors = 0

    _SCHEDULER_SOURCES = {
        ThreatFeedSourceEnum.MITRE_ATTACK,
        ThreatFeedSourceEnum.CISA_KEV,
    }

    for source in payload.sources:
        if source == ThreatFeedSourceEnum.STIX_TAXII:
            if payload.taxii_ingest is not None:
                try:
                    taxii_config = _taxii_config_from_ingest_request(payload.taxii_ingest)
                    adapter = get_stix_adapter()
                    result = adapter.ingest_from_taxii(
                        taxii_config,
                        org_id=effective_org_id,
                        added_after=payload.taxii_ingest.added_after,
                    )
                    result_dict = result.to_dict()
                    per_source_results.append(result_dict)
                    total_inserted += result.iocs_inserted
                    total_updated += result.iocs_updated
                    total_errors += len(result.errors)
                except Exception as exc:
                    logger.error(
                        "threat_detection.refresh_feeds.taxii_error source=%s: %s",
                        source,
                        exc,
                    )
                    per_source_results.append(
                        {
                            "source": ThreatFeedSourceEnum.STIX_TAXII,
                            "status": IngestStatusEnum.FAILED,
                            "error": str(exc),
                            "iocs_inserted": 0,
                            "iocs_updated": 0,
                            "errors": [str(exc)],
                        }
                    )
                    total_errors += 1
            else:
                result_dict = _run_standard_feed(
                    source,
                    org_id=effective_org_id,
                    force=payload.force,
                    custom_url=payload.custom_url,
                )
                per_source_results.append(result_dict)
                total_inserted += int(result_dict.get("iocs_inserted", 0))
                total_updated += int(result_dict.get("iocs_updated", 0))
                total_errors += len(result_dict.get("errors", []))
        elif use_scheduler and source in _SCHEDULER_SOURCES:
            result_dict = _run_scheduler_forced_feed(source, org_id=effective_org_id)
            per_source_results.append(result_dict)
            total_inserted += int(result_dict.get("iocs_inserted", 0))
            total_updated += int(result_dict.get("iocs_updated", 0))
            total_errors += len(result_dict.get("errors", []))
        else:
            result_dict = _run_standard_feed(
                source,
                org_id=effective_org_id,
                force=payload.force,
                custom_url=payload.custom_url,
            )
            per_source_results.append(result_dict)
            total_inserted += int(result_dict.get("iocs_inserted", 0))
            total_updated += int(result_dict.get("iocs_updated", 0))
            total_errors += len(result_dict.get("errors", []))

    logger.info(
        "threat_detection.refresh_feeds request_id=%s sources=%s use_scheduler=%s " "inserted=%d updated=%d errors=%d",
        request_id,
        [s.value for s in payload.sources],
        use_scheduler,
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
# GET /threat/feeds/scheduler/status
# ---------------------------------------------------------------------------


@router.get(
    "/feeds/scheduler/status",
    status_code=status.HTTP_200_OK,
    summary="Get threat feed scheduler status",
    description=("Returns the current status of the background threat feed scheduler, " "including per-source schedule entries, recent run history, " "total run/failure counts, and prune configuration."),
)
async def get_scheduler_status(
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    try:
        from app.services.threat_feed_scheduler import get_threat_feed_scheduler

        scheduler_status = get_threat_feed_scheduler().get_status()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=scheduler_status.to_dict(),
        )
    except Exception as exc:
        logger.error("threat_detection.get_scheduler_status error: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "scheduler_unavailable", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# POST /threat/feeds/taxii/ingest
# ---------------------------------------------------------------------------


@router.post(
    "/feeds/taxii/ingest",
    status_code=status.HTTP_200_OK,
    summary="Ingest a STIX/TAXII 2.1 feed directly",
    description=("Accepts full TAXII 2.1 connection parameters and dispatches directly to " "STIXAdapter.ingest_from_taxii(). Returns a FeedIngestResult with per-page " "IOC insert/update/skip/error counts and ingest metadata."),
)
async def taxii_ingest(
    payload: TAXIIIngestRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    effective_org_id = payload.org_id or auth.org_id

    try:
        taxii_config = _taxii_config_from_ingest_request(payload)
        adapter = get_stix_adapter()
        result = adapter.ingest_from_taxii(
            taxii_config,
            org_id=effective_org_id,
            added_after=payload.added_after,
        )
    except Exception as exc:
        logger.error(
            "threat_detection.taxii_ingest.error discovery_url=%s org_id=%s: %s",
            payload.discovery_url,
            effective_org_id,
            exc,
        )
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": "taxii_ingest_failed",
                "message": str(exc),
                "discovery_url": payload.discovery_url,
            },
        )

    logger.info(
        "threat_detection.taxii_ingest done ingest_id=%s inserted=%d updated=%d skipped=%d errors=%d",
        result.ingest_id,
        result.iocs_inserted,
        result.iocs_updated,
        result.iocs_skipped,
        len(result.errors),
    )

    response_status = status.HTTP_200_OK if result.status in (IngestStatusEnum.SUCCESS, IngestStatusEnum.PARTIAL) else status.HTTP_422_UNPROCESSABLE_ENTITY

    return JSONResponse(
        status_code=response_status,
        content=result.to_dict(),
    )


# ---------------------------------------------------------------------------
# POST /threat/hunt
# ---------------------------------------------------------------------------


@router.post(
    "/hunt",
    response_model=HuntResult,
    status_code=status.HTTP_200_OK,
    summary="Submit a retrospective threat hunt query",
)
async def threat_hunt(
    payload: HuntQuery,
    auth: AuthContext = Depends(get_auth_context),
) -> HuntResult:
    from app.services.threat_hunt_service import get_hunt_service

    effective_org_id = payload.org_id or auth.org_id
    service = get_hunt_service()
    result = service.run_hunt(payload, org_id=effective_org_id)
    try:
        from app.services.threat_alerts import emit_hunt_alert

        emit_hunt_alert(result)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# GET /threat/detections
# ---------------------------------------------------------------------------


@router.get(
    "/detections",
    response_model=list[DetectionSummary],
    status_code=status.HTTP_200_OK,
    summary="List stored detection summaries",
)
async def list_detections(
    org_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    verdict: DetectionVerdict | None = Query(default=None),
    severity: ThreatSeverityLevel | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
) -> list[DetectionSummary]:
    client = _get_supabase_client()
    if client is None:
        return []

    effective_org_id = org_id or auth.org_id

    try:
        query = client.table(_TABLE_DETECTIONS).select("event_id,org_id,agent_id,session_id,verdict,score,severity," "ioc_match_count,correlation_signal_count,assessed_at")
        if effective_org_id:
            query = query.eq("org_id", effective_org_id)
        if agent_id:
            query = query.eq("agent_id", agent_id)
        if session_id:
            query = query.eq("session_id", session_id)
        if verdict:
            query = query.eq("verdict", verdict.value)
        if severity:
            query = query.eq("severity", severity.value)
        query = query.order("assessed_at", desc=True).range(offset, offset + limit - 1)
        resp = query.execute()
        rows = resp.data or []
        return [DetectionSummary(**row) for row in rows]
    except Exception as exc:
        logger.error("threat_detection.list_detections error: %s", exc)
        return []


# ---------------------------------------------------------------------------
# GET /threat/detections/{event_id}
# ---------------------------------------------------------------------------


@router.get(
    "/detections/{event_id}",
    response_model=DetectionResult,
    status_code=status.HTTP_200_OK,
    summary="Get a stored detection result by event ID",
)
async def get_detection(
    event_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "storage_unavailable"},
        )
    try:
        resp = client.table(_TABLE_DETECTIONS).select("*").eq("event_id", event_id).limit(1).execute()
        rows = resp.data or []
        if not rows:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "not_found", "event_id": event_id},
            )
        return JSONResponse(status_code=status.HTTP_200_OK, content=rows[0])
    except Exception as exc:
        logger.error("threat_detection.get_detection error event_id=%s: %s", event_id, exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# GET /threat/correlations
# ---------------------------------------------------------------------------


@router.get(
    "/correlations",
    response_model=list[CorrelationSignal],
    status_code=status.HTTP_200_OK,
    summary="List recent correlation signals",
)
async def list_correlations(
    org_id: str | None = Query(default=None),
    pattern_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    auth: AuthContext = Depends(get_auth_context),
) -> list[CorrelationSignal]:
    effective_org_id = org_id or auth.org_id
    try:
        from app.services.threat_correlation import get_correlation_engine

        corr_engine = get_correlation_engine()
        list_signals = getattr(corr_engine, "list_signals", None)
        if callable(list_signals):
            return list_signals(
                org_id=effective_org_id,
                pattern_type=pattern_type,
                limit=limit,
            )
        return []
    except Exception as exc:
        logger.error("threat_detection.list_correlations error: %s", exc)
        return []
