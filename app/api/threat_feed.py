from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from app.schemas.threat_detection import (
    ThreatFeedSourceEnum,
)
from app.services.threat_feed_ingestion import (
    FeedIngestResult,
    get_threat_feed_service,
    run_feed_ingestion,
)
from app.services.threat_feed_scheduler import (
    SchedulerRunRecord,
    SchedulerStatus,
    get_threat_feed_scheduler,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat/feeds", tags=["threat-feeds"])

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class FeedRefreshRequest(BaseModel):
    source: ThreatFeedSourceEnum = Field(..., description="Feed source to ingest")
    org_id: str | None = Field(default=None, description="Scoping org ID; None for global")
    force: bool = Field(default=False, description="Reserved for future cache-bypass; accepted and logged")
    custom_url: str | None = Field(default=None, description="Override URL for this feed endpoint")


class FeedRefreshResponse(BaseModel):
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


class FeedScheduleEntryResponse(BaseModel):
    source: str
    interval_seconds: int
    enabled: bool
    org_id: str | None
    last_run_at: str | None
    last_ingest_id: str | None
    last_status: str | None
    consecutive_failures: int
    next_run_in_seconds: float


class SchedulerStatusResponse(BaseModel):
    running: bool
    schedule_entries: list[FeedScheduleEntryResponse]
    recent_runs: list[dict[str, Any]]
    total_runs: int
    total_failures: int
    prune_enabled: bool
    prune_interval_seconds: int
    started_at: str | None


class SchedulerStartResponse(BaseModel):
    started: bool
    message: str


class SchedulerStopResponse(BaseModel):
    stopped: bool
    message: str


class FeedForceRunRequest(BaseModel):
    source: ThreatFeedSourceEnum = Field(..., description="Feed source to force-run immediately")
    org_id: str | None = Field(default=None)


class FeedForceRunResponse(BaseModel):
    run_id: str
    source: str
    triggered_by: str
    started_at: str
    completed_at: str | None
    status: str
    ingest_id: str | None
    iocs_inserted: int
    iocs_updated: int
    iocs_skipped: int
    errors: list[str]
    org_id: str | None
    metadata: dict[str, Any]


class FeedIntervalUpdateRequest(BaseModel):
    source: ThreatFeedSourceEnum = Field(..., description="Feed source to update interval for")
    interval_seconds: int = Field(..., ge=60, description="New interval in seconds (minimum 60)")


class FeedIntervalUpdateResponse(BaseModel):
    source: str
    interval_seconds: int
    updated: bool


class FeedToggleRequest(BaseModel):
    source: ThreatFeedSourceEnum = Field(..., description="Feed source to enable or disable")
    enabled: bool = Field(..., description="True to enable, False to disable")


class FeedToggleResponse(BaseModel):
    source: str
    enabled: bool
    updated: bool


class FeedRunHistoryItem(BaseModel):
    run_id: str
    source: str
    triggered_by: str
    started_at: str
    completed_at: str | None
    status: str
    ingest_id: str | None
    iocs_inserted: int
    iocs_updated: int
    iocs_skipped: int
    errors: list[str]
    org_id: str | None
    metadata: dict[str, Any]


class FeedSummaryResponse(BaseModel):
    total_iocs: int
    active_iocs: int
    iocs_by_source: dict[str, int]
    scheduler_running: bool
    scheduler_started_at: str | None
    recent_ingest_ids: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ingest_result_to_response(r: FeedIngestResult) -> FeedRefreshResponse:
    return FeedRefreshResponse(
        ingest_id=r.ingest_id,
        source=str(r.source.value if hasattr(r.source, "value") else r.source),
        status=str(r.status.value if hasattr(r.status, "value") else r.status),
        iocs_parsed=r.iocs_parsed,
        iocs_inserted=r.iocs_inserted,
        iocs_updated=r.iocs_updated,
        iocs_skipped=r.iocs_skipped,
        errors=list(r.errors),
        started_at=r.started_at,
        completed_at=r.completed_at,
        org_id=r.org_id,
        metadata=dict(r.metadata),
    )


def _scheduler_run_record_to_response(r: SchedulerRunRecord) -> FeedRunHistoryItem:
    return FeedRunHistoryItem(
        run_id=r.run_id,
        source=r.source,
        triggered_by=r.triggered_by,
        started_at=r.started_at,
        completed_at=r.completed_at,
        status=str(r.status.value if hasattr(r.status, "value") else r.status),
        ingest_id=r.ingest_id,
        iocs_inserted=r.iocs_inserted,
        iocs_updated=r.iocs_updated,
        iocs_skipped=r.iocs_skipped,
        errors=list(r.errors),
        org_id=r.org_id,
        metadata=dict(r.metadata),
    )


def _scheduler_status_to_response(s: SchedulerStatus) -> SchedulerStatusResponse:
    entries = [
        FeedScheduleEntryResponse(
            source=e["source"],
            interval_seconds=e["interval_seconds"],
            enabled=e["enabled"],
            org_id=e["org_id"],
            last_run_at=e["last_run_at"],
            last_ingest_id=e["last_ingest_id"],
            last_status=e["last_status"],
            consecutive_failures=e["consecutive_failures"],
            next_run_in_seconds=e["next_run_in_seconds"],
        )
        for e in s.schedule_entries
    ]
    return SchedulerStatusResponse(
        running=s.running,
        schedule_entries=entries,
        recent_runs=s.recent_runs,
        total_runs=s.total_runs,
        total_failures=s.total_failures,
        prune_enabled=s.prune_enabled,
        prune_interval_seconds=s.prune_interval_seconds,
        started_at=s.started_at,
    )


# ---------------------------------------------------------------------------
# Feed ingestion routes
# ---------------------------------------------------------------------------


@router.post(
    "/refresh",
    response_model=FeedRefreshResponse,
    status_code=200,
    operation_id="feeds_refresh_feed",
    summary="Trigger immediate feed ingestion for a given source",
)
def refresh_feed(req: FeedRefreshRequest) -> FeedRefreshResponse:
    """
    Dispatch a synchronous feed ingestion run for the given source.
    Delegates exclusively to run_feed_ingestion — no ingestion logic lives here.
    For STIX_TAXII, returns a FAILED result explaining that taxii_config is
    required and must be supplied via the force-run or scheduler path.
    """
    logger.info(
        "feeds.refresh source=%s org_id=%s force=%s custom_url=%s",
        req.source,
        req.org_id,
        req.force,
        req.custom_url,
    )
    try:
        result = run_feed_ingestion(
            source=req.source,
            org_id=req.org_id,
            force=req.force,
            custom_url=req.custom_url,
            taxii_config=None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("feeds.refresh.error source=%s: %s", req.source, exc)
        raise HTTPException(status_code=500, detail=f"Feed ingestion error: {exc}") from exc
    return _ingest_result_to_response(result)


@router.post(
    "/refresh/background",
    response_model=dict,
    status_code=202,
    operation_id="feeds_refresh_feed_background",
    summary="Trigger feed ingestion in the background (non-blocking)",
)
def refresh_feed_background(
    req: FeedRefreshRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, str]:
    """
    Enqueue a feed ingestion run as a FastAPI background task.
    Returns immediately with 202 Accepted. The ingest_id is not available
    at response time — use GET /threat/feeds/history to retrieve the result.
    """

    def _run() -> None:
        try:
            run_feed_ingestion(
                source=req.source,
                org_id=req.org_id,
                force=req.force,
                custom_url=req.custom_url,
                taxii_config=None,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("feeds.refresh.background.error source=%s: %s", req.source, exc)

    background_tasks.add_task(_run)
    logger.info(
        "feeds.refresh.background.enqueued source=%s org_id=%s",
        req.source,
        req.org_id,
    )
    return {
        "accepted": "true",
        "message": f"Feed ingestion enqueued for source={req.source.value}. Poll GET /threat/feeds/history for results.",
    }


# ---------------------------------------------------------------------------
# Ingest history routes  (feed-level; no collision with /threat/iocs/ingest/*)
# ---------------------------------------------------------------------------


@router.get(
    "/history",
    response_model=list[FeedRefreshResponse],
    operation_id="feeds_list_ingest_history",
    summary="List recent feed ingest results",
)
def list_feed_ingest_history(
    source: str | None = Query(default=None, description="Filter by ThreatFeedSourceEnum value"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[FeedRefreshResponse]:
    svc = get_threat_feed_service()
    results = svc.list_ingest_history(source=source, limit=limit)
    return [_ingest_result_to_response(r) for r in results]


@router.get(
    "/history/{ingest_id}",
    response_model=FeedRefreshResponse,
    operation_id="feeds_get_ingest_result",
    summary="Get a specific feed ingest result by ingest_id",
)
def get_feed_ingest_result(ingest_id: str) -> FeedRefreshResponse:
    svc = get_threat_feed_service()
    result = svc.get_ingest_result(ingest_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Ingest result not found: {ingest_id}")
    return _ingest_result_to_response(result)


# ---------------------------------------------------------------------------
# Scheduler lifecycle routes
# ---------------------------------------------------------------------------


@router.post(
    "/scheduler/start",
    response_model=SchedulerStartResponse,
    operation_id="feeds_scheduler_start",
    summary="Start the background feed refresh scheduler",
)
def scheduler_start() -> SchedulerStartResponse:
    scheduler = get_threat_feed_scheduler()
    if scheduler.is_running:
        logger.info("feeds.scheduler.start: already running")
        return SchedulerStartResponse(started=False, message="Scheduler is already running")
    scheduler.start()
    logger.info("feeds.scheduler.start: started")
    return SchedulerStartResponse(started=True, message="Scheduler started")


@router.post(
    "/scheduler/stop",
    response_model=SchedulerStopResponse,
    operation_id="feeds_scheduler_stop",
    summary="Stop the background feed refresh scheduler",
)
def scheduler_stop() -> SchedulerStopResponse:
    scheduler = get_threat_feed_scheduler()
    if not scheduler.is_running:
        return SchedulerStopResponse(stopped=False, message="Scheduler is not running")
    scheduler.stop()
    logger.info("feeds.scheduler.stop: stopped")
    return SchedulerStopResponse(stopped=True, message="Scheduler stopped")


@router.get(
    "/scheduler/status",
    response_model=SchedulerStatusResponse,
    operation_id="feeds_scheduler_status",
    summary="Get current scheduler status, schedule entries, and recent run history",
)
def scheduler_status() -> SchedulerStatusResponse:
    status = get_threat_feed_scheduler().get_status()
    return _scheduler_status_to_response(status)


# ---------------------------------------------------------------------------
# Scheduler control routes
# ---------------------------------------------------------------------------


@router.post(
    "/scheduler/force",
    response_model=FeedForceRunResponse,
    operation_id="feeds_scheduler_force_run",
    summary="Trigger an immediate out-of-band ingest for a source (does not reset schedule)",
)
def scheduler_force_run(req: FeedForceRunRequest) -> FeedForceRunResponse:
    logger.info("feeds.scheduler.force source=%s org_id=%s", req.source, req.org_id)
    try:
        record = get_threat_feed_scheduler().force_run(req.source, org_id=req.org_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("feeds.scheduler.force.error source=%s: %s", req.source, exc)
        raise HTTPException(status_code=500, detail=f"Force run error: {exc}") from exc
    return FeedForceRunResponse(
        run_id=record.run_id,
        source=record.source,
        triggered_by=record.triggered_by,
        started_at=record.started_at,
        completed_at=record.completed_at,
        status=str(record.status.value if hasattr(record.status, "value") else record.status),
        ingest_id=record.ingest_id,
        iocs_inserted=record.iocs_inserted,
        iocs_updated=record.iocs_updated,
        iocs_skipped=record.iocs_skipped,
        errors=list(record.errors),
        org_id=record.org_id,
        metadata=dict(record.metadata),
    )


@router.patch(
    "/scheduler/interval",
    response_model=FeedIntervalUpdateResponse,
    operation_id="feeds_scheduler_set_interval",
    summary="Update the refresh interval for a scheduled feed source",
)
def scheduler_set_interval(req: FeedIntervalUpdateRequest) -> FeedIntervalUpdateResponse:
    updated = get_threat_feed_scheduler().set_interval(req.source, req.interval_seconds)
    if not updated:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to update interval: source={req.source.value} not registered or interval < 60s",
        )
    logger.info("feeds.scheduler.set_interval source=%s interval=%ds", req.source, req.interval_seconds)
    return FeedIntervalUpdateResponse(
        source=req.source.value,
        interval_seconds=req.interval_seconds,
        updated=updated,
    )


@router.patch(
    "/scheduler/toggle",
    response_model=FeedToggleResponse,
    operation_id="feeds_scheduler_toggle",
    summary="Enable or disable a scheduled feed source",
)
def scheduler_toggle(req: FeedToggleRequest) -> FeedToggleResponse:
    updated = get_threat_feed_scheduler().set_enabled(req.source, req.enabled)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"Feed source not registered in scheduler: {req.source.value}",
        )
    logger.info("feeds.scheduler.toggle source=%s enabled=%s", req.source, req.enabled)
    return FeedToggleResponse(source=req.source.value, enabled=req.enabled, updated=updated)


# ---------------------------------------------------------------------------
# Scheduler run history route
# ---------------------------------------------------------------------------


@router.get(
    "/scheduler/runs",
    response_model=list[FeedRunHistoryItem],
    operation_id="feeds_scheduler_run_history",
    summary="Get scheduler run history (background-triggered ingest runs)",
)
def scheduler_run_history(
    source: str | None = Query(default=None, description="Filter by feed source value"),
    limit: int = Query(default=50, ge=1, le=100),
) -> list[FeedRunHistoryItem]:
    records = get_threat_feed_scheduler().get_run_history(source=source, limit=limit)
    return [_scheduler_run_record_to_response(r) for r in records]


# ---------------------------------------------------------------------------
# Feed summary route
# ---------------------------------------------------------------------------


@router.get(
    "/summary",
    response_model=FeedSummaryResponse,
    operation_id="feeds_get_summary",
    summary="High-level feed health and IOC count summary",
)
def get_feed_summary() -> FeedSummaryResponse:
    from app.services.ioc_store import get_ioc_store  # noqa: PLC0415

    store = get_ioc_store()
    svc = get_threat_feed_service()
    scheduler = get_threat_feed_scheduler()

    total_iocs = store.count_iocs()
    active_iocs = store.count_iocs(active=True)

    iocs_by_source: dict[str, int] = {}
    for src in ThreatFeedSourceEnum:
        count = store.count_iocs(source=src.value, active=True)
        if count > 0:
            iocs_by_source[src.value] = count

    recent_history = svc.list_ingest_history(limit=10)
    recent_ingest_ids = [r.ingest_id for r in recent_history]

    sched_status = scheduler.get_status()

    return FeedSummaryResponse(
        total_iocs=total_iocs,
        active_iocs=active_iocs,
        iocs_by_source=iocs_by_source,
        scheduler_running=sched_status.running,
        scheduler_started_at=sched_status.started_at,
        recent_ingest_ids=recent_ingest_ids,
    )
