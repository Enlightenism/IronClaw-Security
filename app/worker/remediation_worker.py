from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_log = logging.getLogger(__name__)


router = APIRouter(
    prefix="/worker/remediation",
    tags=["remediation-worker"],
)


# ---------------------------------------------------------------------------
# Scheduler state
# ---------------------------------------------------------------------------


_scheduler_task: asyncio.Task[None] | None = None
_SCHEDULER_INTERVAL_SECONDS: int = 30  # recurring retry sweep interval


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------


JobStatus = Literal["pending", "running", "succeeded", "failed", "cancelled"]


RemediationKind = Literal[
    "configuration_change",
    "access_control",
    "network_control",
    "detection_rule",
    "data_protection",
    "process_runbook",
    "other",
]


# ---------------------------------------------------------------------------
# Domain model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RemediationJob:
    """Worker-side representation of a remediation action execution job."""

    id: str
    action_id: str
    kind: RemediationKind
    title: str
    description: str
    target: str
    requested_by: str
    status: JobStatus
    created_at: str
    updated_at: str
    started_at: str | None = None
    completed_at: str | None = None
    attempts: int = 0
    max_attempts: int = 3
    last_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action_id": self.action_id,
            "kind": self.kind,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "requested_by": self.requested_by,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "last_error": self.last_error,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# In-memory store (swap for Redis/DB later)
# ---------------------------------------------------------------------------


_JOBS: dict[str, RemediationJob] = {}
_JOB_COUNTER: int = 0


# ---------------------------------------------------------------------------
# Pydantic views
# ---------------------------------------------------------------------------


class RemediationJobCreate(BaseModel):
    """Job creation payload invoked by queue/bridge when a remediation action
    moves to 'queued' state on the UI side."""

    action_id: str = Field(..., description="ID of the remediation action.")
    kind: RemediationKind = Field(..., description="Type of remediation action.")
    title: str = Field(..., description="Short title for this job.")
    description: str = Field(..., description="What this job will attempt to do.")
    target: str = Field(..., description="System/asset this job targets.")
    requested_by: str = Field(..., description="Who requested execution (user, system).")
    max_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of attempts before permanent failure.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional extra context (e.g., incident id, environment).",
    )


class RemediationJobView(BaseModel):
    id: str
    action_id: str
    kind: RemediationKind
    title: str
    description: str
    target: str
    requested_by: str
    status: JobStatus
    created_at: str
    updated_at: str
    started_at: str | None = None
    completed_at: str | None = None
    attempts: int
    max_attempts: int
    last_error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RemediationJobListResponse(BaseModel):
    items: list[RemediationJobView]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    generated_at: str


class RemediationJobStatusUpdate(BaseModel):
    """External status update for a job from an out-of-process worker
    executor or orchestrator."""

    status: JobStatus = Field(
        ...,
        description="New status for this job (running, succeeded, failed, cancelled).",
    )
    last_error: str | None = Field(
        default=None,
        description="Optional error message when marking job as failed.",
    )


class SchedulerStatusResponse(BaseModel):
    running: bool
    interval_seconds: int
    generated_at: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _next_job_id() -> str:
    global _JOB_COUNTER
    _JOB_COUNTER += 1
    return f"job-{_JOB_COUNTER}"


def _paginate_jobs(
    jobs: list[RemediationJob],
    page: int,
    page_size: int,
) -> tuple[list[RemediationJob], int, int]:
    total_items = len(jobs)
    if total_items == 0:
        return [], 0, 0
    total_pages = (total_items + page_size - 1) // page_size
    page = max(1, min(page, total_pages))
    start = (page - 1) * page_size
    end = start + page_size
    return jobs[start:end], total_items, total_pages


def _simulate_execution(job: RemediationJob) -> None:
    """Placeholder execution logic.

    In production, dispatches to a secure executor engine (workflow engine,
    Ansible, Terraform, internal tools) and updates status from the result.
    """
    from random import random  # noqa: PLC0415

    job.attempts += 1
    job.started_at = job.started_at or _utc_now()

    if random() > 0.15:
        job.status = "succeeded"
        job.completed_at = _utc_now()
        job.last_error = None
    else:
        job.status = "failed"
        job.completed_at = _utc_now()
        job.last_error = "Simulated execution failure"
    job.updated_at = _utc_now()


# ---------------------------------------------------------------------------
# Scheduler — recurring delivery retry sweep
# ---------------------------------------------------------------------------


def list_retryable_deliveries() -> list[RemediationJob]:
    """Return all jobs eligible for retry: status=failed and attempts < max_attempts."""
    return [j for j in _JOBS.values() if j.status == "failed" and j.attempts < j.max_attempts]


def retry_failed_delivery(job: RemediationJob) -> None:
    """Re-execute a single retryable job in-place."""
    if job.status != "failed":
        return
    if job.attempts >= job.max_attempts:
        _log.warning(
            "remediation_worker.retry: job %s has hit max_attempts=%d, skipping",
            job.id,
            job.max_attempts,
        )
        return
    _log.info(
        "remediation_worker.retry: retrying job %s (attempt %d/%d)",
        job.id,
        job.attempts + 1,
        job.max_attempts,
    )
    job.status = "running"
    job.updated_at = _utc_now()
    _simulate_execution(job)
    _log.info(
        "remediation_worker.retry: job %s completed with status=%s",
        job.id,
        job.status,
    )


async def _retry_sweep() -> None:
    """Single scheduled sweep: list retryable deliveries and retry each one."""
    retryable = list_retryable_deliveries()
    if not retryable:
        _log.debug("remediation_worker.sweep: no retryable jobs found")
        return
    _log.info("remediation_worker.sweep: found %d retryable job(s)", len(retryable))
    for job in retryable:
        try:
            retry_failed_delivery(job)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "remediation_worker.sweep: unhandled error retrying job %s: %s",
                job.id,
                exc,
            )


async def _scheduler_loop() -> None:
    """Recurring async loop that calls _retry_sweep every SCHEDULER_INTERVAL_SECONDS."""
    _log.info(
        "remediation_worker.scheduler: started (interval=%ds)",
        _SCHEDULER_INTERVAL_SECONDS,
    )
    while True:
        try:
            await _retry_sweep()
        except Exception as exc:  # noqa: BLE001
            _log.error("remediation_worker.scheduler: sweep error: %s", exc)
        await asyncio.sleep(_SCHEDULER_INTERVAL_SECONDS)


def start_remediation_scheduler() -> None:
    """Start the background scheduler task. Safe to call multiple times (idempotent)."""
    global _scheduler_task
    if _scheduler_task is not None and not _scheduler_task.done():
        _log.debug("remediation_worker.scheduler: already running, skipping start")
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _log.warning("remediation_worker.scheduler: no running event loop, cannot start")
        return
    _scheduler_task = loop.create_task(_scheduler_loop(), name="remediation_retry_scheduler")
    _log.info("remediation_worker.scheduler: task created")


def stop_remediation_scheduler() -> None:
    """Cancel the background scheduler task. Safe to call when not running."""
    global _scheduler_task
    if _scheduler_task is None or _scheduler_task.done():
        _log.debug("remediation_worker.scheduler: not running, nothing to stop")
        return
    _scheduler_task.cancel()
    _scheduler_task = None
    _log.info("remediation_worker.scheduler: task cancelled")


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------


@router.post("/jobs", response_model=RemediationJobView, status_code=201)
def create_remediation_job(payload: RemediationJobCreate) -> RemediationJobView:
    """Create a remediation execution job.

    Called by queue/bridge when a remediation action transitions to 'queued'.
    """
    job_id = _next_job_id()
    now = _utc_now()
    job = RemediationJob(
        id=job_id,
        action_id=payload.action_id,
        kind=payload.kind,
        title=payload.title,
        description=payload.description,
        target=payload.target,
        requested_by=payload.requested_by,
        status="pending",
        created_at=now,
        updated_at=now,
        max_attempts=payload.max_attempts,
        metadata=dict(payload.metadata),
    )
    _JOBS[job_id] = job
    return RemediationJobView(**job.to_dict())


@router.get("/jobs", response_model=RemediationJobListResponse)
def list_remediation_jobs(
    page: int = Query(1, ge=1, description="Page number for remediation jobs."),
    page_size: int = Query(
        20,
        ge=1,
        le=100,
        description="Number of jobs per page (max 100).",
    ),
    status: JobStatus | None = Query(
        default=None,
        description="Optional filter by job status.",
    ),
    action_id: str | None = Query(
        default=None,
        description="Optional filter by remediation action id.",
    ),
) -> RemediationJobListResponse:
    """List remediation jobs. Supports filtering by status and action_id."""
    jobs = list(_JOBS.values())
    jobs.sort(key=lambda j: j.created_at, reverse=True)

    if status is not None:
        jobs = [j for j in jobs if j.status == status]
    if action_id is not None:
        jobs = [j for j in jobs if j.action_id == action_id]

    page_items, total_items, total_pages = _paginate_jobs(jobs, page, page_size)

    return RemediationJobListResponse(
        items=[RemediationJobView(**j.to_dict()) for j in page_items],
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        generated_at=_utc_now(),
    )


@router.get("/jobs/retryable", response_model=list[RemediationJobView])
def list_retryable_jobs() -> list[RemediationJobView]:
    """List all jobs currently eligible for retry (status=failed, attempts < max_attempts)."""
    return [RemediationJobView(**j.to_dict()) for j in list_retryable_deliveries()]


@router.get("/jobs/{job_id}", response_model=RemediationJobView)
def get_remediation_job(job_id: str) -> RemediationJobView:
    """Retrieve a single remediation job by id."""
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return RemediationJobView(**job.to_dict())


@router.post("/jobs/{job_id}/execute", response_model=RemediationJobView)
def execute_remediation_job(job_id: str) -> RemediationJobView:
    """Trigger execution of a remediation job.

    In production, restrict to internal workers via network policy, auth
    scopes, or mTLS.
    """
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in ("pending", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot execute job in status {job.status}",
        )

    if job.attempts >= job.max_attempts:
        raise HTTPException(
            status_code=400,
            detail="Max attempts exceeded for this job",
        )

    job.status = "running"
    job.started_at = job.started_at or _utc_now()
    job.updated_at = _utc_now()

    _simulate_execution(job)
    return RemediationJobView(**job.to_dict())


@router.post("/jobs/{job_id}/retry", response_model=RemediationJobView)
def retry_remediation_job(job_id: str) -> RemediationJobView:
    """Manually trigger a retry for a failed job (same guard as scheduler sweep)."""
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "failed":
        raise HTTPException(
            status_code=400,
            detail=f"Job is not in failed status (current: {job.status})",
        )
    if job.attempts >= job.max_attempts:
        raise HTTPException(
            status_code=400,
            detail="Max attempts exceeded; job cannot be retried",
        )
    retry_failed_delivery(job)
    return RemediationJobView(**job.to_dict())


@router.patch("/jobs/{job_id}/status", response_model=RemediationJobView)
def update_remediation_job_status(
    job_id: str,
    payload: RemediationJobStatusUpdate,
) -> RemediationJobView:
    """Update job status from an external worker/orchestrator.

    Keeps the worker-side API generic for out-of-process execution
    (queue consumer, Kubernetes Job, etc.).
    """
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    now = _utc_now()
    job.status = payload.status
    job.updated_at = now

    if payload.status == "running":
        job.started_at = job.started_at or now
    elif payload.status in ("succeeded", "failed", "cancelled"):
        job.completed_at = now

    job.last_error = payload.last_error
    return RemediationJobView(**job.to_dict())


@router.get("/scheduler/status", response_model=SchedulerStatusResponse)
def get_scheduler_status() -> SchedulerStatusResponse:
    """Return whether the background retry scheduler is currently running."""
    running = _scheduler_task is not None and not _scheduler_task.done()
    return SchedulerStatusResponse(
        running=running,
        interval_seconds=_SCHEDULER_INTERVAL_SECONDS,
        generated_at=_utc_now(),
    )


@router.post("/scheduler/start", response_model=SchedulerStatusResponse)
def start_scheduler_endpoint() -> SchedulerStatusResponse:
    """Start the background retry scheduler (idempotent)."""
    start_remediation_scheduler()
    running = _scheduler_task is not None and not _scheduler_task.done()
    return SchedulerStatusResponse(
        running=running,
        interval_seconds=_SCHEDULER_INTERVAL_SECONDS,
        generated_at=_utc_now(),
    )


@router.post("/scheduler/stop", response_model=SchedulerStatusResponse)
def stop_scheduler_endpoint() -> SchedulerStatusResponse:
    """Stop the background retry scheduler."""
    stop_remediation_scheduler()
    return SchedulerStatusResponse(
        running=False,
        interval_seconds=_SCHEDULER_INTERVAL_SECONDS,
        generated_at=_utc_now(),
    )


__all__ = [
    "RemediationJob",
    "RemediationJobCreate",
    "RemediationJobListResponse",
    "RemediationJobStatusUpdate",
    "RemediationJobView",
    "SchedulerStatusResponse",
    "list_retryable_deliveries",
    "retry_failed_delivery",
    "router",
    "start_remediation_scheduler",
    "stop_remediation_scheduler",
]
