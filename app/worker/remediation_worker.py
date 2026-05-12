from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/worker/remediation",
    tags=["remediation-worker"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


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


# In-memory job store (you can swap this for Redis/DB later)
_JOBS: dict[str, RemediationJob] = {}
_JOB_COUNTER: int = 0


# --------- Pydantic views ----------------------------------------------------


class RemediationJobCreate(BaseModel):
    """
    Job creation payload. This is typically invoked by your queue/bridge
    when a remediation action moves to 'queued' state on the UI side.
    """

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
    """
    External status update for a job, for example from an out-of-process
    worker executor or orchestrator.[web:1300][web:1303]
    """

    status: JobStatus = Field(
        ...,
        description="New status for this job (running, succeeded, failed, cancelled).",
    )
    last_error: str | None = Field(
        default=None,
        description="Optional error message when marking job as failed.",
    )


# --------- internal helpers --------------------------------------------------


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
    """
    Placeholder execution logic.

    In a real system, this would dispatch to a secure executor engine
    (e.g., workflow engine, Ansible, Terraform, internal tools) and
    update status based on the external result.[web:1299][web:1303]
    """
    from random import random

    job.attempts += 1
    job.started_at = job.started_at or _utc_now()

    # Simple random success/failure for now
    if random() > 0.15:
        job.status = "succeeded"
        job.completed_at = _utc_now()
        job.last_error = None
    else:
        job.status = "failed"
        job.completed_at = _utc_now()
        job.last_error = "Simulated execution failure"
    job.updated_at = _utc_now()


# --------- HTTP endpoints ----------------------------------------------------


@router.post("/jobs", response_model=RemediationJobView, status_code=201)
def create_remediation_job(payload: RemediationJobCreate) -> RemediationJobView:
    """
    Create a remediation execution job.

    Called by your queue/bridge component when a remediation action
    transitions to 'queued' on the UI side.[web:1300][web:1303]
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
    """
    List remediation jobs for monitoring and debugging.

    Supports filtering by status and action_id, and basic pagination.[web:1301][web:1303]
    """
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


@router.get("/jobs/{job_id}", response_model=RemediationJobView)
def get_remediation_job(job_id: str) -> RemediationJobView:
    """
    Retrieve a single remediation job by id.
    """
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return RemediationJobView(**job.to_dict())


@router.post("/jobs/{job_id}/execute", response_model=RemediationJobView)
def execute_remediation_job(job_id: str) -> RemediationJobView:
    """
    Trigger execution of a remediation job.

    In a real deployment, this would likely be restricted to internal
    workers only (e.g., via network policy, auth scopes, or mTLS).[web:1172][web:1291]
    """
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in ("pending", "failed"):
        raise HTTPException(status_code=400, detail=f"Cannot execute job in status {job.status}")

    if job.attempts >= job.max_attempts:
        raise HTTPException(status_code=400, detail="Max attempts exceeded for this job")

    job.status = "running"
    job.started_at = job.started_at or _utc_now()
    job.updated_at = _utc_now()

    # Simulate execution inline for now
    _simulate_execution(job)

    return RemediationJobView(**job.to_dict())


@router.patch("/jobs/{job_id}/status", response_model=RemediationJobView)
def update_remediation_job_status(
    job_id: str,
    payload: RemediationJobStatusUpdate,
) -> RemediationJobView:
    """
    Update job status from an external worker/orchestrator.

    This keeps the worker-side API generic if you later move execution
    out-of-process (e.g., to a queue consumer or Kubernetes Job).[web:1300][web:1303]
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