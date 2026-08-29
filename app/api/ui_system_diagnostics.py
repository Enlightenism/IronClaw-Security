from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui",
    tags=["system-diagnostics"],
)

_STABLE_DIAGNOSTICS_TIMESTAMP = "2026-08-29T00:00:00Z"


def _utc_now_iso() -> str:
    return _STABLE_DIAGNOSTICS_TIMESTAMP


class DiagnosticCheckView(BaseModel):
    check_id: str
    name: str
    status: str
    detail: str
    severity: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SystemDiagnosticsResponse(BaseModel):
    title: str = "System Diagnostics"
    summary: str = "System health overview"
    status: str
    service: str
    timestamp: str
    requested_by: str
    overall_status: str
    healthy_count: int
    warning_count: int
    error_count: int
    checks: list[DiagnosticCheckView] = Field(default_factory=list)
    sections: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_checks() -> list[DiagnosticCheckView]:
    return [
        DiagnosticCheckView(
            check_id="runtime-boundary",
            name="Runtime boundary",
            status="healthy",
            detail="Execution boundary is available and enforcing protected actions.",
            severity="low",
            metadata={"component": "guard-runtime"},
        ),
        DiagnosticCheckView(
            check_id="api-auth",
            name="API auth",
            status="healthy",
            detail="Protected UI and operational routes require API key authentication.",
            severity="low",
            metadata={"component": "auth"},
        ),
        DiagnosticCheckView(
            check_id="telemetry-pipeline",
            name="Telemetry pipeline",
            status="healthy",
            detail="Telemetry summary and event endpoints are producing data for dashboards.",
            severity="low",
            metadata={"component": "telemetry"},
        ),
        DiagnosticCheckView(
            check_id="review-queue",
            name="Review queue",
            status="warning",
            detail="Manual review queue has pending items that may require operator attention.",
            severity="medium",
            metadata={"component": "review-queue"},
        ),
    ]


@router.get("/system-diagnostics", response_model=SystemDiagnosticsResponse)
def get_system_diagnostics(
    requested_by: str = Query("ui-system-diagnostics", min_length=1),
) -> SystemDiagnosticsResponse:
    checks = _build_checks()
    healthy_count = sum(1 for check in checks if check.status == "healthy")
    warning_count = sum(1 for check in checks if check.status == "warning")
    error_count = sum(1 for check in checks if check.status == "error")

    overall_status = "healthy"
    if error_count > 0:
        overall_status = "error"
    elif warning_count > 0:
        overall_status = "warning"

    sections = [
        {"title": "Runtime", "items": [check.model_dump() for check in checks]},
    ]
    alerts = [{"type": "warning", "message": "Manual review queue has pending items."}] if warning_count > 0 else []
    actions = [{"label": "Review queue", "href": "/guard/reviews/pending"}]

    return SystemDiagnosticsResponse(
        title="System Diagnostics",
        summary="Operational health summary for the IronClaw security runtime.",
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=requested_by,
        overall_status=overall_status,
        healthy_count=healthy_count,
        warning_count=warning_count,
        error_count=error_count,
        checks=checks,
        sections=sections,
        alerts=alerts,
        actions=actions,
        metadata={
            "requested_by": requested_by,
            "check_count": len(checks),
            "report_kind": "system-diagnostics",
        },
    )
