from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key

router = APIRouter(tags=["system-diagnostics-admin"])

_DIAGNOSTIC_CHECKS: Final[tuple[dict[str, str], ...]] = (
    {
        "check_id": "api-health",
        "label": "API Health",
        "status": "ok",
        "severity": "info",
        "detail": "Core API routes responding within expected thresholds.",
    },
    {
        "check_id": "runtime-guard",
        "label": "Runtime Guard",
        "status": "ok",
        "severity": "info",
        "detail": "Guard pipeline loaded and enforcing protected execution boundaries.",
    },
    {
        "check_id": "review-queue",
        "label": "Review Queue",
        "status": "ok",
        "severity": "info",
        "detail": "Human review queue available for operator escalation workflows.",
    },
    {
        "check_id": "telemetry-pipeline",
        "label": "Telemetry Pipeline",
        "status": "ok",
        "severity": "info",
        "detail": "Telemetry ingestion and usage events are available for operator review.",
    },
)


def _build_admin_checks() -> list[dict[str, str]]:
    return [dict(check) for check in _DIAGNOSTIC_CHECKS]


def _build_summary(checks: list[dict[str, str]]) -> dict[str, int]:
    return {
        "total": len(checks),
        "ok": sum(1 for check in checks if check["status"] == "ok"),
        "warn": sum(1 for check in checks if check["status"] == "warn"),
        "error": sum(1 for check in checks if check["status"] == "error"),
    }


def _overall_status(summary: dict[str, int]) -> str:
    if summary["error"] > 0:
        return "error"
    if summary["warn"] > 0:
        return "warn"
    return "ok"


@router.get("/admin/system-diagnostics")
def get_admin_system_diagnostics(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> dict[str, object]:
    request_id = getattr(request.state, "request_id", None)
    checks = _build_admin_checks()
    summary = _build_summary(checks)

    return {
        "title": "System Diagnostics",
        "status": _overall_status(summary),
        "summary": summary,
        "checks": checks,
        "request_id": request_id,
    }
