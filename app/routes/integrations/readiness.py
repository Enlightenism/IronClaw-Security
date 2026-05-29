# app/routes/integrations/readiness.py
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.services.deploymentreadiness import DeploymentReadinessService

router = APIRouter(prefix="/integrations", tags=["integration-readiness"])


_service = DeploymentReadinessService()


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _datetime_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    text = str(value).strip()
    return text or None


def _normalize_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return [str(value)]


def _coerce_mapping(record: Any) -> dict[str, Any]:
    if record is None:
        return {}
    if hasattr(record, "model_dump"):
        return record.model_dump()
    if isinstance(record, dict):
        return dict(record)

    data: dict[str, Any] = {}
    for name in dir(record):
        if name.startswith("_"):
            continue
        try:
            value = getattr(record, name)
        except Exception:
            continue
        if callable(value):
            continue
        data[name] = value
    return data


def _extract_value(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data.get(key) is not None:
            return data.get(key)
    return None


class ReadinessCheckView(BaseModel):
    check_id: str
    title: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReadinessSummaryView(BaseModel):
    overall_status: str
    updated_at: str
    environment: str
    release_id: str | None = None
    total_checks: int
    ready_checks: int
    warning_checks: int
    blocked_checks: int
    blockers: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationReadinessResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    readiness: ReadinessSummaryView
    checks: list[ReadinessCheckView] = Field(default_factory=list)


def _normalize_check_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "pass", "passed", "ready", "success", "healthy"}:
        return "ready"
    if normalized in {"warn", "warning", "degraded"}:
        return "warning"
    if normalized in {"fail", "failed", "blocked", "error"}:
        return "blocked"
    return normalized or "ready"


def _normalize_overall_status(value: Any, checks: list[ReadinessCheckView]) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "pass", "passed", "ready", "success", "healthy"}:
        return "ready"
    if normalized in {"warn", "warning", "degraded"}:
        return "warning"
    if normalized in {"fail", "failed", "blocked", "error"}:
        return "blocked"

    blocked_checks = sum(1 for item in checks if item.status == "blocked")
    warning_checks = sum(1 for item in checks if item.status == "warning")
    if blocked_checks:
        return "blocked"
    if warning_checks:
        return "warning"
    return "ready"


def _build_check_view(record: Any, fallback_index: int) -> ReadinessCheckView:
    data = _coerce_mapping(record)

    check_id = str(
        _extract_value(data, "check_id", "checkid", "id", "name", "key") or f"check-{fallback_index}",
    )
    title = str(
        _extract_value(data, "title", "label", "name", "summary") or check_id.replace("-", " ").replace("_", " ").title(),
    )
    detail = str(
        _extract_value(data, "detail", "details", "message", "summary", "description") or "",
    )
    status_value = _normalize_check_status(
        _extract_value(data, "status", "state", "result"),
    )

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("category", "severity", "component"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return ReadinessCheckView(
        check_id=check_id,
        title=title,
        status=status_value,
        detail=detail,
        metadata=metadata,
    )


def _build_readiness_response(
    integration_id: str,
    result: Any,
    environment: str,
) -> IntegrationReadinessResponse:
    data = _coerce_mapping(result)
    readiness = _coerce_mapping(_extract_value(data, "readiness") or result)

    raw_checks = _extract_value(readiness, "checks", "items") or []
    checks = [_build_check_view(item, index + 1) for index, item in enumerate(raw_checks)]

    ready_checks = sum(1 for item in checks if item.status == "ready")
    warning_checks = sum(1 for item in checks if item.status == "warning")
    blocked_checks = sum(1 for item in checks if item.status == "blocked")

    overall_status = _normalize_overall_status(
        _extract_value(readiness, "overall_status", "status", "state"),
        checks,
    )

    updated_at_value = _extract_value(readiness, "updated_at", "timestamp", "generated_at")
    release_id = _extract_value(readiness, "release_id", "integration_release_id")

    blockers = _normalize_list(_extract_value(readiness, "blockers", "errors"))
    recommendations = _normalize_list(_extract_value(readiness, "recommendations", "notes"))
    metadata = _normalize_dict(readiness.get("metadata"))

    for key in ("platform", "adapter_version", "provider"):
        if key in readiness and key not in metadata and readiness.get(key) is not None:
            metadata[key] = readiness.get(key)

    return IntegrationReadinessResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        readiness=ReadinessSummaryView(
            overall_status=overall_status,
            updated_at=_datetime_to_iso(updated_at_value) or _utc_now_iso(),
            environment=str(_extract_value(readiness, "environment") or environment),
            release_id=str(release_id) if release_id is not None else None,
            total_checks=len(checks),
            ready_checks=ready_checks,
            warning_checks=warning_checks,
            blocked_checks=blocked_checks,
            blockers=blockers,
            recommendations=recommendations,
            metadata=metadata,
        ),
        checks=checks,
    )


def _run_readiness(integration_id: str, environment: str) -> Any:
    candidate_calls = [
        lambda: _service.evaluate(),
        lambda: _service.run(),
    ]

    for call in candidate_calls:
        try:
            return call()
        except AttributeError:
            continue
        except TypeError:
            continue

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="deployment readiness service does not expose a supported readiness method",
    )


@router.get(
    "/{integration_id}/readiness",
    operation_id="integrations_get_readiness",
    response_model=IntegrationReadinessResponse,
    summary="Get integration deployment readiness",
)
def get_integration_readiness(
    integration_id: str = Path(..., min_length=1, max_length=255),
    environment: str = Query(default="production", min_length=1, max_length=100),
) -> IntegrationReadinessResponse:
    normalized_integration_id = integration_id.strip()
    normalized_environment = environment.strip()

    result = _run_readiness(
        integration_id=normalized_integration_id,
        environment=normalized_environment,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{normalized_integration_id}' not found",
        )

    return _build_readiness_response(
        integration_id=normalized_integration_id,
        result=result,
        environment=normalized_environment,
    )
