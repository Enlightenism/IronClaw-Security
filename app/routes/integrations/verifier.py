from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.integrationverifier import IntegrationVerifier

router = APIRouter(prefix="/integrations", tags=["integrations"])

_service = IntegrationVerifier()


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return [str(value)]


class VerificationCheckView(BaseModel):
    check_id: str
    title: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerificationSummaryView(BaseModel):
    state: str
    passed: int
    warned: int
    failed: int
    total: int
    blockers: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationVerificationResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    platform: str | None = None
    adapter_version: str | None = None
    verification: VerificationSummaryView
    checks: list[VerificationCheckView]


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


def _extract_check_id(data: dict[str, Any], fallback_index: int) -> str:
    for key in ("check_id", "checkid", "id", "name", "key"):
        value = data.get(key)
        if value:
            return str(value)
    return f"check-{fallback_index}"


def _extract_title(data: dict[str, Any], check_id: str) -> str:
    for key in ("title", "label", "name", "summary"):
        value = data.get(key)
        if value:
            return str(value)
    return check_id.replace("-", " ").replace("_", " ").title()


def _extract_status(data: dict[str, Any]) -> str:
    for key in ("status", "state", "result", "verdict"):
        value = data.get(key)
        if value:
            normalized = str(value).strip().lower()
            if normalized in {"pass", "passed", "ok", "ready", "success"}:
                return "pass"
            if normalized in {"warn", "warning"}:
                return "warn"
            if normalized in {"fail", "failed", "error", "blocked"}:
                return "fail"
            return normalized
    return "pass"


def _extract_detail(data: dict[str, Any]) -> str:
    for key in ("detail", "details", "message", "summary", "description"):
        value = data.get(key)
        if value:
            return str(value)
    return ""


def _build_check_view(record: Any, fallback_index: int) -> VerificationCheckView:
    data = _coerce_mapping(record)
    check_id = _extract_check_id(data, fallback_index)
    title = _extract_title(data, check_id)
    status_value = _extract_status(data)
    detail = _extract_detail(data)

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("severity", "category", "platform", "adapter_version"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return VerificationCheckView(
        check_id=check_id,
        title=title,
        status=status_value,
        detail=detail,
        metadata=metadata,
    )


def _build_response(integration_id: str, result: Any) -> IntegrationVerificationResponse:
    data = _coerce_mapping(result)

    raw_checks = data.get("checks") or data.get("items") or []
    checks = [
        _build_check_view(record, index + 1)
        for index, record in enumerate(raw_checks)
    ]

    passed = sum(1 for item in checks if item.status == "pass")
    warned = sum(1 for item in checks if item.status == "warn")
    failed = sum(1 for item in checks if item.status == "fail")
    total = len(checks)

    state = (
        data.get("state")
        or data.get("verification_state")
        or data.get("overall_status")
        or data.get("status")
        or ("failed" if failed else "warning" if warned else "passed")
    )
    state = str(state).strip().lower()

    blockers = _normalize_list(data.get("blockers"))
    recommendations = _normalize_list(data.get("recommendations"))
    platform = data.get("platform")
    adapter_version = data.get("adapter_version") or data.get("version")

    summary_metadata = _normalize_dict(data.get("metadata"))
    for key in ("provider", "adapter_name", "compatibility_matrix_version"):
        if key in data and key not in summary_metadata and data.get(key) is not None:
            summary_metadata[key] = data.get(key)

    return IntegrationVerificationResponse(
        status="ok",
        service="integration-verifier",
        timestamp=_utcnow(),
        integration_id=integration_id,
        platform=str(platform) if platform is not None else None,
        adapter_version=str(adapter_version) if adapter_version is not None else None,
        verification=VerificationSummaryView(
            state=state,
            passed=passed,
            warned=warned,
            failed=failed,
            total=total,
            blockers=blockers,
            recommendations=recommendations,
            metadata=summary_metadata,
        ),
        checks=checks,
    )


def _run_verification(integration_id: str, deep: bool) -> Any:
    candidate_calls = [
        lambda: _service.verify(integration_id=integration_id, deep=deep),
        lambda: _service.verify(integration_id, deep),
        lambda: _service.verify(integration_id=integration_id),
        lambda: _service.verify(integration_id),
        lambda: _service.run(integration_id=integration_id, deep=deep),
        lambda: _service.run(integration_id),
        lambda: _service.evaluate(integration_id=integration_id, deep=deep),
        lambda: _service.evaluate(integration_id),
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
        detail="integration verifier service does not expose a supported verify method",
    )


@router.get(
    "/{integration_id}/verify",
    response_model=IntegrationVerificationResponse,
    summary="Verify integration compatibility",
)
def verify_integration(
    integration_id: str,
    deep: bool = Query(default=False),
) -> IntegrationVerificationResponse:
    result = _run_verification(integration_id=integration_id, deep=deep)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{integration_id}' not found",
        )

    return _build_response(integration_id=integration_id, result=result)