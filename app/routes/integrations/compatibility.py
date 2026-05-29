from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.services.integrationverifier import IntegrationVerifier

router = APIRouter(prefix="/integrations", tags=["integration-compatibility"])

_service = IntegrationVerifier()


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


def _normalize_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


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


class CompatibilityIssueView(BaseModel):
    issue_id: str
    severity: str
    category: str
    message: str
    remediation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CompatibilityCheckView(BaseModel):
    check_id: str
    name: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class CompatibilityTargetView(BaseModel):
    platform: str
    provider: str | None = None
    version: str | None = None
    runtime: str | None = None
    environment: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CompatibilitySummaryView(BaseModel):
    compatible: bool
    score: float
    status: str
    checked_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationCompatibilityResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    target: CompatibilityTargetView
    summary: CompatibilitySummaryView
    checks: list[CompatibilityCheckView] = Field(default_factory=list)
    issues: list[CompatibilityIssueView] = Field(default_factory=list)


def _normalize_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "pass", "passed", "success", "compatible"}:
        return "passed"
    if normalized in {"warn", "warning", "partial"}:
        return "warning"
    if normalized in {"fail", "failed", "error", "incompatible"}:
        return "failed"
    return normalized or "unknown"


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"low", "info"}:
        return "low"
    if normalized in {"medium", "warn", "warning"}:
        return "medium"
    if normalized in {"high", "critical", "error"}:
        return "high"
    return normalized or "medium"


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _build_issue_view(record: Any, fallback_index: int) -> CompatibilityIssueView:
    data = _coerce_mapping(record)

    issue_id = str(
        _extract_value(data, "issue_id", "id", "code") or f"issue-{fallback_index}",
    )
    severity = _normalize_severity(_extract_value(data, "severity", "level"))
    category = str(_extract_value(data, "category", "type") or "compatibility")
    message = str(_extract_value(data, "message", "detail", "description") or "")
    remediation = _extract_value(data, "remediation", "fix", "recommendation")

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("field", "expected", "actual", "platform"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return CompatibilityIssueView(
        issue_id=issue_id,
        severity=severity,
        category=category,
        message=message,
        remediation=str(remediation) if remediation is not None else None,
        metadata=metadata,
    )


def _build_check_view(record: Any, fallback_index: int) -> CompatibilityCheckView:
    data = _coerce_mapping(record)

    check_id = str(
        _extract_value(data, "check_id", "id", "name") or f"check-{fallback_index}",
    )
    name = str(
        _extract_value(data, "name", "title", "check") or check_id.replace("-", " ").title(),
    )
    status_value = _normalize_status(
        _extract_value(data, "status", "result", "outcome"),
    )
    detail = str(_extract_value(data, "detail", "message", "description") or "")

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("required", "actual", "expected", "version"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return CompatibilityCheckView(
        check_id=check_id,
        name=name,
        status=status_value,
        detail=detail,
        metadata=metadata,
    )


def _build_target_view(
    payload: dict[str, Any],
    environment: str | None,
) -> CompatibilityTargetView:
    metadata = _normalize_dict(payload.get("metadata"))
    for key in ("adapter", "adapter_version", "region"):
        if key in payload and key not in metadata and payload.get(key) is not None:
            metadata[key] = payload.get(key)

    provider_value = _extract_value(payload, "provider", "vendor")
    version_value = _extract_value(
        payload,
        "version",
        "platform_version",
        "target_version",
    )
    runtime_value = _extract_value(payload, "runtime", "runtime_version")
    environment_value = _extract_value(payload, "environment") or environment

    return CompatibilityTargetView(
        platform=str(_extract_value(payload, "platform", "target_platform") or "unknown"),
        provider=str(provider_value) if provider_value is not None else None,
        version=str(version_value) if version_value is not None else None,
        runtime=str(runtime_value) if runtime_value is not None else None,
        environment=str(environment_value) if environment_value is not None else None,
        metadata=metadata,
    )


def _build_compatibility_response(
    integration_id: str,
    result: Any,
    environment: str | None,
) -> IntegrationCompatibilityResponse:
    data = _coerce_mapping(result)
    payload = _coerce_mapping(_extract_value(data, "compatibility", "verification") or result)

    raw_checks = _extract_value(payload, "checks", "results", "verifications") or []
    checks = [_build_check_view(item, index + 1) for index, item in enumerate(_normalize_list(raw_checks))]

    raw_issues = _extract_value(payload, "issues", "findings", "errors") or []
    issues = [_build_issue_view(item, index + 1) for index, item in enumerate(_normalize_list(raw_issues))]

    compatible = bool(_extract_value(payload, "compatible", "is_compatible"))
    if not compatible and checks:
        compatible = all(check.status != "failed" for check in checks)

    score = _coerce_float(
        _extract_value(payload, "score", "compatibility_score"),
        default=100.0 if compatible else 0.0,
    )

    summary_status = _normalize_status(_extract_value(payload, "status", "result"))
    if summary_status == "unknown":
        summary_status = "passed" if compatible else "failed"

    metadata = _normalize_dict(payload.get("summary_metadata"))
    for key in ("profile", "policy", "matrix_version"):
        if key in payload and key not in metadata and payload.get(key) is not None:
            metadata[key] = payload.get(key)

    checked_at_value = _extract_value(
        payload,
        "checked_at",
        "verified_at",
        "timestamp",
    )

    target_payload = _coerce_mapping(_extract_value(payload, "target") or {})
    if not target_payload:
        for key in ("platform", "provider", "version", "runtime", "environment"):
            if key in payload and payload.get(key) is not None:
                target_payload[key] = payload.get(key)

    return IntegrationCompatibilityResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        target=_build_target_view(target_payload, environment),
        summary=CompatibilitySummaryView(
            compatible=compatible,
            score=score,
            status=summary_status,
            checked_at=_datetime_to_iso(checked_at_value) or _utc_now_iso(),
            metadata=metadata,
        ),
        checks=checks,
        issues=issues,
    )


def _run_compatibility(integration_id: str, environment: str) -> Any:
    candidate_calls = [
        lambda: _service.verify(integration_id=integration_id, environment=environment),
        lambda: _service.check(integration_id=integration_id),
        lambda: _service.verify(integration_id),
        lambda: _service.check(integration_id),
        lambda: _service.verify(),
        lambda: _service.check(),
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
        detail="integration verifier service does not expose a supported compatibility method",
    )


@router.get(
    "/{integration_id}/compatibility",
    operation_id="integrations_get_compatibility",
    response_model=IntegrationCompatibilityResponse,
    summary="Get integration compatibility report",
)
def get_integration_compatibility(
    integration_id: str = Path(..., min_length=1, max_length=255),
    environment: str = Query(default="production", min_length=1, max_length=100),
) -> IntegrationCompatibilityResponse:
    normalized_integration_id = integration_id.strip()
    normalized_environment = environment.strip()

    result = _run_compatibility(
        integration_id=normalized_integration_id,
        environment=normalized_environment,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{normalized_integration_id}' not found",
        )

    return _build_compatibility_response(
        integration_id=normalized_integration_id,
        result=result,
        environment=normalized_environment,
    )
