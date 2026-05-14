from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path, status
from pydantic import BaseModel, Field

from app.services.integrationinstaller import IntegrationInstaller

router = APIRouter(prefix="/integrations", tags=["integration-installer"])

_service = IntegrationInstaller()


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


def _normalize_step_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "pass", "passed", "complete", "completed", "success", "installed"}:
        return "completed"
    if normalized in {"fail", "failed", "error", "blocked"}:
        return "failed"
    if normalized in {"running", "installing", "pending", "queued", "in_progress"}:
        return "in_progress"
    if normalized in {"warn", "warning"}:
        return "warning"
    return normalized or "in_progress"


class InstallationStepView(BaseModel):
    step_id: str
    title: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InstallationSummaryView(BaseModel):
    state: str
    installed: bool
    steps_total: int
    steps_completed: int
    steps_failed: int
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationInstallRequest(BaseModel):
    platform: str | None = Field(default=None, min_length=1, max_length=120)
    adapter_version: str | None = Field(default=None, min_length=1, max_length=120)
    initiated_by: str | None = Field(default=None, min_length=1, max_length=120)
    dry_run: bool = False
    force: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationInstallResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    platform: str | None = None
    adapter_version: str | None = None
    installation: InstallationSummaryView
    steps: list[InstallationStepView] = Field(default_factory=list)


def _build_step_view(record: Any, fallback_index: int) -> InstallationStepView:
    data = _coerce_mapping(record)

    step_id = str(
        _extract_value(data, "step_id", "stepid", "id", "name", "key") or f"step-{fallback_index}",
    )
    title = str(
        _extract_value(data, "title", "label", "name", "summary") or step_id.replace("-", " ").replace("_", " ").title(),
    )
    detail = str(
        _extract_value(data, "detail", "details", "message", "summary", "description") or "",
    )
    status_value = _normalize_step_status(
        _extract_value(data, "status", "state", "result"),
    )

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("component", "phase", "duration_ms", "started_at", "completed_at"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return InstallationStepView(
        step_id=step_id,
        title=title,
        status=status_value,
        detail=detail,
        metadata=metadata,
    )


def _build_install_response(integration_id: str, result: Any) -> IntegrationInstallResponse:
    data = _coerce_mapping(result)

    raw_steps = _extract_value(data, "steps", "items", "phases") or []
    steps = [_build_step_view(item, index + 1) for index, item in enumerate(raw_steps)]

    steps_completed = sum(1 for item in steps if item.status == "completed")
    steps_failed = sum(1 for item in steps if item.status == "failed")

    installed_value = _extract_value(data, "installed", "success")
    installed = bool(installed_value) if installed_value is not None else steps_failed == 0 and len(steps) > 0

    state = (
        str(
            _extract_value(
                data,
                "state",
                "installation_state",
                "overall_status",
                "status",
            )
            or ("failed" if steps_failed else "completed" if installed else "pending"),
        )
        .strip()
        .lower()
    )

    platform = _extract_value(data, "platform")
    adapter_version = _extract_value(data, "adapter_version", "version")

    blockers = _normalize_list(_extract_value(data, "blockers", "errors"))
    warnings = _normalize_list(_extract_value(data, "warnings"))
    metadata = _normalize_dict(data.get("metadata"))

    for key in ("provider", "adapter_name", "initiated_by", "dry_run", "force"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return IntegrationInstallResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        platform=str(platform) if platform is not None else None,
        adapter_version=str(adapter_version) if adapter_version is not None else None,
        installation=InstallationSummaryView(
            state=state,
            installed=installed,
            steps_total=len(steps),
            steps_completed=steps_completed,
            steps_failed=steps_failed,
            blockers=blockers,
            warnings=warnings,
            metadata=metadata,
        ),
        steps=steps,
    )


def _run_installation(integration_id: str, request: IntegrationInstallRequest) -> Any:
    payload = request.model_dump()

    candidate_calls = [
        lambda: _service.install(integration_id=integration_id, **payload),
        lambda: _service.install(integration_id, **payload),
        lambda: _service.install(integration_id=integration_id, payload=payload),
        lambda: _service.install(integration_id, payload),
        lambda: _service.install(integration_id=integration_id),
        lambda: _service.install(integration_id),
        lambda: _service.run(integration_id=integration_id, **payload),
        lambda: _service.run(integration_id),
        lambda: _service.execute(integration_id=integration_id, **payload),
        lambda: _service.execute(integration_id),
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
        detail="integration installer service does not expose a supported install method",
    )


@router.post(
    "/{integration_id}/install",
    response_model=IntegrationInstallResponse,
    summary="Install or provision an integration",
)
def install_integration(
    integration_id: str = Path(..., min_length=1, max_length=255),
    request: IntegrationInstallRequest | None = None,
) -> IntegrationInstallResponse:
    normalized_integration_id = integration_id.strip()
    effective_request = request or IntegrationInstallRequest()

    result = _run_installation(
        integration_id=normalized_integration_id,
        request=effective_request,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{normalized_integration_id}' not found",
        )

    return _build_install_response(
        integration_id=normalized_integration_id,
        result=result,
    )
