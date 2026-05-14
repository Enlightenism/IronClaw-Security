from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.services.integrationrollout import IntegrationRollout

router = APIRouter(prefix="/integrations", tags=["integration-rollouts"])

_service = IntegrationRollout()


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


class RolloutStageView(BaseModel):
    stage_id: str
    title: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RolloutSummaryView(BaseModel):
    rollout_id: str | None = None
    state: str
    environment: str
    adapter_version: str | None = None
    target_percentage: int | None = None
    current_percentage: int | None = None
    updated_at: str
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationRolloutResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    rollout: RolloutSummaryView
    stages: list[RolloutStageView] = Field(default_factory=list)


def _normalize_stage_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()

    if normalized in {"ok", "pass", "passed", "complete", "completed", "success", "healthy"}:
        return "completed"
    if normalized in {"warn", "warning", "degraded"}:
        return "warning"
    if normalized in {"fail", "failed", "blocked", "error", "rolled_back", "rollback"}:
        return "failed"
    if normalized in {"pending", "queued", "running", "in_progress", "promoting"}:
        return "in_progress"

    return normalized or "in_progress"


def _normalize_rollout_state(value: Any, stages: list[RolloutStageView]) -> str:
    normalized = str(value or "").strip().lower()

    if normalized in {"ok", "pass", "passed", "complete", "completed", "success", "healthy"}:
        return "completed"
    if normalized in {"warn", "warning", "degraded"}:
        return "warning"
    if normalized in {"fail", "failed", "blocked", "error", "rolled_back", "rollback"}:
        return "failed"
    if normalized in {"pending", "queued", "running", "in_progress", "promoting"}:
        return "in_progress"

    if any(stage.status == "failed" for stage in stages):
        return "failed"
    if any(stage.status == "warning" for stage in stages):
        return "warning"
    if stages and all(stage.status == "completed" for stage in stages):
        return "completed"

    return "in_progress"


def _normalize_percent(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        numeric = int(float(str(value)))
    except (TypeError, ValueError):
        return None
    return max(0, min(100, numeric))


def _build_stage_view(record: Any, fallback_index: int) -> RolloutStageView:
    data = _coerce_mapping(record)

    stage_id = str(
        _extract_value(data, "stage_id", "stageid", "id", "name", "key") or f"stage-{fallback_index}",
    )
    title = str(
        _extract_value(data, "title", "label", "name", "summary") or stage_id.replace("-", " ").replace("_", " ").title(),
    )
    detail = str(_extract_value(data, "detail", "details", "message", "summary", "description") or "")
    status_value = _normalize_stage_status(_extract_value(data, "status", "state", "result"))

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("percentage", "wave", "cohort", "started_at", "completed_at"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return RolloutStageView(
        stage_id=stage_id,
        title=title,
        status=status_value,
        detail=detail,
        metadata=metadata,
    )


def _build_rollout_response(
    integration_id: str,
    result: Any,
    environment: str,
) -> IntegrationRolloutResponse:
    data = _coerce_mapping(result)
    rollout = _coerce_mapping(_extract_value(data, "rollout") or result)

    raw_stages = _extract_value(rollout, "stages", "steps", "items") or []
    stages = [_build_stage_view(item, index + 1) for index, item in enumerate(raw_stages)]

    summary_metadata = _normalize_dict(rollout.get("metadata"))
    for key in ("platform", "provider", "release_id"):
        if key in rollout and key not in summary_metadata and rollout.get(key) is not None:
            summary_metadata[key] = rollout.get(key)

    rollout_id_value = _extract_value(rollout, "rollout_id", "id")
    adapter_version_value = _extract_value(rollout, "adapter_version", "version")
    updated_at_value = _extract_value(rollout, "updated_at", "timestamp", "generated_at")

    return IntegrationRolloutResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        rollout=RolloutSummaryView(
            rollout_id=str(rollout_id_value) if rollout_id_value is not None else None,
            state=_normalize_rollout_state(
                _extract_value(rollout, "state", "status", "rollout_state"),
                stages,
            ),
            environment=str(_extract_value(rollout, "environment") or environment),
            adapter_version=str(adapter_version_value) if adapter_version_value is not None else None,
            target_percentage=_normalize_percent(
                _extract_value(rollout, "target_percentage", "target_percent"),
            ),
            current_percentage=_normalize_percent(
                _extract_value(rollout, "current_percentage", "current_percent", "percentage"),
            ),
            updated_at=_datetime_to_iso(updated_at_value) or _utc_now_iso(),
            blockers=_normalize_list(_extract_value(rollout, "blockers", "errors")),
            warnings=_normalize_list(_extract_value(rollout, "warnings")),
            metadata=summary_metadata,
        ),
        stages=stages,
    )


def _run_rollout_lookup(integration_id: str, environment: str) -> Any:
    candidate_calls = [
        lambda: _service.get(integration_id=integration_id, environment=environment),
        lambda: _service.get(integration_id, environment),
        lambda: _service.get(integration_id),
        lambda: _service.status(integration_id=integration_id, environment=environment),
        lambda: _service.status(integration_id, environment),
        lambda: _service.status(integration_id),
        lambda: _service.current(integration_id=integration_id, environment=environment),
        lambda: _service.current(integration_id, environment),
        lambda: _service.current(integration_id),
        lambda: _service.rollout(integration_id=integration_id, environment=environment),
        lambda: _service.rollout(integration_id, environment),
        lambda: _service.rollout(integration_id),
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
        detail="integration rollout service does not expose a supported rollout method",
    )


@router.get(
    "/{integration_id}/rollouts",
    response_model=IntegrationRolloutResponse,
    summary="Get integration rollout state",
)
def get_integration_rollout(
    integration_id: str = Path(..., min_length=1, max_length=255),
    environment: str = Query(default="production", min_length=1, max_length=100),
) -> IntegrationRolloutResponse:
    result = _run_rollout_lookup(
        integration_id=integration_id.strip(),
        environment=environment.strip(),
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{integration_id}' not found",
        )

    return _build_rollout_response(
        integration_id=integration_id.strip(),
        result=result,
        environment=environment.strip(),
    )
