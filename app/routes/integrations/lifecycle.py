from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.services.integrationstatemachine import IntegrationStateMachine

router = APIRouter(prefix="/integrations", tags=["integration-state"])

_service = IntegrationStateMachine()


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


class IntegrationStateView(BaseModel):
    state: str
    sub_state: str | None = None
    previous_state: str | None = None
    desired_state: str | None = None
    version: str | None = None
    environment: str | None = None
    is_terminal: bool = False
    can_advance: bool = False
    can_rollback: bool = False
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationTransitionView(BaseModel):
    transition_id: str
    from_state: str
    to_state: str
    action: str
    status: str
    detail: str
    timestamp: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationStateMachineResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    state: IntegrationStateView
    transitions: list[IntegrationTransitionView] = Field(default_factory=list)


class IntegrationStateChangeRequest(BaseModel):
    desired_state: str = Field(..., min_length=1, max_length=120)
    environment: str | None = Field(default=None, min_length=1, max_length=120)
    reason: str | None = Field(default=None, max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_state_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"installed", "ready"}:
        return "ready"
    if text in {"enabled", "active", "live"}:
        return "enabled"
    if text in {"disabled", "paused", "stopped"}:
        return "disabled"
    if text in {"failed", "error", "blocked"}:
        return "failed"
    if text in {"installing", "enabling", "rolling_out", "promoting"}:
        return "in_progress"
    return text or "unknown"


def _normalize_transition_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "pass", "passed", "success", "applied"}:
        return "completed"
    if normalized in {"fail", "failed", "error", "rejected"}:
        return "failed"
    if normalized in {"pending", "queued", "running", "in_progress"}:
        return "in_progress"
    return normalized or "completed"


def _build_state_view(result: Any, environment: str | None) -> IntegrationStateView:
    data = _coerce_mapping(result)

    state_raw = _extract_value(data, "state", "current_state")
    sub_state = _extract_value(data, "sub_state", "phase")
    previous_state = _extract_value(data, "previous_state", "from_state")
    desired_state = _extract_value(data, "desired_state", "target_state")
    version = _extract_value(data, "version", "adapter_version", "release_id")
    env_value = _extract_value(data, "environment") or environment

    normalized_state = _normalize_state_name(state_raw)

    is_terminal = bool(_extract_value(data, "is_terminal"))
    if not is_terminal:
        is_terminal = normalized_state in {"disabled", "failed"}

    can_advance = bool(_extract_value(data, "can_advance", "may_advance"))
    can_rollback = bool(_extract_value(data, "can_rollback", "may_rollback"))

    blockers = _normalize_list(_extract_value(data, "blockers", "errors"))
    warnings = _normalize_list(_extract_value(data, "warnings"))

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("platform", "provider", "last_updated_at"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return IntegrationStateView(
        state=normalized_state,
        sub_state=str(sub_state) if sub_state is not None else None,
        previous_state=str(previous_state) if previous_state is not None else None,
        desired_state=str(desired_state) if desired_state is not None else None,
        version=str(version) if version is not None else None,
        environment=str(env_value) if env_value is not None else None,
        is_terminal=is_terminal,
        can_advance=can_advance,
        can_rollback=can_rollback,
        blockers=blockers,
        warnings=warnings,
        metadata=metadata,
    )


def _build_transition_view(record: Any, fallback_index: int) -> IntegrationTransitionView:
    data = _coerce_mapping(record)

    transition_id = str(
        _extract_value(data, "transition_id", "id", "event_id", "sequence")
        or f"transition-{fallback_index}"
    )
    from_state = str(_extract_value(data, "from_state", "previous_state") or "unknown")
    to_state = str(_extract_value(data, "to_state", "next_state", "state") or "unknown")
    action = str(_extract_value(data, "action", "event", "reason") or "unknown")
    status_value = _normalize_transition_status(
        _extract_value(data, "status", "result", "outcome")
    )
    detail = str(_extract_value(data, "detail", "details", "message", "description") or "")
    timestamp_value = _extract_value(data, "timestamp", "occurred_at", "created_at")

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("user", "actor", "environment"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return IntegrationTransitionView(
        transition_id=transition_id,
        from_state=from_state,
        to_state=to_state,
        action=action,
        status=status_value,
        detail=detail,
        timestamp=_datetime_to_iso(timestamp_value) or _utc_now_iso(),
        metadata=metadata,
    )


def _build_state_machine_response(
    integration_id: str,
    result: Any,
    environment: str | None,
) -> IntegrationStateMachineResponse:
    data = _coerce_mapping(result)

    state_payload = _extract_value(data, "state", "current", "status") or result
    transitions_payload = _extract_value(data, "transitions", "history", "events") or []

    state_view = _build_state_view(state_payload, environment=environment)
    transitions = [
        _build_transition_view(item, index + 1)
        for index, item in enumerate(transitions_payload)
    ]

    return IntegrationStateMachineResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        state=state_view,
        transitions=transitions,
    )


def _run_state_lookup(integration_id: str, environment: str | None) -> Any:
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
        detail="integration state machine service does not expose a supported lookup method",
    )


def _run_state_change(
    integration_id: str,
    request: IntegrationStateChangeRequest,
) -> Any:
    payload = request.model_dump()
    desired_state = request.desired_state

    candidate_calls = [
        lambda: _service.transition(integration_id=integration_id, **payload),
        lambda: _service.transition(integration_id, **payload),
        lambda: _service.transition(
            integration_id=integration_id,
            target_state=desired_state,
        ),
        lambda: _service.transition(integration_id, desired_state),
        lambda: _service.set_state(integration_id=integration_id, **payload),
        lambda: _service.set_state(integration_id, **payload),
        lambda: _service.request(integration_id=integration_id, **payload),
        lambda: _service.request(integration_id, **payload),
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
        detail="integration state machine service does not expose a supported transition method",
    )


@router.get(
    "/{integration_id}/state",
    response_model=IntegrationStateMachineResponse,
    summary="Get integration lifecycle state",
)
def get_integration_state(
    integration_id: str = Path(..., min_length=1, max_length=255),
    environment: str | None = Query(default=None, min_length=1, max_length=120),
) -> IntegrationStateMachineResponse:
    result = _run_state_lookup(
        integration_id=integration_id.strip(),
        environment=environment.strip() if environment is not None else None,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{integration_id}' not found",
        )

    return _build_state_machine_response(
        integration_id=integration_id.strip(),
        result=result,
        environment=environment.strip() if environment is not None else None,
    )


@router.post(
    "/{integration_id}/state",
    response_model=IntegrationStateMachineResponse,
    summary="Request an integration state transition",
)
def change_integration_state(
    integration_id: str = Path(..., min_length=1, max_length=255),
    request: IntegrationStateChangeRequest | None = None,
) -> IntegrationStateMachineResponse:
    effective_request = request or IntegrationStateChangeRequest(
        desired_state="enabled",
        environment=None,
        reason=None,
        metadata={},
    )

    result = _run_state_change(
        integration_id=integration_id.strip(),
        request=effective_request,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{integration_id}' not found",
        )

    if isinstance(result, dict) or hasattr(result, "model_dump"):
        return _build_state_machine_response(
            integration_id=integration_id.strip(),
            result=result,
            environment=effective_request.environment,
        )

    lookup = _run_state_lookup(
        integration_id=integration_id.strip(),
        environment=effective_request.environment,
    )
    if lookup is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="state transition completed but the updated state could not be retrieved",
        )

    return _build_state_machine_response(
        integration_id=integration_id.strip(),
        result=lookup,
        environment=effective_request.environment,
    )
}