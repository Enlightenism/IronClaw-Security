from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.services.integrationtelemetry import IntegrationTelemetry

router = APIRouter(prefix="/integrations", tags=["integration-observability"])

_service = IntegrationTelemetry()


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
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _normalize_string_list(value: Any) -> list[str]:
    return [str(item) for item in _normalize_list(value)]


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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "healthy", "active", "enabled", "success"}:
        return "ok"
    if normalized in {"warn", "warning", "degraded"}:
        return "warning"
    if normalized in {"fail", "failed", "error", "critical", "down"}:
        return "error"
    return normalized or "ok"


class IntegrationMetricView(BaseModel):
    metric_id: str
    name: str
    value: float
    unit: str | None = None
    status: str
    updated_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationEventView(BaseModel):
    event_id: str
    category: str
    message: str
    severity: str
    timestamp: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationAlertView(BaseModel):
    alert_id: str
    title: str
    severity: str
    status: str
    opened_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationObservabilitySummaryView(BaseModel):
    overall_status: str
    updated_at: str
    environment: str
    integration_id: str
    total_metrics: int
    total_events: int
    total_alerts: int
    open_alerts: int
    warning_alerts: int
    error_alerts: int
    signal_sources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationObservabilityResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    summary: IntegrationObservabilitySummaryView
    metrics: list[IntegrationMetricView] = Field(default_factory=list)
    events: list[IntegrationEventView] = Field(default_factory=list)
    alerts: list[IntegrationAlertView] = Field(default_factory=list)


def _build_metric_view(record: Any, fallback_index: int) -> IntegrationMetricView:
    data = _coerce_mapping(record)

    metric_id = str(
        _extract_value(data, "metric_id", "metricid", "id", "name", "key")
        or f"metric-{fallback_index}"
    )
    name = str(_extract_value(data, "name", "title", "label") or metric_id)
    value = _safe_float(_extract_value(data, "value", "current_value", "amount"), 0.0)
    unit = _extract_value(data, "unit")
    status_value = _normalize_status(_extract_value(data, "status", "state"))
    updated_at = _datetime_to_iso(_extract_value(data, "updated_at", "timestamp", "observed_at"))

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("description", "source", "provider", "window", "threshold"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return IntegrationMetricView(
        metric_id=metric_id,
        name=name,
        value=value,
        unit=str(unit) if unit is not None else None,
        status=status_value,
        updated_at=updated_at,
        metadata=metadata,
    )


def _build_event_view(record: Any, fallback_index: int) -> IntegrationEventView:
    data = _coerce_mapping(record)

    event_id = str(
        _extract_value(data, "event_id", "eventid", "id", "name", "key")
        or f"event-{fallback_index}"
    )
    category = str(_extract_value(data, "category", "type", "kind") or "activity")
    message = str(
        _extract_value(data, "message", "detail", "summary", "title", "description")
        or event_id
    )
    severity = str(_extract_value(data, "severity", "level") or "info").strip().lower()
    timestamp = _datetime_to_iso(
        _extract_value(data, "timestamp", "created_at", "occurred_at", "observed_at")
    ) or _utc_now_iso()

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("source", "component", "provider", "code", "trace_id"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return IntegrationEventView(
        event_id=event_id,
        category=category,
        message=message,
        severity=severity,
        timestamp=timestamp,
        metadata=metadata,
    )


def _build_alert_view(record: Any, fallback_index: int) -> IntegrationAlertView:
    data = _coerce_mapping(record)

    alert_id = str(
        _extract_value(data, "alert_id", "alertid", "id", "name", "key")
        or f"alert-{fallback_index}"
    )
    title = str(_extract_value(data, "title", "name", "summary", "message") or alert_id)
    severity = str(_extract_value(data, "severity", "level") or "info").strip().lower()
    status_value = _normalize_status(_extract_value(data, "status", "state"))
    opened_at = _datetime_to_iso(_extract_value(data, "opened_at", "created_at", "timestamp"))

    metadata = _normalize_dict(data.get("metadata"))
    for key in ("source", "component", "provider", "rule_id", "runbook"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return IntegrationAlertView(
        alert_id=alert_id,
        title=title,
        severity=severity,
        status=status_value,
        opened_at=opened_at,
        metadata=metadata,
    )


def _collect_section(data: dict[str, Any], primary: str, *fallbacks: str) -> list[Any]:
    for key in (primary, *fallbacks):
        if key in data and data.get(key) is not None:
            return _normalize_list(data.get(key))
    return []


def _build_response(
    integration_id: str,
    environment: str,
    result: Any,
) -> IntegrationObservabilityResponse:
    data = _coerce_mapping(result)
    observability = _coerce_mapping(_extract_value(data, "observability", "summary") or result)

    metrics_raw = _collect_section(
        observability,
        "metrics",
        "signals",
        "kpis",
    )
    events_raw = _collect_section(
        observability,
        "events",
        "activity",
        "logs",
    )
    alerts_raw = _collect_section(
        observability,
        "alerts",
        "issues",
        "incidents",
    )

    metrics = [
        _build_metric_view(item, index + 1)
        for index, item in enumerate(metrics_raw)
    ]
    events = [
        _build_event_view(item, index + 1)
        for index, item in enumerate(events_raw)
    ]
    alerts = [
        _build_alert_view(item, index + 1)
        for index, item in enumerate(alerts_raw)
    ]

    open_alerts = sum(1 for item in alerts if item.status not in {"ok", "resolved", "closed"})
    warning_alerts = sum(1 for item in alerts if item.severity in {"warning", "warn", "medium"})
    error_alerts = sum(1 for item in alerts if item.severity in {"error", "critical", "high"})

    overall_status = _normalize_status(
        _extract_value(observability, "overall_status", "status", "state")
    )
    if overall_status == "ok":
        if error_alerts:
            overall_status = "error"
        elif warning_alerts:
            overall_status = "warning"

    updated_at = _datetime_to_iso(
        _extract_value(observability, "updated_at", "timestamp", "generated_at")
    ) or _utc_now_iso()

    signal_sources = _normalize_string_list(
        _extract_value(observability, "signal_sources", "sources", "providers")
    )

    metadata = _normalize_dict(observability.get("metadata"))
    for key in ("provider", "platform", "adapter_version", "trace_id"):
        if key in observability and key not in metadata and observability.get(key) is not None:
            metadata[key] = observability.get(key)

    return IntegrationObservabilityResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        summary=IntegrationObservabilitySummaryView(
            overall_status=overall_status,
            updated_at=updated_at,
            environment=str(_extract_value(observability, "environment") or environment),
            integration_id=integration_id,
            total_metrics=len(metrics),
            total_events=len(events),
            total_alerts=len(alerts),
            open_alerts=open_alerts,
            warning_alerts=warning_alerts,
            error_alerts=error_alerts,
            signal_sources=signal_sources,
            metadata=metadata,
        ),
        metrics=metrics,
        events=events,
        alerts=alerts,
    )


def _run_observability(integration_id: str, environment: str, limit: int) -> Any:
    candidate_calls = [
        lambda: _service.summary(integration_id=integration_id, environment=environment, limit=limit),
        lambda: _service.summary(integration_id, environment, limit),
        lambda: _service.summary(integration_id=integration_id, environment=environment),
        lambda: _service.summary(integration_id, environment),
        lambda: _service.get(integration_id=integration_id, environment=environment, limit=limit),
        lambda: _service.get(integration_id, environment, limit),
        lambda: _service.get(integration_id=integration_id, environment=environment),
        lambda: _service.get(integration_id, environment),
        lambda: _service.observe(integration_id=integration_id, environment=environment, limit=limit),
        lambda: _service.observe(integration_id, environment, limit),
        lambda: _service.observe(integration_id=integration_id, environment=environment),
        lambda: _service.observe(integration_id, environment),
        lambda: _service.list(integration_id=integration_id, environment=environment, limit=limit),
        lambda: _service.list(integration_id, environment, limit),
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
        detail="integration telemetry service does not expose a supported observability method",
    )


@router.get(
    "/{integration_id}/observability",
    response_model=IntegrationObservabilityResponse,
    summary="Get integration observability and telemetry",
)
def get_integration_observability(
    integration_id: str = Path(..., min_length=1, max_length=255),
    environment: str = Query(default="production", min_length=1, max_length=100),
    limit: int = Query(default=25, ge=1, le=200),
) -> IntegrationObservabilityResponse:
    normalized_integration_id = integration_id.strip()
    normalized_environment = environment.strip()

    result = _run_observability(
        integration_id=normalized_integration_id,
        environment=normalized_environment,
        limit=limit,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{normalized_integration_id}' not found",
        )

    return _build_response(
        integration_id=normalized_integration_id,
        environment=normalized_environment,
        result=result,
    )