from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.integrationtelemetry import IntegrationTelemetry

router = APIRouter(prefix="/integrations", tags=["integrations"])

_service = IntegrationTelemetry()


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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


class TelemetrySeriesPoint(BaseModel):
    timestamp: str
    value: float
    label: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelemetrySeriesView(BaseModel):
    metric: str
    unit: str | None = None
    points: list[TelemetrySeriesPoint] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelemetrySignalView(BaseModel):
    signal_id: str
    category: str
    severity: str
    status: str
    title: str
    detail: str
    timestamp: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelemetrySummaryView(BaseModel):
    environment: str
    window: str
    updated_at: str
    total_signals: int
    healthy_signals: int
    warning_signals: int
    critical_signals: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationTelemetryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    telemetry: TelemetrySummaryView
    metrics: list[TelemetrySeriesView]
    signals: list[TelemetrySignalView]


def _normalize_signal_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "info", "normal", "healthy"}:
        return "healthy"
    if normalized in {"warn", "warning", "medium", "degraded"}:
        return "warning"
    if normalized in {"critical", "high", "error", "failed"}:
        return "critical"
    return normalized or "healthy"


def _normalize_signal_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"open", "active", "firing"}:
        return "active"
    if normalized in {"closed", "resolved", "cleared"}:
        return "resolved"
    if normalized in {"suppressed", "muted"}:
        return "suppressed"
    return normalized or "active"


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _build_series_point(record: Any, fallback_index: int) -> TelemetrySeriesPoint:
    data = _coerce_mapping(record)
    timestamp = str(_extract_value(data, "timestamp", "time", "at") or _utcnow())
    value = _coerce_float(_extract_value(data, "value", "count", "metric"))
    label = _extract_value(data, "label", "name")
    metadata = _normalize_dict(data.get("metadata"))

    for key in ("min", "max", "avg", "p95"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    if not label and fallback_index >= 0:
        label = f"point-{fallback_index}"

    return TelemetrySeriesPoint(
        timestamp=timestamp,
        value=value,
        label=str(label) if label is not None else None,
        metadata=metadata,
    )


def _build_series_view(record: Any, fallback_index: int) -> TelemetrySeriesView:
    data = _coerce_mapping(record)
    metric = str(_extract_value(data, "metric", "name", "id") or f"metric-{fallback_index}")
    unit = _extract_value(data, "unit")
    raw_points = _extract_value(data, "points", "values", "samples") or []
    points = [_build_series_point(item, index + 1) for index, item in enumerate(_normalize_list(raw_points))]
    metadata = _normalize_dict(data.get("metadata"))

    for key in ("source", "aggregation", "platform"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return TelemetrySeriesView(
        metric=metric,
        unit=str(unit) if unit is not None else None,
        points=points,
        metadata=metadata,
    )


def _build_signal_view(record: Any, fallback_index: int) -> TelemetrySignalView:
    data = _coerce_mapping(record)
    signal_id = str(_extract_value(data, "signal_id", "id", "event_id") or f"signal-{fallback_index}")
    category = str(_extract_value(data, "category", "type") or "general")
    severity = _normalize_signal_severity(_extract_value(data, "severity", "level"))
    signal_status = _normalize_signal_status(_extract_value(data, "status", "state"))
    title = str(_extract_value(data, "title", "name", "summary") or signal_id.replace("-", " ").title())
    detail = str(_extract_value(data, "detail", "message", "description") or "")
    timestamp = str(_extract_value(data, "timestamp", "occurred_at", "created_at") or _utcnow())
    metadata = _normalize_dict(data.get("metadata"))

    for key in ("platform", "provider", "component", "metric"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)

    return TelemetrySignalView(
        signal_id=signal_id,
        category=category,
        severity=severity,
        status=signal_status,
        title=title,
        detail=detail,
        timestamp=timestamp,
        metadata=metadata,
    )


def _build_telemetry_response(
    integration_id: str,
    result: Any,
    environment: str,
    window: str,
) -> IntegrationTelemetryResponse:
    data = _coerce_mapping(result)
    payload = _coerce_mapping(_extract_value(data, "telemetry") or result)

    raw_metrics = _extract_value(payload, "metrics", "series") or []
    metrics = [_build_series_view(item, index + 1) for index, item in enumerate(_normalize_list(raw_metrics))]

    raw_signals = _extract_value(payload, "signals", "events", "alerts") or []
    signals = [_build_signal_view(item, index + 1) for index, item in enumerate(_normalize_list(raw_signals))]

    healthy_signals = sum(1 for item in signals if item.severity == "healthy")
    warning_signals = sum(1 for item in signals if item.severity == "warning")
    critical_signals = sum(1 for item in signals if item.severity == "critical")

    metadata = _normalize_dict(payload.get("metadata"))
    for key in ("platform", "adapter_version", "provider"):
        if key in payload and key not in metadata and payload.get(key) is not None:
            metadata[key] = payload.get(key)

    return IntegrationTelemetryResponse(
        status="ok",
        service="integration-telemetry",
        timestamp=_utcnow(),
        integration_id=integration_id,
        telemetry=TelemetrySummaryView(
            environment=str(_extract_value(payload, "environment") or environment),
            window=str(_extract_value(payload, "window", "time_window") or window),
            updated_at=str(_extract_value(payload, "updated_at", "timestamp", "generated_at") or _utcnow()),
            total_signals=len(signals),
            healthy_signals=healthy_signals,
            warning_signals=warning_signals,
            critical_signals=critical_signals,
            metadata=metadata,
        ),
        metrics=metrics,
        signals=signals,
    )


def _run_telemetry_lookup(integration_id: str, environment: str, window: str) -> Any:
    candidate_calls = [
        lambda: _service.get(integration_id=integration_id, environment=environment, window=window),
        lambda: _service.get(integration_id, environment, window),
        lambda: _service.get(integration_id),
        lambda: _service.summary(integration_id=integration_id, environment=environment, window=window),
        lambda: _service.summary(integration_id, environment, window),
        lambda: _service.summary(integration_id),
        lambda: _service.metrics(integration_id=integration_id, environment=environment, window=window),
        lambda: _service.metrics(integration_id, environment, window),
        lambda: _service.metrics(integration_id),
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
        detail="integration telemetry service does not expose a supported telemetry method",
    )


@router.get(
    "/{integration_id}/telemetry",
    response_model=IntegrationTelemetryResponse,
    summary="Get integration telemetry and observability signals",
)
def get_integration_telemetry(
    integration_id: str,
    environment: str = Query(default="production"),
    window: str = Query(default="24h"),
) -> IntegrationTelemetryResponse:
    result = _run_telemetry_lookup(
        integration_id=integration_id,
        environment=environment,
        window=window,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{integration_id}' not found",
        )

    return _build_telemetry_response(
        integration_id=integration_id,
        result=result,
        environment=environment,
        window=window,
    )