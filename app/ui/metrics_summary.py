from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/metrics-summary", tags=["metrics-summary"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class MetricsSummaryWindowView(BaseModel):
    lookback_minutes: int
    environment: str
    aggregation_mode: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricsKPIView(BaseModel):
    label: str
    value: float
    unit: str
    trend: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricsServiceView(BaseModel):
    service_name: str
    status: str
    request_rate: float
    error_rate: float
    p95_latency_ms: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricsLinkView(BaseModel):
    label: str
    path: str
    description: str


class MetricsSummaryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    window: MetricsSummaryWindowView
    kpis: list[MetricsKPIView] = Field(default_factory=list)
    services: list[MetricsServiceView] = Field(default_factory=list)
    links: list[MetricsLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_kpis() -> list[MetricsKPIView]:
    return [
        MetricsKPIView(
            label="Requests per minute",
            value=0.0,
            unit="rpm",
            trend="stable",
            metadata={"source": "metrics-summary-ui"},
        ),
        MetricsKPIView(
            label="Error rate",
            value=0.0,
            unit="percent",
            trend="stable",
            metadata={"source": "metrics-summary-ui"},
        ),
        MetricsKPIView(
            label="P95 latency",
            value=0.0,
            unit="ms",
            trend="stable",
            metadata={"source": "metrics-summary-ui"},
        ),
        MetricsKPIView(
            label="Guard-reviewed events",
            value=0.0,
            unit="count",
            trend="stable",
            metadata={"source": "metrics-summary-ui"},
        ),
    ]


def _build_services() -> list[MetricsServiceView]:
    return [
        MetricsServiceView(
            service_name="IronClaw-Security",
            status="healthy",
            request_rate=0.0,
            error_rate=0.0,
            p95_latency_ms=0.0,
            metadata={
                "role": "primary-api",
                "surface": "metrics-summary",
            },
        ),
        MetricsServiceView(
            service_name="PromptGuard",
            status="healthy",
            request_rate=0.0,
            error_rate=0.0,
            p95_latency_ms=0.0,
            metadata={
                "role": "policy-guard",
                "surface": "metrics-summary",
            },
        ),
    ]


def _build_links() -> list[MetricsLinkView]:
    return [
        MetricsLinkView(
            label="Runtime status",
            path="/ui/runtime-status",
            description="Operational health and readiness overview for the current runtime.",
        ),
        MetricsLinkView(
            label="System diagnostics",
            path="/ui/system-diagnostics",
            description="Diagnostic details, service checks, and troubleshooting signals.",
        ),
        MetricsLinkView(
            label="Telemetry access summary",
            path="/ui/telemetry-access-summary",
            description="Telemetry access activity and recent related operational context.",
        ),
        MetricsLinkView(
            label="Audit log",
            path="/ui/audit-log",
            description="Audit trail for requests, reviews, and operator-visible decisions.",
        ),
    ]


@router.get("", response_model=MetricsSummaryResponse)
def get_metrics_summary(
    lookback_minutes: int = Query(default=60, ge=1, le=1440),
) -> MetricsSummaryResponse:
    return MetricsSummaryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        window=MetricsSummaryWindowView(
            lookback_minutes=lookback_minutes,
            environment="local",
            aggregation_mode="rolling",
            metadata={
                "ui_surface": "metrics-summary",
                "default_mode": "safe-empty",
            },
        ),
        kpis=_build_kpis(),
        services=_build_services(),
        links=_build_links(),
        notes=[
            "Metrics summary provides a compact operational overview for the active IronClaw runtime.",
            "This Gen1 UI view returns a stable empty-state structure until live metrics hydration is connected.",
            "The response contract is designed to support future runtime, telemetry, and policy metric enrichment.",
        ],
    )
