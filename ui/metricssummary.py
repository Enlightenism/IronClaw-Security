from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/metricssummary", tags=["ui-metrics-summary"])


def _metric_card(
    *,
    metric_id: str,
    label: str,
    value: Any,
    tone: str = "neutral",
    trend: str | None = None,
    unit: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    return {
        "metric_id": metric_id,
        "label": label,
        "value": value,
        "tone": tone,
        "trend": trend,
        "unit": unit,
        "description": description,
    }


def _filter_field(
    *,
    name: str,
    label: str,
    value: Any | None = None,
    field_type: str = "text",
    placeholder: str | None = None,
    options: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": field_type,
        "value": value,
        "placeholder": placeholder,
        "options": options or [],
    }


def _series(
    *,
    series_id: str,
    label: str,
    points: list[dict[str, Any]],
    chart_type: str = "line",
    tone: str = "neutral",
) -> dict[str, Any]:
    return {
        "series_id": series_id,
        "label": label,
        "chart_type": chart_type,
        "tone": tone,
        "points": points,
    }


def _section(
    *,
    section_id: str,
    title: str,
    description: str,
    items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "section_id": section_id,
        "title": title,
        "description": description,
        "items": items or [],
    }


@router.get("")
def metrics_summary_page(
    period: str = Query(default="24h"),
    source: str | None = Query(default=None),
    metric_group: str = Query(default="platform"),
) -> dict[str, Any]:
    """Presentation-oriented UI metadata for platform metrics.

    This route returns:
    - filter controls
    - top-level KPI cards
    - trend/chart data
    - sectional summaries
    - jump actions to related pages
    """
    filters = [
        _filter_field(
            name="period",
            label="Period",
            value=period,
            field_type="select",
            options=[
                {"label": "Last 24 hours", "value": "24h"},
                {"label": "Last 7 days", "value": "7d"},
                {"label": "Last 30 days", "value": "30d"},
            ],
        ),
        _filter_field(
            name="source",
            label="Source",
            value=source,
            placeholder="api, ui-console, cli",
        ),
        _filter_field(
            name="metric_group",
            label="Metric Group",
            value=metric_group,
            field_type="select",
            options=[
                {"label": "Platform", "value": "platform"},
                {"label": "Security", "value": "security"},
                {"label": "Usage", "value": "usage"},
                {"label": "Execution", "value": "execution"},
            ],
        ),
    ]

    metric_cards = [
        _metric_card(
            metric_id="total_requests",
            label="Total Requests",
            value=1842,
            tone="neutral",
            trend="+9%",
            unit="requests",
            description="All incoming platform requests during the selected period.",
        ),
        _metric_card(
            metric_id="guard_actions",
            label="Guard Actions",
            value=67,
            tone="warning",
            trend="+5",
            unit="events",
            description="Requests that triggered warn, block, or quarantine actions.",
        ),
        _metric_card(
            metric_id="blocked_requests",
            label="Blocked Requests",
            value=11,
            tone="critical",
            trend="-2",
            unit="events",
            description="High-risk requests blocked by policy or detection logic.",
        ),
        _metric_card(
            metric_id="successful_executions",
            label="Successful Executions",
            value=423,
            tone="positive",
            trend="+11%",
            unit="runs",
            description="Completed execution operations without fatal failure.",
        ),
    ]

    trend_series = [
        _series(
            series_id="request-volume",
            label="Request Volume",
            chart_type="line",
            tone="neutral",
            points=[
                {"x": "00:00", "y": 180},
                {"x": "04:00", "y": 205},
                {"x": "08:00", "y": 260},
                {"x": "12:00", "y": 310},
                {"x": "16:00", "y": 474},
                {"x": "20:00", "y": 413},
            ],
        ),
        _series(
            series_id="guard-events",
            label="Guard Events",
            chart_type="bar",
            tone="warning",
            points=[
                {"x": "00:00", "y": 5},
                {"x": "04:00", "y": 7},
                {"x": "08:00", "y": 11},
                {"x": "12:00", "y": 15},
                {"x": "16:00", "y": 19},
                {"x": "20:00", "y": 10},
            ],
        ),
    ]

    sections = [
        _section(
            section_id="platform-health",
            title="Platform Health",
            description="Top-level health and reliability indicators for the selected interval.",
            items=[
                {
                    "label": "Availability",
                    "value": "99.94%",
                    "tone": "positive",
                    "help_text": "Observed availability across API and UI traffic.",
                },
                {
                    "label": "Median Response Time",
                    "value": "142 ms",
                    "tone": "positive",
                    "help_text": "Median request latency across handled traffic.",
                },
                {
                    "label": "P95 Response Time",
                    "value": "418 ms",
                    "tone": "warning",
                    "help_text": "Higher-percentile latency for slower request paths.",
                },
            ],
        ),
        _section(
            section_id="security-posture",
            title="Security Posture",
            description="Signals related to prompt guard, policy enforcement, and risk handling.",
            items=[
                {
                    "label": "Warn Events",
                    "value": 49,
                    "tone": "warning",
                },
                {
                    "label": "Quarantine Events",
                    "value": 7,
                    "tone": "critical",
                },
                {
                    "label": "Highest Risk Severity",
                    "value": "critical",
                    "tone": "critical",
                },
            ],
        ),
        _section(
            section_id="usage-insights",
            title="Usage Insights",
            description="Demand and billing-aligned usage patterns.",
            items=[
                {
                    "label": "Metered Units",
                    "value": 4312,
                    "tone": "neutral",
                },
                {
                    "label": "Active Principals",
                    "value": 27,
                    "tone": "neutral",
                },
                {
                    "label": "Top Source",
                    "value": source or "ui-console",
                    "tone": "neutral",
                },
            ],
        ),
    ]

    actions = [
        {
            "id": "open-usage-reports",
            "title": "Open Usage Reports",
            "method": "GET",
            "path": "/ui/usagereports",
            "query": {
                "period": period,
                "source": source,
            },
            "description": "Inspect detailed usage and drill down into individual metered events.",
        },
        {
            "id": "open-telemetry-access-summary",
            "title": "Open Telemetry Access Summary",
            "method": "GET",
            "path": "/ui/telemetryaccesssummary",
            "query": {
                "period": period,
            },
            "description": "Review telemetry access posture and audit visibility.",
        },
        {
            "id": "open-request-context",
            "title": "Open Request Context",
            "method": "GET",
            "path": "/ui/requestcontext",
            "query": {
                "target_type": "text",
                "mode": "enforce",
            },
            "description": "Jump into request context tooling for related scan and decision workflows.",
        },
    ]

    return {
        "page": "metrics-summary",
        "title": "Metrics Summary",
        "summary": "Review platform KPIs, trendlines, and security-aware operational metrics.",
        "filters": filters,
        "metric_cards": metric_cards,
        "trends": trend_series,
        "sections": sections,
        "actions": actions,
    }
