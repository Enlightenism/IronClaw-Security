from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/usagereports", tags=["ui-usage-reports"])


def _metric(
    *,
    id: str,
    label: str,
    value: Any,
    unit: str | None = None,
    trend: str | None = None,
    tone: str = "neutral",
) -> dict[str, Any]:
    return {
        "id": id,
        "label": label,
        "value": value,
        "unit": unit,
        "trend": trend,
        "tone": tone,
    }


def _filter(
    *,
    name: str,
    label: str,
    value: Any | None,
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


def _column(
    *,
    key: str,
    label: str,
    kind: str = "text",
) -> dict[str, str]:
    return {
        "key": key,
        "label": label,
        "kind": kind,
    }


def _row(
    *,
    event_id: str,
    timestamp: str,
    principal_id: str | None,
    principal_type: str | None,
    source: str | None,
    route: str | None,
    unit_type: str | None,
    unit_count: float | None,
    verdict: str | None,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "principal_id": principal_id,
        "principal_type": principal_type,
        "source": source,
        "route": route,
        "unit_type": unit_type,
        "unit_count": unit_count,
        "verdict": verdict,
        "detail_path": f"/ui/usageevents/{event_id}/detail",
    }


@router.get("")
def usage_reports_page(
    principal_id: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    request_id: str | None = Query(default=None),
    source: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    """UI metadata page for usage reporting.

    This route intentionally returns a presentation-oriented schema so the UI layer
    can render:
    - filter controls
    - KPI cards
    - a tabular event feed
    - drilldown links into usage event detail
    """
    filters = [
        _filter(
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
        _filter(
            name="principal_id",
            label="Principal ID",
            value=principal_id,
            placeholder="cust_123",
        ),
        _filter(
            name="session_id",
            label="Session ID",
            value=session_id,
            placeholder="sess_123",
        ),
        _filter(
            name="request_id",
            label="Request ID",
            value=request_id,
            placeholder="req_123",
        ),
        _filter(
            name="source",
            label="Source",
            value=source,
            placeholder="ui-console",
        ),
        _filter(
            name="verdict",
            label="Guard Verdict",
            value=verdict,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Allow", "value": "allow"},
                {"label": "Warn", "value": "warn"},
                {"label": "Block", "value": "block"},
                {"label": "Quarantine", "value": "quarantine"},
            ],
        ),
    ]

    metrics = [
        _metric(
            id="total_events",
            label="Total Events",
            value=128,
            trend="+12%",
            tone="positive",
        ),
        _metric(
            id="metered_units",
            label="Metered Units",
            value=4312,
            unit="units",
            trend="+7%",
            tone="neutral",
        ),
        _metric(
            id="guarded_requests",
            label="Guarded Requests",
            value=34,
            trend="+4",
            tone="warning",
        ),
        _metric(
            id="high_risk_events",
            label="High Risk Events",
            value=3,
            trend="-1",
            tone="positive",
        ),
    ]

    columns = [
        _column(key="timestamp", label="Timestamp"),
        _column(key="event_id", label="Event ID"),
        _column(key="principal_id", label="Principal"),
        _column(key="principal_type", label="Principal Type"),
        _column(key="source", label="Source"),
        _column(key="route", label="Route"),
        _column(key="unit_type", label="Unit Type"),
        _column(key="unit_count", label="Unit Count", kind="number"),
        _column(key="verdict", label="Verdict"),
        _column(key="detail_path", label="Detail Path", kind="link"),
    ]

    rows = [
        _row(
            event_id="evt_001",
            timestamp="2026-04-23T18:00:00Z",
            principal_id=principal_id or "cust_demo_001",
            principal_type="customer",
            source=source or "ui-console",
            route="/scan",
            unit_type="scan_request",
            unit_count=1,
            verdict=verdict or "allow",
        ),
        _row(
            event_id="evt_002",
            timestamp="2026-04-23T18:02:00Z",
            principal_id=principal_id or "cust_demo_001",
            principal_type="customer",
            source=source or "ui-console",
            route="/brain/decision",
            unit_type="decision_request",
            unit_count=1,
            verdict=verdict or "warn",
        ),
        _row(
            event_id="evt_003",
            timestamp="2026-04-23T18:04:00Z",
            principal_id=principal_id or "cust_demo_001",
            principal_type="customer",
            source=source or "api",
            route="/customerkeys",
            unit_type="key_management",
            unit_count=1,
            verdict=verdict or "allow",
        ),
    ]

    return {
        "page": "usage-reports",
        "title": "Usage Reports",
        "summary": "Inspect metered usage, security verdicts, and drill into individual events.",
        "filters": filters,
        "metrics": metrics,
        "table": {
            "columns": columns,
            "rows": rows,
            "empty_state": {
                "title": "No usage events found",
                "description": "Adjust your filters or widen the reporting period.",
            },
        },
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh report",
                "method": "GET",
                "path": "/ui/usagereports",
                "query": {
                    "period": period,
                    "principal_id": principal_id,
                    "session_id": session_id,
                    "request_id": request_id,
                    "source": source,
                    "verdict": verdict,
                },
            },
            {
                "id": "request_context",
                "title": "Open request context",
                "method": "GET",
                "path": "/ui/requestcontext",
                "query": {
                    "mode": "enforce",
                    "target_type": "text",
                },
            },
        ],
    }
