from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/uiincidenttriage", tags=["ui-incident-triage"])


def _metric(
    *,
    id: str,
    label: str,
    value: Any,
    tone: str = "neutral",
    trend: str | None = None,
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "label": label,
        "value": value,
        "tone": tone,
        "trend": trend,
        "help_text": help_text,
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
    incident_id: str,
    detected_at: str,
    title: str,
    severity: str,
    status: str,
    source: str,
    principal_id: str | None,
    queue: str,
    score: float | None,
) -> dict[str, Any]:
    return {
        "incident_id": incident_id,
        "detected_at": detected_at,
        "title": title,
        "severity": severity,
        "status": status,
        "source": source,
        "principal_id": principal_id,
        "queue": queue,
        "score": score,
        "detail_path": f"/incidents/triage?incident_id={incident_id}",
    }


def _section(
    *,
    id: str,
    title: str,
    description: str,
    items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "description": description,
        "items": items or [],
    }


def _item(
    *,
    label: str,
    value: Any,
    tone: str = "neutral",
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "label": label,
        "value": value,
        "tone": tone,
        "help_text": help_text,
    }


@router.get("")
def ui_incident_triage_page(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    source: str | None = Query(default=None),
    principal_id: str | None = Query(default=None),
    queue: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    effective_queue = queue or "default-triage"
    effective_source = source or "promptguard"

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
            name="severity",
            label="Severity",
            value=severity,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Low", "value": "low"},
                {"label": "Medium", "value": "medium"},
                {"label": "High", "value": "high"},
                {"label": "Critical", "value": "critical"},
            ],
        ),
        _filter(
            name="status",
            label="Status",
            value=status,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Open", "value": "open"},
                {"label": "Investigating", "value": "investigating"},
                {"label": "Contained", "value": "contained"},
                {"label": "Resolved", "value": "resolved"},
            ],
        ),
        _filter(
            name="source",
            label="Source",
            value=source,
            placeholder="promptguard",
        ),
        _filter(
            name="principal_id",
            label="Principal ID",
            value=principal_id,
            placeholder="cust_123",
        ),
        _filter(
            name="queue",
            label="Queue",
            value=queue,
            placeholder="default-triage",
        ),
    ]

    metrics = [
        _metric(
            id="open_incidents",
            label="Open Incidents",
            value=7,
            tone="warning",
            trend="+1",
            help_text="Incidents that still require operator action.",
        ),
        _metric(
            id="critical_incidents",
            label="Critical Incidents",
            value=1,
            tone="warning",
            trend="0",
            help_text="Highest severity incidents needing immediate triage.",
        ),
        _metric(
            id="contained_incidents",
            label="Contained Incidents",
            value=3,
            tone="positive",
            trend="+1",
            help_text="Incidents with mitigation or containment already applied.",
        ),
        _metric(
            id="mean_triage_minutes",
            label="Mean Triage Minutes",
            value=18,
            tone="neutral",
            trend="-4",
            help_text="Average time to first triage action within the selected period.",
        ),
    ]

    sections = [
        _section(
            id="triage-posture",
            title="Triage Posture",
            description="High-level operational state of the incident triage workflow.",
            items=[
                _item(
                    label="Queue",
                    value=effective_queue,
                    tone="neutral",
                    help_text="The active triage queue used to review incident records.",
                ),
                _item(
                    label="Primary Source",
                    value=effective_source,
                    tone="neutral",
                    help_text="Main subsystem contributing incidents to this triage view.",
                ),
                _item(
                    label="Escalation Routing",
                    value="enabled",
                    tone="positive",
                    help_text="Critical incidents can be escalated into follow-up workflows.",
                ),
                _item(
                    label="Containment Actions",
                    value="available",
                    tone="positive",
                    help_text="Operators can pivot into quarantine, policy, or request workflows.",
                ),
            ],
        ),
        _section(
            id="review-guidance",
            title="Review Guidance",
            description="Suggested triage checks for consistent incident handling.",
            items=[
                _item(
                    label="Correlate Request Context",
                    value="recommended",
                    tone="neutral",
                    help_text="Review request identifiers, session, and policy mode before disposition.",
                ),
                _item(
                    label="Check Related Audit Events",
                    value="recommended",
                    tone="neutral",
                    help_text="Inspect audit trails for operator, customer, or system actions around the incident.",
                ),
                _item(
                    label="Inspect Telemetry Activity",
                    value="recommended",
                    tone="neutral",
                    help_text="Cross-check metered usage and telemetry access patterns for anomalies.",
                ),
                _item(
                    label="Escalate High Severity",
                    value="required",
                    tone="warning",
                    help_text="High and critical incidents should be escalated quickly if active risk remains.",
                ),
            ],
        ),
    ]

    columns = [
        _column(key="detected_at", label="Detected At"),
        _column(key="incident_id", label="Incident ID"),
        _column(key="title", label="Title"),
        _column(key="severity", label="Severity"),
        _column(key="status", label="Status"),
        _column(key="source", label="Source"),
        _column(key="principal_id", label="Principal ID"),
        _column(key="queue", label="Queue"),
        _column(key="score", label="Score", kind="number"),
        _column(key="detail_path", label="Detail Path", kind="link"),
    ]

    rows = [
        _row(
            incident_id="inc_001",
            detected_at="2026-04-23T18:12:00Z",
            title="Prompt injection escalation attempt",
            severity=severity or "high",
            status=status or "open",
            source=source or "promptguard",
            principal_id=principal_id or "cust_demo_001",
            queue=effective_queue,
            score=91,
        ),
        _row(
            incident_id="inc_002",
            detected_at="2026-04-23T18:18:00Z",
            title="Suspicious telemetry drilldown pattern",
            severity=severity or "medium",
            status=status or "investigating",
            source=source or "telemetry",
            principal_id=principal_id or "cust_demo_001",
            queue=effective_queue,
            score=74,
        ),
        _row(
            incident_id="inc_003",
            detected_at="2026-04-23T18:28:00Z",
            title="Customer key misuse warning",
            severity=severity or "critical",
            status=status or "contained",
            source=source or "customerkeys",
            principal_id=principal_id or "cust_demo_001",
            queue=effective_queue,
            score=97,
        ),
    ]

    return {
        "page": "ui-incident-triage",
        "title": "Incident Triage",
        "summary": "Review incident severity, status, and investigation pivots for operator triage workflows.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "table": {
            "title": "Incident Queue",
            "columns": columns,
            "rows": rows,
            "empty_state": {
                "title": "No incidents found",
                "description": "Adjust your filters or widen the reporting period to inspect more incidents.",
            },
        },
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh triage queue",
                "method": "GET",
                "path": "/ui/uiincidenttriage",
                "query": {
                    "severity": severity,
                    "status": status,
                    "source": source,
                    "principal_id": principal_id,
                    "queue": queue,
                    "period": period,
                },
                "description": "Reload the triage queue using the active filters.",
            },
            {
                "id": "open-request-context",
                "title": "Open request context",
                "method": "GET",
                "path": "/ui/requestcontext",
                "query": {
                    "mode": "enforce",
                    "target_type": "text",
                },
                "description": "Pivot into request context for deeper review of related activity.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                    "severity": "warning",
                },
                "description": "Review audit events related to incident investigation.",
            },
            {
                "id": "open-usage-reports",
                "title": "Open usage reports",
                "method": "GET",
                "path": "/ui/usagereports",
                "query": {
                    "period": period,
                    "principal_id": principal_id,
                },
                "description": "Compare incident activity with metered usage and verdict trends.",
            },
        ],
    }
