from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/uiauditlog", tags=["ui-audit-log"])


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
    event_id: str,
    timestamp: str,
    actor_id: str,
    actor_type: str,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str,
    severity: str,
    detail_path: str,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "severity": severity,
        "detail_path": detail_path,
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
def ui_audit_log_page(
    actor_id: str | None = Query(default=None),
    actor_type: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    effective_actor_id = actor_id or "operator_demo_001"
    effective_actor_type = actor_type or "operator"

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
            name="actor_id",
            label="Actor ID",
            value=actor_id,
            placeholder="operator_123",
        ),
        _filter(
            name="actor_type",
            label="Actor Type",
            value=actor_type,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Operator", "value": "operator"},
                {"label": "Admin", "value": "admin"},
                {"label": "Customer", "value": "customer"},
                {"label": "Service", "value": "service"},
                {"label": "System", "value": "system"},
            ],
        ),
        _filter(
            name="action",
            label="Action",
            value=action,
            placeholder="customer_key.rotate",
        ),
        _filter(
            name="resource_type",
            label="Resource Type",
            value=resource_type,
            placeholder="customer_key",
        ),
        _filter(
            name="resource_id",
            label="Resource ID",
            value=resource_id,
            placeholder="ck_001",
        ),
        _filter(
            name="outcome",
            label="Outcome",
            value=outcome,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Success", "value": "success"},
                {"label": "Denied", "value": "denied"},
                {"label": "Error", "value": "error"},
                {"label": "Warning", "value": "warning"},
            ],
        ),
        _filter(
            name="severity",
            label="Severity",
            value=severity,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Info", "value": "info"},
                {"label": "Warning", "value": "warning"},
                {"label": "High", "value": "high"},
                {"label": "Critical", "value": "critical"},
            ],
        ),
    ]

    metrics = [
        _metric(
            id="total_events",
            label="Total Audit Events",
            value=94,
            tone="neutral",
            trend="+9%",
            help_text="Total audit events recorded during the selected reporting period.",
        ),
        _metric(
            id="privileged_actions",
            label="Privileged Actions",
            value=11,
            tone="warning",
            trend="+2",
            help_text="High-impact administrative or security-sensitive actions.",
        ),
        _metric(
            id="denied_actions",
            label="Denied Actions",
            value=4,
            tone="positive",
            trend="-1",
            help_text="Blocked actions prevented by authorization or policy controls.",
        ),
        _metric(
            id="critical_events",
            label="Critical Events",
            value=1,
            tone="warning",
            trend="0",
            help_text="Events requiring immediate operator or compliance review.",
        ),
    ]

    sections = [
        _section(
            id="audit-posture",
            title="Audit Posture",
            description="High-level properties of audit visibility and operator accountability.",
            items=[
                _item(
                    label="Audit Logging",
                    value="enabled",
                    tone="positive",
                    help_text="Security-relevant actions are persisted into the audit trail.",
                ),
                _item(
                    label="Actor Correlation",
                    value="active",
                    tone="positive",
                    help_text="Audit records retain actor identity for investigation and accountability.",
                ),
                _item(
                    label="Retention Policy",
                    value="configured",
                    tone="positive",
                    help_text="Audit data retention is expected to be governed by retention controls.",
                ),
                _item(
                    label="Investigation Drilldown",
                    value="available",
                    tone="neutral",
                    help_text="Operators can pivot from audit records into related detail pages.",
                ),
            ],
        ),
        _section(
            id="current-scope",
            title="Current Scope",
            description="The active filter and review context applied to this audit log view.",
            items=[
                _item(label="Actor ID", value=effective_actor_id),
                _item(label="Actor Type", value=effective_actor_type),
                _item(label="Period", value=period),
                _item(
                    label="Outcome Filter",
                    value=outcome or "any",
                ),
                _item(
                    label="Severity Filter",
                    value=severity or "any",
                ),
            ],
        ),
    ]

    columns = [
        _column(key="timestamp", label="Timestamp"),
        _column(key="event_id", label="Event ID"),
        _column(key="actor_id", label="Actor ID"),
        _column(key="actor_type", label="Actor Type"),
        _column(key="action", label="Action"),
        _column(key="resource_type", label="Resource Type"),
        _column(key="resource_id", label="Resource ID"),
        _column(key="outcome", label="Outcome"),
        _column(key="severity", label="Severity"),
        _column(key="detail_path", label="Detail Path", kind="link"),
    ]

    rows = [
        _row(
            event_id="audit_001",
            timestamp="2026-04-23T18:10:00Z",
            actor_id=effective_actor_id,
            actor_type=effective_actor_type,
            action=action or "customer_key.rotate",
            resource_type=resource_type or "customer_key",
            resource_id=resource_id or "ck_001",
            outcome=outcome or "success",
            severity=severity or "warning",
            detail_path="/ui/uiauditlog/audit_001/detail",
        ),
        _row(
            event_id="audit_002",
            timestamp="2026-04-23T18:16:00Z",
            actor_id=effective_actor_id,
            actor_type=effective_actor_type,
            action="telemetry.read",
            resource_type="telemetry_event",
            resource_id="evt_002",
            outcome=outcome or "success",
            severity=severity or "info",
            detail_path="/ui/uiauditlog/audit_002/detail",
        ),
        _row(
            event_id="audit_003",
            timestamp="2026-04-23T18:22:00Z",
            actor_id="system",
            actor_type="system",
            action="policy.enforce",
            resource_type="request",
            resource_id="req_4421",
            outcome=outcome or "denied",
            severity=severity or "high",
            detail_path="/ui/uiauditlog/audit_003/detail",
        ),
    ]

    payload = {
        "page": "ui-audit-log",
        "title": "Audit Log",
        "summary": "Review operator, admin, customer, and system actions with filterable audit visibility.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "table": {
            "title": "Audit Events",
            "columns": columns,
            "rows": rows,
            "empty_state": {
                "title": "No audit events found",
                "description": "Adjust your filters or widen the reporting period to inspect more events.",
            },
        },
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "actor_id": actor_id,
                    "actor_type": actor_type,
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "outcome": outcome,
                    "severity": severity,
                    "period": period,
                },
                "description": "Reload the audit log using the active review filters.",
            },
            {
                "id": "open-customer-keys",
                "title": "Open customer keys",
                "method": "GET",
                "path": "/ui/customerkeys",
                "description": "Pivot into customer key management after reviewing related audit activity.",
            },
            {
                "id": "open-telemetry-access-summary",
                "title": "Open telemetry access summary",
                "method": "GET",
                "path": "/ui/telemetryaccesssummary",
                "query": {
                    "period": period,
                },
                "description": "Pivot into telemetry access posture from audit review workflows.",
            },
            {
                "id": "open-usage-reports",
                "title": "Open usage reports",
                "method": "GET",
                "path": "/ui/usagereports",
                "query": {
                    "period": period,
                },
                "description": "Compare audit actions with metered usage and event-level activity.",
            },
        ],
    }
    return payload


def build_audit_log_page(
    *,
    selected_event_id: str | None = None,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    filter_values = filters or {}
    payload = ui_audit_log_page(
        actor_id=filter_values.get("actor_id"),
        actor_type=filter_values.get("actor_type"),
        action=filter_values.get("action") or filter_values.get("event_type"),
        resource_type=filter_values.get("resource_type"),
        resource_id=filter_values.get("resource_id"),
        outcome=filter_values.get("verdict") or filter_values.get("outcome"),
        severity=filter_values.get("severity"),
        period=str(filter_values.get("period") or "24h"),
    )

    if selected_event_id and isinstance(payload.get("table"), dict):
        rows = payload["table"].get("rows", [])
        if rows:
            payload["table"]["rows"] = [row for row in rows if row.get("event_id") == selected_event_id] or rows

    return payload
