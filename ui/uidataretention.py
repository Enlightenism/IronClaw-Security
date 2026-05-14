from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/uidataretention", tags=["ui-data-retention"])


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


def _policy_row(
    *,
    policy_id: str,
    resource_type: str,
    retention_days: int,
    disposition: str,
    scope: str,
    status: str,
) -> dict[str, Any]:
    return {
        "policy_id": policy_id,
        "resource_type": resource_type,
        "retention_days": retention_days,
        "disposition": disposition,
        "scope": scope,
        "status": status,
        "detail_path": f"/ui/uidataretention?policy_id={policy_id}",
    }


@router.get("")
def ui_data_retention_page(
    scope: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    period: str = Query(default="30d"),
) -> dict[str, Any]:
    effective_scope = scope or "global"

    filters = [
        _filter(
            name="scope",
            label="Scope",
            value=scope,
            field_type="select",
            options=[
                {"label": "Global", "value": "global"},
                {"label": "Customer", "value": "customer"},
                {"label": "Operator", "value": "operator"},
                {"label": "Quarantine", "value": "quarantine"},
            ],
        ),
        _filter(
            name="resource_type",
            label="Resource Type",
            value=resource_type,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Audit Events", "value": "audit-event"},
                {"label": "Telemetry Events", "value": "telemetry-event"},
                {"label": "Usage Events", "value": "usage-event"},
                {"label": "Quarantine Items", "value": "quarantine-item"},
                {"label": "Review Items", "value": "review-item"},
            ],
        ),
        _filter(
            name="status",
            label="Status",
            value=status,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Active", "value": "active"},
                {"label": "Scheduled", "value": "scheduled"},
                {"label": "Expired", "value": "expired"},
            ],
        ),
        _filter(
            name="period",
            label="Period",
            value=period,
            field_type="select",
            options=[
                {"label": "Last 30 days", "value": "30d"},
                {"label": "Last 90 days", "value": "90d"},
                {"label": "Last 365 days", "value": "365d"},
            ],
        ),
    ]

    metrics = [
        _metric(
            id="active_policies",
            label="Active Policies",
            value=6,
            tone="positive",
            trend="+1",
            help_text="Retention policies currently applied to system data classes.",
        ),
        _metric(
            id="resources_pending_disposition",
            label="Pending Disposition",
            value=18,
            tone="warning",
            trend="+3",
            help_text="Items nearing retention cutoff or awaiting scheduled disposition.",
        ),
        _metric(
            id="disposed_resources",
            label="Disposed Resources",
            value=47,
            tone="positive",
            trend="+9",
            help_text="Records deleted or retained according to policy in the selected period.",
        ),
        _metric(
            id="policy_exceptions",
            label="Policy Exceptions",
            value=1,
            tone="warning",
            trend="0",
            help_text="Resources with retention handling that may require manual review.",
        ),
    ]

    sections = [
        _section(
            id="retention-posture",
            title="Retention Posture",
            description="High-level status of retention governance and lifecycle handling.",
            items=[
                _item(
                    label="Scope",
                    value=effective_scope,
                    tone="neutral",
                    help_text="Current policy scope emphasized by this view.",
                ),
                _item(
                    label="Policy Enforcement",
                    value="enabled",
                    tone="positive",
                    help_text="Retention controls are expected to be active for covered resources.",
                ),
                _item(
                    label="Disposition Automation",
                    value="available",
                    tone="positive",
                    help_text="Eligible records can be scheduled for cleanup or archival handling.",
                ),
                _item(
                    label="Auditability",
                    value="tracked",
                    tone="positive",
                    help_text="Retention actions should remain reviewable through audit surfaces.",
                ),
            ],
        ),
        _section(
            id="operator-guidance",
            title="Operator Guidance",
            description="Suggested operator checks when reviewing retention state and drift.",
            items=[
                _item(
                    label="Verify Policy Scope",
                    value="recommended",
                    tone="neutral",
                    help_text="Confirm that retention policy coverage matches the resource type and tenancy context.",
                ),
                _item(
                    label="Review Quarantine Holds",
                    value="recommended",
                    tone="neutral",
                    help_text="Ensure quarantined or incident-linked records are not disposed prematurely.",
                ),
                _item(
                    label="Check Audit Trail",
                    value="recommended",
                    tone="neutral",
                    help_text="Use audit views to inspect when retention actions or overrides occurred.",
                ),
                _item(
                    label="Escalate Exceptions",
                    value="required",
                    tone="warning",
                    help_text="Retention exceptions should be reviewed before scheduled cleanup proceeds.",
                ),
            ],
        ),
    ]

    policy_columns = [
        {"key": "policy_id", "label": "Policy ID", "kind": "text"},
        {"key": "resource_type", "label": "Resource Type", "kind": "text"},
        {"key": "retention_days", "label": "Retention Days", "kind": "number"},
        {"key": "disposition", "label": "Disposition", "kind": "text"},
        {"key": "scope", "label": "Scope", "kind": "text"},
        {"key": "status", "label": "Status", "kind": "text"},
        {"key": "detail_path", "label": "Detail Path", "kind": "link"},
    ]

    policy_rows = [
        _policy_row(
            policy_id="ret_001",
            resource_type=resource_type or "audit-event",
            retention_days=365,
            disposition="delete",
            scope=effective_scope,
            status=status or "active",
        ),
        _policy_row(
            policy_id="ret_002",
            resource_type=resource_type or "telemetry-event",
            retention_days=90,
            disposition="archive",
            scope=effective_scope,
            status=status or "active",
        ),
        _policy_row(
            policy_id="ret_003",
            resource_type=resource_type or "quarantine-item",
            retention_days=180,
            disposition="manual-review",
            scope=effective_scope,
            status=status or "scheduled",
        ),
    ]

    return {
        "page": "ui-data-retention",
        "title": "Data Retention",
        "summary": "Review retention policies, disposition posture, and governance checks across IronClaw data classes.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "tables": [
            {
                "id": "retention-policies",
                "title": "Retention Policies",
                "columns": policy_columns,
                "rows": policy_rows,
                "empty_state": {
                    "title": "No retention policies found",
                    "description": "Adjust your filters to inspect a different scope or resource type.",
                },
            },
        ],
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh retention view",
                "method": "GET",
                "path": "/ui/uidataretention",
                "query": {
                    "scope": scope,
                    "resource_type": resource_type,
                    "status": status,
                    "period": period,
                },
                "description": "Reload retention posture using the active policy filters.",
            },
            {
                "id": "open-quarantine-overview",
                "title": "Open quarantine overview",
                "method": "GET",
                "path": "/quarantine/overview",
                "query": {
                    "period": period,
                },
                "description": "Check isolated artifacts before modifying retention behavior for sensitive items.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Inspect retention-related actions and overrides in the audit trail.",
            },
            {
                "id": "open-system-diagnostics",
                "title": "Open system diagnostics",
                "method": "GET",
                "path": "/ui/uisystemdiagnostics",
                "query": {
                    "period": period,
                },
                "description": "Review broader runtime posture if retention jobs or cleanup workers drift.",
            },
        ],
    }
