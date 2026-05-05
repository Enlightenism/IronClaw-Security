from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/uiadminoperators", tags=["ui-admin-operators"])


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


def _operator_row(
    *,
    operator_id: str,
    display_name: str,
    email: str,
    role: str,
    status: str,
    last_seen: str,
    assigned_queue: str,
) -> dict[str, Any]:
    return {
        "operator_id": operator_id,
        "display_name": display_name,
        "email": email,
        "role": role,
        "status": status,
        "last_seen": last_seen,
        "assigned_queue": assigned_queue,
        "detail_path": f"/ui/uiadminoperators?operator_id={operator_id}",
    }


@router.get("")
def ui_admin_operators_page(
    role: str | None = Query(default=None),
    status: str | None = Query(default=None),
    assigned_queue: str | None = Query(default=None),
    search: str | None = Query(default=None),
    period: str = Query(default="30d"),
) -> dict[str, Any]:
    effective_queue = assigned_queue or "human-review"

    filters = [
        _filter(
            name="role",
            label="Role",
            value=role,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Operator", "value": "operator"},
                {"label": "Senior Operator", "value": "senior-operator"},
                {"label": "Admin", "value": "admin"},
                {"label": "Compliance", "value": "compliance"},
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
                {"label": "Invited", "value": "invited"},
                {"label": "Suspended", "value": "suspended"},
                {"label": "Disabled", "value": "disabled"},
            ],
        ),
        _filter(
            name="assigned_queue",
            label="Assigned Queue",
            value=assigned_queue,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Human Review", "value": "human-review"},
                {"label": "Incident Triage", "value": "incident-triage"},
                {"label": "Quarantine", "value": "quarantine"},
                {"label": "Audit", "value": "audit"},
            ],
        ),
        _filter(
            name="search",
            label="Search",
            value=search,
            placeholder="alex",
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
            id="total_operators",
            label="Operators",
            value=11,
            tone="neutral",
            trend="+1",
            help_text="Administrative and operational accounts currently tracked by the platform.",
        ),
        _metric(
            id="active_operators",
            label="Active Operators",
            value=9,
            tone="positive",
            trend="+1",
            help_text="Operators in an active and usable state.",
        ),
        _metric(
            id="admin_accounts",
            label="Admin Accounts",
            value=2,
            tone="neutral",
            trend="0",
            help_text="Accounts with elevated administrative permissions.",
        ),
        _metric(
            id="queue_coverage",
            label="Queue Coverage",
            value="good",
            tone="positive",
            trend="stable",
            help_text="Current operator staffing coverage across major review queues.",
        ),
    ]

    sections = [
        _section(
            id="operator-posture",
            title="Operator Posture",
            description="High-level administrative view of operator account readiness and assignment coverage.",
            items=[
                _item(
                    label="Assigned Queue Focus",
                    value=effective_queue,
                    tone="neutral",
                    help_text="Queue emphasized by the current admin operator view.",
                ),
                _item(
                    label="Role Enforcement",
                    value="enabled",
                    tone="positive",
                    help_text="Administrative access is expected to be controlled by role-aware authorization.",
                ),
                _item(
                    label="Account Lifecycle",
                    value="tracked",
                    tone="positive",
                    help_text="Invitation, activation, suspension, and disablement states are visible.",
                ),
                _item(
                    label="Operational Coverage",
                    value="available",
                    tone="positive",
                    help_text="Review, incident, quarantine, and audit queues can be assigned to operators.",
                ),
            ],
        ),
        _section(
            id="admin-guidance",
            title="Admin Guidance",
            description="Suggested checks when reviewing operator accounts and administrative posture.",
            items=[
                _item(
                    label="Verify Role Assignment",
                    value="recommended",
                    tone="neutral",
                    help_text="Confirm each operator has the minimum necessary role for their workflow.",
                ),
                _item(
                    label="Review Queue Placement",
                    value="recommended",
                    tone="neutral",
                    help_text="Ensure operators are assigned to the correct review and triage queues.",
                ),
                _item(
                    label="Check Audit Trail",
                    value="recommended",
                    tone="neutral",
                    help_text="Inspect administrative actions for changes to operator status or permissions.",
                ),
                _item(
                    label="Escalate Suspicious Access",
                    value="required",
                    tone="warning",
                    help_text="Unexpected role changes or operator activity should be escalated promptly.",
                ),
            ],
        ),
    ]

    operator_columns = [
        {"key": "operator_id", "label": "Operator ID", "kind": "text"},
        {"key": "display_name", "label": "Display Name", "kind": "text"},
        {"key": "email", "label": "Email", "kind": "text"},
        {"key": "role", "label": "Role", "kind": "text"},
        {"key": "status", "label": "Status", "kind": "text"},
        {"key": "last_seen", "label": "Last Seen", "kind": "text"},
        {"key": "assigned_queue", "label": "Assigned Queue", "kind": "text"},
        {"key": "detail_path", "label": "Detail Path", "kind": "link"},
    ]

    operator_rows = [
        _operator_row(
            operator_id="op_001",
            display_name=search or "Alex Carter",
            email="alex@ironclaw.local",
            role=role or "admin",
            status=status or "active",
            last_seen="2026-04-23T19:20:00Z",
            assigned_queue=effective_queue,
        ),
        _operator_row(
            operator_id="op_002",
            display_name="Maya Chen",
            email="maya@ironclaw.local",
            role=role or "senior-operator",
            status=status or "active",
            last_seen="2026-04-23T18:58:00Z",
            assigned_queue=effective_queue,
        ),
        _operator_row(
            operator_id="op_003",
            display_name="Jordan Reyes",
            email="jordan@ironclaw.local",
            role=role or "operator",
            status=status or "invited",
            last_seen="2026-04-22T14:10:00Z",
            assigned_queue=effective_queue,
        ),
    ]

    return {
        "page": "ui-admin-operators",
        "title": "Admin Operators",
        "summary": "Review operator accounts, administrative role posture, and queue assignments across IronClaw.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "tables": [
            {
                "id": "operators",
                "title": "Operator Accounts",
                "columns": operator_columns,
                "rows": operator_rows,
                "empty_state": {
                    "title": "No operators found",
                    "description": "Adjust your filters or search criteria to inspect different operator accounts.",
                },
            }
        ],
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh operators",
                "method": "GET",
                "path": "/ui/uiadminoperators",
                "query": {
                    "role": role,
                    "status": status,
                    "assigned_queue": assigned_queue,
                    "search": search,
                    "period": period,
                },
                "description": "Reload operator account posture using the active admin filters.",
            },
            {
                "id": "open-review-queue",
                "title": "Open review queue",
                "method": "GET",
                "path": "/ui/review",
                "query": {
                    "queue": effective_queue,
                    "period": period,
                },
                "description": "Inspect the operational queue currently assigned to this operator context.",
            },
            {
                "id": "open-incident-triage",
                "title": "Open incident triage",
                "method": "GET",
                "path": "/ui/uiincidenttriage",
                "query": {
                    "queue": effective_queue,
                    "period": period,
                },
                "description": "Compare operator coverage with active incident triage workload.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Inspect operator and administrative actions in the audit trail.",
            },
        ],
    }