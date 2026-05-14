from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/uiadminroles", tags=["ui-admin-roles"])


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


def _role_row(
    *,
    role_id: str,
    name: str,
    scope: str,
    status: str,
    member_count: int,
    permission_count: int,
    risk_level: str,
) -> dict[str, Any]:
    return {
        "role_id": role_id,
        "name": name,
        "scope": scope,
        "status": status,
        "member_count": member_count,
        "permission_count": permission_count,
        "risk_level": risk_level,
        "detail_path": f"/ui/uiadminroles?role_id={role_id}",
    }


@router.get("")
def ui_admin_roles_page(
    scope: str | None = Query(default=None),
    status: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    search: str | None = Query(default=None),
    period: str = Query(default="30d"),
) -> dict[str, Any]:
    effective_scope = scope or "platform"

    filters = [
        _filter(
            name="scope",
            label="Scope",
            value=scope,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Platform", "value": "platform"},
                {"label": "Operations", "value": "operations"},
                {"label": "Compliance", "value": "compliance"},
                {"label": "Customer Admin", "value": "customer-admin"},
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
                {"label": "Draft", "value": "draft"},
                {"label": "Disabled", "value": "disabled"},
            ],
        ),
        _filter(
            name="risk_level",
            label="Risk Level",
            value=risk_level,
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
            name="search",
            label="Search",
            value=search,
            placeholder="admin",
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
            id="total_roles",
            label="Roles",
            value=8,
            tone="neutral",
            trend="+1",
            help_text="Role definitions currently tracked in the administrative surface.",
        ),
        _metric(
            id="active_roles",
            label="Active Roles",
            value=6,
            tone="positive",
            trend="+1",
            help_text="Roles currently available for assignment and enforcement.",
        ),
        _metric(
            id="high_privilege_roles",
            label="High Privilege Roles",
            value=2,
            tone="warning",
            trend="0",
            help_text="Roles with broad permissions that require tighter review.",
        ),
        _metric(
            id="permission_sets",
            label="Permission Sets",
            value=14,
            tone="neutral",
            trend="+2",
            help_text="Distinct permission groupings represented across role definitions.",
        ),
    ]

    sections = [
        _section(
            id="role-posture",
            title="Role Posture",
            description="High-level view of authorization model readiness and privilege structure.",
            items=[
                _item(
                    label="Scope Focus",
                    value=effective_scope,
                    tone="neutral",
                    help_text="Role scope emphasized in the current admin roles view.",
                ),
                _item(
                    label="Role Enforcement",
                    value="enabled",
                    tone="positive",
                    help_text="Roles are expected to influence authorization and UI access boundaries.",
                ),
                _item(
                    label="Permission Review",
                    value="recommended",
                    tone="warning",
                    help_text="High-impact roles should be reviewed regularly for least-privilege fit.",
                ),
                _item(
                    label="Assignment Visibility",
                    value="available",
                    tone="positive",
                    help_text="Role counts and assignment posture are visible to administrators.",
                ),
            ],
        ),
        _section(
            id="admin-guidance",
            title="Admin Guidance",
            description="Suggested checks when reviewing role definitions and privilege posture.",
            items=[
                _item(
                    label="Review High Privilege Roles",
                    value="recommended",
                    tone="neutral",
                    help_text="Confirm powerful roles still match operational need and least-privilege goals.",
                ),
                _item(
                    label="Check Member Coverage",
                    value="recommended",
                    tone="neutral",
                    help_text="Verify the right operators and admins hold each role assignment.",
                ),
                _item(
                    label="Inspect Audit Trail",
                    value="recommended",
                    tone="neutral",
                    help_text="Review administrative changes affecting role definitions or assignments.",
                ),
                _item(
                    label="Escalate Critical Drift",
                    value="required",
                    tone="warning",
                    help_text="Unexpected role or permission changes should be escalated quickly.",
                ),
            ],
        ),
    ]

    role_columns = [
        {"key": "role_id", "label": "Role ID", "kind": "text"},
        {"key": "name", "label": "Name", "kind": "text"},
        {"key": "scope", "label": "Scope", "kind": "text"},
        {"key": "status", "label": "Status", "kind": "text"},
        {"key": "member_count", "label": "Members", "kind": "number"},
        {"key": "permission_count", "label": "Permissions", "kind": "number"},
        {"key": "risk_level", "label": "Risk Level", "kind": "text"},
        {"key": "detail_path", "label": "Detail Path", "kind": "link"},
    ]

    role_rows = [
        _role_row(
            role_id="role_001",
            name=search or "platform-admin",
            scope=scope or "platform",
            status=status or "active",
            member_count=2,
            permission_count=18,
            risk_level=risk_level or "critical",
        ),
        _role_row(
            role_id="role_002",
            name="incident-operator",
            scope=scope or "operations",
            status=status or "active",
            member_count=4,
            permission_count=9,
            risk_level=risk_level or "high",
        ),
        _role_row(
            role_id="role_003",
            name="compliance-reviewer",
            scope=scope or "compliance",
            status=status or "draft",
            member_count=1,
            permission_count=6,
            risk_level=risk_level or "medium",
        ),
    ]

    return {
        "page": "ui-admin-roles",
        "title": "Admin Roles",
        "summary": "Review role definitions, privilege posture, and administrative authorization structure across IronClaw.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "tables": [
            {
                "id": "roles",
                "title": "Role Definitions",
                "columns": role_columns,
                "rows": role_rows,
                "empty_state": {
                    "title": "No roles found",
                    "description": "Adjust your filters or search criteria to inspect different role definitions.",
                },
            },
        ],
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh roles",
                "method": "GET",
                "path": "/ui/uiadminroles",
                "query": {
                    "scope": scope,
                    "status": status,
                    "risk_level": risk_level,
                    "search": search,
                    "period": period,
                },
                "description": "Reload role posture using the active administrative filters.",
            },
            {
                "id": "open-admin-operators",
                "title": "Open admin operators",
                "method": "GET",
                "path": "/ui/uiadminoperators",
                "query": {
                    "period": period,
                },
                "description": "Inspect operator accounts that may hold the selected role definitions.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Inspect administrative actions related to role changes and privilege review.",
            },
            {
                "id": "open-organizations",
                "title": "Open organizations",
                "method": "GET",
                "path": "/ui/organizations",
                "query": {
                    "period": period,
                },
                "description": "Compare role structure with tenant and organization administrative posture.",
            },
        ],
    }
