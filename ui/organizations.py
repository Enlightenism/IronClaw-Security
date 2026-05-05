from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/organizations", tags=["ui-organizations"])


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


def _organization_row(
    *,
    organization_id: str,
    name: str,
    slug: str,
    status: str,
    plan: str,
    member_count: int,
    key_count: int,
) -> dict[str, Any]:
    return {
        "organization_id": organization_id,
        "name": name,
        "slug": slug,
        "status": status,
        "plan": plan,
        "member_count": member_count,
        "key_count": key_count,
        "detail_path": f"/ui/organizations?organization_id={organization_id}",
    }


@router.get("")
def ui_organizations_page(
    status: str | None = Query(default=None),
    plan: str | None = Query(default=None),
    search: str | None = Query(default=None),
    period: str = Query(default="30d"),
) -> dict[str, Any]:
    filters = [
        _filter(
            name="status",
            label="Status",
            value=status,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Active", "value": "active"},
                {"label": "Pending", "value": "pending"},
                {"label": "Suspended", "value": "suspended"},
                {"label": "Disabled", "value": "disabled"},
            ],
        ),
        _filter(
            name="plan",
            label="Plan",
            value=plan,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Starter", "value": "starter"},
                {"label": "Growth", "value": "growth"},
                {"label": "Enterprise", "value": "enterprise"},
            ],
        ),
        _filter(
            name="search",
            label="Search",
            value=search,
            placeholder="acme-security",
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
            id="total_organizations",
            label="Organizations",
            value=14,
            tone="neutral",
            trend="+2",
            help_text="Organizations currently managed by the platform.",
        ),
        _metric(
            id="active_organizations",
            label="Active Organizations",
            value=12,
            tone="positive",
            trend="+1",
            help_text="Organizations in an active and usable state.",
        ),
        _metric(
            id="enterprise_accounts",
            label="Enterprise Accounts",
            value=3,
            tone="positive",
            trend="+1",
            help_text="Organizations on the enterprise plan tier.",
        ),
        _metric(
            id="pending_onboarding",
            label="Pending Onboarding",
            value=2,
            tone="warning",
            trend="0",
            help_text="Organizations still in onboarding or awaiting final setup.",
        ),
    ]

    sections = [
        _section(
            id="organization-posture",
            title="Organization Posture",
            description="High-level view of tenant readiness and administrative state.",
            items=[
                _item(
                    label="Tenant Isolation",
                    value="enabled",
                    tone="positive",
                    help_text="Organizations are expected to be isolated by tenant boundaries.",
                ),
                _item(
                    label="Onboarding Flow",
                    value="available",
                    tone="positive",
                    help_text="New organizations can proceed through onboarding and setup workflows.",
                ),
                _item(
                    label="Plan Management",
                    value="tracked",
                    tone="neutral",
                    help_text="Subscription and entitlement plan context is visible to operators.",
                ),
                _item(
                    label="Administrative Coverage",
                    value="partial",
                    tone="warning",
                    help_text="Additional organization and tenant tooling may still need completion.",
                ),
            ],
        ),
        _section(
            id="operator-guidance",
            title="Operator Guidance",
            description="Suggested checks when reviewing tenant setup and account posture.",
            items=[
                _item(
                    label="Verify Organization Status",
                    value="recommended",
                    tone="neutral",
                    help_text="Confirm the organization is in the correct lifecycle state before enabling access.",
                ),
                _item(
                    label="Review Key Ownership",
                    value="recommended",
                    tone="neutral",
                    help_text="Check customer key posture before finalizing onboarding or changes.",
                ),
                _item(
                    label="Inspect Audit Trail",
                    value="recommended",
                    tone="neutral",
                    help_text="Use audit views to review organization admin actions and provisioning changes.",
                ),
                _item(
                    label="Escalate Suspensions",
                    value="required",
                    tone="warning",
                    help_text="Suspended or disabled organizations should be reviewed before reactivation.",
                ),
            ],
        ),
    ]

    organization_columns = [
        {"key": "organization_id", "label": "Organization ID", "kind": "text"},
        {"key": "name", "label": "Name", "kind": "text"},
        {"key": "slug", "label": "Slug", "kind": "text"},
        {"key": "status", "label": "Status", "kind": "text"},
        {"key": "plan", "label": "Plan", "kind": "text"},
        {"key": "member_count", "label": "Members", "kind": "number"},
        {"key": "key_count", "label": "API Keys", "kind": "number"},
        {"key": "detail_path", "label": "Detail Path", "kind": "link"},
    ]

    organization_rows = [
        _organization_row(
            organization_id="org_001",
            name="Acme Security",
            slug=search or "acme-security",
            status=status or "active",
            plan=plan or "enterprise",
            member_count=18,
            key_count=7,
        ),
        _organization_row(
            organization_id="org_002",
            name="Northwind Labs",
            slug="northwind-labs",
            status=status or "pending",
            plan=plan or "growth",
            member_count=6,
            key_count=2,
        ),
        _organization_row(
            organization_id="org_003",
            name="Red Mesa Systems",
            slug="red-mesa-systems",
            status=status or "suspended",
            plan=plan or "starter",
            member_count=4,
            key_count=1,
        ),
    ]

    return {
        "page": "ui-organizations",
        "title": "Organizations",
        "summary": "Review tenant posture, onboarding status, and administrative organization context across IronClaw.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "tables": [
            {
                "id": "organizations",
                "title": "Organizations",
                "columns": organization_columns,
                "rows": organization_rows,
                "empty_state": {
                    "title": "No organizations found",
                    "description": "Adjust your filters or search criteria to inspect different tenants.",
                },
            }
        ],
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh organizations",
                "method": "GET",
                "path": "/ui/organizations",
                "query": {
                    "status": status,
                    "plan": plan,
                    "search": search,
                    "period": period,
                },
                "description": "Reload organization data using the active filters.",
            },
            {
                "id": "open-customer-keys",
                "title": "Open customer keys",
                "method": "GET",
                "path": "/ui/customerkeys",
                "description": "Inspect tenant API key posture for the selected organization context.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Review organization-related administrative and security events.",
            },
            {
                "id": "open-data-retention",
                "title": "Open data retention",
                "method": "GET",
                "path": "/ui/uidataretention",
                "query": {
                    "period": period,
                },
                "description": "Inspect retention posture for organization-linked resources and records.",
            },
        ],
    }