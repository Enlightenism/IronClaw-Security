from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import require_api_key

router = APIRouter(tags=["ui-pages"])


def _pages() -> list[dict[str, str]]:
    return [
        {
            "id": "activity-client-profile",
            "slug": "activity-client-profile",
            "title": "Client Profile",
            "group": "activity",
            "path": "/ui/activity/client-profile",
        },
        {
            "id": "activity-client-sessions",
            "slug": "activity-client-sessions",
            "title": "Client Sessions",
            "group": "activity",
            "path": "/ui/activity/client-sessions",
        },
        {
            "id": "activity-session-timeline",
            "slug": "activity-session-timeline",
            "title": "Session Timeline",
            "group": "activity",
            "path": "/ui/activity/session-timeline",
        },
        {
            "id": "admin-operators",
            "slug": "admin-operators",
            "title": "Operators",
            "group": "admin",
            "path": "/ui/admin/operators",
        },
        {
            "id": "admin-roles",
            "slug": "admin-roles",
            "title": "Roles",
            "group": "admin",
            "path": "/ui/admin/roles",
        },
        {
            "id": "alerts-notifications",
            "slug": "alerts-notifications",
            "title": "Notifications",
            "group": "alerts",
            "path": "/ui/alerts/notifications",
        },
        {
            "id": "audit-log",
            "slug": "audit-log",
            "title": "Audit Log",
            "group": "audit",
            "path": "/ui/audit/log",
        },
        {
            "id": "billing-index",
            "slug": "billing-index",
            "title": "Billing Index",
            "group": "billing",
            "path": "/ui/billing/index",
        },
        {
            "id": "billing-manifest",
            "slug": "billing-manifest",
            "title": "Billing Manifest",
            "group": "billing",
            "path": "/ui/billing/manifest",
        },
        {
            "id": "billing-packages",
            "slug": "billing-packages",
            "title": "Billing Packages",
            "group": "billing",
            "path": "/ui/billing/packages",
        },
        {
            "id": "billing-registry",
            "slug": "billing-registry",
            "title": "Billing Registry",
            "group": "billing",
            "path": "/ui/billing/registry",
        },
        {
            "id": "billing-summary",
            "slug": "billing-summary",
            "title": "Billing Summary",
            "group": "billing",
            "path": "/ui/billing/summary",
        },
        {
            "id": "data-retention",
            "slug": "data-retention",
            "title": "Data Retention",
            "group": "data",
            "path": "/ui/data/retention",
        },
        {
            "id": "executions-dashboard",
            "slug": "executions-dashboard",
            "title": "Execution Dashboard",
            "group": "executions",
            "path": "/ui/executions/dashboard",
        },
        {
            "id": "executions-detail",
            "slug": "executions-detail",
            "title": "Execution Detail",
            "group": "executions",
            "path": "/ui/executions/detail",
        },
        {
            "id": "executions-explorer",
            "slug": "executions-explorer",
            "title": "Execution Explorer",
            "group": "executions",
            "path": "/ui/executions/explorer",
        },
        {
            "id": "executions-test-console",
            "slug": "executions-test-console",
            "title": "Execution Test Console",
            "group": "executions",
            "path": "/ui/executions/test-console",
        },
        {
            "id": "groq",
            "slug": "groq",
            "title": "Groq",
            "group": "groq",
            "path": "/ui/groq",
        },
        {
            "id": "incidents-triage",
            "slug": "incidents-triage",
            "title": "Incident Triage",
            "group": "incidents",
            "path": "/ui/incidents/triage",
        },
        {
            "id": "insights-policy",
            "slug": "insights-policy",
            "title": "Policy Insights",
            "group": "insights",
            "path": "/ui/insights/policy",
        },
        {
            "id": "integrations-settings",
            "slug": "integrations-settings",
            "title": "Integration Settings",
            "group": "integrations",
            "path": "/ui/integrations/settings",
        },
        {
            "id": "reviews-detail",
            "slug": "reviews-detail",
            "title": "Review Detail",
            "group": "reviews",
            "path": "/ui/reviews/detail",
        },
        {
            "id": "reviews-queue",
            "slug": "reviews-queue",
            "title": "Review Queue",
            "group": "reviews",
            "path": "/ui/reviews/queue",
        },
        {
            "id": "runtime-status",
            "slug": "runtime-status",
            "title": "Runtime Status",
            "group": "runtime",
            "path": "/ui/runtime/status",
        },
        {
            "id": "settings-configuration",
            "slug": "settings-configuration",
            "title": "Settings Configuration",
            "group": "settings",
            "path": "/ui/settings/configuration",
        },
        {
            "id": "system-diagnostics",
            "slug": "system-diagnostics",
            "title": "System Diagnostics",
            "group": "system",
            "path": "/ui/system/diagnostics",
        },
    ]


@router.get("/ui/pages", dependencies=[Depends(require_api_key)])
def list_ui_pages() -> list[dict[str, str]]:
    return _pages()