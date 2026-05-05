from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter(prefix="/ui/uimanifest", tags=["ui-manifest"])


def _page(
    *,
    page_id: str,
    title: str,
    path: str,
    category: str,
    summary: str,
    status: str = "available",
    related_paths: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "page_id": page_id,
        "title": title,
        "path": path,
        "category": category,
        "summary": summary,
        "status": status,
        "related_paths": related_paths or [],
    }


@router.get("")
def ui_manifest_page() -> dict[str, Any]:
    pages = [
        _page(
            page_id="customer-keys",
            title="Customer Keys",
            path="/ui/customerkeys",
            category="access",
            summary="Customer API key lifecycle management and visibility.",
            related_paths=["/ui/customerkeydetail", "/ui/organizations"],
        ),
        _page(
            page_id="customer-key-detail",
            title="Customer Key Detail",
            path="/ui/customerkeydetail",
            category="access",
            summary="Detailed customer key metadata, status, and rotation context.",
            related_paths=["/ui/customerkeys", "/ui/uiauditlog"],
        ),
        _page(
            page_id="request-context",
            title="Request Context",
            path="/ui/requestcontext",
            category="analysis",
            summary="Build and inspect request metadata for guarded actions and history-aware decisions.",
            related_paths=["/ui/sessionrisk", "/ui/usagereports"],
        ),
        _page(
            page_id="session-risk",
            title="Session Risk",
            path="/ui/sessionrisk",
            category="analysis",
            summary="Review per-session risk posture, signals, and escalation pivots.",
            related_paths=["/ui/requestcontext", "/ui/uiincidenttriage"],
        ),
        _page(
            page_id="usage-reports",
            title="Usage Reports",
            path="/ui/usagereports",
            category="observability",
            summary="Inspect metered usage, verdicts, and event-level drilldowns.",
            related_paths=["/ui/usageevents/{event_id}/detail", "/ui/telemetryaccesssummary"],
        ),
        _page(
            page_id="usage-event-detail",
            title="Usage Event Detail",
            path="/ui/usageevents/{event_id}/detail",
            category="observability",
            summary="Inspect a single usage or telemetry event and its security context.",
            related_paths=["/ui/usagereports", "/ui/requestcontext"],
        ),
        _page(
            page_id="telemetry-access-summary",
            title="Telemetry Access Summary",
            path="/ui/telemetryaccesssummary",
            category="observability",
            summary="Operator view into telemetry access posture and summary trends.",
            related_paths=["/ui/usagereports", "/ui/uiauditlog"],
        ),
        _page(
            page_id="audit-log",
            title="Audit Log",
            path="/ui/uiauditlog",
            category="observability",
            summary="Review actor, operator, customer, and system audit activity.",
            related_paths=["/ui/usagereports", "/ui/uiadminroles"],
        ),
        _page(
            page_id="incident-triage",
            title="Incident Triage",
            path="/ui/uiincidenttriage",
            category="operations",
            summary="Review incident queue posture, severity, and investigation pivots.",
            related_paths=["/ui/review", "/quarantine/overview"],
        ),
        _page(
            page_id="review-queue",
            title="Review Queue",
            path="/ui/review",
            category="operations",
            summary="Inspect queued human review items and escalation workflows.",
            related_paths=["/ui/uiincidenttriage", "/ui/uiauditlog"],
        ),
        _page(
            page_id="quarantine-overview",
            title="Quarantine Overview",
            path="/quarantine/overview",
            category="operations",
            summary="Review isolated artifacts, containment state, and disposition posture.",
            related_paths=["/ui/review", "/ui/uidataretention"],
        ),
        _page(
            page_id="system-diagnostics",
            title="System Diagnostics",
            path="/ui/uisystemdiagnostics",
            category="platform",
            summary="Review health, controls, and operator-facing diagnostic posture.",
            related_paths=["/ui/uiruntimestatus", "/ui/uiauditlog"],
        ),
        _page(
            page_id="runtime-status",
            title="Runtime Status",
            path="/ui/uiruntimestatus",
            category="platform",
            summary="Inspect worker posture, sandbox readiness, and runtime control state.",
            related_paths=["/ui/uisystemdiagnostics", "/quarantine/overview"],
        ),
        _page(
            page_id="data-retention",
            title="Data Retention",
            path="/ui/uidataretention",
            category="governance",
            summary="Review retention policies, disposition posture, and governance guidance.",
            related_paths=["/quarantine/overview", "/ui/uiauditlog"],
        ),
        _page(
            page_id="organizations",
            title="Organizations",
            path="/ui/organizations",
            category="administration",
            summary="Review tenant posture, onboarding status, and organization state.",
            related_paths=["/ui/customerkeys", "/ui/uiadminoperators"],
        ),
        _page(
            page_id="admin-operators",
            title="Admin Operators",
            path="/ui/uiadminoperators",
            category="administration",
            summary="Review operator accounts, staffing posture, and queue assignments.",
            related_paths=["/ui/uiadminroles", "/ui/review"],
        ),
        _page(
            page_id="admin-roles",
            title="Admin Roles",
            path="/ui/uiadminroles",
            category="administration",
            summary="Review role definitions, privilege posture, and authorization structure.",
            related_paths=["/ui/uiadminoperators", "/ui/uiauditlog"],
        ),
        _page(
            page_id="docs-quickstart",
            title="Docs Quickstart",
            path="/ui/docs_quickstart",
            category="developer",
            summary="Follow the shortest secure onboarding path from API key to first guarded request.",
            related_paths=["/ui/customerkeys", "/ui/usagereports"],
        ),
    ]

    category_counts: dict[str, int] = {}
    for page in pages:
        category = str(page["category"])
        category_counts[category] = category_counts.get(category, 0) + 1

    navigation_groups = [
        {
            "id": "access",
            "title": "Access",
            "pages": [page["page_id"] for page in pages if page["category"] == "access"],
        },
        {
            "id": "analysis",
            "title": "Analysis",
            "pages": [page["page_id"] for page in pages if page["category"] == "analysis"],
        },
        {
            "id": "observability",
            "title": "Observability",
            "pages": [page["page_id"] for page in pages if page["category"] == "observability"],
        },
        {
            "id": "operations",
            "title": "Operations",
            "pages": [page["page_id"] for page in pages if page["category"] == "operations"],
        },
        {
            "id": "platform",
            "title": "Platform",
            "pages": [page["page_id"] for page in pages if page["category"] == "platform"],
        },
        {
            "id": "governance",
            "title": "Governance",
            "pages": [page["page_id"] for page in pages if page["category"] == "governance"],
        },
        {
            "id": "administration",
            "title": "Administration",
            "pages": [page["page_id"] for page in pages if page["category"] == "administration"],
        },
        {
            "id": "developer",
            "title": "Developer",
            "pages": [page["page_id"] for page in pages if page["category"] == "developer"],
        },
    ]

    return {
        "page": "ui-manifest",
        "title": "UI Manifest",
        "summary": "Registry of current IronClaw UI metadata surfaces, grouped for navigation and page discovery.",
        "metrics": [
            {
                "id": "registered_pages",
                "label": "Registered Pages",
                "value": len(pages),
                "tone": "positive",
                "help_text": "UI pages currently included in the manifest registry.",
            },
            {
                "id": "navigation_groups",
                "label": "Navigation Groups",
                "value": len(navigation_groups),
                "tone": "neutral",
                "help_text": "High-level navigation groupings generated from page categories.",
            },
        ],
        "category_counts": category_counts,
        "navigation_groups": navigation_groups,
        "pages": pages,
        "actions": [
            {
                "id": "open-organizations",
                "title": "Open organizations",
                "method": "GET",
                "path": "/ui/organizations",
                "description": "Jump to tenant and organization administration surfaces.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "description": "Jump to audit visibility and operational investigation.",
            },
            {
                "id": "open-docs-quickstart",
                "title": "Open docs quickstart",
                "method": "GET",
                "path": "/ui/docs_quickstart",
                "description": "Jump to the developer onboarding and first-use surface.",
            },
        ],
    }