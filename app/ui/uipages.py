from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/pages",
    tags=["ui-pages"],
)


class UIPageItem(BaseModel):
    slug: str
    label: str
    route: str
    category: str
    summary: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class UIPageSection(BaseModel):
    category: str
    label: str
    total: int
    items: list[UIPageItem] = Field(default_factory=list)


class UIPageSummary(BaseModel):
    totalpages: int
    enabledpages: int
    categories: list[str] = Field(default_factory=list)


class UIPagesResponse(BaseModel):
    generatedat: str
    summary: UIPageSummary
    sections: list[UIPageSection] = Field(default_factory=list)
    items: list[UIPageItem] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_ui_pages() -> list[UIPageItem]:
    return [
        UIPageItem(
            slug="manifest",
            label="UI Manifest",
            route="/ui/manifest",
            category="system",
            summary="Inventory of registered UI surfaces and route metadata.",
            tags=["ui-manifest", "catalog"],
            metadata={"surface": "ui", "kind": "manifest"},
        ),
        UIPageItem(
            slug="status",
            label="UI Status",
            route="/ui/status",
            category="system",
            summary="Top-level UI readiness and system availability summary.",
            tags=["ui-status", "health"],
            metadata={"surface": "ui", "kind": "status"},
        ),
        UIPageItem(
            slug="routes",
            label="UI Routes",
            route="/ui/routes",
            category="system",
            summary="Normalized route inventory for the UI surface.",
            tags=["ui-routes", "inventory"],
            metadata={"surface": "ui", "kind": "routes"},
        ),
        UIPageItem(
            slug="request-stream",
            label="Request Stream",
            route="/ui/request-stream",
            category="security-admin",
            summary="Operational feed of guarded request activity.",
            tags=["request-stream", "operations"],
            metadata={"surface": "operations", "kind": "stream"},
        ),
        UIPageItem(
            slug="system-diagnostics",
            label="System Diagnostics",
            route="/ui/system-diagnostics",
            category="security-admin",
            summary="Health and warning view for core IronClaw services.",
            tags=["system-diagnostics", "operations"],
            metadata={"surface": "operations", "kind": "diagnostics"},
        ),
        UIPageItem(
            slug="execution-test-console",
            label="Execution Test Console",
            route="/ui/executions/test-console",
            category="security-admin",
            summary="Safe preview surface for simulated execution decisions.",
            tags=["execution-test-console", "executions"],
            metadata={"surface": "operations", "kind": "test-console"},
        ),
        UIPageItem(
            slug="runtime-status",
            label="Runtime Status",
            route="/ui/runtime-status",
            category="security-admin",
            summary="Runtime boundary, executor, and policy posture snapshot.",
            tags=["runtime-status", "operations"],
            metadata={"surface": "operations", "kind": "runtime"},
        ),
        UIPageItem(
            slug="audit-log",
            label="Audit Log",
            route="/ui/audit-log",
            category="security-admin",
            summary="Operator-facing audit history of guarded actions.",
            tags=["audit-log", "audit"],
            metadata={"surface": "operations", "kind": "audit"},
        ),
        UIPageItem(
            slug="data-retention",
            label="Data Retention",
            route="/ui/data-retention",
            category="security-admin",
            summary="Retention policy view for execution and review data.",
            tags=["data-retention", "governance"],
            metadata={"surface": "operations", "kind": "retention"},
        ),
        UIPageItem(
            slug="incident-triage",
            label="Incident Triage",
            route="/ui/incidents/triage",
            category="security-admin",
            summary="Queue and decision support for security incident handling.",
            tags=["incident-triage", "incidents"],
            metadata={"surface": "operations", "kind": "triage"},
        ),
        UIPageItem(
            slug="operator-management",
            label="Operator Management",
            route="/ui/admin/operators",
            category="security-admin",
            summary="Operator roster and administrative control surface.",
            tags=["operator-management", "admin"],
            metadata={"surface": "admin", "kind": "operators"},
        ),
        UIPageItem(
            slug="access-control-roles",
            label="Access Control Roles",
            route="/ui/admin/roles",
            category="security-admin",
            summary="Role and permission reference for admin operators.",
            tags=["access-control-roles", "admin"],
            metadata={"surface": "admin", "kind": "roles"},
        ),
        UIPageItem(
            slug="integration-settings",
            label="Integration Settings",
            route="/ui/integrations/settings",
            category="integrations",
            summary="Configuration overview for connected integration surfaces.",
            tags=["integration-settings", "integrations"],
            metadata={"surface": "integrations", "kind": "settings"},
        ),
        UIPageItem(
            slug="customer-keys",
            label="Customer Keys",
            route="/ui/customer-keys",
            category="tenant",
            summary="Customer-managed key inventory and summary view.",
            tags=["customer-keys", "tenant"],
            metadata={"surface": "tenant", "kind": "keys"},
        ),
        UIPageItem(
            slug="customer-key-detail",
            label="Customer Key Detail",
            route="/ui/customer-keys/detail",
            category="tenant",
            summary="Detailed view for a selected customer-managed key.",
            tags=["customer-key-detail", "tenant"],
            metadata={"surface": "tenant", "kind": "key-detail"},
        ),
        UIPageItem(
            slug="telemetry-access-summary",
            label="Telemetry Access Summary",
            route="/ui/telemetry-access-summary",
            category="tenant",
            summary="Summary of telemetry visibility and access posture.",
            tags=["telemetry-access-summary", "tenant"],
            metadata={"surface": "tenant", "kind": "telemetry"},
        ),
        UIPageItem(
            slug="usage-reports",
            label="Usage Reports",
            route="/ui/usage-reports",
            category="billing",
            summary="Usage and billing-oriented reporting surface.",
            tags=["usage-reports", "billing"],
            metadata={"surface": "billing", "kind": "reporting"},
        ),
    ]


def _build_sections(items: list[UIPageItem]) -> list[UIPageSection]:
    category_labels: dict[str, str] = {
        "system": "System",
        "security-admin": "Security Admin",
        "integrations": "Integrations",
        "tenant": "Tenant",
        "billing": "Billing",
    }

    ordered_categories = [
        "system",
        "security-admin",
        "integrations",
        "tenant",
        "billing",
    ]

    sections: list[UIPageSection] = []
    for category in ordered_categories:
        section_items = [item for item in items if item.category == category]
        if not section_items:
            continue
        sections.append(
            UIPageSection(
                category=category,
                label=category_labels.get(category, category.title()),
                total=len(section_items),
                items=section_items,
            )
        )
    return sections


@router.get("", response_model=UIPagesResponse)
def get_ui_pages() -> UIPagesResponse:
    items = _build_ui_pages()
    sections = _build_sections(items)
    return UIPagesResponse(
        generatedat=_utc_now_iso(),
        summary=UIPageSummary(
            totalpages=len(items),
            enabledpages=sum(1 for item in items if item.enabled),
            categories=[section.category for section in sections],
        ),
        sections=sections,
        items=items,
        metadata={
            "surface": "ui",
            "scope": "page-catalog",
            "generatedby": "uipages",
        },
    )