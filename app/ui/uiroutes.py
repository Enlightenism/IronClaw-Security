from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/routes",
    tags=["ui-routes"],
)


class UIRouteRecord(BaseModel):
    prefix: str
    slug: str
    label: str
    category: str
    enabled: bool = True
    metadata: dict[str, str] = Field(default_factory=dict)


class UIRoutesResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    totalroutes: int
    routes: list[UIRouteRecord] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _UIRouteSeed:
    prefix: str
    slug: str
    label: str
    category: str
    enabled: bool = True
    metadata: dict[str, str] = field(default_factory=dict)


_UI_ROUTE_SEEDS: tuple[_UIRouteSeed, ...] = (
    _UIRouteSeed(
        prefix="/ui/manifest",
        slug="manifest",
        label="UI Manifest",
        category="system",
    ),
    _UIRouteSeed(
        prefix="/ui/status",
        slug="status",
        label="UI Status",
        category="system",
    ),
    _UIRouteSeed(
        prefix="/ui/routes",
        slug="routes",
        label="UI Routes",
        category="system",
    ),
    _UIRouteSeed(
        prefix="/ui/request-stream",
        slug="request-stream",
        label="Request Stream",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/system-diagnostics",
        slug="system-diagnostics",
        label="System Diagnostics",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/executions/test-console",
        slug="execution-test-console",
        label="Execution Test Console",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/runtime-status",
        slug="runtime-status",
        label="Runtime Status",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/audit-log",
        slug="audit-log",
        label="Audit Log",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/data-retention",
        slug="data-retention",
        label="Data Retention",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/incidents/triage",
        slug="incident-triage",
        label="Incident Triage",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/admin/operators",
        slug="operator-management",
        label="Operator Management",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/admin/roles",
        slug="access-control-roles",
        label="Access Control Roles",
        category="security-admin",
    ),
    _UIRouteSeed(
        prefix="/ui/integrations/settings",
        slug="integration-settings",
        label="Integration Settings",
        category="integrations",
    ),
    _UIRouteSeed(
        prefix="/ui/customer-keys",
        slug="customer-keys",
        label="Customer Keys",
        category="tenant",
    ),
    _UIRouteSeed(
        prefix="/ui/customer-keys/detail",
        slug="customer-key-detail",
        label="Customer Key Detail",
        category="tenant",
    ),
    _UIRouteSeed(
        prefix="/ui/usage-reports",
        slug="usage-reports",
        label="Usage Reports",
        category="billing",
    ),
    _UIRouteSeed(
        prefix="/ui/telemetry-access-summary",
        slug="telemetry-access-summary",
        label="Telemetry Access Summary",
        category="tenant",
    ),
)


def _build_ui_routes() -> list[UIRouteRecord]:
    return [
        UIRouteRecord(
            prefix=route.prefix,
            slug=route.slug,
            label=route.label,
            category=route.category,
            enabled=route.enabled,
            metadata=route.metadata.copy(),
        )
        for route in _UI_ROUTE_SEEDS
    ]


@router.get("", response_model=UIRoutesResponse)
def get_ui_routes() -> UIRoutesResponse:
    routes = _build_ui_routes()
    return UIRoutesResponse(
        status="ok",
        service="ironclaw-ui",
        timestamp="2026-04-26T00:00:00Z",
        totalroutes=len(routes),
        routes=routes,
        metadata={
            "surface": "ui",
            "scope": "route-inventory",
            "source": "static-registry",
        },
    )