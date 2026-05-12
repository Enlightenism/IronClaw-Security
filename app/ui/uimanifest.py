from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/manifest",
    tags=["ui-manifest"],
)


class UIManifestRoute(BaseModel):
    prefix: str
    tags: list[str] = Field(default_factory=list)
    slug: str
    label: str
    category: str
    enabled: bool = True
    metadata: dict[str, str] = Field(default_factory=dict)


class UIManifestResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    totalroutes: int
    routes: list[UIManifestRoute] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _build_ui_manifest_routes() -> list[UIManifestRoute]:
    return [
        UIManifestRoute(
            prefix="/ui/manifest",
            tags=["ui-manifest"],
            slug="manifest",
            label="UI Manifest",
            category="system",
            metadata={"surface": "ui", "kind": "catalog"},
        ),
        UIManifestRoute(
            prefix="/ui/status",
            tags=["ui-status"],
            slug="status",
            label="UI Status",
            category="system",
            metadata={"surface": "ui", "kind": "health"},
        ),
        UIManifestRoute(
            prefix="/ui/routes",
            tags=["ui-routes"],
            slug="routes",
            label="UI Routes",
            category="system",
            metadata={"surface": "ui", "kind": "inventory"},
        ),
        UIManifestRoute(
            prefix="/ui/request-stream",
            tags=["request-stream"],
            slug="request-stream",
            label="Request Stream",
            category="security-admin",
            metadata={"surface": "operations", "kind": "stream"},
        ),
        UIManifestRoute(
            prefix="/ui/system-diagnostics",
            tags=["system-diagnostics"],
            slug="system-diagnostics",
            label="System Diagnostics",
            category="security-admin",
            metadata={"surface": "operations", "kind": "diagnostics"},
        ),
        UIManifestRoute(
            prefix="/ui/executions/test-console",
            tags=["execution-test-console"],
            slug="execution-test-console",
            label="Execution Test Console",
            category="security-admin",
            metadata={"surface": "operations", "kind": "test-console"},
        ),
        UIManifestRoute(
            prefix="/ui/runtime-status",
            tags=["runtime-status"],
            slug="runtime-status",
            label="Runtime Status",
            category="security-admin",
            metadata={"surface": "operations", "kind": "runtime"},
        ),
        UIManifestRoute(
            prefix="/ui/audit-log",
            tags=["audit-log"],
            slug="audit-log",
            label="Audit Log",
            category="security-admin",
            metadata={"surface": "operations", "kind": "audit"},
        ),
        UIManifestRoute(
            prefix="/ui/data-retention",
            tags=["data-retention"],
            slug="data-retention",
            label="Data Retention",
            category="security-admin",
            metadata={"surface": "operations", "kind": "governance"},
        ),
        UIManifestRoute(
            prefix="/ui/incidents/triage",
            tags=["incident-triage"],
            slug="incident-triage",
            label="Incident Triage",
            category="security-admin",
            metadata={"surface": "operations", "kind": "incident"},
        ),
        UIManifestRoute(
            prefix="/ui/admin/operators",
            tags=["operator-management"],
            slug="operator-management",
            label="Operator Management",
            category="security-admin",
            metadata={"surface": "admin", "kind": "operators"},
        ),
        UIManifestRoute(
            prefix="/ui/admin/roles",
            tags=["access-control-roles"],
            slug="access-control-roles",
            label="Access Control Roles",
            category="security-admin",
            metadata={"surface": "admin", "kind": "roles"},
        ),
        UIManifestRoute(
            prefix="/ui/integrations/settings",
            tags=["integration-settings"],
            slug="integration-settings",
            label="Integration Settings",
            category="integrations",
            metadata={"surface": "integrations", "kind": "settings"},
        ),
        UIManifestRoute(
            prefix="/ui/customer-keys",
            tags=["customer-keys"],
            slug="customer-keys",
            label="Customer Keys",
            category="tenant",
            metadata={"surface": "tenant", "kind": "keys"},
        ),
        UIManifestRoute(
            prefix="/ui/customer-keys/detail",
            tags=["customer-key-detail"],
            slug="customer-key-detail",
            label="Customer Key Detail",
            category="tenant",
            metadata={"surface": "tenant", "kind": "key-detail"},
        ),
        UIManifestRoute(
            prefix="/ui/usage-reports",
            tags=["usage-reports"],
            slug="usage-reports",
            label="Usage Reports",
            category="billing",
            metadata={"surface": "billing", "kind": "reporting"},
        ),
        UIManifestRoute(
            prefix="/ui/telemetry-access-summary",
            tags=["telemetry-access-summary"],
            slug="telemetry-access-summary",
            label="Telemetry Access Summary",
            category="tenant",
            metadata={"surface": "tenant", "kind": "telemetry"},
        ),
    ]


@router.get("", response_model=UIManifestResponse)
def get_ui_manifest() -> UIManifestResponse:
    routes = _build_ui_manifest_routes()
    return UIManifestResponse(
        status="ok",
        service="ironclaw-ui",
        timestamp=_utc_now_iso(),
        totalroutes=len(routes),
        routes=routes,
        metadata={
            "generatedby": "uimanifest",
            "scope": "ui-surface",
        },
    )