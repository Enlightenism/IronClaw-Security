from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/admin",
    tags=["access-control-roles"],
)


class RolePermissionItem(BaseModel):
    role: str
    scope: str
    permissions: list[str] = Field(default_factory=list)
    description: str


class AccessControlRolesSummary(BaseModel):
    total: int = 0
    platformroles: int = 0
    operationsroles: int = 0
    tenantroles: int = 0


class AccessControlRolesResponse(BaseModel):
    title: str = "Access Control Roles"
    status: str = "ok"
    generatedat: str
    summary: AccessControlRolesSummary
    items: list[RolePermissionItem] = Field(default_factory=list)


@router.get("/roles", response_model=AccessControlRolesResponse)
def get_access_control_roles() -> AccessControlRolesResponse:
    items = [
        RolePermissionItem(
            role="platform_admin",
            scope="platform",
            permissions=[
                "read:*",
                "write:review-decision",
                "write:settings",
                "write:integrations",
                "write:roles",
                "write:operators",
            ],
            description="Has full platform configuration, role, and operator control access.",
        ),
        RolePermissionItem(
            role="security_analyst",
            scope="operations",
            permissions=[
                "read:dashboard",
                "read:execution-detail",
                "read:review-queue",
                "read:alerts",
                "read:request-stream",
                "write:incident-triage",
            ],
            description="Can investigate executions, view queued review items, and triage incidents.",
        ),
        RolePermissionItem(
            role="org_admin",
            scope="tenant",
            permissions=[
                "read:organization",
                "write:organization",
                "read:api-keys",
                "read:telemetry",
                "read:integrations",
            ],
            description="Can manage tenant-level organization settings, keys, and integration visibility.",
        ),
    ]

    return AccessControlRolesResponse(
        generatedat=datetime.now(UTC).isoformat(),
        summary=AccessControlRolesSummary(
            total=len(items),
            platformroles=sum(1 for item in items if item.scope == "platform"),
            operationsroles=sum(1 for item in items if item.scope == "operations"),
            tenantroles=sum(1 for item in items if item.scope == "tenant"),
        ),
        items=items,
    )