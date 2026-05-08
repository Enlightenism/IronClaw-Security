from __future__ import annotations


from datetime import UTC, datetime
from typing import Any


from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field


from app.dependencies.auth import require_api_key


router = APIRouter(
    prefix="/ui/admin",
    tags=["access-control-roles"],
    dependencies=[Depends(require_api_key)],
)



def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")



class RolePermissionView(BaseModel):
    key: str
    label: str
    description: str
    granted: bool



class AccessControlRoleView(BaseModel):
    role_id: str
    name: str
    description: str
    operator_count: int
    permissions: list[RolePermissionView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)



class AccessControlRolesResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    requested_by: str
    total: int
    roles: list[AccessControlRoleView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)



def _build_roles() -> list[AccessControlRoleView]:
    return [
        AccessControlRoleView(
            role_id="admin",
            name="Administrator",
            description="Full operational access across review, audit, and operator management workflows.",
            operator_count=1,
            permissions=[
                RolePermissionView(
                    key="review.approve",
                    label="Approve reviews",
                    description="Approve queued review items for execution release.",
                    granted=True,
                ),
                RolePermissionView(
                    key="review.reject",
                    label="Reject reviews",
                    description="Reject risky review items and keep them blocked.",
                    granted=True,
                ),
                RolePermissionView(
                    key="audit.read",
                    label="Read audit log",
                    description="Read full audit trail entries and trace context.",
                    granted=True,
                ),
                RolePermissionView(
                    key="operators.manage",
                    label="Manage operators",
                    description="Create, update, suspend, and reactivate operator accounts.",
                    granted=True,
                ),
            ],
            metadata={"tier": "global"},
        ),
        AccessControlRoleView(
            role_id="analyst",
            name="Analyst",
            description="Operational review access for routine security triage and policy follow-up.",
            operator_count=2,
            permissions=[
                RolePermissionView(
                    key="review.approve",
                    label="Approve reviews",
                    description="Approve queued review items for execution release.",
                    granted=True,
                ),
                RolePermissionView(
                    key="review.reject",
                    label="Reject reviews",
                    description="Reject risky review items and keep them blocked.",
                    granted=True,
                ),
                RolePermissionView(
                    key="audit.read",
                    label="Read audit log",
                    description="Read full audit trail entries and trace context.",
                    granted=True,
                ),
                RolePermissionView(
                    key="operators.manage",
                    label="Manage operators",
                    description="Create, update, suspend, and reactivate operator accounts.",
                    granted=False,
                ),
            ],
            metadata={"tier": "operational"},
        ),
        AccessControlRoleView(
            role_id="responder",
            name="Responder",
            description="Incident response visibility with limited review permissions.",
            operator_count=1,
            permissions=[
                RolePermissionView(
                    key="review.approve",
                    label="Approve reviews",
                    description="Approve queued review items for execution release.",
                    granted=False,
                ),
                RolePermissionView(
                    key="review.reject",
                    label="Reject reviews",
                    description="Reject risky review items and keep them blocked.",
                    granted=False,
                ),
                RolePermissionView(
                    key="audit.read",
                    label="Read audit log",
                    description="Read full audit trail entries and trace context.",
                    granted=True,
                ),
                RolePermissionView(
                    key="operators.manage",
                    label="Manage operators",
                    description="Create, update, suspend, and reactivate operator accounts.",
                    granted=False,
                ),
            ],
            metadata={"tier": "incident-response"},
        ),
    ]



@router.get("/roles", response_model=AccessControlRolesResponse)
def get_access_control_roles(
    requested_by: str = Query("ui-access-control-roles", min_length=1),
) -> AccessControlRolesResponse:
    roles = _build_roles()
    return AccessControlRolesResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=requested_by,
        total=len(roles),
        roles=roles,
        metadata={
            "requested_by": requested_by,
        },
    )