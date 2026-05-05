from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.api.auth import require_api_key

router = APIRouter(
    prefix="/ui/admin",
    tags=["operator-management"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class OperatorPermissionView(BaseModel):
    key: str
    label: str
    enabled: bool


class OperatorItemView(BaseModel):
    operator_id: str
    display_name: str
    role: str
    status: str
    last_active_at: str | None = None
    permissions: list[OperatorPermissionView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OperatorManagementResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    requested_by: str
    total: int
    active_count: int
    suspended_count: int
    items: list[OperatorItemView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_operator_items() -> list[OperatorItemView]:
    return [
        OperatorItemView(
            operator_id="op-001",
            display_name="Primary Security Operator",
            role="admin",
            status="active",
            last_active_at="2026-04-21T16:10:00Z",
            permissions=[
                OperatorPermissionView(
                    key="review.approve",
                    label="Approve review items",
                    enabled=True,
                ),
                OperatorPermissionView(
                    key="review.reject",
                    label="Reject review items",
                    enabled=True,
                ),
                OperatorPermissionView(
                    key="audit.read",
                    label="Read audit log",
                    enabled=True,
                ),
                OperatorPermissionView(
                    key="operators.manage",
                    label="Manage operators",
                    enabled=True,
                ),
            ],
            metadata={"team": "security-ops"},
        ),
        OperatorItemView(
            operator_id="op-002",
            display_name="Review Analyst",
            role="analyst",
            status="active",
            last_active_at="2026-04-21T15:42:00Z",
            permissions=[
                OperatorPermissionView(
                    key="review.approve",
                    label="Approve review items",
                    enabled=True,
                ),
                OperatorPermissionView(
                    key="review.reject",
                    label="Reject review items",
                    enabled=True,
                ),
                OperatorPermissionView(
                    key="audit.read",
                    label="Read audit log",
                    enabled=True,
                ),
                OperatorPermissionView(
                    key="operators.manage",
                    label="Manage operators",
                    enabled=False,
                ),
            ],
            metadata={"team": "security-ops"},
        ),
        OperatorItemView(
            operator_id="op-003",
            display_name="Temporary Responder",
            role="responder",
            status="suspended",
            last_active_at="2026-04-20T19:05:00Z",
            permissions=[
                OperatorPermissionView(
                    key="review.approve",
                    label="Approve review items",
                    enabled=False,
                ),
                OperatorPermissionView(
                    key="review.reject",
                    label="Reject review items",
                    enabled=False,
                ),
                OperatorPermissionView(
                    key="audit.read",
                    label="Read audit log",
                    enabled=True,
                ),
                OperatorPermissionView(
                    key="operators.manage",
                    label="Manage operators",
                    enabled=False,
                ),
            ],
            metadata={"team": "incident-response"},
        ),
    ]


@router.get("/operators", response_model=OperatorManagementResponse)
def get_operator_management(
    requested_by: str = Query("ui-operator-management", min_length=1),
) -> OperatorManagementResponse:
    items = _build_operator_items()
    active_count = sum(1 for item in items if item.status == "active")
    suspended_count = sum(1 for item in items if item.status == "suspended")

    return OperatorManagementResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=requested_by,
        total=len(items),
        active_count=active_count,
        suspended_count=suspended_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )