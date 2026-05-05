from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.dependencies import get_integration_registry
from app.services.integration_registry import list_integrations


router = APIRouter(
    prefix="/ui/integrations",
    tags=["integration-audit"],
)


@dataclass(slots=True)
class IntegrationAuditEntry:
    event_id: str
    integration_id: str
    slug: str
    name: str
    platform: str
    action: str
    actor: str
    status: str
    occurred_at: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "action": self.action,
            "actor": self.actor,
            "status": self.status,
            "occurred_at": self.occurred_at,
            "details": dict(self.details),
        }


class IntegrationAuditEventView(BaseModel):
    event_id: str
    integration_id: str
    slug: str
    name: str
    platform: str
    action: str
    actor: str
    status: str
    occurred_at: str
    details: dict[str, Any] = Field(default_factory=dict)


class IntegrationAuditResponse(BaseModel):
    generated_at: str
    total: int
    items: list[IntegrationAuditEventView] = Field(default_factory=list)


def _build_audit_entries(*, requested_by: str = "ui-audit") -> list[IntegrationAuditEntry]:
    registry = get_integration_registry()
    records = list_integrations(registry)

    items: list[IntegrationAuditEntry] = []

    for index, record in enumerate(records, start=1):
        occurred_at = str(
            getattr(
                record,
                "updated_at",
                getattr(record, "created_at", datetime.now(timezone.utc).isoformat()),
            )
        )

        items.append(
            IntegrationAuditEntry(
                event_id=f"audit-{record.slug}-{index}",
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                action="integration.viewed",
                actor="system",
                status=getattr(record, "status", "unknown"),
                occurred_at=occurred_at,
                details={
                    "requested_by": requested_by,
                    "version": getattr(record, "version", None),
                    "integration_type": getattr(record, "integration_type", "unknown"),
                },
            )
        )

    items.sort(
        key=lambda item: (
            item.occurred_at,
            item.platform,
            item.slug,
            item.event_id,
        ),
        reverse=True,
    )
    return items


@router.get("/audit", response_model=IntegrationAuditResponse)
def get_integration_audit() -> IntegrationAuditResponse:
    entries = _build_audit_entries()
    return IntegrationAuditResponse(
        generated_at=datetime.now(timezone.utc).isoformat(),
        total=len(entries),
        items=[IntegrationAuditEventView(**entry.to_dict()) for entry in entries],
    )