from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.services.guard_security_brain import GuardMode

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-control-audit-log"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


AuditAction = Literal["update"]
AuditObjectType = Literal["control_flags"]


@dataclass(slots=True)
class ControlAuditEvent:
    """Single audit record for a control-panel change."""

    id: str
    occurred_at: str
    actor: str
    action: AuditAction
    object_type: AuditObjectType
    object_id: str
    client_ip: str | None = None
    user_agent: str | None = None
    mode_before: GuardMode | None = None
    mode_after: GuardMode | None = None
    changes: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "action": self.action,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "mode_before": self.mode_before,
            "mode_after": self.mode_after,
            "changes": dict(self.changes),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ControlAuditPage:
    items: list[ControlAuditEvent]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    generated_at: str
    next_page: int | None = None
    prev_page: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items],
            "page": self.page,
            "page_size": self.page_size,
            "total_items": self.total_items,
            "total_pages": self.total_pages,
            "generated_at": self.generated_at,
            "next_page": self.next_page,
            "prev_page": self.prev_page,
            "metadata": dict(self.metadata),
        }


# In-memory ring buffer for audit events (simple, pluggable later)
_AUDIT_EVENTS: list[ControlAuditEvent] = []
_AUDIT_COUNTER: int = 0
_AUDIT_MAX_EVENTS: int = 500


def record_control_audit_event(
    *,
    actor: str,
    changes: dict[str, Any],
    mode_before: GuardMode | None,
    mode_after: GuardMode | None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> ControlAuditEvent:
    """Append a control-audit event to the in-memory buffer.

    Intended to be called from the control_panel PATCH handler whenever
    flags change.
    """
    global _AUDIT_COUNTER, _AUDIT_EVENTS

    _AUDIT_COUNTER += 1
    event_id = f"control-change-{_AUDIT_COUNTER}"

    event = ControlAuditEvent(
        id=event_id,
        occurred_at=_utc_now(),
        actor=actor or "unknown",
        action="update",
        object_type="control_flags",
        object_id="guard-brain-global",
        client_ip=client_ip,
        user_agent=user_agent,
        mode_before=mode_before,
        mode_after=mode_after,
        changes=changes,
        metadata={
            "source": "ui-guard-control-panel",
        },
    )

    _AUDIT_EVENTS.append(event)
    if len(_AUDIT_EVENTS) > _AUDIT_MAX_EVENTS:
        # drop oldest to keep bounded memory
        _AUDIT_EVENTS = _AUDIT_EVENTS[-_AUDIT_MAX_EVENTS:]

    return event


# ---------- Pydantic views ----------


class ControlAuditEventView(BaseModel):
    id: str
    occurred_at: str
    actor: str
    action: AuditAction
    object_type: AuditObjectType
    object_id: str
    client_ip: str | None = None
    user_agent: str | None = None
    mode_before: GuardMode | None = None
    mode_after: GuardMode | None = None
    changes: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ControlAuditLogResponse(BaseModel):
    items: list[ControlAuditEventView]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    generated_at: str
    next_page: int | None = None
    prev_page: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------- internal helpers ----------


def _paginate_events(
    events: list[ControlAuditEvent],
    page: int,
    page_size: int,
) -> ControlAuditPage:
    total_items = len(events)
    if total_items == 0:
        return ControlAuditPage(
            items=[],
            page=1,
            page_size=page_size,
            total_items=0,
            total_pages=0,
            generated_at=_utc_now(),
            next_page=None,
            prev_page=None,
            metadata={},
        )

    total_pages = (total_items + page_size - 1) // page_size
    page = max(1, min(page, total_pages))

    start = (page - 1) * page_size
    end = start + page_size
    slice_items = events[start:end]

    next_page = page + 1 if page < total_pages else None
    prev_page = page - 1 if page > 1 else None

    return ControlAuditPage(
        items=slice_items,
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        generated_at=_utc_now(),
        next_page=next_page,
        prev_page=prev_page,
        metadata={},
    )


def _filter_events(
    *,
    actor: str | None,
    mode: GuardMode | None,
) -> list[ControlAuditEvent]:
    events = list(reversed(_AUDIT_EVENTS))  # newest first
    if actor is not None:
        events = [e for e in events if e.actor == actor]
    if mode is not None:
        events = [e for e in events if e.mode_after == mode or e.mode_before == mode]
    return events


# ---------- HTTP endpoint ----------


@router.get("/control/audit-log", response_model=ControlAuditLogResponse)
def get_control_audit_log(
    page: int = Query(1, ge=1, description="Page number for the audit log."),
    page_size: int = Query(
        20,
        ge=1,
        le=100,
        description="Number of audit events per page (max 100).",
    ),
    actor: str | None = Query(
        default=None,
        description="Optional filter to return only events for a specific actor.",
    ),
    mode: GuardMode | None = Query(
        default=None,
        description="Optional filter to return events where this mode was before/after.",
    ),
) -> ControlAuditLogResponse:
    """Paginated audit log of Guard control-panel changes.

    Designed for security / ops UIs and export tools that need to answer:
    * who changed which control flags
    * what the old and new values were
    * when the change happened
    """
    filtered = _filter_events(actor=actor, mode=mode)
    page_obj = _paginate_events(filtered, page=page, page_size=page_size)
    data = page_obj.to_dict()

    return ControlAuditLogResponse(
        items=[ControlAuditEventView(**item) for item in data["items"]],
        page=data["page"],
        page_size=data["page_size"],
        total_items=data["total_items"],
        total_pages=data["total_pages"],
        generated_at=data["generated_at"],
        next_page=data["next_page"],
        prev_page=data["prev_page"],
        metadata=data["metadata"],
    )
