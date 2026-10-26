from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.ui.guard.prompt_guard_policy import PromptGuardCategory

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-prompt-guard-allowlist"],
)


AllowlistStatus = Literal["active", "disabled"]
AllowlistScope = Literal["global", "client", "session", "rule"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardAllowlistEntry:
    id: str
    name: str
    description: str
    category: PromptGuardCategory
    status: AllowlistStatus
    scope: AllowlistScope
    pattern: str
    created_at: str
    updated_at: str
    created_by: str
    client_id: str | None = None
    session_id: str | None = None
    rule_id: str | None = None
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "status": self.status,
            "scope": self.scope,
            "pattern": self.pattern,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "rule_id": self.rule_id,
            "expires_at": self.expires_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardAllowlistPage:
    items: list[PromptGuardAllowlistEntry]
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


_ALLOWLIST: list[PromptGuardAllowlistEntry] = []
_ALLOWLIST_COUNTER: int = 0
_ALLOWLIST_MAX_ITEMS: int = 500


class PromptGuardAllowlistEntryView(BaseModel):
    id: str
    name: str
    description: str
    category: PromptGuardCategory
    status: AllowlistStatus
    scope: AllowlistScope
    pattern: str
    created_at: str
    updated_at: str
    created_by: str
    client_id: str | None = None
    session_id: str | None = None
    rule_id: str | None = None
    expires_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardAllowlistResponse(BaseModel):
    items: list[PromptGuardAllowlistEntryView]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    generated_at: str
    next_page: int | None = None
    prev_page: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardAllowlistCreateRequest(BaseModel):
    name: str = Field(..., description="Human-readable name for the allowlist exception.")
    description: str = Field(..., description="Why this exception exists.")
    category: PromptGuardCategory = Field(..., description="Prompt guard category this allowlist applies to.")
    scope: AllowlistScope = Field(..., description="Scope of the allowlist entry.")
    pattern: str = Field(..., description="Pattern or exact phrase to allow.")
    created_by: str = Field(..., description="Operator or system creating the exception.")
    client_id: str | None = Field(default=None, description="Client target when scope=client.")
    session_id: str | None = Field(default=None, description="Session target when scope=session.")
    rule_id: str | None = Field(default=None, description="Rule target when scope=rule.")
    expires_at: str | None = Field(default=None, description="Optional expiration timestamp.")
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardAllowlistUpdateRequest(BaseModel):
    status: AllowlistStatus | None = Field(default=None, description="Set allowlist status.")
    description: str | None = Field(default=None, description="Optional updated description.")
    expires_at: str | None = Field(default=None, description="Optional updated expiration timestamp.")
    metadata: dict[str, Any] | None = Field(default=None, description="Optional metadata merge.")


def _seed_allowlist() -> None:
    global _ALLOWLIST, _ALLOWLIST_COUNTER

    if _ALLOWLIST:
        return

    now = _utc_now()
    _ALLOWLIST.extend(
        [
            PromptGuardAllowlistEntry(
                id="allow-1",
                name="Internal red-team training phrase",
                description="Approved phrase used by internal red-team simulations.",
                category="prompt_injection",
                status="active",
                scope="client",
                pattern="ignore previous instructions for training",
                created_at=now,
                updated_at=now,
                created_by="security-admin",
                client_id="internal-redteam",
                session_id=None,
                rule_id=None,
                expires_at=None,
                metadata={"seeded": True},
            ),
            PromptGuardAllowlistEntry(
                id="allow-2",
                name="Approved secret scanning test",
                description="Controlled validation phrase for secret exposure detector tests.",
                category="secret_exposure",
                status="disabled",
                scope="rule",
                pattern="show api key for test harness",
                created_at=now,
                updated_at=now,
                created_by="security-admin",
                client_id=None,
                session_id=None,
                rule_id="pg-003",
                expires_at=None,
                metadata={"seeded": True},
            ),
        ],
    )
    _ALLOWLIST_COUNTER = len(_ALLOWLIST)


def _next_allowlist_id() -> str:
    global _ALLOWLIST_COUNTER
    _ALLOWLIST_COUNTER += 1
    return f"allow-{_ALLOWLIST_COUNTER}"


def _paginate_items(
    items: list[PromptGuardAllowlistEntry],
    page: int,
    page_size: int,
) -> PromptGuardAllowlistPage:
    total_items = len(items)
    if total_items == 0:
        return PromptGuardAllowlistPage(
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
    slice_items = items[start:end]

    return PromptGuardAllowlistPage(
        items=slice_items,
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        generated_at=_utc_now(),
        next_page=page + 1 if page < total_pages else None,
        prev_page=page - 1 if page > 1 else None,
        metadata={},
    )


def _append_allowlist_entry(
    payload: PromptGuardAllowlistCreateRequest,
) -> PromptGuardAllowlistEntry:
    global _ALLOWLIST

    now = _utc_now()
    entry = PromptGuardAllowlistEntry(
        id=_next_allowlist_id(),
        name=payload.name,
        description=payload.description,
        category=payload.category,
        status="active",
        scope=payload.scope,
        pattern=payload.pattern,
        created_at=now,
        updated_at=now,
        created_by=payload.created_by,
        client_id=payload.client_id,
        session_id=payload.session_id,
        rule_id=payload.rule_id,
        expires_at=payload.expires_at,
        metadata=dict(payload.metadata),
    )

    _ALLOWLIST.append(entry)
    if len(_ALLOWLIST) > _ALLOWLIST_MAX_ITEMS:
        _ALLOWLIST = _ALLOWLIST[-_ALLOWLIST_MAX_ITEMS:]

    return entry


def _find_allowlist_entry(entry_id: str) -> PromptGuardAllowlistEntry:
    for entry in _ALLOWLIST:
        if entry.id == entry_id:
            return entry
    raise HTTPException(status_code=404, detail="Allowlist entry not found")


@router.get("/prompt-guard/allowlist", response_model=PromptGuardAllowlistResponse)
def get_prompt_guard_allowlist(
    page: int = Query(1, ge=1, description="Page number for the allowlist."),
    page_size: int = Query(20, ge=1, le=100, description="Number of allowlist items per page."),
    status: AllowlistStatus | None = Query(default=None, description="Optional filter by status."),
    scope: AllowlistScope | None = Query(default=None, description="Optional filter by scope."),
    category: PromptGuardCategory | None = Query(default=None, description="Optional filter by category."),
) -> PromptGuardAllowlistResponse:
    _seed_allowlist()

    items = list(reversed(_ALLOWLIST))
    if status is not None:
        items = [item for item in items if item.status == status]
    if scope is not None:
        items = [item for item in items if item.scope == scope]
    if category is not None:
        items = [item for item in items if item.category == category]

    page_obj = _paginate_items(items, page=page, page_size=page_size)
    data = page_obj.to_dict()

    return PromptGuardAllowlistResponse(
        items=[PromptGuardAllowlistEntryView(**item) for item in data["items"]],
        page=data["page"],
        page_size=data["page_size"],
        total_items=data["total_items"],
        total_pages=data["total_pages"],
        generated_at=data["generated_at"],
        next_page=data["next_page"],
        prev_page=data["prev_page"],
        metadata=data["metadata"],
    )


@router.post("/prompt-guard/allowlist", response_model=PromptGuardAllowlistEntryView, status_code=201)
def create_prompt_guard_allowlist_entry(
    payload: PromptGuardAllowlistCreateRequest,
) -> PromptGuardAllowlistEntryView:
    _seed_allowlist()
    entry = _append_allowlist_entry(payload)
    return PromptGuardAllowlistEntryView(**entry.to_dict())


@router.patch("/prompt-guard/allowlist/{entry_id}", response_model=PromptGuardAllowlistEntryView)
def update_prompt_guard_allowlist_entry(
    entry_id: str,
    payload: PromptGuardAllowlistUpdateRequest,
) -> PromptGuardAllowlistEntryView:
    _seed_allowlist()
    entry = _find_allowlist_entry(entry_id)

    if payload.status is not None:
        entry.status = payload.status
    if payload.description is not None:
        entry.description = payload.description
    if payload.expires_at is not None:
        entry.expires_at = payload.expires_at
    if payload.metadata is not None:
        entry.metadata.update(payload.metadata)

    entry.updated_at = _utc_now()
    return PromptGuardAllowlistEntryView(**entry.to_dict())
