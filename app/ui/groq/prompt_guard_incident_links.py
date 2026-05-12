from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.groq_security_brain import GroqSecurityVerdict
from app.ui.groq.incidents import _INCIDENTS
from app.ui.groq.prompt_guard_audit_trail import _AUDIT_TRAIL

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-incident-links"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardIncidentLink:
    id: str
    incident_id: str
    prompt_excerpt: str
    verdict: GroqSecurityVerdict
    risk_score: int
    audit_event_id: str | None
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "prompt_excerpt": self.prompt_excerpt,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "audit_event_id": self.audit_event_id,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardIncidentLinksPage:
    items: list[PromptGuardIncidentLink]
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


_INCIDENT_LINKS: list[PromptGuardIncidentLink] = []
_INCIDENT_LINK_COUNTER: int = 0
_INCIDENT_LINK_MAX_ITEMS: int = 1_000


class PromptGuardIncidentLinkView(BaseModel):
    id: str
    incident_id: str
    prompt_excerpt: str
    verdict: GroqSecurityVerdict
    risk_score: int
    audit_event_id: str | None
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardIncidentLinksResponse(BaseModel):
    items: list[PromptGuardIncidentLinkView]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    generated_at: str
    next_page: int | None = None
    prev_page: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardIncidentLinkCreateRequest(BaseModel):
    incident_id: str = Field(..., description="ID of the incident to link to this guarded prompt.")
    prompt_excerpt: str = Field(..., description="Redacted or safe excerpt of the guarded prompt.")
    verdict: GroqSecurityVerdict = Field(..., description="Prompt guard verdict that contributed to this incident.")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score associated with the prompt.")
    audit_event_id: str | None = Field(
        default=None,
        description="Optional audit event id that recorded the original guardrail decision.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional extra context such as client/session IDs.",
    )


def _next_incident_link_id() -> str:
    global _INCIDENT_LINK_COUNTER
    _INCIDENT_LINK_COUNTER += 1
    return f"plink-{_INCIDENT_LINK_COUNTER}"


def _seed_incident_links() -> None:
    """
    Seed a few synthetic links so the UI has something to render
    before the real pipeline wires in.[web:1466][web:1469]
    """
    global _INCIDENT_LINKS, _INCIDENT_LINK_COUNTER

    if _INCIDENT_LINKS:
        return

    if not _INCIDENTS:
        return

    now = _utc_now()

    # Try to pair first couple of incidents with matching audit events by simple heuristic
    seeded: list[PromptGuardIncidentLink] = []
    for idx, incident in enumerate(_INCIDENTS[:2], start=1):
        matching_audit = next(
            (
                a
                for a in _AUDIT_TRAIL
                if a.prompt_excerpt
                and incident.title.lower().split()[0] in a.prompt_excerpt.lower()
            ),
            None,
        )
        link = PromptGuardIncidentLink(
            id=f"plink-{idx}",
            incident_id=incident.id,
            prompt_excerpt=(
                matching_audit.prompt_excerpt
                if matching_audit and matching_audit.prompt_excerpt
                else incident.summary[:160]
            ),
            verdict=matching_audit.verdict if matching_audit and matching_audit.verdict else "warn",
            risk_score=matching_audit.risk_score if matching_audit and matching_audit.risk_score is not None else 60,
            audit_event_id=matching_audit.id if matching_audit else None,
            created_at=now,
            metadata={"seeded": True},
        )
        seeded.append(link)

    _INCIDENT_LINKS.extend(seeded)
    _INCIDENT_LINK_COUNTER = len(_INCIDENT_LINKS)


def _append_incident_link(
    payload: PromptGuardIncidentLinkCreateRequest,
) -> PromptGuardIncidentLink:
    """
    Append a new link entry, enforcing a rolling window.[web:1189][web:1188]
    """
    global _INCIDENT_LINKS

    # Basic validation that incident exists; keep cheap and in-memory
    incident_ids = {inc.id for inc in _INCIDENTS}
    if payload.incident_id not in incident_ids:
        raise HTTPException(status_code=400, detail="Unknown incident_id for prompt guard incident link")

    now = _utc_now()
    link = PromptGuardIncidentLink(
        id=_next_incident_link_id(),
        incident_id=payload.incident_id,
        prompt_excerpt=payload.prompt_excerpt,
        verdict=payload.verdict,
        risk_score=payload.risk_score,
        audit_event_id=payload.audit_event_id,
        created_at=now,
        metadata=dict(payload.metadata),
    )

    _INCIDENT_LINKS.append(link)
    if len(_INCIDENT_LINKS) > _INCIDENT_LINK_MAX_ITEMS:
        _INCIDENT_LINKS = _INCIDENT_LINKS[-_INCIDENT_LINK_MAX_ITEMS:]

    return link


def _paginate_links(
    links: list[PromptGuardIncidentLink],
    page: int,
    page_size: int,
) -> PromptGuardIncidentLinksPage:
    total_items = len(links)
    if total_items == 0:
        return PromptGuardIncidentLinksPage(
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
    slice_items = links[start:end]

    next_page = page + 1 if page < total_pages else None
    prev_page = page - 1 if page > 1 else None

    return PromptGuardIncidentLinksPage(
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


@router.get("/prompt-guard/incident-links", response_model=PromptGuardIncidentLinksResponse)
def get_prompt_guard_incident_links(
    page: int = Query(1, ge=1, description="Page number for prompt guard incident links."),
    page_size: int = Query(20, ge=1, le=100, description="Number of links per page."),
    incident_id: str | None = Query(
        default=None,
        description="Optional filter by incident id.",
    ),
) -> PromptGuardIncidentLinksResponse:
    """
    List links between prompt guard decisions and incidents so operators
    can see which guarded prompts escalated into incidents.[web:1464][web:1466]
    """
    _seed_incident_links()

    links = list(reversed(_INCIDENT_LINKS))
    if incident_id is not None:
        links = [link for link in links if link.incident_id == incident_id]

    page_obj = _paginate_links(links, page=page, page_size=page_size)
    data = page_obj.to_dict()

    return PromptGuardIncidentLinksResponse(
        items=[PromptGuardIncidentLinkView(**item) for item in data["items"]],
        page=data["page"],
        page_size=data["page_size"],
        total_items=data["total_items"],
        total_pages=data["total_pages"],
        generated_at=data["generated_at"],
        next_page=data["next_page"],
        prev_page=data["prev_page"],
        metadata=data["metadata"],
    )


@router.post(
    "/prompt-guard/incident-links",
    response_model=PromptGuardIncidentLinkView,
    status_code=201,
)
def create_prompt_guard_incident_link(
    payload: PromptGuardIncidentLinkCreateRequest,
) -> PromptGuardIncidentLinkView:
    """
    Manually or programmatically link a guarded prompt decision to an
    existing incident, creating a correlation record for audit and UI.[web:1463][web:1468]
    """
    _seed_incident_links()
    link = _append_incident_link(payload)
    return PromptGuardIncidentLinkView(**link.to_dict())