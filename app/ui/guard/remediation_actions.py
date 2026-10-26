from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.guard_security_brain import GuardMode
from app.ui.guard.incidents import IncidentSeverity

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-remediation-actions"],
)

_GENERATION_UNAVAILABLE_DETAIL = "Remediation suggestions require a local generative model. The configured Prompt Guard model only classifies prompts."


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


RemediationKind = Literal[
    "configuration_change",
    "access_control",
    "network_control",
    "detection_rule",
    "data_protection",
    "process_runbook",
    "other",
]

RemediationStatus = Literal["suggested", "queued", "executed", "failed", "cancelled"]


@dataclass(slots=True)
class RemediationAction:
    """AI-suggested remediation step, structured for safe review + later execution."""

    id: str
    kind: RemediationKind
    title: str
    description: str
    status: RemediationStatus
    created_at: str
    updated_at: str
    created_by: str
    target: str
    severity: IncidentSeverity
    estimated_impact: str
    estimated_effort: str
    depends_on: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
            "target": self.target,
            "severity": self.severity,
            "estimated_impact": self.estimated_impact,
            "estimated_effort": self.estimated_effort,
            "depends_on": list(self.depends_on),
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class RemediationSuggestionBundle:
    """A bundle of actions for a single incident or query."""

    source_type: Literal["incident", "freeform"]
    source_id: str | None
    actions: list[RemediationAction]
    generated_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source_id": self.source_id,
            "actions": [a.to_dict() for a in self.actions],
            "generated_at": self.generated_at,
            "metadata": dict(self.metadata),
        }


# In-memory queue placeholder (for UI + worker wiring)
_REMEDIATION_ACTIONS: dict[str, RemediationAction] = {}


# ---------------- Pydantic views --------------------------------------------


class RemediationActionView(BaseModel):
    id: str
    kind: RemediationKind
    title: str
    description: str
    status: RemediationStatus
    created_at: str
    updated_at: str
    created_by: str
    target: str
    severity: IncidentSeverity
    estimated_impact: str
    estimated_effort: str
    depends_on: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RemediationSuggestionResponse(BaseModel):
    source_type: Literal["incident", "freeform"]
    source_id: str | None
    actions: list[RemediationActionView]
    generated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RemediationSuggestFromIncidentRequest(BaseModel):
    incident_id: str = Field(
        ...,
        description="Incident identifier; this endpoint returns 501 until a local generative model is available.",
    )
    mode: GuardMode = Field(
        default="assist",
        description="AI mode context for remediation suggestions.",
    )


class RemediationSuggestFreeformRequest(BaseModel):
    prompt: str = Field(
        ...,
        description="Freeform situation; this endpoint returns 501 until a local generative model is available.",
    )
    mode: GuardMode = Field(
        default="assist",
        description="AI mode context for remediation suggestions.",
    )


class RemediationQueueRequest(BaseModel):
    action_ids: list[str] = Field(
        ...,
        description="IDs of remediation actions to queue for execution.",
    )
    requested_by: str = Field(
        ...,
        description="Identifier of the human/automation requesting queuing.",
    )


class RemediationQueueResponse(BaseModel):
    actions: list[RemediationActionView]
    queued_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------- internal helpers ------------------------------------------


def _queue_actions(action_ids: Sequence[str], requested_by: str) -> list[RemediationAction]:
    now = _utc_now()
    queued: list[RemediationAction] = []
    for aid in action_ids:
        action = _REMEDIATION_ACTIONS.get(aid)
        if not action:
            continue
        action.status = "queued"
        action.updated_at = now
        action.metadata.setdefault("queued_by", requested_by)
        queued.append(action)
    return queued


# ---------------- HTTP endpoints --------------------------------------------


@router.post(
    "/remediation/suggest/incident",
    response_model=RemediationSuggestionResponse,
    responses={501: {"description": "Local generative model unavailable"}},
)
def suggest_remediation_for_incident(
    payload: RemediationSuggestFromIncidentRequest,
) -> RemediationSuggestionResponse:
    raise HTTPException(status_code=501, detail=_GENERATION_UNAVAILABLE_DETAIL)


@router.post(
    "/remediation/suggest/freeform",
    response_model=RemediationSuggestionResponse,
    responses={501: {"description": "Local generative model unavailable"}},
)
def suggest_remediation_freeform(
    payload: RemediationSuggestFreeformRequest,
) -> RemediationSuggestionResponse:
    raise HTTPException(status_code=501, detail=_GENERATION_UNAVAILABLE_DETAIL)


@router.post(
    "/remediation/queue",
    response_model=RemediationQueueResponse,
)
def queue_remediation_actions(
    payload: RemediationQueueRequest,
) -> RemediationQueueResponse:
    """Mark one or more remediation actions as 'queued' for later execution
    by a separate worker. This endpoint does NOT execute any actions itself,
    keeping a strong separation of duties.[web:1292][web:1294]
    """
    queued = _queue_actions(payload.action_ids, requested_by=payload.requested_by)
    now = _utc_now()

    return RemediationQueueResponse(
        actions=[RemediationActionView(**a.to_dict()) for a in queued],
        queued_at=now,
        metadata={
            "requested_by": payload.requested_by,
        },
    )
