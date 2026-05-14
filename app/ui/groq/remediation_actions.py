from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.groq_client import GroqChatClient  # you implement this
from app.services.groq_security_brain import GroqMode
from app.ui.groq.brain_status import build_groq_brain_status_view
from app.ui.groq.control_panel import CONTROL_FLAGS
from app.ui.groq.incidents import _INCIDENTS, IncidentSeverity

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-remediation-actions"],
)


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
_REMEDIATION_BUNDLES: dict[str, RemediationSuggestionBundle] = {}
_REMEDIATION_COUNTER: int = 0


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
    incident_id: str = Field(..., description="Incident to generate remediation for.")
    mode: GroqMode = Field(
        default="assist",
        description="AI mode context for remediation suggestions.",
    )


class RemediationSuggestFreeformRequest(BaseModel):
    prompt: str = Field(
        ...,
        description="Freeform security situation or question for which to propose remediation.",
    )
    mode: GroqMode = Field(
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


def _next_action_id() -> str:
    global _REMEDIATION_COUNTER
    _REMEDIATION_COUNTER += 1
    return f"remedy-{_REMEDIATION_COUNTER}"


def _severity_from_incident_severity(inc_sev: IncidentSeverity) -> IncidentSeverity:
    return inc_sev


def _posture_summary_for_prompt() -> str:
    brain_view = build_groq_brain_status_view(mode=CONTROL_FLAGS.mode)
    status = brain_view.status

    total = max(status.total_evaluations, 1)
    blocked = status.blocked_count
    quarantined = status.quarantined_count
    warns = status.warned_count

    open_incidents = [i for i in _INCIDENTS if i.status == "open"]

    summary = f"Runtime mode: {CONTROL_FLAGS.mode}. Recent decisions: {total} total, {blocked} blocked, {quarantined} quarantined, {warns} warned. Open incidents: {len(open_incidents)}."
    return summary


def _system_prompt_for_remediation(incident_text: str | None, free_text: str | None) -> str:
    """System prompt that asks Groq to output *structured* remediation actions.[web:1292][web:1296]"""
    base = (
        "You are an AI security remediation planner. "
        "Given a security incident or situation description, propose a small set of "
        "concrete remediation actions. Each action should be precise, safe-by-default, "
        "and suitable for approval and later automated execution.\n\n"
        "Focus on:\n"
        "- Configuration hardening\n"
        "- Access control and identity\n"
        "- Network restrictions\n"
        "- Detection/monitoring improvements\n"
        "- Data protection and secrets management\n\n"
        "Output actions as JSON with this schema (array of objects):\n"
        "[\n"
        "  {\n"
        '    "kind": "configuration_change" | "access_control" | '
        '"network_control" | "detection_rule" | "data_protection" | '
        '"process_runbook" | "other",\n'
        '    "title": "short human-readable title",\n'
        '    "description": "clear step-by-step remediation description",\n'
        '    "target": "what system/asset/app this applies to",\n'
        '    "severity": "low" | "medium" | "high" | "critical",\n'
        '    "estimated_impact": "short description of risk reduction",\n'
        '    "estimated_effort": "low" | "medium" | "high",\n'
        '    "depends_on": ["optional id-like or label of prerequisite step"],\n'
        '    "tags": ["short tags for filtering, like incident type or system"]\n'
        "  }\n"
        "]\n\n"
        "Return only valid JSON, no extra commentary.\n"
    )

    context_bits = []

    posture = _posture_summary_for_prompt()
    context_bits.append(f"Current AI posture summary: {posture}")

    if incident_text:
        context_bits.append(f"Incident context: {incident_text}")

    if free_text:
        context_bits.append(f"Freeform context: {free_text}")

    context_str = "\n".join(context_bits)
    return base + "\n" + context_str


def _parse_actions_from_model_output(raw: str) -> list[dict[str, Any]]:
    import json

    # Be tolerant: try to parse even if model adds whitespace or newlines.
    raw = raw.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [a for a in data if isinstance(a, dict)]
        if isinstance(data, dict):
            # Allow a top-level object with an "actions" array
            arr = data.get("actions")
            if isinstance(arr, list):
                return [a for a in arr if isinstance(a, dict)]
    except Exception:
        return []
    return []


def _bundle_from_incident(
    *,
    incident_id: str,
    mode: GroqMode,
    groq_client: GroqChatClient,
) -> RemediationSuggestionBundle:
    incident = next((i for i in _INCIDENTS if i.id == incident_id), None)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    incident_text = f"Incident title: {incident.title}. Severity: {incident.severity}. Description: {incident.description}. Signals: {', '.join(incident.signals) or 'none'}."

    system_prompt = _system_prompt_for_remediation(incident_text=incident_text, free_text=None)

    model_output = groq_client.chat(
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "Propose remediation actions for this incident.",
            },
        ],
        model="groq-security-remediation",
        metadata={
            "source": "incident",
            "incident_id": incident_id,
            "mode": mode,
        },
    )

    raw_actions = _parse_actions_from_model_output(model_output)

    now = _utc_now()
    actions: list[RemediationAction] = []

    for item in raw_actions:
        action_id = _next_action_id()
        kind: RemediationKind = item.get("kind", "other")  # type: ignore[assignment]
        sev: IncidentSeverity = item.get("severity", incident.severity)  # type: ignore[assignment]

        action = RemediationAction(
            id=action_id,
            kind=kind,
            title=item.get("title", "Remediation step"),
            description=item.get("description", ""),
            status="suggested",
            created_at=now,
            updated_at=now,
            created_by="groq-security-remediation-ai",
            target=item.get("target", incident.target or "unknown target"),
            severity=_severity_from_incident_severity(sev),
            estimated_impact=item.get("estimated_impact", "Reduce risk related to this incident."),
            estimated_effort=item.get("estimated_effort", "medium"),
            depends_on=list(item.get("depends_on", [])),
            tags=list(item.get("tags", [])),
            metadata={
                "source": "incident",
                "incident_id": incident_id,
            },
        )
        _REMEDIATION_ACTIONS[action_id] = action
        actions.append(action)

    bundle = RemediationSuggestionBundle(
        source_type="incident",
        source_id=incident_id,
        actions=actions,
        generated_at=now,
        metadata={
            "mode": mode,
        },
    )

    _REMEDIATION_BUNDLES[incident_id] = bundle
    return bundle


def _bundle_from_freeform(
    *,
    prompt: str,
    mode: GroqMode,
    groq_client: GroqChatClient,
) -> RemediationSuggestionBundle:
    system_prompt = _system_prompt_for_remediation(incident_text=None, free_text=prompt)

    model_output = groq_client.chat(
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "Propose remediation actions for this situation.",
            },
        ],
        model="groq-security-remediation",
        metadata={
            "source": "freeform",
            "mode": mode,
        },
    )

    raw_actions = _parse_actions_from_model_output(model_output)

    now = _utc_now()
    actions: list[RemediationAction] = []

    # Default severity for freeform if not included
    default_sev: IncidentSeverity = "medium"

    for item in raw_actions:
        action_id = _next_action_id()
        kind: RemediationKind = item.get("kind", "other")  # type: ignore[assignment]
        sev: IncidentSeverity = item.get("severity", default_sev)  # type: ignore[assignment]

        action = RemediationAction(
            id=action_id,
            kind=kind,
            title=item.get("title", "Remediation step"),
            description=item.get("description", ""),
            status="suggested",
            created_at=now,
            updated_at=now,
            created_by="groq-security-remediation-ai",
            target=item.get("target", "unspecified"),
            severity=_severity_from_incident_severity(sev),
            estimated_impact=item.get("estimated_impact", "Reduce risk related to this situation."),
            estimated_effort=item.get("estimated_effort", "medium"),
            depends_on=list(item.get("depends_on", [])),
            tags=list(item.get("tags", [])),
            metadata={
                "source": "freeform",
            },
        )
        _REMEDIATION_ACTIONS[action_id] = action
        actions.append(action)

    bundle_id = f"freeform-{hash(prompt) & 0xFFFFFFFF:x}"

    bundle = RemediationSuggestionBundle(
        source_type="freeform",
        source_id=bundle_id,
        actions=actions,
        generated_at=now,
        metadata={
            "mode": mode,
        },
    )

    _REMEDIATION_BUNDLES[bundle_id] = bundle
    return bundle


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
)
def suggest_remediation_for_incident(
    payload: RemediationSuggestFromIncidentRequest,
) -> RemediationSuggestionResponse:
    """Ask the AI to propose structured remediation actions for a given incident.

    The response includes actions with stable IDs that can later be queued
    for execution by a separate worker layer.[web:1292][web:1293]
    """
    groq_client = GroqChatClient.default()

    bundle = _bundle_from_incident(
        incident_id=payload.incident_id,
        mode=payload.mode,
        groq_client=groq_client,
    )
    data = bundle.to_dict()

    return RemediationSuggestionResponse(
        source_type=data["source_type"],
        source_id=data["source_id"],
        actions=[RemediationActionView(**a) for a in data["actions"]],
        generated_at=data["generated_at"],
        metadata=data["metadata"],
    )


@router.post(
    "/remediation/suggest/freeform",
    response_model=RemediationSuggestionResponse,
)
def suggest_remediation_freeform(
    payload: RemediationSuggestFreeformRequest,
) -> RemediationSuggestionResponse:
    """Ask the AI to propose structured remediation actions for a freeform
    security situation or question.[web:1292][web:1277]
    """
    groq_client = GroqChatClient.default()

    bundle = _bundle_from_freeform(
        prompt=payload.prompt,
        mode=payload.mode,
        groq_client=groq_client,
    )
    data = bundle.to_dict()

    return RemediationSuggestionResponse(
        source_type=data["source_type"],
        source_id=data["source_id"],
        actions=[RemediationActionView(**a) for a in data["actions"]],
        generated_at=data["generated_at"],
        metadata=data["metadata"],
    )


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
