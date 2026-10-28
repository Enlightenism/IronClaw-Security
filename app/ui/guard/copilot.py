from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from math import floor
from typing import Any, Literal, cast

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.services.guard_security_brain import GuardMode
from app.services.prompt_guard_client import PromptGuardClient
from app.ui.guard.brain_status import build_guard_brain_status_view
from app.ui.guard.control_panel import CONTROL_FLAGS
from app.ui.guard.incidents import _INCIDENTS, seed_demo_incidents
from app.ui.guard.request_stream import _REQUEST_EVENTS, seed_demo_requests

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-copilot"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


CopilotRole = Literal["user", "assistant", "system"]


@dataclass(slots=True)
class CopilotMessage:
    role: CopilotRole
    content: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class CopilotContextSnapshot:
    mode: GuardMode
    posture_score: int
    open_incident_count: int
    recent_high_risk_decisions: int
    control_flags_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "posture_score": self.posture_score,
            "open_incident_count": self.open_incident_count,
            "recent_high_risk_decisions": self.recent_high_risk_decisions,
            "control_flags_summary": dict(self.control_flags_summary),
        }


@dataclass(slots=True)
class CopilotTurn:
    messages: list[CopilotMessage]
    context: CopilotContextSnapshot
    generated_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages": [message.to_dict() for message in self.messages],
            "context": self.context.to_dict(),
            "generated_at": self.generated_at,
            "metadata": dict(self.metadata),
        }


class CopilotHistoryMessage(BaseModel):
    role: CopilotRole
    content: str = Field(..., min_length=1)
    created_at: str | None = Field(
        default=None,
        description="Optional client-side timestamp; server will not rely on this.",
    )


class CopilotChatRequest(BaseModel):
    history: list[CopilotHistoryMessage] = Field(
        default_factory=list,
        description="Previous messages in this chat, oldest first.",
    )
    user_message: str = Field(
        ...,
        min_length=1,
        description="The latest user message to pass to the Copilot.",
    )
    mode: GuardMode | None = Field(
        default=None,
        description="Optional override of current security brain mode for this turn.",
    )


class CopilotMessageView(BaseModel):
    role: CopilotRole
    content: str
    created_at: str


class CopilotContextSnapshotView(BaseModel):
    mode: GuardMode
    posture_score: int
    open_incident_count: int
    recent_high_risk_decisions: int
    control_flags_summary: dict[str, Any] = Field(default_factory=dict)


class CopilotChatResponse(BaseModel):
    messages: list[CopilotMessageView]
    context: CopilotContextSnapshotView
    generated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


def _estimate_posture_score_from_runtime(mode: GuardMode) -> int:
    brain_view = build_guard_brain_status_view(mode=mode)
    status = brain_view.status

    total = max(status.total_evaluations, 1)
    high_risk = status.blocked_count

    high_risk_ratio = high_risk / total

    base = 100.0
    base -= high_risk_ratio * 55.0

    if mode == "disabled":
        base -= 35.0
    elif mode == "observe":
        base -= 20.0
    elif mode == "assist":
        base -= 10.0

    return max(0, min(100, floor(base)))


def _build_context_snapshot(mode: GuardMode | None) -> CopilotContextSnapshot:
    effective_mode: GuardMode = mode or CONTROL_FLAGS.mode

    seed_demo_incidents()
    seed_demo_requests(mode=effective_mode)

    posture_score = _estimate_posture_score_from_runtime(effective_mode)
    open_incident_count = sum(1 for incident in _INCIDENTS if incident.status == "open")
    recent_high_risk_decisions = sum(1 for event in _REQUEST_EVENTS[-50:] if event.risk_score >= RISK_THRESHOLD_BLOCK_MIN or event.verdict == "block")

    control_summary = {
        "mode": CONTROL_FLAGS.mode,
        "allow_shell_commands": CONTROL_FLAGS.allow_shell_commands,
        "allow_network": CONTROL_FLAGS.allow_network,
        "allow_file_write": CONTROL_FLAGS.allow_file_write,
        "allow_prompt_injection_testing": CONTROL_FLAGS.allow_prompt_injection_testing,
        "log_only_mode": CONTROL_FLAGS.log_only_mode,
        "maintenance_mode": CONTROL_FLAGS.maintenance_mode,
        "updated_at": CONTROL_FLAGS.updated_at,
        "updated_by": CONTROL_FLAGS.updated_by,
    }

    return CopilotContextSnapshot(
        mode=effective_mode,
        posture_score=posture_score,
        open_incident_count=open_incident_count,
        recent_high_risk_decisions=recent_high_risk_decisions,
        control_flags_summary=control_summary,
    )


def _system_prompt_for_copilot(context: CopilotContextSnapshot) -> str:
    return (
        "You are the IronClaw Security Copilot for this environment.\n"
        "You know the current AI security posture and must provide concise, actionable guidance to security engineers and operators.\n\n"
        f"Current AI runtime mode: {context.mode}\n"
        f"Estimated security posture score: {context.posture_score}/100\n"
        f"Open AI-created incidents: {context.open_incident_count}\n"
        f"Recent high-risk decisions (last 50): {context.recent_high_risk_decisions}\n"
        f"Control flags summary: {context.control_flags_summary}\n\n"
        "Guidelines:\n"
        "- Focus on cybersecurity, incident response, and AI safety.\n"
        "- When asked for help, give step-by-step but concise recommendations.\n"
        "- When referencing incidents or decisions, suggest how to investigate and mitigate risk rather than just describing.\n"
        "- If the user asks for something out of scope or unsafe, explain why and offer a safer alternative.\n"
    )


def _convert_history(history: Sequence[CopilotHistoryMessage]) -> list[CopilotMessage]:
    return [
        CopilotMessage(
            role=message.role,
            content=message.content,
            created_at=message.created_at or _utc_now(),
        )
        for message in history
    ]


def build_copilot_turn(
    *,
    payload: CopilotChatRequest,
    prompt_guard_client: PromptGuardClient,
) -> CopilotTurn:
    context = _build_context_snapshot(mode=payload.mode)

    system_message = CopilotMessage(
        role="system",
        content=_system_prompt_for_copilot(context),
        created_at=_utc_now(),
    )
    history_messages = _convert_history(payload.history)
    user_message = CopilotMessage(
        role="user",
        content=payload.user_message.strip(),
        created_at=_utc_now(),
    )

    classification = prompt_guard_client.classify(user_message.content)
    if classification is None:
        not_classified_reason = "guard_disabled" if not prompt_guard_client.enabled else "empty_prompt"
        assistant_text = f"Prompt Guard did not classify this message ({not_classified_reason})."
        classification_metadata = {
            "status": "not_classified",
            "reason": not_classified_reason,
        }
        model_name = prompt_guard_client.model_path
    else:
        assistant_text = f"Prompt Guard classification: {classification.label} (malicious score {classification.malicious_score:.3f})."
        classification_metadata = classification.to_dict()
        model_name = classification.model_name

    assistant_message = CopilotMessage(
        role="assistant",
        content=assistant_text,
        created_at=_utc_now(),
    )

    return CopilotTurn(
        messages=[system_message, *history_messages, user_message, assistant_message],
        context=context,
        generated_at=_utc_now(),
        metadata={
            "model": model_name,
            "classification": classification_metadata,
            "mode": context.mode,
            "history_count": len(history_messages),
        },
    )


@router.post("/copilot/chat", response_model=CopilotChatResponse)
def post_copilot_chat(payload: CopilotChatRequest) -> CopilotChatResponse:
    prompt_guard_client = PromptGuardClient.default()
    turn = build_copilot_turn(payload=payload, prompt_guard_client=prompt_guard_client)
    data = turn.to_dict()

    visible_messages = [message for message in cast("list[dict[str, Any]]", data["messages"]) if message["role"] != "system"]

    return CopilotChatResponse(
        messages=[CopilotMessageView(**message) for message in visible_messages],
        context=CopilotContextSnapshotView(**cast("dict[str, Any]", data["context"])),
        generated_at=cast("str", data["generated_at"]),
        metadata=cast("dict[str, Any]", data["metadata"]),
    )
