from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.groq_security_brain import (
    GroqMode,
    GroqSecurityDecision,
    GroqSecurityVerdict,
    build_groq_security_request,
    evaluate_groq_security_request,
    summarize_groq_security_decision,
)

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-verdict-assist"],
)

HealthState = Literal["healthy", "warning", "critical", "disabled"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- Core dataclasses ----------


@dataclass(slots=True)
class VerdictAssistContext:
    """Raw input and environment used to reach a decision."""

    action_type: str
    target: str
    content: str
    client_id: str | None = None
    session_id: str | None = None
    mode: GroqMode = "assist"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_request_payload(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class VerdictAssistInsight:
    """Human-friendly explanation and hints around a single decision."""

    title: str
    explanation: str
    risk_level: Literal["low", "medium", "high"]
    suggested_mode: GroqMode
    suggested_verdict: GroqSecurityVerdict
    mitigation_tips: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class VerdictAssistView:
    """Aggregate view that UI can render directly."""

    context: VerdictAssistContext
    decision: GroqSecurityDecision
    insight: VerdictAssistInsight
    generated_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": {
                "action_type": self.context.action_type,
                "target": self.context.target,
                "content": self.context.content,
                "client_id": self.context.client_id,
                "session_id": self.context.session_id,
                "mode": self.context.mode,
                "metadata": dict(self.context.metadata),
            },
            "decision": {
                "verdict": self.decision.verdict,
                "risk_score": self.decision.risk_score,
                "decided_at": self.decision.decided_at,
                "signals": list(self.decision.signals),
                "metadata": dict(self.decision.metadata or {}),
            },
            "insight": {
                "title": self.insight.title,
                "explanation": self.insight.explanation,
                "risk_level": self.insight.risk_level,
                "suggested_mode": self.insight.suggested_mode,
                "suggested_verdict": self.insight.suggested_verdict,
                "mitigation_tips": list(self.insight.mitigation_tips),
                "signals": list(self.insight.signals),
                "metadata": dict(self.insight.metadata),
            },
            "generated_at": self.generated_at,
            "metadata": dict(self.metadata),
        }


# ---------- Pydantic models (API schema) ----------


class VerdictAssistContextIn(BaseModel):
    """What the UI sends when it wants help explaining / adjusting a verdict."""

    action_type: str = Field(..., description="High-level type such as shellcommand, toolcall, filewrite, network, prompt.")
    target: str = Field(..., description="Logical target of the action, e.g. local, git, /tmp/file, https://api.example.com.")
    content: str = Field(..., description="The content or payload associated with the action.")
    client_id: str | None = Field(default=None, description="Optional client identifier.")
    session_id: str | None = Field(default=None, description="Optional session identifier.")
    mode: GroqMode = Field(default="assist", description="Current Groq security brain mode.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary additional context from UI.")


class VerdictAssistDecisionView(BaseModel):
    verdict: GroqSecurityVerdict
    risk_score: int
    decided_at: str
    signals: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerdictAssistInsightView(BaseModel):
    title: str
    explanation: str
    risk_level: Literal["low", "medium", "high"]
    suggested_mode: GroqMode
    suggested_verdict: GroqSecurityVerdict
    mitigation_tips: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerdictAssistContextView(BaseModel):
    action_type: str
    target: str
    content: str
    client_id: str | None = None
    session_id: str | None = None
    mode: GroqMode
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerdictAssistResponse(BaseModel):
    context: VerdictAssistContextView
    decision: VerdictAssistDecisionView
    insight: VerdictAssistInsightView
    generated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------- Internal helpers ----------


def _risk_level_from_score(score: int) -> Literal["low", "medium", "high"]:
    if score >= 80:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _base_mitigation_tips(
    *,
    verdict: GroqSecurityVerdict,
    action_type: str,
) -> list[str]:
    tips: list[str] = []

    # Generic by verdict
    if verdict in {"block", "quarantine"}:
        tips.append("Review and tighten the security policy for this action type.")
        tips.append("Verify that this action is actually needed in production before allowing.")
    elif verdict == "warn":
        tips.append("Monitor this action for repeated occurrences from the same client or session.")
        tips.append("Consider upgrading to block or quarantine if this becomes frequent.")
    else:
        tips.append("Keep monitoring outcomes to ensure this action stays safe over time.")

    # Action-specific hints (lightweight heuristics)
    if action_type == "shellcommand":
        tips.append("Limit shell commands to a pre-approved allowlist whenever possible.")
        tips.append("Run commands in a sandboxed environment with restricted privileges.")
    elif action_type == "filewrite":
        tips.append("Restrict write access to sensitive directories and configuration paths.")
        tips.append("Scan written files for malware or embedded secrets when feasible.")
    elif action_type == "network":
        tips.append("Restrict outbound network access to known, trusted destinations.")
        tips.append("Log and audit calls to third-party services for anomalies.")
    elif action_type == "prompt":
        tips.append("Harden prompts against injection and ensure system instructions are enforced.")
        tips.append("Avoid allowing models to see raw secrets or credentials in context.")
    elif action_type == "toolcall":
        tips.append("Scope tool capabilities narrowly and validate all arguments before execution.")
        tips.append("Disable or sandbox tools that can exfiltrate data or mutate critical state.")

    return tips


def _build_verdict_assist_insight(
    *,
    context: VerdictAssistContext,
    decision: GroqSecurityDecision,
) -> VerdictAssistInsight:
    risk_level = _risk_level_from_score(decision.risk_score)

    base_title = "Decision explanation"
    if decision.verdict == "block":
        base_title = "Action blocked by Groq security brain"
    elif decision.verdict == "quarantine":
        base_title = "Action quarantined for review"
    elif decision.verdict == "warn":
        base_title = "Action allowed with warning"
    elif decision.verdict == "allow":
        base_title = "Action allowed"

    explanation = summarize_groq_security_decision(decision)

    suggested_mode: GroqMode = context.mode
    suggested_verdict: GroqSecurityVerdict = decision.verdict

    # Very small “assist” logic: nudge mode / verdict if obviously mismatched.
    if decision.verdict in {"block", "quarantine"} and context.mode == "assist":
        suggested_mode = "enforce"
    if decision.verdict == "allow" and decision.risk_score >= 60:
        suggested_verdict = "warn"

    mitigation_tips = _base_mitigation_tips(
        verdict=decision.verdict,
        action_type=context.action_type,
    )

    return VerdictAssistInsight(
        title=base_title,
        explanation=explanation,
        risk_level=risk_level,
        suggested_mode=suggested_mode,
        suggested_verdict=suggested_verdict,
        mitigation_tips=mitigation_tips,
        signals=list(decision.signals),
        metadata={
            "original_mode": context.mode,
            "original_verdict": decision.verdict,
        },
    )


def build_verdict_assist_view(
    *,
    context_in: VerdictAssistContextIn,
) -> VerdictAssistView:
    ctx = VerdictAssistContext(
        action_type=context_in.action_type,
        target=context_in.target,
        content=context_in.content,
        client_id=context_in.client_id,
        session_id=context_in.session_id,
        mode=context_in.mode,
        metadata=dict(context_in.metadata),
    )

    request = build_groq_security_request(
        action_type=ctx.action_type,
        target=ctx.target,
        content=ctx.content,
        client_id=ctx.client_id,
        session_id=ctx.session_id,
        metadata={**ctx.metadata, "requested_by": "ui-groq-verdict-assist"},
    )

    decision = evaluate_groq_security_request(
        request,
        mode=ctx.mode,
        model_name="groq-security-brain-local",
        extra_metadata={"assist": True},
    )

    insight = _build_verdict_assist_insight(
        context=ctx,
        decision=decision,
    )

    return VerdictAssistView(
        context=ctx,
        decision=decision,
        insight=insight,
        generated_at=_utc_now(),
        metadata={
            "version": "v1",
        },
    )


# ---------- HTTP endpoints ----------


@router.post("/verdict/assist", response_model=VerdictAssistResponse)
def post_verdict_assist(payload: VerdictAssistContextIn) -> VerdictAssistResponse:
    """
    Given a potential action and current mode, evaluate it with the Groq security brain
    and return a rich explanation plus suggested adjustments.
    """
    view = build_verdict_assist_view(context_in=payload)
    data = view.to_dict()

    return VerdictAssistResponse(
        context=VerdictAssistContextView(**data["context"]),
        decision=VerdictAssistDecisionView(**data["decision"]),
        insight=VerdictAssistInsightView(**data["insight"]),
        generated_at=data["generated_at"],
        metadata=data["metadata"],
    )