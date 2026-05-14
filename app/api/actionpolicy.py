from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.security.promptinjection import scanpromptinjectiondict

router = APIRouter(prefix="/policy", tags=["action-policy"])


PolicyVerdict = Literal["allow", "warn", "quarantine", "block"]
PolicyAction = Literal["allow", "review", "quarantine", "deny"]


class ActionPolicyRequest(BaseModel):
    actiontype: str = Field(..., description="Action type such as httpfetch or toolcall.")
    target: str = Field(..., description="Target such as URL, shell, filesystem path, or tool id.")
    content: str = Field(..., description="Action content, prompt, or instruction text.")
    riskscore: int = Field(..., ge=0, le=100, description="Base risk score before policy adjustments.")
    clientid: str | None = Field(None, description="Client or actor id.")
    sessionid: str | None = Field(None, description="Session or conversation id.")
    filepath: str | None = Field(
        None,
        description="Optional source file path for audit attribution.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional contextual metadata from retrieved content, tool outputs, or files.",
    )


class PolicyReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int


class ActionPolicyResponse(BaseModel):
    actiontype: str
    target: str
    verdict: PolicyVerdict
    action: PolicyAction
    baseriskscore: int
    adjustedriskscore: int
    promptinjectionflagged: bool
    indirectpromptinjectionflagged: bool
    shouldreview: bool
    shouldquarantine: bool
    shouldblock: bool
    filepath: str
    summary: str
    reasons: list[PolicyReasonView] = Field(default_factory=list)
    promptinjection: dict[str, Any] = Field(default_factory=dict)


def _build_policy_reason(source: str, label: str, details: str, score: int) -> dict[str, Any]:
    return {
        "source": source,
        "label": label,
        "details": details,
        "score": score,
    }


def evaluateactionpolicy(
    *,
    actiontype: str,
    target: str,
    content: str,
    riskscore: int,
    clientid: str | None = None,
    sessionid: str | None = None,
    filepath: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    effective_filepath = filepath or "app/api/actionexecute.py"
    effectivemetadata = dict(metadata or {})
    if clientid:
        effectivemetadata.setdefault("clientid", clientid)
    if sessionid:
        effectivemetadata.setdefault("sessionid", sessionid)
    effectivemetadata.setdefault("filepath", effective_filepath)

    promptscan = scanpromptinjectiondict(
        actiontype=actiontype,
        target=target,
        content=content,
        filepath=effective_filepath,
        metadata=effectivemetadata,
    )

    adjustedriskscore = max(0, min(100, int(riskscore) + int(promptscan.get("riskdelta", 0))))
    categories = set(promptscan.get("categories", []))

    shouldquarantine = bool(promptscan.get("shouldquarantine"))
    shouldblock = adjustedriskscore >= 85 and not shouldquarantine
    shouldreview = bool(promptscan.get("shouldreview")) or adjustedriskscore >= 50

    if shouldquarantine:
        verdict: PolicyVerdict = "quarantine"
        action: PolicyAction = "quarantine"
        summary = "Policy quarantined the action because prompt injection indicators crossed containment thresholds."
    elif shouldblock:
        verdict = "block"
        action = "deny"
        summary = "Policy blocked the action because adjusted runtime risk exceeded the execution threshold."
    elif shouldreview:
        verdict = "warn"
        action = "review"
        summary = "Policy routed the action for review because prompt injection or indirect instruction indicators were detected."
    else:
        verdict = "allow"
        action = "allow"
        summary = "Policy allowed the action because no blocking or review threshold was crossed."

    reasons: list[dict[str, Any]] = [
        _build_policy_reason(
            source="policy",
            label="Risk policy evaluation",
            details=(f"Policy evaluated action '{actiontype}' on target '{target}' with base risk {int(riskscore)} and adjusted risk {adjustedriskscore}."),
            score=adjustedriskscore,
        ),
    ]

    for item in promptscan.get("reasons", []):
        if isinstance(item, dict):
            reasons.append(
                {
                    "source": str(item.get("source", "promptinjection")),
                    "label": str(item.get("label", "Prompt injection indicator")),
                    "details": str(item.get("details", "")),
                    "score": int(item.get("score", 0)),
                },
            )
        else:
            reasons.append(
                _build_policy_reason(
                    source="promptinjection",
                    label="Prompt injection indicator",
                    details=str(item),
                    score=0,
                ),
            )

    return {
        "actiontype": actiontype,
        "target": target,
        "verdict": verdict,
        "action": action,
        "baseriskscore": int(riskscore),
        "adjustedriskscore": adjustedriskscore,
        "promptinjectionflagged": bool(promptscan.get("flagged")),
        "indirectpromptinjectionflagged": "indirect_prompt_injection" in categories,
        "shouldreview": shouldreview,
        "shouldquarantine": shouldquarantine,
        "shouldblock": shouldblock,
        "filepath": effective_filepath,
        "summary": summary,
        "reasons": reasons,
        "promptinjection": promptscan,
    }


@router.post(
    "/action",
    response_model=ActionPolicyResponse,
    summary="Evaluate runtime action policy with prompt injection awareness.",
)
def actionpolicy(payload: ActionPolicyRequest) -> ActionPolicyResponse:
    result = evaluateactionpolicy(
        actiontype=payload.actiontype,
        target=payload.target,
        content=payload.content,
        riskscore=payload.riskscore,
        clientid=payload.clientid,
        sessionid=payload.sessionid,
        filepath=payload.filepath,
        metadata=payload.metadata,
    )
    return ActionPolicyResponse(**result)
