from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.services.policy_store import (
    PolicySettingsRecord as StoredPolicySettingsRecord,
)
from app.services.policy_store import (
    PolicyThresholdRecord,
    get_policy_store,
)

router = APIRouter(
    prefix="/policy",
    tags=["policy"],
    dependencies=[Depends(require_api_key)],
)


PolicyMode = Literal["monitor", "enforce", "lockdown"]
PolicyDecision = Literal["allow", "warn", "quarantine", "block"]


class PolicyThresholdsView(BaseModel):
    prompt_injection_score: float = Field(ge=0.0, le=1.0)
    malware_score: float = Field(ge=0.0, le=1.0)
    exfiltration_score: float = Field(ge=0.0, le=1.0)
    tool_abuse_score: float = Field(ge=0.0, le=1.0)


class PolicySettingsView(BaseModel):
    policy_id: str
    mode: PolicyMode
    default_decision: PolicyDecision
    require_human_review_for_quarantine: bool
    sandbox_all_untrusted_content: bool
    block_high_risk_tool_calls: bool
    strict_prompt_ingress: bool
    thresholds: PolicyThresholdsView
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicySettingsResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    settings: PolicySettingsView


class PolicyUpdateRequest(BaseModel):
    mode: PolicyMode
    default_decision: PolicyDecision
    require_human_review_for_quarantine: bool
    sandbox_all_untrusted_content: bool
    block_high_risk_tool_calls: bool
    strict_prompt_ingress: bool
    thresholds: PolicyThresholdsView
    metadata: dict[str, Any] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _to_view(settings: StoredPolicySettingsRecord) -> PolicySettingsView:
    data = settings.to_dict()
    return PolicySettingsView(
        policy_id=data["policy_id"],
        mode=data["mode"],
        default_decision=data["default_decision"],
        require_human_review_for_quarantine=data["require_human_review_for_quarantine"],
        sandbox_all_untrusted_content=data["sandbox_all_untrusted_content"],
        block_high_risk_tool_calls=data["block_high_risk_tool_calls"],
        strict_prompt_ingress=data["strict_prompt_ingress"],
        thresholds=PolicyThresholdsView(**data["thresholds"]),
        updated_at=data["updated_at"],
        metadata=data["metadata"],
    )


@router.get("/settings", response_model=PolicySettingsResponse)
def get_policy_settings() -> PolicySettingsResponse:
    settings = get_policy_store().get_settings()
    return PolicySettingsResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        settings=_to_view(settings),
    )


@router.put("/settings", response_model=PolicySettingsResponse)
def update_policy_settings(payload: PolicyUpdateRequest) -> PolicySettingsResponse:
    settings = get_policy_store().update_settings(
        mode=payload.mode,
        default_decision=payload.default_decision,
        require_human_review_for_quarantine=payload.require_human_review_for_quarantine,
        sandbox_all_untrusted_content=payload.sandbox_all_untrusted_content,
        block_high_risk_tool_calls=payload.block_high_risk_tool_calls,
        strict_prompt_ingress=payload.strict_prompt_ingress,
        thresholds=PolicyThresholdRecord(
            prompt_injection_score=payload.thresholds.prompt_injection_score,
            malware_score=payload.thresholds.malware_score,
            exfiltration_score=payload.thresholds.exfiltration_score,
            tool_abuse_score=payload.thresholds.tool_abuse_score,
        ),
        metadata=payload.metadata,
    )

    return PolicySettingsResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        settings=_to_view(settings),
    )
