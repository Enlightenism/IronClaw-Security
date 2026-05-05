from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.prompt_service import (
    ContextType,
    PromptGuardBundle,
    analyze_prompt_bundle,
)


router = APIRouter()


class GuardedTextResponse(BaseModel):
    context_type: ContextType
    verdict: Literal["allow", "warn", "quarantine", "block"]
    scan_id: str | None
    summary: str
    risk_score: int
    matched_patterns: list[str]
    original_text: str
    effective_text: str
    should_halt: bool
    should_warn: bool
    client_id: str | None = None
    session_id: str | None = None


class PromptGuardRequest(BaseModel):
    user_prompt: str | None = Field(default=None)
    retrieved_doc: str | None = Field(default=None)
    tool_output: str | None = Field(default=None)
    model_output: str | None = Field(default=None)
    client_id: str | None = Field(default=None)
    session_id: str | None = Field(default=None)


class PromptGuardResponse(BaseModel):
    user_prompt: GuardedTextResponse | None
    retrieved_doc: GuardedTextResponse | None
    tool_output: GuardedTextResponse | None
    model_output: GuardedTextResponse | None
    highest_verdict: Literal["allow", "warn", "quarantine", "block"]
    should_halt: bool
    should_warn: bool
    client_id: str | None = None
    session_id: str | None = None


@router.post("/prompt-bundle", response_model=PromptGuardResponse)
def guard_prompt_bundle(payload: PromptGuardRequest) -> PromptGuardResponse:
    result: PromptGuardBundle = analyze_prompt_bundle(
        user_prompt=payload.user_prompt,
        retrieved_doc=payload.retrieved_doc,
        tool_output=payload.tool_output,
        model_output=payload.model_output,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )
    return PromptGuardResponse(**result)