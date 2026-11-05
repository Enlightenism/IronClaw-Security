"""Return gate routes: audit-only scan for post-run observers and replacement transform for blocked returns."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.auth import AuthContext, InstallKeyAuthContext, require_runtime_auth_context
from app.core.billing import resolve_authenticated_billing_owner
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.dependencies.rate_limit import limit_guard_routes
from app.runtime.return_gate import BLOCKED_REPLACEMENT_TEXT, ReturnGateDecision, run_return_gate

router = APIRouter(dependencies=[Depends(limit_guard_routes)])

RETURN_URL_MAX_CHARS = 8_192
RETURN_COMMAND_MAX_CHARS = 32_768
RETURN_FILE_PATH_MAX_CHARS = 4_096
# The payload rides along with every scan window, so its ASCII-escaped size must stay bounded.
RETURN_PAYLOAD_MAX_BYTES = 524_288


class ReturnGateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: str = Field(min_length=1, max_length=64)
    action_type: str = Field(default="tool_output", min_length=1, max_length=128)
    target: str = Field(default="return", min_length=1, max_length=512)
    content: str = Field(default="")
    payload: dict[str, Any] = Field(default_factory=dict)
    url: str | None = Field(default=None, max_length=RETURN_URL_MAX_CHARS)
    command: str | None = Field(default=None, max_length=RETURN_COMMAND_MAX_CHARS)
    file_path: str | None = Field(default=None, max_length=RETURN_FILE_PATH_MAX_CHARS)
    client_id: str | None = Field(default=None, max_length=256)
    session_id: str | None = Field(default=None, max_length=256)
    agent_id: str | None = Field(default=None, max_length=256)

    def effective_payload(self) -> dict[str, Any]:
        merged = dict(self.payload)
        if self.url is not None:
            merged["url"] = self.url
        if self.command is not None:
            merged["command"] = self.command
        if self.file_path is not None:
            merged["file_path"] = self.file_path
        return merged

    @model_validator(mode="after")
    def _bound_payload(self) -> ReturnGateRequest:
        if len(json.dumps(self.effective_payload())) > RETURN_PAYLOAD_MAX_BYTES:
            raise ValueError("payload exceeds the return payload size limit")
        return self


class ReturnGateScanResponse(BaseModel):
    verdict: str
    sandbox_id: str
    stage: str
    reasons: list[str]
    risk_score: int
    audit_only: bool = True


class ReturnGateTransformResponse(BaseModel):
    verdict: str
    sandbox_id: str
    replacement: str | None
    reasons: list[str]


def _resolve_owner_key(platform: str, auth_ctx: AuthContext | InstallKeyAuthContext) -> str | None:
    if isinstance(auth_ctx, InstallKeyAuthContext):
        if InstallKeyFormatRegistry.normalize_program(platform) != auth_ctx.program:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Install key does not match platform")
        return auth_ctx.owner_key
    return resolve_authenticated_billing_owner(auth_ctx)


def _decide(request: ReturnGateRequest, auth_ctx: AuthContext | InstallKeyAuthContext) -> ReturnGateDecision:
    install_key_id = auth_ctx.key_id if isinstance(auth_ctx, InstallKeyAuthContext) else None
    install_program = auth_ctx.program if isinstance(auth_ctx, InstallKeyAuthContext) else None
    return run_return_gate(
        platform=request.platform,
        payload=request.effective_payload(),
        content=request.content,
        action_type=request.action_type,
        target=request.target,
        client_id=request.client_id,
        session_id=request.session_id,
        agent_id=request.agent_id,
        owner_key=_resolve_owner_key(request.platform, auth_ctx),
        install_key_id=install_key_id,
        program=install_program,
    )


@router.post("/scan", response_model=ReturnGateScanResponse)
def scan_return_output(request: ReturnGateRequest, auth_ctx: AuthContext | InstallKeyAuthContext = Depends(require_runtime_auth_context)) -> ReturnGateScanResponse:
    decision = _decide(request, auth_ctx)
    return ReturnGateScanResponse(
        verdict=decision.verdict,
        sandbox_id=decision.sandbox_id,
        stage=decision.stage,
        reasons=decision.reasons,
        risk_score=decision.risk_score,
    )


@router.post("/transform", response_model=ReturnGateTransformResponse)
def transform_return_output(request: ReturnGateRequest, auth_ctx: AuthContext | InstallKeyAuthContext = Depends(require_runtime_auth_context)) -> ReturnGateTransformResponse:
    decision = _decide(request, auth_ctx)
    return ReturnGateTransformResponse(
        verdict=decision.verdict,
        sandbox_id=decision.sandbox_id,
        replacement=BLOCKED_REPLACEMENT_TEXT if decision.blocked else None,
        reasons=decision.reasons,
    )
