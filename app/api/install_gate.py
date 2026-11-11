"""Install gate routes: pre-run evaluation of install commands. IronClaw-pinned installs are allowed; every other install source is scanned and allowed only when clean. Fails closed."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import AuthContext, InstallKeyAuthContext, require_runtime_auth_context
from app.core.billing import resolve_authenticated_billing_owner
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.dependencies.rate_limit import limit_guard_routes
from app.runtime.install_gate import evaluate_install_command

router = APIRouter(dependencies=[Depends(limit_guard_routes)])


class InstallGateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: str = Field(min_length=1, max_length=64)
    command: str = Field(min_length=1, max_length=8192)
    client_id: str | None = Field(default=None, max_length=256)
    agent_id: str | None = Field(default=None, max_length=256)


class InstallGateResponse(BaseModel):
    verdict: str
    family: str
    program: str | None
    pinned: bool
    reasons: list[str]
    artifacts: list[str] = Field(default_factory=list)


def _resolve_owner_key(platform: str, auth_ctx: AuthContext | InstallKeyAuthContext) -> str | None:
    if isinstance(auth_ctx, InstallKeyAuthContext):
        if InstallKeyFormatRegistry.normalize_program(platform) != auth_ctx.program:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Install key does not match platform")
        return auth_ctx.owner_key
    return resolve_authenticated_billing_owner(auth_ctx)


@router.post("/evaluate", response_model=InstallGateResponse)
def evaluate_install(request: InstallGateRequest, auth_ctx: AuthContext | InstallKeyAuthContext = Depends(require_runtime_auth_context)) -> InstallGateResponse:
    decision = evaluate_install_command(
        request.command,
        platform=request.platform,
        agent_id=request.agent_id,
        client_id=request.client_id,
        owner_key=_resolve_owner_key(request.platform, auth_ctx),
        install_key_id=auth_ctx.key_id if isinstance(auth_ctx, InstallKeyAuthContext) else None,
    )
    return InstallGateResponse(
        verdict=decision.verdict,
        family=decision.family,
        program=decision.program,
        pinned=decision.pinned,
        reasons=decision.reasons,
        artifacts=decision.artifacts,
    )
