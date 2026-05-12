from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Header, Request, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/claude/bootstrap",
    tags=["claude-bootstrap"],
    dependencies=[Depends(require_api_key)],
)


class ClaudeGuardMode(str):
    ENFORCE = "enforce"
    ASSIST = "assist"
    DRYRUN = "dryrun"


class ClaudePlatform(str):
    CLAUDE_CODE = "claude-code"


class ClaudeGuardClientConfig(BaseModel):
    guard_base_url: str = Field(
        ...,
        description="Base URL for IronClaw guard endpoints reachable from Claude Code.",
        examples=["https://ironclaw.local", "https://ironclaw.company.com"],
    )
    api_key: str = Field(
        ...,
        description="API key Claude Code should send as X-API-Key when calling IronClaw.",
        min_length=1,
    )
    guard_mode: Literal["enforce", "assist", "dryrun"] = Field(
        "enforce",
        description="Guard behavior mode: enforce (block), assist (warn only), or dryrun.",
    )
    default_timeout_ms: int = Field(
        8000,
        ge=1000,
        le=30000,
        description="Default timeout for guard calls from the Claude Code proxy.",
    )
    max_payload_kb: int = Field(
        256,
        ge=16,
        le=2048,
        description="Maximum size (in KB) of prompt/output bundles Claude Code should send.",
    )
    use_bundle_guard: bool = Field(
        True,
        description="If true, Claude Code sends consolidated prompt/output bundles to /policy/guard-bundle.",
    )
    use_guard_execute: bool = Field(
        True,
        description="If true, tool calls and external actions are sent to /guard/execute.",
    )


class ClaudeBootstrapRequest(BaseModel):
    platform: Literal["claude-code"] = Field(
        "claude-code",
        description="Target platform; currently fixed to claude-code.",
    )
    display_name: str = Field(
        ...,
        description="Human-readable name for this Claude Code workspace/project.",
        min_length=1,
        max_length=128,
    )
    base_guard_url: str | None = Field(
        None,
        description=(
            "Optional override for IronClaw's externally reachable base URL. "
            "If omitted, this is derived from the current request."
        ),
    )
    guard_mode: Literal["enforce", "assist", "dryrun"] = Field(
        "enforce",
        description="Guard mode to advertise to Claude Code clients.",
    )
    default_timeout_ms: int = Field(
        8000,
        ge=1000,
        le=30000,
        description="Default timeout in ms Claude Code should use when calling IronClaw.",
    )
    max_payload_kb: int = Field(
        256,
        ge=16,
        le=2048,
        description="Maximum bundle size Claude Code should send.",
    )


class ClaudeBootstrapResponse(BaseModel):
    generated_at: str = Field(
        ...,
        description="UTC ISO-8601 timestamp when this config was generated.",
    )
    platform: Literal["claude-code"]
    workspace_name: str
    client_config: ClaudeGuardClientConfig
    one_command_snippet: str = Field(
        ...,
        description="Copy-paste shell snippet for wiring Claude Code's proxy to IronClaw.",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Implementation notes and next steps.",
    )


def _infer_external_base_url(request: Request) -> str:
    scheme = request.headers.get("X-Forwarded-Proto") or request.url.scheme
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or request.url.netloc
    return f"{scheme}://{host}".rstrip("/")


def _build_one_command_snippet(
    config: ClaudeGuardClientConfig,
    workspace_name: str,
) -> str:
    safe_name = workspace_name.replace('"', r"\"")
    return (
        "# One-command wiring for Claude Code -> IronClaw guard\n"
        f'export IRONCLAW_GUARD_BASE_URL="{config.guard_base_url}"\n'
        f'export IRONCLAW_GUARD_API_KEY="{config.api_key}"\n'
        f'export IRONCLAW_GUARD_MODE="{config.guard_mode}"\n'
        f'export IRONCLAW_GUARD_TIMEOUT_MS="{config.default_timeout_ms}"\n'
        f'export IRONCLAW_GUARD_MAX_PAYLOAD_KB="{config.max_payload_kb}"\n'
        f'export IRONCLAW_WORKSPACE_NAME="{safe_name}"\n'
        "# Configure your Claude Code proxy/tooling to:\n"
        "#  - Send guarded actions to:  $IRONCLAW_GUARD_BASE_URL/guard/execute\n"
        "#  - Send prompt/output bundles to: $IRONCLAW_GUARD_BASE_URL/policy/guard-bundle\n"
        "#  - Include header: X-API-Key=$IRONCLAW_GUARD_API_KEY on every call\n"
    )


@router.post(
    "",
    response_model=ClaudeBootstrapResponse,
    status_code=status.HTTP_200_OK,
)
def bootstrap_claude_code_guard(
    request: Request,
    payload: ClaudeBootstrapRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
) -> ClaudeBootstrapResponse:
    base_url = payload.base_guard_url or _infer_external_base_url(request)

    client_config = ClaudeGuardClientConfig(
        guard_base_url=base_url,
        api_key=x_api_key,
        guard_mode=payload.guard_mode,
        default_timeout_ms=payload.default_timeout_ms,
        max_payload_kb=payload.max_payload_kb,
        use_bundle_guard=True,
        use_guard_execute=True,
    )

    now = datetime.now(UTC).isoformat()

    snippet = _build_one_command_snippet(
        config=client_config,
        workspace_name=payload.display_name,
    )

    notes = [
        "Configure Claude Code's proxy to send all external tool calls through /guard/execute.",
        "Send combined prompt/context/model output bundles to /policy/guard-bundle before showing them to the user.",
        "Always include X-API-Key using the value from IRONCLAW_GUARD_API_KEY.",
        "Use IRONCLAW_GUARD_MODE to decide whether to enforce blocks or only warn in the UI.",
    ]

    return ClaudeBootstrapResponse(
        generated_at=now,
        platform="claude-code",
        workspace_name=payload.display_name,
        client_config=client_config,
        one_command_snippet=snippet,
        notes=notes,
    )