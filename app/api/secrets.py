from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.secretservice import build_secret_service


router = APIRouter(prefix="/api/secrets", tags=["secrets"])


class SecretsInspectRequest(BaseModel):
    text: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    content: Any | None = None
    tool_name: str | None = None
    context: str | None = None
    redact_secrets: bool = True
    block_unsafe_commands: bool = True


def _service():
    return build_secret_service()


@router.get("")
def get_secrets_api_overview() -> dict[str, Any]:
    return {
        "ok": True,
        "name": "IronClaw secrets api",
        "routes": [
            "/api/secrets",
            "/api/secrets/inspect",
            "/api/secrets/inspect/text",
            "/api/secrets/inspect/arguments",
            "/api/secrets/inspect/metadata",
            "/api/secrets/health",
        ],
    }


@router.get("/health")
def get_secrets_api_health() -> dict[str, Any]:
    service = _service()
    result = service.inspect_text(
        "health probe",
        context="health_check",
        metadata={"direction": "internal"},
    )
    return {
        "ok": True,
        "service": "secrets",
        "verdict": result.verdict,
        "blocked": result.blocked,
    }


@router.post("/inspect")
def inspect_secret_payload(request: SecretsInspectRequest) -> dict[str, Any]:
    service = _service()

    if request.text is not None:
        result = service.inspect_text(
            request.text,
            context=request.context,
            metadata=request.metadata,
            redact_secrets=request.redact_secrets,
            block_unsafe_commands=request.block_unsafe_commands,
        )
        return result.as_dict()

    if request.arguments:
        result = service.inspect_arguments(
            request.arguments,
            context=request.context,
            metadata=request.metadata,
            redact_secrets=request.redact_secrets,
            block_unsafe_commands=request.block_unsafe_commands,
        )
        return result.as_dict()

    if request.metadata and not request.arguments and request.content is None:
        result = service.inspect_metadata(
            request.metadata,
            context=request.context,
            redact_secrets=request.redact_secrets,
            block_unsafe_commands=request.block_unsafe_commands,
        )
        return result.as_dict()

    result = service.inspect_payload(
        tool_name=request.tool_name,
        arguments=request.arguments,
        metadata=request.metadata,
        content=request.content,
        context=request.context,
        redact_secrets=request.redact_secrets,
        block_unsafe_commands=request.block_unsafe_commands,
    )
    return result.as_dict()


@router.post("/inspect/text")
def inspect_secret_text(request: SecretsInspectRequest) -> dict[str, Any]:
    result = _service().inspect_text(
        request.text or "",
        context=request.context,
        metadata=request.metadata,
        redact_secrets=request.redact_secrets,
        block_unsafe_commands=request.block_unsafe_commands,
    )
    return result.as_dict()


@router.post("/inspect/arguments")
def inspect_secret_arguments(request: SecretsInspectRequest) -> dict[str, Any]:
    result = _service().inspect_arguments(
        request.arguments,
        context=request.context,
        metadata=request.metadata,
        redact_secrets=request.redact_secrets,
        block_unsafe_commands=request.block_unsafe_commands,
    )
    return result.as_dict()


@router.post("/inspect/metadata")
def inspect_secret_metadata(request: SecretsInspectRequest) -> dict[str, Any]:
    result = _service().inspect_metadata(
        request.metadata,
        context=request.context,
        redact_secrets=request.redact_secrets,
        block_unsafe_commands=request.block_unsafe_commands,
    )
    return result.as_dict()


__all__ = ["router"]