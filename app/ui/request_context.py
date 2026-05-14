from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/request-context", tags=["request-context"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RequestContextIdentityView(BaseModel):
    client_id: str | None = None
    session_id: str | None = None
    actor_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequestContextRuntimeView(BaseModel):
    environment: str
    service_name: str
    api_version: str
    security_mode: str
    timezone: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequestContextPolicyView(BaseModel):
    prompt_guard_enabled: bool
    action_guard_enabled: bool
    review_required: bool
    default_verdict: str
    escalation_mode: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequestContextLinkView(BaseModel):
    label: str
    path: str
    description: str


class RequestContextResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    identity: RequestContextIdentityView
    runtime: RequestContextRuntimeView
    policy: RequestContextPolicyView
    links: list[RequestContextLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_links() -> list[RequestContextLinkView]:
    return [
        RequestContextLinkView(
            label="Runtime status",
            path="/ui/runtime-status",
            description="Runtime health, availability, and service readiness snapshot.",
        ),
        RequestContextLinkView(
            label="Policy insights",
            path="/ui/insights/policy",
            description="Prompt and action policy interpretation surfaces for operators.",
        ),
        RequestContextLinkView(
            label="Execution explorer",
            path="/ui/executions/explorer",
            description="Execution-level search and filtering across guarded runtime activity.",
        ),
        RequestContextLinkView(
            label="Audit log",
            path="/ui/audit-log",
            description="Audit-backed review trail for requests, decisions, and operations.",
        ),
    ]


@router.get("", response_model=RequestContextResponse)
def get_request_context() -> RequestContextResponse:
    return RequestContextResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        identity=RequestContextIdentityView(
            client_id=None,
            session_id=None,
            actor_id=None,
            request_id=None,
            trace_id=None,
            metadata={
                "identity_state": "unbound",
                "description": "UI request-context view is currently returning a safe default context.",
            },
        ),
        runtime=RequestContextRuntimeView(
            environment="local",
            service_name="IronClaw-Security",
            api_version="gen1",
            security_mode="guarded",
            timezone="UTC",
            metadata={
                "runtime_state": "active",
                "ui_surface": "request-context",
            },
        ),
        policy=RequestContextPolicyView(
            prompt_guard_enabled=True,
            action_guard_enabled=True,
            review_required=False,
            default_verdict="allow",
            escalation_mode="review-on-risk",
            metadata={
                "policy_source": "request-context-ui-default",
                "supports_trace_binding": True,
            },
        ),
        links=_build_links(),
        notes=[
            "Request context provides a normalized view of request identity, runtime state, and policy posture.",
            "This Gen1 UI surface starts with a safe default context when no bound request metadata is available.",
            "Downstream routes can use request, session, and trace identifiers to hydrate richer context later.",
        ],
    )
