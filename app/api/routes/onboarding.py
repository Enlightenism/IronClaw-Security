from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/onboarding",
    tags=["onboarding"],
    dependencies=[Depends(require_api_key)],
)


class QuickstartStepView(BaseModel):
    step: int
    title: str
    description: str
    action: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationTargetView(BaseModel):
    integration_id: str
    name: str
    category: str
    status: str
    summary: str


class QuickstartGuideView(BaseModel):
    guide_id: str
    title: str
    audience: str
    summary: str
    steps: list[QuickstartStepView] = Field(default_factory=list)
    integrations: list[IntegrationTargetView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OnboardingResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    guide: QuickstartGuideView


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@router.get("/quickstart", response_model=OnboardingResponse)
def get_quickstart_guide() -> OnboardingResponse:
    return OnboardingResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        guide=QuickstartGuideView(
            guide_id="quickstart-default",
            title="IronClaw Quickstart",
            audience="developers and security teams",
            summary=("Connect IronClaw to guarded prompt, tool, and content workflows so suspicious activity can be blocked, quarantined, reviewed, or released under policy control."),
            steps=[
                QuickstartStepView(
                    step=1,
                    title="Create an API key",
                    description="Generate and store the API key used to authenticate protected routes.",
                    action="Set the X-API-Key header in your client or integration adapter.",
                    metadata={"route_group": "auth"},
                ),
                QuickstartStepView(
                    step=2,
                    title="Protect prompt ingress",
                    description="Send prompts and upstream payloads through IronClaw scanning and proxy boundaries first.",
                    action="Route prompt and tool-bound requests through protected API endpoints before execution.",
                    metadata={"route_group": "scan"},
                ),
                QuickstartStepView(
                    step=3,
                    title="Review incidents and quarantine",
                    description="Inspect quarantined payloads, incidents, and audit events when the system detects risk.",
                    action="Use the incidents, quarantine, and audit endpoints to investigate and resolve detections.",
                    metadata={"route_group": "operations"},
                ),
                QuickstartStepView(
                    step=4,
                    title="Set enforcement policy",
                    description="Tune strictness for blocking, quarantining, sandboxing, and review behavior.",
                    action="Update policy settings to match your desired security posture.",
                    metadata={"route_group": "policy"},
                ),
                QuickstartStepView(
                    step=5,
                    title="Wire alerts and dashboard monitoring",
                    description="Track protected request activity and configure delivery endpoints for important events.",
                    action="Connect alerts and dashboard routes for operations visibility.",
                    metadata={"route_group": "monitoring"},
                ),
            ],
            integrations=[
                IntegrationTargetView(
                    integration_id="claude-router-proxy",
                    name="Claude Router Proxy",
                    category="proxy",
                    status="supported",
                    summary="Protects upstream Claude-compatible routed payloads before release.",
                ),
                IntegrationTargetView(
                    integration_id="secure-runtime",
                    name="Secure Runtime",
                    category="execution-boundary",
                    status="supported",
                    summary="Applies guarded execution decisions before risky agent actions continue.",
                ),
                IntegrationTargetView(
                    integration_id="sandbox-pipeline",
                    name="Sandbox Pipeline",
                    category="containment",
                    status="supported",
                    summary="Contains suspicious returned content inside sandbox-backed review flow.",
                ),
            ],
            metadata={
                "recommended_mode": "enforce",
                "default_decision": "quarantine",
            },
        ),
    )
