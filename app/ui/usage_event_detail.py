from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Path
from pydantic import BaseModel, Field


router = APIRouter(prefix="/usage-events/detail", tags=["usage-event-detail"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class UsageEventIdentityView(BaseModel):
    event_id: str
    client_id: str | None = None
    session_id: str | None = None
    actor_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventGuardView(BaseModel):
    verdict: str
    guard_mode: str
    policy_profile: str
    blocked: bool
    truncated: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventBillingView(BaseModel):
    units_consumed: int
    unit_type: str
    package_id: str | None = None
    wallet_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventContextView(BaseModel):
    method: str
    path: str
    upstream_url: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventLinkView(BaseModel):
    label: str
    path: str
    description: str


class UsageEventDetailResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    identity: UsageEventIdentityView
    guard: UsageEventGuardView
    billing: UsageEventBillingView
    context: UsageEventContextView
    links: list[UsageEventLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_links(event_id: str, session_id: str | None, client_id: str | None) -> list[UsageEventLinkView]:
    links: list[UsageEventLinkView] = [
        UsageEventLinkView(
            label="Usage reports",
            path="/ui/usage-reports",
            description="Return to aggregated usage summaries and recent events.",
        ),
        UsageEventLinkView(
            label="Audit log",
            path="/ui/audit-log",
            description="Inspect the full audit trail for related decisions.",
        ),
    ]

    if session_id:
        links.append(
            UsageEventLinkView(
                label="Session timeline",
                path=f"/ui/activity/sessiontimeline/{session_id}",
                description="Timeline view for all activity in this session.",
            )
        )

    if client_id:
        links.append(
            UsageEventLinkView(
                label="Client profile",
                path=f"/ui/activity/clientprofile/{client_id}",
                description="Profile view for the client associated with this usage.",
            )
        )

    return links


@router.get("/{event_id}", response_model=UsageEventDetailResponse)
def get_usage_event_detail(
    event_id: str = Path(..., min_length=1, max_length=255),
) -> UsageEventDetailResponse:
    normalized_event_id = event_id.strip()

    # Gen1 UI returns a safe, self-describing default detail view.
    client_id = "default-client"
    session_id = "default-session"

    identity = UsageEventIdentityView(
        event_id=normalized_event_id,
        client_id=client_id,
        session_id=session_id,
        actor_id=None,
        request_id=None,
        trace_id=None,
        metadata={
            "identity_state": "unbound",
            "description": "Usage event identity is currently represented with a default context.",
        },
    )

    guard = UsageEventGuardView(
        verdict="allow",
        guard_mode="assist",
        policy_profile="default-usage-event",
        blocked=False,
        truncated=False,
        metadata={
            "policy_source": "usage-event-detail-ui",
            "supports_prompt_guard": True,
            "supports_action_guard": True,
        },
    )

    billing = UsageEventBillingView(
        units_consumed=0,
        unit_type="unit",
        package_id=None,
        wallet_id=None,
        metadata={
            "billing_state": "not-charged",
            "description": "No units were consumed in this default usage event view.",
        },
    )

    context = UsageEventContextView(
        method="POST",
        path="/scan",
        upstream_url=None,
        ip_address=None,
        user_agent=None,
        metadata={
            "ui_surface": "usage-event-detail",
            "environment": "local",
        },
    )

    return UsageEventDetailResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        identity=identity,
        guard=guard,
        billing=billing,
        context=context,
        links=_build_links(normalized_event_id, session_id=session_id, client_id=client_id),
        notes=[
            "Usage event detail provides a focused view of a single metered security event.",
            "Gen1 UI returns a safe default representation until the usage-reports backend is wired in.",
            "Downstream iterations can hydrate this view with real usage, billing, and guard metadata.",
        ],
    )