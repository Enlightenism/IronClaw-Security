from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, status
from telemetryaccess import get_usage_event_by_id

router = APIRouter(prefix="/ui/usageevents", tags=["ui-usage-events"])


def _field(
    *,
    name: str,
    label: str,
    value: Any | None = None,
    field_type: str = "text",
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": field_type,
        "value": value,
        "help_text": help_text,
    }


def _section(
    *,
    id: str,
    title: str,
    description: str,
    fields: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "description": description,
        "fields": fields or [],
    }


def _action(
    *,
    id: str,
    title: str,
    method: str,
    path: str,
    description: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "method": method,
        "path": path,
        "description": description,
        "payload": payload,
    }


@router.get(
    "/{event_id}/detail",
    response_model=dict[str, Any],
)
def usage_event_detail_page(
    event_id: str = Path(..., description="Usage / telemetry event identifier."),
    include_raw_payload: bool = Query(
        default=False,
        description="If true, include raw event payload in the UI metadata.",
    ),
) -> dict[str, Any]:
    """UI metadata endpoint for a single usage / telemetry event.

    This returns a shape optimized for route-driven UI:
    - High-level attributes for quick scan (timestamp, source, principal, key)
    - Context and classification fields
    - Optional raw payload for deep debugging
    """
    try:
        event = get_usage_event_by_id(event_id)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to load usage event: {exc}",
        ) from exc

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usage event not found",
        )

    def g(key: str, default: Any = None) -> Any:
        return event.get(key, default)

    identity_section = _section(
        id="identity",
        title="Identity",
        description="Who initiated this event and under which API context it ran.",
        fields=[
            _field(
                name="event_id",
                label="Event ID",
                value=g("id", event_id),
            ),
            _field(
                name="timestamp",
                label="Timestamp",
                value=g("timestamp"),
                help_text="UTC timestamp when this event was recorded.",
            ),
            _field(
                name="principal_type",
                label="Principal Type",
                value=g("principal_type"),
                help_text="Type of principal (customer, operator, system, integration, etc.).",
            ),
            _field(
                name="principal_id",
                label="Principal ID",
                value=g("principal_id"),
                help_text="Stable identifier for the authenticated principal.",
            ),
            _field(
                name="api_key_id",
                label="API Key ID",
                value=g("api_key_id"),
                help_text="Internal identifier of the API key used, if applicable.",
            ),
            _field(
                name="api_key_scope",
                label="API Key Scope",
                value=g("api_key_scope"),
                help_text="Scope of the API key (customer, operator, internal).",
            ),
        ],
    )

    request_section = _section(
        id="request",
        title="Request Context",
        description="Context attached at the time of the request to enable correlation and decisions.",
        fields=[
            _field(
                name="request_id",
                label="Request ID",
                value=g("request_id"),
                help_text="Correlates this event with other logs and traces.",
            ),
            _field(
                name="session_id",
                label="Session ID",
                value=g("session_id"),
                help_text="Session identifier used for related-event history.",
            ),
            _field(
                name="user_id",
                label="User ID",
                value=g("user_id"),
                help_text="End-user identity, when the principal represents a broader account.",
            ),
            _field(
                name="source",
                label="Source",
                value=g("source"),
                help_text="Origin of the request (api, ui-console, integration, cli, etc.).",
            ),
            _field(
                name="route",
                label="Route",
                value=g("route"),
                help_text="API route that handled this event.",
            ),
            _field(
                name="method",
                label="HTTP Method",
                value=g("method"),
            ),
            _field(
                name="client_ip",
                label="Client IP",
                value=g("client_ip"),
                help_text="Remote address if captured by the telemetry pipeline.",
            ),
            _field(
                name="user_agent",
                label="User Agent",
                value=g("user_agent"),
                help_text="Reported user agent string, if present.",
            ),
        ],
    )

    metering_section = _section(
        id="metering",
        title="Usage & Metering",
        description="Metered usage for billing, limits, and analytics.",
        fields=[
            _field(
                name="unit_type",
                label="Unit Type",
                value=g("unit_type"),
                help_text="Logical unit type tracked for this event (requests, tokens, scans, etc.).",
            ),
            _field(
                name="unit_count",
                label="Unit Count",
                value=g("unit_count"),
                field_type="number",
                help_text="Quantity of the metered unit consumed by this event.",
            ),
            _field(
                name="plan",
                label="Plan",
                value=g("plan"),
                help_text="Billing or package plan associated with this usage.",
            ),
            _field(
                name="billing_account_id",
                label="Billing Account ID",
                value=g("billing_account_id"),
            ),
            _field(
                name="trace_id",
                label="Trace ID",
                value=g("trace_id"),
                help_text="Distributed trace identifier when available.",
            ),
        ],
    )

    guard_section = _section(
        id="guard",
        title="Security / Guardrail Context",
        description="How this event interacted with IronClaw guardrails and decisioning.",
        fields=[
            _field(
                name="guard_policy_id",
                label="Guard Policy ID",
                value=g("guard_policy_id"),
                help_text="Identifier of the guardrail policy that applied to this request.",
            ),
            _field(
                name="guard_verdict",
                label="Guard Verdict",
                value=g("guard_verdict"),
                help_text="High-level verdict (allow, warn, block, quarantine).",
            ),
            _field(
                name="guard_mode",
                label="Guard Mode",
                value=g("guard_mode"),
                help_text="Mode in effect (enforce, monitor, strict).",
            ),
            _field(
                name="risk_score",
                label="Risk Score",
                value=g("risk_score"),
                field_type="number",
            ),
            _field(
                name="sandbox_lane",
                label="Sandbox Lane",
                value=g("sandbox_lane"),
                help_text="Lane used when content was detonated or isolated.",
            ),
        ],
    )

    sections = [identity_section, request_section, metering_section, guard_section]

    raw_payload: dict[str, Any] | None = None
    if include_raw_payload:
        raw_payload = {
            "event": event,
        }

    actions = [
        _action(
            id="related-events",
            title="View related events",
            method="GET",
            path="/ui/usagereports",
            description="Open usage reports filtered to the same principal, session, or request for broader investigation.",
            payload={
                "principal_id": g("principal_id"),
                "session_id": g("session_id"),
                "request_id": g("request_id"),
            },
        ),
        _action(
            id="open-request-context",
            title="Open request context view",
            method="GET",
            path="/ui/requestcontext",
            description="Jump to the request context builder pre-populated with identifiers from this event.",
            payload={
                "mode": g("guard_mode") or "enforce",
                "target_type": g("target_type") or "text",
            },
        ),
    ]

    return {
        "page": "usage-event-detail",
        "title": "Usage Event Detail",
        "summary": "Inspect a single metered usage event and its security context.",
        "event_id": event_id,
        "sections": sections,
        "actions": actions,
        "raw": raw_payload,
    }
