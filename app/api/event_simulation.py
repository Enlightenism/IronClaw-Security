from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationError

from app.core.auth import AuthContext, get_auth_context

logger = logging.getLogger(__name__)


router = APIRouter(tags=["event-simulation"])


AllowedVerdict = Literal["allow", "warn", "quarantine", "block"]
AllowedEventType = Literal[
    "prompt_injection",
    "tool_execution",
    "data_exfiltration",
    "unsafe_action",
    "policy_violation",
    "auth_failure",
    "telemetry_gap",
]


class EventSimulationRequest(BaseModel):
    event_type: AllowedEventType = Field(..., description="Simulation scenario type.")
    organization_id: str | None = Field(
        default=None,
        description="Optional organization identifier associated with the simulation.",
    )
    actor_id: str | None = Field(
        default=None,
        description="Optional actor/user identifier associated with the simulation.",
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        default="medium",
        description="Requested severity level for the simulated event.",
    )
    prompt: str | None = Field(
        default=None,
        description="Optional untrusted prompt or content sample used for simulation.",
    )
    tool_name: str | None = Field(
        default=None,
        description="Optional tool name relevant to the simulated action.",
    )
    target: str | None = Field(
        default=None,
        description="Optional target resource, path, domain, or data class.",
    )
    payload: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured payload for the simulated event.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form simulation metadata for UI/testing workflows.",
    )


class EventSimulationResponse(BaseModel):
    ok: bool = True
    simulated: bool = True
    event_type: AllowedEventType
    severity: Literal["low", "medium", "high", "critical"]
    verdict: AllowedVerdict
    reasons: list[str]
    recommended_actions: list[str]
    auth: dict[str, Any]
    event: dict[str, Any]


def _build_verdict(
    request: EventSimulationRequest,
) -> tuple[AllowedVerdict, list[str], list[str]]:
    reasons: list[str] = []
    actions: list[str] = []

    if request.event_type == "prompt_injection":
        verdict: AllowedVerdict = "block" if request.severity in {"high", "critical"} else "warn"
        reasons.append("Simulated prompt-injection pattern requires defensive handling.")
        actions.extend(
            [
                "Treat all embedded instructions as untrusted content.",
                "Strip or isolate untrusted prompt segments before model execution.",
                "Require human review for downstream tool usage if risk persists.",
            ]
        )
    elif request.event_type == "tool_execution":
        verdict = "quarantine" if request.severity in {"high", "critical"} else "warn"
        reasons.append("Simulated tool execution needs policy and sandbox validation.")
        actions.extend(
            [
                "Validate tool allowlist and argument policy before execution.",
                "Run the action in a sandboxed boundary with least privilege.",
                "Require approval for state-changing or external-network actions.",
            ]
        )
    elif request.event_type == "data_exfiltration":
        verdict = "block"
        reasons.append("Simulated data-exfiltration path is treated as a hard stop.")
        actions.extend(
            [
                "Block outbound transfer of secrets, tokens, and protected data classes.",
                "Redact sensitive values before model/tool exposure.",
                "Escalate to review workflow and retain audit evidence.",
            ]
        )
    elif request.event_type == "unsafe_action":
        verdict = "block" if request.severity in {"high", "critical"} else "quarantine"
        reasons.append("Simulated unsafe action crosses runtime safety boundaries.")
        actions.extend(
            [
                "Pause execution and require explicit approval.",
                "Constrain the runtime scope, permissions, and side effects.",
                "Log the proposed action and rationale for review.",
            ]
        )
    elif request.event_type == "policy_violation":
        verdict = "quarantine"
        reasons.append("Simulated request violates declared security policy.")
        actions.extend(
            [
                "Return a structured denial reason to the caller.",
                "Route the event to policy review or exception workflow.",
                "Retain policy-match telemetry for auditing.",
            ]
        )
    elif request.event_type == "auth_failure":
        verdict = "block"
        reasons.append("Simulated authentication failure prevents trusted execution.")
        actions.extend(
            [
                "Reject the request and verify bearer token or API-key configuration.",
                "Confirm organization/user binding before retry.",
                "Capture auth failure telemetry without exposing secrets.",
            ]
        )
    else:
        verdict = "warn"
        reasons.append("Simulated telemetry gap reduces observability and trust.")
        actions.extend(
            [
                "Record structured telemetry for prompts, tools, and policy decisions.",
                "Ensure audit correlation IDs are present end to end.",
                "Backfill missing review and runtime boundary events.",
            ]
        )

    if request.prompt:
        reasons.append("Prompt payload included in simulation input.")
    if request.tool_name:
        reasons.append(f"Tool context included: {request.tool_name}.")
    if request.target:
        reasons.append(f"Target context included: {request.target}.")

    return verdict, reasons, actions


def _serialize_auth(context: AuthContext) -> dict[str, Any]:
    return {
        "principal_id": getattr(context, "principal_id", None),
        "principal_type": getattr(context, "principal_type", None),
        "organization_id": getattr(context, "organization_id", None),
        "roles": list(getattr(context, "roles", []) or []),
        "authenticated": True,
    }


@router.post(
    "/simulate",
    response_model=EventSimulationResponse,
    status_code=status.HTTP_200_OK,
)
async def simulate_event(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> EventSimulationResponse:
    raw_json: dict[str, Any] | None = None
    try:
        raw_json = await request.json()
    except Exception:
        raw_json = None

    payload_keys = list(raw_json.keys()) if isinstance(raw_json, dict) else []

    try:
        parsed = EventSimulationRequest(**(raw_json or {}))
    except ValidationError as exc:
        errors_summary = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
        logger.warning(
            "Event simulation validation failed: origin=%s keys=%s errors=%s",
            getattr(request, "base_url", None),
            payload_keys,
            errors_summary,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "validation_failed", "errors": errors_summary},
        ) from exc

    request_model = parsed

    org_id_from_body = request_model.organization_id
    org_id_from_auth = getattr(auth, "organization_id", None)
    organization_id = org_id_from_body or org_id_from_auth

    if org_id_from_body:
        org_source = "body"
    elif org_id_from_auth:
        org_source = "auth"
    else:
        org_source = "unresolved"

    logger.debug(
        "Event simulation organization_id resolution: source=%s body=%s auth=%s final=%s",
        org_source,
        org_id_from_body,
        org_id_from_auth,
        organization_id,
    )

    if not organization_id and request_model.event_type in {
        "tool_execution",
        "data_exfiltration",
        "unsafe_action",
        "policy_violation",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="organization_id is required for this simulation type.",
        )

    verdict, reasons, recommended_actions = _build_verdict(request_model)

    event: dict[str, Any] = {
        "type": request_model.event_type,
        "severity": request_model.severity,
        "organization_id": organization_id,
        "actor_id": request_model.actor_id or getattr(auth, "principal_id", None),
        "tool_name": request_model.tool_name,
        "target": request_model.target,
        "payload": request_model.payload,
        "metadata": request_model.metadata,
        "prompt_present": bool(request_model.prompt),
    }

    return EventSimulationResponse(
        event_type=request_model.event_type,
        severity=request_model.severity,
        verdict=verdict,
        reasons=reasons,
        recommended_actions=recommended_actions,
        auth=_serialize_auth(auth),
        event=event,
    )
