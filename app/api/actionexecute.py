from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.audit import createauditevent
from app.services.action_guard import ActionGuardDecision, analyze_action
from app.services.actionexecuteservice import (
    ActionExecutionRequest,
    get_action_execute_service,
)

router = APIRouter(prefix="/action", tags=["action-execution"])

AllowedActionType = Literal[
    "httpfetch",
    "browseropen",
    "toolcall",
    "filewrite",
    "fileread",
    "command",
]

_ACTION_TYPE_MAP: dict[str, str] = {
    "httpfetch": "network_request",
    "browseropen": "network_request",
    "toolcall": "tool_call",
    "filewrite": "file_write",
    "fileread": "file_read",
    "command": "shell_command",
}


class ActionExecuteRequestModel(BaseModel):
    actiontype: AllowedActionType = Field(..., description="Type of action requested.")
    target: str = Field(..., min_length=1, description="Target resource or tool name.")
    content: str | None = Field(
        default=None,
        description="Instructional content or payload associated with the action.",
    )
    clientid: str = Field(..., min_length=1, description="Client identifier.")
    sessionid: str = Field(..., min_length=1, description="Session identifier.")
    ownerkey: str = Field(
        default="system",
        min_length=1,
        description="Billing owner identifier.",
    )
    filepath: str | None = Field(
        default=None,
        description="Optional project file associated with the request.",
    )
    requestedunits: int = Field(
        default=1,
        ge=1,
        description="Prepaid usage units required to execute the action.",
    )
    riskscore: int = Field(
        default=0,
        ge=0,
        description="Base risk score assigned before detection analysis.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional execution context used for risk analysis.",
    )


class ActionExecuteResponse(BaseModel):
    status: Literal["allowed", "review", "quarantined", "denied"]
    actiontype: str
    target: str
    ownerkey: str
    requestedunits: int
    finalriskscore: int
    promptinjection: dict[str, Any]
    audit: dict[str, Any]
    executionallowed: bool
    usage: dict[str, Any]
    message: str


def _map_audit_event_to_status(
    eventtype: str,
) -> Literal["allowed", "review", "quarantined", "denied"]:
    if eventtype == "execution_allowed":
        return "allowed"
    if eventtype == "execution_review":
        return "review"
    if eventtype == "execution_quarantined":
        return "quarantined"
    return "denied"


def _empty_usage(reason: str) -> dict[str, Any]:
    return {
        "executionid": None,
        "executed": False,
        "consumedunits": 0,
        "remainingunits": 0,
        "reason": reason,
        "applied": False,
        "plan": None,
        "subscriptionid": None,
        "walletbalance": None,
    }


def _usage_to_dict(receipt: Any) -> dict[str, Any]:
    consumption = getattr(receipt, "consumption", None)
    return {
        "executionid": getattr(receipt, "execution_id", None),
        "executed": getattr(receipt, "executed", False),
        "consumedunits": getattr(receipt, "consumed_units", 0),
        "remainingunits": getattr(receipt, "remaining_units", 0),
        "reason": getattr(receipt, "reason", ""),
        "applied": bool(getattr(consumption, "applied", False)) if consumption else False,
        "plan": getattr(consumption, "plan", None) if consumption else None,
        "subscriptionid": getattr(consumption, "subscription_id", None) if consumption else None,
        "walletbalance": getattr(consumption, "wallet_balance", None) if consumption else None,
    }


def _run_detection(request: ActionExecuteRequestModel) -> ActionGuardDecision | None:
    """Run live threat detection via analyze_action (same pattern as action_guard).

    Maps the camelCase actiontype to the guard's snake_case ActionType enum before
    calling analyze_action so the pattern tables and floor-verdict logic resolve
    correctly.  Returns None on any failure so detection never hard-blocks execution
    when the guard service is unavailable.
    """
    guard_action_type = _ACTION_TYPE_MAP.get(request.actiontype, "tool_call")
    try:
        result: ActionGuardDecision = analyze_action(
            action_type=guard_action_type,  # type: ignore[arg-type]
            target=request.target,
            content=request.content or "",
            client_id=request.clientid,
            session_id=request.sessionid,
        )
        return result
    except Exception:  # noqa: BLE001
        return None


def _detection_to_promptinjection(detection: ActionGuardDecision | None) -> dict[str, Any]:
    """Serialize the detection result into the legacy promptinjection dict shape
    so downstream callers (audit, response) receive a stable contract."""
    if detection is None:
        return {
            "flagged": False,
            "riskdelta": 0,
            "shouldquarantine": False,
            "shouldreview": False,
            "matchedpatterns": [],
            "reasons": [],
        }

    verdict = detection.get("verdict", "allow")
    risk_score = int(detection.get("risk_score", 0) or 0)
    matched_patterns = list(detection.get("matched_patterns", []))
    reasons = list(detection.get("reasons", []))

    flagged = verdict != "allow"
    shouldquarantine = verdict in ("quarantine", "block")
    shouldreview = verdict == "warn"

    return {
        "flagged": flagged,
        "riskdelta": risk_score,
        "shouldquarantine": shouldquarantine,
        "shouldreview": shouldreview,
        "matchedpatterns": matched_patterns,
        "reasons": reasons,
        "verdict": verdict,
        "scan_id": detection.get("scan_id"),
        "summary": detection.get("summary", ""),
        "drift_report": detection.get("drift_report"),
    }


@router.post("/execute", response_model=ActionExecuteResponse)
def executeaction(request: ActionExecuteRequestModel) -> ActionExecuteResponse | JSONResponse:
    normalized_target = request.target.strip()
    if not normalized_target:
        raise HTTPException(status_code=400, detail="target must not be empty")

    # 1. Live detection screen — replaces inline scanpromptinjectiondict call
    detection = _run_detection(request)
    promptinjection = _detection_to_promptinjection(detection)

    detection_risk_delta = int(promptinjection.get("riskdelta", 0) or 0)
    finalriskscore = request.riskscore + detection_risk_delta

    # Hard-block before audit when detection verdict is block
    if detection is not None and detection.get("verdict") == "block":
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Action blocked by IronClaw detection layer.",
                "verdict": "block",
                "risk_score": finalriskscore,
                "reasons": promptinjection.get("reasons", []),
            },
        )

    mergedmetadata = dict(request.metadata)
    mergedmetadata["promptinjection"] = promptinjection
    mergedmetadata["ownerkey"] = request.ownerkey
    mergedmetadata["requestedunits"] = request.requestedunits

    # 2. Security audit decides status
    audit = createauditevent(
        actiontype=request.actiontype,
        target=normalized_target,
        content=request.content,
        riskscore=finalriskscore,
        clientid=request.clientid,
        sessionid=request.sessionid,
        filepath=request.filepath,
        metadata=mergedmetadata,
    )

    status = _map_audit_event_to_status(audit["eventtype"])

    if status != "allowed":
        if status == "review":
            message = "Action requires manual review before execution."
        elif status == "quarantined":
            message = "Action has been quarantined due to elevated risk."
        else:
            message = "Action has been denied."

        return ActionExecuteResponse(
            status=status,
            actiontype=request.actiontype,
            target=normalized_target,
            ownerkey=request.ownerkey,
            requestedunits=request.requestedunits,
            finalriskscore=finalriskscore,
            promptinjection=promptinjection,
            audit=audit,
            executionallowed=False,
            usage=_empty_usage(reason="blocked_by_security_review"),
            message=message,
        )

    # 3. Security says allowed; attempt usage metering (non-fatal)
    service = get_action_execute_service()

    try:
        receipt = service.execute(
            ActionExecutionRequest(
                owner_key=request.ownerkey,
                action_name=f"{request.actiontype}:{normalized_target}",
                requested_units=request.requestedunits,
                payload={
                    "content": request.content,
                    "filepath": request.filepath,
                },
                metadata=mergedmetadata,
            ),
        )
        usage = _usage_to_dict(receipt)
    except Exception:  # noqa: BLE001
        return ActionExecuteResponse(
            status="allowed",
            actiontype=request.actiontype,
            target=normalized_target,
            ownerkey=request.ownerkey,
            requestedunits=request.requestedunits,
            finalriskscore=finalriskscore,
            promptinjection=promptinjection,
            audit=audit,
            executionallowed=True,
            usage=_empty_usage(reason="usage_metering_unavailable"),
            message="Action approved for execution.",
        )

    return ActionExecuteResponse(
        status="allowed",
        actiontype=request.actiontype,
        target=normalized_target,
        ownerkey=request.ownerkey,
        requestedunits=request.requestedunits,
        finalriskscore=finalriskscore,
        promptinjection=promptinjection,
        audit=audit,
        executionallowed=True,
        usage=usage,
        message="Action approved for execution.",
    )
