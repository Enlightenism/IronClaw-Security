from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.api.audit import createauditevent
from app.security.promptinjection import scanpromptinjectiondict
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
        description="Base risk score assigned before prompt-injection analysis.",
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
        "subscriptionid": getattr(consumption, "subscription_id", None)
        if consumption
        else None,
        "walletbalance": getattr(consumption, "wallet_balance", None)
        if consumption
        else None,
    }


@router.post("/execute", response_model=ActionExecuteResponse)
def executeaction(request: ActionExecuteRequestModel) -> ActionExecuteResponse:
    normalized_target = request.target.strip()
    if not normalized_target:
        raise HTTPException(status_code=400, detail="target must not be empty")

    # 1. Prompt injection and risk
    promptinjection = scanpromptinjectiondict(
        actiontype=request.actiontype,
        target=normalized_target,
        content=request.content,
        filepath=request.filepath,
        metadata=request.metadata,
    )

    finalriskscore = request.riskscore + int(promptinjection["riskdelta"])

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

    # If security does not allow, we never try to consume usage
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

    # 3. Security says allowed; we *attempt* usage metering but do not downgrade status
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
            )
        )
        usage = _usage_to_dict(receipt)
    except Exception:
        # Treat metering failures as non-fatal for this boundary
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

    # We do not override the audit-driven status; if audit said allowed, we stay allowed
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