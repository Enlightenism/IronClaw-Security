from __future__ import annotations

import logging
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.audit import createauditevent
from app.config import (
    RISK_THRESHOLD_ALLOW_MAX,
    RISK_THRESHOLD_BLOCK_MIN,
    RISK_THRESHOLD_QUARANTINE_MIN,
)
from app.core.auth import AuthContext, InstallKeyAuthContext, get_runtime_auth_context
from app.services.action_guard import ActionGuardDecision, analyze_action, normalize_action_type
from app.services.actionexecuteservice import (
    ActionExecutionRequest,
    get_action_execute_service,
)

router = APIRouter(prefix="/action", tags=["action-execution"])
logger = logging.getLogger(__name__)

AllowedActionType = Literal[
    "httpfetch",
    "browseropen",
    "toolcall",
    "filewrite",
    "fileread",
    "command",
]

_ACTION_TYPE_MAP: dict[str, str] = {
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
    eventid: str | None = Field(default=None, min_length=1, max_length=128)
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


def _mark_usage_denial(audit: dict[str, Any], reason: str) -> dict[str, Any]:
    denied_audit = dict(audit)
    denied_audit["eventtype"] = "execution_denied"
    denied_audit["severity"] = "high"
    denied_audit["summary"] = reason
    return denied_audit


def _empty_usage(reason: str) -> dict[str, Any]:
    return {
        "executionid": None,
        "executed": False,
        "consumedunits": 0,
        "remainingunits": 0,
        "reason": reason,
        "applied": False,
        "plan": None,
        "packageid": None,
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
        "packageid": getattr(consumption, "package_id", None) if consumption else None,
        "walletbalance": getattr(consumption, "wallet_balance", None) if consumption else None,
    }


def _run_detection(request: ActionExecuteRequestModel) -> ActionGuardDecision | None:
    guard_action_type = normalize_action_type(_ACTION_TYPE_MAP.get(request.actiontype, request.actiontype))
    try:
        result: ActionGuardDecision = analyze_action(
            action_type=guard_action_type,  # type: ignore[arg-type]
            target=request.target,
            content=request.content or "",
            client_id=request.clientid,
            session_id=request.sessionid,
            metadata=request.metadata,
        )
        return result
    except Exception:  # noqa: BLE001
        logger.exception("actionexecute: detection failed; blocking action")
        return None


def _severity_for_risk_score(risk_score: int) -> str:
    if risk_score >= RISK_THRESHOLD_BLOCK_MIN:
        return "critical"
    if risk_score >= (RISK_THRESHOLD_QUARANTINE_MIN + RISK_THRESHOLD_BLOCK_MIN) // 2:
        return "high"
    if risk_score >= (RISK_THRESHOLD_ALLOW_MAX + RISK_THRESHOLD_QUARANTINE_MIN) // 2:
        return "medium"
    return "low" if risk_score > 0 else "none"


def _detection_to_promptinjection(detection: ActionGuardDecision | None) -> dict[str, Any]:
    if detection is None:
        risk_score = RISK_THRESHOLD_BLOCK_MIN
        logger.error("actionexecute: detection result missing; blocking action")
        return {
            "flagged": True,
            "riskdelta": risk_score,
            "shouldquarantine": False,
            "shouldreview": False,
            "matchedpatterns": ["detection_unavailable"],
            "reasons": [
                {
                    "source": "scan",
                    "label": "Detection unavailable",
                    "details": "Action detection failed; action blocked.",
                    "score": risk_score,
                },
            ],
            "verdict": "block",
            "severity": _severity_for_risk_score(risk_score),
            "categories": ["detection_error"],
            "scan_id": None,
            "summary": "Action detection unavailable; action blocked.",
            "drift_report": None,
        }

    invalid_result = False
    raw_verdict = detection.get("verdict")
    if raw_verdict not in ("allow", "block"):
        logger.error("actionexecute: invalid detection verdict; blocking action")
        invalid_result = True

    raw_risk_score = detection.get("risk_score")
    if isinstance(raw_risk_score, int) and not isinstance(raw_risk_score, bool) and 0 <= raw_risk_score <= 100:
        risk_score = raw_risk_score
    else:
        logger.error("actionexecute: invalid detection risk score; blocking action")
        risk_score = RISK_THRESHOLD_BLOCK_MIN
        invalid_result = True

    raw_matched_patterns = detection.get("matched_patterns")
    if isinstance(raw_matched_patterns, list) and all(isinstance(pattern, str) for pattern in raw_matched_patterns):
        matched_patterns = list(raw_matched_patterns)
    else:
        logger.error("actionexecute: invalid matched-pattern result; blocking action")
        matched_patterns = ["invalid_detection_patterns"]
        invalid_result = True

    raw_reasons = detection.get("reasons")
    if isinstance(raw_reasons, list) and all(isinstance(reason, dict) for reason in raw_reasons):
        reasons = list(raw_reasons)
    else:
        logger.error("actionexecute: invalid detection reasons; blocking action")
        reasons = []
        invalid_result = True

    raw_categories = detection.get("categories")
    if isinstance(raw_categories, list) and all(isinstance(category, str) for category in raw_categories):
        categories = list(raw_categories)
    else:
        logger.error("actionexecute: invalid detection categories; blocking action")
        categories = ["detection_error"]
        invalid_result = True

    if invalid_result:
        reasons.append(
            {
                "source": "scan",
                "label": "Invalid detection result",
                "details": "Action detection returned invalid data; action blocked.",
                "score": risk_score,
            },
        )

    verdict = "block" if (invalid_result or raw_verdict != "allow" or risk_score > RISK_THRESHOLD_ALLOW_MAX or bool(matched_patterns) or bool(categories)) else "allow"
    if verdict == "block":
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)

    summary = detection.get("summary")
    if invalid_result:
        summary = "Invalid action detection result; action blocked."
    elif not isinstance(summary, str) or not summary:
        summary = "Suspicious activity detected; action blocked." if verdict == "block" else "No suspicious activity detected."
    scan_id = detection.get("scan_id")
    if not isinstance(scan_id, str):
        scan_id = None

    return {
        "flagged": verdict == "block",
        "riskdelta": risk_score,
        "shouldquarantine": False,
        "shouldreview": raw_verdict == "warn",
        "matchedpatterns": matched_patterns,
        "reasons": reasons,
        "verdict": verdict,
        "severity": _severity_for_risk_score(risk_score),
        "categories": categories,
        "scan_id": scan_id,
        "summary": summary,
        "drift_report": detection.get("drift_report"),
    }


@router.post("/execute", response_model=ActionExecuteResponse)
def executeaction(
    request: ActionExecuteRequestModel,
    auth_context: AuthContext | InstallKeyAuthContext = Depends(get_runtime_auth_context),
) -> ActionExecuteResponse:
    normalized_target = request.target.strip()
    if not normalized_target:
        raise HTTPException(status_code=400, detail="target must not be empty")

    install_key_id = auth_context.key_id if isinstance(auth_context, InstallKeyAuthContext) else None
    install_program = auth_context.program if isinstance(auth_context, InstallKeyAuthContext) else None
    owner_key = auth_context.owner_key if isinstance(auth_context, InstallKeyAuthContext) else auth_context.metadata.get("owner_key") or request.ownerkey

    # 1. Live detection screen — metadata forwarded so documenttext/tooloutput reach scanner
    detection = _run_detection(request)
    promptinjection = _detection_to_promptinjection(detection)

    detection_risk_delta = int(promptinjection.get("riskdelta", 0) or 0)
    finalriskscore = request.riskscore + detection_risk_delta

    mergedmetadata = dict(request.metadata)
    mergedmetadata["promptinjection"] = promptinjection
    mergedmetadata["ownerkey"] = owner_key
    mergedmetadata["requestedunits"] = request.requestedunits
    if install_key_id is not None:
        mergedmetadata["install_key_id"] = install_key_id
        mergedmetadata["program"] = install_program

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
            ownerkey=owner_key,
            requestedunits=request.requestedunits,
            finalriskscore=finalriskscore,
            promptinjection=promptinjection,
            audit=audit,
            executionallowed=False,
            usage=_empty_usage(reason="blocked_by_security_review"),
            message=message,
        )

    # 3. Security says allowed; usage metering is required before execution.
    service = get_action_execute_service()

    try:
        event_id = None
        if install_key_id is not None:
            event_id = f"{install_key_id}:{request.eventid or uuid4().hex}"
        receipt = service.execute(
            ActionExecutionRequest(
                owner_key=owner_key,
                action_name=f"{request.actiontype}:{normalized_target}",
                requested_units=request.requestedunits,
                payload={
                    "content": request.content,
                    "filepath": request.filepath,
                },
                metadata=mergedmetadata,
                install_key_id=install_key_id,
                program=install_program,
                event_id=event_id,
            ),
        )
        usage = _usage_to_dict(receipt)
    except Exception:  # noqa: BLE001
        logger.exception("actionexecute: usage metering failed; blocking action")
        return ActionExecuteResponse(
            status="denied",
            actiontype=request.actiontype,
            target=normalized_target,
            ownerkey=owner_key,
            requestedunits=request.requestedunits,
            finalriskscore=finalriskscore,
            promptinjection=promptinjection,
            audit=_mark_usage_denial(audit, "Action denied because usage could not be recorded."),
            executionallowed=False,
            usage=_empty_usage(reason="usage_metering_unavailable"),
            message="Action denied because usage could not be recorded.",
        )

    if not receipt.executed:
        return ActionExecuteResponse(
            status="denied",
            actiontype=request.actiontype,
            target=normalized_target,
            ownerkey=owner_key,
            requestedunits=request.requestedunits,
            finalriskscore=finalriskscore,
            promptinjection=promptinjection,
            audit=_mark_usage_denial(
                audit,
                "Action denied because the required protection units could not be consumed.",
            ),
            executionallowed=False,
            usage=usage,
            message="Action denied because the required protection units could not be consumed.",
        )

    return ActionExecuteResponse(
        status="allowed",
        actiontype=request.actiontype,
        target=normalized_target,
        ownerkey=owner_key,
        requestedunits=request.requestedunits,
        finalriskscore=finalriskscore,
        promptinjection=promptinjection,
        audit=audit,
        executionallowed=True,
        usage=usage,
        message="Action approved for execution.",
    )
