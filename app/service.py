from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from app.orchestrator.executorboundary import executewithboundary
from app.orchestrator.secureruntimepipeline import (
    SecureRuntimePipeline,
    getactionexecutepipeline,
)

DEFAULT_FILEPATH = "app/api/actionexecute.py"


@dataclass(slots=True)
class ExecutionReason:
    source: str
    label: str
    details: str
    score: int


@dataclass(slots=True)
class ActionExecuteResult:
    executionid: str | None
    executionstate: str
    responseaction: str
    responsestatus: str
    traceid: str | None
    requestid: str | None
    decisionid: str | None
    policyverdict: str
    riskscore: int
    shouldexecute: bool
    haltedbyboundary: bool
    reviewitemid: str | None
    executorname: str | None
    executorresult: dict[str, Any] | None
    reason: str | None
    reasons: list[ExecutionReason] = field(default_factory=list)
    filepath: str | None = None
    promptinjection: dict[str, Any] = field(default_factory=dict)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value):
        data = asdict(value)
        return data if isinstance(data, dict) else {}
    data = getattr(value, "__dict__", None)
    if isinstance(data, dict):
        return dict(data)
    return {}


def _normalize_reason_entry(item: Any) -> ExecutionReason:
    if isinstance(item, ExecutionReason):
        return item

    if is_dataclass(item):
        data = asdict(item)
    elif isinstance(item, Mapping):
        data = dict(item)
    else:
        data = {
            "source": "runtime",
            "label": "Execution reason",
            "details": str(item),
            "score": 0,
        }

    return ExecutionReason(
        source=str(data.get("source", "runtime")),
        label=str(data.get("label", "Execution reason")),
        details=str(data.get("details", "")),
        score=_safe_int(data.get("score", 0)),
    )


def _normalize_reasons(items: Any) -> list[ExecutionReason]:
    if not items:
        return []

    if isinstance(items, (str, bytes)):
        return [
            ExecutionReason(
                source="runtime",
                label="Execution reason",
                details=str(items),
                score=0,
            ),
        ]

    if not isinstance(items, Iterable):
        return [_normalize_reason_entry(items)]

    normalized: list[ExecutionReason] = []
    for item in items:
        normalized.append(_normalize_reason_entry(item))
    return normalized


def _extract_summary_from_runtime_result(runtimeresult: Any) -> dict[str, Any]:
    if isinstance(runtimeresult, Mapping):
        nested = runtimeresult.get("summary")
        if isinstance(nested, Mapping):
            return dict(nested)
        return dict(runtimeresult)

    nested = getattr(runtimeresult, "summary", None)
    if isinstance(nested, Mapping):
        return dict(nested)

    if is_dataclass(runtimeresult):
        data = asdict(runtimeresult)
        if isinstance(data, dict):
            nested = data.get("summary")
            if isinstance(nested, Mapping):
                return dict(nested)
            return data

    data = getattr(runtimeresult, "__dict__", None)
    if isinstance(data, dict):
        nested = data.get("summary")
        if isinstance(nested, Mapping):
            return dict(nested)
        return dict(data)

    return {}


def summarizeexecutionreceipt(receipt: Any, runtimeresult: Any) -> dict[str, Any]:
    summary = _extract_summary_from_runtime_result(runtimeresult)

    executionstate = summary.get("executionstate") or getattr(receipt, "state", None) or "executed"
    responseaction = summary.get("responseaction") or getattr(
        receipt,
        "responseaction",
        None,
    )
    responsestatus = summary.get("responsestatus") or getattr(
        receipt,
        "responsestatus",
        None,
    )
    policyverdict = summary.get("policyverdict") or getattr(receipt, "policyverdict", None) or "allow"
    riskscore = _safe_int(summary.get("riskscore", getattr(receipt, "riskscore", 0)))
    shouldexecute = bool(
        summary.get("shouldexecute", getattr(receipt, "shouldexecute", False)),
    )
    haltedbyboundary = bool(
        summary.get("haltedbyboundary", getattr(receipt, "haltedbyboundary", False)),
    )
    reviewitemid = summary.get("reviewitemid", getattr(receipt, "reviewitemid", None))
    executorname = summary.get("executorname", getattr(receipt, "executorname", None))
    executorresult = summary.get("executorresult")
    reason = summary.get("reason") or getattr(receipt, "reason", None)
    filepath = summary.get("filepath") or getattr(receipt, "filepath", None) or DEFAULT_FILEPATH
    promptinjection = _normalize_mapping(summary.get("promptinjection"))

    if executorresult is None and isinstance(runtimeresult, Mapping) and "summary" not in runtimeresult:
        executorresult = dict(runtimeresult)

    normalized_executor_result = None
    if executorresult is not None:
        normalized_executor_result = _normalize_mapping(executorresult) or (executorresult if isinstance(executorresult, dict) else {"value": executorresult})

    if responseaction is None:
        if executionstate == "denied":
            responseaction = "deny"
        elif executionstate == "queuedforreview":
            responseaction = "review"
        else:
            responseaction = "allow"

    if responsestatus is None:
        if executionstate == "denied":
            responsestatus = "denied"
        elif executionstate == "queuedforreview":
            responsestatus = "queuedforreview"
        else:
            responsestatus = "completed"

    return {
        "executionid": getattr(receipt, "executionid", None),
        "executionstate": str(executionstate),
        "responseaction": str(responseaction),
        "responsestatus": str(responsestatus),
        "traceid": summary.get("traceid") or getattr(receipt, "traceid", None),
        "requestid": summary.get("requestid") or getattr(receipt, "requestid", None),
        "decisionid": summary.get("decisionid") or getattr(receipt, "decisionid", None),
        "policyverdict": str(policyverdict),
        "riskscore": riskscore,
        "shouldexecute": shouldexecute,
        "haltedbyboundary": haltedbyboundary,
        "reviewitemid": reviewitemid,
        "executorname": executorname,
        "executorresult": normalized_executor_result,
        "reason": None if reason is None else str(reason),
        "reasons": _normalize_reasons(
            summary.get("reasons") or getattr(receipt, "reasons", []),
        ),
        "filepath": str(filepath) if filepath is not None else None,
        "promptinjection": promptinjection,
    }


def executeguardedaction(
    actiontype: str,
    target: str,
    content: str,
    riskscore: int,
    clientid: str | None = None,
    sessionid: str | None = None,
    filepath: str | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    active_pipeline = pipeline or getactionexecutepipeline()
    effective_filepath = filepath or DEFAULT_FILEPATH

    receipt, runtimeresult = executewithboundary(
        pipeline=active_pipeline,
        actorid=clientid or "anonymous-client",
        actiontype=actiontype,
        target=target,
        content=content,
        riskscore=riskscore,
        sessionid=sessionid,
        filepath=effective_filepath,
        metadata={
            "clientid": clientid,
            "sessionid": sessionid,
            "filepath": effective_filepath,
        },
        executor=None,
    )

    summary = summarizeexecutionreceipt(receipt, runtimeresult)

    return ActionExecuteResult(
        executionid=summary.get("executionid"),
        executionstate=str(summary["executionstate"]),
        responseaction=str(summary["responseaction"]),
        responsestatus=str(summary["responsestatus"]),
        traceid=summary.get("traceid"),
        requestid=summary.get("requestid"),
        decisionid=summary.get("decisionid"),
        policyverdict=str(summary["policyverdict"]),
        riskscore=_safe_int(summary["riskscore"]),
        shouldexecute=bool(summary["shouldexecute"]),
        haltedbyboundary=bool(summary["haltedbyboundary"]),
        reviewitemid=summary.get("reviewitemid"),
        executorname=summary.get("executorname"),
        executorresult=summary.get("executorresult"),
        reason=summary.get("reason"),
        reasons=_normalize_reasons(summary.get("reasons")),
        filepath=summary.get("filepath"),
        promptinjection=_normalize_mapping(summary.get("promptinjection")),
    )
