from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

from app.security.hostilecontext import scanhostilecontextdict
from app.security.promptinjection import scanpromptinjectiondict

BoundaryState = str
ExecutorCallable = Callable[..., Any]


@dataclass(slots=True)
class ExecutionReceipt:
    executionid: str
    state: str
    policyverdict: str
    shouldexecute: bool
    haltedbyboundary: bool
    reviewitemid: str | None = None
    executorname: str | None = None
    traceid: str | None = None
    requestid: str | None = None
    decisionid: str | None = None
    reason: str | None = None
    reasons: list[dict[str, Any]] = field(default_factory=list)
    filepath: str | None = None
    actiontype: str | None = None
    target: str | None = None
    riskscore: int = 0
    responseaction: str | None = None
    responsestatus: str | None = None
    createdat: str | None = None


class DemoExecutor:
    name = "dryrunexecutor"

    def __call__(
        self,
        *,
        actiontype: str,
        target: str,
        content: str,
        filepath: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "ok": True,
            "mode": "dryrun",
            "actiontype": actiontype,
            "target": target,
            "contentpreview": content[:240],
            "filepath": filepath,
            "metadata": metadata or {},
        }


def initialize_secureruntimepipeline() -> Any:
    from app.orchestrator.secureruntimepipeline import initialize_secureruntimepipeline as _factory

    return _factory()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_executor_for_pipeline(pipeline: Any) -> ExecutorCallable:
    candidate = getattr(pipeline, "executor", None)
    if callable(candidate):
        return candidate
    return DemoExecutor()


def _normalize_metadata(metadata: dict[str, Any] | None, filepath: str | None) -> dict[str, Any]:
    normalized = dict(metadata or {})
    if filepath and "filepath" not in normalized:
        normalized["filepath"] = filepath
    return normalized


def _make_reason(source: str, label: str, details: str, score: int) -> dict[str, Any]:
    return {
        "source": source,
        "label": label,
        "details": details,
        "score": score,
    }


def _decision_from_risk(riskscore: int) -> tuple[str, str, bool, bool, str, str]:
    if riskscore >= 85:
        return "denied", "block", False, True, "deny", "denied"
    if riskscore >= 50:
        return "queuedforreview", "warn", True, False, "review", "queuedforreview"
    return "executed", "allow", True, False, "allow", "completed"


def executewithboundary(
    pipeline: Any,
    actorid: str,
    actiontype: str,
    target: str,
    content: str,
    riskscore: int,
    sessionid: str | None = None,
    filepath: str | None = None,
    metadata: dict[str, Any] | None = None,
    executor: Optional[ExecutorCallable] = None,
) -> tuple[ExecutionReceipt, Any]:
    active_pipeline = pipeline or initialize_secureruntimepipeline()
    effective_filepath = filepath or "app/api/actionexecute.py"
    effective_metadata = _normalize_metadata(metadata, effective_filepath)

    injectionscan = scanpromptinjectiondict(
        actiontype=actiontype,
        target=target,
        content=content,
        filepath=effective_filepath,
        metadata=effective_metadata,
    )

    hostilecontextscan = scanhostilecontextdict(
        actiontype=actiontype,
        target=target,
        content=content,
        filepath=effective_filepath,
        metadata=effective_metadata,
    )

    combined_risk_delta = int(injectionscan.get("riskdelta", 0)) + int(
        hostilecontextscan.get("riskdelta", 0)
    )
    adjusted_riskscore = max(0, min(100, int(riskscore) + combined_risk_delta))

    (
        state,
        policyverdict,
        shouldexecute,
        haltedbyboundary,
        responseaction,
        responsestatus,
    ) = _decision_from_risk(adjusted_riskscore)

    reasons: list[dict[str, Any]] = []
    reasons.append(
        _make_reason(
            source="boundary",
            label="Base risk evaluation",
            details=(
                f"Boundary evaluated action '{actiontype}' targeting '{target}' with base risk "
                f"score {riskscore} and adjusted risk score {adjusted_riskscore} from prompt "
                f"injection and hostile context analysis."
            ),
            score=int(adjusted_riskscore),
        )
    )

    for reason in injectionscan.get("reasons", []):
        if isinstance(reason, dict):
            reasons.append(
                {
                    "source": reason.get("source", "promptinjection"),
                    "label": reason.get("label", "Prompt injection indicator"),
                    "details": reason.get("details", "Prompt injection indicator detected."),
                    "score": int(reason.get("score", 0)),
                }
            )
        else:
            reasons.append(
                _make_reason(
                    source="promptinjection",
                    label="Prompt injection indicator",
                    details=str(reason),
                    score=0,
                )
            )

    for reason in hostilecontextscan.get("reasons", []):
        if isinstance(reason, dict):
            reasons.append(
                {
                    "source": reason.get("source", "hostilecontext"),
                    "label": reason.get("label", "Hostile context indicator"),
                    "details": reason.get("details", "Hostile external context indicator detected."),
                    "score": int(reason.get("score", 0)),
                }
            )
        else:
            reasons.append(
                _make_reason(
                    source="hostilecontext",
                    label="Hostile context indicator",
                    details=str(reason),
                    score=0,
                )
            )

    if injectionscan.get("flagged") or hostilecontextscan.get("flagged"):
        should_quarantine = bool(
            injectionscan.get("shouldquarantine") or hostilecontextscan.get("shouldquarantine")
        )
        should_review = bool(
            injectionscan.get("shouldreview") or hostilecontextscan.get("shouldreview")
        )

        if should_quarantine:
            state = "denied"
            policyverdict = "quarantine"
            shouldexecute = False
            haltedbyboundary = True
            responseaction = "quarantine"
            responsestatus = "denied"
        elif should_review and state == "executed":
            state = "queuedforreview"
            policyverdict = "warn"
            shouldexecute = True
            haltedbyboundary = False
            responseaction = "review"
            responsestatus = "queuedforreview"

    executionid = f"exec_{uuid4().hex}"
    traceid = f"trace_{uuid4().hex}"
    requestid = f"req_{uuid4().hex}"
    decisionid = f"dec_{uuid4().hex}"
    reviewitemid = f"rev_{uuid4().hex}" if state == "queuedforreview" else None

    if state == "denied":
        reason = "Execution denied by secure runtime boundary."
    elif state == "queuedforreview":
        reason = "Execution requires review before unrestricted completion."
    else:
        reason = "Execution allowed by secure runtime boundary."

    receipt = ExecutionReceipt(
        executionid=executionid,
        state=state,
        policyverdict=policyverdict,
        shouldexecute=shouldexecute,
        haltedbyboundary=haltedbyboundary,
        reviewitemid=reviewitemid,
        executorname=None,
        traceid=traceid,
        requestid=requestid,
        decisionid=decisionid,
        reason=reason,
        reasons=reasons,
        filepath=effective_filepath,
        actiontype=actiontype,
        target=target,
        riskscore=adjusted_riskscore,
        responseaction=responseaction,
        responsestatus=responsestatus,
        createdat=_utcnow(),
    )

    active_executor = executor or _default_executor_for_pipeline(active_pipeline)
    executorname = getattr(active_executor, "name", getattr(active_executor, "__name__", "executor"))

    if not shouldexecute and state == "denied":
        receipt.executorname = executorname
        return receipt, None

    if state == "queuedforreview":
        receipt.executorname = executorname
        runtimeresult = {
            "summary": {
                "executionid": executionid,
                "executionstate": receipt.state,
                "responseaction": receipt.responseaction,
                "responsestatus": receipt.responsestatus,
                "traceid": receipt.traceid,
                "requestid": receipt.requestid,
                "decisionid": receipt.decisionid,
                "policyverdict": receipt.policyverdict,
                "riskscore": receipt.riskscore,
                "shouldexecute": receipt.shouldexecute,
                "haltedbyboundary": receipt.haltedbyboundary,
                "reviewitemid": receipt.reviewitemid,
                "executorname": executorname,
                "executorresult": None,
                "reason": receipt.reason,
                "reasons": receipt.reasons,
                "filepath": receipt.filepath,
                "promptinjection": injectionscan,
                "hostilecontext": hostilecontextscan,
            }
        }
        return receipt, runtimeresult

    runtimeoutput = active_executor(
        actiontype=actiontype,
        target=target,
        content=content,
        filepath=effective_filepath,
        metadata=effective_metadata,
    )
    receipt.executorname = executorname

    runtimeresult = {
        "summary": {
            "executionid": executionid,
            "executionstate": receipt.state,
            "responseaction": receipt.responseaction,
            "responsestatus": receipt.responsestatus,
            "traceid": receipt.traceid,
            "requestid": receipt.requestid,
            "decisionid": receipt.decisionid,
            "policyverdict": receipt.policyverdict,
            "riskscore": receipt.riskscore,
            "shouldexecute": receipt.shouldexecute,
            "haltedbyboundary": receipt.haltedbyboundary,
            "reviewitemid": receipt.reviewitemid,
            "executorname": executorname,
            "executorresult": runtimeoutput,
            "reason": receipt.reason,
            "reasons": receipt.reasons,
            "filepath": receipt.filepath,
            "promptinjection": injectionscan,
            "hostilecontext": hostilecontextscan,
        }
    }
    return receipt, runtimeresult