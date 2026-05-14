from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/reviews",
    tags=["review-queue"],
)


class ReviewQueueItem(BaseModel):
    reviewitemid: str
    executionid: str
    timestamp: str
    reviewstatus: str
    clientid: str | None = None
    sessionid: str | None = None
    actiontype: str
    target: str
    riskscore: int
    executionstate: str
    responsestatus: str
    policyverdict: str
    shouldexecute: bool
    haltedbyboundary: bool
    reason: str | None = None
    executorname: str | None = None
    traceid: str | None = None
    requestid: str | None = None
    decisionid: str | None = None


class ReviewQueueResponse(BaseModel):
    items: list[ReviewQueueItem] = Field(default_factory=list)
    total: int = 0
    pending: int = 0
    approved: int = 0
    rejected: int = 0


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _coerce_str(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on"}:
            return True
        if lowered in {"false", "0", "no", "n", "off"}:
            return False
    return bool(value)


def _normalize_reviewstatus(value: Any) -> str:
    status = _coerce_str(value, "pending").lower()
    if status in {"approved", "rejected", "pending"}:
        return status
    return "pending"


def _normalize_executionstate(value: Any) -> str:
    return _coerce_str(value, "unknown")


def _normalize_responsestatus(value: Any, executionstate: str) -> str:
    status = _coerce_str(value, "").lower()
    if status in {"completed", "queuedforreview", "denied"}:
        return status

    if executionstate in {"denied", "blocked", "quarantined"}:
        return "denied"
    if executionstate in {"dryrun", "queued", "queuedforreview", "review"}:
        return "queuedforreview"
    return "completed"


def _normalize_policyverdict(value: Any, executionstate: str) -> str:
    verdict = _coerce_str(value, "").lower()
    if verdict:
        return verdict

    if executionstate in {"denied", "blocked"}:
        return "block"
    if executionstate in {"quarantined"}:
        return "quarantine"
    if executionstate in {"dryrun", "queued", "queuedforreview", "review"}:
        return "review"
    return "allow"


def _build_placeholder_items() -> list[ReviewQueueItem]:
    raw_items = [
        {
            "reviewitemid": "review-demo-001",
            "executionid": "exec-demo-003",
            "timestamp": _utcnow_iso(),
            "reviewstatus": "pending",
            "clientid": "demo-client-003",
            "sessionid": "demo-session-003",
            "actiontype": "httpfetch",
            "target": "https://example.com/docs",
            "riskscore": 55,
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "review",
            "shouldexecute": True,
            "haltedbyboundary": False,
            "reason": "Mid-risk request queued for human review.",
            "executorname": "dryrunexecutor",
            "traceid": "trace-demo-003",
            "requestid": "request-demo-003",
            "decisionid": "decision-demo-003",
        },
        {
            "reviewitemid": "review-demo-002",
            "executionid": "exec-demo-004",
            "timestamp": _utcnow_iso(),
            "reviewstatus": "pending",
            "clientid": "demo-client-004",
            "sessionid": "demo-session-004",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": 74,
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "review",
            "shouldexecute": False,
            "haltedbyboundary": True,
            "reason": "Sensitive shell-adjacent request requires analyst approval.",
            "executorname": None,
            "traceid": "trace-demo-004",
            "requestid": "request-demo-004",
            "decisionid": "decision-demo-004",
        },
        {
            "reviewitemid": "review-demo-003",
            "executionid": "exec-demo-005",
            "timestamp": _utcnow_iso(),
            "reviewstatus": "approved",
            "clientid": "demo-client-005",
            "sessionid": "demo-session-005",
            "actiontype": "httpfetch",
            "target": "https://example.com/public-report",
            "riskscore": 48,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "shouldexecute": True,
            "haltedbyboundary": False,
            "reason": "Previously reviewed and approved.",
            "executorname": "dryrunexecutor",
            "traceid": "trace-demo-005",
            "requestid": "request-demo-005",
            "decisionid": "decision-demo-005",
        },
    ]

    items: list[ReviewQueueItem] = []
    for raw in raw_items:
        executionstate = _normalize_executionstate(raw.get("executionstate"))
        items.append(
            ReviewQueueItem(
                reviewitemid=_coerce_str(raw.get("reviewitemid"), "unknown-review"),
                executionid=_coerce_str(raw.get("executionid"), "unknown-execution"),
                timestamp=_coerce_str(raw.get("timestamp"), _utcnow_iso()),
                reviewstatus=_normalize_reviewstatus(raw.get("reviewstatus")),
                clientid=raw.get("clientid"),
                sessionid=raw.get("sessionid"),
                actiontype=_coerce_str(raw.get("actiontype"), "unknown"),
                target=_coerce_str(raw.get("target"), "unknown"),
                riskscore=_coerce_int(raw.get("riskscore"), 0),
                executionstate=executionstate,
                responsestatus=_normalize_responsestatus(
                    raw.get("responsestatus"),
                    executionstate,
                ),
                policyverdict=_normalize_policyverdict(
                    raw.get("policyverdict"),
                    executionstate,
                ),
                shouldexecute=_coerce_bool(raw.get("shouldexecute"), False),
                haltedbyboundary=_coerce_bool(raw.get("haltedbyboundary"), False),
                reason=raw.get("reason"),
                executorname=raw.get("executorname"),
                traceid=raw.get("traceid"),
                requestid=raw.get("requestid"),
                decisionid=raw.get("decisionid"),
            ),
        )
    return items


@router.get("/queue", response_model=ReviewQueueResponse)
def get_review_queue() -> ReviewQueueResponse:
    items = _build_placeholder_items()
    pending = sum(1 for item in items if item.reviewstatus == "pending")
    approved = sum(1 for item in items if item.reviewstatus == "approved")
    rejected = sum(1 for item in items if item.reviewstatus == "rejected")

    return ReviewQueueResponse(
        items=items,
        total=len(items),
        pending=pending,
        approved=approved,
        rejected=rejected,
    )
