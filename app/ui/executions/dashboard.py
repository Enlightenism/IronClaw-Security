from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

# NOTE:
# This router must be included in your FastAPI app, e.g. in app/main.py:
#   from app.ui.executions.dashboard import router as execution_dashboard_router
#   app.include_router(execution_dashboard_router)

router = APIRouter(
    prefix="/ui/executions",
    tags=["execution-dashboard"],
)


class ExecutionDashboardItem(BaseModel):
    executionid: str
    timestamp: str
    clientid: Optional[str] = None
    sessionid: Optional[str] = None
    actiontype: str
    target: str
    riskscore: int
    executionstate: str
    responsestatus: str
    policyverdict: str
    shouldexecute: bool
    haltedbyboundary: bool
    filepath: Optional[str] = None
    traceid: Optional[str] = None
    requestid: Optional[str] = None
    decisionid: Optional[str] = None
    reviewitemid: Optional[str] = None
    executorname: Optional[str] = None
    reason: Optional[str] = None


class ExecutionDashboardResponse(BaseModel):
    items: list[ExecutionDashboardItem] = Field(default_factory=list)
    total: int = 0


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _object_to_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, BaseModel):
        return value.model_dump()
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "__dict__"):
        return {
            key: val
            for key, val in vars(value).items()
            if not key.startswith("_")
        }
    return {}


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


def _normalize_executionstate(record: dict[str, Any]) -> str:
    return _coerce_str(
        record.get("executionstate") or record.get("state"),
        "unknown",
    )


def _normalize_responsestatus(record: dict[str, Any], executionstate: str) -> str:
    raw_status = record.get("responsestatus")
    if isinstance(raw_status, str) and raw_status.strip():
        return raw_status.strip()

    normalized_state = executionstate.strip().lower()
    if normalized_state in {"denied", "blocked", "quarantined"}:
        return "denied"
    if normalized_state in {"dryrun", "queued", "queuedforreview", "review"}:
        return "queuedforreview"
    return "completed"


def _normalize_policyverdict(record: dict[str, Any], executionstate: str) -> str:
    raw_verdict = record.get("policyverdict")
    if isinstance(raw_verdict, str) and raw_verdict.strip():
        return raw_verdict.strip()

    normalized_state = executionstate.strip().lower()
    if normalized_state in {"denied", "blocked"}:
        return "block"
    if normalized_state in {"quarantined"}:
        return "quarantine"
    if normalized_state in {"dryrun", "queued", "queuedforreview", "review"}:
        return "review"
    return "allow"


def _normalize_timestamp(record: dict[str, Any]) -> str:
    for key in ("timestamp", "createdat", "occurredat", "executedat"):
        value = record.get(key)
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()
        if isinstance(value, str) and value.strip():
            return value.strip()
    return _utcnow_iso()


def _normalize_dashboard_item(record: Any) -> ExecutionDashboardItem:
    data = _object_to_dict(record)
    executionstate = _normalize_executionstate(data)

    return ExecutionDashboardItem(
        executionid=_coerce_str(
            data.get("executionid") or data.get("id"),
            "unknown-execution",
        ),
        timestamp=_normalize_timestamp(data),
        clientid=data.get("clientid"),
        sessionid=data.get("sessionid"),
        actiontype=_coerce_str(data.get("actiontype"), "unknown"),
        target=_coerce_str(data.get("target"), "unknown"),
        riskscore=_coerce_int(data.get("riskscore"), 0),
        executionstate=executionstate,
        responsestatus=_normalize_responsestatus(data, executionstate),
        policyverdict=_normalize_policyverdict(data, executionstate),
        shouldexecute=_coerce_bool(data.get("shouldexecute"), False),
        haltedbyboundary=_coerce_bool(data.get("haltedbyboundary"), False),
        filepath=data.get("filepath"),
        traceid=data.get("traceid"),
        requestid=data.get("requestid"),
        decisionid=data.get("decisionid"),
        reviewitemid=data.get("reviewitemid"),
        executorname=data.get("executorname"),
        reason=data.get("reason"),
    )


def _normalize_dashboard_items(records: Iterable[Any]) -> list[ExecutionDashboardItem]:
    return [_normalize_dashboard_item(record) for record in records]


def _build_placeholder_items() -> list[ExecutionDashboardItem]:
    sample_records: list[dict[str, Any]] = [
        {
            "executionid": "exec-demo-001",
            "timestamp": _utcnow_iso(),
            "clientid": "demo-client-001",
            "sessionid": "demo-session-001",
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "riskscore": 3,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "shouldexecute": True,
            "haltedbyboundary": False,
            "filepath": "app/api/actionexecute.py",
            "traceid": "trace-demo-001",
            "requestid": "request-demo-001",
            "decisionid": "decision-demo-001",
            "reviewitemid": None,
            "executorname": "dryrunexecutor",
            "reason": "Allowed low-risk guarded execution.",
        },
        {
            "executionid": "exec-demo-002",
            "timestamp": _utcnow_iso(),
            "clientid": "demo-client-002",
            "sessionid": "demo-session-002",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": 95,
            "executionstate": "denied",
            "responsestatus": "denied",
            "policyverdict": "block",
            "shouldexecute": False,
            "haltedbyboundary": True,
            "filepath": "app/api/actionexecute.py",
            "traceid": "trace-demo-002",
            "requestid": "request-demo-002",
            "decisionid": "decision-demo-002",
            "reviewitemid": "review-demo-002",
            "executorname": None,
            "reason": "Blocked high-risk shell execution attempt.",
        },
    ]
    return _normalize_dashboard_items(sample_records)


@router.get("", response_model=ExecutionDashboardResponse)
def get_execution_dashboard() -> ExecutionDashboardResponse:
    items = _build_placeholder_items()
    return ExecutionDashboardResponse(items=items, total=len(items))