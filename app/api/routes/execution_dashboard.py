from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/ui/executions",
    tags=["execution-dashboard"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ExecutionDashboardItem(BaseModel):
    execution_id: str
    timestamp: str
    client_id: str | None = None
    session_id: str | None = None
    action_type: str
    target: str
    risk_score: int
    execution_state: str
    response_status: str
    policy_verdict: str
    should_execute: bool
    halted_by_boundary: bool
    filepath: str | None = None
    trace_id: str | None = None
    request_id: str | None = None
    decision_id: str | None = None
    review_item_id: str | None = None
    executor_name: str | None = None
    reason: str | None = None


class ExecutionDashboardResponse(BaseModel):
    items: list[ExecutionDashboardItem] = Field(default_factory=list)
    total: int = 0


class ExecutionReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int | None = None


class ExecutionDetailResponse(BaseModel):
    execution_id: str
    timestamp: str
    action_type: str
    target: str
    content: str = ""
    risk_score: int
    client_id: str | None = None
    session_id: str | None = None
    filepath: str | None = None
    execution_state: str
    response_action: str
    response_status: str
    policy_verdict: str
    should_execute: bool
    halted_by_boundary: bool
    trace_id: str
    request_id: str
    decision_id: str
    review_item_id: str | None = None
    executor_name: str | None = None
    executor_result: dict[str, Any] | None = None
    reason: str | None = None
    reasons: list[ExecutionReasonView] = Field(default_factory=list)


_SAMPLE_EXECUTIONS: list[dict[str, Any]] = [
    {
        "execution_id": "exec_001",
        "timestamp": _utc_now_iso(),
        "client_id": "client-alpha",
        "session_id": "sess-001",
        "action_type": "http_fetch",
        "target": "https://example.com",
        "content": "Fetch a public page for analysis.",
        "risk_score": 12,
        "execution_state": "executed",
        "response_action": "allow",
        "response_status": "completed",
        "policy_verdict": "allow",
        "should_execute": True,
        "halted_by_boundary": False,
        "filepath": None,
        "trace_id": "trace_001",
        "request_id": "req_001",
        "decision_id": "dec_001",
        "review_item_id": None,
        "executor_name": "default_executor",
        "executor_result": {"status": "ok"},
        "reason": "Low-risk public fetch.",
        "reasons": [
            {
                "source": "policy",
                "label": "Allowed target",
                "details": "The request targets a public HTTPS endpoint.",
                "score": 12,
            },
        ],
    },
    {
        "execution_id": "exec_002",
        "timestamp": _utc_now_iso(),
        "client_id": "client-beta",
        "session_id": "sess-002",
        "action_type": "shell_execute",
        "target": "rm -rf /tmp/test",
        "content": "Attempt to remove a local path.",
        "risk_score": 91,
        "execution_state": "denied",
        "response_action": "block",
        "response_status": "denied",
        "policy_verdict": "block",
        "should_execute": False,
        "halted_by_boundary": True,
        "filepath": "/tmp/test",
        "trace_id": "trace_002",
        "request_id": "req_002",
        "decision_id": "dec_002",
        "review_item_id": "review_002",
        "executor_name": "sandbox_executor",
        "executor_result": {"status": "blocked"},
        "reason": "Destructive shell action was blocked.",
        "reasons": [
            {
                "source": "scan",
                "label": "Destructive command",
                "details": "The command attempts to remove local files.",
                "score": 91,
            },
        ],
    },
]


def _to_dashboard_item(record: dict[str, Any]) -> ExecutionDashboardItem:
    return ExecutionDashboardItem(
        execution_id=str(record["execution_id"]),
        timestamp=str(record["timestamp"]),
        client_id=record.get("client_id"),
        session_id=record.get("session_id"),
        action_type=str(record["action_type"]),
        target=str(record["target"]),
        risk_score=int(record["risk_score"]),
        execution_state=str(record["execution_state"]),
        response_status=str(record["response_status"]),
        policy_verdict=str(record["policy_verdict"]),
        should_execute=bool(record["should_execute"]),
        halted_by_boundary=bool(record["halted_by_boundary"]),
        filepath=record.get("filepath"),
        trace_id=record.get("trace_id"),
        request_id=record.get("request_id"),
        decision_id=record.get("decision_id"),
        review_item_id=record.get("review_item_id"),
        executor_name=record.get("executor_name"),
        reason=record.get("reason"),
    )


def _to_detail_response(record: dict[str, Any]) -> ExecutionDetailResponse:
    return ExecutionDetailResponse(
        execution_id=str(record["execution_id"]),
        timestamp=str(record["timestamp"]),
        action_type=str(record["action_type"]),
        target=str(record["target"]),
        content=str(record.get("content", "")),
        risk_score=int(record["risk_score"]),
        client_id=record.get("client_id"),
        session_id=record.get("session_id"),
        filepath=record.get("filepath"),
        execution_state=str(record["execution_state"]),
        response_action=str(record["response_action"]),
        response_status=str(record["response_status"]),
        policy_verdict=str(record["policy_verdict"]),
        should_execute=bool(record["should_execute"]),
        halted_by_boundary=bool(record["halted_by_boundary"]),
        trace_id=str(record["trace_id"]),
        request_id=str(record["request_id"]),
        decision_id=str(record["decision_id"]),
        review_item_id=record.get("review_item_id"),
        executor_name=record.get("executor_name"),
        executor_result=record.get("executor_result"),
        reason=record.get("reason"),
        reasons=[
            ExecutionReasonView(
                source=str(item["source"]),
                label=str(item["label"]),
                details=str(item["details"]),
                score=item.get("score"),
            )
            for item in record.get("reasons", [])
        ],
    )


@router.get("", response_model=ExecutionDashboardResponse)
def get_execution_dashboard(
    limit: int = Query(default=50, ge=1, le=500),
) -> ExecutionDashboardResponse:
    items = [_to_dashboard_item(record) for record in _SAMPLE_EXECUTIONS[:limit]]
    return ExecutionDashboardResponse(items=items, total=len(items))


@router.get("/{execution_id}", response_model=ExecutionDetailResponse)
def get_execution_detail(execution_id: str) -> ExecutionDetailResponse:
    for record in _SAMPLE_EXECUTIONS:
        if record["execution_id"] == execution_id:
            return _to_detail_response(record)

    fallback = {
        "execution_id": execution_id,
        "timestamp": _utc_now_iso(),
        "action_type": "unknown",
        "target": "unknown",
        "content": "",
        "risk_score": 0,
        "client_id": None,
        "session_id": None,
        "filepath": None,
        "execution_state": "failed",
        "response_action": "review",
        "response_status": "denied",
        "policy_verdict": "warn",
        "should_execute": False,
        "halted_by_boundary": False,
        "trace_id": f"trace_{execution_id}",
        "request_id": f"req_{execution_id}",
        "decision_id": f"dec_{execution_id}",
        "review_item_id": None,
        "executor_name": None,
        "executor_result": None,
        "reason": "Execution record not found in the current in-memory dashboard snapshot.",
        "reasons": [
            {
                "source": "policy",
                "label": "Missing record",
                "details": "No execution record matched the provided execution ID.",
                "score": 0,
            },
        ],
    }
    return _to_detail_response(fallback)
