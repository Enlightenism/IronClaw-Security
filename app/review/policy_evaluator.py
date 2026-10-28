from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

DEFAULT_FILE_PATH = "app/api/action_execute.py"
ALLOW_VERDICT = "allow"
WARN_VERDICT = "warn"
BLOCK_VERDICT = "block"
REVIEW_VERDICT = "review"

EXECUTED_STATE = "executed"
DENIED_STATE = "denied"

STATUS_COMPLETED = "completed"
STATUS_QUEUED = "queued_for_review"
STATUS_DENIED = "denied"

ACTION_ALLOW = "allow"
ACTION_REVIEW = "review"
ACTION_BLOCK = "block"


@dataclass(slots=True)
class ExecutionReason:
    source: str
    label: str
    details: str
    score: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "source": self.source,
            "label": self.label,
            "details": self.details,
        }
        if self.score is not None:
            data["score"] = self.score
        return data


@dataclass(slots=True)
class ActionExecuteResult:
    execution_id: str
    execution_state: str
    response_action: str
    response_status: str
    trace_id: str
    request_id: str
    decision_id: str
    policy_verdict: Literal["allow", "block"]
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    review_item_id: str | None
    executor_name: str | None
    executor_result: dict[str, Any] | None
    reason: str
    reasons: list[ExecutionReason]
    filepath: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "execution_state": self.execution_state,
            "response_action": self.response_action,
            "response_status": self.response_status,
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "policy_verdict": self.policy_verdict,
            "risk_score": self.risk_score,
            "should_execute": self.should_execute,
            "halted_by_boundary": self.halted_by_boundary,
            "review_item_id": self.review_item_id,
            "executor_name": self.executor_name,
            "executor_result": self.executor_result,
            "reason": self.reason,
            "reasons": [item.to_dict() for item in self.reasons],
            "filepath": self.filepath,
        }


def _safe_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _build_reasons(summary: dict[str, Any], risk_score: int) -> list[ExecutionReason]:
    raw_reasons = summary.get("reasons")
    reasons: list[ExecutionReason] = []

    if isinstance(raw_reasons, list):
        for item in raw_reasons:
            if isinstance(item, dict):
                reasons.append(
                    ExecutionReason(
                        source=str(item.get("source") or "policy"),
                        label=str(item.get("label") or "decision"),
                        details=str(item.get("details") or summary.get("reason") or "Decision recorded"),
                        score=int(item["score"]) if item.get("score") is not None else None,
                    ),
                )
            else:
                reasons.append(
                    ExecutionReason(
                        source="policy",
                        label="decision",
                        details=str(item),
                        score=risk_score,
                    ),
                )

    if reasons:
        return reasons

    return [
        ExecutionReason(
            source="policy",
            label="decision",
            details=str(summary.get("reason") or "Decision recorded"),
            score=risk_score,
        ),
    ]


def _normalize_summary(summary: dict[str, Any], risk_score: int) -> dict[str, Any]:
    policy_verdict = str(summary.get("policyverdict") or summary.get("policy_verdict") or "").strip().lower()

    if policy_verdict in {"hold", REVIEW_VERDICT, WARN_VERDICT}:
        return {
            "execution_state": DENIED_STATE,
            "response_action": ACTION_REVIEW,
            "response_status": STATUS_QUEUED,
            "policy_verdict": BLOCK_VERDICT,
            "should_execute": False,
            "halted_by_boundary": True,
            "review_item_id": summary.get("reviewitemid") or summary.get("review_item_id"),
            "reason": str(summary.get("reason") or "Queued for review"),
        }

    if policy_verdict == ALLOW_VERDICT:
        return {
            "execution_state": EXECUTED_STATE,
            "response_action": ACTION_ALLOW,
            "response_status": STATUS_COMPLETED,
            "policy_verdict": ALLOW_VERDICT,
            "should_execute": True,
            "halted_by_boundary": False,
            "review_item_id": summary.get("reviewitemid") or summary.get("review_item_id"),
            "reason": str(summary.get("reason") or "Execution completed"),
        }

    return {
        "execution_state": DENIED_STATE,
        "response_action": ACTION_BLOCK,
        "response_status": STATUS_DENIED,
        "policy_verdict": BLOCK_VERDICT,
        "should_execute": False,
        "halted_by_boundary": True,
        "review_item_id": summary.get("reviewitemid") or summary.get("review_item_id"),
        "reason": str(summary.get("reason") or "Blocked by policy boundary"),
    }


def evaluate_policy_result(
    summary: dict[str, Any],
    *,
    risk_score: int,
    filepath: str | None = None,
) -> ActionExecuteResult:
    normalized = _normalize_summary(summary, risk_score)
    reasons = _build_reasons(summary, risk_score)

    executor_name_raw = summary.get("executorname") or summary.get("executor_name")
    executor_name = str(executor_name_raw).replace("_", "").lower() if executor_name_raw else None

    return ActionExecuteResult(
        execution_id=str(summary.get("executionid") or summary.get("execution_id") or ""),
        execution_state=normalized["execution_state"],
        response_action=normalized["response_action"],
        response_status=normalized["response_status"],
        trace_id=str(summary.get("traceid") or summary.get("trace_id") or ""),
        request_id=str(summary.get("requestid") or summary.get("request_id") or ""),
        decision_id=str(summary.get("decisionid") or summary.get("decision_id") or ""),
        policy_verdict=normalized["policy_verdict"],
        risk_score=risk_score,
        should_execute=normalized["should_execute"],
        halted_by_boundary=normalized["halted_by_boundary"],
        review_item_id=normalized["review_item_id"],
        executor_name=executor_name,
        executor_result=_safe_dict(summary.get("executorresult") or summary.get("executor_result")),
        reason=normalized["reason"],
        reasons=reasons,
        filepath=filepath or DEFAULT_FILE_PATH,
    )


def summarize_policy_result(
    summary: dict[str, Any],
    *,
    risk_score: int,
    filepath: str | None = None,
) -> dict[str, Any]:
    return evaluate_policy_result(summary, risk_score=risk_score, filepath=filepath).to_dict()


__all__ = [
    "ACTION_ALLOW",
    "ACTION_BLOCK",
    "ACTION_REVIEW",
    "ALLOW_VERDICT",
    "BLOCK_VERDICT",
    "DEFAULT_FILE_PATH",
    "DENIED_STATE",
    "EXECUTED_STATE",
    "REVIEW_VERDICT",
    "STATUS_COMPLETED",
    "STATUS_DENIED",
    "STATUS_QUEUED",
    "WARN_VERDICT",
    "ActionExecuteResult",
    "ExecutionReason",
    "evaluate_policy_result",
    "summarize_policy_result",
]
