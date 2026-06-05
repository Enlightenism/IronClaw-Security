from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.core.errors import AppError
from app.dependencies.rate_limit import limit_policy_routes
from app.schemas.policy import PolicyStatus
from app.services.policy import get_policy_status, is_policy_loaded_from_db
from app.services.prompt_service import analyze_prompt_bundle
from app.services.review_queue_service import get_review_queue_summary
from app.services.telemetry import append_telemetry_event

router = APIRouter(dependencies=[Depends(limit_policy_routes)])


class GuardBundleRequest(BaseModel):
    user_prompt: str | None = Field(default=None, max_length=20000)
    retrieved_doc: str | None = Field(default=None, max_length=50000)
    tool_output: str | None = Field(default=None, max_length=50000)
    model_output: str | None = Field(default=None, max_length=50000)


class PolicyBundleDecisionResponse(BaseModel):
    highest_verdict: str
    should_halt: bool
    should_warn: bool
    user_prompt: dict[str, Any] | None = None
    retrieved_doc: dict[str, Any] | None = None
    tool_output: dict[str, Any] | None = None
    model_output: dict[str, Any] | None = None


class SystemStatusResponse(BaseModel):
    policy: PolicyStatus
    review_summary: dict[str, Any]


def _has_meaningful_content(value: str | None) -> bool:
    return bool(value and value.strip())


def _request_meta(request: Request) -> dict[str, Any]:
    return {
        "request_id": getattr(request.state, "request_id", None),
        "trace_id": getattr(request.state, "trace_id", None),
        "path": request.url.path,
        "method": request.method,
    }


@router.get("/status", response_model=PolicyStatus)
def read_policy_status(request: Request) -> PolicyStatus:
    raw = get_policy_status()
    raw["policy_loaded_from_db"] = is_policy_loaded_from_db()
    status = PolicyStatus(**raw)

    try:
        append_telemetry_event(
            "policy_status_requested",
            {
                **_request_meta(request),
                "mode": getattr(status, "mode", None),
                "enforcement_enabled": getattr(status, "enforcement_enabled", None),
                "policy_loaded_from_db": status.policy_loaded_from_db,
            },
        )
    except Exception:
        pass

    return status


@router.get("/system-status", response_model=SystemStatusResponse)
def read_system_status(request: Request) -> SystemStatusResponse:
    raw = get_policy_status()
    raw["policy_loaded_from_db"] = is_policy_loaded_from_db()
    policy_status = PolicyStatus(**raw)
    review_summary = get_review_queue_summary()

    try:
        append_telemetry_event(
            "policy_system_status_requested",
            {
                **_request_meta(request),
                "policy_mode": getattr(policy_status, "mode", None),
                "policy_loaded_from_db": policy_status.policy_loaded_from_db,
                "pending_reviews": review_summary.get("pending_items"),
                "critical_items": review_summary.get("critical_items"),
                "total_items": review_summary.get("total_items"),
            },
        )
    except Exception:
        pass

    return SystemStatusResponse(
        policy=policy_status,
        review_summary=review_summary,
    )


@router.post("/guard-bundle", response_model=PolicyBundleDecisionResponse)
def guard_prompt_bundle(
    payload: GuardBundleRequest,
    request: Request,
) -> PolicyBundleDecisionResponse:
    """Internal policy route for guarding multi-source prompt context.

    Expected optional JSON fields:
    - user_prompt
    - retrieved_doc
    - tool_output
    - model_output

    Returns a consolidated verdict bundle using:
    allow < warn < quarantine < block
    """
    if not any(
        [
            _has_meaningful_content(payload.user_prompt),
            _has_meaningful_content(payload.retrieved_doc),
            _has_meaningful_content(payload.tool_output),
            _has_meaningful_content(payload.model_output),
        ],
    ):
        raise AppError(
            error="empty_policy_bundle",
            message="At least one non-empty prompt bundle field must be provided",
            status_code=400,
            details={
                "allowed_fields": [
                    "user_prompt",
                    "retrieved_doc",
                    "tool_output",
                    "model_output",
                ],
            },
        )

    result = analyze_prompt_bundle(
        user_prompt=payload.user_prompt.strip() if payload.user_prompt else None,
        retrieved_doc=payload.retrieved_doc.strip() if payload.retrieved_doc else None,
        tool_output=payload.tool_output.strip() if payload.tool_output else None,
        model_output=payload.model_output.strip() if payload.model_output else None,
    )

    try:
        append_telemetry_event(
            "policy_bundle_decision",
            {
                **_request_meta(request),
                "highest_verdict": result.get("highest_verdict"),
                "should_halt": result.get("should_halt"),
                "should_warn": result.get("should_warn"),
                "has_user_prompt": _has_meaningful_content(payload.user_prompt),
                "has_retrieved_doc": _has_meaningful_content(payload.retrieved_doc),
                "has_tool_output": _has_meaningful_content(payload.tool_output),
                "has_model_output": _has_meaningful_content(payload.model_output),
                "user_prompt_verdict": (result.get("user_prompt") or {}).get("verdict"),
                "user_prompt_risk_score": (result.get("user_prompt") or {}).get("risk_score"),
                "retrieved_doc_verdict": (result.get("retrieved_doc") or {}).get("verdict"),
                "retrieved_doc_risk_score": (result.get("retrieved_doc") or {}).get("risk_score"),
                "tool_output_verdict": (result.get("tool_output") or {}).get("verdict"),
                "tool_output_risk_score": (result.get("tool_output") or {}).get("risk_score"),
                "model_output_verdict": (result.get("model_output") or {}).get("verdict"),
                "model_output_risk_score": (result.get("model_output") or {}).get("risk_score"),
            },
        )
    except Exception:
        pass

    return PolicyBundleDecisionResponse(**result)
