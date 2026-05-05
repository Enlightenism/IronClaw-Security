from __future__ import annotations

"""
Thin compatibility wrapper for the OpenClaw adapter.

This keeps ironclawskill.* as the skill package boundary while delegating
the actual implementation to the canonical ironclaw_skill.adapter_openclaw
module, avoiding duplicate logic.
"""

from typing import Any, Final, Literal

from ironclaw_skill.adapter_openclaw import (  # type: ignore[import-not-found]
    OpenClawAdapterError as OpenClawAdapterError,
    adapt_openclaw_request as adaptopenclawrequest,
    adapt_openclaw_response as adaptopenclawresponse,
    build_openclaw_error_response as buildopenclawerrorresponse,
    build_openclaw_success_response as buildopenclawsuccessresponse,
    openclaw_tool_input_schema as openclawtoolinputschema,
)
from ironclaw_skill.contracts import (  # re-exported for local type signatures
    SkillReason,
    SkillRequest,
    SkillResponseEnvelope,
)

OPENCLAW_PLATFORM: Final[Literal["openclaw"]] = "openclaw"


def adapt_openclaw_request(raw: dict[str, Any]) -> SkillRequest:
    """
    Delegate OpenClaw → IronClaw skill request adaptation to the canonical
    implementation while keeping a stable symbol under ironclawskill.*.
    """
    return adaptopenclawrequest(raw)


def adapt_openclaw_response(response: SkillResponseEnvelope) -> dict[str, Any]:
    """
    Delegate IronClaw skill response → OpenClaw-shaped payload adaptation.
    """
    return adaptopenclawresponse(response)


def build_openclaw_error_response(
    *,
    operation: Literal["scan", "action_policy", "action_decision", "execute"],
    summary: str,
    error_code: str,
    request_id: str | None = None,
) -> dict[str, Any]:
    """
    Build an OpenClaw-shaped error response using the canonical implementation.
    """
    return buildopenclawerrorresponse(
        operation=operation,
        summary=summary,
        error_code=error_code,
        request_id=request_id,
    )


def build_openclaw_success_response(
    *,
    operation: Literal["scan", "action_policy", "action_decision", "execute"],
    verdict: Literal["allow", "review", "block"],
    summary: str,
    should_halt: bool = False,
    should_warn: bool = False,
    request_id: str | None = None,
    scan_id: str | None = None,
    decision_source: Literal[
        "policy", "scan", "ai", "runtime", "combined", "unknown"
    ] = "unknown",
    matched_patterns: list[str] | None = None,
    risk_score: int | None = None,
    reasons: list[SkillReason] | None = None,
    raw_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build an OpenClaw-shaped success response using the canonical implementation.
    """
    return buildopenclawsuccessresponse(
        operation=operation,
        verdict=verdict,
        summary=summary,
        should_halt=should_halt,
        should_warn=should_warn,
        request_id=request_id,
        scan_id=scan_id,
        decision_source=decision_source,
        matched_patterns=matched_patterns,
        risk_score=risk_score,
        reasons=reasons,
        raw_result=raw_result,
    )


def openclaw_tool_input_schema() -> dict[str, Any]:
    """
    Expose the JSON-schema input contract for OpenClaw tools.
    """
    return openclawtoolinputschema()


class OpenClawSkillAdapter:
    """
    High-level runtime adapter facade for OpenClaw.

    Wraps the request/response adaptation helpers so the runtime can treat
    OpenClaw as a provider, while all normalization remains in the
    canonical ironclaw_skill.adapter_openclaw module.
    """

    def __init__(self, config: Any) -> None:
        # We do not duplicate config types here; the runtime passes whatever
        # provider config it owns, and the underlying skill layer interprets it.
        self._config = config


__all__ = [
    "OPENCLAW_PLATFORM",
    "OpenClawAdapterError",
    "OpenClawSkillAdapter",
    "adapt_openclaw_request",
    "adapt_openclaw_response",
    "adaptopenclawrequest",
    "adaptopenclawresponse",
    "build_openclaw_error_response",
    "build_openclaw_success_response",
    "buildopenclawerrorresponse",
    "buildopenclawsuccessresponse",
    "openclaw_tool_input_schema",
    "openclawtoolinputschema",
]