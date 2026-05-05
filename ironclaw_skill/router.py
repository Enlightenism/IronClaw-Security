from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from ironclaw_skill.contracts import (
    SkillActionDecisionRequest,
    SkillActionPolicyRequest,
    SkillExecuteRequest,
    SkillReason,
    SkillRequest,
    SkillResponseEnvelope,
    SkillScanRequest,
    build_skill_error_response,
    build_skill_success_response,
)


class IronClawSkillRouterError(RuntimeError):
    """Raised when routing or handler execution fails."""


HandlerFunc = Callable[[SkillRequest], SkillResponseEnvelope]


@dataclass(slots=True)
class IronClawSkillRouter:
    scan_handler: HandlerFunc | None = None
    action_policy_handler: HandlerFunc | None = None
    action_decision_handler: HandlerFunc | None = None
    execute_handler: HandlerFunc | None = None

    def route(self, request: SkillRequest) -> SkillResponseEnvelope:
        if isinstance(request, SkillScanRequest):
            return self._dispatch("scan", request, self.scan_handler, self._default_scan_handler)
        if isinstance(request, SkillActionPolicyRequest):
            return self._dispatch(
                "action_policy",
                request,
                self.action_policy_handler,
                self._default_action_policy_handler,
            )
        if isinstance(request, SkillActionDecisionRequest):
            return self._dispatch(
                "action_decision",
                request,
                self.action_decision_handler,
                self._default_action_decision_handler,
            )
        if isinstance(request, SkillExecuteRequest):
            return self._dispatch("execute", request, self.execute_handler, self._default_execute_handler)

        raise IronClawSkillRouterError(f"Unsupported request type: {type(request)!r}")

    def register(
        self,
        operation: Literal["scan", "action_policy", "action_decision", "execute"],
        handler: HandlerFunc,
    ) -> None:
        if operation == "scan":
            self.scan_handler = handler
            return
        if operation == "action_policy":
            self.action_policy_handler = handler
            return
        if operation == "action_decision":
            self.action_decision_handler = handler
            return
        if operation == "execute":
            self.execute_handler = handler
            return
        raise IronClawSkillRouterError(f"Unsupported operation registration: {operation}")

    def _dispatch(
        self,
        operation: Literal["scan", "action_policy", "action_decision", "execute"],
        request: SkillRequest,
        handler: HandlerFunc | None,
        fallback: HandlerFunc,
    ) -> SkillResponseEnvelope:
        selected_handler = handler or fallback

        try:
            response = selected_handler(request)
        except Exception as exc:
            return build_skill_error_response(
                operation=operation,
                summary=f"Router handler failure for {operation}: {exc}",
                error_code="router_handler_failure",
                request_id=self._request_id(request),
                reasons=[
                    SkillReason(
                        source="runtime",
                        label="Router handler exception",
                        details=str(exc),
                    )
                ],
                raw_result={"operation": operation},
            )

        if response.operation != operation:
            return build_skill_error_response(
                operation=operation,
                summary=f"Handler returned mismatched operation for {operation}",
                error_code="router_operation_mismatch",
                request_id=self._request_id(request),
                reasons=[
                    SkillReason(
                        source="runtime",
                        label="Operation mismatch",
                        details=f"Expected {operation}, got {response.operation}",
                    )
                ],
                raw_result={"expected_operation": operation, "actual_operation": response.operation},
            )

        return response

    @staticmethod
    def _request_id(request: SkillRequest) -> str | None:
        return request.context.request_id

    def _default_scan_handler(self, request: SkillRequest) -> SkillResponseEnvelope:
        if not isinstance(request, SkillScanRequest):
            raise IronClawSkillRouterError("Invalid request provided to scan handler.")

        details = {
            "target_type": request.input.target_type,
            "policy_mode": request.input.policy_mode,
            "has_bundle": request.input.bundle is not None,
        }

        return build_skill_success_response(
            operation="scan",
            verdict="review",
            summary="Scan request accepted by router placeholder. Runtime scan integration is not wired yet.",
            should_halt=False,
            should_warn=True,
            request_id=request.context.request_id,
            decision_source="runtime",
            matched_patterns=[],
            risk_score=25,
            reasons=[
                SkillReason(
                    source="runtime",
                    label="Placeholder scan handler",
                    details="The skill router accepted the scan request, but the downstream IronClaw scan runtime is not connected yet.",
                    score=0.25,
                )
            ],
            raw_result=details,
        )

    def _default_action_policy_handler(self, request: SkillRequest) -> SkillResponseEnvelope:
        if not isinstance(request, SkillActionPolicyRequest):
            raise IronClawSkillRouterError("Invalid request provided to action policy handler.")

        risk_score = 70 if request.input.action_type in {"shell_command", "system_change", "file_delete"} else 45

        return build_skill_success_response(
            operation="action_policy",
            verdict="review",
            summary="Action policy request accepted by router placeholder. Runtime policy enforcement is not wired yet.",
            should_halt=False,
            should_warn=True,
            request_id=request.context.request_id,
            decision_source="policy",
            matched_patterns=[request.input.action_type],
            risk_score=risk_score,
            reasons=[
                SkillReason(
                    source="policy",
                    label="Placeholder action policy handler",
                    details="The action was normalized successfully, but final policy evaluation is still pending runtime integration.",
                    score=min(risk_score / 100.0, 1.0),
                )
            ],
            raw_result={
                "action_type": request.input.action_type,
                "target": request.input.target,
                "dry_run": request.input.dry_run,
            },
        )

    def _default_action_decision_handler(self, request: SkillRequest) -> SkillResponseEnvelope:
        if not isinstance(request, SkillActionDecisionRequest):
            raise IronClawSkillRouterError("Invalid request provided to action decision handler.")

        high_risk_actions = {"shell_command", "system_change", "file_delete"}
        verdict: Literal["allow", "review", "block"]
        should_halt = False
        should_warn = False
        risk_score = 35

        if request.input.action_type in high_risk_actions:
            verdict = "review"
            should_warn = True
            risk_score = 72
        else:
            verdict = "allow"
            risk_score = 20

        return build_skill_success_response(
            operation="action_decision",
            verdict=verdict,
            summary="Action decision evaluated by router placeholder using conservative pre-runtime defaults.",
            should_halt=should_halt,
            should_warn=should_warn,
            request_id=request.context.request_id,
            decision_source="combined",
            matched_patterns=[request.input.action_type],
            risk_score=risk_score,
            reasons=[
                SkillReason(
                    source="runtime",
                    label="Placeholder decision logic",
                    details="This decision is provisional until the full IronClaw runtime and policy engine are connected.",
                    score=min(risk_score / 100.0, 1.0),
                )
            ],
            raw_result={
                "action_type": request.input.action_type,
                "target": request.input.target,
                "policy_mode": request.input.policy_mode,
            },
        )

    def _default_execute_handler(self, request: SkillRequest) -> SkillResponseEnvelope:
        if not isinstance(request, SkillExecuteRequest):
            raise IronClawSkillRouterError("Invalid request provided to execute handler.")

        return build_skill_success_response(
            operation="execute",
            verdict="block",
            summary="Execution blocked by router placeholder because guarded runtime execution is not wired yet.",
            should_halt=True,
            should_warn=True,
            request_id=request.context.request_id,
            decision_source="runtime",
            matched_patterns=[request.input.action.action_type],
            risk_score=85,
            reasons=[
                SkillReason(
                    source="runtime",
                    label="Execution runtime unavailable",
                    details="The router intentionally blocks execution until IronClaw guarded execution is connected.",
                    score=0.85,
                )
            ],
            raw_result={
                "action_type": request.input.action.action_type,
                "target": request.input.action.target,
                "require_confirmation": request.input.require_confirmation,
                "allow_side_effects": request.input.allow_side_effects,
            },
        )


def route_skill_request(
    request: SkillRequest,
    *,
    scan_handler: HandlerFunc | None = None,
    action_policy_handler: HandlerFunc | None = None,
    action_decision_handler: HandlerFunc | None = None,
    execute_handler: HandlerFunc | None = None,
) -> SkillResponseEnvelope:
    router = IronClawSkillRouter(
        scan_handler=scan_handler,
        action_policy_handler=action_policy_handler,
        action_decision_handler=action_decision_handler,
        execute_handler=execute_handler,
    )
    return router.route(request)


__all__ = [
    "HandlerFunc",
    "IronClawSkillRouter",
    "IronClawSkillRouterError",
    "route_skill_request",
]