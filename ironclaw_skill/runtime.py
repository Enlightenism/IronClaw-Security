from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Literal

import httpx

from ironclaw_skill.context import IronClawSkillContext, require_skill_context
from ironclaw_skill.contracts import (
    SkillActionInput,
    SkillReason,
    SkillResponseEnvelope,
    build_skill_error_response,
    build_skill_success_response,
)
from ironclawshellguard import GuardedCommandResult, IronClawShellGuard, ShellGuardError


class IronClawSkillRuntimeError(RuntimeError):
    """Raised when the IronClaw skill runtime cannot complete an operation."""


@dataclass(frozen=True, slots=True)
class SkillRuntimeResult:
    response: SkillResponseEnvelope
    context: IronClawSkillContext

    def to_dict(self) -> dict[str, Any]:
        return {
            "response": self.response.model_dump(mode="json"),
            "context": self.context.to_dict(),
        }


def _normalize_request_id(request_id: str | None) -> str | None:
    if request_id is None:
        return None
    normalized = request_id.strip()
    return normalized or None


def _headers(context: IronClawSkillContext) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if context.api_secret:
        headers["Authorization"] = f"Bearer {context.api_secret}"
    return headers


def _health_url(context: IronClawSkillContext) -> str:
    return f"{context.base_url.rstrip('/')}/health"


def _scan_url(context: IronClawSkillContext) -> str:
    return f"{context.base_url.rstrip('/')}/scan"


def _policy_url(context: IronClawSkillContext) -> str:
    return f"{context.base_url.rstrip('/')}/policy/evaluate"


def _safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def ping_runtime(
    *,
    context: IronClawSkillContext | None = None,
) -> bool:
    resolved_context = context or require_skill_context()
    try:
        with httpx.Client(timeout=resolved_context.timeout_seconds, headers=_headers(resolved_context)) as client:
            response = client.get(_health_url(resolved_context))
            return response.status_code < 500
    except httpx.HTTPError:
        return False


def scan_for_skill(
    *,
    target_type: Literal["text", "url", "file_path", "prompt_bundle"],
    target_value: str | None = None,
    bundle: dict[str, Any] | None = None,
    policy_mode: Literal["allow", "review", "block"] | None = None,
    request_id: str | None = None,
    context: IronClawSkillContext | None = None,
) -> SkillRuntimeResult:
    resolved_context = context or require_skill_context()
    normalized_request_id = _normalize_request_id(request_id)

    payload: dict[str, Any] = {
        "target_type": target_type,
        "policy_mode": (policy_mode or resolved_context.policy_mode).lower(),
    }

    if target_type == "prompt_bundle":
        payload["bundle"] = bundle or {}
    else:
        payload["target_value"] = (target_value or "").strip()

    try:
        with httpx.Client(timeout=resolved_context.timeout_seconds, headers=_headers(resolved_context)) as client:
            response = client.post(_scan_url(resolved_context), json=payload)
            response_payload = _safe_json(response)

            if response.is_success:
                summary = response_payload.get("summary") or "IronClaw scan completed."
                risk_score = response_payload.get("risk_score")
                raw_verdict = str(response_payload.get("verdict") or "block").lower()
                matched_patterns = response_payload.get("matched_patterns") or []
                failed_checks = response_payload.get("failed_checks") or []
                verdict: Literal["allow", "block"] = "allow" if raw_verdict == "allow" and not matched_patterns and not failed_checks and not response_payload.get("should_halt") and not response_payload.get("should_warn") and not response_payload.get("error_code") else "block"

                envelope = build_skill_success_response(
                    operation="scan",
                    verdict=verdict,
                    summary=summary,
                    should_halt=verdict == "block",
                    should_warn=False,
                    request_id=normalized_request_id,
                    scan_id=response_payload.get("scan_id"),
                    decision_source="scan",
                    matched_patterns=matched_patterns,
                    risk_score=risk_score if isinstance(risk_score, int) else None,
                    reasons=[
                        SkillReason(
                            source="scan",
                            label="Runtime scan completed",
                            details=summary,
                            score=(risk_score / 100.0) if isinstance(risk_score, int) else None,
                        ),
                    ],
                    raw_result=response_payload,
                )
                return SkillRuntimeResult(response=envelope, context=resolved_context)

            envelope = build_skill_error_response(
                operation="scan",
                summary=response_payload.get("summary") or f"Scan request failed with status {response.status_code}.",
                error_code="scan_request_failed",
                request_id=normalized_request_id,
                reasons=[
                    SkillReason(
                        source="runtime",
                        label="Scan request failed",
                        details=f"HTTP {response.status_code}",
                    ),
                ],
                raw_result=response_payload,
            )
            return SkillRuntimeResult(response=envelope, context=resolved_context)
    except httpx.HTTPError as exc:
        envelope = build_skill_error_response(
            operation="scan",
            summary=f"Scan request could not reach IronClaw runtime: {exc}",
            error_code="scan_runtime_unreachable",
            request_id=normalized_request_id,
            reasons=[
                SkillReason(
                    source="runtime",
                    label="Runtime unreachable",
                    details=str(exc),
                ),
            ],
        )
        return SkillRuntimeResult(response=envelope, context=resolved_context)


def evaluate_action_for_skill(
    *,
    action: SkillActionInput,
    request_id: str | None = None,
    context: IronClawSkillContext | None = None,
) -> SkillRuntimeResult:
    resolved_context = context or require_skill_context()
    normalized_request_id = _normalize_request_id(request_id)

    payload = {
        "action_type": action.action_type,
        "target": action.target,
        "content": action.content,
        "policy_mode": action.policy_mode,
        "dry_run": action.dry_run,
    }

    try:
        with httpx.Client(timeout=resolved_context.timeout_seconds, headers=_headers(resolved_context)) as client:
            response = client.post(_policy_url(resolved_context), json=payload)
            response_payload = _safe_json(response)

            if response.is_success:
                summary = response_payload.get("summary") or "IronClaw action evaluation completed."
                risk_score = response_payload.get("risk_score")
                raw_verdict = str(response_payload.get("verdict") or "block").lower()
                matched_patterns = response_payload.get("matched_patterns") or []
                failed_checks = response_payload.get("failed_checks") or []
                verdict: Literal["allow", "block"] = "allow" if raw_verdict == "allow" and not matched_patterns and not failed_checks and not response_payload.get("should_halt") and not response_payload.get("should_warn") and not response_payload.get("error_code") else "block"

                envelope = build_skill_success_response(
                    operation="action_decision",
                    verdict=verdict,
                    summary=summary,
                    should_halt=verdict == "block",
                    should_warn=False,
                    request_id=normalized_request_id,
                    scan_id=response_payload.get("scan_id"),
                    decision_source="policy",
                    matched_patterns=matched_patterns or [action.action_type],
                    risk_score=risk_score if isinstance(risk_score, int) else None,
                    reasons=[
                        SkillReason(
                            source="policy",
                            label="Runtime policy evaluation completed",
                            details=summary,
                            score=(risk_score / 100.0) if isinstance(risk_score, int) else None,
                        ),
                    ],
                    raw_result=response_payload,
                )
                return SkillRuntimeResult(response=envelope, context=resolved_context)

            envelope = build_skill_error_response(
                operation="action_decision",
                summary=response_payload.get("summary") or f"Policy request failed with status {response.status_code}.",
                error_code="policy_request_failed",
                request_id=normalized_request_id,
                reasons=[
                    SkillReason(
                        source="runtime",
                        label="Policy request failed",
                        details=f"HTTP {response.status_code}",
                    ),
                ],
                raw_result=response_payload,
            )
            return SkillRuntimeResult(response=envelope, context=resolved_context)
    except httpx.HTTPError as exc:
        envelope = build_skill_error_response(
            operation="action_decision",
            summary=f"Policy request could not reach IronClaw runtime: {exc}",
            error_code="policy_runtime_unreachable",
            request_id=normalized_request_id,
            reasons=[
                SkillReason(
                    source="runtime",
                    label="Runtime unreachable",
                    details=str(exc),
                ),
            ],
        )
        return SkillRuntimeResult(response=envelope, context=resolved_context)


def execute_guarded_for_skill(
    *,
    command: str | list[str],
    request_id: str | None = None,
    cwd: str | None = None,
    timeout_seconds: float | None = None,
    allow_side_effects: bool = False,
    context: IronClawSkillContext | None = None,
    shell_guard: IronClawShellGuard | None = None,
) -> SkillRuntimeResult:
    resolved_context = context or require_skill_context()
    normalized_request_id = _normalize_request_id(request_id)
    guard = shell_guard or IronClawShellGuard()

    if allow_side_effects:
        envelope = build_skill_error_response(
            operation="execute",
            summary="Guarded execution rejected because side effects are not allowed in this runtime path.",
            error_code="guarded_execution_side_effects_not_allowed",
            request_id=normalized_request_id,
            reasons=[
                SkillReason(
                    source="policy",
                    label="Side effects blocked",
                    details="This skill runtime path only permits guarded command evaluation without elevated side effects.",
                ),
            ],
            raw_result={"command": command},
        )
        return SkillRuntimeResult(response=envelope, context=resolved_context)

    try:
        result: GuardedCommandResult = guard.run(
            command,
            timeout_seconds=timeout_seconds or resolved_context.timeout_seconds,
            cwd=cwd,
            check=False,
        )

        verdict: Literal["allow", "block"] = "allow" if result.returncode == 0 else "block"

        envelope = build_skill_success_response(
            operation="execute",
            verdict=verdict,
            summary="Guarded command executed through IronClaw shell guard.",
            should_halt=verdict == "block",
            should_warn=False,
            request_id=normalized_request_id,
            decision_source="runtime",
            matched_patterns=[],
            risk_score=15 if result.returncode == 0 else 45,
            reasons=[
                SkillReason(
                    source="runtime",
                    label="Shell guard execution complete",
                    details=f"Command completed with return code {result.returncode}.",
                    score=0.15 if result.returncode == 0 else 0.45,
                ),
            ],
            raw_result=result.to_dict(),
        )
        return SkillRuntimeResult(response=envelope, context=resolved_context)
    except ShellGuardError as exc:
        envelope = build_skill_error_response(
            operation="execute",
            summary=f"Guarded execution failed: {exc}",
            error_code="guarded_execution_failed",
            request_id=normalized_request_id,
            reasons=[
                SkillReason(
                    source="runtime",
                    label="Shell guard error",
                    details=str(exc),
                ),
            ],
            raw_result={"command": command},
        )
        return SkillRuntimeResult(response=envelope, context=resolved_context)


def runtime_snapshot(
    *,
    context: IronClawSkillContext | None = None,
) -> dict[str, Any]:
    resolved_context = context or require_skill_context()
    return {
        "context": resolved_context.to_dict(),
        "runtime_reachable": ping_runtime(context=resolved_context),
    }


def runtime_snapshot_json(
    *,
    context: IronClawSkillContext | None = None,
) -> str:
    return json.dumps(runtime_snapshot(context=context), indent=2, ensure_ascii=False)


__all__ = [
    "IronClawSkillRuntimeError",
    "SkillRuntimeResult",
    "evaluate_action_for_skill",
    "execute_guarded_for_skill",
    "ping_runtime",
    "runtime_snapshot",
    "runtime_snapshot_json",
    "scan_for_skill",
]
