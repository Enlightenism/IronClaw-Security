from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ironclaw_skill.contracts import SkillReason, SkillResponseEnvelope, build_skill_error_response


@dataclass(frozen=True, slots=True)
class IronClawSkillError(Exception):
    message: str
    error_code: str = "skill_error"
    operation: str = "scan"
    request_id: str | None = None
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message

    def to_reason(self) -> SkillReason:
        return SkillReason(
            source="skill",
            label=self.__class__.__name__,
            details=self.message,
        )

    def to_response(self) -> SkillResponseEnvelope:
        normalized_operation = self.operation
        if normalized_operation not in {"scan", "action_policy", "action_decision", "execute"}:
            normalized_operation = "scan"

        return build_skill_error_response(
            operation=normalized_operation,  # type: ignore[arg-type]
            summary=self.message,
            error_code=self.error_code,
            request_id=self.request_id,
            reasons=[self.to_reason()],
            raw_result=self.details,
        )


@dataclass(frozen=True, slots=True)
class SkillConfigError(IronClawSkillError):
    error_code: str = "skill_config_error"
    operation: str = "scan"


@dataclass(frozen=True, slots=True)
class SkillValidationError(IronClawSkillError):
    error_code: str = "skill_validation_error"
    operation: str = "scan"


@dataclass(frozen=True, slots=True)
class SkillAdapterError(IronClawSkillError):
    error_code: str = "skill_adapter_error"
    operation: str = "scan"


@dataclass(frozen=True, slots=True)
class SkillRuntimeError(IronClawSkillError):
    error_code: str = "skill_runtime_error"
    operation: str = "execute"


@dataclass(frozen=True, slots=True)
class SkillPolicyError(IronClawSkillError):
    error_code: str = "skill_policy_error"
    operation: str = "action_decision"


@dataclass(frozen=True, slots=True)
class SkillExecutionError(IronClawSkillError):
    error_code: str = "skill_execution_error"
    operation: str = "execute"


def error_to_response(exc: Exception) -> SkillResponseEnvelope:
    if isinstance(exc, IronClawSkillError):
        return exc.to_response()

    wrapped = IronClawSkillError(
        message=str(exc) or exc.__class__.__name__,
        error_code="unhandled_skill_error",
        operation="scan",
        details={"exception_type": exc.__class__.__name__},
    )
    return wrapped.to_response()


__all__ = [
    "IronClawSkillError",
    "SkillAdapterError",
    "SkillConfigError",
    "SkillExecutionError",
    "SkillPolicyError",
    "SkillRuntimeError",
    "SkillValidationError",
    "error_to_response",
]
