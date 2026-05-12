from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

from .contracts import JsonValue, RiskLevel, SkillDecision, SkillProvider


@dataclass(slots=True, frozen=True)
class ErrorContext:
    requestid: str | None = None
    provider: SkillProvider | None = None
    operation: str | None = None
    risk: RiskLevel | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    @property
    def request_id(self) -> str | None:
        return self.requestid


class IronClawSkillError(Exception):
    statuscode: int = HTTPStatus.INTERNAL_SERVER_ERROR
    errorcode: str = "skillerror"
    decision: SkillDecision = SkillDecision.ERROR
    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        statuscode: int | None = None,
        errorcode: str | None = None,
        decision: SkillDecision | None = None,
        retryable: bool | None = None,
        context: ErrorContext | None = None,
        details: Mapping[str, JsonValue] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.statuscode = int(statuscode or self.statuscode)
        self.errorcode = errorcode or self.errorcode
        self.decision = decision or self.decision
        self.retryable = self.retryable if retryable is None else retryable
        self.context = context or ErrorContext()
        self.details = dict(details or {})

    @staticmethod
    def enumvalue(value: Any) -> Any:
        return getattr(value, "value", value)

    def todict(self) -> dict[str, JsonValue]:
        error: dict[str, JsonValue] = {
            "code": self.errorcode,
            "message": self.message,
            "status": self.statuscode,
            "decision": self.enumvalue(self.decision),
            "retryable": self.retryable,
        }
        if self.context.requestid:
            error["requestid"] = self.context.requestid
        if self.context.provider:
            error["provider"] = self.enumvalue(self.context.provider)
        if self.context.operation:
            error["operation"] = self.context.operation
        if self.context.risk:
            error["risk"] = self.enumvalue(self.context.risk)
        if self.details:
            error["details"] = dict(self.details)
        if self.context.metadata:
            error["metadata"] = dict(self.context.metadata)
        return {"error": error}

    def __str__(self) -> str:
        return self.message


class SkillConfigurationError(IronClawSkillError):
    statuscode = HTTPStatus.INTERNAL_SERVER_ERROR
    errorcode = "skillconfigurationerror"


class SkillValidationError(IronClawSkillError):
    statuscode = HTTPStatus.BAD_REQUEST
    errorcode = "skillvalidationerror"


class SkillAuthenticationError(IronClawSkillError):
    statuscode = HTTPStatus.UNAUTHORIZED
    errorcode = "skillauthenticationerror"


class SkillAuthorizationError(IronClawSkillError):
    statuscode = HTTPStatus.FORBIDDEN
    errorcode = "skillauthorizationerror"
    decision = SkillDecision.BLOCK


class SkillPolicyBlockedError(IronClawSkillError):
    statuscode = HTTPStatus.FORBIDDEN
    errorcode = "skillpolicyblocked"
    decision = SkillDecision.BLOCK


class SkillReviewRequiredError(IronClawSkillError):
    statuscode = HTTPStatus.ACCEPTED
    errorcode = "skillreviewrequired"
    decision = SkillDecision.REVIEW


class SkillProviderUnavailableError(IronClawSkillError):
    statuscode = HTTPStatus.BAD_GATEWAY
    errorcode = "skillproviderunavailable"
    retryable = True


class SkillTimeoutError(IronClawSkillError):
    statuscode = HTTPStatus.GATEWAY_TIMEOUT
    errorcode = "skilltimeout"
    retryable = True


class SkillExecutionFailedError(IronClawSkillError):
    statuscode = HTTPStatus.BAD_GATEWAY
    errorcode = "skillexecutionfailed"


class SkillRateLimitError(IronClawSkillError):
    statuscode = HTTPStatus.TOO_MANY_REQUESTS
    errorcode = "skillratelimited"
    retryable = True


class ProviderAuthenticationError(SkillAuthenticationError):
    errorcode = "providerauthenticationerror"


class ProviderExecutionError(SkillExecutionFailedError):
    errorcode = "providerexecutionerror"


class ProviderConfigurationError(SkillConfigurationError):
    errorcode = "providerconfigurationerror"


class ProviderUnavailableError(SkillProviderUnavailableError):
    errorcode = "providerunavailableerror"


class IronClawConfigurationError(SkillConfigurationError):
    errorcode = "ironclawconfigurationerror"


class IronClawRuntimeError(IronClawSkillError):
    statuscode = HTTPStatus.INTERNAL_SERVER_ERROR
    errorcode = "ironclawruntimeerror"


def builderrorcontext(
    *,
    requestid: str | None = None,
    provider: SkillProvider | None = None,
    operation: str | None = None,
    risk: RiskLevel | None = None,
    metadata: Mapping[str, JsonValue] | None = None,
) -> ErrorContext:
    return ErrorContext(
        requestid=requestid,
        provider=provider,
        operation=operation,
        risk=risk,
        metadata=dict(metadata or {}),
    )


__all__ = [
    "ErrorContext",
    "IronClawConfigurationError",
    "IronClawRuntimeError",
    "IronClawSkillError",
    "ProviderAuthenticationError",
    "ProviderConfigurationError",
    "ProviderExecutionError",
    "ProviderUnavailableError",
    "SkillAuthenticationError",
    "SkillAuthorizationError",
    "SkillConfigurationError",
    "SkillExecutionFailedError",
    "SkillPolicyBlockedError",
    "SkillProviderUnavailableError",
    "SkillRateLimitError",
    "SkillReviewRequiredError",
    "SkillTimeoutError",
    "SkillValidationError",
    "builderrorcontext",
]