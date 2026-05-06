from __future__ import annotations


from typing import Annotated, Any, Literal


from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator



def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _normalize_required_text(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("value cannot be empty")
    return normalized


def _normalize_tags(value: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        cleaned = item.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            normalized.append(cleaned)
    return normalized


class SkillBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )


class SkillReason(SkillBaseModel):
    source: Literal["policy", "scan", "ai", "runtime", "installer", "skill"]
    label: str = Field(min_length=1, max_length=200)
    details: str = Field(min_length=1, max_length=4000)
    score: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("label", "details")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _normalize_required_text(value)


class SkillRequestContext(SkillBaseModel):
    client_id: str | None = Field(default=None, max_length=200)
    session_id: str | None = Field(default=None, max_length=200)
    user_id: str | None = Field(default=None, max_length=200)
    tenant_id: str | None = Field(default=None, max_length=200)
    request_id: str | None = Field(default=None, max_length=200)
    source_platform: Literal["claude", "openclaw", "unknown"] = "unknown"
    source_version: str | None = Field(default=None, max_length=100)
    tags: list[str] = Field(default_factory=list)

    @field_validator(
        "client_id",
        "session_id",
        "user_id",
        "tenant_id",
        "request_id",
        "source_version",
    )
    @classmethod
    def _normalize_optional_fields(cls, value: str | None) -> str | None:
        return _normalize_optional_text(value)

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, value: list[str]) -> list[str]:
        return _normalize_tags(value)


class SkillPromptBundleInput(SkillBaseModel):
    user_prompt: str | None = None
    retrieved_doc: str | None = None
    tool_output: str | None = None
    model_output: str | None = None

    @field_validator("user_prompt", "retrieved_doc", "tool_output", "model_output")
    @classmethod
    def _normalize_bundle_fields(cls, value: str | None) -> str | None:
        return _normalize_optional_text(value)

    @model_validator(mode="after")
    def _require_at_least_one_field(self) -> "SkillPromptBundleInput":
        if not any(
            (
                self.user_prompt,
                self.retrieved_doc,
                self.tool_output,
                self.model_output,
            )
        ):
            raise ValueError("at least one prompt bundle field must be provided")
        return self


class SkillScanInput(SkillBaseModel):
    target_type: Literal["text", "url", "file_path", "prompt_bundle"]
    target_value: str | None = None
    bundle: SkillPromptBundleInput | None = None
    policy_mode: Literal["allow", "review", "block"] = "review"

    @field_validator("target_value")
    @classmethod
    def _normalize_target_value(cls, value: str | None) -> str | None:
        # Preserve empty string as-is — the model validator uses it as the
        # "no content provided" sentinel for default/probe scans. Only strip
        # leading/trailing whitespace from non-empty values.
        if value is None:
            return None
        stripped = value.strip()
        # Return empty string rather than None so callers that explicitly pass
        # "" (e.g. adapt_openclaw_request on an empty payload) are not rejected.
        return stripped

    @model_validator(mode="after")
    def _validate_scan_shape(self) -> "SkillScanInput":
        if self.target_type == "prompt_bundle":
            if self.bundle is None:
                raise ValueError("bundle is required when target_type=prompt_bundle")
            if self.target_value is not None:
                raise ValueError("target_value is not allowed when target_type=prompt_bundle")
            return self

        if self.bundle is not None:
            raise ValueError("bundle is only allowed when target_type=prompt_bundle")

        # Allow None OR empty string — empty string means no content was
        # supplied (default-operation probe). Reject only when truly absent
        # (None) AND no fallback was attempted by the caller.
        if self.target_value is None:
            raise ValueError("target_value is required for non-bundle scan inputs")

        return self


class SkillActionInput(SkillBaseModel):
    action_type: Literal[
        "shell_command",
        "python_code",
        "tool_invocation",
        "file_write",
        "file_delete",
        "network_request",
        "system_change",
        "other",
    ]
    target: str = Field(min_length=1, max_length=1000)
    content: str | None = Field(default=None, max_length=20000)
    policy_mode: Literal["allow", "review", "block"] = "review"
    dry_run: bool = False

    @field_validator("target")
    @classmethod
    def _validate_target(cls, value: str) -> str:
        return _normalize_required_text(value)

    @field_validator("content")
    @classmethod
    def _normalize_content(cls, value: str | None) -> str | None:
        return _normalize_optional_text(value)


class SkillExecutionInput(SkillBaseModel):
    action: SkillActionInput
    require_confirmation: bool = False
    allow_side_effects: bool = False


class SkillScanRequest(SkillBaseModel):
    operation: Literal["scan"] = "scan"
    input: SkillScanInput
    context: SkillRequestContext = Field(default_factory=SkillRequestContext)


class SkillActionPolicyRequest(SkillBaseModel):
    operation: Literal["action_policy"] = "action_policy"
    input: SkillActionInput
    context: SkillRequestContext = Field(default_factory=SkillRequestContext)


class SkillActionDecisionRequest(SkillBaseModel):
    operation: Literal["action_decision"] = "action_decision"
    input: SkillActionInput
    context: SkillRequestContext = Field(default_factory=SkillRequestContext)


class SkillExecuteRequest(SkillBaseModel):
    operation: Literal["execute"] = "execute"
    input: SkillExecutionInput
    context: SkillRequestContext = Field(default_factory=SkillRequestContext)


SkillRequest = Annotated[
    SkillScanRequest | SkillActionPolicyRequest | SkillActionDecisionRequest | SkillExecuteRequest,
    Field(discriminator="operation"),
]


class SkillDecisionMetadata(SkillBaseModel):
    scan_id: str | None = Field(default=None, max_length=200)
    decision_source: Literal["policy", "scan", "ai", "runtime", "combined", "unknown"] = "unknown"
    matched_patterns: list[str] = Field(default_factory=list)
    risk_score: int | None = Field(default=None, ge=0, le=100)

    @field_validator("scan_id")
    @classmethod
    def _normalize_scan_id(cls, value: str | None) -> str | None:
        return _normalize_optional_text(value)

    @field_validator("matched_patterns")
    @classmethod
    def _normalize_matched_patterns(cls, value: list[str]) -> list[str]:
        return _normalize_tags(value)


class SkillResponsePayload(SkillBaseModel):
    verdict: Literal["allow", "review", "block", "error"]
    summary: str = Field(min_length=1, max_length=4000)
    should_halt: bool = False
    should_warn: bool = False
    allowed: bool | None = None
    metadata: SkillDecisionMetadata = Field(default_factory=SkillDecisionMetadata)
    reasons: list[SkillReason] = Field(default_factory=list)
    raw_result: dict[str, Any] | None = None

    @field_validator("summary")
    @classmethod
    def _validate_summary(cls, value: str) -> str:
        return _normalize_required_text(value)

    @model_validator(mode="after")
    def _sync_allowed_field(self) -> "SkillResponsePayload":
        if self.allowed is None:
            self.allowed = self.verdict == "allow"
        return self


class SkillResponseEnvelope(SkillBaseModel):
    ok: bool
    operation: Literal["scan", "action_policy", "action_decision", "execute"]
    payload: SkillResponsePayload
    request_id: str | None = Field(default=None, max_length=200)
    error_code: str | None = Field(default=None, max_length=200)

    @field_validator("request_id", "error_code")
    @classmethod
    def _normalize_optional_fields(cls, value: str | None) -> str | None:
        return _normalize_optional_text(value)


def build_skill_success_response(
    *,
    operation: Literal["scan", "action_policy", "action_decision", "execute"],
    verdict: Literal["allow", "review", "block"],
    summary: str,
    should_halt: bool = False,
    should_warn: bool = False,
    request_id: str | None = None,
    scan_id: str | None = None,
    decision_source: Literal["policy", "scan", "ai", "runtime", "combined", "unknown"] = "unknown",
    matched_patterns: list[str] | None = None,
    risk_score: int | None = None,
    reasons: list[SkillReason] | None = None,
    raw_result: dict[str, Any] | None = None,
) -> SkillResponseEnvelope:
    return SkillResponseEnvelope(
        ok=True,
        operation=operation,
        request_id=request_id,
        payload=SkillResponsePayload(
            verdict=verdict,
            summary=summary,
            should_halt=should_halt,
            should_warn=should_warn,
            metadata=SkillDecisionMetadata(
                scan_id=scan_id,
                decision_source=decision_source,
                matched_patterns=matched_patterns or [],
                risk_score=risk_score,
            ),
            reasons=reasons or [],
            raw_result=raw_result,
        ),
    )


def build_skill_error_response(
    *,
    operation: Literal["scan", "action_policy", "action_decision", "execute"],
    summary: str,
    error_code: str,
    request_id: str | None = None,
    reasons: list[SkillReason] | None = None,
    raw_result: dict[str, Any] | None = None,
) -> SkillResponseEnvelope:
    return SkillResponseEnvelope(
        ok=False,
        operation=operation,
        request_id=request_id,
        error_code=error_code,
        payload=SkillResponsePayload(
            verdict="error",
            summary=summary,
            should_halt=True,
            should_warn=True,
            allowed=False,
            reasons=reasons or [],
            raw_result=raw_result,
        ),
    )


__all__ = [
    "SkillActionDecisionRequest",
    "SkillActionInput",
    "SkillActionPolicyRequest",
    "SkillBaseModel",
    "SkillDecisionMetadata",
    "SkillExecuteRequest",
    "SkillExecutionInput",
    "SkillPromptBundleInput",
    "SkillReason",
    "SkillRequest",
    "SkillRequestContext",
    "SkillResponseEnvelope",
    "SkillResponsePayload",
    "SkillScanInput",
    "SkillScanRequest",
    "build_skill_error_response",
    "build_skill_success_response",
]