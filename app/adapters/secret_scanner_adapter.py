from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import re
from typing import Any, Literal

from app.adapters.base import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    BaseIntegrationAdapter,
)
from app.orchestrator.policy_enforcer import (
    PolicyDecision,
    PolicyEngine,
    PolicyInput,
    evaluate_policy,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
)

AdapterVerdict = Literal["allow", "warn", "quarantine", "block"]
AdapterExecutionMode = Literal["monitor", "enforce"]
SecretScanStatus = Literal["clean", "warned", "blocked"]

_REDACT_KEEP_PREFIX = 6
_REDACT_KEEP_SUFFIX = 4
_REDACT_MIN_LENGTH = 12

# ---------------------------------------------------------------------------
# Secret pattern registry
# Each entry: (pattern_type, compiled_regex)
# Order matters — more specific patterns first.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS
    ("aws_access_key_id", re.compile(r"(?<![A-Z0-9])(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("aws_secret_access_key", re.compile(r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s:='\"]+([\\w/+]{40})")),
    # GitHub
    ("github_pat_classic", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_pat_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github_app_token", re.compile(r"\bghs_[A-Za-z0-9]{36}\b")),
    ("github_refresh_token", re.compile(r"\bghr_[A-Za-z0-9]{76}\b")),
    # OpenAI
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("openai_api_key_project", re.compile(r"\bsk-proj-[A-Za-z0-9\-_]{50,200}\b")),
    # Anthropic
    ("anthropic_api_key", re.compile(r"\bsk-ant-(?:api03-)?[A-Za-z0-9\-_]{40,200}\b")),
    # Google
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("google_oauth_client_secret", re.compile(r"(?i)client[_\-\s]?secret[\s:='\"]+([\\w\-]{24,})")),
    # Stripe
    ("stripe_live_secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_test_secret", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_restricted_key", re.compile(r"\brk_live_[0-9a-zA-Z]{24,99}\b")),
    # Slack
    ("slack_bot_token", re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b")),
    ("slack_user_token", re.compile(r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{30,32}\b")),
    ("slack_workspace_token", re.compile(r"\bxoxa-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{30,32}\b")),
    ("slack_webhook_url", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}")),
    # Twilio
    ("twilio_account_sid", re.compile(r"\bAC[a-z0-9]{32}\b")),
    ("twilio_auth_token", re.compile(r"(?i)twilio[_\-\s]?auth[_\-\s]?token[\s:='\"]+([\\w]{32})")),
    # SendGrid
    ("sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b")),
    # HuggingFace
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    # Groq
    ("groq_api_key", re.compile(r"\bgsk_[A-Za-z0-9]{52}\b")),
    # Generic high-entropy bearer / authorization headers
    ("bearer_token", re.compile(r"(?i)bearer\s+([A-Za-z0-9\-_=+/]{32,})")),
    # Generic private key blocks
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    # Generic password patterns in k/v assignment
    ("generic_password", re.compile(r"(?i)(?:password|passwd|pwd|pass|secret|token|apikey|api_key|auth_token|access_token|secret_key|private_key)[\s:='\"\`]+([^\s]{8,})")),
    # Generic hex secret (64 chars — common for SHA-256 HMAC secrets)
    ("hex_secret_64", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")),
    # JWT
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b")),
]

# ---------------------------------------------------------------------------
# Severity classification per pattern type
# ---------------------------------------------------------------------------

_BLOCK_PATTERNS: frozenset[str] = frozenset(
    {
        "aws_access_key_id",
        "aws_secret_access_key",
        "github_pat_classic",
        "github_pat_fine_grained",
        "github_oauth",
        "github_app_token",
        "github_refresh_token",
        "openai_api_key",
        "openai_api_key_project",
        "anthropic_api_key",
        "google_api_key",
        "stripe_live_secret",
        "stripe_restricted_key",
        "slack_bot_token",
        "slack_user_token",
        "huggingface_token",
        "groq_api_key",
        "private_key_block",
    }
)

_WARN_PATTERNS: frozenset[str] = frozenset(
    {
        "google_oauth_client_secret",
        "stripe_test_secret",
        "slack_workspace_token",
        "slack_webhook_url",
        "twilio_account_sid",
        "twilio_auth_token",
        "sendgrid_api_key",
        "bearer_token",
        "generic_password",
        "hex_secret_64",
        "jwt",
    }
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _redact(value: str) -> str:
    length = len(value)
    if length < _REDACT_MIN_LENGTH:
        return "***"
    keep_prefix = min(_REDACT_KEEP_PREFIX, length // 4)
    keep_suffix = min(_REDACT_KEEP_SUFFIX, length // 6)
    redacted_count = max(1, length - keep_prefix - keep_suffix)
    return f"{value[:keep_prefix]}{'*' * redacted_count}{value[length - keep_suffix:]}"


def _extract_match_value(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex >= 1:
        return match.group(1)
    return match.group(0)


# ---------------------------------------------------------------------------
# Core scan result types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SecretMatch:
    pattern_type: str
    verdict: AdapterVerdict
    location: str
    matched_value_redacted: str
    span_start: int
    span_end: int
    context_snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "verdict": self.verdict,
            "location": self.location,
            "matched_value_redacted": self.matched_value_redacted,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "context_snippet": self.context_snippet,
        }

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(slots=True)
class SecretScanResult:
    scan_status: SecretScanStatus
    verdict: AdapterVerdict
    total_matches: int
    block_matches: int
    warn_matches: int
    matches: list[SecretMatch] = field(default_factory=list)
    scanned_locations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_status": self.scan_status,
            "verdict": self.verdict,
            "total_matches": self.total_matches,
            "block_matches": self.block_matches,
            "warn_matches": self.warn_matches,
            "matches": [m.to_dict() for m in self.matches],
            "scanned_locations": list(self.scanned_locations),
        }

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------


def _scan_text(text: str, location: str) -> list[SecretMatch]:
    results: list[SecretMatch] = []
    if not text:
        return results
    for pattern_type, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw_value = _extract_match_value(match)
            verdict: AdapterVerdict = "block" if pattern_type in _BLOCK_PATTERNS else "warn"
            span_start, span_end = match.span(0)
            snippet_start = max(0, span_start - 20)
            snippet_end = min(len(text), span_end + 20)
            raw_snippet = text[snippet_start:snippet_end]
            safe_snippet = re.sub(re.escape(raw_value), _redact(raw_value), raw_snippet)
            results.append(
                SecretMatch(
                    pattern_type=pattern_type,
                    verdict=verdict,
                    location=location,
                    matched_value_redacted=_redact(raw_value),
                    span_start=span_start,
                    span_end=span_end,
                    context_snippet=safe_snippet,
                )
            )
    return results


def _scan_dict_values(data: dict[str, Any], location_prefix: str) -> list[SecretMatch]:
    results: list[SecretMatch] = []
    for key, value in data.items():
        loc = f"{location_prefix}.{key}"
        if isinstance(value, str):
            results.extend(_scan_text(value, loc))
        elif isinstance(value, dict):
            results.extend(_scan_dict_values(value, loc))
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                item_loc = f"{loc}[{idx}]"
                if isinstance(item, str):
                    results.extend(_scan_text(item, item_loc))
                elif isinstance(item, dict):
                    results.extend(_scan_dict_values(item, item_loc))
    return results


def scan_for_secrets(
    *,
    prompt_text: str | None = None,
    tool_call_arguments: dict[str, Any] | None = None,
    file_content: str | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> SecretScanResult:
    all_matches: list[SecretMatch] = []
    scanned: list[str] = []

    if prompt_text:
        scanned.append("prompt_text")
        all_matches.extend(_scan_text(prompt_text, "prompt_text"))

    if tool_call_arguments:
        scanned.append("tool_call_arguments")
        all_matches.extend(_scan_dict_values(tool_call_arguments, "tool_call_arguments"))

    if file_content:
        scanned.append("file_content")
        all_matches.extend(_scan_text(file_content, "file_content"))

    if extra_fields:
        scanned.append("extra_fields")
        all_matches.extend(_scan_dict_values(extra_fields, "extra_fields"))

    block_count = sum(1 for m in all_matches if m.verdict == "block")
    warn_count = sum(1 for m in all_matches if m.verdict == "warn")

    if block_count > 0:
        verdict: AdapterVerdict = "block"
        status: SecretScanStatus = "blocked"
    elif warn_count > 0:
        verdict = "warn"
        status = "warned"
    else:
        verdict = "allow"
        status = "clean"

    return SecretScanResult(
        scan_status=status,
        verdict=verdict,
        total_matches=len(all_matches),
        block_matches=block_count,
        warn_matches=warn_count,
        matches=all_matches,
        scanned_locations=scanned,
    )


# ---------------------------------------------------------------------------
# Policy-facing adapter request / response
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SecretScannerAdapterRequest:
    action_type: str
    target: str
    content: str = ""
    prompt_text: str | None = None
    tool_call_arguments: dict[str, Any] | None = None
    file_content: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        merged: dict[str, Any] = dict(self.metadata)
        if self.context:
            merged.update(self.context)
        if self.prompt_text:
            merged["prompt_text"] = self.prompt_text
        if self.tool_call_arguments:
            merged["tool_call_arguments"] = self.tool_call_arguments
        if self.file_content:
            merged["file_content_length"] = len(self.file_content)
        return PolicyInput(
            action_type=self.action_type,
            target=self.target,
            content=self.content,
            agent_id=self.agent_id,
            session_id=self.session_id,
            metadata=merged,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "prompt_text": self.prompt_text,
            "tool_call_arguments": self.tool_call_arguments,
            "file_content_present": self.file_content is not None,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "context": dict(self.context),
            "metadata": dict(self.metadata),
        }

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(slots=True)
class SecretScannerAdapterResponse:
    adapter_name: str
    platform: str
    mode: AdapterExecutionMode
    verdict: AdapterVerdict
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
    scan_status: SecretScanStatus
    risk_score: int
    risk_level: str
    summary: str
    total_matches: int
    block_matches: int
    warn_matches: int
    scanned_locations: list[str] = field(default_factory=list)
    matches: list[dict[str, Any]] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    decision_id: str | None = None
    trace_id: str | None = None
    reviewed_at: str = field(default_factory=_utc_now)
    request: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "platform": self.platform,
            "mode": self.mode,
            "verdict": self.verdict,
            "should_allow": self.should_allow,
            "should_warn": self.should_warn,
            "should_quarantine": self.should_quarantine,
            "should_block": self.should_block,
            "scan_status": self.scan_status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "total_matches": self.total_matches,
            "block_matches": self.block_matches,
            "warn_matches": self.warn_matches,
            "scanned_locations": list(self.scanned_locations),
            "matches": list(self.matches),
            "matched_rules": list(self.matched_rules),
            "reasons": list(self.reasons),
            "decision_id": self.decision_id,
            "trace_id": self.trace_id,
            "reviewed_at": self.reviewed_at,
            "request": dict(self.request),
            "metadata": dict(self.metadata),
        }

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------


def build_secret_scanner_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    prompt_text: str | None = None,
    tool_call_arguments: dict[str, Any] | None = None,
    file_content: str | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    context: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecretScannerAdapterRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return SecretScannerAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        prompt_text=_normalize_text(prompt_text) or None,
        tool_call_arguments=dict(tool_call_arguments) if tool_call_arguments else None,
        file_content=file_content or None,
        agent_id=_normalize_text(agent_id) or None,
        session_id=_normalize_text(session_id) or None,
        context=dict(context or {}),
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_secret_scanner(
    decision: PolicyDecision,
    scan_result: SecretScanResult,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: SecretScannerAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecretScannerAdapterResponse:
    policy_verdict: AdapterVerdict = decision.verdict  # type: ignore[assignment]
    scan_verdict = scan_result.verdict

    _severity: dict[str, int] = {"allow": 0, "warn": 1, "quarantine": 2, "block": 3}
    final_verdict: AdapterVerdict = scan_verdict if _severity.get(scan_verdict, 0) >= _severity.get(policy_verdict, 0) else policy_verdict

    if final_verdict == "block":
        risk_score = max(decision.risk_score, 90)
        risk_level = "critical"
    elif final_verdict == "quarantine":
        risk_score = max(decision.risk_score, 70)
        risk_level = "high"
    elif final_verdict == "warn":
        risk_score = max(decision.risk_score, 50)
        risk_level = "high" if risk_score >= 70 else "medium"
    else:
        risk_score = decision.risk_score
        risk_level = decision.risk_level

    matched_pattern_types = list({m.pattern_type for m in scan_result.matches})
    matched_rules = [match.rule_id for match in decision.matched_rules] + [f"secret_pattern:{pt}" for pt in matched_pattern_types]

    if scan_result.block_matches > 0:
        summary = f"Secret scanner blocked payload: {scan_result.block_matches} high-severity " f"secret(s) detected across {len(scan_result.scanned_locations)} location(s). " f"Pattern types: {', '.join(matched_pattern_types[:5])}."
    elif scan_result.warn_matches > 0:
        summary = f"Secret scanner warned: {scan_result.warn_matches} potential secret(s) detected. " f"Pattern types: {', '.join(matched_pattern_types[:5])}."
    else:
        summary = decision.summary or "Secret scanner: no secrets detected."

    return SecretScannerAdapterResponse(
        adapter_name="ironclaw-secret-scanner",
        platform="secret-scanner",
        mode=mode,
        verdict=final_verdict,
        should_allow=final_verdict == "allow",
        should_warn=final_verdict == "warn",
        should_quarantine=final_verdict == "quarantine",
        should_block=final_verdict == "block",
        scan_status=scan_result.scan_status,
        risk_score=risk_score,
        risk_level=risk_level,
        summary=summary,
        total_matches=scan_result.total_matches,
        block_matches=scan_result.block_matches,
        warn_matches=scan_result.warn_matches,
        scanned_locations=scan_result.scanned_locations,
        matches=[m.to_dict() for m in scan_result.matches],
        matched_rules=matched_rules,
        reasons=[match.to_dict() for match in decision.matched_rules],
        decision_id=decision.decision_id,
        trace_id=trace_id,
        request=request.to_dict() if request else {},
        metadata=dict(metadata or {}),
    )


def evaluate_secret_scanner_request(
    engine: PolicyEngine,
    request: SecretScannerAdapterRequest,
    *,
    context: dict[str, Any] | None = None,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecretScannerAdapterResponse:
    merged_extra: dict[str, Any] | None = None
    if request.content or context or request.context:
        merged_extra = {}
        if request.content:
            merged_extra["content"] = request.content
        if request.context:
            merged_extra.update(request.context)
        if context:
            merged_extra.update(context)

    scan_result = scan_for_secrets(
        prompt_text=request.prompt_text,
        tool_call_arguments=request.tool_call_arguments,
        file_content=request.file_content,
        extra_fields=merged_extra or None,
    )

    adjusted_risk = max(
        risk_score,
        90 if scan_result.block_matches > 0 else (50 if scan_result.warn_matches > 0 else 0),
    )

    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=adjusted_risk,
    )

    return adapt_policy_decision_to_secret_scanner(
        decision,
        scan_result,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )


def summarize_secret_scanner_adapter_response(
    response: SecretScannerAdapterResponse,
) -> dict[str, Any]:
    return {
        "adapter_name": response.adapter_name,
        "platform": response.platform,
        "mode": response.mode,
        "verdict": response.verdict,
        "scan_status": response.scan_status,
        "total_matches": response.total_matches,
        "block_matches": response.block_matches,
        "warn_matches": response.warn_matches,
        "risk_score": response.risk_score,
        "risk_level": response.risk_level,
        "summary": response.summary,
        "matched_rule_count": len(response.matched_rules),
        "decision_id": response.decision_id,
        "trace_id": response.trace_id,
        "reviewed_at": response.reviewed_at,
    }


# ---------------------------------------------------------------------------
# Integration-facing SecretScannerAdapter class
# ---------------------------------------------------------------------------


@dataclass
class SecretScannerAdapter(BaseIntegrationAdapter):
    runtime: str = "secret-scanner"
    scan_mode: str = "full"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__post_init__()
        self.metadata.setdefault("integration_id", self.record.integration_id)
        self.metadata.setdefault("runtime", self.runtime)
        self.metadata.setdefault("scan_mode", self.scan_mode)

    def supported_action_types(self) -> list[str]:
        return [
            "scan_prompt",
            "scan_tool_call",
            "scan_file_content",
            "scan_completion",
            "scan_tool_output",
        ]

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        self.validate_request(request)

        if self.health == "offline":
            return self.build_result(
                request=request,
                success=False,
                status="offline",
                summary=f"{self.record.name} is offline and cannot execute '{request.action_type}'.",
            )

        payload = request.payload or {}
        scan_result = scan_for_secrets(
            prompt_text=payload.get("prompt_text") or payload.get("content"),
            tool_call_arguments=payload.get("tool_call_arguments"),
            file_content=payload.get("file_content"),
            extra_fields={k: v for k, v in payload.items() if k not in {"prompt_text", "content", "tool_call_arguments", "file_content"}} or None,
        )

        if scan_result.verdict == "block":
            return self.build_result(
                request=request,
                success=False,
                status="blocked",
                summary=(f"{self.record.name} blocked action '{request.action_type}': " f"{scan_result.block_matches} high-severity secret(s) detected."),
                output={
                    "guard_applied": True,
                    "scan_result": scan_result.to_dict(),
                },
                metadata={
                    "runtime": self.runtime,
                    "scan_mode": self.scan_mode,
                },
            )

        if scan_result.verdict == "warn":
            return self.build_result(
                request=request,
                success=True,
                status="accepted_with_warnings",
                summary=(f"{self.record.name} warned on action '{request.action_type}': " f"{scan_result.warn_matches} potential secret(s) detected."),
                output={
                    "guard_applied": True,
                    "scan_result": scan_result.to_dict(),
                },
                metadata={
                    "runtime": self.runtime,
                    "scan_mode": self.scan_mode,
                },
            )

        return self.build_result(
            request=request,
            success=True,
            status="accepted",
            summary=(f"{self.record.name} cleared action '{request.action_type}': " f"no secrets detected."),
            output={
                "guard_applied": True,
                "scan_result": scan_result.to_dict(),
            },
            metadata={
                "runtime": self.runtime,
                "scan_mode": self.scan_mode,
            },
        )


def build_secret_scanner_adapter(registry: IntegrationRegistry) -> SecretScannerAdapter:
    record = get_integration(registry, "secret-scanner")
    if record is None:
        raise KeyError("unknown integration slug: secret-scanner")

    return SecretScannerAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "integration_id": record.integration_id,
            "runtime": "secret-scanner",
            "scan_mode": "full",
        },
    )
