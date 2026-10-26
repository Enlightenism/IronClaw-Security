from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
from pathlib import Path
import re
import time
from typing import Any, Literal

from app.core.settings import get_settings
from app.services.prompt_guard import classify_prompt_guard

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

GuardSecurityVerdict = Literal["allow", "warn", "quarantine", "block"]
GuardMode = Literal["disabled", "assist", "enforce", "strict"]

# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------

_BLOCK_MIN: int = 90
_QUARANTINE_MIN: int = 70
_WARN_MIN: int = 40

# ---------------------------------------------------------------------------
# Signal taxonomy
# ---------------------------------------------------------------------------

SIG_CRITICAL = "critical-pattern-match"
SIG_HIGH = "high-pattern-match"
SIG_MEDIUM = "medium-pattern-match"
SIG_LOW = "low-pattern-match"
SIG_ACTION_TYPE = "sensitive-action-type"
SIG_NETWORK_TARGET = "network-target"
SIG_ENCODING_EVASION = "encoding-evasion"
SIG_MULTILINE_INJECTION = "multiline-injection"
SIG_ROLE_OVERRIDE = "role-override"
SIG_TOOL_CHAIN_ABUSE = "tool-chain-abuse"
SIG_DATA_BOUNDARY = "data-boundary-violation"
SIG_PROMPT_GUARD = "prompt-guard-malicious"
SIG_KEYWORD_FASTPATH = "keyword-fastpath-triggered"

# ---------------------------------------------------------------------------
# Attack pattern library
# ---------------------------------------------------------------------------

_CRITICAL_PATTERNS: list[str] = [
    "system prompt",
    "ignore previous",
    "ignore all previous",
    "override instructions",
    "disregard your instructions",
    "forget everything",
    "new instructions:",
    "exfiltrate",
    "steal credential",
    "export secret",
    "rm -rf",
    "powershell -enc",
    "powershell -e ",
    "cmd /c",
    "net user /add",
    "chmod 777",
    "drop table",
    "delete from",
    "; exec(",
    "xp_cmdshell",
    "exec sp_",
    "union select",
    "1=1--",
    "' or '1'='1",
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "__import__",
    "os.system(",
    "subprocess.call",
    "subprocess.popen",
    "eval(",
    "exec(",
    "compile(",
]

_HIGH_PATTERNS: list[str] = [
    "ssh key",
    "private key",
    "api key",
    "secret key",
    "access token",
    "bearer token",
    "password",
    "passwd",
    ".env",
    "sudo ",
    "curl http",
    "wget http",
    "invoke-webrequest",
    "invoke-expression",
    "iex(",
    "start-process",
    "net localgroup",
    "/etc/passwd",
    "/etc/shadow",
    "~/.ssh",
    "id_rsa",
]

_MEDIUM_PATTERNS: list[str] = [
    "base64",
    "atob(",
    "btoa(",
    "hidden prompt",
    "bypass",
    "disable guard",
    "disable security",
    "upload file",
    "external write",
    "write to disk",
    "open(",
    "file(",
    "tempfile",
    "pickl",
    "marshal.loads",
    "yaml.load(",
]

_LOW_PATTERNS: list[str] = [
    "redirect",
    "http://",
    "https://",
    "ftp://",
    "smb://",
    "ldap://",
    "file://",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
]

_ENCODING_EVASION_RE = re.compile(
    r"(?:%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#\d+;|&[a-z]+;)",
    re.IGNORECASE,
)
_MULTILINE_INJECTION_RE = re.compile(
    r"(\n|\r|\x0a|\x0d){2,}",
)
_ROLE_OVERRIDE_RE = re.compile(
    r"\b(you are now|act as|pretend to be|roleplay as|simulate being|your new persona)\b",
    re.IGNORECASE,
)
_TOOL_CHAIN_RE = re.compile(
    r"\b(call tool|invoke tool|run tool|execute tool|chain tool|tool_call|use_mcp)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _contains_any(haystack: str, needles: list[str]) -> bool:
    lowered = haystack.lower()
    return any(needle in lowered for needle in needles)


def _keyword_scan(content: str) -> tuple[int, list[str], list[str]]:
    risk = 0
    signals: list[str] = []
    reasoning: list[str] = []

    if _contains_any(content, _CRITICAL_PATTERNS):
        risk = max(risk, 95)
        signals.append(SIG_CRITICAL)
        reasoning.append("Critical attack language matched known high-severity indicators.")

    if _contains_any(content, _HIGH_PATTERNS):
        risk = max(risk, 75)
        signals.append(SIG_HIGH)
        reasoning.append("High-risk execution or secret-access indicators were detected.")

    if _contains_any(content, _MEDIUM_PATTERNS):
        risk = max(risk, 45)
        signals.append(SIG_MEDIUM)
        reasoning.append("Suspicious evasion or externalization language was detected.")

    if _contains_any(content, _LOW_PATTERNS):
        risk = max(risk, 15)
        signals.append(SIG_LOW)
        reasoning.append("Low-risk network or filesystem reference detected.")

    if _ENCODING_EVASION_RE.search(content):
        risk = max(risk, 50)
        signals.append(SIG_ENCODING_EVASION)
        reasoning.append("Percent-encoded or unicode-escaped characters indicate evasion attempt.")

    if _MULTILINE_INJECTION_RE.search(content):
        risk = max(risk, 35)
        signals.append(SIG_MULTILINE_INJECTION)
        reasoning.append("Suspicious multi-line injection sequence detected.")

    if _ROLE_OVERRIDE_RE.search(content):
        risk = max(risk, 85)
        signals.append(SIG_ROLE_OVERRIDE)
        reasoning.append("Role override or persona hijack instruction detected.")

    if _TOOL_CHAIN_RE.search(content):
        risk = max(risk, 55)
        signals.append(SIG_TOOL_CHAIN_ABUSE)
        reasoning.append("Tool chain invocation language detected — potential chained tool abuse.")

    return min(risk, 100), signals, reasoning


def _action_type_penalty(action_type: str) -> tuple[int, list[str], list[str]]:
    high_risk = {"shellcommand", "toolcall", "codeexec", "filewrite", "processlaunch"}
    med_risk = {"fileread", "networkfetch", "apicall"}
    at = action_type.lower().replace("_", "").replace("-", "")
    if at in high_risk:
        return 15, [SIG_ACTION_TYPE], ["Requested action type is inherently elevated risk."]
    if at in med_risk:
        return 8, [SIG_ACTION_TYPE], ["Action type accesses external resources or the file system."]
    return 0, [], []


def _target_penalty(target: str) -> tuple[int, list[str], list[str]]:
    if target.lower().startswith(("http://", "https://", "ftp://", "smb://", "ldap://")):
        return 8, [SIG_NETWORK_TARGET], ["Remote target increases exfiltration and pivot risk."]
    if any(t in target.lower() for t in ("/etc/", "/proc/", "~/.ssh", "id_rsa", "shadow", ".env")):
        return 20, [SIG_DATA_BOUNDARY], ["Target path points to a high-value system resource."]
    return 0, [], []


def _verdict_from_score(risk_score: int) -> GuardSecurityVerdict:
    if risk_score >= _BLOCK_MIN:
        return "block"
    if risk_score >= _QUARANTINE_MIN:
        return "quarantine"
    if risk_score >= _WARN_MIN:
        return "warn"
    return "allow"


def _summary_from_verdict(verdict: GuardSecurityVerdict) -> str:
    return {
        "block": "IronClaw-Security recommends blocking the request.",
        "quarantine": "IronClaw-Security recommends quarantining the request.",
        "warn": "IronClaw-Security recommends warning on the request.",
        "allow": "IronClaw-Security found no material risk indicators.",
    }[verdict]


# ---------------------------------------------------------------------------
# Public data contracts
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class GuardSecurityRequest:
    action_type: str
    target: str
    content: str = ""
    client_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class GuardSecurityDecision:
    mode: GuardMode
    verdict: GuardSecurityVerdict
    risk_score: int
    summary: str
    reasoning: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    model_name: str = "prompt-guard-86m-local"
    decided_at: str = field(default_factory=_utc_now)
    request: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "reasoning": list(self.reasoning),
            "signals": list(self.signals),
            "model_name": self.model_name,
            "decided_at": self.decided_at,
            "request": dict(self.request),
            "metadata": dict(self.metadata),
            "confidence": self.confidence,
            "latency_ms": self.latency_ms,
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_guard_security_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> GuardSecurityRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return GuardSecurityRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        client_id=_normalize_text(client_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------


def evaluate_guard_security_request(
    request: GuardSecurityRequest,
    *,
    mode: GuardMode = "assist",
    extra_metadata: dict[str, Any] | None = None,
) -> GuardSecurityDecision:
    """
    Evaluation pipeline:

    1. Mode disabled gate — short-circuit to allow only when mode == "disabled".
    2. Keyword fast-path — always runs regardless of GUARD_ENABLED.
       If risk >= _BLOCK_MIN, skip local inference (already definitive).
    3. Local prompt-guard inference — only when enabled and risk is ambiguous.
    4. Action-type and target penalties applied.
    5. Final verdict derived from composite risk score.
    """
    t_start = time.perf_counter()
    settings = get_settings()
    model_name = Path(settings.guard_model_path).name or "prompt-guard-86m-local"

    # --- gate: mode disabled only (GUARD_ENABLED does not block keyword scan) ---
    if mode == "disabled":
        return GuardSecurityDecision(
            mode=mode,
            verdict="allow",
            risk_score=0,
            summary="IronClaw-Security local prompt guard is disabled.",
            reasoning=["Security evaluation was skipped because mode is disabled."],
            signals=[],
            model_name=model_name,
            request=request.to_dict(),
            metadata=dict(extra_metadata or {}),
            confidence=1.0,
            latency_ms=0.0,
        )

    # --- phase 1: keyword fast-path (always runs) --------------------------
    combined_content = f"{request.action_type} {request.target} {request.content}"
    kw_risk, kw_signals, kw_reasoning = _keyword_scan(combined_content)

    at_penalty, at_signals, at_reasoning = _action_type_penalty(request.action_type)
    tgt_penalty, tgt_signals, tgt_reasoning = _target_penalty(request.target)

    risk_score = min(kw_risk + at_penalty + tgt_penalty, 100)
    signals: list[str] = list(dict.fromkeys(kw_signals + at_signals + tgt_signals))
    reasoning: list[str] = kw_reasoning + at_reasoning + tgt_reasoning

    guard_used = False
    guard_score: float | None = None
    if settings.guard_enabled and request.content.strip() and risk_score < _BLOCK_MIN:
        guard_result = classify_prompt_guard(
            request.content,
            model_path=settings.guard_model_path,
            threshold=settings.guard_threshold,
        )
        guard_used = True
        guard_score = guard_result.malicious_score
        model_name = guard_result.model_name
        if guard_result.is_malicious:
            risk_score = max(risk_score, _BLOCK_MIN)
            signals.append(SIG_PROMPT_GUARD)
            reasoning.append("The local prompt guard classified the request as malicious.")

    confidence = 0.85 if guard_used else 0.60

    # --- strict mode: never downgrade below quarantine when signals exist --
    if mode == "strict" and risk_score < _QUARANTINE_MIN and signals:
        risk_score = max(risk_score, _QUARANTINE_MIN)
        reasoning.append("Strict mode: any detected signal forces minimum quarantine threshold.")

    risk_score = min(risk_score, 100)
    verdict = _verdict_from_score(risk_score)
    summary = _summary_from_verdict(verdict)

    if kw_risk >= _BLOCK_MIN and not guard_used:
        signals.append(SIG_KEYWORD_FASTPATH)

    latency_ms = (time.perf_counter() - t_start) * 1000.0

    metadata = dict(extra_metadata or {})
    metadata["guard_enabled"] = settings.guard_enabled
    metadata["guard_used"] = guard_used
    if guard_score is not None:
        metadata["guard_score"] = guard_score
    metadata["keyword_risk"] = kw_risk

    logger.info(
        "guard_security_brain: verdict=%s risk=%d signals=%s guard=%s latency_ms=%.1f",
        verdict,
        risk_score,
        signals,
        guard_used,
        latency_ms,
    )

    return GuardSecurityDecision(
        mode=mode,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
        reasoning=reasoning,
        signals=list(dict.fromkeys(signals)),
        model_name=model_name,
        request=request.to_dict(),
        metadata=metadata,
        confidence=confidence,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# Summarizer
# ---------------------------------------------------------------------------


def summarize_guard_security_decision(
    decision: GuardSecurityDecision,
) -> dict[str, Any]:
    return {
        "mode": decision.mode,
        "verdict": decision.verdict,
        "risk_score": decision.risk_score,
        "signal_count": len(decision.signals),
        "reason_count": len(decision.reasoning),
        "model_name": decision.model_name,
        "decided_at": decision.decided_at,
        "confidence": decision.confidence,
        "latency_ms": decision.latency_ms,
    }
