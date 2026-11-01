from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import math
from pathlib import Path
import re
import time
from typing import Any, Literal

from app.config import (
    GUARD_ENABLED,
    GUARD_MODEL_PATH,
    GUARD_THRESHOLD,
    RISK_THRESHOLD_ALLOW_MAX,
    RISK_THRESHOLD_BLOCK_MIN,
)
from app.services.prompt_guard import classify_prompt_guard

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

GuardSecurityVerdict = Literal["allow", "block"]
GuardMode = Literal["disabled", "assist", "enforce", "strict"]

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
SIG_PROMPT_GUARD_UNAVAILABLE = "prompt-guard-unavailable"
SIG_SCAN_UNAVAILABLE = "scan-unavailable"
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
    return "block" if risk_score > RISK_THRESHOLD_ALLOW_MAX else "allow"


def _summary_from_verdict(verdict: GuardSecurityVerdict) -> str:
    return {
        "block": "IronClaw-Security blocked the request.",
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

    1. Keyword, action-type, and target checks run in every mode.
    2. Local Prompt Guard runs whenever GUARD_ENABLED is true.
    3. Any signal or scan error blocks; only a clean result can allow.
    """
    t_start = time.perf_counter()
    model_name = Path(GUARD_MODEL_PATH).name or "prompt-guard-86m-local"

    scan_error = False
    try:
        combined_content = f"{request.action_type} {request.target} {request.content}"
        kw_risk, kw_signals, kw_reasoning = _keyword_scan(combined_content)
        at_penalty, at_signals, at_reasoning = _action_type_penalty(request.action_type)
        tgt_penalty, tgt_signals, tgt_reasoning = _target_penalty(request.target)
        risk_score = min(kw_risk + at_penalty + tgt_penalty, 100)
        signals: list[str] = list(dict.fromkeys(kw_signals + at_signals + tgt_signals))
        reasoning: list[str] = kw_reasoning + at_reasoning + tgt_reasoning
    except Exception:  # noqa: BLE001
        logger.exception("guard_security_brain: scan failed; blocking request")
        kw_risk = 0
        risk_score = 0
        signals = [SIG_SCAN_UNAVAILABLE]
        reasoning = ["Security scan unavailable (scan_unavailable); request blocked."]
        scan_error = True

    guard_used = False
    guard_score: float | None = None
    guard_error = False
    if GUARD_ENABLED:
        guard_used = True
        try:
            guard_result = classify_prompt_guard(
                request.content,
                model_path=GUARD_MODEL_PATH,
                threshold=GUARD_THRESHOLD,
            )
            raw_guard_score = guard_result.malicious_score
            if isinstance(raw_guard_score, bool) or not isinstance(raw_guard_score, int | float) or not math.isfinite(raw_guard_score) or not 0.0 <= raw_guard_score <= 1.0:
                raise ValueError("Prompt Guard returned an invalid malicious score.")
            if not isinstance(guard_result.label, str) or not guard_result.label:
                raise ValueError("Prompt Guard returned an invalid label.")
            if not isinstance(guard_result.model_name, str) or not guard_result.model_name:
                raise ValueError("Prompt Guard returned an invalid model name.")

            guard_score = float(raw_guard_score)
            model_name = guard_result.model_name
            if guard_score >= GUARD_THRESHOLD or guard_result.label != "BENIGN" or guard_result.is_malicious:
                risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)
                signals.append(SIG_PROMPT_GUARD)
                reasoning.append("The local prompt guard classified the request as malicious.")
        except Exception:  # noqa: BLE001
            logger.exception("guard_security_brain: Prompt Guard unavailable; blocking request")
            signals.append(SIG_PROMPT_GUARD_UNAVAILABLE)
            reasoning.append("Prompt Guard unavailable (prompt_guard_unavailable); request blocked.")
            guard_error = True

    confidence = 0.0 if guard_error else 0.85 if guard_used else 0.60
    risk_score = min(risk_score, 100)
    verdict = "block" if scan_error or guard_error or signals else _verdict_from_score(risk_score)
    if verdict == "block":
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)
    summary = _summary_from_verdict(verdict)

    if kw_risk >= RISK_THRESHOLD_BLOCK_MIN and not guard_used:
        signals.append(SIG_KEYWORD_FASTPATH)

    latency_ms = (time.perf_counter() - t_start) * 1000.0

    metadata = dict(extra_metadata or {})
    metadata["guard_enabled"] = GUARD_ENABLED
    metadata["guard_used"] = guard_used
    metadata["guard_error"] = guard_error
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
