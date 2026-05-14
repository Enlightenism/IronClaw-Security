from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import PurePath
from typing import Any

from app.runtime.sandbox_router import SandboxLane, route_to_sandbox

HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".scr",
    ".jar",
    ".vbs",
    ".js",
    ".hta",
    ".com",
    ".reg",
    ".apk",
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".tgz",
    ".xz",
    ".iso",
    ".img",
    ".docm",
    ".xlsm",
    ".pptm",
    ".html",
    ".svg",
    ".pdf",
}

HIGH_RISK_KEYWORDS = {
    "macro",
    "payload",
    "dropper",
    "persistence",
    "autorun",
    "credential",
    "token",
    "keylogger",
    "obfuscated",
    "powershell",
    "javascript",
    "executable",
}

MEDIUM_RISK_KEYWORDS = {
    "archive",
    "embedded",
    "downloaded",
    "script",
    "external link",
    "remote content",
    "attachment",
}


@dataclass(slots=True)
class FileReturnGuardDecision:
    allowed: bool
    response_status: str
    policy_verdict: str
    sandbox_lane: str
    risk_score: int
    should_release: bool
    halted_by_boundary: bool
    requires_review: bool
    file_name: str
    file_path: str
    file_extension: str
    reason: str
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_value(payload: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _detect_extension(file_path: str, file_name: str) -> str:
    candidate = file_path or file_name
    if not candidate:
        return ""
    return PurePath(candidate).suffix.lower()


def _collect_signal_text(payload: Mapping[str, Any], file_name: str, file_path: str) -> str:
    parts = [file_name, file_path]

    for key in (
        "summary",
        "reason",
        "quarantine_reason",
        "content_type",
        "description",
        "source",
        "origin",
        "scan_summary",
    ):
        value = payload.get(key)
        if value is not None:
            parts.append(str(value))

    for key in ("tags", "alerts", "matched_patterns", "failed_checks", "reasons"):
        value = payload.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value if item is not None)
        elif value is not None:
            parts.append(str(value))

    return " | ".join(parts).lower()


def _score_extension(file_extension: str) -> tuple[int, list[str]]:
    if file_extension in HIGH_RISK_EXTENSIONS:
        return 70, [f"high-risk file extension detected: {file_extension}"]
    if file_extension in MEDIUM_RISK_EXTENSIONS:
        return 25, [f"reviewable file extension detected: {file_extension}"]
    return 0, []


def _score_keywords(signal_text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in signal_text:
            score += 25
            reasons.append(f"high-risk file keyword detected: {keyword}")

    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in signal_text:
            score += 10
            reasons.append(f"review keyword detected: {keyword}")

    return score, reasons


def evaluate_file_return(payload: Mapping[str, Any]) -> FileReturnGuardDecision:
    file_name = str(_get_value(payload, "file_name", "name") or "")
    file_path = str(_get_value(payload, "file_path", "filepath", "path") or "")
    file_extension = _detect_extension(file_path, file_name)
    base_risk = _safe_int(_get_value(payload, "risk_score", "score"), 0)

    signal_text = _collect_signal_text(payload, file_name, file_path)
    extension_score, extension_reasons = _score_extension(file_extension)
    keyword_score, keyword_reasons = _score_keywords(signal_text)

    total_risk = min(100, base_risk + extension_score + keyword_score)
    reasons = [*extension_reasons, *keyword_reasons]

    route_payload = {
        "target": file_path or file_name,
        "content": signal_text,
        "risk_score": total_risk,
        "reasons": reasons,
        "policy_verdict": payload.get("policy_verdict") or payload.get("verdict"),
        "summary": payload.get("summary"),
        "quarantine_reason": payload.get("quarantine_reason"),
        "reason": payload.get("reason"),
    }
    route_decision = route_to_sandbox(route_payload)

    if route_decision.lane == SandboxLane.HARD_BLOCK:
        response_status = "denied"
        policy_verdict = "deny"
        allowed = False
        halted_by_boundary = True
        should_release = False
    elif route_decision.requires_review:
        response_status = "queued_for_review"
        policy_verdict = "quarantine" if route_decision.lane == SandboxLane.FILE_QUARANTINE else "warn"
        allowed = False
        halted_by_boundary = True
        should_release = False
    else:
        response_status = "completed"
        policy_verdict = "allow"
        allowed = True
        halted_by_boundary = False
        should_release = True

    if not reasons:
        reasons.append("file return accepted under current low-risk policy")

    return FileReturnGuardDecision(
        allowed=allowed,
        response_status=response_status,
        policy_verdict=policy_verdict,
        sandbox_lane=route_decision.lane.value,
        risk_score=total_risk,
        should_release=should_release,
        halted_by_boundary=halted_by_boundary,
        requires_review=route_decision.requires_review,
        file_name=file_name,
        file_path=file_path,
        file_extension=file_extension,
        reason=reasons[0],
        reasons=reasons,
        metadata={"source": "file_return_guard"},
    )


def summarize_file_return_guard(payload: Mapping[str, Any]) -> dict[str, Any]:
    return evaluate_file_return(payload).to_dict()


__all__ = [
    "HIGH_RISK_EXTENSIONS",
    "HIGH_RISK_KEYWORDS",
    "MEDIUM_RISK_EXTENSIONS",
    "MEDIUM_RISK_KEYWORDS",
    "FileReturnGuardDecision",
    "evaluate_file_return",
    "summarize_file_return_guard",
]
