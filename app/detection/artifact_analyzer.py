from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import PurePath
from typing import Any

HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".jar",
    ".apk",
    ".scr",
    ".msi",
    ".com",
    ".reg",
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".tgz",
    ".docm",
    ".xlsm",
    ".pptm",
    ".html",
    ".svg",
    ".js",
    ".pdf",
}

HIGH_RISK_PATTERNS = {
    "obfuscated": 25,
    "payload": 25,
    "macro": 25,
    "persistence": 20,
    "autorun": 20,
    "credential": 20,
    "token": 15,
    "password": 15,
    "keylogger": 30,
    "powershell": 20,
    "registry": 20,
    "download and execute": 30,
}

MEDIUM_RISK_PATTERNS = {
    "download": 10,
    "archive": 10,
    "embedded": 10,
    "external link": 10,
    "javascript": 10,
    "script": 10,
    "remote content": 10,
}


@dataclass(slots=True)
class ArtifactAnalysis:
    detected: bool
    risk_score: int
    verdict: str
    confidence: str
    artifact_name: str
    artifact_path: str
    artifact_extension: str
    reason: str
    matched_patterns: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
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


def _extract_extension(path_value: str, name_value: str) -> str:
    candidate = path_value or name_value
    if not candidate:
        return ""
    return PurePath(candidate).suffix.lower()


def _collect_signal_text(payload: Mapping[str, Any], artifact_name: str, artifact_path: str) -> str:
    parts = [artifact_name, artifact_path]

    for key in (
        "summary",
        "reason",
        "description",
        "content_type",
        "source",
        "origin",
        "scan_summary",
    ):
        value = payload.get(key)
        if value is not None:
            parts.append(str(value))

    for key in ("matched_patterns", "failed_checks", "alerts", "tags", "reasons"):
        value = payload.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value if item is not None)
        elif value is not None:
            parts.append(str(value))

    return " | ".join(parts).lower()


def _score_extension(extension: str) -> tuple[int, list[str]]:
    if extension in HIGH_RISK_EXTENSIONS:
        return 45, [f"high-risk artifact extension detected: {extension}"]
    if extension in MEDIUM_RISK_EXTENSIONS:
        return 20, [f"reviewable artifact extension detected: {extension}"]
    return 0, []


def _score_patterns(signal_text: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []

    for pattern, weight in HIGH_RISK_PATTERNS.items():
        if pattern in signal_text:
            score += weight
            matched.append(pattern)

    for pattern, weight in MEDIUM_RISK_PATTERNS.items():
        if pattern in signal_text:
            score += weight
            matched.append(pattern)

    return min(100, score), matched


def _derive_verdict(score: int) -> tuple[str, str]:
    if score >= 70:
        return "quarantine", "high"
    if score >= 35:
        return "warn", "medium"
    return "allow", "low"


def analyze_artifact(payload: Mapping[str, Any]) -> ArtifactAnalysis:
    artifact_name = str(_get_value(payload, "artifact_name", "file_name", "name") or "")
    artifact_path = str(_get_value(payload, "artifact_path", "file_path", "filepath", "path") or "")
    artifact_extension = _extract_extension(artifact_path, artifact_name)
    base_risk = _safe_int(_get_value(payload, "risk_score", "score"), 0)

    signal_text = _collect_signal_text(payload, artifact_name, artifact_path)
    extension_score, extension_reasons = _score_extension(artifact_extension)
    pattern_score, matched_patterns = _score_patterns(signal_text)

    total_risk = min(100, base_risk + extension_score + pattern_score)
    verdict, confidence = _derive_verdict(total_risk)

    failed_checks = list(extension_reasons)
    if matched_patterns:
        failed_checks.append("artifact content indicators triggered review")

    if any(pattern in {"macro", "payload", "download and execute"} for pattern in matched_patterns):
        failed_checks.append("artifact shows active execution behavior")

    if any(pattern in {"credential", "token", "password", "keylogger"} for pattern in matched_patterns):
        failed_checks.append("artifact shows credential-risk indicators")

    reason = extension_reasons[0] if extension_reasons else matched_patterns[0] if matched_patterns else "no artifact threats detected"

    return ArtifactAnalysis(
        detected=total_risk >= 35,
        risk_score=total_risk,
        verdict=verdict,
        confidence=confidence,
        artifact_name=artifact_name,
        artifact_path=artifact_path,
        artifact_extension=artifact_extension,
        reason=reason,
        matched_patterns=matched_patterns,
        failed_checks=failed_checks,
        metadata={"source": "artifact_analyzer"},
    )


def summarize_artifact_analysis(payload: Mapping[str, Any]) -> dict[str, Any]:
    return analyze_artifact(payload).to_dict()


__all__ = [
    "HIGH_RISK_EXTENSIONS",
    "HIGH_RISK_PATTERNS",
    "MEDIUM_RISK_EXTENSIONS",
    "MEDIUM_RISK_PATTERNS",
    "ArtifactAnalysis",
    "analyze_artifact",
    "summarize_artifact_analysis",
]
