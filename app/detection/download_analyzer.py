from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import PurePath
from typing import Any
from urllib.parse import urlparse

HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".scr",
    ".jar",
    ".apk",
    ".reg",
    ".vbs",
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
    ".js",
}

HIGH_RISK_KEYWORDS = {
    "dropper": 30,
    "payload": 30,
    "macro": 25,
    "autorun": 20,
    "obfuscated": 25,
    "executable": 20,
    "credential": 20,
    "token": 15,
    "password": 15,
    "download and execute": 35,
    "remote script": 25,
}

MEDIUM_RISK_KEYWORDS = {
    "archive": 10,
    "embedded": 10,
    "attachment": 10,
    "redirect": 10,
    "external": 10,
    "script": 10,
    "installer": 10,
}

HIGH_RISK_HOST_PATTERNS = {
    "raw.githubusercontent.com": 10,
    "pastebin": 25,
    "bit.ly": 25,
    "tinyurl": 25,
    "anonfiles": 25,
    "mediafire": 20,
    "mega.nz": 20,
}


@dataclass(slots=True)
class DownloadAnalysis:
    detected: bool
    risk_score: int
    verdict: str
    confidence: str
    url: str
    hostname: str
    file_name: str
    file_extension: str
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


def _extract_url(payload: Mapping[str, Any]) -> str:
    return str(_get_value(payload, "url", "target", "target_value", "download_url") or "")


def _extract_file_name(payload: Mapping[str, Any], url: str) -> str:
    explicit = str(_get_value(payload, "file_name", "name") or "")
    if explicit:
        return explicit

    parsed = urlparse(url if "://" in url else f"https://{url}" if url else "")
    return PurePath(parsed.path).name


def _extract_extension(file_name: str) -> str:
    if not file_name:
        return ""
    return PurePath(file_name).suffix.lower()


def _collect_signal_text(payload: Mapping[str, Any], url: str, file_name: str) -> str:
    parts = [url, file_name]

    for key in (
        "summary",
        "reason",
        "description",
        "target_type",
        "content_type",
        "source",
        "origin",
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
        return 45, [f"high-risk download extension detected: {extension}"]
    if extension in MEDIUM_RISK_EXTENSIONS:
        return 20, [f"reviewable download extension detected: {extension}"]
    return 0, []


def _score_keywords(signal_text: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []

    for keyword, weight in HIGH_RISK_KEYWORDS.items():
        if keyword in signal_text:
            score += weight
            matched.append(keyword)

    for keyword, weight in MEDIUM_RISK_KEYWORDS.items():
        if keyword in signal_text:
            score += weight
            matched.append(keyword)

    return min(100, score), matched


def _score_host(hostname: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    for host_pattern, weight in HIGH_RISK_HOST_PATTERNS.items():
        if host_pattern in hostname:
            score += weight
            reasons.append(f"reviewable download host detected: {host_pattern}")

    return score, reasons


def _derive_verdict(score: int) -> tuple[str, str]:
    if score >= 70:
        return "quarantine", "high"
    if score >= 35:
        return "warn", "medium"
    return "allow", "low"


def analyze_download(payload: Mapping[str, Any]) -> DownloadAnalysis:
    url = _extract_url(payload)
    parsed = urlparse(url if "://" in url else f"https://{url}" if url else "")
    hostname = (parsed.hostname or "").lower()
    file_name = _extract_file_name(payload, url)
    file_extension = _extract_extension(file_name)
    base_risk = _safe_int(_get_value(payload, "risk_score", "score"), 0)

    signal_text = _collect_signal_text(payload, url, file_name)
    extension_score, extension_reasons = _score_extension(file_extension)
    keyword_score, matched_patterns = _score_keywords(signal_text)
    host_score, host_reasons = _score_host(hostname)

    total_risk = min(100, base_risk + extension_score + keyword_score + host_score)
    verdict, confidence = _derive_verdict(total_risk)

    failed_checks = [*extension_reasons, *host_reasons]
    if matched_patterns:
        failed_checks.append("download content indicators triggered review")

    if any(pattern in {"dropper", "payload", "download and execute", "remote script"} for pattern in matched_patterns):
        failed_checks.append("download shows executable delivery behavior")

    if any(pattern in {"credential", "token", "password"} for pattern in matched_patterns):
        failed_checks.append("download shows secret-risk indicators")

    reason = extension_reasons[0] if extension_reasons else host_reasons[0] if host_reasons else matched_patterns[0] if matched_patterns else "no download threats detected"

    return DownloadAnalysis(
        detected=total_risk >= 35,
        risk_score=total_risk,
        verdict=verdict,
        confidence=confidence,
        url=url,
        hostname=hostname,
        file_name=file_name,
        file_extension=file_extension,
        reason=reason,
        matched_patterns=matched_patterns,
        failed_checks=failed_checks,
        metadata={"source": "download_analyzer"},
    )


def summarize_download_analysis(payload: Mapping[str, Any]) -> dict[str, Any]:
    return analyze_download(payload).to_dict()


__all__ = [
    "HIGH_RISK_EXTENSIONS",
    "HIGH_RISK_HOST_PATTERNS",
    "HIGH_RISK_KEYWORDS",
    "MEDIUM_RISK_EXTENSIONS",
    "MEDIUM_RISK_KEYWORDS",
    "DownloadAnalysis",
    "analyze_download",
    "summarize_download_analysis",
]
