from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


ThreatSeverity = Literal["low", "medium", "high", "critical"]
ThreatType = Literal[
    "domain",
    "ip",
    "url",
    "hash",
    "prompt_pattern",
    "tool_pattern",
]
ThreatSourceKind = Literal["manual", "feed", "import"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


@dataclass(slots=True)
class ThreatIndicator:
    indicator_id: str
    indicator_type: ThreatType
    value: str
    severity: ThreatSeverity
    source: ThreatSourceKind = "manual"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    confidence: int = 50
    first_seen_at: str = field(default_factory=_utc_now)
    last_seen_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "value": self.value,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "tags": list(self.tags),
            "confidence": self.confidence,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ThreatIntelFeed:
    feed_id: str
    name: str
    source: ThreatSourceKind = "feed"
    indicators: list[ThreatIndicator] = field(default_factory=list)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "name": self.name,
            "source": self.source,
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ThreatIntelMatch:
    indicator_id: str
    indicator_type: ThreatType
    value: str
    severity: ThreatSeverity
    matched_on: str
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "value": self.value,
            "severity": self.severity,
            "matched_on": self.matched_on,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ThreatIntelScanResult:
    scanned_text: str
    checked_at: str
    matches: list[ThreatIntelMatch] = field(default_factory=list)
    highest_severity: ThreatSeverity = "low"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_text": self.scanned_text,
            "checked_at": self.checked_at,
            "matches": [match.to_dict() for match in self.matches],
            "highest_severity": self.highest_severity,
            "metadata": dict(self.metadata),
        }


_SEVERITY_ORDER: dict[ThreatSeverity, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def build_threat_indicator(
    *,
    indicator_id: str,
    indicator_type: ThreatType,
    value: str,
    severity: ThreatSeverity,
    source: ThreatSourceKind = "manual",
    description: str = "",
    tags: list[str] | None = None,
    confidence: int = 50,
    metadata: dict[str, Any] | None = None,
) -> ThreatIndicator:
    normalized_indicator_id = _normalize_text(indicator_id)
    normalized_value = _normalize_text(value)

    if not normalized_indicator_id:
        raise ValueError("indicator_id is required")
    if not normalized_value:
        raise ValueError("value is required")

    bounded_confidence = max(0, min(int(confidence), 100))
    now = _utc_now()

    return ThreatIndicator(
        indicator_id=normalized_indicator_id,
        indicator_type=indicator_type,
        value=normalized_value,
        severity=severity,
        source=source,
        description=_normalize_text(description),
        tags=[tag.strip() for tag in (tags or []) if tag and tag.strip()],
        confidence=bounded_confidence,
        first_seen_at=now,
        last_seen_at=now,
        metadata=dict(metadata or {}),
    )


def initialize_default_threat_feed() -> ThreatIntelFeed:
    indicators = [
        build_threat_indicator(
            indicator_id="ioc-evil-domain",
            indicator_type="domain",
            value="evil.example",
            severity="critical",
            source="feed",
            description="Known malicious exfiltration domain used in red-team fixtures.",
            tags=["exfiltration", "domain", "red-team"],
            confidence=95,
        ),
        build_threat_indicator(
            indicator_id="ioc-secret-export",
            indicator_type="prompt_pattern",
            value="export secret",
            severity="high",
            source="feed",
            description="Prompt pattern associated with secret exfiltration attempts.",
            tags=["prompt-injection", "secret-access"],
            confidence=88,
        ),
        build_threat_indicator(
            indicator_id="ioc-disable-guard",
            indicator_type="prompt_pattern",
            value="disable guard",
            severity="high",
            source="feed",
            description="Evasion language intended to bypass policy enforcement.",
            tags=["guard-bypass", "prompt-injection"],
            confidence=90,
        ),
        build_threat_indicator(
            indicator_id="ioc-powershell-enc",
            indicator_type="tool_pattern",
            value="powershell -enc",
            severity="critical",
            source="feed",
            description="Common encoded PowerShell execution pattern.",
            tags=["powershell", "encoded-command", "execution"],
            confidence=97,
        ),
    ]

    return ThreatIntelFeed(
        feed_id="feed-default-threat-intel",
        name="IronClaw Default Threat Intel Feed",
        source="feed",
        indicators=indicators,
        metadata={
            "provider": "ironclaw-local",
            "local_first": True,
        },
    )


def ingest_threat_indicators(
    feed: ThreatIntelFeed,
    indicators: list[ThreatIndicator],
) -> ThreatIntelFeed:
    existing = {indicator.indicator_id: indicator for indicator in feed.indicators}

    for indicator in indicators:
        existing[indicator.indicator_id] = indicator

    feed.indicators = sorted(
        existing.values(),
        key=lambda item: (_SEVERITY_ORDER[item.severity], item.indicator_type, item.value),
        reverse=True,
    )
    feed.updated_at = _utc_now()
    return feed


def scan_text_against_threat_feed(
    text: str,
    feed: ThreatIntelFeed,
) -> ThreatIntelScanResult:
    lowered = text.lower()
    matches: list[ThreatIntelMatch] = []
    highest_severity: ThreatSeverity = "low"

    for indicator in feed.indicators:
        candidate = indicator.value.lower()
        matched = False
        matched_on = indicator.value
        reason = ""

        if indicator.indicator_type == "domain":
            matched = candidate in lowered
            reason = "Detected known malicious domain indicator."
        elif indicator.indicator_type == "ip":
            matched = candidate in lowered
            reason = "Detected known malicious IP indicator."
        elif indicator.indicator_type == "url":
            matched = candidate in lowered
            reason = "Detected known malicious URL indicator."
        elif indicator.indicator_type == "hash":
            matched = candidate in lowered
            reason = "Detected known malicious hash indicator."
        elif indicator.indicator_type == "prompt_pattern":
            matched = candidate in lowered
            reason = "Detected prompt injection or exfiltration phrase."
        elif indicator.indicator_type == "tool_pattern":
            matched = candidate in lowered
            reason = "Detected high-risk tool or execution pattern."

        if not matched:
            continue

        matches.append(
            ThreatIntelMatch(
                indicator_id=indicator.indicator_id,
                indicator_type=indicator.indicator_type,
                value=indicator.value,
                severity=indicator.severity,
                matched_on=matched_on,
                reason=reason,
                metadata={
                    "source": indicator.source,
                    "confidence": indicator.confidence,
                    "tags": list(indicator.tags),
                },
            )
        )

        if _SEVERITY_ORDER[indicator.severity] > _SEVERITY_ORDER[highest_severity]:
            highest_severity = indicator.severity

    return ThreatIntelScanResult(
        scanned_text=text,
        checked_at=_utc_now(),
        matches=matches,
        highest_severity=highest_severity if matches else "low",
        metadata={
            "feed_id": feed.feed_id,
            "match_count": len(matches),
        },
    )


def summarize_threat_scan_result(result: ThreatIntelScanResult) -> dict[str, Any]:
    severity_counts: dict[str, int] = {}

    for match in result.matches:
        severity_counts[match.severity] = severity_counts.get(match.severity, 0) + 1

    return {
        "checked_at": result.checked_at,
        "match_count": len(result.matches),
        "highest_severity": result.highest_severity,
        "severity_counts": severity_counts,
    }