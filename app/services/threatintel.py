from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

IOC_PATTERN = re.compile(
    r"(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)|" r"(?P<sha256>\b[a-fA-F0-9]{64}\b)|" r"(?P<sha1>\b[a-fA-F0-9]{40}\b)|" r"(?P<md5>\b[a-fA-F0-9]{32}\b)|" r"(?P<domain>\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b)|" r"(?P<url>https?://[^\s\"'<>]+)",
)

SUSPICIOUS_KEYWORDS = {
    "credential_harvest": {"login", "password", "verify account", "mfa reset", "session cookie"},
    "malware_delivery": {"payload", "dropper", "loader", "macro", "powershell -enc", "rundll32"},
    "command_and_control": {"beacon", "c2", "callback", "exfil", "reverse shell", "dns tunnel"},
    "evasion": {"obfuscation", "packer", "sandbox evade", "sleep mask", "disable defender"},
}

DEFAULT_SOURCE_WEIGHTS = {
    "internal": 1.0,
    "curated": 0.85,
    "community": 0.65,
    "external": 0.55,
}


@dataclass(slots=True)
class ThreatIndicator:
    value: str
    indicator_type: str
    confidence: float
    severity: str
    tags: list[str] = field(default_factory=list)
    source: str = "internal"
    first_seen: str | None = None
    last_seen: str | None = None
    reference: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ThreatMatch:
    value: str
    indicator_type: str
    confidence: float
    severity: str
    source: str
    tags: list[str]
    matched_on: str
    reference: str | None = None


@dataclass(slots=True)
class ThreatAssessment:
    verdict: str
    score: float
    severity: str
    risk_families: list[str]
    matches: list[ThreatMatch]
    extracted_indicators: list[str]
    rationale: list[str]
    assessed_at: str


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _normalize_indicator(value: str, indicator_type: str) -> str:
    normalized = _normalize_text(value)
    if indicator_type in {"sha256", "sha1", "md5", "domain"}:
        return normalized
    if indicator_type == "url":
        return normalized.rstrip("/")
    return normalized


def _indicator_fingerprint(value: str, indicator_type: str) -> str:
    normalized = _normalize_indicator(value, indicator_type)
    return hashlib.sha256(f"{indicator_type}:{normalized}".encode()).hexdigest()


def _infer_indicator_type(value: str) -> str:
    candidate = value.strip()
    lowered = candidate.lower()

    if lowered.startswith(("http://", "https://")):
        return "url"

    if re.fullmatch(r"[a-fA-F0-9]{64}", candidate):
        return "sha256"

    if re.fullmatch(r"[a-fA-F0-9]{40}", candidate):
        return "sha1"

    if re.fullmatch(r"[a-fA-F0-9]{32}", candidate):
        return "md5"

    try:
        ipaddress.ip_address(candidate)
        return "ipv4"
    except ValueError:
        pass

    return "domain"


def _parse_indicator(raw: dict[str, Any]) -> ThreatIndicator:
    value = str(raw.get("value", "")).strip()
    indicator_type = str(raw.get("indicator_type") or _infer_indicator_type(value)).strip().lower()
    confidence = float(raw.get("confidence", 0.5))
    severity = str(raw.get("severity", "medium")).strip().lower()
    tags = [str(tag).strip().lower() for tag in raw.get("tags", []) if str(tag).strip()]
    source = str(raw.get("source", "internal")).strip().lower()

    return ThreatIndicator(
        value=_normalize_indicator(value, indicator_type),
        indicator_type=indicator_type,
        confidence=max(0.0, min(confidence, 1.0)),
        severity=severity if severity in {"low", "medium", "high", "critical"} else "medium",
        tags=tags,
        source=source,
        first_seen=raw.get("first_seen"),
        last_seen=raw.get("last_seen"),
        reference=raw.get("reference"),
        attributes=dict(raw.get("attributes", {})),
    )


def _severity_weight(severity: str) -> float:
    return {
        "low": 0.25,
        "medium": 0.5,
        "high": 0.8,
        "critical": 1.0,
    }.get(severity, 0.5)


class ThreatIntelService:
    def __init__(self, seed_indicators: list[ThreatIndicator] | None = None) -> None:
        self._indicators: dict[str, ThreatIndicator] = {}
        self._updated_at = _utcnow()
        for indicator in seed_indicators or []:
            self.upsert_indicator(indicator)

    @property
    def updated_at(self) -> str:
        return self._updated_at

    def upsert_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        normalized = _normalize_indicator(indicator.value, indicator.indicator_type)
        normalized_indicator = ThreatIndicator(
            value=normalized,
            indicator_type=indicator.indicator_type,
            confidence=max(0.0, min(indicator.confidence, 1.0)),
            severity=indicator.severity if indicator.severity in {"low", "medium", "high", "critical"} else "medium",
            tags=sorted({tag.strip().lower() for tag in indicator.tags if tag.strip()}),
            source=indicator.source.strip().lower() or "internal",
            first_seen=indicator.first_seen,
            last_seen=indicator.last_seen or _utcnow(),
            reference=indicator.reference,
            attributes=dict(indicator.attributes),
        )
        self._indicators[_indicator_fingerprint(normalized, normalized_indicator.indicator_type)] = normalized_indicator
        self._updated_at = _utcnow()
        return normalized_indicator

    def load_from_json(self, payload: str | bytes) -> int:
        raw = json.loads(payload)
        if not isinstance(raw, list):
            raise ValueError("Threat intel payload must be a list of indicators.")
        count = 0
        for item in raw:
            self.upsert_indicator(_parse_indicator(dict(item)))
            count += 1
        return count

    def load_from_file(self, path: str | Path) -> int:
        content = Path(path).read_text(encoding="utf-8")
        return self.load_from_json(content)

    def export_json(self) -> str:
        indicators = [
            {
                "value": indicator.value,
                "indicator_type": indicator.indicator_type,
                "confidence": indicator.confidence,
                "severity": indicator.severity,
                "tags": indicator.tags,
                "source": indicator.source,
                "first_seen": indicator.first_seen,
                "last_seen": indicator.last_seen,
                "reference": indicator.reference,
                "attributes": indicator.attributes,
            }
            for indicator in self._indicators.values()
        ]
        return json.dumps(indicators, indent=2, ensure_ascii=False)

    def indicator_count(self) -> int:
        return len(self._indicators)

    def has_indicator(self, value: str, indicator_type: str | None = None) -> bool:
        resolved_type = indicator_type or _infer_indicator_type(value)
        fingerprint = _indicator_fingerprint(value, resolved_type)
        return fingerprint in self._indicators

    def lookup_indicator(self, value: str, indicator_type: str | None = None) -> ThreatIndicator | None:
        resolved_type = indicator_type or _infer_indicator_type(value)
        fingerprint = _indicator_fingerprint(value, resolved_type)
        return self._indicators.get(fingerprint)

    def extract_indicators(self, text: str) -> list[tuple[str, str]]:
        extracted: list[tuple[str, str]] = []
        seen: set[str] = set()

        for match in IOC_PATTERN.finditer(text):
            group_name = next((name for name, value in match.groupdict().items() if value), None)
            if group_name is None:
                continue

            raw_value = match.group(group_name)
            indicator_type = "url" if group_name == "url" else group_name
            normalized_value = _normalize_indicator(raw_value, indicator_type)

            if indicator_type == "ipv4":
                try:
                    ipaddress.ip_address(normalized_value)
                except ValueError:
                    continue

            key = f"{indicator_type}:{normalized_value}"
            if key in seen:
                continue

            seen.add(key)
            extracted.append((normalized_value, indicator_type))

        return extracted

    def assess_text(
        self,
        text: str,
        *,
        context: str | None = None,
        minimum_confidence: float = 0.0,
    ) -> ThreatAssessment:
        normalized_text = _normalize_text(text)
        extracted = self.extract_indicators(text)
        matches: list[ThreatMatch] = []
        risk_families: set[str] = set()
        rationale: list[str] = []

        for value, indicator_type in extracted:
            indicator = self.lookup_indicator(value, indicator_type)
            if indicator is None or indicator.confidence < minimum_confidence:
                continue

            matches.append(
                ThreatMatch(
                    value=indicator.value,
                    indicator_type=indicator.indicator_type,
                    confidence=indicator.confidence,
                    severity=indicator.severity,
                    source=indicator.source,
                    tags=list(indicator.tags),
                    matched_on=context or "text",
                    reference=indicator.reference,
                ),
            )
            risk_families.update(indicator.tags)

        keyword_hits: dict[str, int] = {}
        for family, keywords in SUSPICIOUS_KEYWORDS.items():
            hits = sum(1 for keyword in keywords if keyword in normalized_text)
            if hits:
                keyword_hits[family] = hits
                risk_families.add(family)

        if matches:
            rationale.append(f"Matched {len(matches)} known threat indicator(s).")

        for family, hits in sorted(keyword_hits.items()):
            rationale.append(f"Detected {hits} suspicious keyword pattern(s) for {family}.")

        source_score = 0.0
        for match in matches:
            source_weight = DEFAULT_SOURCE_WEIGHTS.get(match.source, 0.5)
            source_score += match.confidence * _severity_weight(match.severity) * source_weight

        keyword_score = sum(min(count * 0.12, 0.3) for count in keyword_hits.values())
        score = min(source_score + keyword_score, 1.0)

        if score >= 0.85:
            verdict = "block"
            severity = "critical"
        elif score >= 0.6:
            verdict = "review"
            severity = "high"
        elif score >= 0.3:
            verdict = "monitor"
            severity = "medium"
        else:
            verdict = "allow"
            severity = "low"

        if not rationale:
            rationale.append("No known threat indicators or suspicious keyword clusters were detected.")

        return ThreatAssessment(
            verdict=verdict,
            score=round(score, 4),
            severity=severity,
            risk_families=sorted(risk_families),
            matches=matches,
            extracted_indicators=[value for value, _ in extracted],
            rationale=rationale,
            assessed_at=_utcnow(),
        )

    def assess_artifact(
        self,
        *,
        url: str | None = None,
        domain: str | None = None,
        hashes: list[str] | None = None,
        text: str | None = None,
        context: str | None = None,
    ) -> ThreatAssessment:
        fragments: list[str] = []

        if url:
            fragments.append(url)
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    fragments.append(parsed.hostname)
            except Exception:
                pass

        if domain:
            fragments.append(domain)

        if hashes:
            fragments.extend(hashes)

        if text:
            fragments.append(text)

        combined = "\n".join(fragment for fragment in fragments if fragment)
        return self.assess_text(combined, context=context or "artifact")


def build_default_threatintel_service() -> ThreatIntelService:
    seed = [
        ThreatIndicator(
            value="198.51.100.42",
            indicator_type="ipv4",
            confidence=0.94,
            severity="high",
            tags=["command_and_control", "known_bad_ip"],
            source="internal",
            reference="ironclaw://intel/default/198.51.100.42",
        ),
        ThreatIndicator(
            value="malicious-control.example",
            indicator_type="domain",
            confidence=0.92,
            severity="critical",
            tags=["command_and_control", "phishing_infrastructure"],
            source="curated",
            reference="ironclaw://intel/default/malicious-control.example",
        ),
        ThreatIndicator(
            value="44d88612fea8a8f36de82e1278abb02f",
            indicator_type="md5",
            confidence=0.88,
            severity="high",
            tags=["malware_delivery", "known_sample"],
            source="community",
            reference="ironclaw://intel/default/44d88612fea8a8f36de82e1278abb02f",
        ),
    ]
    return ThreatIntelService(seed_indicators=seed)


__all__ = [
    "DEFAULT_SOURCE_WEIGHTS",
    "IOC_PATTERN",
    "SUSPICIOUS_KEYWORDS",
    "ThreatAssessment",
    "ThreatIndicator",
    "ThreatIntelService",
    "ThreatMatch",
    "build_default_threatintel_service",
]
