from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.services.detonationservice import DetonationService, build_detonation_service
from app.services.malwareservice import MalwareService, build_malware_service
from app.services.threatintel import ThreatIntelService, build_default_threatintel_service

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

VERDICT_RANK = {
    "allow": 1,
    "monitor": 2,
    "review": 3,
    "block": 4,
}


@dataclass(slots=True)
class ArtifactAnalysisComponent:
    name: str
    verdict: str
    severity: str
    score: float
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ArtifactAnalysisResult:
    artifact_id: str
    file_name: str | None
    sha256: str
    verdict: str
    severity: str
    score: float
    confidence: float
    reasons: list[str]
    indicators: list[str]
    components: list[ArtifactAnalysisComponent]
    assessed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "indicators": list(self.indicators),
            "components": [
                {
                    "name": component.name,
                    "verdict": component.verdict,
                    "severity": component.severity,
                    "score": component.score,
                    "confidence": component.confidence,
                    "details": component.details,
                }
                for component in self.components
            ],
            "assessed_at": self.assessed_at,
        }


class ArtifactAnalyzer:
    def __init__(
        self,
        *,
        threatintel_service: ThreatIntelService | None = None,
        malware_service: MalwareService | None = None,
        detonation_service: DetonationService | None = None,
    ) -> None:
        self._threatintel = threatintel_service or build_default_threatintel_service()
        self._malware = malware_service or build_malware_service()
        self._detonation = detonation_service or build_detonation_service()

    def analyze_bytes(
        self,
        payload: bytes,
        *,
        file_name: str | None = None,
        source_url: str | None = None,
        context: str | None = None,
        sandbox_profile: str = "windows-office-user",
    ) -> ArtifactAnalysisResult:
        decoded_text = payload.decode("utf-8", errors="ignore")
        sha256 = hashlib.sha256(payload).hexdigest()
        artifact_id = self._build_artifact_id(sha256, file_name=file_name)

        threat_assessment = self._threatintel.assess_artifact(
            url=source_url,
            hashes=[sha256],
            text=decoded_text if decoded_text else None,
            context=context or "artifact-analysis",
        )
        malware_assessment = self._malware.analyze_bytes(payload, file_name=file_name)
        detonation_assessment = self._detonation.detonate_bytes(
            payload,
            file_name=file_name,
            sandbox_profile=sandbox_profile,
        )

        components = self._build_components(
            threat_assessment=threat_assessment,
            malware_assessment=malware_assessment,
            detonation_assessment=detonation_assessment,
        )
        score = self._resolve_score(components)
        verdict = self._resolve_verdict(components, score)
        severity = self._resolve_severity(components, score)
        confidence = self._resolve_confidence(components)
        indicators = self._collect_indicators(
            sha256=sha256,
            source_url=source_url,
            threat_assessment=threat_assessment,
            malware_assessment=malware_assessment,
        )
        reasons = self._build_reasons(
            components=components,
            threat_assessment=threat_assessment,
            malware_assessment=malware_assessment,
            detonation_assessment=detonation_assessment,
            source_url=source_url,
        )

        return ArtifactAnalysisResult(
            artifact_id=artifact_id,
            file_name=file_name,
            sha256=sha256,
            verdict=verdict,
            severity=severity,
            score=score,
            confidence=confidence,
            reasons=reasons,
            indicators=indicators,
            components=components,
        )

    def analyze_text(
        self,
        text: str,
        *,
        file_name: str | None = None,
        source_url: str | None = None,
        context: str | None = None,
        sandbox_profile: str = "windows-office-user",
    ) -> ArtifactAnalysisResult:
        return self.analyze_bytes(
            text.encode("utf-8", errors="ignore"),
            file_name=file_name,
            source_url=source_url,
            context=context,
            sandbox_profile=sandbox_profile,
        )

    def _build_artifact_id(self, sha256: str, *, file_name: str | None) -> str:
        suffix = (file_name or "artifact").replace(" ", "-").lower()
        return f"artifact-{suffix}-{sha256[:12]}"

    def _build_components(
        self,
        *,
        threat_assessment: Any,
        malware_assessment: Any,
        detonation_assessment: Any,
    ) -> list[ArtifactAnalysisComponent]:
        threat_details = {
            "match_count": len(getattr(threat_assessment, "matches", [])),
            "risk_families": list(getattr(threat_assessment, "risk_families", [])),
            "extracted_indicators": list(getattr(threat_assessment, "extracted_indicators", [])),
        }
        malware_details = {
            "detected_family": getattr(malware_assessment, "detected_family", None),
            "signal_count": len(getattr(malware_assessment, "signals", [])),
            "is_probably_binary": bool(getattr(malware_assessment, "is_probably_binary", False)),
        }
        detonation_details = {
            "behavior_tags": list(getattr(detonation_assessment, "behavior_tags", [])),
            "artifact_count": len(getattr(detonation_assessment, "artifacts", [])),
            "execution_time_ms": int(getattr(detonation_assessment, "execution_time_ms", 0)),
        }

        return [
            ArtifactAnalysisComponent(
                name="threatintel",
                verdict=str(getattr(threat_assessment, "verdict", "allow")),
                severity=str(getattr(threat_assessment, "severity", "low")),
                score=round(float(getattr(threat_assessment, "score", 0.0)), 4),
                confidence=round(min(max(float(getattr(threat_assessment, "score", 0.0)) + 0.2, 0.0), 1.0), 4),
                details=threat_details,
            ),
            ArtifactAnalysisComponent(
                name="malware",
                verdict=str(getattr(malware_assessment, "verdict", "allow")),
                severity=str(getattr(malware_assessment, "severity", "low")),
                score=round(float(getattr(malware_assessment, "score", 0.0)), 4),
                confidence=round(float(getattr(malware_assessment, "confidence", 0.0)), 4),
                details=malware_details,
            ),
            ArtifactAnalysisComponent(
                name="detonation",
                verdict=str(getattr(detonation_assessment, "verdict", "allow")),
                severity=str(getattr(detonation_assessment, "severity", "low")),
                score=round(float(getattr(detonation_assessment, "score", 0.0)), 4),
                confidence=round(float(getattr(detonation_assessment, "confidence", 0.0)), 4),
                details=detonation_details,
            ),
        ]

    def _resolve_score(self, components: list[ArtifactAnalysisComponent]) -> float:
        weights = {
            "threatintel": 0.30,
            "malware": 0.35,
            "detonation": 0.35,
        }
        weighted = 0.0
        for component in components:
            weighted += component.score * weights.get(component.name, 0.0)

        max_component = max((component.score for component in components), default=0.0)
        if max_component >= 0.85:
            weighted = max(weighted, max_component * 0.92)

        return round(min(weighted, 1.0), 4)

    def _resolve_verdict(self, components: list[ArtifactAnalysisComponent], score: float) -> str:
        strongest = max((VERDICT_RANK.get(component.verdict, 1) for component in components), default=1)

        if strongest >= VERDICT_RANK["block"]:
            return "block"
        if score >= 0.70 or strongest >= VERDICT_RANK["review"]:
            return "review"
        if score >= 0.32 or strongest >= VERDICT_RANK["monitor"]:
            return "monitor"
        return "allow"

    def _resolve_severity(self, components: list[ArtifactAnalysisComponent], score: float) -> str:
        strongest = max((SEVERITY_RANK.get(component.severity, 1) for component in components), default=1)

        if strongest >= SEVERITY_RANK["critical"] or score >= 0.85:
            return "critical"
        if strongest >= SEVERITY_RANK["high"] or score >= 0.60:
            return "high"
        if strongest >= SEVERITY_RANK["medium"] or score >= 0.28:
            return "medium"
        return "low"

    def _resolve_confidence(self, components: list[ArtifactAnalysisComponent]) -> float:
        if not components:
            return 0.0
        total = sum(component.confidence for component in components)
        return round(min(total / len(components), 1.0), 4)

    def _collect_indicators(
        self,
        *,
        sha256: str,
        source_url: str | None,
        threat_assessment: Any,
        malware_assessment: Any,
    ) -> list[str]:
        indicators: list[str] = [sha256]
        if source_url:
            indicators.append(source_url)

        indicators.extend(list(getattr(threat_assessment, "extracted_indicators", [])))

        family = getattr(malware_assessment, "detected_family", None)
        if family:
            indicators.append(f"family:{family}")

        deduped: list[str] = []
        seen: set[str] = set()
        for item in indicators:
            normalized = str(item).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    def _build_reasons(
        self,
        *,
        components: list[ArtifactAnalysisComponent],
        threat_assessment: Any,
        malware_assessment: Any,
        detonation_assessment: Any,
        source_url: str | None,
    ) -> list[str]:
        reasons: list[str] = []

        if source_url:
            reasons.append(f"Source URL supplied for correlation: {source_url}")

        matches = getattr(threat_assessment, "matches", [])
        if matches:
            reasons.append(f"Threat intel matched {len(matches)} known indicator(s).")

        malware_family = getattr(malware_assessment, "detected_family", None)
        if malware_family:
            reasons.append(f"Static malware analysis resembles {malware_family} behavior.")

        malware_signals = getattr(malware_assessment, "signals", [])
        if malware_signals:
            top_malware = sorted(malware_signals, key=lambda signal: signal.weight, reverse=True)[:3]
            for signal in top_malware:
                reasons.append(f"Static signal {signal.name}: {signal.evidence}")

        detonation_signals = getattr(detonation_assessment, "signals", [])
        if detonation_signals:
            top_detonation = sorted(detonation_signals, key=lambda signal: signal.weight, reverse=True)[:3]
            for signal in top_detonation:
                reasons.append(f"Detonation signal {signal.name}: {signal.evidence}")

        strongest_component = max(components, key=lambda component: component.score)
        reasons.append(
            f"Strongest contributing subsystem was {strongest_component.name} with score {strongest_component.score:.4f}.",
        )

        if not reasons:
            reasons.append("No material risk indicators were detected across artifact analysis subsystems.")

        return reasons


def build_artifact_analyzer(
    *,
    threatintel_service: ThreatIntelService | None = None,
    malware_service: MalwareService | None = None,
    detonation_service: DetonationService | None = None,
) -> ArtifactAnalyzer:
    return ArtifactAnalyzer(
        threatintel_service=threatintel_service,
        malware_service=malware_service,
        detonation_service=detonation_service,
    )


__all__ = [
    "ArtifactAnalysisComponent",
    "ArtifactAnalysisResult",
    "ArtifactAnalyzer",
    "build_artifact_analyzer",
]
