from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import math
import random
import re
from typing import Any, Literal

NETWORK_PATTERNS = {
    "known_c2_port": (re.compile(r"\b(?:4444|1337|8081|9001)\b"), 0.18),
    "dns_tunneling": (
        re.compile(r"\b(?:txt query|dns tunnel|nslookup -q=txt)\b", re.IGNORECASE),
        0.24,
    ),
    "http_beacon": (re.compile(r"https?://[^\s\"']+", re.IGNORECASE), 0.16),
    "tor_indicator": (re.compile(r"\btor\b|\.onion\b", re.IGNORECASE), 0.28),
}

PROCESS_PATTERNS = {
    "credential_access": (
        re.compile(r"\b(lsass|mimikatz|sekurlsa|sam hive)\b", re.IGNORECASE),
        0.34,
    ),
    "defense_evasion": (
        re.compile(r"\b(disabledefender|set-mppreference|realtimemonitoring)\b", re.IGNORECASE),
        0.28,
    ),
    "lolbin_chain": (
        re.compile(r"\b(powershell|mshta|rundll32|regsvr32|certutil|wmic)\b", re.IGNORECASE),
        0.22,
    ),
    "persistence": (
        re.compile(r"\b(schtasks|startup|run key|currentversion\\run)\b", re.IGNORECASE),
        0.24,
    ),
    "lateral_movement": (
        re.compile(r"\b(psexec|wmic /node|net use \\\\|winrm)\b", re.IGNORECASE),
        0.28,
    ),
}

FILE_PATTERNS = {
    "drops_executable": (
        re.compile(r"\b(writefile|dropper|payload|temp\\.*\.(?:exe|dll|ps1))\b", re.IGNORECASE),
        0.24,
    ),
    "archive_unpack": (
        re.compile(r"\b(zip extract|unpack|inflate resource)\b", re.IGNORECASE),
        0.14,
    ),
    "self_delete": (
        re.compile(r"\b(del /f /q|self-delete|remove-item .* -force)\b", re.IGNORECASE),
        0.18,
    ),
}

BEHAVIOR_BONUSES = {
    ("credential_access", "defense_evasion"): 0.14,
    ("lolbin_chain", "http_beacon"): 0.12,
    ("persistence", "drops_executable"): 0.10,
    ("tor_indicator", "http_beacon"): 0.12,
    ("lateral_movement", "credential_access"): 0.12,
}


@dataclass(slots=True)
class DetonationSignal:
    name: str
    category: str
    weight: float
    evidence: str


@dataclass(slots=True)
class DetonationArtifact:
    path: str
    artifact_type: str
    risk: str


@dataclass(slots=True)
class DetonationAssessment:
    verdict: Literal["allow", "block"]
    severity: str
    score: float
    confidence: float
    sample_sha256: str
    sandbox_profile: str
    execution_time_ms: int
    signals: list[DetonationSignal] = field(default_factory=list)
    artifacts: list[DetonationArtifact] = field(default_factory=list)
    behavior_tags: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    detonated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "sample_sha256": self.sample_sha256,
            "sandbox_profile": self.sandbox_profile,
            "execution_time_ms": self.execution_time_ms,
            "signals": [
                {
                    "name": signal.name,
                    "category": signal.category,
                    "weight": signal.weight,
                    "evidence": signal.evidence,
                }
                for signal in self.signals
            ],
            "artifacts": [
                {
                    "path": artifact.path,
                    "artifact_type": artifact.artifact_type,
                    "risk": artifact.risk,
                }
                for artifact in self.artifacts
            ],
            "behavior_tags": list(self.behavior_tags),
            "rationale": list(self.rationale),
            "detonated_at": self.detonated_at,
        }


class DetonationService:
    def detonate_bytes(
        self,
        payload: bytes,
        *,
        file_name: str | None = None,
        sandbox_profile: str = "windows-office-user",
    ) -> DetonationAssessment:
        text_view = payload.decode("utf-8", errors="ignore")
        return self.detonate_text(
            text_view,
            file_name=file_name,
            payload_bytes=payload,
            sandbox_profile=sandbox_profile,
        )

    def detonate_text(
        self,
        text: str,
        *,
        file_name: str | None = None,
        payload_bytes: bytes | None = None,
        sandbox_profile: str = "windows-office-user",
    ) -> DetonationAssessment:
        raw_bytes = payload_bytes if payload_bytes is not None else text.encode("utf-8", errors="ignore")
        sample_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        normalized = text.strip()
        signals: list[DetonationSignal] = []

        signals.extend(self._scan_patterns(normalized, NETWORK_PATTERNS, "network"))
        signals.extend(self._scan_patterns(normalized, PROCESS_PATTERNS, "process"))
        signals.extend(self._scan_patterns(normalized, FILE_PATTERNS, "filesystem"))

        score = sum(signal.weight for signal in signals)
        score += self._apply_behavior_bonuses(signals)
        score = min(round(score, 4), 1.0)

        verdict, severity = self._resolve_verdict(score)
        if signals:
            verdict = "block"
        confidence = self._derive_confidence(signals, normalized, payload_len=len(raw_bytes))
        artifacts = self._derive_artifacts(signals, file_name=file_name)
        behavior_tags = sorted({signal.name for signal in signals})
        rationale = self._build_rationale(signals, artifacts, sandbox_profile, verdict)
        execution_time_ms = self._simulate_execution_time(sample_sha256, len(raw_bytes), len(signals))

        return DetonationAssessment(
            verdict=verdict,
            severity=severity,
            score=score,
            confidence=confidence,
            sample_sha256=sample_sha256,
            sandbox_profile=sandbox_profile,
            execution_time_ms=execution_time_ms,
            signals=signals,
            artifacts=artifacts,
            behavior_tags=behavior_tags,
            rationale=rationale,
        )

    def _scan_patterns(
        self,
        text: str,
        patterns: dict[str, tuple[re.Pattern[str], float]],
        category: str,
    ) -> list[DetonationSignal]:
        found: list[DetonationSignal] = []
        for name, (pattern, weight) in patterns.items():
            match = pattern.search(text)
            if not match:
                continue
            evidence = match.group(0)[:180]
            found.append(
                DetonationSignal(
                    name=name,
                    category=category,
                    weight=weight,
                    evidence=evidence,
                ),
            )
        return found

    def _apply_behavior_bonuses(self, signals: list[DetonationSignal]) -> float:
        names = {signal.name for signal in signals}
        bonus = 0.0
        for combo, value in BEHAVIOR_BONUSES.items():
            if all(item in names for item in combo):
                bonus += value
        return bonus

    def _resolve_verdict(self, score: float) -> tuple[Literal["allow", "block"], str]:
        if not math.isfinite(score) or score < 0:
            return "block", "high"
        if score >= 0.82:
            return "block", "critical"
        if score >= 0.56:
            return "block", "high"
        if score >= 0.28:
            return "block", "medium"
        if score > 0:
            return "block", "low"
        return "allow", "low"

    def _derive_confidence(self, signals: list[DetonationSignal], text: str, payload_len: int) -> float:
        if not signals:
            return 0.18
        confidence = 0.42 + min(len(signals) * 0.09, 0.32)
        if payload_len > 1000:
            confidence += 0.05
        if any(signal.weight >= 0.28 for signal in signals):
            confidence += 0.10
        if "http" in text.lower():
            confidence += 0.03
        return round(min(confidence, 0.97), 4)

    def _derive_artifacts(
        self,
        signals: list[DetonationSignal],
        *,
        file_name: str | None,
    ) -> list[DetonationArtifact]:
        artifacts: list[DetonationArtifact] = []
        names = {signal.name for signal in signals}

        if "drops_executable" in names:
            artifacts.append(
                DetonationArtifact(
                    path=r"C:\Users\Public\svchost_update.exe",
                    artifact_type="dropped_file",
                    risk="high",
                ),
            )

        if "persistence" in names:
            artifacts.append(
                DetonationArtifact(
                    path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                    artifact_type="registry_persistence",
                    risk="high",
                ),
            )

        if "http_beacon" in names or "tor_indicator" in names:
            artifacts.append(
                DetonationArtifact(
                    path="network://outbound/session-1",
                    artifact_type="network_connection",
                    risk="high",
                ),
            )

        if "credential_access" in names:
            artifacts.append(
                DetonationArtifact(
                    path=r"memory://lsass-access",
                    artifact_type="process_access",
                    risk="critical",
                ),
            )

        if not artifacts and file_name:
            artifacts.append(
                DetonationArtifact(
                    path=file_name,
                    artifact_type="submitted_sample",
                    risk="low",
                ),
            )

        return artifacts

    def _build_rationale(
        self,
        signals: list[DetonationSignal],
        artifacts: list[DetonationArtifact],
        sandbox_profile: str,
        verdict: str,
    ) -> list[str]:
        rationale = [
            f"Sandbox profile selected: {sandbox_profile}.",
            f"Behavioral verdict resolved to {verdict}.",
        ]

        if signals:
            top = sorted(signals, key=lambda signal: signal.weight, reverse=True)[:5]
            for signal in top:
                rationale.append(f"Observed {signal.category} behavior {signal.name}: {signal.evidence}")
        else:
            rationale.append("No suspicious behavioral indicators were observed during simulated detonation.")

        if artifacts:
            for artifact in artifacts[:4]:
                rationale.append(f"Generated artifact {artifact.artifact_type} at {artifact.path} with {artifact.risk} risk.")

        return rationale

    def _simulate_execution_time(self, sample_sha256: str, payload_len: int, signal_count: int) -> int:
        seed = int(sample_sha256[:8], 16)
        rng = random.Random(seed)
        baseline = 900 + min(payload_len // 3, 3200)
        jitter = rng.randint(120, 860)
        return baseline + jitter + signal_count * 140


def build_detonation_service() -> DetonationService:
    return DetonationService()


__all__ = [
    "DetonationArtifact",
    "DetonationAssessment",
    "DetonationService",
    "DetonationSignal",
    "build_detonation_service",
]
