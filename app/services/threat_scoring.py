from __future__ import annotations

import logging
from typing import Any

from app.schemas.threat_detection import (
    DetectionVerdict,
    IOCMatch,
    IOCTypeEnum,
    ThreatSeverityLevel,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity weight table — maps ThreatSeverityLevel → base score contribution
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, float] = {
    ThreatSeverityLevel.INFO: 0.05,
    ThreatSeverityLevel.LOW: 0.20,
    ThreatSeverityLevel.MEDIUM: 0.45,
    ThreatSeverityLevel.HIGH: 0.70,
    ThreatSeverityLevel.CRITICAL: 1.00,
}

# IOC type amplifiers — certain IOC types carry higher intrinsic risk
_IOC_TYPE_AMPLIFIERS: dict[str, float] = {
    IOCTypeEnum.IPV4: 1.0,
    IOCTypeEnum.IPV6: 1.0,
    IOCTypeEnum.DOMAIN: 1.05,
    IOCTypeEnum.URL: 1.10,
    IOCTypeEnum.SHA256: 1.15,
    IOCTypeEnum.SHA1: 1.10,
    IOCTypeEnum.MD5: 1.05,
    IOCTypeEnum.CVE: 1.20,
    IOCTypeEnum.MITRE_TECHNIQUE: 1.15,
    IOCTypeEnum.MITRE_TACTIC: 1.05,
    IOCTypeEnum.EMAIL: 0.90,
    IOCTypeEnum.UNKNOWN: 0.80,
}

# Tag risk modifiers — additive bonus applied per matching tag on any IOC match
_TAG_RISK_BONUS: dict[str, float] = {
    "ransomware": 0.15,
    "exploited-in-wild": 0.12,
    "cisa-kev": 0.10,
    "apt": 0.12,
    "c2": 0.12,
    "command-and-control": 0.12,
    "data-exfiltration": 0.10,
    "lateral-movement": 0.08,
    "privilege-escalation": 0.08,
    "credential-access": 0.08,
    "mitre-attack": 0.05,
    "custom-ioc": 0.0,
    "cve": 0.05,
}

# Verdict thresholds — score ranges mapped to DetectionVerdict
_VERDICT_THRESHOLDS: list[tuple[float, DetectionVerdict]] = [
    (0.75, DetectionVerdict.BLOCK),
    (0.50, DetectionVerdict.REVIEW),
    (0.25, DetectionVerdict.MONITOR),
    (0.00, DetectionVerdict.ALLOW),
]

# Severity thresholds — composite score ranges mapped to ThreatSeverityLevel
_SEVERITY_THRESHOLDS: list[tuple[float, ThreatSeverityLevel]] = [
    (0.85, ThreatSeverityLevel.CRITICAL),
    (0.65, ThreatSeverityLevel.HIGH),
    (0.40, ThreatSeverityLevel.MEDIUM),
    (0.15, ThreatSeverityLevel.LOW),
    (0.00, ThreatSeverityLevel.INFO),
]

# Maximum number of IOC matches to include in composite scoring
# (diminishing returns — avoids runaway scoring from bulk low-quality matches)
_MAX_SCORED_MATCHES = 10

# Correlation signal score contribution cap
_CORRELATION_SCORE_CAP = 0.30


# ---------------------------------------------------------------------------
# Public scoring helpers
# ---------------------------------------------------------------------------


def severity_to_weight(severity: str) -> float:
    """Return the base weight for a severity level string. Safe fallback to 0.0."""
    return _SEVERITY_WEIGHTS.get(severity, 0.0)


def ioc_type_amplifier(ioc_type: str) -> float:
    """Return the risk amplifier for an IOC type. Defaults to 1.0 for unknown types."""
    return _IOC_TYPE_AMPLIFIERS.get(ioc_type, 1.0)


def tag_risk_bonus(tags: list[str]) -> float:
    """Return total tag risk bonus for a tag list. Capped at 0.30 to prevent tag stuffing."""
    total = sum(_TAG_RISK_BONUS.get(t, 0.0) for t in tags)
    return min(total, 0.30)


def score_single_ioc_match(match: IOCMatch) -> float:
    """
    Compute a 0.0–1.0 score contribution for a single IOCMatch.

    Formula:
        raw = severity_weight * ioc_type_amplifier * confidence + tag_bonus
        clamped to [0.0, 1.0]
    """
    base = severity_to_weight(match.severity)
    amp = ioc_type_amplifier(match.ioc_type)
    confidence = max(0.0, min(1.0, float(match.confidence)))
    bonus = tag_risk_bonus(match.tags)
    raw = (base * amp * confidence) + bonus
    return max(0.0, min(1.0, raw))


def score_ioc_matches(matches: list[IOCMatch]) -> float:
    """
    Compute composite IOC score from a list of IOCMatch objects.

    Uses weighted average of top-N matches (by individual score) to prevent
    score inflation from bulk low-confidence matches.

    Returns 0.0–1.0.
    """
    if not matches:
        return 0.0

    scored = sorted(
        [score_single_ioc_match(m) for m in matches],
        reverse=True,
    )[:_MAX_SCORED_MATCHES]

    if not scored:
        return 0.0

    # Weighted average: top match carries highest weight via descending position weights
    total_weight = 0.0
    weighted_sum = 0.0
    for i, s in enumerate(scored):
        weight = 1.0 / (i + 1)  # 1, 0.5, 0.33, ... harmonic decay
        weighted_sum += s * weight
        total_weight += weight

    return max(0.0, min(1.0, weighted_sum / total_weight))


def score_correlation_signals(signals: list[Any]) -> float:
    """
    Compute composite correlation contribution from CorrelationSignal objects.

    Accepts a list of objects with .confidence and .score_contribution attributes.
    Returns 0.0–_CORRELATION_SCORE_CAP.
    """
    if not signals:
        return 0.0

    total = sum(max(0.0, min(1.0, float(getattr(s, "score_contribution", 0.0)))) * max(0.0, min(1.0, float(getattr(s, "confidence", 0.0)))) for s in signals)
    return min(total, _CORRELATION_SCORE_CAP)


def compute_composite_score(
    ioc_matches: list[IOCMatch],
    correlation_signals: list[Any] | None = None,
    *,
    base_score_override: float | None = None,
) -> float:
    """
    Compute the final normalized composite threat score (0.0–1.0).

    Composition:
        ioc_score      = score_ioc_matches(ioc_matches)
        correlation    = score_correlation_signals(correlation_signals)
        composite      = clamp(ioc_score + correlation, 0.0, 1.0)

    If base_score_override is supplied (e.g., from a raw signal not derived from
    IOCMatches), it replaces ioc_score before adding correlation.
    """
    if base_score_override is not None:
        ioc_score = max(0.0, min(1.0, float(base_score_override)))
    else:
        ioc_score = score_ioc_matches(ioc_matches)

    correlation_score = score_correlation_signals(correlation_signals or [])
    composite = ioc_score + correlation_score
    return max(0.0, min(1.0, composite))


def score_to_verdict(score: float) -> DetectionVerdict:
    """
    Map a composite 0.0–1.0 score to a DetectionVerdict.

    Thresholds (inclusive lower bound):
        >= 0.75 → BLOCK
        >= 0.50 → REVIEW
        >= 0.25 → MONITOR
         < 0.25 → ALLOW
    """
    for threshold, verdict in _VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return DetectionVerdict.ALLOW


def score_to_severity(score: float) -> ThreatSeverityLevel:
    """
    Map a composite 0.0–1.0 score to a ThreatSeverityLevel.

    Thresholds (inclusive lower bound):
        >= 0.85 → CRITICAL
        >= 0.65 → HIGH
        >= 0.40 → MEDIUM
        >= 0.15 → LOW
         < 0.15 → INFO
    """
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return ThreatSeverityLevel.INFO


def derive_risk_families(matches: list[IOCMatch]) -> list[str]:
    """
    Derive a deduplicated list of risk family labels from IOCMatch tags and types.

    Used to populate DetectionResult.risk_families.
    """
    families: set[str] = set()

    _TAG_FAMILY_MAP: dict[str, str] = {
        "ransomware": "ransomware",
        "c2": "command_and_control",
        "command-and-control": "command_and_control",
        "exfiltration": "data_exfiltration",
        "data-exfiltration": "data_exfiltration",
        "lateral-movement": "lateral_movement",
        "privilege-escalation": "privilege_escalation",
        "credential-access": "credential_access",
        "initial-access": "initial_access",
        "execution": "execution",
        "persistence": "persistence",
        "defense-evasion": "defense_evasion",
        "discovery": "discovery",
        "collection": "collection",
        "impact": "impact",
        "reconnaissance": "reconnaissance",
        "resource-development": "resource_development",
        "exploited-in-wild": "known_exploited",
        "cisa-kev": "known_exploited",
        "apt": "advanced_persistent_threat",
        "cve": "vulnerability",
    }

    _TYPE_FAMILY_MAP: dict[str, str] = {
        IOCTypeEnum.CVE: "vulnerability",
        IOCTypeEnum.MITRE_TECHNIQUE: "mitre_technique",
        IOCTypeEnum.MITRE_TACTIC: "mitre_tactic",
        IOCTypeEnum.SHA256: "malware_artifact",
        IOCTypeEnum.SHA1: "malware_artifact",
        IOCTypeEnum.MD5: "malware_artifact",
        IOCTypeEnum.URL: "malicious_url",
        IOCTypeEnum.DOMAIN: "malicious_domain",
        IOCTypeEnum.IPV4: "malicious_ip",
        IOCTypeEnum.IPV6: "malicious_ip",
        IOCTypeEnum.EMAIL: "phishing",
    }

    for match in matches:
        for tag in match.tags:
            family = _TAG_FAMILY_MAP.get(tag.lower())
            if family:
                families.add(family)
        type_family = _TYPE_FAMILY_MAP.get(match.ioc_type)
        if type_family:
            families.add(type_family)

    return sorted(families)


def derive_mitre_techniques(matches: list[IOCMatch]) -> list[str]:
    """
    Extract deduplicated MITRE technique IDs from IOCMatch objects.

    Used to populate DetectionResult.mitre_techniques.
    """
    techniques: set[str] = set()
    for match in matches:
        if match.mitre_technique_id:
            techniques.add(match.mitre_technique_id.upper())
        if match.ioc_type == IOCTypeEnum.MITRE_TECHNIQUE and match.value:
            techniques.add(match.value.upper())
    return sorted(techniques)


def build_score_rationale(
    ioc_matches: list[IOCMatch],
    composite_score: float,
    verdict: DetectionVerdict,
) -> list[str]:
    """
    Generate human-readable rationale lines for a DetectionResult.

    Used to populate DetectionResult.rationale.
    """
    rationale: list[str] = []

    if not ioc_matches:
        rationale.append("No IOC matches found.")
        return rationale

    rationale.append(f"Composite threat score: {composite_score:.3f} → verdict: {verdict.value.upper()}")

    high_confidence = [m for m in ioc_matches if m.confidence >= 0.8]
    if high_confidence:
        rationale.append(f"{len(high_confidence)} high-confidence IOC match(es) " f"(confidence >= 0.8): {', '.join(m.value for m in high_confidence[:5])}")

    critical_matches = [m for m in ioc_matches if m.severity in (ThreatSeverityLevel.CRITICAL, ThreatSeverityLevel.HIGH)]
    if critical_matches:
        rationale.append(f"{len(critical_matches)} HIGH/CRITICAL severity match(es): " f"{', '.join(m.value for m in critical_matches[:5])}")

    cve_matches = [m for m in ioc_matches if m.cve_id or m.ioc_type == IOCTypeEnum.CVE]
    if cve_matches:
        rationale.append(f"CVE match(es) detected: {', '.join(m.cve_id or m.value for m in cve_matches[:5])}")

    mitre_matches = [m for m in ioc_matches if m.ioc_type in (IOCTypeEnum.MITRE_TECHNIQUE, IOCTypeEnum.MITRE_TACTIC)]
    if mitre_matches:
        rationale.append(f"MITRE ATT&CK indicator(s) matched: {', '.join(m.value for m in mitre_matches[:5])}")

    ransomware_tags = [m for m in ioc_matches if "ransomware" in m.tags]
    if ransomware_tags:
        rationale.append("Ransomware-tagged IOC(s) present — elevated risk.")

    kev_tags = [m for m in ioc_matches if "exploited-in-wild" in m.tags or "cisa-kev" in m.tags]
    if kev_tags:
        rationale.append("CISA KEV / exploited-in-wild IOC(s) matched — immediate remediation advised.")

    return rationale


# ---------------------------------------------------------------------------
# ThreatScoringEngine — injectable service class
# ---------------------------------------------------------------------------


class ThreatScoringEngine:
    """
    Unified 0.0–1.0 threat scoring engine for IronClaw.

    Stateless by design — no caching, no DB access.
    All inputs are schema objects from app.schemas.threat_detection.
    Called by: threat_detection_engine.py

    Public surface:
        score()             → full ScoreResult dataclass
        verdict_for_score() → DetectionVerdict
        severity_for_score() → ThreatSeverityLevel
    """

    # Expose module-level helpers as instance methods for testability
    @staticmethod
    def severity_weight(severity: str) -> float:
        return severity_to_weight(severity)

    @staticmethod
    def type_amplifier(ioc_type: str) -> float:
        return ioc_type_amplifier(ioc_type)

    @staticmethod
    def compute(
        ioc_matches: list[IOCMatch],
        correlation_signals: list[Any] | None = None,
        *,
        base_score_override: float | None = None,
    ) -> ScoreResult:
        """
        Run the full scoring pipeline and return a ScoreResult.

        Args:
            ioc_matches:          List of IOCMatch objects from ioc_store lookups.
            correlation_signals:  Optional list of CorrelationSignal objects.
            base_score_override:  Optional raw score bypass (skips IOC scoring).

        Returns:
            ScoreResult with score, verdict, severity, risk_families,
            mitre_techniques, and rationale populated.
        """
        composite = compute_composite_score(
            ioc_matches,
            correlation_signals,
            base_score_override=base_score_override,
        )
        verdict = score_to_verdict(composite)
        severity = score_to_severity(composite)
        risk_families = derive_risk_families(ioc_matches)
        mitre_techniques = derive_mitre_techniques(ioc_matches)
        rationale = build_score_rationale(ioc_matches, composite, verdict)

        logger.debug(
            "threat_scoring.compute score=%.3f verdict=%s severity=%s ioc_count=%d",
            composite,
            verdict.value,
            severity.value,
            len(ioc_matches),
        )

        return ScoreResult(
            score=composite,
            verdict=verdict,
            severity=severity,
            risk_families=risk_families,
            mitre_techniques=mitre_techniques,
            rationale=rationale,
        )

    @staticmethod
    def verdict_for_score(score: float) -> DetectionVerdict:
        return score_to_verdict(score)

    @staticmethod
    def severity_for_score(score: float) -> ThreatSeverityLevel:
        return score_to_severity(score)


# ---------------------------------------------------------------------------
# ScoreResult — returned by ThreatScoringEngine.compute()
# ---------------------------------------------------------------------------


class ScoreResult:
    """
    Lightweight result container returned by ThreatScoringEngine.compute().

    Not a Pydantic model — this is an internal service layer object.
    threat_detection_engine.py unpacks these fields into DetectionResult.
    """

    __slots__ = (
        "score",
        "verdict",
        "severity",
        "risk_families",
        "mitre_techniques",
        "rationale",
    )

    def __init__(
        self,
        *,
        score: float,
        verdict: DetectionVerdict,
        severity: ThreatSeverityLevel,
        risk_families: list[str],
        mitre_techniques: list[str],
        rationale: list[str],
    ) -> None:
        self.score = score
        self.verdict = verdict
        self.severity = severity
        self.risk_families = risk_families
        self.mitre_techniques = mitre_techniques
        self.rationale = rationale

    def __repr__(self) -> str:
        return f"ScoreResult(score={self.score:.3f}, verdict={self.verdict.value}, " f"severity={self.severity.value})"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_SCORING_ENGINE: ThreatScoringEngine | None = None


def get_scoring_engine() -> ThreatScoringEngine:
    global _SCORING_ENGINE  # noqa: PLW0603
    if _SCORING_ENGINE is None:
        _SCORING_ENGINE = ThreatScoringEngine()
    return _SCORING_ENGINE


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = [
    "ScoreResult",
    "ThreatScoringEngine",
    "build_score_rationale",
    "compute_composite_score",
    "derive_mitre_techniques",
    "derive_risk_families",
    "get_scoring_engine",
    "ioc_type_amplifier",
    "score_correlation_signals",
    "score_ioc_matches",
    "score_single_ioc_match",
    "score_to_severity",
    "score_to_verdict",
    "severity_to_weight",
    "tag_risk_bonus",
]
