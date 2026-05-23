from __future__ import annotations

from datetime import UTC, datetime
import logging
import re
import uuid

from app.schemas.threat_detection import (
    CorrelationSignal,
    DetectionRequest,
    DetectionResult,
    DetectionVerdict,
    IOCMatch,
    ThreatSeverityLevel,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_ENGINE_VERSION = "1.0.0"

_THRESHOLD_BLOCK = 0.75
_THRESHOLD_REVIEW = 0.50
_THRESHOLD_MONITOR = 0.20

_SEVERITY_WEIGHT: dict[str, float] = {
    ThreatSeverityLevel.CRITICAL: 1.0,
    ThreatSeverityLevel.HIGH: 0.75,
    ThreatSeverityLevel.MEDIUM: 0.50,
    ThreatSeverityLevel.LOW: 0.25,
    ThreatSeverityLevel.INFO: 0.05,
}

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_URL = re.compile(r"https?://[^\s\"'>]+")


# ---------------------------------------------------------------------------
# ScoreResult — internal scoring container
# ---------------------------------------------------------------------------


class ScoreResult:
    """
    Holds the normalized composite threat score and its contributing factors.
    Produced by ThreatScoringEngine.compute() and consumed by
    ThreatDetectionEngine to build a DetectionResult.
    """

    __slots__ = (
        "raw_score",
        "normalized_score",
        "verdict",
        "severity",
        "risk_families",
        "mitre_techniques",
        "rationale",
    )

    def __init__(
        self,
        *,
        raw_score: float,
        normalized_score: float,
        verdict: DetectionVerdict,
        severity: ThreatSeverityLevel,
        risk_families: list[str],
        mitre_techniques: list[str],
        rationale: list[str],
    ) -> None:
        self.raw_score = raw_score
        self.normalized_score = normalized_score
        self.verdict = verdict
        self.severity = severity
        self.risk_families = risk_families
        self.mitre_techniques = mitre_techniques
        self.rationale = rationale


# ---------------------------------------------------------------------------
# ThreatScoringEngine
# ---------------------------------------------------------------------------


class ThreatScoringEngine:
    """
    Pure scoring layer.  Accepts pre-resolved IOCMatch and CorrelationSignal
    lists and produces a ScoreResult with a normalized 0.0–1.0 composite score,
    verdict, severity, and structured rationale.

    No I/O, no Supabase calls — deterministic given the same inputs.
    """

    def compute(
        self,
        ioc_matches: list[IOCMatch],
        correlation_signals: list[CorrelationSignal],
    ) -> ScoreResult:
        raw_score = self._score_iocs(ioc_matches) + self._score_signals(correlation_signals)
        normalized = min(raw_score, 1.0)

        verdict = self._verdict_from_score(normalized)
        severity = self._severity_from_score(normalized, ioc_matches)
        risk_families = self._extract_risk_families(ioc_matches)
        mitre_techniques = self._extract_mitre_techniques(ioc_matches, correlation_signals)
        rationale = self._build_rationale(
            normalized,
            ioc_matches,
            correlation_signals,
            verdict,
        )

        return ScoreResult(
            raw_score=raw_score,
            normalized_score=normalized,
            verdict=verdict,
            severity=severity,
            risk_families=risk_families,
            mitre_techniques=mitre_techniques,
            rationale=rationale,
        )

    def _score_iocs(self, ioc_matches: list[IOCMatch]) -> float:
        if not ioc_matches:
            return 0.0
        total = 0.0
        for match in ioc_matches:
            sev_str = match.severity if isinstance(match.severity, str) else str(match.severity)
            weight = _SEVERITY_WEIGHT.get(sev_str.lower(), 0.25)
            total += weight * float(match.confidence)
        return min(total / max(len(ioc_matches), 1) + (0.05 * len(ioc_matches)), 0.80)

    def _score_signals(self, signals: list[CorrelationSignal]) -> float:
        if not signals:
            return 0.0
        total = sum(s.score_contribution * s.confidence for s in signals)
        return min(total, 0.20)

    @staticmethod
    def _verdict_from_score(score: float) -> DetectionVerdict:
        if score >= _THRESHOLD_BLOCK:
            return DetectionVerdict.BLOCK
        if score >= _THRESHOLD_REVIEW:
            return DetectionVerdict.REVIEW
        if score >= _THRESHOLD_MONITOR:
            return DetectionVerdict.MONITOR
        return DetectionVerdict.ALLOW

    @staticmethod
    def _severity_from_score(
        score: float,
        ioc_matches: list[IOCMatch],
    ) -> ThreatSeverityLevel:
        if score >= 0.75:
            return ThreatSeverityLevel.CRITICAL
        if score >= 0.50:
            sev_order = [
                ThreatSeverityLevel.CRITICAL,
                ThreatSeverityLevel.HIGH,
                ThreatSeverityLevel.MEDIUM,
                ThreatSeverityLevel.LOW,
                ThreatSeverityLevel.INFO,
            ]
            for sev in sev_order:
                if any(m.severity == sev for m in ioc_matches):
                    return sev
            return ThreatSeverityLevel.HIGH
        if score >= 0.25:
            return ThreatSeverityLevel.MEDIUM
        if score >= 0.10:
            return ThreatSeverityLevel.LOW
        return ThreatSeverityLevel.INFO

    @staticmethod
    def _extract_risk_families(ioc_matches: list[IOCMatch]) -> list[str]:
        families: set[str] = set()
        for match in ioc_matches:
            for tag in match.tags:
                families.add(tag.lower().replace(" ", "_"))
        return sorted(families)

    @staticmethod
    def _extract_mitre_techniques(
        ioc_matches: list[IOCMatch],
        signals: list[CorrelationSignal],
    ) -> list[str]:
        techniques: set[str] = set()
        for match in ioc_matches:
            if match.mitre_technique_id:
                techniques.add(match.mitre_technique_id.upper())
        for sig in signals:
            for tid in sig.mitre_technique_ids:
                techniques.add(tid.upper())
        return sorted(techniques)

    @staticmethod
    def _build_rationale(
        score: float,
        ioc_matches: list[IOCMatch],
        signals: list[CorrelationSignal],
        verdict: DetectionVerdict,
    ) -> list[str]:
        lines: list[str] = []
        lines.append(f"Composite threat score: {score:.3f}.")
        lines.append(f"Verdict: {verdict.value}.")
        if ioc_matches:
            lines.append(f"{len(ioc_matches)} IOC match(es) resolved.")
        else:
            lines.append("No IOC matches found.")
        if signals:
            lines.append(f"{len(signals)} correlation signal(s) contributed to scoring.")
        high_sev = [m for m in ioc_matches if m.severity in (ThreatSeverityLevel.CRITICAL, ThreatSeverityLevel.HIGH)]
        if high_sev:
            values = ", ".join(m.value for m in high_sev[:3])
            lines.append(f"High/critical IOC(s): {values}.")
        return lines


# ---------------------------------------------------------------------------
# ThreatDetectionEngine — orchestration layer
# ---------------------------------------------------------------------------


class ThreatDetectionEngine:
    """
    Orchestrates full detection pipeline:
      1. Extract observable values from the DetectionRequest payload.
      2. Resolve IOC matches via ioc_store.
      3. Run ThreatCorrelationEngine on resolved IOC matches to produce signals.
      4. Merge caller-injected CorrelationSignals with engine-derived signals.
      5. Delegate scoring to ThreatScoringEngine.compute().
      6. Return a fully populated DetectionResult.

    This class owns no persistence — all store access is delegated.
    """

    def __init__(self, scoring_engine: ThreatScoringEngine | None = None) -> None:
        self._scoring_engine = scoring_engine or ThreatScoringEngine()

    # ------------------------------------------------------------------
    # Primary pipeline
    # ------------------------------------------------------------------

    def run(
        self,
        request: DetectionRequest,
        *,
        correlation_signals: list[CorrelationSignal] | None = None,
    ) -> DetectionResult:
        """
        Full detection pipeline.  Returns a DetectionResult.
        correlation_signals may be injected by the caller (e.g. from a
        session context or upstream router); the engine also auto-derives
        signals from resolved IOC matches via ThreatCorrelationEngine.
        """
        event_id = request.event_id or str(uuid.uuid4())
        caller_signals: list[CorrelationSignal] = correlation_signals or []

        # Step 1: gather observable values
        observables = self._extract_observables(request)

        # Step 2: resolve IOC matches
        ioc_matches = self._resolve_ioc_matches(
            observables=observables,
            org_id=request.org_id,
            minimum_confidence=request.minimum_confidence,
        )

        # Step 3: run correlation engine on resolved matches
        engine_signals = self._run_correlation(ioc_matches, event_id=event_id)

        # Step 4: merge caller-injected + engine-derived signals (engine first)
        all_signals: list[CorrelationSignal] = engine_signals + caller_signals

        # Step 5: score
        score_result: ScoreResult = self._scoring_engine.compute(ioc_matches, all_signals)

        # Step 6: assemble DetectionResult
        return DetectionResult(
            event_id=event_id,
            org_id=request.org_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            verdict=score_result.verdict,
            score=score_result.normalized_score,
            severity=score_result.severity,
            scanned_text=request.text,
            ioc_matches=ioc_matches,
            correlation_signals=all_signals,
            risk_families=score_result.risk_families,
            extracted_indicators=observables,
            rationale=score_result.rationale,
            mitre_techniques=score_result.mitre_techniques,
            context=request.context,
            metadata=request.metadata,
            assessed_at=_utcnow_iso(),
            detection_engine_version=_ENGINE_VERSION,
        )

    # ------------------------------------------------------------------
    # Correlation delegation
    # ------------------------------------------------------------------

    @staticmethod
    def _run_correlation(
        ioc_matches: list[IOCMatch],
        event_id: str,
    ) -> list[CorrelationSignal]:
        if not ioc_matches:
            return []
        try:
            from app.services.threat_correlation import get_correlation_engine

            corr_engine = get_correlation_engine()
            return corr_engine.correlate(ioc_matches, event_ids=[event_id])
        except Exception as exc:
            logger.error("threat_detection_engine.run_correlation.error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Observable extraction
    # ------------------------------------------------------------------

    def _extract_observables(self, request: DetectionRequest) -> list[str]:
        observables: set[str] = set()

        for v in request.ioc_values or []:
            if v:
                observables.add(v.strip())

        for h in request.hashes or []:
            if h:
                observables.add(h.strip())

        if request.url:
            observables.add(request.url.strip())

        if request.domain:
            observables.add(request.domain.strip().lower())

        if request.text:
            observables.update(self._extract_from_text(request.text))

        return sorted(observables)

    @staticmethod
    def _extract_from_text(text: str) -> list[str]:
        found: set[str] = set()
        found.update(_RE_URL.findall(text))
        found.update(_RE_IPV4.findall(text))
        found.update(_RE_CVE.findall(text))
        found.update(_RE_SHA256.findall(text))
        found.update(_RE_SHA1.findall(text))
        found.update(_RE_MD5.findall(text))
        for dom in _RE_DOMAIN.findall(text):
            if not _RE_IPV4.fullmatch(dom):
                found.add(dom.lower())
        return list(found)

    # ------------------------------------------------------------------
    # IOC resolution
    # ------------------------------------------------------------------

    def _resolve_ioc_matches(
        self,
        *,
        observables: list[str],
        org_id: str | None,
        minimum_confidence: float,
    ) -> list[IOCMatch]:
        if not observables:
            return []

        try:
            from app.services.ioc_store import get_ioc_store

            store = get_ioc_store()
            records = store.lookup_by_values(observables, org_id=org_id, active_only=True)
        except Exception as exc:
            logger.error("threat_detection_engine.resolve_ioc_matches.error: %s", exc)
            return []

        matches: list[IOCMatch] = []
        for rec in records:
            if float(rec.confidence) < minimum_confidence:
                continue
            matches.append(
                IOCMatch(
                    ioc_id=rec.ioc_id,
                    value=rec.value,
                    ioc_type=str(rec.ioc_type),
                    confidence=float(rec.confidence),
                    severity=str(rec.severity),
                    source=str(rec.source),
                    tags=list(rec.tags),
                    matched_on="ioc_store",
                    mitre_technique_id=rec.mitre_technique_id,
                    mitre_tactic=rec.mitre_tactic,
                    cve_id=rec.cve_id,
                    first_seen=rec.first_seen,
                    last_seen=rec.last_seen,
                )
            )
        return matches


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_ENGINE: ThreatDetectionEngine | None = None


def get_scoring_engine() -> ThreatScoringEngine:
    """Return the shared ThreatScoringEngine instance (scoring-only)."""
    return _get_engine()._scoring_engine


def _get_engine() -> ThreatDetectionEngine:
    global _ENGINE  # noqa: PLW0603
    if _ENGINE is None:
        _ENGINE = ThreatDetectionEngine()
    return _ENGINE


def get_detection_engine() -> ThreatDetectionEngine:
    """Return the shared ThreatDetectionEngine singleton."""
    return _get_engine()


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = [
    "ScoreResult",
    "ThreatDetectionEngine",
    "ThreatScoringEngine",
    "get_detection_engine",
    "get_scoring_engine",
]
