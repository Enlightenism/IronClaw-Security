from __future__ import annotations

from datetime import UTC, datetime
import logging
import math
import re
import threading
from typing import TYPE_CHECKING, Any
import uuid

from app.schemas.threat_detection import (
    CorrelationSignal,
    DetectionRequest,
    DetectionResult,
    DetectionVerdict,
    IOCMatch,
    ThreatSeverityLevel,
)
from app.services import mitre_utils as mu  # canonical MITRE helpers
from app.services.ioc_store import get_ioc_store
from app.services.threat_correlation import get_correlation_engine

if TYPE_CHECKING:
    from app.services.notification_service import NotificationEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------


_ENGINE_VERSION = "1.0.0"


_SEVERITY_WEIGHT: dict[ThreatSeverityLevel, float] = {
    ThreatSeverityLevel.CRITICAL: 1.0,
    ThreatSeverityLevel.HIGH: 0.75,
    ThreatSeverityLevel.MEDIUM: 0.50,
    ThreatSeverityLevel.LOW: 0.25,
    ThreatSeverityLevel.INFO: 0.05,
}


_VERDICT_RANK: dict[DetectionVerdict, int] = {
    DetectionVerdict.ALLOW: 0,
    DetectionVerdict.BLOCK: 1,
}


_SEVERITY_RANK: dict[ThreatSeverityLevel, int] = {
    ThreatSeverityLevel.INFO: 0,
    ThreatSeverityLevel.LOW: 1,
    ThreatSeverityLevel.MEDIUM: 2,
    ThreatSeverityLevel.HIGH: 3,
    ThreatSeverityLevel.CRITICAL: 4,
}


_ENGINE_SIGNAL_PRIORITY: dict[str, int] = {
    "attack_chain": 0,
    "high_severity_cluster": 1,
}


_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_URL = re.compile(r"https?://[^\s\"'>]+")

_ENGINE_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Notification engine DI — optional, degrades gracefully
# ---------------------------------------------------------------------------


def _get_optional_notification_engine() -> NotificationEngine | None:
    """
    Returns a NotificationEngine instance if available, else None.
    Import is deferred so the detection engine never hard-depends on
    notification infrastructure being configured.
    """
    try:
        from app.services.notification_service import get_notification_engine  # noqa: PLC0415

        return get_notification_engine()
    except Exception:  # noqa: BLE001
        return None


def getoptionalnotificationengine() -> NotificationEngine | None:
    return _get_optional_notification_engine()


# ---------------------------------------------------------------------------
# ScoreResult — internal scoring container
# ---------------------------------------------------------------------------


class ScoreResult:
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
    def compute(
        self,
        ioc_matches: list[IOCMatch],
        correlation_signals: list[CorrelationSignal],
    ) -> ScoreResult:
        raw_score = self._score_iocs(ioc_matches) + self._score_signals(correlation_signals)
        normalized = min(raw_score, 1.0)

        verdict = self._verdict_from_score(normalized)
        severity = self._severity_from_score(normalized, ioc_matches)
        risk_families = self._extract_risk_families(ioc_matches, correlation_signals)
        mitre_techniques = self._extract_mitre_techniques(ioc_matches, correlation_signals)

        verdict = self._elevate_verdict_for_iocs(verdict, ioc_matches, correlation_signals)
        severity = self._elevate_severity_for_enrichment(severity, ioc_matches, correlation_signals)
        rationale = self._build_rationale(normalized, ioc_matches, correlation_signals, verdict)

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
            resolved = _coerce_severity(match.severity)
            weight = _SEVERITY_WEIGHT.get(resolved, 0.25)
            total += weight * float(match.confidence)
        return min(total / max(len(ioc_matches), 1) + (0.05 * len(ioc_matches)), 0.80)

    def _score_signals(self, signals: list[CorrelationSignal]) -> float:
        if not signals:
            return 0.0
        total = sum(float(s.score_contribution) * float(s.confidence) for s in signals)
        return min(total, 0.20)

    @staticmethod
    def _verdict_from_score(score: float) -> DetectionVerdict:
        return DetectionVerdict.ALLOW if math.isfinite(score) and score == 0 else DetectionVerdict.BLOCK

    @staticmethod
    def _severity_from_score(
        score: float,
        ioc_matches: list[IOCMatch],
    ) -> ThreatSeverityLevel:
        highest_ioc = _highest_ioc_severity(ioc_matches)
        if highest_ioc == ThreatSeverityLevel.CRITICAL:
            return ThreatSeverityLevel.CRITICAL
        if score >= 0.75:
            return ThreatSeverityLevel.CRITICAL
        if score >= 0.50:
            return highest_ioc or ThreatSeverityLevel.HIGH
        if highest_ioc == ThreatSeverityLevel.HIGH:
            return ThreatSeverityLevel.HIGH
        if score >= 0.25:
            return ThreatSeverityLevel.MEDIUM
        if score >= 0.10:
            return ThreatSeverityLevel.LOW
        return ThreatSeverityLevel.INFO

    @staticmethod
    def _extract_risk_families(
        ioc_matches: list[IOCMatch],
        signals: list[CorrelationSignal],
    ) -> list[str]:
        families: list[str] = []
        seen: set[str] = set()
        for match in ioc_matches:
            for value in _extract_match_risk_families(match):
                normalized = _normalize_collection_value(value)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    families.append(normalized)
        for sig in signals:
            normalized_name = _normalize_collection_value(_get_signal_type(sig))
            if normalized_name in {"attack_chain", "high_severity_cluster"} and normalized_name not in seen:
                seen.add(normalized_name)
                families.append(normalized_name)
        return families

    @staticmethod
    def _extract_mitre_techniques(
        ioc_matches: list[IOCMatch],
        signals: list[CorrelationSignal],
    ) -> list[str]:
        """
        Use canonical mitre_utils.aggregate_mitre_techniques to collect technique IDs
        from ioc_matches first (preserving IOC order and intra-match order),
        then from signals (including nested containers). Results are uppercase and
        deduped with first-seen preserved.
        """
        return mu.aggregate_mitre_techniques(ioc_matches, signals)

    @staticmethod
    def _elevate_verdict_for_iocs(
        verdict: DetectionVerdict,
        ioc_matches: list[IOCMatch],
        correlation_signals: list[CorrelationSignal],
    ) -> DetectionVerdict:
        if ioc_matches or correlation_signals:
            return DetectionVerdict.BLOCK
        return verdict

    @staticmethod
    def _elevate_severity_for_enrichment(
        severity: ThreatSeverityLevel,
        ioc_matches: list[IOCMatch],
        correlation_signals: list[CorrelationSignal],
    ) -> ThreatSeverityLevel:
        derived = severity
        highest_ioc = _highest_ioc_severity(ioc_matches)
        if highest_ioc is not None:
            derived = _max_severity(derived, highest_ioc)
        signal_names = {_get_signal_type(sig) for sig in correlation_signals}
        if "high_severity_cluster" in signal_names:
            derived = _max_severity(derived, ThreatSeverityLevel.HIGH)
        if "attack_chain" in signal_names and derived == ThreatSeverityLevel.INFO:
            derived = ThreatSeverityLevel.MEDIUM
        return derived

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
        high_sev = [m for m in ioc_matches if _coerce_severity(m.severity) in (ThreatSeverityLevel.CRITICAL, ThreatSeverityLevel.HIGH)]
        if high_sev:
            values = ", ".join(m.value for m in high_sev[:3])
            lines.append(f"High/critical IOC(s): {values}.")
        derived_signal_names = {_get_signal_type(sig) for sig in signals if _get_signal_type(sig)}
        if "attack_chain" in derived_signal_names:
            lines.append("Attack-chain correlation signal detected.")
        if "high_severity_cluster" in derived_signal_names:
            lines.append("High-severity IOC cluster signal detected.")
        return lines


# ---------------------------------------------------------------------------
# ThreatDetectionEngine — orchestration layer
# ---------------------------------------------------------------------------


class ThreatDetectionEngine:
    def __init__(self, scoring_engine: ThreatScoringEngine | None = None) -> None:
        self._scoring_engine = scoring_engine or ThreatScoringEngine()

    def run(
        self,
        request: DetectionRequest,
        *,
        correlation_signals: list[CorrelationSignal] | None = None,
        notification_engine: NotificationEngine | None = None,
    ) -> DetectionResult:
        event_id = request.event_id or str(uuid.uuid4())
        caller_signals: list[CorrelationSignal] = correlation_signals or []

        observables = self._extract_observables(request)

        ioc_matches = self._resolve_ioc_matches(
            observables=observables,
            org_id=request.org_id,
            minimum_confidence=request.minimum_confidence,
        )

        engine_signals = self._run_correlation(ioc_matches, event_id=event_id)
        all_signals: list[CorrelationSignal] = self._merge_correlation_signals(engine_signals, caller_signals)

        score_result: ScoreResult = self._scoring_engine.compute(ioc_matches, all_signals)

        result = DetectionResult(
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
            mitre_techniques=_dedupe_preserve_order(score_result.mitre_techniques),
            context=request.context,
            metadata=request.metadata,
            assessed_at=_utcnow_iso(),
            detection_engine_version=_ENGINE_VERSION,
        )

        resolved_notification_engine = notification_engine
        if resolved_notification_engine is None:
            resolved_notification_engine = _get_optional_notification_engine()

        if resolved_notification_engine is not None:
            try:
                notify_detection = getattr(resolved_notification_engine, "notify_detection", None)
                if notify_detection is not None:
                    notify_detection(result, org_id=request.org_id)
                else:
                    notify = getattr(resolved_notification_engine, "notify", None)
                    if notify is not None:
                        notify(result)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "threat_detection_engine.run.notify_detection error event_id=%s: %s",
                    event_id,
                    exc,
                )

        return result

    @staticmethod
    def _run_correlation(
        ioc_matches: list[IOCMatch],
        event_id: str,
    ) -> list[CorrelationSignal]:
        if not ioc_matches:
            return []
        derived_signals = ThreatDetectionEngine._derive_engine_signals(ioc_matches)
        try:
            corr_engine = get_correlation_engine()
            signals = corr_engine.correlate(ioc_matches, event_ids=[event_id])
            if not signals:
                return derived_signals
            return ThreatDetectionEngine._merge_correlation_signals(signals, derived_signals)
        except Exception as exc:
            logger.error("threat_detection_engine.run_correlation.error: %s", exc)
            return derived_signals

    @staticmethod
    def _derive_engine_signals(ioc_matches: list[IOCMatch]) -> list[CorrelationSignal]:
        if not ioc_matches:
            return []

        derived: list[CorrelationSignal] = []
        # preserve intra-match order and IOC order; mu.extract_mitre_from_source handles single+list fields
        techniques = _dedupe_preserve_order([technique for match in ioc_matches for technique in _extract_ioc_match_mitre_techniques(match)])
        high_or_critical = [match for match in ioc_matches if _coerce_severity(match.severity) in {ThreatSeverityLevel.HIGH, ThreatSeverityLevel.CRITICAL}]

        if techniques or len(ioc_matches) >= 2:
            derived.append(
                CorrelationSignal(
                    signal_id=str(uuid.uuid4()),
                    pattern_type="attack_chain",
                    signal_type="attack_chain",
                    matched_event_ids=[],
                    contributing_ioc_ids=[],
                    score_contribution=0.12 if techniques else 0.08,
                    confidence=max(float(match.confidence) for match in ioc_matches),
                    mitre_technique_ids=techniques,
                    description="",
                )
            )

        if len(high_or_critical) >= 1:
            derived.append(
                CorrelationSignal(
                    signal_id=str(uuid.uuid4()),
                    pattern_type="high_severity_cluster",
                    signal_type="high_severity_cluster",
                    matched_event_ids=[],
                    contributing_ioc_ids=[],
                    score_contribution=0.15,
                    confidence=max(float(match.confidence) for match in high_or_critical),
                    mitre_technique_ids=techniques,
                    description="",
                )
            )

        if len(ioc_matches) >= 2:
            derived.append(
                CorrelationSignal(
                    signal_id=str(uuid.uuid4()),
                    pattern_type="multi_ioc_cooccurrence",
                    signal_type="multi_ioc_cooccurrence",
                    matched_event_ids=[],
                    contributing_ioc_ids=[],
                    score_contribution=0.10,
                    confidence=max(float(match.confidence) for match in ioc_matches),
                    mitre_technique_ids=techniques,
                    description="",
                )
            )

        return derived

    @staticmethod
    def _merge_correlation_signals(
        engine_signals: list[CorrelationSignal],
        caller_signals: list[CorrelationSignal],
    ) -> list[CorrelationSignal]:
        merged: dict[str, CorrelationSignal] = {}

        def _signal_key(signal: CorrelationSignal) -> str:
            signal_type = _get_signal_type(signal)
            return signal_type or _signal_identity(signal)

        ordered_keys: list[str] = []
        engine_keys: set[str] = set()

        def _remember_key(key: str) -> None:
            if key not in ordered_keys:
                ordered_keys.append(key)

        for signal in engine_signals:
            key = _signal_key(signal)
            existing = merged.get(key)
            if existing is None:
                merged[key] = ThreatDetectionEngine._normalize_signal_instance(signal)
                engine_keys.add(key)
                _remember_key(key)
                continue
            merged[key] = ThreatDetectionEngine._merge_two_correlation_signals(existing, signal)
            engine_keys.add(key)

        for signal in caller_signals:
            key = _signal_key(signal)
            existing = merged.get(key)
            if existing is None:
                merged[key] = ThreatDetectionEngine._normalize_signal_instance(signal)
                _remember_key(key)
                continue
            merged[key] = ThreatDetectionEngine._merge_two_correlation_signals(existing, signal)

        def _signal_sort_key(item: tuple[int, CorrelationSignal]) -> tuple[int, int, int]:
            index, signal = item
            signal_type = _get_signal_type(signal)
            key = _signal_key(signal)
            is_caller_only = 1 if key not in engine_keys else 0
            priority = _ENGINE_SIGNAL_PRIORITY.get(signal_type, 99)
            return (
                is_caller_only,
                priority,
                index,
            )

        ordered = [merged[key] for key in ordered_keys]
        return [signal for _, signal in sorted(enumerate(ordered), key=_signal_sort_key)]

    @staticmethod
    def _normalize_signal_instance(signal: CorrelationSignal) -> CorrelationSignal:
        normalized = ThreatDetectionEngine._build_signal_payload(signal)
        try:
            return CorrelationSignal(**normalized)
        except Exception:
            fallback = signal
            for attr, value in normalized.items():
                try:
                    setattr(fallback, attr, value)
                except Exception:
                    pass
            return fallback

    @staticmethod
    def _merge_two_correlation_signals(
        existing: CorrelationSignal,
        incoming: CorrelationSignal,
    ) -> CorrelationSignal:
        existing_payload = ThreatDetectionEngine._build_signal_payload(existing)
        incoming_payload = ThreatDetectionEngine._build_signal_payload(incoming)

        signal_type = existing_payload["pattern_type"] or incoming_payload["pattern_type"] or _get_signal_type(existing) or _get_signal_type(incoming)

        payload = {
            "signal_id": existing_payload["signal_id"] or incoming_payload["signal_id"] or str(uuid.uuid4()),
            "pattern_type": signal_type,
            "signal_type": signal_type,
            "matched_event_ids": _dedupe_preserve_order(
                [
                    *existing_payload["matched_event_ids"],
                    *incoming_payload["matched_event_ids"],
                ]
            ),
            "contributing_ioc_ids": _dedupe_preserve_order(
                [
                    *existing_payload["contributing_ioc_ids"],
                    *incoming_payload["contributing_ioc_ids"],
                ]
            ),
            "score_contribution": max(
                float(existing_payload["score_contribution"]),
                float(incoming_payload["score_contribution"]),
            ),
            "confidence": max(
                float(existing_payload["confidence"]),
                float(incoming_payload["confidence"]),
            ),
            "mitre_technique_ids": _dedupe_preserve_order(
                [
                    *existing_payload["mitre_technique_ids"],
                    *incoming_payload["mitre_technique_ids"],
                ]
            ),
            "description": existing_payload["description"] or incoming_payload["description"] or "",
        }
        try:
            return CorrelationSignal(**payload)
        except Exception:
            fallback = existing
            for attr, value in payload.items():
                try:
                    setattr(fallback, attr, value)
                except Exception:
                    pass
            return fallback

    @staticmethod
    def _build_signal_payload(signal: CorrelationSignal) -> dict[str, Any]:
        """
        Build a normalized payload dict for a CorrelationSignal.

        Defensive extraction for MITRE technique sources:
        - Prefer canonical extractor mu.extract_mitre_from_signal which inspects top-level
          attributes and nested containers.
        - If canonical extractor misses technique(s), attempt fallbacks:
            - single attribute 'mitre_technique_id' on the signal
            - Pydantic v2 'pydantic_extra' dict
            - signal.dict()/model_dump() keys for MITRE fields
            - nested 'extra' dict on the signal (and extract from it)
        - Final result is deduped preserving first-seen order.
        """
        signal_type = _get_signal_type(signal)

        primary_techs = _extract_signal_mitre_techniques(signal) or []
        fallbacks: list[str] = []

        def _extend_from_source(source: Any) -> None:
            try:
                extracted = mu.extract_mitre_from_source(
                    source,
                    direct_attrs=("mitre_technique_id",),
                    list_attrs=("mitre_technique_ids", "mitre_techniques"),
                )
            except Exception:
                extracted = []
            if extracted:
                fallbacks.extend(extracted)

        single = _string_or_none(getattr(signal, "mitre_technique_id", None))
        if single:
            normalized_single = _normalize_mitre_value(single)
            if normalized_single:
                fallbacks.append(normalized_single)

        pydantic_extra = getattr(signal, "pydantic_extra", None)
        if isinstance(pydantic_extra, dict):
            _extend_from_source(pydantic_extra)

        try:
            signal_dict = None
            if hasattr(signal, "model_dump") and callable(signal.model_dump):
                signal_dict = signal.model_dump()
            elif hasattr(signal, "dict") and callable(signal.dict):
                signal_dict = signal.dict()
            if isinstance(signal_dict, dict):
                _extend_from_source(signal_dict)
        except Exception:
            pass

        extra = getattr(signal, "extra", None)
        if isinstance(extra, dict):
            _extend_from_source(extra)

        combined = _dedupe_preserve_order([*primary_techs, *fallbacks])

        return {
            "signal_id": _string_or_none(getattr(signal, "signal_id", None)) or str(uuid.uuid4()),
            "pattern_type": signal_type,
            "signal_type": signal_type,
            "matched_event_ids": _coerce_str_list(getattr(signal, "matched_event_ids", None)),
            "contributing_ioc_ids": _coerce_str_list(getattr(signal, "contributing_ioc_ids", None)),
            "score_contribution": _coerce_float(getattr(signal, "score_contribution", 0.0), default=0.0),
            "confidence": _coerce_float(getattr(signal, "confidence", 0.0), default=0.0),
            "mitre_technique_ids": combined,
            "description": _string_or_none(getattr(signal, "description", None)) or "",
        }

    def _extract_observables(self, request: DetectionRequest) -> list[str]:
        observables: list[str] = []
        seen: set[str] = set()

        def add(value: str | None, *, normalize_domain: bool = False) -> None:
            if not value:
                return
            stripped = value.strip()
            if not stripped:
                return
            normalized = stripped.lower() if normalize_domain else stripped
            if normalized not in seen:
                seen.add(normalized)
                observables.append(normalized)

        for v in request.ioc_values or []:
            add(v)

        for h in request.hashes or []:
            add(h)

        if request.url:
            add(request.url)

        if request.domain:
            add(request.domain, normalize_domain=True)

        if request.text:
            for item in self._extract_from_text(request.text):
                add(item, normalize_domain=not bool(_RE_URL.match(item)) and bool(_RE_DOMAIN.fullmatch(item)))

        return sorted(observables)

    @staticmethod
    def _extract_from_text(text: str) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()

        def add(value: str) -> None:
            if value not in seen:
                seen.add(value)
                found.append(value)

        for value in _RE_URL.findall(text):
            add(value)
        for value in _RE_IPV4.findall(text):
            add(value)
        for value in _RE_CVE.findall(text):
            add(value.upper())
        for value in _RE_SHA256.findall(text):
            add(value)
        for value in _RE_SHA1.findall(text):
            add(value)
        for value in _RE_MD5.findall(text):
            add(value)
        for dom in _RE_DOMAIN.findall(text):
            if not _RE_IPV4.fullmatch(dom):
                add(dom.lower())
        return found

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
            store = get_ioc_store()
            records = self._lookup_ioc_records(store, observables=observables, org_id=org_id)
        except Exception as exc:
            logger.error("threat_detection_engine.resolve_ioc_matches.error: %s", exc)
            return []

        deduped: dict[str, IOCMatch] = {}
        for rec in records:
            matches = self._record_to_ioc_matches(rec, observables=observables, minimum_confidence=minimum_confidence)
            for match in matches:
                ioc_type = _enum_like_value(getattr(match, "ioc_type", "unknown"))
                key = str(getattr(match, "ioc_id", "")).strip() or f"{getattr(match, 'value', '')}|{ioc_type}"

                existing = deduped.get(key)
                if existing is None:
                    deduped[key] = match
                    continue

                existing_severity = _coerce_severity(existing.severity)
                candidate_severity = _coerce_severity(match.severity)
                candidate_tuple = (
                    _SEVERITY_RANK[candidate_severity],
                    float(match.confidence),
                    1 if _extract_ioc_match_mitre_techniques(match) else 0,
                    len(getattr(match, "tags", []) or []),
                    str(match.value),
                )
                existing_tuple = (
                    _SEVERITY_RANK[existing_severity],
                    float(existing.confidence),
                    1 if _extract_ioc_match_mitre_techniques(existing) else 0,
                    len(getattr(existing, "tags", []) or []),
                    str(existing.value),
                )
                if candidate_tuple > existing_tuple:
                    deduped[key] = match

        return sorted(
            deduped.values(),
            key=lambda m: (
                _SEVERITY_RANK[_coerce_severity(m.severity)],
                float(m.confidence),
                str(m.value),
            ),
            reverse=True,
        )

    @staticmethod
    def _lookup_ioc_records(
        store: Any,
        *,
        observables: list[str],
        org_id: str | None,
    ) -> list[Any]:
        lookup_many = getattr(store, "lookup_by_values", None)
        records: list[Any] = []

        if callable(lookup_many):
            response = ThreatDetectionEngine._call_lookup_by_values(
                lookup_many,
                observables=observables,
                org_id=org_id,
            )
            records.extend(_coerce_lookup_records(response))

        if records:
            return records

        lookup_one = getattr(store, "lookup_by_value", None)
        if callable(lookup_one):
            for observable in observables:
                try:
                    response = ThreatDetectionEngine._call_lookup_by_value(
                        lookup_one,
                        observable=observable,
                        org_id=org_id,
                    )
                except Exception:
                    continue
                records.extend(_coerce_lookup_records(response))

        return records

    @staticmethod
    def _call_lookup_by_values(
        lookup: Any,
        *,
        observables: list[str],
        org_id: str | None,
    ) -> Any:
        attempts = (
            lambda: lookup(observables, org_id=org_id, active_only=True),
            lambda: lookup(values=observables, org_id=org_id, active_only=True),
            lambda: lookup(observables, org_id=org_id),
            lambda: lookup(values=observables, org_id=org_id),
            lambda: lookup(observables),
            lambda: lookup(values=observables),
        )
        last_exc: Exception | None = None
        for attempt in attempts:
            try:
                return attempt()
            except TypeError as exc:
                last_exc = exc
                continue
        if last_exc is not None:
            raise last_exc
        return []

    @staticmethod
    def _call_lookup_by_value(
        lookup: Any,
        *,
        observable: str,
        org_id: str | None,
    ) -> Any:
        attempts = (
            lambda: lookup(observable, org_id=org_id, active_only=True),
            lambda: lookup(value=observable, org_id=org_id, active_only=True),
            lambda: lookup(observable, org_id=org_id),
            lambda: lookup(value=observable, org_id=org_id),
            lambda: lookup(observable),
            lambda: lookup(value=observable),
        )
        last_exc: Exception | None = None
        for attempt in attempts:
            try:
                return attempt()
            except TypeError as exc:
                last_exc = exc
                continue
        if last_exc is not None:
            raise last_exc
        return []

    @staticmethod
    def _record_to_ioc_matches(
        rec: Any,
        *,
        observables: list[str],
        minimum_confidence: float,
    ) -> list[IOCMatch]:
        candidates = ThreatDetectionEngine._coerce_record_candidates(rec, observables)
        matches: list[IOCMatch] = []
        for candidate in candidates:
            match = ThreatDetectionEngine._record_to_ioc_match(candidate, minimum_confidence=minimum_confidence)
            if match is not None:
                matches.append(match)
        return matches

    @staticmethod
    def _coerce_record_candidates(rec: Any, observables: list[str]) -> list[Any]:
        candidates: list[Any] = [rec]
        observed_values = _extract_record_observable_values(rec)
        matched_values = [value for value in observed_values if value in observables]
        if matched_values:
            expanded: list[Any] = []
            for matched_value in matched_values:
                normalized_candidate = _clone_record_with_value(rec, matched_value)
                if normalized_candidate is not None:
                    expanded.append(normalized_candidate)
            if expanded:
                candidates = expanded
        return candidates

    @staticmethod
    def _record_to_ioc_match(rec: Any, *, minimum_confidence: float) -> IOCMatch | None:
        confidence = _coerce_float(getattr(rec, "confidence", 0.0), default=0.0)
        if confidence < minimum_confidence:
            return None

        value = _string_or_none(getattr(rec, "value", None))
        if not value:
            return None

        severity = _coerce_severity(getattr(rec, "severity", ThreatSeverityLevel.LOW))
        ioc_type = _enum_like_value(getattr(rec, "ioc_type", None) or getattr(rec, "type", None) or "unknown")
        source = _enum_like_value(getattr(rec, "source", None) or getattr(rec, "feed", None) or "unknown")
        tags = _coerce_str_list(getattr(rec, "tags", []))
        risk_families = _coerce_str_list(getattr(rec, "risk_families", []))
        if risk_families:
            tags = _dedupe_preserve_order([*tags, *risk_families])

        ioc_id = _string_or_none(getattr(rec, "ioc_id", None)) or f"{value}|{ioc_type}"
        # Use canonical extractor which handles single + list fields and nested containers.
        mitre_values = mu.extract_mitre_from_source(
            rec,
            direct_attrs=("mitre_technique_id",),
            list_attrs=("mitre_technique_ids", "mitre_techniques"),
        )
        mitre_technique_id = mitre_values[0] if mitre_values else None
        mitre_tactic = _string_or_none(getattr(rec, "mitre_tactic", None))
        cve_id = _string_or_none(getattr(rec, "cve_id", None))
        first_seen = _string_or_none(getattr(rec, "first_seen", None))
        last_seen = _string_or_none(getattr(rec, "last_seen", None))

        return IOCMatch(
            ioc_id=ioc_id,
            value=value,
            ioc_type=ioc_type,
            confidence=confidence,
            severity=severity.value,
            source=source,
            tags=tags,
            matched_on="ioc_store",
            mitre_technique_id=mitre_technique_id,
            mitre_tactic=mitre_tactic,
            cve_id=cve_id,
            first_seen=first_seen,
            last_seen=last_seen,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _enum_like_value(value: Any) -> str:
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _coerce_severity(value: Any) -> ThreatSeverityLevel:
    if isinstance(value, ThreatSeverityLevel):
        return value
    sev_str = str(value or "").strip()
    if "." in sev_str:
        sev_str = sev_str.split(".")[-1]
    sev_str = sev_str.lower()
    try:
        return ThreatSeverityLevel(sev_str)
    except ValueError:
        return ThreatSeverityLevel.LOW


def _highest_ioc_severity(ioc_matches: list[IOCMatch]) -> ThreatSeverityLevel | None:
    highest: ThreatSeverityLevel | None = None
    for match in ioc_matches:
        current = _coerce_severity(match.severity)
        if highest is None or _SEVERITY_RANK[current] > _SEVERITY_RANK[highest]:
            highest = current
    return highest


def _max_verdict(left: DetectionVerdict, right: DetectionVerdict) -> DetectionVerdict:
    return left if _VERDICT_RANK[left] >= _VERDICT_RANK[right] else right


def _max_severity(left: ThreatSeverityLevel, right: ThreatSeverityLevel) -> ThreatSeverityLevel:
    return left if _SEVERITY_RANK[left] >= _SEVERITY_RANK[right] else right


def _normalize_mitre_value(value: Any) -> str | None:
    # Delegates to canonical helper; preserves previous contract (uppercase or None)
    return mu.normalize_mitre(value)


def _normalize_collection_value(value: Any) -> str:
    normalized = _string_or_none(value)
    if normalized is None:
        return ""
    return normalized.lower().replace(" ", "_")


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    return mu.dedupe_preserve_order(values)


def _coerce_str_list(value: Any) -> list[str]:
    return mu.coerce_str_list(value)


def _extract_match_risk_families(match: IOCMatch) -> list[str]:
    families = _coerce_str_list(getattr(match, "risk_families", None))
    if families:
        return families
    return _coerce_str_list(getattr(match, "tags", None))


def _extract_mitre_values(
    source: Any,
    *,
    direct_attrs: tuple[str, ...] = (),
    list_attrs: tuple[str, ...] = (),
) -> list[str]:
    """
    Backwards-compatible wrapper around mu.extract_mitre_from_source.
    Accepts direct_attrs and list_attrs to control extraction keys.
    """
    return mu.extract_mitre_from_source(source, direct_attrs=direct_attrs, list_attrs=list_attrs)


def _extract_ioc_match_mitre_techniques(match: IOCMatch) -> list[str]:
    return _extract_mitre_values(
        match,
        direct_attrs=("mitre_technique_id",),
        list_attrs=("mitre_technique_ids", "mitre_techniques"),
    )


def _extract_signal_mitre_techniques(signal: CorrelationSignal) -> list[str]:
    # Delegate to canonical helper that also inspects nested containers.
    return mu.extract_mitre_from_signal(signal)


def _coerce_lookup_records(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    data = getattr(value, "data", None)
    if isinstance(data, list):
        return list(data)
    for key in ("items", "results", "rows", "records", "matches"):
        nested = getattr(value, key, None)
        if isinstance(nested, list):
            return list(nested)
        if isinstance(value, dict):
            nested_dict = value.get(key)
            if isinstance(nested_dict, list):
                return list(nested_dict)
    if isinstance(value, dict):
        return [value]
    return [value]


def _extract_record_observable_values(value: Any) -> list[str]:
    candidates: list[str] = []
    for attr in ("value", "values", "indicator", "indicator_value", "observable", "observables", "match_value", "matched_value"):
        attr_value = value.get(attr) if isinstance(value, dict) else getattr(value, attr, None)
        candidates.extend(_coerce_str_list(attr_value))
    return _dedupe_preserve_order([candidate for candidate in candidates if candidate])


def _clone_record_with_value(record: Any, value: str) -> Any | None:
    if isinstance(record, dict):
        cloned = dict(record)
        cloned["value"] = value
        return cloned
    if hasattr(record, "model_copy"):
        try:
            return record.model_copy(update={"value": value})
        except Exception:
            pass
    if hasattr(record, "copy"):
        try:
            return record.copy(update={"value": value})
        except Exception:
            pass
    if hasattr(record, "__dict__"):
        try:
            cloned = type("IOCRecordCandidate", (), {})()
            for key, item in vars(record).items():
                setattr(cloned, key, item)
            cloned.value = value
            return cloned
        except Exception:
            return None
    return None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if type(value).__module__.startswith("unittest.mock"):
        return None
    if value.__class__.__name__ in {"MagicMock", "Mock", "AsyncMock"}:
        return None
    try:
        stringified = str(value).strip()
    except Exception:
        return None
    return stringified or None


def _coerce_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _get_signal_type(signal: CorrelationSignal) -> str:
    for attr in ("pattern_type", "signal_type", "type"):
        value = _string_or_none(getattr(signal, attr, None))
        if value:
            return value.lower()
    return ""


def _signal_identity(signal: CorrelationSignal) -> str:
    return _string_or_none(getattr(signal, "signal_id", None)) or _string_or_none(getattr(signal, "description", None)) or str(id(signal))


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
        with _ENGINE_LOCK:
            if _ENGINE is None:
                _ENGINE = ThreatDetectionEngine()
    return _ENGINE


def get_detection_engine() -> ThreatDetectionEngine:
    """Return the shared ThreatDetectionEngine singleton."""
    return _get_engine()


def coercefloat(value: Any, *, default: float) -> float:
    return _coerce_float(value, default=default)


def coercelookuprecords(value: Any) -> list[Any]:
    return _coerce_lookup_records(value)


def coerceseverity(value: Any) -> ThreatSeverityLevel:
    return _coerce_severity(value)


def coercestrlist(value: Any) -> list[str]:
    return _coerce_str_list(value)


def dedupepreserveorder(values: list[str]) -> list[str]:
    return _dedupe_preserve_order(values)


def enumlikevalue(value: Any) -> str:
    return _enum_like_value(value)


def extractmatchriskfamilies(match: IOCMatch) -> list[str]:
    return _extract_match_risk_families(match)


def getcorrelationengine() -> Any:
    return get_correlation_engine()


def getdetectionengine() -> ThreatDetectionEngine:
    return get_detection_engine()


def getiocstore() -> Any:
    return get_ioc_store()


def getscoringengine() -> ThreatScoringEngine:
    return get_scoring_engine()


def highestiocseverity(ioc_matches: list[IOCMatch]) -> ThreatSeverityLevel | None:
    return _highest_ioc_severity(ioc_matches)


def maxseverity(left: ThreatSeverityLevel, right: ThreatSeverityLevel) -> ThreatSeverityLevel:
    return _max_severity(left, right)


def maxverdict(left: DetectionVerdict, right: DetectionVerdict) -> DetectionVerdict:
    return _max_verdict(left, right)


def normalizecollectionvalue(value: Any) -> str:
    return _normalize_collection_value(value)


def normalizemitrevalue(value: Any) -> str | None:
    return _normalize_mitre_value(value)


def stringornone(value: Any) -> str | None:
    return _string_or_none(value)


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------


__all__ = [
    "ScoreResult",
    "ThreatDetectionEngine",
    "ThreatScoringEngine",
    "coercefloat",
    "coercelookuprecords",
    "coerceseverity",
    "coercestrlist",
    "dedupepreserveorder",
    "enumlikevalue",
    "extractmatchriskfamilies",
    "get_correlation_engine",
    "get_detection_engine",
    "get_scoring_engine",
    "getcorrelationengine",
    "getdetectionengine",
    "getiocstore",
    "getoptionalnotificationengine",
    "getscoringengine",
    "highestiocseverity",
    "maxseverity",
    "maxverdict",
    "normalizecollectionvalue",
    "normalizemitrevalue",
    "stringornone",
]
