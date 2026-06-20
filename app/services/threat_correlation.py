from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Any
import uuid

from app.schemas.threat_detection import (
    CorrelationSignal,
    IOCMatch,
    IOCTypeEnum,
    ThreatSeverityLevel,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PATTERN_MULTI_IOC_COOCCURRENCE = "multi_ioc_cooccurrence"
_PATTERN_ATTACK_CHAIN = "attack_chain"
_PATTERN_TEMPORAL_CLUSTER = "temporal_cluster"
_PATTERN_HIGH_SEVERITY_CLUSTER = "high_severity_cluster"
_PATTERN_MITRE_CHAIN = "mitre_chain"
_PATTERN_HASH_CLUSTER = "hash_cluster"
_PATTERN_C2_CLUSTER = "c2_cluster"

_MIN_COOCCURRENCE_MATCHES = 2

_PATTERN_SCORE: dict[str, float] = {
    _PATTERN_MULTI_IOC_COOCCURRENCE: 0.08,
    _PATTERN_ATTACK_CHAIN: 0.12,
    _PATTERN_TEMPORAL_CLUSTER: 0.06,
    _PATTERN_HIGH_SEVERITY_CLUSTER: 0.10,
    _PATTERN_MITRE_CHAIN: 0.10,
    _PATTERN_HASH_CLUSTER: 0.09,
    _PATTERN_C2_CLUSTER: 0.11,
}

_C2_TAGS: frozenset[str] = frozenset({"c2", "command-and-control"})

_HASH_TYPES: frozenset[str] = frozenset(
    {
        IOCTypeEnum.SHA256,
        IOCTypeEnum.SHA1,
        IOCTypeEnum.MD5,
    }
)

_SEV_ORDER: list[str] = [
    ThreatSeverityLevel.CRITICAL,
    ThreatSeverityLevel.HIGH,
    ThreatSeverityLevel.MEDIUM,
    ThreatSeverityLevel.LOW,
    ThreatSeverityLevel.INFO,
]

_SEV_CONFIDENCE: dict[str, float] = {
    ThreatSeverityLevel.CRITICAL: 0.95,
    ThreatSeverityLevel.HIGH: 0.85,
    ThreatSeverityLevel.MEDIUM: 0.70,
    ThreatSeverityLevel.LOW: 0.50,
    ThreatSeverityLevel.INFO: 0.30,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _signal_id() -> str:
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _max_severity(matches: list[IOCMatch]) -> str:
    for sev in _SEV_ORDER:
        if any(m.severity == sev for m in matches):
            return sev
    return ThreatSeverityLevel.INFO


def _confidence_from_severity(sev: str) -> float:
    return _SEV_CONFIDENCE.get(sev, 0.50)


def _mean_confidence(matches: list[IOCMatch]) -> float:
    if not matches:
        return 0.0
    return sum(float(m.confidence) for m in matches) / len(matches)


def _ioc_ids(matches: list[IOCMatch]) -> list[str]:
    return [m.ioc_id for m in matches if m.ioc_id]


def _mitre_ids(matches: list[IOCMatch]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in matches:
        if m.mitre_technique_id and m.mitre_technique_id.upper() not in seen:
            seen.add(m.mitre_technique_id.upper())
            out.append(m.mitre_technique_id.upper())
    return out


# ---------------------------------------------------------------------------
# Signal detectors
# ---------------------------------------------------------------------------


def _detect_multi_ioc_cooccurrence(
    matches: list[IOCMatch],
    event_ids: list[str],
) -> CorrelationSignal | None:
    """Fire when >= 2 distinct IOC types appear in the same detection pass."""
    if len(matches) < _MIN_COOCCURRENCE_MATCHES:
        return None

    distinct_types: set[str] = {m.ioc_type for m in matches}
    if len(distinct_types) < 2:
        return None

    conf = min(_mean_confidence(matches) + 0.05, 1.0)
    score = _PATTERN_SCORE[_PATTERN_MULTI_IOC_COOCCURRENCE]

    return CorrelationSignal(
        signal_id=_signal_id(),
        pattern_type=_PATTERN_MULTI_IOC_COOCCURRENCE,
        matched_event_ids=list(event_ids),
        contributing_ioc_ids=_ioc_ids(matches),
        mitre_technique_ids=_mitre_ids(matches),
        confidence=round(conf, 4),
        score_contribution=score,
        description=(f"Multi-IOC cooccurrence: {len(matches)} IOCs across {len(distinct_types)} type(s) detected in a single pass."),
    )


def _detect_attack_chain(
    matches: list[IOCMatch],
    event_ids: list[str],
) -> CorrelationSignal | None:
    """
    Fire when matches span >= 2 distinct MITRE tactics OR techniques,
    suggesting a multi-stage attack chain.
    """
    tactics: set[str] = {m.mitre_tactic for m in matches if m.mitre_tactic}
    techniques: set[str] = {m.mitre_technique_id for m in matches if m.mitre_technique_id}

    if len(tactics) < 2 and len(techniques) < 2:
        return None

    sev = _max_severity(matches)
    conf = _confidence_from_severity(sev)
    score = _PATTERN_SCORE[_PATTERN_ATTACK_CHAIN]

    return CorrelationSignal(
        signal_id=_signal_id(),
        pattern_type=_PATTERN_ATTACK_CHAIN,
        matched_event_ids=list(event_ids),
        contributing_ioc_ids=_ioc_ids(matches),
        mitre_technique_ids=sorted({t.upper() for t in techniques}),
        confidence=round(conf, 4),
        score_contribution=score,
        description=(f"Attack chain detected: {len(tactics)} tactic(s), {len(techniques)} technique(s) across matched IOCs."),
    )


def _detect_high_severity_cluster(
    matches: list[IOCMatch],
    event_ids: list[str],
) -> CorrelationSignal | None:
    """Fire when >= 2 HIGH or CRITICAL severity IOCs appear together."""
    high_crit = [m for m in matches if m.severity in (ThreatSeverityLevel.HIGH, ThreatSeverityLevel.CRITICAL)]
    if len(high_crit) < 2:
        return None

    conf = _confidence_from_severity(ThreatSeverityLevel.HIGH)
    if any(m.severity == ThreatSeverityLevel.CRITICAL for m in high_crit):
        conf = _confidence_from_severity(ThreatSeverityLevel.CRITICAL)

    score = _PATTERN_SCORE[_PATTERN_HIGH_SEVERITY_CLUSTER]

    return CorrelationSignal(
        signal_id=_signal_id(),
        pattern_type=_PATTERN_HIGH_SEVERITY_CLUSTER,
        matched_event_ids=list(event_ids),
        contributing_ioc_ids=_ioc_ids(high_crit),
        mitre_technique_ids=_mitre_ids(high_crit),
        confidence=round(conf, 4),
        score_contribution=score,
        description=(f"High-severity cluster: {len(high_crit)} HIGH/CRITICAL IOC(s) codetected in a single pass."),
    )


def _detect_mitre_chain(
    matches: list[IOCMatch],
    event_ids: list[str],
) -> CorrelationSignal | None:
    """
    Fire when >= 3 distinct MITRE technique IDs are present — indicates
    a mature, multi-technique attack pattern.
    """
    techniques: set[str] = {m.mitre_technique_id.upper() for m in matches if m.mitre_technique_id}
    if len(techniques) < 3:
        return None

    sev = _max_severity(matches)
    conf = min(_confidence_from_severity(sev) + 0.05, 1.0)
    score = _PATTERN_SCORE[_PATTERN_MITRE_CHAIN]

    return CorrelationSignal(
        signal_id=_signal_id(),
        pattern_type=_PATTERN_MITRE_CHAIN,
        matched_event_ids=list(event_ids),
        contributing_ioc_ids=_ioc_ids(matches),
        mitre_technique_ids=sorted(techniques),
        confidence=round(conf, 4),
        score_contribution=score,
        description=(f"MITRE technique chain: {len(techniques)} distinct technique(s) identified across matched IOCs."),
    )


def _detect_hash_cluster(
    matches: list[IOCMatch],
    event_ids: list[str],
) -> CorrelationSignal | None:
    """Fire when >= 2 file hash IOC types (MD5/SHA1/SHA256) co-occur."""
    hash_matches = [m for m in matches if m.ioc_type in _HASH_TYPES]
    if len(hash_matches) < 2:
        return None

    sev = _max_severity(hash_matches)
    conf = _confidence_from_severity(sev)
    score = _PATTERN_SCORE[_PATTERN_HASH_CLUSTER]

    return CorrelationSignal(
        signal_id=_signal_id(),
        pattern_type=_PATTERN_HASH_CLUSTER,
        matched_event_ids=list(event_ids),
        contributing_ioc_ids=_ioc_ids(hash_matches),
        mitre_technique_ids=_mitre_ids(hash_matches),
        confidence=round(conf, 4),
        score_contribution=score,
        description=(f"Hash cluster: {len(hash_matches)} file hash IOC(s) (MD5/SHA1/SHA256) detected in a single pass."),
    )


def _detect_c2_cluster(
    matches: list[IOCMatch],
    event_ids: list[str],
) -> CorrelationSignal | None:
    """
    Fire when >= 1 IOC carries C2/command-and-control tags alongside network
    IOC types (IP or domain), indicating likely beaconing activity.
    """
    c2_matches = [m for m in matches if _C2_TAGS.intersection({t.lower() for t in m.tags})]
    network_matches = [m for m in matches if m.ioc_type in (IOCTypeEnum.IPV4, IOCTypeEnum.IPV6, IOCTypeEnum.DOMAIN, IOCTypeEnum.URL)]

    if not c2_matches or not network_matches:
        return None

    combined = list({m.ioc_id: m for m in c2_matches + network_matches if m.ioc_id}.values())
    sev = _max_severity(combined)
    conf = min(_confidence_from_severity(sev) + 0.05, 1.0)
    score = _PATTERN_SCORE[_PATTERN_C2_CLUSTER]

    return CorrelationSignal(
        signal_id=_signal_id(),
        pattern_type=_PATTERN_C2_CLUSTER,
        matched_event_ids=list(event_ids),
        contributing_ioc_ids=_ioc_ids(combined),
        mitre_technique_ids=_mitre_ids(combined),
        confidence=round(conf, 4),
        score_contribution=score,
        description=(f"C2 cluster: {len(c2_matches)} C2-tagged IOC(s) co-detected with {len(network_matches)} network-type IOC(s)."),
    )


# ---------------------------------------------------------------------------
# ThreatCorrelationEngine
# ---------------------------------------------------------------------------


class ThreatCorrelationEngine:
    """
    Pure correlation layer.

    Accepts resolved IOCMatch lists and optional caller-supplied event IDs,
    runs all signal detectors, and returns a list of CorrelationSignal objects
    with .confidence and .score_contribution fully populated.

    Guarantees:
    - Every returned CorrelationSignal has confidence in [0.0, 1.0].
    - Every returned CorrelationSignal has score_contribution in [0.0, 1.0].
    - No I/O, no Supabase calls — deterministic given the same inputs.

    Consumed by:
    - app.services.threat_detection_engine.ThreatDetectionEngine (injects signals into pipeline)
    - app.services.threat_scoring.score_correlation_signals (scores the signal list)
    """

    def correlate(
        self,
        ioc_matches: list[IOCMatch],
        *,
        event_ids: list[str] | None = None,
    ) -> list[CorrelationSignal]:
        """
        Run all correlation detectors against the resolved IOCMatch list.

        Parameters
        ----------
        ioc_matches:
            Resolved IOCMatch objects from the detection engine.
        event_ids:
            Optional caller-supplied event IDs to attach to signals for
            cross-event correlation traceability.

        Returns
        -------
        list[CorrelationSignal]
            Detected correlation signals.  May be empty if no patterns fire.
        """
        if not ioc_matches:
            return []

        eids: list[str] = event_ids or []
        signals: list[CorrelationSignal] = []

        detectors = [
            _detect_multi_ioc_cooccurrence,
            _detect_attack_chain,
            _detect_high_severity_cluster,
            _detect_mitre_chain,
            _detect_hash_cluster,
            _detect_c2_cluster,
        ]

        for detector in detectors:
            try:
                result = detector(ioc_matches, eids)
                if result is not None:
                    signals.append(result)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "threat_correlation.detector_error detector=%s error=%s",
                    detector.__name__,
                    exc,
                )

        logger.debug(
            "threat_correlation.correlate ioc_count=%d signals_fired=%d",
            len(ioc_matches),
            len(signals),
        )
        return signals

    def summarize(self, signals: list[CorrelationSignal]) -> dict[str, Any]:
        """
        Return a summary dict for telemetry and logging.

        Keys:
            signal_count        — total signals produced
            pattern_types       — deduplicated list of pattern type labels
            total_score_contribution — sum of all signal score_contributions
            max_confidence      — highest confidence across all signals
        """
        if not signals:
            return {
                "signal_count": 0,
                "pattern_types": [],
                "total_score_contribution": 0.0,
                "max_confidence": 0.0,
            }

        pattern_types = sorted({s.pattern_type for s in signals})
        total_score = sum(s.score_contribution for s in signals)
        max_conf = max(s.confidence for s in signals)

        return {
            "signal_count": len(signals),
            "pattern_types": pattern_types,
            "total_score_contribution": round(total_score, 4),
            "max_confidence": round(max_conf, 4),
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_CORRELATION_ENGINE: ThreatCorrelationEngine | None = None


def get_correlation_engine() -> ThreatCorrelationEngine:
    """Return the shared ThreatCorrelationEngine singleton."""
    global _CORRELATION_ENGINE  # noqa: PLW0603
    if _CORRELATION_ENGINE is None:
        _CORRELATION_ENGINE = ThreatCorrelationEngine()
    return _CORRELATION_ENGINE


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = [
    "ThreatCorrelationEngine",
    "get_correlation_engine",
]
