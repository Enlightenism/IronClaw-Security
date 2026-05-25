from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Any
from uuid import uuid4

from app.schemas.threat_detection import (
    AlertSeverityEnum,
    DetectionVerdict,
    HuntMatch,
    HuntResult,
    HuntStatusEnum,
    ThreatAlert,
    ThreatSeverityLevel,
)
from app.services.alertstore import SecurityAlertStore, build_alert_store

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level alert store — single source of truth for this service layer
# ---------------------------------------------------------------------------

_alert_store: SecurityAlertStore | None = None


def _get_alert_store() -> SecurityAlertStore:
    global _alert_store
    if _alert_store is None:
        _alert_store = build_alert_store()
    return _alert_store


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_DETECTION_TO_ALERT_SEVERITY: dict[str, AlertSeverityEnum] = {
    ThreatSeverityLevel.INFO.value: AlertSeverityEnum.LOW,
    ThreatSeverityLevel.LOW.value: AlertSeverityEnum.LOW,
    ThreatSeverityLevel.MEDIUM.value: AlertSeverityEnum.MEDIUM,
    ThreatSeverityLevel.HIGH.value: AlertSeverityEnum.HIGH,
    ThreatSeverityLevel.CRITICAL.value: AlertSeverityEnum.CRITICAL,
}


def _map_severity(severity_value: str) -> AlertSeverityEnum:
    return _DETECTION_TO_ALERT_SEVERITY.get(
        severity_value.lower() if isinstance(severity_value, str) else "",
        AlertSeverityEnum.MEDIUM,
    )


def _peak_severity(matches: list[HuntMatch]) -> AlertSeverityEnum:
    """Return the highest alert severity observed across all hunt matches."""
    peak = AlertSeverityEnum.LOW
    peak_rank = 0
    for match in matches:
        candidate = _map_severity(match.severity.value if hasattr(match.severity, "value") else str(match.severity))
        rank = _SEVERITY_ORDER.get(candidate.value, 0)
        if rank > peak_rank:
            peak_rank = rank
            peak = candidate
    return peak


def _peak_verdict(matches: list[HuntMatch]) -> DetectionVerdict:
    """Return the most severe verdict observed across all hunt matches."""
    _VERDICT_ORDER: dict[str, int] = {
        DetectionVerdict.ALLOW.value: 0,
        DetectionVerdict.MONITOR.value: 1,
        DetectionVerdict.REVIEW.value: 2,
        DetectionVerdict.BLOCK.value: 3,
    }
    peak = DetectionVerdict.MONITOR
    peak_rank = 0
    for match in matches:
        v = match.verdict.value if hasattr(match.verdict, "value") else str(match.verdict)
        rank = _VERDICT_ORDER.get(v, 0)
        if rank > peak_rank:
            peak_rank = rank
            peak = match.verdict if isinstance(match.verdict, DetectionVerdict) else DetectionVerdict(v)
    return peak


def _peak_score(matches: list[HuntMatch]) -> float:
    if not matches:
        return 0.0
    return max(m.score for m in matches)


# ---------------------------------------------------------------------------
# Suppression window — deduplication guard
# ---------------------------------------------------------------------------

_SUPPRESSION_WINDOW_SECONDS: int = 300  # 5 minutes

_suppression_registry: dict[str, float] = {}


def _suppression_key(result: HuntResult) -> str:
    org = result.org_id or "global"
    ioc = result.query_summary.get("ioc_value", "")
    mitre = result.query_summary.get("mitre_technique_id", "")
    cve = result.query_summary.get("cve_id", "")
    risk = result.query_summary.get("risk_family", "")
    return f"hunt:{org}:{ioc}:{mitre}:{cve}:{risk}"


def _is_suppressed(key: str, now_ts: float) -> bool:
    last_seen = _suppression_registry.get(key)
    if last_seen is None:
        return False
    return (now_ts - last_seen) < _SUPPRESSION_WINDOW_SECONDS


def _register_suppression(key: str, now_ts: float) -> None:
    _suppression_registry[key] = now_ts


def _prune_suppression_registry(now_ts: float) -> None:
    expired = [k for k, ts in _suppression_registry.items() if (now_ts - ts) >= _SUPPRESSION_WINDOW_SECONDS]
    for k in expired:
        del _suppression_registry[k]


# ---------------------------------------------------------------------------
# Title builder
# ---------------------------------------------------------------------------


def _build_hunt_alert_title(result: HuntResult) -> str:
    qs = result.query_summary or {}
    parts: list[str] = []
    if qs.get("ioc_value"):
        parts.append(f"IOC match: {qs['ioc_value']}")
    if qs.get("mitre_technique_id"):
        parts.append(f"MITRE {qs['mitre_technique_id']}")
    if qs.get("cve_id"):
        parts.append(f"CVE {qs['cve_id']}")
    if qs.get("risk_family"):
        parts.append(f"risk family '{qs['risk_family']}'")
    label = ", ".join(parts) if parts else "threat hunt"
    return f"Threat hunt completed with {result.total_matches} match(es) — {label}"


def _build_hunt_alert_description(result: HuntResult) -> str:
    lines: list[str] = [
        f"Hunt ID: {result.hunt_id}",
        f"Total matches: {result.total_matches}",
        f"Status: {result.status.value if hasattr(result.status, 'value') else result.status}",
        f"Executed at: {result.executed_at}",
    ]
    if result.duration_ms is not None:
        lines.append(f"Duration: {result.duration_ms}ms")
    if result.errors:
        lines.append(f"Hunt errors: {'; '.join(result.errors)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core: build ThreatAlert from HuntResult
# ---------------------------------------------------------------------------


def _build_hunt_threat_alert(result: HuntResult) -> ThreatAlert:
    matches = result.matches or []
    severity = _peak_severity(matches)
    verdict = _peak_verdict(matches)
    score = _peak_score(matches)

    mitre_techniques: list[str] = []
    risk_families: list[str] = []
    seen_mitre: set[str] = set()
    seen_risk: set[str] = set()

    for match in matches:
        if match.matched_mitre_technique and match.matched_mitre_technique not in seen_mitre:
            mitre_techniques.append(match.matched_mitre_technique)
            seen_mitre.add(match.matched_mitre_technique)
        for rf in match.risk_families:
            if rf not in seen_risk:
                risk_families.append(rf)
                seen_risk.add(rf)

    now_iso = datetime.now(UTC).isoformat()

    metadata: dict[str, Any] = {
        "hunt_id": result.hunt_id,
        "total_matches": result.total_matches,
        "executed_at": result.executed_at,
        "duration_ms": result.duration_ms,
        "query_summary": result.query_summary,
        "hunt_errors": result.errors,
        "source": "threat_hunt",
    }

    return ThreatAlert(
        alert_id=f"hunt-alert-{uuid4().hex[:12]}",
        event_id=result.hunt_id,
        org_id=result.org_id,
        agent_id=None,
        session_id=None,
        verdict=verdict,
        severity=severity,
        score=score,
        title=_build_hunt_alert_title(result),
        description=_build_hunt_alert_description(result),
        ioc_matches=[],
        correlation_signals=[],
        mitre_techniques=mitre_techniques,
        risk_families=risk_families,
        suppressed=False,
        suppression_reason=None,
        incident_id=None,
        created_at=now_iso,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Core: persist ThreatAlert into SecurityAlertStore
# ---------------------------------------------------------------------------


def _persist_hunt_alert(alert: ThreatAlert) -> dict[str, Any] | None:
    store = _get_alert_store()
    try:
        record = store.create_alert(
            alert_id=alert.alert_id,
            title=alert.title,
            summary=alert.description,
            description=alert.description,
            severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            verdict=alert.verdict.value if hasattr(alert.verdict, "value") else str(alert.verdict),
            category="threat_hunt",
            alert_type="threat_hunt",
            source="ironclaw_hunt",
            organization_id=alert.org_id,
            org_id=alert.org_id,
            scan_id=alert.event_id,
            metadata=alert.metadata,
            evidence=[],
            tags=alert.risk_families + alert.mitre_techniques,
            suppressed=alert.suppressed,
            created_at=alert.created_at,
            updated_at=alert.created_at,
        )
        return record
    except Exception as exc:
        logger.error(
            "threat_alerts.persist_hunt_alert alert_id=%s error=%s",
            alert.alert_id,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Core: attempt incident escalation (fail-open)
# ---------------------------------------------------------------------------


def _maybe_escalate_to_incident(alert: ThreatAlert) -> str | None:
    """Attempt to escalate a hunt alert to an incident. Returns incident_id or None."""
    try:
        from app.services.incident_service import get_incident_service  # type: ignore[import]

        service = get_incident_service()
        incident = service.create_from_alert(
            alert_id=alert.alert_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            org_id=alert.org_id,
            metadata=alert.metadata,
        )
        if incident:
            incident_id = str(incident.get("incident_id") or incident.get("id") or "")
            if incident_id:
                logger.info(
                    "threat_alerts.hunt_escalation alert_id=%s incident_id=%s",
                    alert.alert_id,
                    incident_id,
                )
                return incident_id
    except Exception as exc:
        logger.debug(
            "threat_alerts.hunt_escalation skipped alert_id=%s reason=%s",
            alert.alert_id,
            exc,
        )
    return None


# ---------------------------------------------------------------------------
# Core: attempt notification dispatch (fail-open)
# ---------------------------------------------------------------------------


def _maybe_notify(alert: ThreatAlert) -> None:
    try:
        from app.services.notification_service import get_notification_service  # type: ignore[import]

        service = get_notification_service()
        dispatch = getattr(service, "dispatch_threat_alert", None)
        if callable(dispatch):
            dispatch(alert)
    except Exception as exc:
        logger.debug(
            "threat_alerts.notify skipped alert_id=%s reason=%s",
            alert.alert_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Public API: emit_hunt_alert
# ---------------------------------------------------------------------------


def emit_hunt_alert(result: HuntResult) -> ThreatAlert | None:
    """
    Emit a ThreatAlert for a completed HuntResult that has at least one match.

    Contract:
    - Returns None if result.total_matches == 0 or status is not COMPLETED.
    - Returns None if the alert is suppressed within the deduplication window.
    - Persists the alert into SecurityAlertStore (alertstore.py).
    - Attempts incident escalation via incident_service (fail-open).
    - Attempts notification dispatch via notification_service (fail-open).
    - Never raises — all failures are logged and swallowed.
    """
    try:
        if result.status != HuntStatusEnum.COMPLETED:
            logger.debug(
                "threat_alerts.emit_hunt_alert skipped hunt_id=%s status=%s (not COMPLETED)",
                result.hunt_id,
                result.status,
            )
            return None

        if result.total_matches == 0:
            logger.debug(
                "threat_alerts.emit_hunt_alert skipped hunt_id=%s total_matches=0",
                result.hunt_id,
            )
            return None

        now_ts = datetime.now(UTC).timestamp()
        _prune_suppression_registry(now_ts)

        sup_key = _suppression_key(result)
        if _is_suppressed(sup_key, now_ts):
            logger.info(
                "threat_alerts.emit_hunt_alert suppressed hunt_id=%s key=%s",
                result.hunt_id,
                sup_key,
            )
            return None

        _register_suppression(sup_key, now_ts)

        alert = _build_hunt_threat_alert(result)

        persisted = _persist_hunt_alert(alert)
        if persisted:
            persisted_id = persisted.get("alert_id") or persisted.get("id")
            if persisted_id and persisted_id != alert.alert_id:
                alert = alert.model_copy(update={"alert_id": str(persisted_id)})

        incident_id = _maybe_escalate_to_incident(alert)
        if incident_id:
            alert = alert.model_copy(update={"incident_id": incident_id})

        _maybe_notify(alert)

        logger.info(
            "threat_alerts.emit_hunt_alert emitted alert_id=%s hunt_id=%s matches=%d severity=%s verdict=%s org_id=%s",
            alert.alert_id,
            result.hunt_id,
            result.total_matches,
            alert.severity.value if hasattr(alert.severity, "value") else alert.severity,
            alert.verdict.value if hasattr(alert.verdict, "value") else alert.verdict,
            result.org_id,
        )

        return alert

    except Exception as exc:
        logger.error(
            "threat_alerts.emit_hunt_alert unhandled error hunt_id=%s: %s",
            getattr(result, "hunt_id", "unknown"),
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Public API: emit_detection_alert (bridge for DetectionResult escalations)
# ---------------------------------------------------------------------------


def emit_detection_alert(
    event_id: str,
    *,
    org_id: str | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    verdict: DetectionVerdict,
    severity: ThreatSeverityLevel,
    score: float,
    title: str,
    description: str = "",
    ioc_matches: list[Any] | None = None,
    correlation_signals: list[Any] | None = None,
    mitre_techniques: list[str] | None = None,
    risk_families: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ThreatAlert | None:
    """
    Emit a ThreatAlert for a DetectionResult that requires REVIEW or BLOCK action.

    Contract:
    - Only REVIEW and BLOCK verdicts are escalated; others return None.
    - Persists into SecurityAlertStore.
    - Attempts incident escalation and notification dispatch (both fail-open).
    - Never raises.
    """
    try:
        if verdict not in (DetectionVerdict.REVIEW, DetectionVerdict.BLOCK):
            return None

        now_iso = datetime.now(UTC).isoformat()
        now_ts = datetime.now(UTC).timestamp()
        _prune_suppression_registry(now_ts)

        sup_key = f"detect:{org_id or 'global'}:{event_id}"
        if _is_suppressed(sup_key, now_ts):
            logger.info(
                "threat_alerts.emit_detection_alert suppressed event_id=%s",
                event_id,
            )
            return None
        _register_suppression(sup_key, now_ts)

        alert_severity = _map_severity(severity.value if hasattr(severity, "value") else str(severity))

        alert = ThreatAlert(
            alert_id=f"detect-alert-{uuid4().hex[:12]}",
            event_id=event_id,
            org_id=org_id,
            agent_id=agent_id,
            session_id=session_id,
            verdict=verdict,
            severity=alert_severity,
            score=score,
            title=title,
            description=description,
            ioc_matches=list(ioc_matches or []),
            correlation_signals=list(correlation_signals or []),
            mitre_techniques=list(mitre_techniques or []),
            risk_families=list(risk_families or []),
            suppressed=False,
            suppression_reason=None,
            incident_id=None,
            created_at=now_iso,
            metadata=dict(metadata or {}),
        )

        _persist_hunt_alert(alert)

        incident_id = _maybe_escalate_to_incident(alert)
        if incident_id:
            alert = alert.model_copy(update={"incident_id": incident_id})

        _maybe_notify(alert)

        logger.info(
            "threat_alerts.emit_detection_alert emitted alert_id=%s event_id=%s verdict=%s severity=%s",
            alert.alert_id,
            event_id,
            verdict.value,
            alert_severity.value,
        )

        return alert

    except Exception as exc:
        logger.error(
            "threat_alerts.emit_detection_alert unhandled error event_id=%s: %s",
            event_id,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Accessor for tests and DI
# ---------------------------------------------------------------------------


def get_threat_alert_store() -> SecurityAlertStore:
    """Return the active SecurityAlertStore used by this service."""
    return _get_alert_store()


def reset_threat_alert_store() -> None:
    """Reset the module-level store reference. Intended for tests only."""
    global _alert_store
    _alert_store = None
