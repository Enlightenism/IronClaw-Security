from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

DEFAULT_INCIDENT_STATUS = "open"
DEFAULT_INCIDENT_SEVERITY = "medium"
ESCALATED_INCIDENT_SEVERITY = "high"
CRITICAL_INCIDENT_SEVERITY = "critical"


@dataclass(slots=True)
class IncidentRecord:
    incident_id: str
    created_at: str
    updated_at: str
    status: str
    severity: str
    risk_score: int
    client_id: str
    session_id: str
    source: str
    summary: str
    reason: str
    review_item_id: str | None = None
    matched_patterns: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _derive_severity(risk_score: int) -> str:
    if risk_score >= 90:
        return CRITICAL_INCIDENT_SEVERITY
    if risk_score >= 75:
        return ESCALATED_INCIDENT_SEVERITY
    return DEFAULT_INCIDENT_SEVERITY


def _build_incident_id(source: str, session_id: str, created_at: str) -> str:
    normalized_source = (source or "incident").replace(" ", "_").lower()
    normalized_session = (session_id or "unknown").replace(" ", "_").lower()
    compact_time = created_at.replace(":", "").replace("-", "").replace(".", "")
    return f"{normalized_source}-{normalized_session}-{compact_time}"


def create_incident_record(payload: dict[str, Any]) -> IncidentRecord:
    created_at = _utc_now()
    updated_at = created_at

    risk_score = _safe_int(payload.get("risk_score"), 0)
    source = str(payload.get("source") or "security_runtime")
    session_id = str(payload.get("session_id") or "")
    client_id = str(payload.get("client_id") or "")
    summary = str(payload.get("summary") or payload.get("reason") or "Security incident detected")
    reason = str(payload.get("reason") or "Security incident recorded by incident service")
    incident_id = str(payload.get("incident_id") or _build_incident_id(source, session_id, created_at))

    raw_patterns = payload.get("matched_patterns") or []
    matched_patterns = [str(item) for item in raw_patterns] if isinstance(raw_patterns, list) else [str(raw_patterns)]

    raw_failed_checks = payload.get("failed_checks") or []
    failed_checks = [str(item) for item in raw_failed_checks] if isinstance(raw_failed_checks, list) else [str(raw_failed_checks)]

    return IncidentRecord(
        incident_id=incident_id,
        created_at=created_at,
        updated_at=updated_at,
        status=str(payload.get("status") or DEFAULT_INCIDENT_STATUS),
        severity=str(payload.get("severity") or _derive_severity(risk_score)),
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        source=source,
        summary=summary,
        reason=reason,
        review_item_id=str(payload["review_item_id"]) if payload.get("review_item_id") is not None else None,
        matched_patterns=matched_patterns,
        failed_checks=failed_checks,
        payload=dict(payload),
        metadata={"service": "incident_service"},
    )


def summarize_incident_record(payload: dict[str, Any]) -> dict[str, Any]:
    return create_incident_record(payload).to_dict()


__all__ = [
    "CRITICAL_INCIDENT_SEVERITY",
    "DEFAULT_INCIDENT_SEVERITY",
    "DEFAULT_INCIDENT_STATUS",
    "ESCALATED_INCIDENT_SEVERITY",
    "IncidentRecord",
    "create_incident_record",
    "summarize_incident_record",
]
