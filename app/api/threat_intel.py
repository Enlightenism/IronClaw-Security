from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import uuid

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.schemas.threat_detection import (
    DetectionRequest,
    DetectionResult,
    DetectionVerdict,
    IOCMatch,
    ThreatSeverityLevel,
)
from app.services.threat_intel import (
    ThreatIntelFeed,
    ThreatIntelMatch,
    ThreatIntelScanResult,
    initialize_default_threat_feed,
    scan_text_against_threat_feed,
    summarize_threat_scan_result,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _ThreatIntelState:
    feed: ThreatIntelFeed
    last_scan_result: ThreatIntelScanResult | None = None


_STATE = _ThreatIntelState(feed=initialize_default_threat_feed())


# ---------------------------------------------------------------------------
# Local response models with no schema counterpart
# ---------------------------------------------------------------------------


class ThreatIntelFeedResponse(BaseModel):
    feed_id: str
    name: str
    source: str
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelScanSummaryResponse(BaseModel):
    checked_at: str
    match_count: int
    highest_severity: str
    severity_counts: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Severity mapping — ThreatIntelMatch.severity (str) → ThreatSeverityLevel
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, ThreatSeverityLevel] = {
    "critical": ThreatSeverityLevel.CRITICAL,
    "high": ThreatSeverityLevel.HIGH,
    "medium": ThreatSeverityLevel.MEDIUM,
    "low": ThreatSeverityLevel.LOW,
}

_SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _severity_to_enum(value: str) -> ThreatSeverityLevel:
    return _SEVERITY_MAP.get(value.lower(), ThreatSeverityLevel.LOW)


# ---------------------------------------------------------------------------
# Mappers — internal dataclasses → canonical schema shapes
# ---------------------------------------------------------------------------


def _build_ioc_match(match: ThreatIntelMatch) -> IOCMatch:
    return IOCMatch(
        ioc_id=match.indicator_id,
        value=match.value,
        ioc_type=match.indicator_type,
        confidence=round(match.metadata.get("confidence", 50) / 100, 4),
        severity=_severity_to_enum(match.severity).value,
        source=match.metadata.get("source", "internal"),
        tags=match.metadata.get("tags", []),
        matched_on=match.matched_on,
        mitre_technique_id=None,
        mitre_tactic=None,
        cve_id=None,
        reference=None,
        first_seen=None,
        last_seen=None,
    )


def _build_detection_result(
    result: ThreatIntelScanResult,
    event_id: str,
    org_id: str | None,
    agent_id: str | None,
    scanned_text: str | None,
) -> DetectionResult:
    ioc_matches = [_build_ioc_match(m) for m in result.matches]

    severity = _severity_to_enum(result.highest_severity)

    if not ioc_matches:
        verdict = DetectionVerdict.ALLOW
    elif severity in (ThreatSeverityLevel.CRITICAL, ThreatSeverityLevel.HIGH):
        verdict = DetectionVerdict.BLOCK
    elif severity == ThreatSeverityLevel.MEDIUM:
        verdict = DetectionVerdict.REVIEW
    else:
        verdict = DetectionVerdict.MONITOR

    score_map = {
        ThreatSeverityLevel.CRITICAL: 1.0,
        ThreatSeverityLevel.HIGH: 0.75,
        ThreatSeverityLevel.MEDIUM: 0.5,
        ThreatSeverityLevel.LOW: 0.25,
        ThreatSeverityLevel.INFO: 0.1,
    }
    score = score_map.get(severity, 0.0) if ioc_matches else 0.0

    return DetectionResult(
        event_id=event_id,
        org_id=org_id,
        agent_id=agent_id,
        session_id=None,
        verdict=verdict,
        score=score,
        severity=severity,
        scanned_text=scanned_text,
        ioc_matches=ioc_matches,
        correlation_signals=[],
        risk_families=list({tag for m in result.matches for tag in m.metadata.get("tags", [])}),
        extracted_indicators=[m.value for m in result.matches],
        rationale=[m.reason for m in result.matches],
        mitre_techniques=[],
        context=result.metadata.get("feed_id"),
        metadata=dict(result.metadata),
        assessed_at=result.checked_at,
        detection_engine_version="1.0.0",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/feed", response_model=ThreatIntelFeedResponse)
def get_threat_intel_feed() -> ThreatIntelFeedResponse:
    data = _STATE.feed.to_dict()
    return ThreatIntelFeedResponse(
        feed_id=data["feed_id"],
        name=data["name"],
        source=data["source"],
        indicators=data["indicators"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        metadata=data["metadata"],
    )


@router.post("/scan", response_model=DetectionResult)
def scan_threat_intel(request: DetectionRequest) -> DetectionResult:
    text = " ".join(
        filter(
            None,
            [
                request.text,
                request.url,
                request.domain,
                " ".join(request.hashes or []),
                " ".join(request.ioc_values or []),
            ],
        )
    )
    result = scan_text_against_threat_feed(text, _STATE.feed)
    _STATE.last_scan_result = result
    event_id = request.event_id or f"evt-{uuid.uuid4().hex}"
    return _build_detection_result(
        result,
        event_id,
        request.org_id,
        request.agent_id,
        scanned_text=request.text,
    )


@router.get("/scan/summary", response_model=ThreatIntelScanSummaryResponse)
def get_last_threat_intel_scan_summary() -> ThreatIntelScanSummaryResponse:
    result = _STATE.last_scan_result
    if result is None:
        return ThreatIntelScanSummaryResponse(
            checked_at="",
            match_count=0,
            highest_severity=ThreatSeverityLevel.LOW.value,
            severity_counts={},
        )
    summary = summarize_threat_scan_result(result)
    return ThreatIntelScanSummaryResponse(
        checked_at=summary["checked_at"],
        match_count=summary["match_count"],
        highest_severity=summary["highest_severity"],
        severity_counts=summary["severity_counts"],
    )
