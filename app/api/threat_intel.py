from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.schemas.threat_detection import (
    DetectionRequest,
    DetectionResult,
    DetectionVerdict,
    IOCMatch,
    IOCResponse,
    ThreatSeverityLevel,
)
from app.services.threat_feed_ingestion import (
    IOCFilterRequest,
    IOCRecord,
    get_threat_feed_service,
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
# Module state — legacy in-memory feed (keyword/pattern scanning only)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _ThreatIntelState:
    feed: ThreatIntelFeed
    last_scan_result: ThreatIntelScanResult | None = None


_STATE = _ThreatIntelState(feed=initialize_default_threat_feed())


# ---------------------------------------------------------------------------
# Local response models
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


class IOCLookupResponse(BaseModel):
    value: str
    matches: list[IOCResponse]
    match_count: int


# ---------------------------------------------------------------------------
# Severity mapping
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
# Mappers
# ---------------------------------------------------------------------------


def _ioc_record_to_response(r: IOCRecord) -> IOCResponse:
    return IOCResponse(
        ioc_id=r.ioc_id,
        ioc_type=r.ioc_type,
        value=r.value,
        source=r.source,
        severity=r.severity,
        confidence=r.confidence,
        tags=r.tags,
        description=r.description,
        org_id=r.org_id,
        mitre_technique_id=r.mitre_technique_id,
        mitre_tactic=r.mitre_tactic,
        cve_id=r.cve_id,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
        expiry=r.expiry,
        active=r.active,
        feed_ingest_id=r.feed_ingest_id,
        extra=r.extra,
    )


def _build_ioc_match_from_record(r: IOCRecord) -> IOCMatch:
    return IOCMatch(
        ioc_id=r.ioc_id,
        value=r.value,
        ioc_type=r.ioc_type,
        confidence=r.confidence,
        severity=r.severity,
        source=r.source,
        tags=r.tags,
        matched_on="ioc_store_lookup",
        mitre_technique_id=r.mitre_technique_id,
        mitre_tactic=r.mitre_tactic,
        cve_id=r.cve_id,
        reference=None,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
    )


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
    store_matches: list[IOCMatch],
    event_id: str,
    org_id: str | None,
    agent_id: str | None,
    scanned_text: str | None,
) -> DetectionResult:
    feed_matches = [_build_ioc_match(m) for m in result.matches]
    ioc_matches = feed_matches + store_matches

    # Derive highest severity across all match sources
    all_severities = [m.severity for m in ioc_matches]
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    top_severity_str = max(all_severities, key=lambda s: severity_rank.get(s, 0)) if all_severities else result.highest_severity
    severity = _severity_to_enum(top_severity_str)

    verdict = DetectionVerdict.BLOCK if ioc_matches else DetectionVerdict.ALLOW

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
        risk_families=list({tag for m in ioc_matches for tag in m.tags}),
        extracted_indicators=[m.value for m in ioc_matches],
        rationale=[
            *[m.reason for m in result.matches],
            *[f"store_match:{m.ioc_id}" for m in store_matches],
        ],
        mitre_techniques=list({m.mitre_technique_id for m in ioc_matches if m.mitre_technique_id}),
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
    store = get_threat_feed_service()
    event_id = request.event_id or f"evt-{uuid.uuid4().hex}"

    # Build flat text for legacy keyword/pattern scan
    text = " ".join(
        filter(
            None,
            [
                request.text,
                request.url,
                request.domain,
                " ".join(request.hashes or []),
            ],
        )
    )

    # Legacy feed scan (keyword + pattern)
    result = scan_text_against_threat_feed(text, _STATE.feed)
    _STATE.last_scan_result = result

    # Persistent store lookups for explicit IOC values + url/domain/hashes
    store_matches: list[IOCMatch] = []
    lookup_candidates: list[str] = list(request.ioc_values or [])
    if request.url:
        lookup_candidates.append(request.url)
    if request.domain:
        lookup_candidates.append(request.domain)
    if request.hashes:
        lookup_candidates.extend(request.hashes)

    for candidate in lookup_candidates:
        records = store.lookup_by_value(candidate, org_id=request.org_id)
        for r in records:
            if r.confidence >= request.minimum_confidence:
                store_matches.append(_build_ioc_match_from_record(r))

    return _build_detection_result(
        result,
        store_matches,
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


@router.get("/ioc/{ioc_id}", response_model=IOCResponse)
def get_ioc(ioc_id: str) -> IOCResponse:
    store = get_threat_feed_service()
    record = store.get_ioc(ioc_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {ioc_id}")
    return _ioc_record_to_response(record)


@router.get("/ioc/lookup/value", response_model=IOCLookupResponse)
def lookup_ioc_by_value(
    value: str = Query(..., description="IOC value to look up (IP, domain, hash, CVE, MITRE technique, etc.)"),
    org_id: str | None = Query(default=None, description="Org scope filter"),
) -> IOCLookupResponse:
    store = get_threat_feed_service()
    records = store.lookup_by_value(value, org_id=org_id)
    responses = [_ioc_record_to_response(r) for r in records]
    return IOCLookupResponse(value=value, matches=responses, match_count=len(responses))


@router.get("/iocs", response_model=list[IOCResponse])
def filter_iocs(
    source: str | None = Query(default=None),
    ioc_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    org_id: str | None = Query(default=None),
    active: bool | None = Query(default=None),
    tag: str | None = Query(default=None),
    mitre_technique_id: str | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    value_contains: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[IOCResponse]:
    store = get_threat_feed_service()
    req = IOCFilterRequest(
        source=source,
        ioc_type=ioc_type,
        severity=severity,
        org_id=org_id,
        active=active,
        tag=tag,
        mitre_technique_id=mitre_technique_id,
        cve_id=cve_id,
        value_contains=value_contains,
        limit=limit,
        offset=offset,
    )
    records = store.filter_iocs(req)
    return [_ioc_record_to_response(r) for r in records]
