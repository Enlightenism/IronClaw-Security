from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.threat_intel import (
    ThreatIntelFeed,
    ThreatIntelMatch,
    ThreatIntelScanResult,
    initialize_default_threat_feed,
    scan_text_against_threat_feed,
    summarize_threat_scan_result,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@dataclass(slots=True)
class _ThreatIntelState:
    feed: ThreatIntelFeed
    last_scan_result: ThreatIntelScanResult | None = None


_STATE = _ThreatIntelState(feed=initialize_default_threat_feed())


class ThreatIntelScanRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        description="Text to scan against the threat intel feed.",
    )


class ThreatIntelMatchResponse(BaseModel):
    indicator_id: str
    indicator_type: str
    value: str
    severity: str
    matched_on: str
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelScanResponse(BaseModel):
    scanned_text: str
    checked_at: str
    matches: list[ThreatIntelMatchResponse] = Field(default_factory=list)
    highest_severity: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelScanSummaryResponse(BaseModel):
    checked_at: str
    match_count: int
    highest_severity: str
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ThreatIntelFeedResponse(BaseModel):
    feed_id: str
    name: str
    source: str
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_match_response(match: ThreatIntelMatch) -> ThreatIntelMatchResponse:
    return ThreatIntelMatchResponse(
        indicator_id=match.indicator_id,
        indicator_type=match.indicator_type,
        value=match.value,
        severity=match.severity,
        matched_on=match.matched_on,
        reason=match.reason,
        metadata=dict(match.metadata),
    )


def _build_scan_response(result: ThreatIntelScanResult) -> ThreatIntelScanResponse:
    return ThreatIntelScanResponse(
        scanned_text=result.scanned_text,
        checked_at=result.checked_at,
        matches=[_build_match_response(match) for match in result.matches],
        highest_severity=result.highest_severity,
        metadata=dict(result.metadata),
    )


@router.get("/feed", response_model=ThreatIntelFeedResponse)
def get_threat_intel_feed() -> ThreatIntelFeedResponse:
    feed = _STATE.feed
    data = feed.to_dict()
    return ThreatIntelFeedResponse(
        feed_id=data["feed_id"],
        name=data["name"],
        source=data["source"],
        indicators=data["indicators"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        metadata=data["metadata"],
    )


@router.post("/scan", response_model=ThreatIntelScanResponse)
def scan_threat_intel(request: ThreatIntelScanRequest) -> ThreatIntelScanResponse:
    result = scan_text_against_threat_feed(request.text, _STATE.feed)
    _STATE.last_scan_result = result
    return _build_scan_response(result)


@router.get("/scan/summary", response_model=ThreatIntelScanSummaryResponse)
def get_last_threat_intel_scan_summary() -> ThreatIntelScanSummaryResponse:
    result = _STATE.last_scan_result
    if result is None:
        return ThreatIntelScanSummaryResponse(
            checked_at="",
            match_count=0,
            highest_severity="low",
            severity_counts={},
        )

    summary = summarize_threat_scan_result(result)
    return ThreatIntelScanSummaryResponse(
        checked_at=summary["checked_at"],
        match_count=summary["match_count"],
        highest_severity=summary["highest_severity"],
        severity_counts=summary["severity_counts"],
    )