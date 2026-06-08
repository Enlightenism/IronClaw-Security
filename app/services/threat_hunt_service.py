from __future__ import annotations

from datetime import UTC, datetime
import logging
import time
from typing import Any
import uuid

from app.core.supabase import get_supabase_service_client
from app.schemas.threat_detection import (
    DetectionVerdict,
    HuntMatch,
    HuntQuery,
    HuntResult,
    HuntStatusEnum,
    ThreatSeverityLevel,
)

logger = logging.getLogger(__name__)

_TABLE_DETECTIONS = "threat_detections"


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _get_supabase_client() -> Any:
    return get_supabase_service_client()


class ThreatHuntService:
    """
    Retrospective threat hunt engine for IronClaw-Security.

    Sweeps stored detection history (threat_detections table) for matching
    IOC values, MITRE techniques, CVE identifiers, or risk families within
    an optional time window.  Produces a fully-typed HuntResult without
    duplicating logic owned by ThreatDetectionEngine or IOCStore.
    """

    def run_hunt(self, query: HuntQuery, *, org_id: str | None = None) -> HuntResult:
        hunt_id = query.hunt_id or str(uuid.uuid4())
        effective_org_id = org_id if org_id is not None else query.org_id
        started_at = _utcnow_iso()
        t0 = time.monotonic()
        errors: list[str] = []

        try:
            client = _get_supabase_client()
        except Exception as exc:
            logger.warning(
                "threat_hunt_service.run_hunt: supabase client unavailable hunt_id=%s: %s",
                hunt_id,
                exc,
            )
            return HuntResult(
                hunt_id=hunt_id,
                org_id=effective_org_id,
                status=HuntStatusEnum.FAILED,
                total_matches=0,
                matches=[],
                query_summary=self._build_query_summary(query),
                executed_at=started_at,
                duration_ms=0,
                errors=["Supabase client unavailable."],
            )

        if client is None:
            logger.warning(
                "threat_hunt_service.run_hunt: supabase client unavailable hunt_id=%s",
                hunt_id,
            )
            return HuntResult(
                hunt_id=hunt_id,
                org_id=effective_org_id,
                status=HuntStatusEnum.FAILED,
                total_matches=0,
                matches=[],
                query_summary=self._build_query_summary(query),
                executed_at=started_at,
                duration_ms=0,
                errors=["Supabase client unavailable."],
            )

        try:
            rows = self._query_detections(client, query, effective_org_id)
        except Exception as exc:
            logger.error("threat_hunt_service.run_hunt.error hunt_id=%s: %s", hunt_id, exc)
            duration_ms = int((time.monotonic() - t0) * 1000)
            return HuntResult(
                hunt_id=hunt_id,
                org_id=effective_org_id,
                status=HuntStatusEnum.FAILED,
                total_matches=0,
                matches=[],
                query_summary=self._build_query_summary(query),
                executed_at=started_at,
                duration_ms=duration_ms,
                errors=[str(exc)],
            )

        matches: list[HuntMatch] = []
        for row in rows:
            match = self._row_to_hunt_match(row, query)
            if match is not None:
                matches.append(match)

        duration_ms = int((time.monotonic() - t0) * 1000)

        logger.info(
            "threat_hunt_service.run_hunt hunt_id=%s org_id=%s matches=%d duration_ms=%d",
            hunt_id,
            effective_org_id,
            len(matches),
            duration_ms,
        )

        return HuntResult(
            hunt_id=hunt_id,
            org_id=effective_org_id,
            status=HuntStatusEnum.COMPLETED,
            total_matches=len(matches),
            matches=matches,
            query_summary=self._build_query_summary(query),
            executed_at=started_at,
            duration_ms=duration_ms,
            errors=errors,
        )

    def _query_detections(
        self,
        client: Any,
        query: HuntQuery,
        org_id: str | None,
    ) -> list[dict[str, Any]]:
        q = client.table(_TABLE_DETECTIONS).select("event_id,org_id,agent_id,session_id,verdict,score,severity," "assessed_at,context,risk_families,extracted_indicators," "mitre_techniques,ioc_match_count,correlation_signal_count")

        if org_id is not None:
            q = q.eq("org_id", org_id)

        if query.minimum_score > 0.0:
            q = q.gte("score", query.minimum_score)

        if query.start_time is not None:
            q = q.gte("assessed_at", query.start_time.isoformat())

        if query.end_time is not None:
            q = q.lte("assessed_at", query.end_time.isoformat())

        q = q.order("assessed_at", desc=True).range(query.offset, query.offset + query.limit - 1)

        resp = q.execute()
        return resp.data if resp and resp.data else []

    def _row_to_hunt_match(
        self,
        row: dict[str, Any],
        query: HuntQuery,
    ) -> HuntMatch | None:
        risk_families: list[str] = row.get("risk_families") or []
        mitre_techniques: list[str] = row.get("mitre_techniques") or []
        extracted_indicators: list[str] = row.get("extracted_indicators") or []

        matched_ioc_value: str | None = None
        matched_ioc_type: str | None = None
        matched_mitre_technique: str | None = None

        if query.ioc_value is not None:
            needle = query.ioc_value.lower().strip()
            hit = any(needle == ind.lower().strip() for ind in extracted_indicators)
            if not hit:
                return None
            matched_ioc_value = query.ioc_value
            matched_ioc_type = query.ioc_type.value if query.ioc_type else None

        if query.mitre_technique_id is not None:
            needle = query.mitre_technique_id.upper().strip()
            hit = any(needle == t.upper().strip() for t in mitre_techniques)
            if not hit:
                return None
            matched_mitre_technique = query.mitre_technique_id

        if query.cve_id is not None:
            needle = query.cve_id.upper().strip()
            hit = any(needle == ind.upper().strip() for ind in extracted_indicators)
            if not hit:
                return None
            if matched_ioc_value is None:
                matched_ioc_value = query.cve_id
                matched_ioc_type = "cve"

        if query.risk_family is not None:
            needle = query.risk_family.lower().strip()
            hit = any(needle == rf.lower().strip() for rf in risk_families)
            if not hit:
                return None

        try:
            verdict = DetectionVerdict(row["verdict"])
        except (KeyError, ValueError):
            verdict = DetectionVerdict.MONITOR

        try:
            severity = ThreatSeverityLevel(row["severity"])
        except (KeyError, ValueError):
            severity = ThreatSeverityLevel.LOW

        confidence = min(1.0, max(0.0, float(row.get("score", 0.0))))

        return HuntMatch(
            event_id=row["event_id"],
            org_id=row.get("org_id"),
            agent_id=row.get("agent_id"),
            session_id=row.get("session_id"),
            verdict=verdict,
            score=confidence,
            severity=severity,
            matched_ioc_value=matched_ioc_value,
            matched_ioc_type=matched_ioc_type,
            matched_mitre_technique=matched_mitre_technique,
            risk_families=risk_families,
            context=row.get("context"),
            assessed_at=row.get("assessed_at", _utcnow_iso()),
            confidence=confidence,
        )

    @staticmethod
    def _build_query_summary(query: HuntQuery) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        if query.ioc_value is not None:
            summary["ioc_value"] = query.ioc_value
        if query.ioc_type is not None:
            summary["ioc_type"] = query.ioc_type.value
        if query.mitre_technique_id is not None:
            summary["mitre_technique_id"] = query.mitre_technique_id
        if query.cve_id is not None:
            summary["cve_id"] = query.cve_id
        if query.risk_family is not None:
            summary["risk_family"] = query.risk_family
        if query.start_time is not None:
            summary["start_time"] = query.start_time.isoformat()
        if query.end_time is not None:
            summary["end_time"] = query.end_time.isoformat()
        summary["minimum_score"] = query.minimum_score
        summary["limit"] = query.limit
        summary["offset"] = query.offset
        return summary


_hunt_service_instance: ThreatHuntService | None = None


def get_hunt_service() -> ThreatHuntService:
    global _hunt_service_instance
    if _hunt_service_instance is None:
        _hunt_service_instance = ThreatHuntService()
    return _hunt_service_instance


get_threat_hunt_service = get_hunt_service

__all__ = ["ThreatHuntService", "get_hunt_service", "get_threat_hunt_service", "_get_supabase_client"]
