from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from pydantic import ValidationError
import pytest

from app.schemas.threat_detection import (
    DetectionVerdict,
    HuntMatch,
    HuntQuery,
    HuntResult,
    HuntStatusEnum,
    IOCTypeEnum,
    ThreatSeverityLevel,
)
from app.services.threat_hunt_service import ThreatHuntService, get_threat_hunt_service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_NOW = datetime.now(UTC)
_ISO_NOW = _NOW.isoformat()


def _make_row(
    event_id: str = "evt-001",
    verdict: str = "block",
    score: float = 0.85,
    severity: str = "high",
    org_id: str | None = "org-test",
    agent_id: str | None = "agent-1",
    session_id: str | None = "sess-1",
    risk_families: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    extracted_indicators: list[str] | None = None,
    cve_ids: list[str] | None = None,
    context: str | None = "tool_call",
    assessed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "org_id": org_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "verdict": verdict,
        "score": score,
        "severity": severity,
        "assessed_at": assessed_at or _ISO_NOW,
        "context": context,
        "risk_families": risk_families or [],
        "extracted_indicators": extracted_indicators or [],
        "mitre_techniques": mitre_techniques or [],
        "cve_ids": cve_ids or [],
        "ioc_match_count": 1,
        "correlation_signal_count": 0,
    }


def _make_query(**kwargs: Any) -> HuntQuery:
    base: dict[str, Any] = {"ioc_value": "192.0.2.1", "ioc_type": IOCTypeEnum.IPV4}
    base.update(kwargs)
    return HuntQuery(**base)


def _mock_client(rows: list[dict[str, Any]]) -> MagicMock:
    resp = MagicMock()
    resp.data = rows
    chain = MagicMock()
    chain.execute.return_value = resp
    chain.select.return_value = chain
    chain.eq.return_value = chain
    chain.gte.return_value = chain
    chain.lte.return_value = chain
    chain.order.return_value = chain
    chain.range.return_value = chain
    client = MagicMock()
    client.table.return_value = chain
    return client


def _inject_query_backend(
    service: ThreatHuntService,
    backend: Any,
) -> ThreatHuntService:
    service._query_backend = backend  # type: ignore[attr-defined]
    return service


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def service() -> ThreatHuntService:
    return ThreatHuntService()


# ===========================================================================
# ThreatHuntService.run_hunt — supabase unavailable
# ===========================================================================


class TestRunHuntClientUnavailable:
    def test_returns_failed_status_when_client_none(self, service: ThreatHuntService) -> None:
        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            query = _make_query()
            result = service.run_hunt(query)

        assert result.status == HuntStatusEnum.FAILED
        assert result.total_matches == 0
        assert result.matches == []
        assert len(result.errors) > 0
        assert "unavailable" in result.errors[0].lower()

    def test_failed_result_carries_hunt_id(self, service: ThreatHuntService) -> None:
        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            query = _make_query(hunt_id="hunt-fail-001")
            result = service.run_hunt(query)

        assert result.hunt_id == "hunt-fail-001"

    def test_failed_result_carries_org_id(self, service: ThreatHuntService) -> None:
        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            query = _make_query(org_id="org-x")
            result = service.run_hunt(query)

        assert result.org_id == "org-x"

    def test_uses_test_backend_when_supabase_unavailable(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["192.0.2.1"])
        _inject_query_backend(service, lambda query, org_id: [row])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            result = service.run_hunt(_make_query())

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.errors == []

    def test_test_backend_preferred_even_when_client_acquisition_raises(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["192.0.2.1"])
        _inject_query_backend(service, lambda query, org_id: [row])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing env"),
        ):
            result = service.run_hunt(_make_query())

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.errors == []


# ===========================================================================
# ThreatHuntService.run_hunt — query_detections raises
# ===========================================================================


class TestRunHuntQueryError:
    def test_returns_failed_on_query_exception(self, service: ThreatHuntService) -> None:
        def _boom(query: HuntQuery, org_id: str | None) -> list[dict[str, Any]]:
            raise RuntimeError("DB exploded")

        _inject_query_backend(service, _boom)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert result.status == HuntStatusEnum.FAILED
        assert result.total_matches == 0
        assert any("DB exploded" in e for e in result.errors)
        assert not any("missing SUPABASE_URL" in e for e in result.errors)

    def test_duration_ms_is_set_on_query_error(self, service: ThreatHuntService) -> None:
        def _boom(query: HuntQuery, org_id: str | None) -> list[dict[str, Any]]:
            raise RuntimeError("boom")

        _inject_query_backend(service, _boom)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert result.duration_ms is not None
        assert result.duration_ms >= 0

    def test_test_backend_exception_surfaces_in_errors(self, service: ThreatHuntService) -> None:
        def _boom(query: HuntQuery, org_id: str | None) -> list[dict[str, Any]]:
            raise RuntimeError("DB exploded")

        _inject_query_backend(service, _boom)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            result = service.run_hunt(_make_query())

        assert result.status == HuntStatusEnum.FAILED
        assert any("DB exploded" in e for e in result.errors)


# ===========================================================================
# ThreatHuntService.run_hunt — successful sweep
# ===========================================================================


class TestRunHuntSuccess:
    def test_completed_status_on_success(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["192.0.2.1"])
        _inject_query_backend(service, lambda query, org_id: [row])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert result.status == HuntStatusEnum.COMPLETED

    def test_match_count_equals_total_matches(self, service: ThreatHuntService) -> None:
        rows = [
            _make_row(event_id="evt-001", extracted_indicators=["192.0.2.1"]),
            _make_row(event_id="evt-002", extracted_indicators=["192.0.2.1"]),
        ]
        _inject_query_backend(service, lambda query, org_id: rows)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert result.total_matches == 2
        assert len(result.matches) == 2

    def test_empty_rows_yields_zero_matches(self, service: ThreatHuntService) -> None:
        _inject_query_backend(service, lambda query, org_id: [])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 0
        assert result.matches == []
        assert result.errors == []

    def test_duration_ms_is_non_negative_on_success(self, service: ThreatHuntService) -> None:
        _inject_query_backend(service, lambda query, org_id: [])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert result.duration_ms is not None
        assert result.duration_ms >= 0

    def test_executed_at_is_iso_string(self, service: ThreatHuntService) -> None:
        _inject_query_backend(service, lambda query, org_id: [])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        datetime.fromisoformat(result.executed_at)

    def test_errors_list_empty_on_success(self, service: ThreatHuntService) -> None:
        _inject_query_backend(service, lambda query, org_id: [])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert result.errors == []

    def test_org_override_filters_result_rows(self, service: ThreatHuntService) -> None:
        rows = [
            _make_row(event_id="evt-001", org_id="org-a", extracted_indicators=["192.0.2.1"]),
            _make_row(event_id="evt-002", org_id="org-b", extracted_indicators=["192.0.2.1"]),
        ]
        _inject_query_backend(service, lambda query, org_id: rows)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            result = service.run_hunt(_make_query(org_id="org-b"), org_id="org-a")

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.matches[0].event_id == "evt-001"
        assert result.org_id == "org-a"
        assert result.errors == []

    def test_cve_ids_field_matches_cve_query(self, service: ThreatHuntService) -> None:
        row = _make_row(cve_ids=["CVE-2025-0001"])
        _inject_query_backend(service, lambda query, org_id: [row])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            result = service.run_hunt(HuntQuery(cve_id="CVE-2025-0001"))

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.matches[0].matched_ioc_value == "CVE-2025-0001"
        assert result.matches[0].matched_ioc_type == "cve"
        assert result.errors == []


# ===========================================================================
# ThreatHuntService._row_to_hunt_match — IOC value matching
# ===========================================================================


class TestRowToHuntMatchIOC:
    def _call(
        self,
        service: ThreatHuntService,
        row: dict[str, Any],
        query: HuntQuery,
    ) -> HuntMatch | None:
        return service._row_to_hunt_match(row, query)

    def test_ioc_exact_match_returns_hunt_match(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["192.0.2.1"])
        query = _make_query(ioc_value="192.0.2.1", ioc_type=IOCTypeEnum.IPV4)
        match = self._call(service, row, query)

        assert match is not None
        assert match.matched_ioc_value == "192.0.2.1"
        assert match.matched_ioc_type == IOCTypeEnum.IPV4.value

    def test_ioc_case_insensitive_match(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["EVIL.example.com"])
        query = _make_query(ioc_value="evil.example.com", ioc_type=IOCTypeEnum.DOMAIN)
        match = self._call(service, row, query)

        assert match is not None

    def test_ioc_mismatch_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["10.0.0.1"])
        query = _make_query(ioc_value="192.0.2.99")
        match = self._call(service, row, query)

        assert match is None

    def test_ioc_empty_indicators_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=[])
        query = _make_query(ioc_value="192.0.2.1")
        match = self._call(service, row, query)

        assert match is None

    def test_ioc_missing_indicators_key_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row()
        row.pop("extracted_indicators", None)
        query = _make_query(ioc_value="192.0.2.1")
        match = self._call(service, row, query)

        assert match is None

    def test_org_id_mismatch_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(org_id="org-b", extracted_indicators=["192.0.2.1"])
        query = _make_query(ioc_value="192.0.2.1")
        match = service._row_to_hunt_match(row, query, "org-a")

        assert match is None


# ===========================================================================
# ThreatHuntService._row_to_hunt_match — MITRE technique matching
# ===========================================================================


class TestRowToHuntMatchMITRE:
    def _call(
        self,
        service: ThreatHuntService,
        row: dict[str, Any],
        query: HuntQuery,
    ) -> HuntMatch | None:
        return service._row_to_hunt_match(row, query)

    def test_mitre_exact_match_returns_hunt_match(self, service: ThreatHuntService) -> None:
        row = _make_row(mitre_techniques=["T1059"])
        query = HuntQuery(mitre_technique_id="T1059")
        match = self._call(service, row, query)

        assert match is not None
        assert match.matched_mitre_technique == "T1059"

    def test_mitre_case_insensitive(self, service: ThreatHuntService) -> None:
        row = _make_row(mitre_techniques=["t1059"])
        query = HuntQuery(mitre_technique_id="T1059")
        match = self._call(service, row, query)

        assert match is not None

    def test_mitre_mismatch_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(mitre_techniques=["T1078"])
        query = HuntQuery(mitre_technique_id="T1059")
        match = self._call(service, row, query)

        assert match is None

    def test_mitre_empty_techniques_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(mitre_techniques=[])
        query = HuntQuery(mitre_technique_id="T1059")
        match = self._call(service, row, query)

        assert match is None


# ===========================================================================
# ThreatHuntService._row_to_hunt_match — CVE matching
# ===========================================================================


class TestRowToHuntMatchCVE:
    def _call(
        self,
        service: ThreatHuntService,
        row: dict[str, Any],
        query: HuntQuery,
    ) -> HuntMatch | None:
        return service._row_to_hunt_match(row, query)

    def test_cve_exact_match_returns_hunt_match(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["CVE-2024-1234"])
        query = HuntQuery(cve_id="CVE-2024-1234")
        match = self._call(service, row, query)

        assert match is not None
        assert match.matched_ioc_value == "CVE-2024-1234"
        assert match.matched_ioc_type == "cve"

    def test_cve_case_insensitive(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["cve-2024-1234"])
        query = HuntQuery(cve_id="CVE-2024-1234")
        match = self._call(service, row, query)

        assert match is not None

    def test_cve_mismatch_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["CVE-2024-9999"])
        query = HuntQuery(cve_id="CVE-2024-1234")
        match = self._call(service, row, query)

        assert match is None

    def test_cve_matches_cve_ids_field(self, service: ThreatHuntService) -> None:
        row = _make_row(cve_ids=["CVE-2024-1234"])
        query = HuntQuery(cve_id="CVE-2024-1234")
        match = self._call(service, row, query)

        assert match is not None
        assert match.matched_ioc_value == "CVE-2024-1234"
        assert match.matched_ioc_type == "cve"


# ===========================================================================
# ThreatHuntService._row_to_hunt_match — risk_family matching
# ===========================================================================


class TestRowToHuntMatchRiskFamily:
    def _call(
        self,
        service: ThreatHuntService,
        row: dict[str, Any],
        query: HuntQuery,
    ) -> HuntMatch | None:
        return service._row_to_hunt_match(row, query)

    def test_risk_family_exact_match(self, service: ThreatHuntService) -> None:
        row = _make_row(risk_families=["command_and_control"])
        query = HuntQuery(risk_family="command_and_control")
        match = self._call(service, row, query)

        assert match is not None

    def test_risk_family_case_insensitive(self, service: ThreatHuntService) -> None:
        row = _make_row(risk_families=["Command_And_Control"])
        query = HuntQuery(risk_family="command_and_control")
        match = self._call(service, row, query)

        assert match is not None

    def test_risk_family_mismatch_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(risk_families=["exfiltration"])
        query = HuntQuery(risk_family="command_and_control")
        match = self._call(service, row, query)

        assert match is None

    def test_risk_family_empty_returns_none(self, service: ThreatHuntService) -> None:
        row = _make_row(risk_families=[])
        query = HuntQuery(risk_family="command_and_control")
        match = self._call(service, row, query)

        assert match is None


# ===========================================================================
# ThreatHuntService._row_to_hunt_match — HuntMatch field integrity
# ===========================================================================


class TestHuntMatchFieldIntegrity:
    def test_match_verdict_is_deserialized_correctly(self, service: ThreatHuntService) -> None:
        row = _make_row(verdict="block", extracted_indicators=["192.0.2.1"])
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.verdict == DetectionVerdict.BLOCK

    def test_match_severity_is_deserialized_correctly(self, service: ThreatHuntService) -> None:
        row = _make_row(severity="critical", extracted_indicators=["192.0.2.1"])
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.severity == ThreatSeverityLevel.CRITICAL

    def test_match_confidence_clamped_to_one(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["192.0.2.1"])
        row["score"] = 1.5
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.confidence <= 1.0

    def test_match_confidence_min_zero(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["192.0.2.1"])
        row["score"] = -0.5
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.confidence >= 0.0

    def test_match_event_id_preserved(self, service: ThreatHuntService) -> None:
        row = _make_row(event_id="unique-evt-xyz", extracted_indicators=["192.0.2.1"])
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.event_id == "unique-evt-xyz"

    def test_match_org_id_preserved(self, service: ThreatHuntService) -> None:
        row = _make_row(org_id="org-42", extracted_indicators=["192.0.2.1"])
        query = _make_query(org_id="org-42")
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.org_id == "org-42"

    def test_match_risk_families_carried_through(self, service: ThreatHuntService) -> None:
        row = _make_row(
            extracted_indicators=["192.0.2.1"],
            risk_families=["lateral_movement", "exfiltration"],
        )
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert "lateral_movement" in match.risk_families
        assert "exfiltration" in match.risk_families

    def test_invalid_verdict_falls_back_to_monitor(self, service: ThreatHuntService) -> None:
        row = _make_row(verdict="totally_invalid", extracted_indicators=["192.0.2.1"])
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.verdict == DetectionVerdict.MONITOR

    def test_invalid_severity_falls_back_to_low(self, service: ThreatHuntService) -> None:
        row = _make_row(severity="not_a_level", extracted_indicators=["192.0.2.1"])
        query = _make_query()
        match = service._row_to_hunt_match(row, query)

        assert match is not None
        assert match.severity == ThreatSeverityLevel.LOW


# ===========================================================================
# ThreatHuntService._build_query_summary
# ===========================================================================


class TestBuildQuerySummary:
    def test_ioc_value_included_in_summary(self) -> None:
        query = _make_query(ioc_value="10.0.0.1", ioc_type=IOCTypeEnum.IPV4)
        summary = ThreatHuntService._build_query_summary(query)

        assert summary["ioc_value"] == "10.0.0.1"
        assert summary["ioc_type"] == IOCTypeEnum.IPV4.value

    def test_mitre_included_in_summary(self) -> None:
        query = HuntQuery(mitre_technique_id="T1059")
        summary = ThreatHuntService._build_query_summary(query)

        assert summary["mitre_technique_id"] == "T1059"
        assert "ioc_value" not in summary

    def test_cve_included_in_summary(self) -> None:
        query = HuntQuery(cve_id="CVE-2024-5678")
        summary = ThreatHuntService._build_query_summary(query)

        assert summary["cve_id"] == "CVE-2024-5678"

    def test_risk_family_included_in_summary(self) -> None:
        query = HuntQuery(risk_family="exfiltration")
        summary = ThreatHuntService._build_query_summary(query)

        assert summary["risk_family"] == "exfiltration"

    def test_minimum_score_always_present(self) -> None:
        query = HuntQuery(risk_family="exfiltration", minimum_score=0.6)
        summary = ThreatHuntService._build_query_summary(query)

        assert summary["minimum_score"] == 0.6

    def test_limit_and_offset_always_present(self) -> None:
        query = HuntQuery(risk_family="exfiltration", limit=50, offset=10)
        summary = ThreatHuntService._build_query_summary(query)

        assert summary["limit"] == 50
        assert summary["offset"] == 10

    def test_time_window_included_in_summary(self) -> None:
        start = datetime.now(UTC) - timedelta(hours=1)
        end = datetime.now(UTC)
        query = HuntQuery(
            ioc_value="192.0.2.1",
            start_time=start,
            end_time=end,
        )
        summary = ThreatHuntService._build_query_summary(query)

        assert "start_time" in summary
        assert "end_time" in summary

    def test_absent_fields_not_in_summary(self) -> None:
        query = HuntQuery(risk_family="exfiltration")
        summary = ThreatHuntService._build_query_summary(query)

        assert "ioc_value" not in summary
        assert "mitre_technique_id" not in summary
        assert "cve_id" not in summary
        assert "start_time" not in summary
        assert "end_time" not in summary


# ===========================================================================
# HuntQuery schema validation
# ===========================================================================


class TestHuntQueryValidation:
    def test_requires_at_least_one_dimension(self) -> None:
        with pytest.raises(ValidationError):
            HuntQuery()

    def test_ioc_value_alone_is_valid(self) -> None:
        q = HuntQuery(ioc_value="192.0.2.1")
        assert q.ioc_value == "192.0.2.1"

    def test_mitre_alone_is_valid(self) -> None:
        q = HuntQuery(mitre_technique_id="T1059")
        assert q.mitre_technique_id == "T1059"

    def test_cve_alone_is_valid(self) -> None:
        q = HuntQuery(cve_id="CVE-2024-0001")
        assert q.cve_id == "CVE-2024-0001"

    def test_risk_family_alone_is_valid(self) -> None:
        q = HuntQuery(risk_family="exfiltration")
        assert q.risk_family == "exfiltration"

    def test_minimum_score_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            HuntQuery(ioc_value="x", minimum_score=1.5)

    def test_minimum_score_lower_bound(self) -> None:
        with pytest.raises(ValidationError):
            HuntQuery(ioc_value="x", minimum_score=-0.1)

    def test_limit_lower_bound(self) -> None:
        with pytest.raises(ValidationError):
            HuntQuery(ioc_value="x", limit=0)

    def test_limit_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            HuntQuery(ioc_value="x", limit=1001)

    def test_offset_non_negative(self) -> None:
        with pytest.raises(ValidationError):
            HuntQuery(ioc_value="x", offset=-1)

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            HuntQuery(ioc_value="x", unknown_field="bad")

    def test_ioc_type_is_optional(self) -> None:
        q = HuntQuery(ioc_value="10.0.0.1")
        assert q.ioc_type is None

    def test_org_id_is_optional(self) -> None:
        q = HuntQuery(ioc_value="10.0.0.1")
        assert q.org_id is None

    def test_hunt_id_is_optional(self) -> None:
        q = HuntQuery(ioc_value="10.0.0.1")
        assert q.hunt_id is None


# ===========================================================================
# get_threat_hunt_service singleton
# ===========================================================================


class TestGetThreatHuntService:
    def test_returns_threat_hunt_service_instance(self) -> None:
        svc = get_threat_hunt_service()
        assert isinstance(svc, ThreatHuntService)

    def test_returns_same_instance_on_repeated_calls(self) -> None:
        svc1 = get_threat_hunt_service()
        svc2 = get_threat_hunt_service()
        assert svc1 is svc2


# ===========================================================================
# ThreatHuntService._query_detections — Supabase chain verification
# ===========================================================================


class TestQueryDetectionsChain:
    def test_org_id_filter_applied_when_set(self, service: ThreatHuntService) -> None:
        client = _mock_client([])
        query = HuntQuery(ioc_value="x", org_id="org-filter")
        service._query_detections_from_supabase(client, query, "org-filter")
        chain = client.table.return_value
        chain.eq.assert_called_once_with("org_id", "org-filter")

    def test_org_id_filter_skipped_when_none(self, service: ThreatHuntService) -> None:
        client = _mock_client([])
        query = HuntQuery(ioc_value="x")
        service._query_detections_from_supabase(client, query, None)
        chain = client.table.return_value
        chain.eq.assert_not_called()

    def test_minimum_score_filter_applied(self, service: ThreatHuntService) -> None:
        client = _mock_client([])
        query = HuntQuery(ioc_value="x", minimum_score=0.5)
        service._query_detections_from_supabase(client, query, None)
        chain = client.table.return_value
        chain.gte.assert_any_call("score", 0.5)

    def test_time_window_filters_applied(self, service: ThreatHuntService) -> None:
        start = datetime.now(UTC) - timedelta(hours=2)
        end = datetime.now(UTC)
        client = _mock_client([])
        query = HuntQuery(ioc_value="x", start_time=start, end_time=end)
        service._query_detections_from_supabase(client, query, None)
        chain = client.table.return_value
        chain.gte.assert_any_call("assessed_at", start.isoformat())
        chain.lte.assert_any_call("assessed_at", end.isoformat())

    def test_returns_empty_list_on_none_data(self, service: ThreatHuntService) -> None:
        resp = MagicMock()
        resp.data = None
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.gte.return_value = chain
        chain.lte.return_value = chain
        chain.order.return_value = chain
        chain.range.return_value = chain
        client = MagicMock()
        client.table.return_value = chain

        query = HuntQuery(ioc_value="x")
        rows = service._query_detections_from_supabase(client, query, None)
        assert rows == []

    def test_returns_empty_list_on_falsy_response(self, service: ThreatHuntService) -> None:
        chain = MagicMock()
        chain.execute.return_value = None
        chain.select.return_value = chain
        chain.order.return_value = chain
        chain.range.return_value = chain
        client = MagicMock()
        client.table.return_value = chain

        query = HuntQuery(ioc_value="x")
        rows = service._query_detections_from_supabase(client, query, None)
        assert rows == []


# ===========================================================================
# ThreatHuntService._query_detections — backend resolution
# ===========================================================================


class TestQueryDetectionsBackendResolution:
    def test_prefers_test_backend_over_supabase(self, service: ThreatHuntService) -> None:
        rows = [_make_row(extracted_indicators=["192.0.2.1"])]
        _inject_query_backend(service, lambda query, org_id: rows)

        client = _mock_client([])
        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=client,
        ):
            result = service._query_detections(_make_query(), None)

        assert result == rows
        client.table.assert_not_called()

    def test_raises_unavailable_when_no_backend(self, service: ThreatHuntService) -> None:
        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            with pytest.raises(RuntimeError, match="Supabase client unavailable."):
                service._query_detections(_make_query(), None)

    def test_propagates_test_backend_query_error(self, service: ThreatHuntService) -> None:
        def _boom(query: HuntQuery, org_id: str | None) -> list[dict[str, Any]]:
            raise RuntimeError("DB exploded")

        _inject_query_backend(service, _boom)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            with pytest.raises(RuntimeError, match="DB exploded"):
                service._query_detections(_make_query(), None)

    def test_accepts_positional_test_backend_signature(self, service: ThreatHuntService) -> None:
        rows = [_make_row(extracted_indicators=["192.0.2.1"])]

        def _backend(query: HuntQuery, org_id: str | None) -> list[dict[str, Any]]:
            return rows

        _inject_query_backend(service, _backend)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            result = service._query_detections(_make_query(), "org-a")

        assert result == rows

    def test_accepts_single_argument_test_backend_signature(self, service: ThreatHuntService) -> None:
        rows = [_make_row(extracted_indicators=["192.0.2.1"])]

        def _backend(query: HuntQuery) -> list[dict[str, Any]]:
            return rows

        _inject_query_backend(service, _backend)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            return_value=None,
        ):
            result = service._query_detections(_make_query(), "org-a")

        assert result == rows


# ===========================================================================
# Integration: multi-row hunt with score + org filter
# ===========================================================================


class TestRunHuntIntegration:
    def test_hunt_filters_by_org_via_injected_backend(self, service: ThreatHuntService) -> None:
        rows = [
            _make_row(event_id="e1", extracted_indicators=["192.0.2.1"], org_id="org-a"),
            _make_row(event_id="e2", extracted_indicators=["192.0.2.1"], org_id="org-b"),
        ]
        _inject_query_backend(service, lambda query, org_id: rows)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query(org_id="org-a"))

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.org_id == "org-a"
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.matches[0].event_id == "e1"
        assert result.errors == []

    def test_hunt_with_mitre_returns_matched_technique(self, service: ThreatHuntService) -> None:
        rows = [
            _make_row(event_id="e1", mitre_techniques=["T1566"]),
            _make_row(event_id="e2", mitre_techniques=["T1059"]),
        ]
        _inject_query_backend(service, lambda query, org_id: rows)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(HuntQuery(mitre_technique_id="T1566"))

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.matches[0].matched_mitre_technique == "T1566"
        assert result.errors == []

    def test_hunt_with_cve_returns_matched_cve(self, service: ThreatHuntService) -> None:
        rows = [
            _make_row(event_id="e1", extracted_indicators=["CVE-2025-0001"]),
            _make_row(event_id="e2", extracted_indicators=["CVE-2025-9999"]),
        ]
        _inject_query_backend(service, lambda query, org_id: rows)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(HuntQuery(cve_id="CVE-2025-0001"))

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.matches[0].matched_ioc_value == "CVE-2025-0001"
        assert result.matches[0].matched_ioc_type == "cve"
        assert result.errors == []

    def test_hunt_with_risk_family_filters_non_matching_rows(self, service: ThreatHuntService) -> None:
        rows = [
            _make_row(event_id="e1", risk_families=["exfiltration"]),
            _make_row(event_id="e2", risk_families=["lateral_movement"]),
        ]
        _inject_query_backend(service, lambda query, org_id: rows)

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(HuntQuery(risk_family="exfiltration"))

        assert result.status == HuntStatusEnum.COMPLETED
        assert result.total_matches == 1
        assert len(result.matches) == 1
        assert result.matches[0].event_id == "e1"
        assert result.errors == []

    def test_hunt_result_query_summary_populated(self, service: ThreatHuntService) -> None:
        _inject_query_backend(service, lambda query, org_id: [])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query(ioc_value="10.0.0.1"))

        assert result.query_summary.get("ioc_value") == "10.0.0.1"

    def test_hunt_result_is_hunt_result_type(self, service: ThreatHuntService) -> None:
        _inject_query_backend(service, lambda query, org_id: [])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        assert isinstance(result, HuntResult)

    def test_hunt_matches_are_hunt_match_type(self, service: ThreatHuntService) -> None:
        row = _make_row(extracted_indicators=["192.0.2.1"])
        _inject_query_backend(service, lambda query, org_id: [row])

        with patch(
            "app.services.threat_hunt_service._get_supabase_client",
            side_effect=RuntimeError("missing SUPABASE_URL"),
        ):
            result = service.run_hunt(_make_query())

        for m in result.matches:
            assert isinstance(m, HuntMatch)
