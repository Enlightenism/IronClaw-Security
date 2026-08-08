from __future__ import annotations

from typing import Any

from pydantic import ValidationError
import pytest

from app.schemas import threat_detection as canonical
from app.schemas import threatdetection as shim


def _request_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "evt-1",
        "org_id": "org-1",
        "agent_id": "agent-1",
        "session_id": "session-1",
        "text": "connect to 1.2.3.4 via https://evil.example.com",
        "context": "tool_call",
        "metadata": {"source": "unit-test"},
        "minimum_confidence": 0.25,
    }
    payload.update(overrides)
    return payload


def _ioc_match_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ioc_id": "ioc-1",
        "value": "1.2.3.4",
        "ioc_type": canonical.IOCTypeEnum.IPV4.value,
        "confidence": 0.95,
        "severity": canonical.ThreatSeverityLevel.HIGH.value,
        "source": canonical.ThreatFeedSourceEnum.INTERNAL.value,
        "tags": ["c2", "ransomware"],
        "matched_on": "ioc_store",
        "mitre_technique_id": "T1059",
        "mitre_tactic": "execution",
        "cve_id": "CVE-2026-0001",
        "reference": "https://example.test/ioc/1",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def _signal_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "signal_id": "sig-1",
        "pattern_type": "attack_chain",
        "signal_type": "attack_chain",
        "matched_event_ids": ["evt-1", "evt-2"],
        "contributing_ioc_ids": ["ioc-1", "ioc-2"],
        "mitre_technique_ids": ["T1059", "T1204"],
        "confidence": 0.8,
        "score_contribution": 0.2,
        "description": "Execution chain detected.",
    }
    payload.update(overrides)
    return payload


def _result_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "evt-1",
        "org_id": "org-1",
        "agent_id": "agent-1",
        "session_id": "session-1",
        "verdict": canonical.DetectionVerdict.REVIEW,
        "score": 0.7,
        "severity": canonical.ThreatSeverityLevel.HIGH,
        "scanned_text": "connect to 1.2.3.4 via https://evil.example.com",
        "ioc_matches": [_ioc_match_payload()],
        "correlation_signals": [_signal_payload()],
        "risk_families": ["credential_theft", "c2"],
        "extracted_indicators": ["1.2.3.4", "evil.example.com"],
        "rationale": ["High confidence IOC match.", "Attack chain signal detected."],
        "mitre_techniques": ["T1059", "T1204"],
        "context": "tool_call",
        "metadata": {"source": "unit-test"},
        "assessed_at": "2026-01-01T00:00:00Z",
        "detection_engine_version": "1.0.0",
    }
    payload.update(overrides)
    return payload


def _threat_alert_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "alert_id": "alert-1",
        "event_id": "evt-1",
        "org_id": "org-1",
        "agent_id": "agent-1",
        "session_id": "session-1",
        "verdict": canonical.DetectionVerdict.BLOCK,
        "severity": canonical.AlertSeverityEnum.CRITICAL,
        "score": 0.95,
        "title": "Critical threat detected",
        "description": "High-risk execution threat.",
        "ioc_matches": [_ioc_match_payload()],
        "correlation_signals": [_signal_payload()],
        "mitre_techniques": ["T1059", "T1204"],
        "risk_families": ["credential_theft"],
        "suppressed": False,
        "suppression_reason": None,
        "incident_id": "inc-1",
        "created_at": "2026-01-01T00:00:00Z",
        "metadata": {"source": "unit-test"},
    }
    payload.update(overrides)
    return payload


def _hunt_query_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "hunt_id": "hunt-1",
        "org_id": "org-1",
        "ioc_value": "1.2.3.4",
        "ioc_type": canonical.IOCTypeEnum.IPV4,
        "mitre_technique_id": "T1059",
        "cve_id": "CVE-2026-0001",
        "risk_family": "credential_theft",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-02T00:00:00Z",
        "minimum_score": 0.25,
        "limit": 100,
        "offset": 0,
    }
    payload.update(overrides)
    return payload


def _hunt_match_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "evt-1",
        "org_id": "org-1",
        "agent_id": "agent-1",
        "session_id": "session-1",
        "verdict": canonical.DetectionVerdict.REVIEW,
        "score": 0.7,
        "severity": canonical.ThreatSeverityLevel.HIGH,
        "matched_ioc_value": "1.2.3.4",
        "matched_ioc_type": canonical.IOCTypeEnum.IPV4.value,
        "matched_mitre_technique": "T1059",
        "risk_families": ["credential_theft"],
        "context": "tool_call",
        "assessed_at": "2026-01-01T00:00:00Z",
        "confidence": 0.9,
    }
    payload.update(overrides)
    return payload


def _hunt_result_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "hunt_id": "hunt-1",
        "org_id": "org-1",
        "status": canonical.HuntStatusEnum.COMPLETED,
        "total_matches": 1,
        "matches": [_hunt_match_payload()],
        "query_summary": {"ioc_value": "1.2.3.4"},
        "executed_at": "2026-01-01T00:00:00Z",
        "duration_ms": 42,
        "errors": [],
    }
    payload.update(overrides)
    return payload


def _ioc_import_entry_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "value": "1.2.3.4",
        "ioc_type": canonical.IOCTypeEnum.IPV4,
        "severity": canonical.ThreatSeverityLevel.MEDIUM,
        "confidence": 0.8,
        "tags": ["tag1", "tag2"],
        "description": "Known bad host",
        "mitre_technique_id": "T1059",
        "mitre_tactic": "execution",
        "cve_id": "CVE-2026-0001",
        "expiry": "2026-12-31T00:00:00Z",
        "reference": "https://example.test/ref",
        "extra": {"feed": "internal"},
    }
    payload.update(overrides)
    return payload


def _ioc_import_request_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "org_id": "org-1",
        "entries": [_ioc_import_entry_payload()],
        "source_label": "pentest-2026-05",
        "overwrite_existing": True,
    }
    payload.update(overrides)
    return payload


def _ioc_import_result_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ingest_id": "ing-1",
        "org_id": "org-1",
        "iocs_submitted": 1,
        "iocs_inserted": 1,
        "iocs_updated": 0,
        "iocs_skipped": 0,
        "errors": [],
        "status": canonical.IngestStatusEnum.SUCCESS,
        "completed_at": "2026-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def _taxii_ingest_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "discovery_url": "https://taxii.example.com/discovery",
        "collection_id": "collection-1",
        "api_root": "https://taxii.example.com/api",
        "username": "user",
        "password": "pass",
        "verify_ssl": True,
        "timeout": 30,
        "page_size": 500,
        "extra_headers": {"X-Test": "1"},
        "org_id": "org-1",
        "added_after": "2026-01-01T00:00:00Z",
        "source_label": "taxii-feed",
    }
    payload.update(overrides)
    return payload


def _feed_refresh_request_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "sources": [canonical.ThreatFeedSourceEnum.INTERNAL],
        "org_id": "org-1",
        "force": False,
        "custom_url": None,
        "taxii_ingest": None,
    }
    payload.update(overrides)
    return payload


def _feed_refresh_result_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": "req-1",
        "org_id": "org-1",
        "results": [{"source": "internal", "inserted": 1}],
        "total_iocs_inserted": 1,
        "total_iocs_updated": 0,
        "total_errors": 0,
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:05Z",
    }
    payload.update(overrides)
    return payload


def _ioc_filter_params_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": canonical.ThreatFeedSourceEnum.INTERNAL,
        "ioc_type": canonical.IOCTypeEnum.IPV4,
        "severity": canonical.ThreatSeverityLevel.HIGH,
        "org_id": "org-1",
        "active": True,
        "tag": "c2",
        "mitre_technique_id": "T1059",
        "cve_id": "CVE-2026-0001",
        "value_contains": "1.2.3",
        "limit": 100,
        "offset": 0,
    }
    payload.update(overrides)
    return payload


def _ioc_response_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ioc_id": "ioc-1",
        "ioc_type": canonical.IOCTypeEnum.IPV4.value,
        "value": "1.2.3.4",
        "source": canonical.ThreatFeedSourceEnum.INTERNAL.value,
        "severity": canonical.ThreatSeverityLevel.HIGH.value,
        "confidence": 0.9,
        "tags": ["c2"],
        "description": "Known bad host",
        "org_id": "org-1",
        "mitre_technique_id": "T1059",
        "mitre_tactic": "execution",
        "cve_id": "CVE-2026-0001",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "expiry": None,
        "active": True,
        "feed_ingest_id": "ing-1",
        "extra": {"feed": "internal"},
    }
    payload.update(overrides)
    return payload


def _detection_summary_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "evt-1",
        "org_id": "org-1",
        "agent_id": "agent-1",
        "session_id": "session-1",
        "verdict": canonical.DetectionVerdict.REVIEW,
        "score": 0.6,
        "severity": canonical.ThreatSeverityLevel.HIGH,
        "ioc_match_count": 2,
        "correlation_signal_count": 1,
        "assessed_at": "2026-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


class TestThreatDetectionShimIdentity:
    def test_enum_identities_match(self) -> None:
        assert shim.DetectionVerdict is canonical.DetectionVerdict
        assert shim.ThreatSeverityLevel is canonical.ThreatSeverityLevel
        assert shim.IOCTypeEnum is canonical.IOCTypeEnum
        assert shim.ThreatFeedSourceEnum is canonical.ThreatFeedSourceEnum
        assert shim.IngestStatusEnum is canonical.IngestStatusEnum
        assert shim.AlertSeverityEnum is canonical.AlertSeverityEnum
        assert shim.HuntStatusEnum is canonical.HuntStatusEnum

    def test_model_identities_match(self) -> None:
        assert shim.DetectionRequest is canonical.DetectionRequest
        assert shim.IOCMatch is canonical.IOCMatch
        assert shim.CorrelationSignal is canonical.CorrelationSignal
        assert shim.DetectionResult is canonical.DetectionResult
        assert shim.ThreatAlert is canonical.ThreatAlert
        assert shim.HuntQuery is canonical.HuntQuery
        assert shim.HuntMatch is canonical.HuntMatch
        assert shim.HuntResult is canonical.HuntResult
        assert shim.IOCImportEntry is canonical.IOCImportEntry
        assert shim.IOCImportRequest is canonical.IOCImportRequest
        assert shim.IOCImportResult is canonical.IOCImportResult
        assert shim.TAXIIIngestRequest is canonical.TAXIIIngestRequest
        assert shim.FeedRefreshRequest is canonical.FeedRefreshRequest
        assert shim.FeedRefreshResult is canonical.FeedRefreshResult
        assert shim.IOCFilterParams is canonical.IOCFilterParams
        assert shim.IOCResponse is canonical.IOCResponse
        assert shim.DetectionSummary is canonical.DetectionSummary

    def test_shim_all_matches_canonical_all(self) -> None:
        assert set(shim.__all__) == set(canonical.__all__)


class TestCanonicalEnums:
    def test_detection_verdict_values(self) -> None:
        assert canonical.DetectionVerdict.ALLOW.value == "allow"
        assert canonical.DetectionVerdict.MONITOR.value == "monitor"
        assert canonical.DetectionVerdict.REVIEW.value == "review"
        assert canonical.DetectionVerdict.BLOCK.value == "block"

    def test_threat_severity_values(self) -> None:
        assert canonical.ThreatSeverityLevel.INFO.value == "info"
        assert canonical.ThreatSeverityLevel.LOW.value == "low"
        assert canonical.ThreatSeverityLevel.MEDIUM.value == "medium"
        assert canonical.ThreatSeverityLevel.HIGH.value == "high"
        assert canonical.ThreatSeverityLevel.CRITICAL.value == "critical"

    def test_ioc_type_values(self) -> None:
        assert canonical.IOCTypeEnum.IPV4.value == "ipv4"
        assert canonical.IOCTypeEnum.IPV6.value == "ipv6"
        assert canonical.IOCTypeEnum.DOMAIN.value == "domain"
        assert canonical.IOCTypeEnum.URL.value == "url"
        assert canonical.IOCTypeEnum.SHA256.value == "sha256"
        assert canonical.IOCTypeEnum.SHA1.value == "sha1"
        assert canonical.IOCTypeEnum.MD5.value == "md5"
        assert canonical.IOCTypeEnum.CVE.value == "cve"
        assert canonical.IOCTypeEnum.MITRE_TECHNIQUE.value == "mitre_technique"
        assert canonical.IOCTypeEnum.MITRE_TACTIC.value == "mitre_tactic"
        assert canonical.IOCTypeEnum.EMAIL.value == "email"
        assert canonical.IOCTypeEnum.UNKNOWN.value == "unknown"

    def test_threat_feed_source_values(self) -> None:
        assert canonical.ThreatFeedSourceEnum.MITRE_ATTACK.value == "mitre_attack"
        assert canonical.ThreatFeedSourceEnum.CISA_KEV.value == "cisa_kev"
        assert canonical.ThreatFeedSourceEnum.CUSTOM_IOC.value == "custom_ioc"
        assert canonical.ThreatFeedSourceEnum.STIX_TAXII.value == "stix_taxii"
        assert canonical.ThreatFeedSourceEnum.INTERNAL.value == "internal"

    def test_ingest_status_values(self) -> None:
        assert canonical.IngestStatusEnum.SUCCESS.value == "success"
        assert canonical.IngestStatusEnum.PARTIAL.value == "partial"
        assert canonical.IngestStatusEnum.FAILED.value == "failed"
        assert canonical.IngestStatusEnum.SKIPPED.value == "skipped"

    def test_alert_severity_values(self) -> None:
        assert canonical.AlertSeverityEnum.LOW.value == "low"
        assert canonical.AlertSeverityEnum.MEDIUM.value == "medium"
        assert canonical.AlertSeverityEnum.HIGH.value == "high"
        assert canonical.AlertSeverityEnum.CRITICAL.value == "critical"

    def test_hunt_status_values(self) -> None:
        assert canonical.HuntStatusEnum.PENDING.value == "pending"
        assert canonical.HuntStatusEnum.RUNNING.value == "running"
        assert canonical.HuntStatusEnum.COMPLETED.value == "completed"
        assert canonical.HuntStatusEnum.FAILED.value == "failed"


class TestDetectionRequest:
    def test_accepts_text_request(self) -> None:
        model = canonical.DetectionRequest(**_request_payload())
        assert model.text == "connect to 1.2.3.4 via https://evil.example.com"
        assert model.context == "tool_call"
        assert model.metadata == {"source": "unit-test"}
        assert model.minimum_confidence == 0.25

    def test_accepts_url_only(self) -> None:
        model = canonical.DetectionRequest(**_request_payload(text=None, url="https://evil.example.com"))
        assert model.url == "https://evil.example.com"

    def test_accepts_domain_only(self) -> None:
        model = canonical.DetectionRequest(**_request_payload(text=None, domain="evil.example.com"))
        assert model.domain == "evil.example.com"

    def test_accepts_hashes_only(self) -> None:
        sha = "a" * 64
        model = canonical.DetectionRequest(**_request_payload(text=None, hashes=[sha]))
        assert model.hashes == [sha]

    def test_accepts_ioc_values_only(self) -> None:
        model = canonical.DetectionRequest(**_request_payload(text=None, ioc_values=["1.2.3.4"]))
        assert model.ioc_values == ["1.2.3.4"]

    def test_requires_at_least_one_observable(self) -> None:
        with pytest.raises(ValidationError):
            canonical.DetectionRequest(org_id="org-1")

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            canonical.DetectionRequest(**_request_payload(extra_field=True))

    def test_rejects_minimum_confidence_below_zero(self) -> None:
        with pytest.raises(ValidationError):
            canonical.DetectionRequest(**_request_payload(minimum_confidence=-0.01))

    def test_rejects_minimum_confidence_above_one(self) -> None:
        with pytest.raises(ValidationError):
            canonical.DetectionRequest(**_request_payload(minimum_confidence=1.01))

    def test_shim_parses_same_request(self) -> None:
        payload = _request_payload(url="https://evil.example.com", text=None)
        assert canonical.DetectionRequest(**payload).model_dump() == shim.DetectionRequest(**payload).model_dump()


class TestIOCMatch:
    def test_parses_all_fields(self) -> None:
        model = canonical.IOCMatch(**_ioc_match_payload())
        assert model.ioc_id == "ioc-1"
        assert model.value == "1.2.3.4"
        assert model.ioc_type == "ipv4"
        assert model.confidence == 0.95
        assert model.severity == "high"
        assert model.source == "internal"
        assert model.tags == ["c2", "ransomware"]
        assert model.matched_on == "ioc_store"
        assert model.mitre_technique_id == "T1059"
        assert model.mitre_tactic == "execution"
        assert model.cve_id == "CVE-2026-0001"
        assert model.reference == "https://example.test/ioc/1"
        assert model.first_seen == "2026-01-01T00:00:00Z"
        assert model.last_seen == "2026-01-02T00:00:00Z"

    def test_ignores_extra_fields(self) -> None:
        model = canonical.IOCMatch(**_ioc_match_payload(extra_field="ignored"))
        assert model.value == "1.2.3.4"

    def test_shim_parses_same_ioc_match(self) -> None:
        payload = _ioc_match_payload()
        assert canonical.IOCMatch(**payload).model_dump() == shim.IOCMatch(**payload).model_dump()


class TestCorrelationSignal:
    def test_parses_all_fields(self) -> None:
        model = canonical.CorrelationSignal(**_signal_payload())
        assert model.signal_id == "sig-1"
        assert model.pattern_type == "attack_chain"
        assert model.signal_type == "attack_chain"
        assert model.matched_event_ids == ["evt-1", "evt-2"]
        assert model.contributing_ioc_ids == ["ioc-1", "ioc-2"]
        assert model.mitre_technique_ids == ["T1059", "T1204"]
        assert model.confidence == 0.8
        assert model.score_contribution == 0.2
        assert model.description == "Execution chain detected."

    def test_signal_type_alias_defaults_from_pattern_type(self) -> None:
        model = canonical.CorrelationSignal(**_signal_payload(signal_type=None))
        assert model.pattern_type == "attack_chain"
        assert model.signal_type == "attack_chain"

    def test_pattern_type_alias_defaults_from_signal_type(self) -> None:
        model = canonical.CorrelationSignal(**_signal_payload(pattern_type="", signal_type="temporal_cluster"))
        assert model.pattern_type == "temporal_cluster"
        assert model.signal_type == "temporal_cluster"

    def test_ignores_extra_fields(self) -> None:
        model = canonical.CorrelationSignal(**_signal_payload(extra_field="ignored"))
        assert model.signal_id == "sig-1"

    def test_shim_parses_same_signal(self) -> None:
        payload = _signal_payload()
        assert canonical.CorrelationSignal(**payload).model_dump() == shim.CorrelationSignal(**payload).model_dump()


class TestDetectionResult:
    def test_parses_all_fields(self) -> None:
        model = canonical.DetectionResult(**_result_payload())
        assert model.event_id == "evt-1"
        assert model.org_id == "org-1"
        assert model.agent_id == "agent-1"
        assert model.session_id == "session-1"
        assert model.verdict == canonical.DetectionVerdict.REVIEW
        assert model.score == 0.7
        assert model.severity == canonical.ThreatSeverityLevel.HIGH
        assert model.scanned_text == "connect to 1.2.3.4 via https://evil.example.com"
        assert model.risk_families == ["credential_theft", "c2"]
        assert model.extracted_indicators == ["1.2.3.4", "evil.example.com"]
        assert model.rationale == ["High confidence IOC match.", "Attack chain signal detected."]
        assert model.mitre_techniques == ["T1059", "T1204"]
        assert model.context == "tool_call"
        assert model.metadata == {"source": "unit-test"}
        assert model.assessed_at == "2026-01-01T00:00:00Z"
        assert model.detection_engine_version == "1.0.0"

    def test_contract_stable_mitre_fields(self) -> None:
        model = canonical.DetectionResult(**_result_payload())
        assert model.ioc_matches[0].mitre_technique_id == "T1059"
        assert model.correlation_signals[0].mitre_technique_ids == ["T1059", "T1204"]
        assert model.mitre_techniques == ["T1059", "T1204"]

    def test_is_threat_for_review_and_block(self) -> None:
        review = canonical.DetectionResult(**_result_payload(verdict=canonical.DetectionVerdict.REVIEW))
        block = canonical.DetectionResult(**_result_payload(verdict=canonical.DetectionVerdict.BLOCK))
        assert review.is_threat is True
        assert block.is_threat is True

    def test_is_threat_false_for_allow_and_monitor(self) -> None:
        allow = canonical.DetectionResult(**_result_payload(verdict=canonical.DetectionVerdict.ALLOW))
        monitor = canonical.DetectionResult(**_result_payload(verdict=canonical.DetectionVerdict.MONITOR))
        assert allow.is_threat is False
        assert monitor.is_threat is False

    def test_requires_block_only_for_block(self) -> None:
        review = canonical.DetectionResult(**_result_payload(verdict=canonical.DetectionVerdict.REVIEW))
        block = canonical.DetectionResult(**_result_payload(verdict=canonical.DetectionVerdict.BLOCK))
        assert review.requires_block is False
        assert block.requires_block is True

    def test_top_ioc_returns_highest_confidence(self) -> None:
        model = canonical.DetectionResult(
            **_result_payload(
                ioc_matches=[
                    _ioc_match_payload(ioc_id="ioc-low", confidence=0.3),
                    _ioc_match_payload(ioc_id="ioc-high", confidence=0.99),
                ]
            )
        )
        assert model.top_ioc is not None
        assert model.top_ioc.ioc_id == "ioc-high"

    def test_top_ioc_returns_none_when_empty(self) -> None:
        model = canonical.DetectionResult(**_result_payload(ioc_matches=[], correlation_signals=[], mitre_techniques=[]))
        assert model.top_ioc is None

    def test_count_properties(self) -> None:
        model = canonical.DetectionResult(**_result_payload())
        assert model.ioc_match_count == 1
        assert model.correlation_signal_count == 1

    def test_ignores_extra_fields(self) -> None:
        model = canonical.DetectionResult(**_result_payload(extra_field="ignored"))
        assert model.event_id == "evt-1"

    def test_shim_parses_same_result(self) -> None:
        payload = _result_payload()
        assert canonical.DetectionResult(**payload).model_dump() == shim.DetectionResult(**payload).model_dump()


class TestThreatAlert:
    def test_parses_all_fields(self) -> None:
        model = canonical.ThreatAlert(**_threat_alert_payload())
        assert model.alert_id == "alert-1"
        assert model.event_id == "evt-1"
        assert model.verdict == canonical.DetectionVerdict.BLOCK
        assert model.severity == canonical.AlertSeverityEnum.CRITICAL
        assert model.score == 0.95
        assert model.title == "Critical threat detected"
        assert model.incident_id == "inc-1"
        assert model.ioc_matches[0].mitre_technique_id == "T1059"
        assert model.correlation_signals[0].mitre_technique_ids == ["T1059", "T1204"]
        assert model.mitre_techniques == ["T1059", "T1204"]

    def test_ignores_extra_fields(self) -> None:
        model = canonical.ThreatAlert(**_threat_alert_payload(extra_field="ignored"))
        assert model.alert_id == "alert-1"

    def test_shim_parses_same_threat_alert(self) -> None:
        payload = _threat_alert_payload()
        assert canonical.ThreatAlert(**payload).model_dump() == shim.ThreatAlert(**payload).model_dump()


class TestHuntQuery:
    def test_parses_all_fields(self) -> None:
        model = canonical.HuntQuery(**_hunt_query_payload())
        assert model.hunt_id == "hunt-1"
        assert model.ioc_value == "1.2.3.4"
        assert model.ioc_type == canonical.IOCTypeEnum.IPV4
        assert model.mitre_technique_id == "T1059"
        assert model.cve_id == "CVE-2026-0001"
        assert model.risk_family == "credential_theft"
        assert model.minimum_score == 0.25
        assert model.limit == 100
        assert model.offset == 0

    def test_requires_at_least_one_dimension(self) -> None:
        with pytest.raises(ValidationError):
            canonical.HuntQuery(org_id="org-1")

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            canonical.HuntQuery(**_hunt_query_payload(extra_field=True))

    def test_shim_parses_same_hunt_query(self) -> None:
        payload = _hunt_query_payload()
        assert canonical.HuntQuery(**payload).model_dump() == shim.HuntQuery(**payload).model_dump()


class TestHuntMatch:
    def test_parses_all_fields(self) -> None:
        model = canonical.HuntMatch(**_hunt_match_payload())
        assert model.event_id == "evt-1"
        assert model.matched_ioc_value == "1.2.3.4"
        assert model.matched_ioc_type == "ipv4"
        assert model.matched_mitre_technique == "T1059"
        assert model.risk_families == ["credential_theft"]
        assert model.confidence == 0.9

    def test_ignores_extra_fields(self) -> None:
        model = canonical.HuntMatch(**_hunt_match_payload(extra_field="ignored"))
        assert model.event_id == "evt-1"

    def test_shim_parses_same_hunt_match(self) -> None:
        payload = _hunt_match_payload()
        assert canonical.HuntMatch(**payload).model_dump() == shim.HuntMatch(**payload).model_dump()


class TestHuntResult:
    def test_parses_all_fields(self) -> None:
        model = canonical.HuntResult(**_hunt_result_payload())
        assert model.hunt_id == "hunt-1"
        assert model.status == canonical.HuntStatusEnum.COMPLETED
        assert model.total_matches == 1
        assert len(model.matches) == 1
        assert model.query_summary == {"ioc_value": "1.2.3.4"}
        assert model.duration_ms == 42
        assert model.errors == []

    def test_ignores_extra_fields(self) -> None:
        model = canonical.HuntResult(**_hunt_result_payload(extra_field="ignored"))
        assert model.hunt_id == "hunt-1"

    def test_shim_parses_same_hunt_result(self) -> None:
        payload = _hunt_result_payload()
        assert canonical.HuntResult(**payload).model_dump() == shim.HuntResult(**payload).model_dump()


class TestIOCImportEntry:
    def test_parses_all_fields(self) -> None:
        model = canonical.IOCImportEntry(**_ioc_import_entry_payload())
        assert model.value == "1.2.3.4"
        assert model.ioc_type == canonical.IOCTypeEnum.IPV4
        assert model.severity == canonical.ThreatSeverityLevel.MEDIUM
        assert model.confidence == 0.8
        assert model.tags == ["tag1", "tag2"]
        assert model.mitre_technique_id == "T1059"
        assert model.mitre_tactic == "execution"
        assert model.cve_id == "CVE-2026-0001"
        assert model.extra == {"feed": "internal"}

    def test_coerces_string_tags(self) -> None:
        model = canonical.IOCImportEntry(**_ioc_import_entry_payload(tags="tag1, tag2 , tag3"))
        assert model.tags == ["tag1", "tag2", "tag3"]

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            canonical.IOCImportEntry(**_ioc_import_entry_payload(extra_field=True))

    def test_shim_parses_same_import_entry(self) -> None:
        payload = _ioc_import_entry_payload()
        assert canonical.IOCImportEntry(**payload).model_dump() == shim.IOCImportEntry(**payload).model_dump()


class TestIOCImportRequest:
    def test_parses_all_fields(self) -> None:
        model = canonical.IOCImportRequest(**_ioc_import_request_payload())
        assert model.org_id == "org-1"
        assert len(model.entries) == 1
        assert model.source_label == "pentest-2026-05"
        assert model.overwrite_existing is True

    def test_rejects_empty_entries(self) -> None:
        with pytest.raises(ValidationError):
            canonical.IOCImportRequest(org_id="org-1", entries=[])

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            canonical.IOCImportRequest(**_ioc_import_request_payload(extra_field=True))

    def test_shim_parses_same_import_request(self) -> None:
        payload = _ioc_import_request_payload()
        assert canonical.IOCImportRequest(**payload).model_dump() == shim.IOCImportRequest(**payload).model_dump()


class TestIOCImportResult:
    def test_parses_all_fields(self) -> None:
        model = canonical.IOCImportResult(**_ioc_import_result_payload())
        assert model.ingest_id == "ing-1"
        assert model.iocs_submitted == 1
        assert model.iocs_inserted == 1
        assert model.iocs_updated == 0
        assert model.iocs_skipped == 0
        assert model.status == canonical.IngestStatusEnum.SUCCESS
        assert model.completed_at == "2026-01-01T00:00:00Z"

    def test_ignores_extra_fields(self) -> None:
        model = canonical.IOCImportResult(**_ioc_import_result_payload(extra_field="ignored"))
        assert model.ingest_id == "ing-1"

    def test_shim_parses_same_import_result(self) -> None:
        payload = _ioc_import_result_payload()
        assert canonical.IOCImportResult(**payload).model_dump() == shim.IOCImportResult(**payload).model_dump()


class TestTAXIIIngestRequest:
    def test_parses_all_fields(self) -> None:
        model = canonical.TAXIIIngestRequest(**_taxii_ingest_payload())
        assert model.discovery_url == "https://taxii.example.com/discovery"
        assert model.collection_id == "collection-1"
        assert model.api_root == "https://taxii.example.com/api"
        assert model.username == "user"
        assert model.password == "pass"
        assert model.verify_ssl is True
        assert model.timeout == 30
        assert model.page_size == 500
        assert model.extra_headers == {"X-Test": "1"}
        assert model.org_id == "org-1"
        assert model.added_after == "2026-01-01T00:00:00Z"
        assert model.source_label == "taxii-feed"

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            canonical.TAXIIIngestRequest(**_taxii_ingest_payload(extra_field=True))

    def test_shim_parses_same_taxii_request(self) -> None:
        payload = _taxii_ingest_payload()
        assert canonical.TAXIIIngestRequest(**payload).model_dump() == shim.TAXIIIngestRequest(**payload).model_dump()


class TestFeedRefreshRequest:
    def test_parses_all_fields(self) -> None:
        model = canonical.FeedRefreshRequest(**_feed_refresh_request_payload())
        assert model.sources == [canonical.ThreatFeedSourceEnum.INTERNAL]
        assert model.org_id == "org-1"
        assert model.force is False
        assert model.custom_url is None
        assert model.taxii_ingest is None

    def test_custom_url_requires_single_source(self) -> None:
        with pytest.raises(ValidationError):
            canonical.FeedRefreshRequest(
                **_feed_refresh_request_payload(
                    sources=[
                        canonical.ThreatFeedSourceEnum.INTERNAL,
                        canonical.ThreatFeedSourceEnum.CISA_KEV,
                    ],
                    custom_url="https://override.example.com/feed",
                )
            )

    def test_taxii_ingest_requires_stix_taxii_source(self) -> None:
        with pytest.raises(ValidationError):
            canonical.FeedRefreshRequest(
                **_feed_refresh_request_payload(
                    sources=[canonical.ThreatFeedSourceEnum.INTERNAL],
                    taxii_ingest=_taxii_ingest_payload(),
                )
            )

    def test_accepts_taxii_ingest_when_stix_taxii_present(self) -> None:
        model = canonical.FeedRefreshRequest(
            **_feed_refresh_request_payload(
                sources=[canonical.ThreatFeedSourceEnum.STIX_TAXII],
                taxii_ingest=_taxii_ingest_payload(),
            )
        )
        assert model.sources == [canonical.ThreatFeedSourceEnum.STIX_TAXII]
        assert model.taxii_ingest is not None
        assert model.taxii_ingest.discovery_url == "https://taxii.example.com/discovery"

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            canonical.FeedRefreshRequest(**_feed_refresh_request_payload(extra_field=True))

    def test_shim_parses_same_feed_refresh_request(self) -> None:
        payload = _feed_refresh_request_payload()
        assert canonical.FeedRefreshRequest(**payload).model_dump() == shim.FeedRefreshRequest(**payload).model_dump()


class TestFeedRefreshResult:
    def test_parses_all_fields(self) -> None:
        model = canonical.FeedRefreshResult(**_feed_refresh_result_payload())
        assert model.request_id == "req-1"
        assert model.org_id == "org-1"
        assert model.results == [{"source": "internal", "inserted": 1}]
        assert model.total_iocs_inserted == 1
        assert model.total_iocs_updated == 0
        assert model.total_errors == 0
        assert model.started_at == "2026-01-01T00:00:00Z"
        assert model.completed_at == "2026-01-01T00:00:05Z"

    def test_ignores_extra_fields(self) -> None:
        model = canonical.FeedRefreshResult(**_feed_refresh_result_payload(extra_field="ignored"))
        assert model.request_id == "req-1"

    def test_shim_parses_same_feed_refresh_result(self) -> None:
        payload = _feed_refresh_result_payload()
        assert canonical.FeedRefreshResult(**payload).model_dump() == shim.FeedRefreshResult(**payload).model_dump()


class TestIOCFilterParams:
    def test_parses_all_fields(self) -> None:
        model = canonical.IOCFilterParams(**_ioc_filter_params_payload())
        assert model.source == canonical.ThreatFeedSourceEnum.INTERNAL
        assert model.ioc_type == canonical.IOCTypeEnum.IPV4
        assert model.severity == canonical.ThreatSeverityLevel.HIGH
        assert model.org_id == "org-1"
        assert model.active is True
        assert model.tag == "c2"
        assert model.mitre_technique_id == "T1059"
        assert model.cve_id == "CVE-2026-0001"
        assert model.value_contains == "1.2.3"
        assert model.limit == 100
        assert model.offset == 0

    def test_ignores_extra_fields(self) -> None:
        model = canonical.IOCFilterParams(**_ioc_filter_params_payload(extra_field="ignored"))
        assert model.org_id == "org-1"

    def test_shim_parses_same_filter_params(self) -> None:
        payload = _ioc_filter_params_payload()
        assert canonical.IOCFilterParams(**payload).model_dump() == shim.IOCFilterParams(**payload).model_dump()


class TestIOCResponse:
    def test_parses_all_fields(self) -> None:
        model = canonical.IOCResponse(**_ioc_response_payload())
        assert model.ioc_id == "ioc-1"
        assert model.ioc_type == "ipv4"
        assert model.value == "1.2.3.4"
        assert model.source == "internal"
        assert model.severity == "high"
        assert model.confidence == 0.9
        assert model.tags == ["c2"]
        assert model.description == "Known bad host"
        assert model.org_id == "org-1"
        assert model.mitre_technique_id == "T1059"
        assert model.mitre_tactic == "execution"
        assert model.cve_id == "CVE-2026-0001"
        assert model.first_seen == "2026-01-01T00:00:00Z"
        assert model.last_seen == "2026-01-02T00:00:00Z"
        assert model.expiry is None
        assert model.active is True
        assert model.feed_ingest_id == "ing-1"
        assert model.extra == {"feed": "internal"}

    def test_ignores_extra_fields(self) -> None:
        model = canonical.IOCResponse(**_ioc_response_payload(extra_field="ignored"))
        assert model.ioc_id == "ioc-1"

    def test_shim_parses_same_ioc_response(self) -> None:
        payload = _ioc_response_payload()
        assert canonical.IOCResponse(**payload).model_dump() == shim.IOCResponse(**payload).model_dump()


class TestDetectionSummary:
    def test_parses_all_fields(self) -> None:
        model = canonical.DetectionSummary(**_detection_summary_payload())
        assert model.event_id == "evt-1"
        assert model.org_id == "org-1"
        assert model.agent_id == "agent-1"
        assert model.session_id == "session-1"
        assert model.verdict == canonical.DetectionVerdict.REVIEW
        assert model.score == 0.6
        assert model.severity == canonical.ThreatSeverityLevel.HIGH
        assert model.ioc_match_count == 2
        assert model.correlation_signal_count == 1
        assert model.assessed_at == "2026-01-01T00:00:00Z"

    def test_ignores_extra_fields(self) -> None:
        model = canonical.DetectionSummary(**_detection_summary_payload(extra_field="ignored"))
        assert model.event_id == "evt-1"

    def test_shim_parses_same_detection_summary(self) -> None:
        payload = _detection_summary_payload()
        assert canonical.DetectionSummary(**payload).model_dump() == shim.DetectionSummary(**payload).model_dump()


class TestCanonicalExports:
    def test_all_contains_every_public_symbol_from_both_files(self) -> None:
        expected = {
            "AlertSeverityEnum",
            "CorrelationSignal",
            "DetectionRequest",
            "DetectionResult",
            "DetectionSummary",
            "DetectionVerdict",
            "FeedRefreshRequest",
            "FeedRefreshResult",
            "HuntMatch",
            "HuntQuery",
            "HuntResult",
            "HuntStatusEnum",
            "IOCFilterParams",
            "IOCImportEntry",
            "IOCImportRequest",
            "IOCImportResult",
            "IOCMatch",
            "IOCResponse",
            "IOCTypeEnum",
            "IngestStatusEnum",
            "TAXIIIngestRequest",
            "ThreatAlert",
            "ThreatFeedSourceEnum",
            "ThreatSeverityLevel",
        }
        assert set(canonical.__all__) == expected
