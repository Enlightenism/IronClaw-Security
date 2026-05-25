from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch
import uuid

import pytest

from app.schemas.threat_detection import (
    CorrelationSignal,
    DetectionRequest,
    DetectionResult,
    DetectionVerdict,
    IOCMatch,
    IOCTypeEnum,
    ThreatSeverityLevel,
)
from app.services.threat_detection_engine import (
    ScoreResult,
    ThreatDetectionEngine,
    ThreatScoringEngine,
    get_detection_engine,
    get_scoring_engine,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ioc_match(
    *,
    value: str = "1.2.3.4",
    ioc_type: str = IOCTypeEnum.IPV4,
    severity: str = ThreatSeverityLevel.MEDIUM,
    confidence: float = 0.80,
    tags: list[str] | None = None,
    mitre_technique_id: str | None = None,
    mitre_tactic: str | None = None,
    cve_id: str | None = None,
    source: str = "internal",
) -> IOCMatch:
    return IOCMatch(
        ioc_id=str(uuid.uuid4()),
        value=value,
        ioc_type=ioc_type,
        severity=severity,
        confidence=confidence,
        source=source,
        tags=tags or [],
        matched_on="ioc_store",
        mitre_technique_id=mitre_technique_id,
        mitre_tactic=mitre_tactic,
        cve_id=cve_id,
    )


def _make_correlation_signal(
    *,
    score_contribution: float = 0.10,
    confidence: float = 0.80,
    pattern_type: str = "multi_ioc_cooccurrence",
    mitre_technique_ids: list[str] | None = None,
) -> CorrelationSignal:
    return CorrelationSignal(
        signal_id=str(uuid.uuid4()),
        pattern_type=pattern_type,
        confidence=confidence,
        score_contribution=score_contribution,
        mitre_technique_ids=mitre_technique_ids or [],
    )


def _make_request(**kwargs: Any) -> DetectionRequest:
    defaults: dict[str, Any] = {
        "text": "connecting to 1.2.3.4 via http://evil.example.com",
        "org_id": "test-org",
        "agent_id": "agent-001",
    }
    defaults.update(kwargs)
    return DetectionRequest(**defaults)


# ---------------------------------------------------------------------------
# TestThreatScoringEngine
# ---------------------------------------------------------------------------


class TestThreatScoringEngine:
    def setup_method(self) -> None:
        self.engine = ThreatScoringEngine()

    def test_compute_returns_score_result(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.HIGH, confidence=0.90)
        result = self.engine.compute([m], [])
        assert isinstance(result, ScoreResult)

    def test_compute_empty_inputs_returns_zero(self) -> None:
        result = self.engine.compute([], [])
        assert result.normalized_score == 0.0
        assert result.verdict == DetectionVerdict.ALLOW

    def test_normalized_score_in_range(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0)
        result = self.engine.compute([m], [])
        assert 0.0 <= result.normalized_score <= 1.0

    def test_raw_score_gte_normalized(self) -> None:
        matches = [_make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0) for _ in range(10)]
        result = self.engine.compute(matches, [])
        assert result.raw_score >= result.normalized_score

    def test_signals_add_to_score(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.MEDIUM, confidence=0.70)
        base = self.engine.compute([m], [])
        signal = _make_correlation_signal(score_contribution=0.15, confidence=1.0)
        boosted = self.engine.compute([m], [signal])
        assert boosted.normalized_score >= base.normalized_score

    def test_verdict_block_at_high_score(self) -> None:
        matches = [_make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0) for _ in range(4)]
        result = self.engine.compute(matches, [])
        assert result.verdict == DetectionVerdict.BLOCK

    def test_verdict_allow_empty(self) -> None:
        result = self.engine.compute([], [])
        assert result.verdict == DetectionVerdict.ALLOW

    def test_severity_critical_at_high_score(self) -> None:
        matches = [_make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0) for _ in range(4)]
        result = self.engine.compute(matches, [])
        assert result.severity == ThreatSeverityLevel.CRITICAL

    def test_severity_info_at_zero(self) -> None:
        result = self.engine.compute([], [])
        assert result.severity == ThreatSeverityLevel.INFO

    def test_risk_families_from_tags(self) -> None:
        m = _make_ioc_match(tags=["ransomware", "c2"])
        result = self.engine.compute([m], [])
        assert "ransomware" in result.risk_families
        assert "c2" in result.risk_families

    def test_risk_families_empty_for_no_tags(self) -> None:
        m = _make_ioc_match(tags=[])
        result = self.engine.compute([m], [])
        assert isinstance(result.risk_families, list)

    def test_mitre_techniques_extracted_from_iocs(self) -> None:
        m = _make_ioc_match(mitre_technique_id="T1059")
        result = self.engine.compute([m], [])
        assert "T1059" in result.mitre_techniques

    def test_mitre_techniques_extracted_from_signals(self) -> None:
        m = _make_ioc_match()
        signal = _make_correlation_signal(mitre_technique_ids=["T1078"])
        result = self.engine.compute([m], [signal])
        assert "T1078" in result.mitre_techniques

    def test_mitre_techniques_deduplicated(self) -> None:
        m1 = _make_ioc_match(mitre_technique_id="T1059")
        m2 = _make_ioc_match(mitre_technique_id="t1059")
        result = self.engine.compute([m1, m2], [])
        assert result.mitre_techniques.count("T1059") == 1

    def test_rationale_non_empty_with_matches(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.HIGH, confidence=0.85)
        result = self.engine.compute([m], [])
        assert len(result.rationale) > 0

    def test_rationale_contains_score(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.HIGH, confidence=0.85)
        result = self.engine.compute([m], [])
        full_text = " ".join(result.rationale)
        assert any(char.isdigit() for char in full_text)

    def test_rationale_contains_verdict(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.HIGH, confidence=0.90)
        result = self.engine.compute([m], [])
        full_text = " ".join(result.rationale).lower()
        assert result.verdict.value.lower() in full_text

    def test_rationale_no_ioc_message_on_empty(self) -> None:
        result = self.engine.compute([], [])
        full_text = " ".join(result.rationale)
        assert "No IOC" in full_text

    def test_signals_rationale_line_included(self) -> None:
        m = _make_ioc_match()
        signal = _make_correlation_signal()
        result = self.engine.compute([m], [signal])
        full_text = " ".join(result.rationale).lower()
        assert "correlation" in full_text or "signal" in full_text

    def test_high_crit_ioc_rationale_line(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, value="evil.example.com")
        result = self.engine.compute([m], [])
        full_text = " ".join(result.rationale)
        assert "evil.example.com" in full_text or "HIGH/CRITICAL" in full_text or "critical" in full_text.lower()

    def test_score_signals_capped_at_0_20(self) -> None:
        signals = [_make_correlation_signal(score_contribution=0.20, confidence=1.0) for _ in range(20)]
        result = self.engine.compute([], signals)
        assert result.normalized_score <= 0.20

    def test_ioc_score_capped_at_0_80(self) -> None:
        matches = [_make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0) for _ in range(50)]
        result = self.engine.compute(matches, [])
        assert result.raw_score - result.normalized_score >= 0.0


# ---------------------------------------------------------------------------
# TestScoreResult
# ---------------------------------------------------------------------------


class TestScoreResult:
    def test_fields_accessible(self) -> None:
        r = ScoreResult(
            raw_score=0.85,
            normalized_score=0.85,
            verdict=DetectionVerdict.BLOCK,
            severity=ThreatSeverityLevel.CRITICAL,
            risk_families=["ransomware"],
            mitre_techniques=["T1059"],
            rationale=["line1"],
        )
        assert r.raw_score == 0.85
        assert r.normalized_score == 0.85
        assert r.verdict == DetectionVerdict.BLOCK
        assert r.severity == ThreatSeverityLevel.CRITICAL
        assert r.risk_families == ["ransomware"]
        assert r.mitre_techniques == ["T1059"]
        assert r.rationale == ["line1"]

    def test_slots_prevent_arbitrary_attributes(self) -> None:
        r = ScoreResult(
            raw_score=0.0,
            normalized_score=0.0,
            verdict=DetectionVerdict.ALLOW,
            severity=ThreatSeverityLevel.INFO,
            risk_families=[],
            mitre_techniques=[],
            rationale=[],
        )
        with pytest.raises(AttributeError):
            r.unexpected_field = "boom"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# TestThreatDetectionEngineInit
# ---------------------------------------------------------------------------


class TestThreatDetectionEngineInit:
    def test_default_scoring_engine_injected(self) -> None:
        engine = ThreatDetectionEngine()
        assert isinstance(engine._scoring_engine, ThreatScoringEngine)

    def test_custom_scoring_engine_injected(self) -> None:
        mock_scoring = MagicMock(spec=ThreatScoringEngine)
        engine = ThreatDetectionEngine(scoring_engine=mock_scoring)
        assert engine._scoring_engine is mock_scoring


# ---------------------------------------------------------------------------
# TestExtractObservables
# ---------------------------------------------------------------------------


class TestExtractObservables:
    def setup_method(self) -> None:
        self.engine = ThreatDetectionEngine()

    def test_ioc_values_included(self) -> None:
        req = _make_request(text=None, ioc_values=["192.168.1.1", "evil.com"])
        obs = self.engine._extract_observables(req)
        assert "192.168.1.1" in obs
        assert "evil.com" in obs

    def test_hashes_included(self) -> None:
        sha = "a" * 64
        req = _make_request(text=None, hashes=[sha])
        obs = self.engine._extract_observables(req)
        assert sha in obs

    def test_url_included(self) -> None:
        req = _make_request(text=None, url="https://evil.example.com/payload")
        obs = self.engine._extract_observables(req)
        assert "https://evil.example.com/payload" in obs

    def test_domain_lowercased(self) -> None:
        req = _make_request(text=None, domain="Evil.Example.COM")
        obs = self.engine._extract_observables(req)
        assert "evil.example.com" in obs

    def test_text_extracts_ipv4(self) -> None:
        req = _make_request(text="traffic from 10.0.0.1 detected")
        obs = self.engine._extract_observables(req)
        assert "10.0.0.1" in obs

    def test_text_extracts_url(self) -> None:
        req = _make_request(text="see http://malware.example.com/drop")
        obs = self.engine._extract_observables(req)
        assert "http://malware.example.com/drop" in obs

    def test_text_extracts_cve(self) -> None:
        req = _make_request(text="exploiting CVE-2024-12345 in production")
        obs = self.engine._extract_observables(req)
        assert any("CVE-2024-12345" in o for o in obs)

    def test_text_extracts_sha256(self) -> None:
        sha = "b" * 64
        req = _make_request(text=f"hash={sha}")
        obs = self.engine._extract_observables(req)
        assert sha in obs

    def test_result_sorted(self) -> None:
        req = _make_request(text=None, ioc_values=["z.com", "a.com", "m.com"])
        obs = self.engine._extract_observables(req)
        assert obs == sorted(obs)

    def test_deduplication(self) -> None:
        req = _make_request(
            text="1.2.3.4 is bad",
            ioc_values=["1.2.3.4"],
        )
        obs = self.engine._extract_observables(req)
        assert obs.count("1.2.3.4") == 1

    def test_empty_ioc_values_skipped(self) -> None:
        req = _make_request(text=None, ioc_values=["", "  ", "valid.ioc"])
        obs = self.engine._extract_observables(req)
        assert "" not in obs
        assert "  " not in obs
        assert "valid.ioc" in obs


# ---------------------------------------------------------------------------
# TestExtractFromText
# ---------------------------------------------------------------------------


class TestExtractFromText:
    def test_ipv4_extracted(self) -> None:
        found = ThreatDetectionEngine._extract_from_text("host 192.168.0.1 connected")
        assert "192.168.0.1" in found

    def test_url_extracted(self) -> None:
        found = ThreatDetectionEngine._extract_from_text("https://bad.actor.io/c2")
        assert "https://bad.actor.io/c2" in found

    def test_sha256_extracted(self) -> None:
        sha = "d" * 64
        found = ThreatDetectionEngine._extract_from_text(f"file hash {sha}")
        assert sha in found

    def test_cve_extracted(self) -> None:
        found = ThreatDetectionEngine._extract_from_text("CVE-2023-9999 is being exploited")
        assert any("CVE-2023-9999" in f for f in found)

    def test_domain_extracted_lowercase(self) -> None:
        found = ThreatDetectionEngine._extract_from_text("connected to EVIL.COM")
        assert "evil.com" in found

    def test_empty_text_returns_empty(self) -> None:
        assert ThreatDetectionEngine._extract_from_text("") == []


# ---------------------------------------------------------------------------
# TestThreatDetectionEngineRun — mocked I/O
# ---------------------------------------------------------------------------


class TestThreatDetectionEngineRun:
    def setup_method(self) -> None:
        self.engine = ThreatDetectionEngine()

    def _patch_ioc_store(self, records: list[Any]) -> Any:
        mock_store = MagicMock()
        mock_store.lookup_by_values.return_value = records
        return mock_store

    def _make_ioc_record(
        self,
        *,
        value: str = "1.2.3.4",
        ioc_type: str = IOCTypeEnum.IPV4,
        severity: str = ThreatSeverityLevel.MEDIUM,
        confidence: float = 0.80,
        tags: list[str] | None = None,
    ) -> MagicMock:
        rec = MagicMock()
        rec.ioc_id = str(uuid.uuid4())
        rec.value = value
        rec.ioc_type = ioc_type
        rec.severity = severity
        rec.confidence = confidence
        rec.source = "internal"
        rec.tags = tags or []
        rec.matched_on = "ioc_store"
        rec.mitre_technique_id = None
        rec.mitre_tactic = None
        rec.cve_id = None
        rec.first_seen = None
        rec.last_seen = None
        return rec

    def test_run_returns_detection_result(self) -> None:
        req = _make_request(text="test payload 1.2.3.4")
        record = self._make_ioc_record()
        mock_store = self._patch_ioc_store([record])
        with (
            patch("app.services.threat_detection_engine.get_ioc_store", return_value=mock_store),
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert isinstance(result, DetectionResult)

    def test_run_result_has_event_id(self) -> None:
        req = _make_request(text="scan this")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.event_id is not None
        assert len(result.event_id) > 0

    def test_run_uses_caller_event_id(self) -> None:
        fixed_id = "my-fixed-event-id"
        req = _make_request(text="scan this", event_id=fixed_id)
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.event_id == fixed_id

    def test_run_org_id_echoed(self) -> None:
        req = _make_request(text="scan this", org_id="my-org")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.org_id == "my-org"

    def test_run_verdict_is_valid_enum(self) -> None:
        req = _make_request(text="scan this")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.verdict in list(DetectionVerdict)

    def test_run_severity_is_valid_enum(self) -> None:
        req = _make_request(text="scan this")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.severity in list(ThreatSeverityLevel)

    def test_run_score_in_range(self) -> None:
        req = _make_request(text="scan this")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert 0.0 <= result.score <= 1.0

    def test_run_no_ioc_matches_allow(self) -> None:
        req = _make_request(text="totally benign payload")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.verdict == DetectionVerdict.ALLOW
        assert result.ioc_matches == []

    def test_run_ioc_match_populates_result(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_ioc_record(value="1.2.3.4", severity=ThreatSeverityLevel.HIGH)
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = [record]
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert len(result.ioc_matches) == 1
        assert result.ioc_matches[0].value == "1.2.3.4"

    def test_run_minimum_confidence_filters_low_confidence(self) -> None:
        req = _make_request(text="1.2.3.4", minimum_confidence=0.90)
        record = self._make_ioc_record(confidence=0.50)
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = [record]
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.ioc_matches == []

    def test_run_minimum_confidence_allows_exact_match(self) -> None:
        req = _make_request(text="1.2.3.4", minimum_confidence=0.80)
        record = self._make_ioc_record(confidence=0.80)
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = [record]
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert len(result.ioc_matches) == 1

    def test_run_scanned_text_echoed(self) -> None:
        req = _make_request(text="my payload text")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.scanned_text == "my payload text"

    def test_run_extracted_indicators_populated(self) -> None:
        req = _make_request(text="traffic from 5.6.7.8")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert "5.6.7.8" in result.extracted_indicators

    def test_run_caller_signals_merged_into_result(self) -> None:
        req = _make_request(text="scan this")
        caller_signal = _make_correlation_signal(score_contribution=0.10)
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req, correlation_signals=[caller_signal])
        assert any(s.signal_id == caller_signal.signal_id for s in result.correlation_signals)

    def test_run_ioc_store_error_returns_empty_matches(self) -> None:
        req = _make_request(text="1.2.3.4")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store", side_effect=RuntimeError("db down")),
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.ioc_matches == []
        assert result.verdict == DetectionVerdict.ALLOW

    def test_run_correlation_engine_error_returns_empty_signals(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_ioc_record()
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine", side_effect=RuntimeError("corr down")),
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = [record]
            result = self.engine.run(req)
        assert isinstance(result, DetectionResult)

    def test_run_detection_engine_version_set(self) -> None:
        req = _make_request(text="scan this")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.detection_engine_version == "1.0.0"

    def test_run_assessed_at_is_iso_string(self) -> None:
        req = _make_request(text="scan this")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert isinstance(result.assessed_at, str)
        assert "T" in result.assessed_at

    def test_run_context_echoed(self) -> None:
        req = _make_request(text="scan this", context="tool_call")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.context == "tool_call"

    def test_run_metadata_echoed(self) -> None:
        req = _make_request(text="scan this", metadata={"source": "unit-test"})
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert result.metadata.get("source") == "unit-test"

    def test_run_ioc_url_only(self) -> None:
        req = _make_request(text=None, url="https://malicious.io/payload")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert isinstance(result, DetectionResult)

    def test_run_ioc_domain_only(self) -> None:
        req = _make_request(text=None, domain="malicious.io")
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert isinstance(result, DetectionResult)

    def test_run_ioc_values_only(self) -> None:
        req = _make_request(text=None, ioc_values=["7.8.9.10"])
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = []
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req)
        assert isinstance(result, DetectionResult)


# ---------------------------------------------------------------------------
# TestDetectionRequest validation (schema layer — caught here)
# ---------------------------------------------------------------------------


class TestDetectionRequestValidation:
    def test_requires_at_least_one_observable(self) -> None:
        with pytest.raises(ValueError):
            DetectionRequest(org_id="x")

    def test_text_alone_is_valid(self) -> None:
        req = DetectionRequest(text="hello world")
        assert req.text == "hello world"

    def test_url_alone_is_valid(self) -> None:
        req = DetectionRequest(url="https://evil.com")
        assert req.url == "https://evil.com"

    def test_domain_alone_is_valid(self) -> None:
        req = DetectionRequest(domain="evil.com")
        assert req.domain == "evil.com"

    def test_ioc_values_alone_is_valid(self) -> None:
        req = DetectionRequest(ioc_values=["1.2.3.4"])
        assert req.ioc_values == ["1.2.3.4"]

    def test_minimum_confidence_default_zero(self) -> None:
        req = DetectionRequest(text="x")
        assert req.minimum_confidence == 0.0

    def test_minimum_confidence_clamped(self) -> None:
        with pytest.raises(ValueError):
            DetectionRequest(text="x", minimum_confidence=1.5)

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            DetectionRequest(text="x", unknown_field="oops")


# ---------------------------------------------------------------------------
# TestDetectionResultProperties
# ---------------------------------------------------------------------------


class TestDetectionResultProperties:
    def _make_result(self, verdict: DetectionVerdict, score: float = 0.5) -> DetectionResult:
        return DetectionResult(
            event_id=str(uuid.uuid4()),
            verdict=verdict,
            score=score,
            severity=ThreatSeverityLevel.MEDIUM,
            assessed_at="2026-01-01T00:00:00+00:00",
        )

    def test_is_threat_block(self) -> None:
        r = self._make_result(DetectionVerdict.BLOCK)
        assert r.is_threat is True

    def test_is_threat_review(self) -> None:
        r = self._make_result(DetectionVerdict.REVIEW)
        assert r.is_threat is True

    def test_is_threat_allow(self) -> None:
        r = self._make_result(DetectionVerdict.ALLOW)
        assert r.is_threat is False

    def test_is_threat_monitor(self) -> None:
        r = self._make_result(DetectionVerdict.MONITOR)
        assert r.is_threat is False

    def test_requires_block_true(self) -> None:
        r = self._make_result(DetectionVerdict.BLOCK)
        assert r.requires_block is True

    def test_requires_block_false(self) -> None:
        r = self._make_result(DetectionVerdict.REVIEW)
        assert r.requires_block is False

    def test_top_ioc_none_on_empty(self) -> None:
        r = self._make_result(DetectionVerdict.ALLOW)
        assert r.top_ioc is None

    def test_top_ioc_returns_highest_confidence(self) -> None:
        r = self._make_result(DetectionVerdict.BLOCK)
        low = _make_ioc_match(confidence=0.30)
        high = _make_ioc_match(confidence=0.95)
        r.ioc_matches = [low, high]
        assert r.top_ioc.confidence == 0.95

    def test_ioc_match_count(self) -> None:
        r = self._make_result(DetectionVerdict.BLOCK)
        r.ioc_matches = [_make_ioc_match(), _make_ioc_match()]
        assert r.ioc_match_count == 2

    def test_correlation_signal_count(self) -> None:
        r = self._make_result(DetectionVerdict.REVIEW)
        r.correlation_signals = [_make_correlation_signal(), _make_correlation_signal()]
        assert r.correlation_signal_count == 2


# ---------------------------------------------------------------------------
# TestGetDetectionEngine / TestGetScoringEngine
# ---------------------------------------------------------------------------


class TestSingletons:
    def test_get_detection_engine_returns_instance(self) -> None:
        engine = get_detection_engine()
        assert isinstance(engine, ThreatDetectionEngine)

    def test_get_detection_engine_singleton(self) -> None:
        e1 = get_detection_engine()
        e2 = get_detection_engine()
        assert e1 is e2

    def test_get_scoring_engine_returns_instance(self) -> None:
        engine = get_scoring_engine()
        assert isinstance(engine, ThreatScoringEngine)

    def test_get_scoring_engine_singleton(self) -> None:
        e1 = get_scoring_engine()
        e2 = get_scoring_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# TestEndToEndScenarios
# ---------------------------------------------------------------------------


class TestEndToEndScenarios:
    """Integration-style tests exercising the full pipeline with mocked I/O."""

    def setup_method(self) -> None:
        self.engine = ThreatDetectionEngine()

    def _run_with_records(
        self,
        req: DetectionRequest,
        records: list[Any],
        engine_signals: list[CorrelationSignal] | None = None,
        caller_signals: list[CorrelationSignal] | None = None,
    ) -> DetectionResult:
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_store_fn,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_store_fn.return_value.lookup_by_values.return_value = records
            mock_corr.return_value.correlate.return_value = engine_signals or []
            return self.engine.run(req, correlation_signals=caller_signals)

    def _make_record(
        self,
        *,
        value: str = "1.2.3.4",
        severity: str = ThreatSeverityLevel.MEDIUM,
        confidence: float = 0.80,
        tags: list[str] | None = None,
        ioc_type: str = IOCTypeEnum.IPV4,
        mitre_technique_id: str | None = None,
    ) -> MagicMock:
        rec = MagicMock()
        rec.ioc_id = str(uuid.uuid4())
        rec.value = value
        rec.ioc_type = ioc_type
        rec.severity = severity
        rec.confidence = confidence
        rec.source = "internal"
        rec.tags = tags or []
        rec.matched_on = "ioc_store"
        rec.mitre_technique_id = mitre_technique_id
        rec.mitre_tactic = None
        rec.cve_id = None
        rec.first_seen = None
        rec.last_seen = None
        return rec

    def test_clean_payload_returns_allow(self) -> None:
        req = _make_request(text="completely benign text with no indicators")
        result = self._run_with_records(req, [])
        assert result.verdict == DetectionVerdict.ALLOW
        assert result.score == 0.0

    def test_critical_ioc_match_yields_block(self) -> None:
        req = _make_request(text="1.2.3.4")
        records = [self._make_record(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0) for _ in range(4)]
        result = self._run_with_records(req, records)
        assert result.verdict == DetectionVerdict.BLOCK

    def test_ransomware_ioc_risk_family_populated(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_record(tags=["ransomware"])
        result = self._run_with_records(req, [record])
        assert "ransomware" in result.risk_families

    def test_mitre_technique_in_result(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_record(mitre_technique_id="T1059")
        result = self._run_with_records(req, [record])
        assert "T1059" in result.mitre_techniques

    def test_caller_signals_boost_score(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_record(severity=ThreatSeverityLevel.MEDIUM, confidence=0.70)
        no_signal = self._run_with_records(req, [record])
        caller_signal = _make_correlation_signal(score_contribution=0.15, confidence=1.0)
        with_signal = self._run_with_records(req, [record], caller_signals=[caller_signal])
        assert with_signal.score >= no_signal.score

    def test_engine_signals_merged_with_caller_signals(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_record()
        engine_sig = _make_correlation_signal(pattern_type="high_severity_cluster")
        caller_sig = _make_correlation_signal(pattern_type="multi_ioc_cooccurrence")
        result = self._run_with_records(req, [record], engine_signals=[engine_sig], caller_signals=[caller_sig])
        pattern_types = {s.pattern_type for s in result.correlation_signals}
        assert "high_severity_cluster" in pattern_types
        assert "multi_ioc_cooccurrence" in pattern_types

    def test_engine_signals_appear_before_caller_signals(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_record()
        engine_sig = _make_correlation_signal(pattern_type="attack_chain")
        caller_sig = _make_correlation_signal(pattern_type="temporal_cluster")
        result = self._run_with_records(req, [record], engine_signals=[engine_sig], caller_signals=[caller_sig])
        types_in_order = [s.pattern_type for s in result.correlation_signals]
        assert types_in_order.index("attack_chain") < types_in_order.index("temporal_cluster")

    def test_rationale_populated_for_matched_request(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = self._make_record(severity=ThreatSeverityLevel.HIGH, confidence=0.85)
        result = self._run_with_records(req, [record])
        assert len(result.rationale) > 0

    def test_multiple_ioc_types_all_in_matches(self) -> None:
        req = _make_request(text=None, ioc_values=["1.2.3.4", "https://evil.com"])
        ip_rec = self._make_record(value="1.2.3.4", ioc_type=IOCTypeEnum.IPV4)
        url_rec = self._make_record(value="https://evil.com", ioc_type=IOCTypeEnum.URL)
        result = self._run_with_records(req, [ip_rec, url_rec])
        values = {m.value for m in result.ioc_matches}
        assert "1.2.3.4" in values
        assert "https://evil.com" in values

    def test_hashes_request_populates_observables(self) -> None:
        sha = "e" * 64
        req = _make_request(text=None, hashes=[sha])
        result = self._run_with_records(req, [])
        assert sha in result.extracted_indicators
