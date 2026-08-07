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
    _coerce_float,
    _coerce_lookup_records,
    _coerce_severity,
    _coerce_str_list,
    _dedupe_preserve_order,
    _enum_like_value,
    _extract_match_risk_families,
    _get_optional_notification_engine,
    _highest_ioc_severity,
    _max_severity,
    _max_verdict,
    _normalize_collection_value,
    _normalize_mitre_value,
    _string_or_none,
    get_detection_engine,
    get_scoring_engine,
)


def _ioc_type_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _severity_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _signal_type(signal: CorrelationSignal) -> str:
    return (getattr(signal, "pattern_type", None) or getattr(signal, "signal_type", None) or getattr(signal, "type", None) or "").lower().strip()


def _normalize_mitre(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values or []:
        normalized = str(value).upper().strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def _signal_merge_key(signal: CorrelationSignal) -> tuple[str, tuple[str, ...]]:
    return (
        _signal_type(signal),
        tuple(_normalize_mitre(getattr(signal, "mitre_technique_ids", []) or [])),
    )


def _signal_types(signals: list[CorrelationSignal]) -> list[str]:
    return [_signal_type(s) for s in signals]


def _make_ioc_match(
    *,
    value: str = "1.2.3.4",
    ioc_type: str | IOCTypeEnum = IOCTypeEnum.IPV4,
    severity: str | ThreatSeverityLevel = ThreatSeverityLevel.MEDIUM,
    confidence: float = 0.80,
    tags: list[str] | None = None,
    risk_families: list[str] | None = None,
    mitre_technique_id: str | None = None,
    mitre_tactic: str | None = None,
    cve_id: str | None = None,
    source: str = "internal",
    ioc_id: str | None = None,
) -> IOCMatch:
    combined_tags = list(tags or [])
    for value_tag in risk_families or []:
        if value_tag not in combined_tags:
            combined_tags.append(value_tag)

    return IOCMatch(
        ioc_id=ioc_id or str(uuid.uuid4()),
        value=value,
        ioc_type=_ioc_type_value(ioc_type),
        severity=_severity_value(severity),
        confidence=confidence,
        source=source,
        tags=combined_tags,
        matched_on="ioc_store",
        mitre_technique_id=mitre_technique_id,
        mitre_tactic=mitre_tactic,
        cve_id=cve_id,
    )


def _make_correlation_signal(
    *,
    pattern_type: str = "multi_ioc_cooccurrence",
    score_contribution: float = 0.10,
    confidence: float = 0.80,
    mitre_technique_ids: list[str] | None = None,
    description: str = "",
) -> CorrelationSignal:
    return CorrelationSignal(
        signal_id=str(uuid.uuid4()),
        pattern_type=pattern_type,
        signal_type=pattern_type,
        matched_event_ids=[],
        contributing_ioc_ids=[],
        mitre_technique_ids=mitre_technique_ids or [],
        confidence=confidence,
        score_contribution=score_contribution,
        description=description,
    )


def _make_request(**kwargs: Any) -> DetectionRequest:
    defaults: dict[str, Any] = {
        "text": "connecting to 1.2.3.4 via http://evil.example.com",
        "org_id": "test-org",
        "agent_id": "agent-001",
        "session_id": "session-001",
        "minimum_confidence": 0.0,
    }
    defaults.update(kwargs)
    return DetectionRequest(**defaults)


def _make_ioc_record(
    *,
    value: str = "1.2.3.4",
    ioc_type: str | IOCTypeEnum = IOCTypeEnum.IPV4,
    severity: str | ThreatSeverityLevel = ThreatSeverityLevel.MEDIUM,
    confidence: float = 0.80,
    tags: list[str] | None = None,
    risk_families: list[str] | None = None,
    mitre_technique_id: str | None = None,
    mitre_tactic: str | None = None,
    cve_id: str | None = None,
    source: str = "internal",
    ioc_id: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> MagicMock:
    rec = MagicMock()
    rec.ioc_id = ioc_id
    rec.value = value
    rec.ioc_value = value
    rec.ioc_type = _ioc_type_value(ioc_type)
    rec.type = _ioc_type_value(ioc_type)
    rec.severity = severity
    rec.confidence = confidence
    rec.score = confidence
    rec.source = source
    rec.feed = source
    rec.tags = list(tags or [])
    rec.risk_families = list(risk_families or [])
    rec.mitre_technique_id = mitre_technique_id
    rec.mitre_tactic = mitre_tactic
    rec.cve_id = cve_id
    rec.first_seen = first_seen
    rec.last_seen = last_seen
    return rec


class _SignalTypeStub:
    def __init__(
        self,
        *,
        signal_type: str | None = None,
        pattern_type: str | None = None,
        type: str | None = None,
    ) -> None:
        self.signal_type = signal_type
        self.pattern_type = pattern_type
        self.type = type


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
        assert result.severity == ThreatSeverityLevel.INFO

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
        signal = _make_correlation_signal(
            pattern_type="attack_chain",
            score_contribution=0.15,
            confidence=1.0,
        )
        boosted = self.engine.compute([m], [signal])
        assert boosted.normalized_score >= base.normalized_score

    def test_verdict_block_at_high_score(self) -> None:
        matches = [_make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0) for _ in range(4)]
        result = self.engine.compute(matches, [])
        assert result.verdict == DetectionVerdict.BLOCK

    def test_risk_families_from_tags(self) -> None:
        m = _make_ioc_match(tags=["ransomware", "c2"])
        result = self.engine.compute([m], [])
        assert "ransomware" in result.risk_families
        assert "c2" in result.risk_families

    def test_risk_families_include_engine_signal_families(self) -> None:
        m = _make_ioc_match(tags=["credential_theft"])
        signals = [
            _make_correlation_signal(pattern_type="attack_chain"),
            _make_correlation_signal(pattern_type="high_severity_cluster"),
        ]
        result = self.engine.compute([m], signals)
        assert "credential_theft" in result.risk_families
        assert "attack_chain" in result.risk_families
        assert "high_severity_cluster" in result.risk_families

    def test_mitre_techniques_extracted_and_deduplicated_in_order(self) -> None:
        m1 = _make_ioc_match(mitre_technique_id="T1059")
        m2 = _make_ioc_match(mitre_technique_id="t1078")
        sig = _make_correlation_signal(
            pattern_type="attack_chain",
            mitre_technique_ids=["t1059", "T1204"],
        )
        result = self.engine.compute([m1, m2], [sig])
        assert result.mitre_techniques == ["T1059", "T1078", "T1204"]

    def test_high_ioc_plus_attack_chain_elevates_to_block(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.HIGH, confidence=0.40)
        sig = _make_correlation_signal(
            pattern_type="attack_chain",
            score_contribution=0.01,
            confidence=0.20,
        )
        result = self.engine.compute([m], [sig])
        assert result.verdict == DetectionVerdict.BLOCK

    def test_verdict_thresholds_cover_allow_monitor_review_block(self) -> None:
        assert self.engine._verdict_from_score(0.00) == DetectionVerdict.ALLOW
        assert self.engine._verdict_from_score(0.20) == DetectionVerdict.MONITOR
        assert self.engine._verdict_from_score(0.50) == DetectionVerdict.REVIEW
        assert self.engine._verdict_from_score(0.75) == DetectionVerdict.BLOCK

    def test_severity_thresholds_cover_info_low_medium_high_critical(self) -> None:
        assert self.engine._severity_from_score(0.00, []) == ThreatSeverityLevel.INFO
        assert self.engine._severity_from_score(0.10, []) == ThreatSeverityLevel.LOW
        assert self.engine._severity_from_score(0.25, []) == ThreatSeverityLevel.MEDIUM
        high_match = [_make_ioc_match(severity=ThreatSeverityLevel.HIGH)]
        assert self.engine._severity_from_score(0.50, high_match) == ThreatSeverityLevel.HIGH
        assert self.engine._severity_from_score(0.75, []) == ThreatSeverityLevel.CRITICAL

    def test_rationale_includes_no_ioc_matches_line(self) -> None:
        result = self.engine.compute([], [])
        assert "No IOC matches found." in result.rationale

    def test_rationale_includes_signal_specific_lines(self) -> None:
        m = _make_ioc_match(severity=ThreatSeverityLevel.HIGH, confidence=0.90)
        signals = [
            _make_correlation_signal(pattern_type="attack_chain"),
            _make_correlation_signal(pattern_type="high_severity_cluster"),
        ]
        result = self.engine.compute([m], signals)
        assert "Attack-chain correlation signal detected." in result.rationale
        assert "High-severity IOC cluster signal detected." in result.rationale

    def test_attack_chain_without_iocs_elevates_info_to_medium(self) -> None:
        severity = self.engine._elevate_severity_for_enrichment(
            ThreatSeverityLevel.INFO,
            [],
            [_make_correlation_signal(pattern_type="attack_chain")],
        )
        assert severity == ThreatSeverityLevel.MEDIUM

    def test_critical_ioc_always_elevates_verdict_to_block(self) -> None:
        verdict = self.engine._elevate_verdict_for_iocs(
            DetectionVerdict.ALLOW,
            [_make_ioc_match(severity=ThreatSeverityLevel.CRITICAL, confidence=0.10)],
            [],
        )
        assert verdict == DetectionVerdict.BLOCK


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


class TestThreatDetectionEngineInit:
    def test_default_scoring_engine_injected(self) -> None:
        engine = ThreatDetectionEngine()
        assert isinstance(engine._scoring_engine, ThreatScoringEngine)

    def test_custom_scoring_engine_injected(self) -> None:
        mock_scoring = MagicMock(spec=ThreatScoringEngine)
        engine = ThreatDetectionEngine(scoring_engine=mock_scoring)
        assert engine._scoring_engine is mock_scoring


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
        req = _make_request(text=None, url="https://evil.EXAMPLE.com/payload")
        obs = self.engine._extract_observables(req)
        assert "https://evil.EXAMPLE.com/payload" in obs

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
        req = _make_request(text="1.2.3.4 is bad", ioc_values=["1.2.3.4"])
        obs = self.engine._extract_observables(req)
        assert obs.count("1.2.3.4") == 1

    def test_domain_from_text_is_lowercased_but_url_not_lowercased(self) -> None:
        req = _make_request(text="Visit HTTP://EVIL.EXAMPLE.COM and evil.example.com")
        obs = self.engine._extract_observables(req)
        assert "evil.example.com" in obs


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

    def test_sha1_and_md5_extracted(self) -> None:
        sha1 = "a" * 40
        md5 = "b" * 32
        found = ThreatDetectionEngine._extract_from_text(f"{sha1} {md5}")
        assert sha1 in found
        assert md5 in found


class TestThreatDetectionEngineRun:
    def setup_method(self) -> None:
        self.engine = ThreatDetectionEngine()

    def _run(
        self,
        req: DetectionRequest,
        *,
        records: list[Any] | None = None,
        engine_signals: list[CorrelationSignal] | None = None,
        caller_signals: list[CorrelationSignal] | None = None,
        correlation_side_effect: Exception | None = None,
        notification_engine: Any = None,
        derived_signals: list[CorrelationSignal] | None = None,
    ) -> tuple[DetectionResult, MagicMock, MagicMock]:
        mock_store = MagicMock()
        mock_store.lookup_by_values.return_value = records if records is not None else []

        mock_corr = MagicMock()
        if correlation_side_effect is not None:
            mock_corr.correlate.side_effect = correlation_side_effect
        else:
            mock_corr.correlate.return_value = engine_signals if engine_signals is not None else []

        fallback_signals = derived_signals if derived_signals is not None else []

        with (
            patch("app.services.threat_detection_engine.get_ioc_store", return_value=mock_store),
            patch(
                "app.services.threat_detection_engine.get_correlation_engine",
                return_value=mock_corr,
            ),
            patch.object(
                ThreatDetectionEngine,
                "_derive_engine_signals",
                return_value=fallback_signals,
            ),
        ):
            result = self.engine.run(
                req,
                correlation_signals=caller_signals,
                notification_engine=notification_engine,
            )

        return result, mock_store, mock_corr

    def test_run_returns_detection_result(self) -> None:
        req = _make_request(text="test payload 1.2.3.4")
        record = _make_ioc_record()
        result, _, _ = self._run(req, records=[record], derived_signals=[])
        assert isinstance(result, DetectionResult)

    def test_run_result_has_event_id(self) -> None:
        req = _make_request(text="scan this")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.event_id is not None
        assert len(result.event_id) > 0

    def test_run_uses_caller_event_id(self) -> None:
        fixed_id = "my-fixed-event-id"
        req = _make_request(text="scan this", event_id=fixed_id)
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.event_id == fixed_id

    def test_run_org_id_echoed(self) -> None:
        req = _make_request(text="scan this", org_id="my-org")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.org_id == "my-org"

    def test_run_verdict_is_valid_enum(self) -> None:
        req = _make_request(text="scan this")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.verdict in list(DetectionVerdict)

    def test_run_severity_is_valid_enum(self) -> None:
        req = _make_request(text="scan this")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.severity in list(ThreatSeverityLevel)

    def test_run_score_in_range(self) -> None:
        req = _make_request(text="scan this")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert 0.0 <= result.score <= 1.0

    def test_run_no_ioc_matches_allow(self) -> None:
        req = _make_request(text="totally benign payload")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.verdict == DetectionVerdict.ALLOW
        assert result.ioc_matches == []

    def test_run_ioc_match_populates_result(self) -> None:
        req = _make_request(text="1.2.3.4")
        match = _make_ioc_match(
            ioc_id="record-1",
            value="1.2.3.4",
            severity=ThreatSeverityLevel.HIGH,
            confidence=0.80,
        )
        with patch.object(self.engine, "_resolve_ioc_matches", return_value=[match]):
            result, _, _ = self._run(req, records=[], derived_signals=[])
        assert len(result.ioc_matches) == 1
        assert result.ioc_matches[0].value == "1.2.3.4"

    def test_run_minimum_confidence_filters_low_confidence(self) -> None:
        req = _make_request(text="1.2.3.4", minimum_confidence=0.90)
        record = _make_ioc_record(confidence=0.50)
        result, _, _ = self._run(req, records=[record], derived_signals=[])
        assert result.ioc_matches == []

    def test_run_minimum_confidence_allows_exact_match(self) -> None:
        req = _make_request(text="1.2.3.4", minimum_confidence=0.80)
        match = _make_ioc_match(
            ioc_id="record-1",
            value="1.2.3.4",
            severity=ThreatSeverityLevel.MEDIUM,
            confidence=0.80,
        )
        with patch.object(self.engine, "_resolve_ioc_matches", return_value=[match]):
            result, _, _ = self._run(req, records=[], derived_signals=[])
        assert len(result.ioc_matches) == 1

    def test_run_scanned_text_echoed(self) -> None:
        req = _make_request(text="my payload text")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.scanned_text == "my payload text"

    def test_run_extracted_indicators_populated(self) -> None:
        req = _make_request(text="traffic from 5.6.7.8")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert "5.6.7.8" in result.extracted_indicators

    def test_run_caller_signals_merged_into_result(self) -> None:
        req = _make_request(text="scan this")
        caller_signal = _make_correlation_signal(score_contribution=0.10)
        result, _, _ = self._run(
            req,
            records=[],
            caller_signals=[caller_signal],
            derived_signals=[],
        )
        assert any(s.signal_id == caller_signal.signal_id for s in result.correlation_signals)

    def test_run_ioc_store_error_returns_empty_matches(self) -> None:
        req = _make_request(text="1.2.3.4")
        with (
            patch(
                "app.services.threat_detection_engine.get_ioc_store",
                side_effect=RuntimeError("db down"),
            ),
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_corr,
        ):
            mock_corr.return_value.correlate.return_value = []
            result = self.engine.run(req, notification_engine=None)
        assert result.ioc_matches == []
        assert result.verdict == DetectionVerdict.ALLOW

    def test_run_correlation_engine_error_falls_back_to_derived_engine_signals(self) -> None:
        req = _make_request(text="1.2.3.4")
        match = _make_ioc_match(
            ioc_id="record-1",
            value="1.2.3.4",
            severity=ThreatSeverityLevel.HIGH,
            confidence=0.90,
            mitre_technique_id="T1059",
        )
        fallback = [
            _make_correlation_signal(
                pattern_type="attack_chain",
                mitre_technique_ids=["T1059"],
            ),
            _make_correlation_signal(
                pattern_type="high_severity_cluster",
                mitre_technique_ids=["T1059"],
            ),
        ]
        with patch.object(self.engine, "_resolve_ioc_matches", return_value=[match]):
            result, _, _ = self._run(
                req,
                records=[],
                correlation_side_effect=RuntimeError("corr down"),
                derived_signals=fallback,
            )
        types = _signal_types(result.correlation_signals)
        assert "attack_chain" in types
        assert "high_severity_cluster" in types

    def test_run_detection_engine_version_set(self) -> None:
        req = _make_request(text="scan this")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.detection_engine_version == "1.0.0"

    def test_run_assessed_at_is_iso_string(self) -> None:
        req = _make_request(text="scan this")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert isinstance(result.assessed_at, str)
        assert "T" in result.assessed_at

    def test_run_context_echoed(self) -> None:
        req = _make_request(text="scan this", context="tool_call")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.context == "tool_call"

    def test_run_metadata_echoed(self) -> None:
        req = _make_request(text="scan this", metadata={"source": "unit-test"})
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert result.metadata.get("source") == "unit-test"

    def test_run_ioc_url_only(self) -> None:
        req = _make_request(text=None, url="https://malicious.io/payload")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert isinstance(result, DetectionResult)

    def test_run_ioc_domain_only(self) -> None:
        req = _make_request(text=None, domain="malicious.io")
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert isinstance(result, DetectionResult)

    def test_run_ioc_values_only(self) -> None:
        req = _make_request(text=None, ioc_values=["7.8.9.10"])
        result, _, _ = self._run(req, records=[], derived_signals=[])
        assert isinstance(result, DetectionResult)

    def test_run_success_path_calls_notify_detection_once(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = _make_ioc_record(value="1.2.3.4")
        notification_engine = MagicMock()
        result, _, _ = self._run(
            req,
            records=[record],
            notification_engine=notification_engine,
            derived_signals=[],
        )
        assert result.event_id
        notification_engine.notify_detection.assert_called_once()

    def test_run_uses_notify_method_when_notify_detection_missing(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = _make_ioc_record(value="1.2.3.4")
        notification_engine = MagicMock(spec=["notify"])
        result, _, _ = self._run(
            req,
            records=[record],
            notification_engine=notification_engine,
            derived_signals=[],
        )
        assert result.event_id
        notification_engine.notify.assert_called_once()

    def test_run_uses_optional_notification_engine_when_injected_none(self) -> None:
        req = _make_request(text="1.2.3.4")
        record = _make_ioc_record(value="1.2.3.4")

        notification_engine = MagicMock()
        with (
            patch("app.services.threat_detection_engine.get_ioc_store") as mock_get_store,
            patch("app.services.threat_detection_engine.get_correlation_engine") as mock_get_corr,
            patch(
                "app.services.threat_detection_engine._get_optional_notification_engine",
                return_value=notification_engine,
            ),
            patch.object(ThreatDetectionEngine, "_derive_engine_signals", return_value=[]),
        ):
            store = MagicMock()
            store.lookup_by_values.return_value = [record]
            mock_get_store.return_value = store

            corr = MagicMock()
            corr.correlate.return_value = []
            mock_get_corr.return_value = corr

            engine = ThreatDetectionEngine()
            engine.run(req, notification_engine=None)

        notification_engine.notify_detection.assert_called_once()


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


class TestSignalMergeContract:
    def setup_method(self) -> None:
        self.engine = ThreatDetectionEngine()

    def test_merge_places_engine_signals_before_caller_signals(self) -> None:
        engine_signals = [
            _make_correlation_signal(
                pattern_type="attack_chain",
                score_contribution=0.12,
                confidence=0.90,
            ),
            _make_correlation_signal(
                pattern_type="high_severity_cluster",
                score_contribution=0.10,
                confidence=0.80,
            ),
        ]
        caller_signals = [
            _make_correlation_signal(
                pattern_type="temporal_cluster",
                score_contribution=0.20,
                confidence=1.0,
            ),
            _make_correlation_signal(
                pattern_type="custom_signal",
                score_contribution=0.01,
                confidence=0.10,
            ),
        ]
        merged = self.engine._merge_correlation_signals(engine_signals, caller_signals)
        merged_types = _signal_types(merged)

        assert merged_types[:2] == ["attack_chain", "high_severity_cluster"]
        assert set(merged_types[2:]) == {"temporal_cluster", "custom_signal"}

    def test_merge_deduplicates_by_type_and_mitre_and_keeps_max_values(self) -> None:
        s1 = _make_correlation_signal(
            pattern_type="attack_chain",
            score_contribution=0.10,
            confidence=0.40,
            mitre_technique_ids=["t1059", "T1078"],
        )
        s2 = _make_correlation_signal(
            pattern_type="attack_chain",
            score_contribution=0.20,
            confidence=0.90,
            mitre_technique_ids=["T1059", "t1078"],
        )
        merged = self.engine._merge_correlation_signals([s1], [s2])

        grouped: dict[tuple[str, tuple[str, ...]], list[CorrelationSignal]] = {}
        for signal in merged:
            grouped.setdefault(_signal_merge_key(signal), []).append(signal)

        key = ("attack_chain", ("T1059", "T1078"))
        assert key in grouped
        assert len(grouped[key]) == 1
        merged_signal = grouped[key][0]
        assert merged_signal.confidence == 0.90
        assert merged_signal.score_contribution == 0.20
        assert _normalize_mitre(merged_signal.mitre_technique_ids) == ["T1059", "T1078"]

    def test_merge_preserves_existing_when_rebuild_fails(self) -> None:
        existing = _make_correlation_signal(
            pattern_type="attack_chain",
            mitre_technique_ids=["T1059"],
        )
        incoming = _make_correlation_signal(
            pattern_type="attack_chain",
            mitre_technique_ids=["T1059"],
        )
        with patch(
            "app.services.threat_detection_engine.CorrelationSignal",
            side_effect=RuntimeError("boom"),
        ):
            merged = self.engine._merge_correlation_signals([existing], [incoming])
        assert len(merged) == 1
        assert _signal_type(merged[0]) == "attack_chain"


class TestLookupAndRecordConversion:
    def setup_method(self) -> None:
        self.engine = ThreatDetectionEngine()

    def test_lookup_uses_lookup_by_value_when_lookup_by_values_returns_empty(self) -> None:
        store = MagicMock()
        store.lookup_by_values.return_value = []
        store.lookup_by_value.side_effect = lambda observable, **_: [_make_ioc_record(value=observable)]
        records = self.engine._lookup_ioc_records(
            store,
            observables=["1.2.3.4", "evil.com"],
            org_id="org-1",
        )
        assert len(records) == 2
        assert store.lookup_by_value.called

    def test_resolve_ioc_matches_dedupes_and_keeps_best_candidate(self) -> None:
        rec1 = _make_ioc_record(
            ioc_id="same-id",
            value="1.2.3.4",
            severity=ThreatSeverityLevel.MEDIUM,
            confidence=0.60,
            tags=["a"],
        )
        rec2 = _make_ioc_record(
            ioc_id="same-id",
            value="1.2.3.4",
            severity=ThreatSeverityLevel.HIGH,
            confidence=0.90,
            tags=["a", "b"],
            mitre_technique_id="T1059",
        )
        with (
            patch.object(self.engine, "_lookup_ioc_records", return_value=[rec1, rec2]),
            patch.object(
                ThreatDetectionEngine,
                "_coerce_record_candidates",
                side_effect=lambda rec, observables: [rec],
            ),
        ):
            matches = self.engine._resolve_ioc_matches(
                observables=["1.2.3.4"],
                org_id="org-1",
                minimum_confidence=0.0,
            )
        assert len(matches) == 1
        assert matches[0].severity == ThreatSeverityLevel.HIGH.value
        assert matches[0].confidence == 0.90
        assert matches[0].mitre_technique_id == "T1059"

    def test_record_to_ioc_match_filters_below_minimum_confidence(self) -> None:
        rec = _make_ioc_record(confidence=0.19)
        match = self.engine._record_to_ioc_match(rec, minimum_confidence=0.20)
        assert match is None

    def test_record_to_ioc_match_merges_risk_families_into_tags(self) -> None:
        expected = _make_ioc_match(
            ioc_id="test-id",
            value="1.2.3.4",
            tags=["tag1", "rf1", "rf2"],
        )
        rec = _make_ioc_record(
            ioc_id="test-id",
            tags=["tag1"],
            risk_families=["rf1", "rf2"],
        )
        with patch("app.services.threat_detection_engine.IOCMatch", return_value=expected):
            match = self.engine._record_to_ioc_match(rec, minimum_confidence=0.0)
        assert match is not None
        assert match.tags == ["tag1", "rf1", "rf2"]

    def test_record_to_ioc_match_uses_value_plus_type_when_ioc_id_missing(self) -> None:
        expected = _make_ioc_match(
            ioc_id="evil.com|domain",
            value="evil.com",
            ioc_type=IOCTypeEnum.DOMAIN,
        )
        rec = _make_ioc_record(
            ioc_id=None,
            value="evil.com",
            ioc_type=IOCTypeEnum.DOMAIN,
        )
        with patch("app.services.threat_detection_engine.IOCMatch", return_value=expected):
            match = self.engine._record_to_ioc_match(rec, minimum_confidence=0.0)
        assert match is not None
        assert match.ioc_id == "evil.com|domain"

    def test_resolve_ioc_matches_returns_empty_when_store_raises(self) -> None:
        with patch(
            "app.services.threat_detection_engine.get_ioc_store",
            side_effect=RuntimeError("db down"),
        ):
            matches = self.engine._resolve_ioc_matches(
                observables=["1.2.3.4"],
                org_id="org-1",
                minimum_confidence=0.0,
            )
        assert matches == []


class TestDerivedSignals:
    def test_derive_engine_signals_empty_for_no_iocs(self) -> None:
        assert ThreatDetectionEngine._derive_engine_signals([]) == []

    def test_run_correlation_returns_empty_when_no_iocs(self) -> None:
        assert ThreatDetectionEngine._run_correlation([], event_id="evt-1") == []


class TestModuleHelpers:
    def test_coerce_severity_defaults_to_low_for_unknown(self) -> None:
        assert _coerce_severity("not-real") == ThreatSeverityLevel.LOW

    def test_highest_ioc_severity(self) -> None:
        matches = [
            _make_ioc_match(severity=ThreatSeverityLevel.LOW),
            _make_ioc_match(severity=ThreatSeverityLevel.CRITICAL),
            _make_ioc_match(severity=ThreatSeverityLevel.MEDIUM),
        ]
        assert _highest_ioc_severity(matches) == ThreatSeverityLevel.CRITICAL

    def test_max_verdict(self) -> None:
        assert _max_verdict(DetectionVerdict.ALLOW, DetectionVerdict.BLOCK) == DetectionVerdict.BLOCK

    def test_max_severity(self) -> None:
        assert _max_severity(ThreatSeverityLevel.LOW, ThreatSeverityLevel.HIGH) == ThreatSeverityLevel.HIGH

    def test_normalize_mitre_value(self) -> None:
        assert _normalize_mitre_value("t1059") == "T1059"
        assert _normalize_mitre_value(None) is None

    def test_normalize_collection_value(self) -> None:
        assert _normalize_collection_value("High Severity Cluster") == "high_severity_cluster"
        assert _normalize_collection_value(None) == ""

    def test_dedupe_preserve_order(self) -> None:
        assert _dedupe_preserve_order(["a", "b", "a", "c"]) == ["a", "b", "c"]

    def test_coerce_str_list(self) -> None:
        result = _coerce_str_list({"a", "b"})
        assert sorted(result) == sorted(["a", "b"])
        assert _coerce_str_list(" lone ") == ["lone"]

    def test_extract_match_risk_families_prefers_risk_families(self) -> None:
        class _MatchStub:
            risk_families = ["rf1"]
            tags = ["tag1"]

        match = _MatchStub()
        assert _extract_match_risk_families(match) == ["rf1"]

    def test_extract_match_risk_families_falls_back_to_tags(self) -> None:
        match = _make_ioc_match(tags=["tag1"], risk_families=[])
        assert _extract_match_risk_families(match) == ["tag1"]

    def test_coerce_lookup_records_shapes(self) -> None:
        assert _coerce_lookup_records(None) == []
        assert _coerce_lookup_records([1, 2]) == [1, 2]
        assert _coerce_lookup_records((1, 2)) == [1, 2]
        assert _coerce_lookup_records({"items": [1, 2]}) == [1, 2]
        assert _coerce_lookup_records({"x": 1}) == [{"x": 1}]

    def test_string_or_none_handles_mock_objects(self) -> None:
        assert _string_or_none(MagicMock()) is None
        assert _string_or_none(" hi ") == "hi"

    def test_coerce_float(self) -> None:
        assert _coerce_float("1.5", default=0.0) == 1.5
        assert _coerce_float("bad", default=2.5) == 2.5

    def test_get_signal_type_reads_pattern_type_and_signal_type(self) -> None:
        sig_pattern = _make_correlation_signal(pattern_type="attack_chain")
        assert _signal_type(sig_pattern) == "attack_chain"

        sig_signal = _SignalTypeStub(
            pattern_type=None,
            signal_type="high_severity_cluster",
        )
        assert _signal_type(sig_signal) == "high_severity_cluster"

    def test_enum_like_value(self) -> None:
        assert _enum_like_value(ThreatSeverityLevel.HIGH) == ThreatSeverityLevel.HIGH.value

    def test_optional_notification_engine_returns_none_on_import_failure(self) -> None:
        with patch("builtins.__import__", side_effect=ImportError("missing")):
            assert _get_optional_notification_engine() is None


class TestSingletonFactories:
    def test_get_scoring_engine_singleton(self) -> None:
        a = get_scoring_engine()
        b = get_scoring_engine()
        assert a is b

    def test_get_detection_engine_singleton(self) -> None:
        a = get_detection_engine()
        b = get_detection_engine()
        assert a is b


class TestEndToEndScenarios:
    def setup_method(self) -> None:
        self.engine = ThreatDetectionEngine()

    def _run_with_records(
        self,
        req: DetectionRequest,
        *,
        records: list[Any] | None = None,
        engine_signals: list[CorrelationSignal] | None = None,
        caller_signals: list[CorrelationSignal] | None = None,
        notification_engine: Any = None,
        derived_signals: list[CorrelationSignal] | None = None,
        correlation_side_effect: Exception | None = None,
    ) -> tuple[DetectionResult, MagicMock, MagicMock]:
        mock_store = MagicMock()
        mock_store.lookup_by_values.return_value = records if records is not None else []

        mock_corr = MagicMock()
        if correlation_side_effect is not None:
            mock_corr.correlate.side_effect = correlation_side_effect
        else:
            mock_corr.correlate.return_value = engine_signals if engine_signals is not None else []

        fallback_signals = derived_signals if derived_signals is not None else []

        with (
            patch("app.services.threat_detection_engine.get_ioc_store", return_value=mock_store),
            patch(
                "app.services.threat_detection_engine.get_correlation_engine",
                return_value=mock_corr,
            ),
            patch.object(
                ThreatDetectionEngine,
                "_derive_engine_signals",
                return_value=fallback_signals,
            ),
        ):
            result = self.engine.run(
                req,
                correlation_signals=caller_signals,
                notification_engine=notification_engine,
            )

        return result, mock_store, mock_corr

    def test_clean_payload_returns_allow(self) -> None:
        req = _make_request(text="completely benign text with no indicators")
        result, mock_store, _ = self._run_with_records(
            req,
            records=[],
            derived_signals=[],
        )
        assert result.verdict == DetectionVerdict.ALLOW
        assert result.ioc_matches == []
        assert result.correlation_signals == []
        assert result.score == 0.0
        if self.engine._extract_observables(req):
            assert mock_store.lookup_by_values.called

    def test_critical_ioc_end_to_end_populates_full_assembled_result(self) -> None:
        req = _make_request(text="1.2.3.4")
        critical_match = _make_ioc_match(
            ioc_id="critical-1",
            value="1.2.3.4",
            severity=ThreatSeverityLevel.CRITICAL,
            confidence=1.0,
            risk_families=["ransomware"],
            mitre_technique_id="T1059",
            cve_id="CVE-2024-12345",
        )
        engine_signals = [
            _make_correlation_signal(
                pattern_type="attack_chain",
                score_contribution=0.20,
                confidence=0.95,
                mitre_technique_ids=["T1059", "T1204"],
            )
        ]
        with patch.object(self.engine, "_resolve_ioc_matches", return_value=[critical_match]):
            result, _, _ = self._run_with_records(
                req,
                records=[],
                engine_signals=engine_signals,
                derived_signals=[],
            )
        assert result.verdict == DetectionVerdict.BLOCK
        assert result.severity in {ThreatSeverityLevel.HIGH, ThreatSeverityLevel.CRITICAL}
        assert len(result.ioc_matches) == 1
        assert "ransomware" in result.risk_families
        assert result.mitre_techniques == ["T1059", "T1204"]

    def test_engine_and_caller_signals_merge_with_engine_first(self) -> None:
        req = _make_request(text=None, ioc_values=["1.2.3.4", "evil.com"])
        matches = [
            _make_ioc_match(
                ioc_id="m1",
                value="1.2.3.4",
                severity=ThreatSeverityLevel.HIGH,
                confidence=0.90,
                mitre_technique_id="T1059",
            ),
            _make_ioc_match(
                ioc_id="m2",
                value="evil.com",
                ioc_type=IOCTypeEnum.DOMAIN,
                severity=ThreatSeverityLevel.MEDIUM,
                confidence=0.60,
                mitre_technique_id="T1078",
            ),
        ]
        engine_signals = [
            _make_correlation_signal(
                pattern_type="attack_chain",
                score_contribution=0.15,
                confidence=0.90,
                mitre_technique_ids=["T1059", "T1078"],
            )
        ]
        caller_signals = [
            _make_correlation_signal(
                pattern_type="temporal_cluster",
                score_contribution=0.05,
                confidence=0.70,
                mitre_technique_ids=["T1078"],
            )
        ]
        with patch.object(self.engine, "_resolve_ioc_matches", return_value=matches):
            result, _, _ = self._run_with_records(
                req,
                records=[],
                engine_signals=engine_signals,
                caller_signals=caller_signals,
                derived_signals=[],
            )
        result_types = _signal_types(result.correlation_signals)
        assert result_types[0] == "attack_chain"
        assert "temporal_cluster" in result_types[1:]

    def test_duplicate_mitre_techniques_deduplicated_across_iocs_and_signals_in_order(self) -> None:
        req = _make_request(text=None, ioc_values=["1.2.3.4", "evil.com"])
        matches = [
            _make_ioc_match(
                ioc_id="m1",
                value="1.2.3.4",
                severity=ThreatSeverityLevel.HIGH,
                confidence=0.90,
                mitre_technique_id="t1059",
            ),
            _make_ioc_match(
                ioc_id="m2",
                value="evil.com",
                ioc_type=IOCTypeEnum.DOMAIN,
                severity=ThreatSeverityLevel.MEDIUM,
                confidence=0.60,
                mitre_technique_id="T1078",
            ),
        ]
        engine_signals = [
            _make_correlation_signal(
                pattern_type="attack_chain",
                score_contribution=0.10,
                confidence=0.80,
                mitre_technique_ids=["T1059", "t1204", "T1078"],
            )
        ]
        with patch.object(self.engine, "_resolve_ioc_matches", return_value=matches):
            result, _, _ = self._run_with_records(
                req,
                records=[],
                engine_signals=engine_signals,
                derived_signals=[],
            )
        assert result.mitre_techniques == ["T1059", "T1078", "T1204"]

    def test_notification_failures_do_not_change_detection_correctness(self) -> None:
        req = _make_request(text="1.2.3.4")
        match = _make_ioc_match(
            ioc_id="m1",
            value="1.2.3.4",
            severity=ThreatSeverityLevel.HIGH,
            confidence=0.95,
            risk_families=["credential_theft"],
            mitre_technique_id="T1059",
        )
        notification_engine = MagicMock()
        notification_engine.notify_detection.side_effect = RuntimeError("notify failed")

        with patch.object(self.engine, "_resolve_ioc_matches", return_value=[match]):
            result, _, _ = self._run_with_records(
                req,
                records=[],
                engine_signals=[],
                notification_engine=notification_engine,
                derived_signals=[],
            )

        assert len(result.ioc_matches) == 1
        assert result.ioc_matches[0].value == "1.2.3.4"
        assert result.verdict in {
            DetectionVerdict.ALLOW,
            DetectionVerdict.BLOCK,
            DetectionVerdict.MONITOR,
            DetectionVerdict.REVIEW,
        }

    def test_result_contains_engine_version_and_assessed_at(self) -> None:
        req = _make_request(text="1.2.3.4")
        records = [_make_ioc_record(value="1.2.3.4")]
        result, _, _ = self._run_with_records(req, records=records, derived_signals=[])
        assert result.detection_engine_version == "1.0.0"
        assert isinstance(result.assessed_at, str)
        assert result.assessed_at
