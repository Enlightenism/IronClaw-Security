from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from app.schemas.threat_detection import (
    DetectionVerdict,
    IOCTypeEnum,
    ThreatSeverityLevel,
)
from app.services.threat_scoring import (
    ScoreResult,
    ThreatScoringEngine,
    build_score_rationale,
    compute_composite_score,
    derive_mitre_techniques,
    derive_risk_families,
    get_scoring_engine,
    ioc_type_amplifier,
    score_correlation_signals,
    score_ioc_matches,
    score_single_ioc_match,
    score_to_severity,
    score_to_verdict,
    severity_to_weight,
    tag_risk_bonus,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_match(
    *,
    severity: str = ThreatSeverityLevel.MEDIUM,
    ioc_type: str = IOCTypeEnum.IPV4,
    confidence: float = 0.80,
    tags: list[str] | None = None,
    value: str = "1.2.3.4",
    mitre_technique_id: str | None = None,
    cve_id: str | None = None,
) -> Any:
    m = MagicMock()
    m.severity = severity
    m.ioc_type = ioc_type
    m.confidence = confidence
    m.tags = tags or []
    m.value = value
    m.mitre_technique_id = mitre_technique_id
    m.cve_id = cve_id
    return m


def _make_signal(*, score_contribution: float = 0.10, confidence: float = 0.85) -> Any:
    s = MagicMock()
    s.score_contribution = score_contribution
    s.confidence = confidence
    return s


# ---------------------------------------------------------------------------
# TestSeverityToWeight
# ---------------------------------------------------------------------------


class TestSeverityToWeight:
    def test_critical_is_one(self):
        assert severity_to_weight(ThreatSeverityLevel.CRITICAL) == 1.00

    def test_high_weight(self):
        assert severity_to_weight(ThreatSeverityLevel.HIGH) == 0.70

    def test_medium_weight(self):
        assert severity_to_weight(ThreatSeverityLevel.MEDIUM) == 0.45

    def test_low_weight(self):
        assert severity_to_weight(ThreatSeverityLevel.LOW) == 0.20

    def test_info_weight(self):
        assert severity_to_weight(ThreatSeverityLevel.INFO) == 0.05

    def test_unknown_severity_returns_zero(self):
        assert severity_to_weight("GARBAGE") == 0.0


# ---------------------------------------------------------------------------
# TestIocTypeAmplifier
# ---------------------------------------------------------------------------


class TestIocTypeAmplifier:
    def test_cve_highest(self):
        assert ioc_type_amplifier(IOCTypeEnum.CVE) == 1.20

    def test_sha256(self):
        assert ioc_type_amplifier(IOCTypeEnum.SHA256) == 1.15

    def test_url(self):
        assert ioc_type_amplifier(IOCTypeEnum.URL) == 1.10

    def test_ipv4_is_one(self):
        assert ioc_type_amplifier(IOCTypeEnum.IPV4) == 1.0

    def test_unknown_type_defaults_to_one(self):
        assert ioc_type_amplifier("totally_unknown_type") == 1.0

    def test_email_below_one(self):
        assert ioc_type_amplifier(IOCTypeEnum.EMAIL) < 1.0


# ---------------------------------------------------------------------------
# TestTagRiskBonus
# ---------------------------------------------------------------------------


class TestTagRiskBonus:
    def test_empty_tags_zero(self):
        assert tag_risk_bonus([]) == 0.0

    def test_ransomware_tag(self):
        assert tag_risk_bonus(["ransomware"]) == 0.15

    def test_multiple_tags_sum(self):
        total = tag_risk_bonus(["ransomware", "apt"])
        assert total == pytest.approx(0.27, abs=1e-6)

    def test_cap_at_0_30(self):
        many = ["ransomware", "exploited-in-wild", "cisa-kev", "apt", "c2", "data-exfiltration"]
        assert tag_risk_bonus(many) <= 0.30

    def test_unknown_tag_zero_bonus(self):
        assert tag_risk_bonus(["totally-unknown-tag"]) == 0.0

    def test_command_and_control_alias(self):
        assert tag_risk_bonus(["command-and-control"]) == tag_risk_bonus(["c2"])


# ---------------------------------------------------------------------------
# TestScoreSingleIocMatch
# ---------------------------------------------------------------------------


class TestScoreSingleIocMatch:
    def test_result_in_range(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, ioc_type=IOCTypeEnum.SHA256, confidence=0.90)
        result = score_single_ioc_match(m)
        assert 0.0 <= result <= 1.0

    def test_critical_scores_higher_than_info(self):
        critical = _make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0)
        info = _make_match(severity=ThreatSeverityLevel.INFO, confidence=1.0)
        assert score_single_ioc_match(critical) > score_single_ioc_match(info)

    def test_zero_confidence_reduces_score(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.0)
        assert score_single_ioc_match(m) == pytest.approx(0.0, abs=0.35)

    def test_tags_add_bonus(self):
        no_tags = _make_match(severity=ThreatSeverityLevel.MEDIUM, confidence=0.60, tags=[])
        with_tags = _make_match(severity=ThreatSeverityLevel.MEDIUM, confidence=0.60, tags=["ransomware"])
        assert score_single_ioc_match(with_tags) > score_single_ioc_match(no_tags)

    def test_cve_type_amplifier_applied(self):
        cve_match = _make_match(ioc_type=IOCTypeEnum.CVE, severity=ThreatSeverityLevel.HIGH, confidence=0.80)
        ip_match = _make_match(ioc_type=IOCTypeEnum.IPV4, severity=ThreatSeverityLevel.HIGH, confidence=0.80)
        assert score_single_ioc_match(cve_match) > score_single_ioc_match(ip_match)

    def test_clamps_to_1_0(self):
        m = _make_match(
            severity=ThreatSeverityLevel.CRITICAL,
            ioc_type=IOCTypeEnum.CVE,
            confidence=1.0,
            tags=["ransomware", "exploited-in-wild", "apt", "c2"],
        )
        assert score_single_ioc_match(m) <= 1.0

    def test_confidence_clamped_above_1(self):
        m = _make_match(severity=ThreatSeverityLevel.MEDIUM, confidence=99.0)
        assert score_single_ioc_match(m) <= 1.0

    def test_confidence_clamped_below_0(self):
        m = _make_match(severity=ThreatSeverityLevel.MEDIUM, confidence=-5.0)
        result = score_single_ioc_match(m)
        assert result >= 0.0


# ---------------------------------------------------------------------------
# TestScoreIocMatches
# ---------------------------------------------------------------------------


class TestScoreIocMatches:
    def test_empty_list_returns_zero(self):
        assert score_ioc_matches([]) == 0.0

    def test_single_match_in_range(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.90)
        result = score_ioc_matches([m])
        assert 0.0 <= result <= 1.0

    def test_higher_severity_yields_higher_score(self):
        low = [_make_match(severity=ThreatSeverityLevel.LOW, confidence=0.80)]
        high = [_make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.80)]
        assert score_ioc_matches(high) > score_ioc_matches(low)

    def test_many_low_matches_capped(self):
        bulk = [_make_match(severity=ThreatSeverityLevel.INFO, confidence=0.10) for _ in range(50)]
        single_critical = [_make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0)]
        assert score_ioc_matches(bulk) < score_ioc_matches(single_critical)

    def test_result_never_exceeds_1(self):
        matches = [_make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0, tags=["ransomware"]) for _ in range(20)]
        assert score_ioc_matches(matches) <= 1.0

    def test_result_never_below_0(self):
        matches = [_make_match(severity=ThreatSeverityLevel.INFO, confidence=0.0)]
        assert score_ioc_matches(matches) >= 0.0


# ---------------------------------------------------------------------------
# TestScoreCorrelationSignals
# ---------------------------------------------------------------------------


class TestScoreCorrelationSignals:
    def test_empty_returns_zero(self):
        assert score_correlation_signals([]) == 0.0

    def test_single_signal_in_range(self):
        s = _make_signal(score_contribution=0.10, confidence=0.80)
        result = score_correlation_signals([s])
        assert 0.0 <= result <= 0.30

    def test_contribution_scaled_by_confidence(self):
        high_conf = _make_signal(score_contribution=0.10, confidence=1.00)
        low_conf = _make_signal(score_contribution=0.10, confidence=0.10)
        assert score_correlation_signals([high_conf]) > score_correlation_signals([low_conf])

    def test_cap_at_correlation_score_cap(self):
        signals = [_make_signal(score_contribution=0.30, confidence=1.0) for _ in range(10)]
        assert score_correlation_signals(signals) <= 0.30

    def test_missing_attribute_defaults_to_zero(self):
        s = MagicMock(spec=[])
        result = score_correlation_signals([s])
        assert result == 0.0

    def test_clamped_contribution_above_1(self):
        s = _make_signal(score_contribution=99.0, confidence=1.0)
        assert score_correlation_signals([s]) <= 0.30


# ---------------------------------------------------------------------------
# TestComputeCompositeScore
# ---------------------------------------------------------------------------


class TestComputeCompositeScore:
    def test_no_matches_no_signals(self):
        assert compute_composite_score([], []) == 0.0

    def test_ioc_only_in_range(self):
        matches = [_make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.80)]
        result = compute_composite_score(matches, [])
        assert 0.0 <= result <= 1.0

    def test_correlation_adds_to_score(self):
        matches = [_make_match(severity=ThreatSeverityLevel.MEDIUM, confidence=0.70)]
        base = compute_composite_score(matches, [])
        with_signal = compute_composite_score(matches, [_make_signal()])
        assert with_signal >= base

    def test_base_score_override_replaces_ioc_score(self):
        matches = [_make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0)]
        overridden = compute_composite_score(matches, [], base_score_override=0.10)
        natural = compute_composite_score(matches, [])
        assert overridden < natural

    def test_base_score_override_clamped(self):
        assert compute_composite_score([], [], base_score_override=99.0) <= 1.0
        assert compute_composite_score([], [], base_score_override=-5.0) >= 0.0

    def test_result_never_exceeds_1(self):
        matches = [_make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0, tags=["ransomware", "apt"])]
        signals = [_make_signal(score_contribution=0.30, confidence=1.0) for _ in range(5)]
        assert compute_composite_score(matches, signals) <= 1.0

    def test_none_signals_treated_as_empty(self):
        matches = [_make_match()]
        assert compute_composite_score(matches, None) == compute_composite_score(matches, [])


# ---------------------------------------------------------------------------
# TestScoreToVerdict
# ---------------------------------------------------------------------------


class TestScoreToVerdict:
    def test_block_at_0_75(self):
        assert score_to_verdict(0.75) == DetectionVerdict.BLOCK

    def test_block_at_1_0(self):
        assert score_to_verdict(1.0) == DetectionVerdict.BLOCK

    def test_review_at_0_50(self):
        assert score_to_verdict(0.50) == DetectionVerdict.REVIEW

    def test_review_at_0_74(self):
        assert score_to_verdict(0.74) == DetectionVerdict.REVIEW

    def test_monitor_at_0_25(self):
        assert score_to_verdict(0.25) == DetectionVerdict.MONITOR

    def test_monitor_at_0_49(self):
        assert score_to_verdict(0.49) == DetectionVerdict.MONITOR

    def test_allow_at_0_0(self):
        assert score_to_verdict(0.0) == DetectionVerdict.ALLOW

    def test_allow_at_0_24(self):
        assert score_to_verdict(0.24) == DetectionVerdict.ALLOW


# ---------------------------------------------------------------------------
# TestScoreToSeverity
# ---------------------------------------------------------------------------


class TestScoreToSeverity:
    def test_critical_at_0_85(self):
        assert score_to_severity(0.85) == ThreatSeverityLevel.CRITICAL

    def test_critical_at_1_0(self):
        assert score_to_severity(1.0) == ThreatSeverityLevel.CRITICAL

    def test_high_at_0_65(self):
        assert score_to_severity(0.65) == ThreatSeverityLevel.HIGH

    def test_high_at_0_84(self):
        assert score_to_severity(0.84) == ThreatSeverityLevel.HIGH

    def test_medium_at_0_40(self):
        assert score_to_severity(0.40) == ThreatSeverityLevel.MEDIUM

    def test_low_at_0_15(self):
        assert score_to_severity(0.15) == ThreatSeverityLevel.LOW

    def test_info_at_0_0(self):
        assert score_to_severity(0.0) == ThreatSeverityLevel.INFO

    def test_info_at_0_14(self):
        assert score_to_severity(0.14) == ThreatSeverityLevel.INFO


# ---------------------------------------------------------------------------
# TestDeriveRiskFamilies
# ---------------------------------------------------------------------------


class TestDeriveRiskFamilies:
    def test_empty_matches_returns_empty(self):
        assert derive_risk_families([]) == []

    def test_ransomware_tag(self):
        m = _make_match(tags=["ransomware"])
        assert "ransomware" in derive_risk_families([m])

    def test_c2_tag(self):
        m = _make_match(tags=["c2"])
        assert "command_and_control" in derive_risk_families([m])

    def test_command_and_control_alias(self):
        m = _make_match(tags=["command-and-control"])
        assert "command_and_control" in derive_risk_families([m])

    def test_cve_type(self):
        m = _make_match(ioc_type=IOCTypeEnum.CVE)
        assert "vulnerability" in derive_risk_families([m])

    def test_hash_type_yields_malware_artifact(self):
        m = _make_match(ioc_type=IOCTypeEnum.SHA256)
        assert "malware_artifact" in derive_risk_families([m])

    def test_ip_type(self):
        m = _make_match(ioc_type=IOCTypeEnum.IPV4)
        assert "malicious_ip" in derive_risk_families([m])

    def test_deduplication(self):
        m1 = _make_match(tags=["ransomware"])
        m2 = _make_match(tags=["ransomware"])
        families = derive_risk_families([m1, m2])
        assert families.count("ransomware") == 1

    def test_result_is_sorted(self):
        m = _make_match(tags=["ransomware", "c2"], ioc_type=IOCTypeEnum.SHA256)
        families = derive_risk_families([m])
        assert families == sorted(families)

    def test_unknown_tag_not_included(self):
        # Use UNKNOWN ioc_type so no type-family entry is added either
        m = _make_match(tags=["unknown-custom-tag"], ioc_type=IOCTypeEnum.UNKNOWN)
        assert derive_risk_families([m]) == []

    def test_known_exploited_from_cisa_kev(self):
        m = _make_match(tags=["cisa-kev"])
        assert "known_exploited" in derive_risk_families([m])

    def test_apt_tag(self):
        m = _make_match(tags=["apt"])
        assert "advanced_persistent_threat" in derive_risk_families([m])


# ---------------------------------------------------------------------------
# TestDeriveMitreTechniques
# ---------------------------------------------------------------------------


class TestDeriveMitreTechniques:
    def test_empty_matches_returns_empty(self):
        assert derive_mitre_techniques([]) == []

    def test_mitre_technique_id_extracted(self):
        m = _make_match(mitre_technique_id="t1059")
        result = derive_mitre_techniques([m])
        assert "T1059" in result

    def test_normalized_to_uppercase(self):
        m = _make_match(mitre_technique_id="t1059.001")
        result = derive_mitre_techniques([m])
        assert "T1059.001" in result

    def test_mitre_technique_type_value_extracted(self):
        m = _make_match(ioc_type=IOCTypeEnum.MITRE_TECHNIQUE, value="T1078", mitre_technique_id=None)
        result = derive_mitre_techniques([m])
        assert "T1078" in result

    def test_deduplication(self):
        m1 = _make_match(mitre_technique_id="T1059")
        m2 = _make_match(mitre_technique_id="t1059")
        result = derive_mitre_techniques([m1, m2])
        assert result.count("T1059") == 1

    def test_result_is_sorted(self):
        matches = [
            _make_match(mitre_technique_id="T1078"),
            _make_match(mitre_technique_id="T1059"),
            _make_match(mitre_technique_id="T1190"),
        ]
        result = derive_mitre_techniques(matches)
        assert result == sorted(result)

    def test_none_mitre_id_skipped(self):
        m = _make_match(mitre_technique_id=None)
        assert derive_mitre_techniques([m]) == []


# ---------------------------------------------------------------------------
# TestBuildScoreRationale
# ---------------------------------------------------------------------------


class TestBuildScoreRationale:
    def test_empty_matches_returns_no_ioc_message(self):
        rationale = build_score_rationale([], 0.0, DetectionVerdict.ALLOW)
        assert any("No IOC" in r for r in rationale)

    def test_composite_score_line_included(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.80)
        rationale = build_score_rationale([m], 0.75, DetectionVerdict.BLOCK)
        assert any("0.750" in r for r in rationale)
        assert any("BLOCK" in r for r in rationale)

    def test_high_confidence_line_included(self):
        m = _make_match(confidence=0.90)
        rationale = build_score_rationale([m], 0.50, DetectionVerdict.REVIEW)
        assert any("high-confidence" in r.lower() for r in rationale)

    def test_critical_severity_line_included(self):
        m = _make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=0.80)
        rationale = build_score_rationale([m], 0.80, DetectionVerdict.BLOCK)
        assert any("HIGH/CRITICAL" in r or "CRITICAL" in r for r in rationale)

    def test_cve_line_included(self):
        m = _make_match(cve_id="CVE-2024-1234", ioc_type=IOCTypeEnum.CVE)
        rationale = build_score_rationale([m], 0.70, DetectionVerdict.BLOCK)
        assert any("CVE" in r for r in rationale)

    def test_ransomware_line_included(self):
        m = _make_match(tags=["ransomware"])
        rationale = build_score_rationale([m], 0.80, DetectionVerdict.BLOCK)
        assert any("Ransomware" in r or "ransomware" in r for r in rationale)

    def test_kev_line_included(self):
        m = _make_match(tags=["cisa-kev"])
        rationale = build_score_rationale([m], 0.80, DetectionVerdict.BLOCK)
        assert any("KEV" in r or "exploited" in r.lower() for r in rationale)

    def test_returns_list_of_strings(self):
        rationale = build_score_rationale([], 0.0, DetectionVerdict.ALLOW)
        assert isinstance(rationale, list)
        assert all(isinstance(r, str) for r in rationale)


# ---------------------------------------------------------------------------
# TestThreatScoringEngine
# ---------------------------------------------------------------------------


class TestThreatScoringEngine:
    def setup_method(self):
        self.engine = ThreatScoringEngine()

    def test_compute_returns_score_result(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.85)
        result = self.engine.compute([m])
        assert isinstance(result, ScoreResult)

    def test_compute_score_in_range(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.85)
        result = self.engine.compute([m])
        assert 0.0 <= result.score <= 1.0

    def test_compute_verdict_is_valid(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.90)
        result = self.engine.compute([m])
        assert result.verdict in list(DetectionVerdict)

    def test_compute_severity_is_valid(self):
        m = _make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0)
        result = self.engine.compute([m])
        assert result.severity in list(ThreatSeverityLevel)

    def test_compute_risk_families_list(self):
        m = _make_match(tags=["ransomware"], ioc_type=IOCTypeEnum.SHA256)
        result = self.engine.compute([m])
        assert isinstance(result.risk_families, list)

    def test_compute_mitre_techniques_list(self):
        m = _make_match(mitre_technique_id="T1059")
        result = self.engine.compute([m])
        assert isinstance(result.mitre_techniques, list)

    def test_compute_rationale_list(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.80)
        result = self.engine.compute([m])
        assert isinstance(result.rationale, list)

    def test_compute_empty_matches(self):
        result = self.engine.compute([])
        assert result.score == 0.0
        assert result.verdict == DetectionVerdict.ALLOW
        assert result.severity == ThreatSeverityLevel.INFO

    def test_compute_with_correlation_signals(self):
        m = _make_match(severity=ThreatSeverityLevel.MEDIUM, confidence=0.70)
        signals = [_make_signal(score_contribution=0.12, confidence=0.90)]
        with_signals = self.engine.compute([m], correlation_signals=signals)
        without_signals = self.engine.compute([m], correlation_signals=[])
        assert with_signals.score >= without_signals.score

    def test_compute_base_score_override(self):
        matches = [_make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0)]
        result = self.engine.compute(matches, base_score_override=0.10)
        assert result.score < 0.50

    def test_verdict_for_score_block(self):
        assert self.engine.verdict_for_score(0.80) == DetectionVerdict.BLOCK

    def test_verdict_for_score_allow(self):
        assert self.engine.verdict_for_score(0.10) == DetectionVerdict.ALLOW

    def test_severity_for_score_critical(self):
        assert self.engine.severity_for_score(0.90) == ThreatSeverityLevel.CRITICAL

    def test_severity_for_score_info(self):
        assert self.engine.severity_for_score(0.05) == ThreatSeverityLevel.INFO

    def test_severity_weight_static(self):
        assert ThreatScoringEngine.severity_weight(ThreatSeverityLevel.HIGH) == 0.70

    def test_type_amplifier_static(self):
        assert ThreatScoringEngine.type_amplifier(IOCTypeEnum.CVE) == 1.20

    def test_compute_critical_match_yields_block_verdict(self):
        m = _make_match(
            severity=ThreatSeverityLevel.CRITICAL,
            ioc_type=IOCTypeEnum.CVE,
            confidence=1.0,
            tags=["ransomware", "cisa-kev"],
        )
        result = self.engine.compute([m])
        assert result.verdict == DetectionVerdict.BLOCK


# ---------------------------------------------------------------------------
# TestScoreResult
# ---------------------------------------------------------------------------


class TestScoreResult:
    def test_repr_contains_score(self):
        r = ScoreResult(
            score=0.75,
            verdict=DetectionVerdict.BLOCK,
            severity=ThreatSeverityLevel.HIGH,
            risk_families=[],
            mitre_techniques=[],
            rationale=[],
        )
        assert "0.750" in repr(r)
        assert "block" in repr(r).lower()

    def test_all_slots_accessible(self):
        r = ScoreResult(
            score=0.50,
            verdict=DetectionVerdict.REVIEW,
            severity=ThreatSeverityLevel.MEDIUM,
            risk_families=["ransomware"],
            mitre_techniques=["T1059"],
            rationale=["line1"],
        )
        assert r.score == 0.50
        assert r.verdict == DetectionVerdict.REVIEW
        assert r.severity == ThreatSeverityLevel.MEDIUM
        assert r.risk_families == ["ransomware"]
        assert r.mitre_techniques == ["T1059"]
        assert r.rationale == ["line1"]

    def test_cannot_add_arbitrary_attribute(self):
        r = ScoreResult(
            score=0.0,
            verdict=DetectionVerdict.ALLOW,
            severity=ThreatSeverityLevel.INFO,
            risk_families=[],
            mitre_techniques=[],
            rationale=[],
        )
        with pytest.raises(AttributeError):
            r.unexpected_field = "boom"


# ---------------------------------------------------------------------------
# TestGetScoringEngine
# ---------------------------------------------------------------------------


class TestGetScoringEngine:
    def test_returns_threat_scoring_engine_instance(self):
        engine = get_scoring_engine()
        assert isinstance(engine, ThreatScoringEngine)

    def test_singleton_returns_same_instance(self):
        e1 = get_scoring_engine()
        e2 = get_scoring_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# TestEndToEndScenarios
# ---------------------------------------------------------------------------


class TestEndToEndScenarios:
    """Integration-style tests using the full scoring pipeline end-to-end."""

    def test_all_info_iocs_yield_allow(self):
        matches = [_make_match(severity=ThreatSeverityLevel.INFO, confidence=0.20) for _ in range(3)]
        engine = ThreatScoringEngine()
        result = engine.compute(matches)
        assert result.verdict in (DetectionVerdict.ALLOW, DetectionVerdict.MONITOR)

    def test_mix_critical_and_info_scores_correctly(self):
        critical = _make_match(severity=ThreatSeverityLevel.CRITICAL, confidence=1.0, ioc_type=IOCTypeEnum.CVE)
        info = _make_match(severity=ThreatSeverityLevel.INFO, confidence=0.10)
        engine = ThreatScoringEngine()
        result = engine.compute([critical, info])
        assert result.score > 0.5

    def test_ransomware_ioc_with_correlation_exceeds_block_threshold(self):
        m = _make_match(
            severity=ThreatSeverityLevel.CRITICAL,
            ioc_type=IOCTypeEnum.SHA256,
            confidence=1.0,
            tags=["ransomware", "cisa-kev"],
        )
        signal = _make_signal(score_contribution=0.20, confidence=1.0)
        engine = ThreatScoringEngine()
        result = engine.compute([m], correlation_signals=[signal])
        assert result.verdict == DetectionVerdict.BLOCK
        assert result.severity in (ThreatSeverityLevel.CRITICAL, ThreatSeverityLevel.HIGH)

    def test_mitre_technique_preserved_in_result(self):
        m = _make_match(
            ioc_type=IOCTypeEnum.MITRE_TECHNIQUE,
            value="T1059",
            mitre_technique_id="T1059",
        )
        engine = ThreatScoringEngine()
        result = engine.compute([m])
        assert "T1059" in result.mitre_techniques

    def test_risk_families_populated_from_tags_and_types(self):
        m = _make_match(
            ioc_type=IOCTypeEnum.IPV4,
            tags=["c2", "lateral-movement"],
        )
        engine = ThreatScoringEngine()
        result = engine.compute([m])
        assert "command_and_control" in result.risk_families
        assert "lateral_movement" in result.risk_families

    def test_rationale_non_empty_for_real_matches(self):
        m = _make_match(severity=ThreatSeverityLevel.HIGH, confidence=0.85)
        engine = ThreatScoringEngine()
        result = engine.compute([m])
        assert len(result.rationale) > 0
