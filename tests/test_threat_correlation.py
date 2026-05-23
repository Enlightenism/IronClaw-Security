from __future__ import annotations

from app.schemas.threat_detection import (
    CorrelationSignal,
    IOCMatch,
    IOCTypeEnum,
    ThreatSeverityLevel,
)
from app.services.threat_correlation import (
    ThreatCorrelationEngine,
    _detect_attack_chain,
    _detect_c2_cluster,
    _detect_hash_cluster,
    _detect_high_severity_cluster,
    _detect_mitre_chain,
    _detect_multi_ioc_cooccurrence,
    get_correlation_engine,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_ioc(
    value: str = "1.2.3.4",
    ioc_type: str = IOCTypeEnum.IPV4,
    severity: str = ThreatSeverityLevel.MEDIUM,
    confidence: float = 0.80,
    tags: list[str] | None = None,
    mitre_technique_id: str | None = None,
    mitre_tactic: str | None = None,
    ioc_id: str | None = None,
) -> IOCMatch:
    return IOCMatch(
        ioc_id=ioc_id or f"ioc-{value}",
        value=value,
        ioc_type=ioc_type,
        confidence=confidence,
        severity=severity,
        source="test",
        tags=tags or [],
        matched_on="ioc_store",
        mitre_technique_id=mitre_technique_id,
        mitre_tactic=mitre_tactic,
    )


EVENT_IDS = ["evt-001", "evt-002"]


# ---------------------------------------------------------------------------
# get_correlation_engine — singleton contract
# ---------------------------------------------------------------------------


class TestGetCorrelationEngine:
    def test_returns_instance(self) -> None:
        engine = get_correlation_engine()
        assert isinstance(engine, ThreatCorrelationEngine)

    def test_returns_same_singleton(self) -> None:
        a = get_correlation_engine()
        b = get_correlation_engine()
        assert a is b


# ---------------------------------------------------------------------------
# ThreatCorrelationEngine.correlate — empty inputs
# ---------------------------------------------------------------------------


class TestCorrelateEmptyInputs:
    def test_empty_matches_returns_empty(self) -> None:
        engine = ThreatCorrelationEngine()
        result = engine.correlate([])
        assert result == []

    def test_no_event_ids_still_runs(self) -> None:
        iocs = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        engine = ThreatCorrelationEngine()
        result = engine.correlate(iocs)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _detect_multi_ioc_cooccurrence
# ---------------------------------------------------------------------------


class TestDetectMultiIOCCooccurrence:
    def test_fires_on_two_distinct_types(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_multi_ioc_cooccurrence(matches, EVENT_IDS)
        assert result is not None
        assert result.pattern_type == "multi_ioc_cooccurrence"

    def test_no_signal_on_single_match(self) -> None:
        matches = [_make_ioc("1.1.1.1", IOCTypeEnum.IPV4)]
        result = _detect_multi_ioc_cooccurrence(matches, EVENT_IDS)
        assert result is None

    def test_no_signal_on_same_type_only(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("2.2.2.2", IOCTypeEnum.IPV4),
        ]
        result = _detect_multi_ioc_cooccurrence(matches, EVENT_IDS)
        assert result is None

    def test_confidence_bounded(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, confidence=1.0),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN, confidence=1.0),
        ]
        result = _detect_multi_ioc_cooccurrence(matches, EVENT_IDS)
        assert result is not None
        assert 0.0 <= result.confidence <= 1.0

    def test_score_contribution_within_bounds(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_multi_ioc_cooccurrence(matches, EVENT_IDS)
        assert result is not None
        assert 0.0 <= result.score_contribution <= 1.0

    def test_event_ids_attached(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_multi_ioc_cooccurrence(matches, EVENT_IDS)
        assert result is not None
        assert result.matched_event_ids == EVENT_IDS


# ---------------------------------------------------------------------------
# _detect_attack_chain
# ---------------------------------------------------------------------------


class TestDetectAttackChain:
    def test_fires_on_two_distinct_tactics(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_tactic="initial-access"),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, mitre_tactic="execution"),
        ]
        result = _detect_attack_chain(matches, EVENT_IDS)
        assert result is not None
        assert result.pattern_type == "attack_chain"

    def test_fires_on_two_distinct_techniques(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1059"),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1190"),
        ]
        result = _detect_attack_chain(matches, EVENT_IDS)
        assert result is not None

    def test_no_signal_on_single_tactic_single_technique(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_tactic="execution", mitre_technique_id="T1059"),
        ]
        result = _detect_attack_chain(matches, EVENT_IDS)
        assert result is None

    def test_no_signal_on_no_mitre(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_attack_chain(matches, EVENT_IDS)
        assert result is None

    def test_techniques_uppercased(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_technique_id="t1059"),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, mitre_technique_id="t1190"),
        ]
        result = _detect_attack_chain(matches, EVENT_IDS)
        assert result is not None
        assert all(t == t.upper() for t in result.mitre_technique_ids)


# ---------------------------------------------------------------------------
# _detect_high_severity_cluster
# ---------------------------------------------------------------------------


class TestDetectHighSeverityCluster:
    def test_fires_on_two_high_severity(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
        ]
        result = _detect_high_severity_cluster(matches, EVENT_IDS)
        assert result is not None
        assert result.pattern_type == "high_severity_cluster"

    def test_fires_on_mixed_high_critical(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.CRITICAL),
        ]
        result = _detect_high_severity_cluster(matches, EVENT_IDS)
        assert result is not None

    def test_critical_raises_confidence(self) -> None:
        high_only = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
        ]
        with_critical = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.CRITICAL),
        ]
        r_high = _detect_high_severity_cluster(high_only, EVENT_IDS)
        r_crit = _detect_high_severity_cluster(with_critical, EVENT_IDS)
        assert r_crit is not None and r_high is not None
        assert r_crit.confidence >= r_high.confidence

    def test_no_signal_on_one_high(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.LOW),
        ]
        result = _detect_high_severity_cluster(matches, EVENT_IDS)
        assert result is None

    def test_no_signal_on_medium_only(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.MEDIUM),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.MEDIUM),
        ]
        result = _detect_high_severity_cluster(matches, EVENT_IDS)
        assert result is None


# ---------------------------------------------------------------------------
# _detect_mitre_chain
# ---------------------------------------------------------------------------


class TestDetectMitreChain:
    def test_fires_on_three_distinct_techniques(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1059"),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1190"),
            _make_ioc("c.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1078"),
        ]
        result = _detect_mitre_chain(matches, EVENT_IDS)
        assert result is not None
        assert result.pattern_type == "mitre_chain"
        assert len(result.mitre_technique_ids) == 3

    def test_no_signal_on_two_techniques(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1059"),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1190"),
        ]
        result = _detect_mitre_chain(matches, EVENT_IDS)
        assert result is None

    def test_deduplicates_techniques(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1059"),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1059"),
            _make_ioc("c.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1190"),
        ]
        result = _detect_mitre_chain(matches, EVENT_IDS)
        assert result is None

    def test_techniques_are_sorted_and_uppercased(self) -> None:
        matches = [
            _make_ioc("a.com", IOCTypeEnum.DOMAIN, mitre_technique_id="t1078"),
            _make_ioc("b.com", IOCTypeEnum.DOMAIN, mitre_technique_id="t1059"),
            _make_ioc("c.com", IOCTypeEnum.DOMAIN, mitre_technique_id="t1190"),
        ]
        result = _detect_mitre_chain(matches, EVENT_IDS)
        assert result is not None
        assert result.mitre_technique_ids == sorted(result.mitre_technique_ids)
        assert all(t == t.upper() for t in result.mitre_technique_ids)


# ---------------------------------------------------------------------------
# _detect_hash_cluster
# ---------------------------------------------------------------------------


class TestDetectHashCluster:
    def test_fires_on_two_hash_types(self) -> None:
        matches = [
            _make_ioc("a" * 64, IOCTypeEnum.SHA256),
            _make_ioc("b" * 40, IOCTypeEnum.SHA1),
        ]
        result = _detect_hash_cluster(matches, EVENT_IDS)
        assert result is not None
        assert result.pattern_type == "hash_cluster"

    def test_fires_on_md5_and_sha256(self) -> None:
        matches = [
            _make_ioc("a" * 32, IOCTypeEnum.MD5),
            _make_ioc("b" * 64, IOCTypeEnum.SHA256),
        ]
        result = _detect_hash_cluster(matches, EVENT_IDS)
        assert result is not None

    def test_no_signal_on_single_hash(self) -> None:
        matches = [
            _make_ioc("a" * 64, IOCTypeEnum.SHA256),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_hash_cluster(matches, EVENT_IDS)
        assert result is None

    def test_no_signal_on_no_hash_types(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_hash_cluster(matches, EVENT_IDS)
        assert result is None


# ---------------------------------------------------------------------------
# _detect_c2_cluster
# ---------------------------------------------------------------------------


class TestDetectC2Cluster:
    def test_fires_on_c2_tag_with_ip(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, tags=["c2"]),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_c2_cluster(matches, EVENT_IDS)
        assert result is not None
        assert result.pattern_type == "c2_cluster"

    def test_fires_on_command_and_control_tag(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, tags=["command-and-control"]),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_c2_cluster(matches, EVENT_IDS)
        assert result is not None

    def test_fires_with_url_network_type(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, tags=["c2"]),
            _make_ioc("http://evil.com/beacon", IOCTypeEnum.URL),
        ]
        result = _detect_c2_cluster(matches, EVENT_IDS)
        assert result is not None

    def test_no_signal_without_c2_tag(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, tags=["malware"]),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_c2_cluster(matches, EVENT_IDS)
        assert result is None

    def test_no_signal_without_network_type(self) -> None:
        matches = [
            _make_ioc("a" * 64, IOCTypeEnum.SHA256, tags=["c2"]),
            _make_ioc("b" * 40, IOCTypeEnum.SHA1, tags=["c2"]),
        ]
        result = _detect_c2_cluster(matches, EVENT_IDS)
        assert result is None

    def test_tag_case_insensitive(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, tags=["C2"]),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        result = _detect_c2_cluster(matches, EVENT_IDS)
        assert result is not None


# ---------------------------------------------------------------------------
# ThreatCorrelationEngine.correlate — integration coverage
# ---------------------------------------------------------------------------


class TestCorrelateIntegration:
    def test_multiple_signals_can_fire(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, severity=ThreatSeverityLevel.HIGH, tags=["c2"], mitre_technique_id="T1059"),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH, tags=["c2"], mitre_technique_id="T1190"),
            _make_ioc("a" * 64, IOCTypeEnum.SHA256, severity=ThreatSeverityLevel.CRITICAL, mitre_technique_id="T1078"),
            _make_ioc("b" * 40, IOCTypeEnum.SHA1, severity=ThreatSeverityLevel.HIGH),
        ]
        engine = ThreatCorrelationEngine()
        signals = engine.correlate(matches, event_ids=EVENT_IDS)
        assert len(signals) >= 1
        for sig in signals:
            assert isinstance(sig, CorrelationSignal)
            assert 0.0 <= sig.confidence <= 1.0
            assert 0.0 <= sig.score_contribution <= 1.0
            assert sig.signal_id

    def test_all_signals_have_pattern_type(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, mitre_technique_id="T1059", mitre_tactic="execution"),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN, mitre_technique_id="T1190", mitre_tactic="initial-access"),
        ]
        engine = ThreatCorrelationEngine()
        signals = engine.correlate(matches, event_ids=EVENT_IDS)
        for sig in signals:
            assert sig.pattern_type != ""

    def test_no_signals_when_no_patterns_qualify(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, severity=ThreatSeverityLevel.LOW),
        ]
        engine = ThreatCorrelationEngine()
        signals = engine.correlate(matches)
        assert signals == []

    def test_event_ids_propagated_to_signals(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        engine = ThreatCorrelationEngine()
        signals = engine.correlate(matches, event_ids=EVENT_IDS)
        for sig in signals:
            assert sig.matched_event_ids == EVENT_IDS


# ---------------------------------------------------------------------------
# ThreatCorrelationEngine.summarize
# ---------------------------------------------------------------------------


class TestCorrelationEngineSummarize:
    def test_empty_signals_returns_zeroed_summary(self) -> None:
        engine = ThreatCorrelationEngine()
        summary = engine.summarize([])
        assert summary["signal_count"] == 0
        assert summary["pattern_types"] == []
        assert summary["total_score_contribution"] == 0.0
        assert summary["max_confidence"] == 0.0

    def test_summary_keys_present(self) -> None:
        engine = ThreatCorrelationEngine()
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN),
        ]
        signals = engine.correlate(matches, event_ids=EVENT_IDS)
        summary = engine.summarize(signals)
        assert "signal_count" in summary
        assert "pattern_types" in summary
        assert "total_score_contribution" in summary
        assert "max_confidence" in summary

    def test_summary_counts_match_signals(self) -> None:
        matches = [
            _make_ioc("1.1.1.1", IOCTypeEnum.IPV4, severity=ThreatSeverityLevel.HIGH, tags=["c2"]),
            _make_ioc("evil.com", IOCTypeEnum.DOMAIN, severity=ThreatSeverityLevel.HIGH),
        ]
        engine = ThreatCorrelationEngine()
        signals = engine.correlate(matches, event_ids=EVENT_IDS)
        summary = engine.summarize(signals)
        assert summary["signal_count"] == len(signals)

    def test_pattern_types_deduplicated_and_sorted(self) -> None:
        import uuid

        from app.schemas.threat_detection import CorrelationSignal

        signals = [
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="attack_chain",
                confidence=0.80,
                score_contribution=0.10,
            ),
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="attack_chain",
                confidence=0.70,
                score_contribution=0.08,
            ),
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="multi_ioc_cooccurrence",
                confidence=0.60,
                score_contribution=0.06,
            ),
        ]
        engine = ThreatCorrelationEngine()
        summary = engine.summarize(signals)
        assert summary["pattern_types"] == sorted(set(s.pattern_type for s in signals))

    def test_total_score_contribution_is_sum(self) -> None:
        import uuid

        from app.schemas.threat_detection import CorrelationSignal

        signals = [
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="attack_chain",
                confidence=0.80,
                score_contribution=0.12,
            ),
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="hash_cluster",
                confidence=0.70,
                score_contribution=0.09,
            ),
        ]
        engine = ThreatCorrelationEngine()
        summary = engine.summarize(signals)
        assert abs(summary["total_score_contribution"] - 0.21) < 0.0001

    def test_max_confidence_is_highest(self) -> None:
        import uuid

        from app.schemas.threat_detection import CorrelationSignal

        signals = [
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="attack_chain",
                confidence=0.85,
                score_contribution=0.12,
            ),
            CorrelationSignal(
                signal_id=str(uuid.uuid4()),
                pattern_type="hash_cluster",
                confidence=0.50,
                score_contribution=0.09,
            ),
        ]
        engine = ThreatCorrelationEngine()
        summary = engine.summarize(signals)
        assert summary["max_confidence"] == 0.85
