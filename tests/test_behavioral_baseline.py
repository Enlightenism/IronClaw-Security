from __future__ import annotations

import pytest

from app.services.behavioral_baseline import (
    BASELINE_SCHEMA_VERSION,
    MIN_SAMPLES_FOR_BASELINE,
    AgentObservation,
    BehavioralBaselineStore,
    DriftReport,
    _compute_action_rate,
    _compute_action_type_distribution,
    _compute_mean_risk,
    _compute_target_breadth,
    _compute_tool_call_rate,
    _jensen_shannon_divergence,
    _normalize_distribution,
    _safe_mean,
    _safe_stdev,
    _severity_from_score,
    _z_score,
    get_behavioral_baseline_store,
    reset_behavioral_baseline_store,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_store():
    reset_behavioral_baseline_store()
    yield
    reset_behavioral_baseline_store()


@pytest.fixture
def store() -> BehavioralBaselineStore:
    return BehavioralBaselineStore()


def _fill_store(
    store: BehavioralBaselineStore,
    agent_id: str = "agent-alpha",
    count: int = 10,
    action_type: str = "file_read",
    target: str = "app/main.py",
    risk_score: int = 10,
    session_id: str = "sess-001",
    client_id: str = "client-xyz",
) -> list[AgentObservation]:
    return [
        store.record_observation(
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            risk_score=risk_score,
            session_id=session_id,
            client_id=client_id,
        )
        for _ in range(count)
    ]


# ---------------------------------------------------------------------------
# Pure math helpers
# ---------------------------------------------------------------------------


class TestSafeMean:
    def test_empty(self):
        assert _safe_mean([]) == 0.0

    def test_single(self):
        assert _safe_mean([5.0]) == 5.0

    def test_multi(self):
        assert _safe_mean([2.0, 4.0, 6.0]) == pytest.approx(4.0)


class TestSafeStdev:
    def test_empty(self):
        assert _safe_stdev([]) == 0.0

    def test_single(self):
        assert _safe_stdev([42.0]) == 0.0

    def test_multi(self):
        result = _safe_stdev([2.0, 4.0, 6.0])
        assert result > 0.0


class TestZScore:
    def test_zero_stdev_returns_zero(self):
        assert _z_score(10.0, 10.0, 0.0) == 0.0

    def test_no_deviation(self):
        assert _z_score(5.0, 5.0, 1.0) == 0.0

    def test_positive_deviation(self):
        result = _z_score(8.0, 5.0, 1.0)
        assert result == pytest.approx(3.0)

    def test_absolute_value_used(self):
        assert _z_score(2.0, 5.0, 1.0) == pytest.approx(3.0)


class TestJensenShannonDivergence:
    def test_identical_distributions(self):
        p = {"a": 0.5, "b": 0.5}
        assert _jensen_shannon_divergence(p, p) == pytest.approx(0.0, abs=1e-9)

    def test_completely_disjoint(self):
        p = {"a": 1.0}
        q = {"b": 1.0}
        result = _jensen_shannon_divergence(p, q)
        assert result == pytest.approx(1.0, abs=1e-9)

    def test_both_empty(self):
        assert _jensen_shannon_divergence({}, {}) == 0.0

    def test_bounded_zero_to_one(self):
        p = {"x": 0.7, "y": 0.3}
        q = {"x": 0.1, "z": 0.9}
        result = _jensen_shannon_divergence(p, q)
        assert 0.0 <= result <= 1.0

    def test_symmetric(self):
        p = {"a": 0.6, "b": 0.4}
        q = {"a": 0.2, "b": 0.8}
        assert _jensen_shannon_divergence(p, q) == pytest.approx(_jensen_shannon_divergence(q, p), abs=1e-9)


class TestNormalizeDistribution:
    def test_empty(self):
        assert _normalize_distribution({}) == {}

    def test_single(self):
        result = _normalize_distribution({"a": 4})
        assert result == {"a": pytest.approx(1.0)}

    def test_multi(self):
        result = _normalize_distribution({"a": 1, "b": 1, "c": 2})
        assert result["a"] == pytest.approx(0.25)
        assert result["c"] == pytest.approx(0.50)


class TestSeverityFromScore:
    def test_none(self):
        assert _severity_from_score(0.0) == "none"
        assert _severity_from_score(0.19) == "none"

    def test_low(self):
        assert _severity_from_score(0.20) == "low"
        assert _severity_from_score(0.44) == "low"

    def test_medium(self):
        assert _severity_from_score(0.45) == "medium"
        assert _severity_from_score(0.69) == "medium"

    def test_high(self):
        assert _severity_from_score(0.70) == "high"
        assert _severity_from_score(0.89) == "high"

    def test_critical(self):
        assert _severity_from_score(0.90) == "critical"
        assert _severity_from_score(1.0) == "critical"


# ---------------------------------------------------------------------------
# Observation window helpers (using store-produced observations)
# ---------------------------------------------------------------------------


class TestComputeActionRate:
    def test_zero_observations(self):
        assert _compute_action_rate([], 3600) == 0.0

    def test_zero_window(self):
        from datetime import UTC, datetime

        obs = [
            AgentObservation(
                observation_id="x",
                agent_id="a",
                session_id=None,
                client_id=None,
                timestamp=datetime.now(UTC),
                action_type="read",
                target="f",
                risk_score=5,
                matched_patterns=[],
            )
        ]
        assert _compute_action_rate(obs, 0) == 0.0

    def test_rate_calculation(self):
        from datetime import UTC, datetime

        obs = [
            AgentObservation(
                observation_id=f"o{i}",
                agent_id="a",
                session_id=None,
                client_id=None,
                timestamp=datetime.now(UTC),
                action_type="read",
                target="f",
                risk_score=5,
                matched_patterns=[],
            )
            for i in range(36)
        ]
        rate = _compute_action_rate(obs, 3600)
        assert rate == pytest.approx(36.0)


class TestComputeActionTypeDistribution:
    def test_empty(self):
        assert _compute_action_type_distribution([]) == {}

    def test_single_type(self, store):
        _fill_store(store, count=5, action_type="file_write")
        result = _compute_action_type_distribution(store.get_observations("agent-alpha"))
        assert result["file_write"] == pytest.approx(1.0)

    def test_mixed_types(self, store):
        store.record_observation("ag", "file_read", "x", 10)
        store.record_observation("ag", "file_read", "x", 10)
        store.record_observation("ag", "tool_call", "x", 10)
        obs = store.get_observations("ag")
        result = _compute_action_type_distribution(obs)
        assert result["file_read"] == pytest.approx(2 / 3)
        assert result["tool_call"] == pytest.approx(1 / 3)


class TestComputeMeanRisk:
    def test_empty(self):
        assert _compute_mean_risk([]) == 0.0

    def test_uniform(self, store):
        _fill_store(store, count=5, risk_score=20)
        obs = store.get_observations("agent-alpha")
        assert _compute_mean_risk(obs) == pytest.approx(20.0)

    def test_mixed(self, store):
        store.record_observation("ag", "read", "f", 10)
        store.record_observation("ag", "read", "f", 30)
        obs = store.get_observations("ag")
        assert _compute_mean_risk(obs) == pytest.approx(20.0)


class TestComputeTargetBreadth:
    def test_empty(self):
        assert _compute_target_breadth([]) == 0.0

    def test_all_same_target(self, store):
        _fill_store(store, count=5, target="app/main.py")
        obs = store.get_observations("agent-alpha")
        assert _compute_target_breadth(obs) == pytest.approx(1 / 5)

    def test_all_unique_targets(self, store):
        for i in range(5):
            store.record_observation("ag", "read", f"file_{i}.py", 5)
        obs = store.get_observations("ag")
        assert _compute_target_breadth(obs) == pytest.approx(1.0)


class TestComputeToolCallRate:
    def test_empty(self):
        assert _compute_tool_call_rate([]) == 0.0

    def test_all_tool_calls(self, store):
        for _ in range(4):
            store.record_observation("ag", "tool_call", "f", 5)
        obs = store.get_observations("ag")
        assert _compute_tool_call_rate(obs) == pytest.approx(1.0)

    def test_no_tool_calls(self, store):
        _fill_store(store, count=4, action_type="file_read")
        obs = store.get_observations("agent-alpha")
        assert _compute_tool_call_rate(obs) == pytest.approx(0.0)

    def test_partial_tool_calls(self, store):
        store.record_observation("ag", "tool_call", "f", 5)
        store.record_observation("ag", "file_read", "f", 5)
        store.record_observation("ag", "file_read", "f", 5)
        store.record_observation("ag", "file_read", "f", 5)
        obs = store.get_observations("ag")
        assert _compute_tool_call_rate(obs) == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — observation ingestion
# ---------------------------------------------------------------------------


class TestRecordObservation:
    def test_returns_observation(self, store):
        obs = store.record_observation("ag-1", "file_read", "main.py", 10)
        assert isinstance(obs, AgentObservation)
        assert obs.agent_id == "ag-1"
        assert obs.action_type == "file_read"
        assert obs.target == "main.py"
        assert obs.risk_score == 10

    def test_observation_id_is_unique(self, store):
        obs1 = store.record_observation("ag", "read", "f", 5)
        obs2 = store.record_observation("ag", "read", "f", 5)
        assert obs1.observation_id != obs2.observation_id

    def test_risk_score_clamped_low(self, store):
        obs = store.record_observation("ag", "read", "f", -50)
        assert obs.risk_score == 0

    def test_risk_score_clamped_high(self, store):
        obs = store.record_observation("ag", "read", "f", 999)
        assert obs.risk_score == 100

    def test_empty_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.record_observation("", "read", "f", 5)

    def test_whitespace_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.record_observation("   ", "read", "f", 5)

    def test_empty_action_type_raises(self, store):
        with pytest.raises(ValueError):
            store.record_observation("ag", "", "f", 5)

    def test_optional_fields_stored(self, store):
        obs = store.record_observation(
            "ag",
            "read",
            "f",
            5,
            session_id="s1",
            client_id="c1",
            matched_patterns=["pattern_a"],
            metadata={"key": "value"},
        )
        assert obs.session_id == "s1"
        assert obs.client_id == "c1"
        assert "pattern_a" in obs.matched_patterns
        assert obs.metadata["key"] == "value"

    def test_multiple_agents_isolated(self, store):
        store.record_observation("ag-1", "read", "f", 5)
        store.record_observation("ag-2", "write", "g", 15)
        assert len(store.get_observations("ag-1")) == 1
        assert len(store.get_observations("ag-2")) == 1

    def test_cap_respects_max(self):
        s = BehavioralBaselineStore(max_observations_per_agent=3)
        for _ in range(10):
            s.record_observation("ag", "read", "f", 5)
        assert len(s.get_observations("ag")) == 3

    def test_to_dict_shape(self, store):
        obs = store.record_observation("ag", "read", "f", 5)
        d = obs.to_dict()
        assert "observation_id" in d
        assert "agent_id" in d
        assert "timestamp" in d
        assert isinstance(d["timestamp"], str)


class TestRecordObservationsBulk:
    def test_bulk_returns_list(self, store):
        items = [
            {"action_type": "file_read", "target": "a.py", "risk_score": 10},
            {"action_type": "tool_call", "target": "b.py", "risk_score": 20},
        ]
        result = store.record_observations_bulk("ag", items, client_id="c1")
        assert len(result) == 2
        assert all(isinstance(o, AgentObservation) for o in result)

    def test_bulk_empty_list(self, store):
        result = store.record_observations_bulk("ag", [])
        assert result == []

    def test_bulk_contributes_to_baseline(self, store):
        items = [{"action_type": "read", "target": f"f{i}.py", "risk_score": 5} for i in range(MIN_SAMPLES_FOR_BASELINE)]
        store.record_observations_bulk("ag", items)
        baseline = store.get_baseline("ag")
        assert baseline is not None
        assert baseline.status == "active"


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — baseline management
# ---------------------------------------------------------------------------


class TestBaselineProgressions:
    def test_no_baseline_before_observations(self, store):
        assert store.get_baseline("ag-new") is None

    def test_baseline_created_after_first_observation(self, store):
        store.record_observation("ag", "read", "f", 5)
        baseline = store.get_baseline("ag")
        assert baseline is not None

    def test_status_learning_below_min_samples(self):
        s = BehavioralBaselineStore(min_samples_for_baseline=5)
        for _ in range(4):
            s.record_observation("ag", "read", "f", 5)
        assert s.get_baseline("ag").status == "learning"

    def test_status_active_at_min_samples(self):
        s = BehavioralBaselineStore(min_samples_for_baseline=5)
        for _ in range(5):
            s.record_observation("ag", "read", "f", 5)
        assert s.get_baseline("ag").status == "active"

    def test_baseline_schema_version(self, store):
        store.record_observation("ag", "read", "f", 5)
        assert store.get_baseline("ag").schema_version == BASELINE_SCHEMA_VERSION

    def test_baseline_agent_id_matches(self, store):
        store.record_observation("agent-007", "read", "f", 5)
        assert store.get_baseline("agent-007").agent_id == "agent-007"

    def test_baseline_sample_count_increments(self, store):
        for i in range(1, 6):
            store.record_observation("ag", "read", "f", 5)
            assert store.get_baseline("ag").sample_count == i

    def test_baseline_mean_risk_updates(self, store):
        for _ in range(10):
            store.record_observation("ag", "read", "f", 20)
        baseline = store.get_baseline("ag")
        assert baseline.mean_risk_score > 0.0

    def test_baseline_to_dict_shape(self, store):
        store.record_observation("ag", "read", "f", 5)
        d = store.get_baseline("ag").to_dict()
        required_keys = {
            "baseline_id",
            "agent_id",
            "status",
            "sample_count",
            "created_at",
            "updated_at",
            "mean_action_rate",
            "mean_risk_score",
            "action_type_distribution",
            "schema_version",
        }
        assert required_keys.issubset(set(d.keys()))

    def test_baseline_not_overwritten_when_suspended(self, store):
        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        store.suspend_baseline("agent-alpha")
        store.record_observation("agent-alpha", "read", "f", 5)
        assert store.get_baseline("agent-alpha").status == "suspended"


class TestInvalidateBaseline:
    def test_nonexistent_returns_false(self, store):
        assert store.invalidate_baseline("no-such-agent") is False

    def test_invalidate_sets_stale(self, store):
        store.record_observation("ag", "read", "f", 5)
        result = store.invalidate_baseline("ag")
        assert result is True
        assert store.get_baseline("ag").status == "stale"


class TestSuspendBaseline:
    def test_nonexistent_returns_false(self, store):
        assert store.suspend_baseline("ghost") is False

    def test_suspend_sets_status(self, store):
        store.record_observation("ag", "read", "f", 5)
        result = store.suspend_baseline("ag")
        assert result is True
        assert store.get_baseline("ag").status == "suspended"


class TestListBaselines:
    def test_empty_store(self, store):
        assert store.list_baselines() == []

    def test_returns_all(self, store):
        for agent in ["ag-1", "ag-2", "ag-3"]:
            store.record_observation(agent, "read", "f", 5)
        assert len(store.list_baselines()) == 3

    def test_filter_by_client_id(self, store):
        store.record_observation("ag-1", "read", "f", 5, client_id="c1")
        store.record_observation("ag-2", "read", "f", 5, client_id="c2")
        result = store.list_baselines(client_id="c1")
        assert len(result) == 1
        assert result[0].agent_id == "ag-1"

    def test_filter_by_status(self, store):
        store.record_observation("ag-1", "read", "f", 5)
        store.record_observation("ag-2", "read", "f", 5)
        store.suspend_baseline("ag-1")
        suspended = store.list_baselines(status="suspended")
        assert len(suspended) == 1
        assert suspended[0].agent_id == "ag-1"


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — observation retrieval
# ---------------------------------------------------------------------------


class TestGetObservations:
    def test_unknown_agent_returns_empty(self, store):
        assert store.get_observations("no-such-agent") == []

    def test_returns_recorded_observations(self, store):
        _fill_store(store, count=5)
        obs = store.get_observations("agent-alpha")
        assert len(obs) == 5

    def test_limit_applied(self, store):
        _fill_store(store, count=20)
        obs = store.get_observations("agent-alpha", limit=5)
        assert len(obs) == 5

    def test_filter_by_session_id(self, store):
        store.record_observation("ag", "read", "f", 5, session_id="s1")
        store.record_observation("ag", "read", "f", 5, session_id="s2")
        store.record_observation("ag", "read", "f", 5, session_id="s1")
        result = store.get_observations("ag", session_id="s1")
        assert len(result) == 2
        assert all(o.session_id == "s1" for o in result)


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — purge and reset
# ---------------------------------------------------------------------------


class TestPurgeAgent:
    def test_purge_nonexistent_returns_false(self, store):
        assert store.purge_agent("ghost") is False

    def test_purge_clears_observations_and_baseline(self, store):
        _fill_store(store, count=5)
        result = store.purge_agent("agent-alpha")
        assert result is True
        assert store.get_observations("agent-alpha") == []
        assert store.get_baseline("agent-alpha") is None

    def test_purge_does_not_affect_other_agents(self, store):
        _fill_store(store, agent_id="ag-1", count=5)
        _fill_store(store, agent_id="ag-2", count=5)
        store.purge_agent("ag-1")
        assert store.get_baseline("ag-2") is not None


class TestReset:
    def test_reset_clears_all(self, store):
        _fill_store(store, agent_id="ag-1", count=5)
        _fill_store(store, agent_id="ag-2", count=5)
        store.reset()
        assert store.list_baselines() == []
        assert store.get_observations("ag-1") == []


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — drift detection (no-baseline path)
# ---------------------------------------------------------------------------


class TestComputeDriftNoBaseline:
    def test_no_baseline_returns_report(self, store):
        report = store.compute_drift("brand-new-agent")
        assert isinstance(report, DriftReport)
        assert report.agent_id == "brand-new-agent"
        assert report.overall_severity == "none"
        assert report.should_alert is False
        assert report.should_suspend is False
        assert report.baseline_sample_count == 0

    def test_no_baseline_has_recommendation(self, store):
        report = store.compute_drift("brand-new-agent")
        assert len(report.recommendations) > 0


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — drift detection (suspended path)
# ---------------------------------------------------------------------------


class TestComputeDriftSuspended:
    def test_suspended_returns_critical(self, store):
        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        store.suspend_baseline("agent-alpha")
        report = store.compute_drift("agent-alpha")
        assert report.overall_severity == "critical"
        assert report.should_alert is True
        assert report.should_suspend is True
        assert report.baseline_status == "suspended"


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — drift detection (learning path)
# ---------------------------------------------------------------------------


class TestComputeDriftLearning:
    def test_learning_baseline_dampens_severity(self):
        s = BehavioralBaselineStore(min_samples_for_baseline=100)
        s.record_observation("ag", "read", "f", 5)
        report = s.compute_drift("ag")
        assert report.baseline_status == "learning"
        assert report.overall_severity in ("none", "low")

    def test_report_has_report_id(self, store):
        store.record_observation("ag", "read", "f", 5)
        report = store.compute_drift("ag")
        assert report.report_id.startswith("drift-")


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — drift detection (active baseline)
# ---------------------------------------------------------------------------


class TestComputeDriftActive:
    def test_stable_behavior_no_drift(self, store):
        for _ in range(MIN_SAMPLES_FOR_BASELINE * 2):
            store.record_observation("ag", "file_read", "main.py", 10)
        report = store.compute_drift("ag")
        assert report.overall_severity in ("none", "low")
        assert report.should_alert is False

    def test_drift_report_shape(self, store):
        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        report = store.compute_drift("agent-alpha")
        d = report.to_dict()
        required = {
            "report_id",
            "agent_id",
            "timestamp",
            "overall_drift_score",
            "overall_severity",
            "signals",
            "recommendations",
            "should_alert",
            "should_suspend",
            "baseline_sample_count",
            "window_seconds",
            "observation_count",
        }
        assert required.issubset(set(d.keys()))
        assert isinstance(d["signals"], list)
        assert isinstance(d["recommendations"], list)

    def test_risk_elevation_triggers_signal(self, store):
        for _ in range(20):
            store.record_observation("ag", "read", "f", 5)
        for _ in range(5):
            store.record_observation("ag", "read", "f", 100)
        report = store.compute_drift("ag")
        signal_categories = [s.category for s in report.signals]
        assert "risk_score_elevation" in signal_categories

    def test_action_type_shift_triggers_signal(self, store):
        for _ in range(20):
            store.record_observation("ag", "file_read", "f", 5)
        for _ in range(10):
            store.record_observation("ag", "shell_command", "bash", 80)
        report = store.compute_drift("ag")
        signal_categories = [s.category for s in report.signals]
        assert "action_type_distribution" in signal_categories

    def test_custom_window_respected(self, store):
        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        report_narrow = store.compute_drift("agent-alpha", window_seconds=60)
        report_wide = store.compute_drift("agent-alpha", window_seconds=3600)
        assert report_narrow.window_seconds == 60
        assert report_wide.window_seconds == 3600

    def test_session_id_propagated(self, store):
        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        report = store.compute_drift("agent-alpha", session_id="sess-42")
        assert report.session_id == "sess-42"

    def test_client_id_propagated(self, store):
        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        report = store.compute_drift("agent-alpha", client_id="client-99")
        assert report.client_id == "client-99"

    def test_auto_suspend_on_critical_drift(self, store):
        for _ in range(20):
            store.record_observation("ag", "file_read", "main.py", 5)
        for _ in range(20):
            store.record_observation("ag", "shell_command", "bash_root", 100)
        report = store.compute_drift("ag")
        if report.should_suspend:
            assert store.get_baseline("ag").status == "suspended"

    def test_signal_deviation_score_bounded(self, store):
        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        for _ in range(20):
            store.record_observation("agent-alpha", "shell_command", "rm -rf", 99)
        report = store.compute_drift("agent-alpha")
        for sig in report.signals:
            assert 0.0 <= sig.deviation_score <= 1.0

    def test_drift_score_bounded(self, store):
        for _ in range(10):
            store.record_observation("ag", "file_read", "f", 5)
        for _ in range(10):
            store.record_observation("ag", "shell_command", "bash", 100)
        report = store.compute_drift("ag")
        assert 0.0 <= report.overall_drift_score <= 1.0


# ---------------------------------------------------------------------------
# DriftSignal model
# ---------------------------------------------------------------------------


class TestDriftSignalModel:
    def test_signal_fields_present(self, store):
        for _ in range(MIN_SAMPLES_FOR_BASELINE):
            store.record_observation("ag", "read", "f", 5)
        for _ in range(10):
            store.record_observation("ag", "read", "f", 95)
        report = store.compute_drift("ag")
        for sig in report.signals:
            assert hasattr(sig, "category")
            assert hasattr(sig, "observed_value")
            assert hasattr(sig, "baseline_value")
            assert hasattr(sig, "deviation_score")
            assert hasattr(sig, "severity")
            assert hasattr(sig, "detail")
            assert isinstance(sig.detail, str)
            assert len(sig.detail) > 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_returns_instance(self):
        s = get_behavioral_baseline_store()
        assert isinstance(s, BehavioralBaselineStore)

    def test_get_same_instance(self):
        assert get_behavioral_baseline_store() is get_behavioral_baseline_store()

    def test_reset_clears_singleton(self):
        s = get_behavioral_baseline_store()
        s.record_observation("ag", "read", "f", 5)
        reset_behavioral_baseline_store()
        assert get_behavioral_baseline_store().get_baseline("ag") is None

    def test_reset_same_object_persists(self):
        s1 = get_behavioral_baseline_store()
        reset_behavioral_baseline_store()
        s2 = get_behavioral_baseline_store()
        assert s1 is s2


# ---------------------------------------------------------------------------
# Thread safety (basic smoke)
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_record_does_not_raise(self, store):
        import threading

        errors: list[Exception] = []

        def worker(agent_id: str) -> None:
            try:
                for _ in range(10):
                    store.record_observation(agent_id, "read", "f", 5)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"ag-{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(store.list_baselines()) == 5

    def test_concurrent_drift_does_not_raise(self, store):
        import threading

        _fill_store(store, count=MIN_SAMPLES_FOR_BASELINE)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                store.compute_drift("agent-alpha")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
