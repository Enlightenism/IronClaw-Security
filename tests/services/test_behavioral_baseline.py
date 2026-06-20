from __future__ import annotations

from datetime import UTC, datetime, timedelta
import math
from unittest.mock import patch

import pytest

from app.services.behavioral_baseline import (
    BASELINE_SCHEMA_VERSION,
    DRIFT_WINDOW_SECONDS,
    MAX_BASELINE_SAMPLES,
    MIN_SAMPLES_FOR_BASELINE,
    AgentBaseline,
    AgentObservation,
    BehavioralBaselineStore,
    DriftReport,
    DriftSignal,
    _compute_action_rate,
    _compute_action_type_distribution,
    _compute_mean_risk,
    _compute_overall_drift_score,
    _compute_target_breadth,
    _compute_tool_call_rate,
    _jensen_shannon_divergence,
    _normalize_distribution,
    _require_str,
    _safe_mean,
    _safe_stdev,
    _severity_from_score,
    _window_observations,
    _z_score,
    get_behavioral_baseline_store,
    reset_behavioral_baseline_store,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _make_obs(
    agent_id: str = "agent-1",
    action_type: str = "file_read",
    target: str = "readme.txt",
    risk_score: int = 10,
    session_id: str | None = "sess-1",
    client_id: str | None = "client-1",
    ts: datetime | None = None,
) -> AgentObservation:
    return AgentObservation(
        observation_id="obs-test",
        agent_id=agent_id,
        session_id=session_id,
        client_id=client_id,
        timestamp=ts or _utcnow(),
        action_type=action_type,
        target=target,
        risk_score=risk_score,
        matched_patterns=[],
        metadata={},
    )


def _make_store(
    drift_window_seconds: int = DRIFT_WINDOW_SECONDS,
    max_observations_per_agent: int = MAX_BASELINE_SAMPLES,
    min_samples_for_baseline: int = MIN_SAMPLES_FOR_BASELINE,
) -> BehavioralBaselineStore:
    return BehavioralBaselineStore(
        drift_window_seconds=drift_window_seconds,
        max_observations_per_agent=max_observations_per_agent,
        min_samples_for_baseline=min_samples_for_baseline,
    )


def _populate_store(
    store: BehavioralBaselineStore,
    agent_id: str = "agent-1",
    n: int = 10,
    action_type: str = "file_read",
    risk_score: int = 10,
    client_id: str | None = "client-1",
) -> None:
    for i in range(n):
        store.record_observation(
            agent_id=agent_id,
            action_type=action_type,
            target=f"target-{i}",
            risk_score=risk_score,
            session_id="sess-1",
            client_id=client_id,
        )


@pytest.fixture(autouse=True)
def _isolate_store():
    """Each test gets a clean module-level singleton."""
    reset_behavioral_baseline_store()
    yield
    reset_behavioral_baseline_store()


@pytest.fixture()
def store() -> BehavioralBaselineStore:
    return _make_store()


# ---------------------------------------------------------------------------
# Pure helpers — _require_str
# ---------------------------------------------------------------------------


class TestRequireStr:
    def test_valid_string_returned(self):
        assert _require_str("hello", "f") == "hello"

    def test_strips_whitespace(self):
        assert _require_str("  hello  ", "f") == "hello"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="f must be a non-empty string"):
            _require_str("", "f")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            _require_str("   ", "f")

    def test_non_string_raises(self):
        with pytest.raises(ValueError):
            _require_str(None, "f")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Pure helpers — _safe_mean / _safe_stdev / _z_score
# ---------------------------------------------------------------------------


class TestSafeMath:
    def test_safe_mean_empty_returns_zero(self):
        assert _safe_mean([]) == 0.0

    def test_safe_mean_single(self):
        assert _safe_mean([5.0]) == 5.0

    def test_safe_mean_multiple(self):
        assert _safe_mean([2.0, 4.0]) == pytest.approx(3.0)

    def test_safe_stdev_empty_returns_zero(self):
        assert _safe_stdev([]) == 0.0

    def test_safe_stdev_single_returns_zero(self):
        assert _safe_stdev([1.0]) == 0.0

    def test_safe_stdev_two_elements(self):
        assert _safe_stdev([0.0, 2.0]) == pytest.approx(math.sqrt(2))

    def test_z_score_zero_stdev_returns_zero(self):
        assert _z_score(10.0, 5.0, 0.0) == 0.0

    def test_z_score_correct(self):
        assert _z_score(15.0, 10.0, 5.0) == pytest.approx(1.0)

    def test_z_score_absolute_value(self):
        assert _z_score(5.0, 10.0, 5.0) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Pure helpers — _severity_from_score
# ---------------------------------------------------------------------------


class TestSeverityFromScore:
    def test_critical(self):
        assert _severity_from_score(0.95) == "critical"

    def test_high(self):
        assert _severity_from_score(0.75) == "high"

    def test_medium(self):
        assert _severity_from_score(0.50) == "medium"

    def test_low(self):
        assert _severity_from_score(0.25) == "low"

    def test_none(self):
        assert _severity_from_score(0.10) == "none"

    def test_boundary_critical(self):
        assert _severity_from_score(0.90) == "critical"

    def test_boundary_high(self):
        assert _severity_from_score(0.70) == "high"

    def test_boundary_medium(self):
        assert _severity_from_score(0.45) == "medium"

    def test_boundary_low(self):
        assert _severity_from_score(0.20) == "low"

    def test_zero_is_none(self):
        assert _severity_from_score(0.0) == "none"


# ---------------------------------------------------------------------------
# Pure helpers — _normalize_distribution
# ---------------------------------------------------------------------------


class TestNormalizeDistribution:
    def test_empty_returns_empty(self):
        assert _normalize_distribution({}) == {}

    def test_all_zero_returns_empty(self):
        assert _normalize_distribution({"a": 0}) == {}

    def test_sums_to_one(self):
        result = _normalize_distribution({"a": 3, "b": 7})
        assert sum(result.values()) == pytest.approx(1.0)

    def test_correct_proportions(self):
        result = _normalize_distribution({"a": 1, "b": 1})
        assert result["a"] == pytest.approx(0.5)
        assert result["b"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Pure helpers — _jensen_shannon_divergence
# ---------------------------------------------------------------------------


class TestJensenShannonDivergence:
    def test_identical_distributions_zero(self):
        p = {"a": 0.5, "b": 0.5}
        assert _jensen_shannon_divergence(p, p) == pytest.approx(0.0, abs=1e-9)

    def test_completely_different_distributions_nonzero(self):
        p = {"a": 1.0}
        q = {"b": 1.0}
        jsd = _jensen_shannon_divergence(p, q)
        assert jsd > 0.0

    def test_result_bounded_zero_to_one(self):
        p = {"a": 0.9, "b": 0.1}
        q = {"c": 1.0}
        jsd = _jensen_shannon_divergence(p, q)
        assert 0.0 <= jsd <= 1.0

    def test_empty_both_returns_zero(self):
        assert _jensen_shannon_divergence({}, {}) == 0.0

    def test_one_empty_handles_gracefully(self):
        p = {"a": 1.0}
        result = _jensen_shannon_divergence(p, {})
        assert 0.0 <= result <= 1.0

    def test_symmetric(self):
        p = {"a": 0.7, "b": 0.3}
        q = {"a": 0.2, "b": 0.8}
        assert _jensen_shannon_divergence(p, q) == pytest.approx(_jensen_shannon_divergence(q, p), abs=1e-9)


# ---------------------------------------------------------------------------
# Window helpers — _window_observations
# ---------------------------------------------------------------------------


class TestWindowObservations:
    def test_returns_all_within_window(self):
        now = _utcnow()
        obs = [
            _make_obs(ts=now - timedelta(seconds=100)),
            _make_obs(ts=now - timedelta(seconds=200)),
        ]
        result = _window_observations(obs, 300, reference_time=now)
        assert len(result) == 2

    def test_excludes_observations_outside_window(self):
        now = _utcnow()
        obs = [
            _make_obs(ts=now - timedelta(seconds=400)),
        ]
        result = _window_observations(obs, 300, reference_time=now)
        assert len(result) == 0

    def test_empty_list_returns_empty(self):
        assert _window_observations([], 3600) == []

    def test_uses_utcnow_when_reference_time_none(self):
        now = _utcnow()
        obs = [_make_obs(ts=now - timedelta(seconds=10))]
        result = _window_observations(obs, 60)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Window helpers — _compute_action_rate
# ---------------------------------------------------------------------------


class TestComputeActionRate:
    def test_empty_observations_returns_zero(self):
        assert _compute_action_rate([], 3600) == 0.0

    def test_zero_window_returns_zero(self):
        obs = [_make_obs()]
        assert _compute_action_rate(obs, 0) == 0.0

    def test_negative_window_returns_zero(self):
        obs = [_make_obs()]
        assert _compute_action_rate(obs, -1) == 0.0

    def test_rate_per_hour_correct(self):
        obs = [_make_obs() for _ in range(10)]
        rate = _compute_action_rate(obs, 3600)
        assert rate == pytest.approx(10.0)

    def test_rate_half_window(self):
        obs = [_make_obs() for _ in range(10)]
        rate = _compute_action_rate(obs, 1800)
        assert rate == pytest.approx(20.0)


# ---------------------------------------------------------------------------
# Window helpers — _compute_action_type_distribution
# ---------------------------------------------------------------------------


class TestComputeActionTypeDistribution:
    def test_empty_returns_empty(self):
        assert _compute_action_type_distribution([]) == {}

    def test_single_type_is_one(self):
        obs = [_make_obs(action_type="file_read") for _ in range(3)]
        dist = _compute_action_type_distribution(obs)
        assert dist["file_read"] == pytest.approx(1.0)

    def test_two_types_correct_proportions(self):
        obs = [_make_obs(action_type="file_read")] * 3 + [_make_obs(action_type="tool_call")] * 1
        dist = _compute_action_type_distribution(obs)
        assert dist["file_read"] == pytest.approx(0.75)
        assert dist["tool_call"] == pytest.approx(0.25)

    def test_distribution_sums_to_one(self):
        obs = [
            _make_obs(action_type="a"),
            _make_obs(action_type="b"),
            _make_obs(action_type="c"),
        ]
        dist = _compute_action_type_distribution(obs)
        assert sum(dist.values()) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Window helpers — _compute_mean_risk
# ---------------------------------------------------------------------------


class TestComputeMeanRisk:
    def test_empty_returns_zero(self):
        assert _compute_mean_risk([]) == 0.0

    def test_single_observation(self):
        obs = [_make_obs(risk_score=50)]
        assert _compute_mean_risk(obs) == pytest.approx(50.0)

    def test_mean_correct(self):
        obs = [_make_obs(risk_score=20), _make_obs(risk_score=80)]
        assert _compute_mean_risk(obs) == pytest.approx(50.0)


# ---------------------------------------------------------------------------
# Window helpers — _compute_target_breadth
# ---------------------------------------------------------------------------


class TestComputeTargetBreadth:
    def test_empty_returns_zero(self):
        assert _compute_target_breadth([]) == 0.0

    def test_all_same_target_returns_low_breadth(self):
        obs = [_make_obs(target="same") for _ in range(5)]
        breadth = _compute_target_breadth(obs)
        assert breadth == pytest.approx(1 / 5)

    def test_all_unique_targets_returns_one(self):
        obs = [_make_obs(target=f"t{i}") for i in range(5)]
        breadth = _compute_target_breadth(obs)
        assert breadth == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Window helpers — _compute_tool_call_rate
# ---------------------------------------------------------------------------


class TestComputeToolCallRate:
    def test_empty_returns_zero(self):
        assert _compute_tool_call_rate([]) == 0.0

    def test_no_tool_calls_returns_zero(self):
        obs = [_make_obs(action_type="file_read") for _ in range(5)]
        assert _compute_tool_call_rate(obs) == 0.0

    def test_all_tool_calls_returns_one(self):
        obs = [_make_obs(action_type="tool_call") for _ in range(5)]
        assert _compute_tool_call_rate(obs) == pytest.approx(1.0)

    def test_mixed_rate_correct(self):
        obs = [_make_obs(action_type="tool_call")] * 2 + [_make_obs(action_type="file_read")] * 2
        assert _compute_tool_call_rate(obs) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# _compute_overall_drift_score
# ---------------------------------------------------------------------------


class TestComputeOverallDriftScore:
    def _signal(self, score: float) -> DriftSignal:
        return DriftSignal(
            category="action_frequency",
            observed_value=score,
            baseline_value=0.0,
            deviation_score=score,
            severity=_severity_from_score(score),
            detail="test",
        )

    def test_no_signals_returns_zero(self):
        assert _compute_overall_drift_score([]) == 0.0

    def test_single_signal_at_least_that_value(self):
        score = _compute_overall_drift_score([self._signal(0.6)])
        assert score >= 0.6

    def test_capped_at_one(self):
        signals = [self._signal(1.0) for _ in range(10)]
        assert _compute_overall_drift_score(signals) <= 1.0

    def test_multiple_signals_higher_than_single(self):
        single = _compute_overall_drift_score([self._signal(0.5)])
        multiple = _compute_overall_drift_score([self._signal(0.5), self._signal(0.5)])
        assert multiple >= single


# ---------------------------------------------------------------------------
# AgentObservation — to_dict
# ---------------------------------------------------------------------------


class TestAgentObservationToDict:
    def test_timestamp_serialized_as_z_suffix(self):
        obs = _make_obs()
        d = obs.to_dict()
        assert d["timestamp"].endswith("Z")

    def test_all_fields_present(self):
        obs = _make_obs()
        d = obs.to_dict()
        for key in (
            "observation_id",
            "agent_id",
            "session_id",
            "client_id",
            "timestamp",
            "action_type",
            "target",
            "risk_score",
            "matched_patterns",
            "metadata",
        ):
            assert key in d


# ---------------------------------------------------------------------------
# AgentBaseline — to_dict
# ---------------------------------------------------------------------------


class TestAgentBaselineToDict:
    def _make_baseline(self) -> AgentBaseline:
        now = _utcnow()
        return AgentBaseline(
            baseline_id="bl-1",
            agent_id="agent-1",
            client_id="client-1",
            status="active",
            schema_version=BASELINE_SCHEMA_VERSION,
            sample_count=10,
            created_at=now,
            updated_at=now,
            mean_action_rate=5.0,
            stdev_action_rate=2.0,
            action_type_distribution={"file_read": 1.0},
            mean_risk_score=10.0,
            stdev_risk_score=2.0,
            mean_target_breadth=0.5,
            stdev_target_breadth=0.15,
            mean_tool_call_rate=0.1,
            stdev_tool_call_rate=0.05,
        )

    def test_created_at_z_suffix(self):
        bl = self._make_baseline()
        d = bl.to_dict()
        assert d["created_at"].endswith("Z")

    def test_updated_at_z_suffix(self):
        bl = self._make_baseline()
        d = bl.to_dict()
        assert d["updated_at"].endswith("Z")

    def test_all_required_keys_present(self):
        bl = self._make_baseline()
        d = bl.to_dict()
        for key in (
            "baseline_id",
            "agent_id",
            "client_id",
            "status",
            "schema_version",
            "sample_count",
        ):
            assert key in d


# ---------------------------------------------------------------------------
# DriftReport — to_dict
# ---------------------------------------------------------------------------


class TestDriftReportToDict:
    def _make_report(self) -> DriftReport:
        return DriftReport(
            report_id="dr-1",
            agent_id="agent-1",
            client_id="client-1",
            session_id="sess-1",
            timestamp=_utcnow(),
            window_seconds=3600,
            observation_count=5,
            baseline_sample_count=10,
            baseline_status="active",
            overall_drift_score=0.2,
            overall_severity="low",
            signals=[],
            recommendations=["No action required."],
            should_alert=False,
            should_suspend=False,
        )

    def test_timestamp_z_suffix(self):
        report = self._make_report()
        d = report.to_dict()
        assert d["timestamp"].endswith("Z")

    def test_signals_serialized_as_list(self):
        report = self._make_report()
        d = report.to_dict()
        assert isinstance(d["signals"], list)

    def test_all_required_keys_present(self):
        report = self._make_report()
        d = report.to_dict()
        for key in (
            "report_id",
            "agent_id",
            "overall_drift_score",
            "overall_severity",
            "should_alert",
            "should_suspend",
        ):
            assert key in d


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — record_observation
# ---------------------------------------------------------------------------


class TestRecordObservation:
    def test_returns_agent_observation(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=10,
        )
        assert isinstance(obs, AgentObservation)

    def test_observation_id_prefixed(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=10,
        )
        assert obs.observation_id.startswith("obs-")

    def test_agent_id_stored(self, store):
        obs = store.record_observation(
            agent_id="agent-test",
            action_type="file_read",
            target="readme.txt",
            risk_score=10,
        )
        assert obs.agent_id == "agent-test"

    def test_action_type_stored(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="tool_call",
            target="readme.txt",
            risk_score=10,
        )
        assert obs.action_type == "tool_call"

    def test_risk_score_clamped_to_100(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=200,
        )
        assert obs.risk_score == 100

    def test_risk_score_clamped_to_zero(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=-50,
        )
        assert obs.risk_score == 0

    def test_session_id_stored(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=10,
            session_id="sess-xyz",
        )
        assert obs.session_id == "sess-xyz"

    def test_client_id_stored(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=10,
            client_id="client-abc",
        )
        assert obs.client_id == "client-abc"

    def test_matched_patterns_stored(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=10,
            matched_patterns=["pattern-1"],
        )
        assert obs.matched_patterns == ["pattern-1"]

    def test_metadata_stored(self, store):
        obs = store.record_observation(
            agent_id="agent-1",
            action_type="file_read",
            target="readme.txt",
            risk_score=10,
            metadata={"key": "value"},
        )
        assert obs.metadata == {"key": "value"}

    def test_empty_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.record_observation(
                agent_id="",
                action_type="file_read",
                target="readme.txt",
                risk_score=10,
            )

    def test_empty_action_type_raises(self, store):
        with pytest.raises(ValueError):
            store.record_observation(
                agent_id="agent-1",
                action_type="",
                target="readme.txt",
                risk_score=10,
            )

    def test_observations_are_accumulated(self, store):
        for _ in range(5):
            store.record_observation(
                agent_id="agent-1",
                action_type="file_read",
                target="readme.txt",
                risk_score=10,
            )
        obs = store.get_observations("agent-1")
        assert len(obs) == 5

    def test_max_observations_per_agent_enforced(self):
        store = _make_store(max_observations_per_agent=5)
        for i in range(10):
            store.record_observation(
                agent_id="agent-1",
                action_type="file_read",
                target=f"t{i}",
                risk_score=10,
            )
        obs = store.get_observations("agent-1", limit=100)
        assert len(obs) <= 5

    def test_supabase_persist_observation_called(self, store):
        with patch("app.services.behavioral_baseline._supabase_persist_observation") as mock_persist:
            store.record_observation(
                agent_id="agent-1",
                action_type="file_read",
                target="readme.txt",
                risk_score=10,
            )
        mock_persist.assert_called_once()

    def test_supabase_persist_baseline_called_after_enough_observations(self):
        store = _make_store(min_samples_for_baseline=1)
        with patch("app.services.behavioral_baseline._supabase_persist_baseline") as mock_persist:
            store.record_observation(
                agent_id="agent-1",
                action_type="file_read",
                target="readme.txt",
                risk_score=10,
            )
        mock_persist.assert_called()


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — record_observations_bulk
# ---------------------------------------------------------------------------


class TestRecordObservationsBulk:
    def test_returns_list_of_observations(self, store):
        items = [
            {"action_type": "file_read", "target": "t1", "risk_score": 10},
            {"action_type": "tool_call", "target": "t2", "risk_score": 20},
        ]
        result = store.record_observations_bulk("agent-1", items)
        assert len(result) == 2
        assert all(isinstance(o, AgentObservation) for o in result)

    def test_all_observations_stored(self, store):
        items = [{"action_type": "file_read", "target": f"t{i}", "risk_score": i} for i in range(5)]
        store.record_observations_bulk("agent-1", items)
        obs = store.get_observations("agent-1")
        assert len(obs) == 5

    def test_empty_list_returns_empty(self, store):
        result = store.record_observations_bulk("agent-1", [])
        assert result == []

    def test_client_id_propagated(self, store):
        items = [{"action_type": "file_read", "target": "t1", "risk_score": 10}]
        result = store.record_observations_bulk("agent-1", items, client_id="c-bulk")
        assert result[0].client_id == "c-bulk"


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — get_baseline
# ---------------------------------------------------------------------------


class TestGetBaseline:
    def test_returns_none_before_any_observations(self, store):
        assert store.get_baseline("agent-unknown") is None

    def test_returns_baseline_after_observations(self, store):
        _populate_store(store)
        baseline = store.get_baseline("agent-1")
        assert isinstance(baseline, AgentBaseline)

    def test_baseline_agent_id_matches(self, store):
        _populate_store(store)
        baseline = store.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.agent_id == "agent-1"

    def test_empty_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.get_baseline("")

    def test_baseline_status_active_after_min_samples(self):
        store = _make_store(min_samples_for_baseline=3)
        _populate_store(store, n=5)
        baseline = store.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.status == "active"

    def test_baseline_status_learning_before_min_samples(self):
        store = _make_store(min_samples_for_baseline=20)
        _populate_store(store, n=3)
        baseline = store.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.status == "learning"

    def test_schema_version_correct(self, store):
        _populate_store(store)
        baseline = store.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.schema_version == BASELINE_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — list_baselines
# ---------------------------------------------------------------------------


class TestListBaselines:
    def test_empty_store_returns_empty(self, store):
        assert store.list_baselines() == []

    def test_returns_all_baselines(self, store):
        _populate_store(store, agent_id="agent-1")
        _populate_store(store, agent_id="agent-2")
        results = store.list_baselines()
        assert len(results) == 2

    def test_filter_by_client_id(self, store):
        _populate_store(store, agent_id="agent-1", client_id="c-1")
        _populate_store(store, agent_id="agent-2", client_id="c-2")
        results = store.list_baselines(client_id="c-1")
        assert len(results) == 1
        assert results[0].agent_id == "agent-1"

    def test_filter_by_status_active(self, store):
        _populate_store(store, n=10)
        results = store.list_baselines(status="active")
        assert all(b.status == "active" for b in results)

    def test_filter_by_status_returns_empty_when_none_match(self, store):
        _populate_store(store, n=10)
        results = store.list_baselines(status="suspended")
        assert results == []


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — invalidate_baseline
# ---------------------------------------------------------------------------


class TestInvalidateBaseline:
    def test_returns_false_for_unknown_agent(self, store):
        assert store.invalidate_baseline("unknown-agent") is False

    def test_returns_true_after_invalidation(self, store):
        _populate_store(store)
        assert store.invalidate_baseline("agent-1") is True

    def test_status_becomes_stale(self, store):
        _populate_store(store)
        store.invalidate_baseline("agent-1")
        baseline = store.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.status == "stale"

    def test_supabase_persist_baseline_called(self, store):
        _populate_store(store)
        with patch("app.services.behavioral_baseline._supabase_persist_baseline") as mock_persist:
            store.invalidate_baseline("agent-1")
        mock_persist.assert_called_once()

    def test_empty_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.invalidate_baseline("")


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — suspend_baseline
# ---------------------------------------------------------------------------


class TestSuspendBaseline:
    def test_returns_false_for_unknown_agent(self, store):
        assert store.suspend_baseline("unknown-agent") is False

    def test_returns_true_after_suspension(self, store):
        _populate_store(store)
        assert store.suspend_baseline("agent-1") is True

    def test_status_becomes_suspended(self, store):
        _populate_store(store)
        store.suspend_baseline("agent-1")
        baseline = store.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.status == "suspended"

    def test_supabase_persist_baseline_called(self, store):
        _populate_store(store)
        with patch("app.services.behavioral_baseline._supabase_persist_baseline") as mock_persist:
            store.suspend_baseline("agent-1")
        mock_persist.assert_called_once()

    def test_empty_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.suspend_baseline("")


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — get_observations
# ---------------------------------------------------------------------------


class TestGetObservations:
    def test_returns_empty_for_unknown_agent(self, store):
        assert store.get_observations("unknown") == []

    def test_limit_is_respected(self, store):
        _populate_store(store, n=20)
        obs = store.get_observations("agent-1", limit=5)
        assert len(obs) == 5

    def test_returns_most_recent_observations(self, store):
        _populate_store(store, n=10)
        obs = store.get_observations("agent-1", limit=3)
        assert len(obs) == 3

    def test_filter_by_session_id(self, store):
        for i in range(5):
            store.record_observation(
                agent_id="agent-1",
                action_type="file_read",
                target=f"t{i}",
                risk_score=10,
                session_id="sess-A",
            )
        for i in range(3):
            store.record_observation(
                agent_id="agent-1",
                action_type="file_read",
                target=f"t{i}",
                risk_score=10,
                session_id="sess-B",
            )
        obs = store.get_observations("agent-1", session_id="sess-A")
        assert all(o.session_id == "sess-A" for o in obs)

    def test_empty_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.get_observations("")


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — purge_agent
# ---------------------------------------------------------------------------


class TestPurgeAgent:
    def test_returns_false_for_unknown_agent(self, store):
        assert store.purge_agent("unknown-agent") is False

    def test_returns_true_for_known_agent(self, store):
        _populate_store(store)
        assert store.purge_agent("agent-1") is True

    def test_observations_cleared_after_purge(self, store):
        _populate_store(store)
        store.purge_agent("agent-1")
        assert store.get_observations("agent-1") == []

    def test_baseline_cleared_after_purge(self, store):
        _populate_store(store)
        store.purge_agent("agent-1")
        assert store.get_baseline("agent-1") is None

    def test_supabase_delete_agent_called(self, store):
        _populate_store(store)
        with patch("app.services.behavioral_baseline._supabase_delete_agent") as mock_del:
            store.purge_agent("agent-1")
        mock_del.assert_called_once()

    def test_supabase_delete_not_called_for_unknown(self, store):
        with patch("app.services.behavioral_baseline._supabase_delete_agent") as mock_del:
            store.purge_agent("unknown-agent")
        mock_del.assert_not_called()

    def test_empty_agent_id_raises(self, store):
        with pytest.raises(ValueError):
            store.purge_agent("")


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_clears_all_observations(self, store):
        _populate_store(store)
        store.reset()
        assert store.get_observations("agent-1") == []

    def test_clears_all_baselines(self, store):
        _populate_store(store)
        store.reset()
        assert store.get_baseline("agent-1") is None

    def test_list_baselines_empty_after_reset(self, store):
        _populate_store(store, agent_id="agent-1")
        _populate_store(store, agent_id="agent-2")
        store.reset()
        assert store.list_baselines() == []


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — compute_drift (no baseline)
# ---------------------------------------------------------------------------


class TestComputeDriftNoBaseline:
    def test_returns_drift_report(self, store):
        report = store.compute_drift("unknown-agent")
        assert isinstance(report, DriftReport)

    def test_report_id_prefixed(self, store):
        report = store.compute_drift("unknown-agent")
        assert report.report_id.startswith("drift-")

    def test_severity_none_without_baseline(self, store):
        report = store.compute_drift("unknown-agent")
        assert report.overall_severity == "none"

    def test_drift_score_zero_without_baseline(self, store):
        report = store.compute_drift("unknown-agent")
        assert report.overall_drift_score == 0.0

    def test_should_alert_false_without_baseline(self, store):
        report = store.compute_drift("unknown-agent")
        assert report.should_alert is False

    def test_should_suspend_false_without_baseline(self, store):
        report = store.compute_drift("unknown-agent")
        assert report.should_suspend is False

    def test_recommendations_mention_observations_needed(self, store):
        report = store.compute_drift("unknown-agent")
        assert any("observation" in r.lower() for r in report.recommendations)

    def test_baseline_status_learning_without_baseline(self, store):
        report = store.compute_drift("unknown-agent")
        assert report.baseline_status == "learning"

    def test_supabase_persist_drift_report_called(self, store):
        with patch("app.services.behavioral_baseline._supabase_persist_drift_report") as mock_persist:
            store.compute_drift("unknown-agent")
        mock_persist.assert_called_once()


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — compute_drift (suspended baseline)
# ---------------------------------------------------------------------------


class TestComputeDriftSuspended:
    def test_suspended_returns_critical_severity(self, store):
        _populate_store(store)
        store.suspend_baseline("agent-1")
        report = store.compute_drift("agent-1")
        assert report.overall_severity == "critical"

    def test_suspended_drift_score_is_one(self, store):
        _populate_store(store)
        store.suspend_baseline("agent-1")
        report = store.compute_drift("agent-1")
        assert report.overall_drift_score == pytest.approx(1.0)

    def test_suspended_should_alert_true(self, store):
        _populate_store(store)
        store.suspend_baseline("agent-1")
        report = store.compute_drift("agent-1")
        assert report.should_alert is True

    def test_suspended_should_suspend_true(self, store):
        _populate_store(store)
        store.suspend_baseline("agent-1")
        report = store.compute_drift("agent-1")
        assert report.should_suspend is True

    def test_suspended_recommendations_mention_review(self, store):
        _populate_store(store)
        store.suspend_baseline("agent-1")
        report = store.compute_drift("agent-1")
        assert any("review" in r.lower() for r in report.recommendations)


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — compute_drift (active baseline, no anomaly)
# ---------------------------------------------------------------------------


class TestComputeDriftActive:
    def test_returns_drift_report_type(self, store):
        _populate_store(store, n=20, risk_score=10)
        report = store.compute_drift("agent-1")
        assert isinstance(report, DriftReport)

    def test_active_baseline_status_in_report(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1")
        assert report.baseline_status in ("active", "learning")

    def test_custom_window_seconds_respected(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1", window_seconds=60)
        assert report.window_seconds == 60

    def test_default_window_seconds_used_when_none(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1")
        assert report.window_seconds == DRIFT_WINDOW_SECONDS

    def test_session_id_propagated_to_report(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1", session_id="sess-xyz")
        assert report.session_id == "sess-xyz"

    def test_client_id_propagated_to_report(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1", client_id="c-xyz")
        assert report.client_id == "c-xyz"

    def test_agent_id_in_report(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1")
        assert report.agent_id == "agent-1"

    def test_recommendations_non_empty(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1")
        assert len(report.recommendations) > 0

    def test_signals_is_list(self, store):
        _populate_store(store, n=20)
        report = store.compute_drift("agent-1")
        assert isinstance(report.signals, list)

    def test_supabase_persist_drift_report_called(self, store):
        _populate_store(store, n=20)
        with patch("app.services.behavioral_baseline._supabase_persist_drift_report") as mock_persist:
            store.compute_drift("agent-1")
        mock_persist.assert_called_once()


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — compute_drift triggers suspend on critical
# ---------------------------------------------------------------------------


class TestComputeDriftAutoSuspend:
    def test_critical_drift_suspends_baseline(self, store):
        _populate_store(store, n=20, action_type="file_read", risk_score=5)
        for _ in range(20):
            store.record_observation(
                agent_id="agent-1",
                action_type="tool_call",
                target="exfil-target",
                risk_score=100,
            )
        report = store.compute_drift("agent-1", window_seconds=10)
        if report.should_suspend:
            baseline = store.get_baseline("agent-1")
            assert baseline is not None
            assert baseline.status == "suspended"

    def test_critical_drift_emits_telemetry(self, store):
        _populate_store(store, n=20, action_type="file_read", risk_score=5)
        with patch("app.services.behavioral_baseline._emit_telemetry") as mock_telemetry:
            for _ in range(20):
                store.record_observation(
                    agent_id="agent-1",
                    action_type="tool_call",
                    target="exfil",
                    risk_score=100,
                )
            store.compute_drift("agent-1")
        if mock_telemetry.called:
            call_args = mock_telemetry.call_args[0]
            assert call_args[0] == "behavioral_drift_detected"


# ---------------------------------------------------------------------------
# BehavioralBaselineStore — recompute baseline (suspended agent not updated)
# ---------------------------------------------------------------------------


class TestRecomputeBaselineSuspended:
    def test_suspended_agent_baseline_not_updated(self, store):
        _populate_store(store, n=20)
        store.suspend_baseline("agent-1")
        baseline_before = store.get_baseline("agent-1")
        assert baseline_before is not None
        sample_count_before = baseline_before.sample_count

        for _ in range(20):
            store.record_observation(
                agent_id="agent-1",
                action_type="file_read",
                target="target",
                risk_score=10,
            )

        baseline_after = store.get_baseline("agent-1")
        assert baseline_after is not None
        assert baseline_after.sample_count == sample_count_before


# ---------------------------------------------------------------------------
# Module-level singleton — get_behavioral_baseline_store
# ---------------------------------------------------------------------------


class TestGetBehavioralBaselineStore:
    def test_returns_behavioral_baseline_store_instance(self):
        store = get_behavioral_baseline_store()
        assert isinstance(store, BehavioralBaselineStore)

    def test_returns_same_instance_on_repeated_calls(self):
        s1 = get_behavioral_baseline_store()
        s2 = get_behavioral_baseline_store()
        assert s1 is s2

    def test_reset_clears_data(self):
        store = get_behavioral_baseline_store()
        store.record_observation(
            agent_id="agent-singleton",
            action_type="file_read",
            target="readme.txt",
            risk_score=5,
        )
        reset_behavioral_baseline_store()
        assert store.get_observations("agent-singleton") == []

    def test_store_is_independent_from_test_fixture(self):
        singleton = get_behavioral_baseline_store()
        fixture_store = _make_store()
        _populate_store(fixture_store, agent_id="agent-fixture")
        assert singleton.get_baseline("agent-fixture") is None


# ---------------------------------------------------------------------------
# Supabase persistence helpers — fail silently
# ---------------------------------------------------------------------------


class TestSupabasePersistenceFailSilently:
    def test_persist_observation_does_not_raise_on_adapter_unavailable(self):
        with patch(
            "app.services.behavioral_baseline._supabase_persist_observation",
            side_effect=Exception("db down"),
        ):
            store = _make_store()
            try:
                store.record_observation(
                    agent_id="agent-1",
                    action_type="file_read",
                    target="readme.txt",
                    risk_score=10,
                )
            except Exception as exc:
                pytest.fail(f"record_observation raised unexpectedly: {exc}")

    def test_compute_drift_does_not_raise_on_persist_failure(self, store):
        _populate_store(store, n=10)
        with patch(
            "app.services.behavioral_baseline._supabase_persist_drift_report",
            side_effect=Exception("db down"),
        ):
            try:
                store.compute_drift("agent-1")
            except Exception as exc:
                pytest.fail(f"compute_drift raised unexpectedly: {exc}")
