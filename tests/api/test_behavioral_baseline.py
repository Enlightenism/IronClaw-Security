from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.services.behavioral_baseline import (
    MIN_SAMPLES_FOR_BASELINE,
    reset_behavioral_baseline_store,
)

BASE = "/behavioral"
_API_KEY_HEADERS = {"X-API-Key": "test-api-key"}


@pytest.fixture(autouse=True)
def clean_store():
    reset_behavioral_baseline_store()
    yield
    reset_behavioral_baseline_store()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _record(client, agent_id: str, action_type: str = "file_read", target: str = "main.py", risk_score: int = 10, **kwargs):
    payload = {"action_type": action_type, "target": target, "risk_score": risk_score, **kwargs}
    return client.post(f"{BASE}/agents/{agent_id}/observations", json=payload, headers=_API_KEY_HEADERS)


def _fill(client, agent_id: str, count: int = MIN_SAMPLES_FOR_BASELINE, action_type: str = "file_read", risk_score: int = 10):
    for _ in range(count):
        _record(client, agent_id, action_type=action_type, risk_score=risk_score)


# ---------------------------------------------------------------------------
# POST /behavioral/agents/{agent_id}/observations
# ---------------------------------------------------------------------------


class TestRecordObservationEndpoint:
    def test_201_on_valid_observation(self, client):
        r = _record(client, "ag-1")
        assert r.status_code == 201

    def test_response_shape(self, client):
        r = _record(client, "ag-1")
        body = r.json()
        for key in ("observation_id", "agent_id", "timestamp", "action_type", "target", "risk_score", "matched_patterns", "metadata"):
            assert key in body

    def test_agent_id_in_response(self, client):
        r = _record(client, "ag-42")
        assert r.json()["agent_id"] == "ag-42"

    def test_action_type_in_response(self, client):
        r = _record(client, "ag-1", action_type="tool_call")
        assert r.json()["action_type"] == "tool_call"

    def test_risk_score_in_response(self, client):
        r = _record(client, "ag-1", risk_score=55)
        assert r.json()["risk_score"] == 55

    def test_empty_action_type_returns_422(self, client):
        r = client.post(f"{BASE}/agents/ag-1/observations", json={"action_type": "", "target": "f", "risk_score": 5}, headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_whitespace_action_type_returns_422(self, client):
        r = client.post(f"{BASE}/agents/ag-1/observations", json={"action_type": "   ", "target": "f", "risk_score": 5}, headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_risk_score_below_range_returns_422(self, client):
        r = client.post(f"{BASE}/agents/ag-1/observations", json={"action_type": "read", "target": "f", "risk_score": -1}, headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_risk_score_above_range_returns_422(self, client):
        r = client.post(f"{BASE}/agents/ag-1/observations", json={"action_type": "read", "target": "f", "risk_score": 101}, headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_optional_session_id_stored(self, client):
        r = _record(client, "ag-1", session_id="sess-99")
        assert r.json()["session_id"] == "sess-99"

    def test_optional_client_id_stored(self, client):
        r = _record(client, "ag-1", client_id="client-abc")
        assert r.json()["client_id"] == "client-abc"

    def test_matched_patterns_stored(self, client):
        r = _record(client, "ag-1", matched_patterns=["pat-a", "pat-b"])
        assert "pat-a" in r.json()["matched_patterns"]

    def test_metadata_stored(self, client):
        r = _record(client, "ag-1", metadata={"env": "prod"})
        assert r.json()["metadata"]["env"] == "prod"


# ---------------------------------------------------------------------------
# POST /behavioral/agents/{agent_id}/observations/bulk
# ---------------------------------------------------------------------------


class TestBulkObservationEndpoint:
    def test_201_on_valid_bulk(self, client):
        payload = {
            "observations": [
                {"action_type": "file_read", "target": "a.py", "risk_score": 10},
                {"action_type": "tool_call", "target": "b.py", "risk_score": 20},
            ]
        }
        r = client.post(f"{BASE}/agents/ag-1/observations/bulk", json=payload, headers=_API_KEY_HEADERS)
        assert r.status_code == 201

    def test_ingested_count_matches(self, client):
        payload = {
            "observations": [
                {"action_type": "file_read", "target": "a.py", "risk_score": 10},
                {"action_type": "tool_call", "target": "b.py", "risk_score": 20},
            ]
        }
        r = client.post(f"{BASE}/agents/ag-1/observations/bulk", json=payload, headers=_API_KEY_HEADERS)
        assert r.json()["ingested"] == 2

    def test_response_shape(self, client):
        payload = {"observations": [{"action_type": "read", "target": "f", "risk_score": 5}]}
        r = client.post(f"{BASE}/agents/ag-1/observations/bulk", json=payload, headers=_API_KEY_HEADERS)
        body = r.json()
        assert "agent_id" in body
        assert "ingested" in body
        assert "observations" in body

    def test_empty_observations_returns_422(self, client):
        r = client.post(f"{BASE}/agents/ag-1/observations/bulk", json={"observations": []}, headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_client_id_applied_to_all(self, client):
        payload = {
            "observations": [{"action_type": "read", "target": "f", "risk_score": 5}],
            "client_id": "c-bulk",
        }
        r = client.post(f"{BASE}/agents/ag-1/observations/bulk", json=payload, headers=_API_KEY_HEADERS)
        assert r.json()["observations"][0]["client_id"] == "c-bulk"


# ---------------------------------------------------------------------------
# GET /behavioral/agents/{agent_id}/baseline
# ---------------------------------------------------------------------------


class TestGetBaselineEndpoint:
    def test_404_before_any_observations(self, client):
        r = client.get(f"{BASE}/agents/unknown-agent/baseline", headers=_API_KEY_HEADERS)
        assert r.status_code == 404

    def test_200_after_observations(self, client):
        _record(client, "ag-1")
        r = client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS)
        assert r.status_code == 200

    def test_response_shape(self, client):
        _record(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).json()
        for key in (
            "baseline_id",
            "agent_id",
            "status",
            "sample_count",
            "created_at",
            "updated_at",
            "mean_action_rate",
            "action_type_distribution",
            "schema_version",
        ):
            assert key in body

    def test_status_learning_below_min_samples(self, client):
        _record(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).json()
        assert body["status"] == "learning"

    def test_status_active_at_min_samples(self, client):
        _fill(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).json()
        assert body["status"] == "active"

    def test_sample_count_matches(self, client):
        for _ in range(3):
            _record(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).json()
        assert body["sample_count"] == 3


# ---------------------------------------------------------------------------
# GET /behavioral/agents/{agent_id}/drift
# ---------------------------------------------------------------------------


class TestComputeDriftEndpoint:
    def test_200_no_baseline(self, client):
        r = client.get(f"{BASE}/agents/brand-new/drift", headers=_API_KEY_HEADERS)
        assert r.status_code == 200

    def test_no_baseline_severity_none(self, client):
        body = client.get(f"{BASE}/agents/brand-new/drift", headers=_API_KEY_HEADERS).json()
        assert body["overall_severity"] == "none"

    def test_200_with_baseline(self, client):
        _fill(client, "ag-1")
        r = client.get(f"{BASE}/agents/ag-1/drift", headers=_API_KEY_HEADERS)
        assert r.status_code == 200

    def test_response_shape(self, client):
        _fill(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/drift", headers=_API_KEY_HEADERS).json()
        for key in (
            "report_id",
            "agent_id",
            "timestamp",
            "overall_drift_score",
            "overall_severity",
            "signals",
            "recommendations",
            "should_alert",
            "should_suspend",
        ):
            assert key in body

    def test_window_seconds_query_param(self, client):
        _fill(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/drift?window_seconds=120", headers=_API_KEY_HEADERS).json()
        assert body["window_seconds"] == 120

    def test_window_below_minimum_returns_422(self, client):
        r = client.get(f"{BASE}/agents/ag-1/drift?window_seconds=10", headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_window_above_maximum_returns_422(self, client):
        r = client.get(f"{BASE}/agents/ag-1/drift?window_seconds=999999", headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_session_id_propagated(self, client):
        _fill(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/drift?session_id=sess-77", headers=_API_KEY_HEADERS).json()
        assert body["session_id"] == "sess-77"

    def test_client_id_propagated(self, client):
        _fill(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/drift?client_id=c-99", headers=_API_KEY_HEADERS).json()
        assert body["client_id"] == "c-99"

    def test_suspended_returns_critical(self, client):
        _fill(client, "ag-1")
        client.post(f"{BASE}/agents/ag-1/baseline/suspend", headers=_API_KEY_HEADERS)
        body = client.get(f"{BASE}/agents/ag-1/drift", headers=_API_KEY_HEADERS).json()
        assert body["overall_severity"] == "critical"
        assert body["should_alert"] is True
        assert body["should_suspend"] is True

    def test_drift_score_bounded(self, client):
        _fill(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/drift", headers=_API_KEY_HEADERS).json()
        assert 0.0 <= body["overall_drift_score"] <= 1.0


# ---------------------------------------------------------------------------
# GET /behavioral/agents/{agent_id}/observations
# ---------------------------------------------------------------------------


class TestGetObservationsEndpoint:
    def test_200_unknown_agent_returns_empty(self, client):
        r = client.get(f"{BASE}/agents/ghost/observations", headers=_API_KEY_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["observations"] == []

    def test_returns_all_observations(self, client):
        for _ in range(5):
            _record(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/observations", headers=_API_KEY_HEADERS).json()
        assert body["total"] == 5

    def test_limit_query_param(self, client):
        for _ in range(20):
            _record(client, "ag-1")
        body = client.get(f"{BASE}/agents/ag-1/observations?limit=5", headers=_API_KEY_HEADERS).json()
        assert body["total"] == 5

    def test_session_id_filter(self, client):
        _record(client, "ag-1", session_id="s1")
        _record(client, "ag-1", session_id="s2")
        _record(client, "ag-1", session_id="s1")
        body = client.get(f"{BASE}/agents/ag-1/observations?session_id=s1", headers=_API_KEY_HEADERS).json()
        assert body["total"] == 2
        assert all(o["session_id"] == "s1" for o in body["observations"])

    def test_limit_below_minimum_returns_422(self, client):
        r = client.get(f"{BASE}/agents/ag-1/observations?limit=0", headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_limit_above_maximum_returns_422(self, client):
        r = client.get(f"{BASE}/agents/ag-1/observations?limit=9999", headers=_API_KEY_HEADERS)
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# DELETE /behavioral/agents/{agent_id}/baseline
# ---------------------------------------------------------------------------


class TestDeleteBaselineEndpoint:
    def test_404_no_baseline_invalidate(self, client):
        r = client.delete(f"{BASE}/agents/ghost/baseline", headers=_API_KEY_HEADERS)
        assert r.status_code == 404

    def test_404_no_baseline_purge(self, client):
        r = client.delete(f"{BASE}/agents/ghost/baseline?purge=true", headers=_API_KEY_HEADERS)
        assert r.status_code == 404

    def test_invalidate_sets_stale(self, client):
        _record(client, "ag-1")
        client.delete(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS)
        body = client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).json()
        assert body["status"] == "stale"

    def test_purge_removes_baseline(self, client):
        _fill(client, "ag-1")
        r = client.delete(f"{BASE}/agents/ag-1/baseline?purge=true", headers=_API_KEY_HEADERS)
        assert r.status_code == 200
        assert client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).status_code == 404

    def test_response_shape(self, client):
        _record(client, "ag-1")
        body = client.delete(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).json()
        assert "agent_id" in body
        assert "success" in body
        assert "detail" in body
        assert body["success"] is True


# ---------------------------------------------------------------------------
# POST /behavioral/agents/{agent_id}/baseline/suspend
# ---------------------------------------------------------------------------


class TestSuspendBaselineEndpoint:
    def test_404_no_baseline(self, client):
        r = client.post(f"{BASE}/agents/ghost/baseline/suspend", headers=_API_KEY_HEADERS)
        assert r.status_code == 404

    def test_200_on_existing_baseline(self, client):
        _record(client, "ag-1")
        r = client.post(f"{BASE}/agents/ag-1/baseline/suspend", headers=_API_KEY_HEADERS)
        assert r.status_code == 200

    def test_status_becomes_suspended(self, client):
        _record(client, "ag-1")
        client.post(f"{BASE}/agents/ag-1/baseline/suspend", headers=_API_KEY_HEADERS)
        body = client.get(f"{BASE}/agents/ag-1/baseline", headers=_API_KEY_HEADERS).json()
        assert body["status"] == "suspended"

    def test_response_shape(self, client):
        _record(client, "ag-1")
        body = client.post(f"{BASE}/agents/ag-1/baseline/suspend", headers=_API_KEY_HEADERS).json()
        assert body["success"] is True
        assert body["agent_id"] == "ag-1"


# ---------------------------------------------------------------------------
# GET /behavioral/baselines
# ---------------------------------------------------------------------------


class TestListBaselinesEndpoint:
    def test_200_empty_store(self, client):
        r = client.get(f"{BASE}/baselines", headers=_API_KEY_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["baselines"] == []

    def test_total_matches_agents(self, client):
        for agent in ("ag-1", "ag-2", "ag-3"):
            _record(client, agent)
        body = client.get(f"{BASE}/baselines", headers=_API_KEY_HEADERS).json()
        assert body["total"] == 3

    def test_filter_by_client_id(self, client):
        _record(client, "ag-1", client_id="c1")
        _record(client, "ag-2", client_id="c2")
        body = client.get(f"{BASE}/baselines?client_id=c1", headers=_API_KEY_HEADERS).json()
        assert body["total"] == 1
        assert body["baselines"][0]["agent_id"] == "ag-1"

    def test_filter_by_status_suspended(self, client):
        _record(client, "ag-1")
        _record(client, "ag-2")
        client.post(f"{BASE}/agents/ag-1/baseline/suspend", headers=_API_KEY_HEADERS)
        body = client.get(f"{BASE}/baselines?status=suspended", headers=_API_KEY_HEADERS).json()
        assert body["total"] == 1
        assert body["baselines"][0]["agent_id"] == "ag-1"

    def test_invalid_status_returns_422(self, client):
        r = client.get(f"{BASE}/baselines?status=badvalue", headers=_API_KEY_HEADERS)
        assert r.status_code == 422

    def test_response_shape(self, client):
        _record(client, "ag-1")
        body = client.get(f"{BASE}/baselines", headers=_API_KEY_HEADERS).json()
        assert "total" in body
        assert "baselines" in body
        assert isinstance(body["baselines"], list)
