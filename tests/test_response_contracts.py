from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _assert_has_keys(payload: dict, required_keys: set[str]) -> None:
    missing = required_keys - set(payload.keys())
    assert not missing, f"Missing keys: {sorted(missing)} in payload: {payload}"


def test_root_contract():
    response = client.get("/")
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, dict)
    assert body, "Root response should not be empty"


def test_health_contract():
    response = client.get("/health")
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"status"})


def test_policy_status_contract():
    response = client.get("/policy/status")
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, dict)
    assert body, "Policy status response should not be empty"


def test_guard_reviews_summary_contract():
    response = client.get("/guard/reviews/summary")
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, dict)
    assert body, "Summary response should not be empty"


def test_pending_reviews_contract():
    response = client.get("/guard/reviews/pending")
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, list)


def test_history_events_contract():
    response = client.get("/history/events")
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, list)


def test_guard_audit_events_contract():
    response = client.get("/guard/audit/events")
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, list)
