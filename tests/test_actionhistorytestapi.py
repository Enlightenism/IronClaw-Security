from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_actionhistorytest_endpoint_returns_success_payload() -> None:
    response = client.get("/api/actionhistorytest")

    assert response.status_code == 200

    data = response.json()
    assert data["title"] == "Action History Test"
    assert data["total"] == 3
    assert "summary" in data
    assert "selected" in data
    assert "checks" in data
    assert "metadata" in data
    assert "actions_loaded" in data["checks"]
    assert "selection_defaulted" in data["checks"]
    assert "selection_resolved" in data["checks"]
    assert data["metadata"]["requested_by"] == "tester"


def test_actionhistorytest_endpoint_honors_selected_actionid() -> None:
    response = client.get(
        "/api/actionhistorytest",
        params={"selected_actionid": "act-1002"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["title"] == "Action History Test"
    assert data["total"] == 3
    assert "selection_requested" in data["checks"]
    assert "selection_resolved" in data["checks"]
    assert data["selected"] is not None


def test_actionhistorytest_endpoint_matches_executionid_selection() -> None:
    response = client.get(
        "/api/actionhistorytest",
        params={"selected_actionid": "exec-1003"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["total"] == 3
    assert "selection_requested" in data["checks"]
    assert "selection_resolved" in data["checks"]
    assert data["selected"] is not None


def test_actionhistorytest_endpoint_accepts_requested_by_override() -> None:
    response = client.get(
        "/api/actionhistorytest",
        params={"requested_by": "integration-test"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["metadata"]["requested_by"] == "integration-test"
    assert data["title"] == "Action History Test"
    assert data["total"] == 3
