from __future__ import annotations

from fastapi.testclient import TestClient
import pytest


def _base_payload(risk_score: int) -> dict:
    return {
        "action_type": "httpfetch",
        "target": "https://example.com",
        "content": f"Boundary test for risk score {risk_score}",
        "risk_score": risk_score,
        "client_id": f"boundary-client-{risk_score}",
        "session_id": f"boundary-session-{risk_score}",
    }


@pytest.mark.parametrize(
    "risk_score, expected_response_status",
    [
        pytest.param(0, "completed", id="risk-0-safe"),
        pytest.param(4, "completed", id="risk-4-safe-upper"),
        pytest.param(5, "completed", id="risk-5-lower-mid"),
        pytest.param(94, "denied", id="risk-94-denied-upper"),
        pytest.param(95, "denied", id="risk-95-denied-lower"),
    ],
)
def test_guard_execute_boundary_response_statuses(
    test_client: TestClient,
    risk_score: int,
    expected_response_status: str,
):
    response = test_client.post("/guard/execute", json=_base_payload(risk_score))
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, dict)

    assert body["response_status"] == expected_response_status
    assert "execution_state" in body
    assert "executor_name" in body
    assert "executor_result" in body


@pytest.mark.parametrize(
    "risk_score, should_execute, halted_by_boundary",
    [
        pytest.param(0, True, False, id="risk-0"),
        pytest.param(4, True, False, id="risk-4"),
        pytest.param(5, True, False, id="risk-5"),
        pytest.param(94, False, True, id="risk-94"),
        pytest.param(95, False, True, id="risk-95"),
    ],
)
def test_guard_execute_boundary_flags_on_root(
    test_client: TestClient,
    risk_score: int,
    should_execute: bool,
    halted_by_boundary: bool,
):
    response = test_client.post("/guard/execute", json=_base_payload(risk_score))
    assert response.status_code == 200

    body = response.json()

    assert body["should_execute"] is should_execute
    assert body["halted_by_boundary"] is halted_by_boundary


@pytest.mark.parametrize(
    "risk_score, expected_execution_state",
    [
        pytest.param(0, "executed", id="risk-0-executed"),
        pytest.param(4, "executed", id="risk-4-executed"),
        pytest.param(5, "executed", id="risk-5-executed"),
        pytest.param(94, "denied", id="risk-94-denied"),
        pytest.param(95, "denied", id="risk-95-denied"),
    ],
)
def test_guard_execute_boundary_execution_state_on_root(
    test_client: TestClient,
    risk_score: int,
    expected_execution_state: str,
):
    response = test_client.post("/guard/execute", json=_base_payload(risk_score))
    assert response.status_code == 200

    body = response.json()
    assert body["execution_state"] == expected_execution_state


@pytest.mark.parametrize("risk_score", [0, 4, 5, 94, 95])
def test_guard_execute_boundary_preserves_executor_result_shape_on_root(
    test_client: TestClient,
    risk_score: int,
):
    response = test_client.post("/guard/execute", json=_base_payload(risk_score))
    assert response.status_code == 200

    body = response.json()

    assert "executor_result" in body
    if body["executor_result"] is not None:
        assert isinstance(body["executor_result"], dict)
        assert "file_path" in body["executor_result"]
