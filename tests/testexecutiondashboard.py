from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.ui.executions.dashboard import (
    _normalize_policyverdict as normalize_dashboard_policyverdict,
)
from app.ui.executions.detail import (
    _normalize_policyverdict as normalize_detail_policyverdict,
)

client = TestClient(app)


def test_execution_dashboard_route_is_registered() -> None:
    response = client.get("/executions/dashboard")
    assert response.status_code == 200


def test_execution_dashboard_returns_json_object() -> None:
    response = client.get("/executions/dashboard")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_execution_dashboard_contains_basic_dashboard_shape() -> None:
    response = client.get("/executions/dashboard")

    assert response.status_code == 200

    data = response.json()
    assert data
    assert any(
        key in data
        for key in (
            "title",
            "summary",
            "items",
            "executions",
            "status",
        )
    )


def test_missing_execution_verdict_defaults_to_block_for_review_states() -> None:
    for normalize_policyverdict in (
        normalize_dashboard_policyverdict,
        normalize_detail_policyverdict,
    ):
        assert normalize_policyverdict({}, "quarantined") == "block"
        assert normalize_policyverdict({}, "queuedforreview") == "block"
        assert normalize_policyverdict({}, "review") == "block"
        assert (
            normalize_policyverdict(
                {"policyverdict": "quarantine"},
                "quarantined",
            )
            == "quarantine"
        )
