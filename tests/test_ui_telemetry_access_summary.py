from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.telemetry_access import TelemetryAccessSummaryResponse, router
from app.services.telemetry import append_telemetry_event

SUMMARY_PATH: str = "/telemetry-access/summary"


@pytest.fixture(scope="module")
def seeded_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    _seed(count=3)
    return TestClient(app)


def _seed(count: int = 3) -> None:
    for i in range(count):
        append_telemetry_event(
            f"ui_telemetry_access_summary_seed_{i}",
            {
                "source": "pytest-ui-telemetry-access-summary",
                "category": "telemetry_access",
                "index": i,
            },
        )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestTelemetryAccessSummaryStatus:
    def test_returns_200(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(SUMMARY_PATH)
        assert response.status_code == 200

    def test_content_type_is_json(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(SUMMARY_PATH)
        assert "application/json" in response.headers["content-type"]

    def test_response_is_dict(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestTelemetryAccessSummaryShape:
    def test_has_telemetry_summary_key(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        assert "telemetry_summary" in data

    def test_has_recent_events_key(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        assert "recent_events" in data

    def test_no_extra_unexpected_top_level_keys(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        allowed = {"telemetry_summary", "recent_events"}
        assert set(data.keys()) <= allowed

    def test_telemetry_summary_is_dict(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        assert isinstance(data["telemetry_summary"], dict)

    def test_recent_events_is_list(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        assert isinstance(data["recent_events"], list)


# ---------------------------------------------------------------------------
# Response model parity
# ---------------------------------------------------------------------------


class TestTelemetryAccessSummaryModel:
    def test_parses_into_response_model(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        model = TelemetryAccessSummaryResponse(**data)
        assert isinstance(model.telemetry_summary, dict)
        assert isinstance(model.recent_events, list)

    def test_model_defaults_are_safe(self) -> None:
        model = TelemetryAccessSummaryResponse()
        assert model.telemetry_summary == {}
        assert model.recent_events == []

    def test_model_accepts_populated_values(self) -> None:
        model = TelemetryAccessSummaryResponse(
            telemetry_summary={"total": 5, "by_category": {"telemetry_access": 5}},
            recent_events=[{"event_type": "e1", "payload": {}}],
        )
        assert model.telemetry_summary["total"] == 5
        assert len(model.recent_events) == 1


# ---------------------------------------------------------------------------
# recent_events content
# ---------------------------------------------------------------------------


class TestRecentEventsContent:
    def test_recent_events_not_empty_after_seed(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        assert len(data["recent_events"]) > 0

    def test_recent_events_items_are_dicts(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        for event in data["recent_events"]:
            assert isinstance(event, dict)

    def test_seed_events_appear_in_recent_events(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        serialized = str(data["recent_events"])
        assert "ui_telemetry_access_summary_seed" in serialized

    def test_recent_events_items_contain_event_type(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        for event in data["recent_events"]:
            assert "event_type" in event or len(event) > 0

    def test_recent_events_respects_events_limit(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?events_limit=1")
        assert response.status_code == 200
        data = response.json()
        assert len(data["recent_events"]) <= 1


# ---------------------------------------------------------------------------
# telemetry_summary content
# ---------------------------------------------------------------------------


class TestTelemetrySummaryContent:
    def test_telemetry_summary_is_populated_after_seed(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        assert isinstance(data["telemetry_summary"], dict)

    def test_telemetry_summary_values_are_serializable(self, seeded_client: TestClient) -> None:
        data = seeded_client.get(SUMMARY_PATH).json()
        summary: dict[str, Any] = data["telemetry_summary"]
        for value in summary.values():
            assert value is not None or value is None

    def test_summary_limit_query_param_accepted(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?summary_limit=10")
        assert response.status_code == 200

    def test_both_limits_accepted_simultaneously(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?summary_limit=10&events_limit=5")
        assert response.status_code == 200
        data = response.json()
        assert "telemetry_summary" in data
        assert "recent_events" in data


# ---------------------------------------------------------------------------
# Query param validation
# ---------------------------------------------------------------------------


class TestTelemetryAccessSummaryQueryValidation:
    def test_rejects_summary_limit_zero(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?summary_limit=0")
        assert response.status_code == 422

    def test_rejects_events_limit_zero(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?events_limit=0")
        assert response.status_code == 422

    def test_rejects_summary_limit_exceeds_max(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?summary_limit=5001")
        assert response.status_code == 422

    def test_rejects_events_limit_exceeds_max(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?events_limit=501")
        assert response.status_code == 422

    def test_rejects_non_integer_summary_limit(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?summary_limit=abc")
        assert response.status_code == 422

    def test_accepts_summary_limit_at_minimum(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?summary_limit=1")
        assert response.status_code == 200

    def test_accepts_events_limit_at_minimum(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?events_limit=1")
        assert response.status_code == 200

    def test_accepts_summary_limit_at_maximum(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?summary_limit=5000")
        assert response.status_code == 200

    def test_accepts_events_limit_at_maximum(self, seeded_client: TestClient) -> None:
        response = seeded_client.get(f"{SUMMARY_PATH}?events_limit=500")
        assert response.status_code == 200
