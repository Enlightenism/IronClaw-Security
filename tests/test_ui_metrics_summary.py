from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROUTE = "/metrics-summary"

_REQUIRED_TOP_KEYS = {
    "status",
    "service",
    "timestamp",
    "window",
    "kpis",
    "services",
    "links",
    "notes",
}

_REQUIRED_WINDOW_KEYS = {
    "lookback_minutes",
    "environment",
    "aggregation_mode",
    "metadata",
}

_REQUIRED_KPI_KEYS = {"label", "value", "unit", "trend", "metadata"}

_REQUIRED_SERVICE_KEYS = {
    "service_name",
    "status",
    "request_rate",
    "error_rate",
    "p95_latency_ms",
    "metadata",
}

_REQUIRED_LINK_KEYS = {"label", "path", "description"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fetch(test_client: TestClient) -> dict[str, Any]:
    response = test_client.get(_ROUTE)
    assert response.status_code == 200, response.text
    data = response.json()
    assert isinstance(data, dict)
    return data


# ---------------------------------------------------------------------------
# 200 + content-type
# ---------------------------------------------------------------------------


def test_metrics_summary_returns_200(test_client: TestClient) -> None:
    response = test_client.get(_ROUTE)
    assert response.status_code == 200


def test_metrics_summary_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(_ROUTE)
    assert "application/json" in response.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


def test_metrics_summary_top_level_shape(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert _REQUIRED_TOP_KEYS.issubset(data.keys())


def test_metrics_summary_root_is_object_not_array(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data, dict)


def test_metrics_summary_status_is_ok(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert data["status"] == "ok"


def test_metrics_summary_service_is_ironclaw(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert data["service"] == "IronClaw-Security"


def test_metrics_summary_timestamp_is_utc_string(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["timestamp"], str)
    assert data["timestamp"].endswith("Z")


# ---------------------------------------------------------------------------
# Window
# ---------------------------------------------------------------------------


def test_metrics_summary_window_shape(test_client: TestClient) -> None:
    data = _fetch(test_client)
    window = data["window"]
    assert isinstance(window, dict)
    assert _REQUIRED_WINDOW_KEYS.issubset(window.keys())


def test_metrics_summary_window_lookback_minutes_is_int(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    assert isinstance(data["window"]["lookback_minutes"], int)
    assert data["window"]["lookback_minutes"] >= 1


def test_metrics_summary_window_environment_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    assert isinstance(data["window"]["environment"], str)
    assert len(data["window"]["environment"]) > 0


def test_metrics_summary_window_aggregation_mode_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    assert isinstance(data["window"]["aggregation_mode"], str)
    assert len(data["window"]["aggregation_mode"]) > 0


def test_metrics_summary_window_metadata_is_dict(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["window"]["metadata"], dict)


def test_metrics_summary_default_lookback_is_60(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert data["window"]["lookback_minutes"] == 60


def test_metrics_summary_custom_lookback_param_respected(
    test_client: TestClient,
) -> None:
    response = test_client.get(_ROUTE, params={"lookback_minutes": 30})
    assert response.status_code == 200
    data = response.json()
    assert data["window"]["lookback_minutes"] == 30


# ---------------------------------------------------------------------------
# KPIs
# ---------------------------------------------------------------------------


def test_metrics_summary_kpis_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["kpis"], list)


def test_metrics_summary_kpis_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["kpis"]) > 0


def test_metrics_summary_kpi_entries_have_required_fields(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["kpis"]:
        assert _REQUIRED_KPI_KEYS.issubset(entry.keys()), f"KPI missing keys: {entry}"


def test_metrics_summary_kpi_label_is_nonempty_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["kpis"]:
        assert isinstance(entry["label"], str)
        assert len(entry["label"]) > 0


def test_metrics_summary_kpi_value_is_number(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["kpis"]:
        assert isinstance(entry["value"], (int, float))


def test_metrics_summary_kpi_unit_is_string(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["kpis"]:
        assert isinstance(entry["unit"], str)
        assert len(entry["unit"]) > 0


def test_metrics_summary_kpi_trend_is_string(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["kpis"]:
        assert isinstance(entry["trend"], str)


def test_metrics_summary_kpi_metadata_is_dict(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["kpis"]:
        assert isinstance(entry["metadata"], dict)


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def test_metrics_summary_services_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["services"], list)


def test_metrics_summary_services_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["services"]) > 0


def test_metrics_summary_service_entries_have_required_fields(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["services"]:
        assert _REQUIRED_SERVICE_KEYS.issubset(entry.keys()), f"Service missing keys: {entry}"


def test_metrics_summary_service_name_is_nonempty_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["services"]:
        assert isinstance(entry["service_name"], str)
        assert len(entry["service_name"]) > 0


def test_metrics_summary_service_status_is_string(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["services"]:
        assert isinstance(entry["status"], str)


def test_metrics_summary_service_request_rate_is_number(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["services"]:
        assert isinstance(entry["request_rate"], (int, float))
        assert entry["request_rate"] >= 0.0


def test_metrics_summary_service_error_rate_is_number(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["services"]:
        assert isinstance(entry["error_rate"], (int, float))
        assert entry["error_rate"] >= 0.0


def test_metrics_summary_service_p95_latency_is_number(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["services"]:
        assert isinstance(entry["p95_latency_ms"], (int, float))
        assert entry["p95_latency_ms"] >= 0.0


def test_metrics_summary_service_metadata_is_dict(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["services"]:
        assert isinstance(entry["metadata"], dict)


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


def test_metrics_summary_links_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["links"], list)


def test_metrics_summary_links_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["links"]) > 0


def test_metrics_summary_link_entries_have_required_fields(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert _REQUIRED_LINK_KEYS.issubset(entry.keys()), f"Link missing keys: {entry}"


def test_metrics_summary_link_label_is_nonempty_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert isinstance(entry["label"], str)
        assert len(entry["label"]) > 0


def test_metrics_summary_link_path_starts_with_slash(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert isinstance(entry["path"], str)
        assert entry["path"].startswith("/")


def test_metrics_summary_link_description_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert isinstance(entry["description"], str)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def test_metrics_summary_notes_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["notes"], list)


def test_metrics_summary_notes_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["notes"]) > 0


def test_metrics_summary_notes_are_strings(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for note in data["notes"]:
        assert isinstance(note, str)
        assert len(note) > 0


# ---------------------------------------------------------------------------
# Stability / idempotency
# ---------------------------------------------------------------------------


def test_metrics_summary_stable_across_repeated_calls(
    test_client: TestClient,
) -> None:
    d1 = _fetch(test_client)
    d2 = _fetch(test_client)
    assert d1["status"] == d2["status"]
    assert d1["service"] == d2["service"]
    assert d1["window"]["environment"] == d2["window"]["environment"]
    assert d1["window"]["aggregation_mode"] == d2["window"]["aggregation_mode"]
    assert d1["kpis"] == d2["kpis"]
    assert d1["services"] == d2["services"]
    assert d1["links"] == d2["links"]
    assert d1["notes"] == d2["notes"]
