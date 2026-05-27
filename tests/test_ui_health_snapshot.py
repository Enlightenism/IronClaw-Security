from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROUTE = "/health-snapshot"

_REQUIRED_TOP_KEYS = {
    "status",
    "service",
    "timestamp",
    "summary",
    "signals",
    "dependencies",
    "links",
    "notes",
}

_REQUIRED_SUMMARY_KEYS = {
    "overall_status",
    "readiness",
    "liveness",
    "environment",
    "metadata",
}

_REQUIRED_SIGNAL_KEYS = {"label", "status", "detail", "metadata"}

_REQUIRED_DEPENDENCY_KEYS = {
    "dependency",
    "status",
    "latency_ms",
    "required",
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


def test_health_snapshot_returns_200(test_client: TestClient) -> None:
    response = test_client.get(_ROUTE)
    assert response.status_code == 200


def test_health_snapshot_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(_ROUTE)
    assert "application/json" in response.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


def test_health_snapshot_top_level_shape(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert _REQUIRED_TOP_KEYS.issubset(data.keys())


def test_health_snapshot_root_is_object_not_array(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data, dict)


def test_health_snapshot_status_is_ok(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert data["status"] == "ok"


def test_health_snapshot_service_is_ironclaw(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert data["service"] == "IronClaw-Security"


def test_health_snapshot_timestamp_is_utc_string(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["timestamp"], str)
    assert data["timestamp"].endswith("Z")


# ---------------------------------------------------------------------------
# Summary fields
# ---------------------------------------------------------------------------


def test_health_snapshot_summary_shape(test_client: TestClient) -> None:
    data = _fetch(test_client)
    summary = data["summary"]
    assert isinstance(summary, dict)
    assert _REQUIRED_SUMMARY_KEYS.issubset(summary.keys())


def test_health_snapshot_summary_overall_status_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    assert isinstance(data["summary"]["overall_status"], str)
    assert len(data["summary"]["overall_status"]) > 0


def test_health_snapshot_summary_readiness_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    assert isinstance(data["summary"]["readiness"], str)


def test_health_snapshot_summary_liveness_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    assert isinstance(data["summary"]["liveness"], str)


def test_health_snapshot_summary_environment_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    assert isinstance(data["summary"]["environment"], str)


def test_health_snapshot_summary_metadata_is_dict(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["summary"]["metadata"], dict)


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


def test_health_snapshot_signals_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["signals"], list)


def test_health_snapshot_signals_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["signals"]) > 0


def test_health_snapshot_signal_entries_have_required_fields(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["signals"]:
        assert _REQUIRED_SIGNAL_KEYS.issubset(entry.keys()), f"Signal missing keys: {entry}"


def test_health_snapshot_signal_label_is_nonempty_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["signals"]:
        assert isinstance(entry["label"], str)
        assert len(entry["label"]) > 0


def test_health_snapshot_signal_status_is_string(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["signals"]:
        assert isinstance(entry["status"], str)


def test_health_snapshot_signal_detail_is_string(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["signals"]:
        assert isinstance(entry["detail"], str)


def test_health_snapshot_signal_metadata_is_dict(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for entry in data["signals"]:
        assert isinstance(entry["metadata"], dict)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def test_health_snapshot_dependencies_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["dependencies"], list)


def test_health_snapshot_dependencies_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["dependencies"]) > 0


def test_health_snapshot_dependency_entries_have_required_fields(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["dependencies"]:
        assert _REQUIRED_DEPENDENCY_KEYS.issubset(entry.keys()), f"Dependency missing keys: {entry}"


def test_health_snapshot_dependency_name_is_nonempty_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["dependencies"]:
        assert isinstance(entry["dependency"], str)
        assert len(entry["dependency"]) > 0


def test_health_snapshot_dependency_status_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["dependencies"]:
        assert isinstance(entry["status"], str)


def test_health_snapshot_dependency_latency_ms_is_number(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["dependencies"]:
        assert isinstance(entry["latency_ms"], (int, float))
        assert entry["latency_ms"] >= 0.0


def test_health_snapshot_dependency_required_is_bool(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["dependencies"]:
        assert isinstance(entry["required"], bool)


def test_health_snapshot_dependency_metadata_is_dict(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["dependencies"]:
        assert isinstance(entry["metadata"], dict)


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


def test_health_snapshot_links_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["links"], list)


def test_health_snapshot_links_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["links"]) > 0


def test_health_snapshot_link_entries_have_required_fields(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert _REQUIRED_LINK_KEYS.issubset(entry.keys()), f"Link missing keys: {entry}"


def test_health_snapshot_link_label_is_nonempty_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert isinstance(entry["label"], str)
        assert len(entry["label"]) > 0


def test_health_snapshot_link_path_starts_with_slash(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert isinstance(entry["path"], str)
        assert entry["path"].startswith("/")


def test_health_snapshot_link_description_is_string(
    test_client: TestClient,
) -> None:
    data = _fetch(test_client)
    for entry in data["links"]:
        assert isinstance(entry["description"], str)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def test_health_snapshot_notes_is_list(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert isinstance(data["notes"], list)


def test_health_snapshot_notes_are_non_empty(test_client: TestClient) -> None:
    data = _fetch(test_client)
    assert len(data["notes"]) > 0


def test_health_snapshot_notes_are_strings(test_client: TestClient) -> None:
    data = _fetch(test_client)
    for note in data["notes"]:
        assert isinstance(note, str)
        assert len(note) > 0


# ---------------------------------------------------------------------------
# Stability / idempotency
# ---------------------------------------------------------------------------


def test_health_snapshot_stable_across_repeated_calls(
    test_client: TestClient,
) -> None:
    d1 = _fetch(test_client)
    d2 = _fetch(test_client)
    assert d1["status"] == d2["status"]
    assert d1["service"] == d2["service"]
    assert d1["summary"] == d2["summary"]
    assert d1["signals"] == d2["signals"]
    assert d1["dependencies"] == d2["dependencies"]
    assert d1["links"] == d2["links"]
    assert d1["notes"] == d2["notes"]
