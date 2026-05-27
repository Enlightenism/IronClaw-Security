from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.systemdiagnostics import (
    DiagnosticsCheck,
    DiagnosticsIncident,
    DiagnosticsKpi,
    DiagnosticsTimelineEvent,
    SystemDiagnosticsResponse,
    router,
)

# ---------------------------------------------------------------------------
# Test app — GET /ui/systemdiagnostics
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


ENDPOINT = "/ui/systemdiagnostics"

EXPECTED_CHECK_KEYS = {
    "api_router",
    "policy_engine",
    "review_queue",
    "sandbox_router",
    "telemetry_pipeline",
    "persistence_state",
    "integration_registry",
}

VALID_TONES = {"success", "warning", "critical", "neutral", "danger", "info"}
VALID_STATUS = {"healthy", "degraded", "critical", "error", "unknown"}
VALID_SEVERITY = {"low", "medium", "high", "critical"}
VALID_INCIDENT_STATUS = {"open", "monitoring", "resolved", "closed"}


# ---------------------------------------------------------------------------
# Status + content-type
# ---------------------------------------------------------------------------


class TestSystemDiagnosticsStatus:
    def test_status_200(self, client: TestClient) -> None:
        response = client.get(ENDPOINT)
        assert response.status_code == 200

    def test_response_is_json(self, client: TestClient) -> None:
        response = client.get(ENDPOINT)
        assert response.headers["content-type"].startswith("application/json")

    def test_response_model_parses(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        model = SystemDiagnosticsResponse(**data)
        assert isinstance(model, SystemDiagnosticsResponse)

    def test_multiple_calls_both_200(self, client: TestClient) -> None:
        for _ in range(2):
            assert client.get(ENDPOINT).status_code == 200


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestSystemDiagnosticsTopLevelShape:
    def test_top_level_fields_present(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        required = {
            "generated_at",
            "environment",
            "overall_status",
            "overall_tone",
            "service",
            "checks",
            "kpis",
            "active_incidents",
            "timeline",
            "metadata",
        }
        for field in required:
            assert field in data, f"Missing top-level field '{field}'"

    def test_generated_at_is_str(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["generated_at"], str)
        assert len(data["generated_at"]) > 0

    def test_generated_at_ends_with_z(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["generated_at"].endswith("Z")

    def test_environment_is_str(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["environment"], str)
        assert len(data["environment"]) > 0

    def test_environment_default_value(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["environment"] == "local"

    def test_overall_status_is_str(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["overall_status"], str)
        assert len(data["overall_status"]) > 0

    def test_overall_status_valid_value(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["overall_status"] in VALID_STATUS

    def test_overall_tone_is_str(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["overall_tone"], str)

    def test_overall_tone_valid_value(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["overall_tone"] in VALID_TONES

    def test_service_is_ironclaw(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["service"] == "IronClaw"

    def test_metadata_is_dict(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["metadata"], dict)

    def test_metadata_page_id(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["metadata"]["page_id"] == "system-diagnostics"

    def test_metadata_title(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["metadata"]["title"] == "System Diagnostics"

    def test_metadata_supports_live_polling(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert data["metadata"]["supports_live_polling"] is True

    def test_metadata_refresh_interval(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["metadata"]["refresh_interval_seconds"], int)
        assert data["metadata"]["refresh_interval_seconds"] > 0


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------


class TestSystemDiagnosticsChecks:
    def test_checks_is_list(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["checks"], list)

    def test_checks_not_empty(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert len(data["checks"]) > 0

    def test_checks_required_fields(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        required = {
            "key",
            "label",
            "status",
            "tone",
            "summary",
            "last_checked_at",
            "latency_ms",
            "metadata",
        }
        for check in data["checks"]:
            for field in required:
                assert field in check, f"Missing field '{field}' in check {check.get('key')}"

    def test_checks_model_parses(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            model = DiagnosticsCheck(**check)
            assert isinstance(model.key, str)
            assert isinstance(model.label, str)

    def test_expected_check_keys_present(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        found_keys = {c["key"] for c in data["checks"]}
        for expected_key in EXPECTED_CHECK_KEYS:
            assert expected_key in found_keys, f"Expected check key '{expected_key}' not found"

    def test_check_status_valid_values(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            assert check["status"] in VALID_STATUS, f"Unexpected status '{check['status']}' for check '{check['key']}'"

    def test_check_tone_valid_values(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            assert check["tone"] in VALID_TONES, f"Unexpected tone '{check['tone']}' for check '{check['key']}'"

    def test_check_summary_is_str(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            assert isinstance(check["summary"], str)
            assert len(check["summary"]) > 0

    def test_check_last_checked_at_is_str(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            assert isinstance(check["last_checked_at"], str)
            assert len(check["last_checked_at"]) > 0

    def test_check_last_checked_at_ends_with_z(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            assert check["last_checked_at"].endswith("Z"), f"last_checked_at for '{check['key']}' does not end with Z"

    def test_check_latency_ms_nullable_int(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            assert check["latency_ms"] is None or isinstance(check["latency_ms"], int)

    def test_check_metadata_is_dict(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for check in data["checks"]:
            assert isinstance(check["metadata"], dict)

    def test_api_router_check_healthy(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        api_check = next(c for c in data["checks"] if c["key"] == "api_router")
        assert api_check["status"] == "healthy"
        assert api_check["tone"] == "success"

    def test_policy_engine_check_healthy(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        policy_check = next(c for c in data["checks"] if c["key"] == "policy_engine")
        assert policy_check["status"] == "healthy"
        assert policy_check["tone"] == "success"

    def test_review_queue_check_degraded(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        rq_check = next(c for c in data["checks"] if c["key"] == "review_queue")
        assert rq_check["status"] == "degraded"
        assert rq_check["tone"] == "warning"

    def test_review_queue_metadata_fields(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        rq_check = next(c for c in data["checks"] if c["key"] == "review_queue")
        assert "pending_items" in rq_check["metadata"]
        assert "sla_breach_count" in rq_check["metadata"]

    def test_policy_engine_metadata_fields(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        pe_check = next(c for c in data["checks"] if c["key"] == "policy_engine")
        assert "bundle_version" in pe_check["metadata"]
        assert "mode" in pe_check["metadata"]

    def test_telemetry_pipeline_metadata_fields(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        tp_check = next(c for c in data["checks"] if c["key"] == "telemetry_pipeline")
        assert "events_ingested_1h" in tp_check["metadata"]
        assert "queue_depth" in tp_check["metadata"]


# ---------------------------------------------------------------------------
# kpis
# ---------------------------------------------------------------------------


class TestSystemDiagnosticsKpis:
    def test_kpis_is_list(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["kpis"], list)

    def test_kpis_not_empty(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert len(data["kpis"]) > 0

    def test_kpis_required_fields(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for kpi in data["kpis"]:
            assert "label" in kpi
            assert "value" in kpi
            assert "tone" in kpi

    def test_kpis_model_parses(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for kpi in data["kpis"]:
            model = DiagnosticsKpi(**kpi)
            assert isinstance(model.label, str)
            assert isinstance(model.value, str)

    def test_kpi_labels_present(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        labels = {k["label"] for k in data["kpis"]}
        assert "Healthy Checks" in labels
        assert "Degraded Checks" in labels
        assert "Critical Checks" in labels
        assert "Active Incidents" in labels

    def test_kpi_values_are_numeric_strings(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for kpi in data["kpis"]:
            assert kpi["value"].isdigit(), f"KPI '{kpi['label']}' value '{kpi['value']}' is not a numeric string"

    def test_kpi_tone_valid_values(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for kpi in data["kpis"]:
            assert kpi["tone"] in VALID_TONES

    def test_healthy_checks_kpi_value_correct(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        healthy_count = sum(1 for c in data["checks"] if c["status"] == "healthy")
        kpi = next(k for k in data["kpis"] if k["label"] == "Healthy Checks")
        assert int(kpi["value"]) == healthy_count

    def test_degraded_checks_kpi_value_correct(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        degraded_count = sum(1 for c in data["checks"] if c["status"] == "degraded")
        kpi = next(k for k in data["kpis"] if k["label"] == "Degraded Checks")
        assert int(kpi["value"]) == degraded_count

    def test_active_incidents_kpi_matches_list(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        kpi = next(k for k in data["kpis"] if k["label"] == "Active Incidents")
        assert int(kpi["value"]) == len(data["active_incidents"])

    def test_healthy_checks_kpi_tone_success(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        kpi = next(k for k in data["kpis"] if k["label"] == "Healthy Checks")
        assert kpi["tone"] == "success"


# ---------------------------------------------------------------------------
# overall_status / overall_tone derivation consistency
# ---------------------------------------------------------------------------


class TestSystemDiagnosticsOverallStatus:
    def test_degraded_check_produces_degraded_overall(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        has_degraded = any(c["status"] == "degraded" for c in data["checks"])
        if has_degraded:
            assert data["overall_status"] == "degraded"
            assert data["overall_tone"] == "warning"

    def test_overall_status_warning_tone_when_degraded(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        if data["overall_status"] == "degraded":
            assert data["overall_tone"] == "warning"

    def test_overall_status_success_tone_when_healthy(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        if data["overall_status"] == "healthy":
            assert data["overall_tone"] == "success"


# ---------------------------------------------------------------------------
# active_incidents
# ---------------------------------------------------------------------------


class TestSystemDiagnosticsActiveIncidents:
    def test_active_incidents_is_list(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["active_incidents"], list)

    def test_active_incidents_not_empty(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert len(data["active_incidents"]) > 0

    def test_incident_required_fields(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        required = {
            "incident_id",
            "severity",
            "status",
            "title",
            "summary",
            "detected_at",
            "owner",
        }
        for inc in data["active_incidents"]:
            for field in required:
                assert field in inc, f"Missing field '{field}' in incident"

    def test_incident_model_parses(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for inc in data["active_incidents"]:
            model = DiagnosticsIncident(**inc)
            assert isinstance(model.incident_id, str)

    def test_incident_severity_valid(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for inc in data["active_incidents"]:
            assert inc["severity"] in VALID_SEVERITY

    def test_incident_status_valid(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for inc in data["active_incidents"]:
            assert inc["status"] in VALID_INCIDENT_STATUS

    def test_incident_detected_at_ends_with_z(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for inc in data["active_incidents"]:
            assert inc["detected_at"].endswith("Z"), f"detected_at for '{inc['incident_id']}' does not end with Z"

    def test_incident_ids_unique(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        ids = [inc["incident_id"] for inc in data["active_incidents"]]
        assert len(ids) == len(set(ids))

    def test_first_incident_id(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        ids = {inc["incident_id"] for inc in data["active_incidents"]}
        assert "inc_diag_001" in ids

    def test_second_incident_id(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        ids = {inc["incident_id"] for inc in data["active_incidents"]}
        assert "inc_diag_002" in ids

    def test_first_incident_severity(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        inc = next(i for i in data["active_incidents"] if i["incident_id"] == "inc_diag_001")
        assert inc["severity"] == "medium"
        assert inc["status"] == "open"

    def test_second_incident_status_monitoring(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        inc = next(i for i in data["active_incidents"] if i["incident_id"] == "inc_diag_002")
        assert inc["status"] == "monitoring"
        assert inc["severity"] == "low"

    def test_incident_owner_nullable(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for inc in data["active_incidents"]:
            assert inc["owner"] is None or isinstance(inc["owner"], str)


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------


class TestSystemDiagnosticsTimeline:
    def test_timeline_is_list(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert isinstance(data["timeline"], list)

    def test_timeline_not_empty(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert len(data["timeline"]) > 0

    def test_timeline_required_fields(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        required = {"timestamp", "category", "title", "summary", "tone"}
        for event in data["timeline"]:
            for field in required:
                assert field in event, f"Missing field '{field}' in timeline event"

    def test_timeline_model_parses(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for event in data["timeline"]:
            model = DiagnosticsTimelineEvent(**event)
            assert isinstance(model.timestamp, str)
            assert isinstance(model.category, str)

    def test_timeline_tone_valid_values(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for event in data["timeline"]:
            assert event["tone"] in VALID_TONES

    def test_timeline_timestamps_end_with_z(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        for event in data["timeline"]:
            assert event["timestamp"].endswith("Z"), f"Timeline event timestamp does not end with Z: {event['timestamp']}"

    def test_timeline_categories_valid(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        valid_categories = {"telemetry", "review", "runtime", "policy", "incident", "system"}
        for event in data["timeline"]:
            assert event["category"] in valid_categories

    def test_timeline_has_four_events(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        assert len(data["timeline"]) == 4

    def test_timeline_tones_include_warning_and_success(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        tones = {e["tone"] for e in data["timeline"]}
        assert "warning" in tones
        assert "success" in tones

    def test_timeline_has_critical_event(self, client: TestClient) -> None:
        data = client.get(ENDPOINT).json()
        tones = {e["tone"] for e in data["timeline"]}
        assert "critical" in tones
