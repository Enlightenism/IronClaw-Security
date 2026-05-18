from __future__ import annotations

from typing import Any, Final

from fastapi.testclient import TestClient
import pytest

from app.main import app

UI_DATA_RETENTION_PATH: Final[str] = "/ui/data-retention"
API_KEY_HEADER: Final[dict[str, str]] = {"X-API-Key": "test-api-key"}


EXPECTED_RULE_IDS: Final[frozenset[str]] = frozenset({"requests", "telemetry", "review-queue", "audit-log"})


@pytest.fixture(scope="function")
def client() -> TestClient:
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(scope="function")
def retention_payload(client: TestClient) -> dict[str, Any]:
    response = client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestDataRetentionAuth:
    def test_missing_api_key_returns_401_or_403(self, client: TestClient) -> None:
        response = client.get(UI_DATA_RETENTION_PATH)
        assert response.status_code in (401, 403)

    def test_invalid_api_key_returns_401_or_403(self, client: TestClient) -> None:
        response = client.get(UI_DATA_RETENTION_PATH, headers={"X-API-Key": "invalid-key"})
        assert response.status_code in (401, 403)

    def test_valid_api_key_returns_200(self, client: TestClient) -> None:
        response = client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER)
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Top-level response shape
# ---------------------------------------------------------------------------


class TestDataRetentionResponseShape:
    def test_returns_json_object(self, retention_payload: dict[str, Any]) -> None:
        assert isinstance(retention_payload, dict)

    def test_status_is_ok(self, retention_payload: dict[str, Any]) -> None:
        assert retention_payload["status"] == "ok"

    def test_service_is_ironclaw(self, retention_payload: dict[str, Any]) -> None:
        assert retention_payload["service"] == "IronClaw-Security"

    def test_timestamp_is_present_and_non_empty(self, retention_payload: dict[str, Any]) -> None:
        ts = retention_payload["timestamp"]
        assert isinstance(ts, str)
        assert ts.strip()

    def test_timestamp_ends_with_z(self, retention_payload: dict[str, Any]) -> None:
        assert retention_payload["timestamp"].endswith("Z")

    def test_requested_by_is_string(self, retention_payload: dict[str, Any]) -> None:
        assert isinstance(retention_payload["requested_by"], str)
        assert retention_payload["requested_by"].strip()

    def test_rules_is_list(self, retention_payload: dict[str, Any]) -> None:
        assert isinstance(retention_payload["rules"], list)

    def test_total_rules_is_int(self, retention_payload: dict[str, Any]) -> None:
        assert isinstance(retention_payload["total_rules"], int)

    def test_total_rules_matches_rules_length(self, retention_payload: dict[str, Any]) -> None:
        assert retention_payload["total_rules"] == len(retention_payload["rules"])

    def test_metadata_is_dict(self, retention_payload: dict[str, Any]) -> None:
        assert isinstance(retention_payload["metadata"], dict)

    def test_required_keys_present(self, retention_payload: dict[str, Any]) -> None:
        for key in (
            "status",
            "service",
            "timestamp",
            "requested_by",
            "rules",
            "total_rules",
            "metadata",
        ):
            assert key in retention_payload, f"Missing key: {key}"

    def test_root_is_not_array(self, retention_payload: dict[str, Any]) -> None:
        assert not isinstance(retention_payload, list)


# ---------------------------------------------------------------------------
# Rules collection
# ---------------------------------------------------------------------------


class TestDataRetentionRulesCollection:
    def test_rules_count_is_four(self, retention_payload: dict[str, Any]) -> None:
        assert len(retention_payload["rules"]) == 4

    def test_all_expected_rule_ids_present(self, retention_payload: dict[str, Any]) -> None:
        ids = {r["rule_id"] for r in retention_payload["rules"]}
        assert ids == EXPECTED_RULE_IDS

    def test_all_rules_are_dicts(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule, dict)

    def test_each_rule_has_required_fields(self, retention_payload: dict[str, Any]) -> None:
        required = {
            "rule_id",
            "name",
            "category",
            "retention_days",
            "storage_scope",
            "purge_behavior",
            "description",
            "metadata",
        }
        for rule in retention_payload["rules"]:
            missing = required - rule.keys()
            assert not missing, f"Rule {rule.get('rule_id')} missing fields: {missing}"

    def test_rule_ids_are_non_empty_strings(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["rule_id"], str)
            assert rule["rule_id"].strip()

    def test_rule_names_are_non_empty_strings(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["name"], str)
            assert rule["name"].strip()

    def test_rule_categories_are_non_empty_strings(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["category"], str)
            assert rule["category"].strip()

    def test_retention_days_are_positive_ints(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["retention_days"], int)
            assert rule["retention_days"] > 0

    def test_storage_scopes_are_non_empty_strings(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["storage_scope"], str)
            assert rule["storage_scope"].strip()

    def test_purge_behaviors_are_non_empty_strings(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["purge_behavior"], str)
            assert rule["purge_behavior"].strip()

    def test_descriptions_are_non_empty_strings(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["description"], str)
            assert rule["description"].strip()

    def test_rule_metadata_are_dicts(self, retention_payload: dict[str, Any]) -> None:
        for rule in retention_payload["rules"]:
            assert isinstance(rule["metadata"], dict)

    def test_no_duplicate_rule_ids(self, retention_payload: dict[str, Any]) -> None:
        ids = [r["rule_id"] for r in retention_payload["rules"]]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Individual rule contracts
# ---------------------------------------------------------------------------


class TestDataRetentionRuleContracts:
    def _get_rule(self, retention_payload: dict[str, Any], rule_id: str) -> dict[str, Any]:
        for rule in retention_payload["rules"]:
            if rule["rule_id"] == rule_id:
                return rule
        pytest.fail(f"Rule '{rule_id}' not found in payload")

    def test_requests_rule_retention_days(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "requests")
        assert rule["retention_days"] == 30

    def test_requests_rule_category(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "requests")
        assert rule["category"] == "operational"

    def test_requests_rule_purge_behavior(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "requests")
        assert rule["purge_behavior"] == "rolling-window"

    def test_requests_rule_contains_content_false(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "requests")
        assert rule["metadata"].get("contains_content") is False

    def test_telemetry_rule_retention_days(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "telemetry")
        assert rule["retention_days"] == 14

    def test_telemetry_rule_category(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "telemetry")
        assert rule["category"] == "observability"

    def test_telemetry_rule_purge_behavior(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "telemetry")
        assert rule["purge_behavior"] == "rolling-window"

    def test_telemetry_rule_contains_content_false(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "telemetry")
        assert rule["metadata"].get("contains_content") is False

    def test_review_queue_rule_retention_days(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "review-queue")
        assert rule["retention_days"] == 90

    def test_review_queue_rule_category(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "review-queue")
        assert rule["category"] == "security-review"

    def test_review_queue_rule_purge_behavior(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "review-queue")
        assert rule["purge_behavior"] == "archive-then-purge"

    def test_review_queue_rule_contains_content_true(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "review-queue")
        assert rule["metadata"].get("contains_content") is True

    def test_audit_log_rule_retention_days(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "audit-log")
        assert rule["retention_days"] == 180

    def test_audit_log_rule_category(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "audit-log")
        assert rule["category"] == "audit"

    def test_audit_log_rule_purge_behavior(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "audit-log")
        assert rule["purge_behavior"] == "archive-then-purge"

    def test_audit_log_rule_contains_content_true(self, retention_payload: dict[str, Any]) -> None:
        rule = self._get_rule(retention_payload, "audit-log")
        assert rule["metadata"].get("contains_content") is True

    def test_audit_log_has_longest_retention(self, retention_payload: dict[str, Any]) -> None:
        audit_rule = self._get_rule(retention_payload, "audit-log")
        max_days = max(r["retention_days"] for r in retention_payload["rules"])
        assert audit_rule["retention_days"] == max_days

    def test_telemetry_has_shortest_retention(self, retention_payload: dict[str, Any]) -> None:
        telemetry_rule = self._get_rule(retention_payload, "telemetry")
        min_days = min(r["retention_days"] for r in retention_payload["rules"])
        assert telemetry_rule["retention_days"] == min_days


# ---------------------------------------------------------------------------
# requested_by query parameter
# ---------------------------------------------------------------------------


class TestDataRetentionRequestedBy:
    def test_default_requested_by(self, client: TestClient) -> None:
        response = client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER)
        data = response.json()
        assert data["requested_by"] == "ui-data-retention"

    def test_custom_requested_by(self, client: TestClient) -> None:
        response = client.get(
            UI_DATA_RETENTION_PATH,
            params={"requested_by": "security-analyst"},
            headers=API_KEY_HEADER,
        )
        data = response.json()
        assert data["requested_by"] == "security-analyst"

    def test_metadata_contains_requested_by(self, client: TestClient) -> None:
        response = client.get(
            UI_DATA_RETENTION_PATH,
            params={"requested_by": "test-caller"},
            headers=API_KEY_HEADER,
        )
        data = response.json()
        assert data["metadata"]["requested_by"] == "test-caller"

    def test_empty_requested_by_returns_422(self, client: TestClient) -> None:
        response = client.get(
            UI_DATA_RETENTION_PATH,
            params={"requested_by": ""},
            headers=API_KEY_HEADER,
        )
        assert response.status_code == 422

    def test_rules_unchanged_with_custom_requested_by(self, client: TestClient) -> None:
        response = client.get(
            UI_DATA_RETENTION_PATH,
            params={"requested_by": "admin"},
            headers=API_KEY_HEADER,
        )
        data = response.json()
        assert len(data["rules"]) == 4


# ---------------------------------------------------------------------------
# Stability and idempotency
# ---------------------------------------------------------------------------


class TestDataRetentionStability:
    def test_response_is_stable_across_repeated_reads(self, client: TestClient) -> None:
        r1 = client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER).json()
        r2 = client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER).json()
        assert r1["rules"] == r2["rules"]
        assert r1["total_rules"] == r2["total_rules"]
        assert r1["status"] == r2["status"]
        assert r1["service"] == r2["service"]

    def test_rule_ids_are_stable_across_calls(self, client: TestClient) -> None:
        ids1 = {r["rule_id"] for r in client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER).json()["rules"]}
        ids2 = {r["rule_id"] for r in client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER).json()["rules"]}
        assert ids1 == ids2

    def test_content_type_is_json(self, client: TestClient) -> None:
        response = client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER)
        assert response.headers["content-type"].startswith("application/json")

    def test_get_is_idempotent(self, client: TestClient) -> None:
        responses = [client.get(UI_DATA_RETENTION_PATH, headers=API_KEY_HEADER).json() for _ in range(3)]
        rule_sets = [frozenset(r["rule_id"] for r in resp["rules"]) for resp in responses]
        assert len(set(rule_sets)) == 1
