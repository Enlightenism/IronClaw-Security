from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

URL = "/ui/docs/telemetry"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "generatedat",
    "headline",
    "intro",
    "eventschema",
    "emissionrules",
    "queryendpoints",
    "retentiontiers",
    "eventexamples",
    "notes",
)

_REQUIRED_EVENT_FIELD_FIELDS = (
    "fieldid",
    "label",
    "type",
    "nullable",
    "presentwhen",
    "description",
)

_REQUIRED_EMISSION_RULE_FIELDS = (
    "ruleid",
    "label",
    "trigger",
    "emissionmode",
    "eventtype",
    "description",
)

_REQUIRED_QUERY_ENDPOINT_FIELDS = (
    "endpointid",
    "method",
    "path",
    "scope",
    "description",
    "filters",
)

_REQUIRED_QUERY_FILTER_FIELDS = (
    "filterid",
    "parametername",
    "location",
    "type",
    "required",
    "example",
    "description",
)

_REQUIRED_RETENTION_TIER_FIELDS = (
    "tierid",
    "label",
    "retentionperiod",
    "purgepolicy",
    "affectedeventtypes",
    "description",
)

_REQUIRED_EVENT_EXAMPLE_FIELDS = (
    "exampleid",
    "label",
    "scenario",
    "eventsnapshot",
)

_KNOWN_EVENT_TYPES = {
    "guard_action",
    "guard_execute",
    "guard_scan",
    "review_queued",
    "review_decided",
    "quarantine_created",
    "quarantine_released",
    "policy_updated",
    "session_risk_updated",
    "audit_export",
    "telemetry_flush",
}

_KNOWN_VERDICTS = {"allow", "block"}

_KNOWN_EMISSION_MODES = {"automatic", "on-demand"}

_VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

_KNOWN_TIER_IDS = {"hot", "cold", "operator-immutable"}

_CORE_SCHEMA_FIELD_IDS = {
    "eventid",
    "eventtype",
    "timestamp",
    "environment",
    "verdict",
    "riskscore",
}

_KNOWN_QUERY_ENDPOINT_IDS = {
    "guard-audit-events",
    "audit-events",
    "telemetry-events",
    "audit-export",
}


def test_get_docs_telemetry_returns_200(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200


def test_get_docs_telemetry_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert "application/json" in response.headers.get("content-type", "")


def test_get_docs_telemetry_response_is_object(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_get_docs_telemetry_required_top_level_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        assert field in body, f"missing top-level field: {field!r}"


def test_get_docs_telemetry_scalar_fields_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("generatedat", "headline", "intro"):
        assert isinstance(body[field], str), f"{field!r} must be str"
        assert body[field].strip(), f"{field!r} must not be empty"


def test_get_docs_telemetry_generatedat_is_iso8601(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    generatedat = response.json()["generatedat"]
    assert isinstance(generatedat, str)
    assert "T" in generatedat
    assert "Z" in generatedat or "+" in generatedat


def test_get_docs_telemetry_list_fields_are_lists(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in (
        "eventschema",
        "emissionrules",
        "queryendpoints",
        "retentiontiers",
        "eventexamples",
        "notes",
    ):
        assert isinstance(body[field], list), f"{field!r} must be a list"


def test_get_docs_telemetry_list_fields_are_non_empty(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in (
        "eventschema",
        "emissionrules",
        "queryendpoints",
        "retentiontiers",
        "eventexamples",
        "notes",
    ):
        assert len(body[field]) > 0, f"{field!r} must not be empty"


def test_get_docs_telemetry_event_schema_fields_shape(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, field in enumerate(response.json()["eventschema"]):
        assert isinstance(field, dict), f"eventschema[{i}] must be a dict"
        for required in _REQUIRED_EVENT_FIELD_FIELDS:
            assert required in field, f"eventschema[{i}] missing field: {required!r}"
        assert isinstance(field["fieldid"], str)
        assert field["fieldid"].strip()
        assert isinstance(field["label"], str)
        assert field["label"].strip()
        assert isinstance(field["type"], str)
        assert field["type"].strip()
        assert isinstance(field["nullable"], bool)
        assert isinstance(field["presentwhen"], str)
        assert field["presentwhen"].strip()
        assert isinstance(field["description"], str)
        assert field["description"].strip()


def test_get_docs_telemetry_event_schema_field_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    field_ids = [f["fieldid"] for f in response.json()["eventschema"]]
    assert len(field_ids) == len(set(field_ids))


def test_get_docs_telemetry_core_schema_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    field_ids = {f["fieldid"] for f in response.json()["eventschema"]}
    for expected in _CORE_SCHEMA_FIELD_IDS:
        assert expected in field_ids, f"expected schema field {expected!r} not found"


def test_get_docs_telemetry_eventid_field_is_not_nullable(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    eventid_field = next((f for f in response.json()["eventschema"] if f["fieldid"] == "eventid"), None)
    assert eventid_field is not None
    assert eventid_field["nullable"] is False


def test_get_docs_telemetry_timestamp_field_is_not_nullable(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    ts_field = next((f for f in response.json()["eventschema"] if f["fieldid"] == "timestamp"), None)
    assert ts_field is not None
    assert ts_field["nullable"] is False


def test_get_docs_telemetry_emission_rules_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, rule in enumerate(response.json()["emissionrules"]):
        assert isinstance(rule, dict), f"emissionrules[{i}] must be a dict"
        for required in _REQUIRED_EMISSION_RULE_FIELDS:
            assert required in rule, f"emissionrules[{i}] missing field: {required!r}"
            assert isinstance(rule[required], str), f"emissionrules[{i}].{required!r} must be str"
            assert rule[required].strip(), f"emissionrules[{i}].{required!r} must not be empty"


def test_get_docs_telemetry_emission_rule_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    rule_ids = [r["ruleid"] for r in response.json()["emissionrules"]]
    assert len(rule_ids) == len(set(rule_ids))


def test_get_docs_telemetry_emission_modes_are_valid(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, rule in enumerate(response.json()["emissionrules"]):
        assert rule["emissionmode"] in _KNOWN_EMISSION_MODES, f"emissionrules[{i}].emissionmode {rule['emissionmode']!r} is not valid"


def test_get_docs_telemetry_emission_rule_event_types_are_known(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, rule in enumerate(response.json()["emissionrules"]):
        assert rule["eventtype"] in _KNOWN_EVENT_TYPES, f"emissionrules[{i}].eventtype {rule['eventtype']!r} is not a known event type"


def test_get_docs_telemetry_guard_action_rule_is_automatic(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    rule = next(
        (r for r in response.json()["emissionrules"] if r["ruleid"] == "guard-action-auto"),
        None,
    )
    assert rule is not None
    assert rule["emissionmode"] == "automatic"
    assert rule["eventtype"] == "guard_action"


def test_get_docs_telemetry_query_endpoints_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["queryendpoints"]):
        assert isinstance(endpoint, dict), f"queryendpoints[{i}] must be a dict"
        for required in _REQUIRED_QUERY_ENDPOINT_FIELDS:
            assert required in endpoint, f"queryendpoints[{i}] missing field: {required!r}"
        assert isinstance(endpoint["endpointid"], str)
        assert endpoint["endpointid"].strip()
        assert isinstance(endpoint["method"], str)
        assert endpoint["method"] in _VALID_HTTP_METHODS, f"queryendpoints[{i}].method {endpoint['method']!r} is not a valid HTTP method"
        assert isinstance(endpoint["path"], str)
        assert endpoint["path"].startswith("/"), f"queryendpoints[{i}].path must start with '/'"
        assert isinstance(endpoint["scope"], str)
        assert endpoint["scope"].strip()
        assert isinstance(endpoint["description"], str)
        assert endpoint["description"].strip()
        assert isinstance(endpoint["filters"], list)


def test_get_docs_telemetry_query_endpoint_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    endpoint_ids = [e["endpointid"] for e in response.json()["queryendpoints"]]
    assert len(endpoint_ids) == len(set(endpoint_ids))


def test_get_docs_telemetry_known_query_endpoints_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    endpoint_ids = {e["endpointid"] for e in response.json()["queryendpoints"]}
    for expected in _KNOWN_QUERY_ENDPOINT_IDS:
        assert expected in endpoint_ids, f"expected query endpoint {expected!r} not found"


def test_get_docs_telemetry_query_endpoints_have_filters(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["queryendpoints"]):
        assert len(endpoint["filters"]) > 0, f"queryendpoints[{i}] ({endpoint['endpointid']!r}) must have at least one filter"


def test_get_docs_telemetry_query_filter_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["queryendpoints"]):
        for j, fltr in enumerate(endpoint["filters"]):
            assert isinstance(fltr, dict), f"queryendpoints[{i}].filters[{j}] must be a dict"
            for required in _REQUIRED_QUERY_FILTER_FIELDS:
                assert required in fltr, f"queryendpoints[{i}].filters[{j}] missing field: {required!r}"
            assert isinstance(fltr["filterid"], str)
            assert fltr["filterid"].strip()
            assert isinstance(fltr["parametername"], str)
            assert fltr["parametername"].strip()
            assert isinstance(fltr["location"], str)
            assert fltr["location"].strip()
            assert isinstance(fltr["type"], str)
            assert fltr["type"].strip()
            assert isinstance(fltr["required"], bool)
            assert isinstance(fltr["example"], str)
            assert fltr["example"].strip()
            assert isinstance(fltr["description"], str)
            assert fltr["description"].strip()


def test_get_docs_telemetry_guard_audit_events_has_since_filter(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    endpoint = next(
        (e for e in response.json()["queryendpoints"] if e["endpointid"] == "guard-audit-events"),
        None,
    )
    assert endpoint is not None
    filter_ids = {f["filterid"] for f in endpoint["filters"]}
    assert "since" in filter_ids


def test_get_docs_telemetry_retention_tiers_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, tier in enumerate(response.json()["retentiontiers"]):
        assert isinstance(tier, dict), f"retentiontiers[{i}] must be a dict"
        for required in _REQUIRED_RETENTION_TIER_FIELDS:
            assert required in tier, f"retentiontiers[{i}] missing field: {required!r}"
        assert isinstance(tier["tierid"], str)
        assert tier["tierid"].strip()
        assert isinstance(tier["label"], str)
        assert tier["label"].strip()
        assert isinstance(tier["retentionperiod"], str)
        assert tier["retentionperiod"].strip()
        assert isinstance(tier["purgepolicy"], str)
        assert tier["purgepolicy"].strip()
        assert isinstance(tier["affectedeventtypes"], list)
        assert len(tier["affectedeventtypes"]) > 0, f"retentiontiers[{i}].affectedeventtypes must not be empty"
        assert isinstance(tier["description"], str)
        assert tier["description"].strip()


def test_get_docs_telemetry_retention_tier_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    tier_ids = [t["tierid"] for t in response.json()["retentiontiers"]]
    assert len(tier_ids) == len(set(tier_ids))


def test_get_docs_telemetry_known_retention_tiers_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    tier_ids = {t["tierid"] for t in response.json()["retentiontiers"]}
    for expected in _KNOWN_TIER_IDS:
        assert expected in tier_ids, f"expected retention tier {expected!r} not found"


def test_get_docs_telemetry_retention_tier_affected_event_types_are_known(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, tier in enumerate(response.json()["retentiontiers"]):
        for j, event_type in enumerate(tier["affectedeventtypes"]):
            assert isinstance(event_type, str), f"retentiontiers[{i}].affectedeventtypes[{j}] must be str"
            assert event_type in _KNOWN_EVENT_TYPES, f"retentiontiers[{i}].affectedeventtypes[{j}] {event_type!r} is not a known event type"


def test_get_docs_telemetry_operator_immutable_tier_contains_policy_updated(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    tier = next(
        (t for t in response.json()["retentiontiers"] if t["tierid"] == "operator-immutable"),
        None,
    )
    assert tier is not None
    assert "policy_updated" in tier["affectedeventtypes"]
    assert "audit_export" in tier["affectedeventtypes"]


def test_get_docs_telemetry_event_examples_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["eventexamples"]):
        assert isinstance(example, dict), f"eventexamples[{i}] must be a dict"
        for required in _REQUIRED_EVENT_EXAMPLE_FIELDS:
            assert required in example, f"eventexamples[{i}] missing field: {required!r}"
        assert isinstance(example["exampleid"], str)
        assert example["exampleid"].strip()
        assert isinstance(example["label"], str)
        assert example["label"].strip()
        assert isinstance(example["scenario"], str)
        assert example["scenario"].strip()
        assert isinstance(example["eventsnapshot"], dict)


def test_get_docs_telemetry_event_example_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    example_ids = [e["exampleid"] for e in response.json()["eventexamples"]]
    assert len(example_ids) == len(set(example_ids))


def test_get_docs_telemetry_event_examples_snapshots_have_eventtype(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["eventexamples"]):
        snapshot = example["eventsnapshot"]
        assert "eventtype" in snapshot, f"eventexamples[{i}].eventsnapshot missing 'eventtype'"


def test_get_docs_telemetry_event_examples_snapshots_have_timestamp(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["eventexamples"]):
        snapshot = example["eventsnapshot"]
        assert "timestamp" in snapshot, f"eventexamples[{i}].eventsnapshot missing 'timestamp'"


def test_get_docs_telemetry_guard_action_block_example_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    example_ids = {e["exampleid"] for e in response.json()["eventexamples"]}
    assert "guard-action-block" in example_ids


def test_get_docs_telemetry_guard_action_allow_example_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    example_ids = {e["exampleid"] for e in response.json()["eventexamples"]}
    assert "guard-action-allow" in example_ids


def test_get_docs_telemetry_block_example_snapshot_verdict(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    example = next(
        (e for e in response.json()["eventexamples"] if e["exampleid"] == "guard-action-block"),
        None,
    )
    assert example is not None
    assert example["eventsnapshot"].get("verdict") == "block"


def test_get_docs_telemetry_allow_example_snapshot_verdict(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    example = next(
        (e for e in response.json()["eventexamples"] if e["exampleid"] == "guard-action-allow"),
        None,
    )
    assert example is not None
    assert example["eventsnapshot"].get("verdict") == "allow"


def test_get_docs_telemetry_examples_use_only_allow_and_block_verdicts(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for example in response.json()["eventexamples"]:
        verdict = example["eventsnapshot"].get("verdict")
        if verdict is not None:
            assert verdict in _KNOWN_VERDICTS


def test_get_docs_telemetry_notes_are_non_empty_strings(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, note in enumerate(response.json()["notes"]):
        assert isinstance(note, str), f"notes[{i}] must be str"
        assert note.strip(), f"notes[{i}] must not be empty"


def test_get_docs_telemetry_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code != 401
    assert response.status_code != 403


@pytest.mark.parametrize(
    "method",
    ["post", "put", "patch", "delete"],
)
def test_get_docs_telemetry_non_get_methods_not_allowed(
    test_client: TestClient,
    method: str,
) -> None:
    response = getattr(test_client, method)(URL)
    assert response.status_code == 405
