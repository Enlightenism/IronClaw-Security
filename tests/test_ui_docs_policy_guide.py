from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

URL = "/ui/docs/policy-guide"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "generatedat",
    "headline",
    "intro",
    "fields",
    "verdicts",
    "workedexamples",
    "layers",
    "apiendpoints",
    "notes",
)

_REQUIRED_FIELD_VIEW_FIELDS = (
    "fieldid",
    "label",
    "type",
    "defaultvalue",
    "description",
)

_REQUIRED_VERDICT_FIELDS = (
    "verdictid",
    "label",
    "operationalbehavior",
    "logsemitted",
    "executionheld",
    "reviewqueuedentry",
    "harddenied",
    "recommendedthresholdrange",
)

_REQUIRED_WORKED_EXAMPLE_FIELDS = (
    "exampleid",
    "title",
    "scenario",
    "requestsnapshot",
    "verdict",
    "reason",
    "steps",
)

_REQUIRED_EXAMPLE_STEP_FIELDS = (
    "stepid",
    "label",
    "detail",
)

_REQUIRED_LAYER_FIELDS = (
    "layerid",
    "priority",
    "label",
    "description",
)

_REQUIRED_API_ENDPOINT_FIELDS = (
    "endpointid",
    "method",
    "path",
    "scope",
    "description",
)

_KNOWN_VERDICT_IDS = {"allow", "warn", "quarantine", "block"}

_VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def test_get_docs_policy_guide_returns_200(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200


def test_get_docs_policy_guide_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert "application/json" in response.headers.get("content-type", "")


def test_get_docs_policy_guide_response_is_object(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_get_docs_policy_guide_required_top_level_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        assert field in body, f"missing top-level field: {field!r}"


def test_get_docs_policy_guide_scalar_fields_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("generatedat", "headline", "intro"):
        assert isinstance(body[field], str), f"{field!r} must be str"
        assert body[field].strip(), f"{field!r} must not be empty"


def test_get_docs_policy_guide_generatedat_is_iso8601(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    generatedat = response.json()["generatedat"]
    assert isinstance(generatedat, str)
    assert "T" in generatedat
    assert "Z" in generatedat or "+" in generatedat


def test_get_docs_policy_guide_list_fields_are_lists(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("fields", "verdicts", "workedexamples", "layers", "apiendpoints", "notes"):
        assert isinstance(body[field], list), f"{field!r} must be a list"


def test_get_docs_policy_guide_list_fields_are_non_empty(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("fields", "verdicts", "workedexamples", "layers", "apiendpoints", "notes"):
        assert len(body[field]) > 0, f"{field!r} must not be empty"


def test_get_docs_policy_guide_fields_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, field in enumerate(response.json()["fields"]):
        assert isinstance(field, dict), f"fields[{i}] must be a dict"
        for required in _REQUIRED_FIELD_VIEW_FIELDS:
            assert required in field, f"fields[{i}] missing field: {required!r}"
            assert isinstance(field[required], str), f"fields[{i}].{required!r} must be str"
            assert field[required].strip(), f"fields[{i}].{required!r} must not be empty"


def test_get_docs_policy_guide_fields_range_is_str_or_none(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, field in enumerate(response.json()["fields"]):
        rng = field.get("range")
        assert rng is None or isinstance(rng, str), f"fields[{i}].range must be str or None"


def test_get_docs_policy_guide_field_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    field_ids = [f["fieldid"] for f in response.json()["fields"]]
    assert len(field_ids) == len(set(field_ids))


def test_get_docs_policy_guide_known_policy_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    field_ids = {f["fieldid"] for f in response.json()["fields"]}
    for expected in ("mode", "warnthreshold", "reviewthreshold", "blockthreshold"):
        assert expected in field_ids, f"expected policy field {expected!r} not found"


def test_get_docs_policy_guide_verdicts_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, verdict in enumerate(response.json()["verdicts"]):
        assert isinstance(verdict, dict), f"verdicts[{i}] must be a dict"
        for required in _REQUIRED_VERDICT_FIELDS:
            assert required in verdict, f"verdicts[{i}] missing field: {required!r}"
        assert isinstance(verdict["verdictid"], str)
        assert verdict["verdictid"].strip()
        assert isinstance(verdict["label"], str)
        assert verdict["label"].strip()
        assert isinstance(verdict["operationalbehavior"], str)
        assert verdict["operationalbehavior"].strip()
        assert isinstance(verdict["logsemitted"], bool)
        assert isinstance(verdict["executionheld"], bool)
        assert isinstance(verdict["reviewqueuedentry"], bool)
        assert isinstance(verdict["harddenied"], bool)
        assert isinstance(verdict["recommendedthresholdrange"], str)
        assert verdict["recommendedthresholdrange"].strip()


def test_get_docs_policy_guide_all_known_verdicts_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    verdict_ids = {v["verdictid"] for v in response.json()["verdicts"]}
    for expected in _KNOWN_VERDICT_IDS:
        assert expected in verdict_ids, f"expected verdict {expected!r} not found"


def test_get_docs_policy_guide_verdict_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    verdict_ids = [v["verdictid"] for v in response.json()["verdicts"]]
    assert len(verdict_ids) == len(set(verdict_ids))


def test_get_docs_policy_guide_block_verdict_is_hard_denied(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    block = next((v for v in response.json()["verdicts"] if v["verdictid"] == "block"), None)
    assert block is not None
    assert block["harddenied"] is True


def test_get_docs_policy_guide_allow_verdict_does_not_hold_execution(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    allow = next((v for v in response.json()["verdicts"] if v["verdictid"] == "allow"), None)
    assert allow is not None
    assert allow["executionheld"] is False
    assert allow["harddenied"] is False


def test_get_docs_policy_guide_quarantine_verdict_holds_execution(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    quarantine = next((v for v in response.json()["verdicts"] if v["verdictid"] == "quarantine"), None)
    assert quarantine is not None
    assert quarantine["executionheld"] is True


def test_get_docs_policy_guide_worked_examples_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["workedexamples"]):
        assert isinstance(example, dict), f"workedexamples[{i}] must be a dict"
        for required in _REQUIRED_WORKED_EXAMPLE_FIELDS:
            assert required in example, f"workedexamples[{i}] missing field: {required!r}"
        assert isinstance(example["exampleid"], str)
        assert example["exampleid"].strip()
        assert isinstance(example["title"], str)
        assert example["title"].strip()
        assert isinstance(example["scenario"], str)
        assert example["scenario"].strip()
        assert isinstance(example["requestsnapshot"], dict)
        assert isinstance(example["verdict"], str)
        assert example["verdict"].strip()
        assert isinstance(example["reason"], str)
        assert example["reason"].strip()
        assert isinstance(example["steps"], list)


def test_get_docs_policy_guide_worked_example_verdicts_are_known(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["workedexamples"]):
        assert example["verdict"] in _KNOWN_VERDICT_IDS, f"workedexamples[{i}].verdict {example['verdict']!r} is not a known verdict"


def test_get_docs_policy_guide_worked_example_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    example_ids = [e["exampleid"] for e in response.json()["workedexamples"]]
    assert len(example_ids) == len(set(example_ids))


def test_get_docs_policy_guide_worked_example_steps_shape(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["workedexamples"]):
        for j, step in enumerate(example["steps"]):
            assert isinstance(step, dict), f"workedexamples[{i}].steps[{j}] must be a dict"
            for required in _REQUIRED_EXAMPLE_STEP_FIELDS:
                assert required in step, f"workedexamples[{i}].steps[{j}] missing field: {required!r}"
                assert isinstance(step[required], str), f"workedexamples[{i}].steps[{j}].{required!r} must be str"
                assert step[required].strip(), f"workedexamples[{i}].steps[{j}].{required!r} must not be empty"


def test_get_docs_policy_guide_worked_examples_have_steps(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["workedexamples"]):
        assert len(example["steps"]) > 0, f"workedexamples[{i}] ({example['exampleid']!r}) must have at least one step"


def test_get_docs_policy_guide_worked_example_request_snapshot_has_actiontype(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, example in enumerate(response.json()["workedexamples"]):
        snapshot = example["requestsnapshot"]
        assert "actiontype" in snapshot, f"workedexamples[{i}].requestsnapshot missing 'actiontype'"


def test_get_docs_policy_guide_layers_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, layer in enumerate(response.json()["layers"]):
        assert isinstance(layer, dict), f"layers[{i}] must be a dict"
        for required in _REQUIRED_LAYER_FIELDS:
            assert required in layer, f"layers[{i}] missing field: {required!r}"
        assert isinstance(layer["layerid"], str)
        assert layer["layerid"].strip()
        assert isinstance(layer["priority"], int)
        assert layer["priority"] >= 1
        assert isinstance(layer["label"], str)
        assert layer["label"].strip()
        assert isinstance(layer["description"], str)
        assert layer["description"].strip()


def test_get_docs_policy_guide_layer_overriddenby_is_str_or_none(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, layer in enumerate(response.json()["layers"]):
        val = layer.get("overriddenby")
        assert val is None or isinstance(val, str), f"layers[{i}].overriddenby must be str or None"


def test_get_docs_policy_guide_layer_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    layer_ids = [lay["layerid"] for lay in response.json()["layers"]]
    assert len(layer_ids) == len(set(layer_ids))


def test_get_docs_policy_guide_layer_priorities_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    priorities = [lay["priority"] for lay in response.json()["layers"]]
    assert len(priorities) == len(set(priorities))


def test_get_docs_policy_guide_api_endpoints_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["apiendpoints"]):
        assert isinstance(endpoint, dict), f"apiendpoints[{i}] must be a dict"
        for required in _REQUIRED_API_ENDPOINT_FIELDS:
            assert required in endpoint, f"apiendpoints[{i}] missing field: {required!r}"
            assert isinstance(endpoint[required], str), f"apiendpoints[{i}].{required!r} must be str"
            assert endpoint[required].strip(), f"apiendpoints[{i}].{required!r} must not be empty"


def test_get_docs_policy_guide_api_endpoint_methods_are_valid_http(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["apiendpoints"]):
        assert endpoint["method"] in _VALID_HTTP_METHODS, f"apiendpoints[{i}].method {endpoint['method']!r} is not a valid HTTP method"


def test_get_docs_policy_guide_api_endpoint_paths_start_with_slash(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["apiendpoints"]):
        assert endpoint["path"].startswith("/"), f"apiendpoints[{i}].path must start with '/'"


def test_get_docs_policy_guide_api_endpoint_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    endpoint_ids = [e["endpointid"] for e in response.json()["apiendpoints"]]
    assert len(endpoint_ids) == len(set(endpoint_ids))


def test_get_docs_policy_guide_api_endpoints_contain_policy_status(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    endpoint_ids = {e["endpointid"] for e in response.json()["apiendpoints"]}
    assert "policy-status" in endpoint_ids


def test_get_docs_policy_guide_notes_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, note in enumerate(response.json()["notes"]):
        assert isinstance(note, str), f"notes[{i}] must be str"
        assert note.strip(), f"notes[{i}] must not be empty"


def test_get_docs_policy_guide_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code != 401
    assert response.status_code != 403


@pytest.mark.parametrize(
    "method",
    ["post", "put", "patch", "delete"],
)
def test_get_docs_policy_guide_non_get_methods_not_allowed(
    test_client: TestClient,
    method: str,
) -> None:
    response = getattr(test_client, method)(URL)
    assert response.status_code == 405
