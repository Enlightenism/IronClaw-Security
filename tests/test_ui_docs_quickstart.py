from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

URL = "/ui/docs/quickstart"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "generatedat",
    "environment",
    "headline",
    "intro",
    "baseurl",
    "apikeyheadername",
    "steps",
    "sdkoptions",
    "keyendpoints",
    "checklist",
    "notes",
)

_REQUIRED_STEP_FIELDS = (
    "stepid",
    "title",
    "description",
)

_REQUIRED_SDK_FIELDS = (
    "sdkid",
    "name",
    "language",
    "installcommand",
    "samplecall",
)

_REQUIRED_ENDPOINT_FIELDS = (
    "label",
    "method",
    "path",
    "description",
)

_REQUIRED_CHECKLIST_FIELDS = (
    "itemid",
    "label",
    "completed",
)


def test_get_docs_quickstart_returns_200(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200


def test_get_docs_quickstart_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert "application/json" in response.headers.get("content-type", "")


def test_get_docs_quickstart_response_is_object(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_get_docs_quickstart_required_top_level_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        assert field in body, f"missing top-level field: {field!r}"


def test_get_docs_quickstart_scalar_fields_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in (
        "generatedat",
        "environment",
        "headline",
        "intro",
        "baseurl",
        "apikeyheadername",
    ):
        assert isinstance(body[field], str), f"{field!r} must be str"
        assert body[field].strip(), f"{field!r} must not be empty"


def test_get_docs_quickstart_list_fields_are_lists(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("steps", "sdkoptions", "keyendpoints", "checklist", "notes"):
        assert isinstance(body[field], list), f"{field!r} must be a list"


def test_get_docs_quickstart_list_fields_are_non_empty(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("steps", "sdkoptions", "keyendpoints", "checklist", "notes"):
        assert len(body[field]) > 0, f"{field!r} must not be empty"


def test_get_docs_quickstart_generatedat_is_iso8601(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    generatedat = response.json()["generatedat"]
    assert isinstance(generatedat, str)
    assert "T" in generatedat
    assert "Z" in generatedat or "+" in generatedat


def test_get_docs_quickstart_apikeyheadername_value(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["apikeyheadername"] == "X-API-Key"


def test_get_docs_quickstart_baseurl_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    baseurl = response.json()["baseurl"]
    assert isinstance(baseurl, str)
    assert baseurl.strip()


def test_get_docs_quickstart_steps_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    steps = response.json()["steps"]
    for i, step in enumerate(steps):
        assert isinstance(step, dict), f"steps[{i}] must be a dict"
        for field in _REQUIRED_STEP_FIELDS:
            assert field in step, f"steps[{i}] missing field: {field!r}"
            assert isinstance(step[field], str), f"steps[{i}].{field!r} must be str"
            assert step[field].strip(), f"steps[{i}].{field!r} must not be empty"


def test_get_docs_quickstart_steps_codeblock_is_str_or_none(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, step in enumerate(response.json()["steps"]):
        codeblock = step.get("codeblock")
        assert codeblock is None or isinstance(codeblock, str), f"steps[{i}].codeblock must be str or None"


def test_get_docs_quickstart_step_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    step_ids = [s["stepid"] for s in response.json()["steps"]]
    assert len(step_ids) == len(set(step_ids))


def test_get_docs_quickstart_sdkoptions_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    sdkoptions = response.json()["sdkoptions"]
    for i, sdk in enumerate(sdkoptions):
        assert isinstance(sdk, dict), f"sdkoptions[{i}] must be a dict"
        for field in _REQUIRED_SDK_FIELDS:
            assert field in sdk, f"sdkoptions[{i}] missing field: {field!r}"
            assert isinstance(sdk[field], str), f"sdkoptions[{i}].{field!r} must be str"
            assert sdk[field].strip(), f"sdkoptions[{i}].{field!r} must not be empty"


def test_get_docs_quickstart_sdk_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    sdk_ids = [s["sdkid"] for s in response.json()["sdkoptions"]]
    assert len(sdk_ids) == len(set(sdk_ids))


def test_get_docs_quickstart_keyendpoints_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    keyendpoints = response.json()["keyendpoints"]
    for i, endpoint in enumerate(keyendpoints):
        assert isinstance(endpoint, dict), f"keyendpoints[{i}] must be a dict"
        for field in _REQUIRED_ENDPOINT_FIELDS:
            assert field in endpoint, f"keyendpoints[{i}] missing field: {field!r}"
            assert isinstance(endpoint[field], str), f"keyendpoints[{i}].{field!r} must be str"
            assert endpoint[field].strip(), f"keyendpoints[{i}].{field!r} must not be empty"


def test_get_docs_quickstart_keyendpoints_methods_are_valid_http(
    test_client: TestClient,
) -> None:
    valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["keyendpoints"]):
        assert endpoint["method"] in valid_methods, f"keyendpoints[{i}].method {endpoint['method']!r} is not a valid HTTP method"


def test_get_docs_quickstart_keyendpoints_paths_start_with_slash(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, endpoint in enumerate(response.json()["keyendpoints"]):
        assert endpoint["path"].startswith("/"), f"keyendpoints[{i}].path must start with '/'"


def test_get_docs_quickstart_checklist_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    checklist = response.json()["checklist"]
    for i, item in enumerate(checklist):
        assert isinstance(item, dict), f"checklist[{i}] must be a dict"
        for field in _REQUIRED_CHECKLIST_FIELDS:
            assert field in item, f"checklist[{i}] missing field: {field!r}"
        assert isinstance(item["itemid"], str), f"checklist[{i}].itemid must be str"
        assert item["itemid"].strip(), f"checklist[{i}].itemid must not be empty"
        assert isinstance(item["label"], str), f"checklist[{i}].label must be str"
        assert item["label"].strip(), f"checklist[{i}].label must not be empty"
        assert isinstance(item["completed"], bool), f"checklist[{i}].completed must be bool"


def test_get_docs_quickstart_checklist_item_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    item_ids = [item["itemid"] for item in response.json()["checklist"]]
    assert len(item_ids) == len(set(item_ids))


def test_get_docs_quickstart_notes_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    notes = response.json()["notes"]
    for i, note in enumerate(notes):
        assert isinstance(note, str), f"notes[{i}] must be str"
        assert note.strip(), f"notes[{i}] must not be empty"


def test_get_docs_quickstart_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code != 401
    assert response.status_code != 403


@pytest.mark.parametrize(
    "method",
    ["post", "put", "patch", "delete"],
)
def test_get_docs_quickstart_non_get_methods_not_allowed(
    test_client: TestClient,
    method: str,
) -> None:
    response = getattr(test_client, method)(URL)
    assert response.status_code == 405


def test_get_docs_quickstart_steps_contain_create_key(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    step_ids = {s["stepid"] for s in response.json()["steps"]}
    assert "create-key" in step_ids


def test_get_docs_quickstart_sdkoptions_contain_python(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    sdk_ids = {s["sdkid"] for s in response.json()["sdkoptions"]}
    assert "python" in sdk_ids


def test_get_docs_quickstart_keyendpoints_contain_guard_action(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    paths = {e["path"] for e in response.json()["keyendpoints"]}
    assert "/guard/action" in paths
