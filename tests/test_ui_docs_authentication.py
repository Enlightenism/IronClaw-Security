from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

URL = "/ui/docs/authentication"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "generatedat",
    "headline",
    "intro",
    "header_name",
    "header_example",
    "key_naming",
    "scopes",
    "error_shapes",
    "rotation_steps",
    "ui_surfaces",
    "notes",
)

_REQUIRED_KEY_NAMING_FIELDS = (
    "prefix_pattern",
    "example_key",
    "description",
)

_REQUIRED_SCOPE_FIELDS = (
    "scope_id",
    "label",
    "description",
    "environments",
)

_REQUIRED_ERROR_SHAPE_FIELDS = (
    "http_status",
    "error_code",
    "condition",
    "example_body",
)

_REQUIRED_ROTATION_STEP_FIELDS = (
    "stepid",
    "label",
    "description",
)

_REQUIRED_UI_SURFACE_FIELDS = (
    "surface_id",
    "label",
    "path",
    "description",
)


def test_get_docs_authentication_returns_200(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200


def test_get_docs_authentication_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert "application/json" in response.headers.get("content-type", "")


def test_get_docs_authentication_response_is_object(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)


def test_get_docs_authentication_required_top_level_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        assert field in body, f"missing top-level field: {field!r}"


def test_get_docs_authentication_title_fields_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("generatedat", "headline", "intro", "header_name", "header_example"):
        assert isinstance(body[field], str), f"{field!r} must be str"
        assert body[field].strip(), f"{field!r} must not be empty"


def test_get_docs_authentication_sections_are_lists(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("scopes", "error_shapes", "rotation_steps", "ui_surfaces", "notes"):
        assert isinstance(body[field], list), f"{field!r} must be a list"


def test_get_docs_authentication_sections_are_non_empty(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("scopes", "error_shapes", "rotation_steps", "ui_surfaces", "notes"):
        assert len(body[field]) > 0, f"{field!r} must not be empty"


def test_get_docs_authentication_key_naming_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    key_naming = response.json()["key_naming"]
    assert isinstance(key_naming, dict)
    for field in _REQUIRED_KEY_NAMING_FIELDS:
        assert field in key_naming, f"key_naming missing field: {field!r}"
        assert isinstance(key_naming[field], str), f"key_naming.{field!r} must be str"
        assert key_naming[field].strip(), f"key_naming.{field!r} must not be empty"


def test_get_docs_authentication_scopes_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    scopes = response.json()["scopes"]
    for i, scope in enumerate(scopes):
        assert isinstance(scope, dict), f"scopes[{i}] must be a dict"
        for field in _REQUIRED_SCOPE_FIELDS:
            assert field in scope, f"scopes[{i}] missing field: {field!r}"
        assert isinstance(scope["environments"], list), f"scopes[{i}].environments must be list"


def test_get_docs_authentication_error_shapes_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    error_shapes = response.json()["error_shapes"]
    for i, shape in enumerate(error_shapes):
        assert isinstance(shape, dict), f"error_shapes[{i}] must be a dict"
        for field in _REQUIRED_ERROR_SHAPE_FIELDS:
            assert field in shape, f"error_shapes[{i}] missing field: {field!r}"
        assert isinstance(shape["http_status"], int), f"error_shapes[{i}].http_status must be int"
        assert isinstance(shape["example_body"], dict), f"error_shapes[{i}].example_body must be dict"


def test_get_docs_authentication_rotation_steps_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    rotation_steps = response.json()["rotation_steps"]
    for i, step in enumerate(rotation_steps):
        assert isinstance(step, dict), f"rotation_steps[{i}] must be a dict"
        for field in _REQUIRED_ROTATION_STEP_FIELDS:
            assert field in step, f"rotation_steps[{i}] missing field: {field!r}"
            assert isinstance(step[field], str), f"rotation_steps[{i}].{field!r} must be str"
            assert step[field].strip(), f"rotation_steps[{i}].{field!r} must not be empty"


def test_get_docs_authentication_ui_surfaces_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    ui_surfaces = response.json()["ui_surfaces"]
    for i, surface in enumerate(ui_surfaces):
        assert isinstance(surface, dict), f"ui_surfaces[{i}] must be a dict"
        for field in _REQUIRED_UI_SURFACE_FIELDS:
            assert field in surface, f"ui_surfaces[{i}] missing field: {field!r}"
            assert isinstance(surface[field], str), f"ui_surfaces[{i}].{field!r} must be str"
            assert surface[field].strip(), f"ui_surfaces[{i}].{field!r} must not be empty"


def test_get_docs_authentication_notes_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    notes = response.json()["notes"]
    for i, note in enumerate(notes):
        assert isinstance(note, str), f"notes[{i}] must be str"
        assert note.strip(), f"notes[{i}] must not be empty"


def test_get_docs_authentication_generatedat_is_iso8601(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    generatedat = response.json()["generatedat"]
    assert isinstance(generatedat, str)
    assert "T" in generatedat
    assert "Z" in generatedat or "+" in generatedat


def test_get_docs_authentication_header_name_is_x_api_key(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["header_name"] == "X-API-Key"


def test_get_docs_authentication_error_shapes_contain_401_and_403(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    statuses = {shape["http_status"] for shape in response.json()["error_shapes"]}
    assert 401 in statuses
    assert 403 in statuses


def test_get_docs_authentication_scope_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    scope_ids = [s["scope_id"] for s in response.json()["scopes"]]
    assert len(scope_ids) == len(set(scope_ids))


def test_get_docs_authentication_rotation_step_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    step_ids = [s["stepid"] for s in response.json()["rotation_steps"]]
    assert len(step_ids) == len(set(step_ids))


def test_get_docs_authentication_ui_surface_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    surface_ids = [s["surface_id"] for s in response.json()["ui_surfaces"]]
    assert len(surface_ids) == len(set(surface_ids))


def test_get_docs_authentication_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code != 401
    assert response.status_code != 403


@pytest.mark.parametrize(
    "method",
    ["post", "put", "patch", "delete"],
)
def test_get_docs_authentication_non_get_methods_not_allowed(
    test_client: TestClient,
    method: str,
) -> None:
    response = getattr(test_client, method)(URL)
    assert response.status_code == 405
