from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.main import app as _app

_ROUTE = "/ui/request-context"


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(_app, raise_server_exceptions=True) as tc:
        yield tc


@pytest.fixture(scope="module")
def body(client: TestClient) -> dict:
    response = client.get(_ROUTE)
    assert response.status_code == 200, f"Expected 200 from {_ROUTE}, got {response.status_code}: {response.text}"
    return response.json()


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


def test_request_context_returns_200(client: TestClient) -> None:
    response = client.get(_ROUTE)
    assert response.status_code == 200


def test_request_context_has_status(body: dict) -> None:
    assert "status" in body


def test_request_context_status_is_ok(body: dict) -> None:
    assert body["status"] == "ok"


def test_request_context_has_service(body: dict) -> None:
    assert "service" in body


def test_request_context_service_is_string(body: dict) -> None:
    assert isinstance(body["service"], str)
    assert len(body["service"]) > 0


def test_request_context_has_timestamp(body: dict) -> None:
    assert "timestamp" in body


def test_request_context_timestamp_is_string(body: dict) -> None:
    assert isinstance(body["timestamp"], str)
    assert len(body["timestamp"]) > 0


def test_request_context_has_identity(body: dict) -> None:
    assert "identity" in body


def test_request_context_has_runtime(body: dict) -> None:
    assert "runtime" in body


def test_request_context_has_policy(body: dict) -> None:
    assert "policy" in body


def test_request_context_has_links(body: dict) -> None:
    assert "links" in body


def test_request_context_has_notes(body: dict) -> None:
    assert "notes" in body


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------


def test_identity_is_dict(body: dict) -> None:
    assert isinstance(body["identity"], dict)


def test_identity_has_client_id(body: dict) -> None:
    assert "client_id" in body["identity"]


def test_identity_has_session_id(body: dict) -> None:
    assert "session_id" in body["identity"]


def test_identity_has_actor_id(body: dict) -> None:
    assert "actor_id" in body["identity"]


def test_identity_has_request_id(body: dict) -> None:
    assert "request_id" in body["identity"]


def test_identity_has_trace_id(body: dict) -> None:
    assert "trace_id" in body["identity"]


def test_identity_has_metadata(body: dict) -> None:
    assert "metadata" in body["identity"]


def test_identity_metadata_is_dict(body: dict) -> None:
    assert isinstance(body["identity"]["metadata"], dict)


# ---------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------


def test_runtime_is_dict(body: dict) -> None:
    assert isinstance(body["runtime"], dict)


def test_runtime_has_environment(body: dict) -> None:
    assert "environment" in body["runtime"]


def test_runtime_environment_is_string(body: dict) -> None:
    assert isinstance(body["runtime"]["environment"], str)


def test_runtime_has_service_name(body: dict) -> None:
    assert "service_name" in body["runtime"]


def test_runtime_service_name_is_string(body: dict) -> None:
    assert isinstance(body["runtime"]["service_name"], str)


def test_runtime_has_api_version(body: dict) -> None:
    assert "api_version" in body["runtime"]


def test_runtime_has_security_mode(body: dict) -> None:
    assert "security_mode" in body["runtime"]


def test_runtime_has_timezone(body: dict) -> None:
    assert "timezone" in body["runtime"]


def test_runtime_has_metadata(body: dict) -> None:
    assert "metadata" in body["runtime"]


def test_runtime_metadata_is_dict(body: dict) -> None:
    assert isinstance(body["runtime"]["metadata"], dict)


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


def test_policy_is_dict(body: dict) -> None:
    assert isinstance(body["policy"], dict)


def test_policy_has_prompt_guard_enabled(body: dict) -> None:
    assert "prompt_guard_enabled" in body["policy"]


def test_policy_prompt_guard_enabled_is_bool(body: dict) -> None:
    assert isinstance(body["policy"]["prompt_guard_enabled"], bool)


def test_policy_has_action_guard_enabled(body: dict) -> None:
    assert "action_guard_enabled" in body["policy"]


def test_policy_action_guard_enabled_is_bool(body: dict) -> None:
    assert isinstance(body["policy"]["action_guard_enabled"], bool)


def test_policy_has_review_required(body: dict) -> None:
    assert "review_required" in body["policy"]


def test_policy_review_required_is_bool(body: dict) -> None:
    assert isinstance(body["policy"]["review_required"], bool)


def test_policy_has_default_verdict(body: dict) -> None:
    assert "default_verdict" in body["policy"]


def test_policy_default_verdict_is_string(body: dict) -> None:
    assert isinstance(body["policy"]["default_verdict"], str)


def test_policy_has_escalation_mode(body: dict) -> None:
    assert "escalation_mode" in body["policy"]


def test_policy_escalation_mode_is_string(body: dict) -> None:
    assert isinstance(body["policy"]["escalation_mode"], str)


def test_policy_has_metadata(body: dict) -> None:
    assert "metadata" in body["policy"]


def test_policy_metadata_is_dict(body: dict) -> None:
    assert isinstance(body["policy"]["metadata"], dict)


# ---------------------------------------------------------------------------
# links
# ---------------------------------------------------------------------------


def test_links_is_list(body: dict) -> None:
    assert isinstance(body["links"], list)


def test_links_is_non_empty(body: dict) -> None:
    assert len(body["links"]) >= 1


def test_links_items_have_label(body: dict) -> None:
    for link in body["links"]:
        assert "label" in link
        assert isinstance(link["label"], str)


def test_links_items_have_path(body: dict) -> None:
    for link in body["links"]:
        assert "path" in link
        assert isinstance(link["path"], str)


def test_links_items_have_description(body: dict) -> None:
    for link in body["links"]:
        assert "description" in link
        assert isinstance(link["description"], str)


# ---------------------------------------------------------------------------
# notes
# ---------------------------------------------------------------------------


def test_notes_is_list(body: dict) -> None:
    assert isinstance(body["notes"], list)


def test_notes_is_non_empty(body: dict) -> None:
    assert len(body["notes"]) >= 1


def test_notes_items_are_strings(body: dict) -> None:
    for note in body["notes"]:
        assert isinstance(note, str)


# ---------------------------------------------------------------------------
# idempotency
# ---------------------------------------------------------------------------


def test_request_context_is_idempotent(client: TestClient) -> None:
    r1 = client.get(_ROUTE).json()
    r2 = client.get(_ROUTE).json()
    assert r1["status"] == r2["status"]
    assert r1["service"] == r2["service"]
    assert r1["runtime"] == r2["runtime"]
    assert r1["policy"] == r2["policy"]
