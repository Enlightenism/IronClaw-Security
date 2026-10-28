from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

URL = "/ui/docs/webhooks"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "generatedat",
    "headline",
    "intro",
    "registration",
    "eventtypes",
    "signature",
    "retry",
    "testingsteps",
    "notes",
)

_REQUIRED_REGISTRATION_FIELDS = (
    "adminendpoint",
    "method",
    "scope",
    "requiredfields",
    "optionalfields",
    "description",
    "examplerequest",
    "exampleresponse",
)

_REQUIRED_EVENT_TYPE_FIELDS = (
    "eventtypeid",
    "label",
    "trigger",
    "description",
    "payloadshape",
)

_REQUIRED_SIGNATURE_FIELDS = (
    "headername",
    "algorithm",
    "signingkeysource",
    "signingkeyformat",
    "signatureinput",
    "description",
    "verificationexamplepython",
    "verificationexamplecurl",
)

_REQUIRED_RETRY_FIELDS = (
    "maxretries",
    "initialbackoffseconds",
    "backoffmultiplier",
    "maxbackoffseconds",
    "failurestate",
    "successcriteria",
    "description",
)

_REQUIRED_TESTING_STEP_FIELDS = (
    "stepid",
    "label",
    "detail",
)

_KNOWN_EVENT_TYPE_IDS = {
    "scan_verdict_issued",
    "quarantine_triggered",
    "policy_violation_recorded",
}

_REQUIRED_PAYLOAD_TOP_KEYS = {
    "ironclaw_event",
    "ironclaw_delivery_id",
    "ironclaw_timestamp",
    "ironclaw_webhook_id",
    "data",
}

_VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def test_get_docs_webhooks_returns_200(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200


def test_get_docs_webhooks_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert "application/json" in response.headers.get("content-type", "")


def test_get_docs_webhooks_response_is_object(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_get_docs_webhooks_required_top_level_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        assert field in body, f"missing top-level field: {field!r}"


def test_get_docs_webhooks_scalar_fields_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("generatedat", "headline", "intro"):
        assert isinstance(body[field], str), f"{field!r} must be str"
        assert body[field].strip(), f"{field!r} must not be empty"


def test_get_docs_webhooks_generatedat_is_iso8601(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    generatedat = response.json()["generatedat"]
    assert isinstance(generatedat, str)
    assert "T" in generatedat
    assert "Z" in generatedat or "+" in generatedat


def test_get_docs_webhooks_list_fields_are_lists(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("eventtypes", "testingsteps", "notes"):
        assert isinstance(body[field], list), f"{field!r} must be a list"


def test_get_docs_webhooks_list_fields_are_non_empty(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("eventtypes", "testingsteps", "notes"):
        assert len(body[field]) > 0, f"{field!r} must not be empty"


def test_get_docs_webhooks_object_fields_are_dicts(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("registration", "signature", "retry"):
        assert isinstance(body[field], dict), f"{field!r} must be a dict"


def test_get_docs_webhooks_registration_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    registration = response.json()["registration"]
    for required in _REQUIRED_REGISTRATION_FIELDS:
        assert required in registration, f"registration missing field: {required!r}"
    assert isinstance(registration["adminendpoint"], str)
    assert registration["adminendpoint"].startswith("/")
    assert isinstance(registration["method"], str)
    assert registration["method"] in _VALID_HTTP_METHODS
    assert isinstance(registration["scope"], str)
    assert registration["scope"].strip()
    assert isinstance(registration["requiredfields"], list)
    assert len(registration["requiredfields"]) > 0
    assert isinstance(registration["optionalfields"], list)
    assert isinstance(registration["description"], str)
    assert registration["description"].strip()
    assert isinstance(registration["examplerequest"], dict)
    assert isinstance(registration["exampleresponse"], dict)


def test_get_docs_webhooks_registration_required_fields_are_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, field in enumerate(response.json()["registration"]["requiredfields"]):
        assert isinstance(field, str), f"registration.requiredfields[{i}] must be str"
        assert field.strip()


def test_get_docs_webhooks_registration_optional_fields_are_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, field in enumerate(response.json()["registration"]["optionalfields"]):
        assert isinstance(field, str), f"registration.optionalfields[{i}] must be str"
        assert field.strip()


def test_get_docs_webhooks_registration_example_request_has_url_and_events(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    req = response.json()["registration"]["examplerequest"]
    assert "url" in req
    assert "events" in req
    assert isinstance(req["events"], list)
    assert len(req["events"]) > 0


def test_get_docs_webhooks_registration_example_response_has_webhookid(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    resp = response.json()["registration"]["exampleresponse"]
    assert "webhookid" in resp
    assert isinstance(resp["webhookid"], str)
    assert resp["webhookid"].strip()


def test_get_docs_webhooks_event_types_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, event_type in enumerate(response.json()["eventtypes"]):
        assert isinstance(event_type, dict), f"eventtypes[{i}] must be a dict"
        for required in _REQUIRED_EVENT_TYPE_FIELDS:
            assert required in event_type, f"eventtypes[{i}] missing field: {required!r}"
        assert isinstance(event_type["eventtypeid"], str)
        assert event_type["eventtypeid"].strip()
        assert isinstance(event_type["label"], str)
        assert event_type["label"].strip()
        assert isinstance(event_type["trigger"], str)
        assert event_type["trigger"].strip()
        assert isinstance(event_type["description"], str)
        assert event_type["description"].strip()
        assert isinstance(event_type["payloadshape"], dict)


def test_get_docs_webhooks_event_type_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    event_type_ids = [e["eventtypeid"] for e in response.json()["eventtypes"]]
    assert len(event_type_ids) == len(set(event_type_ids))


def test_get_docs_webhooks_all_known_event_types_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    event_type_ids = {e["eventtypeid"] for e in response.json()["eventtypes"]}
    for expected in _KNOWN_EVENT_TYPE_IDS:
        assert expected in event_type_ids, f"expected event type {expected!r} not found in eventtypes"


def test_get_docs_webhooks_event_type_payloads_have_envelope_keys(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, event_type in enumerate(response.json()["eventtypes"]):
        payload = event_type["payloadshape"]
        for required_key in _REQUIRED_PAYLOAD_TOP_KEYS:
            assert required_key in payload, f"eventtypes[{i}].payloadshape missing key: {required_key!r}"


def test_get_docs_webhooks_event_type_payloads_ironclaw_event_matches_id(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, event_type in enumerate(response.json()["eventtypes"]):
        payload = event_type["payloadshape"]
        assert payload["ironclaw_event"] == event_type["eventtypeid"], f"eventtypes[{i}].payloadshape.ironclaw_event must match eventtypeid"


def test_get_docs_webhooks_event_type_payloads_data_is_dict(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, event_type in enumerate(response.json()["eventtypes"]):
        assert isinstance(event_type["payloadshape"]["data"], dict), f"eventtypes[{i}].payloadshape.data must be a dict"


def test_get_docs_webhooks_scan_verdict_payload_has_verdict_field(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    scan_event = next(
        (e for e in response.json()["eventtypes"] if e["eventtypeid"] == "scan_verdict_issued"),
        None,
    )
    assert scan_event is not None
    assert "verdict" in scan_event["payloadshape"]["data"]
    assert "block" in scan_event["trigger"].lower()
    assert "warn" not in scan_event["trigger"].lower()
    assert "quarantine verdict" not in scan_event["trigger"].lower()


def test_get_docs_webhooks_quarantine_payload_has_quarantineid(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    quar_event = next(
        (e for e in response.json()["eventtypes"] if e["eventtypeid"] == "quarantine_triggered"),
        None,
    )
    assert quar_event is not None
    assert "quarantineid" in quar_event["payloadshape"]["data"]
    assert "final verdict remains block" in quar_event["description"].lower()


def test_get_docs_webhooks_policy_violation_payload_has_matchedruleid(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    policy_event = next(
        (e for e in response.json()["eventtypes"] if e["eventtypeid"] == "policy_violation_recorded"),
        None,
    )
    assert policy_event is not None
    assert "matchedruleid" in policy_event["payloadshape"]["data"]


def test_get_docs_webhooks_signature_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    signature = response.json()["signature"]
    for required in _REQUIRED_SIGNATURE_FIELDS:
        assert required in signature, f"signature missing field: {required!r}"
    for str_field in (
        "headername",
        "algorithm",
        "signingkeysource",
        "signingkeyformat",
        "signatureinput",
        "description",
        "verificationexamplepython",
        "verificationexamplecurl",
    ):
        assert isinstance(signature[str_field], str), f"signature.{str_field!r} must be str"
        assert signature[str_field].strip(), f"signature.{str_field!r} must not be empty"


def test_get_docs_webhooks_signature_headername_is_ironclaw(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["signature"]["headername"] == "X-IronClaw-Signature-256"


def test_get_docs_webhooks_signature_algorithm_is_hmac_sha256(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["signature"]["algorithm"] == "HMAC-SHA256"


def test_get_docs_webhooks_signature_python_example_contains_hmac(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    python_example = response.json()["signature"]["verificationexamplepython"]
    assert "hmac" in python_example.lower()
    assert "sha256" in python_example.lower()


def test_get_docs_webhooks_retry_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    retry = response.json()["retry"]
    for required in _REQUIRED_RETRY_FIELDS:
        assert required in retry, f"retry missing field: {required!r}"
    assert isinstance(retry["maxretries"], int)
    assert retry["maxretries"] > 0
    assert isinstance(retry["initialbackoffseconds"], int)
    assert retry["initialbackoffseconds"] > 0
    assert isinstance(retry["backoffmultiplier"], float)
    assert retry["backoffmultiplier"] > 1.0
    assert isinstance(retry["maxbackoffseconds"], int)
    assert retry["maxbackoffseconds"] >= retry["initialbackoffseconds"]
    assert isinstance(retry["failurestate"], str)
    assert retry["failurestate"].strip()
    assert isinstance(retry["successcriteria"], str)
    assert retry["successcriteria"].strip()
    assert isinstance(retry["description"], str)
    assert retry["description"].strip()


def test_get_docs_webhooks_retry_max_backoff_gte_initial_backoff(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    retry = response.json()["retry"]
    assert retry["maxbackoffseconds"] >= retry["initialbackoffseconds"]


def test_get_docs_webhooks_retry_backoff_multiplier_greater_than_one(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["retry"]["backoffmultiplier"] > 1.0


def test_get_docs_webhooks_retry_success_criteria_mentions_2xx(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert "2xx" in response.json()["retry"]["successcriteria"]


def test_get_docs_webhooks_testing_steps_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, step in enumerate(response.json()["testingsteps"]):
        assert isinstance(step, dict), f"testingsteps[{i}] must be a dict"
        for required in _REQUIRED_TESTING_STEP_FIELDS:
            assert required in step, f"testingsteps[{i}] missing field: {required!r}"
        assert isinstance(step["stepid"], str)
        assert step["stepid"].strip()
        assert isinstance(step["label"], str)
        assert step["label"].strip()
        assert isinstance(step["detail"], str)
        assert step["detail"].strip()


def test_get_docs_webhooks_testing_step_codeblock_is_str_or_none(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, step in enumerate(response.json()["testingsteps"]):
        codeblock = step.get("codeblock")
        assert codeblock is None or isinstance(codeblock, str), f"testingsteps[{i}].codeblock must be str or None"


def test_get_docs_webhooks_testing_step_ids_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    step_ids = [s["stepid"] for s in response.json()["testingsteps"]]
    assert len(step_ids) == len(set(step_ids))


def test_get_docs_webhooks_testing_steps_have_at_least_one_with_codeblock(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    steps_with_code = [s for s in response.json()["testingsteps"] if s.get("codeblock")]
    assert len(steps_with_code) > 0


def test_get_docs_webhooks_notes_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, note in enumerate(response.json()["notes"]):
        assert isinstance(note, str), f"notes[{i}] must be str"
        assert note.strip(), f"notes[{i}] must not be empty"


def test_get_docs_webhooks_notes_mention_https(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    notes_text = " ".join(response.json()["notes"]).lower()
    assert "https" in notes_text


def test_get_docs_webhooks_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code != 401
    assert response.status_code != 403


@pytest.mark.parametrize(
    "method",
    ["post", "put", "patch", "delete"],
)
def test_get_docs_webhooks_non_get_methods_not_allowed(
    test_client: TestClient,
    method: str,
) -> None:
    response = getattr(test_client, method)(URL)
    assert response.status_code == 405
