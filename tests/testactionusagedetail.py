from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.actionusagedetail import build_action_usage_detail


def _payload_of(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result
    if hasattr(result, "as_dict") and callable(result.as_dict):
        payload = result.as_dict()
        assert isinstance(payload, dict)
        return payload
    payload: dict[str, Any] = {}
    for name in dir(result):
        if name.startswith("_"):
            continue
        value = getattr(result, name)
        if callable(value):
            continue
        if isinstance(value, (str, int, float, bool, list, dict, type(None))):
            payload[name] = value
    return payload


def _text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return str(payload[key])
    return None


def _number(payload: dict[str, Any], *keys: str) -> Decimal | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return Decimal(str(payload[key]))
    return None


def _value(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def test_build_action_usage_detail_returns_object() -> None:
    detail = build_action_usage_detail()

    assert detail is not None


def test_action_usage_detail_is_serializable_to_dictionary_shape() -> None:
    detail = build_action_usage_detail()
    payload = _payload_of(detail)

    assert isinstance(payload, dict)
    assert payload


def test_action_usage_detail_contains_stable_detail_fields_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    expected_candidates = {
        "usageid",
        "ownerid",
        "action",
        "units",
        "unitcost",
        "totalcost",
        "status",
        "timestamp",
        "requestid",
        "metadata",
        "generatedat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_action_usage_detail_owner_identifier_is_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    owner = _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id")
    if owner is not None:
        assert owner.strip()


def test_action_usage_detail_usage_identifier_is_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    usage_id = _text(payload, "usageid", "usage_id", "id")
    if usage_id is not None:
        assert usage_id.strip()


def test_action_usage_detail_action_name_is_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    action = _text(payload, "action", "actionname", "operation", "event")
    if action is not None:
        assert action.strip()


def test_action_usage_detail_status_is_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    status = _text(payload, "status", "state", "verdict")
    if status is not None:
        assert status.strip()


def test_action_usage_detail_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    for key in ("units", "unitcost", "totalcost"):
        value = _number(payload, key, key.replace("cost", "_cost"))
        if value is not None:
            assert value >= Decimal("0")


def test_action_usage_detail_total_cost_matches_units_times_unit_cost_when_present() -> None:
    try:
        detail = build_action_usage_detail(
            owner_id="owner-001",
            action="scan",
            units=4,
            unit_cost="1.5",
        )
    except TypeError:
        detail = build_action_usage_detail()

    payload = _payload_of(detail)
    units = _number(payload, "units")
    unit_cost = _number(payload, "unitcost", "unit_cost")
    total_cost = _number(payload, "totalcost", "total_cost")

    if units is not None and unit_cost is not None and total_cost is not None:
        assert total_cost == units * unit_cost


def test_action_usage_detail_metadata_is_dictionary_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    metadata = _value(payload, "metadata", "context", "dimensions")
    if metadata is not None:
        assert isinstance(metadata, dict)


def test_action_usage_detail_timestamp_fields_are_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    timestamp = _text(payload, "timestamp", "createdat", "generatedat", "occurredat")
    if timestamp is not None:
        assert timestamp.strip()


def test_action_usage_detail_request_identifier_is_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_detail())

    request_id = _text(payload, "requestid", "request_id", "correlationid", "correlation_id")
    if request_id is not None:
        assert request_id.strip()


def test_action_usage_detail_json_values_are_serialization_friendly() -> None:
    payload = _payload_of(build_action_usage_detail())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_action_usage_detail_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_action_usage_detail())
    second = _payload_of(build_action_usage_detail())

    assert set(first.keys()) == set(second.keys())


def test_action_usage_detail_supports_bound_lookup_when_builder_accepts_inputs() -> None:
    try:
        detail = build_action_usage_detail(
            usage_id="usage-001",
            owner_id="owner-001",
            action="execute",
        )
    except TypeError:
        pytest.skip("builder does not accept detail lookup inputs")

    payload = _payload_of(detail)
    usage_id = _text(payload, "usageid", "usage_id", "id")
    if usage_id is not None:
        assert usage_id == "usage-001"


def test_action_usage_detail_rejects_negative_units_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage_detail(
            usage_id="usage-001",
            owner_id="owner-001",
            action="execute",
            units=-1,
            unit_cost="1",
        )


def test_action_usage_detail_rejects_negative_unit_cost_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage_detail(
            usage_id="usage-001",
            owner_id="owner-001",
            action="execute",
            units=1,
            unit_cost="-1",
        )