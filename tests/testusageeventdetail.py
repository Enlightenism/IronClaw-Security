from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.usageeventdetail import build_usage_event_detail


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


def _number(payload: dict[str, Any], *keys: str) -> Decimal | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return Decimal(str(payload[key]))
    return None


def _text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return str(payload[key])
    return None


def _value(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def test_build_usage_event_detail_returns_object() -> None:
    detail = build_usage_event_detail(event_id="evt-001")

    assert detail is not None


def test_usage_event_detail_is_serializable_to_supported_shape() -> None:
    detail = build_usage_event_detail(event_id="evt-001")

    assert isinstance(detail, dict) or hasattr(detail, "as_dict") or hasattr(detail, "__dict__")


def test_usage_event_detail_serializes_to_non_empty_dict() -> None:
    payload = _payload_of(build_usage_event_detail(event_id="evt-001"))

    assert isinstance(payload, dict)
    assert payload


def test_usage_event_detail_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_usage_event_detail(event_id="evt-001"))
    expected_candidates = {
        "eventid",
        "event_id",
        "requestid",
        "request_id",
        "ownerkey",
        "owner_key",
        "route",
        "units",
        "timestamp",
        "createdat",
        "created_at",
        "status",
        "metadata",
    }

    assert set(payload.keys()).intersection(expected_candidates)


def test_usage_event_detail_event_identifier_matches_requested_when_present() -> None:
    requested_event_id = "evt-001"
    payload = _payload_of(build_usage_event_detail(event_id=requested_event_id))
    actual = _text(payload, "eventid", "event_id", "id")

    if actual is not None:
        assert actual == requested_event_id


def test_usage_event_detail_text_fields_are_non_empty_when_present() -> None:
    payload = _payload_of(build_usage_event_detail(event_id="evt-001"))

    for value in (
        _text(payload, "eventid", "event_id", "id"),
        _text(payload, "requestid", "request_id"),
        _text(payload, "ownerkey", "owner_key"),
        _text(payload, "route", "path"),
        _text(payload, "timestamp", "createdat", "created_at"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_usage_event_detail_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_usage_event_detail(event_id="evt-001"))

    for keys in (
        ("units", "requestedunits", "requested_units"),
        ("remainingunits", "remaining_units"),
        ("walletbalance", "wallet_balance"),
        ("riskscore", "risk_score"),
        ("latencyms", "latency_ms"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal("0")


def test_usage_event_detail_collections_use_json_friendly_shapes_when_present() -> None:
    payload = _payload_of(build_usage_event_detail(event_id="evt-001"))

    for key_group in (
        ("metadata", "details", "context"),
        ("tags", "matchedpatterns", "matched_patterns"),
        ("reasons", "signals"),
    ):
        value = _value(payload, *key_group)
        if value is not None:
            assert isinstance(value, (dict, list))


def test_usage_event_detail_reason_entries_are_strings_or_dicts_when_present() -> None:
    payload = _payload_of(build_usage_event_detail(event_id="evt-001"))
    reasons = _value(payload, "reasons", "signals")

    if isinstance(reasons, list):
        for item in reasons:
            assert isinstance(item, (str, dict))


def test_usage_event_detail_accepts_owner_context_when_supported() -> None:
    try:
        detail = build_usage_event_detail(event_id="evt-001", owner_key="owner-001")
    except TypeError:
        detail = build_usage_event_detail(event_id="evt-001")

    payload = _payload_of(detail)
    assert payload


def test_usage_event_detail_accepts_request_context_when_supported() -> None:
    try:
        detail = build_usage_event_detail(event_id="evt-001", request_id="req-001")
    except TypeError:
        detail = build_usage_event_detail(event_id="evt-001")

    payload = _payload_of(detail)
    request_id = _text(payload, "requestid", "request_id")

    if request_id is not None:
        assert request_id.strip()


def test_usage_event_detail_rejects_blank_event_id() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_event_detail(event_id="")


def test_usage_event_detail_rejects_none_event_id() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_event_detail(event_id=None)  # type: ignore[arg-type]


def test_usage_event_detail_rejects_blank_owner_key_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_event_detail(event_id="evt-001", owner_key="")


def test_usage_event_detail_rejects_blank_request_id_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_event_detail(event_id="evt-001", request_id="")


def test_usage_event_detail_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_usage_event_detail(event_id="evt-001"))

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_usage_event_detail_multiple_builds_have_stable_shape() -> None:
    first = _payload_of(build_usage_event_detail(event_id="evt-001"))
    second = _payload_of(build_usage_event_detail(event_id="evt-001"))

    assert set(first.keys()) == set(second.keys())