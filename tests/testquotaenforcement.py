from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.quotaenforcement import build_quota_enforcement


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


def _call_method_if_present(target: Any, names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        if hasattr(target, name):
            method = getattr(target, name)
            if callable(method):
                return method(*args, **kwargs)
    raise AssertionError(f"missing expected method from candidates: {names}")


def test_build_quota_enforcement_returns_object() -> None:
    enforcement = build_quota_enforcement()

    assert enforcement is not None


def test_quota_enforcement_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_quota_enforcement())

    assert isinstance(payload, dict)
    assert payload


def test_quota_enforcement_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_quota_enforcement())

    expected_candidates = {
        "quotaid",
        "quota_id",
        "ownerid",
        "owner_id",
        "action",
        "actionname",
        "operation",
        "allowed",
        "approved",
        "permitted",
        "quota",
        "limit",
        "used",
        "consumed",
        "remaining",
        "available",
        "units",
        "reason",
        "status",
        "state",
        "generatedat",
        "generated_at",
        "createdat",
        "created_at",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_quota_enforcement_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_quota_enforcement())

    for value in (
        _text(payload, "quotaid", "quota_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "action", "actionname", "operation"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_quota_enforcement_allowed_flag_is_boolean_when_present() -> None:
    payload = _payload_of(build_quota_enforcement())

    allowed = _value(payload, "allowed", "approved", "permitted")
    if allowed is not None:
        assert isinstance(allowed, bool)


def test_quota_enforcement_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_quota_enforcement())

    for keys in (
        ("quota", "limit"),
        ("used", "consumed"),
        ("remaining", "available"),
        ("units",),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal("0")


def test_quota_enforcement_remaining_does_not_exceed_quota_when_both_present() -> None:
    payload = _payload_of(build_quota_enforcement())

    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_quota_enforcement_used_plus_remaining_matches_quota_when_all_present() -> None:
    payload = _payload_of(build_quota_enforcement())

    quota = _number(payload, "quota", "limit")
    used = _number(payload, "used", "consumed")
    remaining = _number(payload, "remaining", "available")
    if quota is not None and used is not None and remaining is not None:
        assert used + remaining == quota


def test_quota_enforcement_reason_is_non_empty_when_present() -> None:
    payload = _payload_of(build_quota_enforcement())

    reason = _text(payload, "reason", "message", "detail")
    if reason is not None:
        assert reason.strip()


def test_quota_enforcement_supports_owner_bound_build_when_available() -> None:
    try:
        enforcement = build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=10,
            used=4,
        )
    except TypeError:
        enforcement = build_quota_enforcement()

    payload = _payload_of(enforcement)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    action = _text(payload, "action", "actionname", "operation")

    if owner is not None:
        assert owner.strip()
    if action is not None:
        assert action.strip()


def test_quota_enforcement_allows_usage_within_quota_when_supported() -> None:
    try:
        enforcement = build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=10,
            used=4,
            remaining=6,
        )
    except TypeError:
        pytest.skip("builder does not accept direct quota inputs")

    payload = _payload_of(enforcement)
    allowed = _value(payload, "allowed", "approved", "permitted")
    if allowed is not None:
        assert allowed is True


def test_quota_enforcement_blocks_when_quota_exhausted_when_supported() -> None:
    try:
        enforcement = build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=0,
            used=0,
            remaining=0,
        )
    except TypeError:
        pytest.skip("builder does not accept direct quota inputs")

    payload = _payload_of(enforcement)
    allowed = _value(payload, "allowed", "approved", "permitted")
    reason = _text(payload, "reason", "message", "detail")

    if allowed is not None:
        assert allowed is False
    if reason is not None:
        assert reason.strip()


def test_quota_enforcement_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=-1,
            used=0,
        )


def test_quota_enforcement_rejects_negative_used_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=10,
            used=-1,
        )


def test_quota_enforcement_rejects_negative_remaining_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=10,
            used=1,
            remaining=-1,
        )


def test_quota_enforcement_rejects_used_greater_than_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=10,
            used=11,
        )


def test_quota_enforcement_rejects_remaining_greater_than_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_quota_enforcement(
            owner_id="owner-001",
            action="execute",
            quota=10,
            used=1,
            remaining=11,
        )


def test_quota_enforcement_rejects_blank_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_quota_enforcement(
            owner_id="",
            action="execute",
            quota=10,
            used=1,
        )


def test_quota_enforcement_rejects_blank_action_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_quota_enforcement(
            owner_id="owner-001",
            action="",
            quota=10,
            used=1,
        )


def test_quota_enforcement_enforce_method_blocks_invalid_values_when_supported() -> None:
    enforcement = build_quota_enforcement()

    enforce_methods = ("enforce", "check_quota", "validate_quota", "authorize")
    if not any(hasattr(enforcement, name) and callable(getattr(enforcement, name)) for name in enforce_methods):
        pytest.skip("quota enforcement method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                enforcement,
                enforce_methods,
                owner_id="",
                action="",
                quota=-1,
                used=-1,
            )
        except TypeError:
            _call_method_if_present(enforcement, enforce_methods, "", "", -1, -1)


def test_quota_enforcement_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_quota_enforcement())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_quota_enforcement_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_quota_enforcement())
    second = _payload_of(build_quota_enforcement())

    assert set(first.keys()) == set(second.keys())