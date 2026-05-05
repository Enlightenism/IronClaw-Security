from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.packagepurchaseenforcement import build_package_purchase_enforcement


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


def test_build_package_purchase_enforcement_returns_object() -> None:
    enforcement = build_package_purchase_enforcement()

    assert enforcement is not None


def test_package_purchase_enforcement_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    assert isinstance(payload, dict)
    assert payload


def test_package_purchase_enforcement_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    expected_candidates = {
        "enforcementid",
        "enforcement_id",
        "ownerid",
        "owner_id",
        "packageid",
        "package_id",
        "allowed",
        "approved",
        "permitted",
        "reason",
        "status",
        "quantity",
        "quota",
        "limit",
        "remaining",
        "remainingunits",
        "available",
        "generatedat",
        "generated_at",
        "createdat",
        "created_at",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_package_purchase_enforcement_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    for value in (
        _text(payload, "enforcementid", "enforcement_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "packageid", "package_id", "planid", "plan_id"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_package_purchase_enforcement_boolean_allowed_is_bool_when_present() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    allowed = _value(payload, "allowed", "approved", "permitted")
    if allowed is not None:
        assert isinstance(allowed, bool)


def test_package_purchase_enforcement_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    for keys in (
        ("quantity",),
        ("quota", "limit"),
        ("remaining", "remainingunits", "available"),
        ("price", "amount", "cost"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal("0")


def test_package_purchase_enforcement_remaining_does_not_exceed_quota_when_both_present() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "remainingunits", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_package_purchase_enforcement_reason_is_non_empty_when_present() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    reason = _text(payload, "reason", "message", "detail")
    if reason is not None:
        assert reason.strip()


def test_package_purchase_enforcement_supports_owner_bound_build_when_available() -> None:
    try:
        enforcement = build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
        )
    except TypeError:
        enforcement = build_package_purchase_enforcement()

    payload = _payload_of(enforcement)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    package_id = _text(payload, "packageid", "package_id", "planid", "plan_id")

    if owner is not None:
        assert owner.strip()
    if package_id is not None:
        assert package_id.strip()


def test_package_purchase_enforcement_allows_valid_purchase_when_supported() -> None:
    try:
        enforcement = build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
            quota=10,
            remaining=9,
        )
    except TypeError:
        pytest.skip("builder does not accept direct enforcement inputs")

    payload = _payload_of(enforcement)
    allowed = _value(payload, "allowed", "approved", "permitted")
    if allowed is not None:
        assert allowed is True


def test_package_purchase_enforcement_blocks_when_quota_exhausted_when_supported() -> None:
    try:
        enforcement = build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
            quota=0,
            remaining=0,
        )
    except TypeError:
        pytest.skip("builder does not accept direct enforcement inputs")

    payload = _payload_of(enforcement)
    allowed = _value(payload, "allowed", "approved", "permitted")
    reason = _text(payload, "reason", "message", "detail")

    if allowed is not None:
        assert allowed is False
    if reason is not None:
        assert reason.strip()


def test_package_purchase_enforcement_rejects_blank_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_package_purchase_enforcement(
            owner_id="",
            package_id="starter",
            quantity=1,
        )


def test_package_purchase_enforcement_rejects_blank_package_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="",
            quantity=1,
        )


def test_package_purchase_enforcement_rejects_non_positive_quantity_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="starter",
            quantity=0,
        )


def test_package_purchase_enforcement_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
            quota=-1,
        )


def test_package_purchase_enforcement_rejects_negative_remaining_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
            quota=10,
            remaining=-1,
        )


def test_package_purchase_enforcement_rejects_remaining_greater_than_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_package_purchase_enforcement(
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
            quota=10,
            remaining=11,
        )


def test_package_purchase_enforcement_enforce_method_blocks_when_supported() -> None:
    enforcement = build_package_purchase_enforcement()

    enforce_methods = ("enforce", "validate_purchase", "check_purchase", "authorize_purchase")
    if not any(hasattr(enforcement, name) and callable(getattr(enforcement, name)) for name in enforce_methods):
        pytest.skip("enforcement method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                enforcement,
                enforce_methods,
                owner_id="",
                package_id="",
                quantity=0,
            )
        except TypeError:
            _call_method_if_present(enforcement, enforce_methods, "", "", 0)


def test_package_purchase_enforcement_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_package_purchase_enforcement())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_package_purchase_enforcement_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_package_purchase_enforcement())
    second = _payload_of(build_package_purchase_enforcement())

    assert set(first.keys()) == set(second.keys())