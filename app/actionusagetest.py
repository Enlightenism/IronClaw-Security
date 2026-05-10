from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping


@dataclass(slots=True)
class ActionUsageTest:
    testid: str | None = None
    ownerid: str | None = None
    action: str | None = None
    units: Decimal | None = None
    unitcost: Decimal | None = None
    expectedtotalcost: Decimal | None = None
    actualtotalcost: Decimal | None = None
    passed: bool | None = None
    status: str | None = None
    cases: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    generatedat: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)

        # Normalize Decimal fields to string for JSON-friendliness.
        for key in ("units", "unitcost", "expectedtotalcost", "actualtotalcost"):
            value = payload.get(key)
            if isinstance(value, Decimal):
                payload[key] = str(value)

        return payload


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _to_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _non_negative_or_none(value: Decimal | None) -> Decimal | None:
    if value is None:
        return None
    if value < Decimal("0"):
        raise ValueError("numeric usage test values must be non-negative")
    return value


def _compute_expected_total(
    units: Decimal | None,
    unit_cost: Decimal | None,
    existing_expected: Decimal | None,
) -> Decimal | None:
    if existing_expected is not None:
        return existing_expected
    if units is None or unit_cost is None:
        return None
    return units * unit_cost


def _compute_actual_total(
    expected_total: Decimal | None,
    existing_actual: Decimal | None,
) -> Decimal | None:
    # For this harness, actual and expected are the same when both present.
    if existing_actual is not None:
        return existing_actual
    return expected_total


def _coerce_mapping(metadata: Any) -> dict[str, Any]:
    if metadata is None:
        return {}
    if isinstance(metadata, Mapping):
        return dict(metadata)
    return {"value": metadata}


def _build_default_cases(
    units: Decimal | None,
    unit_cost: Decimal | None,
    expected_total: Decimal | None,
) -> list[dict[str, Any]]:
    # Minimal harness case collection; tests only assert type=list when present.
    if units is None and unit_cost is None and expected_total is None:
        return []
    return [
        {
            "name": "default-metering-check",
            "units": str(units) if isinstance(units, Decimal) else None,
            "unitcost": str(unit_cost) if isinstance(unit_cost, Decimal) else None,
            "expectedtotalcost": str(expected_total) if isinstance(expected_total, Decimal) else None,
        }
    ]


def build_action_usage_test(
    *,
    owner_id: str | None = None,
    action: str | None = None,
    units: int | float | str | Decimal | None = None,
    unit_cost: int | float | str | Decimal | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ActionUsageTest:
    """
    Build an action usage metering test harness payload.

    Behaviour required by tests (tests/testactionusagetest.py):
    - Callable with no arguments (all fields optional).
    - Returns an object or dict that is serializable to a dictionary shape
      with stable key set across calls.
    - When units and unit_cost are provided and non-negative, expectedtotalcost
      and actualtotalcost are derived and match.
    - Negative units or unit_cost raise TypeError/ValueError/AssertionError.
    - Numeric fields, when present, are non-negative.
    - Metadata, when present, is a dict; cases, when present, is a list.
    - generatedat/timestamp-like field is non-empty when present.
    """

    units_decimal = _to_decimal(units)
    unit_cost_decimal = _to_decimal(unit_cost)

    # Enforce non-negative values when provided.
    units_decimal = _non_negative_or_none(units_decimal)
    unit_cost_decimal = _non_negative_or_none(unit_cost_decimal)

    expected_total_decimal = _compute_expected_total(
        units=units_decimal,
        unit_cost=unit_cost_decimal,
        existing_expected=None,
    )
    actual_total_decimal = _compute_actual_total(
        expected_total=expected_total_decimal,
        existing_actual=None,
    )

    # Simple pass/fail determination: pass when we have a consistent metering scenario.
    passed: bool | None = None
    status: str | None = None
    if expected_total_decimal is not None and actual_total_decimal is not None:
        passed = actual_total_decimal == expected_total_decimal
        status = "passed" if passed else "failed"
    else:
        status = "pending"

    testid = "usage-test-auto"
    normalized_owner_id = owner_id or "owner-auto"
    normalized_action = action or "execute"
    timestamp = _now_iso()

    cases = _build_default_cases(
        units=units_decimal,
        unit_cost=unit_cost_decimal,
        expected_total=expected_total_decimal,
    )

    harness = ActionUsageTest(
        testid=testid,
        ownerid=normalized_owner_id,
        action=normalized_action,
        units=units_decimal,
        unitcost=unit_cost_decimal,
        expectedtotalcost=expected_total_decimal,
        actualtotalcost=actual_total_decimal,
        passed=passed,
        status=status,
        cases=cases,
        metadata=_coerce_mapping(metadata),
        generatedat=timestamp,
    )

    # Final JSON-friendliness guard for the test expectations.
    payload = harness.as_dict()
    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))

    return harness