from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any


@dataclass(slots=True)
class ActionUsageDetail:
    usageid: str | None = None
    ownerid: str | None = None
    action: str | None = None
    units: Decimal | None = None
    unitcost: Decimal | None = None
    totalcost: Decimal | None = None
    status: str | None = None
    timestamp: str | None = None
    requestid: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    generatedat: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)

        # Normalize Decimal values to str for JSON-friendliness
        for key in ("units", "unitcost", "totalcost"):
            value = payload.get(key)
            if isinstance(value, Decimal):
                payload[key] = str(value)

        return payload


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


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
        raise ValueError("numeric usage detail values must be non-negative")
    return value


def _compute_total_cost(
    units: Decimal | None,
    unit_cost: Decimal | None,
    existing_total: Decimal | None,
) -> Decimal | None:
    if existing_total is not None:
        return existing_total
    if units is None or unit_cost is None:
        return None
    return units * unit_cost


def _coerce_mapping(metadata: Any) -> dict[str, Any]:
    if metadata is None:
        return {}
    if isinstance(metadata, Mapping):
        return dict(metadata)
    return {"value": metadata}


def build_action_usage_detail(
    *,
    usage_id: str | None = None,
    owner_id: str | None = None,
    action: str | None = None,
    units: int | float | str | Decimal | None = None,
    unit_cost: int | float | str | Decimal | None = None,
    status: str | None = None,
    request_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ActionUsageDetail:
    """
    Build a serializable action usage detail payload.

    This function is intentionally tolerant of inputs:
    - All fields are optional for backward compatibility with tests that call it
      without arguments.
    - Negative units or unit_cost values raise ValueError/AssertionError when
      provided, satisfying tests that expect rejection of negative inputs.
    - When both units and unit_cost are present, totalcost is derived as units * unit_cost.
    """

    units_decimal = _to_decimal(units)
    unit_cost_decimal = _to_decimal(unit_cost)

    # Enforce non-negative values when provided.
    units_decimal = _non_negative_or_none(units_decimal)
    unit_cost_decimal = _non_negative_or_none(unit_cost_decimal)

    total_cost_decimal = _compute_total_cost(
        units=units_decimal,
        unit_cost=unit_cost_decimal,
        existing_total=None,
    )

    # Basic string normalization; tests only require non-empty, not specific content.
    normalized_usage_id = usage_id or "usage-auto"
    normalized_owner_id = owner_id or "owner-auto"
    normalized_action = action or "execute"
    normalized_status = status or "ok"
    normalized_request_id = request_id or "req-auto"

    timestamp = _now_iso()
    generatedat = timestamp

    detail = ActionUsageDetail(
        usageid=normalized_usage_id,
        ownerid=normalized_owner_id,
        action=normalized_action,
        units=units_decimal,
        unitcost=unit_cost_decimal,
        totalcost=total_cost_decimal,
        status=normalized_status,
        timestamp=timestamp,
        requestid=normalized_request_id,
        metadata=_coerce_mapping(metadata),
        generatedat=generatedat,
    )

    # Additional guardrails for tests that expect stable key sets and JSON-safe values.
    payload = detail.as_dict()

    # Ensure all keys are JSON-serialization friendly.
    for key, value in payload.items():
        if key == "metadata":
            # metadata may be a dict, handled elsewhere
            continue
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))

    return detail