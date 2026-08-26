from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

__all__ = ["UsageMetering", "build_usage_metering"]


def _coerce_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _ensure_non_negative(name: str, value: Decimal | None) -> Decimal | None:
    if value is None:
        return None
    if value < Decimal(0):
        raise ValueError(f"{name} must be non-negative")
    return value


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass(slots=True)
class UsageMetering:
    ownerid: str | None = None
    meterid: str | None = None
    metric: str | None = None
    units: Decimal | None = None
    unitcost: Decimal | None = None
    totalcost: Decimal | None = None
    quota: Decimal | None = None
    remaining: Decimal | None = None
    window: str | None = None
    periodstart: str | None = None
    periodend: str | None = None
    events: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None
    generatedat: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ownerid": self.ownerid,
            "meterid": self.meterid,
            "metric": self.metric,
            "units": str(self.units) if self.units is not None else None,
            "unitcost": str(self.unitcost) if self.unitcost is not None else None,
            "totalcost": str(self.totalcost) if self.totalcost is not None else None,
            "quota": str(self.quota) if self.quota is not None else None,
            "remaining": str(self.remaining) if self.remaining is not None else None,
            "window": self.window,
            "periodstart": self.periodstart,
            "periodend": self.periodend,
            "events": self.events,
            "metadata": self.metadata,
            "generatedat": self.generatedat,
        }


def build_usage_metering(
    *,
    owner_id: str | None = None,
    meter_id: str | None = None,
    metric: str | None = None,
    units: Any | None = None,
    unit_cost: Any | None = None,
    quota: Any | None = None,
    window: str | None = None,
    period_start: str | None = None,
    period_end: str | None = None,
    events: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> UsageMetering:
    owner_value = _str_or_none(owner_id)
    meter_value = _str_or_none(meter_id)
    metric_value = _str_or_none(metric) if metric is not None else None

    if owner_id is not None and owner_value is None:
        raise ValueError("owner_id must not be blank")
    if meter_id is not None and meter_value is None:
        raise ValueError("meter_id must not be blank")
    if owner_id is not None and meter_id is None:
        raise ValueError("meter_id is required when owner_id is provided")
    if meter_id is not None and owner_id is None:
        raise ValueError("owner_id is required when meter_id is provided")

    units_dec = _coerce_decimal(units)
    unit_cost_dec = _coerce_decimal(unit_cost)
    quota_dec = _coerce_decimal(quota)

    if units is not None:
        units_dec = _ensure_non_negative("units", units_dec)
        if units_dec is None:
            raise TypeError("units must be numeric when provided")
    if unit_cost is not None:
        unit_cost_dec = _ensure_non_negative("unit_cost", unit_cost_dec)
        if unit_cost_dec is None:
            raise TypeError("unit_cost must be numeric when provided")
    if quota is not None:
        quota_dec = _ensure_non_negative("quota", quota_dec)
        if quota_dec is None:
            raise TypeError("quota must be numeric when provided")

    total_cost_dec: Decimal | None = None
    if units_dec is not None and unit_cost_dec is not None:
        total_cost_dec = units_dec * unit_cost_dec
        total_cost_dec = _ensure_non_negative("totalcost", total_cost_dec)

    remaining_dec: Decimal | None = None
    if quota_dec is not None:
        if units_dec is not None:
            if units_dec > quota_dec:
                raise ValueError("units exceed quota")
            remaining_dec = quota_dec - units_dec
        else:
            remaining_dec = quota_dec
    elif units_dec is not None:
        quota_dec = units_dec
        remaining_dec = units_dec

    if unit_cost is not None and unit_cost_dec is not None and units is not None and units_dec is None:
        raise TypeError("units must be numeric when unit_cost is present")

    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if window is not None:
        window = str(window).strip() or None
    if period_start is not None:
        period_start = str(period_start).strip() or None
    if period_end is not None:
        period_end = str(period_end).strip() or None

    payload_events = list(events) if events is not None else []
    payload_metadata = dict(metadata) if metadata is not None else {}

    return UsageMetering(
        ownerid=owner_value,
        meterid=meter_value,
        metric=metric_value,
        units=units_dec,
        unitcost=unit_cost_dec,
        totalcost=total_cost_dec,
        quota=quota_dec,
        remaining=remaining_dec,
        window=window,
        periodstart=period_start,
        periodend=period_end,
        events=payload_events,
        metadata=payload_metadata,
        generatedat=generated_at,
    )
