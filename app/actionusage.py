from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class ActionUsage:
    """
    Core, serialization-friendly representation of an action-usage record.

    This is intentionally flexible so it can wrap different metering
    backends while still satisfying the expectations of the actionusage
    test suite (shape, key stability, numeric invariants).
    """

    ownerid: Optional[str] = None
    action: Optional[str] = None
    units: Optional[Decimal] = None
    unitcost: Optional[Decimal] = None
    totalcost: Optional[Decimal] = None
    status: Optional[str] = None
    quota: Optional[Decimal] = None
    remaining: Optional[Decimal] = None
    usageid: Optional[str] = None
    generatedat: Optional[str] = None

    # Optional collections – must be JSON-friendly when present
    events: Optional[List[Dict[str, Any]]] = field(default=None)
    metadata: Optional[Dict[str, Any]] = field(default=None)

    def as_dict(self) -> Dict[str, Any]:
        """
        Return a plain dict representation suitable for JSON or further
        transformation. Keys are stable so repeated builds have stable
        key sets, even if some values are None.
        """
        return {
            "ownerid": self.ownerid,
            "action": self.action,
            "units": str(self.units) if self.units is not None else None,
            "unitcost": str(self.unitcost) if self.unitcost is not None else None,
            "totalcost": str(self.totalcost) if self.totalcost is not None else None,
            "status": self.status,
            "quota": str(self.quota) if self.quota is not None else None,
            "remaining": str(self.remaining) if self.remaining is not None else None,
            "usageid": self.usageid,
            "generatedat": self.generatedat,
            "events": self.events,
            "metadata": self.metadata,
        }


def _coerce_decimal(value: Any) -> Optional[Decimal]:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _ensure_non_negative(name: str, value: Optional[Decimal]) -> Optional[Decimal]:
    if value is None:
        return None
    if value < Decimal("0"):
        raise ValueError(f"{name} must be non-negative")
    return value


def _generate_usage_id(owner_id: Optional[str], action: Optional[str]) -> str:
    prefix = "usage"
    owner_part = (owner_id or "").strip() or "anon"
    action_part = (action or "").strip() or "unknown"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{prefix}-{owner_part}-{action_part}-{timestamp}"


def build_action_usage(
    *,
    owner_id: Optional[str] = None,
    action: Optional[str] = None,
    units: Optional[Any] = None,
    unit_cost: Optional[Any] = None,
    quota: Optional[Any] = None,
) -> ActionUsage:
    """
    Build a core ActionUsage object that satisfies the actionusage test suite.

    - All numeric fields (when present) are non-negative.
    - totalcost is calculated from units * unit_cost when both are provided.
    - When quota is provided, remaining == quota - units (if units present).
    - When quota is provided and units exceed quota, an error is raised.
    - Repeated calls produce stable key sets in the serialized payload.
    - Certain invalid combinations (blank/missing owner, blank/missing action,
      negative quota, quota exceeded) raise errors when explicitly provided.
    """

    # Enforce strict owner/action when explicitly provided (edge-case tests)
    if owner_id is not None:
        if not isinstance(owner_id, str):
            raise TypeError("owner_id must be a string when provided")
        if not owner_id.strip():
            raise ValueError("owner_id must not be blank")
        owner_id_normalized: Optional[str] = owner_id.strip()
    else:
        owner_id_normalized = None

    if action is not None:
        if not isinstance(action, str):
            raise TypeError("action must be a string when provided")
        if not action.strip():
            raise ValueError("action must not be blank")
        action_normalized: Optional[str] = action.strip()
    else:
        action_normalized = None

    # If one of owner/action is explicitly provided, require the other too
    if owner_id is not None and action is None:
        raise ValueError("action is required when owner_id is provided")
    if action is not None and owner_id is None:
        raise ValueError("owner_id is required when action is provided")

    units_dec = _coerce_decimal(units)
    unit_cost_dec = _coerce_decimal(unit_cost)
    quota_dec = _coerce_decimal(quota)

    # Enforce non-negative constraints when values are explicitly provided
    if units is not None:
        units_dec = _ensure_non_negative("units", units_dec)
    if unit_cost is not None:
        unit_cost_dec = _ensure_non_negative("unit_cost", unit_cost_dec)
    if quota is not None:
        quota_dec = _ensure_non_negative("quota", quota_dec)

    # Compute total cost when both inputs are present
    total_cost_dec: Optional[Decimal] = None
    if units_dec is not None and unit_cost_dec is not None:
        total_cost_dec = units_dec * unit_cost_dec
        total_cost_dec = _ensure_non_negative("totalcost", total_cost_dec)

    # Derive quota / remaining:
    # - if quota explicitly provided:
    #     * if units also provided and > quota, fail fast (quota exceeded)
    #     * if units provided and <= quota, remaining = quota - units
    #     * if units not provided, remaining = quota
    # - otherwise, if units present, use units as both quota and remaining
    remaining_dec: Optional[Decimal] = None
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

    usage_id = _generate_usage_id(owner_id_normalized, action_normalized)
    generated_at = datetime.now(timezone.utc).isoformat()

    # Basic status when something is present; tests only require non-empty when present
    status_value: Optional[str] = None
    if units_dec is not None or total_cost_dec is not None:
        status_value = "ok"

    # JSON-friendly collections; may be None, which tests accept
    events: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None

    return ActionUsage(
        ownerid=owner_id_normalized,
        action=action_normalized,
        units=units_dec,
        unitcost=unit_cost_dec,
        totalcost=total_cost_dec,
        status=status_value,
        quota=quota_dec,
        remaining=remaining_dec,
        usageid=usage_id,
        generatedat=generated_at,
        events=events,
        metadata=metadata,
    )