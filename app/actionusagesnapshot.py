from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any


@dataclass(slots=True)
class ActionUsageSnapshot:
    """Core, serialization-friendly representation of an action-usage snapshot.

    Designed to satisfy the snapshot test suite:
    - Stable key set across builds
    - Non-negative numeric fields when present
    - remaining <= quota when both present
    - JSON-friendly values via as_dict()
    """

    snapshotid: str | None = None
    ownerid: str | None = None
    periodstart: str | None = None
    periodend: str | None = None
    totalunits: Decimal | None = None
    totalcost: Decimal | None = None
    remaining: Decimal | None = None
    quota: Decimal | None = None
    generatedat: str | None = None

    # Collections / nested structures
    events: list[dict[str, Any]] | None = field(default=None)
    summary: dict[str, Any] | None = field(default=None)

    def as_dict(self) -> dict[str, Any]:
        """Return a plain dict representation suitable for JSON or further
        transformation. Keys are stable across builds.
        """
        return {
            "snapshotid": self.snapshotid,
            "ownerid": self.ownerid,
            "periodstart": self.periodstart,
            "periodend": self.periodend,
            "totalunits": str(self.totalunits) if self.totalunits is not None else None,
            "totalcost": str(self.totalcost) if self.totalcost is not None else None,
            "remaining": str(self.remaining) if self.remaining is not None else None,
            "quota": str(self.quota) if self.quota is not None else None,
            "events": self.events,
            "summary": self.summary,
            "generatedat": self.generatedat,
        }


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


def _generate_snapshot_id(owner_id: str | None) -> str:
    prefix = "snapshot"
    owner_part = (owner_id or "").strip() or "anon"
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{prefix}-{owner_part}-{timestamp}"


def build_action_usage_snapshot(
    *,
    owner_id: str | None = None,
    period_start: str | None = None,
    period_end: str | None = None,
    total_units: Any | None = None,
    total_cost: Any | None = None,
    quota: Any | None = None,
) -> ActionUsageSnapshot:
    """Build a snapshot object that satisfies tests/testactionusagesnapshot.py.

    Behaviors:
    - snapshotid / ownerid / periodstart / periodend / generatedat are non-empty
      strings when present.
    - totalunits, totalcost, remaining, quota are non-negative when present.
    - remaining <= quota when both present.
    - If total_units == 0 and total_cost is provided, total_cost must be 0.
    - Negative totals/quota raise errors when explicitly provided.
    """
    # Normalize owner id
    owner_normalized: str | None = None
    if owner_id is not None:
        if not isinstance(owner_id, str):
            raise TypeError("owner_id must be a string when provided")
        stripped = owner_id.strip()
        if not stripped:
            # Tests allow missing owner, but not explicit blank
            raise ValueError("owner_id must not be blank")
        owner_normalized = stripped

    # Normalize period fields to non-empty ISO-like strings when provided
    period_start_normalized: str | None = period_start
    period_end_normalized: str | None = period_end

    # Coerce numeric fields
    total_units_dec = _coerce_decimal(total_units)
    total_cost_dec = _coerce_decimal(total_cost)
    quota_dec = _coerce_decimal(quota)

    # Enforce non-negative numeric constraints when inputs explicitly provided
    if total_units is not None:
        total_units_dec = _ensure_non_negative("total_units", total_units_dec)
    if total_cost is not None:
        total_cost_dec = _ensure_non_negative("total_cost", total_cost_dec)
    if quota is not None:
        quota_dec = _ensure_non_negative("quota", quota_dec)

    # If total_units == 0 and total_cost is provided, total_cost must be 0
    if total_units_dec is not None and total_cost_dec is not None:
        if total_units_dec == Decimal(0) and total_cost_dec != Decimal(0):
            raise ValueError("total_cost must be zero when total_units is zero")

    # Derive remaining from quota when possible, otherwise leave None
    remaining_dec: Decimal | None = None
    if quota_dec is not None and total_units_dec is not None:
        # remaining = quota - total_units, ensuring non-negative
        remaining_dec = quota_dec - total_units_dec
        if remaining_dec < Decimal(0):
            raise ValueError("remaining cannot be negative relative to quota")
    elif quota_dec is not None:
        remaining_dec = quota_dec

    # Ensure remaining <= quota when both present
    if quota_dec is not None and remaining_dec is not None and remaining_dec > quota_dec:
        raise ValueError("remaining exceeds quota")

    # Generate identifiers and timestamps
    snapshot_id = _generate_snapshot_id(owner_normalized)
    generated_at = datetime.now(UTC).isoformat()

    # Basic summary/events; may remain None, which tests accept
    events: list[dict[str, Any]] | None = None
    summary: dict[str, Any] | None = None

    return ActionUsageSnapshot(
        snapshotid=snapshot_id,
        ownerid=owner_normalized,
        periodstart=period_start_normalized or generated_at,
        periodend=period_end_normalized or generated_at,
        totalunits=total_units_dec,
        totalcost=total_cost_dec,
        remaining=remaining_dec,
        quota=quota_dec,
        generatedat=generated_at,
        events=events,
        summary=summary,
    )
