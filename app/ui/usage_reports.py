from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

try:
    from app.core.unit_wallet import UNIT_PACKAGE_CATALOG
except Exception:
    UNIT_PACKAGE_CATALOG: dict[str, Any] = {}

router = APIRouter(prefix="/usage-reports", tags=["usage-reports"])

# ---------------------------------------------------------------------------
# Supabase client (service-role, read-only — non-blocking)
# ---------------------------------------------------------------------------
try:
    from supabase import Client as SupabaseClient
    from supabase import create_client

    _SUPABASE_URL: str = os.environ["SUPABASE_URL"]
    _SUPABASE_SERVICE_ROLE_KEY: str = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    _supabase: SupabaseClient | None = create_client(_SUPABASE_URL, _SUPABASE_SERVICE_ROLE_KEY)
    _SUPABASE_AVAILABLE = True
except Exception:
    _supabase = None
    _SUPABASE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Canonical package/pricing constants — single source of truth
# ---------------------------------------------------------------------------
_TOKENS_PER_UNIT = 25_000
_ORDERED_PACKAGE_IDS = ["pkg_5000", "pkg_25000", "pkg_60000"]
_FEATURED_PACKAGE_ID = "pkg_25000"

_PRICING_FALLBACK: dict[str, tuple[int, float, str, str]] = {
    "pkg_5000": (
        5_000,
        20.00,
        "Starter",
        "5,000 units — $20.00",
    ),
    "pkg_25000": (
        25_000,
        90.00,
        "Team",
        "25,000 units — $90.00",
    ),
    "pkg_60000": (
        60_000,
        180.00,
        "Enterprise",
        "60,000 units — $180.00",
    ),
}


# ---------------------------------------------------------------------------
# Token → unit consumption logic
# 1 unit covers up to _TOKENS_PER_UNIT (25,000) tokens.
# Any overflow consumes one additional unit per 25,000-token chunk.
# ---------------------------------------------------------------------------
def _units_required_for_tokens(token_count: int) -> int:
    if token_count <= 0:
        return 0
    full_chunks, remainder = divmod(token_count, _TOKENS_PER_UNIT)
    return full_chunks + (1 if remainder > 0 else 0)


def _get_package_metadata(package_id: str) -> dict[str, Any]:
    package = UNIT_PACKAGE_CATALOG.get(package_id)
    if package is not None:
        price_usd = float(package["price_usd"])
        included_units = int(package["unit_amount"])
        name = str(package["name"])
        display_label = str(package.get("display_label", ""))
    else:
        fallback = _PRICING_FALLBACK.get(package_id)
        if fallback is None:
            return {}
        included_units, price_usd, name, display_label = fallback

    price_per_1k = round((price_usd / included_units) * 1_000, 4) if included_units > 0 else 0.0
    return {
        "package_id": package_id,
        "name": name,
        "display_label": display_label,
        "price_usd": price_usd,
        "price_display": f"${price_usd:.2f}",
        "included_units": included_units,
        "units_display": f"{included_units:,} units",
        "tokens_per_unit": _TOKENS_PER_UNIT,
        "max_tokens_covered": included_units * _TOKENS_PER_UNIT,
        "effective_price_per_1k_units": price_per_1k,
        "featured": package_id == _FEATURED_PACKAGE_ID,
    }


def _billing_catalog() -> dict[str, Any]:
    return {
        "featured_package_id": _FEATURED_PACKAGE_ID,
        "ordered_package_ids": list(_ORDERED_PACKAGE_IDS),
        "tokens_per_unit": _TOKENS_PER_UNIT,
        "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; " "additional units consumed in 25,000-token chunks."),
        "packages": {pkg_id: _get_package_metadata(pkg_id) for pkg_id in _ORDERED_PACKAGE_IDS},
    }


# ---------------------------------------------------------------------------
# Supabase data fetchers — all non-blocking, return safe defaults on failure
# ---------------------------------------------------------------------------
def _fetch_security_events(limit: int) -> list[dict[str, Any]]:
    if not _SUPABASE_AVAILABLE or _supabase is None:
        return []
    try:
        response = _supabase.table("security_events").select("id, user_id, verdict, units_used, platform, timestamp").order("timestamp", desc=True).limit(limit).execute()
        return response.data or []
    except Exception:
        return []


def _fetch_usage_summary(rows: list[dict[str, Any]], period: str, limit: int) -> UsageSummaryListView:
    if not rows:
        return _build_empty_summaries(period=period, limit=limit)

    total_requests = len(rows)
    total_blocked = sum(1 for r in rows if (r.get("verdict") or "").lower() == "block")
    total_warned = sum(1 for r in rows if (r.get("verdict") or "").lower() == "warn")
    total_quarantined = sum(1 for r in rows if (r.get("verdict") or "").lower() == "quarantine")
    total_allowed = sum(1 for r in rows if (r.get("verdict") or "").lower() == "allow")
    total_units = sum(int(r.get("units_used") or 0) for r in rows)
    unique_clients = len({r.get("user_id") for r in rows if r.get("user_id")})
    unique_sessions = len({r.get("platform") for r in rows if r.get("platform")})
    timestamps = [r.get("timestamp") for r in rows if r.get("timestamp")]
    period_start = min(timestamps) if timestamps else _utc_now_iso()
    period_end = max(timestamps) if timestamps else _utc_now_iso()

    item = UsageSummaryItemView(
        summary_id=f"usage-{period}-supabase",
        period_start=str(period_start),
        period_end=str(period_end),
        total_requests=total_requests,
        total_scans=total_requests,
        total_blocked=total_blocked,
        total_warned=total_warned,
        total_quarantined=total_quarantined,
        total_allowed=total_allowed,
        unique_clients=unique_clients,
        unique_sessions=unique_sessions,
        metadata={
            "period": period,
            "sampled": True,
            "limit": limit,
            "source": "supabase",
            "total_units_consumed": total_units,
            "total_tokens_covered": total_units * _TOKENS_PER_UNIT,
            "tokens_per_unit": _TOKENS_PER_UNIT,
            "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; " "additional units consumed in 25,000-token chunks."),
            "billing_catalog": _billing_catalog(),
        },
    )

    return UsageSummaryListView(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        period=period,
        limit=limit,
        items=[item],
        notes=[
            "Usage summaries are aggregated live from Supabase security_events.",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks.",
            "Billing packages: Starter $20 / 5,000 units · Team $90 / 25,000 units · Enterprise $180 / 60,000 units.",
        ],
    )


def _build_events_from_rows(rows: list[dict[str, Any]], limit: int) -> UsageEventListView:
    events: list[UsageEventView] = []
    for row in rows[:limit]:
        units_consumed = int(row.get("units_used") or 0)
        token_count = units_consumed * _TOKENS_PER_UNIT
        events.append(
            UsageEventView(
                event_id=str(row.get("id") or "unknown"),
                occurred_at=str(row.get("timestamp") or _utc_now_iso()),
                client_id=str(row.get("user_id") or "") or None,
                session_id=str(row.get("platform") or "") or None,
                action_type="scan",
                verdict=str(row.get("verdict") or "allow"),
                units_consumed=units_consumed,
                metadata={
                    "source": "supabase",
                    "tokens_covered": token_count,
                    "tokens_per_unit": _TOKENS_PER_UNIT,
                    "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; " "additional units consumed in 25,000-token chunks."),
                },
            )
        )

    return UsageEventListView(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        limit=limit,
        events=events,
        notes=[
            "Usage events are sourced live from Supabase security_events.",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks.",
        ],
    )


# ---------------------------------------------------------------------------
# Fallback builders (preserved for zero-row path)
# ---------------------------------------------------------------------------
def _build_empty_summaries(period: str, limit: int) -> UsageSummaryListView:
    items: list[UsageSummaryItemView] = [
        UsageSummaryItemView(
            summary_id=f"usage-{period}",
            period_start=_utc_now_iso(),
            period_end=_utc_now_iso(),
            total_requests=0,
            total_scans=0,
            total_blocked=0,
            total_warned=0,
            total_quarantined=0,
            total_allowed=0,
            unique_clients=0,
            unique_sessions=0,
            metadata={
                "period": period,
                "sampled": True,
                "limit": limit,
                "source": "fallback",
                "tokens_per_unit": _TOKENS_PER_UNIT,
                "billing_catalog": _billing_catalog(),
            },
        ),
    ]
    return UsageSummaryListView(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        period=period,
        limit=limit,
        items=items[:limit],
        notes=[
            "Usage summaries are aggregated from the underlying usage-reports API.",
            "This UI view provides a safe default zeroed snapshot when no data is available.",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks.",
            "Billing packages: Starter $20 / 5,000 units · Team $90 / 25,000 units · Enterprise $180 / 60,000 units.",
        ],
    )


def _build_empty_events(limit: int) -> UsageEventListView:
    return UsageEventListView(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        limit=limit,
        events=[],
        notes=[
            "Usage events are sourced from the usage-reports events API.",
            "This UI view intentionally returns an empty list when no recent events are present.",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks.",
        ],
    )


# ---------------------------------------------------------------------------
# Pydantic view models (all shapes preserved exactly)
# ---------------------------------------------------------------------------
def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class UsageSummaryItemView(BaseModel):
    summary_id: str
    period_start: str
    period_end: str
    total_requests: int
    total_scans: int
    total_blocked: int
    total_warned: int
    total_quarantined: int
    total_allowed: int
    unique_clients: int
    unique_sessions: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageSummaryListView(BaseModel):
    status: str
    service: str
    timestamp: str
    period: str
    limit: int
    items: list[UsageSummaryItemView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class UsageEventView(BaseModel):
    event_id: str
    occurred_at: str
    client_id: str | None = None
    session_id: str | None = None
    action_type: str
    verdict: str
    units_consumed: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventListView(BaseModel):
    status: str
    service: str
    timestamp: str
    limit: int
    events: list[UsageEventView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class UsageReportsResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    summaries: UsageSummaryListView
    events: UsageEventListView
    billing_catalog: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Route (path, query params, and response_model shape preserved exactly)
# ---------------------------------------------------------------------------
@router.get("", response_model=UsageReportsResponse)
def get_usage_reports(
    period: str = Query(default="24h", min_length=2, max_length=16),
    limit: int = Query(default=10, ge=1, le=100),
) -> UsageReportsResponse:
    rows = _fetch_security_events(limit=limit)

    if rows:
        summaries = _fetch_usage_summary(rows=rows, period=period, limit=limit)
        events = _build_events_from_rows(rows=rows, limit=limit)
    else:
        summaries = _build_empty_summaries(period=period, limit=limit)
        events = _build_empty_events(limit=limit)

    return UsageReportsResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summaries=summaries,
        events=events,
        billing_catalog=_billing_catalog(),
        notes=[
            "Usage reports UI provides a consolidated snapshot of recent security usage sourced from Supabase security_events.",
            "Billing packages: Starter $20 / 5,000 units · Team $90 / 25,000 units · Enterprise $180 / 60,000 units.",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks.",
            "For full historical exports, use the usage-reports API endpoints directly.",
        ],
    )
