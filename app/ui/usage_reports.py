from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.core.billing import FEATURED_PACKAGE_ID as _FEATURED_PACKAGE_ID
from app.core.billing import UNIT_PACKAGE_IDS as _ORDERED_PACKAGE_IDS
from app.core.billing import resolve_package_id
from app.core.unit_wallet import TOKEN_CHUNK_SIZE, UNIT_PACKAGE_CATALOG

router = APIRouter(prefix="/ui/usage-reports", tags=["usage-reports"])


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
# Canonical package/pricing constants
# ---------------------------------------------------------------------------
_TOKENS_PER_UNIT = TOKEN_CHUNK_SIZE


def _package_pricing_summary() -> str:
    return " · ".join(f"{UNIT_PACKAGE_CATALOG[package_id]['name']} ${float(UNIT_PACKAGE_CATALOG[package_id]['price_usd']):.2f} / {int(UNIT_PACKAGE_CATALOG[package_id]['unit_amount']):,} units" for package_id in _ORDERED_PACKAGE_IDS if package_id in UNIT_PACKAGE_CATALOG)


def _get_package_metadata(package_id: str) -> dict[str, Any]:
    canonical_package_id = resolve_package_id(package_id)
    if canonical_package_id is None:
        return {}
    package = UNIT_PACKAGE_CATALOG[canonical_package_id]
    price_usd = float(package["price_usd"])
    included_units = int(package["unit_amount"])
    name = str(package["name"])
    display_label = str(package["display_label"])

    price_per_1k = round((price_usd / included_units) * 1_000, 4) if included_units > 0 else 0.0
    return {
        "package_id": canonical_package_id,
        "aliases": list(package["aliases"]),
        "name": name,
        "display_label": display_label,
        "price_usd": price_usd,
        "price_display": f"${price_usd:.2f}",
        "included_units": included_units,
        "units_display": f"{included_units:,} units",
        "tokens_per_unit": int(package["tokens_per_unit"]),
        "token_coverage": int(package["token_coverage"]),
        "tokens_in_wallet": int(package["token_coverage"]),
        "effective_price_per_1k_units": price_per_1k,
        "featured": bool(package["featured"]),
    }


def _billing_catalog() -> dict[str, Any]:
    return {
        "featured_package_id": _FEATURED_PACKAGE_ID,
        "ordered_package_ids": list(_ORDERED_PACKAGE_IDS),
        "tokens_per_unit": _TOKENS_PER_UNIT,
        "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks."),
        "packages": {pkg_id: _get_package_metadata(pkg_id) for pkg_id in _ORDERED_PACKAGE_IDS},
    }


# ---------------------------------------------------------------------------
# Supabase data fetchers
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
            "tokens_in_wallet": total_units * _TOKENS_PER_UNIT,
            "tokens_per_unit": _TOKENS_PER_UNIT,
            "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks."),
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
            f"Billing packages: {_package_pricing_summary()}.",
        ],
    )


def _build_events_from_rows(rows: list[dict[str, Any]], limit: int) -> UsageEventListView:
    events: list[UsageEventView] = []
    for row in rows[:limit]:
        units_consumed = int(row.get("units_used") or 0)
        tokens_in_wallet = units_consumed * _TOKENS_PER_UNIT
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
                    "tokens_in_wallet": tokens_in_wallet,
                    "tokens_per_unit": _TOKENS_PER_UNIT,
                    "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks."),
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
# Fallback builders
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
            f"Billing packages: {_package_pricing_summary()}.",
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
# Pydantic view models
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
# Route
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
            f"Billing packages: {_package_pricing_summary()}.",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks.",
            "For full historical exports, use the usage-reports API endpoints directly.",
        ],
    )
