from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.actionusage import build_action_usage
from app.core.billing import FEATURED_PACKAGE_ID as _FEATURED_PACKAGE_ID
from app.core.billing import UNIT_PACKAGE_IDS as _ORDERED_PACKAGE_IDS
from app.core.billing import resolve_package_id
from app.core.unit_wallet import TOKEN_CHUNK_SIZE as _TOKENS_PER_UNIT
from app.core.unit_wallet import UNIT_PACKAGE_CATALOG, units_required_for_tokens
from app.unitwallet import build_unit_wallet

router = APIRouter(prefix="/ui/usage", tags=["ui-usage"])

# ---------------------------------------------------------------------------
# Supabase client (service-role, read-only enrichment — non-blocking)
# ---------------------------------------------------------------------------
try:
    from supabase import Client as SupabaseClient
    from supabase import create_client

    _SUPABASE_URL: str = os.environ["SUPABASE_URL"]
    _SUPABASE_SERVICE_KEY: str = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    _supabase: SupabaseClient = create_client(_SUPABASE_URL, _SUPABASE_SERVICE_KEY)
    _SUPABASE_AVAILABLE = True
except Exception:
    _supabase = None  # type: ignore[assignment]
    _SUPABASE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Canonical package/pricing values are derived from app.core.billing.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Token → unit consumption logic
# 1 unit covers up to _TOKENS_PER_UNIT tokens.
# Any overflow consumes one additional unit per token chunk.
# ---------------------------------------------------------------------------
def _units_required_for_tokens(token_count: int) -> int:
    return units_required_for_tokens(token_count)


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
        "max_tokens_covered": int(package["token_coverage"]),
        "effective_price_per_1k_units": price_per_1k,
        "featured": bool(package["featured"]),
    }


def _package_pricing_summary() -> str:
    pricing: list[str] = []
    for package_id in _ORDERED_PACKAGE_IDS:
        package = UNIT_PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue
        pricing.append(
            f"{package['name']}: ${float(package['price_usd']):.2f} / {int(package['unit_amount']):,} units",
        )
    return " · ".join(pricing)


# ---------------------------------------------------------------------------
# Supabase usage enrichment — queries security_events for real unit consumption
# Non-blocking: returns safe defaults on any failure
# ---------------------------------------------------------------------------
def _fetch_supabase_usage() -> dict[str, Any]:
    if not _SUPABASE_AVAILABLE or _supabase is None:
        return {}
    try:
        result = _supabase.table("security_events").select("user_id, units_used, verdict, timestamp").order("timestamp", desc=True).limit(500).execute()
        rows: list[dict[str, Any]] = result.data or []
        total_units = sum(int(r.get("units_used") or 0) for r in rows)
        total_requests = len(rows)
        total_blocks = sum(1 for r in rows if r.get("verdict") == "block")
        total_warnings = sum(1 for r in rows if r.get("verdict") == "warn")
        last_event_at: str | None = rows[0].get("timestamp") if rows else None
        total_tokens_covered = total_units * _TOKENS_PER_UNIT
        return {
            "source": "supabase",
            "total_units_consumed": total_units,
            "total_requests": total_requests,
            "total_blocks": total_blocks,
            "total_warnings": total_warnings,
            "last_event_at": last_event_at,
            "total_tokens_covered": total_tokens_covered,
            "tokens_per_unit": _TOKENS_PER_UNIT,
        }
    except Exception:
        return {"source": "supabase-error"}


def _fetch_supabase_wallet() -> dict[str, Any]:
    if not _SUPABASE_AVAILABLE or _supabase is None:
        return {}
    try:
        result = _supabase.table("users").select("id, email, wallet_units, has_paid, last_payment").limit(1).execute()
        rows: list[dict[str, Any]] = result.data or []
        if not rows:
            return {}
        row = rows[0]
        wallet_units: int = int(row.get("wallet_units") or 0)
        has_paid: bool = bool(row.get("has_paid", False))
        last_payment: dict[str, Any] = row.get("last_payment") or {}
        active_package_id = resolve_package_id(str(last_payment.get("package_id") or "")) or _FEATURED_PACKAGE_ID
        pkg_meta = _get_package_metadata(active_package_id)
        return {
            "source": "supabase",
            "wallet_units": wallet_units,
            "has_paid": has_paid,
            "active_package_id": active_package_id,
            "active_package": pkg_meta,
            "max_tokens_covered": wallet_units * _TOKENS_PER_UNIT,
            "tokens_per_unit": _TOKENS_PER_UNIT,
        }
    except Exception:
        return {"source": "supabase-error"}


# ---------------------------------------------------------------------------
# HTML scaffold (preserved exactly)
# ---------------------------------------------------------------------------
def _render_html(title: str, body_content: str) -> str:
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>{title}</title>
</head>
<body data-usage="true">
    <header>
        <h1>{title}</h1>
    </header>
    <main>
        {body_content}
    </main>
</body>
</html>
""".strip()


# ---------------------------------------------------------------------------
# Routes (all route paths, response classes, and HTML contracts preserved)
# ---------------------------------------------------------------------------
@router.get("", response_class=HTMLResponse)
async def usage_root(request: Request) -> HTMLResponse:
    """Fallback usage UI landing page."""
    wallet = build_unit_wallet()
    usage = build_action_usage()
    sb_wallet = _fetch_supabase_wallet()
    sb_usage = _fetch_supabase_usage()

    sb_units = sb_usage.get("total_units_consumed", 0)
    sb_wallet_units = sb_wallet.get("wallet_units", 0)
    sb_tokens = sb_usage.get("total_tokens_covered", 0)
    pkg_rows = "".join(f"<li>{_get_package_metadata(pid).get('display_label', pid)} — tokens_per_unit: {_TOKENS_PER_UNIT:,}</li>" for pid in _ORDERED_PACKAGE_IDS)
    package_pricing = _package_pricing_summary()

    html = _render_html(
        "Usage Overview",
        f"""
<section>
    <p>Usage summary for current owner.</p>
    <ul>
        <li>usage</li>
        <li>units</li>
        <li>quota</li>
        <li>remaining</li>
        <li>billing</li>
        <li>summary</li>
        <li>owner</li>
    </ul>
    <div>
        <strong>Wallet balance:</strong> {wallet.as_dict().get("balance", "0")}
    </div>
    <div>
        <strong>Usage units:</strong> {usage.as_dict().get("units", "0")}
    </div>
    <div>
        <strong>Live wallet units (Supabase):</strong> {sb_wallet_units:,}
    </div>
    <div>
        <strong>Live units consumed (Supabase):</strong> {sb_units:,}
    </div>
    <div>
        <strong>Tokens covered:</strong> {sb_tokens:,}
        (1 unit = {_TOKENS_PER_UNIT:,} tokens; additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks)
    </div>
    <ul>
        <li>Packages: {package_pricing}</li>
        {pkg_rows}
    </ul>
</section>
""",
    )
    return HTMLResponse(content=html)


@router.get("/reports", response_class=HTMLResponse)
async def usage_reports(request: Request) -> HTMLResponse:
    """Reports view."""
    usage = build_action_usage()
    payload = usage.as_dict()
    sb_usage = _fetch_supabase_usage()

    sb_units = sb_usage.get("total_units_consumed", 0)
    sb_requests = sb_usage.get("total_requests", 0)
    sb_blocks = sb_usage.get("total_blocks", 0)
    sb_warnings = sb_usage.get("total_warnings", 0)
    sb_tokens = sb_usage.get("total_tokens_covered", 0)
    pkg_rows = "".join(
        f"""<tr>
            <td>{_get_package_metadata(pid).get("name", pid)}</td>
            <td>{_get_package_metadata(pid).get("display_label", "")}</td>
            <td>{_get_package_metadata(pid).get("included_units", 0):,}</td>
            <td>${_get_package_metadata(pid).get("price_usd", 0):.2f}</td>
            <td>{_TOKENS_PER_UNIT:,}</td>
        </tr>"""
        for pid in _ORDERED_PACKAGE_IDS
    )

    html = _render_html(
        "Usage Reports",
        f"""
<section>
    <h2>Billing and Usage Reports</h2>
    <table data-usage="table">
        <thead>
            <tr>
                <th>owner</th>
                <th>action</th>
                <th>units</th>
                <th>quota</th>
                <th>remaining</th>
                <th>total cost</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>{payload.get("ownerid", "owner-usage")}</td>
                <td>{payload.get("action", "execute")}</td>
                <td>{payload.get("units", "0")}</td>
                <td>{payload.get("quota", "0")}</td>
                <td>{payload.get("remaining", "0")}</td>
                <td>{payload.get("totalcost", "0")}</td>
            </tr>
        </tbody>
    </table>
    <p>summary totals and billing overview for usage.</p>
    <h3>Live Usage (Supabase)</h3>
    <table data-usage="supabase-table">
        <thead>
            <tr>
                <th>total requests</th>
                <th>units consumed</th>
                <th>tokens covered</th>
                <th>blocks</th>
                <th>warnings</th>
                <th>tokens per unit</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>{sb_requests:,}</td>
                <td>{sb_units:,}</td>
                <td>{sb_tokens:,}</td>
                <td>{sb_blocks:,}</td>
                <td>{sb_warnings:,}</td>
                <td>{_TOKENS_PER_UNIT:,}</td>
            </tr>
        </tbody>
    </table>
    <h3>Package Catalogue</h3>
    <table data-usage="packages-table">
        <thead>
            <tr>
                <th>package</th>
                <th>label</th>
                <th>units</th>
                <th>price (USD)</th>
                <th>tokens per unit</th>
            </tr>
        </thead>
        <tbody>
            {pkg_rows}
        </tbody>
    </table>
</section>
""",
    )
    return HTMLResponse(content=html)


@router.get("/event", response_class=HTMLResponse)
async def usage_event(request: Request) -> HTMLResponse:
    """Event/detail view."""
    usage = build_action_usage()
    payload = usage.as_dict()
    sb_usage = _fetch_supabase_usage()

    last_event_at = sb_usage.get("last_event_at", "—")
    sb_units = sb_usage.get("total_units_consumed", 0)

    html = _render_html(
        "Usage Event Detail",
        f"""
<section>
    <h2>Usage Event Detail</h2>
    <p>event detail for a single usage request.</p>
    <dl>
        <dt>usage id</dt>
        <dd>{payload.get("usageid", "usage-unknown")}</dd>
        <dt>owner</dt>
        <dd>{payload.get("ownerid", "owner-unknown")}</dd>
        <dt>request</dt>
        <dd>execute action with recorded units and quota.</dd>
        <dt>last event (Supabase)</dt>
        <dd>{last_event_at}</dd>
        <dt>total units consumed (Supabase)</dt>
        <dd>{sb_units:,}</dd>
        <dt>tokens per unit</dt>
        <dd>{_TOKENS_PER_UNIT:,} — additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks</dd>
    </dl>
    <p>Billing: {_package_pricing_summary()}</p>
</section>
""",
    )
    return HTMLResponse(content=html)


@router.get("/summary", response_class=HTMLResponse)
async def usage_summary(request: Request) -> HTMLResponse:
    """Summary view."""
    usage = build_action_usage()
    payload = usage.as_dict()
    sb_usage = _fetch_supabase_usage()
    sb_wallet = _fetch_supabase_wallet()

    units = payload.get("units", "0")
    total_cost = payload.get("totalcost", "0")
    quota = payload.get("quota", "0")
    remaining = payload.get("remaining", "0")

    sb_units = sb_usage.get("total_units_consumed", 0)
    sb_tokens = sb_usage.get("total_tokens_covered", 0)
    sb_wallet_units = sb_wallet.get("wallet_units", 0)
    active_pkg = sb_wallet.get("active_package", {})
    active_pkg_label = active_pkg.get("display_label", "—")

    html = _render_html(
        "Usage Summary",
        f"""
<section>
    <h2>Usage Summary</h2>
    <p>summary of usage totals and billing impact.</p>
    <ul>
        <li>summary</li>
        <li>totals</li>
        <li>total units: {units}</li>
        <li>total cost: {total_cost}</li>
        <li>remaining quota: {remaining} / {quota}</li>
    </ul>
    <h3>Live Totals (Supabase)</h3>
    <ul>
        <li>total units consumed: {sb_units:,}</li>
        <li>total tokens covered: {sb_tokens:,}</li>
        <li>wallet units remaining: {sb_wallet_units:,}</li>
        <li>active package: {active_pkg_label}</li>
        <li>tokens per unit: {_TOKENS_PER_UNIT:,}</li>
        <li>unit consumption model: 1 unit covers up to {_TOKENS_PER_UNIT:,} tokens;
            additional units consumed in {_TOKENS_PER_UNIT:,}-token chunks</li>
        <li>{_package_pricing_summary()}</li>
    </ul>
</section>
""",
    )
    return HTMLResponse(content=html)
