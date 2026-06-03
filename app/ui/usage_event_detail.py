from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any

from fastapi import APIRouter, Path
from pydantic import BaseModel, Field

from app.core.unit_wallet import UNIT_PACKAGE_CATALOG

router = APIRouter(prefix="/usage-events/detail", tags=["usage-event-detail"])

try:
    from supabase import Client as SupabaseClient
    from supabase import create_client

    _SUPABASE_URL = os.environ["SUPABASE_URL"]
    _SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    _supabase: SupabaseClient | None = create_client(_SUPABASE_URL, _SUPABASE_SERVICE_ROLE_KEY)
    _SUPABASE_AVAILABLE = True
except Exception:
    _supabase = None
    _SUPABASE_AVAILABLE = False

_TOKENS_PER_UNIT = 25_000
_ORDERED_PACKAGE_IDS = ["pkg_5000", "pkg_25000", "pkg_60000"]
_FEATURED_PACKAGE_ID = "pkg_25000"

_PRICING_FALLBACK: dict[str, tuple[int, float, str, str, str]] = {
    "pkg_5000": (
        5_000,
        20.00,
        "Starter",
        "5,000 units — $20.00",
        "Prepaid protection units for individual builders and small guarded workloads.",
    ),
    "pkg_25000": (
        25_000,
        90.00,
        "Team",
        "25,000 units — $90.00",
        "Prepaid protection units for teams running higher-volume guarded AI activity.",
    ),
    "pkg_60000": (
        60_000,
        180.00,
        "Enterprise",
        "60,000 units — $180.00",
        "Prepaid protection units for large-scale protected agent and workflow operations.",
    ),
}


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _units_required_for_tokens(token_count: int) -> int:
    if token_count <= 0:
        return 0
    full_chunks, remainder = divmod(token_count, _TOKENS_PER_UNIT)
    return full_chunks + (1 if remainder > 0 else 0)


def _package_snapshot(package_id: str | None) -> dict[str, Any]:
    resolved_package_id = package_id if package_id in _ORDERED_PACKAGE_IDS else _FEATURED_PACKAGE_ID
    package = UNIT_PACKAGE_CATALOG.get(resolved_package_id)

    if package is not None:
        included_units = int(package["unit_amount"])
        price_usd = float(package["price_usd"])
        name = str(package["name"])
        display_label = str(package.get("display_label", ""))
        description = str(package.get("description", ""))
    else:
        included_units, price_usd, name, display_label, description = _PRICING_FALLBACK[resolved_package_id]

    price_per_1k = round((price_usd / included_units) * 1_000, 4) if included_units > 0 else 0.0

    return {
        "package_id": resolved_package_id,
        "name": name,
        "description": description,
        "display_label": display_label,
        "price_usd": price_usd,
        "included_units": included_units,
        "featured": resolved_package_id == _FEATURED_PACKAGE_ID,
        "metadata": {
            "price_display": f"${price_usd:.2f}",
            "units_display": f"{included_units:,} units",
            "effective_price_per_1k_units": price_per_1k,
            "tokens_per_unit": _TOKENS_PER_UNIT,
        },
    }


def _package_catalog_metadata() -> dict[str, Any]:
    return {
        "featured_package_id": _FEATURED_PACKAGE_ID,
        "ordered_package_ids": list(_ORDERED_PACKAGE_IDS),
        "packages": {package_id: _package_snapshot(package_id) for package_id in _ORDERED_PACKAGE_IDS},
    }


def _coerce_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "blocked", "truncated"}:
            return True
        if normalized in {"false", "0", "no", "n", "allow"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return default


def _fetch_security_event(event_id: str) -> dict[str, Any] | None:
    if not _SUPABASE_AVAILABLE or _supabase is None:
        return None

    try:
        response = _supabase.table("security_events").select("*").eq("id", event_id).limit(1).execute()
        rows = response.data or []
        if rows:
            return rows[0]
    except Exception:
        return None

    return None


def _fetch_user_by_id(user_id: str | None) -> dict[str, Any] | None:
    if not user_id or not _SUPABASE_AVAILABLE or _supabase is None:
        return None

    try:
        response = _supabase.table("users").select("id, email, wallet_units, has_paid, last_payment, user_token").eq("id", user_id).limit(1).execute()
        rows = response.data or []
        if rows:
            return rows[0]
    except Exception:
        return None

    return None


def _resolve_event_payload(event_id: str) -> dict[str, Any]:
    event_record = _fetch_security_event(event_id)
    if event_record is None:
        return {
            "source": "fallback",
            "event_id": event_id,
            "client_id": "default-client",
            "session_id": "default-session",
            "actor_id": None,
            "request_id": None,
            "trace_id": None,
            "verdict": "allow",
            "guard_mode": "assist",
            "policy_profile": "default-usage-event",
            "blocked": False,
            "truncated": False,
            "units_consumed": 0,
            "unit_type": "unit",
            "wallet_id": None,
            "package_id": _FEATURED_PACKAGE_ID,
            "wallet_units": 0,
            "method": "POST",
            "path": "/scan",
            "upstream_url": None,
            "ip_address": None,
            "user_agent": None,
            "token_count": 0,
            "user_id": None,
            "timestamp": None,
            "metadata": {
                "billing_state": "not-charged",
                "identity_state": "unbound",
                "description": "Usage event detail is using a safe fallback view because no matching Supabase event was found.",
            },
        }

    user_id = _coerce_text(event_record.get("user_id"))
    user_record = _fetch_user_by_id(user_id)
    last_payment = user_record.get("last_payment") if isinstance(user_record, dict) else None
    last_payment = last_payment if isinstance(last_payment, dict) else {}

    package_id = _coerce_text(last_payment.get("package_id")) or _FEATURED_PACKAGE_ID
    units_consumed = _coerce_int(event_record.get("units_used"), default=0)
    token_count = units_consumed * _TOKENS_PER_UNIT
    wallet_units = _coerce_int(user_record.get("wallet_units") if user_record else 0, default=0)

    return {
        "source": "supabase",
        "event_id": event_id,
        "client_id": user_id or "default-client",
        "session_id": _coerce_text(event_record.get("platform")) or "default-session",
        "actor_id": user_id,
        "request_id": _coerce_text(event_record.get("id")),
        "trace_id": _coerce_text(event_record.get("id")),
        "verdict": _coerce_text(event_record.get("verdict")) or "allow",
        "guard_mode": "enforce",
        "policy_profile": "usage-event-security",
        "blocked": (_coerce_text(event_record.get("verdict")) or "").lower() == "block",
        "truncated": False,
        "units_consumed": units_consumed,
        "unit_type": "unit",
        "wallet_id": user_id,
        "package_id": package_id,
        "wallet_units": wallet_units,
        "method": "POST",
        "path": "/scan",
        "upstream_url": None,
        "ip_address": None,
        "user_agent": None,
        "token_count": token_count,
        "user_id": user_id,
        "timestamp": _coerce_text(event_record.get("timestamp")),
        "metadata": {
            "billing_state": "charged" if units_consumed > 0 else "not-charged",
            "identity_state": "bound",
            "description": "Usage event detail is hydrated from Supabase security_events and users records.",
        },
    }


class UsageEventIdentityView(BaseModel):
    event_id: str
    client_id: str | None = None
    session_id: str | None = None
    actor_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventGuardView(BaseModel):
    verdict: str
    guard_mode: str
    policy_profile: str
    blocked: bool
    truncated: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventBillingView(BaseModel):
    units_consumed: int
    unit_type: str
    package_id: str | None = None
    wallet_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventContextView(BaseModel):
    method: str
    path: str
    upstream_url: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventLinkView(BaseModel):
    label: str
    path: str
    description: str


class UsageEventDetailResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    identity: UsageEventIdentityView
    guard: UsageEventGuardView
    billing: UsageEventBillingView
    context: UsageEventContextView
    links: list[UsageEventLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_links(event_id: str, session_id: str | None, client_id: str | None) -> list[UsageEventLinkView]:
    links: list[UsageEventLinkView] = [
        UsageEventLinkView(
            label="Usage reports",
            path="/ui/usage-reports",
            description="Return to aggregated usage summaries and recent events.",
        ),
        UsageEventLinkView(
            label="Audit log",
            path="/ui/audit-log",
            description="Inspect the full audit trail for related decisions.",
        ),
    ]

    if session_id:
        links.append(
            UsageEventLinkView(
                label="Session timeline",
                path=f"/ui/activity/sessiontimeline/{session_id}",
                description="Timeline view for all activity in this session.",
            ),
        )

    if client_id:
        links.append(
            UsageEventLinkView(
                label="Client profile",
                path=f"/ui/activity/clientprofile/{client_id}",
                description="Profile view for the client associated with this usage.",
            ),
        )

    return links


@router.get("/{event_id}", response_model=UsageEventDetailResponse)
def get_usage_event_detail(
    event_id: str = Path(..., min_length=1, max_length=255),
) -> UsageEventDetailResponse:
    normalized_event_id = event_id.strip()
    payload = _resolve_event_payload(normalized_event_id)
    package_snapshot = _package_snapshot(payload.get("package_id"))

    identity = UsageEventIdentityView(
        event_id=normalized_event_id,
        client_id=payload.get("client_id"),
        session_id=payload.get("session_id"),
        actor_id=payload.get("actor_id"),
        request_id=payload.get("request_id"),
        trace_id=payload.get("trace_id"),
        metadata={
            "identity_state": payload["metadata"]["identity_state"],
            "description": payload["metadata"]["description"],
            "source": payload.get("source"),
            "timestamp": payload.get("timestamp"),
        },
    )

    guard = UsageEventGuardView(
        verdict=payload.get("verdict") or "allow",
        guard_mode=payload.get("guard_mode") or "assist",
        policy_profile=payload.get("policy_profile") or "default-usage-event",
        blocked=bool(payload.get("blocked")),
        truncated=bool(payload.get("truncated")),
        metadata={
            "policy_source": "usage-event-detail-ui",
            "supports_prompt_guard": True,
            "supports_action_guard": True,
            "source": payload.get("source"),
        },
    )

    token_count = _coerce_int(payload.get("token_count"), default=0)
    computed_units = _units_required_for_tokens(token_count)

    billing = UsageEventBillingView(
        units_consumed=payload.get("units_consumed", 0),
        unit_type=payload.get("unit_type") or "unit",
        package_id=package_snapshot.get("package_id"),
        wallet_id=payload.get("wallet_id"),
        metadata={
            "billing_state": payload["metadata"]["billing_state"],
            "description": "Each unit covers up to 25,000 tokens and additional units are consumed in 25,000-token chunks.",
            "tokens_per_unit": _TOKENS_PER_UNIT,
            "token_count": token_count,
            "computed_units_for_tokens": computed_units,
            "wallet_units": payload.get("wallet_units", 0),
            "package": package_snapshot,
            "catalog": _package_catalog_metadata(),
        },
    )

    context = UsageEventContextView(
        method=payload.get("method") or "POST",
        path=payload.get("path") or "/scan",
        upstream_url=payload.get("upstream_url"),
        ip_address=payload.get("ip_address"),
        user_agent=payload.get("user_agent"),
        metadata={
            "ui_surface": "usage-event-detail",
            "environment": "local",
            "source": payload.get("source"),
        },
    )

    return UsageEventDetailResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        identity=identity,
        guard=guard,
        billing=billing,
        context=context,
        links=_build_links(
            normalized_event_id,
            session_id=payload.get("session_id"),
            client_id=payload.get("client_id"),
        ),
        notes=[
            "Usage event detail provides a focused view of a single metered security event.",
            "Billing package catalog uses Starter at $20 for 5,000 units, Team at $90 for 25,000 units, and Enterprise at $180 for 60,000 units.",
            "Each protection unit covers up to 25,000 tokens, and token volumes above that consume additional units in 25,000-token chunks.",
            "Package metadata now surfaces tokens_per_unit for every package and the event billing block includes token-based unit calculation details.",
            "When a matching Supabase security event exists, this view hydrates from security_events and users data; otherwise it returns a safe default detail view.",
        ],
    )
