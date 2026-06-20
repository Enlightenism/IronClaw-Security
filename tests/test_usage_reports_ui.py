from __future__ import annotations

import os

from fastapi.testclient import TestClient
import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from app.main import app as _app
from app.ui.usage_reports import (
    _ORDERED_PACKAGE_IDS,
    _TOKENS_PER_UNIT,
    TOKEN_CHUNK_SIZE,
    _billing_catalog,
    _build_events_from_rows,
    _fetch_usage_summary,
    _get_package_metadata,
)

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}

_UI_USAGE_ROUTE = "/ui/usage-reports"


@pytest.fixture()
def client():
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c


# ---------------------------------------------------------------------------
# _get_package_metadata — tokens_in_wallet key, correct value
# ---------------------------------------------------------------------------


def test_get_package_metadata_contains_tokens_in_wallet_key() -> None:
    meta = _get_package_metadata("pkg_5000")
    assert "tokens_in_wallet" in meta


def test_get_package_metadata_does_not_contain_max_tokens_covered() -> None:
    for pkg_id in _ORDERED_PACKAGE_IDS:
        meta = _get_package_metadata(pkg_id)
        assert "max_tokens_covered" not in meta, f"max_tokens_covered must not appear in metadata for {pkg_id}"


def test_get_package_metadata_tokens_in_wallet_equals_included_units_times_chunk_size() -> None:
    for pkg_id in _ORDERED_PACKAGE_IDS:
        meta = _get_package_metadata(pkg_id)
        expected = meta["included_units"] * TOKEN_CHUNK_SIZE
        assert meta["tokens_in_wallet"] == expected, f"{pkg_id}: tokens_in_wallet {meta['tokens_in_wallet']} != included_units({meta['included_units']}) * TOKEN_CHUNK_SIZE({TOKEN_CHUNK_SIZE})"


def test_get_package_metadata_starter_tokens_in_wallet() -> None:
    meta = _get_package_metadata("pkg_5000")
    assert meta["included_units"] == 5_000
    assert meta["tokens_in_wallet"] == 5_000 * _TOKENS_PER_UNIT


def test_get_package_metadata_team_tokens_in_wallet() -> None:
    meta = _get_package_metadata("pkg_25000")
    assert meta["included_units"] == 25_000
    assert meta["tokens_in_wallet"] == 25_000 * _TOKENS_PER_UNIT


def test_get_package_metadata_enterprise_tokens_in_wallet() -> None:
    meta = _get_package_metadata("pkg_60000")
    assert meta["included_units"] == 60_000
    assert meta["tokens_in_wallet"] == 60_000 * _TOKENS_PER_UNIT


def test_get_package_metadata_unknown_package_returns_empty_dict() -> None:
    result = _get_package_metadata("pkg_does_not_exist")
    assert result == {}


# ---------------------------------------------------------------------------
# _fetch_usage_summary — metadata contains tokens_in_wallet
# ---------------------------------------------------------------------------


def test_fetch_usage_summary_metadata_contains_tokens_in_wallet_when_rows_present() -> None:
    rows = [
        {"id": "evt-1", "user_id": "u1", "verdict": "allow", "units_used": 2, "platform": "cli", "timestamp": "2026-06-01T10:00:00Z"},
        {"id": "evt-2", "user_id": "u2", "verdict": "block", "units_used": 1, "platform": "api", "timestamp": "2026-06-01T10:05:00Z"},
    ]
    result = _fetch_usage_summary(rows=rows, period="24h", limit=10)
    assert len(result.items) == 1
    meta = result.items[0].metadata
    assert "tokens_in_wallet" in meta
    assert "max_tokens_covered" not in meta


def test_fetch_usage_summary_tokens_in_wallet_value_is_correct() -> None:
    rows = [
        {"id": "evt-1", "user_id": "u1", "verdict": "allow", "units_used": 4, "platform": "cli", "timestamp": "2026-06-01T10:00:00Z"},
    ]
    result = _fetch_usage_summary(rows=rows, period="24h", limit=10)
    meta = result.items[0].metadata
    assert meta["tokens_in_wallet"] == 4 * _TOKENS_PER_UNIT


def test_fetch_usage_summary_empty_rows_returns_fallback_path() -> None:
    result = _fetch_usage_summary(rows=[], period="24h", limit=10)
    assert result.status == "ok"
    assert len(result.items) == 1
    meta = result.items[0].metadata
    assert meta["source"] == "fallback"


def test_fetch_usage_summary_metadata_tokens_per_unit_matches_constant() -> None:
    rows = [
        {"id": "evt-1", "user_id": "u1", "verdict": "allow", "units_used": 1, "platform": "cli", "timestamp": "2026-06-01T10:00:00Z"},
    ]
    result = _fetch_usage_summary(rows=rows, period="24h", limit=10)
    meta = result.items[0].metadata
    assert meta["tokens_per_unit"] == _TOKENS_PER_UNIT


# ---------------------------------------------------------------------------
# _build_events_from_rows — event metadata contains tokens_in_wallet
# ---------------------------------------------------------------------------


def test_build_events_from_rows_metadata_contains_tokens_in_wallet() -> None:
    rows = [
        {"id": "evt-1", "user_id": "u1", "verdict": "allow", "units_used": 3, "platform": "cli", "timestamp": "2026-06-01T10:00:00Z"},
    ]
    result = _build_events_from_rows(rows=rows, limit=10)
    assert len(result.events) == 1
    meta = result.events[0].metadata
    assert "tokens_in_wallet" in meta


def test_build_events_from_rows_metadata_does_not_contain_tokens_covered() -> None:
    rows = [
        {"id": "evt-1", "user_id": "u1", "verdict": "block", "units_used": 2, "platform": "api", "timestamp": "2026-06-01T11:00:00Z"},
    ]
    result = _build_events_from_rows(rows=rows, limit=10)
    meta = result.events[0].metadata
    assert "tokens_covered" not in meta
    assert "max_tokens_covered" not in meta


def test_build_events_from_rows_tokens_in_wallet_value_is_correct() -> None:
    units = 5
    rows = [
        {"id": "evt-1", "user_id": "u1", "verdict": "warn", "units_used": units, "platform": "sdk", "timestamp": "2026-06-01T12:00:00Z"},
    ]
    result = _build_events_from_rows(rows=rows, limit=10)
    meta = result.events[0].metadata
    assert meta["tokens_in_wallet"] == units * _TOKENS_PER_UNIT


def test_build_events_from_rows_zero_units_produces_zero_tokens_in_wallet() -> None:
    rows = [
        {"id": "evt-1", "user_id": "u1", "verdict": "allow", "units_used": 0, "platform": "cli", "timestamp": "2026-06-01T13:00:00Z"},
    ]
    result = _build_events_from_rows(rows=rows, limit=10)
    assert result.events[0].metadata["tokens_in_wallet"] == 0


def test_build_events_from_rows_limit_is_respected() -> None:
    rows = [{"id": f"evt-{i}", "user_id": "u1", "verdict": "allow", "units_used": 1, "platform": "cli", "timestamp": "2026-06-01T10:00:00Z"} for i in range(20)]
    result = _build_events_from_rows(rows=rows, limit=5)
    assert len(result.events) == 5


def test_build_events_from_rows_empty_rows_returns_empty_events() -> None:
    result = _build_events_from_rows(rows=[], limit=10)
    assert result.status == "ok"
    assert result.events == []


# ---------------------------------------------------------------------------
# GET /ui/usage-reports — fallback path (Supabase unavailable in test env)
# ---------------------------------------------------------------------------


def test_get_usage_reports_returns_200(client: TestClient) -> None:
    resp = client.get(_UI_USAGE_ROUTE)
    assert resp.status_code == 200


def test_get_usage_reports_response_shape(client: TestClient) -> None:
    body = client.get(_UI_USAGE_ROUTE).json()
    assert body["status"] == "ok"
    assert body["service"] == "IronClaw-Security"
    assert "timestamp" in body
    assert "summaries" in body
    assert "events" in body
    assert "billing_catalog" in body
    assert "notes" in body


def test_get_usage_reports_summaries_shape(client: TestClient) -> None:
    body = client.get(_UI_USAGE_ROUTE).json()
    summaries = body["summaries"]
    assert summaries["status"] == "ok"
    assert "items" in summaries
    assert isinstance(summaries["items"], list)


def test_get_usage_reports_events_shape(client: TestClient) -> None:
    body = client.get(_UI_USAGE_ROUTE).json()
    events = body["events"]
    assert events["status"] == "ok"
    assert "events" in events
    assert isinstance(events["events"], list)


def test_get_usage_reports_billing_catalog_present(client: TestClient) -> None:
    body = client.get(_UI_USAGE_ROUTE).json()
    catalog = body["billing_catalog"]
    assert "packages" in catalog
    assert "tokens_per_unit" in catalog
    assert catalog["tokens_per_unit"] == _TOKENS_PER_UNIT


def test_get_usage_reports_notes_non_empty(client: TestClient) -> None:
    body = client.get(_UI_USAGE_ROUTE).json()
    assert len(body["notes"]) >= 1


def test_get_usage_reports_period_query_param_accepted(client: TestClient) -> None:
    resp = client.get(f"{_UI_USAGE_ROUTE}?period=7d&limit=5")
    assert resp.status_code == 200
    body = resp.json()
    assert body["summaries"]["period"] == "7d"
    assert body["summaries"]["limit"] == 5


def test_get_usage_reports_limit_query_param_accepted(client: TestClient) -> None:
    resp = client.get(f"{_UI_USAGE_ROUTE}?limit=1")
    assert resp.status_code == 200


def test_get_usage_reports_invalid_limit_returns_422(client: TestClient) -> None:
    resp = client.get(f"{_UI_USAGE_ROUTE}?limit=-1")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# _billing_catalog — tokens_in_wallet present, max_tokens_covered absent
# ---------------------------------------------------------------------------


def test_billing_catalog_packages_contain_tokens_in_wallet() -> None:
    catalog = _billing_catalog()
    for pkg_id, pkg in catalog["packages"].items():
        assert "tokens_in_wallet" in pkg, f"tokens_in_wallet missing from billing_catalog package {pkg_id}"


def test_billing_catalog_packages_do_not_contain_max_tokens_covered() -> None:
    catalog = _billing_catalog()
    for pkg_id, pkg in catalog["packages"].items():
        assert "max_tokens_covered" not in pkg, f"max_tokens_covered must not appear in billing_catalog package {pkg_id}"


def test_billing_catalog_tokens_per_unit_matches_constant() -> None:
    catalog = _billing_catalog()
    assert catalog["tokens_per_unit"] == _TOKENS_PER_UNIT


def test_billing_catalog_all_ordered_packages_present() -> None:
    catalog = _billing_catalog()
    for pkg_id in _ORDERED_PACKAGE_IDS:
        assert pkg_id in catalog["packages"], f"{pkg_id} missing from billing_catalog packages"
