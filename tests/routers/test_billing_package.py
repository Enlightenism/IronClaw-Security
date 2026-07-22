from __future__ import annotations

from collections.abc import Iterator
import os

from fastapi.testclient import TestClient
import pytest

# ---------------------------------------------------------------------------
# Environment must be set before app import to avoid settings cache bleed
# ---------------------------------------------------------------------------
os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["IRONCLAW_RATE_LIMIT_ENABLED"] = "false"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

from app.core.auth import AuthContext, require_auth_context
from app.core.settings import get_settings
from app.main import app
from app.supabaseclient import TOKENS_PER_UNIT
from app.ui.billing.package import (
    PACKAGE_CATALOGUE,
    _apply_filters,
    _get_stripe_status,
    _static_fallback_packages,
    units_for_tokens,
)

_VALID_KEY = os.environ["IRONCLAW_API_KEY"]
_ROUTE = "/ui/billing/packages"

_TEST_AUTH_CONTEXT = AuthContext(
    api_key=_VALID_KEY,
    principal_type="api_key",
    principal_id="test-principal",
    session_id=None,
    org_id="test-org",
    permissions=(),
    roles=(),
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
)


def _override_require_auth_context() -> AuthContext:
    return _TEST_AUTH_CONTEXT


def _auth(key: str = _VALID_KEY) -> dict[str, str]:
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _refresh_settings() -> Iterator[None]:
    get_settings.cache_clear()
    app.state.settings = get_settings()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    app.dependency_overrides[require_auth_context] = _override_require_auth_context
    yield
    app.dependency_overrides.pop(require_auth_context, None)


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_auth())
    return c


@pytest.fixture()
def no_stripe_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    yield


@pytest.fixture()
def live_stripe_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_test_ironclaw_fixture_key")
    yield


@pytest.fixture()
def test_stripe_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_ironclaw_fixture_key")
    yield


@pytest.fixture()
def stripe_price_ids_seeded(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("STRIPE_PRICE_ID_STARTER", "price_test_starter_xxx")
    monkeypatch.setenv("STRIPE_PRICE_ID_TEAM", "price_test_team_xxx")
    monkeypatch.setenv("STRIPE_PRICE_ID_ENTERPRISE", "price_test_enterprise_xxx")
    yield


# ---------------------------------------------------------------------------
# GET /ui/billing/packages — happy path
# ---------------------------------------------------------------------------


def test_get_billing_packages_200(client: TestClient) -> None:
    r = client.get(_ROUTE)
    assert r.status_code == 200


def test_response_shape(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    assert "stripe" in body
    assert "packages" in body
    assert "totalcount" in body
    assert "page" in body
    assert "pagesize" in body
    assert "statuscounts" in body
    assert "plancounts" in body
    assert "generatedat" in body
    assert "environment" in body
    assert "tokens_per_unit" in body
    assert "package_catalogue" in body
    assert "notes" in body
    assert "filters" in body


def test_stripe_field_present_in_response(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    stripe = body["stripe"]
    assert "configured" in stripe
    assert "mode" in stripe
    assert "note" in stripe


def test_tokens_per_unit_matches_constant(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    assert body["tokens_per_unit"] == TOKENS_PER_UNIT


def test_package_catalogue_present_with_three_plans(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    catalogue = body["package_catalogue"]
    assert "starter" in catalogue
    assert "team" in catalogue
    assert "enterprise" in catalogue


def test_packages_list_is_list(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    assert isinstance(body["packages"], list)


def test_notes_is_nonempty_list(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    assert isinstance(body["notes"], list)
    assert len(body["notes"]) > 0


# ---------------------------------------------------------------------------
# Stripe mode detection — unit level
# ---------------------------------------------------------------------------


def test_stripe_live_mode(live_stripe_env: None) -> None:
    status = _get_stripe_status()
    assert status.configured is True
    assert status.mode == "live"


def test_stripe_test_mode(test_stripe_env: None) -> None:
    status = _get_stripe_status()
    assert status.configured is True
    assert status.mode == "test"


def test_stripe_unconfigured(no_stripe_env: None) -> None:
    status = _get_stripe_status()
    assert status.configured is False
    assert status.mode == "unconfigured"


# ---------------------------------------------------------------------------
# Stripe mode via HTTP — live key in env
# ---------------------------------------------------------------------------


def test_stripe_mode_live_via_route(client: TestClient, live_stripe_env: None) -> None:
    r = client.get(_ROUTE)
    assert r.status_code == 200
    assert r.json()["stripe"]["mode"] == "live"
    assert r.json()["stripe"]["configured"] is True


def test_stripe_mode_test_via_route(client: TestClient, test_stripe_env: None) -> None:
    r = client.get(_ROUTE)
    assert r.status_code == 200
    assert r.json()["stripe"]["mode"] == "test"
    assert r.json()["stripe"]["configured"] is True


def test_stripe_configured_false_when_key_absent(client: TestClient, no_stripe_env: None) -> None:
    r = client.get(_ROUTE)
    assert r.status_code == 200
    assert r.json()["stripe"]["configured"] is False


# ---------------------------------------------------------------------------
# Validation — invalid query params return 422
# ---------------------------------------------------------------------------


def test_invalid_status_returns_422(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"status": "unknown_status_xyz"})
    assert r.status_code == 422


def test_invalid_plan_returns_422(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"plan": "nonexistent_plan_xyz"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Pagination bounds enforcement
# ---------------------------------------------------------------------------


def test_page_below_minimum_returns_422(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"page": 0})
    assert r.status_code == 422


def test_pagesize_above_maximum_returns_422(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"pagesize": 101})
    assert r.status_code == 422


def test_pagesize_below_minimum_returns_422(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"pagesize": 0})
    assert r.status_code == 422


def test_page_minimum_valid(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"page": 1})
    assert r.status_code == 200


def test_pagesize_maximum_valid(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"pagesize": 100})
    assert r.status_code == 200


def test_pagination_reflected_in_response(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"page": 1, "pagesize": 2})
    body = r.json()
    assert body["page"] == 1
    assert body["pagesize"] == 2
    assert len(body["packages"]) <= 2


def test_page_2_returns_next_slice(client: TestClient) -> None:
    r1 = client.get(_ROUTE, params={"page": 1, "pagesize": 2})
    r2 = client.get(_ROUTE, params={"page": 2, "pagesize": 2})
    ids_p1 = [p["packageid"] for p in r1.json()["packages"]]
    ids_p2 = [p["packageid"] for p in r2.json()["packages"]]
    # Pages must not overlap
    assert not set(ids_p1) & set(ids_p2)


# ---------------------------------------------------------------------------
# Filter by status
# ---------------------------------------------------------------------------


def test_filter_by_valid_status_active(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"status": "active"})
    assert r.status_code == 200
    body = r.json()
    for pkg in body["packages"]:
        assert pkg["status"] == "active"


def test_filter_by_valid_status_suspended(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"status": "suspended"})
    assert r.status_code == 200
    body = r.json()
    for pkg in body["packages"]:
        assert pkg["status"] == "suspended"


def test_filter_by_status_units_exhausted(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"status": "units_exhausted"})
    assert r.status_code == 200
    for pkg in r.json()["packages"]:
        assert pkg["status"] == "units_exhausted"


def test_filter_by_status_cancelled(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"status": "cancelled"})
    assert r.status_code == 200
    for pkg in r.json()["packages"]:
        assert pkg["status"] == "cancelled"


def test_filter_status_reduces_totalcount(client: TestClient) -> None:
    r_all = client.get(_ROUTE)
    r_active = client.get(_ROUTE, params={"status": "active"})
    assert r_active.json()["totalcount"] <= r_all.json()["totalcount"]


# ---------------------------------------------------------------------------
# Filter by plan
# ---------------------------------------------------------------------------


def test_filter_by_plan_starter(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"plan": "starter"})
    assert r.status_code == 200
    for pkg in r.json()["packages"]:
        assert pkg["plan"] == "starter"


def test_filter_by_plan_team(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"plan": "team"})
    assert r.status_code == 200
    for pkg in r.json()["packages"]:
        assert pkg["plan"] == "team"


def test_filter_by_plan_enterprise(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"plan": "enterprise"})
    assert r.status_code == 200
    for pkg in r.json()["packages"]:
        assert pkg["plan"] == "enterprise"


def test_filter_plan_reduces_totalcount(client: TestClient) -> None:
    r_all = client.get(_ROUTE)
    r_starter = client.get(_ROUTE, params={"plan": "starter"})
    assert r_starter.json()["totalcount"] <= r_all.json()["totalcount"]


# ---------------------------------------------------------------------------
# Filter by organizationid
# ---------------------------------------------------------------------------


def test_filter_by_organizationid_org_001(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"organizationid": "org-001"})
    assert r.status_code == 200
    body = r.json()
    for pkg in body["packages"]:
        assert pkg["organizationid"] == "org-001"


def test_filter_by_organizationid_reduces_count(client: TestClient) -> None:
    r_all = client.get(_ROUTE)
    r_org = client.get(_ROUTE, params={"organizationid": "org-001"})
    assert r_org.json()["totalcount"] <= r_all.json()["totalcount"]


def test_filter_by_unknown_organizationid_returns_empty(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"organizationid": "org-does-not-exist-zzz"})
    assert r.status_code == 200
    assert r.json()["totalcount"] == 0
    assert r.json()["packages"] == []


def test_filter_org_reflected_in_filters_field(client: TestClient) -> None:
    r = client.get(_ROUTE, params={"organizationid": "org-002"})
    assert r.json()["filters"]["organizationid"] == "org-002"


# ---------------------------------------------------------------------------
# Static demo data fallback — Supabase not configured
# ---------------------------------------------------------------------------


def test_static_fallback_returns_packages_when_supabase_absent(
    client: TestClient,
) -> None:
    # SUPABASE_URL is "" → is_supabase_configured() returns False → static fallback used
    r = client.get(_ROUTE)
    assert r.status_code == 200
    body = r.json()
    assert body["totalcount"] > 0
    assert len(body["packages"]) > 0


def test_static_fallback_packages_unit() -> None:
    pkgs = _static_fallback_packages()
    assert len(pkgs) > 0
    plans = {p.plan for p in pkgs}
    assert "starter" in plans
    assert "team" in plans
    assert "enterprise" in plans


def test_static_fallback_all_have_usage_buckets() -> None:
    pkgs = _static_fallback_packages()
    for pkg in pkgs:
        assert len(pkg.usage) > 0


def test_static_fallback_all_have_valid_status_color() -> None:
    pkgs = _static_fallback_packages()
    valid_colors = {"success", "error", "warning", "neutral"}
    for pkg in pkgs:
        assert pkg.statuscolor in valid_colors


def test_static_fallback_tokens_per_unit_matches() -> None:
    pkgs = _static_fallback_packages()
    for pkg in pkgs:
        assert pkg.tokens_per_unit == TOKENS_PER_UNIT


# ---------------------------------------------------------------------------
# statuscounts and plancounts integrity
# ---------------------------------------------------------------------------


def test_statuscounts_present_and_non_empty(client: TestClient) -> None:
    r = client.get(_ROUTE)
    assert isinstance(r.json()["statuscounts"], list)
    assert len(r.json()["statuscounts"]) > 0


def test_plancounts_present_and_non_empty(client: TestClient) -> None:
    r = client.get(_ROUTE)
    assert isinstance(r.json()["plancounts"], list)
    assert len(r.json()["plancounts"]) > 0


def test_statuscounts_sum_matches_full_dataset(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    total_from_counts = sum(sc["count"] for sc in body["statuscounts"])
    # statuscounts reflect unfiltered total
    r_all = client.get(_ROUTE, params={"pagesize": 100})
    assert total_from_counts == r_all.json()["totalcount"]


def test_statuscounts_have_statuscolor(client: TestClient) -> None:
    r = client.get(_ROUTE)
    valid_colors = {"success", "error", "warning", "neutral"}
    for sc in r.json()["statuscounts"]:
        assert sc["statuscolor"] in valid_colors


# ---------------------------------------------------------------------------
# Package item field integrity
# ---------------------------------------------------------------------------


def test_package_item_has_required_fields(client: TestClient) -> None:
    r = client.get(_ROUTE)
    body = r.json()
    assert len(body["packages"]) > 0
    pkg = body["packages"][0]
    required = {
        "packageid",
        "organizationid",
        "organizationname",
        "plan",
        "status",
        "statuscolor",
        "purchasedat",
        "packageprice",
        "usage",
        "overallusagestatus",
        "tokens_per_unit",
        "token_coverage",
    }
    for field in required:
        assert field in pkg, f"missing field: {field}"


def test_package_price_has_currency_and_display(client: TestClient) -> None:
    r = client.get(_ROUTE)
    pkg = r.json()["packages"][0]
    price = pkg["packageprice"]
    assert price["currency"] == "USD"
    assert "amountcents" in price
    assert "displayamount" in price
    assert price["displayamount"].startswith("$")


def test_usage_buckets_have_percentused(client: TestClient) -> None:
    r = client.get(_ROUTE)
    for pkg in r.json()["packages"]:
        for bucket in pkg["usage"]:
            assert "percentused" in bucket
            assert 0.0 <= bucket["percentused"] <= 100.0


# ---------------------------------------------------------------------------
# units_for_tokens helper — unit tests
# ---------------------------------------------------------------------------


def test_units_for_tokens_zero() -> None:
    assert units_for_tokens(0) == 0


def test_units_for_tokens_one() -> None:
    assert units_for_tokens(1) == 1


def test_units_for_tokens_exact_unit() -> None:
    assert units_for_tokens(TOKENS_PER_UNIT) == 1


def test_units_for_tokens_one_over() -> None:
    assert units_for_tokens(TOKENS_PER_UNIT + 1) == 2


def test_units_for_tokens_three_units() -> None:
    assert units_for_tokens(TOKENS_PER_UNIT * 3) == 3


def test_units_for_tokens_negative() -> None:
    assert units_for_tokens(-1) == 0


# ---------------------------------------------------------------------------
# _apply_filters — unit tests
# ---------------------------------------------------------------------------


def test_apply_filters_by_status() -> None:
    pkgs = _static_fallback_packages()
    filtered = _apply_filters(pkgs, "active", None, None)
    assert all(p.status == "active" for p in filtered)


def test_apply_filters_by_plan() -> None:
    pkgs = _static_fallback_packages()
    filtered = _apply_filters(pkgs, None, "enterprise", None)
    assert all(p.plan == "enterprise" for p in filtered)


def test_apply_filters_by_orgid() -> None:
    pkgs = _static_fallback_packages()
    filtered = _apply_filters(pkgs, None, None, "org-001")
    assert all(p.organizationid == "org-001" for p in filtered)


def test_apply_filters_combined() -> None:
    pkgs = _static_fallback_packages()
    filtered = _apply_filters(pkgs, "active", "enterprise", "org-001")
    assert all(p.status == "active" and p.plan == "enterprise" and p.organizationid == "org-001" for p in filtered)


def test_apply_filters_no_match_returns_empty() -> None:
    pkgs = _static_fallback_packages()
    filtered = _apply_filters(pkgs, "pending", None, None)
    assert filtered == []


# ---------------------------------------------------------------------------
# PACKAGE_CATALOGUE constant integrity
# ---------------------------------------------------------------------------


def test_package_catalogue_keys() -> None:
    assert set(PACKAGE_CATALOGUE.keys()) == {"starter", "team", "enterprise"}


def test_package_catalogue_price_cents_consistency(client: TestClient, stripe_price_ids_seeded: None) -> None:
    r = client.get(_ROUTE)
    assert r.status_code == 200
    catalogue = r.json()["package_catalogue"]
    for plan in ("starter", "team", "enterprise"):
        meta = catalogue[plan]
        assert "price_cents" in meta, f"{plan} missing price_cents in response"
        assert "price_usd" in meta, f"{plan} missing price_usd in response"
        assert meta["price_cents"] == meta["price_usd"] * 100, f"{plan} price_cents mismatch"


def test_package_catalogue_token_coverage_consistency(client: TestClient, stripe_price_ids_seeded: None) -> None:
    r = client.get(_ROUTE)
    assert r.status_code == 200
    catalogue = r.json()["package_catalogue"]
    for plan in ("starter", "team", "enterprise"):
        meta = catalogue[plan]
        assert "token_coverage" in meta, f"{plan} missing token_coverage in response"
        assert "units" in meta, f"{plan} missing units in response"
        assert "tokens_per_unit" in meta, f"{plan} missing tokens_per_unit in response"
        assert meta["token_coverage"] == meta["units"] * meta["tokens_per_unit"], f"{plan} token_coverage mismatch"
