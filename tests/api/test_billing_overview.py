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
from app.ui.billing.overview import _plan_change_url
from app.ui.billing.overview import router as _overview_router

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}

# Register the overview router into the app once for this test module.
# It is not yet wired in app/ui/router.py so we mount it directly here.
_app.include_router(_overview_router)


@pytest.fixture()
def client():
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c


# ---------------------------------------------------------------------------
# GET /ui/billing/overview — HTTP contract
# ---------------------------------------------------------------------------


def test_billing_overview_returns_200(client: TestClient) -> None:
    resp = client.get("/ui/billing/overview")
    assert resp.status_code == 200


def test_billing_overview_response_envelope(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    assert "generatedat" in body
    assert body["environment"] == "local"
    assert "overallstatus" in body
    assert isinstance(body["generatedat"], str)
    assert len(body["generatedat"]) > 0


# ---------------------------------------------------------------------------
# overallstatus
# ---------------------------------------------------------------------------


def test_billing_overview_overallstatus_is_attention_due_to_past_due_gamma(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/overview").json()
    # Gamma Internal QA is seeded past_due — overallstatus must be "attention"
    assert body["overallstatus"] == "attention"


# ---------------------------------------------------------------------------
# packages list
# ---------------------------------------------------------------------------


def test_billing_overview_packages_count(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    assert len(body["packages"]) == 3


def test_billing_overview_packages_have_non_empty_usage(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    for pkg in body["packages"]:
        assert len(pkg["usage"]) >= 1, f"package {pkg['packageid']} has empty usage"
        bucket = pkg["usage"][0]
        assert "included" in bucket
        assert "used" in bucket
        assert "overage" in bucket
        assert "unit" in bucket


def test_billing_overview_team_package_usage_included(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    team_pkg = next(p for p in body["packages"] if p["plan"] == "team")
    assert team_pkg["usage"][0]["included"] == 25_000


def test_billing_overview_starter_package_usage_included(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    starter_pkg = next(p for p in body["packages"] if p["plan"] == "starter")
    assert starter_pkg["usage"][0]["included"] == 5_000


def test_billing_overview_enterprise_package_usage_included_and_overage(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/overview").json()
    enterprise_pkg = next(p for p in body["packages"] if p["plan"] == "enterprise")
    assert enterprise_pkg["usage"][0]["included"] == 60_000
    assert enterprise_pkg["usage"][0]["overage"] == 1_200


# ---------------------------------------------------------------------------
# invoices list
# ---------------------------------------------------------------------------


def test_billing_overview_invoices_count(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    assert len(body["invoices"]) == 3


# ---------------------------------------------------------------------------
# plancounts
# ---------------------------------------------------------------------------


def test_billing_overview_plancounts_has_one_entry_per_plan(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/overview").json()
    plans = {entry["plan"] for entry in body["plancounts"]}
    assert plans == {"starter", "team", "enterprise"}


# ---------------------------------------------------------------------------
# invoicestatuscounts
# ---------------------------------------------------------------------------


def test_billing_overview_invoicestatuscounts_reflects_seeded_invoices(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/overview").json()
    status_map = {e["status"]: e["count"] for e in body["invoicestatuscounts"]}
    assert status_map.get("paid") == 1
    assert status_map.get("draft") == 1
    assert status_map.get("past_due") == 1


# ---------------------------------------------------------------------------
# kpis
# ---------------------------------------------------------------------------


def test_billing_overview_kpis_totalpackages(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    kpi_map = {k["label"]: k["value"] for k in body["kpis"]}
    assert kpi_map["totalpackages"] == 3


def test_billing_overview_kpis_activepackages(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    kpi_map = {k["label"]: k["value"] for k in body["kpis"]}
    assert kpi_map["activepackages"] == 1


def test_billing_overview_kpis_pastduepackages(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    kpi_map = {k["label"]: k["value"] for k in body["kpis"]}
    assert kpi_map["pastduepackages"] == 1


def test_billing_overview_kpis_totalrevenuecents_paid_only(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    kpi_map = {k["label"]: k["value"] for k in body["kpis"]}
    # Only the paid team invoice ($90.00 = 9_000 cents) is counted
    assert kpi_map["totalrevenuecents"] == 9_000


# ---------------------------------------------------------------------------
# notes
# ---------------------------------------------------------------------------


def test_billing_overview_notes_non_empty(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    assert len(body["notes"]) >= 1


def test_billing_overview_notes_contains_unit_price_description(client: TestClient) -> None:
    body = client.get("/ui/billing/overview").json()
    combined = " ".join(body["notes"])
    # overview.py notes describe unit/price: "Starter $20 for 5,000 units"
    assert "units" in combined.lower()
    assert "starter" in combined.lower()


# ---------------------------------------------------------------------------
# _plan_change_url helper
# ---------------------------------------------------------------------------


def test_plan_change_url_produces_correct_query_string_format() -> None:
    url = _plan_change_url("team")
    assert url == "/ui/billing/plan-change?currentplan=team"

    url_starter = _plan_change_url("starter")
    assert url_starter == "/ui/billing/plan-change?currentplan=starter"

    url_enterprise = _plan_change_url("enterprise")
    assert url_enterprise == "/ui/billing/plan-change?currentplan=enterprise"
