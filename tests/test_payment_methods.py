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
from app.ui.billing.package import PACKAGE_CATALOGUE, _get_stripe_status

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}


@pytest.fixture()
def client():
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c


# ---------------------------------------------------------------------------
# GET /ui/billing/payment-methods — Supabase unconfigured path
# ---------------------------------------------------------------------------


def test_get_payment_methods_returns_200_when_supabase_unconfigured(
    client: TestClient,
) -> None:
    resp = client.get("/ui/billing/payment-methods?organizationid=org-001")
    assert resp.status_code == 200


def test_get_payment_methods_not_found_response_shape(client: TestClient) -> None:
    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["status"] == "not_found"
    assert body["organizationid"] == "org-001"
    assert isinstance(body["message"], str)
    assert len(body["message"]) > 0
    assert isinstance(body["generatedat"], str)
    assert len(body["generatedat"]) > 0
    assert isinstance(body["environment"], str)
    assert len(body["environment"]) > 0


def test_get_payment_methods_not_found_message_mentions_supabase(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert "supabase" in body["message"].lower()


def test_get_payment_methods_environment_driven_by_get_environment(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert isinstance(body["environment"], str)
    assert len(body["environment"]) > 0
    assert body["environment"] != "local"


def test_get_payment_methods_environment_not_hardcoded_local(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IRONCLAW_ENV", "staging")
    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["environment"] == "staging"


# ---------------------------------------------------------------------------
# stripe field — sourced from _get_stripe_status(), not inline key inspection
# ---------------------------------------------------------------------------


def test_get_payment_methods_full_response_has_stripe_key_when_configured(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert "stripe" in body
    assert isinstance(body["stripe"]["configured"], bool)
    assert body["stripe"]["mode"] in {"live", "test", "unconfigured"}
    assert isinstance(body["stripe"]["note"], str)
    assert len(body["stripe"]["note"]) > 0


def test_get_payment_methods_stripe_sourced_from_get_stripe_status(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_xyz789")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()

    expected_stripe = _get_stripe_status()
    assert body["stripe"]["configured"] == expected_stripe.configured
    assert body["stripe"]["mode"] == expected_stripe.mode
    assert body["stripe"]["note"] == expected_stripe.note


def test_get_payment_methods_stripe_unconfigured_when_no_key(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe"]["configured"] is False
    assert body["stripe"]["mode"] == "unconfigured"


def test_get_payment_methods_stripe_test_mode(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe"]["configured"] is True
    assert body["stripe"]["mode"] == "test"


def test_get_payment_methods_stripe_live_mode(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_prodkey")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe"]["configured"] is True
    assert body["stripe"]["mode"] == "live"


# ---------------------------------------------------------------------------
# stripe_mode scalar consistent with stripe.mode
# ---------------------------------------------------------------------------


def test_get_payment_methods_stripe_mode_scalar_consistent_with_stripe_block_test(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe_mode"] == body["stripe"]["mode"]


def test_get_payment_methods_stripe_mode_scalar_consistent_with_stripe_block_live(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_prodkey")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe_mode"] == body["stripe"]["mode"]


def test_get_payment_methods_stripe_mode_scalar_is_none_when_unconfigured(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Test Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe_mode"] is None


# ---------------------------------------------------------------------------
# BillingPaymentMethodsResponse shape (Supabase mocked as configured)
# ---------------------------------------------------------------------------


def test_get_payment_methods_full_response_required_keys(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    for key in (
        "generatedat",
        "environment",
        "organizationid",
        "organizationname",
        "stripe_customer_id",
        "stripe",
        "stripe_mode",
        "defaultmethodid",
        "methods",
        "methodcount",
        "canaddnew",
        "maxmethods",
        "statuscounts",
        "tokens_per_unit",
        "package_catalogue",
        "notes",
    ):
        assert key in body, f"missing key: {key}"


def test_get_payment_methods_maxmethods_is_4(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["maxmethods"] == 4


def test_get_payment_methods_canaddnew_true_when_zero_methods(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["canaddnew"] is True
    assert body["methodcount"] == 0


def test_get_payment_methods_canaddnew_false_when_at_max(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod
    from app.ui.billing.payment_methods import BillingPaymentMethodView

    def _utc_iso_helper(y: int, m: int, d: int) -> str:
        from datetime import UTC, datetime

        return datetime(y, m, d, 9, 0, 0, tzinfo=UTC).isoformat()

    def _make_method(idx: int) -> BillingPaymentMethodView:
        return BillingPaymentMethodView(
            methodid=f"pm-00{idx}",
            type="card",
            brand="visa",
            branddisplay="Visa",
            last4=f"{1000 + idx}",
            expmonth=12,
            expyear=2028,
            expdisplay="12/2028",
            isdefault=(idx == 1),
            status="active",
            statuscolor="success",
            createdat=_utc_iso_helper(2026, 1, idx),
            organizationid="org-001",
        )

    four_methods = [_make_method(i) for i in range(1, 5)]

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: four_methods)
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: "cus_abc")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["canaddnew"] is False
    assert body["methodcount"] == 4


# ---------------------------------------------------------------------------
# package_catalogue — stripe_price_id injected from env
# ---------------------------------------------------------------------------


def test_get_payment_methods_package_catalogue_has_all_plans(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    catalogue = body["package_catalogue"]
    assert set(catalogue.keys()) == set(PACKAGE_CATALOGUE.keys())


def test_get_payment_methods_package_catalogue_entries_have_stripe_price_id(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    for plan, entry in body["package_catalogue"].items():
        assert "stripe_price_id" in entry, f"plan '{plan}' missing stripe_price_id"
        assert isinstance(entry["stripe_price_id"], str)


def test_get_payment_methods_package_catalogue_stripe_price_id_from_env(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.setenv("STRIPE_PRICE_ID_STARTER", "price_starter_test_123")
    monkeypatch.setenv("STRIPE_PRICE_ID_TEAM", "price_team_test_456")
    monkeypatch.setenv("STRIPE_PRICE_ID_ENTERPRISE", "price_enterprise_test_789")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    catalogue = body["package_catalogue"]
    assert catalogue["starter"]["stripe_price_id"] == "price_starter_test_123"
    assert catalogue["team"]["stripe_price_id"] == "price_team_test_456"
    assert catalogue["enterprise"]["stripe_price_id"] == "price_enterprise_test_789"


def test_get_payment_methods_package_catalogue_stripe_price_id_empty_when_env_unset(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.delenv("STRIPE_PRICE_ID_STARTER", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_ID_TEAM", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_ID_ENTERPRISE", raising=False)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    catalogue = body["package_catalogue"]
    for plan in PACKAGE_CATALOGUE:
        assert catalogue[plan]["stripe_price_id"] == ""


def test_get_payment_methods_package_catalogue_entry_has_required_fields(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    for plan, entry in body["package_catalogue"].items():
        for field in ("label", "units", "price_usd", "price_cents", "tokens_per_unit", "token_coverage", "stripe_price_id", "notes"):
            assert field in entry, f"plan '{plan}' catalogue entry missing field: {field}"


# ---------------------------------------------------------------------------
# POST /ui/billing/payment-methods — 503 when Supabase unconfigured
# ---------------------------------------------------------------------------


def test_post_payment_method_503_when_supabase_unconfigured(
    client: TestClient,
) -> None:
    payload = {"stripe_payment_method_id": "pm_test_abc123", "set_as_default": False}
    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)
    assert resp.status_code == 503


def test_post_payment_method_503_detail_mentions_supabase(
    client: TestClient,
) -> None:
    payload = {"stripe_payment_method_id": "pm_test_abc123", "set_as_default": False}
    body = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload).json()
    assert "supabase" in body["detail"].lower()


# ---------------------------------------------------------------------------
# POST /ui/billing/payment-methods — 409 when _MAX_METHODS cap reached
# ---------------------------------------------------------------------------


def test_post_payment_method_409_when_max_methods_reached(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod
    from app.ui.billing.payment_methods import BillingPaymentMethodView

    def _utc_iso_helper(y: int, m: int, d: int) -> str:
        from datetime import UTC, datetime

        return datetime(y, m, d, 9, 0, 0, tzinfo=UTC).isoformat()

    def _make_method(idx: int) -> BillingPaymentMethodView:
        return BillingPaymentMethodView(
            methodid=f"pm-00{idx}",
            type="card",
            brand="visa",
            branddisplay="Visa",
            last4=f"{1000 + idx}",
            expmonth=12,
            expyear=2028,
            expdisplay="12/2028",
            isdefault=(idx == 1),
            status="active",
            statuscolor="success",
            createdat=_utc_iso_helper(2026, 1, idx),
            organizationid="org-001",
        )

    four_methods = [_make_method(i) for i in range(1, 5)]

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: four_methods)

    payload = {"stripe_payment_method_id": "pm_new_xyz", "set_as_default": False}
    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)
    assert resp.status_code == 409


def test_post_payment_method_409_detail_mentions_max(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod
    from app.ui.billing.payment_methods import BillingPaymentMethodView

    def _utc_iso_helper(y: int, m: int, d: int) -> str:
        from datetime import UTC, datetime

        return datetime(y, m, d, 9, 0, 0, tzinfo=UTC).isoformat()

    def _make_method(idx: int) -> BillingPaymentMethodView:
        return BillingPaymentMethodView(
            methodid=f"pm-00{idx}",
            type="card",
            brand="visa",
            branddisplay="Visa",
            last4=f"{1000 + idx}",
            expmonth=12,
            expyear=2028,
            expdisplay="12/2028",
            isdefault=(idx == 1),
            status="active",
            statuscolor="success",
            createdat=_utc_iso_helper(2026, 1, idx),
            organizationid="org-001",
        )

    four_methods = [_make_method(i) for i in range(1, 5)]
    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: four_methods)

    payload = {"stripe_payment_method_id": "pm_new_xyz", "set_as_default": False}
    body = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload).json()
    detail = body["detail"].lower()
    assert "maximum" in detail or "4" in detail


def test_post_payment_method_201_when_under_max(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_insert_payment_method_record", lambda **kw: "pm-new-001")

    payload = {"stripe_payment_method_id": "pm_test_abc", "set_as_default": False}
    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)
    assert resp.status_code == 201


def test_post_payment_method_response_shape(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_insert_payment_method_record", lambda **kw: "pm-new-001")

    payload = {"stripe_payment_method_id": "pm_test_abc", "set_as_default": True}
    body = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload).json()
    assert body["status"] == "created"
    assert body["methodid"] == "pm-new-001"
    assert body["organizationid"] == "org-001"
    assert body["set_as_default"] is True
    assert isinstance(body["generatedat"], str)
    assert isinstance(body["environment"], str)
    assert isinstance(body["message"], str)


def test_post_payment_method_500_when_insert_returns_none(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_insert_payment_method_record", lambda **kw: None)

    payload = {"stripe_payment_method_id": "pm_test_abc", "set_as_default": False}
    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)
    assert resp.status_code == 500


# ---------------------------------------------------------------------------
# PATCH /ui/billing/payment-methods/{methodid}/default
# ---------------------------------------------------------------------------


def test_patch_default_503_when_supabase_unconfigured(client: TestClient) -> None:
    resp = client.patch("/ui/billing/payment-methods/pm-001/default?organizationid=org-001")
    assert resp.status_code == 503


def test_patch_default_200_response_shape(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_set_default_method_in_db", lambda **kw: True)

    resp = client.patch("/ui/billing/payment-methods/pm-001/default?organizationid=org-001")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "updated"
    assert body["methodid"] == "pm-001"
    assert body["organizationid"] == "org-001"
    assert isinstance(body["generatedat"], str)
    assert isinstance(body["environment"], str)
    assert isinstance(body["message"], str)
    assert len(body["message"]) > 0


def test_patch_default_500_when_db_fails(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_set_default_method_in_db", lambda **kw: False)

    resp = client.patch("/ui/billing/payment-methods/pm-001/default?organizationid=org-001")
    assert resp.status_code == 500


def test_patch_default_message_identifies_method_and_org(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_set_default_method_in_db", lambda **kw: True)

    body = client.patch("/ui/billing/payment-methods/pm-007/default?organizationid=org-002").json()
    assert "pm-007" in body["message"]
    assert "org-002" in body["message"]


# ---------------------------------------------------------------------------
# DELETE /ui/billing/payment-methods/{methodid}
# ---------------------------------------------------------------------------


def test_delete_method_503_when_supabase_unconfigured(client: TestClient) -> None:
    resp = client.delete("/ui/billing/payment-methods/pm-001?organizationid=org-001")
    assert resp.status_code == 503


def test_delete_method_200_response_shape(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_delete_method_from_db", lambda **kw: True)

    resp = client.delete("/ui/billing/payment-methods/pm-001?organizationid=org-001")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "deleted"
    assert body["methodid"] == "pm-001"
    assert body["organizationid"] == "org-001"
    assert isinstance(body["generatedat"], str)
    assert isinstance(body["environment"], str)
    assert isinstance(body["message"], str)
    assert len(body["message"]) > 0


def test_delete_method_500_when_db_fails(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_delete_method_from_db", lambda **kw: False)

    resp = client.delete("/ui/billing/payment-methods/pm-001?organizationid=org-001")
    assert resp.status_code == 500


def test_delete_method_message_identifies_method_and_org(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_delete_method_from_db", lambda **kw: True)

    body = client.delete("/ui/billing/payment-methods/pm-005?organizationid=org-003").json()
    assert "pm-005" in body["message"]
    assert "org-003" in body["message"]


# ---------------------------------------------------------------------------
# notes block
# ---------------------------------------------------------------------------


def test_get_payment_methods_notes_non_empty_when_supabase_configured(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert len(body["notes"]) >= 1
    for note in body["notes"]:
        assert isinstance(note, str)
        assert len(note) > 0


def test_get_payment_methods_notes_include_stripe_note(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ui.billing.payment_methods as pm_mod

    monkeypatch.setattr(pm_mod, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(pm_mod, "_fetch_org_payment_methods", lambda org: [])
    monkeypatch.setattr(pm_mod, "_fetch_org_name", lambda org: "Alpha Org")
    monkeypatch.setattr(pm_mod, "_fetch_stripe_customer_id", lambda org: None)
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    combined_notes = " ".join(body["notes"]).lower()
    assert "stripe" in combined_notes
