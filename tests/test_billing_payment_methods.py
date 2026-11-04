from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.supabaseclient import TOKENS_PER_UNIT
from app.ui.billing.payment_methods import (
    _BRAND_DISPLAY,
    _MAX_METHODS,
    _STATUS_COLOR,
    BillingPaymentMethodsResponse,
    BillingPaymentMethodStatusCount,
    BillingPaymentMethodView,
    DeletePaymentMethodResponse,
    PackageCatalogueEntry,
    SetDefaultPaymentMethodResponse,
    _brand_display,
    _build_method,
    _build_method_from_stripe,
    _build_package_catalogue,
    _build_status_counts,
    _exp_display,
    _fetch_payment_methods_from_stripe,
    _get_environment,
    _method_brand,
    _method_created_at,
    _method_exp_month,
    _method_exp_year,
    _method_is_default,
    _method_last4,
    _method_status,
    _method_type,
    _normalize_method_id,
    _resolve_default_method_id,
    _resolve_org_id,
    _resolve_org_id_from_request,
    _status_color,
    _stripe_connection_note,
    _stripe_mode,
    _stripe_webhook_secret_note,
)


def make_method(
    methodid: str = "pm-001",
    type: str = "card",
    brand: str = "visa",
    last4: str = "4242",
    expmonth: int = 12,
    expyear: int = 2027,
    isdefault: bool = False,
    status: str = "active",
    createdat: str = "2025-01-01T00:00:00+00:00",
    organizationid: str = "org-001",
) -> BillingPaymentMethodView:
    return _build_method(
        methodid=methodid,
        type=type,
        brand=brand,
        last4=last4,
        expmonth=expmonth,
        expyear=expyear,
        isdefault=isdefault,
        status=status,
        createdat=createdat,
        organizationid=organizationid,
    )


class DummyRequest:
    def __init__(self, query_params: dict[str, str] | None = None) -> None:
        self.query_params = query_params or {}


class TestBuildMethod:
    def test_returns_billing_payment_method_view_instance(self) -> None:
        result = make_method()
        assert isinstance(result, BillingPaymentMethodView)

    def test_build_method_all_fields_populated(self) -> None:
        result = make_method(
            methodid="pm-999",
            type="card",
            brand="mastercard",
            last4="1234",
            expmonth=3,
            expyear=2029,
            isdefault=True,
            status="active",
            createdat="2026-06-01T00:00:00+00:00",
            organizationid="org-abc",
        )
        assert result.methodid == "pm-999"
        assert result.type == "card"
        assert result.brand == "mastercard"
        assert result.branddisplay == "Mastercard"
        assert result.last4 == "1234"
        assert result.expmonth == 3
        assert result.expyear == 2029
        assert result.expdisplay == "03/2029"
        assert result.isdefault is True
        assert result.status == "active"
        assert result.statuscolor == "success"
        assert result.createdat == "2026-06-01T00:00:00+00:00"
        assert result.organizationid == "org-abc"

    def test_branddisplay_derived_from_brand(self) -> None:
        result = make_method(brand="amex")
        assert result.branddisplay == "American Express"

    def test_expdisplay_derived_from_expmonth_expyear(self) -> None:
        result = make_method(expmonth=7, expyear=2031)
        assert result.expdisplay == "07/2031"

    def test_statuscolor_derived_from_status(self) -> None:
        for status, expected_color in _STATUS_COLOR.items():
            result = make_method(status=status)
            assert result.statuscolor == expected_color

    def test_unknown_status_statuscolor_is_neutral(self) -> None:
        result = make_method(status="unrecognized-status")
        assert result.statuscolor == "neutral"

    def test_isdefault_false_propagates(self) -> None:
        result = make_method(isdefault=False)
        assert result.isdefault is False

    def test_isdefault_true_propagates(self) -> None:
        result = make_method(methodid="pm-002", isdefault=True)
        assert result.isdefault is True

    def test_unknown_brand_falls_back_to_title_in_branddisplay(self) -> None:
        result = make_method(brand="custom_brand_name")
        assert result.branddisplay == "Custom Brand Name"

    def test_single_digit_month_zero_padded_in_expdisplay(self) -> None:
        result = make_method(expmonth=1, expyear=2030)
        assert result.expdisplay == "01/2030"

    def test_invalid_exp_values_return_empty_expdisplay(self) -> None:
        result = make_method(expmonth=0, expyear=0)
        assert result.expdisplay == ""


class TestPackageCatalogue:
    def test_catalogue_keys_present(self) -> None:
        catalogue = _build_package_catalogue()
        assert set(catalogue.keys()) == {"starter", "team", "enterprise"}

    def test_catalogue_entries_can_be_loaded_into_model(self) -> None:
        catalogue = _build_package_catalogue()
        for value in catalogue.values():
            entry = PackageCatalogueEntry(**value)
            assert isinstance(entry, PackageCatalogueEntry)
            assert isinstance(entry.stripe_price_id, str)
            assert entry.tokens_per_unit == TOKENS_PER_UNIT

    def test_stripe_price_id_empty_when_env_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("STRIPE_PRICE_ID_STARTER", raising=False)
        monkeypatch.delenv("STRIPE_PRICE_ID_TEAM", raising=False)
        monkeypatch.delenv("STRIPE_PRICE_ID_ENTERPRISE", raising=False)
        catalogue = _build_package_catalogue()
        assert catalogue["starter"]["stripe_price_id"] == ""
        assert catalogue["team"]["stripe_price_id"] == ""
        assert catalogue["enterprise"]["stripe_price_id"] == ""

    def test_stripe_price_id_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_PRICE_ID_STARTER", "price_test_starter_123")
        monkeypatch.setenv("STRIPE_PRICE_ID_TEAM", "price_test_team_123")
        monkeypatch.setenv("STRIPE_PRICE_ID_ENTERPRISE", "price_test_enterprise_123")
        catalogue = _build_package_catalogue()
        assert catalogue["starter"]["stripe_price_id"] == "price_test_starter_123"
        assert catalogue["team"]["stripe_price_id"] == "price_test_team_123"
        assert catalogue["enterprise"]["stripe_price_id"] == "price_test_enterprise_123"

    def test_package_catalogue_entry_types(self) -> None:
        catalogue = _build_package_catalogue()
        for key in ("starter", "team", "enterprise"):
            entry = PackageCatalogueEntry(**catalogue[key])
            assert isinstance(entry.label, str)
            assert isinstance(entry.units, int)
            assert isinstance(entry.price_usd, int)
            assert isinstance(entry.price_cents, int)
            assert isinstance(entry.tokens_per_unit, int)
            assert isinstance(entry.token_coverage, int)
            assert isinstance(entry.stripe_price_id, str)
            assert isinstance(entry.notes, str)


class TestBuildStatusCounts:
    def test_empty_list_returns_empty(self) -> None:
        assert _build_status_counts([]) == []

    def test_single_status_single_count(self) -> None:
        result = _build_status_counts([make_method(status="active")])
        assert len(result) == 1
        assert result[0].status == "active"
        assert result[0].count == 1
        assert result[0].statuscolor == "success"

    def test_multiple_same_status_counts_correctly(self) -> None:
        methods = [
            make_method(methodid="pm-001", status="active"),
            make_method(methodid="pm-002", status="active"),
            make_method(methodid="pm-003", status="active"),
        ]
        result = _build_status_counts(methods)
        assert len(result) == 1
        assert result[0].status == "active"
        assert result[0].count == 3

    def test_multiple_statuses_grouped_correctly(self) -> None:
        methods = [
            make_method(methodid="pm-001", status="active"),
            make_method(methodid="pm-002", status="expired"),
            make_method(methodid="pm-003", status="active"),
            make_method(methodid="pm-004", status="revoked"),
        ]
        result = _build_status_counts(methods)
        counts_by_status = {item.status: item.count for item in result}
        assert counts_by_status["active"] == 2
        assert counts_by_status["expired"] == 1
        assert counts_by_status["revoked"] == 1

    def test_sorted_by_status_alphabetically(self) -> None:
        methods = [
            make_method(methodid="pm-001", status="revoked"),
            make_method(methodid="pm-002", status="active"),
            make_method(methodid="pm-003", status="expired"),
        ]
        result = _build_status_counts(methods)
        statuses = [item.status for item in result]
        assert statuses == sorted(statuses)

    def test_statuscolor_applied_to_each_count(self) -> None:
        methods = [
            make_method(methodid="pm-001", status="active"),
            make_method(methodid="pm-002", status="expired"),
            make_method(methodid="pm-003", status="revoked"),
            make_method(methodid="pm-004", status="pending"),
        ]
        result = _build_status_counts(methods)
        by_status = {item.status: item.statuscolor for item in result}
        assert by_status["active"] == "success"
        assert by_status["expired"] == "warning"
        assert by_status["revoked"] == "error"
        assert by_status["pending"] == "info"

    def test_unknown_status_statuscolor_is_neutral(self) -> None:
        result = _build_status_counts([make_method(status="unknown-custom")])
        assert result[0].statuscolor == "neutral"

    def test_returns_status_count_models(self) -> None:
        result = _build_status_counts([make_method(status="active")])
        assert all(isinstance(item, BillingPaymentMethodStatusCount) for item in result)


class TestResolveDefaultMethodId:
    def test_returns_none_when_no_methods(self) -> None:
        assert _resolve_default_method_id([]) is None

    def test_returns_none_when_no_default(self) -> None:
        methods = [
            make_method(methodid="pm-001", isdefault=False),
            make_method(methodid="pm-002", isdefault=False),
        ]
        assert _resolve_default_method_id(methods) is None

    def test_returns_methodid_of_default(self) -> None:
        methods = [
            make_method(methodid="pm-001", isdefault=False),
            make_method(methodid="pm-002", isdefault=True),
            make_method(methodid="pm-003", isdefault=False),
        ]
        assert _resolve_default_method_id(methods) == "pm-002"

    def test_returns_first_default_when_multiple(self) -> None:
        methods = [
            make_method(methodid="pm-001", isdefault=True),
            make_method(methodid="pm-002", isdefault=True),
        ]
        assert _resolve_default_method_id(methods) == "pm-001"


class TestExpDisplay:
    def test_single_digit_month_zero_padded(self) -> None:
        assert _exp_display(1, 2027) == "01/2027"

    def test_double_digit_month(self) -> None:
        assert _exp_display(12, 2030) == "12/2030"

    def test_month_9_zero_padded(self) -> None:
        assert _exp_display(9, 2025) == "09/2025"

    def test_returns_empty_for_invalid_values(self) -> None:
        assert _exp_display(0, 2026) == ""
        assert _exp_display(-1, 2026) == ""
        assert _exp_display(6, 0) == ""


class TestBrandDisplay:
    def test_known_brand_values(self) -> None:
        assert _brand_display("visa") == "Visa"
        assert _brand_display("mastercard") == "Mastercard"
        assert _brand_display("amex") == "American Express"
        assert _brand_display("discover") == "Discover"
        assert _brand_display("bank_account") == "Bank Account"

    def test_unknown_brand_falls_back_to_title(self) -> None:
        assert _brand_display("unionpay_special") == "Unionpay Special"

    def test_empty_string_returns_unknown(self) -> None:
        assert _brand_display("") == "Unknown"

    def test_brand_display_map_contains_expected_keys(self) -> None:
        assert "visa" in _BRAND_DISPLAY
        assert "mastercard" in _BRAND_DISPLAY
        assert "amex" in _BRAND_DISPLAY
        assert "discover" in _BRAND_DISPLAY
        assert "bank_account" in _BRAND_DISPLAY


class TestStripeHelpers:
    def test_live_key_returns_live(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc123")
        assert _stripe_mode() == "live"

    def test_test_key_returns_test(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")
        assert _stripe_mode() == "test"

    def test_invalid_key_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_SECRET_KEY", "pk_live_not_secret")
        assert _stripe_mode() is None

    def test_empty_key_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_SECRET_KEY", "")
        assert _stripe_mode() is None

    def test_live_connection_note(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc123")
        note = _stripe_connection_note()
        assert "live" in note.lower()
        assert "connected" in note.lower()

    def test_test_connection_note(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")
        note = _stripe_connection_note()
        assert "test" in note.lower()
        assert "connected" in note.lower()

    def test_unconfigured_connection_note(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
        note = _stripe_connection_note()
        assert "not configured" in note.lower() or "unavailable" in note.lower()

    def test_valid_webhook_secret_note(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_abc123")
        note = _stripe_webhook_secret_note()
        assert "configured" in note.lower()

    def test_invalid_webhook_secret_note(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "invalid_secret")
        note = _stripe_webhook_secret_note()
        assert "not configured" in note.lower()
        assert "STRIPE_WEBHOOK_SECRET" in note


class TestEnvironmentHelpers:
    def test_get_environment_prefers_ironclaw_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IRONCLAW_ENV", "staging")
        monkeypatch.setenv("APP_ENV", "development")
        assert _get_environment() == "staging"

    def test_get_environment_falls_back_to_app_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IRONCLAW_ENV", raising=False)
        monkeypatch.setenv("APP_ENV", "development")
        assert _get_environment() == "development"

    def test_get_environment_defaults_to_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IRONCLAW_ENV", raising=False)
        monkeypatch.delenv("APP_ENV", raising=False)
        assert _get_environment() == "production"


class TestMethodExtractionHelpers:
    def test_method_created_at_from_dict(self) -> None:
        value = _method_created_at({"created_at": "2025-01-01T00:00:00+00:00"})
        assert value == "2025-01-01T00:00:00+00:00"

    def test_method_created_at_from_object(self) -> None:
        raw = SimpleNamespace(created_at="2026-02-03T04:05:06+00:00")
        assert _method_created_at(raw) == "2026-02-03T04:05:06+00:00"

    def test_method_created_at_defaults_to_isoformat(self) -> None:
        value = _method_created_at({})
        assert isinstance(value, str)
        assert "T" in value

    def test_method_brand_type_last4(self) -> None:
        raw = {"brand": "visa", "type": "card", "last4": "4242"}
        assert _method_brand(raw) == "visa"
        assert _method_type(raw) == "card"
        assert _method_last4(raw) == "4242"

    def test_method_exp_month_and_year_from_dict(self) -> None:
        raw = {"exp_month": 12, "exp_year": 2030}
        assert _method_exp_month(raw) == 12
        assert _method_exp_year(raw) == 2030

    def test_method_exp_month_and_year_invalid_values_become_zero(self) -> None:
        raw = {"exp_month": "bad", "exp_year": None}
        assert _method_exp_month(raw) == 0
        assert _method_exp_year(raw) == 0

    def test_method_is_default_truthy_aliases(self) -> None:
        assert _method_is_default({"is_default": True}) is True
        assert _method_is_default({"isdefault": True}) is True
        assert _method_is_default({"default": True}) is True

    def test_method_status_uses_explicit_status_when_present(self) -> None:
        assert _method_status({"status": "pending"}) == "pending"

    def test_method_status_detects_expired(self) -> None:
        now = datetime.now(UTC)
        expired_year = now.year - 1
        assert _method_status({"exp_month": 1, "exp_year": expired_year}) == "expired"

    def test_method_status_defaults_active_when_not_expired(self) -> None:
        now = datetime.now(UTC)
        future = now + timedelta(days=365)
        assert _method_status({"exp_month": future.month, "exp_year": future.year}) == "active"

    def test_build_method_from_stripe_dict(self) -> None:
        raw = {
            "payment_method_id": "pm-stripe-123",
            "type": "card",
            "brand": "visa",
            "last4": "4242",
            "exp_month": 9,
            "exp_year": 2032,
            "is_default": True,
            "status": "active",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        result = _build_method_from_stripe(raw, organizationid="org-123")
        assert result.methodid == "pm-stripe-123"
        assert result.organizationid == "org-123"
        assert result.branddisplay == "Visa"
        assert result.expdisplay == "09/2032"
        assert result.isdefault is True

    def test_normalize_method_id(self) -> None:
        assert _normalize_method_id(" pm-123 ") == "pm-123"
        assert _normalize_method_id(None) == ""


class TestOrgResolutionHelpers:
    def test_resolve_org_id_prefers_org_id(self) -> None:
        auth = SimpleNamespace(org_id="org-123", tenant_id="tenant-456")
        assert _resolve_org_id(auth) == "org-123"

    def test_resolve_org_id_falls_back_to_tenant_id(self) -> None:
        auth = SimpleNamespace(org_id=None, tenant_id="tenant-456")
        assert _resolve_org_id(auth) == "tenant-456"

    def test_resolve_org_id_empty_when_none(self) -> None:
        assert _resolve_org_id(None) == ""

    def test_resolve_org_id_from_request_uses_query_fallbacks(self) -> None:
        auth = SimpleNamespace(org_id=None, tenant_id=None)
        assert _resolve_org_id_from_request(auth, DummyRequest({"organizationid": "org-a"})) == "org-a"
        assert _resolve_org_id_from_request(auth, DummyRequest({"organization_id": "org-b"})) == "org-b"
        assert _resolve_org_id_from_request(auth, DummyRequest({"organizationId": "org-c"})) == "org-c"

    def test_resolve_org_id_from_request_prefers_auth(self) -> None:
        auth = SimpleNamespace(org_id="org-auth", tenant_id=None)
        request = DummyRequest({"organizationid": "org-query"})
        assert _resolve_org_id_from_request(auth, request) == "org-auth"


class TestFetchPaymentMethodsFromStripe:
    def test_returns_none_and_empty_when_no_customer_mapping(self) -> None:
        svc = SimpleNamespace(
            resolve_customer_id=lambda _org_id: None,
            list_payment_methods=MagicMock(),
        )
        customer_id, methods = _fetch_payment_methods_from_stripe(svc=svc, organizationid="org-001")
        assert customer_id is None
        assert methods == []
        svc.list_payment_methods.assert_not_called()

    def test_returns_customer_id_and_methods(self) -> None:
        raw_methods = [
            {
                "payment_method_id": "pm-001",
                "brand": "visa",
                "type": "card",
                "last4": "4242",
                "exp_month": 12,
                "exp_year": 2030,
                "is_default": True,
                "status": "active",
                "created_at": "2025-01-01T00:00:00+00:00",
            },
            {
                "payment_method_id": "pm-002",
                "brand": "amex",
                "type": "card",
                "last4": "0005",
                "exp_month": 11,
                "exp_year": 2031,
                "is_default": False,
                "status": "pending",
                "created_at": "2025-01-02T00:00:00+00:00",
            },
        ]
        list_payment_methods = MagicMock(return_value=raw_methods)
        svc = SimpleNamespace(
            resolve_customer_id=lambda org_id: {"org-001": "cus-123"}.get(org_id),
            list_payment_methods=list_payment_methods,
        )

        customer_id, methods = _fetch_payment_methods_from_stripe(svc=svc, organizationid="org-001")

        assert customer_id == "cus-123"
        assert len(methods) == 2
        assert methods[0].methodid == "pm-001"
        assert methods[0].isdefault is True
        assert methods[1].branddisplay == "American Express"
        list_payment_methods.assert_called_once_with(customer_id="cus-123")


class TestResponseModels:
    def test_billing_payment_methods_response_accepts_fields(self) -> None:
        response = BillingPaymentMethodsResponse(
            generatedat="2026-01-01T00:00:00+00:00",
            environment="test",
            organizationid="org-001",
            organizationname="Test Org",
            stripe_customer_id="cus-123",
            stripe_mode="test",
            defaultmethodid="pm-001",
            methods=[make_method(methodid="pm-001", isdefault=True)],
            methodcount=1,
            canaddnew=True,
            maxmethods=_MAX_METHODS,
            statuscounts=[BillingPaymentMethodStatusCount(status="active", count=1, statuscolor="success")],
            tokens_per_unit=TOKENS_PER_UNIT,
            package_catalogue={},
            notes=["ok"],
        )
        data = response.model_dump()
        assert data["stripe_customer_id"] == "cus-123"
        assert data["stripe_mode"] == "test"
        assert data["organizationid"] == "org-001"

    def test_set_default_response_shape(self) -> None:
        response = SetDefaultPaymentMethodResponse(
            status="updated",
            methodid="pm-001",
            organizationid="org-001",
            generatedat="2026-01-01T00:00:00+00:00",
            environment="test",
            message="updated",
        )
        assert response.status == "updated"
        assert response.methodid == "pm-001"

    def test_delete_response_shape(self) -> None:
        response = DeletePaymentMethodResponse(
            status="deleted",
            methodid="pm-001",
            organizationid="org-001",
            generatedat="2026-01-01T00:00:00+00:00",
            environment="test",
            message="deleted",
        )
        assert response.status == "deleted"
        assert response.methodid == "pm-001"


class TestConstants:
    def test_max_methods_constant_is_four(self) -> None:
        assert _MAX_METHODS == 4

    def test_status_color_map_values(self) -> None:
        assert _STATUS_COLOR["active"] == "success"
        assert _STATUS_COLOR["expired"] == "warning"
        assert _STATUS_COLOR["revoked"] == "error"
        assert _STATUS_COLOR["pending"] == "info"

    def test_status_color_map_keys_complete(self) -> None:
        assert set(_STATUS_COLOR.keys()) == {"active", "expired", "revoked", "pending"}

    def test_status_color_helper_returns_neutral_for_unknown(self) -> None:
        assert _status_color("not-real") == "neutral"
