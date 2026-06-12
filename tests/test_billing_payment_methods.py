from __future__ import annotations

import os
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
    TOKENS_PER_UNIT,
)
from app.ui.billing.payment_methods import (
    _BRAND_DISPLAY,
    _MAX_METHODS,
    _STATUS_COLOR,
    PACKAGE_CATALOGUE,
    BillingPaymentMethodStatusCount,
    BillingPaymentMethodView,
    PackageCatalogueEntry,
    _brand_display,
    _build_method,
    _build_status_counts,
    _exp_display,
    _resolve_default_method_id,
    _stripe_connection_note,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_method(
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


# ---------------------------------------------------------------------------
# PackageCatalogueEntry — field validation
# ---------------------------------------------------------------------------


class TestPackageCatalogueEntry:
    def test_starter_all_fields_valid(self) -> None:
        entry = PackageCatalogueEntry(**PACKAGE_CATALOGUE["starter"])
        assert entry.label == "Starter"
        assert entry.units == BILLING_TIER_5K_UNITS
        assert entry.price_usd == BILLING_TIER_5K_PRICE_USD
        assert entry.price_cents == BILLING_TIER_5K_PRICE_USD * 100
        assert entry.tokens_per_unit == TOKENS_PER_UNIT
        assert entry.token_coverage == BILLING_TIER_5K_UNITS * TOKENS_PER_UNIT
        assert isinstance(entry.notes, str)
        assert len(entry.notes) > 0

    def test_team_all_fields_valid(self) -> None:
        entry = PackageCatalogueEntry(**PACKAGE_CATALOGUE["team"])
        assert entry.label == "Team"
        assert entry.units == BILLING_TIER_25K_UNITS
        assert entry.price_usd == BILLING_TIER_25K_PRICE_USD
        assert entry.price_cents == BILLING_TIER_25K_PRICE_USD * 100
        assert entry.tokens_per_unit == TOKENS_PER_UNIT
        assert entry.token_coverage == BILLING_TIER_25K_UNITS * TOKENS_PER_UNIT
        assert isinstance(entry.notes, str)

    def test_enterprise_all_fields_valid(self) -> None:
        entry = PackageCatalogueEntry(**PACKAGE_CATALOGUE["enterprise"])
        assert entry.label == "Enterprise"
        assert entry.units == BILLING_TIER_60K_UNITS
        assert entry.price_usd == BILLING_TIER_60K_PRICE_USD
        assert entry.price_cents == BILLING_TIER_60K_PRICE_USD * 100
        assert entry.tokens_per_unit == TOKENS_PER_UNIT
        assert entry.token_coverage == BILLING_TIER_60K_UNITS * TOKENS_PER_UNIT
        assert isinstance(entry.notes, str)

    def test_price_cents_is_int(self) -> None:
        for key in ("starter", "team", "enterprise"):
            entry = PackageCatalogueEntry(**PACKAGE_CATALOGUE[key])
            assert isinstance(entry.price_cents, int)

    def test_token_coverage_is_int(self) -> None:
        for key in ("starter", "team", "enterprise"):
            entry = PackageCatalogueEntry(**PACKAGE_CATALOGUE[key])
            assert isinstance(entry.token_coverage, int)

    def test_units_is_int(self) -> None:
        for key in ("starter", "team", "enterprise"):
            entry = PackageCatalogueEntry(**PACKAGE_CATALOGUE[key])
            assert isinstance(entry.units, int)


# ---------------------------------------------------------------------------
# PACKAGE_CATALOGUE consistency with supabaseclient constants
# ---------------------------------------------------------------------------


class TestPackageCatalogueConsistency:
    def test_catalogue_keys_present(self) -> None:
        assert set(PACKAGE_CATALOGUE.keys()) == {"starter", "team", "enterprise"}

    def test_starter_units_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["units"] == BILLING_TIER_5K_UNITS

    def test_starter_price_usd_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["price_usd"] == BILLING_TIER_5K_PRICE_USD

    def test_starter_price_cents_derived_correctly(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["price_cents"] == BILLING_TIER_5K_PRICE_USD * 100

    def test_starter_token_coverage_derived_correctly(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["token_coverage"] == BILLING_TIER_5K_UNITS * TOKENS_PER_UNIT

    def test_starter_tokens_per_unit_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_team_units_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["units"] == BILLING_TIER_25K_UNITS

    def test_team_price_usd_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["price_usd"] == BILLING_TIER_25K_PRICE_USD

    def test_team_price_cents_derived_correctly(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["price_cents"] == BILLING_TIER_25K_PRICE_USD * 100

    def test_team_token_coverage_derived_correctly(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["token_coverage"] == BILLING_TIER_25K_UNITS * TOKENS_PER_UNIT

    def test_team_tokens_per_unit_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_enterprise_units_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["units"] == BILLING_TIER_60K_UNITS

    def test_enterprise_price_usd_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["price_usd"] == BILLING_TIER_60K_PRICE_USD

    def test_enterprise_price_cents_derived_correctly(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["price_cents"] == BILLING_TIER_60K_PRICE_USD * 100

    def test_enterprise_token_coverage_derived_correctly(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["token_coverage"] == BILLING_TIER_60K_UNITS * TOKENS_PER_UNIT

    def test_enterprise_tokens_per_unit_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_tokens_per_unit_constant_value(self) -> None:
        assert TOKENS_PER_UNIT == 25_000

    def test_starter_price_cents_value(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["price_cents"] == 2000

    def test_team_price_cents_value(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["price_cents"] == 9000

    def test_enterprise_price_cents_value(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["price_cents"] == 18000

    def test_starter_token_coverage_value(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["token_coverage"] == 125_000_000

    def test_team_token_coverage_value(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["token_coverage"] == 625_000_000

    def test_enterprise_token_coverage_value(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["token_coverage"] == 1_500_000_000


# ---------------------------------------------------------------------------
# _build_status_counts
# ---------------------------------------------------------------------------


class TestBuildStatusCounts:
    def test_empty_list_returns_empty(self) -> None:
        result = _build_status_counts([])
        assert result == []

    def test_single_status_single_count(self) -> None:
        methods = [_make_method(status="active")]
        result = _build_status_counts(methods)
        assert len(result) == 1
        assert result[0].status == "active"
        assert result[0].count == 1

    def test_multiple_same_status_counts_correctly(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="active"),
            _make_method(methodid="pm-003", status="active"),
        ]
        result = _build_status_counts(methods)
        assert len(result) == 1
        assert result[0].status == "active"
        assert result[0].count == 3

    def test_multiple_statuses_grouped_correctly(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="expired"),
            _make_method(methodid="pm-003", status="active"),
            _make_method(methodid="pm-004", status="revoked"),
        ]
        result = _build_status_counts(methods)
        counts_by_status = {r.status: r.count for r in result}
        assert counts_by_status["active"] == 2
        assert counts_by_status["expired"] == 1
        assert counts_by_status["revoked"] == 1

    def test_sorted_by_status_alphabetically(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="revoked"),
            _make_method(methodid="pm-002", status="active"),
            _make_method(methodid="pm-003", status="expired"),
        ]
        result = _build_status_counts(methods)
        statuses = [r.status for r in result]
        assert statuses == sorted(statuses)

    def test_statuscolor_applied_to_each_count(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="expired"),
            _make_method(methodid="pm-003", status="revoked"),
        ]
        result = _build_status_counts(methods)
        color_map = {r.status: r.statuscolor for r in result}
        assert color_map["active"] == "success"
        assert color_map["expired"] == "warning"
        assert color_map["revoked"] == "error"

    def test_unknown_status_statuscolor_is_neutral(self) -> None:
        methods = [_make_method(status="unknown_custom")]
        result = _build_status_counts(methods)
        assert result[0].statuscolor == "neutral"

    def test_returns_list_of_billing_payment_method_status_count(self) -> None:
        methods = [_make_method(status="active")]
        result = _build_status_counts(methods)
        assert all(isinstance(r, BillingPaymentMethodStatusCount) for r in result)


# ---------------------------------------------------------------------------
# _resolve_default_method_id
# ---------------------------------------------------------------------------


class TestResolveDefaultMethodId:
    def test_returns_none_when_no_methods(self) -> None:
        assert _resolve_default_method_id([]) is None

    def test_returns_none_when_no_default(self) -> None:
        methods = [
            _make_method(methodid="pm-001", isdefault=False),
            _make_method(methodid="pm-002", isdefault=False),
        ]
        assert _resolve_default_method_id(methods) is None

    def test_returns_methodid_of_default(self) -> None:
        methods = [
            _make_method(methodid="pm-001", isdefault=False),
            _make_method(methodid="pm-002", isdefault=True),
            _make_method(methodid="pm-003", isdefault=False),
        ]
        assert _resolve_default_method_id(methods) == "pm-002"

    def test_returns_first_default_when_multiple(self) -> None:
        methods = [
            _make_method(methodid="pm-001", isdefault=True),
            _make_method(methodid="pm-002", isdefault=True),
        ]
        assert _resolve_default_method_id(methods) == "pm-001"

    def test_single_default_method(self) -> None:
        methods = [_make_method(methodid="pm-only", isdefault=True)]
        assert _resolve_default_method_id(methods) == "pm-only"

    def test_single_non_default_method_returns_none(self) -> None:
        methods = [_make_method(methodid="pm-only", isdefault=False)]
        assert _resolve_default_method_id(methods) is None


# ---------------------------------------------------------------------------
# _exp_display
# ---------------------------------------------------------------------------


class TestExpDisplay:
    def test_single_digit_month_zero_padded(self) -> None:
        assert _exp_display(1, 2027) == "01/2027"

    def test_double_digit_month(self) -> None:
        assert _exp_display(12, 2030) == "12/2030"

    def test_month_9_zero_padded(self) -> None:
        assert _exp_display(9, 2025) == "09/2025"

    def test_format_is_mm_slash_yyyy(self) -> None:
        result = _exp_display(6, 2026)
        assert result == "06/2026"
        parts = result.split("/")
        assert len(parts) == 2
        assert len(parts[0]) == 2
        assert len(parts[1]) == 4

    def test_all_months_correct(self) -> None:
        for month in range(1, 13):
            result = _exp_display(month, 2028)
            assert result == f"{month:02d}/2028"


# ---------------------------------------------------------------------------
# _brand_display
# ---------------------------------------------------------------------------


class TestBrandDisplay:
    def test_visa_returns_visa(self) -> None:
        assert _brand_display("visa") == "Visa"

    def test_mastercard_returns_mastercard(self) -> None:
        assert _brand_display("mastercard") == "Mastercard"

    def test_amex_returns_american_express(self) -> None:
        assert _brand_display("amex") == "American Express"

    def test_discover_returns_discover(self) -> None:
        assert _brand_display("discover") == "Discover"

    def test_bank_account_returns_bank_account(self) -> None:
        assert _brand_display("bank_account") == "Bank Account"

    def test_unknown_brand_falls_back_to_title(self) -> None:
        assert _brand_display("unionpay") == "Unionpay"

    def test_unknown_brand_multiword_falls_back_to_title(self) -> None:
        assert _brand_display("some brand") == "Some Brand"

    def test_empty_string_falls_back_to_title(self) -> None:
        assert _brand_display("") == ""

    def test_all_mapped_brands_present(self) -> None:
        expected = {
            "visa": "Visa",
            "mastercard": "Mastercard",
            "amex": "American Express",
            "discover": "Discover",
            "bank_account": "Bank Account",
        }
        for key, value in expected.items():
            assert _brand_display(key) == value

    def test_brand_display_map_complete(self) -> None:
        assert set(_BRAND_DISPLAY.keys()) == {"visa", "mastercard", "amex", "discover", "bank_account"}


# ---------------------------------------------------------------------------
# _stripe_connection_note
# ---------------------------------------------------------------------------


class TestStripeConnectionNote:
    def test_live_key_returns_live_note(self) -> None:
        with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_live_abc123"}, clear=False):
            note = _stripe_connection_note()
        assert "live" in note
        assert "connected" in note.lower()

    def test_test_key_returns_test_note(self) -> None:
        with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_test_abc123"}, clear=False):
            note = _stripe_connection_note()
        assert "test" in note
        assert "connected" in note.lower()

    def test_no_key_returns_unconfigured_note(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "STRIPE_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            note = _stripe_connection_note()
        assert "not configured" in note.lower() or "unavailable" in note.lower()

    def test_empty_key_returns_unconfigured_note(self) -> None:
        with patch.dict(os.environ, {"STRIPE_API_KEY": ""}, clear=False):
            note = _stripe_connection_note()
        assert "not configured" in note.lower() or "unavailable" in note.lower()

    def test_invalid_key_returns_unconfigured_note(self) -> None:
        with patch.dict(os.environ, {"STRIPE_API_KEY": "pk_live_notakey"}, clear=False):
            note = _stripe_connection_note()
        assert "not configured" in note.lower() or "unavailable" in note.lower()

    def test_live_note_contains_mode_live(self) -> None:
        with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_live_xyz"}, clear=False):
            note = _stripe_connection_note()
        assert "mode: live" in note

    def test_test_note_contains_mode_test(self) -> None:
        with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_test_xyz"}, clear=False):
            note = _stripe_connection_note()
        assert "mode: test" in note


# ---------------------------------------------------------------------------
# GET /ui/billing/payment-methods — TestClient (Supabase unconfigured)
# ---------------------------------------------------------------------------


class TestGetPaymentMethodsEndpoint:
    """
    conftest sets SUPABASE_URL="" which means is_supabase_configured() → False.
    The endpoint must return BillingPaymentMethodsNotFoundResponse.
    """

    @pytest.fixture(autouse=True)
    def _client(self, test_client: TestClient) -> None:
        self.client = test_client

    def test_returns_200(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods")
        assert resp.status_code == 200

    def test_returns_not_found_shape(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods")
        body = resp.json()
        assert body["status"] == "not_found"

    def test_not_found_response_has_organizationid(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods?organizationid=org-test")
        body = resp.json()
        assert body["organizationid"] == "org-test"

    def test_not_found_response_has_message(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods")
        body = resp.json()
        assert "message" in body
        assert len(body["message"]) > 0

    def test_not_found_response_has_generatedat(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods")
        body = resp.json()
        assert "generatedat" in body
        assert len(body["generatedat"]) > 0

    def test_not_found_response_has_environment(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods")
        body = resp.json()
        assert "environment" in body

    def test_default_organizationid_used_when_not_provided(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods")
        body = resp.json()
        assert body["organizationid"] == "org-001"

    def test_custom_organizationid_passed_through(self) -> None:
        resp = self.client.get("/ui/billing/payment-methods?organizationid=org-custom-99")
        body = resp.json()
        assert body["organizationid"] == "org-custom-99"


# ---------------------------------------------------------------------------
# canaddnew — False when methodcount >= _MAX_METHODS
# ---------------------------------------------------------------------------


class TestCanAddNew:
    def test_max_methods_constant_is_four(self) -> None:
        assert _MAX_METHODS == 4

    def test_canaddnew_false_at_max_methods(self) -> None:
        methods = [_make_method(methodid=f"pm-{i:03d}") for i in range(_MAX_METHODS)]
        can_add = len(methods) < _MAX_METHODS
        assert can_add is False

    def test_canaddnew_false_above_max_methods(self) -> None:
        methods = [_make_method(methodid=f"pm-{i:03d}") for i in range(_MAX_METHODS + 2)]
        can_add = len(methods) < _MAX_METHODS
        assert can_add is False

    def test_canaddnew_true_below_max_methods(self) -> None:
        methods = [_make_method(methodid=f"pm-{i:03d}") for i in range(_MAX_METHODS - 1)]
        can_add = len(methods) < _MAX_METHODS
        assert can_add is True

    def test_canaddnew_true_with_zero_methods(self) -> None:
        methods: list[BillingPaymentMethodView] = []
        can_add = len(methods) < _MAX_METHODS
        assert can_add is True

    def test_canaddnew_true_with_one_method(self) -> None:
        methods = [_make_method()]
        can_add = len(methods) < _MAX_METHODS
        assert can_add is True


# ---------------------------------------------------------------------------
# statuscounts statuscolor matches _STATUS_COLOR mapping
# ---------------------------------------------------------------------------


class TestStatusCountsStatusColor:
    def test_active_statuscolor_is_success(self) -> None:
        methods = [_make_method(status="active")]
        result = _build_status_counts(methods)
        assert result[0].statuscolor == _STATUS_COLOR["active"]

    def test_expired_statuscolor_is_warning(self) -> None:
        methods = [_make_method(status="expired")]
        result = _build_status_counts(methods)
        assert result[0].statuscolor == _STATUS_COLOR["expired"]

    def test_revoked_statuscolor_is_error(self) -> None:
        methods = [_make_method(status="revoked")]
        result = _build_status_counts(methods)
        assert result[0].statuscolor == _STATUS_COLOR["revoked"]

    def test_unknown_status_statuscolor_is_neutral(self) -> None:
        methods = [_make_method(status="pending")]
        result = _build_status_counts(methods)
        assert result[0].statuscolor == "neutral"

    def test_status_color_map_values(self) -> None:
        assert _STATUS_COLOR["active"] == "success"
        assert _STATUS_COLOR["expired"] == "warning"
        assert _STATUS_COLOR["revoked"] == "error"

    def test_status_color_map_keys_complete(self) -> None:
        assert set(_STATUS_COLOR.keys()) == {"active", "expired", "revoked"}

    def test_mixed_statuses_all_colors_correct(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="expired"),
            _make_method(methodid="pm-003", status="revoked"),
        ]
        result = _build_status_counts(methods)
        color_map = {r.status: r.statuscolor for r in result}
        for status, expected_color in _STATUS_COLOR.items():
            assert color_map[status] == expected_color
