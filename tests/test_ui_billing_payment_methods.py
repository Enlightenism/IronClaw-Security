from __future__ import annotations

import importlib
import os
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest

from app.main import app as _app
from app.ui.billing.payment_methods import (
    _BRAND_DISPLAY,
    _MAX_METHODS,
    _STATUS_COLOR,
    BillingPaymentMethodStatusCount,
    BillingPaymentMethodView,
    _brand_display,
    _build_method,
    _build_status_counts,
    _exp_display,
    _resolve_default_method_id,
    _stripe_connection_note,
    _stripe_mode,
    _stripe_webhook_secret_note,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client() -> TestClient:
    return TestClient(_app, raise_server_exceptions=False)


def _make_method(
    methodid: str = "pm-001",
    type: str = "card",
    brand: str = "visa",
    last4: str = "4242",
    expmonth: int = 12,
    expyear: int = 2028,
    isdefault: bool = False,
    status: str = "active",
    createdat: str = "2026-01-01T00:00:00+00:00",
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
# GET /ui/billing/payment-methods — Supabase not configured
# ---------------------------------------------------------------------------


class TestGetPaymentMethodsNoSupabase:
    def test_returns_not_found_shape_when_supabase_not_configured(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.get(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "not_found"
        assert body["organizationid"] == "org-001"
        assert "message" in body
        assert "generatedat" in body
        assert "environment" in body

    def test_not_found_message_references_supabase(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.get(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-test"},
            )

        body = resp.json()
        assert "Supabase" in body["message"] or "supabase" in body["message"].lower()

    def test_not_found_organizationid_echoes_query_param(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.get(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-xyz"},
            )

        assert resp.json()["organizationid"] == "org-xyz"


# ---------------------------------------------------------------------------
# _build_method — instance type, field correctness, computed fields
# ---------------------------------------------------------------------------


class TestBuildMethod:
    def test_returns_billing_payment_method_view_instance(self) -> None:
        # BillingPaymentMethodView and _build_method are both bound at module
        # level from the same import — class identity is guaranteed to match.
        result = _build_method(
            methodid="pm-001",
            type="card",
            brand="visa",
            last4="4242",
            expmonth=12,
            expyear=2027,
            isdefault=False,
            status="active",
            createdat="2025-01-01T00:00:00+00:00",
            organizationid="org-001",
        )
        assert isinstance(result, BillingPaymentMethodView)

    def test_build_method_all_fields_populated(self) -> None:
        result = _build_method(
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
        assert result.last4 == "1234"
        assert result.expmonth == 3
        assert result.expyear == 2029
        assert result.isdefault is True
        assert result.status == "active"
        assert result.createdat == "2026-06-01T00:00:00+00:00"
        assert result.organizationid == "org-abc"
        assert result.branddisplay == "Mastercard"
        assert result.expdisplay == "03/2029"
        assert result.statuscolor == "success"

    def test_branddisplay_derived_from_brand(self) -> None:
        result = _build_method(
            methodid="pm-001",
            type="card",
            brand="amex",
            last4="0005",
            expmonth=1,
            expyear=2028,
            isdefault=False,
            status="active",
            createdat="2025-01-01T00:00:00+00:00",
            organizationid="org-001",
        )
        assert result.branddisplay == "American Express"

    def test_expdisplay_derived_from_expmonth_expyear(self) -> None:
        result = _build_method(
            methodid="pm-001",
            type="card",
            brand="visa",
            last4="4242",
            expmonth=7,
            expyear=2031,
            isdefault=False,
            status="active",
            createdat="2025-01-01T00:00:00+00:00",
            organizationid="org-001",
        )
        assert result.expdisplay == "07/2031"

    def test_branddisplay_visa(self) -> None:
        result = _make_method(brand="visa")
        assert result.branddisplay == "Visa"

    def test_branddisplay_mastercard(self) -> None:
        result = _make_method(brand="mastercard")
        assert result.branddisplay == "Mastercard"

    def test_branddisplay_amex(self) -> None:
        result = _make_method(brand="amex")
        assert result.branddisplay == "American Express"

    def test_branddisplay_discover(self) -> None:
        result = _make_method(brand="discover")
        assert result.branddisplay == "Discover"

    def test_branddisplay_bank_account(self) -> None:
        result = _make_method(brand="bank_account")
        assert result.branddisplay == "Bank Account"

    def test_branddisplay_unknown_brand_is_titlecased(self) -> None:
        result = _make_method(brand="unionpay")
        assert result.branddisplay == "Unionpay"

    def test_expdisplay_zero_padded_month(self) -> None:
        result = _make_method(expmonth=3, expyear=2029)
        assert result.expdisplay == "03/2029"

    def test_expdisplay_two_digit_month(self) -> None:
        result = _make_method(expmonth=11, expyear=2027)
        assert result.expdisplay == "11/2027"

    def test_statuscolor_active(self) -> None:
        result = _make_method(status="active")
        assert result.statuscolor == "success"

    def test_statuscolor_expired(self) -> None:
        result = _make_method(status="expired")
        assert result.statuscolor == "warning"

    def test_statuscolor_revoked(self) -> None:
        result = _make_method(status="revoked")
        assert result.statuscolor == "error"

    def test_statuscolor_pending(self) -> None:
        result = _make_method(status="pending")
        assert result.statuscolor == "info"

    def test_statuscolor_unknown_is_neutral(self) -> None:
        result = _make_method(status="unknown_status")
        assert result.statuscolor == "neutral"

    def test_fields_pass_through_correctly(self) -> None:
        result = _make_method(
            methodid="pm-999",
            type="card",
            brand="visa",
            last4="1234",
            expmonth=6,
            expyear=2030,
            isdefault=True,
            status="active",
            createdat="2026-06-01T00:00:00+00:00",
            organizationid="org-abc",
        )
        assert result.methodid == "pm-999"
        assert result.type == "card"
        assert result.brand == "visa"
        assert result.last4 == "1234"
        assert result.expmonth == 6
        assert result.expyear == 2030
        assert result.isdefault is True
        assert result.status == "active"
        assert result.createdat == "2026-06-01T00:00:00+00:00"
        assert result.organizationid == "org-abc"

    def test_statuscolor_matches_status_color_map(self) -> None:
        for status, expected_color in _STATUS_COLOR.items():
            result = _make_method(status=status)
            assert result.statuscolor == expected_color

    def test_isdefault_false_propagates(self) -> None:
        result = _make_method(isdefault=False)
        assert result.isdefault is False

    def test_isdefault_true_propagates(self) -> None:
        result = _make_method(isdefault=True)
        assert result.isdefault is True


# ---------------------------------------------------------------------------
# _brand_display helper
# ---------------------------------------------------------------------------


class TestBrandDisplay:
    def test_known_brands_in_map(self) -> None:
        for brand, expected in _BRAND_DISPLAY.items():
            assert _brand_display(brand) == expected

    def test_unknown_brand_titlecased(self) -> None:
        assert _brand_display("unionpay") == "Unionpay"

    def test_unknown_multiword_brand_titlecased(self) -> None:
        assert _brand_display("some_card") == "Some_Card"


# ---------------------------------------------------------------------------
# _exp_display helper
# ---------------------------------------------------------------------------


class TestExpDisplay:
    def test_single_digit_month_zero_padded(self) -> None:
        assert _exp_display(1, 2030) == "01/2030"

    def test_double_digit_month(self) -> None:
        assert _exp_display(12, 2028) == "12/2028"

    def test_month_ten_zero_not_padded(self) -> None:
        assert _exp_display(10, 2026) == "10/2026"


# ---------------------------------------------------------------------------
# _resolve_default_method_id
# ---------------------------------------------------------------------------


class TestResolveDefaultMethodId:
    def test_returns_methodid_of_default_method(self) -> None:
        m1 = _make_method(methodid="pm-001", isdefault=False)
        m2 = _make_method(methodid="pm-002", isdefault=True)
        m3 = _make_method(methodid="pm-003", isdefault=False)
        assert _resolve_default_method_id([m1, m2, m3]) == "pm-002"

    def test_returns_none_when_no_default(self) -> None:
        m1 = _make_method(methodid="pm-001", isdefault=False)
        m2 = _make_method(methodid="pm-002", isdefault=False)
        assert _resolve_default_method_id([m1, m2]) is None

    def test_returns_none_for_empty_list(self) -> None:
        assert _resolve_default_method_id([]) is None

    def test_returns_first_default_when_multiple_flagged(self) -> None:
        m1 = _make_method(methodid="pm-001", isdefault=True)
        m2 = _make_method(methodid="pm-002", isdefault=True)
        result = _resolve_default_method_id([m1, m2])
        assert result == "pm-001"

    def test_single_default_method(self) -> None:
        m = _make_method(methodid="pm-solo", isdefault=True)
        assert _resolve_default_method_id([m]) == "pm-solo"


# ---------------------------------------------------------------------------
# _build_status_counts
# ---------------------------------------------------------------------------


class TestBuildStatusCounts:
    def test_groups_by_status(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="active"),
            _make_method(methodid="pm-003", status="expired"),
        ]
        counts = _build_status_counts(methods)
        status_map = {c.status: c.count for c in counts}
        assert status_map["active"] == 2
        assert status_map["expired"] == 1

    def test_sorted_alphabetically_by_status(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="revoked"),
            _make_method(methodid="pm-002", status="active"),
            _make_method(methodid="pm-003", status="expired"),
            _make_method(methodid="pm-004", status="pending"),
        ]
        counts = _build_status_counts(methods)
        statuses = [c.status for c in counts]
        assert statuses == sorted(statuses)

    def test_statuscolor_populated_per_entry(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="revoked"),
        ]
        counts = _build_status_counts(methods)
        color_map = {c.status: c.statuscolor for c in counts}
        assert color_map["active"] == "success"
        assert color_map["revoked"] == "error"

    def test_returns_empty_list_for_no_methods(self) -> None:
        assert _build_status_counts([]) == []

    def test_single_status_single_entry(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="active"),
            _make_method(methodid="pm-003", status="active"),
        ]
        counts = _build_status_counts(methods)
        assert len(counts) == 1
        assert counts[0].status == "active"
        assert counts[0].count == 3

    def test_each_entry_is_billing_payment_method_status_count(self) -> None:
        methods = [_make_method(methodid="pm-001", status="active")]
        counts = _build_status_counts(methods)
        assert isinstance(counts[0], BillingPaymentMethodStatusCount)


# ---------------------------------------------------------------------------
# PackageCatalogueEntry — reload tests re-bind class from reloaded module
# ---------------------------------------------------------------------------


class TestPackageCatalogueEntryReload:
    def test_stripe_price_id_read_from_env_on_reload(self) -> None:
        with patch.dict(os.environ, {"STRIPE_PRICE_ID_STARTER": "price_test_abc"}, clear=False):
            import app.ui.billing.payment_methods as pm_mod

            importlib.reload(pm_mod)
            try:
                # Re-bind from reloaded module to preserve class identity
                ReloadedEntry = pm_mod.PackageCatalogueEntry
                entry = ReloadedEntry(**pm_mod.PACKAGE_CATALOGUE["starter"])
                assert isinstance(entry, ReloadedEntry)
                assert entry.stripe_price_id == "price_test_abc"
            finally:
                importlib.reload(pm_mod)

    def test_stripe_price_id_defaults_empty_when_env_unset_on_reload(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "STRIPE_PRICE_ID_STARTER"}
        with patch.dict(os.environ, env, clear=True):
            import app.ui.billing.payment_methods as pm_mod

            importlib.reload(pm_mod)
            try:
                ReloadedEntry = pm_mod.PackageCatalogueEntry
                entry = ReloadedEntry(**pm_mod.PACKAGE_CATALOGUE["starter"])
                assert isinstance(entry, ReloadedEntry)
                assert isinstance(entry.stripe_price_id, str)
            finally:
                importlib.reload(pm_mod)


# ---------------------------------------------------------------------------
# _stripe_mode
# ---------------------------------------------------------------------------


class TestStripeMode:
    def test_returns_live_for_sk_live_key(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_live_abc123"}, clear=False):
            assert _stripe_mode() == "live"

    def test_returns_test_for_sk_test_key(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_test_abc123"}, clear=False):
            assert _stripe_mode() == "test"

    def test_returns_none_for_empty_key(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": ""}, clear=False):
            assert _stripe_mode() is None

    def test_returns_none_for_missing_key(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "STRIPE_SECRET_KEY"}
        with patch.dict(os.environ, env, clear=True):
            assert _stripe_mode() is None

    def test_returns_none_for_invalid_prefix(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "pk_live_abc123"}, clear=False):
            assert _stripe_mode() is None

    def test_returns_none_for_rk_prefix(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "rk_live_somekey"}, clear=False):
            assert _stripe_mode() is None


# ---------------------------------------------------------------------------
# _stripe_connection_note
# ---------------------------------------------------------------------------


class TestStripeConnectionNote:
    def test_live_mode_note(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_live_abc"}, clear=False):
            note = _stripe_connection_note()
        assert "live" in note.lower()
        assert "real payment" in note.lower() or "enabled" in note.lower()

    def test_test_mode_note(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_test_abc"}, clear=False):
            note = _stripe_connection_note()
        assert "test" in note.lower()

    def test_unconfigured_note(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": ""}, clear=False):
            note = _stripe_connection_note()
        assert "not configured" in note.lower() or "unavailable" in note.lower()

    def test_live_note_does_not_mention_test_mode(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_live_abc"}, clear=False):
            note = _stripe_connection_note()
        assert "test mode" not in note.lower()

    def test_test_note_contains_switch_to_live_warning(self) -> None:
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_test_abc"}, clear=False):
            note = _stripe_connection_note()
        assert "live" in note.lower() or "production" in note.lower()


# ---------------------------------------------------------------------------
# _stripe_webhook_secret_note
# ---------------------------------------------------------------------------


class TestStripeWebhookSecretNote:
    def test_configured_when_whsec_prefix_present(self) -> None:
        with patch.dict(
            os.environ,
            {"STRIPE_WEBHOOK_SECRET": "whsec_abc123"},
            clear=False,
        ):
            note = _stripe_webhook_secret_note()
        assert "configured" in note.lower()
        assert "not configured" not in note.lower()

    def test_unconfigured_when_empty(self) -> None:
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": ""}, clear=False):
            note = _stripe_webhook_secret_note()
        assert "not configured" in note.lower()

    def test_unconfigured_when_missing(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "STRIPE_WEBHOOK_SECRET"}
        with patch.dict(os.environ, env, clear=True):
            note = _stripe_webhook_secret_note()
        assert "not configured" in note.lower()

    def test_unconfigured_when_wrong_prefix(self) -> None:
        with patch.dict(
            os.environ,
            {"STRIPE_WEBHOOK_SECRET": "secret_abc"},
            clear=False,
        ):
            note = _stripe_webhook_secret_note()
        assert "not configured" in note.lower()

    def test_configured_note_mentions_webhook(self) -> None:
        with patch.dict(
            os.environ,
            {"STRIPE_WEBHOOK_SECRET": "whsec_xyz"},
            clear=False,
        ):
            note = _stripe_webhook_secret_note()
        assert "webhook" in note.lower()

    def test_unconfigured_note_mentions_verification_disabled(self) -> None:
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": ""}, clear=False):
            note = _stripe_webhook_secret_note()
        assert "disabled" in note.lower() or "not configured" in note.lower()


# ---------------------------------------------------------------------------
# POST /ui/billing/payment-methods — Supabase not configured → 503
# ---------------------------------------------------------------------------


class TestAddPaymentMethodNoSupabase:
    def test_returns_503_when_supabase_not_configured(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.post(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
                json={"stripe_payment_method_id": "pm_test_abc", "set_as_default": False},
            )
        assert resp.status_code == 503

    def test_503_detail_references_supabase(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.post(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
                json={"stripe_payment_method_id": "pm_test_abc", "set_as_default": False},
            )
        detail = resp.json().get("detail", "")
        assert "supabase" in detail.lower() or "Supabase" in detail


# ---------------------------------------------------------------------------
# PATCH /ui/billing/payment-methods/{methodid}/default — 503
# ---------------------------------------------------------------------------


class TestSetDefaultPaymentMethodNoSupabase:
    def test_returns_503_when_supabase_not_configured(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.patch(
                "/ui/billing/payment-methods/pm-001/default",
                params={"organizationid": "org-001"},
            )
        assert resp.status_code == 503

    def test_503_detail_references_supabase(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.patch(
                "/ui/billing/payment-methods/pm-001/default",
                params={"organizationid": "org-001"},
            )
        detail = resp.json().get("detail", "")
        assert "supabase" in detail.lower() or "Supabase" in detail


# ---------------------------------------------------------------------------
# DELETE /ui/billing/payment-methods/{methodid} — 503
# ---------------------------------------------------------------------------


class TestDeletePaymentMethodNoSupabase:
    def test_returns_503_when_supabase_not_configured(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.delete(
                "/ui/billing/payment-methods/pm-001",
                params={"organizationid": "org-001"},
            )
        assert resp.status_code == 503

    def test_503_detail_references_supabase(self, client: TestClient) -> None:
        with patch(
            "app.ui.billing.payment_methods.is_supabase_configured",
            return_value=False,
        ):
            resp = client.delete(
                "/ui/billing/payment-methods/pm-001",
                params={"organizationid": "org-001"},
            )
        detail = resp.json().get("detail", "")
        assert "supabase" in detail.lower() or "Supabase" in detail


# ---------------------------------------------------------------------------
# canaddnew — False when methodcount >= _MAX_METHODS
# ---------------------------------------------------------------------------


class TestCanAddNew:
    def _mock_supabase_methods(self, method_count: int) -> list[dict]:
        return [
            {
                "id": f"pm-{i:03d}",
                "type": "card",
                "brand": "visa",
                "last4": "4242",
                "exp_month": 12,
                "exp_year": 2028,
                "is_default": i == 0,
                "status": "active",
                "created_at": "2026-01-01T00:00:00+00:00",
                "organization_id": "org-001",
            }
            for i in range(method_count)
        ]

    def _build_mock_client(self, rows: list[dict]) -> MagicMock:
        mock_response = MagicMock()
        mock_response.data = rows
        qb = MagicMock()
        qb.select.return_value = qb
        qb.eq.return_value = qb
        qb.order.return_value = qb
        qb.limit.return_value = qb
        qb.execute.return_value = mock_response
        mock_client = MagicMock()
        mock_client.table.return_value = qb
        return mock_client

    def test_canaddnew_false_when_at_max(self, client: TestClient) -> None:
        rows = self._mock_supabase_methods(_MAX_METHODS)
        mock_sb = self._build_mock_client(rows)

        with (
            patch(
                "app.ui.billing.payment_methods.is_supabase_configured",
                return_value=True,
            ),
            patch(
                "app.ui.billing.payment_methods.get_supabase_client",
                return_value=mock_sb,
            ),
        ):
            resp = client.get(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
            )

        body = resp.json()
        assert resp.status_code == 200
        assert body["methodcount"] == _MAX_METHODS
        assert body["canaddnew"] is False

    def test_canaddnew_false_when_above_max(self, client: TestClient) -> None:
        rows = self._mock_supabase_methods(_MAX_METHODS + 1)
        mock_sb = self._build_mock_client(rows)

        with (
            patch(
                "app.ui.billing.payment_methods.is_supabase_configured",
                return_value=True,
            ),
            patch(
                "app.ui.billing.payment_methods.get_supabase_client",
                return_value=mock_sb,
            ),
        ):
            resp = client.get(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
            )

        body = resp.json()
        assert body["canaddnew"] is False

    def test_canaddnew_true_when_below_max(self, client: TestClient) -> None:
        rows = self._mock_supabase_methods(_MAX_METHODS - 1)
        mock_sb = self._build_mock_client(rows)

        with (
            patch(
                "app.ui.billing.payment_methods.is_supabase_configured",
                return_value=True,
            ),
            patch(
                "app.ui.billing.payment_methods.get_supabase_client",
                return_value=mock_sb,
            ),
        ):
            resp = client.get(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
            )

        body = resp.json()
        assert body["canaddnew"] is True

    def test_maxmethods_field_equals_constant(self, client: TestClient) -> None:
        rows = self._mock_supabase_methods(1)
        mock_sb = self._build_mock_client(rows)

        with (
            patch(
                "app.ui.billing.payment_methods.is_supabase_configured",
                return_value=True,
            ),
            patch(
                "app.ui.billing.payment_methods.get_supabase_client",
                return_value=mock_sb,
            ),
        ):
            resp = client.get(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
            )

        assert resp.json()["maxmethods"] == _MAX_METHODS

    def test_add_payment_method_409_when_at_max(self, client: TestClient) -> None:
        rows = self._mock_supabase_methods(_MAX_METHODS)
        mock_sb = self._build_mock_client(rows)

        with (
            patch(
                "app.ui.billing.payment_methods.is_supabase_configured",
                return_value=True,
            ),
            patch(
                "app.ui.billing.payment_methods.get_supabase_client",
                return_value=mock_sb,
            ),
        ):
            resp = client.post(
                "/ui/billing/payment-methods",
                params={"organizationid": "org-001"},
                json={"stripe_payment_method_id": "pm_test_new", "set_as_default": False},
            )

        assert resp.status_code == 409
