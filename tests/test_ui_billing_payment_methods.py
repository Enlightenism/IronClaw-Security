from __future__ import annotations

from collections.abc import Iterator
import importlib
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.core.billing import PLAN_DEFINITIONS
from app.main import app as _app
from app.routers.stripe_router import get_stripe_service
from app.supabaseclient import TOKENS_PER_UNIT
from app.ui.billing.payment_methods import (
    _BRAND_DISPLAY,
    _MAX_METHODS,
    _STATUS_COLOR,
    BillingPaymentMethodStatusCount,
    BillingPaymentMethodView,
    _brand_display,
    _build_method,
    _build_package_catalogue,
    _build_status_counts,
    _exp_display,
    _resolve_default_method_id,
    _resolve_org_id,
    _resolve_org_id_from_request,
    _status_color,
    _stripe_connection_note,
    _stripe_mode,
    _stripe_webhook_secret_note,
    get_auth_context,
)


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(_app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture()
def authed_client() -> Iterator[TestClient]:
    def _fake_auth_context() -> SimpleNamespace:
        return SimpleNamespace(
            org_id=None,
            tenant_id=None,
        )

    _app.dependency_overrides[get_auth_context] = _fake_auth_context
    try:
        with TestClient(_app, raise_server_exceptions=False) as test_client:
            yield test_client
    finally:
        _app.dependency_overrides.pop(get_auth_context, None)


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


class DummyRequest:
    def __init__(self, query_params: dict[str, str] | None = None) -> None:
        self.query_params = query_params or {}


class TestGetPaymentMethodsUi:
    def test_returns_400_when_org_cannot_be_resolved(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/ui/billing/payment-methods")
        assert resp.status_code == 400
        body = resp.json()
        assert body["detail"]["error"] == "org_id_unresolved"

    def test_returns_payment_methods_payload_with_query_org_id(
        self,
        authed_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class _FakeQuery:
            def select(self, *_args, **_kwargs):
                return self

            def eq(self, *_args, **_kwargs):
                return self

            def order(self, *_args, **_kwargs):
                return self

            def execute(self):
                return SimpleNamespace(data=[])

        class _FakeSupabase:
            def table(self, *_args, **_kwargs):
                return _FakeQuery()

        monkeypatch.setattr("app.ui.billing.payment_methods.is_supabase_configured", lambda: True)
        monkeypatch.setattr("app.ui.billing.payment_methods.get_supabase_client", lambda: _FakeSupabase())

        resp = authed_client.get(
            "/ui/billing/payment-methods",
            params={"organizationid": "org-ui-001"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["organizationid"] == "org-ui-001"
        assert body["environment"]
        assert body["methodcount"] == 0
        assert body["canaddnew"] is True
        assert body["maxmethods"] == _MAX_METHODS
        assert body["methods"] == []

    def test_notes_include_missing_customer_message_when_no_mapping(
        self,
        authed_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class _FakeQuery:
            def select(self, *_args, **_kwargs):
                return self

            def eq(self, *_args, **_kwargs):
                return self

            def order(self, *_args, **_kwargs):
                return self

            def execute(self):
                return SimpleNamespace(data=[])

        class _FakeSupabase:
            def table(self, *_args, **_kwargs):
                return _FakeQuery()

        monkeypatch.setattr("app.ui.billing.payment_methods.is_supabase_configured", lambda: True)
        monkeypatch.setattr("app.ui.billing.payment_methods.get_supabase_client", lambda: _FakeSupabase())

        resp = authed_client.get(
            "/ui/billing/payment-methods",
            params={"organizationid": "org-ui-002"},
        )
        assert resp.status_code == 200
        notes = resp.json()["notes"]
        assert any("No Stripe customer is currently mapped" in note for note in notes)


class TestBuildMethod:
    def test_returns_billing_payment_method_view_instance(self) -> None:
        result = _make_method()
        assert isinstance(result, BillingPaymentMethodView)

    def test_build_method_all_fields_populated(self) -> None:
        result = _make_method(
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
        result = _make_method(brand="amex")
        assert result.branddisplay == "American Express"

    def test_expdisplay_derived_from_expmonth_expyear(self) -> None:
        result = _make_method(expmonth=7, expyear=2031)
        assert result.expdisplay == "07/2031"

    def test_branddisplay_unionpay_uses_mapped_value(self) -> None:
        result = _make_method(brand="unionpay")
        assert result.branddisplay == "UnionPay"

    def test_statuscolor_unknown_is_neutral(self) -> None:
        result = _make_method(status="unknown_status")
        assert result.statuscolor == "neutral"

    def test_isdefault_false_propagates(self) -> None:
        result = _make_method(isdefault=False)
        assert result.isdefault is False

    def test_isdefault_true_propagates(self) -> None:
        result = _make_method(isdefault=True)
        assert result.isdefault is True


class TestBrandDisplay:
    def test_known_brands_in_map(self) -> None:
        for brand, expected in _BRAND_DISPLAY.items():
            assert _brand_display(brand) == expected

    def test_unionpay_uses_explicit_map_value(self) -> None:
        assert _brand_display("unionpay") == "UnionPay"

    def test_unknown_multiword_brand_titlecased(self) -> None:
        assert _brand_display("some_card") == "Some Card"

    def test_empty_brand_returns_unknown(self) -> None:
        assert _brand_display("") == "Unknown"


class TestExpDisplay:
    def test_single_digit_month_zero_padded(self) -> None:
        assert _exp_display(1, 2030) == "01/2030"

    def test_double_digit_month(self) -> None:
        assert _exp_display(12, 2028) == "12/2028"

    def test_month_ten_zero_not_padded(self) -> None:
        assert _exp_display(10, 2026) == "10/2026"

    def test_invalid_values_return_empty(self) -> None:
        assert _exp_display(0, 2026) == ""
        assert _exp_display(10, 0) == ""


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
        assert _resolve_default_method_id([m1, m2]) == "pm-001"


class TestBuildStatusCounts:
    def test_groups_by_status(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="active"),
            _make_method(methodid="pm-003", status="expired"),
        ]
        counts = _build_status_counts(methods)
        status_map = {count.status: count.count for count in counts}
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
        statuses = [count.status for count in counts]
        assert statuses == sorted(statuses)

    def test_statuscolor_populated_per_entry(self) -> None:
        methods = [
            _make_method(methodid="pm-001", status="active"),
            _make_method(methodid="pm-002", status="revoked"),
        ]
        counts = _build_status_counts(methods)
        color_map = {count.status: count.statuscolor for count in counts}
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

    def test_unknown_status_uses_neutral_color(self) -> None:
        methods = [_make_method(methodid="pm-009", status="custom_status")]
        counts = _build_status_counts(methods)
        assert counts[0].statuscolor == "neutral"


class TestPackageCatalogueReload:
    def test_stripe_price_id_read_from_env_on_reload(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_PRICE_ID_STARTER", "price_test_abc")
            import app.ui.billing.payment_methods as pm_mod

            importlib.reload(pm_mod)
            try:
                reloaded_entry = pm_mod.PackageCatalogueEntry
                entry = reloaded_entry(**pm_mod.PACKAGE_CATALOGUE["starter"])
                assert isinstance(entry, reloaded_entry)
                assert entry.stripe_price_id == "price_test_abc"
            finally:
                importlib.reload(pm_mod)

    def test_stripe_price_id_defaults_empty_when_env_unset_on_reload(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("STRIPE_PRICE_ID_STARTER", raising=False)
            import app.ui.billing.payment_methods as pm_mod

            importlib.reload(pm_mod)
            try:
                reloaded_entry = pm_mod.PackageCatalogueEntry
                entry = reloaded_entry(**pm_mod.PACKAGE_CATALOGUE["starter"])
                assert isinstance(entry, reloaded_entry)
                assert entry.stripe_price_id == ""
            finally:
                importlib.reload(pm_mod)

    def test_build_package_catalogue_uses_current_tokens_per_unit(self) -> None:
        catalogue = _build_package_catalogue()
        for key in ("starter", "team", "enterprise"):
            assert catalogue[key]["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_build_package_catalogue_exposes_canonical_identifiers(self) -> None:
        catalogue = _build_package_catalogue()
        for plan in PLAN_DEFINITIONS.values():
            entry = catalogue[plan["name"].casefold()]
            assert entry["code"] == plan["code"]
            assert entry["package_id"] == plan["package_id"]
            assert entry["aliases"] == list(plan["aliases"])


class TestStripeMode:
    def test_returns_live_for_sk_live_key(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc123")
            assert _stripe_mode() == "live"

    def test_returns_test_for_sk_test_key(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")
            assert _stripe_mode() == "test"

    def test_returns_none_for_empty_key(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_SECRET_KEY", "")
            assert _stripe_mode() is None

    def test_returns_none_for_missing_key(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
            assert _stripe_mode() is None

    def test_returns_none_for_invalid_prefix(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_SECRET_KEY", "pk_live_abc123")
            assert _stripe_mode() is None


class TestStripeConnectionNote:
    def test_live_mode_note(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc")
            note = _stripe_connection_note()
        assert "live" in note.lower()
        assert "enabled" in note.lower() or "connected" in note.lower()

    def test_test_mode_note(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc")
            note = _stripe_connection_note()
        assert "test" in note.lower()

    def test_unconfigured_note(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
            note = _stripe_connection_note()
        assert "not configured" in note.lower() or "unavailable" in note.lower()

    def test_test_note_contains_live_warning(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc")
            note = _stripe_connection_note()
        assert "live" in note.lower() or "production" in note.lower()


class TestStripeWebhookSecretNote:
    def test_configured_when_whsec_prefix_present(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_abc123")
            note = _stripe_webhook_secret_note()
        assert "configured" in note.lower()
        assert "not configured" not in note.lower()

    def test_unconfigured_when_empty(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "")
            note = _stripe_webhook_secret_note()
        assert "not configured" in note.lower()

    def test_unconfigured_when_missing(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
            note = _stripe_webhook_secret_note()
        assert "not configured" in note.lower()

    def test_unconfigured_when_wrong_prefix(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "secret_abc")
            note = _stripe_webhook_secret_note()
        assert "not configured" in note.lower()

    def test_configured_note_mentions_webhook(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_xyz")
            note = _stripe_webhook_secret_note()
        assert "webhook" in note.lower()

    def test_unconfigured_note_mentions_verification_disabled(self) -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "")
            note = _stripe_webhook_secret_note()
        assert "disabled" in note.lower() or "not configured" in note.lower()


class TestUiWriteRoutes:
    def test_post_payment_methods_returns_503(self, authed_client: TestClient) -> None:
        resp = authed_client.post(
            "/ui/billing/payment-methods",
            params={"organizationid": "org-001"},
            json={"stripe_payment_method_id": "pm_test_abc", "set_as_default": False},
        )
        assert resp.status_code == 503
        body = resp.json()
        assert "detail" in body

    def test_patch_default_updates_stripe_without_supabase(
        self,
        authed_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        set_default_calls: list[tuple[str, str]] = []

        def set_default(*, customer_id: str, payment_method_id: str) -> None:
            set_default_calls.append((customer_id, payment_method_id))

        def list_payment_methods(*, customer_id: str) -> list[dict[str, object]]:
            assert customer_id == "cus-001"
            return [
                {
                    "id": "pm-001",
                    "type": "card",
                    "brand": "visa",
                    "last4": "4242",
                    "exp_month": 12,
                    "exp_year": 2028,
                    "is_default": False,
                }
            ]

        stripe_service = SimpleNamespace(
            resolve_customer_id=lambda _organizationid: "cus-001",
            list_payment_methods=list_payment_methods,
            set_default_payment_method=set_default,
        )
        monkeypatch.setitem(
            _app.dependency_overrides,
            get_stripe_service,
            lambda: stripe_service,
        )
        monkeypatch.setattr(
            "app.ui.billing.payment_methods.is_supabase_configured",
            lambda: False,
        )

        resp = authed_client.patch(
            "/ui/billing/payment-methods/pm-001/default",
            params={"organizationid": "org-001"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "updated"
        assert set_default_calls == [("cus-001", "pm-001")]

    def test_delete_returns_400_without_resolved_org(
        self,
        authed_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("app.ui.billing.payment_methods.is_supabase_configured", lambda: True)
        resp = authed_client.delete("/ui/billing/payment-methods/pm-001")
        assert resp.status_code == 400
        body = resp.json()
        assert body["detail"]["error"] == "org_id_unresolved"


class TestOrgResolutionHelpers:
    def test_resolve_org_id_prefers_org_id(self) -> None:
        auth = SimpleNamespace(org_id="org-123", tenant_id="tenant-123")
        assert _resolve_org_id(auth) == "org-123"

    def test_resolve_org_id_falls_back_to_tenant_id(self) -> None:
        auth = SimpleNamespace(org_id=None, tenant_id="tenant-456")
        assert _resolve_org_id(auth) == "tenant-456"

    def test_resolve_org_id_returns_empty_for_none(self) -> None:
        assert _resolve_org_id(None) == ""

    def test_resolve_org_id_from_request_uses_query_params(self) -> None:
        auth = SimpleNamespace(org_id=None, tenant_id=None)
        assert _resolve_org_id_from_request(auth, DummyRequest({"organizationid": "org-a"})) == "org-a"
        assert _resolve_org_id_from_request(auth, DummyRequest({"organization_id": "org-b"})) == "org-b"
        assert _resolve_org_id_from_request(auth, DummyRequest({"organizationId": "org-c"})) == "org-c"

    def test_resolve_org_id_from_request_prefers_auth(self) -> None:
        auth = SimpleNamespace(org_id="org-auth", tenant_id=None)
        request = DummyRequest({"organizationid": "org-query"})
        assert _resolve_org_id_from_request(auth, request) == "org-auth"


class TestConstants:
    def test_max_methods_constant(self) -> None:
        assert _MAX_METHODS == 4

    def test_status_color_map_values(self) -> None:
        assert _STATUS_COLOR["active"] == "success"
        assert _STATUS_COLOR["expired"] == "warning"
        assert _STATUS_COLOR["revoked"] == "error"
        assert _STATUS_COLOR["pending"] == "info"

    def test_status_color_helper_unknown_returns_neutral(self) -> None:
        assert _status_color("something_else") == "neutral"
