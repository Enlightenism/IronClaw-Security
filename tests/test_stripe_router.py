from __future__ import annotations

from collections.abc import Generator
from dataclasses import replace
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import pytest

from app.core.auth import AuthContext, get_auth_context
from app.main import app
from app.routers.stripe_router import get_checkout_auth_context, get_stripe_service
from app.services.stripe_service import (
    MeteredSyncResponse,
    StripeCheckoutMode,
    StripeInstallKeyProvisioningError,
    StripeInsufficientUnitsError,
    StripePersistenceError,
    StripeService,
    StripeServiceError,
    StripeSessionNotFoundError,
    StripeUnitEventReason,
    UnitBalanceResponse,
    units_for_tokens,
)

ORG_ID = "test-org-router-001"
CUSTOMER_ID = "cus_test_router_001"
SUB_ITEM_ID = "si_test_item_001"
PM_ID = "pm_test_001"
SESSION_ID = "cs_test_001"
SUBSCRIPTION_ID = "sub_test_001"

_API_KEY = "test-api-key"
_BILLING_BASE = "/api/billing"
_TEST_PRICE_IDS = {"BILLING_TIER_5K_PRICE_ID": "price_pkg5000"}

_ALLOWED_SUCCESS_URL = "https://moving-forward.ca/billing/success"
_ALLOWED_CANCEL_URL = "https://moving-forward.ca/billing/cancel"

_TEST_AUTH_CONTEXT = AuthContext(
    api_key=_API_KEY,
    principal_type="api_key",
    principal_id="test-principal",
    session_id=None,
    org_id=ORG_ID,
    permissions=(),
    roles=(),
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="personal",
    metadata={"email": "buyer@ironclaw.test"},
)


def _override_get_auth_context() -> AuthContext:
    return _TEST_AUTH_CONTEXT


def _auth_headers() -> dict[str, str]:
    return {"X-API-Key": _API_KEY, "X-Org-Id": ORG_ID}


def _billing_path(path: str) -> str:
    normalized = path if path.startswith("/") else f"/{path}"
    return f"{_BILLING_BASE}{normalized}"


def _make_balance_response(org_id: str = ORG_ID, balance: int = 500) -> UnitBalanceResponse:
    return UnitBalanceResponse(org_id=org_id, balance=balance, ledger_entries=[])


def _make_metered_response(
    org_id: str = ORG_ID,
    subscription_item_id: str = SUB_ITEM_ID,
    quantity: int = 10,
    action: str = "increment",
    idempotency_key: str = "ikey-001",
) -> MeteredSyncResponse:
    return MeteredSyncResponse(
        org_id=org_id,
        subscription_id=subscription_item_id,
        quantity=quantity,
        action=action,
        idempotency_key=idempotency_key,
        stripe_usage_record_id="usrec_001",
        success=True,
        error=None,
        synced_at="2026-06-28T00:00:00Z",
    )


def _obj_with_to_dict(**data: object) -> SimpleNamespace:
    obj = SimpleNamespace(**data)
    obj.to_dict = lambda: data.copy()
    return obj


def _build_mock_svc() -> MagicMock:
    svc = MagicMock(spec=StripeService)
    svc._lock = threading.Lock()
    svc._org_customer_map = {}
    svc.resolve_customer_id.side_effect = lambda org_id: svc._org_customer_map.get(org_id)
    svc.get_checkout_units_credited.return_value = 0
    return svc


@pytest.fixture()
def mock_svc() -> MagicMock:
    return _build_mock_svc()


@pytest.fixture()
def client(mock_svc: MagicMock) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_stripe_service] = lambda: mock_svc
    app.dependency_overrides[get_auth_context] = _override_get_auth_context
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_stripe_service, None)
    app.dependency_overrides.pop(get_auth_context, None)


class TestMeteredSync:
    def test_metered_sync_calls_report_with_subscription_item_id(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        metered_resp = _make_metered_response(quantity=5)
        mock_svc.report_metered_usage.return_value = metered_resp
        mock_svc.debit_units.return_value = _make_balance_response()

        payload = {
            "subscriptionItemId": SUB_ITEM_ID,
            "quantity": 5,
            "action": "increment",
        }
        resp = client.post(_billing_path("/metered/sync"), json=payload, headers=_auth_headers())

        assert resp.status_code == 200
        mock_svc.report_metered_usage.assert_called_once_with(
            org_id=ORG_ID,
            subscription_item_id=SUB_ITEM_ID,
            quantity=5,
            action="increment",
            idempotency_key=None,
        )

    def test_metered_sync_calls_debit_units_with_amount_and_metered_sync_reason(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        metered_resp = _make_metered_response(quantity=7)
        mock_svc.report_metered_usage.return_value = metered_resp
        mock_svc.debit_units.return_value = _make_balance_response()

        payload = {"subscriptionItemId": SUB_ITEM_ID, "quantity": 7}
        resp = client.post(_billing_path("/metered/sync"), json=payload, headers=_auth_headers())

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs is not None
        assert "amount" in call_kwargs.kwargs
        assert call_kwargs.kwargs["amount"] == 7
        assert call_kwargs.kwargs["reason"] == StripeUnitEventReason.METERED_SYNC
        assert call_kwargs.kwargs["reference_id"] == metered_resp.idempotency_key

    def test_metered_sync_zero_quantity_skips_debit(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.report_metered_usage.return_value = _make_metered_response(quantity=0)

        payload = {"subscriptionItemId": SUB_ITEM_ID, "quantity": 0}
        resp = client.post(_billing_path("/metered/sync"), json=payload, headers=_auth_headers())

        assert resp.status_code == 200
        mock_svc.debit_units.assert_not_called()

    def test_metered_sync_insufficient_units_does_not_fail_request(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.report_metered_usage.return_value = _make_metered_response(quantity=99)
        mock_svc.debit_units.side_effect = StripeInsufficientUnitsError(org_id=ORG_ID, have=0, need=99)

        payload = {"subscriptionItemId": SUB_ITEM_ID, "quantity": 99}
        resp = client.post(_billing_path("/metered/sync"), json=payload, headers=_auth_headers())

        assert resp.status_code == 200

    def test_metered_sync_with_idempotency_key(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.report_metered_usage.return_value = _make_metered_response(idempotency_key="custom-key-abc")
        mock_svc.debit_units.return_value = _make_balance_response()

        payload = {
            "subscriptionItemId": SUB_ITEM_ID,
            "quantity": 3,
            "idempotencyKey": "custom-key-abc",
        }
        resp = client.post(_billing_path("/metered/sync"), json=payload, headers=_auth_headers())

        assert resp.status_code == 200
        mock_svc.report_metered_usage.assert_called_once_with(
            org_id=ORG_ID,
            subscription_item_id=SUB_ITEM_ID,
            quantity=3,
            action="increment",
            idempotency_key="custom-key-abc",
        )


class TestResolveCustomerIdNone:
    def test_set_default_payment_method_no_customer_returns_404(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map.clear()

        resp = client.post(
            _billing_path(f"/payment-methods/{PM_ID}/set-default"),
            headers=_auth_headers(),
        )

        assert resp.status_code == 404
        detail = resp.json().get("detail", "")
        assert "no_stripe_customer_for_org" in str(detail)

    def test_list_payment_methods_no_customer_returns_empty_list(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map.clear()

        resp = client.get(_billing_path("/payment-methods"), headers=_auth_headers())

        assert resp.status_code == 200
        body = resp.json()
        assert body["payment_methods"] == []
        assert body["customer_id"] is None


class TestDebitUnits:
    def test_debit_units_calls_svc_with_amount_keyword(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.debit_units.return_value = _make_balance_response(balance=490)

        token_count = 25_000
        resp = client.post(
            _billing_path("/units/debit"),
            json={"tokenCount": token_count},
            headers=_auth_headers(),
        )

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs is not None
        assert "amount" in call_kwargs.kwargs
        expected_amount = units_for_tokens(token_count)
        assert call_kwargs.kwargs["amount"] == expected_amount

    def test_debit_units_insufficient_units_returns_402(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.debit_units.side_effect = StripeInsufficientUnitsError(org_id=ORG_ID, have=0, need=5)

        resp = client.post(
            _billing_path("/units/debit"),
            json={"tokenCount": 125_000},
            headers=_auth_headers(),
        )

        assert resp.status_code == 402
        body = resp.json()
        detail = body.get("detail", {})
        assert detail.get("error") == "insufficient_units"
        assert detail.get("have") == 0
        assert detail.get("need") == 5
        assert detail.get("org_id") == ORG_ID

    def test_debit_units_reason_is_metered_sync(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.debit_units.return_value = _make_balance_response(balance=499)

        resp = client.post(
            _billing_path("/units/debit"),
            json={"tokenCount": 1},
            headers=_auth_headers(),
        )

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs.kwargs["reason"] == StripeUnitEventReason.METERED_SYNC

    def test_debit_units_with_reference_id(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.debit_units.return_value = _make_balance_response(balance=498)

        resp = client.post(
            _billing_path("/units/debit"),
            json={"tokenCount": 50_000, "referenceId": "scan-ref-abc"},
            headers=_auth_headers(),
        )

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs.kwargs.get("reference_id") == "scan-ref-abc"

    def test_debit_units_missing_org_id_returns_error(self, client: TestClient) -> None:
        no_org_context = AuthContext(
            api_key=_API_KEY,
            principal_type="api_key",
            principal_id="test-principal",
            session_id=None,
            org_id=None,
            permissions=(),
            roles=(),
            authenticated=True,
            auth_source="test",
            auth_method="api_key",
            key_type="personal",
        )
        app.dependency_overrides[get_auth_context] = lambda: no_org_context
        try:
            resp = client.post(
                _billing_path("/units/debit"),
                json={"tokenCount": 1},
                headers={"X-API-Key": _API_KEY},
            )
            assert resp.status_code == 400
            detail = resp.json()["detail"]
            assert detail["error"] == "org_id_unresolved"
        finally:
            app.dependency_overrides[get_auth_context] = _override_get_auth_context


class TestPatchObjectLockAndMap:
    def _bare_svc_with_attrs(self) -> StripeService:
        svc = StripeService.__new__(StripeService)
        svc._lock = threading.Lock()
        svc._org_customer_map = {}
        return svc

    def test_resolve_customer_id_via_patch_object_returns_customer(self) -> None:
        svc = self._bare_svc_with_attrs()
        real_map = {ORG_ID: CUSTOMER_ID}

        from app.routers.stripe_router import _resolve_customer_id

        svc._org_customer_map = real_map
        result = _resolve_customer_id(svc, ORG_ID)

        assert result == CUSTOMER_ID

    def test_resolve_customer_id_via_patch_object_returns_none_for_unknown_org(self) -> None:
        svc = self._bare_svc_with_attrs()
        real_map: dict[str, str] = {}

        from app.routers.stripe_router import _resolve_customer_id

        svc._org_customer_map = real_map
        result = _resolve_customer_id(svc, ORG_ID)

        assert result is None

    def test_set_default_route_404_controlled_via_patch_object(self) -> None:
        svc = _build_mock_svc()
        app.dependency_overrides[get_stripe_service] = lambda: svc
        app.dependency_overrides[get_auth_context] = _override_get_auth_context
        try:
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.post(
                _billing_path(f"/payment-methods/{PM_ID}/set-default"),
                headers=_auth_headers(),
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_stripe_service, None)
            app.dependency_overrides.pop(get_auth_context, None)

    def test_list_payment_methods_empty_via_patch_object(self) -> None:
        svc = _build_mock_svc()
        app.dependency_overrides[get_stripe_service] = lambda: svc
        app.dependency_overrides[get_auth_context] = _override_get_auth_context
        try:
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.get(_billing_path("/payment-methods"), headers=_auth_headers())
            assert resp.status_code == 200
            assert resp.json()["payment_methods"] == []
        finally:
            app.dependency_overrides.pop(get_stripe_service, None)
            app.dependency_overrides.pop(get_auth_context, None)


class TestAncillaryRoutes:
    def test_get_billing_catalogue_no_auth_required(self, client: TestClient) -> None:
        resp = client.get(_billing_path("/catalogue"), headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert "packages" in body
        assert "tokens_per_unit" in body

    def test_get_unit_balance(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.get_unit_balance.return_value = _make_balance_response(balance=250)
        resp = client.get(_billing_path("/units/balance"), headers=_auth_headers())
        assert resp.status_code == 200
        assert resp.json()["balance"] == 250

    def test_get_unit_ledger(self, client: TestClient, mock_svc: MagicMock) -> None:
        balance_resp = UnitBalanceResponse(
            org_id=ORG_ID,
            balance=100,
            ledger_entries=[{"entry_id": "ule-001", "delta": 100}],
        )
        mock_svc.get_unit_balance.return_value = balance_resp
        resp = client.get(_billing_path("/units/ledger"), headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["balance"] == 100
        assert len(body["ledger"]) == 1

    def test_calculate_units_endpoint(self, client: TestClient) -> None:
        resp = client.post(_billing_path("/units/calculate?tokenCount=50000"), headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["units_required"] == 2
        assert body["token_count"] == 50_000


class TestCheckoutAuthContext:
    def test_checkout_auth_context_returns_authenticated_bearer_context(self) -> None:
        request = MagicMock()
        request.headers = {"authorization": "Bearer valid-token"}
        auth = AuthContext(
            api_key=None,
            principal_type="user",
            principal_id="user-123",
            session_id=None,
            org_id=ORG_ID,
            permissions=(),
            roles=(),
            authenticated=True,
            auth_source="bearer",
            auth_method="bearer",
            key_type="personal",
        )

        result = get_checkout_auth_context(request=request, auth=auth)

        assert result is auth

    def test_checkout_auth_context_preserves_bearer_context_when_header_present_but_not_authenticated(self) -> None:
        request = MagicMock()
        request.headers = {"authorization": "Bearer candidate-token"}
        auth = AuthContext(
            api_key=None,
            principal_type="user",
            principal_id=None,
            session_id=None,
            org_id=None,
            permissions=(),
            roles=(),
            authenticated=False,
            auth_source="bearer",
            auth_method="bearer",
            key_type="personal",
        )

        result = get_checkout_auth_context(request=request, auth=auth)

        assert result is auth

    def test_checkout_auth_context_returns_anonymous_context_when_auth_not_required(self) -> None:
        request = MagicMock()
        request.headers = {}

        auth = AuthContext(
            api_key=None,
            principal_type="anonymous",
            principal_id=None,
            session_id=None,
            org_id=None,
            permissions=(),
            roles=(),
            authenticated=False,
            auth_source="disabled",
            auth_method=None,
            key_type="personal",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router._allow_anonymous_checkout", lambda: True)
            result = get_checkout_auth_context(request=request, auth=auth)

        assert result.principal_type == "anonymous"
        assert result.authenticated is False
        assert result.auth_source == "disabled"

    def test_checkout_auth_context_returns_original_context_when_auth_required_and_not_authenticated(self) -> None:
        request = MagicMock()
        request.headers = {}
        auth = AuthContext(
            api_key=None,
            principal_type="anonymous",
            principal_id=None,
            session_id=None,
            org_id=None,
            permissions=(),
            roles=(),
            authenticated=False,
            auth_source="disabled",
            auth_method=None,
            key_type="personal",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router._allow_anonymous_checkout", lambda: False)
            result = get_checkout_auth_context(request=request, auth=auth)

        assert result is auth


class TestCheckoutSessionRoutes:
    def test_create_checkout_session_with_package_id_calls_service_with_resolved_values(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.create_checkout_session.return_value = _obj_with_to_dict(
            session_id=SESSION_ID,
            checkout_url="https://checkout.stripe.com/c/pay/test",
            org_id=ORG_ID,
            mode=StripeCheckoutMode.PAYMENT.value,
            price_id="price_pkg5000",
            quantity=1,
            unit_credits=5000,
            expires_at=None,
            metadata={"source": "test", "package_id": "pkg5000", "org_id": ORG_ID},
            created_at="2026-06-28T00:00:00Z",
            schema_version="1.0",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            resp = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "priceId": "price_attacker",
                    "unitCredits": 42,
                    "quantity": 1,
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                    "metadata": {
                        "source": "test",
                        "owner_key": "attacker@ironclaw.test",
                        "org_id": "attacker-org",
                        "unit_credits": "999999",
                    },
                },
                headers=_auth_headers(),
            )

        assert resp.status_code == 201
        mock_svc.create_checkout_session.assert_called_once_with(
            org_id=ORG_ID,
            price_id="price_pkg5000",
            mode=StripeCheckoutMode.PAYMENT,
            quantity=1,
            unit_credits=5000,
            success_url=_ALLOWED_SUCCESS_URL,
            cancel_url=_ALLOWED_CANCEL_URL,
            customer_id=None,
            owner_key="buyer@ironclaw.test",
            metadata={
                "source": "test",
                "owner_key": "buyer@ironclaw.test",
                "package_id": "pkg_5000",
                "org_id": ORG_ID,
                "unit_credits": "5000",
            },
        )

    def test_create_checkout_session_ignores_request_owner_and_customer_ids(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        auth_without_org = replace(_TEST_AUTH_CONTEXT, org_id=None)
        mock_svc.create_checkout_session.return_value = _obj_with_to_dict(
            session_id=SESSION_ID,
            checkout_url="https://checkout.stripe.com/c/pay/personal",
            org_id="buyer@ironclaw.test",
            mode=StripeCheckoutMode.PAYMENT.value,
            price_id="price_pkg5000",
            quantity=1,
            unit_credits=5000,
            expires_at=None,
            metadata={},
            created_at="2026-06-28T00:00:00Z",
            schema_version="1.0",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(app.dependency_overrides, get_auth_context, lambda: auth_without_org)
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            response = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "organizationId": "attacker-org",
                    "customerId": "cus_attacker",
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert response.status_code == 201
        checkout_kwargs = mock_svc.create_checkout_session.call_args.kwargs
        assert checkout_kwargs["org_id"] == "buyer@ironclaw.test"
        assert checkout_kwargs["customer_id"] is None
        assert checkout_kwargs["metadata"]["org_id"] == "buyer@ironclaw.test"
        assert checkout_kwargs["metadata"]["owner_key"] == "buyer@ironclaw.test"

    @pytest.mark.parametrize(
        ("success_url", "cancel_url"),
        [
            ("https://moving-forward.ca/billing/success", "https://moving-forward.ca/billing/cancel"),
            ("https://www.moving-forward.ca/billing/success", "https://www.moving-forward.ca/billing/cancel"),
            ("https://ironclaw-security.pages.dev/billing/success", "https://ironclaw-security.pages.dev/billing/cancel"),
            ("http://localhost:3000/billing/success", "http://localhost:3000/billing/cancel"),
            ("http://127.0.0.1:5173/billing/success", "http://127.0.0.1:5173/billing/cancel"),
        ],
    )
    def test_create_checkout_session_accepts_canonical_domain_variants(
        self,
        client: TestClient,
        mock_svc: MagicMock,
        success_url: str,
        cancel_url: str,
    ) -> None:
        mock_svc.create_checkout_session.return_value = _obj_with_to_dict(
            session_id=SESSION_ID,
            checkout_url="https://checkout.stripe.com/c/pay/canonical",
            org_id=ORG_ID,
            mode=StripeCheckoutMode.PAYMENT.value,
            price_id="price_pkg5000",
            quantity=1,
            unit_credits=5000,
            expires_at=None,
            metadata={"flow": "canonical", "org_id": ORG_ID},
            created_at="2026-06-28T00:00:00Z",
            schema_version="1.0",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            resp = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "unitCredits": 42,
                    "successUrl": success_url,
                    "cancelUrl": cancel_url,
                    "metadata": {"flow": "canonical"},
                },
                headers=_auth_headers(),
            )

        assert resp.status_code == 201
        assert mock_svc.create_checkout_session.call_args.kwargs["success_url"] == success_url
        assert mock_svc.create_checkout_session.call_args.kwargs["cancel_url"] == cancel_url

    def test_create_checkout_session_rejects_unconfigured_price_id(self, client: TestClient) -> None:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            resp = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "priceId": "price_direct_123",
                    "unitCredits": 42,
                    "quantity": 1,
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert detail["error"] == "unsupported_price_id"

    def test_create_checkout_session_rejects_nonpayment_package_mode(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            response = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "mode": "subscription",
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "package_checkout_mode_invalid"
        mock_svc.create_checkout_session.assert_not_called()

    def test_create_checkout_session_with_direct_price_id_calls_service(self, client: TestClient, mock_svc: MagicMock) -> None:
        checkout_result = _obj_with_to_dict(
            session_id=SESSION_ID,
            checkout_url="https://checkout.stripe.com/c/pay/direct",
            org_id=ORG_ID,
            mode=StripeCheckoutMode.PAYMENT.value,
            price_id="price_pkg5000",
            quantity=2,
            unit_credits=10000,
            expires_at=None,
            metadata={
                "flow": "direct",
                "package_id": "pkg_5000",
                "org_id": ORG_ID,
                "unit_credits": "10000",
                "owner_key": "buyer@ironclaw.test",
            },
            created_at="2026-06-28T00:00:00Z",
            schema_version="1.0",
        )
        mock_svc.create_checkout_session.return_value = checkout_result

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            resp = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "priceId": "price_pkg5000",
                    "unitCredits": 42,
                    "quantity": 2,
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                    "metadata": {"flow": "direct"},
                },
                headers=_auth_headers(),
            )

        assert resp.status_code == 201
        mock_svc.create_checkout_session.assert_called_once_with(
            org_id=ORG_ID,
            price_id="price_pkg5000",
            mode=StripeCheckoutMode.PAYMENT,
            quantity=2,
            unit_credits=10000,
            success_url=_ALLOWED_SUCCESS_URL,
            cancel_url=_ALLOWED_CANCEL_URL,
            customer_id=None,
            owner_key="buyer@ironclaw.test",
            metadata={
                "flow": "direct",
                "package_id": "pkg_5000",
                "org_id": ORG_ID,
                "unit_credits": "10000",
                "owner_key": "buyer@ironclaw.test",
            },
        )

    def test_create_checkout_session_requires_billing_owner(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        auth_without_owner = replace(_TEST_AUTH_CONTEXT, metadata={})

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(app.dependency_overrides, get_auth_context, lambda: auth_without_owner)
            resp = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "priceId": "price_direct_123",
                    "unitCredits": 42,
                    "quantity": 1,
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "verified_billing_identity_required"
        mock_svc.create_checkout_session.assert_not_called()

    def test_create_checkout_session_unexpected_error_returns_json_502(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.create_checkout_session.side_effect = RuntimeError("socket reset")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            resp = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "priceId": "price_pkg5000",
                    "unitCredits": 42,
                    "quantity": 2,
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                    "metadata": {"flow": "direct"},
                },
                headers=_auth_headers(),
            )

        assert resp.status_code == 502
        assert resp.json()["detail"]["error"] == "stripe_checkout_unavailable"

    def test_create_checkout_session_fails_closed_when_fulfillment_storage_is_unavailable(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.create_checkout_session.side_effect = StripePersistenceError(
            "durable fulfillment storage is unavailable",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            response = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "checkout_storage_unavailable"
        assert response.json()["detail"]["retryable"] is True

    def test_create_checkout_session_fails_closed_when_customer_link_storage_is_unavailable(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.resolve_customer_id.side_effect = StripePersistenceError(
            "Stripe customer link could not be loaded from durable storage.",
            error_code="checkout_customer_lookup_unavailable",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            response = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "checkout_customer_lookup_unavailable"
        assert response.json()["detail"]["retryable"] is True
        assert "customer link" in response.json()["detail"]["detail"]
        mock_svc.create_checkout_session.assert_not_called()

    def test_create_checkout_session_returns_distinct_code_for_customer_persist_failure(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.create_checkout_session.side_effect = StripePersistenceError(
            "Stripe customer link could not be persisted to durable storage.",
            error_code="checkout_customer_persist_unavailable",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            response = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "checkout_customer_persist_unavailable"
        assert response.json()["detail"]["retryable"] is True

    def test_create_checkout_session_returns_distinct_code_for_fulfillment_storage_failure(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.create_checkout_session.side_effect = StripePersistenceError(
            "Checkout fulfillment storage is unavailable.",
            error_code="checkout_fulfillment_storage_unavailable",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            response = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "checkout_fulfillment_storage_unavailable"
        assert response.json()["detail"]["retryable"] is True

    def test_checkout_session_status_checks_owner_and_redacts_owner_metadata(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "mode": "payment",
            "org_id": ORG_ID,
            "customer_id": CUSTOMER_ID,
            "unit_credits": 5000,
            "units_credited": False,
            "url": "https://checkout.stripe.com/c/pay/test",
            "metadata": {
                "owner_key": "buyer@ironclaw.test",
                "package_id": "pkg_5000",
            },
        }

        response = client.get(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/status"),
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["payment_status"] == "paid"
        assert payload["metadata"] == {"package_id": "pkg_5000"}
        mock_svc.retrieve_checkout_session.assert_called_once_with(SESSION_ID)

    def test_checkout_session_status_reports_ledger_units_credited(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "unit_credits": 5000,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }
        mock_svc.get_checkout_units_credited.return_value = 5000

        response = client.get(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/status"),
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        assert response.json()["units_credited"] == 5000
        assert mock_svc.get_checkout_units_credited.call_args.args[0] == SESSION_ID

    def test_checkout_session_status_rejects_another_billing_owner(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "org_id": ORG_ID,
            "metadata": {"owner_key": "another-buyer@ironclaw.test"},
        }

        response = client.get(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/status"),
            headers=_auth_headers(),
        )

        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "checkout_session_not_accessible"

    def test_complete_checkout_session_rejects_unpaid_session(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "unpaid",
            "org_id": ORG_ID,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/complete"),
            json={},
            headers=_auth_headers(),
        )

        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "checkout_payment_not_confirmed"
        mock_svc.complete_checkout_session.assert_not_called()

    def test_reconcile_checkout_session_returns_units_credited(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "customer_id": CUSTOMER_ID,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }
        mock_svc.reconcile_checkout_session.return_value = {"payment_confirmed": True}
        mock_svc.get_checkout_units_credited.return_value = 5000

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/reconcile"),
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        assert response.json()["payment_status"] == "paid"
        assert response.json()["units_credited"] == 5000
        mock_svc.reconcile_checkout_session.assert_called_once_with(SESSION_ID)

    def test_reconcile_checkout_session_rejects_other_owner(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "metadata": {"owner_key": "someone-else@ironclaw.test"},
        }

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/reconcile"),
            headers=_auth_headers(),
        )

        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "checkout_session_not_accessible"
        mock_svc.reconcile_checkout_session.assert_not_called()

    def test_reconcile_checkout_session_maps_missing_session_to_404(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }
        mock_svc.reconcile_checkout_session.side_effect = StripeSessionNotFoundError("checkout session not found")

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/reconcile"),
            headers=_auth_headers(),
        )

        assert response.status_code == 404

    def test_reconcile_checkout_session_maps_stripe_failure_to_502(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }
        mock_svc.reconcile_checkout_session.side_effect = StripeServiceError("stripe unavailable")

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/reconcile"),
            headers=_auth_headers(),
        )

        assert response.status_code == 502
        assert response.json()["detail"]["error"] == "reconcile_error"

    def test_reconcile_checkout_session_reports_pending_install_keys_after_credit(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }
        mock_svc.reconcile_checkout_session.side_effect = StripeInstallKeyProvisioningError("install keys failed")
        mock_svc.get_checkout_units_credited.return_value = 5000

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/reconcile"),
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        body = response.json()
        assert body["payment_confirmed"] is True
        assert body["fulfillment_status"] == "install_keys_pending"
        assert body["error"] == "install_key_provisioning_failed"
        assert body["units_credited"] == 5000

    def test_reconcile_recent_checkout_sessions_returns_wallet_verified_results(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        result = {
            "status": "complete",
            "pages_scanned": 1,
            "sessions_scanned": 1,
            "sessions_matched": 1,
            "sessions_reconciled": 1,
            "units_credited": 5000,
            "sessions": [
                {
                    "session_id": SESSION_ID,
                    "status": "fulfilled",
                    "fulfillment_status": "fulfilled",
                    "units_credited": 5000,
                    "support_reference": SESSION_ID,
                    "action": None,
                },
            ],
            "truncated": False,
        }
        mock_svc.reconcile_owner_checkout_sessions.return_value = result

        response = client.post(
            _billing_path("/checkout/reconcile-recent"),
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        assert response.json() == result
        mock_svc.reconcile_owner_checkout_sessions.assert_called_once_with("buyer@ironclaw.test")

    def test_reconcile_recent_checkout_sessions_returns_partial_failures(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        result = {
            "status": "partial",
            "pages_scanned": 1,
            "sessions_scanned": 2,
            "sessions_matched": 2,
            "sessions_reconciled": 1,
            "units_credited": 5000,
            "sessions": [
                {
                    "session_id": SESSION_ID,
                    "status": "failed",
                    "fulfillment_status": "failed",
                    "error": "Checkout session integrity verification failed.",
                    "support_reference": SESSION_ID,
                    "action": "retry_sync",
                },
                {
                    "session_id": "cs_test_002",
                    "status": "fulfilled",
                    "fulfillment_status": "fulfilled",
                    "units_credited": 5000,
                    "support_reference": "cs_test_002",
                    "action": None,
                },
            ],
            "truncated": False,
        }
        mock_svc.reconcile_owner_checkout_sessions.return_value = result

        response = client.post(
            _billing_path("/checkout/reconcile-recent"),
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        assert response.json() == result

    def test_reconcile_recent_preserves_refund_support_action(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        result = {
            "status": "partial",
            "sessions_matched": 1,
            "sessions_reconciled": 0,
            "units_credited": 0,
            "sessions": [
                {
                    "session_id": SESSION_ID,
                    "status": "refunded",
                    "fulfillment_status": "refunded",
                    "units_credited": 0,
                    "action": "contact_support",
                    "support_reference": SESSION_ID,
                }
            ],
            "truncated": False,
        }
        mock_svc.reconcile_owner_checkout_sessions.return_value = result

        response = client.post(
            _billing_path("/checkout/reconcile-recent"),
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        outcome = response.json()["sessions"][0]
        assert outcome["status"] == "refunded"
        assert outcome["action"] == "contact_support"
        assert outcome["support_reference"] == SESSION_ID

    def test_reconcile_recent_checkout_sessions_requires_billing_owner(
        self,
        client: TestClient,
        mock_svc: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "app.routers.stripe_router.resolve_authenticated_billing_owner",
            lambda _auth: None,
        )

        response = client.post(
            _billing_path("/checkout/reconcile-recent"),
            headers=_auth_headers(),
        )

        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "billing_owner_unavailable"
        mock_svc.reconcile_owner_checkout_sessions.assert_not_called()

    def test_reconcile_recent_checkout_sessions_exposes_service_failure(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.reconcile_owner_checkout_sessions.side_effect = StripeServiceError(
            "STRIPE_SECRET_KEY is not configured.",
        )

        response = client.post(
            _billing_path("/checkout/reconcile-recent"),
            headers=_auth_headers(),
        )

        assert response.status_code == 502
        assert response.json()["detail"] == {
            "error": "reconcile_error",
            "detail": "STRIPE_SECRET_KEY is not configured.",
        }

    def test_complete_checkout_session_uses_stripe_customer_id(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "customer_id": CUSTOMER_ID,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }
        mock_svc.complete_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "already_complete": False,
            "units_credited": 5000,
        }

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/complete"),
            json={},
            headers=_auth_headers(),
        )

        assert response.status_code == 200
        mock_svc.complete_checkout_session.assert_called_once_with(
            session_id=SESSION_ID,
            customer_id=CUSTOMER_ID,
        )

    def test_complete_checkout_session_rejects_client_customer_mismatch(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.retrieve_checkout_session.return_value = {
            "session_id": SESSION_ID,
            "status": "complete",
            "payment_status": "paid",
            "org_id": ORG_ID,
            "customer_id": CUSTOMER_ID,
            "metadata": {"owner_key": "buyer@ironclaw.test"},
        }

        response = client.post(
            _billing_path(f"/checkout/sessions/{SESSION_ID}/complete"),
            json={"customerId": "cus_attacker"},
            headers=_auth_headers(),
        )

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "checkout_customer_mismatch"
        mock_svc.complete_checkout_session.assert_not_called()

    def test_create_checkout_session_uses_existing_customer_id_from_service_map(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.create_checkout_session.return_value = _obj_with_to_dict(
            session_id=SESSION_ID,
            checkout_url="https://checkout.stripe.com/c/pay/customer",
            org_id=ORG_ID,
            mode=StripeCheckoutMode.PAYMENT.value,
            price_id="price_pkg5000",
            quantity=1,
            unit_credits=5000,
            expires_at=None,
            metadata={"org_id": ORG_ID},
            created_at="2026-06-28T00:00:00Z",
            schema_version="1.0",
        )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.routers.stripe_router.vault.get", MagicMock(side_effect=_TEST_PRICE_IDS.get))
            resp = client.post(
                _billing_path("/checkout/sessions"),
                json={
                    "packageId": "pkg5000",
                    "unitCredits": 10,
                    "quantity": 1,
                    "successUrl": _ALLOWED_SUCCESS_URL,
                    "cancelUrl": _ALLOWED_CANCEL_URL,
                },
                headers=_auth_headers(),
            )

        assert resp.status_code == 201
        mock_svc.create_checkout_session.assert_called_once()
        assert mock_svc.create_checkout_session.call_args.kwargs["customer_id"] == CUSTOMER_ID


class TestAdditionalRoutes:
    def test_get_subscription(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.get_subscription.return_value = _obj_with_to_dict(
            subscription_id=SUBSCRIPTION_ID,
            status="active",
            customer_id=CUSTOMER_ID,
        )

        resp = client.get(_billing_path(f"/subscriptions/{SUBSCRIPTION_ID}"), headers=_auth_headers())

        assert resp.status_code == 200
        body = resp.json()
        assert body["subscription_id"] == SUBSCRIPTION_ID
        assert body["status"] == "active"

    def test_set_default_payment_method_success(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.list_payment_methods.return_value = [
            _obj_with_to_dict(
                payment_method_id=PM_ID,
                customer_id=CUSTOMER_ID,
                type="card",
                brand="visa",
                last4="4242",
                exp_month=12,
                exp_year=2030,
                is_default=False,
                created_at="2026-06-28T00:00:00Z",
                schema_version="1.0",
            )
        ]
        mock_svc.set_default_payment_method.return_value = _obj_with_to_dict(
            payment_method_id=PM_ID,
            customer_id=CUSTOMER_ID,
            type="card",
            brand="visa",
            last4="4242",
            exp_month=12,
            exp_year=2030,
            is_default=True,
            created_at="2026-06-28T00:00:00Z",
            schema_version="1.0",
        )

        resp = client.post(
            _billing_path(f"/payment-methods/{PM_ID}/set-default"),
            headers=_auth_headers(),
        )

        assert resp.status_code == 200
        mock_svc.set_default_payment_method.assert_called_once_with(
            customer_id=CUSTOMER_ID,
            payment_method_id=PM_ID,
        )

    def test_credit_units_success(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.credit_units.return_value = _make_balance_response(balance=750)
        admin_context = replace(_TEST_AUTH_CONTEXT, roles=("platform_admin",))
        client.app.dependency_overrides[get_auth_context] = lambda: admin_context
        try:
            resp = client.post(
                _billing_path("/units/credit"),
                json={"units": 250, "reason": "manual.credit", "referenceId": "credit-ref-001"},
                headers=_auth_headers(),
            )
        finally:
            client.app.dependency_overrides[get_auth_context] = _override_get_auth_context

        assert resp.status_code == 200
        mock_svc.credit_units.assert_called_once()
        call_kwargs = mock_svc.credit_units.call_args.kwargs
        assert call_kwargs["org_id"] == ORG_ID
        assert call_kwargs["amount"] == 250
        assert call_kwargs["reason"] == StripeUnitEventReason.MANUAL_CREDIT
        assert call_kwargs["reference_id"] == "credit-ref-001"

    def test_credit_units_rejects_non_admin(self, client: TestClient, mock_svc: MagicMock) -> None:
        resp = client.post(
            _billing_path("/units/credit"),
            json={"units": 250, "reason": "manual.credit"},
            headers=_auth_headers(),
        )

        assert resp.status_code == 403
        mock_svc.credit_units.assert_not_called()

    def test_credit_units_rejects_anonymous(self, client: TestClient, mock_svc: MagicMock) -> None:
        anonymous_context = AuthContext(
            api_key=None,
            principal_type="anonymous",
            principal_id=None,
            session_id=None,
            org_id=None,
            authenticated=False,
            auth_source="disabled",
            auth_method=None,
            key_type="personal",
        )
        client.app.dependency_overrides[get_auth_context] = lambda: anonymous_context
        try:
            resp = client.post(
                _billing_path("/units/credit"),
                json={"units": 250, "reason": "manual.credit"},
                headers={"X-Org-Id": ORG_ID},
            )
        finally:
            client.app.dependency_overrides[get_auth_context] = _override_get_auth_context

        assert resp.status_code == 401
        mock_svc.credit_units.assert_not_called()


class TestStripeWebhookFailureRetry:
    def test_handler_failure_returns_non_success_status_to_stripe(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        mock_svc.verify_webhook_signature.return_value = SimpleNamespace(
            valid=True,
            event_type="checkout.session.completed",
            event_id="evt_retry_001",
            error=None,
            payload={
                "id": "evt_retry_001",
                "type": "checkout.session.completed",
                "data": {"object": {"id": "cs_retry_001"}},
            },
        )
        mock_svc.handle_webhook_event.return_value = {
            "action": "error",
            "error": "sensitive internal details",
        }

        response = client.post(
            "/webhooks/stripe",
            content=b"{}",
            headers={"stripe-signature": "t=1,v1=test"},
        )

        assert response.status_code == 502
        assert "sensitive internal details" not in response.text

    def test_charge_refunded_is_acknowledged_with_200(
        self,
        client: TestClient,
        mock_svc: MagicMock,
    ) -> None:
        refund_payload = {
            "id": "evt_refund_route_001",
            "type": "charge.refunded",
            "data": {"object": {"id": "ch_route_001", "payment_intent": "pi_route_001"}},
        }
        mock_svc.verify_webhook_signature.return_value = SimpleNamespace(
            valid=True,
            event_type="charge.refunded",
            event_id="evt_refund_route_001",
            error=None,
            payload=refund_payload,
        )
        mock_svc.handle_webhook_event.return_value = {"action": "processed"}

        response = client.post(
            "/webhooks/stripe",
            content=b"{}",
            headers={"stripe-signature": "t=1,v1=test"},
        )

        assert response.status_code == 200
        mock_svc.handle_webhook_event.assert_called_once_with(refund_payload)
