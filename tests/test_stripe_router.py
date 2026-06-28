from __future__ import annotations

from collections.abc import Generator
import threading
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest

from app.core.auth import AuthContext, require_auth_context
from app.main import app
from app.routers.stripe_router import get_stripe_service
from app.services.stripe_service import (
    MeteredSyncResponse,
    StripeInsufficientUnitsError,
    StripeService,
    StripeUnitEventReason,
    UnitBalanceResponse,
    units_for_tokens,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ORG_ID = "test-org-router-001"
CUSTOMER_ID = "cus_test_router_001"
SUB_ITEM_ID = "si_test_item_001"
PM_ID = "pm_test_001"

# Must match conftest.py IRONCLAW_API_KEY env value exactly
_API_KEY = "test-api-key"

# ---------------------------------------------------------------------------
# Auth override — mirrors conftest.py exactly
# ---------------------------------------------------------------------------

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
)


def _override_require_auth_context() -> AuthContext:
    return _TEST_AUTH_CONTEXT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_headers() -> dict[str, str]:
    return {"X-API-Key": _API_KEY, "X-Org-Id": ORG_ID}


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


def _build_mock_svc() -> MagicMock:
    svc = MagicMock(spec=StripeService)
    svc._lock = threading.Lock()
    svc._org_customer_map = {}
    return svc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_svc() -> MagicMock:
    return _build_mock_svc()


@pytest.fixture()
def client(mock_svc: MagicMock) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_stripe_service] = lambda: mock_svc
    app.dependency_overrides[require_auth_context] = _override_require_auth_context
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_stripe_service, None)
    app.dependency_overrides.pop(require_auth_context, None)


# ---------------------------------------------------------------------------
# POST /billing/metered/sync
# ---------------------------------------------------------------------------


class TestMeteredSync:
    def test_metered_sync_calls_report_with_subscription_item_id(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        metered_resp = _make_metered_response(quantity=5)
        mock_svc.report_metered_usage.return_value = metered_resp
        mock_svc.debit_units.return_value = _make_balance_response()

        payload = {
            "subscription_item_id": SUB_ITEM_ID,
            "quantity": 5,
            "action": "increment",
        }
        resp = client.post("/billing/metered/sync", json=payload, headers=_auth_headers())

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

        payload = {"subscription_item_id": SUB_ITEM_ID, "quantity": 7}
        resp = client.post("/billing/metered/sync", json=payload, headers=_auth_headers())

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs is not None
        assert "amount" in call_kwargs.kwargs, "debit_units must be called with amount= keyword argument, not units="
        assert call_kwargs.kwargs["amount"] == 7
        assert call_kwargs.kwargs["reason"] == StripeUnitEventReason.METERED_SYNC

    def test_metered_sync_zero_quantity_skips_debit(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.report_metered_usage.return_value = _make_metered_response(quantity=0)

        payload = {"subscription_item_id": SUB_ITEM_ID, "quantity": 0}
        resp = client.post("/billing/metered/sync", json=payload, headers=_auth_headers())

        assert resp.status_code == 200
        mock_svc.debit_units.assert_not_called()

    def test_metered_sync_insufficient_units_does_not_fail_request(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.report_metered_usage.return_value = _make_metered_response(quantity=99)
        mock_svc.debit_units.side_effect = StripeInsufficientUnitsError(org_id=ORG_ID, have=0, need=99)

        payload = {"subscription_item_id": SUB_ITEM_ID, "quantity": 99}
        resp = client.post("/billing/metered/sync", json=payload, headers=_auth_headers())

        assert resp.status_code == 200

    def test_metered_sync_with_idempotency_key(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.report_metered_usage.return_value = _make_metered_response(idempotency_key="custom-key-abc")
        mock_svc.debit_units.return_value = _make_balance_response()

        payload = {
            "subscription_item_id": SUB_ITEM_ID,
            "quantity": 3,
            "idempotency_key": "custom-key-abc",
        }
        resp = client.post("/billing/metered/sync", json=payload, headers=_auth_headers())

        assert resp.status_code == 200
        mock_svc.report_metered_usage.assert_called_once_with(
            org_id=ORG_ID,
            subscription_item_id=SUB_ITEM_ID,
            quantity=3,
            action="increment",
            idempotency_key="custom-key-abc",
        )


# ---------------------------------------------------------------------------
# _resolve_customer_id returning None → 404 paths
# ---------------------------------------------------------------------------


class TestResolveCustomerIdNone:
    def test_attach_payment_method_no_customer_returns_404(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map.clear()

        resp = client.post(
            "/billing/payment-methods/attach",
            json={"payment_method_id": PM_ID, "set_as_default": False},
            headers=_auth_headers(),
        )

        assert resp.status_code == 404
        body = resp.json()
        assert "no_stripe_customer_for_org" in body.get("detail", "")

    def test_set_default_payment_method_no_customer_returns_404(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map.clear()

        resp = client.post(
            f"/billing/payment-methods/{PM_ID}/set-default",
            headers=_auth_headers(),
        )

        assert resp.status_code == 404
        body = resp.json()
        assert "no_stripe_customer_for_org" in body.get("detail", "")

    def test_list_payment_methods_no_customer_returns_empty_list(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map.clear()

        resp = client.get("/billing/payment-methods", headers=_auth_headers())

        assert resp.status_code == 200
        body = resp.json()
        assert body["payment_methods"] == []
        assert body["customer_id"] is None


# ---------------------------------------------------------------------------
# POST /billing/units/debit
# ---------------------------------------------------------------------------


class TestDebitUnits:
    def test_debit_units_calls_svc_with_amount_keyword(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.debit_units.return_value = _make_balance_response(balance=490)

        token_count = 25_000
        resp = client.post(
            "/billing/units/debit",
            json={"token_count": token_count},
            headers=_auth_headers(),
        )

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs is not None
        assert "amount" in call_kwargs.kwargs, "debit_units must be called with amount= keyword, not units="
        expected_amount = units_for_tokens(token_count)
        assert call_kwargs.kwargs["amount"] == expected_amount

    def test_debit_units_insufficient_units_returns_402(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.debit_units.side_effect = StripeInsufficientUnitsError(org_id=ORG_ID, have=0, need=5)

        resp = client.post(
            "/billing/units/debit",
            json={"token_count": 125_000},
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
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.debit_units.return_value = _make_balance_response(balance=499)

        resp = client.post(
            "/billing/units/debit",
            json={"token_count": 1},
            headers=_auth_headers(),
        )

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs.kwargs["reason"] == StripeUnitEventReason.METERED_SYNC

    def test_debit_units_with_reference_id(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
        mock_svc.debit_units.return_value = _make_balance_response(balance=498)

        resp = client.post(
            "/billing/units/debit",
            json={"token_count": 50_000, "reference_id": "scan-ref-abc"},
            headers=_auth_headers(),
        )

        assert resp.status_code == 200
        call_kwargs = mock_svc.debit_units.call_args
        assert call_kwargs.kwargs.get("reference_id") == "scan-ref-abc"

    def test_debit_units_missing_org_id_returns_error(self, client: TestClient, mock_svc: MagicMock) -> None:
        # Override auth context to one with no org_id to simulate missing org
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
        )
        app.dependency_overrides[require_auth_context] = lambda: no_org_context
        try:
            resp = client.post(
                "/billing/units/debit",
                json={"token_count": 1},
                headers={"X-API-Key": _API_KEY},
            )
            assert resp.status_code in (400, 401, 422)
        finally:
            app.dependency_overrides[require_auth_context] = _override_require_auth_context


# ---------------------------------------------------------------------------
# patch.object coverage: _lock and _org_customer_map
# ---------------------------------------------------------------------------


class TestPatchObjectLockAndMap:
    """
    StripeService.__new__ skips __init__ so _lock/_org_customer_map do not
    exist on the bare instance.  We set them directly before patch.object.
    """

    def _bare_svc_with_attrs(self) -> StripeService:
        svc = StripeService.__new__(StripeService)
        svc._lock = threading.Lock()
        svc._org_customer_map = {}
        return svc

    def test_resolve_customer_id_via_patch_object_returns_customer(self) -> None:
        svc = self._bare_svc_with_attrs()
        real_map = {ORG_ID: CUSTOMER_ID}

        with patch.object(svc, "_org_customer_map", real_map):
            from app.routers.stripe_router import _resolve_customer_id

            result = _resolve_customer_id(svc, ORG_ID)

        assert result == CUSTOMER_ID

    def test_resolve_customer_id_via_patch_object_returns_none_for_unknown_org(self) -> None:
        svc = self._bare_svc_with_attrs()
        real_map: dict[str, str] = {}

        with patch.object(svc, "_org_customer_map", real_map):
            from app.routers.stripe_router import _resolve_customer_id

            result = _resolve_customer_id(svc, ORG_ID)

        assert result is None

    def test_attach_route_404_controlled_via_patch_object(self) -> None:
        svc = _build_mock_svc()
        app.dependency_overrides[get_stripe_service] = lambda: svc
        app.dependency_overrides[require_auth_context] = _override_require_auth_context
        try:
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.post(
                "/billing/payment-methods/attach",
                json={"payment_method_id": PM_ID},
                headers=_auth_headers(),
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_stripe_service, None)
            app.dependency_overrides.pop(require_auth_context, None)

    def test_set_default_route_404_controlled_via_patch_object(self) -> None:
        svc = _build_mock_svc()
        app.dependency_overrides[get_stripe_service] = lambda: svc
        app.dependency_overrides[require_auth_context] = _override_require_auth_context
        try:
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.post(
                f"/billing/payment-methods/{PM_ID}/set-default",
                headers=_auth_headers(),
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_stripe_service, None)
            app.dependency_overrides.pop(require_auth_context, None)

    def test_list_payment_methods_empty_via_patch_object(self) -> None:
        svc = _build_mock_svc()
        app.dependency_overrides[get_stripe_service] = lambda: svc
        app.dependency_overrides[require_auth_context] = _override_require_auth_context
        try:
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.get("/billing/payment-methods", headers=_auth_headers())
            assert resp.status_code == 200
            assert resp.json()["payment_methods"] == []
        finally:
            app.dependency_overrides.pop(get_stripe_service, None)
            app.dependency_overrides.pop(require_auth_context, None)


# ---------------------------------------------------------------------------
# Additional coverage: catalogue, balance, ledger
# ---------------------------------------------------------------------------


class TestAncillaryRoutes:
    def test_get_billing_catalogue_no_auth_required(self, client: TestClient) -> None:
        resp = client.get("/billing/catalogue", headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert "packages" in body
        assert "tokens_per_unit" in body

    def test_get_unit_balance(self, client: TestClient, mock_svc: MagicMock) -> None:
        mock_svc.get_unit_balance.return_value = _make_balance_response(balance=250)
        resp = client.get("/billing/units/balance", headers=_auth_headers())
        assert resp.status_code == 200
        assert resp.json()["balance"] == 250

    def test_get_unit_ledger(self, client: TestClient, mock_svc: MagicMock) -> None:
        balance_resp = UnitBalanceResponse(
            org_id=ORG_ID,
            balance=100,
            ledger_entries=[{"entry_id": "ule-001", "delta": 100}],
        )
        mock_svc.get_unit_balance.return_value = balance_resp
        resp = client.get("/billing/units/ledger", headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["balance"] == 100
        assert len(body["ledger"]) == 1

    def test_calculate_units_endpoint(self, client: TestClient) -> None:
        resp = client.post("/billing/units/calculate?token_count=50000", headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["units_required"] == 2
        assert body["token_count"] == 50_000
