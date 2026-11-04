from __future__ import annotations

from collections.abc import Generator
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

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

from app.core.auth import AuthContext, get_auth_context
from app.main import app as _app
from app.routers.stripe_router import get_stripe_service
from app.services.stripe_service import StripeService, StripeServiceError
from app.ui.billing import payment_methods as payment_methods_module
from app.ui.billing.package import PACKAGE_CATALOGUE, _get_stripe_status

_MOCK_API_KEY = "test-api-key"
ORG_ID = "org-001"
CUSTOMER_ID = "cus_test_001"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY, "X-Org-Id": ORG_ID}


_TEST_AUTH_CONTEXT = AuthContext(
    api_key=_MOCK_API_KEY,
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
)


def _override_get_auth_context() -> AuthContext:
    return _TEST_AUTH_CONTEXT


def _build_mock_svc() -> MagicMock:
    svc = MagicMock(spec=StripeService)
    svc._org_customer_map = {}
    svc.resolve_customer_id.side_effect = lambda org_id: svc._org_customer_map.get(org_id)
    svc.list_payment_methods.return_value = []
    svc.set_default_payment_method.return_value = {"status": "updated"}
    svc.detach_payment_method.return_value = {"status": "deleted"}
    return svc


class FakeSupabaseQuery:
    def __init__(self, table_name: str, client: FakeSupabaseClient) -> None:
        self.table_name = table_name
        self.client = client
        self.filters_eq: list[tuple[str, object]] = []
        self.filters_neq: list[tuple[str, object]] = []
        self.order_by: str | None = None
        self.insert_payload: dict[str, object] | None = None
        self.update_payload: dict[str, object] | None = None
        self.mode: str | None = None

    def select(self, *_args, **_kwargs) -> FakeSupabaseQuery:
        self.mode = "select"
        return self

    def eq(self, key: str, value: object) -> FakeSupabaseQuery:
        self.filters_eq.append((key, value))
        return self

    def neq(self, key: str, value: object) -> FakeSupabaseQuery:
        self.filters_neq.append((key, value))
        return self

    def order(self, column: str, *_args, **_kwargs) -> FakeSupabaseQuery:
        self.order_by = column
        return self

    def insert(self, payload: dict[str, object]) -> FakeSupabaseQuery:
        self.mode = "insert"
        self.insert_payload = dict(payload)
        return self

    def update(self, payload: dict[str, object]) -> FakeSupabaseQuery:
        self.mode = "update"
        self.update_payload = dict(payload)
        return self

    def delete(self) -> FakeSupabaseQuery:
        self.mode = "delete"
        return self

    def execute(self) -> SimpleNamespace:
        rows = self.client.tables.setdefault(self.table_name, [])

        if self.mode == "select":
            result = [dict(row) for row in rows if self._matches(row)]
            if self.order_by is not None:
                result.sort(key=lambda row: row.get(self.order_by) or "")
            return SimpleNamespace(data=result)

        if self.mode == "insert":
            payload = dict(self.insert_payload or {})
            if not payload.get("id"):
                payload["id"] = f"row-{self.client.next_id}"
                self.client.next_id += 1
            rows.append(payload)
            return SimpleNamespace(data=[dict(payload)])

        if self.mode == "update":
            updated: list[dict[str, object]] = []
            for row in rows:
                if self._matches(row):
                    row.update(self.update_payload or {})
                    updated.append(dict(row))
            return SimpleNamespace(data=updated)

        if self.mode == "delete":
            kept: list[dict[str, object]] = []
            deleted: list[dict[str, object]] = []
            for row in rows:
                if self._matches(row):
                    deleted.append(dict(row))
                else:
                    kept.append(row)
            self.client.tables[self.table_name] = kept
            return SimpleNamespace(data=deleted)

        return SimpleNamespace(data=[])

    def _matches(self, row: dict[str, object]) -> bool:
        for key, value in self.filters_eq:
            if row.get(key) != value:
                return False
        for key, value in self.filters_neq:
            if row.get(key) == value:
                return False
        return True


class FakeSupabaseClient:
    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, object]]] = {
            "billing_payment_methods": [],
        }
        self.next_id = 1

    def table(self, table_name: str) -> FakeSupabaseQuery:
        return FakeSupabaseQuery(table_name=table_name, client=self)


@pytest.fixture()
def mock_svc() -> MagicMock:
    return _build_mock_svc()


@pytest.fixture()
def fake_supabase(monkeypatch: pytest.MonkeyPatch) -> FakeSupabaseClient:
    client = FakeSupabaseClient()
    monkeypatch.setattr(payment_methods_module, "is_supabase_configured", lambda: True)
    monkeypatch.setattr(payment_methods_module, "get_supabase_client", lambda: client)
    return client


@pytest.fixture()
def client(mock_svc: MagicMock) -> Generator[TestClient, None, None]:
    _app.dependency_overrides[get_stripe_service] = lambda: mock_svc
    _app.dependency_overrides[get_auth_context] = _override_get_auth_context
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c
    _app.dependency_overrides.pop(get_stripe_service, None)
    _app.dependency_overrides.pop(get_auth_context, None)


def _make_method_dict(
    *,
    methodid: str,
    brand: str = "visa",
    last4: str = "4242",
    expmonth: int = 12,
    expyear: int = 2028,
    isdefault: bool = False,
    status: str | None = "active",
    type: str = "card",
    createdat: str = "2026-01-01T09:00:00+00:00",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": methodid,
        "stripe_payment_method_id": methodid,
        "payment_method_id": methodid,
        "type": type,
        "brand": brand,
        "last4": last4,
        "exp_month": expmonth,
        "exp_year": expyear,
        "is_default": isdefault,
        "created_at": createdat,
        "organization_id": ORG_ID,
    }
    if status is not None:
        payload["status"] = status
    return payload


def _seed_db_method(
    fake_supabase: FakeSupabaseClient,
    *,
    row_id: str,
    organizationid: str = ORG_ID,
    stripe_payment_method_id: str | None = None,
    payment_method_id: str | None = None,
    is_default: bool = False,
    created_at: str = "2026-01-01T09:00:00+00:00",
    brand: str = "visa",
    last4: str = "4242",
    exp_month: int = 12,
    exp_year: int = 2028,
    status: str = "active",
    type: str = "card",
) -> None:
    method_id = stripe_payment_method_id or payment_method_id or row_id
    fake_supabase.tables["billing_payment_methods"].append(
        {
            "id": row_id,
            "organization_id": organizationid,
            "stripe_payment_method_id": method_id,
            "payment_method_id": payment_method_id or method_id,
            "type": type,
            "brand": brand,
            "last4": last4,
            "exp_month": exp_month,
            "exp_year": exp_year,
            "is_default": is_default,
            "status": status,
            "created_at": created_at,
        }
    )


# ---------------------------------------------------------------------------
# Import safety
# ---------------------------------------------------------------------------


def test_payment_methods_module_imports_without_stripe_payment_method_view_dependency() -> None:
    assert hasattr(payment_methods_module, "router")
    assert "StripePaymentMethodView" not in payment_methods_module.__dict__


# ---------------------------------------------------------------------------
# GET /ui/billing/payment-methods
# ---------------------------------------------------------------------------


def test_get_payment_methods_returns_not_found_when_supabase_not_configured(
    client: TestClient,
    mock_svc: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_svc._org_customer_map.clear()
    monkeypatch.setattr(payment_methods_module, "is_supabase_configured", lambda: False)

    resp = client.get("/ui/billing/payment-methods?organizationid=org-001")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "not_found"
    assert body["organizationid"] == "org-001"
    assert "generatedat" in body
    assert "environment" in body


def test_get_payment_methods_response_shape_when_no_customer_mapping(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map.clear()

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["organizationid"] == "org-001"
    assert body["organizationname"] == "org-001"
    assert body["stripe_customer_id"] is None
    assert body["defaultmethodid"] is None
    assert body["methods"] == []
    assert body["methodcount"] == 0
    assert body["statuscounts"] == []
    assert body["canaddnew"] is True
    assert isinstance(body["generatedat"], str)
    assert isinstance(body["environment"], str)


def test_get_payment_methods_notes_mentions_missing_customer_mapping(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map.clear()

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    joined = " ".join(body["notes"]).lower()
    assert "no stripe customer" in joined or "create a stripe customer" in joined


def test_get_payment_methods_environment_not_hardcoded_local(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_svc._org_customer_map.clear()
    monkeypatch.setenv("IRONCLAW_ENV", "staging")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["environment"] == "staging"


def test_get_payment_methods_stripe_sourced_from_get_stripe_status(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = []
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_xyz789")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()

    expected_stripe = _get_stripe_status()
    assert body["stripe"]["configured"] == expected_stripe.configured
    assert body["stripe"]["mode"] == expected_stripe.mode
    assert body["stripe"]["note"] == expected_stripe.note


def test_get_payment_methods_stripe_mode_scalar_consistent_with_stripe_block_test(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = []
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe_mode"] == body["stripe"]["mode"]


def test_get_payment_methods_stripe_mode_scalar_is_none_when_unconfigured(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = []
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["stripe_mode"] is None


def test_get_payment_methods_full_response_required_keys(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = []

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


def test_get_payment_methods_canaddnew_false_when_at_max(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = [
        _make_method_dict(methodid="pm-001", isdefault=True, createdat="2026-01-01T09:00:00+00:00"),
        _make_method_dict(methodid="pm-002", createdat="2026-01-02T09:00:00+00:00"),
        _make_method_dict(methodid="pm-003", createdat="2026-01-03T09:00:00+00:00"),
        _make_method_dict(methodid="pm-004", createdat="2026-01-04T09:00:00+00:00"),
    ]

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["canaddnew"] is False
    assert body["methodcount"] == 4


def test_get_payment_methods_defaultmethodid_resolves_from_default_flag(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = [
        _make_method_dict(methodid="pm-001"),
        _make_method_dict(methodid="pm-002", isdefault=True),
    ]

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    assert body["defaultmethodid"] == "pm-002"


def test_get_payment_methods_statuscounts_populated(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = [
        _make_method_dict(methodid="pm-001", status="active"),
        _make_method_dict(methodid="pm-002", status="expired"),
        _make_method_dict(methodid="pm-003", status="active"),
    ]

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    counts = {entry["status"]: entry["count"] for entry in body["statuscounts"]}
    assert counts["active"] == 2
    assert counts["expired"] == 1


def test_get_payment_methods_package_catalogue_has_all_plans(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = []

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    catalogue = body["package_catalogue"]
    assert set(catalogue.keys()) == set(PACKAGE_CATALOGUE.keys())


def test_get_payment_methods_package_catalogue_stripe_price_id_from_env(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.return_value = []
    monkeypatch.setenv("STRIPE_PRICE_ID_STARTER", "price_starter_test_123")
    monkeypatch.setenv("STRIPE_PRICE_ID_TEAM", "price_team_test_456")
    monkeypatch.setenv("STRIPE_PRICE_ID_ENTERPRISE", "price_enterprise_test_789")

    body = client.get("/ui/billing/payment-methods?organizationid=org-001").json()
    catalogue = body["package_catalogue"]
    assert catalogue["starter"]["stripe_price_id"] == "price_starter_test_123"
    assert catalogue["team"]["stripe_price_id"] == "price_team_test_456"
    assert catalogue["enterprise"]["stripe_price_id"] == "price_enterprise_test_789"


def test_get_payment_methods_returns_502_on_stripe_service_error(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    mock_svc._org_customer_map[ORG_ID] = CUSTOMER_ID
    mock_svc.list_payment_methods.side_effect = StripeServiceError("boom")

    resp = client.get("/ui/billing/payment-methods?organizationid=org-001")

    assert resp.status_code == 502
    body = resp.json()
    assert body["detail"]["error"] == "payment_methods_fetch_error"


def test_get_payment_methods_uses_query_org_id_when_auth_org_missing(
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    auth_without_org = AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="api_key",
        principal_id="test-principal",
        session_id=None,
        org_id="",
        permissions=(),
        roles=(),
        authenticated=True,
        auth_source="test",
        auth_method="api_key",
        key_type="personal",
    )

    _app.dependency_overrides[get_stripe_service] = lambda: mock_svc
    _app.dependency_overrides[get_auth_context] = lambda: auth_without_org
    try:
        with TestClient(_app, raise_server_exceptions=True) as test_client:
            test_client.headers.update(_AUTH_HEADERS)
            body = test_client.get("/ui/billing/payment-methods?organizationid=org-fallback").json()
            assert body["organizationid"] == "org-fallback"
    finally:
        _app.dependency_overrides.pop(get_stripe_service, None)
        _app.dependency_overrides.pop(get_auth_context, None)


# ---------------------------------------------------------------------------
# POST /ui/billing/payment-methods
# ---------------------------------------------------------------------------


def test_post_add_payment_method_creates_record(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    payload = {"stripe_payment_method_id": "pm_test_abc123", "set_as_default": False}

    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "created"
    assert body["organizationid"] == "org-001"
    assert body["methodid"] == "pm_test_abc123"
    rows = fake_supabase.tables["billing_payment_methods"]
    assert len(rows) == 1
    assert rows[0]["stripe_payment_method_id"] == "pm_test_abc123"


def test_post_add_payment_method_sets_default_and_unsets_old_row(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    _seed_db_method(
        fake_supabase,
        row_id="row-existing",
        stripe_payment_method_id="pm-existing",
        payment_method_id="pm-existing",
        is_default=True,
    )
    payload = {"stripe_payment_method_id": "pm_test_new_default", "set_as_default": True}

    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)

    assert resp.status_code == 201
    rows = fake_supabase.tables["billing_payment_methods"]
    old_row = next(row for row in rows if row["id"] == "row-existing")
    new_row = next(row for row in rows if row["stripe_payment_method_id"] == "pm_test_new_default")
    assert old_row["is_default"] is False
    assert new_row["is_default"] is True
    assert resp.json()["methodid"] == "pm_test_new_default"


def test_post_add_payment_method_returns_409_at_max_methods(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    _seed_db_method(fake_supabase, row_id="row-1")
    _seed_db_method(fake_supabase, row_id="row-2")
    _seed_db_method(fake_supabase, row_id="row-3")
    _seed_db_method(fake_supabase, row_id="row-4")

    payload = {"stripe_payment_method_id": "pm_test_overflow", "set_as_default": False}
    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)

    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "payment_method_limit_reached"


def test_post_add_payment_method_returns_503_when_supabase_not_configured(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(payment_methods_module, "is_supabase_configured", lambda: False)

    payload = {"stripe_payment_method_id": "pm_test_abc123", "set_as_default": False}
    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)

    assert resp.status_code == 503


def test_post_add_payment_method_returns_422_when_method_id_blank(
    client: TestClient,
    fake_supabase: FakeSupabaseClient,
) -> None:
    payload = {"stripe_payment_method_id": "", "set_as_default": False}

    resp = client.post("/ui/billing/payment-methods?organizationid=org-001", json=payload)

    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /ui/billing/payment-methods/{methodid}/default
# ---------------------------------------------------------------------------


def test_patch_default_sets_requested_row_default(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    _seed_db_method(
        fake_supabase,
        row_id="row-1",
        stripe_payment_method_id="pm-001",
        payment_method_id="pm-001",
        is_default=True,
    )
    _seed_db_method(
        fake_supabase,
        row_id="row-2",
        stripe_payment_method_id="pm-002",
        payment_method_id="pm-002",
        is_default=False,
    )

    resp = client.patch("/ui/billing/payment-methods/pm-002/default?organizationid=org-001")

    assert resp.status_code == 200
    rows = fake_supabase.tables["billing_payment_methods"]
    row_1 = next(row for row in rows if row["id"] == "row-1")
    row_2 = next(row for row in rows if row["id"] == "row-2")
    assert row_1["is_default"] is False
    assert row_2["is_default"] is True


def test_patch_default_response_shape(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    _seed_db_method(
        fake_supabase,
        row_id="row-1",
        stripe_payment_method_id="pm-001",
        payment_method_id="pm-001",
    )

    resp = client.patch("/ui/billing/payment-methods/pm-001/default?organizationid=org-001")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "updated"
    assert body["methodid"] == "pm-001"
    assert body["organizationid"] == "org-001"
    assert isinstance(body["generatedat"], str)
    assert isinstance(body["environment"], str)
    assert isinstance(body["message"], str)


def test_patch_default_returns_400_when_method_id_blank_after_normalize(
    client: TestClient,
    fake_supabase: FakeSupabaseClient,
) -> None:
    resp = client.patch("/ui/billing/payment-methods/%20/default?organizationid=org-001")

    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "payment_method_id_required"


def test_patch_default_returns_503_when_supabase_not_configured(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(payment_methods_module, "is_supabase_configured", lambda: False)

    resp = client.patch("/ui/billing/payment-methods/pm-001/default?organizationid=org-001")

    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# DELETE /ui/billing/payment-methods/{methodid}
# ---------------------------------------------------------------------------


def test_delete_method_deletes_requested_row(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    _seed_db_method(fake_supabase, row_id="row-1", stripe_payment_method_id="pm-001", payment_method_id="pm-001")
    _seed_db_method(fake_supabase, row_id="row-2", stripe_payment_method_id="pm-002", payment_method_id="pm-002")

    resp = client.delete("/ui/billing/payment-methods/pm-001?organizationid=org-001")

    assert resp.status_code == 200
    rows = fake_supabase.tables["billing_payment_methods"]
    remaining_ids = {row["id"] for row in rows}
    assert "row-1" not in remaining_ids
    assert "row-2" in remaining_ids


def test_delete_method_response_shape(
    client: TestClient,
    mock_svc: MagicMock,
    fake_supabase: FakeSupabaseClient,
) -> None:
    _seed_db_method(fake_supabase, row_id="row-1", stripe_payment_method_id="pm-001", payment_method_id="pm-001")

    resp = client.delete("/ui/billing/payment-methods/pm-001?organizationid=org-001")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "deleted"
    assert body["methodid"] == "pm-001"
    assert body["organizationid"] == "org-001"
    assert isinstance(body["generatedat"], str)
    assert isinstance(body["environment"], str)
    assert isinstance(body["message"], str)


def test_delete_method_returns_400_when_method_id_blank_after_normalize(
    client: TestClient,
    fake_supabase: FakeSupabaseClient,
) -> None:
    resp = client.delete("/ui/billing/payment-methods/%20?organizationid=org-001")

    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "payment_method_id_required"


def test_delete_method_returns_503_when_supabase_not_configured(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(payment_methods_module, "is_supabase_configured", lambda: False)

    resp = client.delete("/ui/billing/payment-methods/pm-001?organizationid=org-001")

    assert resp.status_code == 503
