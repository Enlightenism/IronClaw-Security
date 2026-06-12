from __future__ import annotations

from collections.abc import Generator
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest

from app.core.unit_wallet import TOKEN_CHUNK_SIZE
from app.main import app as _app
from app.services.organization_store import OrganizationStore, reset_organization_store
from app.ui.organizations import (
    _ORDERED_PACKAGE_IDS,
    _fetch_owner_wallet,
    _get_package_metadata,
    get_store,
)

_BASE = "/ui/organizations"

_VALID_PAYLOAD: dict[str, object] = {
    "name": "Acme Corp",
    "slug": "acme-corp",
    "owner_email": "owner@acme.com",
    "owner_display_name": "Acme Owner",
}


@pytest.fixture(autouse=True)
def _isolated_store() -> Generator[OrganizationStore, None, None]:
    store = OrganizationStore()
    _app.dependency_overrides[get_store] = lambda: store
    yield store
    _app.dependency_overrides.pop(get_store, None)
    reset_organization_store()


@pytest.fixture()
def client(_isolated_store: OrganizationStore) -> Generator[TestClient, None, None]:
    with TestClient(_app, raise_server_exceptions=True) as tc:
        yield tc


# ---------------------------------------------------------------------------
# _get_package_metadata — unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pkg_id", _ORDERED_PACKAGE_IDS)
def test_get_package_metadata_tokens_in_wallet(pkg_id: str) -> None:
    """tokens_in_wallet == included_units * TOKEN_CHUNK_SIZE for every package."""
    meta = _get_package_metadata(pkg_id)
    assert "tokens_in_wallet" in meta, f"{pkg_id}: key 'tokens_in_wallet' missing"
    assert "max_tokens_covered" not in meta, f"{pkg_id}: obsolete key 'max_tokens_covered' present"
    included_units = meta["included_units"]
    assert meta["tokens_in_wallet"] == included_units * TOKEN_CHUNK_SIZE


@pytest.mark.parametrize("pkg_id", _ORDERED_PACKAGE_IDS)
def test_get_package_metadata_base_fields(pkg_id: str) -> None:
    meta = _get_package_metadata(pkg_id)
    for key in ("package_id", "name", "price_usd", "included_units", "tokens_per_unit", "featured"):
        assert key in meta, f"{pkg_id}: missing field '{key}'"


def test_get_package_metadata_unknown_returns_empty() -> None:
    assert _get_package_metadata("pkg_unknown_xyz") == {}


# ---------------------------------------------------------------------------
# _fetch_owner_wallet — unit tests
# ---------------------------------------------------------------------------


def test_fetch_owner_wallet_supabase_unavailable_returns_empty() -> None:
    """Returns {} when Supabase is unavailable (_SUPABASE_AVAILABLE=False)."""
    import app.ui.organizations as _mod

    orig = _mod._SUPABASE_AVAILABLE
    try:
        _mod._SUPABASE_AVAILABLE = False
        result = _fetch_owner_wallet("owner@acme.com")
        assert result == {}
    finally:
        _mod._SUPABASE_AVAILABLE = orig


def test_fetch_owner_wallet_empty_email_returns_empty() -> None:
    assert _fetch_owner_wallet("") == {}


def test_fetch_owner_wallet_supabase_valid_row_tokens_in_wallet() -> None:
    """tokens_in_wallet == wallet_units * TOKEN_CHUNK_SIZE when Supabase returns a row."""
    wallet_units = 500
    mock_result = MagicMock()
    mock_result.data = [
        {
            "id": "user-uuid-123",
            "email": "owner@acme.com",
            "wallet_units": wallet_units,
            "has_paid": True,
            "last_payment": {"package_id": "pkg_5000"},
        }
    ]

    mock_supabase = MagicMock()
    mock_supabase.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = mock_result

    import app.ui.organizations as _mod

    with (
        patch.object(_mod, "_supabase", mock_supabase),
        patch.object(_mod, "_SUPABASE_AVAILABLE", True),
    ):
        result = _fetch_owner_wallet("owner@acme.com")

    assert "tokens_in_wallet" in result, "key 'tokens_in_wallet' missing from wallet result"
    assert "max_tokens_covered" not in result, "obsolete key 'max_tokens_covered' present"
    assert result["tokens_in_wallet"] == wallet_units * TOKEN_CHUNK_SIZE
    assert result["wallet_units"] == wallet_units
    assert result["has_paid"] is True


def test_fetch_owner_wallet_supabase_no_rows_returns_empty() -> None:
    """Returns {} when Supabase returns no rows for the email."""
    mock_result = MagicMock()
    mock_result.data = []

    mock_supabase = MagicMock()
    mock_supabase.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = mock_result

    import app.ui.organizations as _mod

    with (
        patch.object(_mod, "_supabase", mock_supabase),
        patch.object(_mod, "_SUPABASE_AVAILABLE", True),
    ):
        result = _fetch_owner_wallet("nobody@example.com")

    assert result == {}


def test_fetch_owner_wallet_supabase_exception_returns_empty() -> None:
    """Returns {} when Supabase raises an exception (non-blocking)."""
    mock_supabase = MagicMock()
    mock_supabase.table.side_effect = RuntimeError("DB down")

    import app.ui.organizations as _mod

    with (
        patch.object(_mod, "_supabase", mock_supabase),
        patch.object(_mod, "_SUPABASE_AVAILABLE", True),
    ):
        result = _fetch_owner_wallet("owner@acme.com")

    assert result == {}


# ---------------------------------------------------------------------------
# GET /ui/organizations — list
# ---------------------------------------------------------------------------


def test_list_organizations_empty_returns_200(client: TestClient) -> None:
    response = client.get(_BASE)
    assert response.status_code == 200


def test_list_organizations_empty_shape(client: TestClient) -> None:
    body = client.get(_BASE).json()
    assert body["status"] == "ok"
    assert "billing_catalog" in body
    assert body["items"] == []


def test_list_organizations_empty_summary(client: TestClient) -> None:
    body = client.get(_BASE).json()
    assert "summary" in body
    assert body["summary"]["total"] == 0


def test_list_organizations_after_create(client: TestClient) -> None:
    client.post(_BASE, json=_VALID_PAYLOAD)
    body = client.get(_BASE).json()
    assert body["summary"]["total"] >= 1


def test_list_organizations_item_shape(client: TestClient) -> None:
    client.post(_BASE, json=_VALID_PAYLOAD)
    items = client.get(_BASE).json()["items"]
    assert len(items) >= 1
    item = items[0]
    assert "organization_id" in item
    assert "name" in item
    assert "slug" in item
    assert "status" in item
    assert "owner_email" in item
    assert "created_at" in item


def test_list_organizations_summary_keys(client: TestClient) -> None:
    summary = client.get(_BASE).json()["summary"]
    assert "total" in summary
    assert "active" in summary
    assert "suspended" in summary
    assert "member_total" in summary


def test_list_organizations_actions_keys(client: TestClient) -> None:
    actions = client.get(_BASE).json()["actions"]
    assert "list_route" in actions
    assert "create_route" in actions


def test_list_organizations_status_is_ok(client: TestClient) -> None:
    assert client.get(_BASE).json()["status"] == "ok"


# ---------------------------------------------------------------------------
# billing_catalog — field contract
# ---------------------------------------------------------------------------


def test_billing_catalog_present_on_empty_list(client: TestClient) -> None:
    body = client.get(_BASE).json()
    assert "billing_catalog" in body


def test_billing_catalog_packages_tokens_in_wallet(client: TestClient) -> None:
    """Every package in billing_catalog uses tokens_in_wallet, not max_tokens_covered."""
    catalog = client.get(_BASE).json()["billing_catalog"]
    packages = catalog["packages"]
    assert len(packages) == 3
    for pkg_id, pkg in packages.items():
        assert "tokens_in_wallet" in pkg, f"{pkg_id}: 'tokens_in_wallet' missing from billing_catalog package"
        assert "max_tokens_covered" not in pkg, f"{pkg_id}: obsolete 'max_tokens_covered' present"
        assert pkg["tokens_in_wallet"] == pkg["included_units"] * TOKEN_CHUNK_SIZE


def test_billing_catalog_tokens_per_unit(client: TestClient) -> None:
    catalog = client.get(_BASE).json()["billing_catalog"]
    assert catalog["tokens_per_unit"] == TOKEN_CHUNK_SIZE


# ---------------------------------------------------------------------------
# POST /ui/organizations — create
# ---------------------------------------------------------------------------


def test_create_organization_returns_201(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201


def test_create_organization_response_has_organization_key(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    assert "organization" in response.json()


def test_create_organization_response_shape(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    body = response.json()
    assert "status" in body
    assert "organization" in body


def test_create_organization_organization_shape(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    org = response.json()["organization"]
    assert "organizationid" in org
    assert "name" in org
    assert "slug" in org
    assert "status" in org
    assert "owner_email" in org
    assert "members" in org
    assert "created_at" in org


def test_create_organization_persists_name(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    assert response.json()["organization"]["name"] == _VALID_PAYLOAD["name"]


def test_create_organization_persists_owneremail(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    assert response.json()["organization"]["owner_email"] == str(_VALID_PAYLOAD["owner_email"]).lower()


def test_create_organization_has_organizationid(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    org_id = response.json()["organization"]["organizationid"]
    assert isinstance(org_id, str)
    assert len(org_id) > 0


def test_create_organization_default_status_active(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    assert response.json()["organization"]["status"] == "active"


def test_create_organization_members_is_list(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201
    assert isinstance(response.json()["organization"]["members"], list)


def test_create_organization_duplicate_slug_returns_409(client: TestClient) -> None:
    client.post(_BASE, json=_VALID_PAYLOAD)
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 409


def test_create_organization_with_metadata(client: TestClient) -> None:
    payload = {**_VALID_PAYLOAD, "slug": "acme-meta", "metadata": {"tier": "pro"}}
    response = client.post(_BASE, json=payload)
    assert response.status_code == 201
    assert response.json()["organization"]["metadata"] == {"tier": "pro"}


# ---------------------------------------------------------------------------
# GET /ui/organizations/{id} — detail
# ---------------------------------------------------------------------------


def test_get_organization_by_id_returns_200(client: TestClient) -> None:
    create_resp = client.post(_BASE, json=_VALID_PAYLOAD)
    assert create_resp.status_code == 201
    org_id = create_resp.json()["organization"]["organizationid"]
    assert client.get(f"{_BASE}/{org_id}").status_code == 200


def test_get_organization_by_id_response_shape(client: TestClient) -> None:
    create_resp = client.post(_BASE, json=_VALID_PAYLOAD)
    assert create_resp.status_code == 201
    org_id = create_resp.json()["organization"]["organizationid"]
    body = client.get(f"{_BASE}/{org_id}").json()
    assert "status" in body
    assert "organization" in body


def test_get_organization_by_id_organization_shape(client: TestClient) -> None:
    create_resp = client.post(_BASE, json=_VALID_PAYLOAD)
    assert create_resp.status_code == 201
    org_id = create_resp.json()["organization"]["organizationid"]
    org = client.get(f"{_BASE}/{org_id}").json()["organization"]
    assert "organizationid" in org
    assert "name" in org
    assert "slug" in org
    assert "status" in org
    assert "owner_email" in org
    assert "members" in org
    assert "created_at" in org


def test_get_organization_by_id_matches_created(client: TestClient) -> None:
    create_resp = client.post(_BASE, json=_VALID_PAYLOAD)
    assert create_resp.status_code == 201
    created_org = create_resp.json()["organization"]
    org_id = created_org["organizationid"]
    fetched_org = client.get(f"{_BASE}/{org_id}").json()["organization"]
    assert fetched_org["organizationid"] == org_id
    assert fetched_org["name"] == created_org["name"]


def test_get_organization_by_id_not_found_returns_404(client: TestClient) -> None:
    assert client.get(f"{_BASE}/org-doesnotexist999").status_code == 404


def test_get_organization_timestamp_is_string(client: TestClient) -> None:
    create_resp = client.post(_BASE, json=_VALID_PAYLOAD)
    assert create_resp.status_code == 201
    org_id = create_resp.json()["organization"]["organizationid"]
    org = client.get(f"{_BASE}/{org_id}").json()["organization"]
    assert isinstance(org["created_at"], str)
    assert len(org["created_at"]) > 0
