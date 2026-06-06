from __future__ import annotations

from collections.abc import Generator

from fastapi.testclient import TestClient
import pytest

from app.main import app as _app
from app.services.organization_store import OrganizationStore, reset_organization_store
from app.ui.organizations import get_store

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
# GET /ui/organizations — list
# ---------------------------------------------------------------------------


def test_list_organizations_empty_returns_200(client: TestClient) -> None:
    response = client.get(_BASE)
    assert response.status_code == 200


def test_list_organizations_empty_shape(client: TestClient) -> None:
    body = client.get(_BASE).json()
    assert "status" in body
    assert "items" in body
    assert "summary" in body
    assert "total" in body["summary"]


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
# POST /ui/organizations — create
# ---------------------------------------------------------------------------


def test_create_organization_returns_201(client: TestClient) -> None:
    response = client.post(_BASE, json=_VALID_PAYLOAD)
    assert response.status_code == 201


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
