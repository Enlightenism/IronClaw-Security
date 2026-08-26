"""tests/test_ui_customer_keys.py

Tests for the UI-facing customer-key API contract used by the app-level router.
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi.testclient import TestClient
import pytest

from app.api.customer_keys import CustomerKeyRegistry
from app.core.auth import require_api_key

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> CustomerKeyRegistry:
    return CustomerKeyRegistry()


@pytest.fixture()
def client(registry: CustomerKeyRegistry) -> Generator[TestClient, None, None]:
    import app.api.customer_keys as ck_module
    from app.main import app

    def _override_require_api_key() -> str:
        return "test-token"

    def _override_registry() -> CustomerKeyRegistry:
        return registry

    app.dependency_overrides[require_api_key] = _override_require_api_key

    original = ck_module.get_customer_key_registry
    ck_module.get_customer_key_registry = _override_registry  # type: ignore[assignment]

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    app.dependency_overrides.pop(require_api_key, None)
    ck_module.get_customer_key_registry = original  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_AUTH = {"X-API-Key": "test-token"}
_BASE = "/customer-keys"


def _create(
    client: TestClient,
    *,
    customer_id: str = "cust-001",
    owner_key: str = "owner-001",
    display_name: str = "Test Key",
    org_id: str | None = None,
    metadata: dict | None = None,
) -> dict:
    body: dict = {
        "customer_id": customer_id,
        "owner_key": owner_key,
        "display_name": display_name,
    }
    if org_id is not None:
        body["org_id"] = org_id
    if metadata is not None:
        body["metadata"] = metadata
    resp = client.post(_BASE, json=body, headers=_AUTH)
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# GET /customer-keys
# ---------------------------------------------------------------------------


def test_list_customer_keys_empty_returns_200(client: TestClient) -> None:
    resp = client.get(_BASE, headers=_AUTH)
    assert resp.status_code == 200


def test_list_customer_keys_key_view_shape(client: TestClient) -> None:
    _create(client)
    resp = client.get(_BASE, headers=_AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "service" in data
    assert "timestamp" in data
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) >= 1
    key = data["items"][0]
    for field in ("key_id", "customer_id", "owner_key", "display_name", "active", "metadata"):
        assert field in key, f"missing field: {field}"


def test_list_customer_keys_content_type_json(client: TestClient) -> None:
    resp = client.get(_BASE, headers=_AUTH)
    assert "application/json" in resp.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# POST /customer-keys
# ---------------------------------------------------------------------------


def test_create_customer_key_returns_201(client: TestClient) -> None:
    resp = client.post(
        _BASE,
        json={
            "customer_id": "cust-001",
            "owner_key": "owner-001",
            "display_name": "My Key",
        },
        headers=_AUTH,
    )
    assert resp.status_code == 201


def test_create_customer_key_content_type_json(client: TestClient) -> None:
    resp = client.post(
        _BASE,
        json={
            "customer_id": "cust-001",
            "owner_key": "owner-001",
            "display_name": "My Key",
        },
        headers=_AUTH,
    )
    assert "application/json" in resp.headers.get("content-type", "")


def test_create_customer_key_top_level_fields(client: TestClient) -> None:
    resp = client.post(
        _BASE,
        json={
            "customer_id": "cust-001",
            "owner_key": "owner-001",
            "display_name": "My Key",
        },
        headers=_AUTH,
    )
    data = resp.json()
    for field in ("status", "service", "timestamp", "key"):
        assert field in data, f"missing top-level field: {field}"


def test_create_customer_key_key_view_shape(client: TestClient) -> None:
    data = _create(client)
    key = data["key"]
    for field in (
        "key_id",
        "customer_id",
        "owner_key",
        "display_name",
        "active",
        "metadata",
        "created_at",
        "updated_at",
    ):
        assert field in key, f"missing key view field: {field}"


def test_create_customer_key_display_name_stripped(client: TestClient) -> None:
    data = _create(client, display_name="  Padded Name  ")
    assert data["key"]["display_name"] == "Padded Name"


def test_create_customer_key_with_metadata(client: TestClient) -> None:
    meta = {"env": "staging", "team": "platform"}
    data = _create(client, display_name="Meta Key", metadata=meta)
    assert data["key"]["metadata"]["env"] == "staging"
    assert data["key"]["metadata"]["team"] == "platform"


def test_create_customer_key_appears_in_list(client: TestClient) -> None:
    created = _create(client, customer_id="cust-list", owner_key="owner-list", display_name="ListCheck")
    key_id = created["key"]["key_id"]
    resp = client.get(_BASE, headers=_AUTH)
    ids = [k["key_id"] for k in resp.json()["items"]]
    assert key_id in ids


def test_create_multiple_keys_increments_total(client: TestClient) -> None:
    _create(client, customer_id="cust-one", owner_key="owner-one", display_name="Key One")
    _create(client, customer_id="cust-two", owner_key="owner-two", display_name="Key Two")
    resp = client.get(_BASE, headers=_AUTH)
    assert resp.json()["total"] >= 2


def test_create_customer_key_active_true(client: TestClient) -> None:
    data = _create(client)
    assert data["key"]["active"] is True


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


def test_revoke_customer_key_returns_200(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    assert resp.status_code == 200


def test_revoke_customer_key_response_shape(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    data = resp.json()
    for field in ("status", "service", "timestamp", "key_id", "active"):
        assert field in data, f"missing revoke response field: {field}"
    assert data["key_id"] == key_id


def test_revoke_customer_key_marks_key_inactive(client: TestClient, registry: CustomerKeyRegistry) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    record = registry.get_by_id(key_id)
    assert record is not None
    assert record.active is False


def test_revoke_customer_key_content_type_json(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    assert "application/json" in resp.headers.get("content-type", "")


def test_revoke_customer_key_revoked_key_id_matches(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    assert resp.json()["key_id"] == key_id
