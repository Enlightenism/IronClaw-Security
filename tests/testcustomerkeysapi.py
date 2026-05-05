from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.api_keys import create_api_key_registry
from app.main import app


client = TestClient(app)


def _install_fresh_registry():
    registry = create_api_key_registry()

    original_get_api_key_registry = app.routes[0].endpoint.__globals__.get("get_api_key_registry")
    return registry, original_get_api_key_registry


def test_create_customer_key_returns_revealed_once_secret(monkeypatch) -> None:
    from app.routes import customerkeys as customerkeys_module

    registry = create_api_key_registry()
    monkeypatch.setattr(customerkeys_module, "get_api_key_registry", lambda: registry)

    response = client.post(
        "/customer-keys",
        json={
            "label": "Primary Production Key",
            "owner_type": "customer",
            "owner_id": "tenant-123",
            "scopes": ["scan:write", "history:read"],
            "environment": "production",
            "metadata": {"rotation_due": False},
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert data["status"] == "ok"
    assert data["operation"] == "create"
    assert data["label"] == "Primary Production Key"
    assert data["key_status"] == "active"
    assert data["owner_type"] == "customer"
    assert data["owner_id"] == "tenant-123"
    assert data["scopes"] == ["scan:write", "history:read"]
    assert data["revealed_once_key"]
    assert data["revealed_once_key"].startswith("icg1_")
    assert "…" in data["masked_key"] or len(data["masked_key"]) <= 12


def test_rotate_customer_key_invalidates_old_secret_and_returns_new_one(monkeypatch) -> None:
    from app.routes import customerkeys as customerkeys_module

    registry = create_api_key_registry()
    monkeypatch.setattr(customerkeys_module, "get_api_key_registry", lambda: registry)

    created = registry.create_key(
        display_name="Rotate Me",
        metadata={
            "owner_type": "customer",
            "owner_id": "tenant-rotate",
            "scopes": ["scan:write"],
            "environment": "production",
            "rotation_due": True,
        },
    )
    old_secret = created.raw_key
    assert old_secret is not None

    response = client.post(f"/customer-keys/{created.key_id}/rotate")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["operation"] == "rotate"
    assert data["key_id"] == created.key_id
    assert data["revealed_once_key"]
    assert data["revealed_once_key"] != old_secret
    assert data["metadata"]["rotation_due"] is False

    assert registry.resolve_api_key(old_secret) is None
    assert registry.resolve_api_key(data["revealed_once_key"]) is not None


def test_revoke_customer_key_marks_key_revoked(monkeypatch) -> None:
    from app.routes import customerkeys as customerkeys_module

    registry = create_api_key_registry()
    monkeypatch.setattr(customerkeys_module, "get_api_key_registry", lambda: registry)

    created = registry.create_key(
        display_name="Revoke Me",
        metadata={
            "owner_type": "customer",
            "owner_id": "tenant-revoke",
            "scopes": ["history:read"],
            "environment": "staging",
        },
    )
    created_secret = created.raw_key
    assert created_secret is not None

    response = client.post(f"/customer-keys/{created.key_id}/revoke")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["operation"] == "revoke"
    assert data["key_id"] == created.key_id
    assert data["key_status"] == "revoked"
    assert data["revealed_once_key"] is None

    revoked_record = registry.get_key(created.key_id)
    assert revoked_record is not None
    assert revoked_record.active is False
    assert registry.resolve_api_key(created_secret) is None


def test_rotate_missing_customer_key_returns_404(monkeypatch) -> None:
    from app.routes import customerkeys as customerkeys_module

    registry = create_api_key_registry()
    monkeypatch.setattr(customerkeys_module, "get_api_key_registry", lambda: registry)

    response = client.post("/customer-keys/key_missing/rotate")
    assert response.status_code == 404


def test_revoke_missing_customer_key_returns_404(monkeypatch) -> None:
    from app.routes import customerkeys as customerkeys_module

    registry = create_api_key_registry()
    monkeypatch.setattr(customerkeys_module, "get_api_key_registry", lambda: registry)

    response = client.post("/customer-keys/key_missing/revoke")
    assert response.status_code == 404