from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.services.secret_service import create_secret_service

client = TestClient(app)


def test_create_integration_secret_returns_revealed_once_value(monkeypatch) -> None:
    from app.routes.integrations import secrets as secrets_module

    service = create_secret_service()
    monkeypatch.setattr(secrets_module, "get_secret_service", lambda: service)

    response = client.post(
        "/integrations/secrets",
        json={
            "name": "groq-primary",
            "value": "gsk_live_primary_secret",
            "provider": "groq",
            "kind": "api_key",
            "metadata": {"environment": "production"},
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert data["status"] == "ok"
    assert data["operation"] == "create"
    assert data["name"] == "groq-primary"
    assert data["provider"] == "groq"
    assert data["kind"] == "api_key"
    assert data["secret_status"] == "active"
    assert data["revealed_once_value"] == "gsk_live_primary_secret"
    assert data["masked_value"] != data["revealed_once_value"]


def test_list_integration_secrets_returns_created_records(monkeypatch) -> None:
    from app.routes.integrations import secrets as secrets_module

    service = create_secret_service()
    monkeypatch.setattr(secrets_module, "get_secret_service", lambda: service)

    service.create_secret(
        name="groq-primary",
        value="gsk_live_primary_secret",
        provider="groq",
        kind="api_key",
        metadata={"environment": "production"},
    )
    service.create_secret(
        name="claude-secondary",
        value="claude_secondary_secret",
        provider="anthropic",
        kind="api_key",
        metadata={"environment": "staging"},
    )

    response = client.get("/integrations/secrets")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["total"] == 2
    assert data["active"] == 2
    assert data["inactive"] == 0
    assert len(data["secrets"]) == 2
    assert {item["name"] for item in data["secrets"]} == {"groq-primary", "claude-secondary"}


def test_rotate_integration_secret_returns_new_revealed_value(monkeypatch) -> None:
    from app.routes.integrations import secrets as secrets_module

    service = create_secret_service()
    monkeypatch.setattr(secrets_module, "get_secret_service", lambda: service)

    created = service.create_secret(
        name="groq-primary",
        value="gsk_live_primary_secret",
        provider="groq",
        kind="api_key",
        metadata={"environment": "production"},
    )

    response = client.post(
        f"/integrations/secrets/{created.secret_id}/rotate",
        json={
            "value": "gsk_live_rotated_secret",
            "metadata": {"rotation_reason": "scheduled"},
        },
    )
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["operation"] == "rotate"
    assert data["secret_id"] == created.secret_id
    assert data["revealed_once_value"] == "gsk_live_rotated_secret"
    assert data["metadata"]["rotation_reason"] == "scheduled"

    rotated = service.get_secret(created.secret_id)
    assert rotated is not None
    assert service.verify_secret_value(created.secret_id, "gsk_live_rotated_secret") is True
    assert service.verify_secret_value(created.secret_id, "gsk_live_primary_secret") is False


def test_revoke_integration_secret_marks_secret_inactive(monkeypatch) -> None:
    from app.routes.integrations import secrets as secrets_module

    service = create_secret_service()
    monkeypatch.setattr(secrets_module, "get_secret_service", lambda: service)

    created = service.create_secret(
        name="claude-primary",
        value="claude_primary_secret",
        provider="anthropic",
        kind="api_key",
        metadata={"environment": "production"},
    )

    response = client.post(f"/integrations/secrets/{created.secret_id}/revoke")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["operation"] == "revoke"
    assert data["secret_id"] == created.secret_id
    assert data["secret_status"] == "revoked"
    assert data["revealed_once_value"] is None

    revoked = service.get_secret(created.secret_id)
    assert revoked is not None
    assert revoked.active is False


def test_create_duplicate_secret_returns_400(monkeypatch) -> None:
    from app.routes.integrations import secrets as secrets_module

    service = create_secret_service()
    monkeypatch.setattr(secrets_module, "get_secret_service", lambda: service)

    first_response = client.post(
        "/integrations/secrets",
        json={
            "name": "groq-primary",
            "value": "gsk_live_primary_secret",
            "provider": "groq",
            "kind": "api_key",
            "metadata": {},
        },
    )
    assert first_response.status_code == 200

    duplicate_response = client.post(
        "/integrations/secrets",
        json={
            "name": "groq-primary",
            "value": "gsk_other_secret",
            "provider": "groq",
            "kind": "api_key",
            "metadata": {},
        },
    )
    assert duplicate_response.status_code == 400


def test_rotate_missing_secret_returns_404(monkeypatch) -> None:
    from app.routes.integrations import secrets as secrets_module

    service = create_secret_service()
    monkeypatch.setattr(secrets_module, "get_secret_service", lambda: service)

    response = client.post(
        "/integrations/secrets/secret_missing/rotate",
        json={"value": "new_secret_value", "metadata": {}},
    )
    assert response.status_code == 404


def test_revoke_missing_secret_returns_404(monkeypatch) -> None:
    from app.routes.integrations import secrets as secrets_module

    service = create_secret_service()
    monkeypatch.setattr(secrets_module, "get_secret_service", lambda: service)

    response = client.post("/integrations/secrets/secret_missing/revoke")
    assert response.status_code == 404
